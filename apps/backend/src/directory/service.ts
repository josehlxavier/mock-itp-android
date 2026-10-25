import { readSecret, type Config } from '../config.js';
import { z } from 'zod';
import { verifySsa, type CryptoService } from '../security/jose.js';
import type { JSONWebKeySet } from 'jose';
import type { DataStore } from '../persistence/store.js';
import { Transport } from '../transport.js';
import { ensure, AppError } from '../errors.js';

const endpoint = z.url();
const apiSchema = z.object({ ApiFamilyType: z.string(), ApiVersion: z.string(),
  ApiDiscoveryEndpoints: z.array(z.object({ ApiEndpoint: endpoint })) });
export const serverSchema = z.object({ AuthorisationServerId: z.string(), OrganisationId: z.string().optional(),
  CustomerFriendlyName: z.string().optional(), CustomerFriendlyLogoUri: z.string().optional(),
  OpenIDDiscoveryDocument: endpoint, Issuer: endpoint,
  PayloadSigningCertLocationUri: endpoint.optional(), ApiResources: z.array(apiSchema).default([]) });
export const participantsSchema = z.array(z.object({ OrganisationId: z.string(), OrganisationName: z.string(),
  Status: z.string(), AuthorisationServers: z.array(serverSchema).default([]) }));
export const oidcSchema = z.object({
  issuer: endpoint, authorization_endpoint: endpoint, token_endpoint: endpoint, registration_endpoint: endpoint,
  jwks_uri: endpoint, pushed_authorization_request_endpoint: endpoint.optional(),
  mtls_endpoint_aliases: z.record(z.string(), endpoint).default({}),
  token_endpoint_auth_methods_supported: z.array(z.string()),
  token_endpoint_auth_signing_alg_values_supported: z.array(z.string()),
  request_object_signing_alg_values_supported: z.array(z.string()).optional(),
  id_token_signing_alg_values_supported: z.array(z.string()).optional(),
  grant_types_supported: z.array(z.string()).optional(), response_types_supported: z.array(z.string()).optional(),
  scopes_supported: z.array(z.string()).optional()
}).passthrough();
export type Oidc = z.infer<typeof oidcSchema>;
export type Selection = Awaited<ReturnType<DirectoryService['select']>>;

export function mtlsEndpoint(metadata: Oidc, name: 'token_endpoint' | 'registration_endpoint' | 'pushed_authorization_request_endpoint') {
  const value = metadata.mtls_endpoint_aliases[name] ?? metadata[name];
  ensure(typeof value === 'string', 'ENDPOINT_NOT_ADVERTISED'); return value;
}

export class DirectoryService {
  constructor(readonly config: Config, readonly http: Transport, private readonly store: DataStore) {}
  private async cached<T>(key: string, loader: () => Promise<T>, refresh: boolean): Promise<T> {
    const cacheKey = `${this.config.mode}:metadata:${key}`;
    const cached = await this.store.get<{ expires: number; value: T }>(cacheKey);
    if (!refresh && cached && cached.expires > Date.now()) return cached.value;
    // Never serve expired entries or fall back to a simulator after a failure.
    const value = await loader();
    await this.store.put(cacheKey, { value, expires: Date.now() + this.config.directory.cacheSeconds * 1000 });
    return value;
  }
  async participants(refresh = false) {
    return this.cached('participants', async () => {
      const data = participantsSchema.parse(await this.http.json(this.config.directory.participantsUrl, 'directory.participants'));
      return data.filter(p => p.Status === 'Active');
    }, refresh);
  }
  async select(organisationId: string, serverId: string, refresh = false) {
    const org = (await this.participants(refresh)).find(p => p.OrganisationId === organisationId);
    const server = org?.AuthorisationServers.find(s => s.AuthorisationServerId === serverId);
    ensure(org && server, 'INSTITUTION_OR_AS_NOT_FOUND', 404);
    ensure(!server.OrganisationId || server.OrganisationId === org.OrganisationId, 'DIRECTORY_ASSOCIATION_MISMATCH');
    const metadata = await this.cached(`oidc:${organisationId}:${serverId}`, async () => {
      const value = oidcSchema.parse(await this.http.json(server.OpenIDDiscoveryDocument, 'oidc.discovery'));
      ensure(value.issuer === server.Issuer, 'OIDC_ISSUER_MISMATCH');
      for (const name of ['authorization_endpoint', 'token_endpoint', 'registration_endpoint', 'jwks_uri', 'pushed_authorization_request_endpoint'] as const) {
        if (value[name]) this.http.checkUrl(value[name]);
      }
      for (const uri of Object.values(value.mtls_endpoint_aliases)) this.http.checkUrl(uri);
      ensure(value.token_endpoint_auth_methods_supported.includes('private_key_jwt') && value.token_endpoint_auth_signing_alg_values_supported.includes('PS256'), 'AS_SECURITY_PROFILE_UNSUPPORTED');
      ensure(value.pushed_authorization_request_endpoint, 'AS_PAR_REQUIRED');
      return value;
    }, refresh);
    ensure(metadata.issuer === server.Issuer, 'OIDC_ISSUER_MISMATCH');
    const resources = server.ApiResources.filter(a => ['enrollments', 'payments'].includes(a.ApiFamilyType));
    for (const api of resources) for (const e of api.ApiDiscoveryEndpoints) this.http.checkUrl(e.ApiEndpoint);
    return { organisation: org.OrganisationId, organisationName: org.OrganisationName,
      serverId, brand: server.CustomerFriendlyName, metadata, resources,
      resourceJwksUri: server.PayloadSigningCertLocationUri };
  }
  async keys(uri: string, refresh = false): Promise<JSONWebKeySet> {
    return this.cached(`jwks:${uri}`, async () => {
      const result = await this.http.json<JSONWebKeySet>(uri, 'jwks.fetch');
      ensure(Array.isArray(result.keys) && result.keys.length > 0 && !result.keys.some(k => 'd' in k || k.kty === 'oct'), 'INVALID_JWKS');
      return result;
    }, refresh);
  }
  async ssa() {
    const c = this.config;
    let token: string;
    if (c.directory.ssaFile) token = await readSecret(c.directory.ssaFile);
    else {
      const headers: Record<string, string> = { accept: 'application/jwt' };
      if (c.directory.tokenFile) headers.authorization = `Bearer ${await readSecret(c.directory.tokenFile)}`;
      const result = await this.http.send(c.directory.ssaUrl!, { method: 'GET', operation: 'directory.ssa', headers });
      ensure(String(result.headers['content-type']).includes('application/jwt'), 'INVALID_SSA_CONTENT_TYPE');
      token = result.text.trim();
    }
    const keys = await this.keys(c.directory.jwksUri);
    let payload;
    try { payload = await verifySsa(token, keys, c.directory.issuer); }
    catch (e) {
      if (!(e instanceof AppError)) throw e;
      payload = await verifySsa(token, await this.keys(c.directory.jwksUri, true), c.directory.issuer);
    }
    ensure(payload.org_id === c.organisationId && payload.software_id === c.softwareId, 'SSA_IDENTITY_MISMATCH');
    ensure(payload.software_jwks_uri === c.jwksUri, 'SSA_JWKS_MISMATCH');
    const redirects = z.array(z.string()).parse(payload.software_redirect_uris);
    const origins = z.array(z.string()).parse(payload.origin);
    ensure(payload.org_status === 'Active', 'SSA_ORGANISATION_INACTIVE');
    const roles = z.array(z.object({ role: z.string(), status: z.string() })).parse(payload.software_statement_roles);
    ensure(roles.some(r => r.role === 'PAGTO' && r.status === 'Active'), 'SSA_PAGTO_ROLE_REQUIRED');
    const paymentScopes = new Set(['openid', 'payments', 'recurring-payments', 'nrp-consents']);
    ensure(c.scopes.every(scope => paymentScopes.has(scope)), 'SSA_SCOPE_NOT_AUTHORISED_FOR_ITP');
    ensure(c.redirectUris.every(v => redirects.includes(v)), 'SSA_REDIRECT_MISMATCH');
    ensure(c.androidOrigins.every(v => origins.includes(v)), 'SSA_ANDROID_ORIGIN_MISMATCH');
    return { token, payload };
  }
  async verifyResource(crypto: CryptoService, selection: Selection, token: string, clientId?: string) {
    ensure(selection.resourceJwksUri, 'RESOURCE_KEYS_NOT_PUBLISHED');
    const expected = { issuer: selection.organisation, audience: this.config.organisationId, clientId };
    try { return await crypto.verify('resource', token, await this.keys(selection.resourceJwksUri), expected); }
    catch (e) {
      if (!(e instanceof AppError) || !['AMBIGUOUS_OR_UNKNOWN_KID', 'BAD_SIGNATURE'].includes(e.code)) throw e;
      return crypto.verify('resource', token, await this.keys(selection.resourceJwksUri, true), expected);
    }
  }
}
