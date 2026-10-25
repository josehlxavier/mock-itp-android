import { createHash, X509Certificate, randomUUID } from 'node:crypto';
import { z } from 'zod';
import type { Config } from '../config.js';
import { DirectoryService, mtlsEndpoint, type Selection } from '../directory/service.js';
import type { DataStore } from '../persistence/store.js';
import { Vault } from '../security/vault.js';
import type { CryptoService } from '../security/jose.js';
import type { Material } from '../security/certificates.js';
import { ensure, AppError } from '../errors.js';

const registrationSchema = z.object({ client_id: z.string().min(1), registration_client_uri: z.url(),
  registration_access_token: z.string().min(1).optional() }).passthrough();
export interface Registration {
  clientId: string; managementUri: string; accessToken: string; metadata: Record<string, unknown>;
  fingerprint: string; issuer: string; transportThumbprint: string; signingKid: string;
}
interface Saved { status: 'pending' | 'active' | 'uncertain'; encrypted?: string }
const hash = (v: unknown) => createHash('sha256').update(JSON.stringify(v)).digest('hex');
const OMIT = new Set(['registration_access_token', 'registration_client_uri', 'client_secret', 'client_id_issued_at', 'client_secret_expires_at', 'software_statement']);

export class DcrService {
  private readonly thumbprint: string;
  private readonly transportPublic: { n?: string; e?: string };
  constructor(private readonly config: Config, private readonly directory: DirectoryService,
    private readonly crypto: CryptoService, private readonly store: DataStore,
    private readonly vault: Vault, material: Material) {
    this.thumbprint = new X509Certificate(material.transportCert).fingerprint256.replaceAll(':', '');
    this.transportPublic = new X509Certificate(material.transportCert).publicKey.export({ format: 'jwk' });
  }
  private key(org: string, as: string) { return JSON.stringify(['client', this.config.mode, this.config.organisationId, this.config.softwareId, org, as]); }
  private async desired(selection: Selection) {
    const { token, payload } = await this.directory.ssa();
    const c = this.config; const m = selection.metadata;
    const publishedKeys = await this.directory.keys(c.jwksUri, true);
    const local = this.crypto.jwks.keys[0]!;
    ensure(publishedKeys.keys.some(k => k.kid === this.crypto.kid && k.use === 'sig' && k.alg === 'PS256' && k.n === local.n && k.e === local.e), 'SIGNING_KEY_NOT_PUBLISHED');
    const enc = this.crypto.jwks.keys[1]!;
    ensure(publishedKeys.keys.some(k => k.kid === enc.kid && k.use === 'enc' && k.alg === 'RSA-OAEP' && k.n === enc.n && k.e === enc.e), 'ENCRYPTION_KEY_NOT_PUBLISHED');
    ensure(typeof payload.software_jwks_transport_uri === 'string', 'TRANSPORT_KEY_LOCATION_MISSING');
    const transportKeys = await this.directory.keys(payload.software_jwks_transport_uri, true);
    ensure(transportKeys.keys.some(k => k.n === this.transportPublic.n && k.e === this.transportPublic.e), 'TRANSPORT_KEY_NOT_PUBLISHED');
    ensure(!m.scopes_supported || c.scopes.every(s => m.scopes_supported!.includes(s)), 'SCOPE_NOT_SUPPORTED');
    ensure(!m.grant_types_supported || c.grantTypes.every(s => m.grant_types_supported!.includes(s)), 'GRANT_NOT_SUPPORTED');
    ensure(!m.response_types_supported || c.responseTypes.every(s => m.response_types_supported!.includes(s)), 'RESPONSE_TYPE_NOT_SUPPORTED');
    ensure(!m.request_object_signing_alg_values_supported || m.request_object_signing_alg_values_supported.includes('PS256'), 'REQUEST_ALGORITHM_NOT_SUPPORTED');
    const metadata = {
      application_type: 'web', // The confidential OAuth client is the backend, not the Android app.
      software_id: c.softwareId, software_statement: token,
      redirect_uris: c.redirectUris, jwks_uri: c.jwksUri,
      grant_types: c.grantTypes, response_types: c.responseTypes, scope: c.scopes.join(' '),
      subject_type: 'public', token_endpoint_auth_method: 'private_key_jwt',
      token_endpoint_auth_signing_alg: 'PS256', request_object_signing_alg: 'PS256',
      id_token_signed_response_alg: 'PS256', id_token_encrypted_response_alg: 'RSA-OAEP',
      id_token_encrypted_response_enc: 'A256GCM', require_signed_request_object: true,
      require_pushed_authorization_requests: Boolean(m.pushed_authorization_request_endpoint),
      tls_client_certificate_bound_access_tokens: true
    };
    const { software_statement: _ssa, ...stable } = metadata;
    const { iat: _iat, exp: _exp, jti: _jti, ...statementMetadata } = payload;
    const fingerprint = hash({ stable, statementMetadata,
      signingKid: this.crypto.kid, transportThumbprint: this.thumbprint });
    return { metadata, fingerprint };
  }
  private parseResponse(text: string, selection: Selection, fingerprint: string, old?: Registration): Registration {
    let raw: z.infer<typeof registrationSchema>;
    try { raw = registrationSchema.parse(JSON.parse(text)); } catch { throw new AppError('INVALID_REGISTRATION_RESPONSE', 502); }
    ensure(!old || raw.client_id === old.clientId, 'CLIENT_ID_CHANGED', 502);
    const uri = this.directory.http.checkUrl(raw.registration_client_uri);
    const registrationEndpoint = this.directory.http.checkUrl(mtlsEndpoint(selection.metadata, 'registration_endpoint'));
    ensure(uri.origin === registrationEndpoint.origin, 'DCM_ORIGIN_MISMATCH', 502);
    ensure(raw.token_endpoint_auth_method === 'private_key_jwt' && raw.jwks_uri === this.config.jwksUri && raw.tls_client_certificate_bound_access_tokens === true, 'REGISTRATION_SECURITY_DOWNGRADE', 502);
    ensure(raw.token_endpoint_auth_signing_alg === 'PS256' && raw.request_object_signing_alg === 'PS256', 'REGISTRATION_ALGORITHM_DOWNGRADE', 502);
    const redirects = z.array(z.string()).parse(raw.redirect_uris);
    ensure(this.config.redirectUris.every(v => redirects.includes(v)), 'REGISTRATION_REDIRECT_MISMATCH', 502);
    const scope = z.string().parse(raw.scope);
    ensure(this.config.scopes.every(s => scope.split(' ').includes(s)), 'REGISTRATION_SCOPE_MISMATCH', 502);
    const accessToken = raw.registration_access_token ?? old?.accessToken;
    ensure(accessToken, 'MISSING_REGISTRATION_TOKEN', 502);
    // All unexpected returned metadata stays encrypted too (including provider extensions).
    const metadata = Object.fromEntries(Object.entries(raw).filter(([k]) => !OMIT.has(k)));
    return { clientId: raw.client_id, managementUri: uri.href, accessToken, metadata, fingerprint,
      issuer: selection.metadata.issuer, transportThumbprint: this.thumbprint, signingKid: this.crypto.kid };
  }
  private async current(store: DataStore, key: string) {
    const saved = await store.get<Saved>(key);
    ensure(!saved || saved.status === 'active', 'REGISTRATION_RECONCILIATION_REQUIRED', 409);
    return saved?.encrypted ? this.vault.open<Registration>(saved.encrypted, key) : undefined;
  }
  private async save(store: DataStore, key: string, value: Registration) {
    await store.put(key, { status: 'active', encrypted: this.vault.seal(value, key) });
  }
  private summary(value: Registration) {
    return { clientId: value.clientId, managementUri: value.managementUri, issuer: value.issuer,
      signingKid: value.signingKid, transportThumbprint: value.transportThumbprint };
  }
  async inspect(org: string, as: string) {
    const r = await this.current(this.store, this.key(org, as));
    return r ? this.summary(r) : undefined;
  }
  async register(org: string, as: string) {
    const key = this.key(org, as);
    return this.store.locked(key, async store => {
      const selection = await this.directory.select(org, as);
      const desired = await this.desired(selection);
      const old = await this.current(store, key);
      if (old) {
        ensure(old.issuer === selection.metadata.issuer, 'AS_ISSUER_CHANGED', 409);
        if (old.fingerprint === desired.fingerprint) return { ...this.summary(old), created: false };
        const updated = await this.manageLocked('PUT', key, store, selection, old, desired);
        ensure('clientId' in updated, 'INVALID_UPDATE_RESULT', 500);
        return { ...updated, created: false };
      }
      await store.put(key, { status: 'pending' });
      try {
        const response = await this.directory.http.send(mtlsEndpoint(selection.metadata, 'registration_endpoint'), {
          method: 'POST', operation: 'dcr.register', headers: { 'content-type': 'application/json' }, body: JSON.stringify(desired.metadata)
        });
        ensure(response.status === 201, 'INVALID_DCR_STATUS', 502);
        ensure(String(response.headers['content-type']).includes('application/json'), 'INVALID_DCR_CONTENT_TYPE', 502);
        const value = this.parseResponse(response.text, selection, desired.fingerprint);
        await this.save(store, key, value);
        return { ...this.summary(value), created: true };
      } catch (e) {
        // A definite rejection is retryable after correction; ambiguous outcomes must be reconciled.
        if (e instanceof AppError && /^UPSTREAM_HTTP_4\d\d$/.test(e.code)) await store.remove(key);
        else await store.put(key, { status: 'uncertain' });
        throw e;
      }
    });
  }
  private async manageLocked(method: 'GET' | 'PUT' | 'DELETE', key: string, store: DataStore,
    selection: Selection, old: Registration, desired?: Awaited<ReturnType<DcrService['desired']>>) {
    ensure(old.issuer === selection.metadata.issuer, 'AS_ISSUER_CHANGED', 409);
    const headers: Record<string, string> = { authorization: `Bearer ${old.accessToken}` };
    const body = method === 'PUT' ? JSON.stringify({ ...old.metadata, ...desired!.metadata, client_id: old.clientId }) : undefined;
    if (body) headers['content-type'] = 'application/json';
    // Mark uncertain before sending: management tokens can rotate even on GET.
    await store.put(key, { status: 'uncertain', encrypted: this.vault.seal(old, key) });
    try {
      const response = await this.directory.http.send(old.managementUri, { method, operation: `dcm.${method.toLowerCase()}`, headers, body });
      if (method === 'DELETE') {
        ensure(response.status === 204, 'INVALID_DCM_DELETE_STATUS', 502);
        await store.remove(key); return { deleted: true };
      }
      ensure(response.status === 200, 'INVALID_DCM_STATUS', 502);
      ensure(String(response.headers['content-type']).includes('application/json'), 'INVALID_DCM_CONTENT_TYPE', 502);
      const value = this.parseResponse(response.text, selection, desired?.fingerprint ?? old.fingerprint, old);
      await this.save(store, key, value);
      if (value.accessToken !== old.accessToken) await store.audit({ operation: 'dcm.provider_deviation', outcome: 'REGISTRATION_TOKEN_ROTATION_DCR_BR_2_1', interactionId: randomUUID(), elapsedMs: 0 });
      return this.summary(value);
    } catch (e) {
      if (e instanceof AppError && /^UPSTREAM_HTTP_4\d\d$/.test(e.code) && e.code !== 'UPSTREAM_HTTP_401' && e.code !== 'UPSTREAM_HTTP_403') await this.save(store, key, old);
      throw e;
    }
  }
  async manage(org: string, as: string, method: 'GET' | 'PUT' | 'DELETE') {
    const key = this.key(org, as);
    return this.store.locked(key, async store => {
      const old = await this.current(store, key); ensure(old, 'CLIENT_NOT_REGISTERED', 404);
      const selection = await this.directory.select(org, as, true);
      const desired = method === 'PUT' ? await this.desired(selection) : undefined;
      return this.manageLocked(method, key, store, selection, old, desired);
    });
  }
  /** Explicit operator recovery after an ambiguous result. Never issues another registration POST. */
  async reconcile(org: string, as: string, recoveredResponse: string) {
    const key = this.key(org, as);
    return this.store.locked(key, async store => {
      const saved = await store.get<Saved>(key);
      ensure(saved?.status === 'pending' || saved?.status === 'uncertain', 'RECONCILIATION_NOT_REQUIRED', 409);
      const selection = await this.directory.select(org, as, true);
      const desired = await this.desired(selection);
      const recovered = this.parseResponse(recoveredResponse, selection, desired.fingerprint);
      // Prove the provider recognises the recovered token/record before making it active locally.
      return this.manageLocked('GET', key, store, selection, recovered);
    });
  }
  /** Acceptance probe only. Full OAuth session orchestration belongs to M04. Never returns a token to the console. */
  async tokenProbe(org: string, as: string) {
    const key = this.key(org, as);
    const old = await this.current(this.store, key); ensure(old, 'CLIENT_NOT_REGISTERED', 404);
    ensure(old.transportThumbprint === this.thumbprint && old.signingKid === this.crypto.kid, 'CREDENTIAL_ROTATION_REQUIRES_DCM', 409);
    const selection = await this.directory.select(org, as);
    ensure(old.issuer === selection.metadata.issuer, 'AS_ISSUER_CHANGED', 409);
    const endpoint = mtlsEndpoint(selection.metadata, 'token_endpoint');
    const assertion = await this.crypto.clientAssertion(old.clientId, selection.metadata.issuer);
    const probeScopes = this.config.scopes.filter(scope => scope !== 'openid');
    ensure(probeScopes.length > 0, 'TOKEN_PROBE_SCOPE_REQUIRED');
    const body = new URLSearchParams({ grant_type: 'client_credentials', client_id: old.clientId,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: assertion,
      scope: probeScopes.join(' ') }).toString();
    const result = await this.directory.http.send(endpoint, { method: 'POST', operation: 'oauth.token_probe', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body });
    ensure(String(result.headers['content-type']).includes('application/json'), 'INVALID_TOKEN_CONTENT_TYPE', 502);
    let value;
    try { value = z.object({ access_token: z.string().min(1), token_type: z.literal('Bearer'), expires_in: z.number().int().positive(), scope: z.string() }).parse(JSON.parse(result.text)); }
    catch { throw new AppError('INVALID_TOKEN_RESPONSE', 502); }
    ensure(probeScopes.every(s => value.scope.split(' ').includes(s)), 'TOKEN_SCOPE_MISMATCH', 502);
    ensure(value.expires_in >= 300 && value.expires_in <= 900, 'TOKEN_LIFETIME_OUTSIDE_FAPI_PROFILE', 502);
    return { authenticated: true, tokenType: value.token_type, expiresIn: value.expires_in, scope: value.scope };
  }
}
