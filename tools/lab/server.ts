import Fastify from 'fastify';
import { readFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { X509Certificate, randomUUID, createHash, constants } from 'node:crypto';
import { SignJWT, importPKCS8, importX509, exportJWK, calculateJwkThumbprint, jwtVerify, createLocalJWKSet } from 'jose';
import { z } from 'zod';
import { CryptoService, verifySsa } from '../../apps/backend/src/security/jose.js';
import { loadMaterial } from '../../apps/backend/src/security/certificates.js';
import { Vault } from '../../apps/backend/src/security/vault.js';
import { readSecret, type Config } from '../../apps/backend/src/config.js';
import { AppError, ensure } from '../../apps/backend/src/errors.js';
import type { DataStore } from '../../apps/backend/src/persistence/store.js';
import type { TLSSocket } from 'node:tls';

interface LabClient { metadata: Record<string, unknown>; token: string; transportHash: string }
export interface LabFaults { badIssuer?: boolean; ssaOrigins?: string[]; malformedDcr?: boolean; timeoutAfterDcr?: boolean; badTokenScope?: boolean; rotateManagementToken?: boolean }
export async function createLab(config: Config, store: DataStore, origin: string, faults: LabFaults = {}) {
  ensure(config.mode === 'local', 'LAB_FORBIDDEN_IN_SANDBOX');
  const dir = dirname(config.tls.caFile);
  const material = await loadMaterial(config);
  const verifier = await CryptoService.create(material, store);
  const vault = new Vault(Buffer.from(await readSecret(config.vaultKeyFile), 'base64url'));
  const app = Fastify({ https: { key: await readSecret(`${dir}/server.key`), cert: await readFile(`${dir}/server.pem`),
    ca: material.ca, crl: material.crl, requestCert: true, rejectUnauthorized: true, minVersion: 'TLSv1.2',
    secureOptions: constants.SSL_OP_NO_RENEGOTIATION | constants.SSL_OP_NO_TICKET }, logger: false, bodyLimit: 32_768 });
  const dirKey = await importPKCS8(await readSecret(`${dir}/directory-signing.key`), 'PS256');
  const dirPublic = await exportJWK(await importX509(new X509Certificate(await readFile(`${dir}/directory-signing.pem`, 'utf8')).toString(), 'PS256'));
  dirPublic.kid = await calculateJwkThumbprint(dirPublic); dirPublic.use = 'sig'; dirPublic.alg = 'PS256';
  const directoryJwks = { keys: [dirPublic] };
  const bankKey = await importPKCS8(await readSecret(`${dir}/bank-signing.key`), 'PS256');
  const bankPublic = await exportJWK(await importX509(new X509Certificate(await readFile(`${dir}/bank-signing.pem`, 'utf8')).toString(), 'PS256'));
  bankPublic.kid = await calculateJwkThumbprint(bankPublic); bankPublic.use = 'sig'; bankPublic.alg = 'PS256';
  const bankJwks = { keys: [bankPublic] };
  const now = () => Math.floor(Date.now() / 1000);
  const key = (as: string, id: string) => `lab:${as}:${id}`;
  const clientSchema = z.object({ software_statement: z.string(), redirect_uris: z.array(z.url()).min(1),
    jwks_uri: z.url(), scope: z.string(),
    token_endpoint_auth_method: z.literal('private_key_jwt'), token_endpoint_auth_signing_alg: z.literal('PS256'),
    request_object_signing_alg: z.literal('PS256'), tls_client_certificate_bound_access_tokens: z.literal(true)
  }).passthrough();
  app.addContentTypeParser('application/x-www-form-urlencoded', { parseAs: 'string' }, (_, body, done) => done(null, body));
  app.setErrorHandler((e, _, reply) => {
    const status = e instanceof AppError ? e.status : 400;
    reply.code(status).send({ error: e instanceof AppError && e.code === 'INVALID_SOFTWARE_STATEMENT' ? 'invalid_software_statement' : status === 401 ? 'invalid_client' : 'invalid_client_metadata' });
  });
  app.addHook('onRequest', async (req, reply) => {
    const socket = req.raw.socket as TLSSocket;
    ensure(socket.authorized, 'MTLS_REQUIRED', 401);
    reply.header('x-fapi-interaction-id', req.headers['x-fapi-interaction-id'] ?? randomUUID());
  });
  const peer = (socket: TLSSocket) => {
    const cert = new X509Certificate(socket.getPeerCertificate().raw);
    ensure(cert.subject.split('\n').includes('UID=wallet-lab') && cert.subject.includes('OFBBR-local-itp'), 'CLIENT_CERTIFICATE_IDENTITY', 401);
    return createHash('sha256').update(cert.raw).digest('base64url');
  };
  const currentItpKeys = async () => (await CryptoService.create(await loadMaterial(config), store)).jwks;
  const validateMetadata = async (body: unknown) => {
    const metadata = clientSchema.parse(body);
    let ssa;
    try { ssa = await verifySsa(metadata.software_statement, directoryJwks, config.directory.issuer); }
    catch { throw new AppError('INVALID_SOFTWARE_STATEMENT'); }
    ensure(ssa.org_id === config.organisationId && ssa.software_id === config.softwareId, 'INVALID_SSA_IDENTITY');
    ensure(metadata.jwks_uri === ssa.software_jwks_uri, 'INVALID_JWKS_URI');
    const redirects = z.array(z.string()).parse(ssa.software_redirect_uris);
    const origins = z.array(z.string()).parse(ssa.origin);
    ensure(metadata.redirect_uris.every(v => redirects.includes(v)), 'INVALID_REDIRECT_URI');
    ensure(config.androidOrigins.every(v => origins.includes(v)), 'INVALID_ORIGIN');
    return metadata;
  };
  const response = (as: string, id: string, client: LabClient) => ({ ...client.metadata, client_id: id,
    registration_client_uri: `${origin}/as/${as}/mtls/register/${id}`, registration_access_token: client.token });
  app.get('/participants', async () => ['a', 'b'].map(as => ({ OrganisationId: `bank-${as}`, OrganisationName: `Banco Laboratório ${as.toUpperCase()}`, Status: 'Active',
    AuthorisationServers: [{ AuthorisationServerId: `as-${as}`, OrganisationId: `bank-${as}`, CustomerFriendlyName: `Marca ${as.toUpperCase()}`,
      OpenIDDiscoveryDocument: `${origin}/as/${as}/.well-known/openid-configuration`, Issuer: `${origin}/as/${as}`,
      PayloadSigningCertLocationUri: `${origin}/as/${as}/jwks`, SupportsDCR: true,
      ApiResources: ['enrollments', 'payments'].map(family => ({ ApiFamilyType: family, ApiVersion: family === 'enrollments' ? '2.3.0' : '5.0.0',
        ApiDiscoveryEndpoints: [{ ApiEndpoint: `${origin}/resources/${as}/${family}` }] })) }]
  })));
  app.get('/directory/jwks', async () => directoryJwks);
  app.get('/itp/jwks', currentItpKeys);
  app.get('/itp/transport-jwks', async () => {
    const cert = new X509Certificate((await loadMaterial(config)).transportCert);
    return { keys: [{ ...cert.publicKey.export({ format: 'jwk' }), kid: cert.fingerprint256.replaceAll(':', '') }] };
  });
  app.get('/organisations/local-itp/softwarestatements/wallet-lab/assertion', async (_, reply) => {
    const token = await new SignJWT({ org_id: config.organisationId, software_id: config.softwareId,
      software_jwks_uri: config.jwksUri, software_redirect_uris: config.redirectUris,
      software_jwks_transport_uri: `${origin}/itp/transport-jwks`,
      origin: faults.ssaOrigins ?? config.androidOrigins, org_status: 'Active', software_statement_roles: [{ role: 'PAGTO', status: 'Active' }], software_version: '0.1.0' })
      .setProtectedHeader({ alg: 'PS256', typ: 'JWT', kid: dirPublic.kid })
      .setIssuer(config.directory.issuer).setIssuedAt().setExpirationTime('5m').sign(dirKey);
    return reply.type('application/jwt').send(token);
  });
  for (const as of ['a', 'b']) {
    const issuer = `${origin}/as/${as}`;
    app.get(`/as/${as}/.well-known/openid-configuration`, async () => ({ issuer: faults.badIssuer ? `${origin}/wrong` : issuer,
      authorization_endpoint: `${issuer}/authorize`, token_endpoint: `${issuer}/token`, registration_endpoint: `${issuer}/register`,
      pushed_authorization_request_endpoint: `${issuer}/par`, jwks_uri: `${issuer}/jwks`,
      mtls_endpoint_aliases: { token_endpoint: `${issuer}/mtls/token`, registration_endpoint: `${issuer}/mtls/register`, pushed_authorization_request_endpoint: `${issuer}/mtls/par` },
      token_endpoint_auth_methods_supported: ['private_key_jwt'], token_endpoint_auth_signing_alg_values_supported: ['PS256'],
      request_object_signing_alg_values_supported: ['PS256'], id_token_signing_alg_values_supported: ['PS256'],
      grant_types_supported: config.grantTypes, response_types_supported: config.responseTypes, scopes_supported: config.scopes }));
    app.get(`/as/${as}/jwks`, async () => bankJwks);
    // Non-mTLS aliases intentionally have no handlers. Ignoring discovery aliases fails the tests.
    app.post(`/as/${as}/mtls/register`, async (req, reply) => {
      const transportHash = peer(req.raw.socket as TLSSocket);
      const metadata = await validateMetadata(req.body);
      return store.locked(`lab-register:${as}`, async locked => {
        ensure(!await locked.get(`lab-current:${as}:${config.softwareId}`), 'DUPLICATE_SOFTWARE_REGISTRATION');
        const id = randomUUID(); const client = { metadata, token: randomUUID(), transportHash };
        await locked.put(key(as, id), vault.seal(client, key(as, id)));
        await locked.put(`lab-current:${as}:${config.softwareId}`, id);
        if (faults.timeoutAfterDcr) return reply.hijack();
        return reply.code(201).send(faults.malformedDcr ? { client_id: id } : response(as, id, client));
      });
    });
    for (const method of ['GET', 'PUT', 'DELETE'] as const) {
      app.route({ method, url: `/as/${as}/mtls/register/:id`, handler: async (req, reply) => {
        const { id } = req.params as { id: string };
        return store.locked(key(as, id), async locked => {
          const encrypted = await locked.get<string>(key(as, id)); ensure(encrypted, 'CLIENT_NOT_FOUND', 404);
          const client = vault.open<LabClient>(encrypted, key(as, id));
          ensure(req.headers.authorization === `Bearer ${client.token}`, 'INVALID_REGISTRATION_TOKEN', 401);
          const transportHash = peer(req.raw.socket as TLSSocket);
          if (method === 'DELETE') {
            await locked.remove(key(as, id)); await locked.remove(`lab-current:${as}:${config.softwareId}`);
            return reply.code(204).send();
          }
          if (method === 'PUT') { client.metadata = await validateMetadata(req.body); client.transportHash = transportHash; }
          // DCR-BR 2.1 prohibits rotation. The explicit fault exercises resilience to RFC7592 providers that rotate anyway.
          if (faults.rotateManagementToken) client.token = randomUUID();
          await locked.put(key(as, id), vault.seal(client, key(as, id)));
          return response(as, id, client);
        });
      } });
    }
    app.post(`/as/${as}/mtls/token`, async req => {
      const body = new URLSearchParams(req.body as string);
      ensure(body.get('grant_type') === 'client_credentials' && body.get('client_assertion_type') === 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', 'INVALID_GRANT');
      const id = body.get('client_id') ?? '';
      const encrypted = await store.get<string>(key(as, id)); ensure(encrypted, 'INVALID_CLIENT', 401);
      const client = vault.open<LabClient>(encrypted, key(as, id));
      const transportHash = peer(req.raw.socket as TLSSocket);
      ensure(transportHash === client.transportHash, 'CERTIFICATE_BINDING_MISMATCH', 401);
      await verifier.verify('assertion', body.get('client_assertion') ?? '', await currentItpKeys(), { issuer: id, audience: issuer });
      const scopes = (body.get('scope') ?? '').split(' ');
      ensure(scopes.every(s => String(client.metadata.scope).split(' ').includes(s)), 'INVALID_SCOPE', 401);
      const scope = faults.badTokenScope ? 'wrong' : scopes.join(' ');
      const accessToken = await new SignJWT({ scope, cnf: { 'x5t#S256': transportHash } }).setProtectedHeader({ alg: 'PS256', typ: 'at+jwt', kid: bankPublic.kid })
        .setIssuer(issuer).setAudience(`${origin}/lab/protected`).setSubject(id).setIssuedAt(now()).setExpirationTime('300s').setJti(randomUUID()).sign(bankKey);
      return { access_token: accessToken, token_type: 'Bearer', expires_in: 300, scope };
    });
  }
  app.get('/lab/protected', async req => {
    const token = req.headers.authorization?.replace(/^Bearer /, '') ?? '';
    const { payload } = await jwtVerify(token, createLocalJWKSet(bankJwks), { algorithms: ['PS256'], issuer: ['a', 'b'].map(as => `${origin}/as/${as}`), audience: `${origin}/lab/protected`, typ: 'at+jwt' });
    ensure((payload.cnf as Record<string, unknown>)?.['x5t#S256'] === peer(req.raw.socket as TLSSocket), 'TOKEN_BINDING_MISMATCH', 401);
    ensure(typeof payload.scope === 'string' && payload.scope.split(' ').includes('payments'), 'INSUFFICIENT_SCOPE', 403);
    return { authorised: true, simulated: true };
  });
  return app;
}
