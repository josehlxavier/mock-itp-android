import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { request, createServer } from 'node:https';
import { SignJWT, importPKCS8, decodeJwt } from 'jose';
import { randomUUID } from 'node:crypto';
import { scenario, cleanupFixtures } from './helpers.js';
import { validateCertificate, loadMaterial } from '../src/security/certificates.js';
import { verifySsa } from '../src/security/jose.js';
import { Vault } from '../src/security/vault.js';
import { Transport, fapiHeaders } from '../src/transport.js';
import { DcrService } from '../src/dcr/service.js';
import { loadConfig } from '../src/config.js';

let s: Awaited<ReturnType<typeof scenario>>;
before(async () => { s = await scenario(); });
after(async () => { await s?.close(); await cleanupFixtures(); });
const now = () => Math.floor(Date.now() / 1000);
async function assertion(overrides: Record<string, unknown> = {}, header: Record<string, unknown> = {}) {
  const alg = String(header.alg ?? 'PS256');
  const key = await importPKCS8(s.runtime.material.signingKey, alg);
  return new SignJWT({ iss: 'client-test', sub: 'client-test', aud: 'as-test', iat: now(), exp: now() + 60, jti: randomUUID(), ...overrides })
    .setProtectedHeader({ alg, typ: 'JWT', kid: s.runtime.crypto.kid, ...header }).sign(key);
}
const verify = (token: string) => s.runtime.crypto.verify('assertion', token, s.runtime.crypto.jwks, { issuer: 'client-test', audience: 'as-test' });

test('M02: PS256 assertion accepted once, replay rejected', async () => {
  const token = await assertion(); assert.equal((await verify(token)).sub, 'client-test');
  await assert.rejects(verify(token), /JWT_REPLAY/);
});
for (const [name, overrides] of Object.entries({
  audience: { aud: 'other-as' }, issuer: { iss: 'other-client' }, subject: { sub: 'other-client' },
  expired: { iat: now() - 120, exp: now() - 60 }, future: { iat: now() + 60, exp: now() + 120 },
  lifetime: { exp: now() + 3600 }, 'missing-expiration': { exp: undefined }, 'empty-jti': { jti: '' }
})) test(`M02: rejects assertion with invalid ${name}`, async () => { await assert.rejects(verify(await assertion(overrides))); });
test('M02: rejects forbidden algorithm, unknown/duplicate kid and untrusted key URL', async () => {
  await assert.rejects(verify(await assertion({}, { alg: 'RS256' })), /INVALID_JOSE_HEADER/);
  await assert.rejects(verify(await assertion({}, { kid: 'unknown' })), /AMBIGUOUS_OR_UNKNOWN_KID/);
  await assert.rejects(verify(await assertion({}, { jku: 'https://attacker.invalid/jwks' })), /UNTRUSTED_KEY_REFERENCE/);
  await assert.rejects(s.runtime.crypto.verify('assertion', await assertion(), { keys: [s.runtime.crypto.jwks.keys[0]!, s.runtime.crypto.jwks.keys[0]!] }, { issuer: 'client-test', audience: 'as-test' }), /AMBIGUOUS_OR_UNKNOWN_KID/);
});
test('M02: tampering with payload invalidates signature', async () => {
  const token = await assertion(); const parts = token.split('.');
  parts[1] = Buffer.from(JSON.stringify({ ...decodeJwt(token), sub: 'forged' })).toString('base64url');
  await assert.rejects(verify(parts.join('.')), /JWT_VERIFICATION_FAILED/);
});
test('M02: request objects have their own JOSE header, PKCE, state and nonce validation', async () => {
  const params = { redirect_uri: s.config.redirectUris[0]!, scope: 'openid', response_type: 'code id_token',
    state: 'state-with-adequate-entropy', nonce: 'nonce-with-adequate-entropy', code_challenge: 'A'.repeat(43), code_challenge_method: 'S256' as const };
  const token = await s.runtime.crypto.requestObject('client-test', 'as-test', params);
  await assert.rejects(verify(token), /INVALID_JOSE_HEADER/);
  await assert.rejects(s.runtime.crypto.verify('request', token, s.runtime.crypto.jwks, { issuer: 'client-test', audience: 'as-test', state: 'wrong', nonce: params.nonce }), /STATE_OR_NONCE_MISMATCH/);
  await assert.rejects(s.runtime.crypto.verify('request', token, s.runtime.crypto.jwks, { issuer: 'client-test', audience: 'as-test', state: params.state, nonce: 'wrong' }), /STATE_OR_NONCE_MISMATCH/);
  assert.equal((await s.runtime.crypto.verify('request', token, s.runtime.crypto.jwks, { issuer: 'client-test', audience: 'as-test', state: params.state, nonce: params.nonce })).client_id, 'client-test');
});
test('M02: application/jwt resource messages use organisation issuer, resource audience and replay window', async () => {
  const token = await s.runtime.crypto.resourceMessage('local-itp', `${s.origin}/resource`, { amount: '1.00' });
  const context = { issuer: 'local-itp', audience: `${s.origin}/resource` };
  await assert.rejects(s.runtime.crypto.verify('assertion', token, s.runtime.crypto.jwks, context));
  assert.deepEqual((await s.runtime.crypto.verify('resource', token, s.runtime.crypto.jwks, context)).data, { amount: '1.00' });
  await assert.rejects(s.runtime.crypto.verify('resource', token, s.runtime.crypto.jwks, context), /JWT_REPLAY/);
});
test('M02: RSA-OAEP/A256GCM nested encryption round-trip and tamper rejection', async () => {
  const signed = await assertion(); const encrypted = await s.runtime.crypto.encrypt(signed, s.runtime.crypto.jwks);
  const nested = await s.runtime.crypto.decrypt(encrypted); assert.equal(nested, signed); await verify(nested);
  const parts = encrypted.split('.'); const cipher = Buffer.from(parts[3]!, 'base64url'); cipher[0] = cipher[0]! ^ 1; parts[3] = cipher.toString('base64url');
  await assert.rejects(s.runtime.crypto.decrypt(parts.join('.')), /JWE_DECRYPTION_FAILED/);
});
test('M01/M02: validates SSA using Directory keys; rejects stale assertions and different issuer', async () => {
  const data = await s.runtime.directory.ssa(); assert.equal(data.payload.software_id, s.config.softwareId);
  const keys = await s.runtime.directory.keys(s.config.directory.jwksUri);
  await assert.rejects(verifySsa(data.token, keys, 'wrong-directory'));
  const key = await importPKCS8(await readFile(`${s.dir}/directory-signing.key`, 'utf8'), 'PS256');
  const stale = await new SignJWT({ ...data.payload, iat: now() - 600 }).setProtectedHeader({ alg: 'PS256', kid: keys.keys[0]!.kid }).sign(key);
  await assert.rejects(verifySsa(stale, keys, s.config.directory.issuer));
});
test('M02: rejects expired, incompatible and mismatched certificates', async () => {
  const m = s.runtime.material;
  assert.throws(() => validateCertificate(m.transportCert, m.transportKey, Date.now() + 10 * 86400000), /CERTIFICATE_EXPIRED/);
  assert.throws(() => validateCertificate(m.transportCert, m.signingKey), /CERTIFICATE_KEY_MISMATCH/);
  await assert.rejects(loadMaterial({ ...s.config, signing: { ...s.config.tls } }), /SIGNING_CERTIFICATE_ORGANISATION_MISMATCH/);
  await assert.rejects(loadMaterial({ ...s.config, tls: { ...s.config.tls, caFile: `${s.dir}/signing.pem` } }), /CERTIFICATE_CHAIN_INVALID/);
});
test('M02: actual mTLS handshake rejects a client without certificate', async () => {
  await assert.rejects(new Promise((resolve, reject) => {
    const req = request(`${s.origin}/participants`, { ca: s.runtime.material.ca, rejectUnauthorized: true }, resolve);
    req.once('error', reject); req.end();
  }));
});
test('M02: actual TLS handshakes reject expired client and server certificates', async () => {
  const expiredClient = new Transport({ ...s.runtime.material, transportCert: await readFile(`${s.dir}/expired-transport.pem`, 'utf8'), transportKey: await readFile(`${s.dir}/expired-transport.key`, 'utf8') }, [s.origin], s.store);
  const server = createServer({ key: await readFile(`${s.dir}/expired-server.key`), cert: await readFile(`${s.dir}/expired-server.pem`) }, (_, reply) => reply.end('{}'));
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
  const origin = `https://localhost:${(server.address() as { port: number }).port}`;
  const client = new Transport(s.runtime.material, [origin], s.store);
  try {
    await assert.rejects(expiredClient.json(`${s.origin}/participants`, 'test.expired-client'), /TLS_OR_NETWORK_FAILURE/);
    await assert.rejects(client.json(origin, 'test.expired-server'), /TLS_OR_NETWORK_FAILURE/);
  } finally { expiredClient.close(); client.close(); await new Promise<void>(r => server.close(() => r())); }
});
test('M02: revoked client is rejected by import and by an actual mTLS handshake', async () => {
  await assert.rejects(loadMaterial({ ...s.config, tls: { ...s.config.tls, certFile: `${s.dir}/revoked-transport.pem`, keyFile: `${s.dir}/revoked-transport.key` } }), /CERTIFICATE_CHAIN_INVALID/);
  const revoked = new Transport({ ...s.runtime.material, transportCert: await readFile(`${s.dir}/revoked-transport.pem`, 'utf8'), transportKey: await readFile(`${s.dir}/revoked-transport.key`, 'utf8') }, [s.origin], s.store);
  try { await assert.rejects(revoked.json(`${s.origin}/participants`, 'test.revoked-client'), /TLS_OR_NETWORK_FAILURE/); }
  finally { revoked.close(); }
});
test('M02: resource replay is retained for 24 hours across endpoints, with UUID v4 jti', async () => {
  const key = await importPKCS8(s.runtime.material.signingKey, 'PS256');
  const id = randomUUID();
  const sign = (aud: string, iat: number, jti: string = id) => new SignJWT({ iss: 'resource-org', aud, iat, jti, data: {} })
    .setProtectedHeader({ alg: 'PS256', typ: 'JWT', kid: s.runtime.crypto.kid }).sign(key);
  const verify = (token: string, audience: string) => s.runtime.crypto.verify('resource', token, s.runtime.crypto.jwks, { issuer: 'resource-org', audience, clientId: 'registered-client' });
  await verify(await sign('endpoint-a', now() + 30), 'endpoint-a');
  await assert.rejects(verify(await sign('endpoint-b', now()), 'endpoint-b'), e => e instanceof Error && e.message === 'JWT_REPLAY' && (e as { status?: number }).status === 403);
  await assert.rejects(verify(await sign('endpoint-c', now(), 'not-uuid'), 'endpoint-c'), /INVALID_RESOURCE_CLAIMS/);
  const replayValues = [...(s.store as import('../src/persistence/store.js').MemoryStore).data.entries()].filter(([k]) => k.startsWith('replay:')).map(([, v]) => v as number);
  assert.ok(replayValues.some(v => v > Date.now() + 86300 * 1000));
});
test('M02: validates server hostname and rejects untrusted server chains', async () => {
  const server = createServer({ key: await readFile(`${s.dir}/wrong-host.key`), cert: await readFile(`${s.dir}/wrong-host.pem`) }, (_, res) => res.end('{}'));
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
  const origin = `https://localhost:${(server.address() as { port: number }).port}`;
  const http = new Transport(s.runtime.material, [origin], s.store);
  const untrusted = new Transport({ ...s.runtime.material, ca: await readFile(`${s.dir}/signing.pem`, 'utf8') }, [s.origin], s.store);
  try {
    await assert.rejects(http.json(origin, 'test.hostname'), /TLS_OR_NETWORK_FAILURE/);
    await assert.rejects(untrusted.json(`${s.origin}/participants`, 'test.chain'), /TLS_OR_NETWORK_FAILURE/);
  } finally { http.close(); untrusted.close(); await new Promise<void>(r => server.close(() => r())); }
});
test('M02: outbound credentials cannot be sent to an origin outside configuration', async () => {
  await assert.rejects(s.runtime.http.json('https://attacker.invalid', 'test.ssrf'), /ORIGIN_NOT_ALLOWED/);
});
test('M02: FAPI correlation/idempotency headers reject invalid values', () => {
  const h = fapiHeaders({ idempotencyKey: 'same-operation' }); assert.equal(h['x-idempotency-key'], 'same-operation');
  assert.throws(() => fapiHeaders({ interactionId: 'bad' }), /INVALID_INTERACTION_ID/);
  assert.throws(() => fapiHeaders({ idempotencyKey: 'a\r\nb' }), /INVALID_IDEMPOTENCY/);
  assert.throws(() => fapiHeaders({ customerIp: 'not-ip' }), /INVALID_CUSTOMER_IP/);
  assert.throws(() => fapiHeaders({ authDate: 'Invalid Date' }), /INVALID_AUTH_DATE/);
  assert.throws(() => fapiHeaders({ idempotencyKey: '' }), /INVALID_IDEMPOTENCY_KEY/);
});
test('M03: encryption at rest rejects modified ciphertext and moving secrets across AS records', () => {
  const vault = new Vault(Buffer.alloc(32, 1)); const encrypted = vault.seal({ token: 'sensitive' }, 'as-a');
  assert.doesNotMatch(encrypted, /sensitive/);
  assert.throws(() => vault.open(encrypted, 'as-b'));
  const parts = encrypted.split('.'); parts[2] = Buffer.alloc(16).toString('base64url');
  assert.throws(() => vault.open(parts.join('.'), 'as-a'));
});
test('M01: rejects metadata issuer mismatch instead of accepting discovered URLs', async () => {
  const other = await scenario({ badIssuer: true });
  try { await assert.rejects(other.runtime.directory.select('bank-a', 'as-a'), /OIDC_ISSUER_MISMATCH/); }
  finally { await other.close(); }
});
test('M03: Android origins missing from SSA prevent registration before POST', async () => {
  const other = await scenario({ ssaOrigins: [] });
  try { await assert.rejects(other.runtime.dcr.register('bank-a', 'as-a'), /SSA_ANDROID_ORIGIN_MISMATCH/); }
  finally { await other.close(); }
});
test('M03: malformed successful DCR response blocks automatic duplicate registration', async () => {
  const other = await scenario({ malformedDcr: true });
  try {
    await assert.rejects(other.runtime.dcr.register('bank-a', 'as-a'), /INVALID_REGISTRATION_RESPONSE/);
    await assert.rejects(other.runtime.dcr.register('bank-a', 'as-a'), /REGISTRATION_RECONCILIATION_REQUIRED/);
    // Simulates the operator securely recovering the provider's current record, not another POST.
    const id = await other.store.get<string>('lab-current:a:wallet-lab'); assert.ok(id);
    const key = `lab:a:${id}`;
    const vault = new Vault(Buffer.from((await readFile(other.config.vaultKeyFile, 'utf8')).trim(), 'base64url'));
    const client = vault.open<{ metadata: object; token: string }>((await other.store.get<string>(key))!, key);
    const recovered = JSON.stringify({ ...client.metadata, client_id: id, registration_client_uri: `${other.origin}/as/a/mtls/register/${id}`, registration_access_token: client.token });
    const reconciled = await other.runtime.dcr.reconcile('bank-a', 'as-a', recovered);
    assert.ok('clientId' in reconciled); assert.equal(reconciled.clientId, id);
    assert.equal((await other.runtime.dcr.register('bank-a', 'as-a')).created, false);
    assert.equal((await other.runtime.dcr.tokenProbe('bank-a', 'as-a')).authenticated, true);
  } finally { await other.close(); }
});
test('M02: signed resource messages verify only with keys and organisation associated by Directory', async () => {
  const selected = await s.runtime.directory.select('bank-a', 'as-a');
  const keys = await s.runtime.directory.keys(selected.resourceJwksUri!);
  const key = await importPKCS8(await readFile(`${s.dir}/bank-signing.key`, 'utf8'), 'PS256');
  const token = await new SignJWT({ iss: 'bank-a', aud: s.config.organisationId, iat: now(), jti: randomUUID(), data: { status: 'ok' } })
    .setProtectedHeader({ alg: 'PS256', typ: 'JWT', kid: keys.keys[0]!.kid }).sign(key);
  await assert.rejects(s.runtime.directory.verifyResource(s.runtime.crypto, { ...selected, organisation: 'bank-b' }, token));
  assert.deepEqual((await s.runtime.directory.verifyResource(s.runtime.crypto, selected, token)).data, { status: 'ok' });
});
test('M01: expired OIDC cache fails closed when provider returns inconsistent metadata', async () => {
  const faults = { badIssuer: false }; const other = await scenario(faults);
  try {
    other.config.directory.cacheSeconds = 1;
    await other.runtime.directory.select('bank-a', 'as-a');
    faults.badIssuer = true;
    await new Promise(r => setTimeout(r, 1100));
    await assert.rejects(other.runtime.directory.select('bank-a', 'as-a'), /OIDC_ISSUER_MISMATCH/);
  } finally { await other.close(); }
});
test('M03: timeout after server creates client does not cause another POST', async () => {
  const other = await scenario({ timeoutAfterDcr: true });
  const http = new Transport(other.runtime.material, [other.origin], other.store, 100);
  const Directory = (await import('../src/directory/service.js')).DirectoryService;
  const directory = new Directory(other.config, http, other.store);
  const vault = new Vault(Buffer.from((await readFile(other.config.vaultKeyFile, 'utf8')).trim(), 'base64url'));
  const dcr = new DcrService(other.config, directory, other.runtime.crypto, other.store, vault, other.runtime.material);
  try {
    await assert.rejects(dcr.register('bank-a', 'as-a'), /UPSTREAM_TIMEOUT/);
    await assert.rejects(dcr.register('bank-a', 'as-a'), /REGISTRATION_RECONCILIATION_REQUIRED/);
  } finally { http.close(); await other.close(); }
});
test('M03: token with a different scope fails the acceptance probe', async () => {
  const other = await scenario({ badTokenScope: true });
  try { await other.runtime.dcr.register('bank-a', 'as-a'); await assert.rejects(other.runtime.dcr.tokenProbe('bank-a', 'as-a'), /TOKEN_SCOPE_MISMATCH/); }
  finally { await other.close(); }
});
test('Sandbox configuration cannot silently use localhost laboratory endpoints', async () => {
  const path = `${s.dir}/invalid-sandbox.json`;
  await writeFile(path, JSON.stringify({ ...s.config, mode: 'sandbox' }), { mode: 0o600 });
  await assert.rejects(loadConfig(path), /SANDBOX_LOOPBACK_FORBIDDEN/);
});
