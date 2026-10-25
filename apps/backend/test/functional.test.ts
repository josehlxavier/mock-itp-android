import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { scenario, cleanupFixtures } from './helpers.js';
import { createApp } from '../src/app.js';
import { createRuntime } from '../src/runtime.js';
import { MemoryStore } from '../src/persistence/store.js';
import { mtlsEndpoint } from '../src/directory/service.js';
import { Transport } from '../src/transport.js';

after(cleanupFixtures);
test('M01: discovers organisations, brands, resources and OIDC mTLS aliases; cache refresh is explicit', async () => {
  const s = await scenario();
  try {
    const participants = await s.runtime.directory.participants();
    assert.equal(participants.length, 2);
    const selection = await s.runtime.directory.select('bank-b', 'as-b');
    assert.equal(selection.brand, 'Marca B');
    assert.deepEqual(selection.resources.map(a => [a.ApiFamilyType, a.ApiVersion]), [['enrollments', '2.3.0'], ['payments', '5.0.0']]);
    assert.equal(mtlsEndpoint(selection.metadata, 'registration_endpoint'), `${s.origin}/as/b/mtls/register`);
    assert.equal(mtlsEndpoint(selection.metadata, 'token_endpoint'), `${s.origin}/as/b/mtls/token`);
    assert.equal(mtlsEndpoint(selection.metadata, 'pushed_authorization_request_endpoint'), `${s.origin}/as/b/mtls/par`);
    const events = (s.store as MemoryStore).events;
    const count = events.length;
    await s.runtime.directory.select('bank-b', 'as-b'); assert.equal(events.length, count);
    await s.runtime.directory.select('bank-b', 'as-b', true); assert.equal(events.length, count + 2);
  } finally { await s.close(); }
});
test('M03: concurrent registration, token authentication, DCM token rotation, update, delete and re-register', async () => {
  const s = await scenario({ rotateManagementToken: true });
  try {
    const results = await Promise.all(Array.from({ length: 4 }, () => s.runtime.dcr.register('bank-a', 'as-a')));
    assert.equal(results.filter(r => r.created).length, 1);
    assert.equal(new Set(results.map(r => r.clientId)).size, 1);
    assert.equal((await s.runtime.dcr.tokenProbe('bank-a', 'as-a')).authenticated, true);
    await s.runtime.dcr.manage('bank-a', 'as-a', 'GET');
    await s.runtime.dcr.manage('bank-a', 'as-a', 'GET');
    await s.runtime.dcr.manage('bank-a', 'as-a', 'PUT');
    assert.equal((await s.runtime.dcr.tokenProbe('bank-a', 'as-a')).authenticated, true);
    const second = await s.runtime.dcr.register('bank-b', 'as-b');
    assert.notEqual(second.clientId, results[0]!.clientId);
    await s.runtime.dcr.manage('bank-a', 'as-a', 'DELETE');
    assert.equal(await s.runtime.dcr.inspect('bank-a', 'as-a'), undefined);
    await assert.rejects(s.runtime.dcr.tokenProbe('bank-a', 'as-a'), /CLIENT_NOT_REGISTERED/);
    assert.notEqual((await s.runtime.dcr.register('bank-a', 'as-a')).clientId, results[0]!.clientId);
  } finally { await s.close(); }
});
test('M03: existing client survives runtime restart; signing/transport/origin rotation uses PUT', async () => {
  const s = await scenario(); let restarted: Awaited<ReturnType<typeof createRuntime>> | undefined;
  try {
    const original = await s.runtime.dcr.register('bank-a', 'as-a');
    s.config.signing = { certFile: `${s.dir}/signing-next.pem`, keyFile: `${s.dir}/signing-next.key` };
    s.config.tls = { ...s.config.tls, certFile: `${s.dir}/transport-next.pem`, keyFile: `${s.dir}/transport-next.key` };
    s.config.androidOrigins = ['android:apk-key-hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'];
    restarted = await createRuntime(s.config, s.store);
    await assert.rejects(restarted.dcr.tokenProbe('bank-a', 'as-a'), /CREDENTIAL_ROTATION_REQUIRES_DCM/);
    const maintained = await restarted.dcr.register('bank-a', 'as-a');
    assert.equal(maintained.created, false); assert.equal(maintained.clientId, original.clientId);
    assert.notEqual(maintained.signingKid, original.signingKid);
    assert.equal((await restarted.dcr.tokenProbe('bank-a', 'as-a')).authenticated, true);
    assert.equal((await restarted.dcr.manage('bank-a', 'as-a', 'GET') as { clientId: string }).clientId, original.clientId);
  } finally { restarted?.close(); await s.close(); }
});
test('M01–M03: protected HTTP administration exposes public JWKS and sanitised results only', async () => {
  const s = await scenario(); const app = await createApp(s.runtime, false);
  try {
    assert.equal((await app.inject('/health')).json().simulated, true);
    assert.equal((await app.inject('/admin/institutions')).statusCode, 401);
    const auth = { authorization: `Bearer ${(await readFile(s.config.adminTokenFile, 'utf8')).trim()}` };
    const publicKeys = (await app.inject('/.well-known/jwks.json')).json();
    assert.equal(publicKeys.keys.length, 2); assert.equal(publicKeys.keys.some((k: object) => 'd' in k || 'p' in k), false);
    const base = '/admin/institutions/bank-a/servers/as-a';
    const response = await app.inject({ method: 'POST', url: `${base}/registration`, headers: auth });
    assert.equal(response.statusCode, 201);
    assert.equal((await app.inject({ method: 'POST', url: `${base}/token-probe`, headers: auth })).json().authenticated, true);
    assert.equal((await app.inject({ method: 'GET', url: `${base}/registration`, headers: auth })).statusCode, 200);
    assert.doesNotMatch(response.body, /registration_access_token|software_statement|PRIVATE KEY|access_token/);
    const saved = JSON.stringify([...(s.store as MemoryStore).data.entries()]);
    assert.doesNotMatch(saved, /registration_access_token|PRIVATE KEY|software_statement/);
  } finally { await app.close(); await s.close(); }
});
test('M03: issued access token works on lab resource and fails with another transport certificate', async () => {
  const s = await scenario();
  const other = new Transport({ ...s.runtime.material, transportCert: await readFile(`${s.dir}/transport-next.pem`, 'utf8'), transportKey: await readFile(`${s.dir}/transport-next.key`, 'utf8') }, [s.origin], s.store);
  try {
    const registration = await s.runtime.dcr.register('bank-a', 'as-a');
    const assertion = await s.runtime.crypto.clientAssertion(registration.clientId, `${s.origin}/as/a`);
    const body = new URLSearchParams({ client_id: registration.clientId, grant_type: 'client_credentials',
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: assertion, scope: 'payments' }).toString();
    const response = await s.runtime.http.send(`${s.origin}/as/a/mtls/token`, { method: 'POST', operation: 'test.token', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body });
    const token = JSON.parse(response.text).access_token;
    assert.deepEqual(await s.runtime.http.json(`${s.origin}/lab/protected`, 'test.protected', { authorization: `Bearer ${token}` }), { authorised: true, simulated: true });
    await assert.rejects(other.json(`${s.origin}/lab/protected`, 'test.wrong-binding', { authorization: `Bearer ${token}` }), /UPSTREAM_HTTP_401/);
    await assert.rejects(s.runtime.http.send(`${s.origin}/as/a/mtls/token`, { method: 'POST', operation: 'test.replayed-assertion', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body }));
  } finally { other.close(); await s.close(); }
});
