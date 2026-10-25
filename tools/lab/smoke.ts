import assert from 'node:assert/strict';
import { readSecret } from '../../apps/backend/src/config.js';

const origin = process.env.BACKEND_URL ?? 'http://127.0.0.1:3000';
const headers = { authorization: `Bearer ${await readSecret('.local/admin.token')}` };
async function call(path: string, method = 'GET') {
  const r = await fetch(`${origin}${path}`, { method, headers });
  const body = await r.json();
  assert.ok(r.ok, `HTTP ${r.status} (${body.error ?? 'unexpected'})`); return body;
}
assert.equal((await call('/health')).mode, 'local');
assert.equal((await call('/admin/institutions')).length, 2);
const path = '/admin/institutions/bank-a/servers/as-a';
const discovery = await call(`${path}/discovery/refresh`, 'POST');
assert.ok(discovery.metadata.mtls_endpoint_aliases.registration_endpoint);
const first = await call(`${path}/registration`, 'POST');
assert.equal((await call(`${path}/registration`, 'POST')).clientId, first.clientId);
assert.equal((await call(`${path}/token-probe`, 'POST')).authenticated, true);
assert.equal((await call(`${path}/registration`)).clientId, first.clientId);
assert.equal((await call(`${path}/registration`, 'PUT')).clientId, first.clientId);
assert.equal((await call(`${path}/token-probe`, 'POST')).authenticated, true);
await call(`${path}/registration`, 'DELETE');
console.log('PASS: Directory → discovery → DCR → repeated registration → token → DCM GET/PUT → token → DELETE (local simulation).');
