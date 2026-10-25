import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import YAML from 'yaml';
import { Ajv } from 'ajv';
import { scenario, cleanupFixtures } from './helpers.js';
import { after } from 'node:test';
after(cleanupFixtures);
test('Pinned official contract snapshots retain their recorded checksums', async () => {
  const manifest = JSON.parse(await readFile('contracts/sources.json', 'utf8'));
  for (const source of manifest.sources) {
    const data = await readFile(`contracts/vendor/${source.file}`);
    assert.equal(createHash('sha256').update(data).digest('hex'), source.sha256, source.file);
  }
});
test('Local DCR response satisfies official 2.0.1 required fields; missing management token fails', async () => {
  const document = YAML.parse(await readFile('contracts/vendor/dcr-dcm-2.0.1.yaml', 'utf8'));
  assert.equal(document.info.version, '2.0.1');
  const ajv = new Ajv({ strict: false });
  ajv.addFormat('int32', { type: 'number', validate: (v: number) => Number.isInteger(v) && v >= -2147483648 && v <= 2147483647 });
  const validate = ajv.compile<Record<string, unknown>>(document.components.schemas.ClientRegistrationResponseSuccess);
  const s = await scenario();
  try {
    const desired = { application_type: 'web', software_statement: (await s.runtime.directory.ssa()).token,
      redirect_uris: s.config.redirectUris, jwks_uri: s.config.jwksUri,
      scope: s.config.scopes.join(' '), token_endpoint_auth_method: 'private_key_jwt', token_endpoint_auth_signing_alg: 'PS256',
      request_object_signing_alg: 'PS256', tls_client_certificate_bound_access_tokens: true };
    const response = await s.runtime.http.send(`${s.origin}/as/a/mtls/register`, { method: 'POST', operation: 'contract.dcr', headers: { 'content-type': 'application/json' }, body: JSON.stringify(desired) });
    const value = JSON.parse(response.text); assert.ok(validate(value), JSON.stringify(validate.errors));
    delete value.registration_access_token; assert.equal(validate(value), false);
    await assert.rejects(s.runtime.http.send(`${s.origin}/as/a/mtls/register`, { method: 'POST', operation: 'contract.duplicate', headers: { 'content-type': 'application/json' }, body: JSON.stringify(desired) }), /UPSTREAM_HTTP_400/);
    await assert.rejects(s.runtime.http.send(`${s.origin}/as/b/mtls/register`, { method: 'POST', operation: 'contract.invalid', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...desired, software_statement: 'invalid' }) }), /UPSTREAM_HTTP_400/);
  } finally { await s.close(); }
});
