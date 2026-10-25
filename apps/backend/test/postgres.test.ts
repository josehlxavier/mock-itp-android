import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { readSecret } from '../src/config.js';
import { PostgresStore } from '../src/persistence/store.js';
import { createRuntime } from '../src/runtime.js';
import { scenario, cleanupFixtures } from './helpers.js';
import { randomUUID } from 'node:crypto';
import pg from 'pg';

after(cleanupFixtures);
async function isolatedDatabase() {
  const original = process.env.TEST_DATABASE_URL ?? await readSecret('.local/database.url');
  const client = new pg.Client({ connectionString: original }); await client.connect();
  const schema = `test_${randomUUID().replaceAll('-', '')}`;
  await client.query(`CREATE SCHEMA ${schema}`);
  const url = new URL(original); url.searchParams.set('options', `-csearch_path=${schema}`);
  return { url: url.href, close: async () => { await client.query(`DROP SCHEMA ${schema} CASCADE`); await client.end(); } };
}
test('PostgreSQL: atomic replay and per-AS locks across independent connections', async () => {
  const db = await isolatedDatabase(); const url = db.url;
  const a = await PostgresStore.connect(url), b = await PostgresStore.connect(url);
  const key = `test:${randomUUID()}`;
  try {
    const claims = await Promise.all([a.claim(key, Date.now() + 60_000), b.claim(key, Date.now() + 60_000)]);
    assert.equal(claims.filter(Boolean).length, 1);
    await a.put(key, 0);
    await Promise.all(Array.from({ length: 6 }, (_, i) => (i % 2 ? a : b).locked(key, async locked => {
      const value = await locked.get<number>(key); await locked.put(key, value! + 1);
    })));
    assert.equal(await b.get(key), 6);
    await a.remove(key);
  } finally { await a.close(); await b.close(); await db.close(); }
});
test('PostgreSQL: encrypted DCR state survives connection/runtime restart and DCM token rotation', async () => {
  const db = await isolatedDatabase(); const url = db.url;
  const a = await PostgresStore.connect(url);
  const s = await scenario({ rotateManagementToken: true }, a);
  let b: PostgresStore | undefined; let runtime: Awaited<ReturnType<typeof createRuntime>> | undefined;
  try {
    const first = await s.runtime.dcr.register('bank-a', 'as-a');
    await s.runtime.dcr.manage('bank-a', 'as-a', 'GET');
    b = await PostgresStore.connect(url); runtime = await createRuntime(s.config, b);
    const restored = await runtime.dcr.register('bank-a', 'as-a');
    assert.equal(restored.clientId, first.clientId); assert.equal(restored.created, false);
    assert.equal((await runtime.dcr.tokenProbe('bank-a', 'as-a')).authenticated, true);
    await runtime.dcr.manage('bank-a', 'as-a', 'PUT');
    await runtime.dcr.manage('bank-a', 'as-a', 'DELETE');
  } finally { runtime?.close(); await s.close(); await b?.close(); await a.close(); await db.close(); }
});
