import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import { initLab } from '../../../tools/lab/init.js';
import { createLab, type LabFaults } from '../../../tools/lab/server.js';
import { loadConfig } from '../src/config.js';
import { createRuntime } from '../src/runtime.js';
import { MemoryStore, type DataStore } from '../src/persistence/store.js';

let base: Promise<string> | undefined;
export async function fixtureDir() {
  base ??= (async () => { const dir = await mkdtemp(join(tmpdir(), 'wallet-pki-')); await initLab(dir); return dir; })();
  return base;
}
export async function cleanupFixtures() { if (base) await rm(await base, { recursive: true, force: true }); }
async function unusedPort() {
  const server = createServer();
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as { port: number }).port;
  await new Promise<void>((r, reject) => server.close(e => e ? reject(e) : r()));
  return port;
}
export async function scenario(faults: LabFaults = {}, store: DataStore = new MemoryStore()) {
  const dir = await fixtureDir(); const port = await unusedPort();
  const origin = `https://localhost:${port}`;
  const raw = await loadConfig(join(dir, 'config.json'));
  const config = JSON.parse(JSON.stringify(raw).replaceAll('https://localhost:9443', origin)) as typeof raw;
  const lab = await createLab(config, store, origin, faults);
  await lab.listen({ host: '127.0.0.1', port });
  const runtime = await createRuntime(config, store);
  return { dir, config, origin, store, lab, runtime,
    close: async () => { runtime.close(); await lab.close(); } };
}
