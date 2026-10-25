import { loadConfig, readSecret } from '../../apps/backend/src/config.js';
import { PostgresStore } from '../../apps/backend/src/persistence/store.js';
import { createLab } from './server.js';

async function main() {
  const config = await loadConfig(process.env.ITP_CONFIG ?? '.local/config.json');
  const url = process.env.DATABASE_URL ?? await readSecret(process.env.DATABASE_URL_FILE ?? config.databaseUrlFile!);
  const store = await PostgresStore.connect(url);
  const origin = process.env.LAB_ORIGIN ?? config.allowedOrigins[0]!;
  const app = await createLab(config, store, origin);
  app.addHook('onClose', () => store.close());
  await app.listen({ host: process.env.BIND_HOST ?? '127.0.0.1', port: Number(new URL(origin).port || 443) });
  console.log('Local mTLS Directory and two simulated Authorization Servers listening.');
  for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => { void app.close(); });
}
main().catch(() => { console.error('LAB_STARTUP_FAILED: check local configuration and PostgreSQL.'); process.exitCode = 1; });
