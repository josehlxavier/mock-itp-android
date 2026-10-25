import { loadConfig, readSecret } from './config.js';
import { PostgresStore } from './persistence/store.js';
import { createRuntime } from './runtime.js';
import { createApp } from './app.js';

async function main() {
  const config = await loadConfig(process.env.ITP_CONFIG ?? '.local/config.json');
  const urlFile = process.env.DATABASE_URL_FILE ?? config.databaseUrlFile;
  const url = process.env.DATABASE_URL ?? (urlFile ? await readSecret(urlFile) : undefined);
  if (!url) throw new Error('DATABASE_URL_REQUIRED');
  const store = await PostgresStore.connect(url);
  try {
    const runtime = await createRuntime(config, store);
    const app = await createApp(runtime);
    app.addHook('onClose', () => store.close());
    await app.listen({ host: process.env.BIND_HOST ?? config.host, port: config.port });
    for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { void app.close(); });
  } catch (error) { await store.close(); throw error; }
}
main().catch(() => { console.error('STARTUP_FAILED: verify configuration, certificates, secret permissions and PostgreSQL connectivity.'); process.exitCode = 1; });
