import { loadConfig, readSecret } from './config.js';
import { PostgresStore } from './persistence/store.js';
import { createRuntime } from './runtime.js';

async function main() {
  const [org, server, responseFile] = process.argv.slice(2);
  if (!org || !server || !responseFile) throw new Error('Use: reconcile <organisation> <server> <private-response-file>');
  const config = await loadConfig(process.env.ITP_CONFIG ?? '.local/config.json');
  const url = process.env.DATABASE_URL ?? await readSecret(process.env.DATABASE_URL_FILE ?? config.databaseUrlFile!);
  const store = await PostgresStore.connect(url);
  const runtime = await createRuntime(config, store);
  try { console.log(await runtime.dcr.reconcile(org, server, await readSecret(responseFile))); }
  finally { runtime.close(); await store.close(); }
}
main().catch(() => { console.error('RECONCILIATION_FAILED: verify private recovery file and provider record.'); process.exitCode = 1; });
