import { readSecret, type Config } from './config.js';
import { loadMaterial } from './security/certificates.js';
import { CryptoService } from './security/jose.js';
import { Vault } from './security/vault.js';
import { Transport } from './transport.js';
import { DirectoryService } from './directory/service.js';
import { DcrService } from './dcr/service.js';
import type { DataStore } from './persistence/store.js';

export async function createRuntime(config: Config, store: DataStore) {
  const material = await loadMaterial(config);
  const crypto = await CryptoService.create(material, store);
  const vault = new Vault(Buffer.from(await readSecret(config.vaultKeyFile), 'base64url'));
  const http = new Transport(material, config.allowedOrigins, store);
  const directory = new DirectoryService(config, http, store);
  const dcr = new DcrService(config, directory, crypto, store, vault, material);
  return { config, material, crypto, store, http, directory, dcr, close: () => http.close() };
}
export type Runtime = Awaited<ReturnType<typeof createRuntime>>;
