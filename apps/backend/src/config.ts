import { readFile, stat } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { z } from 'zod';
import { ensure } from './errors.js';

const httpsUrl = z.url().refine(v => {
  const u = new URL(v); return u.protocol === 'https:' && !u.username && !u.password && !u.hash;
}, 'HTTPS URL without credentials required');
export const configSchema = z.object({
  mode: z.enum(['local', 'sandbox']),
  port: z.number().int().min(1).max(65535).default(3000),
  host: z.string().default('127.0.0.1'),
  organisationId: z.string().min(1), softwareId: z.string().min(1),
  jwksUri: httpsUrl,
  redirectUris: z.array(httpsUrl).min(1),
  androidOrigins: z.array(z.string().regex(/^android:apk-key-hash:[A-Za-z0-9_-]{43}$/)).min(1),
  scopes: z.array(z.string().regex(/^[\x21\x23-\x5B\x5D-\x7E]+$/)).min(1),
  grantTypes: z.array(z.enum(['client_credentials', 'authorization_code', 'refresh_token', 'implicit'])).min(1),
  responseTypes: z.array(z.enum(['code', 'code id_token'])).min(1),
  directory: z.object({
    participantsUrl: httpsUrl, ssaUrl: httpsUrl.optional(), ssaFile: z.string().optional(),
    jwksUri: httpsUrl, issuer: z.string().min(1), tokenFile: z.string().optional(),
    cacheSeconds: z.number().int().min(1).max(3600).default(300)
  }).refine(d => Boolean(d.ssaUrl) !== Boolean(d.ssaFile), 'Choose ssaUrl or ssaFile'),
  allowedOrigins: z.array(httpsUrl.refine(v => new URL(v).origin === v)).min(1),
  tls: z.object({ caFile: z.string(), certFile: z.string(), keyFile: z.string(), crlFile: z.string().optional() }),
  signing: z.object({ certFile: z.string(), keyFile: z.string() }),
  encryptionKeyFile: z.string(), vaultKeyFile: z.string(), adminTokenFile: z.string(),
  databaseUrlFile: z.string().optional()
}).strict();
export type Config = z.infer<typeof configSchema>;

export async function readSecret(path: string): Promise<string> {
  const info = await stat(path);
  ensure(info.isFile() && (info.mode & 0o077) === 0, 'INSECURE_SECRET_FILE');
  return (await readFile(path, 'utf8')).trim();
}
export async function loadConfig(path: string): Promise<Config> {
  const raw = configSchema.parse(JSON.parse(await readFile(path, 'utf8')));
  const base = dirname(resolve(path));
  const file = (p: string) => resolve(base, p);
  raw.tls = { ...raw.tls, caFile: file(raw.tls.caFile), certFile: file(raw.tls.certFile), keyFile: file(raw.tls.keyFile), crlFile: raw.tls.crlFile ? file(raw.tls.crlFile) : undefined };
  raw.signing = { certFile: file(raw.signing.certFile), keyFile: file(raw.signing.keyFile) };
  raw.encryptionKeyFile = file(raw.encryptionKeyFile);
  raw.vaultKeyFile = file(raw.vaultKeyFile); raw.adminTokenFile = file(raw.adminTokenFile);
  if (raw.databaseUrlFile) raw.databaseUrlFile = file(raw.databaseUrlFile);
  if (raw.directory.ssaFile) raw.directory.ssaFile = file(raw.directory.ssaFile);
  if (raw.directory.tokenFile) raw.directory.tokenFile = file(raw.directory.tokenFile);
  for (const u of [raw.directory.participantsUrl, raw.directory.jwksUri, raw.directory.ssaUrl, raw.jwksUri]) {
    if (u) ensure(raw.allowedOrigins.includes(new URL(u).origin), 'ORIGIN_NOT_ALLOWED');
  }
  if (raw.mode === 'sandbox') {
    ensure(!raw.allowedOrigins.some(v => ['localhost', '127.0.0.1', '[::1]'].includes(new URL(v).hostname)), 'SANDBOX_LOOPBACK_FORBIDDEN');
    ensure(raw.tls.crlFile, 'SANDBOX_REVOCATION_CRL_REQUIRED');
  }
  return raw;
}
