import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { ensure } from '../errors.js';

export class Vault {
  constructor(private readonly key: Buffer) { ensure(key.length === 32, 'VAULT_KEY_MUST_BE_32_BYTES'); }
  seal(value: unknown, context: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, iv);
    cipher.setAAD(Buffer.from(context));
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value)), cipher.final()]);
    return ['v1', iv.toString('base64url'), cipher.getAuthTag().toString('base64url'), ciphertext.toString('base64url')].join('.');
  }
  open<T>(value: string, context: string): T {
    const [version, iv, tag, ciphertext] = value.split('.');
    ensure(version === 'v1' && iv && tag && ciphertext, 'INVALID_CIPHERTEXT');
    const cipher = createDecipheriv('aes-256-gcm', this.key, Buffer.from(iv, 'base64url'));
    cipher.setAAD(Buffer.from(context)); cipher.setAuthTag(Buffer.from(tag, 'base64url'));
    return JSON.parse(Buffer.concat([cipher.update(Buffer.from(ciphertext, 'base64url')), cipher.final()]).toString()) as T;
  }
}
