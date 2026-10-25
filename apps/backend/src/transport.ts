import { Agent, request as httpsRequest } from 'node:https';
import { randomUUID, constants } from 'node:crypto';
import { isIP } from 'node:net';
import type { Material } from './security/certificates.js';
import type { AuditEvent, DataStore } from './persistence/store.js';
import { ensure, AppError } from './errors.js';

export function fapiHeaders(input: { interactionId?: string; idempotencyKey?: string; customerIp?: string; authDate?: string } = {}) {
  const id = input.interactionId ?? randomUUID();
  ensure(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id), 'INVALID_INTERACTION_ID');
  const headers: Record<string, string> = { 'x-fapi-interaction-id': id };
  if (input.idempotencyKey !== undefined) {
    ensure(/^[\x21-\x7e]{1,40}$/.test(input.idempotencyKey), 'INVALID_IDEMPOTENCY_KEY');
    headers['x-idempotency-key'] = input.idempotencyKey;
  }
  if (input.customerIp !== undefined) { ensure(isIP(input.customerIp), 'INVALID_CUSTOMER_IP'); headers['x-fapi-customer-ip-address'] = input.customerIp; }
  if (input.authDate !== undefined) { ensure(Number.isFinite(Date.parse(input.authDate)) && new Date(input.authDate).toUTCString() === input.authDate, 'INVALID_AUTH_DATE'); headers['x-fapi-auth-date'] = input.authDate; }
  return headers;
}
export interface HttpResult { status: number; headers: Record<string, string | string[] | undefined>; text: string }
export class Transport {
  private readonly agent: Agent;
  constructor(material: Material, private readonly allowedOrigins: string[], private readonly store: DataStore, private readonly timeoutMs = 10_000) {
    this.agent = new Agent({ ca: material.ca, crl: material.crl, cert: material.transportCert, key: material.transportKey,
      rejectUnauthorized: true, minVersion: 'TLSv1.2', keepAlive: true, maxSockets: 8,
      maxCachedSessions: 0, secureOptions: constants.SSL_OP_NO_RENEGOTIATION | constants.SSL_OP_NO_TICKET,
      ciphers: 'TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384' });
  }
  checkUrl(value: string) {
    const url = new URL(value);
    ensure(url.protocol === 'https:' && !url.username && !url.password && !url.hash && this.allowedOrigins.includes(url.origin), 'ORIGIN_NOT_ALLOWED');
    return url;
  }
  async send(url: string, options: { method?: string; headers?: Record<string, string>; body?: string; operation: string }): Promise<HttpResult> {
    const target = this.checkUrl(url);
    const provided = Object.fromEntries(Object.entries(options.headers ?? {}).map(([name, value]) => [name.toLowerCase(), value]));
    const headers = { ...provided, ...fapiHeaders({ interactionId: provided['x-fapi-interaction-id'], idempotencyKey: provided['x-idempotency-key'], customerIp: provided['x-fapi-customer-ip-address'], authDate: provided['x-fapi-auth-date'] }) };
    const start = Date.now(); let status: number | undefined;
    let outcome = 'TRANSPORT_FAILURE';
    try {
      const result = await new Promise<HttpResult>((resolve, reject) => {
        const request = httpsRequest(target, { method: options.method ?? 'GET', headers, agent: this.agent }, response => {
          const chunks: Buffer[] = []; let size = 0;
          response.on('data', (chunk: Buffer) => {
            size += chunk.length;
            if (size > 2 * 1024 * 1024) request.destroy(new AppError('RESPONSE_TOO_LARGE', 502));
            else chunks.push(chunk);
          });
          response.on('error', reject);
          response.on('end', () => resolve({ status: response.statusCode ?? 502, headers: response.headers, text: Buffer.concat(chunks).toString('utf8') }));
        });
        const timer = setTimeout(() => request.destroy(new AppError('UPSTREAM_TIMEOUT', 504)), this.timeoutMs);
        request.once('close', () => clearTimeout(timer)); request.once('error', reject);
        request.end(options.body);
      });
      status = result.status;
      ensure(status >= 200 && status < 300, `UPSTREAM_HTTP_${status}`, 502);
      outcome = 'OK'; return result;
    } catch (e) { if (e instanceof AppError) { outcome = e.code; throw e; } throw new AppError('TLS_OR_NETWORK_FAILURE', 502); }
    finally {
      const event: AuditEvent = { operation: options.operation, outcome, interactionId: headers['x-fapi-interaction-id']!, elapsedMs: Date.now() - start, status };
      await this.store.audit(event);
    }
  }
  async json<T = unknown>(url: string, operation: string, headers?: Record<string, string>): Promise<T> {
    const result = await this.send(url, { operation, headers: { accept: 'application/json, application/jwk-set+json', ...headers } });
    ensure(['application/json', 'application/jwk-set+json'].includes(String(result.headers['content-type']).split(';')[0]!.trim()), 'INVALID_CONTENT_TYPE', 502);
    try { return JSON.parse(result.text) as T; } catch { throw new AppError('INVALID_UPSTREAM_JSON', 502); }
  }
  close() { this.agent.destroy(); }
}
