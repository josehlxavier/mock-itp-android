import Fastify, { LogController } from 'fastify';
import { createHash, timingSafeEqual, randomUUID, X509Certificate } from 'node:crypto';
import { readSecret } from './config.js';
import { z } from 'zod';
import { AppError, ensure } from './errors.js';
import type { Runtime } from './runtime.js';

export async function createApp(runtime: Runtime, logger = true) {
  const app = Fastify({ logger: logger ? { level: 'info', redact: ['req.headers.authorization', '*.access_token', '*.registration_access_token', '*.software_statement'] } : false,
    logController: new LogController({ disableRequestLogging: true }), bodyLimit: 32 * 1024, requestTimeout: 30_000,
    genReqId: () => randomUUID() });
  const adminToken = await readSecret(runtime.config.adminTokenFile);
  ensure(adminToken.length >= 32, 'ADMIN_TOKEN_TOO_SHORT');
  const hash = (value: string) => createHash('sha256').update(value).digest();
  app.addHook('onRequest', async (req, reply) => {
    reply.header('x-fapi-interaction-id', req.id).header('cache-control', 'no-store').header('x-content-type-options', 'nosniff');
    if (req.routeOptions.url?.startsWith('/admin')) {
      ensure(timingSafeEqual(hash(req.headers.authorization ?? ''), hash(`Bearer ${adminToken}`)), 'UNAUTHORIZED', 401);
    }
  });
  app.setErrorHandler((error, req, reply) => {
    const known = error instanceof AppError;
    const code = known ? error.code : error instanceof z.ZodError ? 'INVALID_CONTRACT' : 'INTERNAL_ERROR';
    app.log.warn({ code, interactionId: req.id }, 'Request failed');
    reply.code(known ? error.status : error instanceof z.ZodError ? 400 : 500).send({ error: code, interactionId: req.id });
  });
  app.get('/health', async () => { await runtime.store.get('__health'); return { status: 'ok', mode: runtime.config.mode, simulated: runtime.config.mode === 'local' }; });
  app.get('/.well-known/jwks.json', async (_, reply) => reply.header('cache-control', 'public, max-age=60').send(runtime.crypto.jwks));
  app.get('/admin/environment', async () => ({ mode: runtime.config.mode, organisationId: runtime.config.organisationId,
    softwareId: runtime.config.softwareId, jwksUri: runtime.config.jwksUri, androidOrigins: runtime.config.androidOrigins,
    certificates: [runtime.material.transportCert, runtime.material.signingCert].map(pem => {
      const c = new X509Certificate(pem); return { fingerprint: c.fingerprint256, validFrom: c.validFrom, validTo: c.validTo };
    }) }));
  app.get('/admin/institutions', async () => runtime.directory.participants());
  app.get('/admin/software-statement', async () => {
    const { payload } = await runtime.directory.ssa();
    return Object.fromEntries(['org_id', 'software_id', 'software_version', 'software_jwks_uri', 'software_redirect_uris', 'origin', 'org_status', 'software_statement_roles', 'iat', 'exp']
      .filter(key => payload[key] !== undefined).map(key => [key, payload[key]]));
  });
  const paramsSchema = z.object({ org: z.string().min(1).max(100), as: z.string().min(1).max(100) });
  const base = '/admin/institutions/:org/servers/:as';
  app.get(`${base}/discovery`, async req => { const p = paramsSchema.parse(req.params); return runtime.directory.select(p.org, p.as); });
  app.post(`${base}/discovery/refresh`, async req => { const p = paramsSchema.parse(req.params); return runtime.directory.select(p.org, p.as, true); });
  app.post('/admin/metadata/refresh', async () => ({ institutions: await runtime.directory.participants(true) }));
  app.get(`${base}/registration/local`, async req => { const p = paramsSchema.parse(req.params); return await runtime.dcr.inspect(p.org, p.as) ?? null; });
  app.post(`${base}/registration`, async (req, reply) => {
    const p = paramsSchema.parse(req.params); const result = await runtime.dcr.register(p.org, p.as);
    reply.code(result.created ? 201 : 200); return result;
  });
  for (const method of ['GET', 'PUT', 'DELETE'] as const) {
    app.route({ method, url: `${base}/registration`, handler: async req => {
      const p = paramsSchema.parse(req.params); return runtime.dcr.manage(p.org, p.as, method);
    } });
  }
  app.post(`${base}/token-probe`, async req => { const p = paramsSchema.parse(req.params); return runtime.dcr.tokenProbe(p.org, p.as); });
  app.addHook('onClose', async () => { runtime.close(); });
  return app;
}
