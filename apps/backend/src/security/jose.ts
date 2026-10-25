import {
  SignJWT, jwtVerify, createLocalJWKSet, exportJWK, importPKCS8, importX509,
  CompactEncrypt, compactDecrypt, decodeProtectedHeader, calculateJwkThumbprint,
  type JSONWebKeySet, type JWTPayload
} from 'jose';
import { randomUUID, createHash, X509Certificate } from 'node:crypto';
import type { DataStore } from '../persistence/store.js';
import type { Material } from './certificates.js';
import { AppError, ensure } from '../errors.js';

const seconds = () => Math.floor(Date.now() / 1000);
const digest = (value: string) => createHash('sha256').update(value).digest('hex');
export interface VerifyContext { issuer: string; audience: string; nonce?: string; state?: string; clientId?: string }
export type Artifact = 'assertion' | 'request' | 'resource';
const types: Record<Artifact, string> = { assertion: 'JWT', request: 'oauth-authz-req+jwt', resource: 'JWT' };

export class CryptoService {
  private constructor(
    private readonly signingKey: CryptoKey, readonly kid: string,
    private readonly encryptionKey: CryptoKey, readonly jwks: JSONWebKeySet,
    private readonly replay: DataStore, private readonly validUntil: number
  ) {}
  static async create(material: Material, replay: DataStore) {
    const signingKey = await importPKCS8(material.signingKey, 'PS256');
    const publicJwk = await exportJWK(await importX509(new X509Certificate(material.signingCert).toString(), 'PS256'));
    const kid = await calculateJwkThumbprint(publicJwk);
    publicJwk.kid = kid; publicJwk.alg = 'PS256'; publicJwk.use = 'sig';
    const encryptionKey = await importPKCS8(material.encryptionKey, 'RSA-OAEP', { extractable: true });
    const { d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, ...enc } = await exportJWK(encryptionKey);
    enc.kid = await calculateJwkThumbprint(enc); enc.alg = 'RSA-OAEP'; enc.use = 'enc';
    return new CryptoService(signingKey, kid, encryptionKey, { keys: [publicJwk, enc] }, replay, Date.parse(new X509Certificate(material.signingCert).validTo));
  }
  private sign(kind: Artifact, payload: JWTPayload) {
    ensure(Date.now() < this.validUntil, 'SIGNING_CERTIFICATE_EXPIRED');
    return new SignJWT(payload).setProtectedHeader({ alg: 'PS256', kid: this.kid, typ: types[kind] }).sign(this.signingKey);
  }
  clientAssertion(clientId: string, audience: string) {
    const now = seconds();
    return this.sign('assertion', { iss: clientId, sub: clientId, aud: audience, iat: now, exp: now + 60, jti: randomUUID() });
  }
  requestObject(clientId: string, issuer: string, params: {
    redirect_uri: string; scope: string; response_type: string; state: string; nonce: string;
    code_challenge: string; code_challenge_method: 'S256';
  }) {
    ensure(params.state.length >= 16 && params.nonce.length >= 16 && /^[A-Za-z0-9_-]{43}$/.test(params.code_challenge), 'INVALID_REQUEST_PARAMETERS');
    const now = seconds();
    ensure(params.response_type === 'code id_token', 'FAPI_RESPONSE_TYPE_REQUIRED');
    return this.sign('request', { ...params, response_mode: 'fragment', claims: { id_token: { acr: { essential: true } } }, client_id: clientId, iss: clientId, aud: issuer, iat: now, exp: now + 60, jti: randomUUID() });
  }
  resourceMessage(organisationId: string, audience: string, data: unknown) {
    return this.sign('resource', { iss: organisationId, aud: audience, iat: seconds(), jti: randomUUID(), data });
  }
  resourceRequest(organisationId: string, endpoint: string, data: unknown) {
    ensure(new URL(endpoint).protocol === 'https:', 'HTTPS_RESOURCE_REQUIRED');
    return this.resourceMessage(organisationId, endpoint, data);
  }
  resourceResponse(organisationId: string, recipientOrganisation: string, data: unknown) {
    ensure(recipientOrganisation && !recipientOrganisation.includes('://'), 'RECIPIENT_ORGANISATION_REQUIRED');
    return this.resourceMessage(organisationId, recipientOrganisation, data);
  }
  async verify(kind: Artifact, token: string, jwks: JSONWebKeySet, expected: VerifyContext): Promise<JWTPayload> {
    try {
      const header = decodeProtectedHeader(token);
      ensure(header.alg === 'PS256' && typeof header.kid === 'string' && header.typ === types[kind], 'INVALID_JOSE_HEADER');
      ensure(!header.jku && !header.jwk && !header.x5u && !header.crit, 'UNTRUSTED_KEY_REFERENCE');
      const candidates = jwks.keys.filter(k => k.kid === header.kid && k.kty === 'RSA' && k.use === 'sig' && k.alg === 'PS256');
      ensure(candidates.length === 1, 'AMBIGUOUS_OR_UNKNOWN_KID');
      const key = candidates[0]!;
      ensure(!key.d && key.n && Buffer.from(key.n, 'base64url').length >= 256, 'INVALID_PUBLIC_KEY');
      const { payload } = await jwtVerify(token, createLocalJWKSet({ keys: candidates }), {
        algorithms: ['PS256'], issuer: expected.issuer, audience: expected.audience,
        requiredClaims: ['iss', 'aud', 'iat', 'jti', ...(kind === 'resource' ? [] : ['exp'])],
        maxTokenAge: kind === 'resource' ? undefined : 60, clockTolerance: kind === 'resource' ? 0 : 5
      });
      ensure(typeof payload.iat === 'number' && (kind === 'resource' ? Math.abs(seconds() - payload.iat) <= 60 : payload.iat <= seconds() + 5), 'INVALID_IAT_WINDOW');
      ensure(typeof payload.jti === 'string' && payload.jti.length > 0, 'INVALID_JTI');
      if (payload.exp !== undefined && kind !== 'resource') ensure(payload.exp <= payload.iat + 60, 'TOKEN_LIFETIME_TOO_LONG');
      if (kind === 'assertion') {
        ensure(payload.sub === expected.issuer && !payload.client_id && !payload.data, 'INVALID_ASSERTION_CLAIMS');
      }
      if (kind === 'request') {
        ensure(payload.client_id === expected.issuer && !payload.sub, 'INVALID_REQUEST_CLAIMS');
        ensure(expected.nonce && expected.state && payload.nonce === expected.nonce && payload.state === expected.state, 'STATE_OR_NONCE_MISMATCH');
        ensure(payload.code_challenge_method === 'S256' && typeof payload.code_challenge === 'string' && /^[A-Za-z0-9_-]{43}$/.test(payload.code_challenge), 'INVALID_PKCE');
      }
      if (kind === 'resource') ensure('data' in payload && !payload.sub && !payload.client_id && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(payload.jti), 'INVALID_RESOURCE_CLAIMS');
      const replayContext = kind === 'resource' ? `${kind}:${expected.clientId ?? expected.issuer}:${payload.jti}` : `${kind}:${expected.issuer}:${expected.audience}:${payload.jti}`;
      const replayExpires = kind === 'resource' ? (seconds() + 86400) * 1000 : ((payload.exp ?? payload.iat + 60) + 5) * 1000;
      ensure(await this.replay.claim(`replay:${digest(replayContext)}`, replayExpires), 'JWT_REPLAY', kind === 'resource' ? 403 : 401);
      return payload;
    } catch (e) { if (e instanceof AppError) throw e; throw new AppError(kind === 'resource' ? 'BAD_SIGNATURE' : 'JWT_VERIFICATION_FAILED', kind === 'resource' ? 400 : 401); }
  }
  async encrypt(signedJwt: string, recipient: JSONWebKeySet) {
    const keys = recipient.keys.filter(k => k.kty === 'RSA' && k.use === 'enc' && k.alg === 'RSA-OAEP');
    ensure(keys.length === 1 && keys[0]?.kid && !keys[0].d, 'AMBIGUOUS_ENCRYPTION_KEY');
    const { importJWK } = await import('jose');
    return new CompactEncrypt(new TextEncoder().encode(signedJwt)).setProtectedHeader({
      alg: 'RSA-OAEP', enc: 'A256GCM', cty: 'JWT', kid: keys[0].kid
    }).encrypt(await importJWK(keys[0], 'RSA-OAEP'));
  }
  async decrypt(encrypted: string): Promise<string> {
    try {
      const header = decodeProtectedHeader(encrypted);
      ensure(header.kid === this.jwks.keys[1]?.kid && header.cty === 'JWT' && !header.zip, 'INVALID_JWE_HEADER');
      const { plaintext } = await compactDecrypt(encrypted, this.encryptionKey, { keyManagementAlgorithms: ['RSA-OAEP'], contentEncryptionAlgorithms: ['A256GCM'] });
      // Caller must verify the nested JWS with its category and expected claims.
      return new TextDecoder().decode(plaintext);
    } catch { throw new AppError('JWE_DECRYPTION_FAILED', 401); }
  }
}

export async function verifySsa(token: string, jwks: JSONWebKeySet, issuer: string) {
  try {
    const header = decodeProtectedHeader(token);
    ensure(header.alg === 'PS256' && typeof header.kid === 'string' && !header.jku && !header.jwk && !header.x5u, 'INVALID_SSA_HEADER');
    const keys = jwks.keys.filter(k => k.kid === header.kid && k.kty === 'RSA' && k.use !== 'enc' && (!k.alg || k.alg === 'PS256') && !k.d);
    ensure(keys.length === 1 && keys[0]?.n && Buffer.from(keys[0].n, 'base64url').length >= 256, 'INVALID_SSA_KEY');
    const { payload } = await jwtVerify(token, createLocalJWKSet({ keys }), { algorithms: ['PS256'], issuer, requiredClaims: ['iat'], maxTokenAge: 300, clockTolerance: 5 });
    ensure(typeof payload.iat === 'number' && payload.iat <= seconds() + 5, 'FUTURE_SSA');
    return payload;
  } catch (e) { if (e instanceof AppError) throw e; throw new AppError('SSA_VERIFICATION_FAILED', 401); }
}
