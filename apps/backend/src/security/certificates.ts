import { X509Certificate, createPrivateKey, createPublicKey } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile } from 'node:fs/promises';
import { readSecret, type Config } from '../config.js';
import { ensure, AppError } from '../errors.js';

export function validateCertificate(certPem: string, keyPem: string, now = Date.now()) {
  const cert = new X509Certificate(certPem);
  ensure(now >= Date.parse(cert.validFrom) && now < Date.parse(cert.validTo), 'CERTIFICATE_EXPIRED_OR_NOT_YET_VALID');
  ensure(!cert.ca, 'LEAF_CERTIFICATE_REQUIRED');
  ensure(cert.checkPrivateKey(createPrivateKey(keyPem)), 'CERTIFICATE_KEY_MISMATCH');
  ensure(cert.publicKey.asymmetricKeyType === 'rsa' && (cert.publicKey.asymmetricKeyDetails?.modulusLength ?? 0) >= 2048, 'RSA_2048_REQUIRED');
  return cert;
}
export async function loadMaterial(config: Config) {
  const crl = config.tls.crlFile ? (await readFile(config.tls.crlFile, 'utf8')).match(/-----BEGIN X509 CRL-----[\s\S]+?-----END X509 CRL-----/g) : undefined;
  if (config.tls.crlFile) ensure(crl?.length, 'INVALID_REVOCATION_CRL');
  const [ca, transportCert, transportKey, signingCert, signingKey, encryptionKey] = await Promise.all([
    readFile(config.tls.caFile, 'utf8'), readFile(config.tls.certFile, 'utf8'), readSecret(config.tls.keyFile),
    readFile(config.signing.certFile, 'utf8'), readSecret(config.signing.keyFile), readSecret(config.encryptionKeyFile)
  ]);
  for (const [cert, key, path, purpose] of [
    [transportCert, transportKey, config.tls.certFile, 'sslclient'],
    [signingCert, signingKey, config.signing.certFile, 'any']
  ] as const) {
    const parsed = validateCertificate(cert, key);
    const attributes = parsed.toLegacyObject().subject as unknown as Record<string, string | string[]>;
    const attribute = (...names: string[]) => Object.entries(attributes).filter(([name]) => names.includes(name.toLowerCase())).flatMap(([, values]) => Array.isArray(values) ? values : [values]);
    if (purpose === 'sslclient') {
      const uid = attribute('uid', '0.9.2342.19200300.100.1.1');
      ensure(uid.length === 1 && uid[0] === config.softwareId, 'CERTIFICATE_SOFTWARE_MISMATCH');
      const org = attribute('organizationidentifier', '2.5.4.97');
      ensure(org.length === 1 && org[0] === `OFBBR-${config.organisationId}`, 'CERTIFICATE_ORGANISATION_MISMATCH');
    } else {
      const org = attribute('uid', '0.9.2342.19200300.100.1.1');
      ensure(org.length === 1 && org[0] === config.organisationId, 'SIGNING_CERTIFICATE_ORGANISATION_MISMATCH');
    }
    try {
      await promisify(execFile)('openssl', ['verify', '-CAfile', config.tls.caFile, '-untrusted', path, '-purpose', purpose,
        ...(config.tls.crlFile ? ['-crl_check_all', '-CRLfile', config.tls.crlFile] : []), path]);
    } catch { throw new AppError('CERTIFICATE_CHAIN_INVALID'); }
    const { stdout } = await promisify(execFile)('openssl', ['x509', '-in', path, '-noout', '-ext', 'keyUsage']);
    ensure(stdout.includes('Digital Signature') && (purpose !== 'sslclient' || stdout.includes('Key Encipherment')), 'CERTIFICATE_KEY_USAGE_INVALID');
  }
  ensure(transportCert !== signingCert && transportKey !== signingKey, 'SEPARATE_TRANSPORT_AND_SIGNING_KEYS_REQUIRED');
  const enc = createPrivateKey(encryptionKey);
  ensure(enc.asymmetricKeyType === 'rsa' && (enc.asymmetricKeyDetails?.modulusLength ?? 0) >= 2048, 'RSA_2048_REQUIRED');
  ensure(!createPublicKey(enc).equals(new X509Certificate(signingCert).publicKey), 'SEPARATE_ENCRYPTION_KEY_REQUIRED');
  return { ca, crl: crl ?? undefined, transportCert, transportKey, signingCert, signingKey, encryptionKey };
}
export type Material = Awaited<ReturnType<typeof loadMaterial>>;
