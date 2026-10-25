import { mkdir, readFile, writeFile, access } from 'node:fs/promises';
import { resolve } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const run = promisify(execFile);
export async function generateCrlFiles(base: string, revokedCertificate?: string) {
  for (const name of ['ca', 'intermediate']) {
    const config = `[ca]\ndefault_ca=local_ca\n[local_ca]\ndatabase=crl-${name}.index\nserial=crl-${name}.serial\ncrlnumber=crl-${name}.number\nnew_certs_dir=.\ncertificate=${name}.pem\nprivate_key=${name}.key\ndefault_md=sha256\ndefault_crl_days=7\npolicy=policy\n[policy]\ncommonName=supplied\n`;
    for (const [file, content] of [[`crl-${name}.cnf`, config], [`crl-${name}.index`, ''], [`crl-${name}.serial`, '1000\n'], [`crl-${name}.number`, '1000\n']]) await writeFile(`${base}/${file}`, content!, { mode: 0o600 });
    if (name === 'intermediate' && revokedCertificate) await run('openssl', ['ca', '-batch', '-config', `crl-${name}.cnf`, '-revoke', revokedCertificate, '-crl_reason', 'keyCompromise'], { cwd: base });
    await run('openssl', ['ca', '-batch', '-config', `crl-${name}.cnf`, '-gencrl', '-out', `${name}.crl.pem`], { cwd: base });
  }
  await writeFile(`${base}/crls.pem`, await readFile(`${base}/ca.crl.pem`, 'utf8') + await readFile(`${base}/intermediate.crl.pem`, 'utf8'), { mode: 0o600 });
}
export async function initLab(dir: string, origin = 'https://localhost:9443') {
  const base = resolve(dir);
  await mkdir(base, { recursive: true, mode: 0o700 });
  try {
    await access(`${base}/config.json`);
    try { await access(`${base}/database.container.url`); }
    catch {
      const password = (await readFile(`${base}/postgres.password`, 'utf8')).trim();
      await writeFile(`${base}/database.container.url`, `postgres://itp:${password}@postgres:5432/itp`, { mode: 0o600, flag: 'wx' });
    }
    return;
  } catch (e) { if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e; }
  const prior = process.umask(0o077);
  try {
    const command = (...args: string[]) => run('openssl', args, { cwd: base });
    await command('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '30', '-subj', '/CN=Wallet Local Root CA', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign');
    await writeFile(`${base}/intermediate.ext`, 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n', { mode: 0o600 });
    await command('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'intermediate.key', '-out', 'intermediate.csr', '-subj', '/CN=Wallet Local Issuing CA');
    await command('x509', '-req', '-in', 'intermediate.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'intermediate.pem', '-days', '14', '-extfile', 'intermediate.ext');
    await writeFile(`${base}/expired-index`, '', { mode: 0o600 });
    await writeFile(`${base}/expired-serial`, '1000\n', { mode: 0o600 });
    await writeFile(`${base}/expired-ca.cnf`, '[ca]\ndefault_ca=local_ca\n[local_ca]\ndatabase=expired-index\nserial=expired-serial\nnew_certs_dir=.\ncertificate=intermediate.pem\nprivate_key=intermediate.key\ndefault_md=sha256\npolicy=local_policy\n[local_policy]\ncommonName=supplied\ncountryName=optional\norganizationName=optional\norganizationIdentifier=optional\nUID=optional\n', { mode: 0o600 });
    for (const name of ['transport', 'transport-next', 'signing', 'signing-next', 'bank-signing', 'directory-signing', 'server', 'wrong-host', 'expired-transport', 'expired-server', 'revoked-transport']) {
      const server = ['server', 'wrong-host', 'expired-server'].includes(name);
      const signing = name.includes('signing');
      const hostname = name === 'wrong-host' ? 'wrong.invalid' : 'localhost';
      const subject = server ? `/CN=${hostname}` : `/C=BR/O=Local ITP/organizationIdentifier=OFBBR-local-itp/UID=${signing ? 'local-itp' : 'wallet-lab'}/CN=${name}`;
      const extension = `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,${signing ? 'nonRepudiation' : 'keyEncipherment'}\n${signing ? '' : `extendedKeyUsage=${server ? 'serverAuth' : 'clientAuth'}\n`}${server ? `subjectAltName=DNS:${hostname}\n` : ''}`;
      await writeFile(`${base}/${name}.ext`, extension, { mode: 0o600 });
      await command('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', `${name}.key`, '-out', `${name}.csr`, '-subj', subject);
      if (name.startsWith('expired')) {
        await command('ca', '-batch', '-config', 'expired-ca.cnf', '-in', `${name}.csr`, '-out', `${name}.pem`, '-startdate', '20000101000000Z', '-enddate', '20000102000000Z', '-extfile', `${name}.ext`, '-notext');
      } else {
        await command('x509', '-req', '-in', `${name}.csr`, '-CA', 'intermediate.pem', '-CAkey', 'intermediate.key', '-CAcreateserial', '-out', `${name}.pem`, '-days', '7', '-extfile', `${name}.ext`);
      }
      const leaf = await readFile(`${base}/${name}.pem`, 'utf8');
      await writeFile(`${base}/${name}.pem`, leaf + await readFile(`${base}/intermediate.pem`, 'utf8'), { mode: 0o600 });
    }
    await generateCrlFiles(base, 'revoked-transport.pem');
    await command('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', 'encryption.key');
    for (const name of ['vault.key', 'admin.token', 'postgres.password']) await writeFile(`${base}/${name}`, randomBytes(32).toString('base64url'), { mode: 0o600 });
    const password = await readFile(`${base}/postgres.password`, 'utf8');
    await writeFile(`${base}/database.url`, `postgres://itp:${password}@127.0.0.1:5432/itp`, { mode: 0o600 });
    await writeFile(`${base}/database.container.url`, `postgres://itp:${password}@postgres:5432/itp`, { mode: 0o600 });
    const config = { mode: 'local', port: 3000, organisationId: 'local-itp', softwareId: 'wallet-lab',
      jwksUri: `${origin}/itp/jwks`, redirectUris: ['https://wallet.example.test/callback'],
      androidOrigins: [`android:apk-key-hash:${randomBytes(32).toString('base64url')}`],
      scopes: ['openid', 'payments', 'nrp-consents'], grantTypes: ['client_credentials', 'authorization_code', 'refresh_token'], responseTypes: ['code id_token'],
      directory: { participantsUrl: `${origin}/participants`, ssaUrl: `${origin}/organisations/local-itp/softwarestatements/wallet-lab/assertion`,
        jwksUri: `${origin}/directory/jwks`, issuer: 'Wallet Local Directory', cacheSeconds: 60 },
      allowedOrigins: [origin], tls: { caFile: 'ca.pem', certFile: 'transport.pem', keyFile: 'transport.key', crlFile: 'crls.pem' },
      signing: { certFile: 'signing.pem', keyFile: 'signing.key' }, encryptionKeyFile: 'encryption.key', vaultKeyFile: 'vault.key', adminTokenFile: 'admin.token', databaseUrlFile: 'database.url' };
    await writeFile(`${base}/config.json`, JSON.stringify(config, null, 2) + '\n', { mode: 0o600 });
  } finally { process.umask(prior); }
}
if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  await initLab(process.env.LAB_DIR ?? '.local', process.env.LAB_ORIGIN);
  console.log('Local PKI and configuration prepared; secrets remain in the ignored lab directory.');
}
