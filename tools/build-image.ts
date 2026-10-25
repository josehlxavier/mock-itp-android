import { spawn } from 'node:child_process';
import { lookup } from 'node:dns/promises';
import { mkdir, access } from 'node:fs/promises';
import { resolve } from 'node:path';

// Cloud hosts may require the existing egress proxy in the Docker build namespace.
// Predefined Docker proxy arguments are not persisted as Dockerfile ENV instructions.
const args = ['build', '--network=host', '-t', 'wallet-itp:local'];
const proxyValues = new Set<string>();
for (const name of ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy', 'NO_PROXY', 'no_proxy']) {
  const value = process.env[name]; if (!value) continue;
  args.push('--build-arg', name);
  if (name.toLowerCase() !== 'no_proxy') proxyValues.add(value);
}
const hosts = new Set([...proxyValues].map(v => new URL(v).hostname));
for (const host of hosts) args.push('--add-host', `${host}:${(await lookup(host, { family: 4 })).address}`);
const ca = process.env.NODE_EXTRA_CA_CERTS;
if (ca) { await access(ca); args.push('--secret', `id=build_ca,src=${ca}`); }
const dockerConfig = process.env.DOCKER_CONFIG ?? resolve('.local/docker-config');
await mkdir(dockerConfig, { recursive: true, mode: 0o700 });
args.push('.');
const processChild = spawn('docker', args, { env: { ...process.env, DOCKER_CONFIG: dockerConfig }, stdio: ['ignore', 'pipe', 'pipe'] });
// Buffer complete lines so a proxy URL split across stream chunks is still redacted.
for (const stream of [processChild.stdout, processChild.stderr]) {
  let pending = '';
  const output = (value: string) => { for (const proxy of proxyValues) value = value.replaceAll(proxy, '[configured proxy]'); process.stdout.write(value); };
  stream.setEncoding('utf8');
  stream.on('data', (chunk: string) => {
    pending += chunk; const end = pending.lastIndexOf('\n');
    if (end >= 0) { output(pending.slice(0, end + 1)); pending = pending.slice(end + 1); }
  });
  stream.on('end', () => { if (pending) output(pending); });
}
processChild.on('error', () => { console.error('IMAGE_BUILD_FAILED: Docker unavailable.'); process.exitCode = 1; });
processChild.on('close', code => { process.exitCode = code ?? 1; });
