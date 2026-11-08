import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtemp, chmod, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const crypto = webcrypto;
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const dir = await mkdtemp(join(tmpdir(), 'gc-sync-e2e-'));
await chmod(dir, 0o700);
const port = 18783 + Math.floor(Math.random() * 1000);
const origin = `http://127.0.0.1:${port}`;
const executable = join(dir, 'sync-test-server');
execFileSync('go', ['build', '-o', executable, './cmd/sync'], { stdio: 'pipe' });
const proc = spawn(executable, ['-listen', `127.0.0.1:${port}`, '-data', dir], { stdio: 'ignore' });
const base64 = bytes => Buffer.from(bytes).toString('base64url');
const exited = new Promise(resolve => proc.once('exit', resolve));
const joinBytes = (...chunks) => {
  const bytes = new Uint8Array(chunks.reduce((n, v) => n + v.length, 0));
  let offset = 0;
  for (const part of chunks) { bytes.set(part, offset); offset += part.length; }
  return bytes;
};
async function seal(key, data) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data));
  return joinBytes(iv, ct);
}
async function decrypt(key, data) {
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: data.subarray(0, 12) }, key, data.subarray(12)));
}
try {
  let ready = false;
  for (let i = 0; i < 60; i++) {
    try { const r = await fetch(origin + '/api/health'); if (r.ok) { ready = true; break; } } catch {}
    await delay(150);
  }
  assert.ok(ready, 'local server did not start');
  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt', 'decrypt']);
  const content = encoder.encode('GoreeCloud Sync encrypted protocol integration test ✓');
  const meta = await seal(key, encoder.encode(JSON.stringify({ name: 'private.txt', type: 'text/plain' })));
  const payload = await seal(key, content);
  const revokeToken = crypto.getRandomValues(new Uint8Array(32));
  const revokeDigest = new Uint8Array(await crypto.subtle.digest('SHA-256', revokeToken));
  const response = await fetch(origin + '/api/shares', { method: 'POST', headers: {
    'Content-Type': 'application/octet-stream', 'X-GC-Client': 'web-v1', 'Origin': origin,
    'X-GC-Meta': base64(meta), 'X-GC-TTL': '3600', 'X-GC-Downloads': '1',
    'X-GC-Revoke-Digest': base64(revokeDigest),
  }, body: joinBytes(encoder.encode('GCS1'), payload) });
  assert.equal(response.status, 201);
  const { id } = await response.json();
  assert.match(id, /^[a-f0-9]{32}$/);
  const received = await fetch(origin + '/api/shares/' + id, {headers: {'X-GC-Client': 'web-v1'}});
  assert.equal(received.status, 200);
  assert.equal(received.headers.get('Cache-Control'), 'no-store');
  assert.equal(received.headers.get('Cross-Origin-Resource-Policy'), 'same-origin');
  const encryptedBody = new Uint8Array(await received.arrayBuffer());
  assert.equal(decoder.decode(encryptedBody.subarray(0, 4)), 'GCS1');
  const recovered = await decrypt(key, encryptedBody.subarray(4));
  assert.deepEqual(recovered, content);
  const savedMeta = new Uint8Array(Buffer.from(received.headers.get('X-GC-Meta'), 'base64url'));
  const recoveredMeta = JSON.parse(decoder.decode(await decrypt(key, savedMeta)));
  assert.equal(recoveredMeta.name, 'private.txt');
  const stored = await readFile(join(dir, id + '.bin'));
  assert.ok(!stored.includes(Buffer.from(content)), 'plaintext leaked into server storage');
  const savedRecord = await readFile(join(dir, id + '.json'), 'utf8');
  assert.ok(!savedRecord.includes('private.txt'), 'plaintext metadata leaked into server storage');
  const wrong = crypto.getRandomValues(new Uint8Array(32));
  const wrongKey = await crypto.subtle.importKey('raw', wrong, 'AES-GCM', false, ['decrypt']);
  await assert.rejects(() => decrypt(wrongKey, encryptedBody.subarray(4)));
  const altered = encryptedBody.subarray(4).slice(); altered[altered.length - 1] ^= 1;
  await assert.rejects(() => decrypt(key, altered));
  assert.equal((await fetch(origin + '/api/shares/' + id, {headers: {'X-GC-Client': 'web-v1'}})).status, 410);
  const second = await fetch(origin + '/api/shares', {method: 'POST',headers: {
    'Content-Type':'application/octet-stream','Origin':origin,'X-GC-Client':'web-v1',
    'X-GC-Meta':base64(meta),'X-GC-TTL':'3600','X-GC-Downloads':'5',
    'X-GC-Revoke-Digest':base64(revokeDigest)
  },body:joinBytes(encoder.encode('GCS1'),payload)});
  assert.equal(second.status,201);
  const secondID=(await second.json()).id;
  const requestRevoke = token => fetch(origin+'/api/shares/'+secondID+'/revoke',{
    method:'POST',headers:{'Origin':origin,'X-GC-Client':'web-v1','X-GC-Revoke-Token':base64(token)}
  });
  assert.equal((await requestRevoke(new Uint8Array(32))).status,403,'incorrect owner token should fail');
  assert.equal((await requestRevoke(revokeToken)).status,204);
  assert.equal((await fetch(origin+'/api/shares/'+secondID,{headers:{'X-GC-Client':'web-v1'}})).status,404);
  console.log('PASS: encrypted round trip, metadata privacy, tamper rejection, download limits, and owner-only revocation');
} finally {
  if (proc.exitCode === null) proc.kill('SIGTERM');
  const fallback = setTimeout(() => { if (proc.exitCode === null) proc.kill('SIGKILL'); }, 2000);
  fallback.unref();
  await exited;
  clearTimeout(fallback);
  await rm(dir, { recursive: true, force: true });
}
