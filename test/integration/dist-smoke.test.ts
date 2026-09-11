/**
 * Runs the PUBLISHED artifact, not the source.
 *
 * Every other test in this suite imports src/*.ts through vitest's transform,
 * which supplies a CommonJS `require` shim. The compiled dist/ is native ESM
 * and has no such shim — so `require('node:https')` in createSecureHttpsServer
 * passed 1199 tests and threw `ReferenceError: require is not defined` on the
 * first call by a real consumer, from 0.0.17 to 0.0.20 (ship run #1,
 * 2026-09-10). The only instrument that can see that class of defect is a
 * separate node process importing dist/, which is what this file is.
 *
 * Builds dist/ if absent (prepublishOnly runs build before test anyway).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const root = path.resolve(__dirname, '../..');
const dist = path.join(root, 'dist', 'index.js');

/** Run an ESM snippet in a fresh node process against dist/; returns stdout, fails loudly on non-zero exit. */
function runAgainstDist(snippet: string, timeoutMs = 15000): string {
  const script = `import * as m from ${JSON.stringify(dist)};\n${snippet}`;
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    cwd: root, encoding: 'utf8', timeout: timeoutMs
  });
  if (r.status !== 0) {
    throw new Error(`dist smoke child exited ${r.status} (signal ${r.signal})\nSTDERR:\n${r.stderr}\nSTDOUT:\n${r.stdout}`);
  }
  return r.stdout;
}

describe('dist/ smoke (published ESM artifact, separate process)', () => {
  beforeAll(() => {
    if (!existsSync(dist)) execFileSync('npm', ['run', 'build'], { cwd: root, stdio: 'inherit' });
  }, 120000);

  it('imports and exposes the documented entry points', () => {
    const out = runAgainstDist(`
      const names = ['SecureMcpServer', 'createSecureHttpHandler', 'createSecureHttpServer', 'createSecureHttpsServer'];
      console.log(JSON.stringify(names.map(n => [n, typeof m[n]])));`);
    expect(JSON.parse(out)).toEqual([
      ['SecureMcpServer', 'function'], ['createSecureHttpHandler', 'function'],
      ['createSecureHttpServer', 'function'], ['createSecureHttpsServer', 'function']
    ]);
  });

  it('createSecureHttpsServer fails on bad PEM, not on `require` (the 0.0.17-0.0.20 defect)', () => {
    // The pre-fix test asserted "throws something containing PEM/key" — which
    // the ReferenceError did not, but vitest's shim hid that. Here the
    // discriminator is explicit: a TLS/PEM error is the correct failure; a
    // ReferenceError means the ESM build cannot execute this function at all.
    const out = runAgainstDist(`
      const server = await m.SecureMcpServer.create({ name: 't', version: '0', securityLevel: 'standard' });
      try {
        m.createSecureHttpsServer(server, { key: 'not-a-key', cert: 'not-a-cert' });
        console.log(JSON.stringify({ threw: false }));
      } catch (e) {
        console.log(JSON.stringify({ threw: true, name: e.constructor.name, message: String(e.message) }));
      }`);
    const r = JSON.parse(out);
    expect(r.threw).toBe(true);
    expect(r.name).not.toBe('ReferenceError');
    expect(r.message).not.toMatch(/require is not defined/);
    expect(r.message).toMatch(/PEM|key|cert/i);
  });

  it('HTTP listener survives a hostile Host header and a null body (ship run #1 AF-001 x2)', () => {
    const out = runAgainstDist(`
      import { request } from 'node:http';
      const server = await m.SecureMcpServer.create({ name: 't', version: '0', securityLevel: 'standard', enableLogging: true, logDir: ${JSON.stringify(mkdtempSync(path.join(tmpdir(), 'mss-log-')))} });
      const http = m.createSecureHttpServer(server, { endpoint: '/mcp' });
      await new Promise(r => http.listen(0, '127.0.0.1', r));
      const port = http.address().port;
      const send = (opts, body) => new Promise((resolve) => {
        const req = request({ host: '127.0.0.1', port, ...opts }, (res) => {
          let data = ''; res.on('data', c => data += c); res.on('end', () => resolve({ status: res.statusCode, data }));
        });
        req.on('error', (e) => resolve({ error: e.code }));
        if (body !== undefined) req.write(body);
        req.end();
      });
      const badHost = await send({ method: 'GET', path: '/mcp', headers: { Host: 'a^b' } });
      const nullBody = await send({ method: 'POST', path: '/mcp', headers: { 'content-type': 'application/json' } }, 'null');
      const afterwards = await send({ method: 'POST', path: '/mcp', headers: { 'content-type': 'application/json' } }, JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' }));
      http.close();
      await server.shutdown?.();
      console.log(JSON.stringify({ badHost, nullBody, afterwards }));`);
    const r = JSON.parse(out);
    // Both requests get a response (any status) instead of killing the process,
    // and the process is still serving afterwards.
    expect(r.badHost.error).toBeUndefined();
    expect(r.nullBody.error).toBeUndefined();
    expect(r.nullBody.status).toBeGreaterThanOrEqual(400);
    expect(r.afterwards.error).toBeUndefined();
    expect(typeof r.afterwards.status).toBe('number');
  });

  it('HTTPS server routes a real TLS request end to end', () => {
    const which = spawnSync('openssl', ['version'], { encoding: 'utf8' });
    if (which.status !== 0) {
      throw new Error('openssl not available — this test needs it to mint an ephemeral cert; install it rather than skipping');
    }
    const dir = mkdtempSync(path.join(tmpdir(), 'mss-tls-'));
    try {
      execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=localhost', '-keyout', path.join(dir, 'k.pem'), '-out', path.join(dir, 'c.pem')], { stdio: 'ignore' });
      const out = runAgainstDist(`
        import { request } from 'node:https';
        import { readFileSync } from 'node:fs';
        const server = await m.SecureMcpServer.create({ name: 't', version: '0', securityLevel: 'standard' });
        const key = readFileSync(${JSON.stringify(path.join(dir, 'k.pem'))});
        const cert = readFileSync(${JSON.stringify(path.join(dir, 'c.pem'))});
        const https = m.createSecureHttpsServer(server, { key, cert, endpoint: '/mcp' });
        await new Promise(r => https.listen(0, '127.0.0.1', r));
        const port = https.address().port;
        const send = (p) => new Promise((resolve) => {
          const req = request({ host: '127.0.0.1', port, path: p, method: 'GET', rejectUnauthorized: false }, (res) => {
            let data = ''; res.on('data', c => data += c); res.on('end', () => resolve({ status: res.statusCode, data }));
          });
          req.on('error', (e) => resolve({ error: e.code })); req.end();
        });
        const notFound = await send('/nope');
        const endpoint = await send('/mcp');
        https.close();
        console.log(JSON.stringify({ notFound, endpoint }));`);
      const r = JSON.parse(out);
      expect(r.notFound.status).toBe(404);
      expect(r.endpoint.error).toBeUndefined();
      expect(r.endpoint.status).not.toBe(404);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
