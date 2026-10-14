#!/usr/bin/env node
/**
 * Run the typecheck and the full test suite against the latest published 1.x of
 * @modelcontextprotocol/sdk, in a scratch copy, so this checkout's node_modules and
 * lockfile are never touched.
 *
 * Why: the HTTP session registry relies on the SDK's stateful transport and its handle
 * internals. `npm test` runs against the locked version (the floor in package.json);
 * this runs against the newest version a consumer's `^` range can resolve. The repo has
 * no CI, so this script is the matrix's second column (spec http-transport-per-session,
 * Phase 4). Pass a version to test another one: `npm run test:sdk-latest -- 1.31.0`.
 */
import { execFileSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const run = (cmd, args, cwd, capture = false) =>
  execFileSync(cmd, args, { cwd, stdio: capture ? ['ignore', 'pipe', 'inherit'] : 'inherit', encoding: 'utf8' });

const requested = process.argv[2];
const versions = JSON.parse(run('npm', ['view', '@modelcontextprotocol/sdk', 'versions', '--json'], root, true));
const latest1x = versions.filter(v => /^1\.\d+\.\d+$/.test(v)).at(-1);
const version = requested ?? latest1x;
if (!version || !versions.includes(version)) {
  console.error(`No published @modelcontextprotocol/sdk version ${requested ?? '1.x'}`);
  process.exit(1);
}

const skip = new Set(['node_modules', 'cookbook', 'dist', '.git', '.probes', 'coverage', 'logs']);
const copy = mkdtempSync(path.join(tmpdir(), 'mss-sdk-'));
try {
  cpSync(root, copy, { recursive: true, filter: src => !skip.has(path.basename(src)) || src === root });
  run('npm', ['ci', '--no-audit', '--no-fund', '--silent'], copy);
  run('npm', ['install', '--no-save', '--no-audit', '--no-fund', '--silent', `@modelcontextprotocol/sdk@${version}`], copy);
  // The SDK's exports map hides package.json from require(); read the file itself.
  const installed = JSON.parse(readFileSync(path.join(copy, 'node_modules/@modelcontextprotocol/sdk/package.json'), 'utf8')).version;
  if (installed !== version) throw new Error(`expected SDK ${version} in the copy, found ${installed}`);
  console.log(`\n@modelcontextprotocol/sdk ${installed}: typecheck, then the full suite\n`);
  run('npx', ['tsc', '--noEmit'], copy);
  run('npx', ['vitest', 'run'], copy);
} finally {
  rmSync(copy, { recursive: true, force: true });
}
