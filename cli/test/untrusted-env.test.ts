import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, realpathSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

const CLI = new URL('../src/cli.ts', import.meta.url).pathname;
const TSX = new URL('../node_modules/tsx/dist/loader.mjs', import.meta.url).pathname;

function setup() {
  const base = realpathSync(mkdtempSync(path.join(tmpdir(), 'osmosecure-env-')));
  const cfg = path.join(base, 'cfg');
  const cwd = path.join(base, 'untrusted');
  mkdirSync(cfg);
  mkdirSync(cwd);
  writeFileSync(path.join(cfg, 'osmosecure.config.json'), '{"projects":[]}\n');
  writeFileSync(path.join(base, 'in.txt'), 'some advisory text\n');
  const module = path.join(cwd, 'x.mjs');
  writeFileSync(module, `import fs from 'node:fs';fs.writeFileSync(${JSON.stringify(path.join(cwd, 'pwned'))}, '1');export default () => ({ complete: async () => '{}' });\n`);
  const run = (): string => {
    try {
      return execFileSync('node', ['--import', TSX, CLI, 'triage', path.join(base, 'in.txt'), '--config', path.join(cfg, 'osmosecure.config.json')], {
        cwd,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: 60_000,
        env: { PATH: process.env.PATH ?? '', HOME: base, CLAUDE_BIN: '/nonexistent' },
      });
    } catch (e) {
      const x = e as { stdout?: string; stderr?: string };
      return `${x.stdout ?? ''}${x.stderr ?? ''}`;
    }
  };
  return { cfg, cwd, module, run };
}

test('a .env in the current directory is not loaded', () => {
  const s = setup();
  writeFileSync(path.join(s.cwd, '.env'), `TRIAGE_BACKEND=module:${s.module}\n`);
  const out = s.run();
  assert.ok(!existsSync(path.join(s.cwd, 'pwned')), 'untrusted module was executed');
  assert.ok(!/from the environment/.test(out), `cwd .env reached the environment: ${out}`);
});

test('a .env in the config directory is still loaded, but cannot select a module backend', () => {
  const s = setup();
  writeFileSync(path.join(s.cfg, '.env'), `TRIAGE_BACKEND=module:${s.module}\n`);
  const out = s.run();
  assert.match(out, /cannot load a module from the environment/);
  assert.ok(!existsSync(path.join(s.cwd, 'pwned')), 'module was executed');
});

test('a config found by default in the current directory cannot run a module backend', () => {
  const s = setup();
  writeFileSync(path.join(s.cwd, 'osmosecure.config.json'), JSON.stringify({ projects: [], triage: { backend: `module:${s.module}` } }));
  let out = '';
  try {
    out = execFileSync('node', ['--import', TSX, CLI, 'triage', path.join(path.dirname(s.cfg), 'in.txt')], {
      cwd: s.cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 60_000,
      env: { PATH: process.env.PATH ?? '', HOME: path.dirname(s.cfg), CLAUDE_BIN: '/nonexistent' },
    });
  } catch (e) {
    const x = e as { stdout?: string; stderr?: string };
    out = `${x.stdout ?? ''}${x.stderr ?? ''}`;
  }
  assert.match(out, /refused when the config was found in the current directory/);
  assert.ok(!existsSync(path.join(s.cwd, 'pwned')), 'module from an implicit cwd config was executed');
});

test('a config found by default in the current directory cannot run the fixer or go live', () => {
  const s = setup();
  writeFileSync(path.join(s.cwd, 'osmosecure.config.json'), JSON.stringify({ projects: [], fix: { testCommand: ['node', s.module] } }));
  const run = (args: string[]): string => {
    try {
      return execFileSync('node', ['--import', TSX, CLI, ...args], { cwd: s.cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 60_000, env: { PATH: process.env.PATH ?? '', HOME: path.dirname(s.cfg) } });
    } catch (e) {
      const x = e as { stdout?: string; stderr?: string };
      return `${x.stdout ?? ''}${x.stderr ?? ''}`;
    }
  };
  assert.match(run(['fix', '--list']), /refused when the config was found in the current directory/);
  assert.match(run(['watch', '--once', '--remediate-live']), /refused when the config was found in the current directory/);
  assert.ok(!existsSync(path.join(s.cwd, 'pwned')), 'a command from an implicit cwd config ran');
});
