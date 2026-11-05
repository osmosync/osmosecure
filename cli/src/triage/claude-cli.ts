import { spawn as nodeSpawn, type ChildProcess, type SpawnOptions } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { TriageClient } from './llm.js';

export type SpawnFn = (cmd: string, args: string[], opts: SpawnOptions) => ChildProcess;

export const DEFAULT_CLI_MODEL = 'sonnet';

/**
 * Only these variables reach the child. Subscription auth lives in ~/.claude (found via HOME) or in
 * CLAUDE_CODE_OAUTH_TOKEN. ANTHROPIC_API_KEY and every other secret in our env are deliberately dropped.
 */
const ENV_ALLOWLIST = ['PATH', 'HOME', 'USER', 'LOGNAME', 'LANG', 'LC_ALL', 'TMPDIR', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'CLAUDE_CONFIG_DIR', 'CLAUDE_CODE_OAUTH_TOKEN'];

export function scrubbedEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  for (const k of ENV_ALLOWLIST) if (env[k] !== undefined) out[k] = env[k];
  out.DISABLE_TELEMETRY = '1';
  out.CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = '1';
  return out;
}

export interface ClaudeCliOptions {
  model: string;
  timeoutMs: number;
  /** Max concurrent child processes (1 to 2). */
  concurrency: number;
  bin?: string;
  env?: NodeJS.ProcessEnv;
  spawnFn?: SpawnFn;
}

/** Pulls the model reply text out of `claude -p --output-format json` stdout. */
export function parseCliOutput(stdout: string): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new Error('claude cli: stdout is not JSON');
  }
  // Newer CLIs may emit an array of events; the final one is type "result".
  const obj = (Array.isArray(parsed) ? [...parsed].reverse().find((e) => (e as { type?: string })?.type === 'result') : parsed) as
    | { is_error?: boolean; subtype?: string; result?: unknown }
    | undefined;
  if (!obj || typeof obj !== 'object') throw new Error('claude cli: no result object');
  if (obj.is_error) throw new Error(`claude cli: error result (${String(obj.subtype ?? 'unknown')})`);
  if (typeof obj.result !== 'string' || !obj.result.trim()) throw new Error('claude cli: empty result');
  return obj.result;
}

/**
 * Triage through the user's Claude subscription via headless `claude -p`. No tools, one turn,
 * prompt on stdin, scrubbed env, empty temp cwd, hard timeout, bounded concurrency.
 */
export class ClaudeCliTriageClient implements TriageClient {
  private active = 0;
  private readonly waiters: (() => void)[] = [];
  private readonly max: number;
  private readonly spawnFn: SpawnFn;

  constructor(private readonly opts: ClaudeCliOptions) {
    this.max = Math.min(2, Math.max(1, Math.floor(opts.concurrency)));
    this.spawnFn = opts.spawnFn ?? (nodeSpawn as SpawnFn);
  }

  private async acquire(): Promise<void> {
    if (this.active < this.max) {
      this.active++;
      return;
    }
    await new Promise<void>((resolve) => this.waiters.push(resolve));
  }

  private release(): void {
    const next = this.waiters.shift();
    if (next) next(); // slot is handed over; active count unchanged
    else this.active--;
  }

  async complete(system: string, user: string): Promise<string> {
    await this.acquire();
    try {
      return parseCliOutput(await this.run(system, user));
    } finally {
      this.release();
    }
  }

  buildArgs(system: string): string[] {
    return [
      '-p',
      '--output-format', 'json',
      '--tools', '',
      '--model', this.opts.model,
      '--system-prompt', system,
      '--no-session-persistence',
      '--disable-slash-commands',
      '--strict-mcp-config',
    ];
  }

  private run(system: string, user: string): Promise<string> {
    const cwd = mkdtempSync(path.join(tmpdir(), 'osmosecure-triage-'));
    return new Promise<string>((resolve, reject) => {
      let settled = false;
      const done = (err: Error | null, out?: string) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try {
          rmSync(cwd, { recursive: true, force: true });
        } catch {
          /* best effort */
        }
        if (err) reject(err);
        else resolve(out ?? '');
      };
      let child: ChildProcess;
      try {
        child = this.spawnFn(this.opts.bin ?? 'claude', this.buildArgs(system), {
          cwd,
          env: scrubbedEnv(this.opts.env ?? process.env),
          stdio: ['pipe', 'pipe', 'pipe'],
        });
      } catch (err) {
        done(err instanceof Error ? err : new Error(String(err)));
        return;
      }
      const timer = setTimeout(() => {
        child.kill('SIGKILL');
        done(new Error(`claude cli: timed out after ${this.opts.timeoutMs}ms`));
      }, this.opts.timeoutMs);
      let stdout = '';
      let stderrLen = 0;
      child.stdout?.on('data', (d: Buffer | string) => {
        stdout += d.toString();
        if (stdout.length > 2_000_000) {
          child.kill('SIGKILL');
          done(new Error('claude cli: output too large'));
        }
      });
      child.stderr?.on('data', (d: Buffer | string) => {
        stderrLen += d.length; // content not retained: it can echo prompt text
      });
      child.on('error', (err) => done(err));
      child.on('close', (code) => {
        if (code === 0) done(null, stdout);
        else done(new Error(`claude cli: exit ${code} (stderr ${stderrLen} bytes)`));
      });
      child.stdin?.on('error', () => undefined);
      child.stdin?.end(user);
    });
  }
}
