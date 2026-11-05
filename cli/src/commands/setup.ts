import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { z } from 'zod';
import { CONFIG_FILENAME } from '../config.js';

export const SETUP_PATH = '/api/v1/setup/exchange';
const MAX_RESPONSE_BYTES = 64 * 1024;
const TIMEOUT_MS = 15_000;

export class SetupRefusal extends Error {}

export interface SetupOptions {
  code?: string;
  server?: string;
  dir: string;
  force: boolean;
  allowPropose: boolean;
}

export interface SetupIo {
  out: (line: string) => void;
  err: (line: string) => void;
}

const channelNotifier = z.discriminatedUnion('type', [
  z.object({ type: z.literal('stdout') }).strict(),
  z.object({ type: z.literal('slack') }).strict(),
  z.object({ type: z.literal('telegram') }).strict(),
]);

/** Strict on purpose: any field we do not know about (an apiKey, a token) fails validation. */
const exchangeSchema = z
  .object({
    config: z
      .object({
        schemaVersion: z.literal(1),
        projects: z.array(z.object({ id: z.string().min(1), root: z.string().min(1) }).strict()),
        notify: z.object({ notifiers: z.array(channelNotifier) }).strict(),
        accessLevel: z.number().int(),
        /** Sent by older servers; accepted and ignored. */
        openPullRequests: z.boolean().optional(),
      })
      .strict(),
  })
  .strict();

const SECRET_KEY = /(api[-_]?key|secret|token|password|passwd|credential|authorization|private[-_]?key|bearer|webhook[-_]?url)/i;
const SECRET_VALUE = /(osc_[0-9a-f]{16,}|xox[abprs]-[\w-]{8,}|sk-[\w-]{16,}|\d{6,}:[\w-]{25,}|-----BEGIN [A-Z ]*PRIVATE KEY|hooks\.slack\.com\/services\/)/;

/** Returns the JSON path of the first secret-looking key or value, or null. Never returns the value itself. */
export function findSecretLike(v: unknown, at = '$', depth = 0): string | null {
  if (depth > 12) return at;
  if (typeof v === 'string') return SECRET_VALUE.test(v) ? at : null;
  if (Array.isArray(v)) {
    for (let i = 0; i < v.length; i++) {
      const hit = findSecretLike(v[i], `${at}[${i}]`, depth + 1);
      if (hit) return hit;
    }
    return null;
  }
  if (v && typeof v === 'object') {
    for (const [k, child] of Object.entries(v)) {
      if (SECRET_KEY.test(k)) return `${at}.${k}`;
      const hit = findSecretLike(child, `${at}.${k}`, depth + 1);
      if (hit) return hit;
    }
  }
  return null;
}

/** https only; plain http is allowed for loopback development hosts. */
export function validateServer(raw: string): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new SetupRefusal('--server is not a valid URL');
  }
  if (u.username || u.password) throw new SetupRefusal('--server must not contain credentials');
  const localHttp = u.protocol === 'http:' && (u.hostname === '127.0.0.1' || u.hostname === 'localhost');
  if (u.protocol !== 'https:' && !localHttp) {
    throw new SetupRefusal('--server must be https (http is allowed only for 127.0.0.1 or localhost)');
  }
  return u;
}

const ENV_FOR: Record<string, string[]> = {
  slack: ['SLACK_WEBHOOK_URL'],
  telegram: ['TELEGRAM_BOT_TOKEN', 'TELEGRAM_CHAT_ID'],
};

function gitignoreMissing(dir: string): string[] {
  const file = path.join(dir, '.gitignore');
  if (!existsSync(file)) return [];
  const lines = new Set(readFileSync(file, 'utf8').split(/\r?\n/).map((l) => l.trim()));
  const has = (...names: string[]) => names.some((n) => lines.has(n));
  const missing: string[] = [];
  if (!has('.osmosecure', '.osmosecure/', '/.osmosecure', '/.osmosecure/', '.osmosecure/*')) missing.push('.osmosecure/');
  if (!has('.env', '/.env', '.env*', '.env.*')) missing.push('.env');
  return missing;
}

export async function runSetup(opts: SetupOptions, io: SetupIo, fetchImpl: typeof fetch = fetch): Promise<number> {
  try {
    const code = opts.code?.trim();
    if (!code) throw new SetupRefusal('--code is required');
    const serverRaw = opts.server ?? process.env.OSMOSECURE_SERVER;
    if (!serverRaw) throw new SetupRefusal('--server is required (or set OSMOSECURE_SERVER)');
    const server = validateServer(serverRaw);

    const dir = path.resolve(opts.dir);
    const target = path.join(dir, CONFIG_FILENAME);
    if (existsSync(target) && !opts.force) {
      throw new SetupRefusal(`${CONFIG_FILENAME} already exists in ${dir}; use --force to overwrite (the setup code was not used)`);
    }

    const url = `${server.origin}${server.pathname.replace(/\/+$/, '')}${SETUP_PATH}`;
    let res: Response;
    try {
      res = await fetchImpl(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({ code }),
        redirect: 'error',
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch {
      throw new SetupRefusal('could not reach the setup server');
    }
    if (!res.ok) {
      throw new SetupRefusal(
        res.status === 429 ? 'too many attempts; wait and try again' : `setup code was not accepted (HTTP ${res.status}); it may be invalid, used or expired`,
      );
    }
    const text = await res.text();
    if (text.length > MAX_RESPONSE_BYTES) throw new SetupRefusal('setup response is too large');
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      throw new SetupRefusal('setup response was not valid JSON');
    }

    const leak = findSecretLike(body);
    if (leak) throw new SetupRefusal(`setup response contains a secret-looking field at ${leak}; refusing to write anything`);

    const parsed = exchangeSchema.safeParse(body);
    if (!parsed.success) {
      const where = [...new Set(parsed.error.issues.map((i) => ['$', ...i.path.map(String)].join('.')))].slice(0, 5).join(', ');
      throw new SetupRefusal(`setup response failed validation at ${where}`);
    }
    const resp = parsed.data.config;

    const level = resp.accessLevel;
    if (level !== 1 && level !== 2 && level !== 3) throw new SetupRefusal(`access level ${level} is not supported; refusing`);
    if (level === 3 && !opts.allowPropose) {
      throw new SetupRefusal('access level 3 (propose fixes) needs the explicit --allow-propose flag; nothing was written');
    }

    const notifiers: Record<string, unknown>[] = [{ type: 'stdout' }];
    const envNames: string[] = [];
    if (level >= 2) {
      const seen = new Set<string>();
      for (const n of resp.notify.notifiers) {
        if (n.type === 'stdout' || seen.has(n.type)) continue;
        seen.add(n.type);
        if (n.type === 'slack') notifiers.push({ type: 'slack', urlEnv: 'SLACK_WEBHOOK_URL' });
        else notifiers.push({ type: 'telegram', tokenEnv: 'TELEGRAM_BOT_TOKEN', chatIdEnv: 'TELEGRAM_CHAT_ID' });
        envNames.push(...ENV_FOR[n.type]);
      }
    }

    const config: Record<string, unknown> = {
      schemaVersion: 1,
      dataDir: '.osmosecure',
      accessLevel: level,
      projects: resp.projects.map((p) => ({ id: p.id, root: p.root })),
      notify: { notifiers },
    };
    if (level === 3) config.allowPropose = true;

    mkdirSync(dir, { recursive: true });
    try {
      writeFileSync(target, `${JSON.stringify(config, null, 2)}\n`, { flag: opts.force ? 'w' : 'wx', mode: 0o600 });
    } catch {
      throw new SetupRefusal(`could not write ${target}`);
    }

    io.out(`wrote ${target} (access level ${level}, ${resp.projects.length} project${resp.projects.length === 1 ? '' : 's'})`);
    if (envNames.length) {
      io.out('set these environment variables yourself (names only, values are never sent or stored):');
      for (const n of envNames) io.out(`  ${n}`);
    } else {
      io.out('no environment variables are needed at this access level');
    }
    const missing = gitignoreMissing(dir);
    if (missing.length) {
      io.out(`your .gitignore in ${dir} is missing these lines; add them:`);
      for (const m of missing) io.out(`  ${m}`);
    }
    return 0;
  } catch (err) {
    if (err instanceof SetupRefusal) {
      io.err(`refused: ${err.message}`);
      return 1;
    }
    io.err('setup failed');
    return 1;
  }
}
