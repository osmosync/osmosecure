import { createServer, type IncomingHttpHeaders, type Server } from 'node:http';
import type { Config } from './config.js';
import { resolveDataDir } from './config.js';
import { verifySignature } from './remediate.js';
import { StateStore } from './state.js';
import type { Logger } from './types.js';

/**
 * Optional receiver for the signed osmosecure.remediation.v1 requests. The request only SELECTS a
 * finding by its fingerprint; every field the fixer acts on is read from local state, never from the
 * request body, so a forged-but-signed or tampered body cannot steer what gets bumped.
 * The server can only start a fix (which stops at awaiting-approval). It cannot approve or publish.
 */

export const MAX_BODY_BYTES = 64 * 1024;
const MAX_QUEUE = 5;
export const MIN_SECRET_CHARS = 16;
const LOOPBACK_HOSTS = ['127.0.0.1', '::1', 'localhost'];

/** The receiver is loopback only; remote senders go through a TLS reverse proxy on the same machine. */
export function assertLoopbackHost(host: string): void {
  if (!LOOPBACK_HOSTS.includes(host)) throw new Error('fix.server.host must be loopback (127.0.0.1, ::1 or localhost); put a TLS reverse proxy in front for remote senders');
}

/** Finding keys are advisory|project|eco:name@version strings from local state: bounded, printable, no control characters. */
export function isValidFindingKey(key: string): boolean {
  return key.length >= 1 && key.length <= 400 && !/[\u0000-\u001f\u007f]/.test(key);
}

export interface HandlerDeps {
  secret: string;
  windowSeconds: number;
  hasFinding: (key: string) => boolean;
  enqueue: (key: string) => boolean;
  now?: () => Date;
  /** signature -> first seen epoch seconds; rejects replays inside the window. */
  seen?: Map<string, number>;
}

export interface HandlerResult {
  status: number;
  body: Record<string, unknown>;
}

export function handleFixRequest(
  req: { method: string; url: string; headers: IncomingHttpHeaders; body: string },
  deps: HandlerDeps,
): HandlerResult {
  if (req.url !== '/fix') return { status: 404, body: { error: 'not found' } };
  if (req.method !== 'POST') return { status: 405, body: { error: 'method not allowed' } };
  const at = deps.now ? deps.now() : new Date();
  const ts = req.headers['x-osmosecure-timestamp'];
  const sig = req.headers['x-osmosecure-signature'];
  const v = verifySignature(req.body, deps.secret, typeof ts === 'string' ? ts : undefined, typeof sig === 'string' ? sig : undefined, at, deps.windowSeconds);
  if (!v.ok) return { status: 401, body: { error: 'unauthorized' } }; // reason deliberately not echoed
  if (deps.seen) {
    const nowS = at.getTime() / 1000;
    for (const [k, t] of deps.seen) if (nowS - t > deps.windowSeconds * 2) deps.seen.delete(k);
    if (deps.seen.has(sig as string)) return { status: 409, body: { error: 'replay' } };
    deps.seen.set(sig as string, nowS);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(req.body);
  } catch {
    return { status: 400, body: { error: 'invalid json' } };
  }
  const o = parsed as { schema?: unknown; fingerprint?: unknown };
  if (!o || o.schema !== 'osmosecure.remediation.v1' || typeof o.fingerprint !== 'string' || !o.fingerprint.startsWith('osmosecure-')) {
    return { status: 422, body: { error: 'unsupported request' } };
  }
  const key = o.fingerprint.slice('osmosecure-'.length);
  if (!isValidFindingKey(key)) return { status: 422, body: { error: 'unsupported request' } };
  if (!deps.hasFinding(key)) return { status: 422, body: { error: 'unknown finding' } };
  if (!deps.enqueue(key)) return { status: 429, body: { error: 'queue full' } };
  return { status: 202, body: { accepted: true } };
}

/** Serial in-process queue; each job is a startFix call that stops at awaiting-approval. */
export function startFixServer(config: Config, secret: string, runFix: (key: string) => Promise<unknown>, log: Logger): Server {
  if (secret.length < MIN_SECRET_CHARS) throw new Error(`the hook secret must be at least ${MIN_SECRET_CHARS} characters`);
  assertLoopbackHost(config.fix.server.host);
  const queue: string[] = [];
  let busy = false;
  const pump = async () => {
    if (busy) return;
    busy = true;
    while (queue.length) {
      const key = queue.shift() as string;
      try {
        await runFix(key);
      } catch (err) {
        log.warn('fix job refused', { error: err instanceof Error ? err.message : String(err) });
      }
    }
    busy = false;
  };
  const seen = new Map<string, number>();
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let tooBig = false;
    let replied = false;
    const reply = (out: HandlerResult, dropRequest = false) => {
      if (replied) return;
      replied = true;
      res.writeHead(out.status, { 'content-type': 'application/json', connection: 'close' });
      res.end(JSON.stringify(out.body), () => {
        if (dropRequest) req.destroy(); // stop reading an oversize upload once the 413 is flushed
      });
    };
    const declared = Number(req.headers['content-length']);
    if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
      reply({ status: 413, body: { error: 'too large' } }, true);
      return;
    }
    req.on('error', () => undefined);
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        tooBig = true;
        chunks.length = 0;
        reply({ status: 413, body: { error: 'too large' } }, true); // chunked bodies carry no length up front: stop reading at the cap
      } else if (!tooBig) chunks.push(c);
    });
    req.on('end', () => {
      let out: HandlerResult;
      try {
        out = handleFixRequest(
          { method: req.method ?? '', url: req.url ?? '', headers: req.headers, body: Buffer.concat(chunks).toString('utf8') },
          {
            secret,
            windowSeconds: config.fix.server.timestampWindowSeconds,
            seen,
            hasFinding: (k) => Object.hasOwn(new StateStore(resolveDataDir(config)).state.findings, k),
            enqueue: (k) => {
              if (queue.length >= MAX_QUEUE) return false;
              queue.push(k);
              void pump();
              return true;
            },
          },
        );
      } catch (err) {
        log.warn('fix request failed', { error: err instanceof Error ? err.message : String(err) });
        out = { status: 500, body: { error: 'internal error' } };
      }
      reply(out);
    });
  });
  server.headersTimeout = 10_000;
  server.requestTimeout = 15_000;
  return server;
}
