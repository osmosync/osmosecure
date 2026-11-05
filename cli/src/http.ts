import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { Agent, type Dispatcher } from 'undici';
import { assertPublicUrl, guardedLookup, HttpGuardError, makeGuardedLookup, systemLookup, type AddressResolver, type HostLookup } from './lib/netguard.js';
import type { Logger } from './types.js';

export const DEFAULT_MAX_BYTES = 16 * 1024 * 1024;
const MAX_REDIRECTS = 5;
/** Headers that must not follow a redirect to a different origin. */
const CREDENTIAL_HEADERS = ['authorization', 'apikey', 'x-api-key', 'cookie', 'proxy-authorization'];

export interface HttpGuardConfig {
  /** Allow loopback / private / link-local targets (default false). */
  allowPrivateNetwork?: boolean;
  /** Hostname resolver for the private-address check. Default: system DNS, but only with the real global fetch. */
  lookup?: HostLookup;
  /** Resolver used at connect time by the pinned dispatcher. Default: system DNS. Tests inject a rebinding resolver here. */
  connectResolver?: AddressResolver;
}

let sharedGuardedAgent: Agent | undefined;
/** Agent whose sockets can only dial addresses that passed the private-address check (closes the DNS rebinding gap). */
function guardedAgent(resolver?: AddressResolver): Agent {
  const connect = { lookup: (resolver ? makeGuardedLookup(resolver) : guardedLookup) as never };
  if (resolver) return new Agent({ connect });
  return (sharedGuardedAgent ??= new Agent({ connect }));
}

interface CacheEntry {
  etag?: string;
  lastModified?: string;
  body: string;
  fetchedAt: string;
}

export interface HttpOptions {
  headers?: Record<string, string>;
  /** minimum ms between requests to the same host */
  minIntervalMs?: number;
  timeoutMs?: number;
  /** use ETag / If-Modified-Since cache */
  cache?: boolean;
  /** hard cap on the response body (default 16 MiB) */
  maxBytes?: number;
  /** When set, the request URL and every redirect hop must be on one of these exact hostnames. */
  allowedHosts?: string[];
}

export interface HttpResult {
  status: number;
  body: string;
  notModified: boolean;
  /** lowercased Content-Type header, empty when absent or served from cache */
  contentType: string;
}

export type FetchLike = typeof fetch;

/** Polite fetch: user agent, per-host spacing, ETag cache, 429/5xx backoff, hard timeout. */
export class HttpClient {
  private cache: Record<string, CacheEntry> = {};
  private readonly cacheFile?: string;
  private readonly lastHit = new Map<string, number>();
  private readonly lookup?: HostLookup;
  private readonly dispatcher?: Dispatcher;

  constructor(
    private readonly userAgent: string,
    private readonly log: Logger,
    cacheDir?: string,
    private readonly fetchImpl: FetchLike = fetch,
    private readonly sleep: (ms: number) => Promise<void> = (ms) => new Promise((r) => setTimeout(r, ms)),
    private readonly guard: HttpGuardConfig = {},
  ) {
    this.lookup = guard.lookup ?? (fetchImpl === globalThis.fetch ? systemLookup : undefined);
    // Pin connections only for the real global fetch. An injected fetchImpl (tests) bypasses the pin, so production
    // code must never pass one: run.ts constructs HttpClient without fetchImpl. The assertPublicUrl pre-check still
    // runs on injected paths but is a fast fail, not the boundary.
    if (fetchImpl === globalThis.fetch && !guard.allowPrivateNetwork) this.dispatcher = guardedAgent(guard.connectResolver);
    if (cacheDir) {
      mkdirSync(cacheDir, { recursive: true });
      this.cacheFile = path.join(cacheDir, 'http-cache.json');
      if (existsSync(this.cacheFile)) {
        try {
          this.cache = JSON.parse(readFileSync(this.cacheFile, 'utf8'));
        } catch {
          this.cache = {};
        }
      }
    }
  }

  persist(): void {
    if (!this.cacheFile) return;
    const tmp = `${this.cacheFile}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.cache), { mode: 0o600 });
    renameSync(tmp, this.cacheFile);
  }

  private async throttle(host: string, minIntervalMs: number): Promise<void> {
    const last = this.lastHit.get(host) ?? 0;
    const wait = last + minIntervalMs - Date.now();
    if (wait > 0) await this.sleep(wait);
    this.lastHit.set(host, Date.now());
  }

  /** Follows redirects by hand so every hop is checked against the private-address policy. */
  private async fetchGuarded(url: string, init: RequestInit, headers: Record<string, string>, signal: AbortSignal, allowedHosts?: string[]): Promise<Response> {
    let cur = url;
    let method = init.method ?? 'GET';
    let body = init.body;
    let hdrs = headers;
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      if (allowedHosts && !allowedHosts.includes(new URL(cur).hostname.toLowerCase())) throw new HttpGuardError(`host ${new URL(cur).hostname} is not on the allowlist for this request`);
      await assertPublicUrl(cur, { allowPrivate: this.guard.allowPrivateNetwork, lookup: this.lookup });
      const res = await this.fetchImpl(cur, { ...init, method, body, headers: hdrs, redirect: 'manual', signal, ...(this.dispatcher ? { dispatcher: this.dispatcher } : {}) } as RequestInit);
      const loc = res.status >= 300 && res.status < 400 && res.status !== 304 ? res.headers.get('location') : null;
      if (!loc) return res;
      await res.body?.cancel().catch(() => undefined);
      let next: URL;
      try {
        next = new URL(loc, cur);
      } catch {
        throw new HttpGuardError('redirect to an invalid url');
      }
      if (next.origin !== new URL(cur).origin) {
        hdrs = Object.fromEntries(Object.entries(hdrs).filter(([k]) => !CREDENTIAL_HEADERS.includes(k.toLowerCase())));
      }
      if (res.status !== 307 && res.status !== 308) {
        method = 'GET';
        body = undefined;
      }
      cur = next.href;
    }
    throw new HttpGuardError(`too many redirects (more than ${MAX_REDIRECTS})`);
  }

  async request(url: string, init: RequestInit = {}, opts: HttpOptions = {}): Promise<HttpResult> {
    const host = new URL(url).host;
    const cacheKey = `${init.method ?? 'GET'} ${url}`;
    const useCache = opts.cache && (init.method ?? 'GET') === 'GET';
    const cached = useCache ? this.cache[cacheKey] : undefined;
    const headers: Record<string, string> = {
      'user-agent': this.userAgent,
      accept: 'application/json, application/xml;q=0.9, */*;q=0.5',
      ...(opts.headers ?? {}),
    };
    if (cached?.etag) headers['if-none-match'] = cached.etag;
    else if (cached?.lastModified) headers['if-modified-since'] = cached.lastModified;

    let lastErr: unknown;
    for (let attempt = 0; attempt < 3; attempt++) {
      await this.throttle(host, opts.minIntervalMs ?? 1000);
      try {
        const signal = AbortSignal.timeout(opts.timeoutMs ?? 30_000);
        const res = await this.fetchGuarded(url, init, { ...headers, ...(init.headers as Record<string, string> | undefined) }, signal, opts.allowedHosts);
        if (res.status === 304 && cached) return { status: 200, body: cached.body, notModified: true, contentType: '' };
        if (res.status === 429 || res.status >= 500) {
          const retryAfter = Number(res.headers.get('retry-after'));
          const backoff = Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : 2000 * 2 ** attempt;
          this.log.warn('http backoff', { host, status: res.status, backoffMs: backoff });
          await res.body?.cancel().catch(() => undefined);
          lastErr = new Error(`HTTP ${res.status} from ${host}`);
          await this.sleep(Math.min(backoff, 60_000));
          continue;
        }
        const body = await readCapped(res, opts.maxBytes ?? DEFAULT_MAX_BYTES, host);
        if (res.ok && useCache) {
          this.cache[cacheKey] = {
            etag: res.headers.get('etag') ?? undefined,
            lastModified: res.headers.get('last-modified') ?? undefined,
            body,
            fetchedAt: new Date().toISOString(),
          };
        }
        return { status: res.status, body, notModified: false, contentType: (res.headers.get('content-type') ?? '').toLowerCase() };
      } catch (err) {
        // fetch wraps connect-time lookup failures as TypeError('fetch failed') with the guard error as cause
        const guardErr = err instanceof HttpGuardError ? err : (err as { cause?: unknown })?.cause instanceof HttpGuardError ? ((err as { cause: HttpGuardError }).cause) : undefined;
        if (guardErr) throw new Error(`request blocked for ${host}: ${guardErr.message}`);
        lastErr = err;
        await this.sleep(1000 * 2 ** attempt);
      }
    }
    throw new Error(`request failed for ${host}: ${lastErr instanceof Error ? lastErr.message : String(lastErr)}`);
  }

  async json<T>(url: string, init: RequestInit = {}, opts: HttpOptions = {}): Promise<{ data: T; notModified: boolean }> {
    const res = await this.request(url, init, opts);
    if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status} for ${new URL(url).host}${new URL(url).pathname}`);
    return { data: JSON.parse(res.body) as T, notModified: res.notModified };
  }
}

/** Reads a response body as UTF-8 text, aborting once it exceeds maxBytes (also checks Content-Length up front). */
export async function readCapped(res: Response, maxBytes: number, host = 'response'): Promise<string> {
  const declared = Number(res.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) {
    await res.body?.cancel().catch(() => undefined);
    throw new HttpGuardError(`response from ${host} exceeds ${maxBytes} bytes`);
  }
  if (!res.body) {
    const text = await res.text();
    if (Buffer.byteLength(text) > maxBytes) throw new HttpGuardError(`response from ${host} exceeds ${maxBytes} bytes`);
    return text;
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder('utf-8');
  let total = 0;
  let out = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined);
      throw new HttpGuardError(`response from ${host} exceeds ${maxBytes} bytes`);
    }
    out += decoder.decode(value, { stream: true });
  }
  return out + decoder.decode();
}
