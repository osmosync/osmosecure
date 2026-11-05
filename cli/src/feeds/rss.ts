import type { FeedItem } from '../types.js';
import { extractCves, type FeedContext, type FeedResult } from './types.js';

const ENTITIES: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };

/** Feeds are small; anything larger is truncated before parsing so one feed cannot dominate a run. */
export const MAX_FEED_CHARS = 2_000_000;
const MAX_BLOCK_CHARS = 100_000;
const MAX_FIELD_CHARS = 20_000;

function codePoint(n: number): string {
  return Number.isInteger(n) && n > 0 && n <= 0x10ffff && !(n >= 0xd800 && n <= 0xdfff) ? String.fromCodePoint(n) : '';
}

function decode(s: string): string {
  return s
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/&#x([0-9a-f]{1,8});/gi, (_, h: string) => codePoint(Number.parseInt(h, 16)))
    .replace(/&#(\d{1,8});/g, (_, d: string) => codePoint(Number.parseInt(d, 10)))
    .replace(/&([a-z]+);/gi, (m, n: string) => ENTITIES[n.toLowerCase()] ?? m);
}

// `<[^<>]*>` cannot rescan past the next `<`, so a run of unterminated tags stays linear.
function stripTags(s: string): string {
  return decode(decode(s.slice(0, MAX_FIELD_CHARS)).replace(/<[^<>]*>/g, ' ')).replace(/\s+/g, ' ').trim();
}

/** Body of the first <name ...>...</name> in a block, found with indexOf so unclosed tags cannot cause quadratic regex scans. */
function tag(block: string, lower: string, names: string[]): string | undefined {
  for (const n of names) {
    let from = 0;
    for (;;) {
      const open = lower.indexOf(`<${n}`, from);
      if (open < 0) break;
      const after = lower[open + n.length + 1];
      from = open + 1;
      if (after !== '>' && after !== ' ' && after !== '\t' && after !== '\n' && after !== '\r') continue;
      const gt = lower.indexOf('>', open);
      if (gt < 0) break;
      const close = lower.indexOf(`</${n}>`, gt);
      if (close < 0) break; // no closing tag after this one means none after any later one either
      return block.slice(gt + 1, close);
    }
  }
  return undefined;
}

/** Only http(s) links survive; javascript:, data: and the like are dropped before they reach a notification. */
function safeUrl(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  try {
    const u = new URL(raw.trim());
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.href.slice(0, 500) : undefined;
  } catch {
    return undefined;
  }
}

function hrefLink(block: string, lower: string): string | undefined {
  let from = 0;
  for (let i = 0; i < 20; i++) {
    const open = lower.indexOf('<link', from);
    if (open < 0) return undefined;
    from = open + 1;
    const gt = lower.indexOf('>', open);
    if (gt < 0) return undefined;
    const m = /href=["']([^"']+)["']/i.exec(block.slice(open, gt));
    if (m) return m[1];
  }
  return undefined;
}

/** Splits <item>/<entry> elements with indexOf (linear). */
function blocksOf(xml: string, max: number): string[] {
  const lower = xml.toLowerCase();
  const out: string[] = [];
  let from = 0;
  while (out.length < max) {
    const a = lower.indexOf('<item', from);
    const b = lower.indexOf('<entry', from);
    const open = a < 0 ? b : b < 0 ? a : Math.min(a, b);
    if (open < 0) break;
    const name = open === a ? 'item' : 'entry';
    const after = lower[open + name.length + 1];
    from = open + 1;
    if (after !== '>' && after !== ' ' && after !== '\t' && after !== '\n' && after !== '\r') continue;
    const gt = lower.indexOf('>', open);
    if (gt < 0) break;
    const close = lower.indexOf(`</${name}>`, gt);
    if (close < 0) break; // an unclosed item cannot be followed by a closed one
    out.push(xml.slice(gt + 1, Math.min(close, gt + 1 + MAX_BLOCK_CHARS)));
    from = close + 1;
  }
  return out;
}

/** Throws on any DOCTYPE or ENTITY declaration: feeds have no use for them and they are the vector for entity-expansion attacks. */
export function assertNoDtd(xml: string): void {
  if (/<!\s*(?:DOCTYPE|ENTITY)/i.test(xml)) throw new Error('feed refused: DOCTYPE/ENTITY declarations are not allowed');
}

export function parseFeed(xmlIn: string, sourceId: string, max = 40): FeedItem[] {
  assertNoDtd(xmlIn);
  const xml = xmlIn.slice(0, MAX_FEED_CHARS);
  const out: FeedItem[] = [];
  for (const b of blocksOf(xml, max)) {
    const lb = b.toLowerCase();
    const title = stripTags(tag(b, lb, ['title']) ?? '');
    const linkText = tag(b, lb, ['link']);
    const link = safeUrl((linkText && stripTags(linkText)) || hrefLink(b, lb));
    const body = stripTags(tag(b, lb, ['content:encoded', 'content', 'description', 'summary']) ?? '');
    const id = (stripTags(tag(b, lb, ['guid', 'id']) ?? '') || link || title).slice(0, 500);
    const date = stripTags(tag(b, lb, ['pubdate', 'dc:date', 'published', 'updated']) ?? '');
    const ts = Date.parse(date);
    if (!title && !body) continue;
    out.push({
      source: `rss:${sourceId}`,
      id,
      title: title.slice(0, 300),
      text: body,
      url: link,
      publishedAt: Number.isNaN(ts) ? undefined : new Date(ts).toISOString(),
      cves: extractCves(`${title} ${body}`),
      productHints: [],
    });
  }
  return out;
}

export async function collectRss(ctx: FeedContext): Promise<FeedResult[]> {
  const results: FeedResult[] = [];
  const cutoff = ctx.now.getTime() - Math.max(ctx.config.feeds.lookbackDays, 2) * 86_400_000;
  for (const feed of ctx.config.feeds.rss) {
    if (!feed.enabled || !feed.url) continue;
    try {
      const res = await ctx.http.request(feed.url, {}, { cache: true, minIntervalMs: 1000, maxBytes: 5 * 1024 * 1024 });
      if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status}`);
      if (/html|json|octet-stream|image|video|audio/.test(res.contentType)) throw new Error(`unexpected content-type ${res.contentType.split(';')[0]}`);
      const items = parseFeed(res.body, feed.id).filter((i) => !i.publishedAt || Date.parse(i.publishedAt) >= cutoff);
      results.push({ source: `rss:${feed.id}`, items });
    } catch (err) {
      results.push({ source: `rss:${feed.id}`, items: [], error: err instanceof Error ? err.message : String(err) });
    }
  }
  return results;
}
