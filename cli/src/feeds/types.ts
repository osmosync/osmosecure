import type { Config } from '../config.js';
import type { HttpClient } from '../http.js';
import type { StateStore } from '../state.js';
import type { FeedItem, Logger } from '../types.js';

export interface FeedContext {
  http: HttpClient;
  config: Config;
  state: StateStore;
  log: Logger;
  now: Date;
  /** lowercased package names present in the inventory, by ecosystem */
  inventoryNames: Map<string, Set<string>>;
}

export interface FeedResult {
  source: string;
  items: FeedItem[];
  /** Set when the source could not be read; the run continues with other sources. */
  error?: string;
}

export const CVE_RE = /CVE-\d{4}-\d{4,7}/gi;

export function extractCves(text: string): string[] {
  return [...new Set((text.match(CVE_RE) ?? []).map((c) => c.toUpperCase()))];
}

export function lookbackStart(ctx: FeedContext, cursorKey: string): Date {
  const cursor = ctx.state.state.cursors[cursorKey];
  const floor = ctx.now.getTime() - ctx.config.feeds.lookbackDays * 86_400_000;
  if (cursor && Date.parse(cursor) > floor) return new Date(cursor);
  return new Date(floor);
}
