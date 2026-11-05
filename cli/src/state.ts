import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import type { Finding, Tier } from './types.js';

export interface EpssEntry {
  score: number;
  percentile: number;
  fetchedAt: string;
}

export interface State {
  schemaVersion: 1;
  /** group name -> ISO time of last completed run */
  lastRun: Record<string, string>;
  /** source -> advisory/item id -> ISO time first seen */
  seenItems: Record<string, Record<string, string>>;
  /** per-source cursors (for example OSV modified timestamps) */
  cursors: Record<string, string>;
  findings: Record<string, Finding & { firstSeen: string; lastSeen: string }>;
  /** finding key -> highest tier already notified */
  notified: Record<string, { tier: Tier; at: string }>;
  /** finding keys waiting for the daily digest */
  digestPending: string[];
  /** finding key -> ISO time a remediation incident was posted or dry-run recorded */
  remediated: Record<string, { at: string; dryRun: boolean }>;
  epss: Record<string, EpssEntry>;
  kevCves: string[];
}

export function emptyState(): State {
  return {
    schemaVersion: 1,
    lastRun: {},
    seenItems: {},
    cursors: {},
    findings: {},
    notified: {},
    digestPending: [],
    remediated: {},
    epss: {},
    kevCves: [],
  };
}

export class StateStore {
  readonly file: string;
  state: State;

  constructor(dataDir: string) {
    mkdirSync(dataDir, { recursive: true });
    this.file = path.join(dataDir, 'state.json');
    this.state = existsSync(this.file)
      ? { ...emptyState(), ...(JSON.parse(readFileSync(this.file, 'utf8')) as Partial<State>) }
      : emptyState();
  }

  save(): void {
    const tmp = `${this.file}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.state, null, 2), { mode: 0o600 });
    renameSync(tmp, this.file);
  }

  /** Returns true if the id is new for this source, and records it. */
  markSeen(source: string, id: string, now = new Date()): boolean {
    const bucket = (this.state.seenItems[source] ??= {});
    if (bucket[id]) return false;
    bucket[id] = now.toISOString();
    return true;
  }

  isSeen(source: string, id: string): boolean {
    return Boolean(this.state.seenItems[source]?.[id]);
  }

  pruneSeen(maxAgeDays: number, now = new Date()): void {
    const cutoff = now.getTime() - maxAgeDays * 86_400_000;
    for (const bucket of Object.values(this.state.seenItems)) {
      for (const [id, at] of Object.entries(bucket)) {
        if (Date.parse(at) < cutoff) delete bucket[id];
      }
    }
  }

  isDue(group: string, everyMinutes: number, now = new Date()): boolean {
    const last = this.state.lastRun[group];
    if (!last) return true;
    // 2 minute grace so an hourly cron that drifts a few seconds still fires on schedule
    return now.getTime() - Date.parse(last) >= everyMinutes * 60_000 - 120_000;
  }
}
