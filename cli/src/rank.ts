import type { Config } from './config.js';
import type { EpssEntry } from './state.js';
import type { Candidate, Finding, Tier } from './types.js';

export const TIER_ORDER: Tier[] = ['log', 'digest', 'alert', 'page'];
export const tierRank = (t: Tier): number => TIER_ORDER.indexOf(t);

export interface RankContext {
  kevCves: Set<string>;
  epss: Record<string, EpssEntry>;
  config: Config;
}

export function epssBoost(score: number | undefined, config: Config): number {
  if (score === undefined) return 0;
  const tiers = [...config.scoring.epss].sort((a, b) => b.min - a.min);
  return tiers.find((t) => score >= t.min)?.boost ?? 0;
}

export function tierFor(score: number, config: Config): Tier {
  const t = config.thresholds;
  if (score >= t.page) return 'page';
  if (score >= t.alert) return 'alert';
  if (score >= t.digest) return 'digest';
  return 'log';
}

/** Severity base plus KEV and EPSS boosts. Runtime and unverified adjustments come from config. */
export function rank(c: Candidate, ctx: RankContext): Finding {
  const ids = [c.advisoryId, ...c.aliases, ...c.cves];
  const kev = ids.some((i) => ctx.kevCves.has(i));
  const epss = Math.max(0, ...c.cves.map((cve) => ctx.epss[cve]?.score ?? 0)) || undefined;
  const s = ctx.config.scoring;
  let score = s.severity[c.severity];
  if (kev) score += s.kevBoost;
  score += epssBoost(epss, ctx.config);
  if (c.component.kind === 'runtime') score += s.runtimeBoost;
  if (c.verdict === 'needs-verification') score -= s.unverifiedPenalty;
  return { ...c, kev, epss, score, tier: tierFor(score, ctx.config) };
}
