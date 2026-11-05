import { normalizeUntrusted } from '../lib/untrusted.js';
import type { FeedItem, Severity } from '../types.js';
import type { TriageProduct, TriageResult } from './schema.js';

/**
 * Deterministic checks applied to a model reply before anything downstream sees it. The model reads untrusted text, so
 * its reply is a claim about that text, not a fact: every product name, version and CVE id must literally appear in
 * the disclosure it was given, and its severity can never outrank structured data or the cap below.
 *
 * What this does not stop: an attacker who controls the disclosure text can still write a product, a version and a CVE
 * id into it. The grounding check removes claims the text does not make; it cannot tell a true bulletin from a forged one.
 */

const squash = (s: string): string => normalizeUntrusted(s).toLowerCase().replace(/[\s._-]+/g, '');

/** Without structured severity (CVSS, GHSA) the model may report at most this; critical needs structured evidence. */
export const MODEL_SEVERITY_CAP: Severity = 'high';
const ORDER: Severity[] = ['unknown', 'low', 'medium', 'high', 'critical'];
const rank = (s: Severity): number => ORDER.indexOf(s);

/** Structured severity wins. Otherwise the model's value is capped, so injected text cannot page someone as critical. */
export function resolveSeverity(item: Pick<FeedItem, 'severity'>, model: Severity): Severity {
  if (item.severity && item.severity !== 'unknown') return item.severity;
  return rank(model) > rank(MODEL_SEVERITY_CAP) ? MODEL_SEVERITY_CAP : model;
}

/** Drops products, ranges and versions that the disclosure text does not contain. Pure. */
export function groundProducts(products: TriageProduct[], text: string): TriageProduct[] {
  const hay = normalizeUntrusted(text).toLowerCase();
  const squashed = squash(text);
  const has = (v: string): boolean => hay.includes(v.toLowerCase());
  const out: TriageProduct[] = [];
  for (const p of products) {
    if (!squashed.includes(squash(p.name))) continue;
    // A range with any ungrounded bound is dropped whole: keeping only "introduced" would widen it to "everything since".
    const affectedRanges = p.affectedRanges.filter((r) => [r.introduced, r.fixed, r.lastAffected].every((v) => v === null || has(v)));
    out.push({ ...p, affectedRanges, fixedVersions: p.fixedVersions.filter(has) });
  }
  return out;
}

/** CVE ids are kept only when the item or its text states them. */
export function groundCves(cves: string[], item: Pick<FeedItem, 'title' | 'text' | 'cves'>): string[] {
  const hay = normalizeUntrusted(`${item.title}\n${item.text}`).toUpperCase();
  const known = new Set(item.cves.map((c) => c.toUpperCase()));
  return [...new Set(cves.map((c) => c.toUpperCase()))].filter((c) => known.has(c) || hay.includes(c));
}

/**
 * The reply as the rest of the program may use it. exploitedInWild is never consulted anywhere: exploitation status
 * comes only from the KEV feed, so a model (or text) claiming "actively exploited" changes nothing.
 */
export function constrainTriage(item: FeedItem, t: TriageResult): TriageResult {
  return {
    ...t,
    severity: resolveSeverity(item, t.severity),
    cves: groundCves(t.cves, item),
    products: groundProducts(t.products, `${item.title}\n${item.text}`),
  };
}
