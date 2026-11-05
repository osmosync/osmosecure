import type { FeedItem, Severity } from '../types.js';
import { lookbackStart, type FeedContext, type FeedResult } from './types.js';

interface GhsaAdvisory {
  ghsa_id: string;
  cve_id: string | null;
  summary: string;
  description?: string;
  severity?: string;
  html_url?: string;
  updated_at: string;
  vulnerabilities?: { package?: { ecosystem?: string; name?: string }; first_patched_version?: string | null }[];
}

const ECO: Record<string, string> = { npm: 'npm', composer: 'Packagist', rubygems: 'RubyGems', pip: 'PyPI' };

function sev(s?: string): Severity {
  return s === 'critical' || s === 'high' || s === 'medium' || s === 'low' ? s : 'unknown';
}

export function ghsaToItems(list: GhsaAdvisory[], inventoryNames: Map<string, Set<string>>, since: Date): FeedItem[] {
  const out: FeedItem[] = [];
  for (const a of list) {
    if (Date.parse(a.updated_at) < since.getTime()) continue;
    const packages = (a.vulnerabilities ?? [])
      .map((v) => ({ ecosystem: ECO[v.package?.ecosystem ?? ''] ?? '', name: (v.package?.name ?? '').toLowerCase() }))
      .filter((p) => p.name && inventoryNames.get(p.ecosystem)?.has(p.name));
    if (packages.length === 0) continue;
    out.push({
      source: 'ghsa',
      id: a.ghsa_id,
      title: a.summary.slice(0, 200),
      text: '',
      url: a.html_url,
      publishedAt: a.updated_at,
      cves: a.cve_id ? [a.cve_id] : [],
      productHints: packages.map((p) => p.name),
      packages,
      severity: sev(a.severity),
    });
  }
  return out;
}

export async function collectGhsa(ctx: FeedContext): Promise<FeedResult> {
  const cfg = ctx.config.feeds.ghsa;
  const since = lookbackStart(ctx, 'ghsa');
  const headers: Record<string, string> = { accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28' };
  if (process.env.GITHUB_TOKEN) headers.authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  try {
    const url = `${cfg.url}?per_page=${cfg.perPage}&sort=updated&direction=desc&type=reviewed`;
    const { data } = await ctx.http.json<GhsaAdvisory[]>(url, {}, {
      headers,
      cache: true,
      minIntervalMs: ctx.config.feeds.minIntervalMs.github ?? 1000,
    });
    const items = ghsaToItems(data, ctx.inventoryNames, since);
    ctx.state.state.cursors.ghsa = data[0]?.updated_at ?? since.toISOString();
    return { source: 'ghsa', items };
  } catch (err) {
    return { source: 'ghsa', items: [], error: err instanceof Error ? err.message : String(err) };
  }
}
