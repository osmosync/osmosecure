import type { FeedItem, Severity } from '../types.js';
import { lookbackStart, type FeedContext, type FeedResult } from './types.js';

interface NvdCve {
  cve: {
    id: string;
    published: string;
    descriptions?: { lang: string; value: string }[];
    metrics?: Record<string, { cvssData?: { baseSeverity?: string } }[]>;
    configurations?: { nodes?: { cpeMatch?: { criteria: string; vulnerable?: boolean }[] }[] }[];
  };
}

function severity(c: NvdCve['cve']): Severity {
  for (const key of ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']) {
    const s = c.metrics?.[key]?.[0]?.cvssData?.baseSeverity?.toLowerCase();
    if (s === 'critical' || s === 'high' || s === 'medium' || s === 'low') return s;
  }
  return 'unknown';
}

export function cpeHints(c: NvdCve['cve']): string[] {
  const out = new Set<string>();
  for (const conf of c.configurations ?? []) {
    for (const node of conf.nodes ?? []) {
      for (const m of node.cpeMatch ?? []) {
        const parts = m.criteria.split(':'); // cpe:2.3:a:vendor:product:version...
        if (parts[3]) out.add(parts[3]);
        if (parts[4]) out.add(parts[4]);
      }
    }
  }
  return [...out];
}

export function nvdToItems(list: NvdCve[]): FeedItem[] {
  return list.map(({ cve }) => ({
    source: 'nvd',
    id: cve.id,
    title: cve.id,
    text: cve.descriptions?.find((d) => d.lang === 'en')?.value ?? '',
    url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
    publishedAt: cve.published,
    cves: [cve.id],
    productHints: cpeHints(cve),
    severity: severity(cve),
  }));
}

const nvdDate = (d: Date) => d.toISOString().replace('Z', '');

export async function collectNvd(ctx: FeedContext): Promise<FeedResult> {
  const cfg = ctx.config.feeds.nvd;
  const since = lookbackStart(ctx, 'nvd');
  const headers: Record<string, string> = {};
  if (process.env.NVD_API_KEY) headers.apiKey = process.env.NVD_API_KEY;
  const interval = process.env.NVD_API_KEY ? 700 : (ctx.config.feeds.minIntervalMs.nvd ?? 6500);
  try {
    const items: FeedItem[] = [];
    let startIndex = 0;
    for (let page = 0; page < cfg.maxPages; page++) {
      const url =
        `${cfg.url}?pubStartDate=${encodeURIComponent(nvdDate(since))}` +
        `&pubEndDate=${encodeURIComponent(nvdDate(ctx.now))}&resultsPerPage=${cfg.maxResults}&startIndex=${startIndex}`;
      const { data } = await ctx.http.json<{ vulnerabilities?: NvdCve[]; totalResults?: number }>(url, {}, {
        headers,
        minIntervalMs: interval,
        timeoutMs: 90_000,
      });
      items.push(...nvdToItems(data.vulnerabilities ?? []));
      startIndex += cfg.maxResults;
      if (startIndex >= (data.totalResults ?? 0)) break;
      if (page === cfg.maxPages - 1) ctx.log.warn('nvd results truncated', { total: data.totalResults, fetched: items.length });
    }
    ctx.state.state.cursors.nvd = ctx.now.toISOString();
    return { source: 'nvd', items };
  } catch (err) {
    return { source: 'nvd', items: [], error: err instanceof Error ? err.message : String(err) };
  }
}
