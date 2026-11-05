import type { FeedItem } from '../types.js';
import { extractCves, type FeedContext, type FeedResult } from './types.js';

interface KevJson {
  vulnerabilities: {
    cveID: string;
    vendorProject: string;
    product: string;
    vulnerabilityName: string;
    dateAdded: string;
    shortDescription: string;
    requiredAction: string;
  }[];
}

export function kevToItems(json: KevJson, since: Date): FeedItem[] {
  return json.vulnerabilities
    .filter((v) => Date.parse(v.dateAdded) >= since.getTime() - 86_400_000)
    .map((v) => ({
      source: 'kev',
      id: v.cveID,
      title: `${v.cveID}: ${v.vulnerabilityName}`,
      text: `${v.vendorProject} ${v.product}. ${v.shortDescription} Required action: ${v.requiredAction}`,
      url: `https://nvd.nist.gov/vuln/detail/${v.cveID}`,
      publishedAt: v.dateAdded,
      cves: extractCves(v.cveID),
      productHints: [v.vendorProject, v.product],
      kev: true,
      severity: 'high' as const,
    }));
}

export async function collectKev(ctx: FeedContext): Promise<FeedResult> {
  try {
    const { data } = await ctx.http.json<KevJson>(ctx.config.feeds.kev.url, {}, { cache: true });
    ctx.state.state.kevCves = data.vulnerabilities.map((v) => v.cveID);
    const since = new Date(ctx.now.getTime() - ctx.config.feeds.lookbackDays * 86_400_000);
    return { source: 'kev', items: kevToItems(data, since) };
  } catch (err) {
    return { source: 'kev', items: [], error: err instanceof Error ? err.message : String(err) };
  }
}
