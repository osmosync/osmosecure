import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { expandPath, resolveDataDir, type Config } from './config.js';
import { collectGhsa } from './feeds/ghsa.js';
import { collectKev } from './feeds/kev.js';
import { collectNvd } from './feeds/nvd.js';
import { collectOsv } from './feeds/osv.js';
import { collectRss } from './feeds/rss.js';
import { refreshEpss } from './feeds/epss.js';
import type { FeedContext, FeedResult } from './feeds/types.js';
import { HttpClient } from './http.js';
import { buildInventory, summarizeInventory } from './inventory/index.js';
import { createNotifiers, formatMessage, sendAll, type Notifier } from './notify/index.js';
import { rank, tierRank } from './rank.js';
import type { Exec } from './fix.js';
import { buildRequest, decide, hookReady, postRequest } from './remediate.js';
import { osvScannerAvailable, scanWithOsvScanner } from './scan/osv-scanner.js';
import { OsvApi, scanWithOsvApi, scannable } from './scan/osv.js';
import { StateStore, type State } from './state.js';
import { createTriageClient, triageItem, type TriageClient } from './triage/llm.js';
import { matchTriage } from './triage/matcher.js';
import { buildPackageNames, buildProductTerms, prefilter } from './triage/prefilter.js';
import type { Candidate, FeedItem, Finding, Inventory, Logger } from './types.js';

export interface RunOptions {
  /** Run only groups whose cadence has elapsed. */
  due: boolean;
  /** Explicit groups (overrides due). */
  groups?: string[];
  /** Read public sources only: no notifications, no remediation post, no state write. */
  dryRun: boolean;
  /** Post remediation requests for real (still needs a hook URL and its secret). */
  remediateLive: boolean;
  noLlm: boolean;
  /** Record every current finding as seen and notified; send nothing, post nothing. */
  baseline?: boolean;
  deadlineMs: number;
}

export interface RunSummary {
  groupsRun: string[];
  groupsSkipped: string[];
  inventory: string;
  manifests: number;
  inventoryErrors: string[];
  feedErrors: { source: string; error: string }[];
  itemsNew: number;
  itemsTriaged: number;
  itemsSkippedNoLlm: number;
  findingsTotal: number;
  findingsNew: number;
  notified: number;
  remediation: { queued: number; approvalRequired: number; posted: number; dryRun: boolean };
  baseline?: { recorded: number; byTier: Record<string, number>; byBasis: Record<string, number> };
  message?: string;
}

function inventoryNames(inv: Inventory): Map<string, Set<string>> {
  const m = new Map<string, Set<string>>();
  for (const c of inv.components) {
    if (!scannable(c)) continue;
    if (!m.has(c.ecosystem)) m.set(c.ecosystem, new Set());
    m.get(c.ecosystem)!.add(c.name);
  }
  return m;
}

/**
 * The full scan, the feed-driven rescan and AI triage can report the same finding in one run. Keep one per key
 * so a finding is never alerted twice, and keep the strongest copy (highest score, then deterministic over
 * AI triage) so a weaker duplicate can never downgrade or suppress the alert.
 */
/** False when an AI-triage finding would overwrite a deterministic one stored under the same key. */
export function mayReplaceFinding(prev: Pick<Finding, 'basis'> | undefined, next: Pick<Finding, 'basis'>): boolean {
  return !(prev && prev.basis === 'deterministic' && next.basis !== 'deterministic');
}

export function strongestByKey(items: Finding[]): Finding[] {
  const best = new Map<string, Finding>();
  for (const f of items) {
    const cur = best.get(f.key);
    // A deterministic candidate always beats an AI-triage one; score only breaks ties within the same class.
    const det = f.basis === 'deterministic';
    const curDet = cur?.basis === 'deterministic';
    const stronger = !cur || (det !== curDet ? det : f.score > cur.score);
    if (stronger) best.set(f.key, f);
  }
  return [...best.values()];
}

/** AI-triage finding keys live in their own namespace so they can never equal a deterministic key. */
export const TRIAGE_KEY_PREFIX = 'triage:';

/**
 * Move findings stored by an older build under an un-prefixed triage key into the triage namespace, with the
 * per-key notification state, so an upgrade does not re-announce them.
 */
export function migrateTriageKeys(state: State): void {
  const rename = (rec: Record<string, unknown>, from: string, to: string) => {
    if (from in rec && !(to in rec)) rec[to] = rec[from];
    delete rec[from];
  };
  for (const [key, f] of Object.entries(state.findings)) {
    if (f.basis !== 'llm-triage' || key.startsWith(TRIAGE_KEY_PREFIX)) continue;
    const to = TRIAGE_KEY_PREFIX + key;
    rename(state.findings, key, to);
    state.findings[to].key = to;
    rename(state.notified, key, to);
    rename(state.remediated, key, to);
    state.digestPending = state.digestPending.map((k) => (k === key ? to : k));
  }
}

export function selectGroups(config: Config, state: StateStore, opts: Pick<RunOptions, 'due' | 'groups'>, now = new Date()) {
  const all = Object.keys(config.sourceGroups);
  if (opts.groups?.length) {
    const unknown = opts.groups.filter((g) => !all.includes(g));
    if (unknown.length) throw new Error(`unknown group(s): ${unknown.join(', ')}`);
    return { run: opts.groups, skipped: all.filter((g) => !opts.groups!.includes(g)) };
  }
  if (!opts.due) return { run: all, skipped: [] as string[] };
  const run = all.filter((g) => state.isDue(g, config.sourceGroups[g].everyMinutes, now));
  return { run, skipped: all.filter((g) => !run.includes(g)) };
}

export async function runAudit(
  config: Config,
  opts: RunOptions,
  log: Logger,
  overrides: { triage?: TriageClient | null; http?: HttpClient; now?: Date; notifiers?: Notifier[]; exec?: Exec } = {},
): Promise<RunSummary> {
  const now = overrides.now ?? new Date();
  const deadline = Date.now() + opts.deadlineMs;
  const dataDir = resolveDataDir(config);
  const store = new StateStore(dataDir);
  migrateTriageKeys(store.state);
  const http = overrides.http ?? new HttpClient(config.feeds.userAgent, log, path.join(dataDir, 'cache'), undefined, undefined, { allowPrivateNetwork: config.feeds.allowPrivateNetwork });
  const { run: groups, skipped } = selectGroups(config, store, opts, now);

  const summary: RunSummary = {
    groupsRun: groups,
    groupsSkipped: skipped,
    inventory: '',
    manifests: 0,
    inventoryErrors: [],
    feedErrors: [],
    itemsNew: 0,
    itemsTriaged: 0,
    itemsSkippedNoLlm: 0,
    findingsTotal: 0,
    findingsNew: 0,
    notified: 0,
    remediation: { queued: 0, approvalRequired: 0, posted: 0, dryRun: !opts.remediateLive && config.remediation.dryRun },
  };
  if (groups.length === 0) {
    log.info('no source group due');
    return summary;
  }

  const wants = (source: string) => groups.some((g) => config.sourceGroups[g].sources.includes(source));
  const failedGroups = new Set<string>();
  const markFailed = (source: string) => {
    for (const g of groups) if (config.sourceGroups[g].sources.includes(source)) failedGroups.add(g);
  };

  // 1. inventory (cheap local walk; always needed to filter feeds)
  const inv = buildInventory(config, dataDir, log);
  summary.inventory = summarizeInventory(inv);
  summary.manifests = inv.manifests.length;
  summary.inventoryErrors = inv.errors;
  if (!opts.dryRun) writeFileSync(path.join(dataDir, 'inventory.json'), JSON.stringify(inv, null, 2), { mode: 0o600 });

  const candidates: Candidate[] = [];
  let fullScan = false;
  const osvApi = new OsvApi(http, config.feeds.osv.apiUrl, log);

  // 2. scan
  if (wants('scan')) {
    try {
      const useScanner = config.scan.prefer !== 'api' && (await osvScannerAvailable());
      if (config.scan.prefer === 'osv-scanner' && !useScanner) throw new Error('osv-scanner requested but not installed');
      if (useScanner) {
        const roots = config.projects.map((p) => expandPath(p.root, config.configDir));
        candidates.push(...(await scanWithOsvScanner(roots, inv.components)));
        log.info('scan via osv-scanner');
      } else {
        const r = await scanWithOsvApi(osvApi, inv.components, config.scan.maxDetailFetchPerRun, log);
        candidates.push(...r.candidates);
        if (r.skippedDetails) log.warn('osv detail fetch capped; remaining ids picked up next run', { skipped: r.skippedDetails });
        log.info('scan via osv api', { candidates: r.candidates.length });
        fullScan = r.skippedDetails === 0;
      }
    } catch (err) {
      markFailed('scan');
      summary.feedErrors.push({ source: 'scan', error: err instanceof Error ? err.message : String(err) });
    }
  }

  // 3. feeds
  const ctx: FeedContext = { http, config, state: store, log, now, inventoryNames: inventoryNames(inv) };
  const results: FeedResult[] = [];
  if (wants('kev')) results.push(await collectKev(ctx));
  if (wants('osv')) results.push(await collectOsv(ctx));
  if (wants('ghsa')) results.push(await collectGhsa(ctx));
  if (wants('nvd')) results.push(await collectNvd(ctx));
  if (wants('rss')) results.push(...(await collectRss(ctx)));
  for (const r of results) {
    if (r.error) {
      const base = r.source.split(':')[0];
      markFailed(base);
      summary.feedErrors.push({ source: r.source, error: r.error });
      log.warn('feed failed', { source: r.source, error: r.error });
    }
  }

  const fresh: FeedItem[] = results.flatMap((r) => r.items).filter((i) => !store.isSeen(i.source, i.id));
  summary.itemsNew = fresh.length;
  const processed: FeedItem[] = [];

  // 3a. structured package advisories -> authoritative rescan of the named packages
  const structured = fresh.filter((i) => i.packages?.length);
  if (structured.length) {
    const names = new Set(structured.flatMap((i) => i.packages!.map((p) => `${p.ecosystem}\0${p.name}`)));
    const comps = inv.components.filter((c) => scannable(c) && names.has(`${c.ecosystem}\0${c.name}`));
    try {
      const r = await scanWithOsvApi(osvApi, comps, config.scan.maxDetailFetchPerRun, log);
      candidates.push(...r.candidates);
      processed.push(...structured);
    } catch (err) {
      markFailed('osv');
      log.warn('rescan failed', { error: err instanceof Error ? err.message : String(err) });
    }
  }

  // 3b. free-text disclosures -> prefilter -> LLM triage -> deterministic matcher
  const terms = buildProductTerms(inv.components);
  const pkgNames = buildPackageNames(inv.components);
  const freeText = fresh.filter((i) => !i.packages?.length);
  const relevant = freeText.filter((i) => prefilter(i, terms, pkgNames));
  processed.push(...freeText.filter((i) => !relevant.includes(i))); // irrelevant: mark seen
  const client = opts.noLlm ? null : overrides.triage !== undefined ? overrides.triage : await createTriageClient(config);
  if (relevant.length && !client) {
    summary.itemsSkippedNoLlm = relevant.length;
    log.warn('LLM triage unavailable (check triage.backend and its credentials); relevant items left unseen', { items: relevant.length });
  } else if (client) {
    const ordered = [...relevant].sort((a, b) => Number(b.kev ?? false) - Number(a.kev ?? false) || b.cves.length - a.cves.length);
    for (const item of ordered.slice(0, config.triage.maxItemsPerRun)) {
      if (Date.now() > deadline) {
        log.warn('deadline reached during triage');
        break;
      }
      try {
        const t = await triageItem(client, item, config.triage.maxInputChars);
        summary.itemsTriaged++;
        processed.push(item);
        if (!t.relevant) continue;
        for (const m of matchTriage(t.products, inv.components)) {
          const cves = [...new Set([...item.cves, ...t.cves.map((c) => c.toUpperCase())])];
          candidates.push({
            key: `${TRIAGE_KEY_PREFIX}${item.id}|${m.component.project}|${m.component.ecosystem}:${m.component.name}@${m.component.version}`,
            advisoryId: item.id,
            aliases: [],
            cves,
            title: item.title,
            severity: t.severity !== 'unknown' ? t.severity : (item.severity ?? 'unknown'),
            source: item.source,
            url: item.url,
            component: m.component,
            fixedVersion: m.fixedVersion,
            basis: 'llm-triage',
            verdict: m.verdict === 'affected' ? 'affected' : 'needs-verification',
            note: m.reason,
          });
        }
      } catch (err) {
        log.warn('triage failed; item will retry next run', { id: item.id, error: err instanceof Error ? err.message : String(err) });
      }
    }
    // items beyond the per-run cap stay unseen and are picked up next run
  }

  // 4. EPSS enrichment for everything we may rank, then rank
  const cveSet = new Set<string>([...candidates.flatMap((c) => c.cves)]);
  if (wants('epss') || candidates.length) {
    const e = await refreshEpss(ctx, [...cveSet]);
    if (e.error) {
      markFailed('epss');
      summary.feedErrors.push({ source: 'epss', error: e.error });
    }
  }
  const rankCtx = { kevCves: new Set(store.state.kevCves), epss: store.state.epss, config };
  const ranked = strongestByKey(candidates.map((c) => rank(c, rankCtx)));

  // 5. upsert + dedupe + notify decisions
  const nowIso = now.toISOString();
  const immediate: Finding[] = [];
  for (const f of ranked) {
    const prev = store.state.findings[f.key];
    // A deterministic record is never replaced by an AI-triage record that happens to share its key (a feed item id can
    // equal a real advisory id), so feed text cannot take over a finding the fixer is allowed to act on.
    if (!mayReplaceFinding(prev, f)) continue;
    store.state.findings[f.key] = { ...f, firstSeen: prev?.firstSeen ?? nowIso, lastSeen: nowIso };
    if (!prev) summary.findingsNew++;
    const notified = store.state.notified[f.key];
    const escalated = !notified || tierRank(f.tier) > tierRank(notified.tier);
    if (!escalated) continue;
    if (f.tier === 'page' || f.tier === 'alert') immediate.push(f);
    else if (f.tier === 'digest' && !store.state.digestPending.includes(f.key) && !notified) store.state.digestPending.push(f.key);
  }
  if (fullScan) {
    // Findings from an earlier full scan that no longer appear are fixed; forget them.
    const live = new Set(ranked.map((f) => f.key));
    for (const [key, f] of Object.entries(store.state.findings)) {
      if (f.basis === 'deterministic' && (f.source === 'osv-api' || f.source === 'osv-scanner') && !live.has(key)) {
        delete store.state.findings[key];
        delete store.state.notified[key];
        store.state.digestPending = store.state.digestPending.filter((k) => k !== key);
      }
    }
  }
  summary.findingsTotal = Object.keys(store.state.findings).length;
  immediate.sort((a, b) => b.score - a.score);

  // 6. remediation hand-off (dry-run by default)
  const live = opts.remediateLive || !config.remediation.dryRun;
  summary.remediation.dryRun = !live || opts.dryRun;
  const hook = hookReady(config);
  let remediationBudget = config.remediation.maxPerRun;
  for (const f of opts.baseline ? [] : immediate) {
    const d = decide(f, config);
    if (d.action === 'none') continue;
    if (d.action === 'approval-required') {
      summary.remediation.approvalRequired++;
      f.note = `${f.note ? `${f.note}; ` : ''}fix needs approval (${d.why}); run: osmosecure remediate "${f.key}"`;
      continue;
    }
    summary.remediation.queued++;
    if (store.state.remediated[f.key] || remediationBudget <= 0) continue;
    const request = buildRequest(f, d, config, now);
    if (summary.remediation.dryRun || !hook) {
      log.info('remediation dry-run', { target: request.target, title: request.title, hookConfigured: Boolean(config.remediation.hook.url) });
      if (!opts.dryRun) store.state.remediated[f.key] = { at: nowIso, dryRun: true };
      remediationBudget--;
      f.note = `${f.note ? `${f.note}; ` : ''}patch fix queued (dry-run)`;
    } else if (await postRequest(request, config, hook.secret, log)) {
      store.state.remediated[f.key] = { at: nowIso, dryRun: false };
      summary.remediation.posted++;
      remediationBudget--;
      f.note = `${f.note ? `${f.note}; ` : ''}patch fix handed to the remediation hook`;
    }
  }

  // 6b. baseline: everything currently known counts as already notified; nothing is sent.
  if (opts.baseline) {
    const byTier: Record<string, number> = {};
    const byBasis: Record<string, number> = {};
    for (const [key, f] of Object.entries(store.state.findings)) {
      store.state.notified[key] = { tier: f.tier, at: nowIso };
      byTier[f.tier] = (byTier[f.tier] ?? 0) + 1;
      byBasis[f.basis] = (byBasis[f.basis] ?? 0) + 1;
    }
    store.state.digestPending = [];
    summary.baseline = { recorded: Object.keys(store.state.findings).length, byTier, byBasis };
    immediate.length = 0;
  }

  // 7. notify
  const messages: string[] = [];
  if (immediate.length) {
    const urgent = immediate.some((f) => f.tier === 'page');
    messages.push(formatMessage(urgent ? 'OsmoSecure urgent alert' : 'OsmoSecure alert', immediate, config.notify.maxFindingsPerMessage));
  }
  const digestDue = !opts.baseline && groups.some((g) => config.sourceGroups[g].sources.includes('digest'));
  if (digestDue && store.state.digestPending.length) {
    const items = store.state.digestPending.map((k) => store.state.findings[k]).filter(Boolean).sort((a, b) => b.score - a.score);
    messages.push(formatMessage('OsmoSecure digest', items, config.notify.maxFindingsPerMessage));
  }
  summary.message = messages.join('\n\n----\n\n') || undefined;
  if (messages.length && !opts.dryRun) {
    const notifiers = overrides.notifiers ?? createNotifiers(config);
    let allSent = true;
    for (const m of messages) allSent = (await sendAll(notifiers, m, log)) && allSent;
    if (allSent) {
      for (const f of immediate) store.state.notified[f.key] = { tier: f.tier, at: nowIso };
      if (digestDue) {
        for (const k of store.state.digestPending) {
          const f = store.state.findings[k];
          if (f) store.state.notified[k] = { tier: f.tier, at: nowIso };
        }
        store.state.digestPending = [];
      }
      summary.notified = immediate.length;
    }
  }

  // 8. persist. Items are marked seen only after they were fully processed.
  if (!opts.dryRun) {
    for (const i of processed) store.markSeen(i.source, i.id, now);
    store.pruneSeen(180, now);
    for (const g of groups) if (!failedGroups.has(g)) store.state.lastRun[g] = nowIso;
    store.save();
  }
  http.persist();
  return summary;
}
