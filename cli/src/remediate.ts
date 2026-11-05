import { createHmac, timingSafeEqual } from 'node:crypto';
import { isAllowedHookUrl } from './notify/index.js';
import type { Config } from './config.js';
import { bumpClass, type BumpClass } from './lib/version.js';
import { tierRank } from './rank.js';
import type { Finding, Logger, Severity } from './types.js';

export type Decision =
  | { action: 'queue'; bump: BumpClass; target: string; project: string }
  | { action: 'approval-required'; bump: BumpClass; target: string; project: string; why: string }
  | { action: 'none'; why: string };

export function targetFor(config: Config, f: Finding): { project: string; target: string } | null {
  const proj = config.projects.find((p) => p.id === f.component.project);
  if (!proj) return null;
  const origin = f.component.origin;
  const prefix = Object.keys(proj.pathTargets)
    .filter((p) => origin === p || origin.startsWith(`${p}/`))
    .sort((a, b) => b.length - a.length)[0];
  const target = prefix !== undefined ? proj.pathTargets[prefix] : proj.target;
  return target ? { project: proj.id, target } : null;
}

/** Policy: only deterministic app-dependency findings with a known fix are eligible. */
export function decide(f: Finding, config: Config): Decision {
  if (f.basis !== 'deterministic' || f.component.kind !== 'package') return { action: 'none', why: 'not an app dependency finding' };
  if (tierRank(f.tier) < tierRank(config.remediation.minTier)) return { action: 'none', why: 'below remediation tier' };
  if (!f.fixedVersion) return { action: 'none', why: 'no fixed version known' };
  const target = targetFor(config, f);
  if (!target) return { action: 'none', why: 'no remediation target mapped for this path' };
  const bump = bumpClass(f.component.version, f.fixedVersion);
  if (bump === 'patch' && config.autoFix.patchBumpsQueued) return { action: 'queue', bump, ...target };
  return {
    action: 'approval-required',
    bump,
    ...target,
    why: bump === 'patch' ? 'patch queueing disabled' : `${bump} bump needs human approval`,
  };
}

const SEVERITY_MAP: Record<Severity, 'info' | 'warning' | 'error' | 'critical'> = {
  critical: 'critical',
  high: 'error',
  medium: 'warning',
  low: 'info',
  unknown: 'warning',
};

export interface RemediationRequest {
  schema: 'osmosecure.remediation.v1';
  project: string;
  target: string;
  title: string;
  instruction: string;
  fingerprint: string;
  severity: 'info' | 'warning' | 'error' | 'critical';
  occurredAt: string;
  metadata: {
    advisoryId: string;
    ecosystem: string;
    package: string;
    currentVersion: string;
    fixedVersion: string | undefined;
    bumpClass: BumpClass;
    kev: boolean;
    policy: { neverPushOrDeploy: true; requiresApproval: boolean };
  };
}

/**
 * Builds the remediation request. The instruction is composed only from our own structured
 * fields; no feed or LLM free text is forwarded, so a hostile advisory cannot steer the receiver.
 */
export function buildRequest(f: Finding, d: Extract<Decision, { action: 'queue' | 'approval-required' }>, config: Config, now = new Date()): RemediationRequest {
  const c = f.component;
  return {
    schema: 'osmosecure.remediation.v1',
    project: d.project,
    target: d.target,
    title: `Security: ${f.advisoryId} in ${c.name}@${c.version}`.slice(0, 200),
    instruction: [
      `Dependency ${c.name} (${c.ecosystem}) is at ${c.version} in ${c.origin}. Advisory ${f.advisoryId} is fixed in ${f.fixedVersion}.`,
      `Bump class: ${d.bump}. Make the smallest lockfile and manifest change that reaches ${f.fixedVersion}.`,
      config.autoFix.requireTestsPass ? 'Run the narrowest tests and typecheck; report findings only if they fail.' : '',
      'Do not push, merge, deploy, or touch unrelated files.',
    ]
      .filter(Boolean)
      .join(' '),
    fingerprint: `osmosecure-${f.key}`.slice(0, 200),
    severity: SEVERITY_MAP[f.severity],
    occurredAt: now.toISOString(),
    metadata: {
      advisoryId: f.advisoryId,
      ecosystem: c.ecosystem,
      package: c.name,
      currentVersion: c.version,
      fixedVersion: f.fixedVersion,
      bumpClass: d.bump,
      kev: f.kev,
      policy: { neverPushOrDeploy: true, requiresApproval: d.action === 'approval-required' },
    },
  };
}

/** Signature covers the timestamp and the exact body so a captured request cannot be replayed later. */
export function signBody(body: string, secret: string, timestamp: string): string {
  return `sha256=${createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex')}`;
}

/** Receiver side of signBody: constant-time compare plus a timestamp window against replay of old captures. */
export function verifySignature(
  body: string,
  secret: string,
  timestamp: string | undefined,
  signature: string | undefined,
  now = new Date(),
  windowSeconds = 300,
): { ok: true } | { ok: false; why: string } {
  if (!timestamp || !/^\d{1,12}$/.test(timestamp)) return { ok: false, why: 'missing or malformed timestamp' };
  if (Math.abs(now.getTime() / 1000 - Number(timestamp)) > windowSeconds) return { ok: false, why: 'timestamp outside window' };
  if (!signature) return { ok: false, why: 'missing signature' };
  const expected = Buffer.from(signBody(body, secret, timestamp));
  const given = Buffer.from(signature);
  if (expected.length !== given.length || !timingSafeEqual(expected, given)) return { ok: false, why: 'bad signature' };
  return { ok: true };
}

export async function postRequest(
  req: RemediationRequest,
  config: Config,
  secret: string,
  log: Logger,
  fetchImpl: typeof fetch = fetch,
  now = new Date(),
): Promise<boolean> {
  const url = config.remediation.hook.url;
  if (!isAllowedHookUrl(url)) {
    log.warn('remediation hook url rejected: must be https (or loopback http)');
    return false;
  }
  const body = JSON.stringify(req);
  const timestamp = String(Math.floor(now.getTime() / 1000));
  try {
    const res = await fetchImpl(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-osmosecure-timestamp': timestamp,
        'x-osmosecure-signature': signBody(body, secret, timestamp),
      },
      body,
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) log.warn('remediation hook rejected request', { status: res.status });
    return res.ok;
  } catch (err) {
    log.warn('remediation hook unreachable', { error: err instanceof Error ? err.message : String(err) });
    return false;
  }
}

/** True when a hook URL is configured and its secret is present in the environment. */
export function hookReady(config: Config, env: NodeJS.ProcessEnv = process.env): { url: string; secret: string } | null {
  const url = config.remediation.hook.url;
  const secret = env[config.remediation.hook.secretEnv];
  return url && secret ? { url, secret } : null;
}
