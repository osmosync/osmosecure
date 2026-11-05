#!/usr/bin/env node
// Validate a report JSON file. Usage: node validate-report.mjs <report.json> [--inventory inventory.json]
// Exit 0 valid, 1 invalid, 2 usage or read error. Dependency-free.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { validateSchema } from './lib/mini-schema.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const schema = JSON.parse(readFileSync(join(here, '..', 'report-schema.json'), 'utf8'));

const SECRET_PATTERNS = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, 'private key block'],
  [/\bAKIA[0-9A-Z]{16}\b/, 'AWS access key id'],
  [/\bgh[pousr]_[A-Za-z0-9]{30,}\b/, 'GitHub token'],
  [/\bsk-[A-Za-z0-9_-]{20,}\b/, 'API secret key'],
  [/\bBearer\s+[A-Za-z0-9._~+/-]{20,}/, 'bearer token'],
  [/\b(password|passwd|secret|api[_-]?key)\s*[=:]\s*["']?[^\s"']{8,}/i, 'credential assignment'],
];
const EXPLOIT_HINTS = [/\bshellcode\b/i, /\bmsfvenom\b/i, /\bexploit\.(py|rb|sh|c)\b/i, /```/];

export function validateReport(report, inventory = null) {
  const errors = validateSchema(report, schema);
  if (errors.length) return errors;

  const text = JSON.stringify(report);
  for (const [re, label] of SECRET_PATTERNS) if (re.test(text)) errors.push(`report appears to contain a ${label}; redact it`);
  for (const re of EXPLOIT_HINTS) if (re.test(text)) errors.push(`report appears to contain exploit material (${re}); describe the issue, do not include a PoC`);

  const ids = new Set();
  const assetIds = inventory ? new Set(inventory.assets.map((a) => a.id)) : null;
  for (const f of report.findings) {
    const p = `finding ${f.id}`;
    if (ids.has(f.id)) errors.push(`${p}: duplicate id`);
    ids.add(f.id);
    if (assetIds && !assetIds.has(f.affected.asset_id)) errors.push(`${p}: asset_id "${f.affected.asset_id}" is not in the inventory`);
    if (f.advisory.embargo_respected === false) errors.push(`${p}: embargo not respected; do not report on embargoed material`);
    const v = f.verifier.result;
    if (f.verdict === 'confirmed') {
      if (v !== 'survived') errors.push(`${p}: confirmed requires verifier.result "survived" (got "${v}")`);
      if (f.affected.match_basis === 'manual_reading') errors.push(`${p}: confirmed cannot rest on manual_reading alone`);
      if (f.rejection_reason) errors.push(`${p}: confirmed must not carry rejection_reason`);
      if (['host_runtime_version', 'distro_tracker'].includes(f.affected.match_basis) || f.origin !== 'scanner') {
        if (f.affected.backport_checked !== true) errors.push(`${p}: confirmed runtime or free-text finding requires affected.backport_checked true`);
        if (f.affected.match_basis === 'host_runtime_version' && !f.affected.distro_fixed_version && !f.affected.upstream_fixed_version) {
          errors.push(`${p}: confirmed runtime finding needs a fixed version to compare against`);
        }
      }
    } else if (f.verdict === 'needs_validation') {
      if (v === 'disproved') errors.push(`${p}: needs_validation cannot have a disproved verifier result`);
      if (!f.open_question) errors.push(`${p}: needs_validation requires open_question`);
    } else if (f.verdict === 'rejected') {
      if (v !== 'disproved') errors.push(`${p}: rejected requires verifier.result "disproved" (got "${v}")`);
      if (!f.rejection_reason) errors.push(`${p}: rejected requires rejection_reason`);
    }
    if (f.origin !== 'scanner' && f.verdict === 'confirmed' && !f.advisory.published_at) {
      errors.push(`${p}: free-text finding needs advisory.published_at`);
    }
  }

  if (assetIds) {
    const covered = new Set();
    for (const c of report.coverage) if (c.status === 'checked') c.asset_ids.forEach((a) => covered.add(a));
    for (const c of report.coverage) for (const a of c.asset_ids) if (!assetIds.has(a)) errors.push(`coverage "${c.source}": unknown asset "${a}"`);
    for (const id of assetIds) if (!covered.has(id)) errors.push(`asset "${id}" has no coverage entry with status "checked"`);
  }
  for (const c of report.coverage) {
    if (['skipped', 'failed', 'partial'].includes(c.status) && !c.reason) errors.push(`coverage "${c.source}": status ${c.status} requires reason`);
  }

  if (report.mode === 'remediation_plan' && !report.remediation_plan) errors.push('mode remediation_plan requires remediation_plan');
  if (report.remediation_plan) {
    for (const s of report.remediation_plan.steps) {
      if (!ids.has(s.finding_id)) errors.push(`plan step references unknown finding "${s.finding_id}"`);
      else {
        const f = report.findings.find((x) => x.id === s.finding_id);
        if (f.verdict === 'rejected') errors.push(`plan step for rejected finding ${s.finding_id}`);
      }
      if (s.dry_run === false && s.approval !== 'approved') errors.push(`step for ${s.finding_id}: live run needs approval "approved"`);
      if (s.approval === 'approved' && !s.approved_by) errors.push(`step for ${s.finding_id}: approved requires approved_by`);
    }
  }
  return errors;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const file = args[0];
  const invIdx = args.indexOf('--inventory');
  if (!file) { console.error('usage: validate-report.mjs <report.json> [--inventory inventory.json]'); process.exit(2); }
  let report, inv = null;
  try {
    report = JSON.parse(readFileSync(file, 'utf8'));
    if (invIdx > -1) inv = JSON.parse(readFileSync(args[invIdx + 1], 'utf8'));
  } catch (e) { console.error(`cannot read input: ${e.message}`); process.exit(2); }
  const errors = validateReport(report, inv);
  if (errors.length) { errors.forEach((e) => console.error(`ERROR ${e}`)); process.exit(1); }
  const n = (v) => report.findings.filter((f) => f.verdict === v).length;
  console.log(`OK ${report.findings.length} findings (confirmed ${n('confirmed')}, needs_validation ${n('needs_validation')}, rejected ${n('rejected')})`);
}
