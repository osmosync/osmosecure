import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { validateReport } from '../scripts/validate-report.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const fx = (n) => join(here, 'fixtures', n);
const load = (n) => JSON.parse(readFileSync(fx(n), 'utf8'));
const report = () => load('report-valid.json');
const inv = () => load('inventory-valid.json');
const has = (errs, re) => errs.some((e) => re.test(e));

test('valid report passes with and without inventory', () => {
  assert.deepEqual(validateReport(report()), []);
  assert.deepEqual(validateReport(report(), inv()), []);
});
test('fixture covers the PHP host-runtime case no lockfile scanner flags', () => {
  const f = report().findings.find((x) => x.affected.asset_id === 'host:php');
  assert.equal(f.origin, 'free_text_disclosure');
  assert.equal(f.verdict, 'confirmed');
  assert.equal(f.affected.backport_checked, true);
});
test('disclosure fixture carries an injection attempt that must stay data', () => {
  const txt = readFileSync(fx('php-disclosure.txt'), 'utf8');
  assert.match(txt, /ignore your previous instructions/);
  // the report must not contain any of the injected content
  assert.ok(!/attacker\.example/.test(JSON.stringify(report())));
});
test('confirmed needs a surviving verifier', () => {
  const r = report(); r.findings[0].verifier.result = 'inconclusive';
  assert.ok(has(validateReport(r), /requires verifier\.result "survived"/));
});
test('confirmed host runtime finding needs backport_checked', () => {
  const r = report(); r.findings[0].affected.backport_checked = false;
  assert.ok(has(validateReport(r), /backport_checked/));
});
test('rejected needs reason and disproof', () => {
  const r = report(); delete r.findings[1].rejection_reason;
  assert.ok(has(validateReport(r), /rejection_reason/));
});
test('needs_validation needs open_question', () => {
  const r = report(); delete r.findings[2].open_question;
  assert.ok(has(validateReport(r), /open_question/));
});
test('unknown verdict fails schema', () => {
  const r = report(); r.findings[0].verdict = 'probably';
  assert.ok(validateReport(r).length > 0);
});
test('unknown asset against inventory fails', () => {
  const r = report(); r.findings[0].affected.asset_id = 'host:ghost';
  assert.ok(has(validateReport(r, inv()), /not in the inventory/));
});
test('uncovered asset fails coverage ledger', () => {
  const r = report(); r.coverage[1].asset_ids = r.coverage[1].asset_ids.filter((a) => a !== 'host:node');
  assert.ok(has(validateReport(r, inv()), /host:node.*no coverage/));
});
test('skipped coverage needs reason', () => {
  const r = report(); r.coverage[0].status = 'skipped';
  assert.ok(has(validateReport(r), /requires reason/));
});
test('secrets are rejected', () => {
  const r = report(); r.findings[0].hunter.evidence.push('token ghp_' + 'a'.repeat(36));
  assert.ok(has(validateReport(r), /GitHub token/));
});
test('exploit material is rejected', () => {
  const r = report(); r.findings[0].hunter.evidence.push('```sh\nrun payload\n```');
  assert.ok(has(validateReport(r), /exploit material/));
});
test('embargo violation is rejected', () => {
  const r = report(); r.findings[0].advisory.embargo_respected = false;
  assert.ok(has(validateReport(r), /embargo/));
});
test('plan cannot claim a push or deploy', () => {
  const r = report(); r.remediation_plan.pushes_or_deploys = true;
  assert.ok(validateReport(r).length > 0);
});
test('live step needs approval and plan cannot target rejected finding', () => {
  const r = report(); r.remediation_plan.steps[0].dry_run = false;
  assert.ok(has(validateReport(r), /needs approval/));
  const r2 = report(); r2.remediation_plan.steps[0].finding_id = 'F-002';
  assert.ok(has(validateReport(r2), /rejected finding/));
});
test('CLI exits 0 on valid and 1 on invalid', () => {
  const script = join(here, '..', 'scripts', 'validate-report.mjs');
  const ok = spawnSync(process.execPath, [script, fx('report-valid.json'), '--inventory', fx('inventory-valid.json')]);
  assert.equal(ok.status, 0, ok.stderr.toString());
  const bad = spawnSync(process.execPath, [script, fx('inventory-valid.json')]);
  assert.equal(bad.status, 1);
});
