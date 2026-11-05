import assert from 'node:assert/strict';
import { test } from 'node:test';
import { scrubSecrets } from '../src/triage/scrub.js';

// Fake values assembled at runtime so no secret-shaped literal sits in the repository.
const rep = (c: string, n: number) => c.repeat(n);
const cases: [string, string][] = [
  [`{"password": "${rep('h', 12)}"}`, rep('h', 12)],
  [`aws_secret_access_key = ${rep('w', 30)}`, rep('w', 30)],
  [`https://bob:${rep('p', 10)}@example.com/x`, rep('p', 10)],
  [`postgres://u:${rep('q', 10)}@db/x`, rep('q', 10)],
  [`npm_${rep('a', 36)}`, rep('a', 36)],
  [`glpat-${rep('b', 20)}`, rep('b', 20)],
  [`${'sk'}_live_${rep('c', 20)}`, rep('c', 20)],
  [`Authorization: Basic ${rep('d', 20)}==`, rep('d', 20)],
  [`ASIA${rep('E', 16)}`, rep('E', 16)],
  [`SG.${rep('f', 22)}.${rep('g', 22)}`, rep('f', 22)],
];

test('scrubSecrets redacts additional common secret shapes', () => {
  for (const [input, secret] of cases) {
    const out = scrubSecrets(input, {});
    assert.ok(!out.includes(secret), `leaked: ${input.slice(0, 20)}`);
    assert.ok(out.includes('[redacted') || out.includes('Basic [redacted]'), `no marker: ${out}`);
  }
});

test('scrubSecrets leaves ordinary prose and short strings alone', () => {
  const t = 'Fixed in 1.2.3; see https://example.com/advisory and set token=abc';
  assert.equal(scrubSecrets(t, {}), t);
});

test('scrubSecrets still redacts long userinfo and long key names', () => {
  const longPass = rep('p', 400);
  assert.ok(!scrubSecrets(`https://bob:${longPass}@example.com/x`, {}).includes(longPass));
  const v = rep('v', 20);
  assert.ok(!scrubSecrets(`password_for_the_primary_production_database = ${v}`, {}).includes(v));
});

test('scrubSecrets stays fast on hostile repetitive input', () => {
  for (const s of [rep('secret', 10000), `${rep('ab-', 20000)}x`, `a://a${rep(':a', 20000)}`, `password${rep(' ', 30000)}=`]) {
    const t = Date.now();
    scrubSecrets(s, {});
    assert.ok(Date.now() - t < 200, `took ${Date.now() - t} ms on ${s.slice(0, 12)}`);
  }
});
