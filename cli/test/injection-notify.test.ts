import assert from 'node:assert/strict';
import { test } from 'node:test';
import { formatFinding, formatMessage } from '../src/notify/index.js';
import { plainAlertText, safeAlertUrl } from '../src/notify/format.js';
import type { Finding } from '../src/types.js';

const cp = (...n: number[]) => String.fromCodePoint(...n);

const base: Finding = {
  key: 'k', advisoryId: 'vendor-1', aliases: [], cves: [], title: 'Security update', severity: 'high', source: 'rss:x',
  component: { ecosystem: 'npm', name: 'lodash', version: '4.17.20', origin: 'package-lock.json', project: 'demo', kind: 'package' },
  basis: 'llm-triage', verdict: 'needs-verification', score: 60, tier: 'alert', kev: false, firstSeen: 'a', lastSeen: 'a',
} as unknown as Finding;

test('INJ-N01 an advisory title cannot put a clickable link, Slack token or mention into an alert', () => {
  const titles = [
    'Urgent: verify your account at https://evil.example/login now',
    'See <https://evil.example|our fix> and <!channel> <@U12345>',
    'Click [here](https://evil.example/x) or [there](javascript:alert(1))',
    'Open www.evil.example/pay and data:text/html;base64,AAAA',
    'ping @channel @here @everyone',
    'back`tick`',
  ];
  for (const title of titles) {
    const out = formatFinding({ ...base, title });
    assert.ok(!/evil\.example/.test(out), `host survived in: ${out}`);
    assert.ok(!/[<>`]/.test(out), `markup survived in: ${out}`);
    assert.ok(!/javascript:|data:text/i.test(out), `scheme survived in: ${out}`);
    assert.ok(!/@(channel|here|everyone)\b/i.test(out), `mention survived in: ${out}`);
  }
});

test('INJ-N02 note, advisory id, project and package fields get the same treatment', () => {
  const out = formatFinding({
    ...base,
    advisoryId: 'https://evil.example/advisory',
    note: 'run <!here> and visit http://evil.example/a',
    component: { ...base.component, name: '[x](http://evil.example)', project: '<!channel>' },
  });
  assert.ok(!/evil\.example|<|>/.test(out), out);
});

test('INJ-N03 hidden characters and bidi controls are removed from alert text', () => {
  const out = plainAlertText(`pay${cp(0x200b)}load${cp(0x202e)}${cp(0xe0041)}`, 100);
  assert.equal(out, 'payload');
});

test('INJ-N04 only a plain https advisory link is shown; others are left out', () => {
  assert.equal(safeAlertUrl('https://github.com/advisories/GHSA-aaaa-bbbb-cccc'), 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc');
  for (const u of ['http://example.com/a', 'javascript:alert(1)', 'https://user:pw@example.com/', 'https://example.com/a b', 'https://example.com/<x>', `https://example.com/${'a'.repeat(400)}`, 'ftp://example.com', undefined]) {
    assert.equal(safeAlertUrl(u), undefined, String(u));
  }
  assert.ok(!formatFinding({ ...base, url: 'javascript:alert(1)' }).includes('javascript'));
  assert.ok(formatFinding({ ...base, url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc' }).endsWith('GHSA-aaaa-bbbb-cccc'));
});

test('INJ-N05 a hostile title cannot grow the message past its bound', () => {
  const msg = formatMessage('H', Array.from({ length: 40 }, () => ({ ...base, title: 'x '.repeat(5000), note: 'y '.repeat(5000) })), 40);
  assert.ok(msg.length <= 4000);
});

test('INJ-N06 bypass strings: split scheme, scheme prefix, bare domain, nested markup', () => {
  const bypass = ['h<t>tps://x.y/a', 'h`t`tp://evil.example', 'xhttps://a.b/c', 'evil.example/path', 'Visit evil.example now', 'a.evil.example', 'ht<<>>tps://evil.example', 'jav<>ascript:alert(1)', 'sub.domain.co.uk/x?y=1'];
  for (const b of bypass) {
    const out = plainAlertText(b, 200);
    assert.ok(!/https?:\/\//i.test(out), `scheme in ${JSON.stringify(out)}`);
    assert.ok(!/[a-z0-9]\.[a-z]{2,}/i.test(out), `linkable domain in ${JSON.stringify(out)}`);
    assert.ok(!/javascript:/i.test(out), out);
    assert.equal(plainAlertText(out, 200), out, `not stable: ${out}`);
  }
  assert.ok(!formatFinding({ ...base, title: 'h<t>tps://x.y/a and evil.example/path' }).match(/x\.y|evil\.example/));
});

test('INJ-N07 dot look-alikes, IDN hosts, IPs with ports and numeric hosts cannot linkify', () => {
  const dots = [0x3002, 0xff0e, 0xff61].map((c) => String.fromCharCode(c));
  const cases = [...dots.map((d) => `evil${d}example`), 'b' + String.fromCharCode(0xfc) + 'cher.example', '1.2.3.4:8080/x', '1.2.3.4', 'host:8080/path', 'a.b.c.d.example/x?y=1'];
  for (const c of cases) {
    const out = plainAlertText(c, 200);
    assert.ok(!/[^\s[]\.[^\s\]]/.test(out), `unbracketed dot in ${JSON.stringify(out)}`);
    assert.equal(plainAlertText(out, 200), out);
  }
  assert.equal(plainAlertText('upgrade to 4.17.21.', 50), 'upgrade to 4.17.21.', 'plain versions and sentence dots are kept');
});

test('INJ-N08 a version-looking prefix cannot carry a domain tail past the neutralizer', () => {
  for (const c of ['1.2.3-evil.example.com', 'v2.0.0+x.attacker.io', '1.2.3-rc.evil.example', '1.2.3-a-b.c.d.example', '1.2.3-x.10.0.0.1', '1.2-a.192.168.1.10', '1.2.3-a.1.2.3.4']) {
    const out = plainAlertText(c, 200);
    assert.ok(!/[^\s[]\.[^\s\]]/.test(out), `unbracketed dot in ${JSON.stringify(out)}`);
    assert.equal(plainAlertText(out, 200), out);
  }
  for (const v of ['1.2.3-rc.1', '2.0.0+build.5', 'v1.2', '4.17.21']) assert.equal(plainAlertText(v, 50), v, `${v} stays readable`);
});
