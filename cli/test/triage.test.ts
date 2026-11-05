import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { scannable } from '../src/scan/osv.js';
import { triageItem, type TriageClient } from '../src/triage/llm.js';
import { matchTriage } from '../src/triage/matcher.js';
import { buildPackageNames, buildProductTerms, prefilter } from '../src/triage/prefilter.js';
import { buildTriageUserMessage, sanitizeDisclosure } from '../src/triage/prompt.js';
import { parseTriageReply } from '../src/triage/schema.js';
import type { Component, FeedItem } from '../src/types.js';

const fx = (n: string) => readFileSync(fileURLToPath(new URL(`./fixtures/${n}`, import.meta.url)), 'utf8');

const host = (name: string, version: string, hostId: string, distro: boolean): Component => ({
  ecosystem: 'Host', name, version, origin: `${hostId}:dpkg`, project: `host:${hostId}`, kind: 'runtime', distroPackaged: distro,
});

const inventory: Component[] = [
  host('php', '8.3.6-0ubuntu0.24.04.2', 'host-a', true), // distro build, branch 8.3
  host('php', '8.2.19', 'host-b', false), // upstream build below 8.2.20
  host('php', '8.3.9', 'local', false), // already fixed
  host('php', '8.4.1', 'edge', false), // branch not listed in the bulletin
  host('nginx', '1.24.0', 'host-a', true),
  { ecosystem: 'npm', name: 'lodash', version: '4.17.20', origin: 'package-lock.json', project: 'demo', kind: 'package' },
];

const item: FeedItem = {
  source: 'rss:php-news', id: 'php-8.3.8', title: 'PHP 8.3.8, 8.2.20 and 8.1.29 security releases',
  text: fx('php-disclosure.txt'), cves: ['CVE-2024-4577'], productHints: [],
};

test('PHP-style disclosure: no package scanner can see host runtimes', () => {
  const php = inventory.filter((c) => c.name === 'php');
  assert.ok(php.length === 4 && php.every((c) => !scannable(c)), 'host runtimes are outside OSV package scanning');
});

test('prefilter passes the PHP bulletin and rejects unrelated text', () => {
  const terms = buildProductTerms(inventory);
  const names = buildPackageNames(inventory);
  assert.ok(prefilter(item, terms, names));
  assert.ok(!prefilter({ ...item, title: 'Weekly gardening digest', text: 'tomatoes and basil' }, terms, names));
});

test('prefilter: hints decide when present; bare "node" in prose is ignored', () => {
  const terms = buildProductTerms([...inventory, host('node', '22.1.0', 'local', false)]);
  const names = buildPackageNames(inventory);
  const base: FeedItem = { source: 'nvd', id: 'CVE-2099-0001', title: 'CVE-2099-0001', text: 'A DOM node is mishandled in php', cves: [], productHints: [] };
  assert.ok(prefilter(base, terms, names)); // no hints: prose mentions php
  assert.ok(!prefilter({ ...base, text: 'A tree node is mishandled' }, terms, names));
  assert.ok(prefilter({ ...base, text: 'runs on Node.js' }, terms, names));
  assert.ok(!prefilter({ ...base, productHints: ['wordpress', 'acme'] }, terms, names)); // hints say other products
  assert.ok(prefilter({ ...base, text: 'x', productHints: ['lodash'] }, terms, names));
  assert.ok(prefilter({ ...base, text: 'x', productHints: ['nodejs'] }, terms, names));
});

test('fixture reply + matcher flags the right PHP runtimes, branch-aware', () => {
  const t = parseTriageReply(fx('php-triage-reply.json'));
  const matches = matchTriage(t.products, inventory);
  const by = Object.fromEntries(matches.map((m) => [m.component.project, m]));
  // distro build below the fixed upstream version: downgraded because backports are likely
  assert.equal(by['host:host-a'].verdict, 'needs-verification');
  assert.match(by['host:host-a'].reason, /backport/);
  assert.equal(by['host:host-a'].fixedVersion, '8.3.8');
  // plain upstream build below its branch fix is affected
  assert.equal(by['host:host-b'].verdict, 'affected');
  assert.equal(by['host:host-b'].fixedVersion, '8.2.20');
  // fixed build produces no match
  assert.equal(by['host:local'], undefined);
  // branch 8.4 not listed: cannot be judged
  assert.equal(by['host:edge'].verdict, 'needs-verification');
  // unrelated products never match
  assert.ok(!matches.some((m) => m.component.name === 'nginx' || m.component.name === 'lodash'));
});

test('library package ranges and ecosystem guard', () => {
  const t = parseTriageReply(JSON.stringify({
    relevant: true, severity: 'high',
    products: [{ name: 'lodash', ecosystem: 'npm', affectedRanges: [{ introduced: '4.0.0', fixed: '4.17.21' }], fixedVersions: [] }],
  }));
  const m = matchTriage(t.products, inventory);
  assert.equal(m.length, 1);
  assert.equal(m[0].verdict, 'affected');
  assert.equal(m[0].fixedVersion, '4.17.21');
  const wrongEco = parseTriageReply(JSON.stringify({ relevant: true, products: [{ name: 'lodash', ecosystem: 'PyPI', affectedRanges: [{ fixed: '9.9.9' }] }] }));
  assert.equal(matchTriage(wrongEco.products, inventory).length, 0);
});

test('floating image tags need verification rather than a verdict', () => {
  const img: Component = { ecosystem: 'Docker', name: 'library/postgres', version: 'latest', origin: 'compose', project: 'demo', kind: 'image' };
  const t = parseTriageReply(JSON.stringify({ relevant: true, products: [{ name: 'postgres', fixedVersions: ['16.4'] }] }));
  const m = matchTriage(t.products, [img, { ...img, version: '16' }]);
  assert.deepEqual(m.map((x) => x.verdict), ['needs-verification', 'needs-verification']);
});

test('feed text is wrapped as untrusted data; delimiter injection is neutralized', () => {
  const msg = buildTriageUserMessage(item.title, item.text, item.source, 6000);
  assert.equal((msg.match(/<disclosure>/g) ?? []).length, 1);
  assert.equal((msg.match(/<\/disclosure>/g) ?? []).length, 1);
  assert.match(msg, /\[tag removed\]/);
  assert.ok(sanitizeDisclosure('x'.repeat(10_000), 100).length === 100);
  assert.equal(sanitizeDisclosure('a\u0000b', 10), 'a b');
});

test('triageItem frames feed text as untrusted, tool-free, and tolerates fenced JSON', async () => {
  const seen: { system: string; user: string }[] = [];
  const client: TriageClient = {
    async complete(system, user) {
      seen.push({ system, user });
      return 'Here you go:\n```json\n' + fx('php-triage-reply.json') + '\n```';
    },
  };
  const t = await triageItem(client, item, 6000);
  assert.equal(t.relevant, true);
  assert.match(seen[0].system, /untrusted/);
  assert.match(seen[0].system, /no tools/);
});

test('malformed or hostile model output is rejected', () => {
  assert.throws(() => parseTriageReply('no json here'));
  assert.throws(() => parseTriageReply('{"relevant":"yes"}'));
  assert.throws(() => parseTriageReply(JSON.stringify({ relevant: true, products: [{ name: 'php', fixedVersions: ['8.3.8; rm -rf /'] }] })));
  assert.throws(() => parseTriageReply(JSON.stringify({ relevant: true, cves: ['not-a-cve'] })));
});
