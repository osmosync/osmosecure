import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseComposeImages } from '../src/inventory/compose.js';
import { normalizeProduct, parseDpkgTsv, parseImagesTsv } from '../src/inventory/host.js';
import {
  parseComposerLock,
  parseGemfileLock,
  parsePackageLock,
  parsePnpmLock,
  parseRequirements,
  parseYarnLock,
} from '../src/inventory/lockfiles.js';
import { bumpClass, compareVersions } from '../src/lib/version.js';

test('package-lock v3 reads nested node_modules names and skips links', () => {
  const text = JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': { name: 'root' },
      'node_modules/lodash': { version: '4.17.20' },
      'node_modules/a/node_modules/@scope/Pkg': { version: '1.2.3', dev: true },
      'node_modules/linked': { version: '9.9.9', link: true },
    },
  });
  assert.deepEqual(parsePackageLock(text).map((p) => `${p.name}@${p.version}`), ['lodash@4.17.20', '@scope/pkg@1.2.3']);
  assert.equal(parsePackageLock(text, false).length, 1);
});

test('pnpm-lock v9 and v5 keys', () => {
  const text = [
    'lockfileVersion: 9',
    'packages:',
    "  '@scope/pkg@2.0.1':",
    '    resolution: {}',
    '  express@4.18.2(peer@1.0.0):',
    '    resolution: {}',
    'snapshots:',
    '  ignored@1.0.0:',
  ].join('\n');
  assert.deepEqual(parsePnpmLock(text).map((p) => `${p.name}@${p.version}`), ['@scope/pkg@2.0.1', 'express@4.18.2']);
  assert.deepEqual(parsePnpmLock("packages:\n  /left-pad/1.3.0:\n    dev: false\n").map((p) => `${p.name}@${p.version}`), ['left-pad@1.3.0']);
});

test('yarn.lock v1 and berry', () => {
  const v1 = '"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.2.0"\n\nms@2.0.0:\n  version "2.0.0"\n';
  assert.deepEqual(parseYarnLock(v1).map((p) => `${p.name}@${p.version}`), ['@babel/core@7.2.0', 'ms@2.0.0']);
  const berry = '"debug@npm:^4.0.0":\n  version: 4.3.4\n  resolution: "debug@npm:4.3.4"\n';
  assert.deepEqual(parseYarnLock(berry).map((p) => `${p.name}@${p.version}`), ['debug@4.3.4']);
});

test('composer, gemfile, requirements', () => {
  const composer = JSON.stringify({ packages: [{ name: 'Laravel/Framework', version: 'v10.1.0' }], 'packages-dev': [{ name: 'phpunit/phpunit', version: '10.0.0' }] });
  assert.deepEqual(parseComposerLock(composer).map((p) => `${p.ecosystem}:${p.name}@${p.version}`), ['Packagist:laravel/framework@10.1.0', 'Packagist:phpunit/phpunit@10.0.0']);
  const gem = 'GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.4)\n      actionpack (= 7.0.4)\n    nokogiri (1.15.0-x86_64-linux)\n\nPLATFORMS\n  ruby\n';
  assert.deepEqual(parseGemfileLock(gem).map((p) => `${p.name}@${p.version}`), ['rails@7.0.4', 'nokogiri@1.15.0']);
  assert.deepEqual(parseRequirements('Django==4.2.1  # pin\nrequests>=2\nPyYAML[extra]==6.0\n').map((p) => `${p.name}@${p.version}`), ['django@4.2.1', 'pyyaml@6.0']);
});

test('compose images with defaults, digests and missing tags', () => {
  const text = 'services:\n  a:\n    image: postgres:16-alpine\n  b:\n    image: "ghcr.io/org/App:${TAG:-1.2.3}"\n  c:\n    image: redis\n  d:\n    image: ${UNSET}\n  e:\n    image: nginx@sha256:' + 'a'.repeat(64) + '\n';
  assert.deepEqual(parseComposeImages(text).map((i) => `${i.repository}:${i.tag}`), ['postgres:16-alpine', 'ghcr.io/org/app:1.2.3', 'redis:latest', 'nginx:latest']);
});

test('host dumps keep only watchlisted runtimes and normalize names', () => {
  const dpkg = 'php8.3-cli\t8.3.6-0ubuntu0.24.04.2\nphp8.3-common\t8.3.6-0ubuntu0.24.04.2\nlibssl3t64\t3.0.13-0ubuntu3\nbash\t5.2\nnginx\t1.24.0-2ubuntu7\npostgresql-16\t16.4-0ubuntu0.24.04.1\n';
  const comps = parseDpkgTsv(dpkg, 'host-a');
  assert.deepEqual(comps.map((c) => c.name).sort(), ['nginx', 'openssl', 'php', 'postgres']);
  assert.ok(comps.every((c) => c.distroPackaged));
  assert.equal(normalizeProduct('nodejs'), 'node');
  const imgs = parseImagesTsv('postgres:16\tabc123\nvendor/postgres:15.1.0.147\tdef\n', 'host-a');
  assert.equal(imgs[1].name, 'vendor/postgres');
});

test('version helpers', () => {
  assert.equal(compareVersions('8.3.6-0ubuntu0.24.04.2', '8.3.8'), -1);
  assert.equal(compareVersions('1:2.3.4', '2.3.4'), 0);
  assert.equal(compareVersions('latest', '1.0'), null);
  assert.equal(bumpClass('4.17.20', '4.17.21'), 'patch');
  assert.equal(bumpClass('4.17.20', '4.18.0'), 'minor');
  assert.equal(bumpClass('4.17.20', '5.0.0'), 'major');
  assert.equal(bumpClass('0.2.1', '0.3.0'), 'major');
});
