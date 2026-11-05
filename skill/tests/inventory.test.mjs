import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { validateInventory } from '../scripts/validate-inventory.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const load = () => JSON.parse(readFileSync(join(here, 'fixtures', 'inventory-valid.json'), 'utf8'));

test('valid inventory passes', () => {
  assert.deepEqual(validateInventory(load()), []);
});
test('duplicate ids fail', () => {
  const inv = load(); inv.assets.push({ ...inv.assets[0] });
  assert.ok(validateInventory(inv).some((e) => /duplicate/.test(e)));
});
test('host runtime without distro fails', () => {
  const inv = load(); delete inv.assets.find((a) => a.id === 'host:php').distro;
  assert.ok(validateInventory(inv).some((e) => /distro/.test(e)));
});
test('image without digest fails', () => {
  const inv = load(); delete inv.assets.find((a) => a.id === 'img:api').digest;
  assert.ok(validateInventory(inv).some((e) => /digest/.test(e)));
});
test('floating version fails', () => {
  const inv = load(); inv.assets[0].version = 'latest';
  assert.ok(validateInventory(inv).some((e) => /concrete/.test(e)));
});
test('unknown kind fails schema', () => {
  const inv = load(); inv.assets[0].kind = 'mystery';
  assert.ok(validateInventory(inv).length > 0);
});
