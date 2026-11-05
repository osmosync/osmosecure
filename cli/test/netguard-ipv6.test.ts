import assert from 'node:assert/strict';
import { test } from 'node:test';
import { isPrivateAddress } from '../src/lib/netguard.js';

const PRIVATE: [string, string][] = [
  ['2002:7f00:1::1', '6to4 embedding 127.0.0.1'],
  ['2002:0a00:0001::1', '6to4 embedding 10.0.0.1'],
  ['2002:a9fe:a9fe::1', '6to4 embedding the cloud metadata address'],
  ['2001:0:4136:e378:8000:63bf:3fff:fdd2', 'Teredo 2001::/32'],
  ['2001::1', 'Teredo 2001::/32'],
  ['64:ff9b:1::1', '64:ff9b:1::/48'],
  ['64:ff9b:1:abcd::7f00:1', '64:ff9b:1::/48'],
  ['64:ff9b::7f00:1', 'NAT64 embedding 127.0.0.1'],
  ['64:ff9b::a9fe:a9fe', 'NAT64 embedding the metadata address'],
  ['100::1', 'discard 100::/64'],
  ['100::ffff:ffff:ffff:ffff', 'discard 100::/64'],
  ['2001:db8::1', 'documentation 2001:db8::/32'],
  ['2001:db8:ffff::5', 'documentation 2001:db8::/32'],
  ['::ffff:127.0.0.1', 'IPv4-mapped loopback'],
  ['::ffff:10.0.0.1', 'IPv4-mapped private'],
  ['::1', 'loopback'],
  ['::', 'unspecified'],
  ['fc00::1', 'unique local'],
  ['fe80::1', 'link local'],
  ['ff02::1', 'multicast'],
  ['4000::1', 'outside 2000::/3'],
  ['not-an-ip', 'unparseable'],
];
const PUBLIC: [string, string][] = [
  ['2606:4700:4700::1111', 'global unicast'],
  ['2001:4860:4860::8888', 'global unicast'],
  ['2002:5db8:d822::1', '6to4 embedding public 93.184.216.34'],
  ['64:ff9b::5db8:d822', 'NAT64 embedding public 93.184.216.34'],
  ['::ffff:93.184.216.34', 'IPv4-mapped public'],
  ['93.184.216.34', 'public IPv4'],
];

test('netguard: IPv6 transition and special-purpose prefixes are private', () => {
  for (const [ip, why] of PRIVATE) assert.equal(isPrivateAddress(ip), true, `${ip} (${why})`);
});

test('netguard: public global unicast and public embedded IPv4 are allowed', () => {
  for (const [ip, why] of PUBLIC) assert.equal(isPrivateAddress(ip), false, `${ip} (${why})`);
});
