import type { LookupAddress } from 'node:dns';
import { lookup as dnsLookup } from 'node:dns/promises';
import { isIP } from 'node:net';

/** Raised for requests the client refuses on policy grounds (private target, oversize body). Never retried. */
export class HttpGuardError extends Error {}

export type HostLookup = (host: string) => Promise<string[]>;

export const systemLookup: HostLookup = async (host) => (await dnsLookup(host, { all: true })).map((a) => a.address);

function v4Parts(ip: string): number[] | null {
  const p = ip.split('.').map(Number);
  return p.length === 4 && p.every((n) => Number.isInteger(n) && n >= 0 && n <= 255) ? p : null;
}

function privateV4(ip: string): boolean {
  const p = v4Parts(ip);
  if (!p) return true; // unparseable: refuse
  const [a, b, c] = p;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) || // carrier-grade NAT
    (a === 169 && b === 254) || // link local, cloud metadata
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && c === 0) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224 // multicast and reserved
  );
}

/** Expands an IPv6 literal to eight 16-bit groups, or null when it does not parse. */
function v6Groups(ip: string): number[] | null {
  let s = ip;
  const zone = s.indexOf('%');
  if (zone >= 0) s = s.slice(0, zone);
  const tail = /(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (tail) {
    const p = v4Parts(tail[1]);
    if (!p) return null;
    s = s.slice(0, s.length - tail[1].length) + ((p[0] << 8) | p[1]).toString(16) + ':' + ((p[2] << 8) | p[3]).toString(16);
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = halves.length === 2 ? 8 - head.length - rest.length : 0;
  if (fill < 0 || (halves.length === 1 && head.length !== 8)) return null;
  const all = [...head, ...Array(fill).fill('0'), ...rest].map((g) => Number.parseInt(g, 16));
  return all.length === 8 && all.every((n) => Number.isInteger(n) && n >= 0 && n <= 0xffff) ? all : null;
}

function privateV6(ip: string): boolean {
  const g = v6Groups(ip);
  if (!g) return true;
  const embeddedV4 = (): string => `${g[6] >> 8}.${g[6] & 255}.${g[7] >> 8}.${g[7] & 255}`;
  if (g.slice(0, 5).every((x) => x === 0) && (g[5] === 0xffff || g[5] === 0)) {
    // ::, ::1, ::ffff:a.b.c.d and deprecated IPv4-compatible forms
    return g[5] === 0 && g[6] === 0 && g[7] <= 1 ? true : privateV4(embeddedV4());
  }
  if (g[0] === 0x64 && g[1] === 0xff9b) {
    if (g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0) return privateV4(embeddedV4()); // 64:ff9b::/96 NAT64
    return true; // 64:ff9b:1::/48 local-use NAT64 and the rest of 64:ff9b::/32
  }
  if (g[0] === 0x2002) return privateV4(`${g[1] >> 8}.${g[1] & 255}.${g[2] >> 8}.${g[2] & 255}`); // 6to4: classify the embedded IPv4
  if (g[0] === 0x2001 && g[1] === 0) return true; // Teredo 2001::/32
  if (g[0] === 0x2001 && g[1] === 0xdb8) return true; // documentation 2001:db8::/32
  // 100::/64 discard, fc00::/7, fe80::/10, ff00::/8 and everything else outside 2000::/3 global unicast are refused.
  return (g[0] & 0xe000) !== 0x2000;
}

/** True for loopback, private, link-local, metadata, multicast and unspecified addresses. */
export function isPrivateAddress(ip: string): boolean {
  const bare = ip.replace(/^\[|\]$/g, '');
  const kind = isIP(bare);
  if (kind === 4) return privateV4(bare);
  if (kind === 6) return privateV6(bare);
  return true;
}

function privateName(host: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  return h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.home.arpa') || !h.includes('.');
}

export interface GuardOptions {
  allowPrivate?: boolean;
  /** When set, hostnames are resolved and every returned address must be public. */
  lookup?: HostLookup;
}

/** Throws HttpGuardError unless the URL is http(s), credential-free and points at a public address. */
export async function assertPublicUrl(raw: string, opts: GuardOptions = {}): Promise<URL> {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new HttpGuardError('invalid url');
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new HttpGuardError(`blocked scheme ${u.protocol}`);
  if (u.username || u.password) throw new HttpGuardError('credentials in url are not allowed');
  if (opts.allowPrivate) return u;
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (isIP(host)) {
    if (isPrivateAddress(host)) throw new HttpGuardError(`blocked private address for ${u.host}`);
    return u;
  }
  if (privateName(host)) throw new HttpGuardError(`blocked internal host name ${u.host}`);
  if (opts.lookup) {
    let addrs: string[];
    try {
      addrs = await opts.lookup(host);
    } catch (err) {
      throw new Error(`dns lookup failed for ${u.host}: ${err instanceof Error ? err.message : String(err)}`);
    }
    if (addrs.length === 0 || addrs.some(isPrivateAddress)) throw new HttpGuardError(`blocked: ${u.host} resolves to a private address`);
  }
  return u;
}

/** Resolves every address for a host (dns.lookup with all:true semantics). */
export type AddressResolver = (host: string) => Promise<LookupAddress[]>;

const systemResolve: AddressResolver = (host) => dnsLookup(host, { all: true });

type LookupCallback = (err: NodeJS.ErrnoException | null, address?: string | LookupAddress[], family?: number) => void;

/**
 * Builds a connect-time lookup for undici. It resolves with all:true, refuses an empty list or ANY private
 * address, and hands back only addresses that passed, so the socket can never dial an unchecked address.
 */
export function makeGuardedLookup(resolve: AddressResolver = systemResolve) {
  return (hostname: string, options: { all?: boolean; family?: number | string } | undefined, callback: LookupCallback): void => {
    resolve(hostname).then(
      (addrs) => {
        const fam = options?.family;
        const wanted = fam === 4 || fam === 'IPv4' ? 4 : fam === 6 || fam === 'IPv6' ? 6 : 0;
        const list = wanted ? addrs.filter((a) => a.family === wanted) : addrs;
        if (addrs.length === 0 || list.length === 0) {
          callback(new HttpGuardError(`blocked: ${hostname} has no usable address`));
          return;
        }
        if (addrs.some((a) => isPrivateAddress(a.address))) {
          callback(new HttpGuardError(`blocked: ${hostname} resolves to a private address`));
          return;
        }
        if (options?.all) callback(null, list);
        else callback(null, list[0].address, list[0].family);
      },
      (err: unknown) => callback(err instanceof Error ? (err as NodeJS.ErrnoException) : new Error(String(err))),
    );
  };
}

/** Connect-time guard using system DNS. The security boundary against DNS rebinding; assertPublicUrl is only a fast fail. */
export const guardedLookup = makeGuardedLookup();
