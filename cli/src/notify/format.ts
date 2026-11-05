import { normalizeUntrusted } from '../lib/untrusted.js';
import type { Finding } from '../types.js';

const MESSAGE_LIMIT = 4000;

/**
 * One line of plain text from a field that may carry feed, lockfile or model text. Alert channels render markup
 * (Slack `<url|label>` and `<!channel>`, Markdown links), and a clickable attacker URL inside a trusted alert is a
 * phishing tool, so links, angle brackets, backticks and broadcast mentions are removed, not escaped.
 */
export function plainAlertText(s: string, n: number): string {
  // Repeat until nothing changes, so text such as "h<t>tps://x.y" cannot turn back into a link after a later step.
  let out = normalizeUntrusted(s);
  for (let i = 0; i < 6; i++) {
    const next = normalizeUntrusted(neutralizeAlertPass(out)).replace(/\s+/g, ' ').trim();
    if (next === out) break;
    out = next;
  }
  return out.slice(0, n);
}

// BEGIN shared-alert-rules
const DOT_LIKE = [0x3002, 0xff0e, 0xff61, 0x2024, 0xfe52];
/** Two or three numeric parts with an optional pre-release or build tail. Four parts (a dotted quad) is not a version here. */
const PLAIN_VERSION = /^v?\d+(?:\.\d+){1,2}(?:[-+~][0-9A-Za-z]+(?:\.\d+)?){0,3}$/;
const IPV4_LIKE = /\d+\.\d+\.\d+\.\d+/;

/** Every dot between two non-space characters is bracketed, so hosts (ASCII, IDN, IP, host:port) cannot linkify. Plain versions are left alone. */
function neutralizeToken(tok: string): string {
  const m = /^([\s\S]*?)([.,;:!?)\]]*)$/.exec(tok) as RegExpExecArray;
  if (PLAIN_VERSION.test(m[1]) && !IPV4_LIKE.test(m[1])) return tok;
  return m[1].replace(/(?<=[^\s[])\.(?=[^\s\]])/g, '[.]') + m[2];
}

/** One pass of the alert-text rules. Callers repeat it until the output stops changing. */
export function neutralizeAlertPass(input: string): string {
  let s = input.normalize('NFKC');
  for (const c of DOT_LIKE) s = s.split(String.fromCharCode(c)).join('.');
  return s
    .replace(/[<>`]/g, '')
    .replace(/[a-z][a-z0-9+.-]{1,15}:\/\/\S*/gi, '(link removed)')
    .replace(/(?:javascript|data|vbscript|file|mailto|tel):\S*/gi, '(link removed)')
    .replace(/www\.\S+/gi, '(link removed)')
    .replace(/\]\([^)]*\)?/g, ']')
    .replace(/@(channel|here|everyone)(?![\w/-])/gi, '($1)')
    .replace(/\S+/g, neutralizeToken);
}
// END shared-alert-rules

const clean = plainAlertText;

/** Only a plain https link survives: no credentials, no whitespace, bounded length. Anything else is left out of the alert. */
export function safeAlertUrl(raw: string | undefined): string | undefined {
  if (!raw || raw.length > 300 || /[\s<>"'`]/.test(raw)) return undefined;
  try {
    const u = new URL(raw);
    return u.protocol === 'https:' && !u.username && !u.password ? u.href : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Notifications never carry exploit material. Feed or model text can embed a proof of concept, so
 * code fences, shell one-liners that fetch or execute, and long encoded payloads are replaced
 * with a marker before anything leaves the process. Refer to the advisory URL instead.
 */
export function redactPoc(text: string): string {
  return text
    .replace(/```[\s\S]*?```/g, '[code removed]')
    .replace(/`[^`\n]{40,}`/g, '[code removed]')
    .replace(/\b(?:curl|wget|nc|ncat|bash|sh|python3?|perl|powershell|msfconsole)\s+[^\n]{0,200}(?:\||;|&&|-e\b|-c\b|http)[^\n]*/gi, '[command removed]')
    .replace(/[A-Za-z0-9+/_=-]{80,}/g, '[payload removed]');
}

const SEVERITY_WORD: Record<string, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };

/**
 * Plain-English text for one finding, for people reading Telegram or Slack: what is wrong and where, whether it
 * is being exploited, what to do, the advisory id and its public link. Package details and public advisory text
 * only (proof-of-concept material is removed); never project code or environment values.
 */
export function formatFinding(f: Finding): string {
  const c = f.component;
  const what = c.kind === 'image' ? `container image ${c.name} ${c.version}` : `${c.name} ${c.version}`;
  const facts: string[] = [];
  if (f.kev) facts.push('Known to be exploited in the wild.');
  else if (f.epss !== undefined && f.epss >= 0.1) facts.push(`Estimated chance of exploitation soon: ${(f.epss * 100).toFixed(0)}%.`);
  facts.push(f.fixedVersion ? `Fix: upgrade to ${clean(f.fixedVersion, 60)}.` : 'No fixed version is published yet.');
  if (f.verdict === 'needs-verification') facts.push('Check that it really affects you.');
  const lines = [
    `${SEVERITY_WORD[f.severity] ?? 'Unrated'} security issue in ${clean(what, 120)} (${c.ecosystem}, project ${clean(c.project, 60)}).`,
    facts.join(' '),
    `Advisory ${clean(f.advisoryId, 60)}: ${clean(redactPoc(f.title), 120)}`,
  ];
  if (f.note) lines.push(clean(redactPoc(f.note), 160));
  const link = safeAlertUrl(f.url);
  if (link) lines.push(link);
  return lines.join('\n');
}

export function formatMessage(heading: string, findings: Finding[], max: number): string {
  const shown = findings.slice(0, max);
  const n = findings.length;
  const parts = [`${heading}: ${n} security ${n === 1 ? 'issue' : 'issues'} to look at.`, ...shown.map(formatFinding)];
  if (n > shown.length) parts.push(`And ${n - shown.length} more. Run "osmosecure status" to see them all.`);
  return parts.join('\n\n').slice(0, MESSAGE_LIMIT);
}
