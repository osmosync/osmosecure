/**
 * Secret scrubbing applied to every string before it reaches a model backend. Disclosures come from
 * public feeds and should not contain secrets, but a feed can quote a leaked token and the
 * process environment is never allowed into a prompt. Two layers: known token shapes, and the
 * literal values of secret-looking environment variables.
 */
const PATTERNS: [RegExp, string][] = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g, '[redacted:private-key]'],
  [/\bAKIA[0-9A-Z]{16}\b/g, '[redacted:aws-key]'],
  [/\bgh[pousr]_[A-Za-z0-9]{30,}\b/g, '[redacted:github-token]'],
  [/\bgithub_pat_[A-Za-z0-9_]{40,}\b/g, '[redacted:github-token]'],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, '[redacted:slack-token]'],
  [/\bsk-ant-[A-Za-z0-9_-]{20,}\b/g, '[redacted:anthropic-key]'],
  [/\bsk-[A-Za-z0-9_-]{32,}\b/g, '[redacted:api-key]'],
  [/\bAIza[0-9A-Za-z_-]{35}\b/g, '[redacted:google-key]'],
  [/\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, '[redacted:jwt]'],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]{16,}/g, 'Bearer [redacted]'],
  [/\b\d{6,}:[A-Za-z0-9_-]{30,}\b/g, '[redacted:bot-token]'],
  [/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, '[redacted:aws-key]'],
  [/\bnpm_[A-Za-z0-9]{36}\b/g, '[redacted:npm-token]'],
  [/\bglpat-[A-Za-z0-9_-]{20,}/g, '[redacted:gitlab-token]'],
  [/\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g, '[redacted:stripe-key]'],
  [/\bwhsec_[A-Za-z0-9]{16,}\b/g, '[redacted:webhook-secret]'],
  [/\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g, '[redacted:sendgrid-key]'],
  [/\bhf_[A-Za-z0-9]{30,}\b/g, '[redacted:api-key]'],
  [/\bBasic\s+[A-Za-z0-9+/]{16,}={0,2}/g, 'Basic [redacted]'],
  [/(\b[a-z][a-z0-9+.-]{0,31}:\/\/)[^\s/@:]+:[^\s/@]+@/gi, '$1[redacted]@'],
  [/((?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)[A-Za-z0-9_-]{0,64}["']?\s{0,32}[=:]\s{0,32})["']?[^\s"']{8,}["']?/gi, '$1[redacted]'],
];

const SECRET_ENV_NAME = /(key|token|secret|pass|credential|auth|webhook|cookie|session|signature|dsn)/i;

/** Literal values of secret-looking variables, long enough that a match is not a coincidence. */
export function secretValuesFromEnv(env: NodeJS.ProcessEnv = process.env): string[] {
  const out: string[] = [];
  for (const [k, v] of Object.entries(env)) if (v && v.length >= 12 && SECRET_ENV_NAME.test(k)) out.push(v);
  return out;
}

export function scrubSecrets(text: string, env: NodeJS.ProcessEnv = process.env): string {
  let out = text;
  for (const v of secretValuesFromEnv(env)) out = out.split(v).join('[redacted:env]');
  for (const [re, rep] of PATTERNS) out = out.replace(re, rep);
  return out;
}
