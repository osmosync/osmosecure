import type { Config } from '../config.js';
import { scrubSecrets } from '../triage/scrub.js';
import type { Logger } from '../types.js';

export { formatFinding, formatMessage, redactPoc } from './format.js';

/** A destination for plain-text alerts. send() resolves false on failure and never throws. */
export interface Notifier {
  readonly name: string;
  send(text: string, log: Logger): Promise<boolean>;
}

type Env = Record<string, string | undefined>;
type FetchLike = typeof fetch;

/** Error text can quote the request URL (Telegram bot token, Slack webhook path), so the URL is masked before logging. */
function errMsg(err: unknown, url?: string): string {
  let m = err instanceof Error ? err.message : String(err);
  if (url) m = m.split(url).join('[redacted:url]');
  return scrubSecrets(m).replace(/https?:\/\/[^\s"')]+/g, (u) => `${u.split('/').slice(0, 3).join('/')}/[redacted]`);
}

/** Only https URLs, or http to a loopback address, may receive alerts. */
export function isAllowedHookUrl(raw: string): boolean {
  try {
    const u = new URL(raw);
    if (u.protocol === 'https:') return true;
    return u.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
  } catch {
    return false;
  }
}

async function postJson(name: string, url: string, body: unknown, log: Logger, fetchImpl: FetchLike): Promise<boolean> {
  try {
    const res = await fetchImpl(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) log.warn(`${name} send failed`, { status: res.status });
    return res.ok;
  } catch (err) {
    log.warn(`${name} send error`, { error: errMsg(err, url) });
    return false;
  }
}

export class StdoutNotifier implements Notifier {
  readonly name = 'stdout';
  constructor(private readonly write: (s: string) => void = (s) => process.stderr.write(`${s}\n`)) {}
  async send(text: string): Promise<boolean> {
    this.write(text);
    return true;
  }
}

export class WebhookNotifier implements Notifier {
  constructor(
    readonly name: string,
    private readonly urlEnv: string,
    private readonly env: Env = process.env,
    private readonly fetchImpl: FetchLike = fetch,
  ) {}
  async send(text: string, log: Logger): Promise<boolean> {
    const url = this.env[this.urlEnv];
    if (!url) {
      log.warn(`${this.name} not configured (${this.urlEnv} is empty); message not sent`);
      return false;
    }
    if (!isAllowedHookUrl(url)) {
      log.warn(`${this.name} url rejected: must be https (or loopback http)`);
      return false;
    }
    return postJson(this.name, url, { text }, log, this.fetchImpl);
  }
}

export class TelegramNotifier implements Notifier {
  readonly name = 'telegram';
  constructor(
    private readonly env: Env = process.env,
    private readonly fetchImpl: FetchLike = fetch,
    private readonly tokenEnv = 'TELEGRAM_BOT_TOKEN',
    private readonly chatIdEnv = 'TELEGRAM_CHAT_ID',
  ) {}
  async send(text: string, log: Logger): Promise<boolean> {
    const token = this.env[this.tokenEnv];
    const chat = this.env[this.chatIdEnv];
    if (!token || !chat) {
      log.warn('telegram not configured; message not sent');
      return false;
    }
    return postJson('telegram', `https://api.telegram.org/bot${token}/sendMessage`, { chat_id: chat, text, disable_web_page_preview: true }, log, this.fetchImpl);
  }
}

export function createNotifiers(config: Config, env: Env = process.env, fetchImpl: FetchLike = fetch): Notifier[] {
  // Access level 1 never sends alerts: only the local stdout notifier remains.
  const configured = config.accessLevel === 1 ? config.notify.notifiers.filter((n) => n.type === 'stdout') : config.notify.notifiers;
  return configured.map((n): Notifier => {
    switch (n.type) {
      case 'stdout':
        return new StdoutNotifier();
      case 'webhook':
        return new WebhookNotifier('webhook', n.urlEnv, env, fetchImpl);
      case 'slack':
        return new WebhookNotifier('slack', n.urlEnv, env, fetchImpl);
      case 'telegram':
        return new TelegramNotifier(env, fetchImpl, n.tokenEnv, n.chatIdEnv);
    }
  });
}

/** Sends to every notifier; true only when all of them succeeded (so a failed alert is retried next run). */
export async function sendAll(notifiers: Notifier[], text: string, log: Logger): Promise<boolean> {
  let all = true;
  for (const n of notifiers) all = (await n.send(text, log)) && all;
  return all;
}
