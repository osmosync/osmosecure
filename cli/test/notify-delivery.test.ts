import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { test } from 'node:test';
import { parseConfig } from '../src/config.js';
import { silentLogger } from '../src/lib/log.js';
import { createNotifiers, sendAll } from '../src/notify/index.js';

// Real HTTP stubs for the Telegram Bot API and a Slack/webhook endpoint. Telegram's host is fixed to
// api.telegram.org in production code, so the injected fetch rewrites that one host to the stub (no prod override).
async function stub(status = 200): Promise<{ server: Server; port: number; hits: { url: string; body: string }[] }> {
  const hits: { url: string; body: string }[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      hits.push({ url: req.url ?? '', body: Buffer.concat(chunks).toString() });
      res.statusCode = status;
      res.end('ok');
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  return { server, port: (server.address() as AddressInfo).port, hits };
}
const stop = (s: Server): Promise<void> => new Promise((r) => { s.closeAllConnections(); s.close(() => r()); });

test('notify delivery: Telegram and Slack/webhook notifiers post the expected bodies to stub servers', async () => {
  const tg = await stub();
  const hook = await stub();
  try {
    const f: typeof fetch = (url, init) => {
      const u = String(url);
      return fetch(u.startsWith('https://api.telegram.org/') ? `http://127.0.0.1:${tg.port}${new URL(u).pathname}` : u, init);
    };
    const cfg = parseConfig({ notify: { notifiers: [{ type: 'telegram' }, { type: 'slack', urlEnv: 'HOOK' }] } }, '.');
    const env = { TELEGRAM_BOT_TOKEN: '123:tok', TELEGRAM_CHAT_ID: '42', HOOK: `http://127.0.0.1:${hook.port}/services/x` };
    assert.equal(await sendAll(createNotifiers(cfg, env, f), 'alert text', silentLogger), true);
    assert.equal(tg.hits[0].url, '/bot123:tok/sendMessage');
    assert.deepEqual(JSON.parse(tg.hits[0].body), { chat_id: '42', text: 'alert text', disable_web_page_preview: true });
    assert.deepEqual(JSON.parse(hook.hits[0].body), { text: 'alert text' });
  } finally {
    await stop(tg.server); await stop(hook.server);
  }
});

test('notify delivery: a non-2xx stub makes sendAll report failure so the alert is retried', async () => {
  const hook = await stub(500);
  try {
    const cfg = parseConfig({ notify: { notifiers: [{ type: 'webhook', urlEnv: 'HOOK' }] } }, '.');
    assert.equal(await sendAll(createNotifiers(cfg, { HOOK: `http://127.0.0.1:${hook.port}/h` }), 'x', silentLogger), false);
    assert.equal(hook.hits.length, 1);
  } finally {
    await stop(hook.server);
  }
});
