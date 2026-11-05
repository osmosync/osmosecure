import Anthropic from '@anthropic-ai/sdk';
import { pathToFileURL } from 'node:url';
import { expandPath, type Config } from '../config.js';
import type { FeedItem } from '../types.js';
import { ClaudeCliTriageClient, DEFAULT_CLI_MODEL } from './claude-cli.js';
import { buildTriageUserMessage, TRIAGE_SYSTEM_PROMPT } from './prompt.js';
import { parseTriageReply, type TriageResult } from './schema.js';
import { constrainTriage } from './trust.js';

/** Single text-in text-out call. No tools are ever passed. */
export interface TriageClient {
  complete(system: string, user: string): Promise<string>;
}

export class AnthropicTriageClient implements TriageClient {
  private readonly client: Anthropic;

  constructor(
    apiKey: string,
    private readonly model: string,
    private readonly maxTokens: number,
  ) {
    this.client = new Anthropic({ apiKey, maxRetries: 2, timeout: 60_000 });
  }

  async complete(system: string, user: string): Promise<string> {
    const res = await this.client.messages.create({
      model: this.model,
      max_tokens: this.maxTokens,
      system,
      messages: [{ role: 'user', content: user }],
    });
    return res.content.map((b) => (b.type === 'text' ? b.text : '')).join('');
  }
}

export interface BackendContext {
  config: Config;
  env: NodeJS.ProcessEnv;
}

/** A backend factory returns a client, or null when it is not configured (triage is then skipped). */
export type BackendFactory = (ctx: BackendContext) => TriageClient | null | Promise<TriageClient | null>;

const registry = new Map<string, BackendFactory>();

/** Registers a named backend. Library users can call this before running an audit. */
export function registerTriageBackend(name: string, factory: BackendFactory): void {
  registry.set(name, factory);
}

registerTriageBackend('claude-cli', ({ env }) =>
  new ClaudeCliTriageClient({
    model: env.CLAUDE_TRIAGE_MODEL || DEFAULT_CLI_MODEL,
    timeoutMs: Number(env.CLAUDE_TRIAGE_TIMEOUT_MS) || 120_000,
    concurrency: Number(env.CLAUDE_TRIAGE_CONCURRENCY) || 1,
    bin: env.CLAUDE_BIN || undefined,
    env,
  }),
);

registerTriageBackend('anthropic-api', ({ config, env }) => {
  const key = env.ANTHROPIC_API_KEY;
  const model = env.OSMOSECURE_MODEL ?? env.ANTHROPIC_MODEL;
  if (!key || !model) return null;
  return new AnthropicTriageClient(key, model, config.triage.maxOutputTokens);
});

/**
 * Backend selection: TRIAGE_BACKEND env (built-in names only), else triage.backend in the config. Built in: claude-cli
 * (Claude subscription through `claude -p`, no API key) and anthropic-api (ANTHROPIC_API_KEY plus
 * ANTHROPIC_MODEL). A custom backend is a module whose default export is a BackendFactory:
 * `module:./my-backend.mjs`, allowed only when declared in the config file, never via the environment. Whatever the backend, it receives only scrubbed prompt text and must not use tools.
 */
export async function createTriageClient(config: Config, env: NodeJS.ProcessEnv = process.env): Promise<TriageClient | null> {
  const fromEnv = env.TRIAGE_BACKEND?.trim();
  // Loading code is an explicit, config-file-only choice: the environment (and any .env) can select a built-in backend only.
  if (fromEnv?.startsWith('module:')) throw new Error('TRIAGE_BACKEND cannot load a module from the environment; declare triage.backend "module:<path>" in the config file instead');
  const backend = (fromEnv || config.triage.backend).trim();
  if (backend.startsWith('module:')) {
    const file = expandPath(backend.slice('module:'.length), config.configDir);
    const mod = (await import(pathToFileURL(file).href)) as { default?: BackendFactory };
    if (typeof mod.default !== 'function') throw new Error(`triage backend module ${file} must default-export a factory function`);
    return mod.default({ config, env });
  }
  const factory = registry.get(backend);
  if (!factory) throw new Error(`unknown triage backend "${backend}" (use ${[...registry.keys()].join(', ')} or module:<path>)`);
  return factory({ config, env });
}

export async function triageItem(client: TriageClient, item: FeedItem, maxChars: number): Promise<TriageResult> {
  const reply = await client.complete(
    TRIAGE_SYSTEM_PROMPT,
    buildTriageUserMessage(item.title, item.text, item.source, maxChars),
  );
  // The reply is a claim about untrusted text: ground it in that text before anything else uses it.
  return constrainTriage(item, parseTriageReply(reply));
}
