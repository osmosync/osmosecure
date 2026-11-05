import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { CONFIG_FILENAME } from '../config.js';

export const CONFIG_TEMPLATE = {
  schemaVersion: 1,
  dataDir: '.osmosecure',
  projects: [{ id: 'my-app', root: '.', maxDepth: 4 }],
  inventoryFiles: [],
  hosts: [],
  sourceGroups: {
    kev: { everyMinutes: 60, sources: ['kev'] },
    advisories: { everyMinutes: 360, sources: ['osv', 'ghsa', 'nvd', 'epss'] },
    bulletins: { everyMinutes: 1440, sources: ['rss'] },
    'inventory-scan': { everyMinutes: 1440, sources: ['inventory', 'scan'] },
    digest: { everyMinutes: 1440, sources: ['digest'] },
  },
  notify: { notifiers: [{ type: 'stdout' }] },
  remediation: { dryRun: true, hook: { url: '' } },
  triage: { backend: 'claude-cli' },
};

export const ENV_TEMPLATE = `# Copy to .env (gitignored). Never commit real values.

# Triage backend: claude-cli (default, uses a logged-in Claude subscription via "claude -p", no API key)
# or anthropic-api (needs ANTHROPIC_API_KEY and ANTHROPIC_MODEL). Overrides triage.backend in the config.
# A module: backend can only be set in the config file. This .env is read from the config directory only.
# TRIAGE_BACKEND=claude-cli
# CLAUDE_TRIAGE_MODEL=sonnet
# CLAUDE_CODE_OAUTH_TOKEN=
# ANTHROPIC_API_KEY=
# ANTHROPIC_MODEL=

# Notifiers (only the ones listed in notify.notifiers are used)
# TELEGRAM_BOT_TOKEN=
# TELEGRAM_CHAT_ID=
# SLACK_WEBHOOK_URL=
# OSMOSECURE_WEBHOOK_URL=

# Signed remediation hook secret (HMAC-SHA256). Live posting also needs remediation.hook.url.
# OSMOSECURE_HOOK_SECRET=

# Optional: raise public API rate limits. Every source works without them.
# GITHUB_TOKEN=
# NVD_API_KEY=
`;

/** Writes a starter config and .env.example into dir. Never overwrites without force. */
export function initProject(dir: string, force = false): string[] {
  mkdirSync(dir, { recursive: true });
  const written: string[] = [];
  const files: [string, string][] = [
    [CONFIG_FILENAME, `${JSON.stringify(CONFIG_TEMPLATE, null, 2)}\n`],
    ['.env.example', ENV_TEMPLATE],
  ];
  for (const [name, body] of files) {
    const file = path.join(dir, name);
    if (existsSync(file) && !force) continue;
    writeFileSync(file, body);
    written.push(file);
  }
  return written;
}
