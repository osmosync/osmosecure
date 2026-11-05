# osmosecure

An agent skill that audits what a team runs and watches for new disclosures. It is the runtime-side counterpart to source-code security audit skills: instead of hunting bugs in code, it asks which published weaknesses apply to the lockfiles, container images, and host runtimes (php, openssl, nginx, node, postgres) you actually operate.

Structure is inspired by Cloudflare's MIT-licensed security-audit-skill (thin router file, per-topic references, JSON schema with dependency-free validators, hunter and verifier split, three-state verdicts, coverage ledger). All content here is original.

## Install

```
npx skills add OsmoSync/osmosecure --skill osmosecure
```

The skill works on its own. The `osmosecure` CLI in this repository automates modes 1 and 2 on a schedule and reads the same inventory format (`inventory-schema.json`).

## Modes

1. Inventory audit: build an inventory and match it against OSV, GHSA, NVD, CISA KEV, EPSS, and distro trackers.
2. Disclosure watch: triage free-text disclosures that scanners have not flagged, map them to the inventory with distro backport rules.
3. Remediation plan: dry-run first, approval-gated, never pushes or deploys.

## Layout

```
SKILL.md                    router and hard rules
references/                 per-topic guidance (runtime gap, injection defense, safety, sources, contract)
inventory-schema.json       inventory shape
report-schema.json          report shape
scripts/validate-inventory.mjs
scripts/validate-report.mjs
scripts/lib/mini-schema.mjs tiny schema checker (no dependencies)
tests/                      node:test suites and fixtures
```

## Use

Validators need Node 18 or newer and nothing else.

```
node scripts/validate-inventory.mjs inventory.json
node scripts/validate-report.mjs report.json --inventory inventory.json
node --test tests/*.test.mjs
```

The fixtures include a fictional php-fpm disclosure that no lockfile scanner would flag, and an advisory containing a prompt-injection attempt.

## Safety summary

Own assets only, no target code execution, no PoCs, embargoes honored, no secrets sent to a model, advisory text treated as untrusted data and triaged by a tool-less step with structured output. Read `references/safety.md` and `references/prompt-injection-defense.md` before adopting.

## License

Apache-2.0, copyright 2026 OsmoSync. See `LICENSE`.
