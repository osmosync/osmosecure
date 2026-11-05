# osmosecure

osmosecure watches the vulnerabilities that apply to what you actually run: application lockfiles, container image tags, and the host runtimes underneath them (PHP, OpenSSL, nginx, Node, PostgreSQL and similar). It checks structured sources such as OSV and CISA KEV on a schedule you define, and it reads free-text security announcements with an LLM so that a bulletin on a mailing list can be matched to your inventory before any database carries it.

Watching is read-only with respect to your systems. It never merges, deploys, or changes a host. Remediation is either a dry-run request to a signed webhook that you control, or a local dependency-bump fix (`osmosecure fix`) that works in an isolated git worktree and stops for your approval. Pushing is off by default and only ever happens through an explicit `fix --publish`.

Licensed under Apache-2.0. Two parts ship in this repository:

- `cli/`: the `osmosecure` command line tool (Node 22, TypeScript).
- `skill/`: the same method as an agent skill, for interactive audits. Install with `npx skills add OsmoSync/osmosecure --skill osmosecure`.

A hosted OsmoSecure service exists at https://secure.osmosync.com. It is optional: everything in this repository works on its own, and `osmosecure setup` connects to the hosted service only when you choose to use it.

## The wedge

Lockfile scanners answer one question well: which pinned library versions in my repository appear in a vulnerability database. They cannot see much of what really exposes a service:

- A PHP-FPM, OpenSSL or nginx release installed from the distro, which appears in no lockfile.
- A security release announced as prose ("fixed in 8.3.8, 8.2.20 and 8.1.29") before an identifier and a machine-readable range exist.
- A distro build whose version number looks vulnerable upstream but carries a backported fix, or the reverse.

osmosecure builds a single inventory that includes host runtimes and image tags next to lockfile packages. For free-text disclosures it runs a deterministic keyword prefilter against that inventory, asks a model to extract product, affected ranges and fixed versions into a strict JSON object (the model has no tools and sees the text as untrusted data), and then a plain deterministic matcher compares that object with your versions, branch by branch. The model reads; code decides.

## Quickstart

```bash
git clone https://github.com/OsmoSync/osmosecure.git
cd osmosecure/cli
npm ci && npm run build
mkdir ~/osmosecure-demo && cd ~/osmosecure-demo
node /path/to/osmosecure/cli/dist/cli.js init       # writes osmosecure.config.json and .env.example
```

Or try the bundled example, which needs no setup beyond Node 22:

```bash
cd examples
node ../cli/dist/cli.js scan --config osmosecure.config.json
```

`scan` is a read-only pass: it fetches public sources, prints what it would report, writes no state and sends nothing. Add `--llm` to include free-text triage (see the backends below). A first full pass takes a few minutes because public APIs are rate limited and the client spaces its requests.

Typical continuous setup:

```bash
osmosecure baseline           # once: record everything currently known, send nothing
osmosecure watch              # long-running; runs each source group on its own cadence
osmosecure watch --once       # cron or CI: run what is due, then exit
osmosecure status             # last runs and finding counts by tier
osmosecure triage advisory.txt   # run one disclosure through triage against your inventory
osmosecure remediate <finding-key>            # prints the request; dry-run unless --live
osmosecure fix <finding-key>                  # bump one npm/pnpm dependency in a worktree, run tests, stop at awaiting-approval
osmosecure fix --list
osmosecure fix --approve <run>                # commit the reviewed change locally on its fix branch
```

Run `baseline` before you enable notifications. Without it the first live run reports the highest-scoring findings that already exist as if they were new.

## How it differs from other tools

These tools are good at what they do, and osmosecure is meant to sit beside them, not replace them.

| Tool | Strong at | Where osmosecure differs |
|---|---|---|
| Dependabot, Renovate | Opening version-bump pull requests from manifests and lockfiles | They act on dependency manifests. osmosecure does not open version-bump pull requests; it watches runtimes and prose disclosures too and can hand a request to your own pipeline. Keep using them for bumps. |
| Snyk | Broad commercial platform: dependency, code, container and IaC scanning, with its own curated database | Hosted and commercial, with deep fix workflows. osmosecure is open source and self-hosted, narrower, and focuses on the free-text and host-runtime gap. |
| Socket | Supply-chain behavior analysis of packages (install scripts, malware signals) | A different problem. osmosecure matches published vulnerabilities, not package behavior. |
| Trivy, grype | Scanning images, filesystems and OS packages against vulnerability databases, including distro data and SBOMs | Excellent for image and OS package scanning. osmosecure currently covers a runtime watchlist, not the full OS package set, and does not scan image layers. Its addition is reading announcements ahead of the databases and flagging backport uncertainty instead of guessing. Running Trivy or grype alongside it is sensible. |
| osv-scanner | Lockfile and SBOM scanning against OSV | osmosecure uses OSV (and can use osv-scanner when installed) as its deterministic base, and adds feeds, KEV and EPSS ranking, scheduling and the disclosure triage layer. |

Honest limits: osmosecure matches names and versions. It does not do reachability analysis, it does not read your source code for bugs, and an LLM-derived finding is always labelled `needs-verification` or `affected` by the deterministic matcher, never treated as proof. Distro package versions are reported as needing verification against the vendor tracker because backports make upstream comparison unreliable.

## Safety model

Details in [docs/safety.md](docs/safety.md) and [docs/threat-model.md](docs/threat-model.md). In short:

- Only run it with a config you trust. The config can point at a triage backend module, notifier URLs and a remediation hook, so treat `osmosecure.config.json` like code and never run it from a checkout you do not trust.
- Own assets only. It reads the projects, inventory files and host dumps you list. It does not scan or probe hosts, and it contacts only the public sources in the catalog plus the notifier and hook endpoints you configure.
- Advisory text is untrusted. It is wrapped in delimiters with the delimiter stripped from input, the model gets no tools, and its reply must validate against a strict schema before any code uses it. Model output is never forwarded into notifications or remediation requests; feed titles that appear in alerts are length-bounded and redacted.
- Secrets are scrubbed, best effort, from every string before any model call (known token shapes plus the literal values of secret-looking environment variables), and the `claude-cli` backend runs with an allowlisted environment.
- Proof-of-concept material is filtered by pattern: code fences, fetch-and-execute one-liners and long encoded payloads are removed from outgoing messages, and the skill refuses to record exploit code.
- Remediation is dry-run first, needs a configured https hook and a secret from the environment to go live, is capped per run, and states "do not push, merge, deploy" in every request. `autoFix.neverPushOrDeploy` must be `true` or the config is rejected. The fixer works in an isolated worktree, makes no LLM calls, builds every command from validated structured fields, stops at `awaiting-approval`, and pushes only through an explicit `fix --publish` that is disabled by default.

## Optional hosted service

`osmosecure setup --code <setup-code> --server https://secure.osmosync.com` exchanges a one-time setup code for a local `osmosecure.config.json` (configuration only, never secrets). The service adds what is hard to run yourself: deep audits, continuous monitoring across projects and hosts, fix proposals, and team history. It is opt-in; the scanner, watcher, triage, notifiers and fixer in this repository never need it.

## Triage backends

`triage.backend` in the config (or `TRIAGE_BACKEND` in the environment, built-in names only):

- `claude-cli`: runs `claude -p` as the current user, so triage uses an existing Claude subscription login with no API key. Tools disabled, one turn, no session persistence, empty temporary working directory, hard timeout, 1 to 2 concurrent children.
- `anthropic-api`: Anthropic Messages API; needs `ANTHROPIC_API_KEY` and `ANTHROPIC_MODEL`.
- `module:./my-backend.mjs`: your own backend, loaded only when declared in the config file. `TRIAGE_BACKEND=module:...` in the environment or a `.env` is refused. Default-export a function `({ config, env }) => ({ complete(system, user): Promise<string> }) | null`. Library users can also call `registerTriageBackend(name, factory)`.

If no backend is configured, deterministic scanning and notification still work, and free-text items that pass the prefilter wait unseen until triage is available.

## Configuration

The config is a JSON file; anything you omit falls back to built-in defaults (objects merge, arrays replace). Relative paths resolve against the config file's directory. See [examples/osmosecure.config.json](examples/osmosecure.config.json) for a minimal file and [examples/osmosecure.config.full.json](examples/osmosecure.config.full.json) for the options.

| Key | Purpose |
|---|---|
| `projects[]` | Directories to inventory (`id`, `root`, `maxDepth`, `skipDirs`, `optional`, `target`, `pathTargets`) |
| `inventoryFiles[]` | Skill-format inventory JSON (host runtimes, images, packages) |
| `hosts[]` | Host ids whose `dpkg.tsv` and `images.tsv` dumps live under `<dataDir>/host/<id>/` |
| `sourceGroups` | Your cadence: group name to `everyMinutes` and `sources` (`kev`, `osv`, `ghsa`, `nvd`, `epss`, `rss`, `inventory`, `scan`, `digest`) |
| `thresholds`, `scoring` | Tier cutoffs and the severity, KEV and EPSS weights |
| `notify.notifiers[]` | `stdout`, `webhook`, `slack`, `telegram`; URLs and tokens come from environment variables |
| `fix` | `testCommand`, `testTimeoutMs`, `installTimeoutMs`, `smokeCommand`, `smokeTimeoutMs`, `maxRunsPerDay`, `maxOpenRuns`, `worktreeRoot`, `passEnv`, `publish.enabled`, `publish.remote`, `pullRequests.remote`, `pullRequests.provider`, `pullRequests.maxOpen`, `pullRequests.unattended`, `server.host`, `server.port`, `server.timestampWindowSeconds` |
| `remediation` | `dryRun`, `minTier`, `maxPerRun`, `hook.url`, `hook.secretEnv` |
| `triage` | `backend`, `maxItemsPerRun`, `maxInputChars`, `maxOutputTokens` |
| `feeds` | Source URLs, RSS list, lookback, user agent, request spacing |

Environment variables are documented in the `.env.example` that `init` writes. Credentials never belong in the config file.

### Remediation hook

When `remediation.hook.url` is set, eligible findings (deterministic, an application package, known fixed version, at or above `minTier`, mapped to a target through `target` or `pathTargets`) are POSTed as JSON (`osmosecure.remediation.v1`). Patch-level bumps are queued; anything larger needs approval via `osmosecure remediate <key> --live`. Verify requests with the `x-osmosecure-timestamp` and `x-osmosecure-signature` headers: the signature is `sha256=` plus the hex HMAC-SHA256, keyed with your secret, of `<timestamp>.<raw body>`. Reject old timestamps. See [docs/architecture.md](docs/architecture.md) and the receiver notes under the fixer below.

### Fixer (dependency bumps)

`osmosecure fix <finding-key>` handles one finding at a time. Scope in this version: **npm and pnpm dependency bumps only**, for a package that is declared in `package.json` and has a known fixed version. What it does:

1. Refuses unless the finding is deterministic, the fixed version is a plain `x.y.z` release, and the bump is patch or minor (`--allow-major` for a major). It refuses if the project checkout has uncommitted changes to tracked files.
2. Creates a git worktree on a new branch `osmosecure/fix-<advisory>-<package>` from the checkout's current HEAD, under `<dataDir>/fix/worktrees` (or `fix.worktreeRoot`).
3. Runs `npm install <pkg>@<fixed> --ignore-scripts` (or `pnpm add`) in the manifest's directory, then checks that the lockfile resolves the package at or above the fixed version and that only `package.json` and the lockfile changed.
4. Runs the test command (`fix.testCommand`, an argv array; default `<pm> test` when `scripts.test` exists). With `autoFix.requireTestsPass` true, no tests means failure.
4a. If `fix.smokeCommand` is set (argv array), runs it after the tests as a runtime check; failure or timeout blocks the run. An override for an `@opentelemetry/` or other instrumentation package is refused unless it is set. See [docs/safety.md](docs/safety.md#runtime-smoke-check).
5. On success writes a report (`<dataDir>/fix/runs/<run>.json` and `.md`: before and after versions, advisory id, test result) and stops at `awaiting-approval`. On failure it removes the worktree and branch and keeps the failed report.

`fix --approve <run>` stages only the changed manifest and lockfile and commits locally (git hooks disabled). `fix --discard <run>` removes a run. `fix --publish <run>` pushes only the fix branch (never forced) and opens a draft PR with `gh`; it is refused unless the config sets `fix.publish.enabled: true`, and it is never part of the default flow. osmosecure does not merge or deploy.

Caps: `fix.maxRunsPerDay` (default 3) and `fix.maxOpenRuns` (default 3 runs awaiting approval). Child processes get a minimal environment (`PATH`, `HOME` and similar); add names to `fix.passEnv` if your registry needs a token.

Optional receiver: `osmosecure fix-server` listens on loopback (`fix.server.host` and `fix.server.port`, default 127.0.0.1:8787), accepts `POST /fix` with the same `x-osmosecure-signature` and `x-osmosecure-timestamp` headers as the remediation hook, and needs the hook secret in the environment. It checks the HMAC in constant time, enforces a timestamp window, rejects replays, and reads only the finding key from the request fingerprint. Everything it acts on comes from local state, never from the request body. It can start a fix but cannot approve or publish. For remote senders put a TLS reverse proxy in front of it.

Not covered yet: yarn, composer, pip requirements, transitive dependencies (these need overrides), monorepo workspaces that change files beyond the one manifest and lockfile, and projects whose tests need dependency install scripts (they are disabled). Network access is whatever the package manager needs to reach your registry. The test command runs your project's code, so treat it as trusted code and run the fixer where that is acceptable.

### Host collection

Lockfiles cannot see host runtimes. Either describe them in an inventory file (`skill/inventory-schema.json`) or capture text dumps on each host and place them under `<dataDir>/host/<id>/`:

```bash
dpkg-query -W -f='${Package}\t${Version}\n' > dpkg.tsv
docker ps --format '{{.Image}}\t{{.ImageID}}' > images.tsv
```

## Docker

`docker/Dockerfile` builds a non-root image with no secrets baked in; `docker/compose.example.yml` shows a read-only, capability-dropped deployment. The image does not include the `claude` binary, so use `anthropic-api` or a custom backend inside it.

## Development

```bash
cd cli && npm ci && npm run typecheck && npm test && npm run build
node --test skill/tests/*.test.mjs      # from the repository root
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Further reading: [docs/architecture.md](docs/architecture.md), [docs/threat-model.md](docs/threat-model.md), [docs/safety.md](docs/safety.md), [docs/source-catalog.md](docs/source-catalog.md), [docs/demo-run.md](docs/demo-run.md).

## Roadmap

- Fixer coverage beyond npm and pnpm: yarn, composer, pip requirements, and transitive bumps through overrides.
- Distro-tracker lookups (Debian, Ubuntu, Red Hat, Alpine) to resolve backports automatically instead of marking host findings `needs-verification`.
- Full OS package coverage through OSV distro ecosystems, not only the runtime watchlist.
- Automated host collection with a read-only collector.
- Vendor pages without feeds (OpenSSL, PostgreSQL) through a user-supplied fetcher.
- SBOM (CycloneDX, SPDX) import, image digest to CVE scanning.
- Additional notifiers and backends.

## Credit

The skill's structure (thin router, per-topic references, dependency-free schema validators, a hunter and verifier split, three-state verdicts, coverage ledger) was inspired by Cloudflare's MIT-licensed security-audit-skill. No text or code was copied from it; the content here is original.

## License

Apache-2.0, copyright 2026 OsmoSync. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Security reports: [SECURITY.md](SECURITY.md). Contributing: [CONTRIBUTING.md](CONTRIBUTING.md). Conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

osmosecure is a monitoring tool. It is not a substitute for professional security review, and findings are advisory.
