# Architecture

osmosecure is a command line tool with no server component. A run is a pipeline over local state; the scheduler (`watch`, cron, CI) only decides when to start it.

```
projects + inventoryFiles + host dumps
              |
          inventory  ------------------------------+
              |                                    |
   scan (OSV API or osv-scanner)              prefilter terms
              |                                    |
   public feeds: KEV, OSV, GHSA, NVD, EPSS, RSS --> new items
              |                                    |
   structured advisories --> rescan named packages |
                                                   v
                              free text --> prefilter --> triage backend (no tools)
                                                   |
                                      strict schema validation
                                                   |
                                      deterministic matcher
              +------------------------------------+
              v
        candidates --> rank (severity, KEV, EPSS) --> tier: page | alert | digest | log
              |
     dedupe against state (notify once, again only on escalation)
              |
   notifiers (stdout, webhook, Slack, Telegram)      remediation request (signed hook, dry-run first)
```

## Stages

1. **Inventory** (`cli/src/inventory`). Parses `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `composer.lock`, `Gemfile.lock`, pinned `requirements*.txt`, compose `image:` lines, skill-format inventory files, and `dpkg.tsv` / `images.tsv` host dumps. Every row is a component with an ecosystem, name, version, origin and project.
2. **Scan** (`cli/src/scan`). Packages go to OSV (the batch API, or `osv-scanner` when it is on PATH). Only package names and versions leave the machine.
3. **Feeds** (`cli/src/feeds`). CISA KEV, OSV recent modifications, GitHub advisories, NVD, EPSS and RSS/Atom feeds. Requests are ETag-cached, spaced per host and back off on 429. Feeds are grouped into source groups, each with its own `everyMinutes`.
4. **Triage** (`cli/src/triage`). A free-text item passes a deterministic prefilter (it must name a product in your inventory). A backend returns one JSON object. `schema.ts` validates it, `matcher.ts` compares versions branch by branch and applies the distro and image downgrades to `needs-verification`.
5. **Rank** (`cli/src/rank.ts`). Score = severity base + KEV boost + EPSS boost + runtime boost - unverified penalty. Thresholds map the score to a tier.
6. **State** (`cli/src/state.ts`). One JSON file in the data directory, written atomically with mode 0600. It records seen items, findings, what was notified at which tier, and remediation requests.
7. **Notify** (`cli/src/notify`). Notifiers implement `send(text, log): Promise<boolean>`. A message is marked notified only when every notifier succeeded, so failures retry on the next run.
8. **Remediate** (`cli/src/remediate.ts`). Builds a request from structured fields only and posts it to a signed webhook, dry-run by default.

9. **Fix** (`cli/src/fix.ts`, `cli/src/fix-server.ts`). Local dependency-bump fixer for npm and pnpm. `startFix` validates a stored deterministic finding (package name and versions against strict patterns, patch or minor unless `--allow-major`, clean checkout, run caps), adds a git worktree on `osmosecure/fix-<advisory>-<package>`, runs the package manager with lifecycle scripts disabled, verifies the lockfile and that only the manifest and lockfile changed, runs the test command and writes a report under `<dataDir>/fix/runs`. It stops at `awaiting-approval`. `approveFix` commits locally, `publishFix` (off unless `fix.publish.enabled`) pushes only the fix branch and opens a draft PR via `gh`, `discardFix` removes a run. No model is involved: commands come from structured fields, never advisory text. `fix-server` is an optional loopback receiver for the signed remediation request; it takes only the finding key from the fingerprint and acts on local state.

## Scheduling

`watch` loops with a tick (default 60 seconds) and runs the groups whose cadence has elapsed. `watch --once` does one tick and exits, suitable for cron, systemd timers and CI. A lock file in the data directory prevents two instances from writing state together, and each run has a 15 minute ceiling.

A source group whose feed failed does not advance its last-run time, so it retries on the next tick.

## Extension points

- Triage backend: `registerTriageBackend(name, factory)` or `module:` in config.
- Notifier: implement the `Notifier` interface in `cli/src/notify/index.ts` and add a case in `createNotifiers`.
- Remediation receiver: any HTTPS endpoint that verifies the signature described in the README, or the bundled loopback `osmosecure fix-server`.
- Fixer ecosystems: add a case to `packageManagerFor` and `bumpCommand` in `cli/src/fix.ts` plus a lockfile check; yarn, composer and pip are not implemented.

## Remediation request

`osmosecure.remediation.v1` JSON: `project`, `target`, `title`, `instruction`, `fingerprint`, `severity`, `occurredAt` and a `metadata` object (advisory id, package, versions, bump class, KEV flag, policy). The instruction text is assembled from those fields only. Headers: `x-osmosecure-timestamp` (unix seconds) and `x-osmosecure-signature` (`sha256=` + HMAC-SHA256 of `<timestamp>.<body>`). A receiver should check the signature in constant time and reject timestamps outside a short window.
