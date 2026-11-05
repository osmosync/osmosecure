# Contributing

Thanks for helping. Small, focused changes are easiest to review.

## Setup

```bash
cd cli
npm ci
npm run typecheck
npm test
```

Skill validators:

```bash
node --test skill/tests/*.test.mjs
```

Node 22 or newer is required.

## Guidelines

- Open an issue first for anything larger than a bug fix, especially new data sources, notifiers or backends.
- Add a test with each behavior change. Tests must not touch the network; stub `fetch` as the existing tests do.
- Never add a fixture containing a real credential, a working exploit, or non-public vulnerability details. Fixtures use fictional identifiers (the `CVE-2099-` range).
- Keep the safety controls intact: untrusted text handling, secret scrubbing, PoC redaction, dry-run-first remediation, own-assets-only. A change that weakens one needs a written rationale in the pull request.
- Match the existing style: TypeScript strict mode, no new runtime dependency without discussion.
- Do not commit `.env` files or state directories.

## Pull requests

Describe what changed and why, how you tested it, and any safety implications. CI runs typecheck, tests and the skill validators.

By submitting a pull request you agree that your contribution is licensed under the Apache License 2.0, the same license as this project (see LICENSE), as described in section 5 of that license.

## Reporting security issues

Use the private process in [SECURITY.md](SECURITY.md), not a public issue.
