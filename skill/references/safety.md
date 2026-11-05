# Safety

## Own assets only

- Run only against infrastructure, repositories, images, and hosts the requester owns or is authorized in writing to assess.
- Record the owner in the inventory (`owner`) and in the report (`scope.own_assets_confirmed: true`). If you cannot confirm ownership, stop.
- Do not scan third-party hosts, probe versions over the network, or fingerprint services you do not run. Read versions from the host's own package database or from the owner's CI output.
- Data sources are queried with package names and versions only.

## No target code execution

- Version reads (`dpkg -s`, `php -v`, `nginx -v`) are allowed on owned hosts when the owner runs them or has delegated that access.
- Do not run application code, test suites, build scripts, install hooks, or anything from an advisory. If verification seems to require running target code, stop and propose an isolated sandbox with no network and no credentials. Without one, mark the finding `needs_validation`.

## PoCs

- Never write, reproduce, or store a working exploit. The report describes the weakness, affected versions, and fix. The validator rejects code fences and exploit file names.
- If an advisory includes a PoC, do not copy it, even partially. Refer to it by URL.

## Embargoes

- Do not report on or circulate material that is under embargo or marked private (vendor-only lists, pre-notification mail, restricted trackers).
- Respect stated disclosure dates. If publication status is unclear, mark `needs_validation` and ask a human.
- `advisory.embargo_respected: false` fails validation.

## Secrets and data to models

- Never send secrets (keys, tokens, passwords, `.env` contents, certificates) to a model or third-party API. Inventory rows carry names and versions only.
- Redact before any model call: hostnames beyond a short asset label, IPs, user names, paths that reveal customers.
- Sanity-scan the final report. The validator rejects common key and token shapes; it is a backstop, not the control.
- Use the owner's approved model endpoint. Do not paste inventories into public chat tools.

## Rate and etiquette

- Respect API terms and rate limits (see `source-catalog.md`). Cache responses. Identify the client in the User-Agent where the source asks for it.
- Use API keys only from the environment; never print them.

## Remediation limits

See `remediation-plan.md`. Plans are dry-run first, approval-gated, and never push or deploy.
