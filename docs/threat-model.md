# Threat model

## Assets

- Your inventory (names and versions of what you run), which reveals attack surface.
- Credentials: notifier tokens, the model backend key or login, the hook secret.
- The integrity of alerts and remediation requests, since someone may act on them.
- Your hosts and repositories, which osmosecure must never change.

## Trust boundaries

| Input | Trust |
|---|---|
| Feed text (RSS, NVD descriptions, KEV text, mailing lists) | Untrusted. Written by third parties, possibly hostile. |
| Model output | Untrusted until validated; never trusted for instructions. |
| Structured advisory data (OSV, GHSA) | Trusted for ids and ranges, still length- and shape-checked. |
| Your config, inventory files and environment | Trusted. A custom backend module is code you chose to run. |
| Notifier and hook endpoints | Yours; https required except loopback. |

## Threats and controls

| Threat | Control |
|---|---|
| Prompt injection in an advisory steers the model | Text wrapped in `<disclosure>` tags with the delimiter stripped from input; the system prompt says it is data; no tools are exposed; the reply must validate against a strict schema (version strings pattern-checked); only validated fields reach the matcher. The test suite includes a hostile fixture. Model claims are additionally grounded in the source text and severity is capped. |
| Injection that makes the system act (push code, run commands) | The model has no tools. Remediation requests are built only from our own structured fields; model and feed text are never forwarded. Every request says not to push, merge or deploy. |
| Secrets leak to a model provider | Best-effort scrubbing of known token shapes and literal secret-looking environment values before any model call. The `claude-cli` child gets an allowlisted environment. Inventories sent to a model contain names and versions only. |
| Secrets in logs | The logger redacts values for keys matching key, token, secret, authorization, password. The Telegram token appears only in the request URL and is not logged. The `claude-cli` backend never retains stderr, since it can echo prompt text. |
| Exploit material in alerts | Pattern-based filtering: code fences, fetch-and-execute one-liners and long encoded blobs are removed from outgoing messages; novel encodings can slip through. |
| Forged or replayed remediation requests | HMAC-SHA256 over timestamp and body with a secret from the environment; receivers should enforce a short window. |
| Alert or hook sent to an attacker-controlled or plaintext endpoint | URLs come from your environment or config; https is required except for loopback. |
| Scanning systems you do not own | There is no network scanning code. The tool reads local files and public vulnerability sources. |
| Silent failure creates false assurance | Failed sources are reported in the run summary and do not advance the group's last-run time. Items that could not be triaged remain unseen and retry. |
| Resource exhaustion | Per-run caps on triage items and OSV detail fetches, a 15 minute run ceiling, bounded model input and output, a lock against overlapping runs. |
| Tampered state file | State is written with mode 0600 in your data directory. Anyone who can write it already controls the host account. |

## Out of scope

- Detecting vulnerabilities in your own source code.
- Reachability or exploitability proof. EPSS and KEV rank findings; they do not prove exposure.
- Defending against a compromised host account or a malicious custom backend module.
- Catching a secret that matches no known shape and is not in the environment.
- Guaranteeing the model extracts every product correctly. A missed item is a false negative; treat the tool as an early-warning layer beside, not instead of, a scanner.
