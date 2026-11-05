# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities in osmosecure privately. Do not open a public issue.

- Preferred: GitHub private vulnerability reporting on this repository (Security tab, "Report a vulnerability"), once enabled.
- Email: contact@osmosync.com

Include the version, a description of the issue, steps or a minimal input to reproduce it, and the impact you expect. Please do not include live credentials or third-party data.

## What to expect

- Acknowledgement within 5 business days.
- An initial assessment within 10 business days, and updates when status changes.
- Coordinated disclosure: we aim to ship a fix before details are public and will credit you if you want credit. Please allow up to 90 days before public disclosure unless we agree otherwise.

## In scope

The CLI in `cli/`, the skill's validators in `skill/scripts/`, and the Docker image definition. Of particular interest: a bypass of the prompt-injection, secret-scrubbing, PoC-redaction or dry-run controls; a way to make the tool execute attacker-controlled text; credential disclosure in logs or output; request-signing flaws in the remediation hook.

## Out of scope

Vulnerabilities in third-party services or databases the tool reads from, findings that require a compromised host account, and denial of service through public feeds that the tool already caps.

The hosted service at https://secure.osmosync.com is not part of this repository; report issues with it to the same address.

## Supported versions

The latest released version.
