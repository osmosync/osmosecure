# osmosecure

Watches the vulnerabilities that apply to what you actually run: lockfiles, container images and host runtimes, including free-text security announcements that package scanners do not carry yet. Read-only toward your systems; remediation is dry-run first.

Requires Node 22 or newer. Open source under Apache-2.0. Source: https://github.com/OsmoSync/osmosecure.

## Install

```bash
npm install -g osmosecure
# or run without installing
npx osmosecure --help
```

## Optional: connect to the hosted OsmoSecure service

The CLI works fully on its own. If you use the hosted service at https://secure.osmosync.com, create a setup code there, then run:

```bash
osmosecure setup --code <setup-code> --server https://secure.osmosync.com
```

This writes an `osmosecure.config.json` for your projects and prints the names of the environment variables to set. It never prints or stores secret values, and it refuses to overwrite an existing config without `--force`. `--server` defaults to `OSMOSECURE_SERVER`.

## Scan

```bash
osmosecure init
osmosecure scan
```

Other commands: `watch`, `baseline`, `triage`, `remediate`, `fix`, `status`. Run `osmosecure --help` for the full list and options.

## Access levels

When you use the hosted service, the level is carried in your setup code.

| Level | Name | What the CLI does |
|---|---|---|
| 1 | Watch | Reads inventory and feeds, reports findings locally. |
| 2 | Alert | Also sends alerts to your own Telegram or Slack bot, or a signed webhook. |
| 3 | Propose fixes | Also prepares dependency-bump proposals for you to review. Needs the explicit `--allow-propose` flag at setup. Never pushes. |

Level 4 (automatic changes) does not exist; the CLI refuses it.

## Disclaimer

OsmoSecure is a monitoring tool. It makes no guarantee that your systems are secure and is not a substitute for professional security review. Findings are advisory and you remain responsible for your systems.
