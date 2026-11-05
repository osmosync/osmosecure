# Source catalog

The CLI queries only these sources, all public. Each is read-only, cached with ETags where supported, and spaced per host (`feeds.minIntervalMs`). Override endpoints under `feeds` in the config.

| Source | Group default | Use | Sent to the source |
|---|---|---|---|
| OSV (`api.osv.dev`, `osv-vulnerabilities.storage.googleapis.com`) | `inventory-scan`, `advisories` | Package vulnerabilities, recent modifications | Package names and versions |
| CISA Known Exploited Vulnerabilities | `kev` | Exploited-in-the-wild flag and free-text entries | Nothing (a download) |
| GitHub Advisory Database (`api.github.com/advisories`) | `advisories` | GHSA records | Nothing beyond the query; `GITHUB_TOKEN` raises limits |
| NVD 2.0 | `advisories` | CVE records and CPE hints | Date window; `NVD_API_KEY` raises limits |
| EPSS (`api.first.org`) | `advisories` | Exploit probability for ranking | CVE ids |
| RSS and Atom bulletins | `bulletins` | oss-security, php.net, nginx, Node.js, Debian DSA, Ubuntu USN by default; add your own under `feeds.rss` | Nothing (a download) |

Some vendors have no feed (for example OpenSSL and PostgreSQL announcements); the defaults list them as disabled. Add a feed URL if you have one.

The skill's catalog, which also lists distro trackers and the endoflife.date API used in interactive audits, is in [skill/references/source-catalog.md](../skill/references/source-catalog.md).

Every free-text source is untrusted input and goes through the triage controls in [threat-model.md](threat-model.md).
