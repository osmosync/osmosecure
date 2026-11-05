# Why package scanners miss runtime-class issues

Package scanners (npm audit, pip-audit, OSV-Scanner on lockfiles, image scanners) answer: "which declared dependencies match a known advisory?" Several classes of real exposure are not declared dependencies, so they never enter that question.

## What falls through

| Class | Why it is invisible | Example shape |
|---|---|---|
| Interpreter and server binaries on the host | Installed by the OS package manager, not a lockfile. Nothing in the repo names the version. | php-fpm, nginx, openssl, postgres, node installed from the distro or a tarball |
| Linked system libraries | Apps use whatever the host provides. | libssl, libxml2, zlib |
| Base image layers not scanned or scanned stale | The scan ran at build time; the advisory appeared later. | An image rebuilt never, running for months |
| Advisories with no machine-readable record yet | Published as a mailing-list post or blog first; OSV, GHSA, and NVD entries lag by hours to weeks, and some never get ranges. | A maintainer announcement on oss-security |
| Distro-versioned fixes | The fix ships under a distro version string; upstream version comparison gives a wrong answer in both directions. | `8.2.20-1~deb12u1` vs upstream `8.2.24` |
| Configuration-conditional issues | Only exposed with a feature enabled; scanners report all or nothing. | A module compiled in but unused |

## How to close the gap

1. Put runtimes in the inventory as rows. Collect `name`, upstream `version`, distro, release, and the package manager's exact version string. Source them from `php -v`, `nginx -v`, `openssl version`, `dpkg -s` or `rpm -q`, not from memory.
2. Record exposure: is the service internet facing, which port, which user.
3. Watch the free-text sources that precede database entries (`source-catalog.md`). Triage them with the isolated step in `prompt-injection-defense.md`.
4. Map each disclosure to inventory rows by product, then by version range.
5. Apply distro backport rules before concluding anything:
   - Compare the installed package version to the distro tracker's fixed version for that release, not to the upstream fixed version.
   - If the tracker lists the CVE as fixed in a version at or below the installed one, the finding is `rejected` with that citation.
   - If the tracker has no entry yet, the finding is `needs_validation` with an open question and a recheck date. Do not assume affected or safe.
   - For non-distro installs (tarball, vendor repo, language-manager installs) upstream comparison is correct; say which basis you used in `match_basis`.
6. Re-run the match when the inventory changes and when trackers update. A `needs_validation` finding is a scheduled recheck, not a terminal state.
7. Log coverage so a runtime with no source checked shows as a gap in the ledger.

## Comparison pitfalls

- Debian and Ubuntu use epoch, upstream, and revision parts. Compare with the distro's own tooling (`dpkg --compare-versions`) or the tracker's stated fixed version; never string-compare.
- RPM uses `rpmdev-vercmp` semantics. Alpine uses `apk version -t`.
- Version banners can be hidden or lie. Prefer package database output over network banners.
- Rebuilt or vendor-patched binaries can carry fixes without version changes. Treat these as `needs_validation` until the vendor statement is read.
