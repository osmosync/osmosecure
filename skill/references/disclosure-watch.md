# Mode 2: disclosure watch

Finds disclosures that databases and scanners do not yet carry.

## Steps

1. Load the current inventory and validate it.
2. Fetch new items from the free-text sources in `source-catalog.md` since the last watermark. Store the watermark (timestamp and item hash) outside the report.
3. Pre-filter by product keywords drawn from inventory names (php, openssl, nginx, node, postgres, plus lockfile package names). Items matching nothing are logged in coverage as seen and skipped.
4. Triage each remaining item in the isolated, tool-less step with the closed output schema (`prompt-injection-defense.md`).
5. Map each triage record to inventory rows by product, then by version range from the record.
6. Apply distro backport rules (`runtime-gap.md`). Query the distro tracker for the installed release.
7. Deduplicate against scanner results. If a scanner already flags it, mark `origin: both` and add nothing new.
8. Run hunter and verifier. Typical outcomes:
   - Tracker lists a fix at or below installed: `rejected` with citation.
   - Tracker has no entry: `needs_validation`, recheck within a stated window.
   - Installed is below the fixed version on the tracker, component enabled: `confirmed`.
9. Honor embargoes and do not copy PoCs (`safety.md`).
10. Emit the report with `mode: disclosure_watch` and validate it.

## Cadence

Schedule through the owner's scheduler. Re-run `needs_validation` items when trackers update. A daily sweep is typical; the skill does not require a particular cadence.

## What to report to humans

Lead with confirmed findings that touch internet-exposed runtimes. Then needs_validation items with the open question. List rejected items in one line each. State any source that failed.
