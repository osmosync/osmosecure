# Mode 1: inventory audit

## Steps

1. Confirm scope and owner (`safety.md`).
2. Build the inventory. Collect only what exists:
   - `lockfile_package`: parse `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `poetry.lock`, `requirements*.txt` with hashes, `composer.lock`, `Gemfile.lock`, `go.sum` / `go.mod`, `Cargo.lock`. Record the file path as `location`.
   - `container_image`: from compose files, Kubernetes manifests, and running containers. Pin a `digest`; a tag alone is not an inventory row.
   - `host_runtime`: php, openssl, nginx, node, postgres, and any other interpreter or server. Record upstream version, `distro`, `distro_release`, and the package manager's exact version string in `notes`.
   - `os_package`: the host packages relevant to exposed services.
3. Validate: `node scripts/validate-inventory.mjs inventory.json`. Fix errors before matching.
4. Match:
   - Lockfile packages: OSV batch query, cross-check GHSA.
   - Images: scan layers with the owner's scanner output if available; otherwise match the OS package list.
   - Host runtimes and OS packages: distro tracker first, then NVD/OSV for upstream.
5. Enrich with KEV and EPSS for ranking.
6. Run the hunter then the verifier (`hunter-verifier.md`).
7. Write the coverage ledger: one entry per source with the asset ids it covered.
8. Emit and validate the report (`report-contract.md`).

## Notes

- Dev-only dependencies and unreachable images are lower priority, not excluded.
- If the inventory is older than the report scope allows, say so in `scope.inventory_generated_at`.
- The scanner output counts as a source. Deduplicate against it and set `origin: scanner` or `both`.
