# Report contract

Machine schema: `report-schema.json`. Validator: `scripts/validate-report.mjs`. Inventory schema: `inventory-schema.json`, validator `scripts/validate-inventory.mjs`.

```
node scripts/validate-inventory.mjs inventory.json
node scripts/validate-report.mjs report.json --inventory inventory.json
```

Exit codes: 0 valid, 1 invalid (errors on stderr), 2 unreadable input.

## Top level

| Field | Meaning |
|---|---|
| `schema_version` | 1 |
| `mode` | `inventory_audit`, `disclosure_watch`, `remediation_plan` |
| `scope` | `owner`, `own_assets_confirmed: true`, optional `inventory_generated_at` |
| `coverage` | Ledger, see below |
| `findings` | Zero or more findings |
| `remediation_plan` | Required when mode is `remediation_plan` |

## Coverage ledger

One entry per source queried: `source`, `status` (`checked`, `partial`, `skipped`, `failed`), `checked_at`, `asset_ids`, and `reason` (required unless `checked`). With `--inventory`, every inventory asset must appear under a `checked` entry. A gap must be visible, not implied.

## Finding

`id` (F-001 style), `title`, `verdict`, `severity`, `origin` (`scanner`, `free_text_disclosure`, `both`), `advisory` (ids, source, https url, optional published_at, embargo_respected, excerpt up to 500 characters, kev, epss), `affected` (asset_id, installed_version, fixed versions, match_basis, backport_checked), `hunter` (claim, evidence), `verifier` (disproof_attempts, result, notes), plus `open_question` or `rejection_reason` by verdict.

## Semantic rules enforced by the validator

- confirmed: verifier survived; not `manual_reading`; runtime or free-text origin needs `backport_checked: true`; free-text needs `published_at`.
- needs_validation: needs `open_question`; verifier not disproved.
- rejected: verifier disproved; needs `rejection_reason`.
- asset ids must exist in the inventory when one is supplied.
- no secrets, code fences, or exploit file names anywhere in the report.
- `embargo_respected: false` fails.
- plan steps: no rejected findings; live steps need approval; approved steps need `approved_by`.

## Human summary

After the JSON, write a short summary: confirmed findings first (KEV, then EPSS, then severity), then needs_validation with open questions, then rejected one-liners, then coverage gaps. No PoCs.
