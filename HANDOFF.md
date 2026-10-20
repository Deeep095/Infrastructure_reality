# Project handoff: `reality`

## Current state

`reality` is a working Python CLI prototype for local Terraform-export parsing, optional read-only AWS collection, evidence-based reconciliation, resource explanations, graph export, impact traversal, and plan-target simulation. The repo includes an offline fixture-backed demo and unit/integration tests.

The project is not a complete AWS inventory, production risk engine, or outage-prevention product. Its present AWS scope is a few resource types and relationship shapes in one selected region, plus global IAM/S3 behavior. CloudTrail lookup is explicitly bounded and does not provide general data-plane usage history.

### Main paths

- `src/reality/cli.py` — parser, safety gates, command dispatch, output selection.
- `src/reality/adapters/` — Terraform JSON, selected AWS resources, IAM policies, CloudTrail.
- `src/reality/services/reconcile.py` — snapshot-scoped comparison and conclusions.
- `src/reality/services/impact.py` — bounded reverse traversal and plan simulation.
- `src/reality/services/reports.py` — text/table/JSON/YAML/CSV renderers.
- `src/reality/storage/` — SQLite schema, migrations, and repositories.
- `scripts/build_demo_db.py` — offline demo fixture replay.
- `tests/` — unit, integration, and offline demo coverage.

## Important model distinctions

- Terraform declarations, AWS observations, IAM permissions, and CloudTrail activity are not interchangeable evidence.
- A Lambda's configured execution role is modeled as `uses_role`; an IAM grant is `permission_on` and is not proof of runtime use.
- IAM-policy-only edges are excluded from impact dependents. Reconciliation still reports permission-only candidates as `possible`.
- `high` / `medium` / `low` in impact are deterministic review bands, not calibrated risk values.
- Missing coverage must remain visible. Do not turn an unrequested or unavailable source into evidence of absence.
- Avoid fuzzy name-based joins. Exact identifiers and explicit identity mappings are part of the safety contract.

## Verification

Run from the repository root with the development environment installed:

```bash
python -m pytest
python -m ruff check src tests
python -m mypy
python scripts/build_demo_db.py --out demo.db
```

The AWS demo replay uses local JSON fixtures and must stay offline. Never run a live-account test unless the user explicitly requests it and the read-only/profile/region boundary is confirmed.

## Highest-priority follow-up

1. **Relationship-aware AWS coverage.** AWS resources, IAM, and CloudTrail now retain per-call coverage and a final completeness record; one failed call can no longer be hidden by another successful call. This is intentionally conservative. Next, associate each relationship family with the exact API capabilities that can reveal it, so an unrelated denied call does not make every conclusion unknown. Keep regression tests for partial scans.
2. **Document the comparison boundary in reports.** Make it obvious that reconciliation compares extracted relationship candidates, not entire Terraform and AWS inventories. Keep unsupported resource families visibly out of scope.
3. **Improve finding usability.** The table/text report should make conclusion, relationship type, endpoints, evidence source, and coverage caveat easy to scan without dumping opaque IDs first. Keep JSON stable and machine-friendly.
4. **Validate the relationship catalog.** Every new edge needs a documented direction and meaning (for example, configured role use versus policy authorization), tests for the exact source field, and a statement about what the edge does _not_ prove.
5. **Validate packaging and live compatibility separately.** Test clean installation and supported Python versions; add carefully scoped AWS integration validation only after fixture coverage and API permission docs are clear.

## Do not do next

- Do not add lots of AWS services just to increase node or edge counts.
- Do not label all permission grants as dependencies or runtime usage.
- Do not advertise `high` / `medium` / `low` as measured or objective risk.
- Do not claim full AWS drift detection, complete account coverage, outage prevention, or multi-cloud readiness without evidence.
- Do not remove explanatory comments that document a safety boundary or a non-obvious domain rule. Remove stale instructions and repeated narration instead.

## User-facing docs

`README.md` is the main usage guide. `INTERVIEW_GUIDE.md` contains a deliberately conservative interview pitch and a current-scope checklist. `AWS_DATA_COLLECTION_EXPLAINED.md` documents actual collection calls and their limits. Keep all three aligned with the adapters and tests when behavior changes.
