# Handoff: Complete `reality` Project

## Current State (pushed to main @ 4fa5b75)

All gates green: **528 tests pass, mypy clean (29 files), ruff clean**.

### What Works
- `reality scan` (local Terraform + optional AWS)
- `reality reconcile` with `--fail-on` + `--conclusion` filter
- `reality why` / `impact` / `simulate` / `graph`
- `reality config` (init/show/path) + `reality doctor`
- Test isolation via `tests/conftest.py` (REALITY_CONFIG + boto3 guard)
- AWS provenance note before first call

### Remaining Work

| Priority | Item | Details |
|----------|------|---------|
| **P0** | **Complex demo environment** | `Atest/` with recorded AWS responses (moto/localstack) + multi-resource Terraform state → run full `scan → reconcile → why/impact/graph/simulate` offline |
| **P0** | **CLI visual polish** | Rich tables aligned, colors per conclusion, progress bars, `--output table` default when rich installed, mermaid copy-paste friendly |
| **P1** | **Package metadata** | `py.typed`, version from `pyproject.toml`, `pip install -e .` produces `reality` entry point |
| **P1** | **Docs/README sync** | All new flags documented, mermaid examples, CI gate example |
| **P2** | **Cleanup** | Remove `debug_*.py`, `Atest/*.db` (gitignore), any `__pycache__` |
| **P2** | **Emulator integration** | Add `moto` to dev extra; script to record real AWS → replay offline |

---

## Immediate Next Steps for Next Agent

### 1. Build `Atest/complex-demo/` (offline, reproducible)

```
Atest/complex-demo/
├── terraform/
│   ├── main.tf              # VPC, SG, EC2, RDS, Lambda, IAM, S3, CloudFront
│   └── terraform.tfstate    # Pre-recorded state (json)
├── moto-responses/
│   ├── ec2.json             # DescribeInstances, DescribeSecurityGroups, etc.
│   ├── iam.json             # ListRoles, GetRolePolicy, SimulatePrincipalPolicy
│   ├── cloudtrail.json      # LookupEvents for 30-day window
│   └── lambda.json          # ListFunctions, GetFunction
├── run_demo.py              # Orchestrates: scan → reconcile → why/impact/graph/simulate
└── expected/                # Golden outputs for regression
    ├── reconcile.json
    ├── graph-*.mmd
    └── impact.json
```

**Constraints**: Zero real AWS calls. Use `moto` to mock boto3, or pre-recorded JSON fixtures. The demo must run in CI (GitHub Actions) without credentials.

### 2. CLI Visual Polish

- **Rich tables**: Conclusion colors (green/red/orange/blue/gray), fixed column widths, wrap long IDs
- **Progress**: Spinner + "source: X resources" per source, ETA for CloudTrail
- **`--output table`**: Auto-enable when `rich` installed and stdout is TTY
- **Mermaid**: Sanitized IDs (`n<hash>`), labels with `terraform_address | native_id | arn_suffix`, classDef per conclusion
- **Error messages**: "Did you mean X?" for ambiguous IDs, show resolution path

### 3. Package Metadata

```toml
# pyproject.toml additions
[tool.setuptools.packages.find]
where = ["src"]

[tool.mypy]
python_version = "3.12"
```

Add `src/reality/py.typed` (empty file). Version from `pyproject.toml` via `importlib.metadata`.

### 4. Cleanup

```bash
# Add to .gitignore
**/__pycache__/
*.db
*.pyc
debug_*.py
Atest/*.db
Atest/complex-demo/*.db
```

Delete `debug_graph.py`, `debug_schema.py` from repo root.

### 5. Emulator Script (optional but high leverage)

```bash
# scripts/record_aws.py --profile deepanshu --region us-east-1 --output Atest/complex-demo/moto-responses/
# Uses boto3 to hit real AWS once, saves JSON fixtures
# CI replays via moto: responses from JSON, zero network
```

---

## Current Atest/ State (for context)

```bash
Atest/
├── reality.db          # Last scan (30 IAM roles, 2 SGs, 2 Lambdas, 9 TF resources)
└── state.json          # Terraform state used
```

Run from `Atest/`:
```bash
reality graph "aws/iam/role/-/905418449359/aws-service-role/resource-explorer-2.amazonaws.com/AWSServiceRoleForResourceExplorer" --direction outgoing --output mermaid
reality graph "aws/logs/log-group/us-east-1/905418449359/aws/lambda/PostUploadFunction" --output mermaid  # fix ID first
reality reconcile --fail-on undocumented --output table
reality impact "aws/iam/role/-/905418449359/AmazonSSMAutomationRole" --fail-on high
reality simulate state.json  # needs plan.json
```

---

## Key Files to Know

| File | Purpose |
|------|---------|
| `src/reality/cli.py` | Entry point, parser, dispatch, provenance note |
| `src/reality/services/graph.py` | `GraphView`, `GraphExporter` (DOT/Mermaid/text) |
| `src/reality/services/reconcile.py` | Verdict logic, `ReconcileReport.filter_conclusion` |
| `src/reality/services/reports.py` | Renderers (text/table/JSON/YAML/CSV) |
| `src/reality/settings.py` | Config precedence, TOML, doctor checks |
| `tests/conftest.py` | Isolation fixtures (autouse) |
| `tests/unit/test_settings_and_doctor.py` | 41 tests for config/doctor/contract |

---

## Acceptance Criteria for "Done"

1. `cd Atest/complex-demo && python run_demo.py` runs **fully offline**, produces:
   - `reconcile` with mixed conclusions (confirmed/undocumented/possible/declared_only/unknown)
   - `graph --output mermaid` with ≥20 nodes, styled edges
   - `impact` with blast radius depth ≥3
   - `simulate` with plan showing replace/delete targets
2. `pip install -e . && reality --version` works
3. `reality --help` shows all flags; `reality doctor` shows green checks
4. GitHub Actions: `ubuntu-latest` + `windows-latest` both pass
5. No uncommitted `.db`, `__pycache__`, `debug_*.py`

---

## Example Prompt for Next Agent

> "Finish the `reality` project. Build `Atest/complex-demo/` with a complex Terraform state + moto-recorded AWS responses so the full pipeline runs offline. Polish CLI output (rich tables, mermaid, progress). Add `py.typed`, version, entry point. Clean up temp files. All gates must pass on Linux + Windows CI."

---

## Current Command Outputs (for reference)

```bash
# From Atest/ after scan+reconcile
$ reality reconcile --fail-on undocumented
reality: reconcile pass 5 (analysing scan run 4)
  findings (220): undocumented 13, declared_only 8, possible 199
  undocumented (13) - observed in the cloud, but no declaration accounts for it
    - aws:iam/role:905418449359:AWSServiceRoleForResourceExplorer -> aws:logs/log-group::us-east-1:905418449359:aws/lambda/PostUploadFunction [depends_on]
    ...

$ reality graph "aws/iam/role/-/905418449359/aws-service-role/resource-explorer-2.amazonaws.com/AWSServiceRoleForResourceExplorer" --direction outgoing --output mermaid
graph TD
  n30a7994c5da9["AmazonSSMAutomationRole | role/AmazonSSMAutomationRole"]
  # (no edges because permissions target unresolved:* filtered by default)
```

The demo environment must produce richer graphs — multiple hops, mixed conclusions, visible blast radius.