
# Infrastructure_reality


Read-only cloud infrastructure discovery and local blast-radius simulation.

`reality` builds a local, evidence-backed picture of your infrastructure from
two worlds — what Terraform **declares** and what AWS **reports** — and then
answers "what would be affected?" for a resource or a Terraform plan, without
ever touching the infrastructure itself. It never makes a mutating AWS call,
never runs Terraform, and never applies a plan: the safety contract in
[docs/safety.md](docs/safety.md) is the hard boundary every feature is built
inside.

The core ideas:

- **Evidence is not a conclusion.** Raw observations, relationship candidates,
  reconciliation findings, and coverage records are stored separately. Missing
  data is `UNKNOWN` — never "no dependency".
- **No guessing identities.** Every identifier passes through canonical-ID
  normalization ([docs/architecture.md](docs/architecture.md#canonical-ids));
  the declared world (`terraform/...`) and the observed world (`aws/...`) stay
  distinct namespaces, and an unresolvable reference is recorded unresolved
  rather than joined to something similar.
- **AWS is strictly opt-in.** No default profile, no default region. AWS
  adapters run only with the explicit `--aws --profile PROFILE --region REGION`
  triple; a partial selection is an error, not a fallback to local-only.
- **Risk is documented, not scored.** Blast radius is reported as HIGH /
  MEDIUM / LOW bands with the reasoning attached, never as a fabricated number.

## Install

Python 3.12+.

```bash
pip install -e .            # core (local Terraform parsing + storage + reports)
pip install -e .[aws]       # + boto3, for the optional AWS discovery sources
pip install -e .[dev]       # + pytest, ruff, mypy for development
```

`boto3` is optional: it is imported only inside the AWS adapters, only when
you opt in. Everything else — scan of local `terraform show -json` exports,
`why`, `impact`, `simulate` — works without it.

## A complete local demo (no AWS, no Terraform, offline)

The repository ships fixtures under `tests/fixtures/`. This demo runs entirely
offline — no AWS credentials, no network, and the Terraform executable is never
invoked (the fixtures are pre-exported JSON documents).

```bash
# 1. Scan the declared world: a local `terraform show -json` state export.
$ python -m reality --database demo.db scan tests/fixtures/terraform/state.json
reality: scan 1 complete; 4 source(s) considered
  terraform: available - 1 file(s) parsed: 9 declared resource(s), 8 relationship candidate(s)
  aws_resources: not_requested - not requested for this scan
  iam: not_requested - not requested for this scan
  cloudtrail: not_requested - not requested for this scan
  wrote 9 resource(s), 8 relationship(s), 8 evidence item(s), and 4 coverage record(s) to demo.db

# 2. Ask why a resource exists: relationships, evidence, findings, coverage limits.
$ python -m reality --database demo.db why terraform/aws/aws_security_group/-/-/aws_security_group.web_sg
reality: why terraform/aws/aws_security_group/-/-/aws_security_group.web_sg
  resource: security_group provider=terraform region=- account=- name=web_sg
    native_id: sg-0aaa111
    arn: arn:aws:ec2:eu-west-1:123456789012:security-group/sg-0aaa111
    terraform_address: aws_security_group.web_sg
  relationships (0 outgoing, 3 incoming):
    <- terraform/aws/aws_instance/-/-/aws_instance.web references [terraform_declared] evidence: tf:...:depends_on:aws_security_group.web_sg
    <- terraform/aws/aws_instance/-/-/aws_instance.web attached_to [terraform_declared] evidence: tf:...:vpc_security_group_ids:sg-0aaa111
    <- terraform/aws/aws_db_instance/-/-/aws_db_instance.primary attached_to [terraform_declared] evidence: tf:...:vpc_security_group_ids:sg-0aaa111
  evidence (3):
    - tf:...: terraform_state/config_reference high - Terraform configuration declares an explicit depends_on ...
    ...
  findings (0):
    none
  coverage limitations (4):
    - aws_resources: not_requested - AWS was not opted in with --aws --profile PROFILE --region REGION
    ...

# 3. Blast radius of that security group: reverse-traverse stored relationships.
$ python -m reality --database demo.db impact terraform/aws/aws_security_group/-/-/aws_security_group.web_sg
reality: impact of terraform/aws/aws_security_group/-/-/aws_security_group.web_sg (basis discovery_graph, depth 3)
  risk: medium
  dependents (2):
    - terraform/aws/aws_db_instance/-/-/aws_db_instance.primary (depth 1, unknown)
        path: ...aws_security_group.web_sg -> ...aws_db_instance.primary
        provenance: terraform_declared
        evidence: tf:...:vpc_security_group_ids:sg-0aaa111
    - terraform/aws/aws_instance/-/-/aws_instance.web (depth 1, unknown)
        path: ...aws_security_group.web_sg -> ...aws_instance.web
        provenance: terraform_declared
        evidence: tf:...:attached_to:vpc_security_group_ids:sg-0aaa111, tf:...:references:depends_on:...
  notes:
    - ...: no reconciliation finding; run reality reconcile

# 4. Simulate an exported plan: what would its delete/replace targets affect?
$ python -m reality --database demo.db simulate tests/fixtures/terraform/plan_replace.json
reality: simulate tests/fixtures/terraform/plan_replace.json (read-only; the plan is never applied)
  overall risk: low
  targets (1):
    - aws_instance.web [replace] -> terraform/aws/aws_instance/-/-/aws_instance.web
        risk: low
        dependents: none
```

Two honest details worth noticing in that output:

- The dependents in step 3 are classified `unknown`, and the note says to run
  `reality reconcile` — unreconciled evidence is never silently upgraded to a
  conclusion.
- Step 4 reports `low` because nothing in the declared graph depends on
  `aws_instance.web` **and** the declared side (the scanned state file) was
  actually consulted. If coverage were missing, the same empty result would be
  `medium` — absence of evidence is not evidence of absence.

Delete `demo.db` when you are done; it is a plain SQLite file and nothing else
was written.

## Commands

| Command | What it does |
|---|---|
| `reality scan [TFJSON …]` | Parse local `terraform show -json` state/plan exports into the database; with the AWS opt-in triple, also discover live resources (EC2, Lambda, RDS, S3, security groups), IAM role permissions, and CloudTrail usage |
| `reality why RESOURCE` | Show one resource with its relationships, evidence, findings, and coverage limitations |
| `reality impact RESOURCE [--depth N] [--json]` | Reverse-traverse stored relationships to report the blast radius of a resource |
| `reality simulate PLAN_JSON [--depth N] [--json]` | Select the delete/replace targets of an exported plan and report each one's blast radius; the plan is parsed, never applied |
| `reality reconcile` | Registered, not yet wired (exit 3) |

Global flags: `--database PATH` (default `reality.db`), and the AWS opt-in
group `--aws --profile PROFILE --region REGION` (all three required together).
`scan --cloudtrail-start/--cloudtrail-end` bound the CloudTrail lookup window
and additionally require the AWS triple.

Exit codes: `0` success · `2` usage error · `3` command registered but not
implemented · `4` configuration rejected by the safety contract · `5` invalid
local input (a refused scan/simulation, or a resource/plan the database has
never seen).

`impact` and `simulate` accept `--json` for byte-stable machine-readable
output (sorted keys, no timestamps): identical inputs produce identical bytes.

## Where to read more

- [docs/safety.md](docs/safety.md) — the read-only guarantee, how it is
  enforced, and what this tool will never do.
- [docs/architecture.md](docs/architecture.md) — supported resource and
  evidence scope, canonical-ID rules, coverage and reconciliation semantics,
  blast-radius traversal and risk bands, storage layout, and the known
  limitations of the IAM and CloudTrail sources.

## Development

```bash
python -m pytest                      # full suite (offline; no AWS credentials)
python -m pytest tests/unit -q        # unit only
python -m ruff format src tests       # formatter
python -m ruff check src tests        # linter
python -m mypy                        # type checker (configured in pyproject.toml)
```

The test suite runs entirely offline: AWS-facing tests use scripted fake
clients (plus one botocore `Stubber` test that skips cleanly when boto3 is not
installed), Terraform input is pre-exported fixture JSON, and CI pins dummy
AWS environment variables to prove nothing needs real credentials.