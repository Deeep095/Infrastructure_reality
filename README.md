
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
pip install -e .[table]     # + rich, for `--output table` only
pip install -e .[dev]       # + pytest, ruff, mypy (and rich) for development
```

`boto3` is optional: it is imported only inside the AWS adapters, only when
you opt in. `rich` is optional in the same way — imported only by the
`--output table` renderer. Everything else — scan of local `terraform show -json`
exports, `reconcile`, `why`, `impact`, `simulate`, and the `text`, `json`, `yaml`
and `csv` output formats — works without either.

## A complete local demo (no AWS, no Terraform, offline)

### The whole product in one command

```bash
$ python scripts/build_demo_db.py
demo: wrote ...\demo.db from recorded responses (no AWS call was made)
  scan 1: 22 resource(s), 23 relationship(s)
  reconcile pass 2: 23 finding(s) - confirmed 6 undocumented 4 possible 8 declared_only 5 unknown 0
  undocumented: aws/ec2/instance/eu-west-1/123456789012/i-0batch -> aws/ec2/security-group/eu-west-1/123456789012/sg-0bbb222
  undocumented: aws/ec2/instance/eu-west-1/123456789012/i-0web -> aws/ec2/security-group/eu-west-1/123456789012/sg-0zzz999
  undocumented: aws/iam/role/-/123456789012/processor_role -> aws/s3/bucket/-/-/data-lake
  undocumented: aws/lambda/function/eu-west-1/123456789012/cleanup -> aws/iam/role/-/123456789012/cleanup_role
```

The builder replays the API responses recorded under `tests/fixtures/` through the
real adapters, so this is the actual code path — not a hand-written database. No
credentials are read, no request is made, and the Terraform executable is never
invoked. The counts are the point: 6 confirmed (both worlds agree, joined through
an identity mapping rather than a name), **4 undocumented** (observed in the
cloud, with no declaration accounting for them), 8 possible (a permission with no
observed usage behind it), and 5 `declared_only` — one world only, so no verdict
is claimed. Every conclusion is listed, so the tally always equals the number of
findings.

The headline is the `sg-0zzz999` line: a live security group attachment that no
state resource declares and no identity mapping can reach. Ask the tool about
the instance carrying it, and use the role as a CI gate:

```bash
$ python -m reality --database demo.db why aws:ec2/instance:eu-west-1:123456789012:i-0web
reality: why aws/ec2/instance/eu-west-1/123456789012/i-0web
  resource: ec2_instance provider=aws region=eu-west-1 account=123456789012 name=web-server
    native_id: i-0web
  relationships (2 outgoing, 0 incoming):
    -> .../sg-0aaa111 attached_to [aws_observed] evidence: aws:ec2:DescribeInstances:i-0web:...
    -> .../sg-0zzz999 attached_to [aws_observed] evidence: aws:ec2:DescribeInstances:i-0web:...
  findings (2):
    - reconcile:attached_to:...i-0web:...sg-0aaa111: confirmed - declared by Terraform and observed by aws_observed; both worlds agree on this dependency; the Terraform and AWS identities of this dependency were joined by an exact-identifier identity mapping (never a name match)
    - reconcile:attached_to:...i-0web:...sg-0zzz999: undocumented - observed by aws_observed with no matching Terraform declaration; Terraform was consulted, so the declared counterpart is missing rather than unread
  ...

$ python -m reality --database demo.db impact aws:iam/role:123456789012:cleanup_role --fail-on high
reality: impact of aws/iam/role/-/123456789012/cleanup_role (basis discovery_graph, depth 3)
  risk: high
  dependents (1):
    - aws/lambda/function/eu-west-1/123456789012/cleanup (depth 1, undocumented)
        path: aws/lambda/function/eu-west-1/123456789012/cleanup -> aws/iam/role/-/123456789012/cleanup_role
        provenance: aws_observed
  ...
$ echo $?
6
```

Read those two findings together — they are the whole product in four lines. The
declared `aws_instance.web` and the observed `i-0web` are the *same* instance,
joined because the state's ARN names `i-0web` and AWS reports `i-0web`; that
attachment is `confirmed`. The second attachment, to `sg-0zzz999`, has no
declaration anywhere and no mapping can reach it, so it is `undocumented` — a live
dependency Terraform does not account for. Neither is quietly upgraded, and the
distinction between them is the reason the tool exists.

`--fail-on` is the CI-facing part: the report is always printed, and only the
**exit code** carries the verdict, so a pipeline can gate on it while a human
still reads the reasoning.

### The local-only path, command by command

The demo above needs the fixtures. To follow the same ground by hand, start from
just a Terraform state export — no AWS at all:

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
        path: ...aws_db_instance.primary -> ...aws_security_group.web_sg
        provenance: terraform_declared
        evidence: tf:...:vpc_security_group_ids:sg-0aaa111
    - terraform/aws/aws_instance/-/-/aws_instance.web (depth 1, unknown)
        path: ...aws_instance.web -> ...aws_security_group.web_sg
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

Each `path:` runs in the direction its edges point — the dependent leads, the
subject you asked about ends it.

Two honest details worth noticing in that output:

- The dependents in step 3 are classified `unknown`, and the note says to run
  `reality reconcile` — unreconciled evidence is never silently upgraded to a
  conclusion.
- Step 4 reports `low` because nothing in the declared graph depends on
  `aws_instance.web` **and** the declared side (the scanned state file) was
  actually consulted. If coverage were missing, the same empty result would be
  `medium` — absence of evidence is not evidence of absence.

Run `reconcile` and the eight `unknown` findings above resolve to `unknown` with
the missing coverage named, because this scan never consulted AWS:

```bash
$ python -m reality --database demo.db reconcile
reality: reconcile pass 2 (analysing scan run 1)
  findings (8): unknown 8
  unknown (8) - the coverage needed to decide was missing:
    - ...aws_db_instance.primary -> ...aws_security_group.web_sg [attached_to]
        declared by Terraform, but whether it is observed could not be determined: aws_resources: not_requested; cloudtrail: not_requested
```

That is the honest answer for a local-only scan, and it is why the full demo
above replays recorded AWS responses: with them consulted, the same pass
separates the declared world from the observed one instead of shrugging.

Delete `demo.db` when you are done; it is a plain SQLite file and nothing else
was written.

## Commands

| Command | What it does |
|---|---|
| `reality scan [TFJSON …]` | Parse local `terraform show -json` state/plan exports into the database; with the AWS opt-in triple, also discover live resources (EC2, Lambda, RDS, S3, security groups), IAM role permissions, and CloudTrail usage |
| `reality reconcile [--scan-run N] [--output FORMAT]` | Compare the declared and observed worlds and store a conclusion per relationship candidate: `confirmed`, `undocumented`, `possible`, `declared_only`, or `unknown` with the missing coverage named. Idempotent — re-running replaces the same rows |
| `reality why RESOURCE` | Show one resource with its relationships, evidence, findings, and coverage limitations |
| `reality impact RESOURCE [--depth N] [--fail-on LEVEL] [--json]` | Reverse-traverse stored relationships to report the blast radius of a resource |
| `reality simulate PLAN_JSON [--depth N] [--fail-on LEVEL] [--json]` | Select the delete/replace targets of an exported plan and report each one's blast radius; the plan is parsed, never applied |

`RESOURCE` may be a full canonical ID, a Terraform address
(`aws_security_group.web_sg`), an ARN, a native ID, or the short display form
(`aws:iam/role:123456789012:cleanup_role`). Resolution never falls back to a
name match, and an ID that matches more than one stored resource is refused
rather than resolved to a guess.

Global flags: `--database PATH` (default `reality.db`), and the AWS opt-in
group `--aws --profile PROFILE --region REGION` (all three required together).
These go **before** the subcommand — `reality --database x.db scan` — but they
also work **after** it, so `reality scan --database x.db` is accepted too.
`scan --cloudtrail-start/--cloudtrail-end` bound the CloudTrail lookup window
and additionally require the AWS triple.

`--output` accepts `text` (default), `table`, `json`, `yaml`, and `csv`; `json`
is byte-stable (sorted keys, no timestamps), so identical inputs produce
identical bytes and the output diffs cleanly in CI. One deliberate exception:
re-running `reconcile` advances `scan_run_id`, because each pass is a new scan
run. The conclusions themselves — `findings` and `counts` — do not move, and a
test asserts exactly that.

`table` is the only format with an extra dependency. Without `rich` installed it
exits `2` and says so, rather than failing with a traceback:

```
$ reality --database demo.db reconcile --output table
reality: error: the 'table' output format needs the optional 'rich' package;
install it with: pip install 'reality[table]' ...
```

Exit codes: `0` success · `2` usage error · `3` command registered but not
implemented · `4` configuration rejected by the safety contract · `5` invalid
local input (a refused scan/simulation, an ambiguous or unknown resource, or a
plan the database has never seen) · `6` the `--fail-on` threshold was met.

`--fail-on {never,medium,high}` (default `never`) turns the risk band into a
CI verdict. The report is always printed regardless; only the exit code gates:

```bash
reality --database demo.db impact aws:iam/role:123456789012:cleanup_role --fail-on high || exit 1
```

Because the default is `never`, adding the flag to a human's command changes
nothing — it only takes effect where someone opted into gating.

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

## Testing against a real AWS account

The offline suite proves the code paths; it cannot prove they work against a
real account. `ManualTests/aws-live/` does. It points the real adapters at a
real account and checks the whole flow end to end:

```bat
pip install -e ".[aws]"
python ManualTests\aws-live\run_live_test.py --profile deepanshu
```

Add `--with-state` to also parse a Terraform state export, so `reconcile` has
both worlds to compare:

```bat
python ManualTests\aws-live\run_live_test.py --profile deepanshu --with-state
```

It is strictly read-only — the adapters whitelist only List/Get/Describe
operations, and the script asserts that whitelist before trusting anything.
The CloudTrail window is bounded to one day. Everything writes to
`ManualTests/aws-live/live.db`; delete that file to start over.

The script checks the safety contract, `sts GetCallerIdentity`, `scan --aws`,
`reconcile`, `why`, `impact`, all five output formats, the `--fail-on` gate,
and that rows actually landed in the database.
