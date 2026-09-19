# Architecture

`reality` is a vertical slice: one pipeline from **local evidence in** to
**local blast radius out**, with a hard read-only boundary around it
([safety.md](safety.md)). This document describes what the slice covers, how
identity and evidence are modeled, and what each conclusion honestly means.

```
terraform show -json ──┐
aws (opt-in) read APIs ─┼─> adapters ──> ScanStore (SQLite) ──> reconcile ──> findings
iam (opt-in)      ──────┤                     │
cloudtrail (opt-in) ────┘                     └─> why / impact / simulate (reports)
```

Module map:

| Module | Responsibility |
|---|---|
| `reality.domain` | Frozen Pydantic models, enums, canonical-ID normalization (`ids.py`) |
| `reality.adapters` | `terraform` (local JSON only), `aws_resources`, `iam`, `cloudtrail` (injected clients, opt-in) |
| `reality.storage` | SQLite connection, migrations, repositories (one transaction per scan) |
| `reality.services` | `scan` (orchestration), `reconcile`, `hidden_dependencies`, `impact`, `reports` |
| `reality.cli` | Argument parsing, the AWS opt-in gate, exit codes |

## Supported scope

**Resource types** (the vertical slice): EC2 instances, security groups,
Lambda functions, RDS DB instances, S3 buckets, IAM roles. Terraform
declarations for any *other* resource type are still recorded, typed
`terraform_resource`, rather than dropped.

**Evidence sources** and what each can prove:

| Source | Input | Evidence kinds |
|---|---|---|
| `terraform_state` / `terraform_plan` | local `terraform show -json` files the user exported | config references (`depends_on`, security-group IDs, role ARNs) |
| `aws_resources` | read/describe/list APIs (opt-in) | observed attributes (instance↔security-group attachments, function→role) |
| `iam` | List/Get policy APIs (opt-in) | policy statements: *possible* permissions, never proof of use |
| `cloudtrail` | `lookup_events` (opt-in, bounded window) | observed API usage linking a principal to a target |

**Relationship types**: `depends_on`, `attached_to`, `permission_on`,
`contains`, `references`. Each relationship carries an **origin** —
`terraform_declared`, `aws_observed`, `iam_policy`, `cloudtrail` — because
which world made a claim is part of the claim. Evidence strength is
qualitative (`high`/`medium`/`low`/`unknown`), never a number.

## Canonical IDs

Every identifier becomes a canonical key of six segments:

```
provider / service / resource_type / region / account / resource_id
aws/ec2/instance/eu-west-1/123456789012/i-0web
terraform/aws/aws_instance/-/-/aws_instance.web
unresolved/-/-/-/-/arn:aws:s3:::data-lake/*
```

Rules (`reality.domain.ids`):

- **Three identity namespaces never merge implicitly.** `terraform/...`
  (the address *is* the ID), `aws/...` (an ARN partition + the scan's native
  IDs), and `unresolved/...` (wildcard ARNs, policy variables, hostnames).
  A declared `aws_instance.web` and the observed `i-0web` it manages are two
  different identities until evidence joins them — the *only* joins are
  explicit: the `terraform_addresses` mapping a plan scan records (read by
  `simulate`) and the evidence-backed `identity_mappings` a scan computes
  (read by reconciliation, below). Names never join anything.
- **Global services** (`s3`, `iam`, `cloudfront`, `route53`, `waf`) are
  region-less regardless of what an ARN claims; an S3 bucket's discovered
  region stays `None` even though `ListBuckets` reports one.
- **No guessing.** Wildcards are rejected by `parse_arn` and must go through
  `unresolved()`, where they can never equal a resolved ID. Region-scoped
  resources require an explicit region to build. `safe_join` refuses naive
  cross-account joins: region-scoped resources must match region *and*
  account; a missing account never matches a known one.
- **Refinement, never overwrite.** When later context (e.g. the STS account)
  fills in a missing region/account, `refine` applies it; a *contradiction*
  raises instead of silently resolving.
- The source-native identifier (native ID, ARN, Terraform address) is always
  preserved alongside the canonical key; parsing never destroys the original.

## Storage and data retention

One SQLite file (default `reality.db`), one transaction per scan. Tables:
`scan_runs` (anchor for everything a scan wrote), `resources`,
`relationships` + `relationship_evidence`, `evidence`, `coverage`,
`terraform_addresses`, `identity_mappings`, `findings`, `schema_metadata`.

- **What is stored**: discovery results only — identities, relationship
  candidates, evidence records (with a `raw_locator` pointing back into the
  source document or API response), coverage records, reconciliation
  findings. Nothing else.
- **What is never stored**: credentials or secrets. Credentials stay in the
  environment / AWS credentials file / named profile the user supplies; the
  database stores only the *name* of the profile inside coverage reasons.
  Adapters extract only non-secret metadata (a `Name` tag, a function name);
  the AWS fixtures deliberately contain secret-*shaped* values (Lambda
  environment variables, an RDS master-password field) and tests assert those
  values never appear in any persisted result.
- **Retention**: rows are upserted idempotently (re-scanning the same input
  writes the same facts once); coverage is append-only history where the
  latest record per source wins. Deleting the database file deletes
  everything the tool has ever recorded — there is no other output location,
  no telemetry, no cache outside the file you point it at.
- `why` / `impact` / `simulate` open the database **without migrating or
  writing**; if the file does not exist they exit 5 with "run reality scan
  first" rather than creating one.

## Coverage semantics

Every source consultation records `coverage(source, status, reason)`:

- `available` — the source was consulted.
- `unavailable` — the source was selected but could not be consulted (access
  denied, throttling, exhausted history). Per-service failures during an AWS
  scan discard that service's partial results and record `unavailable`; the
  scan continues.
- `not_requested` — the source was never selected (e.g. no AWS opt-in).

Coverage is the gate on every conclusion: **missing data is `UNKNOWN`, never
"no dependency"**. Within the analysed scan run, the latest record per source
decides — a source that was available once but failed most recently counts as
unavailable.

## Reconciliation

Reconciliation (`reality.services.reconcile`) compares candidates on **exact
canonical (source, target, type) triples only** — no fuzzy matching, no
name-based resolution. Candidates and their evidence are never modified;
conclusions are written as separate `findings` rows (stable IDs
`reconcile:{type}:{source}:{target}`).

**The snapshot boundary.** A pass analyses exactly one scan run — the latest
non-reconciliation run, or an explicit one. Only relationships with evidence
anchored to that run participate (evidence is the anchor; a relationship
itself carries no scan-run column), and only coverage that run recorded
gates the conclusions. Historic CloudTrail or IAM evidence stays stored but
cannot influence a newer scan's findings. Each pass first deletes findings
it no longer concludes, so a stale conclusion cannot survive into a newer
snapshot's report.

**Identity mappings.** When a single scan observed both worlds, it computes
evidence-backed joins (`reality.services.identity`) from the state's ARN —
authoritative, region and account included — or, only when the state carried
no usable ARN, from a native ID that exactly one observed resource of the
same type shares. Both identities are preserved; each mapping row points at
its own `identity_match` evidence record and a plain-text reason. The pass
groups candidates by *translated* triple (a Terraform identity replaced by
the AWS identity its mapping joins it to) and emits one finding per
contributing (source, target) pair, so both namespaces keep their own
finding rather than one invented identity replacing either.

The five conclusions and their coverage gates:

| Conclusion | Meaning | Requires |
|---|---|---|
| `confirmed` | declared and observed on the same triple | both sides present |
| `undocumented` | observed, no declaration, Terraform was consulted | declared side available |
| `possible` | IAM permission with no observed usage | CloudTrail available (only CloudTrail observes usage) |
| `declared_only` | declared, not observed, an observed source was consulted | observed side available |
| `unknown` | the coverage to decide was missing | — blocking sources recorded on the finding |

`declared_only` is explicitly **not** evidence of inactivity. Hidden
dependency reporting is a narrow projection of `undocumented` findings:
resolved endpoints, at least one observed evidence record, a qualitative
confidence band (strong/moderate/weak) and a text rationale — no fabricated
numbers.

## Impact and simulate

`impact RESOURCE` reverse-traverses stored relationships (a *dependent* is
the source of an edge pointing into the radius): breadth-first, bounded by
`--depth` (default 3), shortest path wins, parallel edges from one dependent
aggregate (evidence union, most-cautionary classification — a blast radius is
a worst-case report), and the visited set is seeded with the subject so
cycles and self-loops terminate. Each dependent is classified from its
reconciliation finding:

| Finding | Dependent kind |
|---|---|
| `confirmed` / `declared_only` | `documented` |
| `undocumented` | `undocumented` |
| `possible` | `possible` |
| `unknown` or no finding | `unknown` (with a note naming the blocker or suggesting `reality reconcile`) |

**Risk bands, documented rather than scored:**

- **HIGH** — any dependent is `undocumented`: the change would touch
  something the declared world does not know about.
- **MEDIUM** — known dependents of any other kind, or no dependents while
  relevant coverage is missing (absence of evidence is not evidence of
  absence).
- **LOW** — no dependents *and* the sources that could have revealed one
  were actually consulted. Relevant coverage is provider-based: a
  Terraform-namespace subject can only carry declared dependents, so the
  declared side (state **or** plan) suffices; any other subject also requires
  `aws_resources`, `cloudtrail`, and `iam` individually.

`simulate PLAN_JSON` parses a local plan file through the Terraform adapter
(a JSON reader — Terraform is never executed), selects targets whose actions
include `delete` or `replace` (delete+create is classified as `replace`;
updates are not destructive), resolves each address through the stored
`terraform_addresses` mapping (then the address's own Terraform-namespace
identity, if that resource was scanned), and runs the same impact traversal
per target. An address that resolves to nothing is reported `unresolved`
with `risk: unknown` — never guessed. The report's overall risk is the
highest target risk.

Both commands accept `--json`: byte-stable output (sorted keys, no
timestamps), so identical inputs produce identical bytes.

## Limitations of the AWS-side sources

**IAM**: a policy allow is a *possible* permission, never proof of runtime
use — only CloudTrail observes use. The slice covers **roles** (inline and
attached managed policies, default version only), not users or groups.
Wildcard resources, policy variables (`${...}`), and non-ARN strings cannot
name a specific target and are recorded `unresolved`; an explicit `Deny` is
kept as evidence but never emitted as a `permission_on` relationship.

**CloudTrail**: `lookup_events` exposes **management-plane events only** —
the adapter never claims data-plane visibility, and every coverage record and
explanation says so. A bounded, timezone-aware window of at most 90 days
(LookupEvents' own horizon) is mandatory. An empty lookup is recorded with
the caveat that a missing trail, a trail that does not cover the window, and
genuinely no activity all look identical — missing events are never negative
evidence. Only events where both principal and target resolve to canonical
IDs become relationship candidates; the rest are retained as unlinked
evidence.

## What is deliberately absent

- **No action engine.** `simulate` calculates and reports; it never applies,
  proposes automatic deletion, or generates commands to run.
- **No default AWS profile or region.** The opt-in triple is all-or-nothing.
- **No cross-namespace identity guessing.** The `terraform/` and `aws/`
  namespaces stay distinct by construction; the only joins are the stored
  address mapping (read by `simulate`) and exact-identifier identity
  mappings backed by their own evidence (read by reconciliation). Neither
  ever matches by name.
- **No numeric risk scores.** Bands with attached reasoning only.
