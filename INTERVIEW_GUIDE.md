# Infrastructure Reality — Interview Notes

## 30-second pitch

> I built `reality`, a local-first Python CLI that compares Terraform JSON exports with a read-only snapshot of selected AWS resources. It keeps evidence separate from conclusions, uses exact identifiers rather than name guesses, and marks conclusions as unknown when required inputs were not available. It can also trace stored dependents and inspect destructive targets from an exported Terraform plan. It is a focused prototype, not a complete cloud inventory or a replacement for Terraform, AWS Config, or a production risk engine.

## What the project actually does

A scan can combine local `terraform show -json` state/plan exports with explicitly opted-in AWS reads. The results are stored in SQLite. `reality reconcile` compares relationship candidates from that one scan snapshot and records one of five outcomes:

- `confirmed`: a declaration and an observation match.
- `undocumented`: an observation has no matching declaration, and Terraform input was available.
- `possible`: an IAM policy grants access, but that does not establish runtime use.
- `declared_only`: Terraform declares a relationship but no consulted observation found it. This does not mean it is unused.
- `unknown`: missing coverage prevents a defensible conclusion.

The labels describe the comparison, not an overall health grade. They do not tell you whether a finding is exploitable, important to the business, or safe to change.

## Current collection scope

AWS collection is opt-in and requires an explicit profile and region. The current resource adapter reads EC2 instances and security groups, Lambda functions, RDS DB instances, and S3 bucket names. It records a small set of direct links: EC2/RDS security-group associations and a Lambda function's execution role. IAM policy reads produce _permission candidates_, not proof that a role used a resource. CloudTrail lookup is bounded by a caller-supplied time window and only supports the management events visible through `LookupEvents`; it does not provide complete S3 or other data-plane access history.

This is intentionally not a full AWS account inventory. It does not currently enumerate every service, every resource configuration, every region, network routes, security-group rules as dependency edges, or every possible runtime relationship. A missing resource or edge may simply be outside this tool's collection scope.

## Demo you can run offline

From the repository root:

```bash
python scripts/build_demo_db.py --out demo.db
python -m reality --database demo.db reconcile
python -m reality --database demo.db reconcile --conclusion undocumented --verbose
python -m reality --database demo.db why aws:ec2/instance:eu-west-1:123456789012:i-0web
python -m reality --database demo.db impact aws:iam/role:123456789012:cleanup_role
python -m reality --database demo.db simulate path/to/plan.json
```

The demo replays committed response fixtures through the adapters. It does not use credentials, contact AWS, invoke Terraform, or apply a plan. Use the output as a demonstration of this fixed fixture world, not as a benchmark or production-account result.

## Technical decisions worth discussing

### Evidence and coverage are separate

Adapters record source-native evidence and candidate relationships. Reconciliation applies explicit rules later. This makes a result auditable and lets the tool distinguish a missing declaration from an unconsulted source. An unavailable or unrequested source must not be treated as proof that no dependency exists.

### Identity is exact, not fuzzy

Canonical IDs preserve provider, service, type, region, account, and native identity. Terraform and AWS identities remain distinct unless an exact ARN or unambiguous native-ID mapping joins them. Names are display aids, not identity keys. Ambiguous lookups are rejected rather than guessed.

### Not all edges mean the same thing

`uses_role` means a Lambda is configured to run with a role. `permission_on` from IAM means a policy allows an action against a resource; it does not mean the action happened. The impact traversal excludes IAM-policy-only grants from runtime dependents. CloudTrail observations are management-plane evidence and remain bounded by the requested window.

### Local-first and read-only boundaries

AWS access requires explicit opt-in, the adapters use an allowlist of read operations, and the Terraform adapter reads exported JSON rather than invoking Terraform. `simulate` reads a plan JSON and reports on delete/replace targets; it never applies changes. The SQLite write is transactional per scan. These boundaries are tested, but this does not make the collected data complete or the resulting recommendations infallible.

## Honest limitations and next steps

1. **Coverage is narrow.** Add resource types and edges only with service-specific evidence and tests; do not call the result a complete dependency graph.
2. **Coverage granularity needs care.** AWS resources, IAM, and CloudTrail retain per-call records and a final completeness record, so one successful call cannot hide a failure in another. That all-or-nothing rule is conservative; the next step is mapping relationship families to the exact API capabilities that can reveal them.
3. **CloudTrail is not a usage oracle.** Its supported lookup cannot provide data-plane history, and the chosen interval may miss infrequent behavior.
4. **Impact bands are heuristics.** `high`, `medium`, and `low` are rule-based review bands, not probability, severity, blast-radius magnitude, or a calibrated risk score. Business criticality is not modeled.
5. **One-region scans are not account-wide.** AWS resources are collected in the selected region (with global IAM/S3 behavior where applicable); users need repeatable multi-region orchestration before claiming account-wide coverage.
6. **Production readiness is unproven.** There is no published package/release process, large-account benchmark, or long-running live-account validation in this project.

A credible follow-up is relationship-aware coverage and a focused collection contract for one additional relationship family, backed by fixtures and known limitations. Avoid adding more AWS API calls just to make the graph look larger.

## Resume wording

Use only claims you can demonstrate:

> Built a Python CLI that reconciles Terraform JSON exports with read-only AWS observations, stores evidence-backed snapshots in SQLite, and reports undocumented relationships and bounded impact paths while preserving unknowns for missing coverage.

Optional second bullet if useful:

> Added offline AWS-response replay, deterministic identity resolution, CI exit thresholds, and tests for opt-in/read-only behavior.

Do not claim that the project prevents outages, detects all drift, inventories all AWS resources, or computes objective risk. Update any test-count claim immediately before an interview by running the current suite.

## Interview questions to prepare for

**How is this different from `terraform plan`?**

It consumes Terraform exports but compares their declared relationships with selected AWS observations. A plan describes Terraform's proposed changes; `reality` is a separate, limited reconciliation view. They are complementary, and neither view alone proves full infrastructure state.

**What does `possible` mean?**

An IAM policy grants a permission to a resource. The permission may be unused, conditionally usable, or wider/narrower in effect than this parser captures. It is not evidence of an actual call. CloudTrail events can add management-plane observations, subject to their scope and time window.

**Why can a result be `unknown`?**

Because the tool distinguishes “not observed” from “not checked.” Missing Terraform input, denied APIs, unrequested AWS sources, or unsupported coverage prevent a reliable absence claim.

**What would you fix before calling it production-ready?**

Make coverage capability-specific, clarify regional and service scope in every report, validate identity joins against more real resource shapes, benchmark large inventories, and add an explicit integration/compatibility policy. I would not present the current impact bands as a risk score.

**How would you extend it?**

Pick one useful use case, define the exact AWS API fields and relationship semantics, add read-only permission tests and captured fixtures, preserve provenance and coverage, then test the end-to-end reconciliation. Do not generalize to another cloud until the identity and coverage model has been validated for it.
