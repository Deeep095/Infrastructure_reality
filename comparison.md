# Scenario-based CLI comparison

**Prepared:** 2026-10-20
**Subject:** `reality` compared with adjacent command-line infrastructure, cloud
inventory, security, graph, and cost tools.

## Executive summary

`reality` is not a general cloud inventory tool, a compliance scanner, or a
Terraform replacement. Its narrow job is:

> Take a Terraform JSON export and, optionally, read-only AWS observations;
> preserve the evidence and coverage boundaries; reconcile the declared and
> observed relationship graphs; then explain the blast radius of a resource or
> destructive Terraform plan without applying anything.

That makes it most useful in the gap between **"Terraform says this should
exist"** and **"what is actually connected to it right now?"**

The closest alternatives are complementary rather than interchangeable:

- **Terraform plan** is the authority for intended IaC change, not a live
  relationship/evidence database.
- **AWS Config** is stronger for continuous AWS configuration history and
  compliance, but requires an AWS Config deployment and does not model this
  repository's Terraform-versus-observation conclusions.
- **Steampipe** and **CloudQuery** are stronger general-purpose query/sync
  foundations; they require the operator to define the joins, evidence rules,
  and impact interpretation.
- **Cartography** is much broader as a multi-platform graph; it requires Neo4j
  and is oriented toward graph exploration and security analysis rather than a
  local Terraform reconciliation workflow.
- **Scout Suite** and **Prowler** are stronger security posture/compliance
  scanners; they answer security-control questions, not whether a specific
  live dependency is absent from Terraform.
- **Infracost** is the right tool for cost change review; it does not answer
  runtime dependency or blast-radius questions.

## What `reality` actually does today

The comparison below treats the current implementation as the contract:

| Area | Current behavior |
|---|---|
| Local input | Parses user-exported `terraform show -json` state/plan files; never invokes Terraform |
| Cloud input | AWS is explicit opt-in with `--aws --profile PROFILE --region REGION`; selected read-only adapters cover EC2 instances/security groups, Lambda, RDS, S3 bucket names, IAM role policies, and bounded CloudTrail management events |
| Persistence | Stores resources, relationships, evidence, coverage, identity mappings, and findings in local SQLite |
| Identity | Keeps Terraform and AWS namespaces separate; joins only through explicit identity evidence; does not name-match |
| Reconciliation | Produces `confirmed`, `undocumented`, `possible`, `declared_only`, and `unknown` conclusions |
| Impact | Reverse-traverses declared/observed dependents; excludes IAM permission-only edges from runtime dependents |
| Simulation | Reads destructive targets from an exported Terraform plan and reports each target's stored blast radius; never applies the plan |
| Explainability | `why` shows relationships, evidence, findings, and coverage limits; output supports text, table, JSON, YAML, and CSV where applicable |
| Safety | No mutating AWS calls, no Terraform subprocess, no automatic remediation, and no implicit AWS access |
| Offline path | Local Terraform scan, reconciliation, reports, graph export, and simulation work without AWS credentials |

## Scenario 1 — “What will this Terraform change do before the apply?”

### Situation

A pull request replaces a database or security group. The reviewer wants to
know which currently known dependents may be affected, and the CI job must fail
without applying anything.

### How the tools behave

| Tool | Result in this scenario |
|---|---|
| **`reality`** | `simulate PLAN_JSON` selects delete/replace targets from the exported plan, resolves them against the local evidence store, reverse-traverses dependents, prints paths and conclusions, and supports `--fail-on` exit policy. It can say `unknown` when the stored coverage cannot answer the question. |
| **Terraform plan** | Calculates the proposed resource actions and dependency ordering from Terraform configuration/state/provider refresh behavior. It is the best source for “what Terraform intends to change,” but it does not by itself explain undocumented runtime attachments discovered outside the configuration. |
| **AWS Config** | Can show related AWS resources and historical configuration when Config recording is already enabled. It is not a Terraform plan evaluator and does not select Terraform delete/replace targets. |
| **Steampipe** | Can query current AWS and other APIs with SQL. The operator must write the query joining plan targets to cloud dependents and decide how missing data should affect a gate. |
| **CloudQuery** | Can sync cloud data to a destination and query it. The operator must build the plan-to-inventory join and the CI policy. |
| **Cartography** | Can answer graph reachability questions after its graph is populated. It needs Neo4j and a graph query; it does not natively use this project’s Terraform-plan target and evidence semantics. |
| **Scout Suite / Prowler** | May flag security posture issues related to a changed resource, but neither is primarily a dependency blast-radius simulator. |
| **Infracost** | Estimates cost deltas for IaC changes. It answers “what will this cost?” rather than “what runtime dependents may be affected?” |

### Best choice

Use **Terraform plan + `reality simulate`** together:

1. Terraform determines the intended action.
2. `reality` determines the evidence-backed impact of that action.
3. CI uses the report plus the exit code, while a reviewer gets the paths and
   evidence instead of only a red/green result.

### Product gap to close

The most valuable next improvement is a first-class CI input path that accepts
the exact plan artifact produced by the pipeline and emits a compact,
stable “target → dependent → evidence → coverage” result. The current command
already has the core behavior; the improvement is workflow ergonomics and
failure diagnostics, not a new risk score.

## Scenario 2 — “What exists in AWS that Terraform does not account for?”

### Situation

A live EC2 instance has a security-group attachment that is absent from the
Terraform state, or a Lambda uses a role that no declared resource accounts
for. The operator wants a defensible finding, not a name-based guess.

### How the tools behave

| Tool | Result in this scenario |
|---|---|
| **`reality`** | Reads selected AWS evidence, keeps it separate from Terraform declarations, joins only through exact identity mappings, and reports `undocumented` only when the observed relationship has no matching declaration and Terraform was actually consulted. Missing source coverage remains visible as `unknown`. |
| **Terraform plan** | Shows differences relevant to Terraform’s configuration/state and provider refresh. It is not a general detector for every relationship that exists outside the Terraform model. |
| **AWS Config** | Provides AWS resource configuration, relationships, and history for recorded resource types. It is strong for AWS-side drift/history, but it does not inherently know which relationships are intentionally represented by a particular Terraform repository. |
| **Steampipe** | Makes current AWS data easy to inspect and join with custom SQL. The user must supply Terraform data, identity rules, and the definition of “unaccounted for.” |
| **CloudQuery** | Builds a durable, queryable inventory and can support custom reconciliation. It is broader and more operationally involved; the reconciliation policy is not the narrow built-in contract of `reality`. |
| **Cartography** | Builds a broad relationship graph across cloud, identity, code, and security systems. It is stronger for cross-system graph questions, but requires graph infrastructure and does not make Terraform coverage semantics the center of the workflow. |
| **Scout Suite / Prowler** | Focus on insecure or noncompliant configurations. An undocumented but secure relationship may not be a finding for either tool. |
| **Infracost** | Does not answer this question. |

### Best choice

Use **`reality`** when the question is specifically **declared-versus-observed
relationship drift** and the operator needs to know why a conclusion was
reached. Use AWS Config, Steampipe, CloudQuery, or Cartography when the
question is broader AWS inventory or cross-platform discovery.

### Important limitation

`reality` is not a complete AWS inventory. Absence from its report means only
that the selected adapters did not produce that fact; it does not prove that
the resource or relationship is absent from AWS. A production deployment
should make the selected source coverage visible in the report and should not
turn partial collection into a “clean” result.

## Scenario 3 — “Can I investigate an incident offline after collection?”

### Situation

Credentials are unavailable or must be revoked. An engineer has a local
database and wants to answer why a resource exists, what depends on it, and
which evidence supports each statement.

### How the tools behave

| Tool | Result in this scenario |
|---|---|
| **`reality`** | `why`, `impact`, `graph`, and reconciliation reports read the local SQLite snapshot. The local-only path is deterministic and preserves raw evidence locators plus coverage limits. No AWS call is needed for these commands. |
| **Terraform plan** | A saved plan can be inspected, but it is not a general evidence store for AWS observations, CloudTrail findings, or a historical relationship report. |
| **AWS Config** | Historical investigation is strong if Config was enabled beforehand and its data remains available. It is a managed AWS service rather than a self-contained local snapshot. |
| **Steampipe** | Export CLIs and snapshots can support offline use, but the normal query model is live API access or a configured database/FDW. |
| **CloudQuery** | A persisted destination can support offline SQL analysis; setup and storage are heavier than a single SQLite file. |
| **Cartography** | The Neo4j graph supports exploration and path queries after synchronization. It requires the graph database and its retained data. |
| **Scout Suite** | Explicitly supports offline use after collection through its generated report, with a security-audit orientation. |
| **Prowler** | Produces security/compliance findings and exports, but the offline question is centered on checks rather than evidence-backed Terraform relationship reconciliation. |
| **Infracost** | A local IaC cost estimate can be reviewed, but it does not retain cloud dependency evidence. |

### Best choice

Use **`reality`** for a small, inspectable, local evidence package where every
conclusion must retain its coverage boundary. Use Scout Suite/Prowler for
offline security findings and AWS Config for managed historical configuration
history.

## Scenario 4 — “Which identities can reach a datastore?”

### Situation

Security or platform engineering wants a cross-account, multi-cloud graph of
users, roles, workloads, networks, datastores, vulnerabilities, and access
paths.

### How the tools behave

| Tool | Result in this scenario |
|---|---|
| **`reality`** | Covers a narrow AWS relationship slice and distinguishes runtime observations from IAM permission candidates. It is useful for a focused Terraform/AWS question, not a full attack-path graph. |
| **Cartography** | The strongest fit among this comparison set: it pulls assets and relationships from AWS, GCP, Azure, Kubernetes, GitHub, identity systems, and many other platforms into Neo4j, then supports graph queries and rules. |
| **Steampipe** | Strong for ad-hoc SQL across many APIs and accounts/regions. The user composes the graph logic rather than receiving one opinionated dependency model. |
| **CloudQuery** | Strong for broad normalized inventory, history/snapshots, and SQL destinations. It is a data pipeline first; graph semantics and path interpretation are user-defined. |
| **AWS Config** | Strong inside AWS for recorded resource configurations and relationships, but not a cross-provider identity graph. |
| **Scout Suite / Prowler** | Stronger for security posture checks than relationship-path exploration. Prowler has broad provider/compliance coverage; neither is a general dependency graph database. |

### Best choice

Use **Cartography** for broad attack-path and cross-platform graph analysis,
**Steampipe/CloudQuery** for queryable inventory, and **`reality`** when the
important boundary is “what does this Terraform-controlled AWS relationship
actually prove?”

## Scenario 5 — “Which cloud settings violate security/compliance policy?”

### Situation

A security team wants CIS-style checks, compliance frameworks, findings,
remediation guidance, and scans across many accounts or providers.

### How the tools behave

| Tool | Result in this scenario |
|---|---|
| **`reality`** | Not the right primary tool. It reports relationship conclusions and coverage, not a catalog of security controls or compliance frameworks. |
| **Prowler** | Strongest fit here: a CLI security platform with thousands of checks, compliance frameworks, multiple cloud providers, and export/integration options. |
| **Scout Suite** | Strong fit for a point-in-time, multi-cloud security posture assessment and an HTML report that can be reviewed offline after collection. |
| **AWS Config** | Strong for continuously recording AWS configuration and evaluating AWS Config rules over time. |
| **Steampipe** | Strong if the team prefers SQL-based controls and custom queries; controls and reporting are assembled by the operator or a related benchmark framework. |
| **CloudQuery** | Strong if checks should run over a durable normalized inventory and feed downstream data systems. |
| **Cartography** | Strong when a security finding depends on graph relationships or attack paths rather than a single configuration control. |

### Best choice

Use **Prowler or Scout Suite** for security posture/compliance, optionally
enriching investigation with **Cartography** or **Steampipe**. Do not position
`reality` as a replacement for those scanners; position it as the
declared-versus-observed dependency and blast-radius companion.

## Scenario 6 — “Will this IaC change increase monthly cost?”

### Situation

A pull request changes instance types, database capacity, or the number of
resources. The reviewer needs a cost delta and a CI budget gate.

### How the tools behave

| Tool | Result in this scenario |
|---|---|
| **`reality`** | Does not estimate prices or budgets. It can simulate dependency impact for the same plan artifact. |
| **Infracost** | Strongest fit: parses Terraform, CloudFormation, or CDK, estimates costs, reports changes in pull requests, and supports cost-aware workflows. |
| **Terraform plan** | Identifies planned resource changes but does not provide a complete price estimate by itself. |
| **AWS Config / Steampipe / CloudQuery / Cartography** | Can provide inputs for custom cost analysis, but cost estimation is not their primary workflow. |
| **Prowler / Scout Suite** | May find cost-related security or configuration concerns, but are not cost-delta engines. |

### Best choice

Use **Infracost** for financial impact and **`reality simulate`** for
dependency impact. These are complementary gates, not competing outputs.

## Scenario 7 — “Can the tool safely run in a developer laptop or CI worker?”

### Situation

The team wants a tool that cannot accidentally apply infrastructure, silently
contact AWS, or hide incomplete collection behind a green result.

| Tool | Safety and operational profile |
|---|---|
| **`reality`** | Local-first SQLite; AWS requires explicit opt-in, profile, and region; no mutating AWS calls; no Terraform subprocess; read-only commands do not migrate or write; coverage is part of the answer; `--fail-on` is policy-only and still prints the report. |
| **Terraform plan** | Read-oriented planning, but provider refresh and state/config behavior still require careful credential and backend handling. It is not a replacement for a local evidence database. |
| **AWS Config** | Managed AWS service with setup, IAM, S3/SNS, recording, and ongoing account cost/operations. |
| **Steampipe** | Direct API querying is powerful but can contact many services/accounts; credential and query scoping are operator responsibilities. |
| **CloudQuery** | Sync jobs and destinations require credential, scheduling, storage, and retention decisions. |
| **Cartography** | Requires a graph database and broad source credentials; the graph can be powerful but has a larger operational footprint. |
| **Scout Suite / Prowler** | Read-only audit orientation, but broad scans can make many API calls and require carefully scoped credentials. |
| **Infracost** | Does not change cloud resources, but may use a pricing API depending on workflow and configuration. |

### Best choice

For a constrained, auditable local/CI check, **`reality`** has the clearest
small-surface safety model. For continuous organization-wide controls, managed
services and broader scanners trade that small surface for coverage and
centralization.

## Scenario 8 — “What should a platform team adopt as its primary system?”

| Primary question | Best-fit tool | Why |
|---|---|---|
| What will Terraform change? | Terraform plan | It is the IaC planner and source of intended actions |
| What live relationship is missing from Terraform? | `reality` | Evidence-backed reconciliation with explicit identity and coverage semantics |
| What AWS configuration changed over time? | AWS Config | Managed configuration history and rule evaluation |
| How do I query many live APIs with SQL? | Steampipe | Direct relational access to APIs and plugins |
| How do I sync broad cloud inventory into data systems? | CloudQuery | Code-first sync and durable destinations |
| How do I navigate cross-platform identity and attack paths? | Cartography | Broad relationship graph backed by Neo4j |
| Which security controls fail? | Prowler or Scout Suite | Security posture and compliance-oriented checks/reports |
| What will the change cost? | Infracost | IaC cost estimation and PR budget workflows |

The strongest platform is usually a **stack**, not one CLI:

```text
Terraform plan
       +-- Infracost ------------------> financial gate
       +-- reality simulate ------------> dependency/blast-radius gate
       +-- reality reconcile ------------> declared-vs-observed drift
       +-- Prowler / Scout Suite --------> security/compliance controls
       +-- AWS Config -------------------> continuous AWS history/rules
       +-- Cartography or Steampipe -----> broad graph/query investigation
```

## Differentiation that should remain non-negotiable

To make `reality` best at its chosen job, preserve these distinctions:

1. **Evidence is not a conclusion.** Never turn an uncollected source into
   “no dependency.”
2. **Authorization is not usage.** IAM permission candidates should remain
   distinct from observed runtime relationships.
3. **Identity is not a name.** Do not silently join Terraform and AWS resources
   by display name or tag.
4. **A plan is not reality.** Terraform intent and live observation must stay
   separate until explicit evidence joins them.
5. **A risk gate is not a risk score.** Exit thresholds should encode an
   operator policy over a report, not fabricated likelihood or business impact.
6. **Read-only means more than “usually no writes.”** Keep the explicit AWS
   opt-in and local-only paths testable.

## Highest-value improvements suggested by the comparison

These are scenario-driven priorities, in order:

1. **CI artifact ergonomics:** make `simulate` easy to consume from standard
   Terraform plan artifacts, with stable machine-readable target/dependent/
   evidence/coverage records and clear exit-policy documentation.
2. **Coverage expansion by relationship family:** add sources only when their
   completeness can be represented honestly; do not grow a resource inventory
   without corresponding relationship and coverage semantics.
3. **Review workflow:** add a concise report mode for pull requests that shows
   only changed targets, newly undocumented relationships, unresolved
   identities, and unavailable sources, with links back to full local evidence.
4. **Interoperability:** support importing or linking to AWS Config, Steampipe,
   CloudQuery, or Cartography exports rather than reimplementing their broad
   inventories.
5. **Explicit scope profiles:** offer documented “local Terraform only,”
   “AWS reconciliation,” and “plan impact” profiles so users know exactly
   which question a run can answer.
6. **Do not chase every competitor feature:** security checks, cost pricing,
   multi-cloud inventory, and graph database hosting are better integrations
   than an expansion of the core safety/evidence model.

## Sources

Official or primary documentation consulted on 2026-10-20:

- [Terraform `plan` command](https://developer.hashicorp.com/terraform/cli/commands/plan)
- [AWS Config overview and use cases](https://docs.aws.amazon.com/config/latest/developerguide/WhatIsConfig.html)
- [Steampipe documentation](https://steampipe.io/docs)
- [CloudQuery CLI introduction](https://www.cloudquery.io/docs/cli/introduction)
- [Cartography project README](https://github.com/cartography-cncf/cartography#readme)
- [Scout Suite project README](https://github.com/nccgroup/ScoutSuite#readme)
- [Prowler documentation](https://docs.prowler.com/)
- [Infracost documentation](https://www.infracost.io/docs/)

## Practical recommendation

If the question is **“can this proposed destructive change affect a live
dependency that Terraform does not fully explain?”**, start with:

```text
terraform show -json
        -> reality scan
        -> reality reconcile
        -> reality simulate plan.json
        -> CI gate + evidence-bearing report
```

If the question is instead **security compliance, broad inventory, graph
exploration, or cost**, invoke the specialist tool for that scenario and use
`reality` as the focused reconciliation/impact layer.
