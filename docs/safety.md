# Safety contract

`reality` is a **read-only discovery and local simulation** tool. Its value
depends on it being safe to run anywhere, against any account, at any time.
This document is the hard boundary. Every phase of development must keep it
true, and any change that weakens it is out of scope by definition.

## Hard boundary

1. **No mutating AWS API calls.** Nothing in this code base may call an AWS
   write API — no create, modify, delete, tag, put, or attach operation, and
   no control-plane action that alters state. AWS access, when explicitly
   selected, is limited to read/describe/list/get-style calls.

2. **No Terraform subprocess execution.** The tool never invokes the
   `terraform` executable, in any mode. Not `apply`, not `destroy`, not
   `refresh`, not `init`, not `plan`. Terraform input is accepted only as
   already-exported JSON files produced by the user running
   `terraform show -json` themselves.

3. **No plan apply.** `reality simulate` calculates and reports blast radius
   from an exported plan JSON. It never applies, partially applies,
   auto-approves, or proposes automatic deletion. There is no action engine.

4. **No credentials written to disk.** Credentials live in the environment,
   the AWS shared credentials file, or a named profile the user supplies —
   never in this project's files, database, logs, or reports. The local
   SQLite database stores discovery results only.

## How the boundary is enforced

- **AWS is strictly opt-in.** No AWS adapter can run unless the user
  explicitly passes `--aws --profile PROFILE --region REGION`. There is no
  default region and no default profile anywhere in the code; a partial
  selection is rejected with an error, not completed with guesses.
- **`boto3` stays optional.** It is an extra (`pip install reality[aws]`)
  and is imported only inside AWS adapters, never at package import time.
- **Operation whitelists.** Each AWS adapter declares
  `ALLOWED_OPERATIONS` — the complete set of operations it may ever invoke —
  and every entry is a read/describe/list/get-style call. Tests assert that
  no scripted client ever receives an operation outside its adapter's
  whitelist, and an AST test asserts the adapter sources contain no mutating
  operation calls at all.
- **No subprocess anywhere.** The Terraform adapter parses JSON files; tests
  assert its source contains no subprocess usage, and a simulate test
  monkeypatches every `subprocess` entry point (and the `boto3`/`botocore`
  imports) to fail loudly — a simulation completes only if it contacted
  nothing.
- **Evidence is not a conclusion.** Missing data (for example, no CloudTrail
  history) is recorded as `UNKNOWN` coverage — never interpreted as "no
  dependency."
- **Simulation is local arithmetic.** It reads a plan JSON file that already
  exists on disk and computes consequences; it contacts nothing.
- **Read-only commands cannot write.** `why`, `impact`, and `simulate` open
  the database without running migrations; a missing database file is an
  error (exit 5, "run reality scan first"), never silently created. A test
  asserts every table count is unchanged after a simulation.
- **`reconcile` writes locally, and only locally.** It is the one command
  besides `scan` that opens the database for writing: it stores its findings
  and runs schema migrations on an existing database. That is arithmetic over
  rows already in the file — it contacts no API, and the set of operations it
  can invoke is unchanged. A missing database is still an error, because
  reconciling nothing would be a vacuous success.
- **Optional dependencies are imported lazily, never at module scope.**
  `boto3` is confined to the AWS adapters and `rich` to the `--output table`
  renderers. Importing either at module scope would put it in the chain of
  *every* command, so a plain install without the extra could not run `why` at
  all. A test simulates a missing `rich` and asserts the CLI still works and
  that `table` fails with an actionable message, not a traceback.

## Data retention and secrets

- The SQLite database stores discovery results only: identities, relationship
  candidates, evidence records (each with a locator back into its source),
  coverage records, and reconciliation findings.
- Credentials are never written to disk by this tool. They live in the
  environment, the AWS shared credentials file, or the named profile the user
  supplies; only the profile *name* appears (in coverage reasons).
- Adapters extract only non-secret metadata (a `Name` tag, a function or
  database identifier). The test fixtures deliberately contain
  secret-shaped values — Lambda environment variables, an RDS
  master-credential field — and tests assert those values never appear in
  any adapter result or persisted row.
- Deleting the database file deletes everything the tool has ever recorded.
  There is no telemetry, no secondary cache, and no other output location.

## What this tool will never do

- Apply, destroy, refresh, or import Terraform state
- Create, modify, or delete any cloud resource
- Execute shell commands that initialize, refresh, or alter infrastructure
- Store credentials or secrets
- Treat absent evidence as proof of absence
