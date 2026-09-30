# Live AWS smoke test

The one test this project has never had. Every other test uses recorded
fixtures or `botocore` stubs; this points the real adapters at a real AWS
account, so it is the first time the AWS code path meets real API responses.

It is **strictly read-only**. The adapters whitelist only List/Get/Describe
operations, and the script asserts that whitelist before trusting anything.

## Run it

```bat
python ManualTests\aws-live\run_live_test.py --profile deepanshu
```

Add `--with-state path\to\state.json` to also parse a Terraform state export,
so `reconcile` has both worlds to compare:

```bat
python ManualTests\aws-live\run_live_test.py --profile deepanshu --with-state ManualTests\fake-terraform-state.json
```

## What it checks

1. The operation whitelist contains no mutating call.
2. STS `GetCallerIdentity` resolves the account.
3. `scan --aws` exits 0.
4. `reconcile` exits 0 and produces findings.
5. `why` and `impact` work on a real ARN.
6. All five output formats render.
7. `--fail-on high` returns 0 or 6.
8. Rows actually landed in the database.

## Notes

- Everything writes to `live.db` in this folder. Delete it to start over.
- The CloudTrail window is bounded to **one day** to limit cost and calls.
- Nothing here touches Terraform, and no plan is ever applied.
- Requires the `aws` extra: `pip install -e ".[aws]"`.
