# AWS collection scope

`reality scan` can optionally collect a limited AWS snapshot. AWS access is never implicit: the caller must opt in with `--aws`, an explicit profile, and an explicit region. The adapters make read-only API calls; they do not create, update, or delete AWS resources.

This is a project-specific discovery slice, not a full AWS inventory. A resource or relationship not returned by these calls is not necessarily absent from the account.

## Calls made today

| Adapter         | AWS calls                                                  | What is retained                                                                                                                                                                                                           |
| --------------- | ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Caller identity | STS `GetCallerIdentity`                                    | Account and principal context. Failure stops AWS collection because resources cannot safely be attributed.                                                                                                                 |
| AWS resources   | EC2 `DescribeInstances`, EC2 `DescribeSecurityGroups`      | EC2 instances, security groups, and instance-to-security-group attachments.                                                                                                                                                |
| AWS resources   | Lambda `ListFunctions`                                     | Lambda functions and the configured execution role (`uses_role`). This identifies configuration, not whether the function has run.                                                                                         |
| AWS resources   | RDS `DescribeDBInstances`                                  | RDS DB instances and attached VPC security groups.                                                                                                                                                                         |
| AWS resources   | S3 `ListBuckets`                                           | Bucket names only. It does not inspect bucket policies, ACLs, object contents, or data access.                                                                                                                             |
| IAM             | IAM role and attached/inline policy listing and retrieval  | Role resources and policy statements. Allow statements may produce `permission_on` candidates; they do not prove a role used the permission. Deny statements are retained as evidence but not emitted as allow candidates. |
| CloudTrail      | `LookupEvents` over the caller-supplied start/end interval | Parsed management events where actor and resource target can be resolved. These are bounded observations, not a complete usage history.                                                                                    |

The AWS resource adapter scans the selected region for regional services. S3 bucket listing and IAM are global-service operations; the selected region is still retained as scan context. One invocation is not a multi-region account scan.

## Relationship meanings

- `attached_to`: a returned EC2/RDS field names a security group.
- `uses_role`: a Lambda configuration names its execution role.
- `permission_on`: an IAM allow policy names a resource. This is authorization scope, not observed usage.
- `depends_on`: Terraform or a supported CloudTrail event supplied a dependency candidate, with provenance identifying which one.
- `references`: a supported Terraform field or declaration points at another identity.

Direction is meaningful: `source -> target` describes the resource with the field/claim and the resource it names. Evidence preserves the raw reference, canonical identities where resolvable, the source operation or file locator, and a plain-language explanation.

Reconciliation compares candidates only when their canonical source, target, and relationship type match (including exact-identifier mappings between Terraform and AWS identities). Similar names do not join. IAM permission candidates without observed use become `possible`, not `confirmed` dependencies. Impact analysis excludes IAM-policy-only edges from runtime dependents.

## Coverage and failure behavior

Expected AWS access, throttling, and service failures are represented as unavailable coverage so other adapters can continue. A failed service collector discards its partial results rather than publishing an incomplete page sequence as a complete observation. Unexpected errors still surface.

Coverage is essential context: an unavailable or unrequested source cannot support a claim that no dependency exists. The adapters keep call-level records and a final completeness record; any failed sub-call marks that adapter incomplete so a successful call cannot mask a gap. This all-or-nothing rule is conservative because evidence-source labels are still broad. A future refinement should connect each relationship family to the exact service capabilities that can reveal it.

## Important limitations

- The supported resource types and relationship fields are intentionally limited.
- No VPC/subnet/route-table topology, security-group ingress/egress rules, S3 policy inspection, or general service discovery is implemented by these calls.
- CloudTrail `LookupEvents` is not a data-plane log service. It cannot establish complete S3 object or other data-plane access, and an event outside the selected interval is invisible.
- A configured role, an IAM grant, and an observed API call are different facts; reports must not collapse them into “the workload depends on this resource.”
- The `high` / `medium` / `low` impact bands are rule-based review hints, not calibrated risk, probability, or business impact.

Use the offline demo and tests to understand the supported paths. Live AWS testing should use a dedicated least-privilege profile and a deliberately selected region; never infer that read-only means complete or risk-free.
