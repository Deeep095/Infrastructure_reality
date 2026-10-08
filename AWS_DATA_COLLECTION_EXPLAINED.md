# How Infrastructure Reality Scrapes AWS Data

This document explains exactly how the project collects data from AWS, CloudTrail, and IAM.

---

## 🏗️ Architecture Overview

The project uses **adapter pattern** with three separate adapters:
1. **AWS Resources Adapter** (`aws_resources.py`) - EC2, Lambda, RDS, S3, Security Groups
2. **IAM Adapter** (`iam.py`) - IAM roles and their permissions
3. **CloudTrail Adapter** (`cloudtrail.py`) - Historical usage events

Each adapter is **completely independent** and can fail without affecting others.

---

## 📦 1. AWS Resources Adapter (`aws_resources.py`)

### Entry Point: `collect()` method

```python
# Lines 228-262
def collect(self) -> AdapterResult:
    """Main entry point - orchestrates all AWS API calls"""
    
    # Step 1: Get AWS account identity (who am I?)
    account, principal = self._caller_identity()  # STS GetCallerIdentity
    scan_at = datetime.now(UTC)
    
    # Step 2: Scan each AWS service independently
    for label, run in (
        ("ec2 DescribeInstances", self._scan_instances),
        ("ec2 DescribeSecurityGroups", self._scan_security_groups),
        ("lambda ListFunctions", self._scan_functions),
        ("rds DescribeDBInstances", self._scan_db_instances),
        ("s3 ListBuckets", self._scan_buckets),
    ):
        outcome = self._isolated(label, run, account, principal, scan_at)
        resources.extend(outcome.resources)
        relationships.extend(outcome.relationships)
        evidence.extend(outcome.evidence)
        coverage.append(outcome.coverage)
    
    return AdapterResult(...)
```

**Key Design**: Each service is wrapped in `_isolated()` so if one fails (AccessDenied), others continue.

---

### Step 1: Get AWS Account Identity

```python
# Lines 300-322
def _caller_identity(self) -> tuple[str, str]:
    """Call STS GetCallerIdentity to get account number"""
    try:
        response = self._client_factory("sts").get_caller_identity()
    except Exception as err:
        # This is FATAL - without account ID, we can't attribute anything
        raise AdapterError(
            f"sts GetCallerIdentity failed: no account context"
        ) from err
    
    account = response.get("Account")  # "123456789012"
    principal = response.get("Arn")     # "arn:aws:iam::123456789012:user/dev"
    
    if not account:
        raise AdapterError("sts GetCallerIdentity returned no account")
    
    return account, principal
```

**Why this matters**: Every resource needs an account ID in its canonical ID. If STS fails, the entire scan stops.

**API Call**:
```json
{
  "Account": "123456789012",
  "UserId": "AIDAI123456789EXAMPLE",
  "Arn": "arn:aws:iam::123456789012:user/deepanshu"
}
```

---

### Step 2: Scan EC2 Instances

```python
# Lines 326-381
def _scan_instances(self, account: str, principal: str, scan_at: datetime) -> _Outcome:
    """Scan all EC2 instances in the region"""
    client = self._client_factory("ec2")
    resources: list[Resource] = []
    relationships: list[Relationship] = []
    evidence: list[Evidence] = []
    
    # Pagination: handle large AWS accounts
    for page in _paginate(client.describe_instances, "NextToken", "NextToken"):
        reservations = page.get("Reservations") or []
        
        for res_index, reservation in enumerate(reservations):
            for inst_index, raw in enumerate(reservation.get("Instances") or []):
                # Track exactly where this data came from
                locator = f"ec2:DescribeInstances#Reservations[{res_index}].Instances[{inst_index}]"
                
                # Extract instance ID (required)
                instance_id = _string(raw, "InstanceId", locator)  # "i-0abc123"
                
                # Build canonical ID: aws/ec2/instance/eu-west-1/123456789012/i-0abc123
                canonical = canonical_from_native(
                    "ec2", "instance", instance_id, 
                    region=self._region, 
                    account=account
                )
                
                # Create Resource record
                resources.append(Resource(
                    canonical_id=canonical.key,
                    resource_type=ResourceType.EC2_INSTANCE,
                    provider=canonical.provider,
                    native_id=instance_id,
                    region=self._region,
                    account=account,
                    name=_name_tag(raw.get("Tags")),  # Extract "Name" tag
                    discovered_at=scan_at,
                    source=EvidenceSource.AWS_RESOURCES,
                ))
                
                # Extract security groups attached to this instance
                for sg_index, sg in enumerate(raw.get("SecurityGroups") or []):
                    sg_locator = f"{locator}.SecurityGroups[{sg_index}]"
                    group_id = _string(sg, "GroupId", sg_locator)  # "sg-0abc123"
                    
                    target = canonical_from_native(
                        "ec2", "security-group", group_id,
                        region=self._region, account=account
                    )
                    
                    # Create relationship: instance -> security group
                    self._link(
                        source=canonical,
                        target=target,
                        relationship_type=RelationshipType.ATTACHED_TO,
                        service="ec2",
                        operation="DescribeInstances",
                        attribute="SecurityGroups",
                        locator=sg_locator,
                        principal=principal,
                        scan_at=scan_at,
                        relationships=relationships,
                        evidence=evidence,
                    )
    
    return _Outcome(resources, relationships, evidence, coverage)
```

**Real AWS API Response** (simplified):
```json
{
  "Reservations": [
    {
      "Instances": [
        {
          "InstanceId": "i-0abc123",
          "InstanceType": "t3.micro",
          "State": {"Name": "running"},
          "SecurityGroups": [
            {"GroupId": "sg-0aaa111", "GroupName": "web-sg"},
            {"GroupId": "sg-0bbb222", "GroupName": "ssh-sg"}
          ],
          "Tags": [
            {"Key": "Name", "Value": "web-server"}
          ]
        }
      ]
    }
  ]
}
```

**What Gets Stored**:
1. **Resource**: `aws/ec2/instance/eu-west-1/123456789012/i-0abc123`
2. **Relationships**: 
   - `i-0abc123` → `sg-0aaa111` (ATTACHED_TO)
   - `i-0abc123` → `sg-0bbb222` (ATTACHED_TO)
3. **Evidence**: Each relationship has evidence pointing to the exact API response location

---

### Pagination Helper

```python
# Lines 161-172
def _paginate(operation: Callable, request_key: str, response_key: str) -> Iterator:
    """Generic pagination for AWS APIs with NextToken pattern"""
    params: dict[str, Any] = {}
    
    while True:
        page = operation(**params)  # Call AWS API
        yield page
        
        token = page.get(response_key)  # Check for NextToken
        if not token:
            return  # No more pages
        
        params[request_key] = token  # Use token for next request
```

**Why this matters**: Large AWS accounts might have 1000+ instances. Pagination ensures we get them all.

---

### Step 3: Scan Lambda Functions

```python
# Lines 416-471
def _scan_functions(self, account: str, principal: str, scan_at: datetime) -> _Outcome:
    """Scan all Lambda functions"""
    client = self._client_factory("lambda")
    
    for page in _paginate(client.list_functions, "Marker", "NextMarker"):
        functions = page.get("Functions") or []
        
        for fn_index, raw in enumerate(functions):
            locator = f"lambda:ListFunctions#Functions[{fn_index}]"
            
            function_name = _string(raw, "FunctionName", locator)
            function_arn = _string(raw, "FunctionArn", locator)
            
            # Create Lambda function resource
            canonical = self._canonical_from_arn(
                function_arn, "lambda", "function", function_name, account
            )
            
            resources.append(Resource(...))
            
            # Extract IAM role (Lambda execution role)
            role = raw.get("Role")  # "arn:aws:iam::123456789012:role/lambda-exec"
            if isinstance(role, str) and role:
                try:
                    target = parse_arn(role)  # Parse IAM role ARN
                except IdParseError:
                    target = unresolved(role)  # Can't parse? Mark unresolved
                
                # Create relationship: function -> IAM role
                self._link(
                    source=canonical,
                    target=target,
                    relationship_type=RelationshipType.PERMISSION_ON,
                    service="lambda",
                    operation="ListFunctions",
                    attribute="Role",
                    ...
                )
```

**Real AWS API Response**:
```json
{
  "Functions": [
    {
      "FunctionName": "data-processor",
      "FunctionArn": "arn:aws:lambda:eu-west-1:123456789012:function:data-processor",
      "Runtime": "python3.11",
      "Role": "arn:aws:iam::123456789012:role/lambda-execution-role",
      "Handler": "index.handler",
      "MemorySize": 128
    }
  ]
}
```

**What Gets Stored**:
- **Resource**: `aws/lambda/function/eu-west-1/123456789012/data-processor`
- **Relationship**: `data-processor` → `lambda-execution-role` (PERMISSION_ON)

---

### Step 4: Scan RDS Databases

```python
# Lines 473-525
def _scan_db_instances(self, account: str, principal: str, scan_at: datetime) -> _Outcome:
    """Scan all RDS database instances"""
    client = self._client_factory("rds")
    
    for page in _paginate(client.describe_db_instances, "Marker", "Marker"):
        databases = page.get("DBInstances") or []
        
        for db_index, raw in enumerate(databases):
            locator = f"rds:DescribeDBInstances#DBInstances[{db_index}]"
            
            identifier = _string(raw, "DBInstanceIdentifier", locator)
            db_arn = _string(raw, "DBInstanceArn", locator)
            
            # Create RDS resource
            resources.append(Resource(...))
            
            # Extract VPC security groups attached to DB
            for sg_index, sg in enumerate(raw.get("VpcSecurityGroups") or []):
                group_id = _string(sg, "VpcSecurityGroupId", sg_locator)
                
                target = canonical_from_native(
                    "ec2", "security-group", group_id,
                    region=self._region, account=account
                )
                
                # Create relationship: database -> security group
                self._link(
                    source=canonical,
                    target=target,
                    relationship_type=RelationshipType.ATTACHED_TO,
                    service="rds",
                    operation="DescribeDBInstances",
                    attribute="VpcSecurityGroups",
                    ...
                )
```

**Real AWS API Response**:
```json
{
  "DBInstances": [
    {
      "DBInstanceIdentifier": "production-db",
      "DBInstanceArn": "arn:aws:rds:eu-west-1:123456789012:db:production-db",
      "Engine": "postgres",
      "DBInstanceClass": "db.t3.micro",
      "VpcSecurityGroups": [
        {"VpcSecurityGroupId": "sg-0ccc333", "Status": "active"}
      ]
    }
  ]
}
```

---

### Step 5: Scan S3 Buckets (Global Service)

```python
# Lines 527-569
def _scan_buckets(self, account: str, principal: str, scan_at: datetime) -> _Outcome:
    """Scan all S3 buckets (global service, no region)"""
    client = self._client_factory("s3")
    response = client.list_buckets()
    
    buckets = response.get("Buckets") or []
    for index, raw in enumerate(buckets):
        locator = f"s3:ListBuckets#Buckets[{index}]"
        bucket_name = _string(raw, "Name", locator)
        
        # IMPORTANT: S3 is GLOBAL - no region attached
        canonical = canonical_from_native(
            "s3", "bucket", bucket_name,
            region=None,  # <-- No region!
            account=account
        )
        
        resources.append(Resource(
            canonical_id=canonical.key,  # aws/s3/bucket/-/-/my-bucket
            resource_type=ResourceType.S3_BUCKET,
            native_id=bucket_name,
            region=None,  # <-- Global
            account=account,
            ...
        ))
```

**Real AWS API Response**:
```json
{
  "Buckets": [
    {
      "Name": "acme-customer-data",
      "CreationDate": "2024-01-15T10:30:00Z"
    },
    {
      "Name": "acme-logs",
      "CreationDate": "2024-02-20T14:20:00Z"
    }
  ]
}
```

---

### Creating Relationships with Evidence

```python
# Lines 592-642
def _link(
    self,
    source: CanonicalId,
    target: CanonicalId,
    relationship_type: RelationshipType,
    service: str,
    operation: str,
    attribute: str,
    locator: str,
    principal: str,
    scan_at: datetime,
    relationships: list[Relationship],
    evidence: list[Evidence],
) -> None:
    """Create a relationship AND its evidence record"""
    
    # Build evidence ID (unique identifier)
    evidence_id = (
        f"aws:{service}:{operation}:{source_ref}:"
        f"{relationship_type.value}:{attribute}:{target_ref}"
    )
    # Example: "aws:ec2:DescribeInstances:i-0abc123:attached_to:SecurityGroups:sg-0aaa111"
    
    # Create Evidence record (proves this relationship exists)
    evidence.append(Evidence(
        id=evidence_id,
        source=EvidenceSource.AWS_RESOURCES,
        type=EvidenceType.OBSERVED_ATTRIBUTE,
        observed_at=scan_at,
        actor=principal,
        source_ref=source_ref,
        target_ref=target_ref,
        source_canonical_id=source.key,
        target_canonical_id=target.key,
        strength=EvidenceStrength.HIGH,
        raw_locator=locator,
        explanation=(
            f"AWS {operation} directly reports '{attribute}' = {target_ref!r} "
            f"on {source_ref}"
        ),
    ))
    
    # Create Relationship record
    relationships.append(Relationship(
        source_canonical_id=source.key,
        target_canonical_id=target.key,
        type=relationship_type,
        origin=RelationshipOrigin.AWS_OBSERVED,
        evidence_ids=(evidence_id,),
    ))
```

**What this does**: Every relationship has **traceable evidence** back to the exact API response.

---

## 📜 2. CloudTrail Adapter (`cloudtrail.py`)

CloudTrail shows **historical usage** - who did what, when.

### Entry Point

```python
# Lines 300-400 (simplified)
def collect(self, start: datetime, end: datetime) -> AdapterResult:
    """Query CloudTrail for events in time window"""
    
    # Validate time window (max 90 days)
    if end - start > MAX_LOOKUP_WINDOW:
        raise AdapterError("CloudTrail window cannot exceed 90 days")
    
    client = self._client_factory("cloudtrail")
    events: list[Evidence] = []
    relationships: list[Relationship] = []
    
    # Paginate through CloudTrail events
    for page in _paginate_cloudtrail(client, start, end):
        for event_index, raw in enumerate(page.get("Events") or []):
            # Parse each event
            event_name = raw.get("EventName")
            event_time = raw.get("EventTime")
            username = raw.get("Username")
            
            # Extract embedded CloudTrailEvent JSON
            embedded = _parse_embedded(raw.get("CloudTrailEvent"))
            
            # Who did this? (the actor)
            actor_arn, actor_canonical, _ = _actor(raw, embedded)
            
            # What was affected? (the target)
            target_arns = _resources(raw, embedded)
            
            # Create evidence for each target
            for target_arn in target_arns:
                try:
                    target_canonical = parse_arn(target_arn)
                    
                    # Create relationship: actor -> target
                    relationships.append(Relationship(
                        source_canonical_id=actor_canonical.key,
                        target_canonical_id=target_canonical.key,
                        type=RelationshipType.DEPENDS_ON,
                        origin=RelationshipOrigin.CLOUDTRAIL,
                        evidence_ids=(evidence_id,),
                    ))
                except IdParseError:
                    # Can't parse ARN - skip but log as evidence
                    pass
```

### Real CloudTrail Event

```json
{
  "EventName": "GetObject",
  "EventTime": "2026-10-07T14:32:10Z",
  "Username": "lambda-execution-role",
  "CloudTrailEvent": "{
    \"eventVersion\": \"1.08\",
    \"userIdentity\": {
      \"type\": \"AssumedRole\",
      \"arn\": \"arn:aws:sts::123456789012:assumed-role/processor_role/session-1\"
    },
    \"eventName\": \"GetObject\",
    \"requestParameters\": {
      \"bucketName\": \"data-lake\",
      \"key\": \"input/data.json\"
    },
    \"resources\": [
      {
        \"type\": \"AWS::S3::Object\",
        \"ARN\": \"arn:aws:s3:::data-lake/input/data.json\"
      }
    ]
  }"
}
```

**What this means**: The `processor_role` IAM role accessed the `data-lake` S3 bucket.

**What gets stored**:
- **Relationship**: `processor_role` → `data-lake` (DEPENDS_ON)
- **Evidence**: CloudTrail event showing the GetObject call
- **Conclusion**: This proves runtime usage, not just IAM permission

---

### Normalizing Assumed Role Sessions

```python
# Lines 170-185
def _role_arn(principal_arn: str) -> str:
    """Convert session ARN to role ARN"""
    # Input:  "arn:aws:sts::123456789012:assumed-role/processor_role/session-1"
    # Output: "arn:aws:iam::123456789012:role/processor_role"
    
    parts = principal_arn.split(":", 5)
    if len(parts) != 6 or parts[2] != "sts":
        return principal_arn  # Not an assumed role
    
    base, _, session = parts[5].rpartition("/")
    if not base.startswith("assumed-role/"):
        return principal_arn
    
    # Extract role name from "assumed-role/processor_role"
    role_name = base[len('assumed-role/'):]
    
    # Rebuild as IAM role ARN
    return f"arn:{parts[1]}:iam::{parts[4]}:role/{role_name}"
```

**Why this matters**: CloudTrail reports sessions, but IAM adapter reports roles. This normalization lets them join.

---

## 🔐 3. IAM Adapter (`iam.py`)

IAM adapter scrapes **possible permissions** from policy documents.

### Entry Point

```python
# Lines 250-350 (simplified)
def collect(self) -> AdapterResult:
    """Scan all IAM roles and their permissions"""
    client = self._client_factory("iam")
    resources: list[Resource] = []
    relationships: list[Relationship] = []
    evidence: list[Evidence] = []
    
    # Step 1: List all IAM roles
    for page in _paginate(client.list_roles, "Marker", "Marker"):
        roles = page.get("Roles") or []
        
        for role_index, raw in enumerate(roles):
            role_name = _string(raw, "RoleName", locator)
            role_arn = _string(raw, "Arn", locator)
            
            # Create IAM role resource
            canonical = parse_arn(role_arn)
            resources.append(Resource(
                canonical_id=canonical.key,
                resource_type=ResourceType.IAM_ROLE,
                native_id=role_name,
                arn=role_arn,
                ...
            ))
            
            # Step 2: Get inline policies for this role
            inline_names = client.list_role_policies(RoleName=role_name)
            for policy_name in inline_names.get("PolicyNames", []):
                policy_doc = client.get_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )
                
                # Parse policy document
                self._parse_policy(
                    role_canonical=canonical,
                    policy_doc=policy_doc,
                    relationships=relationships,
                    evidence=evidence,
                )
            
            # Step 3: Get attached managed policies
            attached = client.list_attached_role_policies(RoleName=role_name)
            for policy in attached.get("AttachedPolicies", []):
                policy_arn = policy.get("PolicyArn")
                
                # Get policy document
                policy_obj = client.get_policy(PolicyArn=policy_arn)
                version_id = policy_obj["Policy"]["DefaultVersionId"]
                
                version_obj = client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=version_id
                )
                
                # Parse this policy too
                self._parse_policy(...)
```

### Parsing IAM Policy Documents

```python
# Lines 400-500 (simplified)
def _parse_policy(
    self,
    role_canonical: CanonicalId,
    policy_doc: dict,
    relationships: list[Relationship],
    evidence: list[Evidence],
) -> None:
    """Parse IAM policy and extract permissions"""
    
    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]  # Normalize to list
    
    for stmt_index, statement in enumerate(statements):
        effect = statement.get("Effect")  # "Allow" or "Deny"
        
        if effect != "Allow":
            continue  # Deny statements don't grant permissions
        
        actions = _string_list(statement.get("Action"))      # ["s3:GetObject"]
        resources = _string_list(statement.get("Resource"))  # ["arn:aws:s3:::bucket/*"]
        
        if not actions or not resources:
            continue  # Malformed statement
        
        # Create relationship for each action+resource pair
        for action in actions:
            for resource_arn in resources:
                try:
                    target = parse_arn(resource_arn)
                except IdParseError:
                    # Wildcard or variable - mark as unresolved
                    target = unresolved(resource_arn)
                
                # Create evidence
                evidence_id = (
                    f"iam:inline:{role_arn}:{policy_name}:"
                    f"{stmt_index}:{effect}:{action}:{resource_arn}"
                )
                
                evidence.append(Evidence(
                    id=evidence_id,
                    source=EvidenceSource.IAM,
                    type=EvidenceType.POLICY_STATEMENT,
                    strength=EvidenceStrength.MEDIUM,  # Possible, not proven
                    explanation=(
                        f"an IAM policy grants this permission and no usage was observed; "
                        f"data-plane usage is not visible, so this is POSSIBLE"
                    ),
                ))
                
                # Create relationship
                relationships.append(Relationship(
                    source_canonical_id=role_canonical.key,
                    target_canonical_id=target.key,
                    type=RelationshipType.PERMISSION_ON,
                    origin=RelationshipOrigin.IAM_POLICY,
                    evidence_ids=(evidence_id,),
                ))
```

### Example IAM Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::data-lake",
        "arn:aws:s3:::data-lake/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": "dynamodb:GetItem",
      "Resource": "arn:aws:dynamodb:eu-west-1:123456789012:table/processed-events"
    }
  ]
}
```

**What gets stored** (for role `processor_role`):
1. `processor_role` → `data-lake` (PERMISSION_ON) - s3:GetObject
2. `processor_role` → `data-lake` (PERMISSION_ON) - s3:ListBucket
3. `processor_role` → `data-lake/*` (PERMISSION_ON, unresolved wildcard)
4. `processor_role` → `processed-events` (PERMISSION_ON) - dynamodb:GetItem

**Conclusion**: These are **POSSIBLE** permissions until CloudTrail proves usage.

---

## 🔍 4. How Reconciliation Works

After all adapters run, reconciliation compares the evidence:

```python
# src/reality/services/reconcile.py (lines 251-294)
def _verdict(
    candidate: RelationshipCandidate,
    declared: set[EvidenceSource],  # Terraform
    observed: set[EvidenceSource],  # AWS, CloudTrail
    coverage: dict[EvidenceSource, CoverageStatus],
) -> Conclusion:
    """Determine conclusion from evidence"""
    
    has_declared = bool(declared)  # Terraform says it exists
    has_observed = bool(observed)  # AWS APIs say it exists
    
    # CASE 1: Both agree - CONFIRMED
    if has_declared and has_observed:
        return Conclusion.CONFIRMED
    
    # CASE 2: AWS sees it, Terraform doesn't - UNDOCUMENTED (drift!)
    if has_observed and not has_declared:
        if EvidenceSource.TERRAFORM_STATE in coverage:
            return Conclusion.UNDOCUMENTED
    
    # CASE 3: Terraform declares, AWS doesn't see - DECLARED_ONLY
    if has_declared and not has_observed:
        return Conclusion.DECLARED_ONLY
    
    # CASE 4: IAM policy allows but no usage - POSSIBLE
    if EvidenceSource.IAM in observed:
        return Conclusion.POSSIBLE
    
    # CASE 5: Missing coverage - UNKNOWN
    return Conclusion.UNKNOWN
```

---

## 📊 Complete Data Flow Example

Let's trace a real example: **EC2 instance with undocumented security group**

### 1. Terraform declares (from state file):
```json
{
  "address": "aws_instance.web",
  "values": {
    "id": "i-0web",
    "vpc_security_group_ids": ["sg-0aaa111"]
  }
}
```

### 2. AWS reports (from DescribeInstances):
```json
{
  "InstanceId": "i-0web",
  "SecurityGroups": [
    {"GroupId": "sg-0aaa111"},
    {"GroupId": "sg-0zzz999"}  // <-- NOT in Terraform!
  ]
}
```

### 3. Stored Evidence:
```
Resource: aws/ec2/instance/eu-west-1/123456789012/i-0web

Relationship 1:
  Source: aws/ec2/instance/eu-west-1/123456789012/i-0web
  Target: aws/ec2/security-group/eu-west-1/123456789012/sg-0aaa111
  Type: ATTACHED_TO
  Origin: AWS_OBSERVED
  Evidence: aws:ec2:DescribeInstances:i-0web:attached_to:SecurityGroups:sg-0aaa111

Relationship 2:
  Source: aws/ec2/instance/eu-west-1/123456789012/i-0web
  Target: aws/ec2/security-group/eu-west-1/123456789012/sg-0zzz999
  Type: ATTACHED_TO
  Origin: AWS_OBSERVED
  Evidence: aws:ec2:DescribeInstances:i-0web:attached_to:SecurityGroups:sg-0zzz999
```

### 4. Reconciliation Verdict:
```
Finding 1: CONFIRMED
  i-0web -> sg-0aaa111
  Both Terraform and AWS agree

Finding 2: UNDOCUMENTED ⚠️
  i-0web -> sg-0zzz999
  AWS observed but Terraform never declared it
  This is infrastructure drift!
```

---

## 🔒 Safety Guarantees

### Whitelisted Operations

```python
# aws_resources.py (lines 52-61)
ALLOWED_OPERATIONS: frozenset[str] = frozenset({
    "get_caller_identity",     # STS - get account ID
    "describe_instances",      # EC2 - read only
    "describe_security_groups", # EC2 - read only
    "list_functions",          # Lambda - read only
    "describe_db_instances",   # RDS - read only
    "list_buckets",            # S3 - read only
})
```

### Error Handling

```python
# Lines 264-298
def _isolated(self, label: str, run: Callable, ...) -> _Outcome:
    """Run one service; failure doesn't stop others"""
    try:
        return run(account, principal, scan_at)
    except Exception as err:
        code = _expected_failure_code(err)
        
        if code is None:
            raise  # Unexpected error - propagate
        
        # Expected failure (AccessDenied, Throttling)
        return _Outcome(
            [],  # Discard partial results
            [],
            [],
            Coverage(
                source=EvidenceSource.AWS_RESOURCES,
                status=CoverageStatus.UNAVAILABLE,
                reason=f"{label} could not be consulted ({code})",
            ),
        )
```

**Why this matters**: If EC2 is denied, Lambda/RDS/S3 still scan. Partial results are **discarded** to avoid false negatives.

---

## 🎯 Key Interview Points

### 1. **Adapter Pattern**
"I used the adapter pattern with three independent adapters. Each adapter can fail without affecting others, and each reports its own coverage status."

### 2. **Pagination**
"AWS APIs return paginated results. I built a generic `_paginate()` helper that handles NextToken/Marker patterns for all services."

### 3. **Evidence-Based**
"Every relationship has traceable evidence back to the exact API response location. For example: `aws:ec2:DescribeInstances:i-0abc123:attached_to:SecurityGroups:sg-0aaa111`"

### 4. **Canonical ID System**
"I built a six-segment canonical ID system to normalize identities across Terraform, AWS, and wildcards. This prevents false positives from name collisions."

### 5. **Error Handling**
"I distinguish between expected failures (AccessDenied, Throttling) and unexpected errors. Expected failures are recorded as coverage gaps, not silently ignored."

### 6. **Safety First**
"Every adapter has a whitelist of allowed operations. Tests enforce that no mutating operations (Create, Delete, Modify) can ever be called."

### 7. **boto3 Optional**
"boto3 is imported lazily inside the client factory, never at module level. This lets the tool work without AWS dependencies when using fixtures."

---

## 📝 Code Locations Quick Reference

| Feature | File | Lines |
|---------|------|-------|
| **AWS Resources Entry Point** | `aws_resources.py` | 228-262 |
| **STS GetCallerIdentity** | `aws_resources.py` | 300-322 |
| **EC2 Instance Scanner** | `aws_resources.py` | 326-381 |
| **Lambda Scanner** | `aws_resources.py` | 416-471 |
| **RDS Scanner** | `aws_resources.py` | 473-525 |
| **S3 Scanner** | `aws_resources.py` | 527-569 |
| **Pagination Helper** | `aws_resources.py` | 161-172 |
| **Relationship Builder** | `aws_resources.py` | 592-642 |
| **CloudTrail Entry** | `cloudtrail.py` | 300-450 |
| **IAM Entry** | `iam.py` | 250-350 |
| **Policy Parser** | `iam.py` | 400-500 |
| **Reconciliation Logic** | `reconcile.py` | 251-294 |

---

Good luck explaining this in your interviews! Focus on the adapter pattern, evidence-based reconciliation, and safety guarantees. The code is well-structured and shows strong system design skills.
