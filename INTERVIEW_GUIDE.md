# Infrastructure Reality - Interview Guide

## 🎯 30-Second Elevator Pitch

"I built Infrastructure Reality, a Python CLI tool that detects infrastructure drift and hidden dependencies in AWS environments without making any changes. It reconciles what Terraform **declares** with what AWS **actually has** running, identifying undocumented dependencies that could cause production outages. Think of it as a safety net that catches configuration drift before it causes incidents - completely read-only, so it's safe to run anywhere."

## 📋 2-Minute Technical Overview

### The Problem It Solves
- **Infrastructure Drift**: Terraform state doesn't always match reality (manual changes, console edits, orphaned resources)
- **Hidden Dependencies**: Security groups attached outside Terraform, IAM permissions not tracked, CloudTrail usage patterns
- **Blast Radius Uncertainty**: "If I change this security group, what breaks?" - teams don't know
- **Production Safety**: No existing tools let you analyze dependencies without risk of mutations

### The Solution
Infrastructure Reality is a **read-only** discovery and simulation tool that:
1. Parses Terraform state exports (JSON)
2. Optionally queries AWS APIs (EC2, Lambda, RDS, IAM, CloudTrail)
3. Reconciles both worlds in a local SQLite database
4. Reports 5 types of findings: `confirmed`, `undocumented`, `possible`, `declared_only`, `unknown`
5. Simulates blast radius for Terraform plan changes

### Key Innovation
**Evidence-based reconciliation with strict identity resolution** - never guesses, never assumes missing data means "no dependency"

---

## 🏗️ Architecture & Design Decisions

### 1. Safety-First Design
**Location**: `docs/safety.md`, `src/reality/cli.py:174-237` (AWS opt-in gate)

```python
# src/reality/cli.py (lines 213-237)
def _validate_aws_selection(
    aws_requested: bool,
    profile: str | None,
    region: str | None,
    has_boto3: bool,
) -> None:
    """Enforce the AWS opt-in contract: all three required together, or none."""
    # CRITICAL: This prevents accidental AWS access
    has_profile = profile is not None
    has_region = region is not None
    partial = (has_profile or has_region) and not (has_profile and has_region)
    
    if partial:
        # User typed --profile without --region (or vice versa)
        raise ConfigError(
            "AWS profile and region must both be specified",
            exit_code=4,
        )
    
    if not aws_requested and (has_profile or has_region):
        # AWS-shaped command without explicit --aws flag
        raise ConfigError(
            "AWS profile/region were provided but --aws was not; "
            "AWS is never contacted without explicit opt-in",
            exit_code=4,
        )
```

**Why This Matters**: 
- No default profile, no default region - explicit `--aws --profile --region` required
- Prevents accidental production queries
- boto3 is optional dependency, imported only in AWS adapters

**Interview Talking Point**: "I implemented a strict safety contract where AWS access requires three explicit flags. This prevents accidental production queries and makes the tool safe to run anywhere. The validation happens before any adapters load, so there's zero chance of an accidental API call."

---

### 2. Canonical ID System
**Location**: `src/reality/domain/ids.py` (entire file), `docs/architecture.md:48-80`

```python
# src/reality/domain/ids.py (lines 47-82)
@dataclass(frozen=True)
class CanonicalID:
    """Six-segment normalized identity key.
    
    provider/service/resource_type/region/account/resource_id
    Examples:
      aws/ec2/instance/eu-west-1/123456789012/i-0abc123
      terraform/aws/aws_instance/-/-/aws_instance.web
      unresolved/-/-/-/-/arn:aws:s3:::bucket/*
    """
    provider: str
    service: str
    resource_type: str
    region: str | None
    account: str | None
    resource_id: str
    
    def __post_init__(self) -> None:
        # Validate no slashes in segments (would break parsing)
        for name, value in [
            ("provider", self.provider),
            ("service", self.service),
            ("resource_type", self.resource_type),
            ("resource_id", self.resource_id),
        ]:
            if "/" in value:
                raise ValueError(f"{name} cannot contain '/': {value!r}")
```

**Key Design Choice**: Three separate namespaces
- `terraform/...` - Terraform address is the identity
- `aws/...` - AWS native IDs (from API responses)
- `unresolved/...` - Wildcards, policy variables that can't be resolved

```python
# src/reality/domain/ids.py (lines 235-267)
def safe_join(left: CanonicalID, right: CanonicalID) -> bool:
    """Whether two IDs can be the same resource (never a name match).
    
    Rules:
    - Different providers never join (terraform vs aws are distinct namespaces)
    - Different services/types never join (ec2/instance vs iam/role)
    - Region-scoped resources must match region AND account
    - Missing account never matches known account (prevents cross-account bugs)
    """
    if left.provider != right.provider:
        return False
    if left.service != right.service or left.resource_type != right.resource_type:
        return False
    
    # Global services (S3, IAM) ignore region
    if left.service in GLOBAL_SERVICES:
        if left.account != right.account:
            return False
        return left.resource_id == right.resource_id
    
    # Region-scoped: both must match
    if left.region != right.region or left.account != right.account:
        return False
    return left.resource_id == right.resource_id
```

**Interview Talking Point**: "I designed a canonical ID system with three namespaces - terraform, aws, and unresolved. This prevents false positives from name collisions. For example, `aws_instance.web` in Terraform and `i-0abc123` in AWS are kept as separate identities until evidence proves they're the same resource. The `safe_join` function enforces region and account matching to prevent dangerous cross-account assumptions."

---

### 3. Evidence-Based Reconciliation
**Location**: `src/reality/services/reconcile.py:180-350` (verdict logic)

```python
# src/reality/services/reconcile.py (lines 251-294)
def _verdict(
    candidate: RelationshipCandidate,
    declared: set[EvidenceSource],
    observed: set[EvidenceSource],
    coverage: dict[EvidenceSource, CoverageStatus],
) -> Conclusion:
    """Determine conclusion from coverage and evidence presence.
    
    Logic:
    - CONFIRMED: Both Terraform and AWS agree (highest confidence)
    - UNDOCUMENTED: AWS observed, but Terraform never declared it (drift!)
    - POSSIBLE: IAM policy allows it, but no usage seen (maybe unused)
    - DECLARED_ONLY: Terraform declares, AWS doesn't see it
    - UNKNOWN: Missing coverage prevents verdict
    """
    has_declared = bool(declared)
    has_observed = bool(observed)
    
    # Both worlds agree - highest confidence
    if has_declared and has_observed:
        return Conclusion.CONFIRMED
    
    # AWS sees it, Terraform doesn't - this is drift!
    if has_observed and not has_declared:
        # But only if Terraform was actually consulted
        if EvidenceSource.TERRAFORM_STATE in coverage:
            return Conclusion.UNDOCUMENTED
    
    # Terraform declares, AWS doesn't see it
    if has_declared and not has_observed:
        # Could be unused, could be data-plane (not visible to our APIs)
        return Conclusion.DECLARED_ONLY
    
    # IAM policy exists but no usage observed
    if EvidenceSource.IAM in observed:
        return Conclusion.POSSIBLE
    
    # Missing critical coverage - can't decide
    return Conclusion.UNKNOWN
```

**The 5 Conclusion Types**:
1. **CONFIRMED** (green) - Both worlds agree, identity-mapped
2. **UNDOCUMENTED** (red) - Observed in cloud, no Terraform declaration (THIS IS DRIFT)
3. **POSSIBLE** (yellow) - IAM policy allows it, but no observed usage
4. **DECLARED_ONLY** (yellow) - Terraform declares, not observed (might be data-plane)
5. **UNKNOWN** (gray) - Missing coverage, can't determine

**Interview Talking Point**: "The reconciliation engine uses evidence-based logic with five conclusion types. The critical one is UNDOCUMENTED - when AWS shows a dependency that Terraform doesn't know about. For example, an EC2 instance with a security group attached manually in the console. This is infrastructure drift that could cause outages if someone modifies that security group thinking it's unused. The tool never guesses - if coverage is missing, it reports UNKNOWN rather than claiming 'no dependency'."

---

### 4. Database Schema & Transactions
**Location**: `src/reality/storage/sqlite.py`, `src/reality/storage/repositories.py:563-633`

```python
# src/reality/storage/repositories.py (lines 563-633)
@contextmanager
def scan(
    self,
    *,
    description: str = "scan",
) -> Iterator[tuple[int, datetime]]:
    """Open a write transaction for one scan run.
    
    Key Design:
    - ONE transaction per scan (all-or-nothing)
    - Ctrl+C leaves database unchanged (no partial writes)
    - Schema migrations run on first write
    - Read-only commands (why/impact) can't modify database
    """
    if self._readonly:
        raise RuntimeError("scan() called on read-only store")
    
    conn = self._connection
    try:
        # Migrations run here, inside transaction
        migrate(conn)
        
        # Create scan_run record
        scan_run_id, scan_time = self._store_scan_run(description)
        
        conn.execute("BEGIN IMMEDIATE")
        
        yield scan_run_id, scan_time
        
        # All writes succeed or none do
        conn.commit()
        
    except KeyboardInterrupt:
        # User hit Ctrl+C - rollback everything
        conn.rollback()
        raise Cancelled from None
    except Exception:
        conn.rollback()
        raise
```

**Schema Highlights**:
- `resources` - Discovered resources with canonical IDs
- `relationships` - Directed edges with provenance (terraform_declared, aws_observed, etc.)
- `evidence` - Raw observations (API responses, config references)
- `identity_mappings` - Proven terraform ↔ aws equivalences
- `findings` - Reconciliation verdicts per relationship
- `coverage` - What each scan consulted (proves we checked)

**Interview Talking Point**: "I implemented single-transaction scans so Ctrl+C leaves the database unchanged. The entire scan runs in one atomic transaction - all resources, relationships, and evidence commit together or not at all. This prevents partial data corruption and makes the database state always consistent. Read-only commands like `why` and `impact` open the database without write permissions, so they literally can't modify anything."

---

### 5. Impact Analysis & Blast Radius
**Location**: `src/reality/services/impact.py:190-280` (BFS traversal)

```python
# src/reality/services/impact.py (lines 190-252)
def compute_impact(
    subject_canonical_id: str,
    *,
    depth: int = DEFAULT_DEPTH,
    basis: GraphBasis = GraphBasis.DISCOVERY,
) -> ImpactReport:
    """Compute blast radius via reverse BFS traversal.
    
    Finds all resources that depend on the subject, up to depth hops.
    Direction: follows edges BACKWARDS (who points at me?)
    """
    view = self._graph_view
    visited: set[str] = set()
    queue: deque[tuple[str, int, list[str]]] = deque()
    dependents: list[Dependent] = []
    
    # Start from subject
    queue.append((subject_canonical_id, 0, [subject_canonical_id]))
    visited.add(subject_canonical_id)
    
    # BFS: explore incoming edges
    while queue:
        current_id, current_depth, path = queue.popleft()
        
        if current_depth >= depth:
            continue
        
        # Get resources that point TO current (incoming edges)
        for rel in view.incoming(current_id):
            source_id = rel.source_canonical_id
            
            if source_id in visited:
                continue
            
            visited.add(source_id)
            new_path = [source_id] + path
            
            # This is a dependent!
            dependents.append(Dependent(
                canonical_id=source_id,
                depth=current_depth + 1,
                path=tuple(new_path),
                provenance=rel.origin.value,
                evidence_ids=rel.evidence_ids,
                kind=_classify_dependent(current_depth + 1, rel),
            ))
            
            # Continue traversal
            queue.append((source_id, current_depth + 1, new_path))
    
    # Risk assessment
    risk = _assess_risk(dependents, view, subject_canonical_id)
    
    return ImpactReport(
        subject_canonical_id=subject_canonical_id,
        basis=basis,
        depth=depth,
        risk=risk,
        dependents=tuple(dependents),
        notes=tuple(_generate_notes(view, subject_canonical_id)),
    )
```

**Risk Levels**:
- **HIGH**: 5+ dependents OR any undocumented dependency
- **MEDIUM**: 1-4 dependents OR unknown conclusions
- **LOW**: 0 dependents AND coverage was actually checked

**Interview Talking Point**: "The impact analysis uses reverse BFS traversal to find all resources that depend on a target. For example, if you ask about a security group, it finds all EC2 instances, RDS databases, and Lambda functions using it. The risk assessment is evidence-based: HIGH if there are 5+ dependents or ANY undocumented dependencies. This can be used in CI pipelines with `--fail-on high` to block risky changes."

---

## 🔬 Technical Highlights to Mention

### 1. Testing Strategy
**Location**: `tests/` directory, 528 passing tests

```python
# tests/conftest.py (lines 18-35) - Test Isolation
@pytest.fixture(autouse=True)
def _isolate_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Force every test to use isolated config (no user's real config)."""
    fake_config = tmp_path / "isolated_reality_config.toml"
    monkeypatch.setenv("REALITY_CONFIG", str(fake_config))

@pytest.fixture(autouse=True)
def _guard_boto3_import(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail if test imports boto3 without marking itself aws-optional."""
    original_import = builtins.__import__
    def guarded_import(name, *args, **kwargs):
        if name.startswith("boto"):
            raise ImportError(f"Test tried to import {name} without boto3 guard")
        return original_import(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "__import__", guarded_import)
```

**Key Points**:
- 528 tests, fully offline (no AWS credentials needed)
- Autouse fixtures prevent tests from touching real config
- boto3 import guard ensures optional dependency stays optional
- Recorded API responses (fixtures) for deterministic testing
- CI runs on Windows + Linux

**Interview Talking Point**: "I wrote 528 tests that run completely offline with no AWS credentials. The test suite uses autouse fixtures to isolate config and guard against boto3 imports unless explicitly allowed. This ensures the tool works without AWS dependencies and tests are deterministic."

---

### 2. Progress Reporting
**Location**: `src/reality/services/progress.py:154-199` (Rich + fallback)

```python
# src/reality/services/progress.py (lines 154-172)
def reporter_for_interactive(*, force: bool = False) -> ProgressReporter:
    """Best reporter for current terminal (Rich or plain-text).
    
    Strategy:
    1. If stderr is redirected (CI logs) -> NullProgressReporter (silent)
    2. If rich installed + TTY -> _RichProgressReporter (spinner + bar)
    3. Fallback -> StderrProgressReporter (plain percentage)
    """
    stderr = sys.stderr
    if not force and not bool(getattr(stderr, "isatty", lambda: False)()):
        return NullProgressReporter()  # CI logs stay clean
    
    try:
        from rich.console import Console
        from rich.progress import Progress, BarColumn, TextColumn
    except ImportError:
        return StderrProgressReporter(stderr)  # No rich? Plain text.
    
    console = Console(stderr=True)
    return _RichProgressReporter(console, Progress, BarColumn, TextColumn)
```

**Features**:
- Rich spinner/progress bar when available
- Falls back to plain text percentage
- Silent when stderr is redirected (keeps CI logs clean)
- All progress on stderr (stdout reserved for JSON/YAML output)

**Interview Talking Point**: "Progress reporting degrades gracefully - Rich spinner if available, plain text percentage as fallback, and completely silent in CI. All progress goes to stderr so stdout stays clean for piping JSON output."

---

### 3. Output Formats
**Location**: `src/reality/services/reports.py:618-676` (table renderer)

```python
# src/reality/services/reports.py (lines 361-370)
def _conclusion_style(conclusion: str) -> str:
    """Rich colors for conclusions (visual hierarchy)."""
    styles = {
        Conclusion.UNDOCUMENTED.value: "bold red",      # ALERT
        Conclusion.DECLARED_ONLY.value: "yellow",       # WARNING
        Conclusion.POSSIBLE.value: "yellow",            # WARNING
        Conclusion.UNKNOWN.value: "dim",                # UNSURE
        Conclusion.CONFIRMED.value: "green",            # GOOD
    }
    return styles.get(conclusion.lower(), "")
```

**5 Output Formats**:
1. `text` - Human-readable (default)
2. `table` - Rich formatted tables with colors
3. `json` - Byte-stable (sorted keys, no timestamps) for CI diffs
4. `yaml` - Human-readable structured
5. `csv` - Spreadsheet import

**Interview Talking Point**: "The tool supports 5 output formats. JSON is byte-stable with sorted keys and no timestamps, so identical inputs produce identical bytes - perfect for CI diffs. Rich tables use color-coding: red for undocumented (drift), green for confirmed, yellow for warnings."

---

## 🎤 Interview Questions & Answers

### Q: "How is this different from Terraform plan?"
**Answer**: 
"Terraform plan only shows what Terraform *intends* to change based on its state file. It doesn't show:
- Resources created manually in the AWS console
- Dependencies Terraform doesn't know about (hidden security group attachments)
- IAM permissions that exist but aren't tracked in state
- CloudTrail usage patterns showing real runtime dependencies

Infrastructure Reality reconciles Terraform's view with AWS's reality to find drift and undocumented dependencies. It's complementary to `terraform plan` - you run both."

---

### Q: "Why SQLite instead of a cloud database?"
**Answer**:
"Three reasons:
1. **Local-first**: No external dependencies, works offline, no credentials needed
2. **Single transaction per scan**: Atomic commits, Ctrl+C leaves database unchanged
3. **Portability**: The entire database is one file - easy to share, version control, or archive

For a read-only discovery tool, SQLite is perfect. If this scaled to multi-team dashboards, I'd add an optional PostgreSQL backend, but the local-first mode should remain."

---

### Q: "How do you handle large AWS accounts?"
**Answer**:
"The design handles large accounts well:
- **Streaming parsing**: Terraform JSON parsed incrementally, not loaded entirely into memory
- **Batch inserts**: Resources written in bulk within the transaction
- **Indexed queries**: Canonical IDs are indexed for fast lookups
- **Progress reporting**: Shows live status so users know it's working

In testing with 200+ resources, scans complete in seconds. For 10,000+ resources, I'd add pagination to AWS API calls and benchmark memory usage, but the architecture supports it."

---

### Q: "What's the most complex bug you fixed?"
**Answer**:
"The canonical ID resolution for global vs regional services. Initially, S3 buckets were getting region from the API response, but S3 is region-agnostic - a bucket in `us-east-1` can be accessed globally. This caused false negatives where the same bucket appeared as two different resources.

I added the `GLOBAL_SERVICES` set and modified `safe_join` to ignore region for S3/IAM/CloudFront. The fix required updating ID parsing, join logic, and adding 15 test cases covering regional vs global resources. The lesson: AWS's own APIs aren't always consistent about regional vs global identity."

---

### Q: "How would you add support for Azure or GCP?"
**Answer**:
"The architecture is cloud-agnostic by design:

1. **New adapter**: `src/reality/adapters/azure_resources.py` with `ALLOWED_OPERATIONS` whitelist
2. **Extend canonical ID**: Add `azure/` namespace (parallel to `aws/`)
3. **Resource types**: Map Azure's VMs, NSGs, etc. to our resource type enum
4. **Reconciliation**: Same logic works - declared vs observed, evidence-based verdicts
5. **Safety contract**: Same read-only guarantees, explicit opt-in

The domain models, storage layer, and reconciliation engine are cloud-agnostic. Only the adapters know about specific cloud APIs."

---

## 📊 Metrics to Highlight

- **528 tests**, all passing, 0 flakes
- **29 files** type-checked with mypy (strict mode)
- **100% ruff clean** (linter)
- **~6,000 lines** of production code
- **~8,000 lines** of test code (better than 1:1 test ratio)
- **5 output formats** (text, table, JSON, YAML, CSV)
- **5 evidence sources** (Terraform, AWS resources, IAM, CloudTrail, Terraform plan)
- **0 AWS mutations** (read-only guarantee enforced by tests)

---

## 🎯 Key Differentiators

### vs. Terraform Plan
- ✅ Detects manual AWS changes Terraform doesn't know about
- ✅ Shows runtime dependencies (CloudTrail, IAM permissions)
- ✅ Read-only (safe to run in production)

### vs. AWS Config
- ✅ Reconciles with Terraform declarations (not just AWS state)
- ✅ Local-first (no AWS Config setup required)
- ✅ Evidence-based verdicts (not just config snapshots)

### vs. Checkov / tfsec
- ✅ Runtime reconciliation (not just static analysis)
- ✅ Blast radius analysis (who depends on what)
- ✅ Detects drift (observed vs declared)

---

## 🚀 Demo Flow for Interviews

**1. Run the complex demo** (2 minutes):
```bash
cd Atest/complex-demo
python run_demo.py
```
Shows: scan → reconcile → findings with colors → blast radius graph

**2. Highlight an undocumented finding**:
```
undocumented: aws/ec2/instance/.../i-0web -> aws/ec2/security-group/.../sg-0zzz999
```
"This security group is attached to an EC2 instance, but Terraform doesn't know about it. If someone deletes this SG thinking it's unused, the instance loses network access."

**3. Show the impact command**:
```bash
reality impact aws:iam/role:123456789012:cleanup_role --fail-on high
```
"Exit code 6 means high risk - perfect for CI gates."

**4. Show the graph export**:
```bash
reality graph aws_security_group.web_sg --output mermaid
```
"Paste this into GitHub markdown or Obsidian for visual documentation."

---

## 💡 Future Enhancements (Good Interview Topics)

1. **Multi-cloud support** (Azure, GCP) - Architecture already supports it
2. **Continuous monitoring** - Run as a daemon, alert on new drift
3. **Terraform remediation** - Generate `.tf` files for undocumented resources
4. **Web UI** - Dashboard showing drift over time
5. **Policy engine** - Custom rules ("no SG should allow 0.0.0.0/0")
6. **Historical tracking** - Compare scans over time, detect trends

---

## 📝 Code Walkthrough Script

**If asked to walk through code:**

1. **Start with entry point**: `src/reality/cli.py:main()` → argument parsing
2. **Show safety gate**: `_validate_aws_selection()` → explains opt-in
3. **Scan orchestration**: `src/reality/services/scan.py:scan()` → adapter coordination
4. **Canonical IDs**: `src/reality/domain/ids.py:CanonicalID` → identity resolution
5. **Reconciliation logic**: `src/reality/services/reconcile.py:_verdict()` → evidence-based conclusions
6. **Impact analysis**: `src/reality/services/impact.py:compute_impact()` → BFS traversal
7. **Database**: `src/reality/storage/repositories.py:scan()` → atomic transactions

---

## 🎓 Lessons Learned

1. **Safety contracts must be enforceable by code** - Tests assert the read-only guarantee
2. **Evidence is not a conclusion** - Missing data = UNKNOWN, never "no dependency"
3. **Identity resolution is hard** - Never guess, never match on names
4. **Optional dependencies are powerful** - boto3 and rich imported lazily
5. **Local-first enables testing** - 528 offline tests, no credentials needed
6. **User intent matters** - Explicit opt-in prevents accidents

---

## ✨ One-Liners for Impact

- "Prevents production outages by detecting infrastructure drift"
- "Read-only guarantee enforced by tests, not just documentation"
- "Evidence-based reconciliation - never guesses, never assumes"
- "528 offline tests, works without AWS credentials"
- "CI-ready with `--fail-on` gates and byte-stable JSON output"

---

Good luck with your interviews! Focus on the safety contract, canonical ID system, and reconciliation logic - these show system design thinking. The demo speaks for itself.
