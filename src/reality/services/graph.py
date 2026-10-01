"""A scan-scoped view over the stored graph.

The store holds raw observations: resources, relationships, evidence, coverage,
and the identity mappings a scan computed. Every consumer — reconciliation,
``why``, ``impact``, ``simulate`` and the graph exporters — needs to answer the
same questions about that data:

* Does this canonical ID denote a resource we have stored?
* Which stored IDs are the *same* real-world thing, recorded with more or less
  identity than the reference we are holding?
* What coverage bounds what we may conclude?

Answering those differently in each consumer is how the S3 bucket ended up
unreachable: the scan stored it account-qualified, the edges that reference it
were recorded accountless, and the traversal compared the two strings exactly.

``IdentityResolver`` is the first piece of that view. It resolves a canonical
ID to every stored ID denoting the same concrete resource, and — crucially —
finds the edges that *point at* a resource even when the edge recorded less
identity than the resource itself.
"""

from __future__ import annotations

from collections.abc import Sequence

from reality.domain.ids import (
    IdParseError,
    parse_canonical,
    resolve_compatible,
)
from reality.domain.models import (
    Coverage,
    Finding,
    IdentityMapping,
    Relationship,
    Resource,
    TerraformChange,
)
from reality.storage.repositories import ScanStore


class IdentityResolver:
    """Resolve canonical IDs and edges across compatible identities.

    The resolver indexes stored resources by their base identity
    (provider, service, type, resource ID) so a lookup only compares candidates
    that could possibly match — an accountless S3 bucket ARN is checked against
    the buckets we hold, not against every resource in the store. Edges are
    indexed the same way, so a traversal can find every edge that points at a
    resource regardless of how much identity the edge recorded.
    """

    def __init__(
        self, resources: Sequence[Resource], relationships: Sequence[Relationship] = ()
    ) -> None:
        self._by_id: dict[str, Resource] = {
            resource.canonical_id: resource for resource in resources
        }
        self._resources_by_base: dict[tuple[str, str, str, str], list[str]] = {}
        for resource in resources:
            try:
                cid = parse_canonical(resource.canonical_id)
            except IdParseError:
                continue
            key = (cid.provider, cid.service, cid.resource_type, cid.resource_id)
            self._resources_by_base.setdefault(key, []).append(resource.canonical_id)

        self._edges_by_base: dict[tuple[str, str, str, str], list[Relationship]] = {}
        for edge in relationships:
            for endpoint in (edge.source_canonical_id, edge.target_canonical_id):
                try:
                    cid = parse_canonical(endpoint)
                except IdParseError:
                    continue
                key = (cid.provider, cid.service, cid.resource_type, cid.resource_id)
                self._edges_by_base.setdefault(key, []).append(edge)

    # --- resources -------------------------------------------------------------

    def resolve(self, canonical_id: str) -> tuple[str, ...]:
        """Stored resource IDs that denote the same resource as ``canonical_id``.

        Always includes ``canonical_id`` itself when it is stored verbatim. An
        unparseable or unresolved reference resolves only to itself — a pattern
        is never silently promoted to a concrete resource.
        """
        try:
            query = parse_canonical(canonical_id)
        except IdParseError:
            return (canonical_id,)
        if query.is_unresolved:
            return (canonical_id,)
        key = (query.provider, query.service, query.resource_type, query.resource_id)
        matches = sorted(
            stored_id
            for stored_id in self._resources_by_base.get(key, ())
            if resolve_compatible(query, parse_canonical(stored_id))
        )
        return tuple(matches) if matches else (canonical_id,)

    def is_stored(self, canonical_id: str) -> bool:
        """Whether this exact ID is stored, ignoring compatible identities."""
        return canonical_id in self._by_id

    # --- edges ----------------------------------------------------------------

    def _edges_touching(self, canonical_id: str, *, target: bool) -> tuple[Relationship, ...]:
        """Edges whose source (or target) denotes the same resource."""
        try:
            query = parse_canonical(canonical_id)
        except IdParseError:
            return ()
        if query.is_unresolved:
            return ()
        key = (query.provider, query.service, query.resource_type, query.resource_id)
        endpoint = "target_canonical_id" if target else "source_canonical_id"
        return tuple(
            edge
            for edge in self._edges_by_base.get(key, ())
            if resolve_compatible(query, parse_canonical(getattr(edge, endpoint)))
        )

    def incoming(self, canonical_id: str) -> tuple[Relationship, ...]:
        """Edges pointing *at* this resource, across compatible identities."""
        return self._edges_touching(canonical_id, target=True)

    def outgoing(self, canonical_id: str) -> tuple[Relationship, ...]:
        """Edges pointing *away from* this resource, across compatible identities."""
        return self._edges_touching(canonical_id, target=False)


# --- GraphView ------------------------------------------------------------------


class GraphView:
    """A scan-scoped view over the stored graph.

    Every consumer — reconciliation, ``why``, ``impact``, ``simulate`` and the
    graph exporters — needs to answer the same questions about *one* scan run:

    * Does this canonical ID denote a resource stored **in that scan**?
    * Which stored IDs are the *same* real-world thing, recorded with more or
      less identity than the reference we are holding?
    * What coverage bounds what we may conclude **for that scan**?
    """

    def __init__(
        self,
        store: ScanStore,
        scan_run_id: int,
    ) -> None:
        self._store = store
        self._scan_run_id = scan_run_id
        self._resolver = IdentityResolver(
            store.resources.for_scan_run(scan_run_id),
            store.relationships.for_scan_run(scan_run_id),
        )

    @property
    def scan_run_id(self) -> int:
        return self._scan_run_id

    @property
    def resolver(self) -> IdentityResolver:
        return self._resolver

    # --- resources -------------------------------------------------------------

    def get_resource(self, canonical_id: str) -> Resource | None:
        """Get a resource if it exists in this scan."""
        for stored_id in self._resolver.resolve(canonical_id):
            resource = self._store.resources.get(stored_id)
            if resource is not None:
                return resource
        return None

    def has_resource(self, canonical_id: str) -> bool:
        for stored_id in self._resolver.resolve(canonical_id):
            if self._store.resources.get(stored_id) is not None:
                return True
        return False

    # --- edges ----------------------------------------------------------------

    def incoming(self, canonical_id: str) -> tuple[Relationship, ...]:
        """Edges pointing *at* this resource, across compatible identities."""
        return self._resolver.incoming(canonical_id)

    def outgoing(self, canonical_id: str) -> tuple[Relationship, ...]:
        """Edges pointing *away from* this resource, across compatible identities."""
        return self._resolver.outgoing(canonical_id)

    def outgoing_all(self) -> tuple[Relationship, ...]:
        """Every candidate edge in this scan, deduplicated by canonical ID.

        Reconciliation groups candidates rather than traversing from a root, so
        it needs the scan's whole edge set in one pass.
        """
        return self._store.relationships.for_scan_run(self._scan_run_id)

    # --- coverage --------------------------------------------------------------

    def coverage(self) -> tuple[Coverage, ...]:
        return self._store.coverage.for_scan_run(self._scan_run_id)

    # --- findings -------------------------------------------------------------

    def findings(self) -> tuple[Finding, ...]:
        return self._store.findings.for_scan_run(self._scan_run_id)

    # --- identity mappings ----------------------------------------------------

    def identity_mappings(self) -> tuple[IdentityMapping, ...]:
        return self._store.identity_mappings.for_scan_run(self._scan_run_id)

    # --- terraform addresses --------------------------------------------------

    def terraform_addresses(self) -> tuple[TerraformChange, ...]:
        return self._store.terraform_addresses.for_scan_run(self._scan_run_id)

    # --- resolve subject ------------------------------------------------------

    def resolve_subject(self, canonical_id: str) -> str | None:
        """Resolve a user-provided identifier to the stored canonical ID.

        Resolves through compatible identities so a less-qualified reference
        (an accountless S3 bucket ARN) reaches the stored, account-qualified
        resource.
        """
        for stored_id in self._resolver.resolve(canonical_id):
            if self._store.resources.get(stored_id) is not None:
                return stored_id
        return None

    # --- graph export ---------------------------------------------------------

    def export_graph(self, root: str, depth: int = 3, output_format: str = "text") -> str:
        """Export a subgraph starting at root, up to depth.

        output_format: "text" | "dot" | "mermaid"
        """
        if output_format == "dot":
            return self._export_dot(root, depth)
        elif output_format == "mermaid":
            return self._export_mermaid(root, depth)
        else:
            return self._export_text(root, depth)

    def _export_text(self, root: str, depth: int) -> str:
        lines = [f"Graph rooted at {root} (depth {depth}):"]
        queue: list[tuple[str, int]] = [(root, 0)]
        visited: set[str] = set()
        while queue:
            node, d = queue.pop(0)
            if d > depth or node in visited:
                continue
            visited.add(node)
            lines.append(f"  {'  ' * d}{node}")
            for edge in self.outgoing(node):
                queue.append((edge.target_canonical_id, d + 1))
        return "\n".join(lines)

    def _export_dot(self, root: str, depth: int) -> str:
        lines = ["digraph G {"]
        queue: list[tuple[str, int]] = [(root, 0)]
        visited: set[str] = set()
        while queue:
            node, d = queue.pop(0)
            if d > depth or node in visited:
                continue
            visited.add(node)
            for edge in self.outgoing(node):
                target = edge.target_canonical_id
                lines.append(f'  "{node}" -> "{target}";')
                if d < depth and target not in visited:
                    queue.append((target, d + 1))
        lines.append("}")
        return "\n".join(lines)

    def _export_mermaid(self, root: str, depth: int) -> str:
        lines = ["```mermaid", "graph TD"]
        queue: list[tuple[str, int]] = [(root, 0)]
        visited: set[str] = set()
        while queue:
            node, d = queue.pop(0)
            if d > depth or node in visited:
                continue
            visited.add(node)
            for edge in self.outgoing(node):
                target = edge.target_canonical_id
                lines.append(f"  {node} --> {target}")
                if d < depth and target not in visited:
                    queue.append((target, d + 1))
        lines.append("```")
        return "\n".join(lines)
