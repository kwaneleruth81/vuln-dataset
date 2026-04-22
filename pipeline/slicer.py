"""
slicer.py — Step 5 of the pipeline: compute the multi-function slice.

The slice identifies nodes "vulnerability-relevant" in the sense of:

    in_slice(n)  iff  (patch reaches n forward) AND (n reaches sink backward)

over the traversable edge set:  CFG ∪ DFG ∪ CALL ∪ PARAM_BIND.

Rationale
---------
A node sits inside the bug if it can both be *influenced by* the patch
(forward reach) and *influence* a sink (backward reach). The intersection
captures the "funnel" between them without requiring a single end-to-end
path — that stricter definition is more expensive and doesn't add signal
for GNN training.

Fallbacks
---------
* No sinks marked: treat patch nodes as implicit sinks, so the slice becomes
  the local dataflow neighborhood of the patch. Step 3 has already logged a
  warning in this case.
* No patch nodes on this version: slice is empty; we flag it so downstream
  code can decide whether to drop the sample or keep it as pure label-0
  context. Typical cause is Step 1 not finding any modified lines inside a
  function body (struct-only change, etc.).

Hops
----
Every edge is one hop regardless of type. Defaults: 10 backward, 10 forward.
Both configurable. Hops cap total BFS depth, not path length through the
intersection — once a node is reached within the cap on either BFS, it
remains eligible for the intersection.
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field

import networkx as nx

log = logging.getLogger(__name__)


# Edge types we traverse for slicing. AST edges are structural-only and
# intentionally excluded — they don't carry semantic dependence.
TRAVERSAL_EDGE_TYPES: frozenset[str] = frozenset({
    "CFG", "DFG", "CALL", "PARAM_BIND",
})


@dataclass
class SliceReport:
    """Summary of the computed slice. Emitted for logs and persisted on the
    graph via G.graph['slice_report']."""
    slice_size: int = 0
    n_patch_nodes: int = 0
    n_sink_nodes: int = 0
    forward_reached: int = 0      # |Forward(P)|
    backward_reached: int = 0     # |Backward(S)|
    used_sink_fallback: bool = False   # true if sinks empty -> used patch as sinks
    skipped: str | None = None    # non-None iff we returned an empty slice early
    # Role breakdown of slice members — useful for eval (is slice concentrated
    # in the patch function or spilling into neighbors?).
    slice_by_role: dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Internal: identify patch and sink nodes on the graph
# ---------------------------------------------------------------------------

def _patch_nodes(G: nx.MultiDiGraph) -> set[str]:
    """Nodes that sit on a patched line in a patch-role function.

    The `candidate_functions` metadata stashed by Step 2 tells us the
    patched line numbers per patch function. We match statements by
    (function, line). This is strict: only patch-role functions contribute,
    never callers or callees (they'd have empty modified_lines anyway)."""
    cand = G.graph.get("candidate_functions", {})
    # Build: function_full_name -> set of patched lines.
    patched_lines: dict[str, set[int]] = {}
    for fn_full, meta in cand.items():
        lines = set(int(l) for l in meta.get("modified_lines", []) if l)
        if lines and meta.get("role") == "patch":
            patched_lines[fn_full] = lines

    hits: set[str] = set()
    for nid, attrs in G.nodes(data=True):
        fn = attrs.get("function", "")
        if fn not in patched_lines:
            continue
        line = int(attrs.get("line") or 0)
        if line and line in patched_lines[fn]:
            hits.add(nid)
    return hits


def _sink_nodes(G: nx.MultiDiGraph) -> set[str]:
    """Nodes marked as sinks by Step 3."""
    return {nid for nid, a in G.nodes(data=True) if a.get("is_sink")}


# ---------------------------------------------------------------------------
# Internal: directional BFS over the traversable edge set
# ---------------------------------------------------------------------------

def _traverse(
    G: nx.MultiDiGraph,
    sources: set[str],
    *,
    reverse: bool,
    max_hops: int,
) -> set[str]:
    """BFS from every source up to max_hops over TRAVERSAL_EDGE_TYPES.

    Parameters
    ----------
    reverse : False = forward (follow edges as-is)
              True  = backward (follow edges in reversed direction)

    Returns the set of reachable nodes INCLUDING the sources themselves
    (a source trivially reaches itself in 0 hops)."""
    if not sources:
        return set()

    # Pre-filter: a source not in the graph is silently dropped.
    sources = {s for s in sources if s in G}
    if not sources:
        return set()

    reached: set[str] = set(sources)
    # (node, remaining_hops) — BFS semantics: we enqueue at depth d if we
    # haven't seen the node yet OR we have seen it with fewer remaining hops.
    # Using set-based "first visit wins" works because BFS explores in order
    # of shortest hops; a later rediscovery always has <= remaining_hops.
    q: deque[tuple[str, int]] = deque((s, max_hops) for s in sources)
    while q:
        u, hops_left = q.popleft()
        if hops_left <= 0:
            continue
        # Choose which edges to iterate based on direction.
        if reverse:
            # Incoming edges: predecessors with matching edge type become
            # the next nodes to visit.
            neighbors = (
                nu for nu, _, k, d in G.in_edges(u, keys=True, data=True)
                if d.get("edge_type", k) in TRAVERSAL_EDGE_TYPES
            )
        else:
            neighbors = (
                nv for _, nv, k, d in G.out_edges(u, keys=True, data=True)
                if d.get("edge_type", k) in TRAVERSAL_EDGE_TYPES
            )
        for nb in neighbors:
            if nb not in reached:
                reached.add(nb)
                q.append((nb, hops_left - 1))
    return reached


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def compute_slice(
    G: nx.MultiDiGraph,
    *,
    max_hops_backward: int = 10,
    max_hops_forward: int = 10,
) -> SliceReport:
    """Compute in_slice for every node of G and attach a SliceReport.

    Mutates G in place: every node gets attribute `in_slice: bool`.
    Returns the SliceReport (also stashed on G.graph['slice_report']).
    """
    report = SliceReport()

    # Default every node to False so downstream never KeyErrors.
    for nid in G.nodes:
        G.nodes[nid]["in_slice"] = False

    patch = _patch_nodes(G)
    sinks = _sink_nodes(G)
    report.n_patch_nodes = len(patch)
    report.n_sink_nodes = len(sinks)

    if not patch:
        report.skipped = "no patch nodes on this version"
        log.warning("slice: %s", report.skipped)
        G.graph["slice_report"] = report
        return report

    # Sink fallback: empty sinks -> treat patch as implicit sinks so the
    # slice degenerates to "local dataflow neighborhood of patch."
    effective_sinks = sinks
    if not effective_sinks:
        effective_sinks = patch
        report.used_sink_fallback = True
        log.info(
            "slice: no sinks marked; using patch nodes as implicit sinks (%d)",
            len(patch),
        )

    # Two BFSes.
    backward = _traverse(G, effective_sinks, reverse=True,
                         max_hops=max_hops_backward)
    forward = _traverse(G, patch, reverse=False,
                        max_hops=max_hops_forward)
    report.backward_reached = len(backward)
    report.forward_reached = len(forward)

    slice_set = backward & forward

    # Edge case: the intersection can be empty even with both BFSes non-empty
    # if the patch and sink live in disconnected components (in terms of the
    # traversable edge set). In that case the union of the two anchor sets is
    # the most useful minimal slice — it preserves the known-relevant nodes
    # for the label without introducing spurious context. We flag it in the
    # report so eval can filter these cases.
    if not slice_set:
        log.warning(
            "slice: empty intersection (patch=%d, sinks=%d, fwd=%d, bwd=%d); "
            "falling back to union of anchors",
            len(patch), len(effective_sinks),
            report.forward_reached, report.backward_reached,
        )
        slice_set = set(patch) | set(effective_sinks)
        report.skipped = "empty intersection; used anchor-union fallback"

    # Mark the slice.
    cand = G.graph.get("candidate_functions", {})
    role_counts: dict[str, int] = defaultdict(int)
    for nid in slice_set:
        G.nodes[nid]["in_slice"] = True
        fn = G.nodes[nid].get("function", "")
        role = cand.get(fn, {}).get("role", "unknown")
        role_counts[role] += 1

    report.slice_size = len(slice_set)
    report.slice_by_role = dict(role_counts)
    log.info(
        "slice: %d nodes (by role: %s); fwd=%d bwd=%d patch=%d sinks=%d",
        report.slice_size, report.slice_by_role,
        report.forward_reached, report.backward_reached,
        report.n_patch_nodes, report.n_sink_nodes,
    )

    G.graph["slice_report"] = report
    return report
