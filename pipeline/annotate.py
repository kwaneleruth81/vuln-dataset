"""
annotate.py — Step 7 of the pipeline: produce the final per-node dataset.

Takes the fully-processed statement graph (after Steps 1-5) and emits one
record per node matching the deliverable schema:

    id, function, statement, type, depth_cfg, depth_ast,
    variables_used, variables_defined,
    is_patch_related, distance_to_patch, is_cross_function,
    CFG_successors, CFG_predecessors,
    DFG_successors, DFG_predecessors,
    CALL_edges, PARAM_BIND_edges,
    in_loop, in_branch, called_function,
    is_sink, sink_reason,
    role, modified_lines,
    label

Returns a list of dicts, one per node. Serialization format (JSONL /
Parquet / PyG) is left to downstream code.

Key derived fields:
  distance_to_patch  : bidirectional BFS distance over CFG ∪ DFG ∪ CALL ∪
                       PARAM_BIND. Patch nodes have distance 0. Unreachable
                       nodes get None.
  is_patch_related   : distance_to_patch is finite (not None).
  is_cross_function  : node has at least one incoming or outgoing CALL or
                       PARAM_BIND edge.
  label              : 1 if in_slice else 0.
"""

from __future__ import annotations

import logging
from collections import deque

import networkx as nx

log = logging.getLogger(__name__)


TRAVERSAL_EDGE_TYPES: frozenset[str] = frozenset({
    "CFG", "DFG", "CALL", "PARAM_BIND",
})


def _patch_nodes(G: nx.MultiDiGraph) -> set[str]:
    """Identify patch nodes by (function, line) match against modified_lines
    for patch-role candidates. Mirrors slicer.py's definition."""
    cand = G.graph.get("candidate_functions", {})
    patched: dict[str, set[int]] = {}
    for fn_full, meta in cand.items():
        if meta.get("role") != "patch":
            continue
        lines = {int(l) for l in meta.get("modified_lines", []) if l}
        if lines:
            patched[fn_full] = lines
    hits: set[str] = set()
    for nid, a in G.nodes(data=True):
        fn = a.get("function", "")
        if fn not in patched:
            continue
        line = int(a.get("line") or 0)
        if line and line in patched[fn]:
            hits.add(nid)
    return hits


def _bidirectional_distance(
    G: nx.MultiDiGraph, sources: set[str],
) -> dict[str, int]:
    """Multi-source BFS treating the traversable edge set as undirected.
    Returns {node_id: hops}. Sources at distance 0. Unreachable nodes absent."""
    if not sources:
        return {}
    dist: dict[str, int] = {s: 0 for s in sources if s in G}
    q: deque[str] = deque(dist)
    while q:
        u = q.popleft()
        d = dist[u]
        for _, v, k, ed in G.out_edges(u, keys=True, data=True):
            if ed.get("edge_type", k) in TRAVERSAL_EDGE_TYPES and v not in dist:
                dist[v] = d + 1
                q.append(v)
        for v, _, k, ed in G.in_edges(u, keys=True, data=True):
            if ed.get("edge_type", k) in TRAVERSAL_EDGE_TYPES and v not in dist:
                dist[v] = d + 1
                q.append(v)
    return dist


def _neighbors_by_type(
    G: nx.MultiDiGraph, nid: str,
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Return (successors_by_type, predecessors_by_type) keyed by edge type."""
    succ: dict[str, set[str]] = {t: set() for t in TRAVERSAL_EDGE_TYPES}
    pred: dict[str, set[str]] = {t: set() for t in TRAVERSAL_EDGE_TYPES}
    for _, v, k, ed in G.out_edges(nid, keys=True, data=True):
        et = ed.get("edge_type", k)
        if et in succ:
            succ[et].add(v)
    for u, _, k, ed in G.in_edges(nid, keys=True, data=True):
        et = ed.get("edge_type", k)
        if et in pred:
            pred[et].add(u)
    return (
        {t: sorted(s) for t, s in succ.items()},
        {t: sorted(s) for t, s in pred.items()},
    )


def _short_function_name(fn_full: str) -> str:
    """Strip Joern filename prefix: 'file.c:func' -> 'func'."""
    if ":" in fn_full:
        return fn_full.rsplit(":", 1)[-1]
    return fn_full


def annotate_nodes(G: nx.MultiDiGraph) -> list[dict]:
    """Produce the final per-node dataset.

    Preconditions: G has been through Steps 1-5. Returns list of dicts,
    ordered deterministically (function, line, column, joern_id) so re-runs
    on the same graph produce identical `id` assignments.
    """
    patch_id = G.graph.get("patch_id", "unknown")
    version = G.graph.get("version", "unknown")
    cand = G.graph.get("candidate_functions", {})

    patch = _patch_nodes(G)
    dist = _bidirectional_distance(G, patch)
    if not patch:
        log.warning("annotate: no patch nodes; distance_to_patch will be None")

    def _sort_key(nid: str) -> tuple:
        a = G.nodes[nid]
        return (
            a.get("function", ""),
            int(a.get("line") or 0),
            int(a.get("column") or 0),
            str(nid),
        )

    ordered_nids = sorted(G.nodes, key=_sort_key)

    # Canonical id mapping: old joern id -> "{patch_id}:{version}:{ordinal}"
    nid_map: dict[str, str] = {
        old: f"{patch_id}:{version}:{i:05d}"
        for i, old in enumerate(ordered_nids)
    }

    def _rewrite(ids: list[str]) -> list[str]:
        return [nid_map.get(x, x) for x in ids]

    records: list[dict] = []
    for nid in ordered_nids:
        a = G.nodes[nid]
        fn_full = a.get("function", "")
        role_meta = cand.get(fn_full, {})

        succ, pred = _neighbors_by_type(G, nid)

        is_cross_function = bool(
            succ.get("CALL") or pred.get("CALL")
            or succ.get("PARAM_BIND") or pred.get("PARAM_BIND")
        )

        d = dist.get(nid)

        rec = {
            "id": nid_map[nid],
            "patch_id": patch_id,
            "version": version,
            "commit": G.graph.get("commit", ""),
            "function": _short_function_name(fn_full),
            "function_full": fn_full,
            "role": role_meta.get("role", "unknown"),
            "file": role_meta.get("file", ""),
            "modified_lines": list(role_meta.get("modified_lines", [])),

            "statement": a.get("code", ""),
            "type": a.get("stmt_type", "OTHER"),
            "line": int(a.get("line") or 0),

            "depth": int(a.get("depth_cfg", -1)),
            "depth_cfg": int(a.get("depth_cfg", -1)),
            "depth_ast": int(a.get("depth_ast", -1)),

            "variables_used":    list(a.get("variables_used", [])),
            "variables_defined": list(a.get("variables_defined", [])),

            "in_loop":   bool(a.get("in_loop", False)),
            "in_branch": bool(a.get("in_branch", False)),
            "called_function": a.get("called_function"),

            "is_sink":     bool(a.get("is_sink", False)),
            "sink_reason": a.get("sink_reason"),

            "is_patch_related": d is not None,
            "distance_to_patch": d,
            "is_cross_function": is_cross_function,

            "CFG_successors":    _rewrite(succ.get("CFG", [])),
            "CFG_predecessors":  _rewrite(pred.get("CFG", [])),
            "DFG_successors":    _rewrite(succ.get("DFG", [])),
            "DFG_predecessors":  _rewrite(pred.get("DFG", [])),
            "CALL_edges":        _rewrite(succ.get("CALL", [])),
            "CALL_predecessors": _rewrite(pred.get("CALL", [])),
            "PARAM_BIND_edges":        _rewrite(succ.get("PARAM_BIND", [])),
            "PARAM_BIND_predecessors": _rewrite(pred.get("PARAM_BIND", [])),

            "in_slice": bool(a.get("in_slice", False)),
            "label": 1 if a.get("in_slice") else 0,
        }
        records.append(rec)

    n_labeled = sum(1 for r in records if r["label"])
    n_cross = sum(1 for r in records if r["is_cross_function"])
    log.info(
        "annotated %d nodes: %d labeled=1, %d cross-function",
        len(records), n_labeled, n_cross,
    )
    return records
