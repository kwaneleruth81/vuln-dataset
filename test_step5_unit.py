"""Unit tests for Step 5 (multi-function slicing). No Joern required.

Hand-build statement graphs that exercise each slicing branch:
  - Basic: patch -> sink with intermediate node, slice contains all three
  - Hop cap enforced
  - Backward-only node (reaches sink but not reached by patch) excluded
  - Forward-only node (reached by patch but doesn't reach sink) excluded
  - PARAM_BIND traversal crosses function boundary in both directions
  - DFG edge traversal (reversed for backward)
  - No sinks -> fallback to patch-as-sinks
  - No patch nodes -> empty slice, skipped flag set
  - Disconnected patch and sinks -> anchor-union fallback
  - AST edges excluded from traversal
"""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import networkx as nx
from pipeline.slicer import compute_slice, _traverse, TRAVERSAL_EDGE_TYPES


def _mk(stmts, edges, candidate_functions=None):
    """Build a test graph. `stmts` = list of (nid, function, line, is_sink?).
    `edges` = list of (u, v, edge_type)."""
    G = nx.MultiDiGraph()
    for row in stmts:
        nid, fn, line = row[:3]
        is_sink = row[3] if len(row) > 3 else False
        G.add_node(nid, function=fn, line=line,
                   is_sink=is_sink, stmt_type="CALL" if is_sink else "OTHER")
    for u, v, t in edges:
        G.add_edge(u, v, key=t, edge_type=t)
    G.graph["candidate_functions"] = candidate_functions or {}
    return G


# ---------------------------------------------------------------------------
# Basic correctness
# ---------------------------------------------------------------------------

def test_basic_path():
    """patch (n1) --CFG--> mid (n2) --CFG--> sink (n3). All three in slice."""
    G = _mk(
        [("n1", "f", 10), ("n2", "f", 11), ("n3", "f", 12, True)],
        [("n1", "n2", "CFG"), ("n2", "n3", "CFG")],
        candidate_functions={
            "f": {"role": "patch", "modified_lines": [10], "file": "x.c"}
        },
    )
    r = compute_slice(G)
    assert r.slice_size == 3, r
    for n in ("n1", "n2", "n3"):
        assert G.nodes[n]["in_slice"], n
    assert not r.used_sink_fallback
    assert r.skipped is None
    print("test_basic_path OK")


def test_backward_only_excluded():
    """A node that can reach the sink but is NOT reached by the patch is
    EXCLUDED from the slice. The slice is strictly the intersection."""
    G = _mk(
        [("n1", "f", 10), ("x", "f", 50), ("n3", "f", 12, True)],
        # Patch -> sink path (through n1)
        [("n1", "n3", "CFG"),
         # x also reaches sink but isn't reached by the patch
         ("x", "n3", "CFG")],
        candidate_functions={
            "f": {"role": "patch", "modified_lines": [10], "file": "x.c"}
        },
    )
    compute_slice(G)
    assert G.nodes["n1"]["in_slice"]
    assert G.nodes["n3"]["in_slice"]
    assert not G.nodes["x"]["in_slice"], "x is backward-only, must be excluded"
    print("test_backward_only_excluded OK")


def test_forward_only_excluded():
    """A node reached from the patch but not reaching the sink is excluded."""
    G = _mk(
        [("n1", "f", 10), ("dead", "f", 20), ("n3", "f", 12, True)],
        [("n1", "dead", "CFG"),  # patch -> dead, but dead doesn't reach sink
         ("n1", "n3", "CFG")],
        candidate_functions={
            "f": {"role": "patch", "modified_lines": [10], "file": "x.c"}
        },
    )
    compute_slice(G)
    assert G.nodes["n1"]["in_slice"]
    assert G.nodes["n3"]["in_slice"]
    assert not G.nodes["dead"]["in_slice"], "dead is forward-only, must be excluded"
    print("test_forward_only_excluded OK")


# ---------------------------------------------------------------------------
# DFG direction: backward = follow reversed
# ---------------------------------------------------------------------------

def test_dfg_backward_reversed():
    """DFG edge goes def -> use. Backward from a sink USE must reach the DEF
    by following DFG in reverse."""
    G = _mk(
        [("def", "f", 10), ("use_sink", "f", 12, True)],
        [("def", "use_sink", "DFG")],  # def flows to use (sink)
        candidate_functions={
            "f": {"role": "patch", "modified_lines": [10], "file": "x.c"}
        },
    )
    compute_slice(G)
    # def is the patch node (line 10). Sink reaches def via reversed DFG.
    assert G.nodes["def"]["in_slice"]
    assert G.nodes["use_sink"]["in_slice"]
    print("test_dfg_backward_reversed OK")


# ---------------------------------------------------------------------------
# Cross-function via PARAM_BIND
# ---------------------------------------------------------------------------

def test_param_bind_forward_and_backward():
    """Patch in caller -> PARAM_BIND to callee METHOD_ENTRY -> CFG to sink
    inside callee. Slice must cross the function boundary in both BFSes."""
    G = _mk(
        [
            ("caller_patch", "caller", 5),
            ("callee_entry", "callee", 1),
            ("callee_sink",  "callee", 3, True),
        ],
        [
            ("caller_patch", "callee_entry", "PARAM_BIND"),
            ("callee_entry", "callee_sink",  "CFG"),
        ],
        candidate_functions={
            "caller": {"role": "patch", "modified_lines": [5], "file": "c.c"},
            "callee": {"role": "callee", "modified_lines": [], "file": "c.c"},
        },
    )
    r = compute_slice(G)
    assert r.slice_size == 3, r
    for n in ("caller_patch", "callee_entry", "callee_sink"):
        assert G.nodes[n]["in_slice"], n
    # Role breakdown should show both patch and callee represented.
    assert r.slice_by_role.get("patch", 0) >= 1
    assert r.slice_by_role.get("callee", 0) >= 1
    print("test_param_bind_forward_and_backward OK")


def test_call_edge_traversal():
    """Same as above but with a CALL edge rather than PARAM_BIND. Confirms
    both edge types are treated identically for traversal."""
    G = _mk(
        [
            ("caller_patch", "caller", 5),
            ("callee_entry", "callee", 1),
            ("callee_sink",  "callee", 3, True),
        ],
        [
            ("caller_patch", "callee_entry", "CALL"),
            ("callee_entry", "callee_sink",  "CFG"),
        ],
        candidate_functions={
            "caller": {"role": "patch", "modified_lines": [5], "file": "c.c"},
            "callee": {"role": "callee", "modified_lines": [], "file": "c.c"},
        },
    )
    compute_slice(G)
    assert all(G.nodes[n]["in_slice"] for n in
               ("caller_patch", "callee_entry", "callee_sink"))
    print("test_call_edge_traversal OK")


# ---------------------------------------------------------------------------
# Hop cap
# ---------------------------------------------------------------------------

def test_hop_cap_forward():
    """With max_hops_forward=2, a sink 3 hops from the patch is unreachable
    in the forward BFS -> excluded from slice even though it's a sink."""
    G = _mk(
        [
            ("n1", "f", 10),  # patch
            ("n2", "f", 11),
            ("n3", "f", 12),
            ("n4", "f", 13, True),  # sink, 3 hops from n1
        ],
        [("n1", "n2", "CFG"), ("n2", "n3", "CFG"), ("n3", "n4", "CFG")],
        candidate_functions={
            "f": {"role": "patch", "modified_lines": [10], "file": "x.c"}
        },
    )
    r = compute_slice(G, max_hops_forward=2, max_hops_backward=10)
    # Forward set from n1 with cap 2 = {n1, n2, n3}, excludes n4.
    # Backward from n4 = {n4, n3, n2, n1} (within cap 10).
    # Intersection = {n1, n2, n3}.
    assert G.nodes["n1"]["in_slice"]
    assert G.nodes["n2"]["in_slice"]
    assert G.nodes["n3"]["in_slice"]
    assert not G.nodes["n4"]["in_slice"], "n4 beyond forward hop cap"
    print("test_hop_cap_forward OK")


def test_hop_cap_backward():
    """Symmetric: with max_hops_backward=2, a patch 3 hops from the sink is
    unreachable in the backward BFS -> excluded."""
    G = _mk(
        [
            ("n1", "f", 10),  # patch
            ("n2", "f", 11),
            ("n3", "f", 12),
            ("n4", "f", 13, True),  # sink
        ],
        [("n1", "n2", "CFG"), ("n2", "n3", "CFG"), ("n3", "n4", "CFG")],
        candidate_functions={
            "f": {"role": "patch", "modified_lines": [10], "file": "x.c"}
        },
    )
    r = compute_slice(G, max_hops_forward=10, max_hops_backward=2)
    # Backward from n4 with cap 2 = {n4, n3, n2}, excludes n1.
    # Forward from n1 = all four.
    # Intersection = {n2, n3, n4}.
    assert not G.nodes["n1"]["in_slice"], "n1 beyond backward hop cap"
    assert G.nodes["n2"]["in_slice"]
    assert G.nodes["n3"]["in_slice"]
    assert G.nodes["n4"]["in_slice"]
    print("test_hop_cap_backward OK")


# ---------------------------------------------------------------------------
# Fallbacks
# ---------------------------------------------------------------------------

def test_no_sinks_fallback_to_patch():
    """With zero sinks, we treat patch as implicit sinks.
    Slice = Backward(patch) ∩ Forward(patch) = nodes that both reach AND are
    reached by patch. For a simple chain, that's just the patch itself."""
    G = _mk(
        [("n1", "f", 10), ("n2", "f", 11)],
        [("n1", "n2", "CFG")],
        candidate_functions={
            "f": {"role": "patch", "modified_lines": [10], "file": "x.c"}
        },
    )
    r = compute_slice(G)
    assert r.used_sink_fallback is True
    # n1 is the patch. Forward reaches {n1, n2}. Backward from n1 = {n1}.
    # Intersection = {n1}.
    assert G.nodes["n1"]["in_slice"]
    assert not G.nodes["n2"]["in_slice"]
    print("test_no_sinks_fallback_to_patch OK")


def test_no_patch_empty_slice():
    """If no nodes are on patched lines, slice is empty and skipped flag set."""
    G = _mk(
        [("n1", "f", 10), ("n2", "f", 11, True)],
        [("n1", "n2", "CFG")],
        candidate_functions={
            "f": {"role": "patch", "modified_lines": [99], "file": "x.c"}
            # patched line 99 doesn't match any node
        },
    )
    r = compute_slice(G)
    assert r.slice_size == 0
    assert r.skipped is not None
    assert "no patch nodes" in r.skipped.lower()
    assert all(not G.nodes[n]["in_slice"] for n in G)
    print("test_no_patch_empty_slice OK")


def test_disconnected_patch_and_sink():
    """Patch and sink live in totally disconnected components. The anchor-
    union fallback kicks in so we at least preserve the known-relevant
    anchor nodes as the slice."""
    G = _mk(
        [
            ("p", "f", 10),
            ("s", "g", 20, True),
            # No edges between p and s at all.
        ],
        [],
        candidate_functions={
            "f": {"role": "patch", "modified_lines": [10], "file": "x.c"},
            "g": {"role": "callee", "modified_lines": [], "file": "y.c"},
        },
    )
    r = compute_slice(G)
    # Both p and s should be in slice via anchor-union.
    assert G.nodes["p"]["in_slice"]
    assert G.nodes["s"]["in_slice"]
    assert r.skipped is not None and "intersection" in r.skipped.lower()
    print("test_disconnected_patch_and_sink OK")


# ---------------------------------------------------------------------------
# AST edges are NOT traversed
# ---------------------------------------------------------------------------

def test_ast_edges_not_traversed():
    """Only CFG/DFG/CALL/PARAM_BIND are traversed. An AST-only path between
    patch and sink should NOT produce a slice."""
    G = _mk(
        [("p", "f", 10), ("s", "f", 20, True)],
        [("p", "s", "AST")],  # AST only, no semantic edge
        candidate_functions={
            "f": {"role": "patch", "modified_lines": [10], "file": "x.c"}
        },
    )
    r = compute_slice(G)
    # No CFG/DFG/CALL/PARAM_BIND connection, so forward BFS from p returns {p}
    # and backward BFS from s returns {s}. Intersection is empty.
    # With the disconnection fallback, both end up in the anchor union.
    assert G.nodes["p"]["in_slice"], "anchor-union fallback should include patch"
    assert G.nodes["s"]["in_slice"], "anchor-union fallback should include sink"
    assert r.skipped is not None
    print("test_ast_edges_not_traversed OK")


# ---------------------------------------------------------------------------
# Traversal helper direct tests
# ---------------------------------------------------------------------------

def test_traverse_self_inclusion():
    """A source node is always in its own reachable set (0 hops)."""
    G = nx.MultiDiGraph()
    G.add_node("a")
    r = _traverse(G, {"a"}, reverse=False, max_hops=5)
    assert r == {"a"}
    print("test_traverse_self_inclusion OK")


def test_traverse_max_hops_zero():
    """max_hops=0 means only the sources themselves."""
    G = nx.MultiDiGraph()
    G.add_node("a"); G.add_node("b")
    G.add_edge("a", "b", key="CFG", edge_type="CFG")
    r = _traverse(G, {"a"}, reverse=False, max_hops=0)
    assert r == {"a"}, r
    print("test_traverse_max_hops_zero OK")


def test_traverse_missing_source_silently_dropped():
    """Sources not in G are dropped without error."""
    G = nx.MultiDiGraph()
    G.add_node("a")
    r = _traverse(G, {"a", "nonexistent"}, reverse=False, max_hops=5)
    assert r == {"a"}
    print("test_traverse_missing_source_silently_dropped OK")


if __name__ == "__main__":
    test_basic_path()
    test_backward_only_excluded()
    test_forward_only_excluded()
    test_dfg_backward_reversed()
    test_param_bind_forward_and_backward()
    test_call_edge_traversal()
    test_hop_cap_forward()
    test_hop_cap_backward()
    test_no_sinks_fallback_to_patch()
    test_no_patch_empty_slice()
    test_disconnected_patch_and_sink()
    test_ast_edges_not_traversed()
    test_traverse_self_inclusion()
    test_traverse_max_hops_zero()
    test_traverse_missing_source_silently_dropped()
    print("\nAll Step 5 unit tests passed.")
