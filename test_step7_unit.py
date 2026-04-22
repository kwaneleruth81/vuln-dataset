"""Unit tests for Step 7 (annotate_nodes). No Joern required.

Validates:
  - Every schema field is populated
  - distance_to_patch is bidirectional, finite for reachable, None for not
  - is_patch_related tracks distance_to_patch
  - is_cross_function detects CALL/PARAM_BIND touch
  - Canonical id format is stable across runs
  - Neighbor lists are rewritten to canonical ids
  - Ordering is deterministic (function, line, column, joern_id)
  - label comes from in_slice
  - Unreachable nodes get None for distance
  - AST edges don't count for distance or cross-function detection
"""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import networkx as nx
from pipeline.annotate import (
    annotate_nodes, _bidirectional_distance, _short_function_name,
)


def _mk(stmts, edges, patch_id="p1", version="vulnerable",
        candidate_functions=None):
    """stmts: (nid, function, line, [attrs...])"""
    G = nx.MultiDiGraph()
    for row in stmts:
        nid, fn, line = row[:3]
        extra = row[3] if len(row) > 3 else {}
        attrs = dict(function=fn, line=line, stmt_type="OTHER",
                     code=f"code_{nid}", column=0,
                     depth_cfg=-1, depth_ast=-1,
                     variables_used=[], variables_defined=[],
                     in_loop=False, in_branch=False, called_function=None,
                     is_sink=False, sink_reason=None,
                     in_slice=False)
        attrs.update(extra)
        G.add_node(nid, **attrs)
    for u, v, t in edges:
        G.add_edge(u, v, key=t, edge_type=t)
    G.graph["candidate_functions"] = candidate_functions or {}
    G.graph["patch_id"] = patch_id
    G.graph["version"] = version
    return G


def test_short_function_name():
    assert _short_function_name("foo") == "foo"
    assert _short_function_name("parser.c:parse_header") == "parse_header"
    assert _short_function_name("src/foo.c:bar") == "bar"
    assert _short_function_name("a:b:c") == "c"
    print("test_short_function_name OK")


def test_bidirectional_distance():
    G = _mk(
        [("a", "f", 1), ("b", "f", 2), ("c", "f", 3)],
        [("a", "b", "CFG"), ("c", "b", "CFG")],
    )
    dist = _bidirectional_distance(G, {"a"})
    assert dist == {"a": 0, "b": 1, "c": 2}, dist
    print("test_bidirectional_distance OK")


def test_distance_no_sources():
    G = _mk([("a", "f", 1)], [])
    assert _bidirectional_distance(G, set()) == {}
    print("test_distance_no_sources OK")


def test_distance_respects_edge_types():
    G = _mk(
        [("a", "f", 1), ("b", "f", 2), ("c", "f", 3)],
        [("a", "b", "AST"), ("b", "c", "CFG")],
    )
    dist = _bidirectional_distance(G, {"a"})
    assert dist == {"a": 0}, dist
    print("test_distance_respects_edge_types OK")


def test_annotate_schema_completeness():
    G = _mk(
        [("n1", "f", 10, {"stmt_type": "ASSIGN", "in_slice": True})],
        [],
        candidate_functions={
            "f": {"role": "patch", "modified_lines": [10], "file": "x.c"}
        },
    )
    recs = annotate_nodes(G)
    assert len(recs) == 1
    r = recs[0]
    expected = {
        "id", "function", "function_full", "role", "modified_lines",
        "statement", "type", "line",
        "depth_cfg", "depth_ast",
        "variables_used", "variables_defined",
        "in_loop", "in_branch", "called_function",
        "is_sink", "sink_reason",
        "is_patch_related", "distance_to_patch", "is_cross_function",
        "CFG_successors", "CFG_predecessors",
        "DFG_successors", "DFG_predecessors",
        "CALL_edges", "CALL_predecessors",
        "PARAM_BIND_edges", "PARAM_BIND_predecessors",
        "label",
    }
    missing = expected - set(r.keys())
    extra = set(r.keys()) - expected
    assert not missing, f"missing fields: {missing}"
    assert not extra, f"extra fields: {extra}"
    print("test_annotate_schema_completeness OK")


def test_annotate_canonical_ids():
    G = _mk(
        [("n_B", "f", 20), ("n_A", "f", 10)],
        [("n_A", "n_B", "CFG")],
        patch_id="cve/demo", version="fixed",
        candidate_functions={
            "f": {"role": "patch", "modified_lines": [10], "file": "x.c"}
        },
    )
    recs = annotate_nodes(G)
    assert recs[0]["id"] == "cve/demo:fixed:00000"
    assert recs[1]["id"] == "cve/demo:fixed:00001"
    assert recs[0]["line"] == 10
    assert recs[1]["line"] == 20
    recs2 = annotate_nodes(G)
    assert [r["id"] for r in recs] == [r["id"] for r in recs2]
    print("test_annotate_canonical_ids OK")


def test_annotate_neighbor_rewriting():
    G = _mk(
        [("n_A", "f", 10), ("n_B", "f", 20)],
        [("n_A", "n_B", "CFG")],
        candidate_functions={
            "f": {"role": "patch", "modified_lines": [10], "file": "x.c"}
        },
    )
    recs = annotate_nodes(G)
    a, b = recs
    assert a["CFG_successors"] == [b["id"]], a["CFG_successors"]
    assert b["CFG_predecessors"] == [a["id"]], b["CFG_predecessors"]
    print("test_annotate_neighbor_rewriting OK")


def test_annotate_distance_and_patch_related():
    G = _mk(
        [
            ("p", "f", 10),
            ("m", "f", 11),
            ("s", "f", 12),
            ("x", "g", 50),
        ],
        [("p", "m", "CFG"), ("m", "s", "CFG")],
        candidate_functions={
            "f": {"role": "patch", "modified_lines": [10], "file": "x.c"},
            "g": {"role": "callee", "modified_lines": [], "file": "y.c"},
        },
    )
    recs = {r["line"]: r for r in annotate_nodes(G)}
    assert recs[10]["distance_to_patch"] == 0
    assert recs[10]["is_patch_related"] is True
    assert recs[11]["distance_to_patch"] == 1
    assert recs[12]["distance_to_patch"] == 2
    assert recs[50]["distance_to_patch"] is None
    assert recs[50]["is_patch_related"] is False
    print("test_annotate_distance_and_patch_related OK")


def test_annotate_is_cross_function():
    G = _mk(
        [
            ("caller", "f", 10),
            ("callee_entry", "g", 1),
            ("local",  "f", 11),
        ],
        [
            ("caller", "callee_entry", "PARAM_BIND"),
            ("caller", "local", "CFG"),
        ],
        candidate_functions={
            "f": {"role": "patch", "modified_lines": [10], "file": "x.c"},
            "g": {"role": "callee", "modified_lines": [], "file": "y.c"},
        },
    )
    recs = {r["line"]: r for r in annotate_nodes(G)}
    assert recs[10]["is_cross_function"] is True
    assert recs[1]["is_cross_function"] is True
    assert recs[11]["is_cross_function"] is False
    print("test_annotate_is_cross_function OK")


def test_annotate_label_follows_in_slice():
    G = _mk(
        [
            ("a", "f", 10, {"in_slice": True}),
            ("b", "f", 11, {"in_slice": False}),
        ],
        [],
        candidate_functions={
            "f": {"role": "patch", "modified_lines": [10], "file": "x.c"}
        },
    )
    recs = {r["line"]: r for r in annotate_nodes(G)}
    assert recs[10]["label"] == 1
    assert recs[11]["label"] == 0
    print("test_annotate_label_follows_in_slice OK")


def test_annotate_empty_patch_produces_none_distance():
    G = _mk(
        [("n1", "f", 10)],
        [],
        candidate_functions={
            "f": {"role": "caller", "modified_lines": [], "file": "x.c"}
        },
    )
    recs = annotate_nodes(G)
    assert recs[0]["distance_to_patch"] is None
    assert recs[0]["is_patch_related"] is False
    print("test_annotate_empty_patch_produces_none_distance OK")


def test_annotate_cross_function_via_call_edges():
    G = _mk(
        [("caller", "f", 10), ("callee", "g", 1)],
        [("caller", "callee", "CALL")],
        candidate_functions={
            "f": {"role": "patch", "modified_lines": [10], "file": "x.c"},
            "g": {"role": "callee", "modified_lines": [], "file": "y.c"},
        },
    )
    recs = {r["function"]: r for r in annotate_nodes(G)}
    assert recs["f"]["is_cross_function"]
    assert recs["g"]["is_cross_function"]
    assert recs["f"]["CALL_edges"] == [recs["g"]["id"]]
    print("test_annotate_cross_function_via_call_edges OK")


def test_annotate_modified_lines_passthrough():
    G = _mk(
        [("a", "f", 10), ("b", "f", 11)],
        [],
        candidate_functions={
            "f": {"role": "patch", "modified_lines": [10, 11], "file": "x.c"}
        },
    )
    recs = annotate_nodes(G)
    for r in recs:
        assert r["modified_lines"] == [10, 11]
    print("test_annotate_modified_lines_passthrough OK")


def test_annotate_variables_split_preserved():
    G = _mk(
        [("assign", "f", 10, {
            "stmt_type": "ASSIGN",
            "variables_used": ["y"],
            "variables_defined": ["x"],
        })],
        [],
        candidate_functions={
            "f": {"role": "patch", "modified_lines": [10], "file": "x.c"}
        },
    )
    r = annotate_nodes(G)[0]
    assert r["variables_used"] == ["y"]
    assert r["variables_defined"] == ["x"]
    assert "variables" not in r
    print("test_annotate_variables_split_preserved OK")


if __name__ == "__main__":
    test_short_function_name()
    test_bidirectional_distance()
    test_distance_no_sources()
    test_distance_respects_edge_types()
    test_annotate_schema_completeness()
    test_annotate_canonical_ids()
    test_annotate_neighbor_rewriting()
    test_annotate_distance_and_patch_related()
    test_annotate_is_cross_function()
    test_annotate_label_follows_in_slice()
    test_annotate_empty_patch_produces_none_distance()
    test_annotate_cross_function_via_call_edges()
    test_annotate_modified_lines_passthrough()
    test_annotate_variables_split_preserved()
    print("\nAll Step 7 unit tests passed.")
