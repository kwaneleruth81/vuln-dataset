"""Pure-logic tests for Step 2. No Joern required.

Tests the statement classification, statement-hood filter, identifier
collection, and edge-lifting logic by feeding hand-built graphs that mimic
what Joern would produce. Catches regressions in the parts of Step 2 that
don't depend on real CPG output."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import networkx as nx
from pipeline.build_program_graph import (
    _classify_stmt, _is_statement,
    _collect_identifiers, extract_statement_graph,
    _RawCPG,
)

# --- Test 1: stmt_type classification ----------------------------------------

def test_classify():
    cases = [
        (("CALL",    {"name": "memcpy"}),                        "CALL"),
        (("CALL",    {"name": "<operator>.assignment"}),         "ASSIGN"),
        (("CALL",    {"name": "<operator>.addition"}),           "ARITH"),
        (("CALL",    {"name": "<operator>.indirectIndexAccess"}),"INDEX"),
        (("CALL",    {"name": "<operator>.fieldAccess"}),        "FIELD"),
        (("CONTROL_STRUCTURE", {"controlStructureType": "IF"}),  "IF"),
        (("CONTROL_STRUCTURE", {"controlStructureType": "FOR"}), "FOR"),
        (("CONTROL_STRUCTURE", {"controlStructureType": "XYZ"}), "CONTROL"),
        (("RETURN",  {}),                                        "RETURN"),
        (("LOCAL",   {}),                                        "DECL"),
        (("METHOD",  {}),                                        "METHOD_ENTRY"),
        (("BLOCK",   {}),                                        "BLOCK"),
        (("IDENTIFIER", {}),                                     "OTHER"),
    ]
    for (lab, props), want in cases:
        got = _classify_stmt(lab, props)
        assert got == want, f"_classify_stmt({lab}, {props}) = {got!r}, want {want!r}"
    print("test_classify OK")


def test_is_statement():
    # Sub-expressions never become statements; structural types are candidates.
    assert not _is_statement("IDENTIFIER")
    assert not _is_statement("LITERAL")
    assert not _is_statement("FIELD_IDENTIFIER")
    assert _is_statement("CALL")
    assert _is_statement("CONTROL_STRUCTURE")
    assert _is_statement("RETURN")
    assert _is_statement("METHOD")
    assert _is_statement("BLOCK")
    assert _is_statement("LOCAL")
    print("test_is_statement OK")


# --- Test 2: identifier collection on a mocked assignment subtree ------------

def _make_raw(nodes, edges):
    G = nx.MultiDiGraph()
    for nid, attrs in nodes:
        G.add_node(nid, **attrs)
    for u, v, k in edges:
        G.add_edge(u, v, key=k, edge_type=k)
    return _RawCPG(graph=G, method_node_by_name={}, owner={})


def test_collect_identifiers_assignment():
    # Model: x = y + 1
    # CALL(<operator>.assignment)
    #   AST -> IDENTIFIER(x)      # LHS, should be "defined"
    #   AST -> CALL(<operator>.addition)
    #            AST -> IDENTIFIER(y)   # "used"
    #            AST -> LITERAL(1)
    nodes = [
        ("assign", {"_label": "CALL", "name": "<operator>.assignment"}),
        ("lhs",    {"_label": "IDENTIFIER", "name": "x"}),
        ("add",    {"_label": "CALL", "name": "<operator>.addition"}),
        ("y",      {"_label": "IDENTIFIER", "name": "y"}),
        ("one",    {"_label": "LITERAL"}),
    ]
    edges = [
        ("assign", "lhs", "AST"),
        ("assign", "add", "AST"),
        ("add", "y", "AST"),
        ("add", "one", "AST"),
    ]
    raw = _make_raw(nodes, edges)
    used, defined = _collect_identifiers(raw, "assign")
    assert defined == {"x"}, f"defined={defined}"
    assert used == {"y"},    f"used={used}"
    print("test_collect_identifiers_assignment OK")


def test_collect_identifiers_call():
    # Model: foo(a, b)
    # CALL(foo)
    #   AST -> IDENTIFIER(a)
    #   AST -> IDENTIFIER(b)
    nodes = [
        ("call", {"_label": "CALL", "name": "foo"}),
        ("a", {"_label": "IDENTIFIER", "name": "a"}),
        ("b", {"_label": "IDENTIFIER", "name": "b"}),
    ]
    edges = [("call", "a", "AST"), ("call", "b", "AST")]
    raw = _make_raw(nodes, edges)
    used, defined = _collect_identifiers(raw, "call")
    # Non-assignment call: everything is "used".
    assert used == {"a", "b"}, f"used={used}"
    assert defined == set(),   f"defined={defined}"
    print("test_collect_identifiers_call OK")


# --- Test 3: end-to-end statement extraction on a tiny hand-built graph ------

def test_extract_statement_graph_minimal():
    """
    Mimic a single function:
       int f() {
           int x;          // LOCAL declaration, stmt under BLOCK
           x = 1;          // assignment
           return x;       // RETURN
       }

    Joern shape:
       METHOD(f)
         --AST--> BLOCK(body)
                     --AST--> LOCAL(x)
                     --AST--> CALL(<operator>.assignment)
                                --AST--> IDENTIFIER(x)  # LHS
                                --AST--> LITERAL(1)
                     --AST--> RETURN
                                --AST--> IDENTIFIER(x)

    CFG: METHOD -> LOCAL -> assignment -> RETURN
    DFG: assignment --REACHING_DEF--> RETURN  (x flows from def to use)
    """
    nodes = [
        ("m",      {"_label": "METHOD", "function": "f", "name": "f", "fullName": "f"}),
        ("block",  {"_label": "BLOCK",  "function": "f"}),
        ("decl",   {"_label": "LOCAL",  "function": "f", "name": "x", "lineNumber": 2}),
        ("assign", {"_label": "CALL",   "function": "f",
                    "name": "<operator>.assignment", "lineNumber": 3,
                    "code": "x = 1"}),
        ("lhs",    {"_label": "IDENTIFIER", "function": "f", "name": "x"}),
        ("lit",    {"_label": "LITERAL",    "function": "f"}),
        ("ret",    {"_label": "RETURN", "function": "f", "lineNumber": 4,
                    "code": "return x"}),
        ("retid",  {"_label": "IDENTIFIER", "function": "f", "name": "x"}),
    ]
    edges = [
        # AST structure
        ("m", "block", "AST"),
        ("block", "decl", "AST"),
        ("block", "assign", "AST"),
        ("assign", "lhs", "AST"),
        ("assign", "lit", "AST"),
        ("block", "ret", "AST"),
        ("ret", "retid", "AST"),
        # CFG (simplified: METHOD -> first stmt, then linear)
        ("m", "decl", "CFG"),
        ("decl", "assign", "CFG"),
        ("assign", "ret", "CFG"),
        # DFG: assignment defines x, return uses x.
        # Joern emits REACHING_DEF between identifier-level nodes, but the
        # lifter will pull them up to the statement level.
        ("lhs", "retid", "REACHING_DEF"),
    ]
    raw = _make_raw(nodes, edges)
    # Set the method_node_by_name so depth BFS works.
    raw.method_node_by_name["f"] = "m"

    S = extract_statement_graph(raw, worktree=Path("/nonexistent"))

    # Expected statement nodes: m (METHOD_ENTRY), decl, assign, ret.
    # Sub-expressions (lhs, lit, retid, block) should be rolled up, not present.
    assert set(S.nodes) == {"m", "decl", "assign", "ret"}, set(S.nodes)

    # Classifications
    assert S.nodes["m"]["stmt_type"] == "METHOD_ENTRY"
    assert S.nodes["decl"]["stmt_type"] == "DECL"
    assert S.nodes["assign"]["stmt_type"] == "ASSIGN"
    assert S.nodes["ret"]["stmt_type"] == "RETURN"

    # Variables rolled up from sub-expressions
    assert S.nodes["assign"]["variables_defined"] == ["x"], S.nodes["assign"]
    assert S.nodes["assign"]["variables_used"] == [],       S.nodes["assign"]
    assert S.nodes["ret"]["variables_used"] == ["x"],       S.nodes["ret"]

    # CFG edges preserved (METHOD->decl->assign->ret)
    cfg_edges = {(u, v) for u, v, k in S.edges(keys=True) if k == "CFG"}
    assert ("m", "decl") in cfg_edges
    assert ("decl", "assign") in cfg_edges
    assert ("assign", "ret") in cfg_edges

    # DFG: the raw REACHING_DEF between lhs and retid should lift to
    # assign -> ret (lhs's statement ancestor is assign; retid's is ret).
    dfg_edges = {(u, v) for u, v, k in S.edges(keys=True) if k == "DFG"}
    assert ("assign", "ret") in dfg_edges, f"DFG edges: {dfg_edges}"

    # CFG depths: m=0, decl=1, assign=2, ret=3
    assert S.nodes["m"]["depth_cfg"] == 0
    assert S.nodes["decl"]["depth_cfg"] == 1
    assert S.nodes["assign"]["depth_cfg"] == 2
    assert S.nodes["ret"]["depth_cfg"] == 3

    print("test_extract_statement_graph_minimal OK")
    print(f"  nodes: {sorted(S.nodes)}")
    print(f"  edges: {sorted((u,v,k) for u,v,k in S.edges(keys=True))}")


if __name__ == "__main__":
    test_classify()
    test_is_statement()
    test_collect_identifiers_assignment()
    test_collect_identifiers_call()
    test_extract_statement_graph_minimal()
    print("\nAll Step 2 unit tests passed.")
