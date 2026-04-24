"""
build_program_graph.py — Step 2 of the pipeline.

Given a CPGHandle and a Step1Result, build a single in-memory program graph
covering ALL candidate functions for that commit version, with:

    Nodes  : coarse statement-level nodes (one per executable statement)
             attrs: function, line, column, stmt_type, ast_type, code,
                    depth_ast, depth_cfg, variables_used, variables_defined,
                    called_function, in_loop, in_branch
    Edges  : CFG           (intra-procedural control flow, from Joern)
             DFG           (intra-procedural reaching-def, from Joern)
             CALL          (caller-statement -> callee METHOD node)
             PARAM_BIND    (argument-at-call-site -> callee's formal parameter)

The graph is a networkx.MultiDiGraph with edge keys = edge_type so that
(u, v, "CFG") and (u, v, "DFG") can coexist.

This module is structured as three passes so each is testable in isolation:
    1. load_cpg_subgraph      : GraphSON -> raw CPG for our methods only
    2. extract_statement_graph: raw CPG  -> coarse statement graph
    3. augment_param_bindings : add PARAM_BIND edges at call sites
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path

import networkx as nx  # pip install networkx

from .cpg_cache import CPGHandle
from ._cpg_loader import load_cpg_graph
from .find_candidates import Step1Result, CandidateFunction

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pass 1: load the raw Joern CPG, scoped to our candidate methods
# ---------------------------------------------------------------------------

@dataclass
class _RawCPG:
    """Everything we need from Joern's export to build the statement graph.

    We keep the raw graph (with all node types and edges) scoped to nodes
    owned by candidate methods, plus the METHOD nodes themselves and their
    METHOD_PARAMETER_IN nodes (needed for PARAM_BIND edges even when the
    parameter is never used in the body)."""
    graph: nx.MultiDiGraph
    # method_full_name -> method_node_id
    method_node_by_name: dict[str, str]
    # node_id -> method_full_name (ownership map)
    owner: dict[str, str]


def load_cpg_subgraph(
    handle: CPGHandle,
    step1: Step1Result,
) -> _RawCPG:
    """Read the Joern graphml export and return a subgraph containing only
    nodes owned by candidate functions. Cross-function CALL edges whose
    target is a candidate method are preserved; other outbound CALL edges
    are dropped (we don't care about calls to non-candidates for Step 2)."""

    want_methods = {cf.method_full_name for cf in step1.candidate_functions}
    if not want_methods:
        raise ValueError("step1 has no candidate functions to build a graph for")

    full_graph = _load_cpg_graphml(handle.graph_dir)

    method_node_by_name: dict[str, str] = {}
    owner: dict[str, str] = {}

    def _first(attrs: dict, *keys: str, default=""):
        for k in keys:
            if k in attrs and attrs[k] not in (None, ""):
                return attrs[k]
        return default

    # --- Find METHOD nodes for our candidates ----------------------------
    for nid, attrs in full_graph.nodes(data=True):
        if attrs.get("_label") != "METHOD":
            continue
        full_name = str(_first(attrs, "FULL_NAME", "fullName",
                               default=_first(attrs, "NAME", "name", default="")))
        if full_name in want_methods:
            method_node_by_name[full_name] = str(nid)
            owner[str(nid)] = full_name

    missing = want_methods - method_node_by_name.keys()
    if missing:
        log.warning("candidate methods not found in CPG: %s", sorted(missing)[:5])

    # --- Propagate ownership via CONTAINS + AST edges --------------------
    adj: dict[str, list[str]] = defaultdict(list)
    for u, v, k in full_graph.edges(keys=True):
        if k in ("CONTAINS", "AST"):
            adj[str(u)].append(str(v))

    for full_name, method_nid in list(method_node_by_name.items()):
        stack = [method_nid]
        while stack:
            cur = stack.pop()
            for child in adj[cur]:
                if child not in owner:
                    owner[child] = full_name
                    stack.append(child)

    # --- Build the subgraph: copy owned nodes, filter edges --------------
    G = nx.MultiDiGraph()
    for nid, full_name in owner.items():
        attrs = full_graph.nodes.get(nid, {})
        if not attrs:
            continue
        # Copy all attributes; add `function` (our tag) on top.
        copy_attrs = {k: v for k, v in attrs.items() if k != "function"}
        G.add_node(nid, function=full_name, **copy_attrs)

    kept = 0
    for u, v, k, attrs in full_graph.edges(keys=True, data=True):
        us, vs = str(u), str(v)
        u_in, v_in = us in owner, vs in owner
        if k == "CALL":
            # Cross-function calls: keep only if target is also a candidate.
            if u_in and v_in:
                G.add_edge(us, vs, key=k, edge_type=k, **attrs)
                kept += 1
        elif u_in and v_in:
            G.add_edge(us, vs, key=k, edge_type=k, **attrs)
            kept += 1

    log.info(
        "loaded CPG subgraph: %d nodes, %d edges (methods: %d/%d)",
        G.number_of_nodes(), kept,
        len(method_node_by_name), len(want_methods),
    )
    return _RawCPG(graph=G, method_node_by_name=method_node_by_name, owner=owner)


def _load_cpg_graphml(graph_dir: Path) -> "nx.MultiDiGraph":
    """Load the Joern neo4jcsv export in graph_dir into a NetworkX MultiDiGraph."""
    return load_cpg_graph(graph_dir)


# ---------------------------------------------------------------------------
# Pass 2: raw CPG -> coarse statement-level graph
# ---------------------------------------------------------------------------
#
# Statement-node rule (locked spec): a node is a "statement" if it's
#   (a) a direct AST child of a BLOCK node, OR
#   (b) a CONTROL_STRUCTURE (if/while/for/switch/etc.) — its condition is
#       folded into the statement, its body is a BLOCK whose children are
#       their own statements, OR
#   (c) a RETURN node.
#
# Everything else — IDENTIFIERs, LITERALs, operator CALLs, FIELD_IDENTIFIERs,
# LOCALs for pure declarations without initializer — is a sub-expression that
# gets rolled UP into its enclosing statement's attributes.
#
# Note: Joern models operators (assignment, arithmetic, field access, deref,
# etc.) as CALL nodes whose `name` starts with "<operator>.". A plain CALL
# whose name doesn't start with "<operator>." is a real function call. Both
# can be top-level statements if they're direct children of a BLOCK (e.g.,
# `foo();` or `x = 1;`).

# Joern node labels we treat as "belongs to a sub-expression and never
# appears as a statement on its own". Everything not in this set is evaluated
# for statement-hood by its parent relationship.
_SUBEXPR_LABELS = frozenset({
    "IDENTIFIER", "LITERAL", "FIELD_IDENTIFIER", "METHOD_PARAMETER_IN",
    "METHOD_PARAMETER_OUT", "METHOD_RETURN", "TYPE_REF", "MEMBER",
    "MODIFIER", "ANNOTATION", "ANNOTATION_LITERAL", "NAMESPACE_BLOCK",
})

# Map: Joern label (+ optional controlStructureType) -> normalized stmt_type
_CONTROL_STRUCT_MAP = {
    "IF": "IF", "ELSE": "ELSE", "FOR": "FOR", "WHILE": "WHILE",
    "DO": "DO_WHILE", "SWITCH": "SWITCH", "BREAK": "BREAK",
    "CONTINUE": "CONTINUE", "GOTO": "GOTO", "TRY": "TRY", "CATCH": "CATCH",
}

# Joern's operator pseudo-functions. Any CALL with name in this map is
# classified by the mapped stmt_type instead of as "CALL".
_OPERATOR_TO_STMT = {
    "<operator>.assignment":           "ASSIGN",
    "<operator>.assignmentPlus":       "ASSIGN",
    "<operator>.assignmentMinus":      "ASSIGN",
    "<operator>.assignmentMultiplication": "ASSIGN",
    "<operator>.assignmentDivision":   "ASSIGN",
    "<operator>.assignmentModulo":     "ASSIGN",
    "<operator>.assignmentShiftLeft":  "ASSIGN",
    "<operator>.assignmentArithmeticShiftRight": "ASSIGN",
    "<operator>.assignmentOr":         "ASSIGN",
    "<operator>.assignmentAnd":        "ASSIGN",
    "<operator>.assignmentXor":        "ASSIGN",
    "<operator>.addition":             "ARITH",
    "<operator>.subtraction":          "ARITH",
    "<operator>.multiplication":       "ARITH",
    "<operator>.division":             "ARITH",
    "<operator>.modulo":               "ARITH",
    "<operator>.logicalAnd":           "LOGICAL",
    "<operator>.logicalOr":            "LOGICAL",
    "<operator>.logicalNot":           "LOGICAL",
    "<operator>.equals":               "COMPARE",
    "<operator>.notEquals":            "COMPARE",
    "<operator>.lessThan":             "COMPARE",
    "<operator>.greaterThan":          "COMPARE",
    "<operator>.lessEqualsThan":       "COMPARE",
    "<operator>.greaterEqualsThan":    "COMPARE",
    "<operator>.indirectIndexAccess":  "INDEX",
    "<operator>.indexAccess":          "INDEX",
    "<operator>.fieldAccess":          "FIELD",
    "<operator>.indirectFieldAccess":  "FIELD",
    "<operator>.indirection":          "DEREF",
    "<operator>.addressOf":            "ADDROF",
    "<operator>.cast":                 "CAST",
    "<operator>.conditional":          "TERNARY",
    "<operator>.preIncrement":         "ARITH",
    "<operator>.postIncrement":        "ARITH",
    "<operator>.preDecrement":         "ARITH",
    "<operator>.postDecrement":        "ARITH",
}


def _classify_stmt(label: str, props: dict) -> str:
    """Return the normalized stmt_type for a node. Matches the schema enum."""
    if label == "CALL":
        name = props.get("name", "") or ""
        return _OPERATOR_TO_STMT.get(name, "CALL")
    if label == "CONTROL_STRUCTURE":
        return _CONTROL_STRUCT_MAP.get(
            props.get("controlStructureType", ""), "CONTROL"
        )
    if label == "RETURN":
        return "RETURN"
    if label == "LOCAL":
        return "DECL"
    if label == "BLOCK":
        return "BLOCK"
    if label == "METHOD":
        return "METHOD_ENTRY"
    return "OTHER"


def _is_statement(label: str) -> bool:
    """Is this node eligible to be a statement, given Joern's typing?

    We use the rule: any non-sub-expression label is ELIGIBLE; whether it
    actually IS a statement depends on its structural position (direct child
    of BLOCK, or a CONTROL_STRUCTURE/RETURN). That positional check happens
    in extract_statement_graph — this helper is the first filter."""
    return label not in _SUBEXPR_LABELS


# ---------------------------------------------------------------------------

def _build_ast_parent_map(raw: _RawCPG) -> dict[str, str]:
    """Return node_id -> parent_node_id along AST edges."""
    parent: dict[str, str] = {}
    for u, v, k in raw.graph.edges(keys=True):
        if k == "AST":
            parent[v] = u
    return parent


def _read_source_line(worktree: Path, filename: str, line: int) -> str:
    """Best-effort fallback when Joern's `code` property is missing/empty."""
    if not filename or not line:
        return ""
    p = worktree / filename
    try:
        with p.open() as f:
            for i, txt in enumerate(f, start=1):
                if i == line:
                    return txt.rstrip("\n")
    except OSError:
        pass
    return ""


def _collect_identifiers(
    raw: _RawCPG, root: str, *, max_nodes: int = 2000,
) -> tuple[set[str], set[str]]:
    """Walk the AST subtree rooted at `root` and return
    (variables_used, variables_defined).

    Conventions:
      * Any IDENTIFIER we encounter goes to variables_used by default.
      * If the root is an assignment (`<operator>.assignment*`) or the LHS of
        one, its leftmost IDENTIFIER descendant is moved to variables_defined.
      * LOCAL (declaration) nodes contribute their `name` to variables_defined.

    This is coarse but matches how most Joern-based extractors in the
    literature handle it. True def/use precision comes from the DFG edges;
    these attribute sets are for features/embeddings, not ground truth.
    """
    used: set[str] = set()
    defined: set[str] = set()
    # Bounded BFS so a pathological deep subtree can't blow up.
    q = deque([root])
    seen: set[str] = {root}
    count = 0
    while q and count < max_nodes:
        cur = q.popleft()
        count += 1
        attrs = raw.graph.nodes.get(cur, {})
        lab = attrs.get("_label", "")
        if lab == "IDENTIFIER":
            n = attrs.get("name", "")
            if n:
                used.add(n)
        elif lab == "LOCAL":
            n = attrs.get("name", "")
            if n:
                defined.add(n)
        for _, child, k in raw.graph.out_edges(cur, keys=True):
            if k == "AST" and child not in seen:
                seen.add(child)
                q.append(child)

    # Assignment: LHS identifier moves from used -> defined.
    root_attrs = raw.graph.nodes.get(root, {})
    if root_attrs.get("_label") == "CALL" and \
       (root_attrs.get("name") or "").startswith("<operator>.assignment"):
        # First AST child = LHS. Its leftmost IDENTIFIER descendant is the
        # defined variable (handles simple assignments; misses complex lvalues
        # like `a[i] = x` where we'd arguably want `a` too — acceptable for v1).
        ast_children = [v for _, v, k in raw.graph.out_edges(root, keys=True) if k == "AST"]
        if ast_children:
            lhs = ast_children[0]
            sub = deque([lhs])
            while sub:
                cur = sub.popleft()
                a = raw.graph.nodes.get(cur, {})
                if a.get("_label") == "IDENTIFIER":
                    n = a.get("name", "")
                    if n:
                        defined.add(n)
                        used.discard(n)
                    break
                for _, ch, k in raw.graph.out_edges(cur, keys=True):
                    if k == "AST":
                        sub.append(ch)
    return used, defined


def _compute_depths(
    raw: _RawCPG, method_node_id: str, stmt_ids: set[str],
) -> tuple[dict[str, int], dict[str, int]]:
    """Compute AST depth and CFG depth for each statement node.

    AST depth: shortest hops from METHOD node via AST edges.
    CFG depth: shortest hops from METHOD node via CFG edges. The METHOD
    node itself has a CFG edge to the first statement in Joern's model.
    """
    ast_depth: dict[str, int] = {method_node_id: 0}
    q = deque([method_node_id])
    while q:
        u = q.popleft()
        for _, v, k in raw.graph.out_edges(u, keys=True):
            if k == "AST" and v not in ast_depth:
                ast_depth[v] = ast_depth[u] + 1
                q.append(v)

    cfg_depth: dict[str, int] = {method_node_id: 0}
    q = deque([method_node_id])
    while q:
        u = q.popleft()
        for _, v, k in raw.graph.out_edges(u, keys=True):
            if k == "CFG" and v not in cfg_depth:
                cfg_depth[v] = cfg_depth[u] + 1
                q.append(v)

    # Restrict to the stmt set we actually care about.
    return (
        {n: ast_depth.get(n, -1) for n in stmt_ids},
        {n: cfg_depth.get(n, -1) for n in stmt_ids},
    )


def _in_loop_or_branch(
    parent: dict[str, str], raw: _RawCPG, stmt: str,
) -> tuple[bool, bool]:
    """Walk up AST parents and check whether this statement sits inside a
    loop or inside a conditional branch."""
    in_loop = in_branch = False
    cur = parent.get(stmt)
    hops = 0
    while cur is not None and hops < 64:
        attrs = raw.graph.nodes.get(cur, {})
        if attrs.get("_label") == "CONTROL_STRUCTURE":
            cst = attrs.get("controlStructureType", "")
            if cst in ("FOR", "WHILE", "DO"):
                in_loop = True
            elif cst in ("IF", "ELSE", "SWITCH"):
                in_branch = True
        cur = parent.get(cur)
        hops += 1
    return in_loop, in_branch


def extract_statement_graph(
    raw: _RawCPG,
    worktree: Path,
    *,
    max_stmts_warn: int = 1000,
) -> nx.MultiDiGraph:
    """Collapse the raw CPG into a coarse statement-level graph.

    Preserved edges (only between statement nodes, not between sub-expressions):
      CFG          from Joern
      REACHING_DEF from Joern, relabeled to 'DFG' on the output
      CALL         a statement that issues a call -> the callee METHOD (node
                   remains a statement node of type METHOD_ENTRY)

    Everything else from raw.graph is discarded (AST structure, literals,
    identifiers, operator CALLs are rolled up into attributes).
    """
    parent = _build_ast_parent_map(raw)

    # Step A: decide which raw nodes become statement nodes.
    # Rule: node N is a statement iff
    #   (a) N is a METHOD (becomes a METHOD_ENTRY statement — serves as graph
    #       anchor and call target), OR
    #   (b) N is a CONTROL_STRUCTURE or RETURN, OR
    #   (c) N's AST parent is a BLOCK (making N a top-level statement within
    #       that block).
    # And N must not be a sub-expression label.
    stmt_ids: set[str] = set()
    for nid, attrs in raw.graph.nodes(data=True):
        label = attrs.get("_label", "")
        if not _is_statement(label):
            continue
        if label == "METHOD":
            stmt_ids.add(nid)
            continue
        if label in ("CONTROL_STRUCTURE", "RETURN"):
            stmt_ids.add(nid)
            continue
        p = parent.get(nid)
        if p and raw.graph.nodes[p].get("_label") == "BLOCK":
            stmt_ids.add(nid)

    # Step B: build the output graph with statement nodes + rolled-up attrs.
    S = nx.MultiDiGraph()

    # Per-method depth maps — one BFS per method.
    # (Running one big BFS across all methods would conflate their entries.)
    depths_by_method: dict[str, tuple[dict[str, int], dict[str, int]]] = {}
    method_ids = {nid for nid in stmt_ids
                  if raw.graph.nodes[nid].get("_label") == "METHOD"}
    stmts_in_method = defaultdict(set)
    for sid in stmt_ids:
        fn = raw.graph.nodes[sid].get("function", "")
        stmts_in_method[fn].add(sid)

    for m_nid in method_ids:
        fn = raw.graph.nodes[m_nid].get("function", "")
        ast_d, cfg_d = _compute_depths(raw, m_nid, stmts_in_method[fn])
        depths_by_method[fn] = (ast_d, cfg_d)

    for sid in stmt_ids:
        attrs = raw.graph.nodes[sid]
        label = attrs.get("_label", "UNKNOWN")
        fn = attrs.get("function", "")

        stmt_type = _classify_stmt(label, attrs)
        code = attrs.get("code", "")
        line = int(attrs.get("lineNumber") or 0)
        col = int(attrs.get("columnNumber") or 0)

        # Source-read fallback for empty `code`.
        if not code and line:
            filename = attrs.get("filename") or ""
            if not filename:
                # METHOD nodes have `filename`; statements often don't — look up
                # the owning METHOD and use its filename.
                m_nid = raw.method_node_by_name.get(fn)
                if m_nid:
                    filename = raw.graph.nodes[m_nid].get("filename", "")
            code = _read_source_line(worktree, filename, line)

        used, defined = _collect_identifiers(raw, sid)

        ast_d, cfg_d = depths_by_method.get(fn, ({}, {}))
        in_loop, in_branch = _in_loop_or_branch(parent, raw, sid)

        called_function: str | None = None
        if label == "CALL":
            name = attrs.get("name", "") or ""
            if not name.startswith("<operator>"):
                called_function = name

        S.add_node(
            sid,
            function=fn,
            line=line,
            column=col,
            stmt_type=stmt_type,
            ast_type=label,
            code=code.strip() if code else "",
            depth_ast=ast_d.get(sid, -1),
            depth_cfg=cfg_d.get(sid, -1),
            variables_used=sorted(used),
            variables_defined=sorted(defined),
            called_function=called_function,
            in_loop=in_loop,
            in_branch=in_branch,
        )

    # Step C: copy CFG / DFG / CALL edges — but only between statement nodes.
    # Joern's CFG connects every node; we need to "lift" edges whose endpoints
    # are sub-expressions up to their enclosing statement. Simplest correct
    # approach: for each raw edge (u, v, kind), find the smallest statement
    # ancestor of each endpoint. If both lift to statements in our set and
    # the lifted endpoints differ, add a lifted edge.
    def _lift_to_stmt(node_id: str) -> str | None:
        """Walk AST parents until we hit a statement node."""
        cur = node_id
        hops = 0
        while cur is not None and hops < 128:
            if cur in stmt_ids:
                return cur
            cur = parent.get(cur)
            hops += 1
        return None

    # Deduplicate lifted edges — lifting often produces many duplicates.
    seen_edges: set[tuple[str, str, str]] = set()
    for u, v, k in raw.graph.edges(keys=True):
        if k == "CFG":
            out_k = "CFG"
        elif k == "REACHING_DEF":
            out_k = "DFG"
        elif k == "CALL":
            out_k = "CALL"
        else:
            continue  # drop AST, CONTAINS, ARGUMENT, etc. in the statement graph
        lu = _lift_to_stmt(u)
        lv = _lift_to_stmt(v)
        if lu is None or lv is None or lu == lv:
            continue
        tag = (lu, lv, out_k)
        if tag in seen_edges:
            continue
        seen_edges.add(tag)
        S.add_edge(lu, lv, key=out_k, edge_type=out_k)

    n_stmts_per_fn = {fn: len(ids) for fn, ids in stmts_in_method.items()}
    biggest = max(n_stmts_per_fn.values(), default=0)
    if biggest > max_stmts_warn:
        over = {fn: n for fn, n in n_stmts_per_fn.items() if n > max_stmts_warn}
        log.warning("functions exceed %d stmts: %s", max_stmts_warn, over)

    log.info(
        "statement graph: %d stmt nodes, %d edges across %d functions",
        S.number_of_nodes(), S.number_of_edges(), len(stmts_in_method),
    )
    return S


# ---------------------------------------------------------------------------
# Pass 3: add PARAM_BIND edges at call sites
# ---------------------------------------------------------------------------
#
# For each in-graph call site `foo(a, b, c)` whose target METHOD is also a
# candidate, add edges:
#     arg_i_statement  --PARAM_BIND-->  callee's formal parameter_i
#
# The callee's parameters are METHOD_PARAMETER_IN sub-expressions — they're
# not statement nodes in our coarse model. We "lift" them to the callee's
# METHOD_ENTRY statement as the target. This gives the slicer a structural
# edge "data at this argument flows into this callee's entry" without
# requiring full inter-procedural DFG.
#
# Why lift to METHOD_ENTRY rather than adding parameter sub-expression nodes
# back into the graph? Two reasons: (1) keeps node granularity consistent —
# one "statement" abstraction, not two — and (2) the first real statement in
# the callee already uses the parameter via DFG, so a PARAM_BIND into the
# METHOD_ENTRY plus the existing DFG gets us end-to-end flow via 2 hops.

def augment_param_bindings(
    raw: _RawCPG, stmt_graph: nx.MultiDiGraph,
) -> None:
    """Add PARAM_BIND edges in-place to stmt_graph.

    Semantics: for each CALL edge (call_site_stmt -> callee_method_entry)
    already present in stmt_graph, look up the ARGUMENT edges in the raw CPG
    from the original CALL node to its argument sub-expressions; for each
    argument whose index maps to a formal parameter of the callee, add a
    PARAM_BIND edge from the argument's enclosing statement to the callee
    METHOD_ENTRY. (In most cases the enclosing statement IS the call site
    statement; we keep the lifting general for nested calls.)
    """
    # Collect (caller_stmt, callee_method_entry) pairs from existing CALL edges.
    call_edges = [(u, v) for u, v, k in stmt_graph.edges(keys=True) if k == "CALL"]
    added = 0

    # Build AST parent map on the raw graph (we need it for "lifting" args).
    parent = _build_ast_parent_map(raw)

    def _lift_to_stmt_in(stmt_graph: nx.MultiDiGraph, node_id: str) -> str | None:
        cur = node_id
        hops = 0
        while cur is not None and hops < 128:
            if cur in stmt_graph:
                return cur
            cur = parent.get(cur)
            hops += 1
        return None

    for caller_stmt, callee_entry in call_edges:
        # caller_stmt is a statement node in S; the ORIGINAL raw CALL node(s)
        # that lifted to this statement may be multiple (e.g., nested calls
        # in the same statement). Find them: raw CALL nodes whose lift is
        # caller_stmt and whose CALL edge in raw targets callee_entry.
        # We iterate over raw CALL edges to find the matching source(s).
        matching_raw_calls: list[str] = []
        for u, v, k in raw.graph.out_edges(keys=True):
            # Enumerating all edges is O(E) per call_edge — OK for Step 2 scale.
            # If this becomes a hotspot, precompute an index from raw CALL
            # node -> target METHOD.
            if k != "CALL" or v != callee_entry:
                continue
            # Check that u lifts to caller_stmt.
            if _lift_to_stmt_in(stmt_graph, u) == caller_stmt:
                matching_raw_calls.append(u)

        for raw_call in matching_raw_calls:
            # Joern emits ARGUMENT edges from the CALL node to each argument.
            # Each argument has an ARGUMENT_INDEX property (1-based in C front-end).
            args: list[tuple[int, str]] = []
            for _, arg, ek in raw.graph.out_edges(raw_call, keys=True):
                if ek != "ARGUMENT":
                    continue
                a_attrs = raw.graph.nodes.get(arg, {})
                idx_raw = a_attrs.get("argumentIndex") or a_attrs.get("ARGUMENT_INDEX")
                try:
                    idx = int(idx_raw)
                except (TypeError, ValueError):
                    continue
                if idx <= 0:
                    # Index 0 is the receiver in OO front-ends; we skip for C.
                    continue
                args.append((idx, arg))

            for idx, arg in args:
                # The target side: we always lift to the callee's METHOD_ENTRY
                # statement. A more precise model could target the specific
                # METHOD_PARAMETER_IN node by matching idx, but we chose to
                # keep statement granularity uniform (see module docstring).
                src_stmt = _lift_to_stmt_in(stmt_graph, arg)
                if src_stmt is None:
                    continue
                # One edge per argument index — use idx in the key so that
                # multiple args at the same call site each get their own edge.
                pb_key = f"PARAM_BIND_{idx}"
                if stmt_graph.has_edge(src_stmt, callee_entry, key=pb_key):
                    continue
                stmt_graph.add_edge(
                    src_stmt, callee_entry,
                    key=pb_key,
                    edge_type="PARAM_BIND",
                    arg_index=idx,
                )
                added += 1

    log.info("added %d PARAM_BIND edges", added)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def build_program_graph(
    handle: CPGHandle,
    step1: Step1Result,
) -> nx.MultiDiGraph:
    """Run Step 2 end-to-end. Returns the coarse statement graph with CFG,
    DFG, CALL, and PARAM_BIND edges, scoped to step1's candidate functions."""
    if step1.skipped_reason:
        raise ValueError(f"Step 1 was skipped: {step1.skipped_reason}")

    raw = load_cpg_subgraph(handle, step1)
    S = extract_statement_graph(raw, handle.worktree)
    augment_param_bindings(raw, S)

    # Tag the graph with provenance so later steps can see what they're holding.
    S.graph["commit"] = step1.commit
    S.graph["version"] = step1.version
    S.graph["patch_id"] = step1.patch_id
    S.graph["candidate_functions"] = {
        cf.method_full_name: {
            "name": cf.function_name, "role": cf.role,
            "hop_distance": cf.hop_distance,
            "modified_lines": cf.modified_lines,
            "file": cf.file,
        }
        for cf in step1.candidate_functions
    }
    return S