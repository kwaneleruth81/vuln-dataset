#!/usr/bin/env python3
"""
build_dataset.py — Convert a Joern CPG export into a node-level
vulnerability dataset (functions.jsonl, nodes.jsonl, edges.jsonl).

Inputs
------
  --graph      : directory from `joern-export ... --format graphson`
  --patch-meta : JSON with {file, function, patched_lines, sinks, sources,
                            cve, cwe, commit_vuln, commit_fix, version}
  --out        : output directory

This is a reference implementation — it handles the common CPG node/edge
types. Extend `STMT_TYPE_MAP` and `iter_functions` for your target language.
"""

from __future__ import annotations
import argparse, json, math, hashlib
from collections import defaultdict, deque
from pathlib import Path

import networkx as nx  


# --- 1. Joern node label -> normalized stmt_type ------------------------------

STMT_TYPE_MAP = {
    "CALL": "CALL",
    "RETURN": "RETURN",
    "CONTROL_STRUCTURE": "CONTROL",   # refined below by 'controlStructureType'
    "IDENTIFIER": "OTHER",
    "LITERAL": "OTHER",
    "LOCAL": "DECL",
    "METHOD_PARAMETER_IN": "DECL",
    "BLOCK": "BLOCK",
    "FIELD_IDENTIFIER": "FIELD",
    "UNKNOWN": "OTHER",
}

CONTROL_STRUCT_MAP = {
    "IF": "IF", "ELSE": "ELSE", "FOR": "FOR", "WHILE": "WHILE",
    "DO": "DO_WHILE", "SWITCH": "SWITCH", "BREAK": "BREAK",
    "CONTINUE": "CONTINUE", "GOTO": "GOTO",
}

# Operators Joern emits as CALL with special names
OPERATOR_TO_STMT = {
    "<operator>.assignment": "ASSIGN",
    "<operator>.addition": "ARITH",
    "<operator>.subtraction": "ARITH",
    "<operator>.multiplication": "ARITH",
    "<operator>.division": "ARITH",
    "<operator>.logicalAnd": "LOGICAL",
    "<operator>.logicalOr":  "LOGICAL",
    "<operator>.equals":     "COMPARE",
    "<operator>.notEquals":  "COMPARE",
    "<operator>.lessThan":   "COMPARE",
    "<operator>.greaterThan":"COMPARE",
    "<operator>.indirectIndexAccess": "INDEX",
    "<operator>.fieldAccess":         "FIELD",
    "<operator>.indirection":         "DEREF",
    "<operator>.addressOf":           "ADDROF",
    "<operator>.cast":                "CAST",
    "<operator>.conditional":         "TERNARY",
}


def classify_stmt(node_attrs: dict) -> str:
    label = node_attrs.get("labelV") or node_attrs.get("_label", "")
    if label == "CALL":
        name = node_attrs.get("name", "")
        if name in OPERATOR_TO_STMT:
            return OPERATOR_TO_STMT[name]
        return "CALL"
    if label == "CONTROL_STRUCTURE":
        return CONTROL_STRUCT_MAP.get(
            node_attrs.get("controlStructureType", ""), "CONTROL"
        )
    return STMT_TYPE_MAP.get(label, "OTHER")


# --- 2. Load Joern graphson into NetworkX -------------------------------------

def load_graph(graph_dir: Path) -> nx.MultiDiGraph:
    """Joern's graphson export is one JSON file per method, or a single
    combined file depending on version. This handles both."""
    G = nx.MultiDiGraph()
    for jf in graph_dir.glob("*.json"):
        data = json.loads(jf.read_text())
        for v in data.get("vertices", data.get("@value", {}).get("vertices", [])):
            nid = str(v["id"])
            props = {k: (vals[0]["value"] if isinstance(vals, list) else vals)
                     for k, vals in v.get("properties", {}).items()}
            props["_label"] = v.get("label", "UNKNOWN")
            G.add_node(nid, **props)
        for e in data.get("edges", data.get("@value", {}).get("edges", [])):
            G.add_edge(str(e["outV"]), str(e["inV"]), key=e["label"],
                       edge_type=e["label"])
    return G


# --- 3. Iterate functions and build per-function subgraphs --------------------

def iter_functions(G: nx.MultiDiGraph):
    """Yield (method_node_id, method_attrs, subgraph_node_ids) for each
    function in the CPG. Joern models functions as METHOD nodes; all nodes
    reachable via AST edges from a METHOD belong to that function."""
    for nid, attrs in G.nodes(data=True):
        if attrs.get("_label") != "METHOD":
            continue
        # Collect all AST descendants.
        body = {nid}
        stack = [nid]
        while stack:
            cur = stack.pop()
            for _, child, k in G.out_edges(cur, keys=True):
                if k == "AST" and child not in body:
                    body.add(child)
                    stack.append(child)
        yield nid, attrs, body


# --- 4. Distance computation (BFS over CFG+DFG) -------------------------------

def multi_source_bfs(G: nx.MultiDiGraph, sources: set[str],
                     body: set[str], edge_types=("CFG", "REACHING_DEF")) -> dict:
    """Return min hop distance from any source to every node in body.
    Walks both directions — root-cause nodes may lie upstream of sinks."""
    dist = {n: math.inf for n in body}
    q = deque()
    for s in sources:
        if s in body:
            dist[s] = 0
            q.append(s)
    while q:
        u = q.popleft()
        for _, v, k in G.out_edges(u, keys=True):
            if k in edge_types and v in body and dist[v] > dist[u] + 1:
                dist[v] = dist[u] + 1
                q.append(v)
        for v, _, k in G.in_edges(u, keys=True):
            if k in edge_types and v in body and dist[v] > dist[u] + 1:
                dist[v] = dist[u] + 1
                q.append(v)
    return dist


# --- 5. Build the final records -----------------------------------------------

def compute_depth(G, body, method_id):
    """AST depth from method root."""
    depth = {method_id: 0}
    q = deque([method_id])
    while q:
        u = q.popleft()
        for _, v, k in G.out_edges(u, keys=True):
            if k == "AST" and v in body and v not in depth:
                depth[v] = depth[u] + 1
                q.append(v)
    return depth


def fid(repo, commit, file, func, line):
    raw = f"{repo}@{commit}:{file}:{func}:{line}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def build(G: nx.MultiDiGraph, patch_meta: dict):
    patched_lines = set(patch_meta.get("patched_lines", []))
    sink_lines    = {s["line"] for s in patch_meta.get("sinks", [])}
    source_lines  = {s["line"] for s in patch_meta.get("sources", [])}

    fn_records, node_records, edge_records = [], [], []

    for method_id, mattrs, body in iter_functions(G):
        fname = mattrs.get("name", "<anon>")
        if patch_meta.get("function") and fname != patch_meta["function"]:
            continue

        file_name = mattrs.get("filename", patch_meta.get("file", "?"))
        start = int(mattrs.get("lineNumber", 0) or 0)
        end   = int(mattrs.get("lineNumberEnd", 0) or 0)

        function_id = fid(patch_meta["repo"], patch_meta["commit_vuln"],
                          file_name, fname, start)

        # Identify sink/patched/source nodes by line number.
        patched_nodes = {n for n in body
                         if int(G.nodes[n].get("lineNumber", -1) or -1) in patched_lines}
        sink_nodes    = {n for n in body
                         if int(G.nodes[n].get("lineNumber", -1) or -1) in sink_lines}
        source_nodes  = {n for n in body
                         if int(G.nodes[n].get("lineNumber", -1) or -1) in source_lines}

        d_patch = multi_source_bfs(G, patched_nodes, body)
        d_sink  = multi_source_bfs(G, sink_nodes, body)
        ast_depth = compute_depth(G, body, method_id)

        # Scoring constants — tune on a labeled subset.
        A, B, W = 0.5, 0.3, (0.3, 0.3, 0.2, 0.2)

        # Taint reachability: node lies on CFG/DFG path source -> sink.
        on_taint = set()
        if source_nodes and sink_nodes:
            fwd = multi_source_bfs(G, source_nodes, body)
            bwd = multi_source_bfs(G, sink_nodes, body)
            on_taint = {n for n in body
                        if math.isfinite(fwd[n]) and math.isfinite(bwd[n])}

        for order, n in enumerate(sorted(body,
                                         key=lambda x: (int(G.nodes[x].get("lineNumber", 0) or 0),
                                                        int(G.nodes[x].get("columnNumber", 0) or 0)))):
            a = G.nodes[n]
            line = int(a.get("lineNumber", 0) or 0)
            stmt_type = classify_stmt(a)

            # Variables: identifiers referenced by this node's AST subtree.
            used, defined = set(), set()
            for _, ch, k in G.out_edges(n, keys=True):
                if k == "AST" and G.nodes[ch].get("_label") == "IDENTIFIER":
                    used.add(G.nodes[ch].get("name", ""))
            # Defs: LHS of an assignment CALL node.
            if a.get("name") == "<operator>.assignment":
                children = [ch for _, ch, k in G.out_edges(n, keys=True) if k == "AST"]
                if children:
                    lhs = children[0]
                    if G.nodes[lhs].get("_label") == "IDENTIFIER":
                        defined.add(G.nodes[lhs].get("name", ""))
                        used.discard(G.nodes[lhs].get("name", ""))

            dp = d_patch[n] if math.isfinite(d_patch[n]) else None
            ds = d_sink[n]  if math.isfinite(d_sink[n])  else None

            is_patched = n in patched_nodes
            taint = 1 if n in on_taint else 0

            score = (W[0] * (math.exp(-A * dp) if dp is not None else 0) +
                     W[1] * (math.exp(-B * ds) if ds is not None else 0) +
                     W[2] * taint +
                     W[3] * (1 if is_patched else 0))
            score = min(1.0, max(0.0, score))

            # Binary label: patched OR on taint path to sink.
            label = 1 if (is_patched or (taint and ds is not None and ds <= 3)) else 0

            node_records.append({
                "node_id":   f"{function_id}:n{order:04d}",
                "function_id": function_id,
                "order": order,
                "line": line,
                "stmt_type": stmt_type,
                "ast_type":  a.get("_label"),
                "code":      a.get("code", ""),
                "depth_ast": ast_depth.get(n, -1),
                "depth_cfg": dp if dp is not None else -1,
                "variables_used":    sorted(v for v in used if v),
                "variables_defined": sorted(defined),
                "called_function":   a.get("name") if a.get("_label") == "CALL"
                                       and not a.get("name", "").startswith("<operator>")
                                       else None,
                "is_sink":    n in sink_nodes,
                "is_source":  n in source_nodes,
                "is_patched": is_patched,
                "dist_to_patch": dp,
                "dist_to_sink":  ds,
                "on_taint_path": bool(taint),
                "label": label,
                "score": round(score, 4),
                "label_source": "patch+taint",
            })

        # Edges for this function's subgraph.
        for u, v, k in G.edges(keys=True):
            if u in body and v in body and k in ("CFG", "REACHING_DEF", "CALL", "AST", "CDG"):
                edge_records.append({
                    "function_id": function_id,
                    "src": u, "dst": v, "edge_type": k,
                })

        fn_records.append({
            "function_id": function_id,
            "repo": patch_meta["repo"],
            "cve":  patch_meta.get("cve"),
            "cwe":  patch_meta.get("cwe", []),
            "commit_vuln": patch_meta["commit_vuln"],
            "commit_fix":  patch_meta["commit_fix"],
            "version": patch_meta.get("version", "vulnerable"),
            "file": file_name,
            "function_name": fname,
            "start_line": start,
            "end_line": end,
            "language": "c",
            "patched_lines": sorted(patched_lines),
            "sinks":   patch_meta.get("sinks", []),
            "sources": patch_meta.get("sources", []),
            "num_nodes": len(body),
            "num_edges": sum(1 for e in edge_records if e["function_id"] == function_id),
        })

    return fn_records, node_records, edge_records


def write_jsonl(path: Path, records):
    with path.open("w") as f:
        for r in records:
            f.write(json.dumps(r, default=str) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--graph", required=True, type=Path)
    ap.add_argument("--patch-meta", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    G = load_graph(args.graph)
    patch_meta = json.loads(args.patch_meta.read_text())

    fns, nodes, edges = build(G, patch_meta)

    write_jsonl(args.out / "functions.jsonl", fns)
    write_jsonl(args.out / "nodes.jsonl",     nodes)
    write_jsonl(args.out / "edges.jsonl",     edges)

    print(f"Wrote {len(fns)} functions, {len(nodes)} nodes, {len(edges)} edges")


if __name__ == "__main__":
    main()
