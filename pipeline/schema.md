# Vulnerability Node-Level Dataset — Schema

## Function-level record (`functions.jsonl`)

```json
{
  "function_id": "sha256(repo@commit:file:func_name:start_line)",
  "repo": "torvalds/linux",
  "cve": "CVE-2023-12345",
  "cwe": ["CWE-416"],
  "commit_vuln": "abc123...",
  "commit_fix":  "def456...",
  "version": "vulnerable",           // "vulnerable" | "patched"
  "file": "drivers/net/foo.c",
  "function_name": "foo_handle_packet",
  "signature": "static int foo_handle_packet(struct sk_buff *skb)",
  "start_line": 142,
  "end_line": 201,
  "loc": 60,
  "language": "c",
  "patched_lines": [158, 159, 167],  // lines changed in fix commit
  "sinks": [
    {"line": 171, "api": "memcpy", "arg_index": 2, "source": "cwe_list|asan|manual"}
  ],
  "sources": [                        // optional: known taint sources
    {"line": 144, "kind": "user_input", "expr": "skb->data"}
  ],
  "pair_id": "fn_pair_0001",         // links vulnerable and patched versions
  "num_nodes": 87,
  "num_edges": 214
}
```

## Node-level record (`nodes.jsonl`)

```json
{
  "node_id": "fn_pair_0001:vuln:n_042",
  "function_id": "...",
  "order": 42,                        // traversal order within function
  "line": 171,
  "column": 4,
  "stmt_type": "CALL",                // see enum below
  "ast_type": "CallExpression",       // raw Joern/tree-sitter label
  "code": "memcpy(dst, skb->data, len);",
  "tokens": ["memcpy", "(", "dst", ",", "skb", "->", "data", ",", "len", ")"],
  "depth_ast": 4,                     // nesting in AST
  "depth_cfg": 7,                     // distance from function entry in CFG
  "in_loop": true,
  "in_branch": true,
  "variables_used":    ["dst", "skb", "len"],
  "variables_defined": [],
  "called_function":   "memcpy",      // null if not a call
  "is_sink": true,
  "is_source": false,
  "is_patched": false,                // this node's line appears in patched_lines
  "dist_to_patch": 2,                 // min CFG/DFG hops to any patched node
  "dist_to_sink":  0,
  "label": 1,                         // binary: on patched line or taint path
  "score": 0.87,                      // continuous relevance, see formula
  "label_source": "patch+taint"       // "patch" | "taint" | "manual" | combo
}
```

## Edge record (`edges.jsonl`)

```json
{
  "function_id": "...",
  "src": "fn_pair_0001:vuln:n_042",
  "dst": "fn_pair_0001:vuln:n_045",
  "edge_type": "CFG"                  // CFG | DFG | CALL | AST | CDG | PDG
}
```

## `stmt_type` enum (normalized across languages)

```
ASSIGN, CALL, RETURN, IF, ELSE, SWITCH, CASE,
FOR, WHILE, DO_WHILE, BREAK, CONTINUE, GOTO, LABEL,
DECL, ALLOC, FREE, CAST, ARITH, LOGICAL, COMPARE,
INDEX, FIELD, DEREF, ADDROF, TERNARY, BLOCK, OTHER
```

Normalize at extraction time — raw Joern labels go in `ast_type` for debugging.

## Score formula (suggested)

```
score = w1 * exp(-alpha * dist_to_patch)
      + w2 * exp(-beta  * dist_to_sink)
      + w3 * on_taint_path
      + w4 * is_patched
```

Clip to [0, 1]. Typical starting values: `alpha=0.5, beta=0.3, w=[0.3,0.3,0.2,0.2]`.
Tune on a held-out set where you have manual root-cause annotations.
