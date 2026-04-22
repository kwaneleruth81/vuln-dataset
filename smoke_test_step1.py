"""
smoke_test_step1.py — End-to-end smoke test for Step 1.

Builds a tiny synthetic C "repo" with two commits (vulnerable, fixed),
runs find_candidate_functions, and asserts the expected candidate list.

What we're testing:
  * Diff parsing against a real git diff (not a hand-crafted string)
  * Joern CPG build + call graph extraction on real C code
  * Patch function identification from modified lines
  * 1-hop caller/callee expansion
  * Version-aware processing (vulnerable vs fixed)
  * Pure-addition fix handling (second sub-test)

What we're NOT testing (out of scope for Step 1):
  * Sink identification
  * Program graph extraction at statement level
  * Slicing, labeling

Run:   python3 smoke_test_step1.py
Requires: git, joern-parse, joern-export in PATH.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from pipeline.find_candidates import find_candidate_functions  # noqa: E402
from pipeline.cpg_cache import purge_cache, get_or_build_cpg  # noqa: E402
from pipeline.build_program_graph import build_program_graph  # noqa: E402
from pipeline.sinks import identify_sinks  # noqa: E402
from pipeline.slicer import compute_slice  # noqa: E402
from pipeline.annotate import annotate_nodes  # noqa: E402
from pipeline.annotate import annotate_nodes  # noqa: E402
from pipeline.annotate import annotate_nodes  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger("smoke")


# ---------------------------------------------------------------------------
# Synthetic C source — designed to exercise every Step 1 code path
# ---------------------------------------------------------------------------
#
# Call graph we want Joern to recover:
#
#     handle_request  (caller of parse_header)
#         └── parse_header   <-- THE PATCH FUNCTION
#                 └── copy_bytes  (callee of parse_header)
#
# Plus one unrelated function, `unused_helper`, which MUST NOT appear in
# the candidate list — it proves we're actually using the call graph and
# not just "all functions in the file."
#
# The vulnerable version has an unbounded memcpy via copy_bytes. The fix
# adds a length check in parse_header. This produces a *mixed* diff
# (both added and context lines in parse_header), so Case 1 of the diff
# parser is exercised.

VULN_SRC = """\
#include <string.h>
#include <stdio.h>

void copy_bytes(char *dst, const char *src, int len) {
    memcpy(dst, src, len);
}

int parse_header(const char *input, int input_len, char *out) {
    int declared_len;
    declared_len = input[0];
    copy_bytes(out, input + 1, declared_len);
    return declared_len;
}

int handle_request(const char *req, int req_len) {
    char buf[64];
    int n = parse_header(req, req_len, buf);
    return n;
}

void unused_helper(int x) {
    printf("%d\\n", x);
}
"""

# Fix: add a bounds check in parse_header. Mixed hunk (additions + context).
FIXED_SRC = """\
#include <string.h>
#include <stdio.h>

void copy_bytes(char *dst, const char *src, int len) {
    memcpy(dst, src, len);
}

int parse_header(const char *input, int input_len, char *out) {
    int declared_len;
    if (input_len < 1) return -1;
    declared_len = input[0];
    if (declared_len < 0 || declared_len > input_len - 1) return -1;
    copy_bytes(out, input + 1, declared_len);
    return declared_len;
}

int handle_request(const char *req, int req_len) {
    char buf[64];
    int n = parse_header(req, req_len, buf);
    return n;
}

void unused_helper(int x) {
    printf("%d\\n", x);
}
"""


def _run(cmd: list[str], cwd: Path) -> None:
    """Run a git command, raising with useful context on failure."""
    res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed:\n{res.stderr}")


def build_synthetic_repo(root: Path) -> tuple[str, str]:
    """Create a git repo with two commits. Returns (commit_vuln, commit_fix)."""
    root.mkdir(parents=True, exist_ok=True)
    _run(["git", "init", "-q", "-b", "main"], cwd=root)
    # Local identity so commits work in isolated CI environments.
    _run(["git", "config", "user.email", "test@example.com"], cwd=root)
    _run(["git", "config", "user.name", "Smoke Test"], cwd=root)
    # commit.gpgsign off in case the user has global signing enabled.
    _run(["git", "config", "commit.gpgsign", "false"], cwd=root)

    src = root / "src" / "parser.c"
    src.parent.mkdir(parents=True, exist_ok=True)

    src.write_text(VULN_SRC)
    _run(["git", "add", "."], cwd=root)
    _run(["git", "commit", "-q", "-m", "initial (vulnerable)"], cwd=root)
    commit_vuln = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()

    src.write_text(FIXED_SRC)
    _run(["git", "add", "."], cwd=root)
    _run(["git", "commit", "-q", "-m", "add bounds check"], cwd=root)
    commit_fix = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()

    log.info("synthetic repo at %s", root)
    log.info("  commit_vuln = %s", commit_vuln[:8])
    log.info("  commit_fix  = %s", commit_fix[:8])
    return commit_vuln, commit_fix


# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------

def _fn_names_by_role(result) -> dict[str, set[str]]:
    """Group candidate function names by role for easy assertion."""
    out: dict[str, set[str]] = {"patch": set(), "caller": set(), "callee": set()}
    for cf in result.candidate_functions:
        out[cf.role].add(cf.function_name)
    return out


def assert_step1(results: dict, version: str) -> None:
    """Step 1 assertions: candidate list is correct for this version."""
    r = results[version]
    assert r.skipped_reason is None, f"{version} unexpectedly skipped: {r.skipped_reason}"

    by_role = _fn_names_by_role(r)
    log.info("%s: patch=%s caller=%s callee=%s",
             version, by_role["patch"], by_role["caller"], by_role["callee"])

    assert by_role["patch"] == {"parse_header"}, \
        f"{version}: expected patch={{parse_header}}, got {by_role['patch']}"
    assert "handle_request" in by_role["caller"], \
        f"{version}: expected handle_request in callers, got {by_role['caller']}"
    assert "copy_bytes" in by_role["callee"], \
        f"{version}: expected copy_bytes in callees, got {by_role['callee']}"

    all_fns = by_role["patch"] | by_role["caller"] | by_role["callee"]
    assert "unused_helper" not in all_fns, \
        f"{version}: unused_helper leaked into candidates"

    patch_entry = next(cf for cf in r.candidate_functions if cf.role == "patch")
    assert patch_entry.modified_lines, \
        f"{version}: patch function has no modified_lines"
    log.info("  %s modified_lines: %s", version, patch_entry.modified_lines)


def _nodes_in_fn(G, function_short_name: str):
    """Return statement nodes whose function full_name ends with the short name.
    Joern's fullName for C is typically just the short name, but some front-ends
    use 'file.c:func' — endswith handles both."""
    return [
        (nid, attrs) for nid, attrs in G.nodes(data=True)
        if attrs.get("function", "").endswith(function_short_name)
        or attrs.get("function") == function_short_name
    ]


def _edges_between_fns(G, src_fn: str, dst_fn: str, kind: str):
    """Return edges of `kind` whose src is in src_fn and dst is in dst_fn."""
    src_ids = {nid for nid, a in G.nodes(data=True)
               if a.get("function", "").endswith(src_fn)}
    dst_ids = {nid for nid, a in G.nodes(data=True)
               if a.get("function", "").endswith(dst_fn)}
    return [(u, v) for u, v, k, d in G.edges(keys=True, data=True)
            if d.get("edge_type", k) == kind and u in src_ids and v in dst_ids]


def assert_step2(G, version: str) -> None:
    """Step 2 assertions: statement graph over candidate functions is correct."""
    log.info("---- Step 2 assertions (%s) ----", version)
    log.info("graph: %d nodes, %d edges", G.number_of_nodes(), G.number_of_edges())

    # A. All three candidate functions present; unused_helper absent.
    fn_names = {a.get("function", "") for _, a in G.nodes(data=True)}
    log.info("  functions in graph: %s", fn_names)

    for expected in ("parse_header", "handle_request", "copy_bytes"):
        matches = [f for f in fn_names if f.endswith(expected) or f == expected]
        assert matches, f"{version}: {expected} missing from graph (have {fn_names})"
    unused_matches = [f for f in fn_names if f.endswith("unused_helper")]
    assert not unused_matches, \
        f"{version}: unused_helper leaked into graph: {unused_matches}"

    # B. parse_header has reasonable statement-level granularity.
    ph_nodes = _nodes_in_fn(G, "parse_header")
    ph_types = [a["stmt_type"] for _, a in ph_nodes]
    log.info("  parse_header stmt_types: %s", ph_types)

    # Should include: METHOD_ENTRY, at least one ASSIGN (declared_len = input[0]),
    # at least one CALL (copy_bytes), a RETURN.
    assert "METHOD_ENTRY" in ph_types, f"no METHOD_ENTRY in parse_header: {ph_types}"
    assert "ASSIGN" in ph_types,       f"no ASSIGN in parse_header: {ph_types}"
    assert "CALL" in ph_types,         f"no CALL in parse_header: {ph_types}"
    assert "RETURN" in ph_types,       f"no RETURN in parse_header: {ph_types}"

    # Sanity on size: a 4-line function should produce ~5-12 statement nodes,
    # not hundreds (which would indicate the rollup failed) and not 1-2
    # (which would indicate we collapsed too aggressively).
    assert 3 <= len(ph_nodes) <= 30, \
        f"parse_header has suspicious node count {len(ph_nodes)}: {ph_types}"

    # C. Version-specific: fixed version should have IF statements from the
    #    two added bounds checks; vulnerable version should have zero.
    n_ifs = sum(1 for t in ph_types if t == "IF")
    if version == "fixed":
        assert n_ifs >= 2, \
            f"fixed version should have >=2 IF stmts in parse_header, got {n_ifs}"
        log.info("  fixed: parse_header has %d IF stmts (from bounds checks)", n_ifs)
    else:
        assert n_ifs == 0, \
            f"vulnerable version should have 0 IF stmts in parse_header, got {n_ifs}"
        log.info("  vulnerable: parse_header has 0 IF stmts (pre-fix)")

    # D. CFG chain: parse_header's METHOD_ENTRY must reach its RETURN via CFG.
    import networkx as nx
    ph_entry = next(nid for nid, a in ph_nodes if a["stmt_type"] == "METHOD_ENTRY")
    ph_returns = [nid for nid, a in ph_nodes if a["stmt_type"] == "RETURN"]
    assert ph_returns, "parse_header has no RETURN stmt"

    # Build a CFG-only view and check reachability from entry.
    cfg_view = nx.DiGraph()
    for u, v, k in G.edges(keys=True):
        if k == "CFG":
            cfg_view.add_edge(u, v)
    reachable = nx.descendants(cfg_view, ph_entry) | {ph_entry}
    reached_returns = [r for r in ph_returns if r in reachable]
    assert reached_returns, \
        f"parse_header RETURN(s) {ph_returns} not CFG-reachable from METHOD_ENTRY"
    log.info("  CFG: %d/%d RETURN(s) reachable from parse_header entry",
             len(reached_returns), len(ph_returns))

    # E. Cross-function CALL edges: parse_header -> copy_bytes.
    call_edges = _edges_between_fns(G, "parse_header", "copy_bytes", "CALL")
    assert call_edges, \
        f"{version}: no CALL edges from parse_header to copy_bytes"
    log.info("  CALL: parse_header -> copy_bytes edges: %d", len(call_edges))

    # F. PARAM_BIND edges: parse_header -> copy_bytes should have 3 (dst, src, len).
    pb_edges = _edges_between_fns(G, "parse_header", "copy_bytes", "PARAM_BIND")
    # Joern may emit duplicates or miss args depending on version; require at
    # least 2 of the 3 args to materialize as PARAM_BIND edges.
    assert len(pb_edges) >= 2, \
        f"{version}: expected >=2 PARAM_BIND edges parse_header->copy_bytes, got {len(pb_edges)}"
    log.info("  PARAM_BIND: parse_header -> copy_bytes edges: %d", len(pb_edges))

    # G. Variable rollup: the statement `declared_len = input[0]` should have
    #    declared_len in variables_defined AND input in variables_used.
    assign_nodes = [(nid, a) for nid, a in ph_nodes if a["stmt_type"] == "ASSIGN"]
    # The assignment we care about is the one touching `declared_len`.
    declared_len_assigns = [
        (nid, a) for nid, a in assign_nodes
        if "declared_len" in a.get("variables_defined", [])
    ]
    assert declared_len_assigns, \
        f"{version}: no ASSIGN stmt defines declared_len in parse_header; " \
        f"all assigns: {[(a.get('code'), a.get('variables_defined')) for _, a in assign_nodes]}"
    declared_len_assign_nid, a = declared_len_assigns[0]
    assert "input" in a.get("variables_used", []), \
        f"{version}: declared_len assign should use 'input'; used={a['variables_used']}"
    log.info("  var rollup: '%s' def=%s use=%s",
             a.get("code", ""), a["variables_defined"], a["variables_used"])

    # H. Intra-function DFG: the definition of declared_len must reach the
    #    copy_bytes call site via DFG edges (declared_len is passed as arg 3).
    #    Joern's REACHING_DEF, lifted to statement level, should give us this.
    copy_bytes_calls = [
        (nid, a) for nid, a in ph_nodes
        if a["stmt_type"] == "CALL" and a.get("called_function") == "copy_bytes"
    ]
    assert copy_bytes_calls, \
        f"{version}: no CALL to copy_bytes found in parse_header; " \
        f"calls present: {[a.get('called_function') for _, a in ph_nodes if a['stmt_type']=='CALL']}"
    copy_bytes_call_nid, _ = copy_bytes_calls[0]

    dfg_view = nx.DiGraph()
    for u, v, k in G.edges(keys=True):
        if k == "DFG":
            dfg_view.add_edge(u, v)
    # Reachability from the declared_len def to the copy_bytes call.
    if declared_len_assign_nid in dfg_view:
        dfg_reach = nx.descendants(dfg_view, declared_len_assign_nid)
    else:
        dfg_reach = set()
    assert copy_bytes_call_nid in dfg_reach, (
        f"{version}: no DFG path from declared_len def to copy_bytes call; "
        f"declared_len def has {dfg_view.out_degree(declared_len_assign_nid) if declared_len_assign_nid in dfg_view else 0} DFG out-edges"
    )
    log.info("  DFG: declared_len def -> copy_bytes call reachable")

    # I. AST depth values match expected nesting. parse_header has only one
    #    level of body (no nested control structures in vulnerable; bounds
    #    checks in fixed sit at the same body level). So every body statement
    #    should have AST depth in a tight range — specifically > METHOD_ENTRY's
    #    depth and bounded by a small constant for this flat function.
    entry_depth = next(a["depth_ast"] for _, a in ph_nodes
                       if a["stmt_type"] == "METHOD_ENTRY")
    body_depths = [a["depth_ast"] for _, a in ph_nodes
                   if a["stmt_type"] != "METHOD_ENTRY" and a["depth_ast"] >= 0]
    assert body_depths, f"{version}: no body statements have a valid depth_ast"
    assert all(d > entry_depth for d in body_depths), \
        f"{version}: body stmts should have depth > entry ({entry_depth}), got {body_depths}"
    # Flat function: body stmts are within a small window of each other.
    assert max(body_depths) - min(body_depths) <= 3, \
        f"{version}: parse_header body depths span too wide — {body_depths}"
    log.info("  AST depth: entry=%d, body range=[%d, %d]",
             entry_depth, min(body_depths), max(body_depths))

    # J. Caller-side PARAM_BIND: handle_request's call to parse_header should
    #    produce PARAM_BIND edges into parse_header (args: req, req_len, buf).
    caller_pb = _edges_between_fns(G, "handle_request", "parse_header", "PARAM_BIND")
    assert len(caller_pb) >= 2, \
        f"{version}: expected >=2 PARAM_BIND edges handle_request->parse_header, got {len(caller_pb)}"
    log.info("  PARAM_BIND: handle_request -> parse_header edges: %d", len(caller_pb))

    # K. Every statement has non-empty `code`. Joern usually populates this,
    #    and our source-read fallback should handle the rest. Empty code on
    #    many nodes means both Joern's property AND the fallback failed —
    #    probably a worktree path issue.
    all_stmts = [(nid, a) for nid, a in G.nodes(data=True)]
    empty_code = [(nid, a) for nid, a in all_stmts
                  if a["stmt_type"] != "METHOD_ENTRY"  # METHOD nodes have full fn text in code
                  and not a.get("code", "").strip()]
    # Tolerate a small number of empty — BLOCK nodes sometimes have empty code.
    empty_frac = len(empty_code) / max(1, len(all_stmts))
    assert empty_frac < 0.2, (
        f"{version}: too many stmts with empty code ({len(empty_code)}/{len(all_stmts)}); "
        f"sample: {[(a['stmt_type'], a.get('line')) for _, a in empty_code[:5]]}"
    )
    log.info("  code population: %d/%d stmts have code (%.0f%%)",
             len(all_stmts) - len(empty_code), len(all_stmts),
             100 * (1 - empty_frac))

    log.info("Step 2 assertions passed for %s", version)


def assert_step3(G, version: str) -> None:
    """Step 3 assertions: sinks are identified correctly on the statement graph.

    Expected: the call to `memcpy` in copy_bytes gets flagged as a sink under
    CWE-120 (buffer overflow) on BOTH versions — the memcpy itself is there
    whether or not the caller added a bounds check.
    """
    log.info("---- Step 3 assertions (%s) ----", version)

    # memcpy must be flagged in copy_bytes under CWE-120.
    sinks = [(nid, a) for nid, a in G.nodes(data=True) if a.get("is_sink")]
    log.info("  %d sinks marked:", len(sinks))
    for nid, a in sinks:
        log.info("    fn=%s line=%s api=%s reason=%s",
                 a.get("function"), a.get("line"),
                 a.get("called_function"), a.get("sink_reason"))

    assert sinks, f"{version}: no sinks marked (expected memcpy in copy_bytes)"

    # At least one sink must be a memcpy call inside copy_bytes.
    memcpy_sinks = [
        (nid, a) for nid, a in sinks
        if a.get("called_function") == "memcpy"
        and a.get("function", "").endswith("copy_bytes")
    ]
    assert memcpy_sinks, (
        f"{version}: expected memcpy sink in copy_bytes, sinks present: "
        f"{[(a.get('called_function'), a.get('function')) for _,a in sinks]}"
    )
    _, mattrs = memcpy_sinks[0]
    assert mattrs["sink_reason"] == "cwe_api:memcpy", \
        f"expected cwe_api:memcpy, got {mattrs['sink_reason']}"

    # Sanity: non-dangerous calls (printf is in our table via CWE-134, but
    # with CWE-120 alone it should NOT be flagged) — check unused_helper's
    # printf if it leaked... but it shouldn't leak, we asserted that in Step 2.
    # Instead, verify the CALL to copy_bytes itself is NOT a sink — we
    # haven't listed copy_bytes as dangerous.
    copy_bytes_calls = [
        (nid, a) for nid, a in G.nodes(data=True)
        if a.get("stmt_type") == "CALL"
        and a.get("called_function") == "copy_bytes"
    ]
    assert copy_bytes_calls, "expected at least one call to copy_bytes in graph"
    for _, a in copy_bytes_calls:
        assert a.get("is_sink") is False, \
            f"copy_bytes call should not be a sink: {a}"

    # SinkReport should be stashed on the graph.
    report = G.graph.get("sink_report")
    assert report is not None, "sink_report missing from G.graph"
    assert report.total_sinks >= 1
    assert report.apis_hit.get("memcpy", 0) >= 1

    log.info("Step 3 assertions passed for %s", version)


def assert_step5(G, version: str) -> None:
    """Step 5 assertions: multi-function slice crosses from parse_header
    (patched) through PARAM_BIND to copy_bytes (sink via memcpy).
    """
    log.info("---- Step 5 assertions (%s) ----", version)
    report = G.graph.get("slice_report")
    assert report is not None, "slice_report missing"
    log.info("  slice: size=%d patch=%d sinks=%d by_role=%s",
             report.slice_size, report.n_patch_nodes,
             report.n_sink_nodes, report.slice_by_role)

    # A. The slice is non-empty.
    assert report.slice_size > 0, f"{version}: empty slice"

    # B. At least one patch node is in the slice (patch nodes self-include
    #    through both BFSes).
    patch_in_slice = [
        (nid, a) for nid, a in G.nodes(data=True)
        if a.get("in_slice") and
           G.graph["candidate_functions"].get(a.get("function", ""), {}).get("role") == "patch"
    ]
    assert patch_in_slice, f"{version}: no patch-role nodes in slice"

    # C. The memcpy sink in copy_bytes must be in the slice. This is the
    #    cross-function property — the slice crossed PARAM_BIND from
    #    parse_header's patch nodes into copy_bytes.
    sink_in_slice = [
        (nid, a) for nid, a in G.nodes(data=True)
        if a.get("in_slice")
        and a.get("called_function") == "memcpy"
        and a.get("function", "").endswith("copy_bytes")
    ]
    assert sink_in_slice, (
        f"{version}: memcpy sink in copy_bytes not in slice. "
        f"slice_by_role={report.slice_by_role} "
        f"skipped={report.skipped}"
    )
    log.info("  ✓ memcpy sink in copy_bytes is in slice")

    # D. Slice touches the callee role (copy_bytes).
    assert report.slice_by_role.get("callee", 0) >= 1, \
        f"{version}: slice doesn't reach any callee-role node"

    # E. Disconnected / fallback flags should NOT be set for our well-formed
    #    synthetic test case. If they are, something in the CFG/DFG/PARAM_BIND
    #    plumbing is broken upstream.
    assert not report.used_sink_fallback, \
        f"{version}: unexpected sink fallback — Step 3 should have found memcpy"
    # The skipped flag *may* be set if the intersection is unexpectedly empty;
    # for this test we want a real intersection, not the anchor-union fallback.
    assert report.skipped is None, \
        f"{version}: slicer took a fallback path ({report.skipped}); " \
        f"graph connectivity likely broken (check CFG/DFG/PARAM_BIND)"

    # F. unused_helper nodes (if any) are NEVER in the slice — they should
    #    already be absent from the graph per Step 2's scoping, but check
    #    defensively in case a future bug re-introduces them.
    leaked = [
        (nid, a) for nid, a in G.nodes(data=True)
        if a.get("in_slice") and a.get("function", "").endswith("unused_helper")
    ]
    assert not leaked, f"{version}: unused_helper nodes in slice: {leaked}"

    log.info("Step 5 assertions passed for %s", version)


def assert_step7(records: list[dict], version: str) -> None:
    """Step 7 assertions: final per-node records match schema, derived fields
    are consistent, slicing labels propagate, and cross-function info is
    visible on the memcpy sink and the parse_header call site.
    """
    log.info("---- Step 7 assertions (%s) ----", version)
    log.info("  %d records emitted", len(records))
    assert records, f"{version}: no records emitted"

    # A. Schema completeness: every record has every expected field.
    required = {
        "id", "function", "role", "statement", "type", "line",
        "depth_cfg", "variables_used", "variables_defined",
        "is_patch_related", "distance_to_patch", "is_cross_function",
        "CFG_successors", "DFG_successors", "CALL_edges",
        "is_sink", "sink_reason", "label",
    }
    for r in records:
        missing = required - set(r.keys())
        assert not missing, f"{version}: record missing {missing}: {r.get('id')}"

    # B. At least one record has label=1 (the slice was non-empty on both
    #    versions — we asserted that in Step 5).
    n_labeled = sum(1 for r in records if r["label"])
    assert n_labeled > 0, f"{version}: no records with label=1"
    log.info("  labeled=1: %d/%d (%.0f%%)",
             n_labeled, len(records), 100 * n_labeled / len(records))

    # C. The memcpy call in copy_bytes is present, flagged as sink, labeled 1,
    #    cross-function. This is the most diagnostic single-record check.
    memcpy_recs = [
        r for r in records
        if r["function"] == "copy_bytes" and r["called_function"] == "memcpy"
    ]
    assert memcpy_recs, \
        f"{version}: no memcpy record in copy_bytes"
    r = memcpy_recs[0]
    assert r["is_sink"], f"{version}: memcpy record not flagged is_sink"
    assert r["sink_reason"] == "cwe_api:memcpy", \
        f"{version}: unexpected sink_reason {r['sink_reason']!r}"
    assert r["label"] == 1, \
        f"{version}: memcpy record has label={r['label']}, expected 1"
    # copy_bytes receives a call from parse_header, so its body is reached
    # via PARAM_BIND from the caller — is_cross_function must be True for at
    # least some copy_bytes nodes. The memcpy itself may or may not have
    # a cross-function edge directly depending on how the graph is organized;
    # check the function as a whole.
    cb_cross = [rr for rr in records
                if rr["function"] == "copy_bytes" and rr["is_cross_function"]]
    assert cb_cross, \
        f"{version}: no copy_bytes records are cross-function"
    log.info("  memcpy record: id=%s label=%d sink_reason=%s distance=%s",
             r["id"], r["label"], r["sink_reason"], r["distance_to_patch"])

    # D. Derived field consistency: is_patch_related <=> distance is not None.
    for rr in records:
        if rr["distance_to_patch"] is None:
            assert not rr["is_patch_related"], \
                f"{version}: distance None but is_patch_related True: {rr['id']}"
        else:
            assert rr["is_patch_related"], \
                f"{version}: distance finite but is_patch_related False: {rr['id']}"

    # E. Patch-role nodes on modified lines have distance 0. (Other patch-role
    #    nodes inside the function but not on modified lines have distance >=1.)
    patch_on_modified = [
        rr for rr in records
        if rr["role"] == "patch" and rr["line"] in rr["modified_lines"]
    ]
    assert patch_on_modified, \
        f"{version}: no patch-role record sits on a modified line"
    for rr in patch_on_modified:
        assert rr["distance_to_patch"] == 0, \
            f"{version}: patch node on modified line has distance {rr['distance_to_patch']}: {rr['id']}"
    log.info("  patch-on-modified records: %d (all distance=0)",
             len(patch_on_modified))

    # F. Canonical id format: "patch_id:version:NNNNN".
    for rr in records:
        parts = rr["id"].split(":")
        assert len(parts) >= 3, f"bad id format: {rr['id']}"
        assert parts[-2] == version, \
            f"{version}: id has wrong version segment: {rr['id']}"
        # Last segment is 5-digit ordinal.
        assert parts[-1].isdigit() and len(parts[-1]) == 5, \
            f"bad ordinal in id: {rr['id']}"

    # G. Neighbor rewriting: every neighbor id in CFG/DFG/CALL/PARAM_BIND lists
    #    must be a valid canonical id present in the record set.
    all_ids = {rr["id"] for rr in records}
    for rr in records:
        for field in ("CFG_successors", "CFG_predecessors",
                      "DFG_successors", "DFG_predecessors",
                      "CALL_edges", "CALL_predecessors",
                      "PARAM_BIND_edges", "PARAM_BIND_predecessors"):
            for nb in rr.get(field, []):
                assert nb in all_ids, \
                    f"{version}: neighbor {nb!r} in {field} of {rr['id']} not a canonical id"

    # H. Role distribution: we should see at least the three roles present.
    roles = {rr["role"] for rr in records}
    assert {"patch", "caller", "callee"}.issubset(roles), \
        f"{version}: missing roles in output — got {roles}"

    log.info("Step 7 assertions passed for %s", version)


def assert_step7(records: list[dict], version: str) -> None:
    """Step 7 assertions: the final dataset records are well-formed and
    reflect what we asserted structurally in Steps 1-5."""
    log.info("---- Step 7 assertions (%s) ----", version)
    log.info("  %d records", len(records))
    assert records, f"{version}: no records produced"

    # A. All records have unique IDs with the expected prefix.
    ids = [r["id"] for r in records]
    assert len(ids) == len(set(ids)), f"{version}: duplicate IDs"
    for rid in ids:
        assert rid.startswith(f"smoke/test1:{version}:"), rid

    # B. Record shape: every record has all required fields.
    required = [
        "id", "patch_id", "version", "function", "function_role",
        "file", "line", "statement", "type", "depth",
        "variables_used", "variables_defined",
        "is_patch_related", "distance_to_patch", "is_cross_function",
        "CFG_successors", "DFG_successors", "CALL_edges",
        "PARAM_BIND_edges", "label",
    ]
    for r in records[:5]:  # spot-check first 5
        for f in required:
            assert f in r, f"{version}: missing field {f} in record {r.get('id')}"

    # C. At least one record has label=1 (the slice was non-empty).
    pos = [r for r in records if r["label"] == 1]
    assert pos, f"{version}: no positive labels in dataset"
    log.info("  positive records: %d / %d (%.1f%%)",
             len(pos), len(records), 100 * len(pos) / len(records))

    # D. parse_header records: at least one statement should have been marked
    #    in_slice (via Step 5), so label=1.
    ph = [r for r in records if r["function"] == "parse_header"]
    assert ph, f"{version}: no parse_header records"
    ph_pos = [r for r in ph if r["label"] == 1]
    assert ph_pos, f"{version}: no parse_header records labeled 1"

    # E. copy_bytes's memcpy call: should be a sink, label=1, cross-function.
    memcpy_records = [
        r for r in records
        if r["called_function"] == "memcpy" and r["function"] == "copy_bytes"
    ]
    assert memcpy_records, \
        f"{version}: no memcpy call in copy_bytes found in dataset"
    m = memcpy_records[0]
    assert m["is_sink"] is True, f"memcpy should be is_sink=True: {m}"
    assert m["sink_reason"] == "cwe_api:memcpy", m
    assert m["label"] == 1, f"memcpy sink should be label=1: {m}"
    # The memcpy is reached from the patch via PARAM_BIND + CFG, so distance
    # should be finite and >= 1 (it's not a patch node itself).
    assert m["distance_to_patch"] >= 1, m
    assert m["is_patch_related"] is True, m
    log.info("  memcpy record: distance=%d is_cross_function=%s type=%s",
             m["distance_to_patch"], m["is_cross_function"], m["type"])

    # F. distance_to_patch is 0 for exactly the patch nodes.
    zero_dist = [r for r in records if r["distance_to_patch"] == 0]
    assert zero_dist, f"{version}: no nodes with distance_to_patch=0"
    for r in zero_dist:
        assert r["function_role"] == "patch", \
            f"distance=0 but role != patch: {r}"
    log.info("  %d records at distance 0 (all in patch function)", len(zero_dist))

    # G. Neighbor lists cross-reference correctly. Pick a record with a
    #    CFG successor and verify the successor's predecessors contain us.
    by_id = {r["id"]: r for r in records}
    sample = next((r for r in records if r["CFG_successors"]), None)
    if sample:
        succ_id = sample["CFG_successors"][0]
        assert succ_id in by_id, f"CFG successor {succ_id} not in dataset"
        succ = by_id[succ_id]
        assert sample["id"] in succ["CFG_predecessors"], (
            f"{sample['id']} -> {succ_id} via CFG, but reverse edge missing "
            f"in successor's predecessors: {succ['CFG_predecessors']}"
        )
        log.info("  CFG edge symmetry verified")

    # H. At least one record is cross-function (parse_header's call to
    #    copy_bytes, plus copy_bytes's entry).
    cross = [r for r in records if r["is_cross_function"]]
    assert cross, f"{version}: no cross-function records"
    log.info("  %d cross-function records", len(cross))

    # I. `modified_lines` is populated exactly on patch-role function records.
    for r in records:
        if r["function_role"] == "patch":
            assert r["modified_lines"], \
                f"patch role but empty modified_lines: {r['id']}"
        else:
            assert not r["modified_lines"], \
                f"non-patch role has modified_lines: {r['id']} role={r['function_role']}"

    log.info("Step 7 assertions passed for %s", version)


def assert_step7(records, version: str) -> None:
    """Step 7 assertions: the emitted records are well-formed and the memcpy
    sink shows up as a label=1 record with the expected structure."""
    import json
    log.info("---- Step 7 assertions (%s) ----", version)
    log.info("  %d records emitted", len(records))

    # A. JSON-serializable.
    s = json.dumps(records)
    assert "Infinity" not in s and "NaN" not in s
    log.info("  ✓ JSON round-trip clean (%d bytes)", len(s))

    # B. Every record has the required schema fields.
    required = {
        "id", "patch_id", "version", "commit",
        "function", "role", "file", "line",
        "statement", "type", "depth", "depth_ast",
        "variables_used", "variables_defined",
        "in_loop", "in_branch", "called_function",
        "is_sink", "sink_reason",
        "is_patch_related", "distance_to_patch", "is_cross_function",
        "CFG_successors", "CFG_predecessors",
        "DFG_successors", "DFG_predecessors",
        "CALL_edges", "PARAM_BIND_edges",
        "in_slice", "label",
    }
    for r in records[:3]:  # check a sample; all records built from same code path
        missing = required - r.keys()
        assert not missing, f"{version}: record missing fields {missing}"

    # C. IDs are unique.
    ids = [r["id"] for r in records]
    assert len(ids) == len(set(ids)), f"{version}: duplicate IDs in output"

    # D. At least one record has label=1 (the slice is non-empty — Step 5
    #    already checked this at graph level; here we check it made it out).
    positives = [r for r in records if r["label"] == 1]
    assert positives, f"{version}: no label=1 records emitted"
    log.info("  label=1: %d records (%.1f%%)",
             len(positives), 100 * len(positives) / len(records))

    # E. The memcpy sink in copy_bytes shows up as a label=1 record with
    #    is_sink=True, sink_reason='cwe_api:memcpy', and a finite
    #    distance_to_patch (because PARAM_BIND + CFG connects it back).
    memcpy_records = [
        r for r in records
        if r["function"] == "copy_bytes" and r["called_function"] == "memcpy"
    ]
    assert memcpy_records, f"{version}: no memcpy record in copy_bytes"
    m = memcpy_records[0]
    assert m["is_sink"] is True, f"memcpy not marked is_sink: {m}"
    assert m["sink_reason"] == "cwe_api:memcpy", m["sink_reason"]
    assert m["label"] == 1, f"memcpy should be in slice -> label=1, got {m['label']}"
    assert m["distance_to_patch"] is not None, \
        f"memcpy should have finite distance_to_patch (via PARAM_BIND); got None"
    assert m["is_patch_related"] is True
    log.info("  ✓ memcpy record: label=%d distance=%s reason=%s",
             m["label"], m["distance_to_patch"], m["sink_reason"])

    # F. Neighbor-list IDs are valid canonical IDs, not raw Joern IDs.
    id_set = set(ids)
    for r in records:
        for field in ("CFG_successors", "CFG_predecessors",
                      "DFG_successors", "DFG_predecessors",
                      "CALL_edges", "PARAM_BIND_edges"):
            for nid in r[field]:
                assert nid in id_set, \
                    f"{version}: {r['id']}.{field} refs unknown id {nid!r}"

    # G. is_cross_function is set where expected — the parse_header -> copy_bytes
    #    call site and copy_bytes's METHOD_ENTRY both should have it.
    ph_cross = [r for r in records
                if r["function"] == "parse_header" and r["is_cross_function"]]
    assert ph_cross, f"{version}: no is_cross_function=True record in parse_header"
    log.info("  ✓ %d cross-function records in parse_header", len(ph_cross))

    # H. Variables are rolled up: the memcpy record uses dst, src, len (or
    #    whatever Joern's identifier extraction found — at least ONE var).
    assert m["variables_used"], \
        f"memcpy record has no variables_used: {m}"
    log.info("  ✓ memcpy variables_used: %s", m["variables_used"])

    # I. Role diversity in positives: the slice should include BOTH patch and
    #    callee roles (we tested this at graph level in Step 5; here at record level).
    roles_in_positives = {r["role"] for r in positives}
    assert "patch" in roles_in_positives
    assert "callee" in roles_in_positives, \
        f"callee role missing from positive labels: {roles_in_positives}"

    log.info("Step 7 assertions passed for %s", version)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    # Every run uses a fresh temp dir AND a fresh CPG cache to avoid any
    # cross-test contamination. The cache uses sha1(repo_path + commit) so
    # two tmp runs already can't collide, but purging removes a whole class
    # of "why is this stale?" surprises during development.
    tmp = Path(tempfile.mkdtemp(prefix="vuln_smoke_"))
    log.info("tmp dir: %s", tmp)

    try:
        repo = tmp / "repo"
        commit_vuln, commit_fix = build_synthetic_repo(repo)

        # Scope the CPG cache to this tmp dir so we don't pollute the user's
        # real ~/.cache, and so a failed test leaves no state behind.
        cache_root = tmp / "cpg_cache"
        from pipeline import cpg_cache
        original_default = cpg_cache.DEFAULT_CACHE_ROOT
        cpg_cache.DEFAULT_CACHE_ROOT = cache_root

        try:
            log.info("---- running Step 1 ----")
            results = find_candidate_functions(
                repo_path=repo,
                commit_vuln=commit_vuln,
                commit_fix=commit_fix,
                patch_id="smoke/test1",
            )

            log.info("---- asserting Step 1 ----")
            assert_step1(results, "vulnerable")
            assert_step1(results, "fixed")

            log.info("---- running Step 2 (both versions) ----")
            graphs = {}
            for version, commit in (("vulnerable", commit_vuln),
                                    ("fixed", commit_fix)):
                handle = get_or_build_cpg(repo, commit)
                graphs[version] = build_program_graph(handle, results[version])

            log.info("---- asserting Step 2 ----")
            assert_step2(graphs["vulnerable"], "vulnerable")
            assert_step2(graphs["fixed"], "fixed")

            log.info("---- running Step 3 (both versions) ----")
            # Our synthetic CVE is a classic buffer overflow -> CWE-120.
            for version, G in graphs.items():
                identify_sinks(G, cwes=["CWE-120"])

            log.info("---- asserting Step 3 ----")
            assert_step3(graphs["vulnerable"], "vulnerable")
            assert_step3(graphs["fixed"], "fixed")

            log.info("---- running Step 5 (both versions) ----")
            for version, G in graphs.items():
                compute_slice(G)

            log.info("---- asserting Step 5 ----")
            assert_step5(graphs["vulnerable"], "vulnerable")
            assert_step5(graphs["fixed"], "fixed")

            log.info("---- running Step 7 (both versions) ----")
            all_records = {
                version: annotate_nodes(G) for version, G in graphs.items()
            }

            log.info("---- asserting Step 7 ----")
            assert_step7(all_records["vulnerable"], "vulnerable")
            assert_step7(all_records["fixed"], "fixed")

            # Small diagnostic: show the memcpy record on the vulnerable version.
            memcpy_rec = next(
                r for r in all_records["vulnerable"]
                if r["function"] == "copy_bytes" and r["called_function"] == "memcpy"
            )
            log.info("---- sample memcpy record (vulnerable) ----")
            for k in ("id", "function", "role", "statement", "type",
                      "line", "distance_to_patch", "is_patch_related",
                      "is_cross_function", "is_sink", "sink_reason",
                      "variables_used", "label"):
                log.info("  %-20s %s", k, memcpy_rec.get(k))

            log.info("---- running Step 7 (annotation) ----")
            datasets = {v: annotate_nodes(g) for v, g in graphs.items()}

            log.info("---- asserting Step 7 ----")
            assert_step7(datasets["vulnerable"], "vulnerable")
            assert_step7(datasets["fixed"], "fixed")

            # Emit a sample record so running the smoke test shows what the
            # final deliverable looks like.
            import json as _json
            sample = datasets["vulnerable"][0]
            log.info("---- sample record (vulnerable, first node) ----")
            log.info("\n%s", _json.dumps(sample, indent=2, default=str))

            log.info("---- running Step 7 (both versions) ----")
            records_by_version = {}
            for version, G in graphs.items():
                records_by_version[version] = annotate_nodes(G)

            log.info("---- asserting Step 7 ----")
            assert_step7(records_by_version["vulnerable"], "vulnerable")
            assert_step7(records_by_version["fixed"], "fixed")

        finally:
            cpg_cache.DEFAULT_CACHE_ROOT = original_default

        log.info("SMOKE TEST PASSED")
        return 0

    except Exception as e:
        log.error("SMOKE TEST FAILED: %s", e, exc_info=True)
        return 1
    finally:
        # Keep tmp dir on failure for debugging; clean on success.
        if os.environ.get("KEEP_TMP"):
            log.info("KEEP_TMP set, leaving %s", tmp)
        else:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())