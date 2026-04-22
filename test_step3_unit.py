"""Unit tests for Step 3 (sink identification). No Joern required.

Builds synthetic statement graphs by hand and exercises every branch:
  - CWE-matched API
  - Broad-fallback when CWE missing
  - Broad-fallback when CWE provided but unknown
  - Patch-proximity refinement picks up adjacent sink
  - Patch-proximity does NOT reach past proximity_lines
  - User-provided extra_sinks
  - Zero-sink case is handled gracefully
  - CWE normalization ("120" / "cwe-120" / "CWE-120" all match)
  - Deduplication: a node matched by CWE is NOT re-marked by proximity
"""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import networkx as nx
from pipeline.sinks import (
    identify_sinks, _normalize_cwe, _apis_for_cwes,
    CWE_API_MAP, ALL_DANGEROUS_APIS,
)


def _make_graph(stmts, candidate_functions=None, patched_lines_by_fn=None):
    """Build a minimal statement graph. `stmts` is a list of
    (nid, stmt_type, called_function, function, line, file?)."""
    G = nx.MultiDiGraph()
    for row in stmts:
        nid, st, cf, fn, line = row[:5]
        file = row[5] if len(row) > 5 else None
        attrs = dict(
            stmt_type=st, called_function=cf,
            function=fn, line=line,
        )
        if file is not None:
            attrs["filename"] = file
        G.add_node(nid, **attrs)
    # Stash candidate_functions metadata as build_program_graph would.
    G.graph["candidate_functions"] = candidate_functions or {}
    return G


# ---------------------------------------------------------------------------
# CWE normalization
# ---------------------------------------------------------------------------

def test_normalize_cwe():
    assert _normalize_cwe("CWE-120") == "CWE-120"
    assert _normalize_cwe("cwe-120") == "CWE-120"
    assert _normalize_cwe("CWE120")  == "CWE-120"
    assert _normalize_cwe("120")     == "CWE-120"
    assert _normalize_cwe("  CWE-787 ") == "CWE-787"
    print("test_normalize_cwe OK")


def test_apis_for_cwes():
    # CWE-120 should include memcpy.
    assert "memcpy" in _apis_for_cwes(["CWE-120"])
    # Unknown CWE -> empty.
    assert _apis_for_cwes(["CWE-9999"]) == set()
    # Mixed: known + unknown returns just the known one's APIs.
    assert "memcpy" in _apis_for_cwes(["CWE-120", "CWE-9999"])
    # Lowercase still works.
    assert "memcpy" in _apis_for_cwes(["cwe-120"])
    print("test_apis_for_cwes OK")


# ---------------------------------------------------------------------------
# Core identification paths
# ---------------------------------------------------------------------------

def test_cwe_matched_api():
    """CWE-120 patch with a memcpy call — should be flagged with cwe_api reason."""
    G = _make_graph([
        ("n1", "METHOD_ENTRY", None, "foo", 10),
        ("n2", "ASSIGN", None, "foo", 11),
        ("n3", "CALL", "memcpy", "foo", 12),
        ("n4", "RETURN", None, "foo", 13),
    ])
    report = identify_sinks(G, cwes=["CWE-120"])
    assert G.nodes["n3"]["is_sink"] is True, G.nodes["n3"]
    assert G.nodes["n3"]["sink_reason"] == "cwe_api:memcpy"
    assert G.nodes["n1"]["is_sink"] is False
    assert G.nodes["n2"]["is_sink"] is False
    assert G.nodes["n4"]["is_sink"] is False
    assert report.total_sinks == 1
    assert report.apis_hit == {"memcpy": 1}
    print("test_cwe_matched_api OK")


def test_cwe_mismatched_api():
    """CWE-77 (command injection) patch — memcpy should NOT be flagged because
    it's not in that CWE's API set."""
    G = _make_graph([
        ("n1", "CALL", "memcpy", "foo", 10),
        ("n2", "CALL", "system", "foo", 11),
    ])
    report = identify_sinks(G, cwes=["CWE-77"])
    assert G.nodes["n1"]["is_sink"] is False, "memcpy not in CWE-77"
    assert G.nodes["n2"]["is_sink"] is True,  "system IS in CWE-77"
    assert G.nodes["n2"]["sink_reason"] == "cwe_api:system"
    assert report.total_sinks == 1
    print("test_cwe_mismatched_api OK")


def test_broad_fallback_empty_cwe():
    """No CWE given -> broad fallback should hit memcpy."""
    G = _make_graph([
        ("n1", "CALL", "memcpy", "foo", 10),
        ("n2", "CALL", "harmless_helper", "foo", 11),
    ])
    report = identify_sinks(G, cwes=[])
    assert G.nodes["n1"]["is_sink"] is True
    assert G.nodes["n2"]["is_sink"] is False
    assert report.note and "broad fallback" in report.note.lower()
    print("test_broad_fallback_empty_cwe OK")


def test_broad_fallback_unknown_cwe():
    """CWE provided but not in our table -> broad fallback with explicit note."""
    G = _make_graph([("n1", "CALL", "memcpy", "foo", 10)])
    report = identify_sinks(G, cwes=["CWE-9999"])
    assert G.nodes["n1"]["is_sink"] is True
    assert report.note and "CWE-9999" in report.note
    print("test_broad_fallback_unknown_cwe OK")


# ---------------------------------------------------------------------------
# Patch-proximity
# ---------------------------------------------------------------------------

def test_patch_proximity_picks_up_adjacent_sink():
    """CWE-362 doesn't list memcpy, but a memcpy call within 3 lines of a
    patched line should still be flagged via proximity."""
    cand = {"foo": {
        "name": "foo", "role": "patch", "hop_distance": 0,
        "modified_lines": [50], "file": "src/foo.c",
    }}
    G = _make_graph([
        ("n1", "CALL", "memcpy", "foo", 52, "src/foo.c"),   # within 3 of line 50
        ("n2", "CALL", "memcpy", "foo", 60, "src/foo.c"),   # too far
    ], candidate_functions=cand)
    report = identify_sinks(G, cwes=["CWE-362"], proximity_lines=3)
    assert G.nodes["n1"]["is_sink"] is True, "n1 within proximity"
    assert G.nodes["n1"]["sink_reason"].startswith("patch_proximity:")
    assert G.nodes["n2"]["is_sink"] is False, "n2 beyond proximity"
    assert report.total_sinks == 1
    print("test_patch_proximity_picks_up_adjacent_sink OK")


def test_proximity_respects_file_boundary():
    """A memcpy call on line 50 of file B should NOT be flagged as proximate
    to a patched line 50 of file A."""
    cand = {"foo": {
        "name": "foo", "role": "patch", "hop_distance": 0,
        "modified_lines": [50], "file": "src/a.c",
    }, "bar": {
        "name": "bar", "role": "callee", "hop_distance": 1,
        "modified_lines": [], "file": "src/b.c",
    }}
    G = _make_graph([
        ("n1", "CALL", "memcpy", "bar", 50, "src/b.c"),
    ], candidate_functions=cand)
    report = identify_sinks(G, cwes=["CWE-362"], proximity_lines=3)
    assert G.nodes["n1"]["is_sink"] is False, "different file, no proximity"
    assert report.total_sinks == 0
    print("test_proximity_respects_file_boundary OK")


def test_cwe_match_wins_over_proximity():
    """If a node is matched by both CWE and proximity, the reason should be
    cwe_api (CWE pass runs first and idempotent mark keeps it)."""
    cand = {"foo": {
        "name": "foo", "role": "patch", "hop_distance": 0,
        "modified_lines": [10], "file": "src/foo.c",
    }}
    G = _make_graph([
        ("n1", "CALL", "memcpy", "foo", 11, "src/foo.c"),
    ], candidate_functions=cand)
    report = identify_sinks(G, cwes=["CWE-120"], proximity_lines=3)
    assert G.nodes["n1"]["is_sink"] is True
    assert G.nodes["n1"]["sink_reason"] == "cwe_api:memcpy"
    # Only counted once.
    assert report.total_sinks == 1
    assert report.apis_hit == {"memcpy": 1}
    print("test_cwe_match_wins_over_proximity OK")


# ---------------------------------------------------------------------------
# User overrides
# ---------------------------------------------------------------------------

def test_user_override():
    """A statement at (file, line) in extra_sinks is marked even if not a
    dangerous API. Use case: crash trace points to a custom wrapper."""
    G = _make_graph([
        ("n1", "CALL", "custom_wrapper", "foo", 42, "src/foo.c"),
    ])
    report = identify_sinks(
        G, cwes=["CWE-120"],
        extra_sinks=[("src/foo.c", 42)],
    )
    assert G.nodes["n1"]["is_sink"] is True
    assert G.nodes["n1"]["sink_reason"] == "user"
    print("test_user_override OK")


def test_user_override_does_not_override_cwe_reason():
    """If a node matches CWE and is also in extra_sinks, CWE reason wins
    (it's the more informative one)."""
    G = _make_graph([
        ("n1", "CALL", "memcpy", "foo", 42, "src/foo.c"),
    ])
    identify_sinks(
        G, cwes=["CWE-120"],
        extra_sinks=[("src/foo.c", 42)],
    )
    assert G.nodes["n1"]["sink_reason"] == "cwe_api:memcpy"
    print("test_user_override_does_not_override_cwe_reason OK")


# ---------------------------------------------------------------------------
# Zero-sink case
# ---------------------------------------------------------------------------

def test_zero_sinks_is_not_an_error():
    """Patch with only assignments and arithmetic — no sinks found, no error."""
    G = _make_graph([
        ("n1", "ASSIGN", None, "foo", 10),
        ("n2", "ARITH",  None, "foo", 11),
        ("n3", "RETURN", None, "foo", 12),
    ])
    report = identify_sinks(G, cwes=["CWE-120"])
    assert report.total_sinks == 0
    # Every node still initialized.
    for n in ("n1", "n2", "n3"):
        assert G.nodes[n]["is_sink"] is False
        assert G.nodes[n]["sink_reason"] is None
    print("test_zero_sinks_is_not_an_error OK")


# ---------------------------------------------------------------------------
# Multiple CWEs — union semantics
# ---------------------------------------------------------------------------

def test_multiple_cwes_union():
    """CWE-120 covers memcpy; CWE-77 covers system. Patch tagged with both
    should flag both."""
    G = _make_graph([
        ("n1", "CALL", "memcpy", "foo", 10),
        ("n2", "CALL", "system", "foo", 11),
        ("n3", "CALL", "strlen", "foo", 12),  # CWE-126, not in our list here
    ])
    report = identify_sinks(G, cwes=["CWE-120", "CWE-77"])
    assert G.nodes["n1"]["is_sink"] is True
    assert G.nodes["n2"]["is_sink"] is True
    assert G.nodes["n3"]["is_sink"] is False
    assert report.total_sinks == 2
    print("test_multiple_cwes_union OK")


# ---------------------------------------------------------------------------
# Non-CALL statements are never sinks via API match
# ---------------------------------------------------------------------------

def test_non_call_stmts_never_flagged_by_api():
    """An ASSIGN whose called_function happens to be set to 'memcpy' (nonsense
    but defensive) must not be flagged — only CALL statements are eligible."""
    G = _make_graph([
        ("n1", "ASSIGN", "memcpy", "foo", 10),  # pathological
    ])
    report = identify_sinks(G, cwes=["CWE-120"])
    assert G.nodes["n1"]["is_sink"] is False
    assert report.total_sinks == 0
    print("test_non_call_stmts_never_flagged_by_api OK")


# ---------------------------------------------------------------------------
# Data sanity
# ---------------------------------------------------------------------------

def test_api_map_wellformed():
    """Basic sanity on the CWE_API_MAP itself so refactors don't break it."""
    for cwe, apis in CWE_API_MAP.items():
        assert cwe.startswith("CWE-"), f"bad CWE key: {cwe}"
        assert apis, f"empty API set for {cwe}"
        for a in apis:
            assert a and a.strip() == a, f"malformed API in {cwe}: {a!r}"
    assert "memcpy" in ALL_DANGEROUS_APIS
    assert "system" in ALL_DANGEROUS_APIS
    print("test_api_map_wellformed OK")


if __name__ == "__main__":
    test_normalize_cwe()
    test_apis_for_cwes()
    test_cwe_matched_api()
    test_cwe_mismatched_api()
    test_broad_fallback_empty_cwe()
    test_broad_fallback_unknown_cwe()
    test_patch_proximity_picks_up_adjacent_sink()
    test_proximity_respects_file_boundary()
    test_cwe_match_wins_over_proximity()
    test_user_override()
    test_user_override_does_not_override_cwe_reason()
    test_zero_sinks_is_not_an_error()
    test_multiple_cwes_union()
    test_non_call_stmts_never_flagged_by_api()
    test_api_map_wellformed()
    print("\nAll Step 3 unit tests passed.")
