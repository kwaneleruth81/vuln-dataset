"""
sinks.py — Step 3 of the pipeline: identify sink nodes in the program graph.

Sinks are statements where a vulnerability *manifests* — typically calls to
dangerous APIs (memcpy, strcpy, system, ...) or otherwise-suspicious operations.
We flag them here so Step 5 (slicing) knows where to anchor backward traversal.

Three signal sources, unioned:

  1. CWE-keyed dangerous-API list
       If the patch has known CWE(s), use the APIs mapped to those CWEs.
       If CWE is unknown/empty, fall back to the full API set.
  2. Patch proximity
       Any dangerous-API call within PROXIMITY_LINES lines of a patched line
       is flagged, even if its CWE wasn't in the patch's CWE list. Broadens
       recall — useful when CVE's CWE tagging is imprecise.
  3. User-provided overrides
       Caller may pass `extra_sinks=[(file, line), ...]` for crash-trace or
       manually annotated sinks. Always marked regardless of API match.

Output: graph mutated in-place with per-node attributes:
    is_sink      : bool
    sink_reason  : str | None   — "cwe_api:<name>" | "patch_proximity:<name>"
                                  | "user" | None
Plus a returned SinkReport with counts, for logging/debugging.

Zero sinks is NOT an error — some patches target logic bugs with no dangerous
API in sight. Step 5's slicer will fall back to patch-only anchoring.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Iterable

import networkx as nx

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CWE -> dangerous API map
# ---------------------------------------------------------------------------
#
# Conventions:
# * Keys are normalized CWE IDs as "CWE-<num>" (string, zero-padding optional).
# * Values are sets of function names as Joern would report them in C.
# * A single API may appear under multiple CWEs (expected — one API can
#   cause multiple bug classes).
# * Only the APIs most commonly implicated in CVEs are listed. Expand as we
#   learn from real data. If this grows past ~100 entries, move to a YAML file.
#
# Coverage note: no wildcards or aliases (e.g., `__builtin_memcpy` not listed).
# Joern's C front-end canonicalizes most of these to the POSIX name, but
# repo-specific wrappers (like `safe_memcpy`) will NOT be caught here. That's
# what `extra_sinks` is for.

CWE_API_MAP: dict[str, set[str]] = {
    # Memory safety — buffer overflow family
    "CWE-119": {  # Improper restriction of ops within bounds
        "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat", "strncat",
        "sprintf", "snprintf", "vsprintf", "vsnprintf", "gets", "scanf", "sscanf",
        "fscanf", "alloca", "bcopy",
    },
    "CWE-120": {  # Classic buffer overflow (CWE-119 child)
        "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf", "sscanf",
        "memcpy", "memmove", "bcopy", "strncpy", "strncat",
    },
    "CWE-121": {"alloca", "strcpy", "sprintf", "gets", "memcpy", "strcat"},  # stack overflow
    "CWE-122": {"malloc", "calloc", "realloc", "memcpy", "strcpy", "strcat", "sprintf"},  # heap
    "CWE-125": {"memcpy", "memmove", "strncpy", "strncat", "memcmp", "strcmp"},  # out-of-bounds read
    "CWE-126": {"strlen", "strnlen", "memchr", "strchr"},  # buffer over-read
    "CWE-787": {  # Out-of-bounds write
        "memcpy", "memmove", "strcpy", "strncpy", "strcat", "strncat",
        "sprintf", "snprintf", "vsprintf", "vsnprintf", "bcopy",
    },

    # Use-after-free / double-free / uninitialized
    "CWE-416": {"free", "g_free", "kfree", "vfree", "delete"},  # UAF — `free` is the classic hint
    "CWE-415": {"free", "g_free", "kfree", "vfree"},             # double-free
    "CWE-476": {"strcpy", "memcpy", "memset", "strlen", "strcmp"},  # NULL deref — these crash on NULL
    "CWE-457": {"memcpy", "strcpy"},  # use of uninitialized

    # Integer issues (the operators themselves aren't "sinks" but the APIs
    # that accept sizes derived from tainted math are)
    "CWE-190": {"malloc", "calloc", "realloc", "memcpy", "memmove", "memset"},  # overflow
    "CWE-191": {"malloc", "calloc", "realloc", "memcpy", "memmove", "memset"},  # underflow

    # Command/shell/SQL injection
    "CWE-77":  {"system", "popen", "exec", "execl", "execle", "execlp", "execv", "execvp", "execve"},
    "CWE-78":  {"system", "popen", "exec", "execl", "execle", "execlp", "execv", "execvp", "execve"},
    "CWE-88":  {"system", "popen", "exec", "execl", "execle", "execlp", "execv", "execvp"},
    "CWE-89":  {"mysql_query", "sqlite3_exec", "PQexec", "sqlite3_prepare"},

    # Format string
    "CWE-134": {"printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf",
                "vsprintf", "vsnprintf", "syslog", "err", "warn"},

    # Path traversal / unsafe file ops
    "CWE-22":  {"fopen", "open", "openat", "readlink", "access"},
    "CWE-73":  {"fopen", "open", "openat", "readlink"},

    # Cryptographic weakness (function presence is the hint)
    "CWE-327": {"MD5", "MD5_Init", "MD5_Update", "MD5_Final", "SHA1", "DES_set_key"},
    "CWE-338": {"rand", "srand", "random"},

    # Race conditions — these APIs are classic TOCTOU pairs
    "CWE-362": {"access", "stat", "lstat", "fstat", "chmod", "chown"},
    "CWE-367": {"access", "stat", "lstat", "fstat"},
}

# Union of every listed API. Used when the patch has no CWE assigned.
ALL_DANGEROUS_APIS: frozenset[str] = frozenset().union(*CWE_API_MAP.values())


# ---------------------------------------------------------------------------
# Public dataclass
# ---------------------------------------------------------------------------

@dataclass
class SinkReport:
    """Summary of what identify_sinks flagged. Emitted for logging and
    inclusion in the per-patch metadata down the line."""
    total_sinks: int = 0
    by_reason: dict[str, int] = field(default_factory=dict)
    # APIs that were matched (good for sanity checks)
    apis_hit: dict[str, int] = field(default_factory=dict)
    # If empty and cwes was non-empty, the CWE->API set didn't match any call
    # in this patch's candidate functions — worth noting.
    note: str | None = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _normalize_cwe(cwe: str) -> str:
    """Accept 'CWE-120', 'cwe-120', '120', 'CWE120' — normalize to 'CWE-120'."""
    s = cwe.strip().upper().replace(" ", "")
    if s.startswith("CWE-"):
        return s
    if s.startswith("CWE"):
        return "CWE-" + s[3:]
    if s.isdigit():
        return "CWE-" + s
    return s  # give up; will simply miss the map


def _apis_for_cwes(cwes: Iterable[str]) -> set[str]:
    """Union of dangerous APIs across the given CWE list. Empty input or
    unknown CWEs -> empty set."""
    out: set[str] = set()
    for c in cwes:
        apis = CWE_API_MAP.get(_normalize_cwe(c))
        if apis:
            out.update(apis)
    return out


def _collect_patched_lines(G: nx.MultiDiGraph) -> dict[str, set[int]]:
    """Return {file -> {patched line numbers}} for all candidate functions,
    using the metadata stashed on G by build_program_graph."""
    out: dict[str, set[int]] = {}
    for fn_full, meta in G.graph.get("candidate_functions", {}).items():
        file = meta.get("file", "")
        for ln in meta.get("modified_lines", []):
            out.setdefault(file, set()).add(int(ln))
    return out


def _node_file(G: nx.MultiDiGraph, nid: str) -> str:
    """File the statement belongs to. Joern sometimes puts `filename` on the
    statement node itself; if not, fall back to the owning function's file
    (tracked in G.graph['candidate_functions'])."""
    direct = G.nodes[nid].get("filename")
    if direct:
        return str(direct)
    fn = G.nodes[nid].get("function", "")
    meta = G.graph.get("candidate_functions", {}).get(fn, {})
    return str(meta.get("file", ""))


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def identify_sinks(
    G: nx.MultiDiGraph,
    cwes: list[str] | None = None,
    *,
    extra_sinks: list[tuple[str, int]] | None = None,
    proximity_lines: int = 3,
) -> SinkReport:
    """Mutate G in-place: set `is_sink` and `sink_reason` on every node.

    Parameters
    ----------
    G : statement graph from build_program_graph (Step 2).
    cwes : list like ["CWE-120", "CWE-787"]. Empty/None triggers broad fallback.
    extra_sinks : optional [(file, line), ...] — statements at these locations
                  are marked regardless of API match.
    proximity_lines : a dangerous-API call within this many lines of a patched
                  line is flagged via the patch-proximity rule, even if its
                  CWE wasn't listed. Default 3.

    Returns
    -------
    SinkReport with counts and API frequencies.
    """
    cwes = cwes or []
    extra_sinks = extra_sinks or []

    # 1. Decide which API set applies per strategy.
    cwe_apis = _apis_for_cwes(cwes)
    # Broad fallback when no CWE provided OR the CWE list didn't match our table.
    broad_fallback = (not cwe_apis)
    active_api_set = cwe_apis if cwe_apis else ALL_DANGEROUS_APIS

    # 2. Precompute patched lines by file for proximity checks.
    patched_by_file = _collect_patched_lines(G)

    # 3. Precompute user-provided sink lookup: {file: {lines}}
    extra_by_file: dict[str, set[int]] = {}
    for file, line in extra_sinks:
        extra_by_file.setdefault(file, set()).add(int(line))

    # 4. Initialize attributes on every node (so downstream code never sees
    #    KeyError on missing `is_sink`).
    for nid in G.nodes:
        G.nodes[nid]["is_sink"] = False
        G.nodes[nid]["sink_reason"] = None

    report = SinkReport()

    def _mark(nid: str, reason: str) -> None:
        """Idempotent mark. If the node is already a sink, keep the earliest
        reason — CWE match is emitted before proximity, so CWE wins naturally
        via loop ordering below. (This matters for `apis_hit` attribution.)"""
        if G.nodes[nid]["is_sink"]:
            return
        G.nodes[nid]["is_sink"] = True
        G.nodes[nid]["sink_reason"] = reason
        report.total_sinks += 1
        report.by_reason[reason] = report.by_reason.get(reason, 0) + 1

    # 5. Pass A: CWE-keyed API match across every candidate-function statement.
    for nid, attrs in G.nodes(data=True):
        if attrs.get("stmt_type") != "CALL":
            continue
        api = attrs.get("called_function")
        if not api or api not in active_api_set:
            continue
        _mark(nid, f"cwe_api:{api}")
        report.apis_hit[api] = report.apis_hit.get(api, 0) + 1

    # 6. Pass B: patch-proximity refinement. Use the FULL api set here — the
    #    whole point of proximity is to catch APIs whose CWE isn't listed.
    if patched_by_file and proximity_lines >= 0:
        for nid, attrs in G.nodes(data=True):
            if attrs.get("is_sink"):
                continue  # already flagged by pass A
            if attrs.get("stmt_type") != "CALL":
                continue
            api = attrs.get("called_function")
            if not api or api not in ALL_DANGEROUS_APIS:
                continue
            file = _node_file(G, nid)
            if file not in patched_by_file:
                continue
            line = int(attrs.get("line") or 0)
            if not line:
                continue
            if any(abs(line - pl) <= proximity_lines
                   for pl in patched_by_file[file]):
                _mark(nid, f"patch_proximity:{api}")
                report.apis_hit[api] = report.apis_hit.get(api, 0) + 1

    # 7. Pass C: user-provided overrides. Match by (file, line) exactly.
    if extra_by_file:
        for nid, attrs in G.nodes(data=True):
            file = _node_file(G, nid)
            line = int(attrs.get("line") or 0)
            if file in extra_by_file and line in extra_by_file[file]:
                _mark(nid, "user")

    # 8. Bookkeeping / notes.
    if cwes and not cwe_apis:
        report.note = (
            f"CWE list {cwes} had no entries in CWE_API_MAP; used broad fallback"
        )
        log.info(report.note)
    elif broad_fallback:
        report.note = "no CWE provided; used broad fallback (all dangerous APIs)"

    if report.total_sinks == 0:
        log.warning(
            "no sinks identified for this patch (cwes=%s); "
            "Step 5 will anchor on patch nodes only", cwes,
        )
    else:
        log.info(
            "identified %d sinks (by_reason=%s, top APIs=%s)",
            report.total_sinks, report.by_reason,
            sorted(report.apis_hit.items(), key=lambda kv: -kv[1])[:5],
        )

    # Stash report on the graph too, so downstream steps can see it without
    # threading it through every call signature.
    G.graph["sink_report"] = report
    return report
