"""
find_candidates.py — Step 1 of the vulnerability dataset pipeline.

Given a patch (repo, commit_vuln, commit_fix, changed_files), produce the
candidate function list PER COMMIT VERSION:

    candidate_functions = patch_functions ∪ callers(patch_functions)
                                          ∪ callees(patch_functions)

where callers/callees are 1-hop by default (configurable). The result is
the "bounded subgraph" of functions that downstream steps operate on.

Version-aware modified lines (locked decision from spec):
  * commit_vuln : modified lines = lines REMOVED by the patch + context
  * commit_fix  : modified lines = lines ADDED   by the patch

Outputs a list of CandidateFunction dicts (see schema below). Patches with
no function-scope changes are flagged SKIP and logged — the caller decides
whether to drop them from the work queue.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable, Literal

from .cpg_cache import CPGHandle, get_or_build_cpg
from ._cpg_loader import load_cpg_graph

log = logging.getLogger(__name__)

Version = Literal["vulnerable", "fixed"]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class CandidateFunction:
    """One function in the bounded subgraph for a given commit."""
    function_name: str
    file: str                       # repo-relative path
    start_line: int
    end_line: int
    role: Literal["patch", "caller", "callee"]
    hop_distance: int               # 0 for patch, 1..N for neighbors
    modified_lines: list[int] = field(default_factory=list)
    method_full_name: str = ""      # Joern's unique ID, used downstream
    commit: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Step1Result:
    patch_id: str
    commit: str
    version: Version
    candidate_functions: list[CandidateFunction]
    skipped_reason: str | None = None   # set if no usable patch functions


# ---------------------------------------------------------------------------
# Sub-task A: parse the diff, extract modified lines per file per version
# ---------------------------------------------------------------------------

# A unified-diff hunk header looks like:
#   @@ -old_start,old_count +new_start,new_count @@ optional_section_heading
_HUNK_RE = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? "
    r"\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@"
)


def _git_diff(repo: Path, commit_vuln: str, commit_fix: str) -> str:
    """Return the unified diff between two commits.

    Robustness flags:
      * errors="replace" — some real-world commits touch binary or non-UTF-8
        text files, and the default strict UTF-8 decoding explodes. We replace
        bad bytes with U+FFFD since we only parse hunk headers and +/-
        prefixes, not the actual line content.
      * --binary-files=without-match via the text-only diff path (no binary
        patches in output) — we don't need the binary blob content anyway.
    """
    res = subprocess.run(
        ["git", "diff", "--unified=3",
         # Omit binary file diffs entirely. We couldn't parse them usefully,
         # and they inflate diff size enormously on CVEs that touch, e.g.,
         # test fixtures.
         "--no-textconv",
         f"{commit_vuln}..{commit_fix}"],
        cwd=repo, capture_output=True, text=True, check=True,
        errors="replace",
    )
    return res.stdout


def parse_modified_lines(
    diff_text: str,
) -> dict[str, dict[Version, list[int]]]:
    """
    Walk the unified diff and, per file, collect:
      * vulnerable-side line numbers for every '-' line (and context adjacent
        to additions — the "nearby" vulnerable code the fix touches)
      * fixed-side line numbers for every '+' line

    Returns {repo_relative_path: {"vulnerable": [..], "fixed": [..]}}

    We DON'T try to be clever about whitespace-only or comment-only changes
    here. That filtering (if we want it) happens later, after we know which
    function each line lands in.
    """
    per_file: dict[str, dict[Version, list[int]]] = {}
    current_file: str | None = None
    old_lineno = new_lineno = 0

    for raw in diff_text.splitlines():
        # File header: "+++ b/path/to/file.c" is the post-patch path.
        # We key on this; renames would need "--- a/..." tracking too, punt for v1.
        if raw.startswith("+++ "):
            path = raw[4:].strip()
            if path == "/dev/null":
                current_file = None
                continue
            # Strip the "b/" prefix git adds
            current_file = path[2:] if path.startswith("b/") else path
            per_file.setdefault(current_file, {"vulnerable": [], "fixed": []})
            continue

        if current_file is None:
            continue

        m = _HUNK_RE.match(raw)
        if m:
            old_lineno = int(m["old_start"])
            new_lineno = int(m["new_start"])
            continue

        if not raw or raw[0] not in " +-":
            continue  # metadata line inside a file block (e.g., "\ No newline")

        tag, _, _ = raw[0], raw[1:], None
        if tag == "-":
            # Removed line: belongs to the vulnerable version.
            per_file[current_file]["vulnerable"].append(old_lineno)
            old_lineno += 1
        elif tag == "+":
            # Added line: belongs to the fixed version.
            per_file[current_file]["fixed"].append(new_lineno)
            new_lineno += 1
        else:  # context line ' '
            # Context next to changes is a useful proxy for "the vulnerable
            # neighborhood" when a hunk is pure additions (nothing removed).
            # We'll include immediate-context lines as modified-on-vuln-side
            # ONLY when the hunk has no '-' lines at all — handled in a
            # post-pass below so we don't bloat every file.
            old_lineno += 1
            new_lineno += 1

    # Post-pass: for any file where fixed has lines but vulnerable is empty
    # (pure-addition patch), we still want SOMETHING function-scoped on the
    # vuln side. Re-walk and grab the context lines of additive hunks.
    # This keeps the vulnerable-version processing meaningful for
    # "added a bounds check" style fixes.
    _fill_vuln_context_for_pure_additions(diff_text, per_file)

    return per_file


def _fill_vuln_context_for_pure_additions(
    diff_text: str, per_file: dict[str, dict[Version, list[int]]],
    *, window: int = 2,
) -> None:
    """For files where the vulnerable side has no removed lines, approximate
    "what was vulnerable" by collecting old-side line numbers of context lines
    IMMEDIATELY ADJACENT to additions (within `window` lines before or after
    a `+` line).

    We can't just grab every context line in an additive hunk, because hunks
    have 3+ lines of context at their edges by default, and those edges can
    sit inside an unrelated adjacent function. For example, a fix that adds
    a bounds check inside `parse_header()` will have hunk context that includes
    the closing `}` of the function above it — we don't want to attribute
    that line to the prior function.

    This walker does one pass, buffering recent context lines and flushing
    them as "kept" whenever a `+` line is seen (within `window` distance)."""
    current_file: str | None = None
    old_lineno = 0
    hunk_has_additions = False
    # Running buffer: the last N context lines' old-side line numbers.
    recent_context: list[int] = []
    # Context lines we've committed to keeping (they were within `window`
    # of a `+` line, either before or after it).
    kept_context: list[int] = []
    # Counter: how many more upcoming context lines should be kept because
    # we just saw a '+'. Reset on each new hunk.
    keep_next_n = 0

    def flush():
        nonlocal hunk_has_additions, recent_context, kept_context, keep_next_n
        if current_file and hunk_has_additions and not per_file[current_file]["vulnerable"]:
            per_file[current_file]["vulnerable"].extend(sorted(set(kept_context)))
        hunk_has_additions = False
        recent_context = []
        kept_context = []
        keep_next_n = 0

    for raw in diff_text.splitlines():
        if raw.startswith("+++ "):
            flush()
            path = raw[4:].strip()
            current_file = None if path == "/dev/null" else (
                path[2:] if path.startswith("b/") else path
            )
            continue
        if current_file is None:
            continue
        m = _HUNK_RE.match(raw)
        if m:
            flush()
            old_lineno = int(m["old_start"])
            continue
        if not raw or raw[0] not in " +-":
            continue
        t = raw[0]
        if t == "+":
            hunk_has_additions = True
            # Keep the trailing `window` context lines we just saw (pre-addition).
            kept_context.extend(recent_context[-window:])
            # And flag the next `window` context lines (post-addition).
            keep_next_n = window
            # Don't advance old_lineno — '+' lines don't exist on the old side.
        elif t == "-":
            # Removals; non-pure-addition files are handled by the primary
            # walker, but stay consistent with line bookkeeping.
            old_lineno += 1
            recent_context = []  # a removal breaks the adjacency chain
        else:  # context line ' '
            if keep_next_n > 0:
                kept_context.append(old_lineno)
                keep_next_n -= 1
            recent_context.append(old_lineno)
            # Keep recent_context bounded so we don't retain earlier hunk context.
            if len(recent_context) > window:
                recent_context = recent_context[-window:]
            old_lineno += 1
    flush()


# ---------------------------------------------------------------------------
# Sub-task B: load Joern CPG and extract the call graph + function metadata
# ---------------------------------------------------------------------------

def _load_cpg_graphml(graph_dir: Path) -> "nx.MultiDiGraph":
    """Load the Joern neo4jcsv export in graph_dir into a NetworkX MultiDiGraph."""
    return load_cpg_graph(graph_dir)


@dataclass
class _MethodInfo:
    """Minimal info we need about every function in the CPG."""
    full_name: str                # Joern's unique ID
    name: str                     # short name
    filename: str                 # repo-relative where possible
    start_line: int
    end_line: int


def load_methods_and_callgraph(
    handle: CPGHandle,
) -> tuple[dict[str, _MethodInfo], dict[str, set[str]], dict[str, set[str]]]:
    """Load the exported graphml CPG and extract:
        methods    : full_name -> _MethodInfo
        callers    : full_name -> {full_names of methods that CALL it}
        callees    : full_name -> {full_names of methods IT calls}

    METHOD nodes give us methods; CALL nodes with a 'METHOD_FULL_NAME' / or
    'methodFullName' property give us each call's target. The enclosing
    method of a call is found via CONTAINS / AST edge BFS from each METHOD."""

    G = _load_cpg_graphml(handle.graph_dir)

    methods: dict[str, _MethodInfo] = {}
    callers: dict[str, set[str]] = {}
    callees: dict[str, set[str]] = {}

    # node_id -> owning method full_name
    node_owner: dict[str, str] = {}
    pending_calls: list[tuple[str, str]] = []   # (call_node_id, target_full_name)

    worktree_prefix = str(handle.worktree.resolve()) + "/"

    def _first(attrs: dict, *keys: str, default=""):
        """Attempt multiple attribute names for a property; Joern's graphml
        uses SCREAMING_SNAKE (FULL_NAME, LINE_NUMBER, METHOD_FULL_NAME) but
        older versions used camelCase (fullName, lineNumber, methodFullName)."""
        for k in keys:
            if k in attrs and attrs[k] not in (None, ""):
                return attrs[k]
        return default

    # Pass 1: collect METHOD nodes, stash CALL targets for later resolution.
    for nid, attrs in G.nodes(data=True):
        label = attrs.get("_label", "")
        if label == "METHOD":
            full_name = str(_first(attrs, "FULL_NAME", "fullName",
                                   default=_first(attrs, "NAME", "name", default="")))
            short = str(_first(attrs, "NAME", "name", default=""))
            if not full_name or full_name.startswith("<operator>"):
                continue
            if short in ("<global>", "<includes>") or \
               full_name.endswith(":<global>") or \
               full_name.endswith(":<includes>"):
                continue
            fname = str(_first(attrs, "FILENAME", "filename", default=""))
            if fname.startswith(worktree_prefix):
                fname = fname[len(worktree_prefix):]
            methods[full_name] = _MethodInfo(
                full_name=full_name,
                name=short,
                filename=fname,
                start_line=int(_first(attrs, "LINE_NUMBER", "lineNumber", default=0) or 0),
                end_line=int(_first(attrs, "LINE_NUMBER_END", "lineNumberEnd", default=0) or 0),
            )
            node_owner[str(nid)] = full_name
        elif label == "CALL":
            target = str(_first(attrs, "METHOD_FULL_NAME", "methodFullName", default=""))
            if target and not target.startswith("<operator>"):
                pending_calls.append((str(nid), target))

    # Pass 2: propagate ownership via CONTAINS and AST edges (BFS from each METHOD).
    from collections import defaultdict as _dd
    adj: dict[str, list[str]] = _dd(list)
    for u, v, k in G.edges(keys=True):
        if k in ("CONTAINS", "AST"):
            adj[str(u)].append(str(v))

    for method_nid in list(node_owner.keys()):
        owner = node_owner[method_nid]
        stack = [method_nid]
        while stack:
            cur = stack.pop()
            for child in adj.get(cur, ()):
                if child not in node_owner:
                    node_owner[child] = owner
                    stack.append(child)

    # Resolve pending CALLs.
    resolved = external = orphan = 0
    sample_unresolved: list[str] = []
    for call_nid, target in pending_calls:
        caller = node_owner.get(call_nid)
        if caller is None:
            orphan += 1
            continue
        if target not in methods:
            external += 1
            if len(sample_unresolved) < 5:
                sample_unresolved.append(target)
            continue
        callees.setdefault(caller, set()).add(target)
        callers.setdefault(target, set()).add(caller)
        resolved += 1

    log.info(
        "call graph: %d methods, %d caller-edges, %d callee-edges "
        "(resolved=%d external=%d orphan=%d)",
        len(methods),
        sum(len(v) for v in callers.values()),
        sum(len(v) for v in callees.values()),
        resolved, external, orphan,
    )
    if sample_unresolved:
        log.info("  sample unresolved call targets: %s", sample_unresolved)
        log.info("  known methods (first 5): %s", list(methods.keys())[:5])
    return methods, callers, callees


# ---------------------------------------------------------------------------
# Sub-task C: map modified lines -> patch functions, then expand neighbors
# ---------------------------------------------------------------------------

def _methods_containing_lines(
    methods: dict[str, _MethodInfo],
    file: str,
    lines: Iterable[int],
    *,
    orphan_fuzz: int = 3,
) -> dict[str, list[int]]:
    """Return {method_full_name: [lines that fall inside it]} for methods in
    `file`.

    Primary rule: a line belongs to method M if M.start_line <= line <= M.end_line.

    Fuzzy rule for orphans: if a modified line falls OUTSIDE every function
    (typical for removed comments, blank lines, or preprocessor directives
    immediately adjacent to a function), attribute it to the nearest
    function within `orphan_fuzz` lines. This handles cases like a comment
    above a function being rewritten as part of the patch.

    Lines further than orphan_fuzz from any function are dropped — they
    represent file-scope changes (struct defs, globals, macros) that we
    don't handle in v1.
    """
    hits: dict[str, list[int]] = {}
    lines = sorted(set(lines))
    file_methods = sorted(
        (m for m in methods.values() if m.filename == file),
        key=lambda m: m.start_line or 0,
    )
    if not file_methods:
        return hits

    for ln in lines:
        # Find all methods containing this line. A line may be inside multiple
        # if Joern emits any nested synthetic wrappers (we already filter
        # <global>/<includes>, but belt-and-suspenders). Pick the NARROWEST
        # range — the real function, not any outer wrapper.
        containing = [
            m for m in file_methods
            if m.start_line and m.start_line <= ln <= (m.end_line or m.start_line)
        ]
        if containing:
            m = min(containing, key=lambda m: (m.end_line or m.start_line) - m.start_line)
            hits.setdefault(m.full_name, []).append(ln)
            continue
        # Orphan: find nearest method within orphan_fuzz lines.
        best: tuple[int, _MethodInfo] | None = None
        for m in file_methods:
            if not m.start_line:
                continue
            end = m.end_line or m.start_line
            dist = min(abs(ln - m.start_line), abs(ln - end))
            if dist <= orphan_fuzz and (best is None or dist < best[0]):
                best = (dist, m)
        if best is not None:
            hits.setdefault(best[1].full_name, []).append(ln)
    return hits


def _expand_neighbors(
    patch_fns: set[str],
    callers: dict[str, set[str]],
    callees: dict[str, set[str]],
    hops: int,
) -> dict[str, tuple[str, int]]:
    """BFS outward from patch functions. Returns {full_name: (role, hop)}
    for every neighbor, excluding the patch functions themselves.
    'role' is 'caller' or 'callee' based on how we first reached it; if a
    function is both (e.g., mutual recursion), the first traversal wins.
    This is a minor information loss we accept for simplicity."""
    out: dict[str, tuple[str, int]] = {}
    frontier: set[str] = set(patch_fns)
    for hop in range(1, hops + 1):
        next_frontier: set[str] = set()
        for fn in frontier:
            for c in callers.get(fn, ()):
                if c not in patch_fns and c not in out:
                    out[c] = ("caller", hop)
                    next_frontier.add(c)
            for c in callees.get(fn, ()):
                if c not in patch_fns and c not in out:
                    out[c] = ("callee", hop)
                    next_frontier.add(c)
        frontier = next_frontier
        if not frontier:
            break
    return out


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def find_candidate_functions(
    repo_path: Path,
    commit_vuln: str,
    commit_fix: str,
    *,
    hops: int = 1,
    patch_id: str | None = None,
) -> dict[Version, Step1Result]:
    """Run Step 1 for both commit versions. Returns {version: Step1Result}.

    Caller is responsible for feeding the results into Step 2 (program-graph
    extraction). This function doesn't look at CWE / sinks / labels — those
    are later steps.
    """
    patch_id = patch_id or f"{repo_path.name}:{commit_fix[:8]}"

    # 1. Parse the diff once. Gives us modified lines per file per version.
    diff_text = _git_diff(repo_path, commit_vuln, commit_fix)
    modified = parse_modified_lines(diff_text)

    results: dict[Version, Step1Result] = {}

    for version, commit in (("vulnerable", commit_vuln), ("fixed", commit_fix)):
        # 2. Get the CPG for this version (cached if we've seen it).
        handle = get_or_build_cpg(repo_path, commit)
        methods, callers, callees = load_methods_and_callgraph(handle)

        # 3. Map modified lines -> patch functions.
        patch_fns: dict[str, list[int]] = {}
        for file, per_version in modified.items():
            lines = per_version[version]
            if not lines:
                continue
            hits = _methods_containing_lines(methods, file, lines)
            for fn, lns in hits.items():
                patch_fns.setdefault(fn, []).extend(lns)

        if not patch_fns:
            results[version] = Step1Result(
                patch_id=patch_id, commit=commit, version=version,
                candidate_functions=[],
                skipped_reason="no function-scope changes on this version",
            )
            log.info("SKIP %s/%s: %s", patch_id, version, results[version].skipped_reason)
            continue

        # 4. Expand 1-hop (or configured) neighbors via call graph.
        neighbors = _expand_neighbors(set(patch_fns), callers, callees, hops=hops)

        # 5. Build the output records.
        candidates: list[CandidateFunction] = []
        for fn_name, lns in patch_fns.items():
            m = methods[fn_name]
            candidates.append(CandidateFunction(
                function_name=m.name, file=m.filename,
                start_line=m.start_line, end_line=m.end_line,
                role="patch", hop_distance=0,
                modified_lines=sorted(set(lns)),
                method_full_name=m.full_name, commit=commit,
            ))
        for fn_name, (role, hop) in neighbors.items():
            m = methods[fn_name]
            candidates.append(CandidateFunction(
                function_name=m.name, file=m.filename,
                start_line=m.start_line, end_line=m.end_line,
                role=role, hop_distance=hop,
                modified_lines=[],
                method_full_name=m.full_name, commit=commit,
            ))

        results[version] = Step1Result(
            patch_id=patch_id, commit=commit, version=version,
            candidate_functions=candidates,
        )
        log.info(
            "%s/%s: %d patch fns, %d neighbors",
            patch_id, version, len(patch_fns), len(neighbors),
        )

    return results