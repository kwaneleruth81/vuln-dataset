"""
cpg_cache.py — Build-or-load a Joern CPG for a (repo, commit) pair.

One CPG per (repo, commit) is built once and reused by every pipeline step.
The CPG is Joern's Code Property Graph — a single graph containing AST, CFG,
CDG, DDG, and CALL edges for all functions in the checked-out source tree.

Design choices
--------------
* Cache key = sha1(repo_path + commit). Deterministic, collision-free for
  our scale. Cache dir defaults to ~/.cache/vuln_dataset/cpgs.
* We check out the commit into a *worktree*, not the main repo, so the
  user's HEAD is never disturbed and multiple commits can be processed in
  parallel.
* We export the CPG as neo4jcsv (all edge types). Downstream steps
  load these CSV files into NetworkX — no Joern runtime dependency after build.
* Failures are logged and raise CPGBuildError; callers decide whether to
  skip the patch or abort.
"""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)


# Module-level default, overridable by tests (e.g. smoke test sets this to
# a tmp dir so each run starts clean and doesn't pollute the real cache).
DEFAULT_CACHE_ROOT: Path = Path.home() / ".cache" / "vuln_dataset" / "cpgs"


class CPGBuildError(RuntimeError):
    """Raised when Joern fails to produce a usable CPG."""


@dataclass(frozen=True)
class CPGHandle:
    """Everything a downstream step needs to consume a cached CPG."""
    cache_dir: Path        # directory holding cpg.bin and graph/
    worktree: Path         # checked-out source tree for this commit
    commit: str
    repo_path: Path

    @property
    def graph_dir(self) -> Path:
        return self.cache_dir / "graph"

    @property
    def cpg_bin(self) -> Path:
        return self.cache_dir / "cpg.bin"


def _cache_key(repo_path: Path, commit: str) -> str:
    # Absolute path so moving the repo invalidates the cache, 
    # a different checkout location may have different relative-path semantics.
    raw = f"{repo_path.resolve()}::{commit}"
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


def _run(cmd: list[str], cwd: Path | None = None) -> None:
    log.debug("exec: %s", " ".join(cmd))
    res = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if res.returncode != 0:
        raise CPGBuildError(
            f"command failed ({res.returncode}): {' '.join(cmd)}\n"
            f"stderr: {res.stderr[-500:]}"
        )


def get_or_build_cpg(
    repo_path: Path,
    commit: str,
    *,
    cache_root: Path | None = None,
    language: str = "c",
    force_rebuild: bool = False,
) -> CPGHandle:
    """Return a CPGHandle for the given (repo, commit).

    Builds the CPG if not cached. Safe to call concurrently on *different*
    commits (each gets its own cache dir); not safe for the same commit in
    parallel — add a file lock if you need that.

    cache_root defaults to the module-level DEFAULT_CACHE_ROOT (which is
    ~/.cache/vuln_dataset/cpgs). Tests override by setting
    `cpg_cache.DEFAULT_CACHE_ROOT = some_tmp_path` before calling.
    """
    if cache_root is None:
        cache_root = DEFAULT_CACHE_ROOT
    key = _cache_key(repo_path, commit)
    cache_dir = cache_root / key
    worktree = cache_dir / "src"
    handle = CPGHandle(
        cache_dir=cache_dir, worktree=worktree,
        commit=commit, repo_path=repo_path,
    )

    # Fast path: fully cached.
    marker = cache_dir / ".complete"
    if marker.exists() and not force_rebuild:
        log.info("CPG cache hit: %s @ %s", repo_path.name, commit[:8])
        return handle

    if force_rebuild and cache_dir.exists():
        shutil.rmtree(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)


    if not worktree.exists():
        log.info("creating worktree for %s @ %s", repo_path.name, commit[:8])
        subprocess.run(
            ["git", "worktree", "prune"],
            cwd=repo_path, capture_output=True,
        )
        _run(["git", "worktree", "add", "--detach", str(worktree), commit],
             cwd=repo_path)

    # 2. joern-parse: source tree -> cpg.bin
    log.info("joern-parse (this can take minutes on large repos)...")
    _run([
        "joern-parse", str(worktree),
        "--language", language,
        "--output", str(handle.cpg_bin),
    ])

    # 3. joern-export: cpg.bin -> neo4jcsv.
    #    graphml is not used: on large real-world CPGs Joern crashes in its
    #    own xmlFormatInPlace step when Java's SAX parser hits the default
    #    100 000-char entity size limit on a long `code` property.
    #    neo4jcsv writes flat CSV files with no such constraint.
    #    NB: joern-export refuses to run if --out already exists.
    log.info("joern-export...")
    if handle.graph_dir.exists():
        shutil.rmtree(handle.graph_dir)
    _run([
        "joern-export", str(handle.cpg_bin),
        "--repr", "all",
        "--format", "neo4jcsv",
        "--out", str(handle.graph_dir),
    ])

    # 4. Sanity check: at least one non-empty node data file exists.
    exported = list(handle.graph_dir.glob("nodes_*_data.csv"))
    if not exported or all(p.stat().st_size == 0 for p in exported):
        raise CPGBuildError(f"joern-export produced no usable output in {handle.graph_dir}")

    # 5. Manifest so as to debug stale caches later.
    (cache_dir / "manifest.json").write_text(json.dumps({
        "repo_path": str(repo_path.resolve()),
        "commit": commit,
        "language": language,
        "num_graph_files": len(exported),
    }, indent=2))
    marker.touch()

    log.info("CPG built: %s (%d graph files)", cache_dir, len(exported))
    return handle


def purge_cache(cache_root: Path | None = None) -> None:
    """Wipe the whole CPG cache. Use during development when schemas change."""
    if cache_root is None:
        cache_root = DEFAULT_CACHE_ROOT
    if cache_root.exists():
        shutil.rmtree(cache_root)
        log.info("purged CPG cache: %s", cache_root)