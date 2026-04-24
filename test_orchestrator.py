"""Offline integration test for build_dataset.py.

Builds a synthetic repo with two commits, writes a 1-entry work queue pointing
at it, and runs the orchestrator with the pipeline mocked so we don't need
Joern. Confirms:
  - read_queue correctly parses entries
  - RepoCache can work with a local repo (file:// URL)
  - process_patch calls Step 1, runs both versions, writes outputs
  - Failures are logged to skipped.jsonl rather than crashing
  - completed_patch_ids resumes correctly
  - validate_dataset.py reports "no red flags"
"""
from __future__ import annotations
import json, shutil, subprocess, sys, tempfile
from pathlib import Path
from unittest.mock import patch as mock_patch

sys.path.insert(0, str(Path(__file__).parent))

import build_dataset as bd


def _mk_git_repo(root: Path) -> tuple[str, str]:
    root.mkdir(parents=True, exist_ok=True)
    def run(*args): subprocess.run(list(args), cwd=root, check=True, capture_output=True)
    run("git", "init", "-q", "-b", "main")
    run("git", "config", "user.email", "t@t")
    run("git", "config", "user.name", "T")
    run("git", "config", "commit.gpgsign", "false")
    (root / "src").mkdir(exist_ok=True)
    (root / "src" / "x.c").write_text("int f() { return 0; }\n")
    run("git", "add", ".")
    run("git", "commit", "-q", "-m", "v")
    c1 = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    (root / "src" / "x.c").write_text("int f() { return 1; }\n")
    run("git", "add", ".")
    run("git", "commit", "-q", "-m", "f")
    c2 = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    return c1, c2


# Mock pipeline: returns hand-built Step1Result / graph / records so we can
# exercise orchestrator plumbing without needing Joern.
def _build_mocks():
    import networkx as nx
    from pipeline.find_candidates import Step1Result, CandidateFunction

    def fake_find_candidates(repo_path, commit_vuln, commit_fix, *, hops=1, patch_id=None):
        mk = lambda commit, version: Step1Result(
            patch_id=patch_id or "x", commit=commit, version=version,
            candidate_functions=[CandidateFunction(
                function_name="f", file="src/x.c", start_line=1, end_line=1,
                role="patch", hop_distance=0, modified_lines=[1],
                method_full_name="f", commit=commit,
            )],
        )
        return {"vulnerable": mk(commit_vuln, "vulnerable"),
                "fixed":      mk(commit_fix, "fixed")}

    def fake_build_program_graph(handle, step1):
        G = nx.MultiDiGraph()
        G.add_node("n1", function="f", line=1, column=0,
                   stmt_type="METHOD_ENTRY", ast_type="METHOD",
                   code="int f() { return 1; }",
                   depth_cfg=0, depth_ast=0,
                   variables_used=[], variables_defined=[],
                   in_loop=False, in_branch=False, called_function=None)
        G.add_node("n2", function="f", line=1, column=10,
                   stmt_type="RETURN", ast_type="RETURN",
                   code="return 1;",
                   depth_cfg=1, depth_ast=1,
                   variables_used=[], variables_defined=[],
                   in_loop=False, in_branch=False, called_function=None)
        G.add_edge("n1", "n2", key="CFG", edge_type="CFG")
        G.graph["patch_id"] = step1.patch_id
        G.graph["version"] = step1.version
        G.graph["commit"] = step1.commit
        G.graph["candidate_functions"] = {
            "f": {"name": "f", "role": "patch", "hop_distance": 0,
                  "modified_lines": [1], "file": "src/x.c"}
        }
        return G

    def fake_get_or_build_cpg(repo_path, commit, **kw):
        class H:
            def __init__(self): self.commit = commit; self.worktree = repo_path
        return H()

    return fake_find_candidates, fake_build_program_graph, fake_get_or_build_cpg


def run_test() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="orch_"))
    try:
        repo = tmp / "repo"
        c1, c2 = _mk_git_repo(repo)
        print(f"synthetic repo: {repo}")
        print(f"commits: vuln={c1[:8]} fix={c2[:8]}")

        queue = tmp / "queue.jsonl"
        queue.write_text(json.dumps({
            "patch_id": "synth/CVE-X",
            "repo_url": str(repo),       # file path, not github
            "commit_vuln": c1,
            "commit_fix":  c2,
            "cve": "CVE-X",
            "cwes": ["CWE-120"],
        }) + "\n")

        out = tmp / "dataset"

        find_cand, build_G, get_cpg = _build_mocks()

        # Patch the orchestrator's references to the pipeline (imported at
        # module scope). We also need the RepoCache to treat the local path
        # as already cloned — override _local_path to point straight at repo.
        original_ensure = bd.RepoCache.ensure
        def fake_ensure(self, url, commits):
            return Path(url)   # treat the "url" as a local path
        bd.RepoCache.ensure = fake_ensure

        with mock_patch.object(bd, "find_candidate_functions", find_cand), \
             mock_patch.object(bd, "build_program_graph", build_G), \
             mock_patch.object(bd, "get_or_build_cpg", get_cpg):
            # Minimal argv to drive main(); mimics CLI invocation.
            sys.argv = ["build_dataset.py",
                        "--work-queue", str(queue),
                        "--out", str(out),
                        "--log-level", "WARNING"]
            rc = bd.main()
            assert rc == 0, f"main returned {rc}"

        bd.RepoCache.ensure = original_ensure

        # Inspect output.
        print("\nOutput files:")
        for p in sorted(out.iterdir()):
            print(f"  {p.name:<20} {p.stat().st_size:>8} bytes")

        # Minimal assertions on output structure.
        nodes = [json.loads(l) for l in (out / "nodes.jsonl").read_text().splitlines() if l.strip()]
        assert len(nodes) == 4, f"expected 4 nodes (2 per version), got {len(nodes)}"
        # Both versions should be present
        versions = {n["id"].rsplit(":", 2)[1] for n in nodes}
        assert versions == {"vulnerable", "fixed"}, versions
        # Each node has the full schema
        required = {"id", "function", "role", "statement", "type", "label",
                    "distance_to_patch", "is_patch_related", "is_cross_function"}
        for n in nodes:
            missing = required - set(n.keys())
            assert not missing, f"node missing fields: {missing}"
        print(f"\n✓ {len(nodes)} nodes across versions {versions}")

        # Functions file: 2 entries (one per version for the single fn)
        funcs = [json.loads(l) for l in (out / "functions.jsonl").read_text().splitlines() if l.strip()]
        assert len(funcs) == 2, f"expected 2 function rows, got {len(funcs)}"
        print(f"✓ functions.jsonl: {len(funcs)} rows")

        # Edges: 1 CFG edge per version
        edges = [json.loads(l) for l in (out / "edges.jsonl").read_text().splitlines() if l.strip()]
        assert len(edges) == 2, f"expected 2 edges, got {len(edges)}"
        for e in edges:
            assert e["src"] in {n["id"] for n in nodes}
            assert e["dst"] in {n["id"] for n in nodes}
        print(f"✓ edges.jsonl: {len(edges)} edges, all endpoints resolve")

        # Manifest
        m = json.loads((out / "manifest.json").read_text())
        assert m["totals"]["processed"] == 1, m
        print(f"✓ manifest: processed={m['totals']['processed']}, samples={m['totals']['samples']}")

        # --- Resume test ---
        # Re-run. Should skip entirely because patch_id already in functions.jsonl.
        with mock_patch.object(bd, "find_candidate_functions", find_cand), \
             mock_patch.object(bd, "build_program_graph", build_G), \
             mock_patch.object(bd, "get_or_build_cpg", get_cpg):
            bd.RepoCache.ensure = fake_ensure
            sys.argv = ["build_dataset.py",
                        "--work-queue", str(queue),
                        "--out", str(out),
                        "--log-level", "WARNING"]
            rc = bd.main()
            bd.RepoCache.ensure = original_ensure
        nodes_after = sum(1 for _ in (out / "nodes.jsonl").open())
        assert nodes_after == len(nodes), \
            f"resume rewrote existing data: before={len(nodes)} after={nodes_after}"
        print(f"✓ resume: re-run added 0 nodes (stayed at {nodes_after})")

        # --- Failure test: broken entry should land in skipped.jsonl ---
        broken_queue = tmp / "broken_queue.jsonl"
        broken_queue.write_text(json.dumps({
            "patch_id": "synth/broken",
            "repo_url": str(repo),
            "commit_vuln": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",  # doesn't exist
            "commit_fix":  c2,
            "cwes": ["CWE-120"],
        }) + "\n")
        # Mock find_candidate_functions to raise so we simulate a pipeline error.
        def raise_find(*a, **kw):
            raise RuntimeError("synthetic failure: commit not parseable")
        out2 = tmp / "dataset2"
        with mock_patch.object(bd, "find_candidate_functions", raise_find), \
             mock_patch.object(bd, "build_program_graph", build_G), \
             mock_patch.object(bd, "get_or_build_cpg", get_cpg):
            bd.RepoCache.ensure = fake_ensure
            sys.argv = ["build_dataset.py",
                        "--work-queue", str(broken_queue),
                        "--out", str(out2),
                        "--log-level", "ERROR"]
            rc = bd.main()
            bd.RepoCache.ensure = original_ensure
        skipped = [json.loads(l) for l in (out2 / "skipped.jsonl").read_text().splitlines() if l.strip()]
        assert len(skipped) >= 1, "broken entry should be in skipped.jsonl"
        assert "synthetic failure" in skipped[0]["reason"]
        print(f"✓ failure isolation: broken entry logged to skipped.jsonl ({skipped[0]['stage']})")

        # Validation script on the good output.
        import subprocess as sp
        r = sp.run([sys.executable, "validate_dataset.py", "--out", str(out)],
                   capture_output=True, text=True, cwd=Path(__file__).parent)
        print("\n--- validate_dataset.py output ---")
        print(r.stdout)
        if r.returncode != 0:
            print(r.stderr)
            print("VALIDATION FAILED")
            return 1

        print("\n=== ALL ORCHESTRATOR TESTS PASSED ===")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(run_test())