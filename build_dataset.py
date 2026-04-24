"""
build_dataset.py — Batch orchestrator for the vulnerability dataset pipeline.

Reads a work queue (JSONL), runs Steps 1-7 per patch per version, writes the
dataset to disk. Handles:

  * Shared repo cache (~/.cache/vuln_dataset/repos/): clone once, fetch later
  * Failure isolation: one bad patch never aborts the run
  * Resumption: restart with the same --out dir; already-processed entries skip
  * Streaming JSONL writes: memory stays bounded

Usage:
  python3 build_dataset.py --work-queue queue.jsonl --out dataset/
  python3 build_dataset.py --work-queue queue.jsonl --out dataset/ --debug-samples
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import subprocess
import sys
import time
import traceback
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import IO, Iterable

from pipeline.cpg_cache import get_or_build_cpg, CPGBuildError
from pipeline.find_candidates import find_candidate_functions
from pipeline.build_program_graph import build_program_graph
from pipeline.sinks import identify_sinks
from pipeline.slicer import compute_slice
from pipeline.annotate import annotate_nodes

log = logging.getLogger("orchestrator")


class RepoCache:
    """Clone-once, fetch-later repo manager."""

    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def _local_path(self, repo_url: str) -> Path:
        s = repo_url
        for prefix in ("https://", "http://", "git://", "ssh://", "git@"):
            if s.startswith(prefix):
                s = s[len(prefix):]
        if ":" in s:
            s = s.replace(":", "/", 1)
        if s.endswith(".git"):
            s = s[:-4]
        parts = [p for p in s.split("/") if p]
        if len(parts) >= 3:
            parts = parts[1:]   # strip host segment (github.com, ...)
        return self.root / "__".join(parts)

    def ensure(self, repo_url: str, commits: Iterable[str]) -> Path:
        path = self._local_path(repo_url)
        if not path.exists():
            log.info("cloning %s -> %s", repo_url, path)
            # Partial clone to save bandwidth; fall back to full if server
            # doesn't support it.
            try:
                subprocess.run(
                    ["git", "clone", "--no-tags", "--filter=blob:none",
                     repo_url, str(path)],
                    check=True, capture_output=True, text=True,
                )
            except subprocess.CalledProcessError:
                log.info("partial-clone failed; full clone")
                subprocess.run(
                    ["git", "clone", repo_url, str(path)],
                    check=True, capture_output=True, text=True,
                )

        missing: list[str] = []
        for c in commits:
            r = subprocess.run(
                ["git", "cat-file", "-e", f"{c}^{{commit}}"],
                cwd=path, capture_output=True,
            )
            if r.returncode != 0:
                missing.append(c)
        if missing:
            log.info("fetching %d missing commits in %s", len(missing), path.name)
            try:
                subprocess.run(
                    ["git", "fetch", "--no-tags", "origin", *missing],
                    cwd=path, check=True, capture_output=True, text=True,
                )
            except subprocess.CalledProcessError:
                subprocess.run(
                    ["git", "fetch", "--no-tags", "origin"],
                    cwd=path, check=True, capture_output=True, text=True,
                )
        return path


class DatasetWriter:
    """Append-only streaming JSONL writer. Resume-safe: re-opening appends."""

    def __init__(self, out_dir: Path, debug_samples: bool = False):
        self.out_dir = out_dir
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.debug_samples = debug_samples
        if debug_samples:
            (self.out_dir / "samples").mkdir(exist_ok=True)

        self.f_nodes:     IO = (out_dir / "nodes.jsonl").open("a")
        self.f_functions: IO = (out_dir / "functions.jsonl").open("a")
        self.f_edges:     IO = (out_dir / "edges.jsonl").open("a")
        self.f_sinks:     IO = (out_dir / "sinks.jsonl").open("a")
        self.f_skipped:   IO = (out_dir / "skipped.jsonl").open("a")

    def close(self):
        for f in (self.f_nodes, self.f_functions, self.f_edges,
                  self.f_sinks, self.f_skipped):
            try:
                f.close()
            except Exception:
                pass

    @staticmethod
    def _dump(f: IO, obj: dict) -> None:
        f.write(json.dumps(obj, default=str))
        f.write("\n")

    def write_sample(self, patch_id: str, version: str,
                     node_records: list[dict], graph) -> None:
        """Persist one (patch_id, version) sample's node/function/edge/sink data."""
        # 1. Nodes (the payload).
        for r in node_records:
            self._dump(self.f_nodes, r)

        # 2. Functions.
        cand = graph.graph.get("candidate_functions", {})
        for fn_full, meta in cand.items():
            self._dump(self.f_functions, {
                "patch_id": patch_id, "version": version,
                "function_full": fn_full,
                "function": meta.get("name"),
                "role": meta.get("role"),
                "file": meta.get("file"),
                "hop_distance": meta.get("hop_distance"),
                "modified_lines": list(meta.get("modified_lines", [])),
            })

        # 3. Edges: map joern ids to canonical ids (same sort key as annotate).
        def _sort_key(nid: str) -> tuple:
            a = graph.nodes[nid]
            return (
                a.get("function", ""),
                int(a.get("line") or 0),
                int(a.get("column") or 0),
                str(nid),
            )
        ordered = sorted(graph.nodes, key=_sort_key)
        canonical = {str(j): r["id"] for j, r in zip(ordered, node_records)}

        for u, v, k in graph.edges(keys=True):
            cu = canonical.get(str(u))
            cv = canonical.get(str(v))
            if cu is None or cv is None:
                continue
            self._dump(self.f_edges, {
                "patch_id": patch_id, "version": version,
                "src": cu, "dst": cv, "edge_type": k,
            })

        # 4. Sinks.
        for rec in node_records:
            if rec.get("is_sink"):
                self._dump(self.f_sinks, {
                    "patch_id": patch_id, "version": version,
                    "node_id": rec["id"],
                    "function": rec["function"],
                    "line": rec["line"],
                    "called_function": rec.get("called_function"),
                    "sink_reason": rec.get("sink_reason"),
                    "label": rec["label"],
                })

        # 5. Debug dump.
        if self.debug_samples:
            dp = self.out_dir / "samples" / f"{patch_id.replace('/', '__')}__{version}.json"
            dp.parent.mkdir(parents=True, exist_ok=True)
            dp.write_text(json.dumps({
                "patch_id": patch_id, "version": version,
                "n_nodes": len(node_records),
                "n_positive": sum(1 for r in node_records if r["label"]),
                "nodes": node_records,
            }, indent=2, default=str))

    def write_skip(self, patch_id: str, version: str | None, stage: str,
                   reason: str, tb_tail: str = "") -> None:
        self._dump(self.f_skipped, {
            "patch_id": patch_id, "version": version,
            "stage": stage, "reason": reason,
            "traceback_tail": tb_tail,
            "ts": time.time(),
        })

    def flush(self) -> None:
        for f in (self.f_nodes, self.f_functions, self.f_edges,
                  self.f_sinks, self.f_skipped):
            try:
                f.flush()
            except Exception:
                pass


@dataclass
class PatchConfig:
    patch_id: str
    repo_url: str
    commit_vuln: str
    commit_fix: str
    cve: str = ""
    cwes: list[str] = field(default_factory=list)
    extra_sinks: list[list] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "PatchConfig":
        extra = d.get("extra_sinks") or []
        normalized: list = []
        for item in extra:
            if isinstance(item, dict) and "file" in item and "line" in item:
                normalized.append([item["file"], int(item["line"])])
            elif isinstance(item, (list, tuple)) and len(item) >= 2:
                normalized.append([str(item[0]), int(item[1])])
        return cls(
            patch_id=d["patch_id"],
            repo_url=d.get("repo_url", ""),
            commit_vuln=d["commit_vuln"],
            commit_fix=d["commit_fix"],
            cve=d.get("cve", ""),
            cwes=list(d.get("cwes", [])),
            extra_sinks=normalized,
        )


@dataclass
class RunConfig:
    hops: int = 1
    max_hops_slice: int = 10
    proximity_lines: int = 3
    debug_samples: bool = False


def _run_one_version(repo_path, pc, version, step1_result, rc):
    if step1_result.skipped_reason:
        return None
    handle = get_or_build_cpg(repo_path, step1_result.commit)
    G = build_program_graph(handle, step1_result)
    if G.number_of_nodes() == 0:
        return None
    identify_sinks(
        G, cwes=pc.cwes,
        extra_sinks=[tuple(s) for s in pc.extra_sinks],
        proximity_lines=rc.proximity_lines,
    )
    compute_slice(G,
                  max_hops_backward=rc.max_hops_slice,
                  max_hops_forward=rc.max_hops_slice)
    records = annotate_nodes(G)
    return records, G


def process_patch(pc: PatchConfig, rc: RunConfig,
                  repo_cache: RepoCache, writer: DatasetWriter) -> dict:
    """Run the full pipeline for one work-queue entry. Never raises."""
    stats = {"patch_id": pc.patch_id, "samples_written": 0,
             "nodes_written": 0, "positives_written": 0,
             "skipped": False, "reason": None}

    try:
        repo_path = repo_cache.ensure(pc.repo_url,
                                      [pc.commit_vuln, pc.commit_fix])
    except subprocess.CalledProcessError as e:
        reason = f"git command failed: {(e.stderr or str(e))[-300:]}"
        writer.write_skip(pc.patch_id, None, "clone/fetch", reason,
                          tb_tail=traceback.format_exc()[-500:])
        stats["skipped"] = True; stats["reason"] = "clone/fetch"
        return stats
    except Exception as e:
        writer.write_skip(pc.patch_id, None, "clone/fetch",
                          f"{type(e).__name__}: {e}",
                          tb_tail=traceback.format_exc()[-500:])
        stats["skipped"] = True; stats["reason"] = "clone/fetch"
        return stats

    try:
        step1 = find_candidate_functions(
            repo_path=repo_path,
            commit_vuln=pc.commit_vuln, commit_fix=pc.commit_fix,
            hops=rc.hops, patch_id=pc.patch_id,
        )
    except CPGBuildError as e:
        writer.write_skip(pc.patch_id, None, "step1/cpg_build", str(e)[-300:],
                          tb_tail=traceback.format_exc()[-500:])
        stats["skipped"] = True; stats["reason"] = "step1/cpg_build"
        return stats
    except Exception as e:
        writer.write_skip(pc.patch_id, None, "step1",
                          f"{type(e).__name__}: {e}",
                          tb_tail=traceback.format_exc()[-500:])
        stats["skipped"] = True; stats["reason"] = "step1"
        return stats

    any_success = False
    for version in ("vulnerable", "fixed"):
        s1 = step1.get(version)
        if s1 is None or s1.skipped_reason:
            reason = s1.skipped_reason if s1 else "no step1 result"
            writer.write_skip(pc.patch_id, version, "step1", reason)
            continue
        try:
            result = _run_one_version(repo_path, pc, version, s1, rc)
        except CPGBuildError as e:
            writer.write_skip(pc.patch_id, version, "cpg_build", str(e)[-300:],
                              tb_tail=traceback.format_exc()[-500:])
            continue
        except Exception as e:
            writer.write_skip(pc.patch_id, version, "steps2-7",
                              f"{type(e).__name__}: {e}",
                              tb_tail=traceback.format_exc()[-500:])
            continue

        if result is None:
            writer.write_skip(pc.patch_id, version, "steps2-7",
                              "empty graph or step1 skipped")
            continue

        records, G = result
        writer.write_sample(pc.patch_id, version, records, G)
        any_success = True
        stats["samples_written"] += 1
        stats["nodes_written"]   += len(records)
        stats["positives_written"] += sum(1 for r in records if r["label"])

    if not any_success:
        stats["skipped"] = True
        stats["reason"] = "no-version-succeeded"
    return stats


def completed_patch_ids(out_dir: Path) -> set[str]:
    """Patch_ids with at least one sample already written. Resume skips these.

    Uses functions.jsonl (small & always written on success) instead of
    nodes.jsonl (huge) for fast resume scans."""
    done: set[str] = set()
    p = out_dir / "functions.jsonl"
    if not p.exists():
        return done
    try:
        with p.open() as f:
            for line in f:
                try:
                    done.add(json.loads(line)["patch_id"])
                except (json.JSONDecodeError, KeyError):
                    continue
    except OSError:
        pass
    return done


def read_queue(path: Path) -> list[PatchConfig]:
    entries: list[PatchConfig] = []
    with path.open() as f:
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                entries.append(PatchConfig.from_dict(json.loads(line)))
            except (json.JSONDecodeError, KeyError) as e:
                log.error("queue line %d invalid: %s", i, e)
    return entries


def write_manifest(out_dir: Path, rc: RunConfig, queue_path: Path,
                   totals: dict, elapsed_s: float) -> None:
    (out_dir / "manifest.json").write_text(json.dumps({
        "run_config": asdict(rc),
        "queue_path": str(queue_path.resolve()),
        "totals": totals,
        "elapsed_seconds": round(elapsed_s, 1),
        "generated_at": time.time(),
    }, indent=2))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--work-queue", required=True, type=Path)
    ap.add_argument("--out",        required=True, type=Path)
    ap.add_argument("--hops",             type=int, default=1)
    ap.add_argument("--max-hops-slice",   type=int, default=10)
    ap.add_argument("--proximity-lines",  type=int, default=3)
    ap.add_argument("--debug-samples",    action="store_true")
    ap.add_argument("--repo-cache", type=Path,
                    default=Path.home() / ".cache" / "vuln_dataset" / "repos")
    ap.add_argument("--log-level", default="INFO")
    args = ap.parse_args()

    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    rc = RunConfig(
        hops=args.hops,
        max_hops_slice=args.max_hops_slice,
        proximity_lines=args.proximity_lines,
        debug_samples=args.debug_samples,
    )

    entries = read_queue(args.work_queue)
    log.info("work queue: %d entries", len(entries))

    already = completed_patch_ids(args.out)
    if already:
        log.info("resume: %d patch_ids already done — will skip", len(already))

    repo_cache = RepoCache(args.repo_cache)
    writer = DatasetWriter(args.out, debug_samples=args.debug_samples)

    def _sig(*_):
        log.warning("interrupt received — flushing")
        writer.flush(); writer.close()
        sys.exit(130)
    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    totals = {"processed": 0, "skipped": 0,
              "samples": 0, "nodes": 0, "positives": 0}
    t0 = time.time()

    try:
        for i, pc in enumerate(entries, start=1):
            if pc.patch_id in already:
                continue
            log.info("[%d/%d] %s", i, len(entries), pc.patch_id)
            stats = process_patch(pc, rc, repo_cache, writer)
            writer.flush()
            if stats["skipped"]:
                totals["skipped"] += 1
                log.info("  skipped: %s", stats["reason"])
            else:
                totals["processed"] += 1
                totals["samples"]   += stats["samples_written"]
                totals["nodes"]     += stats["nodes_written"]
                totals["positives"] += stats["positives_written"]
                log.info("  ok: %d samples, %d nodes (%d pos)",
                         stats["samples_written"], stats["nodes_written"],
                         stats["positives_written"])
    finally:
        writer.close()

    elapsed = time.time() - t0
    write_manifest(args.out, rc, args.work_queue, totals, elapsed)
    log.info("DONE in %.1fs — totals: %s", elapsed, totals)
    return 0


if __name__ == "__main__":
    sys.exit(main())