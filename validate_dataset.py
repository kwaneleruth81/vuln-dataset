"""
validate_dataset.py — Sanity-check a dataset produced by build_dataset.py.

Run AFTER the orchestrator. Reports (does not assert) on the output:
  - File presence & record counts
  - Schema completeness per record type
  - Label distribution
  - Per-patch coverage (samples per patch, nodes per sample)
  - Cross-file referential integrity (edge src/dst are valid node ids)

Exit code: 0 if no red flags, 1 if something is clearly broken.

Usage:
  python3 validate_dataset.py --out dataset/
"""
from __future__ import annotations
import argparse, json, sys
from collections import Counter, defaultdict
from pathlib import Path


def _iter_jsonl(p: Path):
    if not p.exists():
        return
    with p.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()
    d = args.out
    print(f"Validating {d.resolve()}")

    red_flags: list[str] = []

    # 1. File presence.
    required = ["nodes.jsonl", "functions.jsonl", "edges.jsonl",
                "sinks.jsonl", "skipped.jsonl", "manifest.json"]
    for name in required:
        p = d / name
        if not p.exists():
            red_flags.append(f"missing file: {name}")
            continue
        sz = p.stat().st_size
        print(f"  {name:<22} {sz:>12,} bytes")

    # 2. Load small files fully; count lines for big ones.
    def wc(p: Path) -> int:
        if not p.exists():
            return 0
        with p.open() as f:
            return sum(1 for _ in f)

    counts = {name: wc(d / name) for name in
              ("nodes.jsonl", "functions.jsonl", "edges.jsonl",
               "sinks.jsonl", "skipped.jsonl")}
    print(f"\nRecord counts:")
    for k, v in counts.items():
        print(f"  {k:<22} {v:>10,}")

    if counts["nodes.jsonl"] == 0:
        red_flags.append("no nodes emitted — dataset is empty")

    # 3. Manifest.
    mp = d / "manifest.json"
    if mp.exists():
        manifest = json.loads(mp.read_text())
        print(f"\nManifest totals: {manifest.get('totals')}")
        print(f"Elapsed: {manifest.get('elapsed_seconds')} s")
        t = manifest.get("totals", {})
        if t.get("skipped", 0) and t.get("processed", 0) == 0:
            red_flags.append("every queue entry was skipped — see skipped.jsonl")

    # 4. Node schema spot-check: pull the first N records and verify fields.
    expected_fields = {
        "id", "function", "role", "statement", "type", "line",
        "depth_cfg", "variables_used", "variables_defined",
        "is_patch_related", "distance_to_patch", "is_cross_function",
        "CFG_successors", "DFG_successors", "CALL_edges",
        "is_sink", "sink_reason", "label",
    }
    missing_fields_any: set[str] = set()
    n_checked = 0
    node_by_id: dict[str, dict] = {}
    label_counts = Counter()
    type_counts = Counter()
    per_patch_nodes: dict[tuple[str, str], int] = defaultdict(int)
    for rec in _iter_jsonl(d / "nodes.jsonl"):
        n_checked += 1
        if n_checked <= 2000:        # only remember the first 2k for cross-check
            node_by_id[rec["id"]] = rec
        missing_fields_any |= (expected_fields - set(rec.keys()))
        label_counts[rec.get("label")] += 1
        type_counts[rec.get("type")] += 1
        # Patch id prefix is first 2 segments of the canonical id "p:v:nnnnn"
        parts = str(rec.get("id", "")).rsplit(":", 2)
        if len(parts) == 3:
            per_patch_nodes[(parts[0], parts[1])] += 1
    if missing_fields_any:
        red_flags.append(f"nodes.jsonl missing fields: {sorted(missing_fields_any)}")

    if n_checked:
        pos_frac = 100.0 * label_counts.get(1, 0) / n_checked
        print(f"\nNodes: {n_checked:,}  label=1: {label_counts.get(1, 0):,} ({pos_frac:.2f}%)")
        print("Top node types:")
        for t, c in type_counts.most_common(10):
            print(f"  {t!r:<20} {c:,}")

    # 5. Per-patch coverage.
    if per_patch_nodes:
        print("\nSamples observed (patch_id, version → #nodes):")
        for key, n in sorted(per_patch_nodes.items()):
            print(f"  {key[0]:<40} {key[1]:<11} {n:>7,}")
    else:
        red_flags.append("could not identify any (patch, version) samples from node ids")

   # 6. Full referential integrity: load all node IDs and walk every edge.
    print("\nChecking full edge integrity (this may take a moment)...")
    all_node_ids: set[str] = set()
    for rec in _iter_jsonl(d / "nodes.jsonl"):
        nid = rec.get("id")
        if nid:
            all_node_ids.add(nid)

    total_edges = 0
    unresolved = 0
    cross_sample = 0
    for e in _iter_jsonl(d / "edges.jsonl"):
        total_edges += 1
        src = e.get("src")
        dst = e.get("dst")
        src_in = src in all_node_ids
        dst_in = dst in all_node_ids
        if not (src_in and dst_in):
            unresolved += 1
            continue
        # Both resolve. Check they're in the same sample.
        # Canonical ID format: "<patch_id>:<version>:<index>".
        # Same-sample iff the prefix before the final ':' matches.
        if src.rsplit(":", 1)[0] != dst.rsplit(":", 1)[0]:
            cross_sample += 1

    if total_edges:
        unres_pct = 100.0 * unresolved / total_edges
        print(f"\nEdge integrity (full):")
        print(f"  total edges:   {total_edges:,}")
        print(f"  unresolved:    {unresolved:,} ({unres_pct:.2f}%)")
        print(f"  cross-sample:  {cross_sample:,} (should be 0)")
        if unresolved > 0:
            red_flags.append(
                f"{unresolved} edges have endpoints not in nodes.jsonl "
                f"({unres_pct:.2f}%)"
            )
        if cross_sample > 0:
            red_flags.append(
                f"{cross_sample} edges connect nodes from different samples "
                f"(canonical IDs leaking across samples)"
            )
    else:
        print("\nNo edges to check.")

    # 7. Sinks sanity.
    sink_count = counts["sinks.jsonl"]
    print(f"\nSinks: {sink_count:,}")
    if sink_count:
        sr_counts = Counter()
        for s in _iter_jsonl(d / "sinks.jsonl"):
            sr_counts[s.get("sink_reason")] += 1
        print("Top sink_reasons:")
        for r, c in sr_counts.most_common(5):
            print(f"  {r!r:<35} {c}")

    # 8. Skipped entries.
    skipped = list(_iter_jsonl(d / "skipped.jsonl"))
    if skipped:
        print(f"\nSkipped rows: {len(skipped)}")
        by_stage = Counter(s.get("stage") for s in skipped)
        for stage, c in by_stage.most_common():
            print(f"  {stage!r:<30} {c}")
        # Show one example per stage.
        shown: set[str] = set()
        for s in skipped:
            stg = s.get("stage")
            if stg in shown:
                continue
            shown.add(stg)
            print(f"  e.g. {s.get('patch_id')} / {s.get('version')}: {s.get('reason', '')[:200]}")

    # 9. Report.
    print()
    if red_flags:
        print("RED FLAGS:")
        for r in red_flags:
            print(f"  - {r}")
        return 1
    print("No red flags. Dataset looks structurally sound.")
    return 0


if __name__ == "__main__":
    sys.exit(main())