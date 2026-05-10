# Vulnerability Dataset Pipeline

A pipeline for producing **node-level vulnerability detection datasets** from real CVE patches in open-source C projects. Each statement in the source code becomes one labeled training record, with features describing its position in the program graph and a binary label indicating whether it participates in the vulnerability.

The output is designed to support research on automated vulnerability detection and inter-procedural program slicing, particularly approaches that consider multi-function interactions and patch proximity.

---

## Dataset Download

The current public release of this dataset (500-CVE production run) is hosted on Google Drive:

**[Download dataset_500/ from Google Drive →](INSERT_GOOGLE_DRIVE_LINK_HERE)**

The download contains six files totaling ~1.7 GB:

| File | Size | Content |
|------|------|---------|
| `nodes.jsonl` | 922 MB | 601,662 labeled node records (the main payload) |
| `edges.jsonl` | 790 MB | 4,546,098 graph edges between nodes |
| `functions.jsonl` | 5 MB | 23,294 function-level provenance records |
| `sinks.jsonl` | 1.7 MB | 7,571 dangerous-API sink records |
| `skipped.jsonl` | 183 KB | 338 records of CVEs that could not be processed |
| `manifest.json` | 388 B | Run config and totals |

Smaller provenance files (`functions.jsonl`, `sinks.jsonl`, `manifest.json`, `skipped.jsonl`) are also tracked in this repository under `dataset_500/` for inspection without downloading the full archive.

---

## Quick Summary

| | |
|---|---|
| **Dataset format** | JSONL (one JSON record per line) |
| **CVEs processed** | 215 (of 500 attempted) |
| **Samples** | 420 (vulnerable + fixed version per CVE) |
| **Node records** | 601,662 |
| **Edge records** | 4,546,098 |
| **Positive label rate** | 23.27% |
| **CVEs in source pool (CVEfixes)** | 11,873 across 4,249 projects |
| **Unique projects in dataset** | 100+ |
| **Languages covered** | C |
| **CWE families** | CWE-119, CWE-122, CWE-125, CWE-787, CWE-20, CWE-190, CWE-476, and others |
| **Total processing time** | ~24 hours sequential on a 16 GB MacBook Pro |

---

## Table of Contents

1. [Background and Motivation](#1-background-and-motivation)
2. [How It Works](#2-how-it-works)
3. [The Seven Pipeline Steps](#3-the-seven-pipeline-steps)
4. [How Graphs Are Constructed](#4-how-graphs-are-constructed)
5. [How Slices Are Computed](#5-how-slices-are-computed)
6. [Features Included in Each Node Record](#6-features-included-in-each-node-record)
7. [Repository Layout](#7-repository-layout)
8. [Setup and Prerequisites](#8-setup-and-prerequisites)
9. [Reproducing the Dataset from Scratch](#9-reproducing-the-dataset-from-scratch)
10. [Development History: From 5 CVEs to 500](#10-development-history-from-5-cves-to-500)
11. [Bugs Encountered During Development](#11-bugs-encountered-during-development)
12. [Empirical Results](#12-empirical-results)
13. [Future Work](#13-future-work)
14. [Citation](#14-citation)

---

## 1. Background and Motivation

Most existing vulnerability detection datasets label entire functions as "vulnerable" or "clean." That granularity has two limitations.

First, it does not identify *which statements* within a function are responsible for the vulnerability. For automated patch suggestion or root-cause analysis, knowing the function is too coarse — you need the specific lines.

Second, it ignores inter-procedural dependencies. Many real vulnerabilities arise from values flowing across function boundaries: a length is computed wrong in one function and consumed unsafely as a memcpy argument in another. Function-level classifiers cannot model this.

This pipeline produces a **node-level dataset** where each record represents one C statement, with both its features and a label indicating whether it participates in the vulnerability. The labeling is computed via inter-procedural program slicing, so multi-function vulnerability propagation is captured directly in the labels.

---

## 2. How It Works

```
CVEfixes SQLite DB
       │
       ▼
┌──────────────────────────────────────┐
│ ingest_cvefixes.py                    │  Filter to C-language CVEs with
│                                       │  usable fix commits, derive
│                                       │  vulnerable commit from git parents
└───────────────┬──────────────────────┘
                │
                ▼ Work queue (JSONL)
┌──────────────────────────────────────┐
│ build_dataset.py                      │
│                                       │
│  For each (CVE, repo, vuln_commit,    │
│            fix_commit) in queue:      │
│                                       │
│   1. Clone repo (cached)              │
│   2. Run Joern on each commit         │
│   3. Find candidate functions         │
│   4. Build statement graph            │
│   5. Identify dangerous-API sinks     │
│   6. Compute vulnerability slice      │
│   7. Annotate nodes with features     │
│      and label (1=in slice, 0=else)   │
└───────────────┬──────────────────────┘
                │
                ▼
┌──────────────────────────────────────┐
│ Streaming JSONL output                │
│  nodes.jsonl, edges.jsonl,            │
│  functions.jsonl, sinks.jsonl,        │
│  skipped.jsonl, manifest.json         │
└──────────────────────────────────────┘
                │
                ▼
┌──────────────────────────────────────┐
│ validate_dataset.py                   │
│  Schema check, label distribution,    │
│  edge integrity, sink coverage        │
└──────────────────────────────────────┘
```

A CVE is processed end-to-end in roughly 30 seconds to 5 minutes depending on the size of the project. Joern parsing dominates the runtime.

---

## 3. The Seven Pipeline Steps

| Step | Module | Purpose |
|------|--------|---------|
| 1 | `pipeline/find_candidates.py` | Parse the patch diff; find patched functions and their 1-hop callers/callees in the call graph |
| 2 | `pipeline/build_program_graph.py` | Build a coarse statement-level graph with CFG, DFG, CALL, and PARAM_BIND edges over the candidate functions |
| 3 | `pipeline/sinks.py` | Identify dangerous-API call sites using a CWE-keyed table, patch proximity, and user overrides |
| 4 | (folded into Step 5) | — |
| 5 | `pipeline/slicer.py` | Compute the slice = backward(sinks) ∩ forward(patch) over CFG ∪ DFG ∪ CALL ∪ PARAM_BIND |
| 6 | (folded into Step 7) | — |
| 7 | `pipeline/annotate.py` | Emit per-node feature records with binary labels and canonical IDs |

Supporting infrastructure:

- `pipeline/cpg_cache.py` — caches Joern Code Property Graph builds per `(repo, commit)` pair
- `pipeline/_cpg_loader.py` — reads Joern's `neo4jcsv` export into NetworkX

---

## 4. How Graphs Are Constructed

### From source code to Code Property Graph

Joern parses the C source at each commit and builds a **Code Property Graph (CPG)**. The CPG unifies multiple program representations in one graph:

- **AST** (Abstract Syntax Tree) — syntactic structure
- **CFG** (Control Flow Graph) — execution order
- **DDG/PDG** (Data/Program Dependence Graph) — data-flow including REACHING_DEF
- **Call graph** — function call relationships
- **CDG** (Control Dependence Graph) — which statements depend on which conditions

### Scoping: why not the whole program

Building a full-program CPG is expensive (Joern takes minutes to hours per commit on large projects). More importantly, training a model on a graph where 99% of nodes are unrelated to the vulnerability would dilute the signal.

The pipeline scopes each sample to **patch functions plus 1-hop callers and callees**:

```
candidate functions = patched functions
                    ∪ {f : f calls a patched function}        (callers)
                    ∪ {f : a patched function calls f}        (callees)
```

This captures the most important inter-procedural cases (data flowing into a callee where a memcpy lives, or into the caller from an unsafe argument) while keeping graph size tractable.

### Lifting to statement granularity

Joern's CPG is fine-grained: a single C assignment produces nodes for the assignment, both identifiers, the binary operator, and so on. This is too granular for statement-level labeling.

The pipeline lifts CPG nodes to **coarse statement nodes** corresponding to one recognizable C construct each. Statement types include:

`METHOD_ENTRY`, `ASSIGN`, `CALL`, `DECL`, `IF`, `ELSE`, `FOR`, `WHILE`, `DO_WHILE`, `RETURN`, `BREAK`, `CONTINUE`, `GOTO`, and `OTHER`.

After lifting, only edges where both endpoints are statement nodes are retained. Edge types preserved on the final graph:

| Type | Source in CPG | Meaning |
|------|---------------|---------|
| `CFG` | Joern CFG edges | Control-flow successor |
| `REACHING_DEF` | Joern REACHING_DEF | Data-flow (which definitions reach which uses) |
| `CALL` | Joern CALL | Function call (cross-function when both endpoints are candidates) |
| `PARAM_BIND` | Synthesized | Argument-to-parameter flow at a call site |
| `CDG` | Joern CDG | Control-dependence |
| `AST` | Joern AST (coarsened) | Syntactic parent |

### Why a multigraph

The output is a `MultiDiGraph` because two statement nodes can be connected by multiple edge types simultaneously — for example, both a CALL edge and a REACHING_DEF edge between the same caller and callee. Heterogeneous graph models that learn separate weights per edge type can use this structure directly.

---

## 5. How Slices Are Computed

### The intuition

The fundamental insight: a statement is vulnerability-relevant if it lies on a path from where the patch was made to a dangerous operation.

The pipeline formalizes this as a **bidirectional program slice**:

```
slice = backward_slice(sinks) ∩ forward_slice(patch_nodes)
```

- The **backward slice from sinks** captures everything that contributes to a dangerous operation: all definitions, conditions, and assignments that influence a sink's arguments.
- The **forward slice from patch nodes** captures everything the patch change affects: all uses, propagations, and downstream calls.
- Their **intersection** is the set of statements that are both upstream of the fix and downstream of a sink — the vulnerability-mediating code.

### Traversal mechanics

Both slices are computed via bounded BFS over:

```
traversable_edges = CFG ∪ REACHING_DEF ∪ CALL ∪ PARAM_BIND
```

AST and CDG edges are excluded from slice traversal. They represent syntactic and structural relationships that would create spurious shortcuts (an AST edge from a method to its first statement makes everything trivially reachable).

Backward BFS from sinks follows edges in reverse. Forward BFS from patch nodes follows edges forward. Each is bounded by `max_hops` (default 10).

### Fallback handling

| Situation | Fallback |
|-----------|----------|
| No CWE-matched sinks identified | Use patch nodes as implicit sinks |
| Backward ∩ forward intersection is empty | Take the union as the slice |
| No patch nodes in the candidate graph | Empty slice |

These fallbacks keep the pipeline producing usable output on edge cases — most notably CVEs with logic-only fixes that don't touch any dangerous APIs.

### Label assignment

Every node in the slice gets `label = 1`. Every node outside the slice (but still in the candidate-function graph) gets `label = 0`. All candidate nodes are kept in the dataset, so negative examples are preserved alongside positives.

---

## 6. Features Included in Each Node Record

Each `nodes.jsonl` record is a JSON object with these fields:

### Identity and provenance

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Canonical ID: `<patch_id>:<version>:<index>` |
| `patch_id` | string | e.g. `curl/CVE-2023-38545` |
| `version` | string | `vulnerable` or `fixed` |
| `function` | string | Short function name |
| `function_full` | string | Joern's full method name |
| `role` | string | `patch`, `caller`, or `callee` |
| `file` | string | Repo-relative file path |
| `line` | int | Source line number |
| `column` | int | Source column |

### Statement content

| Field | Type | Description |
|-------|------|-------------|
| `statement` | string | Source text |
| `type` | string | Statement type (see Section 4) |
| `called_function` | string or null | Callee name, when type=CALL |

### Structural features

| Field | Type | Description |
|-------|------|-------------|
| `depth_cfg` | int | CFG depth from method entry |
| `depth_ast` | int | AST depth from method root |
| `in_loop` | bool | Inside a loop construct |
| `in_branch` | bool | Inside a conditional |
| `variables_used` | list[str] | Variables read by this statement |
| `variables_defined` | list[str] | Variables written by this statement |

### Graph neighborhood (canonical IDs)

| Field | Type | Description |
|-------|------|-------------|
| `CFG_successors` | list[str] | CFG-successor node IDs |
| `CFG_predecessors` | list[str] | CFG-predecessor node IDs |
| `DFG_successors` | list[str] | DFG-successor node IDs |
| `DFG_predecessors` | list[str] | DFG-predecessor node IDs |
| `CALL_edges` | list[str] | Nodes connected by CALL edges |
| `n_cfg_succ`, `n_cfg_pred`, `n_dfg_succ`, `n_dfg_pred` | int | Degree counts |

### Vulnerability-specific features

| Field | Type | Description |
|-------|------|-------------|
| `is_patch_related` | bool | This node's line appears in the diff |
| `distance_to_patch` | int | Min graph-hop distance to any patch node |
| `is_cross_function` | bool | This node has at least one cross-function edge |
| `hop_distance` | int | Distance of this function from a patch function (0 = patch, 1 = neighbor) |
| `is_sink` | bool | Identified as a dangerous-API sink |
| `sink_reason` | string or null | `cwe_api:<name>`, `proximity`, or `user` |

### Label

| Field | Type | Description |
|-------|------|-------------|
| `label` | int | `1` if in the vulnerability slice, `0` otherwise |

---

## 7. Repository Layout

```
vulnerability-dataset/
├── README.md                       (this file)
├── pipeline/
│   ├── __init__.py
│   ├── cpg_cache.py                Joern CPG build + cache
│   ├── _cpg_loader.py              neo4jcsv → NetworkX loader
│   ├── find_candidates.py          Step 1: diff parsing, candidate selection
│   ├── build_program_graph.py      Step 2: statement-level graph
│   ├── sinks.py                    Step 3: dangerous-API sink identification
│   ├── slicer.py                   Step 5: bidirectional slice computation
│   └── annotate.py                 Step 7: feature extraction
├── ingest_cvefixes.py              CVEfixes SQLite → work-queue JSONL
├── build_dataset.py                Batch orchestrator (the driver)
├── validate_dataset.py             Output sanity checker
├── test_*.py                       Unit and integration tests
├── smoke_test_step1.py             End-to-end smoke test on synthetic C
├── queue_500.jsonl                 The 500-CVE work queue
├── test_queue.jsonl                Hand-picked test queue (5 CVEs)
└── dataset_500/
    ├── manifest.json               Run config and totals
    ├── functions.jsonl             Function-level provenance (committed to git)
    ├── sinks.jsonl                 Sink records (committed to git)
    ├── skipped.jsonl               Failed entries (committed to git)
    ├── nodes.jsonl                 Main payload (Google Drive only)
    └── edges.jsonl                 Edge records (Google Drive only)
```

---

## 8. Setup and Prerequisites

### Software

| Tool | Version | Purpose |
|------|---------|---------|
| Python | 3.12+ | Runtime |
| Joern | 4.0.520 | Code Property Graph builder |
| NetworkX | recent | In-memory graph representation |
| Git | 2.x | Repo management and worktrees |

Joern must be on `PATH` so that `joern`, `joern-parse`, and `joern-export` are callable.

### Hardware

| Resource | Recommended | Notes |
|----------|-------------|-------|
| RAM | 16 GB minimum, 32 GB ideal | Joern + Python both consume memory |
| Disk | 250 GB free | CPG cache grows large during multi-CVE runs |
| CPU | Any modern multi-core | Joern is single-threaded internally per CPG |

A 16 GB MacBook Pro completed the 500-CVE production run (after banning the largest projects). Larger machines can include them.

### Joern's export format

This pipeline uses `--format neo4jcsv` (a set of flat CSV files). Two other formats were tried and rejected:

- `--format graphson`: Joern's GraphSON exporter has a serialization bug that crashes on real C codebases (`flatgraph.formats.graphson.GraphSONExporter` exception).
- `--format graphml`: Joern writes the GraphML successfully, then internally re-parses it for pretty-printing. On large CPGs this hits the JVM's default XML entity-size limit and crashes.

`neo4jcsv` is reliable on all tested projects (zlib 15k LoC up to curl 100k LoC).

---

## 9. Reproducing the Dataset from Scratch

### Step 1: download CVEfixes

CVEfixes v1.0.8 is hosted on Zenodo (DOI: 10.5281/zenodo.13118970). The archive is 12.7 GB.

```bash
mkdir -p ~/.cache/vuln_dataset/cvefixes
cd ~/.cache/vuln_dataset/cvefixes
curl -L -C - -o CVEfixes_v1.0.8.zip \
    "https://zenodo.org/records/13118970/files/CVEfixes_v1.0.8.zip?download=1"

# Verify the MD5 hash
md5 CVEfixes_v1.0.8.zip
# Expected: 4586a358977acfa4c60b1a2cdd096221
```

If the connection is unstable, the `-C -` flag tells curl to resume from where it stopped on the next attempt.

### Step 2: extract the SQL dump and restore to SQLite

```bash
unzip CVEfixes_v1.0.8.zip
gzcat CVEfixes_v1.0.8/Data/CVEfixes_v1.0.8.sql.gz | sqlite3 CVEfixes.db
```

The restore takes 30–90 minutes and produces a ~48 GB SQLite database.

### Step 3: generate the work queue

```bash
cd ~/vulnerability-dataset
python3 ingest_cvefixes.py \
    --db ~/.cache/vuln_dataset/cvefixes/CVEfixes.db \
    --out queue_500.jsonl \
    --limit 500 \
    --ban "php-src,ImageMagick"
```

The `--ban` flag excludes large projects whose CPGs exceed 16 GB RAM during loading. On machines with more memory, these can be re-included.

### Step 4: run the pipeline

```bash
caffeinate python3 build_dataset.py \
    --work-queue queue_500.jsonl \
    --out dataset_500/ \
    2>&1 | tee -a dataset_500_run.log
```

`caffeinate` prevents macOS from sleeping during the multi-hour run. On Linux, this is unnecessary.

The orchestrator handles failures, resumes from interruptions, and writes incrementally — interrupting with Ctrl-C is safe and preserves progress.

### Step 5: validate

```bash
python3 validate_dataset.py --out dataset_500/
```

The validator runs nine structural checks: file presence, record counts, schema completeness, label distribution, per-CVE coverage, edge integrity, sink distribution, and skip breakdown.

---

## 10. Development History: From 5 CVEs to 500

The pipeline went through three validation stages before the production run.

### Stage 1: synthetic C (1 fake CVE)

Initial validation used a synthetic 4-function C project with two commits: a "vulnerable" version with a bounds-check missing, and a "fixed" version with the bounds check added. This was implemented as `smoke_test_step1.py`.

The synthetic test caught most of the early bugs in diff parsing, function identification, and graph construction. It runs in under 30 seconds and was used as the regression check throughout development.

### Stage 2: hand-picked CVEs (5 real CVEs)

The first run on real data used 5 hand-picked CVEs covering diverse projects, CWEs, and bug shapes:

| CVE | Project | LoC | CWE | Slice character |
|-----|---------|-----|-----|-----------------|
| CVE-2023-38545 | curl | ~100k | CWE-122 | Heap overflow, mostly patch-fn |
| CVE-2022-37434 | zlib | ~15k | CWE-125/787 | Locally contained in inflate |
| CVE-2017-16808 | tcpdump | ~70k | CWE-125 | 80% of slice in callee functions |
| CVE-2018-14468 | tcpdump | ~70k | CWE-125 | No-sink fallback (logic-only fix) |
| CVE-2019-15161 | libpcap | ~30k | CWE-125 | Mixed patch + callee slice |

Result: 11,000 nodes, 166,177 edges, 0 failures, ~4 minutes total.

This stage validated:
- Cross-function slicing actually works (tcpdump CVE-2017-16808 had 82% of slice in callees)
- The patch-fallback path activates cleanly on CVEs with no dangerous APIs
- Project sizes from 15k to 100k LoC all parse correctly

### Stage 3: CVEfixes-derived CVEs (10 CVEs)

This stage shifted to CVEs ingested directly from the CVEfixes database, rather than hand-picked. The `ingest_cvefixes.py` script was written and tested at this stage.

Result: 8 of 10 processed (80% success rate), 26,421 nodes, 11.93% positive rate.

Two failures:
- 1 Joern parse crash on krb5 (a known issue with Joern's C frontend on macro-heavy code)
- 1 CVE where the patch didn't touch any C functions (build files only)

These failure modes are intrinsic to real-world data and confirmed the orchestrator's failure isolation works correctly.

This stage also revealed the first systemic data-format issue: CVEfixes stores commit parents as a Python list literal (`"['hash1']"`) rather than space-separated SHAs. The ingestor's parser was updated to use `ast.literal_eval` with a space-separated fallback for older CVEfixes versions.

### Stage 4: production run (500 CVEs)

The full run on a 500-CVE queue. Produced the dataset described in this document.

The run did not complete on the first attempt: an out-of-memory kill on a php-src CPG (3.1M nodes, 27M edges loaded into Python on a 16 GB machine) terminated the process partway through. The shared CPG cache had also grown to ~200 GB by then, leaving only 5 GB free disk.

Recovery steps:
1. Wiped the CPG cache (Joern rebuilds CPGs on demand; the wipe freed 200 GB)
2. Added `php-src` and `ImageMagick` to the ingestor's ban list
3. Re-ran the ingestor with the new bans, producing a queue with the largest projects excluded
4. Resumed the orchestrator with the same `--out` directory; it skipped the 78 already-processed CVEs and continued

The run completed across two sessions totaling ~24 hours of compute. The resume mechanism, designed in early development, worked correctly without intervention. Final result: 215 of 500 entries processed (43% success rate). The 42% skip rate is dominated by CVEfixes data quality — most skipped entries are CVEs whose fix commits don't touch any C functions (the patches are in build files, comments, headers only, etc.).

---

## 11. Bugs Encountered During Development

The following engineering issues came up during development and were resolved. They are documented here for anyone extending the pipeline or porting it to a different Joern version.

| # | Issue | How it manifested | Fix |
|---|-------|-------------------|-----|
| 1 | GraphSON v3 nested property format | Properties returned as `{"@type": ..., "@value": ...}` instead of bare values | Recursive unwrapping helpers |
| 2 | Joern `<global>` synthetic methods | Synthetic per-file `<global>` method spans the whole file, winning every line-containment lookup | Filter out by name pattern |
| 3 | Wrong vulnerable commit | Using OSV's "introduced" hash instead of fix's parent gave a 13MB diff spanning years | Always use `commit_fix~1` as `commit_vuln` |
| 4 | UTF-8 decode errors on git diff | Some commits touch non-UTF-8 files, raising `UnicodeDecodeError` | `errors="replace"` on the subprocess decode |
| 5 | Hunk context spilling into adjacent functions | Pure-addition diffs assigned closing `}` of prior function to patch fn | Limit context to lines within 2 of any `+` line |
| 6 | Dict-items unpacking swap | BFS started from a function name string instead of node ID | Fix variable order in unpacking |
| 7 | GraphSON serializer crashes on real CPGs | `flatgraph.formats.graphson.GraphSONExporter` exception on curl | Switched export to neo4jcsv |
| 8 | GraphML JVM entity size limit | Joern writes GraphML, then re-parses for pretty-printing; crashes on >100k-char nodes | Avoided GraphML; stayed on neo4jcsv |
| 9 | Stale git worktree registry | After cache wipe, `git worktree add` refused with "already registered" | `git worktree prune` before every add |
| 10 | PARAM_BIND deduplication collapsing arguments | All arguments of a call collapsed to a single edge | Include arg index in dedup key: `PARAM_BIND_{idx}` |
| 11 | CVEfixes `parents` field format | Stored as Python list literal `"['hash1']"`, not space-separated | Parse with `ast.literal_eval` |
| 12 | OOM on 3M-node CPGs | 16 GB machines crashed loading php-src/ImageMagick into Python | Banned the largest projects from the queue |

---

## 12. Empirical Results

### 5-CVE validation (Stage 2)

| CVE | Project | LoC | Time | Nodes | Positives | Sinks | Notable |
|-----|---------|-----|------|-------|-----------|-------|---------|
| CVE-2023-38545 | curl | ~100k | 32s | 1,299 | 772 (59%) | 10 | Heap overflow, SOCKS5 |
| CVE-2022-37434 | zlib | ~15k | 38s | 4,638 | 1,776 (38%) | 10 | OOB read/write |
| CVE-2017-16808 | tcpdump | ~70k | 47s | 3,133 | 787 (25%) | 22 | 82% of slice in callees |
| CVE-2018-14468 | tcpdump | ~70k | 23s | 666 | 168 (25%) | 0* | Patch-fallback activated |
| CVE-2019-15161 | libpcap | ~30k | 32s | 1,264 | 261 (21%) | 4 | Mixed slice |

\* No CWE-matched sinks; slicer fell back to using patch nodes as implicit sinks.

Total: 11,000 nodes, 166,177 edges, 46 sinks, 235s wall time, 0 failures.

### 500-CVE production run (Stage 4)

| Metric | Value |
|--------|-------|
| CVEs processed | 215 of 500 (43%) |
| Samples emitted | 420 |
| Node records | 601,662 |
| Edge records | 4,546,098 |
| Sinks identified | 7,571 |
| Positive label rate | 23.27% |
| Unique projects | 100+ |
| Total processing time | ~24 hours (across two sessions) |

### Skip breakdown (production)

| Stage | Count | Cause |
|-------|-------|-------|
| `step1` | 236 | "No function-scope changes" — patches that don't touch any C functions (build files, comments, etc.) |
| `step1/cpg_build` | 68 | Joern parse failures on specific codebases |
| `clone/fetch` | 34 | Network issues during the run |

The 42% skip rate is dominated by CVEfixes data quality (236 of 338 skips), not pipeline failures.

### Top dangerous APIs identified

| API | Sink count | CWE families |
|-----|-----------|--------------|
| `memcpy` | 1,528 | CWE-119, CWE-122, CWE-125, CWE-787 |
| `fprintf` | 1,270 | CWE-134 (format string) |
| `free` | 1,121 | CWE-415, CWE-416 (UAF/double-free) |
| `printf` | 856 | CWE-134 |
| `memset` | 829 | CWE-119, CWE-125 |

### Statement type distribution (production)

| Type | Count | % |
|------|-------|---|
| ASSIGN | 129,949 | 21.6% |
| CALL | 115,995 | 19.3% |
| DECL | 92,724 | 15.4% |
| IF | 84,713 | 14.1% |
| RETURN | 29,688 | 4.9% |
| OTHER | 26,645 | 4.4% |
| METHOD_ENTRY | 23,358 | 3.9% |
| ELSE | 17,604 | 2.9% |
| BREAK | 16,633 | 2.8% |
| GOTO | 14,619 | 2.4% |

The `OTHER` category at 4.4% indicates the statement classifier is discriminating well — most nodes fall into a meaningful semantic type rather than a catch-all.

### Edge integrity

A full walk of all 4.5M edges reported:

- 387 edges (0.0085%) with endpoints not in the node set — within noise tolerance
- 0 cross-sample edges (no canonical-ID leakage between samples)

---

## 13. Future Work

### A. Train a baseline GNN

The dataset is designed for graph neural network training. A natural first model is a heterogeneous GNN (R-GCN or HGT) for node-level binary classification, with separate weights per edge type (CFG vs DFG vs CALL etc.).

This would establish:
- A baseline F1/precision/recall for the dataset
- Whether the dataset's signal is learnable
- Comparison points for future methodology improvements

### B. Tune `max_hops_slice`

The default of 10 produces a 23.27% positive rate aggregated across CVEs but with high per-CVE variance (5–60%). A tuning run that varies the parameter from 4 to 12 and reports per-CVE label distributions would inform a better default and document the trade-off.

### C. Parallel processing

The orchestrator runs sequentially. A multi-process version using `multiprocessing.Pool` would give a near-linear speedup up to the number of cores, bounded by per-Joern memory cost. Two preconditions: file-locking the shared CPG cache, and per-worker output files merged at the end.

### D. Graded labels

Replace the binary `label` with a four-tier ordinal scheme:

| Label | Meaning |
|-------|---------|
| 3 | PATCH_CORE — node is on a modified line |
| 2 | TAINT_RELEVANT — backward-slice from a sink |
| 1 | SEMANTIC_SEED — forward-slice from patch nodes |
| 0 | NEGATIVE — outside all slices |

This enables ordinal regression or multi-class classification.

### E. PyG/PyTorch dataset loader

A `torch_geometric.data.Dataset` subclass that reads `nodes.jsonl` and `edges.jsonl`, tensorizes features, and emits `Data` objects per sample.

### F. Re-include large projects on bigger machines

`php-src` and `ImageMagick` were banned for the production run because their CPGs exceed 16 GB RAM during loading. On machines with 32 GB+ RAM, these can be re-included via:

```bash
python3 ingest_cvefixes.py --db ... --out queue.jsonl --limit 500
# (no --ban argument)
```

### G. Publish to Zenodo for permanent DOI

The current dataset is hosted on Google Drive. For long-term archival and academic citability, future work should publish to Zenodo (the same archive that hosts CVEfixes) for a permanent DOI. This is the standard pattern for vulnerability research datasets and what reviewers expect.

---

## 14. Citation

If you use this dataset or pipeline, please cite the underlying CVEfixes data:

```
Bhandari, G., Naseer, A., & Moonen, L. (2021). CVEfixes: Automated
Collection of Vulnerabilities and Their Fixes from Open-Source Software.
In Proceedings of the 17th International Conference on Predictive Models
and Data Analytics in Software Engineering (PROMISE '21). ACM.
DOI: 10.1145/3475960.3475985
```

For the pipeline itself, please cite this repository.
