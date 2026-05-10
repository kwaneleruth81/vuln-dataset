# Vulnerability Dataset Pipeline: Technical Documentation

**Project**: Node-Level Vulnerability Dataset for Automated Vulnerability Detection  
**Author**: Kwanele Ruth  
**Last updated**: May 2026

---

## Table of Contents

1. [Overview and Motivation](#1-overview-and-motivation)
2. [System Architecture](#2-system-architecture)
3. [Prerequisites and Environment](#3-prerequisites-and-environment)
4. [Pipeline Steps in Detail](#4-pipeline-steps-in-detail)
   - [Step 1: Candidate Function Discovery](#step-1-candidate-function-discovery)
   - [Step 2: Program Graph Construction](#step-2-program-graph-construction)
   - [Step 3: Sink Identification](#step-3-sink-identification)
   - [Step 5: Slice Computation](#step-5-slice-computation)
   - [Step 7: Node Annotation and Feature Extraction](#step-7-node-annotation-and-feature-extraction)
5. [How Graphs Were Constructed](#5-how-graphs-were-constructed)
6. [How Slices Were Computed](#6-how-slices-were-computed)
7. [Features Included](#7-features-included)
8. [The Batch Orchestrator](#8-the-batch-orchestrator)
9. [Output Dataset Schema](#9-output-dataset-schema)
10. [Validation](#10-validation)
11. [Empirical Results](#11-empirical-results)
12. [The CVEfixes Ingestor](#12-the-cvefixes-ingestor)
13. [Production Run Operations Notes](#13-production-run-operations-notes)
14. [Known Bugs Fixed During Development](#14-known-bugs-fixed-during-development)
15. [Dataset Information](#15-dataset-information)
16. [Future Work](#16-future-work)

---

## 1. Overview and Motivation

### Problem Statement

Modern software security research increasingly relies on machine learning models to automate
vulnerability detection. Most prior work operates at the function or file level, classifying
entire functions as "vulnerable" or "clean." This coarse granularity has two problems:

1. **It does not identify which statements** within a function are responsible for
   the vulnerability — information that is essential for automated patch suggestion,
   vulnerability localisation, and root cause analysis.
2. **It ignores inter-procedural dependencies.** Many real vulnerabilities arise from
   data flowing across function boundaries, a dangerous value computed in one function
   and consumed unsafely in another. Function level classifiers by definition cannot
   model this.

### What This Pipeline Produces

This pipeline produces a **node-level dataset** where each record represents one C
statement. Each record carries:

- **Features** derived from the Code Property Graph (CPG): control-flow neighbors,
  data-flow neighbors, call edges, loop/branch depth, variables used and defined,
  distance to the patch, and whether the node participates in cross-function edges.
- **A binary label**: `1` if the statement lies within the vulnerability-relevant
  slice (i.e., it contributes to or is affected by the vulnerability), `0` otherwise.
- **Provenance**: which CVE, which project, which function, which version
  (vulnerable or fixed), and which role (patch function, caller, callee).

### Research Goals

The dataset is designed to:

- Train models to predict which program statements contribute to a vulnerability,
  considering multi-function interactions.
- Support research on automated vulnerability detection and inter-procedural
  program slicing.
- Enable comparison between the vulnerable and fixed versions of the same code,
  which is valuable for patch suggestion and fix localization.

---

## 2. System Architecture

```
Work Queue (JSONL)
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│                   build_dataset.py                       │
│              (Batch Orchestrator)                        │
│                                                         │
│  ┌──────────┐  ┌──────────────────────────────────────┐ │
│  │RepoCache │  │         Per-Patch Pipeline            │ │
│  │(git clone│  │                                       │ │
│  │ + fetch) │  │  Step 1: find_candidate_functions()   │ │
│  └──────────┘  │         ↓                             │ │
│                │  Step 2: build_program_graph()         │ │
│  ┌──────────┐  │         ↓                             │ │
│  │CPG Cache │  │  Step 3: identify_sinks()             │ │
│  │(Joern    │  │         ↓                             │ │
│  │ neo4jcsv)│  │  Step 5: compute_slice()              │ │
│  └──────────┘  │         ↓                             │ │
│                │  Step 7: annotate_nodes()             │ │
│                └──────────────────────────────────────┘ │
│                          ↓                               │
│  ┌───────────────────────────────────────────────────┐  │
│  │             DatasetWriter (JSONL)                  │  │
│  │  nodes.jsonl  edges.jsonl  functions.jsonl         │  │
│  │  sinks.jsonl  skipped.jsonl  manifest.json         │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### Key components

| File | Role |
|------|------|
| `pipeline/cpg_cache.py` | Build and cache Joern CPGs per `(repo, commit)` |
| `pipeline/_cpg_loader.py` | Read Joern's neo4jcsv export into NetworkX |
| `pipeline/find_candidates.py` | Step 1: diff parsing and candidate function discovery |
| `pipeline/build_program_graph.py` | Step 2: coarse statement graph construction |
| `pipeline/sinks.py` | Step 3: sink identification |
| `pipeline/slicer.py` | Step 5: bidirectional BFS slice computation |
| `pipeline/annotate.py` | Step 7: feature extraction and record emission |
| `build_dataset.py` | Batch orchestrator |
| `validate_dataset.py` | Dataset structural sanity checker |

---

## 3. Prerequisites and Environment

### Software requirements

| Tool | Version | Purpose |
|------|---------|---------|
| Python | 3.12+ | Pipeline runtime |
| Joern | 4.0.520 | Code Property Graph generation |
| NetworkX | any recent | In-memory graph representation |

Joern must be on your `PATH` (`joern`, `joern-parse`, `joern-export`).

### Joern export format

After evaluating all four of Joern's export formats (`dot`, `graphml`, `graphson`,
`neo4jcsv`), this pipeline uses **`neo4jcsv`** exclusively.

- `graphson`: Joern's GraphSON exporter has a known serialization bug triggered by
  large C codebases (crashes inside `flatgraph.formats.graphson.GraphSONExporter`).
- `graphml`: Joern writes the XML file successfully but then re-parses it internally
  for pretty-printing. On large CPGs (>400MB), this hits the JVM's default XML entity
  size limit and crashes before the process exits cleanly.
- `neo4jcsv`: Reliable on all tested projects (zlib 15k LoC to curl 100k LoC).
  Produces ~150 flat CSV files per commit; all required edge types are present
  (AST, CFG, REACHING_DEF, CALL, CONTAINS, ARGUMENT).

### CPG Cache

Joern builds are cached at `~/.cache/vuln_dataset/cpgs/<hash>/` where `<hash>`
is derived from the (repo path, commit sha) pair. Building a CPG is expensive
(2–15 minutes per commit depending on codebase size), so the cache means that
re-runs and multi-CVE queues on the same project share their CPGs.

The cache is content-addressed. Wiping it forces a rebuild. Keeping the repo
clone (at `~/.cache/vuln_dataset/repos/`) while wiping CPGs is fine — the
clone does not need to be re-downloaded.

---

## 4. Pipeline Steps in Detail

### Step 1: Candidate Function Discovery

**Module**: `pipeline/find_candidates.py`  
**Input**: repo path, `commit_vuln`, `commit_fix`  
**Output**: `Step1Result` per version with a list of `CandidateFunction` objects

#### Diff parsing

The pipeline runs `git diff --unified=3 <commit_vuln>..<commit_fix>` to extract the
patch. The diff is walked line by line to compute per-file modified line sets for
both the vulnerable and fixed versions.

**Pure-addition patches** require special handling. When a fix only adds lines (no
removals), the vulnerable version has no explicitly "removed" lines. In this case
the pipeline uses a windowed context approach: context lines within 2 lines of any
`+` line in the hunk are treated as the vulnerable-side modified lines. This
correctly attributes the patch location to the right function even when hunk context
spills into an adjacent function above or below.

#### CPG construction and call-graph extraction

For each version (vulnerable and fixed), Joern is invoked:

```
joern-parse  <worktree>  --output  <cache>/cpg.bin
joern-export <cache>/cpg.bin  --repr all  --format neo4jcsv  --out <cache>/graph/
```

A git worktree (not a full clone) is used to materialize the repo at each commit.
This is lightweight and does not move the main checkout's HEAD.

The exported CPG is loaded into a NetworkX `MultiDiGraph`. METHOD nodes give us
function metadata. CALL node attributes give us call targets. Ownership of every
CPG node is determined by BFS from each METHOD node following CONTAINS and AST
edges.

**Filtered synthetic nodes**: Joern's C frontend emits synthetic METHOD nodes
`<global>` and `<includes>` that span entire files. These are filtered out before
any line-to-function mapping.

#### Candidate function selection

Modified lines are mapped to functions using a **narrowest-range containment** rule:
if multiple functions' line ranges contain a modified line (possible with Joern's
synthetic wrappers), the function with the smallest `(end_line - start_line)` wins.

From patch functions, 1-hop callers and 1-hop callees are added as neighbor
candidates. The hop count is configurable via `--hops` (default 1). Result roles:

| Role | Meaning |
|------|---------|
| `patch` | Function directly modified by the diff |
| `caller` | Function that calls a patch function |
| `callee` | Function called by a patch function |

---

### Step 2: Program Graph Construction

**Module**: `pipeline/build_program_graph.py`  
**Input**: CPGHandle, Step1Result  
**Output**: NetworkX MultiDiGraph (statement-level)

#### From CPG nodes to statement nodes

Joern's CPG is fine-grained: a single C assignment like `x = a + b` produces
nodes for the assignment, the identifier `x`, the binary operator `+`, the
identifiers `a` and `b`, and more. This level of detail is too granular for
statement-level vulnerability labeling.

The pipeline **lifts** CPG nodes to statement-level by identifying "coarse
statement nodes" — METHOD, CALL, CONTROL_STRUCTURE, RETURN, BLOCK-with-code,
and similar nodes that correspond to one recognizable C construct. This
approximates the granularity a developer sees in a code review.

Statement type classification:

| Type | Joern node labels matched |
|------|--------------------------|
| `METHOD_ENTRY` | METHOD |
| `CALL` | CALL |
| `ASSIGN` | CALL with `<operator>.assignment*`, BLOCK with `=` |
| `DECL` | LOCAL, BLOCK with declaration pattern |
| `IF` | CONTROL_STRUCTURE where `controlStructureType=IF` |
| `ELSE` | CONTROL_STRUCTURE where type=ELSE/ELSE_IF |
| `FOR` | CONTROL_STRUCTURE where type=FOR |
| `WHILE` | CONTROL_STRUCTURE where type=WHILE |
| `DO_WHILE` | CONTROL_STRUCTURE where type=DO |
| `RETURN` | RETURN |
| `BREAK` | CONTROL_STRUCTURE where type=BREAK |
| `GOTO` | CONTROL_STRUCTURE where type=GOTO |
| `OTHER` | Everything else |

#### Edge types preserved

After lifting to statement level, only edges where both endpoints are statement
nodes are kept. Edge types:

| Key | Source in CPG | Meaning |
|-----|---------------|---------|
| `CFG` | CFG edges | Control-flow successor |
| `REACHING_DEF` | REACHING_DEF edges | Data-flow (reaching definition) |
| `CALL` | CALL edges | Function call |
| `PARAM_BIND` | Derived from ARGUMENT edges | Argument-to-parameter binding |
| `CDG` | CDG edges | Control-dependence |
| `AST` | AST edges (coarsened) | Syntactic parent |

#### PARAM_BIND edges

CALL → CALLEE_METHOD_ENTRY edges represent the call itself. But to model
*which argument flows to which parameter*, PARAM_BIND edges are synthesized:
for each ARGUMENT edge from a call expression to an argument node, a
`PARAM_BIND_{idx}` edge is added from the call-site statement to the
corresponding method entry node of the callee. Each argument index gets its
own edge key to prevent deduplication collapsing multiple arguments to one.

---

### Step 3: Sink Identification

**Module**: `pipeline/sinks.py`  
**Input**: Statement graph from Step 2, CWE list, optional extra_sinks  
**Output**: `is_sink=True`, `sink_reason` attributes set on matching nodes

Sinks are call sites of dangerous APIs that are relevant to the CVE's CWE.
Three passes, applied in order:

**Pass 1 — CWE-keyed API table.**
A hardcoded table maps CWEs to dangerous API names:

| CWE | Dangerous APIs |
|-----|----------------|
| CWE-119, CWE-120, CWE-122, CWE-787 | memcpy, memset, memmove, strcpy, strncpy, sprintf, gets, ... |
| CWE-125 | memcpy, memcmp, memset, read, recv, fread, ... |
| CWE-190, CWE-191 | malloc, realloc, calloc, operator new |
| CWE-416 | free, delete |
| CWE-476 | (pointer dereference patterns) |
| CWE-369 | (division operators) |

For each CWE in the patch's CWE list, every CALL-type statement node whose
`called_function` attribute matches one of the table's APIs is marked as a sink
with `sink_reason = "cwe_api:<api_name>"`.

**Pass 2 — Patch-proximity.**
Any call-site node within `proximity_lines` (default 3) lines of a modified line
is also marked as a sink with `sink_reason = "proximity"`. This catches dangerous
calls that sit immediately next to the fix but aren't in the CWE table.

**Pass 3 — User overrides.**
If the work-queue entry includes `extra_sinks` (a list of `[file, line]` pairs),
nodes at those exact locations are marked as sinks with `sink_reason = "user"`.
This is useful when a crash trace or manual analysis identifies a specific
dangerous location.

**Fallback**: If no sinks are identified after all three passes, the slicer
receives the patch nodes themselves as implicit sinks. A warning is logged.
This path was tested and confirmed to work on `tcpdump/CVE-2018-14468` which
uses CWE-125 with a logic-only fix (no dangerous-API calls).

---

### Step 5: Slice Computation

**Module**: `pipeline/slicer.py`  
**Input**: Statement graph with sinks and patch nodes marked  
**Output**: `in_slice=True` attribute set on relevant nodes

See [Section 6](#6-how-slices-were-computed) for the full technical description.

---

### Step 7: Node Annotation and Feature Extraction

**Module**: `pipeline/annotate.py`  
**Input**: Statement graph with `in_slice`, `is_sink`, patch metadata  
**Output**: List of node record dicts (one per statement node)

Each node is assigned a **canonical ID** of the form:

```
<patch_id>:<version>:<zero-padded-index>
```

for example: `curl/CVE-2023-38545:vulnerable:00042`

The index is derived by sorting nodes by `(function, line, column, joern_id)`,
giving a deterministic ordering across runs.

See [Section 7](#7-features-included) for the full feature schema.

---

## 5. How Graphs Were Constructed

### From source code to CPG

Joern generates a Code Property Graph (CPG) by parsing C source files with its
built-in C frontend (based on Eclipse CDT). The CPG unifies:

- **AST** (Abstract Syntax Tree): syntactic structure
- **CFG** (Control Flow Graph): execution order edges
- **DDG/PDG** (Data/Program Dependence Graph): data-flow edges including
  REACHING_DEF (which definitions reach which uses)
- **CALL graph**: function call relationships
- **CDG** (Control Dependence Graph): which statements are control-dependent
  on which conditions

Joern exports these as neo4jcsv: a set of CSV files with node attributes and
edge types. The pipeline's `_cpg_loader.py` reads these into a single NetworkX
`MultiDiGraph` using the header files for column type coercion.

### Scoping: why not the whole program

Generating and storing a full-program CPG for every CVE would be:
1. Extremely slow (Joern takes 2-15 minutes per commit just for the CPG build)
2. Wasteful for training: most nodes in a 100k-line program are irrelevant
3. Risky for model generalisation: diluting a small patch change with thousands
   of unrelated nodes makes learning the signal much harder

Instead, the pipeline scopes to **patch functions + 1-hop call graph neighbors**:

```
scope = patch_functions
      ∪ {f | f calls any patch function}       # 1-hop callers
      ∪ {f | any patch function calls f}       # 1-hop callees
```

This captures cross-function vulnerability propagation (the most important case
for inter-procedural analysis) while keeping the graph tractable.

### Graph construction in detail

For each candidate function, the pipeline:

1. Extracts the CPG subgraph containing only nodes owned by candidate functions.
   Ownership is determined by BFS from each METHOD node following CONTAINS and
   AST edges — every CPG node reachable this way belongs to that function.

2. Lifts fine grained CPG nodes to coarse statement nodes (see Step 2 above).

3. Re-indexes all edges: an edge is kept if and only if both endpoints are
   statement nodes. Edge type is preserved as a MultiDiGraph key, allowing
   multiple edge types between the same pair of nodes.

4. Synthesizes PARAM_BIND edges to represent argument-to-parameter flow across
   function calls.

5. Annotates each node with function-level metadata: which function it belongs to,
   its role (patch/caller/callee), and hop distance from the patch.

### Multi-graph structure

The final graph is a **MultiDiGraph** (directed, multiple edges allowed between
the same node pair). This is necessary because two nodes can be connected by
multiple edge types simultaneously — for example, a CALL edge (syntactic call)
and a REACHING_DEF edge (data-flow dependency) between the same caller and callee.

---

## 6. How Slices Were Computed

### Motivation

Not every statement in the scoped neighborhood is vulnerability relevant. A
1-hop neighborhood can include hundreds of statements in callee functions that
have nothing to do with the vulnerability. The slice identifies the relevant
subset.

The key insight is:

> A statement is vulnerability-relevant if it lies on a path from the patched
> code (where the developer made the fix) to a dangerous operation (a sink).

This is formalized as a **bidirectional program slice**:

```
slice = backward_slice(sinks) ∩ forward_slice(patch_nodes)
```

- The **backward slice from sinks** captures everything that *contributes to*
  the dangerous operation: all definitions, conditions, and assignments that
  influence the sink's arguments.
- The **forward slice from patch nodes** captures everything that the patch
  change *affects*: all uses, propagations, and calls downstream of where
  the fix was made.
- Their **intersection** is the set of nodes that are both upstream of the
  fix and downstream of the sink — the vulnerability-mediating statements.

### Traversal

Both slices are computed as BFS over the combined edge set:

```
traversable_edges = CFG ∪ REACHING_DEF ∪ CALL ∪ PARAM_BIND
```

AST and CDG edges are intentionally excluded from slice traversal. They are
syntactic/structural relationships that can create spurious long-range paths
(e.g., an AST edge from a method to its first statement would immediately
make everything reachable).

**Backward BFS from sinks** follows edges in **reverse**: from a sink node,
follow incoming edges. A node is in the backward slice if it has any data-flow
or control-flow path leading to the sink.

**Forward BFS from patch nodes** follows edges **forward**: from each node
on a modified line, follow outgoing edges. A node is in the forward slice if
it is reachable from where the patch was made.

Both BFS runs are bounded by `max_hops` (default 10). This prevents infinite
expansion in large strongly-connected subgraphs.

### Fallback strategies

Three fallback strategies handle edge cases:

| Situation | Fallback |
|-----------|----------|
| No sinks identified after Pass 1-3 | Use patch nodes as implicit sinks |
| Backward ∩ forward slice is empty | Return union of both slices (anchor-union) |
| No patch nodes found (e.g. pure callee patch) | Return empty slice |

### Label assignment

After slicing:
- Every node in the slice gets `label = 1`
- Every node outside the slice gets `label = 0`
- All candidate-function nodes are kept in the dataset (not filtered); label
  determines whether they were in the slice

This preserves negatives (label=0 nodes) in the training data, which is
important for learning a classifier.

### Cross-function slicing in practice

On `tcpdump/CVE-2017-16808`, the slice contained 387 nodes:
- 69 nodes (18%) in the patch functions
- 318 nodes (82%) in callee functions

This demonstrates that the inter-procedural slice is functioning correctly:
the vulnerability involves data flowing from the patch function into callees
where the dangerous memcpy/memcmp operations reside.

---

## 7. Features Included

Each node record is a JSON object with the following fields:

### Identity and provenance

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Canonical node ID: `<patch_id>:<version>:<index>` |
| `patch_id` | string | e.g. `curl/CVE-2023-38545` |
| `version` | string | `vulnerable` or `fixed` |
| `function` | string | Short function name |
| `function_full` | string | Joern full name (includes file path) |
| `role` | string | `patch`, `caller`, or `callee` |
| `file` | string | Repo-relative file path |
| `line` | int | Source line number |
| `column` | int | Source column number |

### Statement content

| Field | Type | Description |
|-------|------|-------------|
| `statement` | string | Source text of the statement (from Joern's `code` attribute) |
| `type` | string | Statement type: ASSIGN, CALL, IF, DECL, RETURN, etc. |
| `called_function` | string or null | If type=CALL, the name of the called function |

### Structural features

| Field | Type | Description |
|-------|------|-------------|
| `depth_cfg` | int | Depth of this node in the CFG from METHOD_ENTRY |
| `depth_ast` | int | Depth of this node in the AST from METHOD |
| `in_loop` | bool | True if this node is inside a loop construct |
| `in_branch` | bool | True if this node is inside a conditional branch |
| `variables_used` | list[str] | Variable names read by this statement |
| `variables_defined` | list[str] | Variable names written by this statement |

### Graph neighborhood features

| Field | Type | Description |
|-------|------|-------------|
| `CFG_successors` | list[str] | Canonical IDs of CFG successors |
| `CFG_predecessors` | list[str] | Canonical IDs of CFG predecessors |
| `DFG_successors` | list[str] | Canonical IDs of REACHING_DEF successors |
| `DFG_predecessors` | list[str] | Canonical IDs of REACHING_DEF predecessors |
| `CALL_edges` | list[str] | Canonical IDs of nodes connected by CALL edges |
| `n_cfg_succ` | int | Count of CFG successors |
| `n_cfg_pred` | int | Count of CFG predecessors |
| `n_dfg_succ` | int | Count of DFG successors |
| `n_dfg_pred` | int | Count of DFG predecessors |

### Vulnerability-relevant features

| Field | Type | Description |
|-------|------|-------------|
| `is_patch_related` | bool | True if this node's line appears in the diff |
| `distance_to_patch` | int | Minimum graph-hop distance to any patch node |
| `is_cross_function` | bool | True if this node has edges crossing a function boundary |
| `hop_distance` | int | Hop distance of this function from the patch function (0=patch, 1=neighbor) |
| `is_sink` | bool | True if this node was identified as a dangerous-API sink |
| `sink_reason` | string or null | Sink identification reason: `cwe_api:<name>`, `proximity`, or `user` |

### Label

| Field | Type | Description |
|-------|------|-------------|
| `label` | int | `1` if in the vulnerability slice, `0` otherwise |

### Feature design rationale

**Why graph neighborhood features?**
Graph Neural Networks — the most natural model for this task — aggregate information
from neighbors. Providing the canonical IDs of neighbors allows a downstream GNN
loader to reconstruct the adjacency matrix from `nodes.jsonl` and `edges.jsonl`
together, without needing a separate adjacency file.

**Why both CFG and DFG?**
Control-flow and data-flow capture fundamentally different aspects of a
vulnerability. A buffer overflow requires both a data condition (buffer size
vs. copy size) and a control path reaching the dangerous call. CFG alone misses
the data semantics; DFG alone misses the control path.

**Why `distance_to_patch`?**
Nodes immediately adjacent to the patched line are typically more vulnerability-
relevant than nodes ten hops away. Providing this as a continuous feature lets
the model learn a soft distance penalty, rather than making a hard in/out
decision at an arbitrary threshold.

**Why `is_cross_function`?**
The primary research question involves *inter-procedural* vulnerability
propagation. Flagging cross-function nodes explicitly lets the model give
more weight to the paths that cross function boundaries — the most novel
aspect of this dataset compared to function-level work.

---

## 8. The Batch Orchestrator

**Module**: `build_dataset.py`

The orchestrator takes a work queue (JSONL, one CVE patch per line) and runs
the full pipeline for each entry. It is designed to run unattended overnight.

### Work queue schema

```json
{
  "patch_id": "curl/CVE-2023-38545",
  "repo_url": "https://github.com/curl/curl",
  "commit_vuln": "09e25b9d94f4106eac8ca3a43b221bdc66f405e4",
  "commit_fix":  "fb4415d8aee6c1045be932a34fe6107c2f5ed147",
  "cve": "CVE-2023-38545",
  "cwes": ["CWE-122", "CWE-787", "CWE-119"],
  "extra_sinks": []
}
```

`commit_vuln` should be the parent of `commit_fix` (i.e. `commit_fix~1`) for
surgical one-commit patches. Using the OSV "introduced" commit is a common
mistake — it creates a diff spanning years of unrelated changes.

### Repo cache

Repos are cloned once to `~/.cache/vuln_dataset/repos/<owner>__<name>/`.
Multiple CVEs from the same project share one clone. Missing commits are
fetched individually (`git fetch origin <sha>`) rather than re-cloning.

### Failure isolation

Every failure surface is caught independently. A Joern crash on one CVE does
not abort the run. Failures are logged to `skipped.jsonl` with:

- `stage`: where the failure occurred (`clone/fetch`, `step1/cpg_build`,
  `step1`, `cpg_build`, `steps2-7`)
- `reason`: the exception message or last 300 chars of stderr
- `traceback_tail`: last 500 chars of the Python traceback
- `ts`: Unix timestamp

### Resume

On restart, the orchestrator scans `functions.jsonl` to find patch_ids already
processed. Those are skipped. Entries in `skipped.jsonl` only (failures) are
retried — transient errors like network failures often succeed on retry.

### Signal handling

`SIGINT` (Ctrl-C) and `SIGTERM` trigger a graceful shutdown: the current patch
is abandoned, all open files are flushed, and the process exits with code 130.
The partial output is safe to resume from.

### CLI reference

```
python3 build_dataset.py \
    --work-queue  queue.jsonl      # required
    --out         dataset/         # required
    --hops        1                # neighbor hop count (default 1)
    --max-hops-slice 10            # slice BFS cap (default 10)
    --proximity-lines 3            # sink proximity window (default 3)
    --debug-samples                # write per-patch JSON to dataset/samples/
    --repo-cache  ~/.cache/...     # override default repo cache location
    --log-level   INFO             # DEBUG for verbose Joern output
```

---

## 9. Output Dataset Schema

The dataset directory contains six files:

### `nodes.jsonl`

One JSON record per node per sample. This is the primary output. See
[Section 7](#7-features-included) for the full field listing.

Example record:

```json
{
  "id": "curl/CVE-2023-38545:vulnerable:00042",
  "patch_id": "curl/CVE-2023-38545",
  "version": "vulnerable",
  "function": "Curl_SOCKS5",
  "role": "patch",
  "file": "lib/socks.c",
  "line": 875,
  "statement": "len = hostname_len + 1;",
  "type": "ASSIGN",
  "depth_cfg": 12,
  "in_loop": false,
  "in_branch": true,
  "variables_used": ["hostname_len"],
  "variables_defined": ["len"],
  "is_patch_related": true,
  "distance_to_patch": 0,
  "is_cross_function": false,
  "is_sink": false,
  "label": 1
}
```

### `edges.jsonl`

One record per graph edge. Src and dst are canonical node IDs from `nodes.jsonl`.

```json
{
  "patch_id": "curl/CVE-2023-38545",
  "version": "vulnerable",
  "src": "curl/CVE-2023-38545:vulnerable:00042",
  "dst": "curl/CVE-2023-38545:vulnerable:00043",
  "edge_type": "CFG"
}
```

### `functions.jsonl`

One record per candidate function per sample. Useful for provenance queries.

```json
{
  "patch_id": "curl/CVE-2023-38545",
  "version": "vulnerable",
  "function_full": "Curl_SOCKS5",
  "function": "Curl_SOCKS5",
  "role": "patch",
  "file": "lib/socks.c",
  "hop_distance": 0,
  "modified_lines": [875, 876, 877]
}
```

### `sinks.jsonl`

One record per identified sink node. Useful for auditing sink quality without
parsing all of `nodes.jsonl`.

```json
{
  "patch_id": "curl/CVE-2023-38545",
  "version": "vulnerable",
  "node_id": "curl/CVE-2023-38545:vulnerable:00089",
  "function": "Curl_SOCKS5",
  "line": 921,
  "called_function": "memcpy",
  "sink_reason": "cwe_api:memcpy",
  "label": 1
}
```

### `skipped.jsonl`

One record per failed patch. Empty means zero failures. See
[Section 8](#8-the-batch-orchestrator) for the field schema.

### `manifest.json`

Run metadata: config, totals, elapsed time.

```json
{
  "run_config": {
    "hops": 1,
    "max_hops_slice": 10,
    "proximity_lines": 3,
    "debug_samples": false
  },
  "totals": {
    "processed": 4,
    "skipped": 0,
    "samples": 8,
    "nodes": 9701,
    "positives": 2992
  },
  "elapsed_seconds": 235.1
}
```

### Downloading the production dataset

The production 500-CVE dataset (`dataset_500/`) is not stored in this repository — `nodes.jsonl` (922 MB) and `edges.jsonl` (790 MB) exceed GitHub's file size limit. The smaller provenance files (`functions.jsonl`, `sinks.jsonl`, `skipped.jsonl`, `manifest.json`) are tracked in git directly.

The full dataset is available for download at: **[Google Drive link to be added by author]**

| File | Size | Location |
|------|------|----------|
| `nodes.jsonl` | 922 MB | Google Drive |
| `edges.jsonl` | 790 MB | Google Drive |
| `functions.jsonl` | 5 MB | Git repository |
| `sinks.jsonl` | 1.7 MB | Git repository |
| `skipped.jsonl` | 183 KB | Git repository |
| `manifest.json` | 388 B | Git repository |

---

## 10. Validation

Run after every batch:

```bash
python3 validate_dataset.py --out dataset/
```

The validator checks nine things and exits 0 (no issues) or 1 (red flags):

1. All required files exist
2. Record counts per file
3. Manifest totals parse correctly
4. First 2,000 node records have all expected fields
5. Label distribution (warns on extreme imbalance)
6. Per-patch sample coverage
7. Edge referential integrity (src/dst resolve to known node IDs)
8. Sink reason distribution
9. Skipped entries breakdown by stage with one example per stage

---

## 11. Empirical Results

### Validation run: 5 CVEs across 4 projects

| CVE | Project | LoC | Time | Nodes | Positives | Sinks | Cross-fn nodes |
|-----|---------|-----|------|-------|-----------|-------|----------------|
| CVE-2023-38545 | curl | ~100k | 32s | 1,299 | 772 (59%) | 10 | 274 |
| CVE-2022-37434 | zlib | ~15k | 38s | 4,638 | 1,776 (38%) | 10 | 490 |
| CVE-2017-16808 | tcpdump | ~70k | 47s | 3,133 | 787 (25%) | 22 | 468 |
| CVE-2018-14468 | tcpdump | ~70k | 23s | 666 | 168 (25%) | 0* | 138 |
| CVE-2019-15161 | libpcap | ~30k | 32s | 1,264 | 261 (21%) | 4 | 244 |

*No CWE-matched sinks; patch-fallback activated cleanly.

**Total**: 11,000 nodes, 166,177 edges, 46 sinks, 34.2% positive rate, 0 failures, 235s total.

### Node type distribution

| Type | Count | % |
|------|-------|---|
| ASSIGN | 2,694 | 24.5% |
| CALL | 2,308 | 21.0% |
| IF | 1,620 | 14.7% |
| DECL | 1,269 | 11.5% |
| OTHER | 506 | 4.6% |
| GOTO | 404 | 3.7% |
| RETURN | 395 | 3.6% |
| ELSE | 374 | 3.4% |
| BREAK | 344 | 3.1% |
| METHOD_ENTRY | 274 | 2.5% |

`OTHER` at 4.6% indicates the statement classifier is discriminating well —
most nodes are categorized into a meaningful type.

### Positive rate discussion

The aggregate 34.2% positive rate is higher than typical binary classifiers see
in vulnerability datasets (often <5%). The reasons are:

1. We scope to the neighborhood (not the whole file), so the ratio of
   relevant-to-irrelevant nodes is higher by construction.
2. The slice BFS runs to `max_hops=10`, which on small functions can reach most
   of the candidate nodes.

Per-CVE positive rates vary: tcpdump/CVE-2017-16808 (25%) vs curl/CVE-2023-38545
(59%). This variance is expected and reflects different vulnerability containment
patterns. Class weighting or `max_hops` tuning can adjust this tradeoff at
training time.

### Production run: 500-CVE dataset

The production run processed 500 CVEs from the CVEfixes v1.0.8 dataset over
approximately 24 hours across two sessions (see [Section 13](#13-production-run-operations-notes)
for operational details).

| Metric | Value |
|--------|-------|
| CVEs in queue | 500 |
| CVEs successfully processed | 215 (43%) |
| Total samples | 420 |
| Total node records | 601,662 |
| Total edge records | 4,546,098 |
| Total sinks identified | 7,571 |
| Positive label rate | 23.27% (140,027 / 601,661) |
| Project diversity | 100+ unique C projects |
| Processing time | ~24 hours across two sessions |

#### Skip breakdown

285 of 500 CVEs were skipped:

| Stage | Count | % of skips | Primary reason |
|-------|-------|------------|----------------|
| `step1` — no function-scope changes | 236 | 70% | CVEfixes patches touched non-C files only |
| `step1/cpg_build` — Joern parse failures | 68 | 20% | Joern failed to parse the commit's source |
| `clone/fetch` — network drops | 34 | 10% | Network failures during the run |

The dominant skip cause — "no function-scope changes" — reflects a data quality
issue in CVEfixes: many CVEs whose metadata lists C as the language have patches
that modify only Makefiles, documentation, or header-only changes with no function
bodies. This is a property of the upstream dataset, not the pipeline.

#### Top sink types

| API | Count |
|-----|-------|
| `memcpy` | 1,528 |
| `fprintf` | 1,270 |
| `free` | 1,121 |
| `printf` | 856 |
| `memset` | 829 |

#### Statement type distribution

| Type | % |
|------|---|
| ASSIGN | 21.6% |
| CALL | 19.3% |
| DECL | 15.4% |
| IF | 14.1% |
| OTHER | 4.4% |

The positive rate of 23.27% is lower than the 5-CVE validation run (34.2%).
The validation CVEs were selected because they were known to work cleanly with
the pipeline. The production set includes more diverse patch shapes, some with
sparse or diffuse vulnerability patterns that produce smaller slices.

---

## 12. The CVEfixes Ingestor

**Module**: `ingest_cvefixes.py`

### Purpose

`ingest_cvefixes.py` converts a CVEfixes SQLite dump into the work-queue JSONL
format consumed by `build_dataset.py`. Each output line is one CVE entry ready
for pipeline processing.

### The CVEfixes dataset

CVEfixes v1.0.8 (Bhandari et al., 2021) contains fix commits for CVEs across a
wide range of open-source projects:

| Metric | Value |
|--------|-------|
| Fix commits | 12,107 |
| CVEs covered | 11,873 |
| Projects | 4,249 |
| Download size | 12.7 GB |
| Zenodo DOI | 10.5281/zenodo.13118970 |

### Filter chain

The ingestor applies five filters in sequence:

| Filter | Effect |
|--------|--------|
| `language = 'C'` | Drops non-C CVEs (Python, Java, JavaScript, etc.) |
| Has fix commit | Drops entries with no resolvable commit URL |
| Non-banned project | Drops projects on the ban list |
| Has CWE classification | Drops entries with no CWE (needed for Step 3 sink table) |
| Has parent commit | Drops entries where `commit_fix~1` cannot be resolved |

Starting from 12,931 `(CVE, fix)` rows, the chain produces **2,144 unique
C-language CVEs**. The 18% pass rate is dominated by language filtering: 71% of
CVEfixes is non-C code.

Where multiple fix commits exist for the same CVE, the ingestor keeps the
chronologically earliest one.

### Schema-aware design

CVEfixes has undergone schema changes across versions. The ingestor probes for
the presence of the `language` column at startup and skips the language filter
if the column is absent, for compatibility with older dumps.

The `parents` field in CVEfixes is stored as a Python-list-literal string
(e.g. `"['abc123def']"`), not a space-separated SHA or a JSON array. The
ingestor parses this with `ast.literal_eval` rather than string splitting.

### Ban list

Large codebases are unsuitable for the pipeline's 1-hop scoping strategy: their
CPGs exceed available memory. The default ban list includes the Linux kernel.
During the 500-CVE production run, `php-src` and `ImageMagick` were added after
OOM crashes on their CPGs (3M+ nodes). Machines with 16 GB RAM should include
these in their ban list by default.

### CLI reference

```
python3 ingest_cvefixes.py \
    --db    CVEfixes.db    \   # path to downloaded SQLite dump
    --out   queue.jsonl    \   # output work queue
    --limit 500            \   # cap output at N entries
    --ban   linux,php-src  \   # comma-separated projects to exclude
    --no-c-filter              # skip language=C filter (for testing)
```

---

## 13. Production Run Operations Notes

This section records observations from the 500-CVE production run that are
relevant to anyone running the pipeline at scale.

### OOM crash on php-src

After processing 110 CVEs successfully, the first session was killed by the OS
OOM killer while building the Joern CPG for a `php-src` commit. The `php-src`
CPG at that commit had approximately 3.1M nodes and 27M edges — beyond the
memory capacity of the 16 GB machine used. The run was restarted after adding
`php-src` and `ImageMagick` to the ban list. The resume mechanism picked up
from CVE 111 with no data loss.

### Disk pressure

The CPG cache at `~/.cache/vuln_dataset/cpgs/` grew to over 200 GB during
the run as Joern CPG binaries accumulated for each processed commit. The cache
is safe to wipe between sessions: Joern rebuilds CPGs from the source repo as
needed, and the source repos remain in `~/.cache/vuln_dataset/repos/`. After
wiping the CPG cache and restarting the second session, the pipeline resumed
cleanly.

### Resume correctness

The resume mechanism (scanning `functions.jsonl` for already-processed
`patch_id` entries) worked correctly across both sessions and after the CPG
cache wipe. No duplicate entries were produced.

### Practical recommendations for 16 GB RAM machines

- Ban `php-src`, `ImageMagick`, and other large C codebases whose CPGs exceed
  available memory.
- Monitor disk usage during the run; the CPG cache can grow to hundreds of GB
  for a 500-CVE queue. Wipe between sessions if needed.
- Run sequentially (the default). Parallel processing would multiply peak
  memory usage.
- `Ctrl-C` triggers a graceful shutdown; the partial output is safe to resume
  from.

### Skip rate interpretation

The 42% overall skip rate (285 / 500 CVEs) is dominated by CVEfixes data
quality, not pipeline failures. 236 of 285 skips (70%) are "no function-scope
changes" — CVEs whose patches touched Makefiles, documentation, or
non-function C code. These entries pass the ingestor's language filter but
produce no candidate functions in Step 1. This is a known limitation of using
CVEfixes as an upstream data source and is not correctable without manual
curation.

---

## 14. Known Bugs Fixed During Development

The following engineering challenges were encountered and resolved during the
development of this pipeline. They are documented here as guidance for
anyone extending the pipeline or porting it to a new Joern version.

| # | Bug | Symptom | Fix |
|---|-----|---------|-----|
| 1 | GraphSON v3 nested property format | Properties returned `{"@type": ..., "@value": ...}` instead of bare values | Added recursive `_unwrap()` and `_extract_property_value()` helpers |
| 2 | Joern `<global>` synthetic methods | `<global>` spans whole file; wins every line-containment check | Filter out by name and full_name pattern before any mapping |
| 3 | Bug-introduction vs. fix commit confusion | Diffing OSV "introduced" → fix spanned years of history (13MB diff) | Always use `commit_fix~1` (parent of fix) as `commit_vuln` |
| 4 | UTF-8 decoding on git diff output | `UnicodeDecodeError` on commits touching binary or non-UTF-8 files | Added `errors="replace"` to subprocess text decoding |
| 5 | Hunk context spilling into adjacent functions | Pure-addition diffs attributed closing `}` of prior function to patch fn | Limit context to lines within 2 of any `+` line (windowed collection) |
| 6 | Dict-items unpacking swap | BFS started from full_name string instead of node_id | Fixed variable order in `for full_name, nid in .items()` |
| 7 | GraphSON serializer crash on real CPGs | `flatgraph.formats.graphson.GraphSONExporter` exception on large C codebases | Switched to neo4jcsv export |
| 8 | GraphML JVM entity size limit | Joern writes GraphML successfully, then re-parses for pretty-printing; crashes on large nodes | Avoided GraphML entirely; remained on neo4jcsv |
| 9 | Stale git worktree registry | After CPG cache wipe, `git worktree add` refused with "already registered" | Added `git worktree prune` before every `git worktree add` |
| 10 | PARAM_BIND deduplication collapsing arguments | All arguments of a call collapsed to one edge | Included arg index in dedup key: `PARAM_BIND_{idx}` |

---

## 15. Dataset Information

This section documents the 5-CVE validation dataset in `test_dataset/`, generated
during the initial pipeline validation phase. The production 500-CVE dataset is
described in [Section 11](#11-empirical-results) and is available for download
via the link in [Section 9](#9-output-dataset-schema).

The validation dataset lives in the `test_dataset/` folder in this repository. It is not a
single file — it is six files that together form the complete dataset.

```
test_dataset/
├── nodes.jsonl          22 MB   — the main payload (11,000 node records)
├── edges.jsonl          28 MB   — 166,177 graph edges between nodes
├── functions.jsonl      59 KB   — 274 function-level provenance records
├── sinks.jsonl          10 KB   — 46 identified dangerous-API sink nodes
├── skipped.jsonl         0 B    — failures logged here (empty = none)
└── manifest.json       376 B    — run configuration and totals
```

`nodes.jsonl` is the primary file for model training — one JSON record per line,
one line per C statement node. `edges.jsonl` is used to reconstruct the graph
adjacency for GNN training. The remaining files are supporting metadata and
provenance records.

---

### Dataset Summary Card

| Property | Value |
|----------|-------|
| **Format** | JSONL (one JSON record per line) |
| **Primary file** | `nodes.jsonl` |
| **Total node records** | 11,000 |
| **Total edge records** | 166,177 |
| **CVEs covered** | 5 |
| **Projects covered** | 4 (curl, zlib, tcpdump, libpcap) |
| **Samples** | 10 (each CVE produces 2: vulnerable version + fixed version) |
| **Positive rate** | 34.2% (3,764 of 11,000 nodes labeled 1) |
| **CWEs represented** | CWE-119, CWE-122, CWE-125, CWE-787 |
| **Languages** | C |
| **Graph type** | Directed multigraph (CFG + DFG + CALL + PARAM_BIND edges) |
| **Labeling method** | Bidirectional program slice: backward(sinks) ∩ forward(patch) |
| **Scoping** | Patch functions + 1-hop callers and callees |
| **Processing time** | 235 seconds total (sequential, single machine) |
| **Storage** | ~51 MB (nodes + edges combined) |

---

### Node Type Distribution

| Statement Type | Count | % of Total |
|----------------|-------|------------|
| ASSIGN | 2,694 | 24.5% |
| CALL | 2,308 | 21.0% |
| IF | 1,620 | 14.7% |
| DECL | 1,269 | 11.5% |
| GOTO | 404 | 3.7% |
| RETURN | 395 | 3.6% |
| ELSE | 374 | 3.4% |
| BREAK | 344 | 3.1% |
| METHOD_ENTRY | 274 | 2.5% |
| OTHER | 506 | 4.6% |

The `OTHER` category at 4.6% indicates the statement classifier is discriminating
well — the large majority of nodes are classified into a meaningful semantic type
rather than falling through to a catch-all bucket.

---

### Per-CVE Breakdown

| CVE | Project | CWE | Nodes | Positives | Sinks | Positive Rate | Notable characteristic |
|-----|---------|-----|-------|-----------|-------|---------------|------------------------|
| CVE-2023-38545 | curl | CWE-122 | 1,299 | 772 | 10 | 59% | Heap buffer overflow in SOCKS5 handler |
| CVE-2022-37434 | zlib | CWE-125/787 | 4,638 | 1,776 | 10 | 38% | Out-of-bounds read/write in inflate |
| CVE-2017-16808 | tcpdump | CWE-125 | 3,133 | 787 | 22 | 25% | 82% of slice lives in callee functions |
| CVE-2018-14468 | tcpdump | CWE-125 | 666 | 168 | 0* | 25% | No CWE-matched sinks; patch-fallback used |
| CVE-2019-15161 | libpcap | CWE-125 | 1,264 | 261 | 4 | 21% | Mixed patch-function and callee slice |

\* Sink identification found no CWE-125 matched APIs in the candidate neighborhood.
The slicer fell back to using patch nodes as implicit sinks, producing a
conservative but valid slice.

---

### Sink Distribution

Sinks are call sites of dangerous APIs identified via CWE-keyed matching.

| API | Count | CWE families matched |
|-----|-------|---------------------|
| `memcpy` | 40 | CWE-119, CWE-122, CWE-125, CWE-787 |
| `memcmp` | 4 | CWE-125 |
| `strcpy` | 2 | CWE-119, CWE-122, CWE-787 |
| **Total** | **46** | |

---

### Key Dataset Properties

**Paired samples.**
Every CVE contributes exactly two samples — one for the vulnerable version of the
code and one for the fixed version. Both samples share a `patch_id` and differ only
in the `version` field (`vulnerable` or `fixed`). This pairing enables contrastive
learning approaches, fix localization experiments, and before/after comparison of
graph structure around the patch.

**Inter-procedural coverage.**
Across all samples, 1,614 of 11,000 nodes (14.7%) are flagged as cross-function
nodes — nodes that have at least one edge crossing a function boundary. The most
striking example is `tcpdump/CVE-2017-16808`, where 318 of 387 slice nodes (82%)
reside in callee functions rather than the patched function itself. This confirms
the dataset captures multi-function vulnerability propagation that function-level
datasets cannot represent.

**Heterogeneous graph structure.**
Each sample is a directed multigraph with up to five distinct edge types: `CFG`
(control flow), `REACHING_DEF` (data flow), `CALL` (function call), `PARAM_BIND`
(argument-to-parameter binding), and `CDG` (control dependence). This is directly
suitable for heterogeneous GNN architectures that learn different message-passing
functions per edge type, such as RGCN or HGT.

**Zero processing failures.**
All five CVEs were processed without a single skipped or failed entry. The
pipeline's seven-layer failure isolation — each catch surface logging to
`skipped.jsonl` with stage, reason, and traceback — was not triggered on this
run. The empty `skipped.jsonl` file (0 bytes) confirms this.

**Reproducibility.**
The dataset is fully reproducible from the work queue file `test_queue.jsonl`
and the pipeline code in this repository. Re-running `build_dataset.py` with
the same queue on a machine with Joern 4.0.520 installed will produce an
identical dataset (modulo Joern's internal CPG node ID assignment, which may
vary across machines but does not affect the canonical node IDs in the output).

---

## 16. Future Work

### A. CVEfixes Ingestor

**Status**: Complete. See [Section 12](#12-the-cvefixes-ingestor).

The ingestor was implemented as `ingest_cvefixes.py`. It processed CVEfixes
v1.0.8 (12,107 fix commits, 11,873 CVEs) and produced a 500-entry work queue
of C-language CVEs. The actual pass rate was 18% (2,144 qualifying C CVEs from
12,931 rows), dominated by language filtering (71% of CVEfixes is non-C).

### B. Full-Scale Dataset Run

**Status**: Complete. See [Section 11](#11-empirical-results) and
[Section 13](#13-production-run-operations-notes).

A 500-CVE queue was processed over approximately 24 hours across two sessions.
215 CVEs (43%) were processed successfully, producing 601,662 node records
across 100+ unique C projects. The 42% skip rate was dominated by CVEfixes data
quality. Operational notes (OOM crash, disk pressure, resume) are in Section 13.

### C. Parallel Processing

**Status**: Designed, not implemented.

The current pipeline is sequential. On a machine with multiple cores, parallel
processing of independent CVEs would give a near-linear speedup up to the
number of available cores (bounded by Joern's own parallelism and memory).

Implementation plan: replace the `for pc in entries` loop in `build_dataset.py`
with a `multiprocessing.Pool`. Two preconditions must be met first:

1. The CPG cache needs file-locking so two workers don't try to build the same
   CPG simultaneously.
2. The `DatasetWriter` needs a lock or per-worker output files that are merged
   at the end.

Estimated speedup: 3-4× on a 4-core machine, 6-8× on an 8-core machine.

### D. Graded Labels (v2)

**Status**: Designed during early development; deferred.

The current labeling is binary: `in_slice=1` or `0`. A graded scheme would
differentiate between degrees of vulnerability relevance:

| Tier | Label | Meaning |
|------|-------|---------|
| `PATCH_CORE` | 3 | Node is directly on a modified line |
| `TAINT_RELEVANT` | 2 | Node is in the backward slice from a sink |
| `SEMANTIC_SEED` | 1 | Node is in the forward slice from patch nodes |
| `NEGATIVE` | 0 | Node is outside all slices |

This gives the model more nuanced signal and enables ordinal regression or
multi-class classification as an alternative to binary prediction.

### E. PyG/PyTorch Dataset Loader

**Status**: Not yet started. Depends on B.

A `torch_geometric.data.Dataset` subclass that reads `nodes.jsonl` and
`edges.jsonl`, builds node feature tensors, constructs adjacency from canonical
IDs, and emits a `torch_geometric.data.Data` object per sample. This is the
natural interface for GNN training with frameworks like PyTorch Geometric or DGL.

### F. Positive-Rate Tuning

**Observation**: Aggregate positive rate is ~34%, but per-CVE rates vary from
21% to 59%. The primary driver is `max_hops_slice` (default 10). On small
functions, 10 hops can reach nearly every node.

**Recommendation**: After collecting 50+ CVEs, plot the positive-rate distribution
and choose a `max_hops_slice` value that pushes the aggregate rate below 20%.
This reduces class imbalance without sacrificing meaningful slice coverage. Pilot
experiments can be run by re-running the validator on the same cached CPGs with
different hop counts (the CPG cache makes re-slicing cheap).

### G. Dataset Publication and Sharing

**Status**: Partially complete.

The 500-CVE dataset was uploaded to Google Drive (link in [Section 9](#9-output-dataset-schema)).
For long-term archival and citability, future work could publish to Zenodo for
a permanent DOI, following the CVEfixes precedent (DOI 10.5281/zenodo.13118970).
A Zenodo record would allow the dataset to be cited in academic papers and would
guarantee availability independent of the author's Google Drive account.

---

*End of documentation.*
