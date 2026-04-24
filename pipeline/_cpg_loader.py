"""
_cpg_loader.py — Load a Joern neo4jcsv export into a NetworkX MultiDiGraph.

Private helper shared by find_candidates.py and build_program_graph.py.
Not a public entry point.

Format
------
Joern neo4jcsv writes pairs of files per node/edge type:
  nodes_<LABEL>_header.csv  — one line: column names with type suffixes
  nodes_<LABEL>_data.csv    — one row per node (standard CSV quoting)
  edges_<TYPE>_header.csv   — one line: :START_ID,:END_ID,:TYPE[,extras]
  edges_<TYPE>_data.csv     — one row per edge

Node column 0 = :ID, column 1 = :LABEL.
Edge columns 0-2 = :START_ID, :END_ID, :TYPE.

Type suffixes handled: :string, :int, :long, :boolean, :string[] (split on ';').
Bare columns (no suffix) are treated as :string.
Empty cells become None and are not stored.

Property names are normalized from SCREAMING_SNAKE to camelCase so that
existing downstream attrs.get("lineNumber"), attrs.get("name") etc. work
without changes (the graphml exporter used camelCase; neo4jcsv uses
SCREAMING_SNAKE for the same properties).
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path

import networkx as nx

log = logging.getLogger(__name__)


def _to_camel(name: str) -> str:
    """SCREAMING_SNAKE → camelCase.  LINE_NUMBER → lineNumber, FULL_NAME → fullName."""
    parts = name.lower().split("_")
    return parts[0] + "".join(p.capitalize() for p in parts[1:])


def _coerce(value: str, suffix: str):
    """Convert a CSV cell to a Python value, or None for empty/unparseable."""
    if not value:
        return None
    if suffix in ("int", "long"):
        try:
            return int(value)
        except ValueError:
            return None
    if suffix == "boolean":
        return value.lower() in ("true", "1", "yes")
    if suffix == "string[]":
        parts = [p for p in value.split(";") if p]
        return parts or None
    # :string or bare (no suffix)
    return value


def _parse_header(raw: str) -> list[tuple[str, str]]:
    """Return [(col_name, type_suffix), ...] for each column in a header line.

    Special neo4j columns (:ID, :LABEL, :START_ID, :END_ID, :TYPE) come back
    as ("", "ID"), ("", "LABEL"), etc.  Property columns like NAME:string
    come back as ("NAME", "string").  Bare columns like HASH come back as
    ("HASH", "").
    """
    result = []
    for col in raw.strip().split(","):
        col = col.strip()
        if ":" in col:
            name, suffix = col.rsplit(":", 1)
        else:
            name, suffix = col, ""
        result.append((name, suffix))
    return result


def load_cpg_graph(graph_dir: Path) -> nx.MultiDiGraph:
    """Load all neo4jcsv exports in *graph_dir* into a single NetworkX MultiDiGraph.

    Node attributes
    ---------------
    _label  : Joern node label (METHOD, CALL, BLOCK, IDENTIFIER, …)
    <prop>  : all other columns, stored in camelCase, e.g. lineNumber, fullName

    Edge key
    --------
    Edge type string: AST, CFG, CALL, REACHING_DEF, CONTAINS, ARGUMENT, …
    """
    G: nx.MultiDiGraph = nx.MultiDiGraph()

    # ------------------------------------------------------------------
    # Nodes
    # ------------------------------------------------------------------
    node_files = sorted(graph_dir.glob("nodes_*_data.csv"))
    if not node_files:
        raise RuntimeError(f"no neo4jcsv node files found in {graph_dir}")

    for data_path in node_files:
        header_path = data_path.with_name(
            data_path.name.replace("_data.csv", "_header.csv")
        )
        if not header_path.exists():
            log.warning("missing header for %s, skipping", data_path.name)
            continue

        cols = _parse_header(header_path.read_text(encoding="utf-8"))
        id_idx = next(
            (i for i, (n, s) in enumerate(cols) if n == "" and s == "ID"), None
        )
        label_idx = next(
            (i for i, (n, s) in enumerate(cols) if n == "" and s == "LABEL"), None
        )
        if id_idx is None:
            log.warning("no :ID column in %s, skipping", header_path.name)
            continue

        with data_path.open(newline="", encoding="utf-8", errors="replace") as fh:
            for row in csv.reader(fh):
                if not row or id_idx >= len(row):
                    continue
                node_id = row[id_idx]
                if not node_id:
                    continue
                label = (
                    row[label_idx]
                    if label_idx is not None and label_idx < len(row)
                    else "UNKNOWN"
                )
                attrs: dict = {"_label": label}
                for i, (col_name, suffix) in enumerate(cols):
                    if i in (id_idx, label_idx) or not col_name:
                        continue
                    cell = row[i] if i < len(row) else ""
                    v = _coerce(cell, suffix)
                    if v is not None:
                        attrs[_to_camel(col_name)] = v
                G.add_node(node_id, **attrs)

    # ------------------------------------------------------------------
    # Edges
    # ------------------------------------------------------------------
    for data_path in sorted(graph_dir.glob("edges_*_data.csv")):
        header_path = data_path.with_name(
            data_path.name.replace("_data.csv", "_header.csv")
        )
        if not header_path.exists():
            log.warning("missing header for %s, skipping", data_path.name)
            continue

        cols = _parse_header(header_path.read_text(encoding="utf-8"))
        start_idx = next(
            (i for i, (n, s) in enumerate(cols) if n == "" and s == "START_ID"), None
        )
        end_idx = next(
            (i for i, (n, s) in enumerate(cols) if n == "" and s == "END_ID"), None
        )
        type_idx = next(
            (i for i, (n, s) in enumerate(cols) if n == "" and s == "TYPE"), None
        )
        if start_idx is None or end_idx is None:
            log.warning("no :START_ID/:END_ID in %s, skipping", header_path.name)
            continue

        with data_path.open(newline="", encoding="utf-8", errors="replace") as fh:
            for row in csv.reader(fh):
                max_needed = max(
                    start_idx,
                    end_idx,
                    type_idx if type_idx is not None else 0,
                )
                if len(row) <= max_needed:
                    continue
                src = row[start_idx]
                dst = row[end_idx]
                etype = row[type_idx] if type_idx is not None else "UNKNOWN"
                if not src or not dst:
                    continue
                edge_attrs: dict = {}
                for i, (col_name, suffix) in enumerate(cols):
                    if i in (start_idx, end_idx, type_idx) or not col_name:
                        continue
                    cell = row[i] if i < len(row) else ""
                    v = _coerce(cell, suffix)
                    if v is not None:
                        edge_attrs[_to_camel(col_name)] = v
                G.add_edge(src, dst, key=etype, **edge_attrs)

    log.info(
        "CPG graph loaded: %d nodes, %d edges from %s",
        G.number_of_nodes(), G.number_of_edges(), graph_dir,
    )
    return G
