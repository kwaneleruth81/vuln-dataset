#!/usr/bin/env bash
# extract_cpg.sh — Run Joern on one source file/project and export CPG as JSON.
#
# Usage:
#   ./extract_cpg.sh <source_dir> <output_dir>
#
# Requires Joern (https://joern.io) in PATH: joern-parse, joern-export.

set -euo pipefail

SRC_DIR="$1"
OUT_DIR="$2"
mkdir -p "$OUT_DIR"

CPG_BIN="$OUT_DIR/cpg.bin"

# 1. Parse source into a CPG binary.
#    --language c handles C/C++; use 'javasrc', 'jssrc', 'pythonsrc' as needed.
joern-parse "$SRC_DIR" --language c --output "$CPG_BIN"

# 2. Export the CPG as JSON graph (nodes + edges, all types).
#    'all' includes AST, CFG, CDG, DDG (data dep), CALL edges.
joern-export "$CPG_BIN" --repr all --format graphson --out "$OUT_DIR/graph"

echo "CPG exported to $OUT_DIR/graph"
