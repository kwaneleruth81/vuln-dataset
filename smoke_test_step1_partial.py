"""Partial smoke test: verify the pieces that don't need Joern.

This runs the synthetic repo construction and then feeds the real git diff
through parse_modified_lines, asserting that Step 1 would correctly identify
parse_header's modified lines on both versions.

Running this here proves the harness's repo setup and diff parsing are solid
before you take it to a Joern-equipped machine.
"""
from __future__ import annotations
import logging, os, shutil, subprocess, sys, tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from smoke_test_step1 import build_synthetic_repo, VULN_SRC, FIXED_SRC
from pipeline.find_candidates import parse_modified_lines, _git_diff

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("partial")

def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="vuln_partial_"))
    try:
        repo = tmp / "repo"
        commit_vuln, commit_fix = build_synthetic_repo(repo)

        diff_text = _git_diff(repo, commit_vuln, commit_fix)
        log.info("raw diff:\n%s", diff_text)

        modified = parse_modified_lines(diff_text)
        log.info("parsed: %s", modified)

        assert "src/parser.c" in modified, f"expected src/parser.c, got {list(modified)}"
        v = modified["src/parser.c"]["vulnerable"]
        f = modified["src/parser.c"]["fixed"]

        # parse_header spans roughly lines 9..14 in VULN_SRC and gets extra
        # lines added in the fix. Assert the modified lines fall inside the
        # parse_header range for each version.
        vuln_lines = VULN_SRC.splitlines()
        fix_lines = FIXED_SRC.splitlines()

        def contains(lines, needle):
            return [i+1 for i, l in enumerate(lines) if needle in l]

        parse_header_vuln_start = contains(vuln_lines, "int parse_header")[0]
        parse_header_fix_start  = contains(fix_lines,  "int parse_header")[0]

        assert any(l >= parse_header_vuln_start for l in v), \
            f"vulnerable modified lines {v} should land in parse_header (starts line {parse_header_vuln_start})"
        assert any(l >= parse_header_fix_start for l in f), \
            f"fixed modified lines {f} should land in parse_header (starts line {parse_header_fix_start})"

        log.info("PARTIAL SMOKE PASSED")
        log.info("  vuln-side modified lines: %s (parse_header starts line %d)",
                 v, parse_header_vuln_start)
        log.info("  fix-side  modified lines: %s (parse_header starts line %d)",
                 f, parse_header_fix_start)
        return 0
    except Exception as e:
        log.error("FAILED: %s", e, exc_info=True)
        return 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

if __name__ == "__main__":
    sys.exit(main())
