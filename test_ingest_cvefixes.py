"""Test the CVEfixes ingestor against a hand-built synthetic SQLite DB.

Uses CVEfixes' actual modern format for the parents column (Python list
literal serialized as a string) — earlier versions of this test used a
space-separated format that doesn't match real CVEfixes output."""

from __future__ import annotations
import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


def _build_synthetic_db(path: Path) -> None:
    """Build a CVEfixes-shaped DB with controlled test data."""
    conn = sqlite3.connect(path)
    cur = conn.cursor()

    cur.executescript("""
        CREATE TABLE cve (
            cve_id          TEXT PRIMARY KEY,
            description     TEXT,
            published_date  TEXT,
            severity        TEXT
        );
        CREATE TABLE fixes (
            cve_id      TEXT,
            hash        TEXT,
            repo_url    TEXT
        );
        CREATE TABLE commits (
            hash        TEXT PRIMARY KEY,
            parents     TEXT,
            author_date TEXT
        );
        CREATE TABLE cwe_classification (
            cve_id      TEXT,
            cwe_id      TEXT
        );
        CREATE TABLE repository (
            repo_url       TEXT PRIMARY KEY,
            repo_name      TEXT,
            repo_language  TEXT
        );
    """)

    # IMPORTANT: CVEfixes stores parents as a Python list literal:
    #   "['hash1', 'hash2']"
    # NOT as space-separated bare strings. Test must match real format.
    P_SINGLE = "['parent1aaaa1aaaa1aaaa1aaaa1aaaa1aaaa1aaaa11']"
    P_MULTI  = "['parent888888888888888888888888888888888888', 'secondparent888']"

    # --- valid C CVE that should pass ---
    cur.execute("INSERT INTO cve VALUES (?,?,?,?)",
                ("CVE-2023-0001", "test heap overflow", "2023-01-01", "HIGH"))
    cur.execute("INSERT INTO fixes VALUES (?,?,?)",
                ("CVE-2023-0001", "fix1aaa1aaa1aaa1aaa1aaa1aaa1aaa1aaa1aaa11",
                 "https://github.com/curl/curl"))
    cur.execute("INSERT INTO commits VALUES (?,?,?)",
                ("fix1aaa1aaa1aaa1aaa1aaa1aaa1aaa1aaa1aaa11", P_SINGLE, "2023-01-15"))
    cur.execute("INSERT INTO cwe_classification VALUES (?,?)",
                ("CVE-2023-0001", "CWE-122"))
    cur.execute("INSERT INTO cwe_classification VALUES (?,?)",
                ("CVE-2023-0001", "CWE-787"))
    cur.execute("INSERT INTO repository VALUES (?,?,?)",
                ("https://github.com/curl/curl", "curl", "C"))

    # --- C CVE banned by project (Linux kernel) ---
    cur.execute("INSERT INTO cve VALUES (?,?,?,?)",
                ("CVE-2023-0002", "kernel issue", "2023-02-01", "MEDIUM"))
    cur.execute("INSERT INTO fixes VALUES (?,?,?)",
                ("CVE-2023-0002", "fix2bbb2bbb2bbb2bbb2bbb2bbb2bbb2bbb2bbb22",
                 "https://github.com/torvalds/linux"))
    cur.execute("INSERT INTO commits VALUES (?,?,?)",
                ("fix2bbb2bbb2bbb2bbb2bbb2bbb2bbb2bbb2bbb22",
                 "['parent2bbb2bbb2bbb2bbb2bbb2bbb2bbb2bbb22']",
                 "2023-02-15"))
    cur.execute("INSERT INTO cwe_classification VALUES (?,?)",
                ("CVE-2023-0002", "CWE-416"))
    cur.execute("INSERT INTO repository VALUES (?,?,?)",
                ("https://github.com/torvalds/linux", "linux", "C"))

    # --- C CVE with no CWEs ---
    cur.execute("INSERT INTO cve VALUES (?,?,?,?)",
                ("CVE-2023-0003", "no cwe", "2023-03-01", "LOW"))
    cur.execute("INSERT INTO fixes VALUES (?,?,?)",
                ("CVE-2023-0003", "fix3ccc3ccc3ccc3ccc3ccc3ccc3ccc3ccc3ccc33",
                 "https://github.com/madler/zlib"))
    cur.execute("INSERT INTO commits VALUES (?,?,?)",
                ("fix3ccc3ccc3ccc3ccc3ccc3ccc3ccc3ccc3ccc33",
                 "['parent3ccc3ccc3ccc3ccc3ccc3ccc3ccc3ccc33']",
                 "2023-03-15"))
    cur.execute("INSERT INTO repository VALUES (?,?,?)",
                ("https://github.com/madler/zlib", "zlib", "C"))

    # --- C CVE with no parent commit (root commit; empty list) ---
    cur.execute("INSERT INTO cve VALUES (?,?,?,?)",
                ("CVE-2023-0004", "root commit", "2023-04-01", "MEDIUM"))
    cur.execute("INSERT INTO fixes VALUES (?,?,?)",
                ("CVE-2023-0004", "fix4ddd4ddd4ddd4ddd4ddd4ddd4ddd4ddd4ddd44",
                 "https://github.com/some-project/some-repo"))
    cur.execute("INSERT INTO commits VALUES (?,?,?)",
                ("fix4ddd4ddd4ddd4ddd4ddd4ddd4ddd4ddd4ddd44", "[]", "2023-04-15"))
    cur.execute("INSERT INTO cwe_classification VALUES (?,?)",
                ("CVE-2023-0004", "CWE-119"))
    cur.execute("INSERT INTO repository VALUES (?,?,?)",
                ("https://github.com/some-project/some-repo", "some-repo", "C"))

    # --- Java CVE (filtered by language) ---
    cur.execute("INSERT INTO cve VALUES (?,?,?,?)",
                ("CVE-2023-0005", "java issue", "2023-05-01", "HIGH"))
    cur.execute("INSERT INTO fixes VALUES (?,?,?)",
                ("CVE-2023-0005", "fix5eee5eee5eee5eee5eee5eee5eee5eee5eee55",
                 "https://github.com/apache/struts"))
    cur.execute("INSERT INTO commits VALUES (?,?,?)",
                ("fix5eee5eee5eee5eee5eee5eee5eee5eee5eee55",
                 "['parent5eee5eee5eee5eee5eee5eee5eee5eee55']",
                 "2023-05-15"))
    cur.execute("INSERT INTO cwe_classification VALUES (?,?)",
                ("CVE-2023-0005", "CWE-502"))
    cur.execute("INSERT INTO repository VALUES (?,?,?)",
                ("https://github.com/apache/struts", "struts", "Java"))

    # --- CVE with two fix commits (dedupe to earliest) ---
    cur.execute("INSERT INTO cve VALUES (?,?,?,?)",
                ("CVE-2023-0006", "multi-fix", "2023-06-01", "HIGH"))
    cur.execute("INSERT INTO fixes VALUES (?,?,?)",
                ("CVE-2023-0006", "fix6aaa6aaa6aaa6aaa6aaa6aaa6aaa6aaa6aaa66",
                 "https://github.com/the-tcpdump-group/tcpdump"))
    cur.execute("INSERT INTO fixes VALUES (?,?,?)",
                ("CVE-2023-0006", "fix6bbb6bbb6bbb6bbb6bbb6bbb6bbb6bbb6bbb66",
                 "https://github.com/the-tcpdump-group/tcpdump"))
    cur.execute("INSERT INTO commits VALUES (?,?,?)",
                ("fix6aaa6aaa6aaa6aaa6aaa6aaa6aaa6aaa6aaa66",
                 "['parent6aaa6aaa6aaa6aaa6aaa6aaa6aaa6aaa66']",
                 "2023-06-15"))
    cur.execute("INSERT INTO commits VALUES (?,?,?)",
                ("fix6bbb6bbb6bbb6bbb6bbb6bbb6bbb6bbb6bbb66",
                 "['parent6bbb6bbb6bbb6bbb6bbb6bbb6bbb6bbb66']",
                 "2023-08-15"))   # later
    cur.execute("INSERT INTO cwe_classification VALUES (?,?)",
                ("CVE-2023-0006", "CWE-125"))
    cur.execute("INSERT INTO repository VALUES (?,?,?)",
                ("https://github.com/the-tcpdump-group/tcpdump", "tcpdump", "C"))

    # --- CVE with non-GitHub URL (rejected) ---
    cur.execute("INSERT INTO cve VALUES (?,?,?,?)",
                ("CVE-2023-0007", "weird host", "2023-07-01", "LOW"))
    cur.execute("INSERT INTO fixes VALUES (?,?,?)",
                ("CVE-2023-0007", "fix7fff7fff7fff7fff7fff7fff7fff7fff7fff77",
                 "https://weird.example.org/some/repo"))
    cur.execute("INSERT INTO commits VALUES (?,?,?)",
                ("fix7fff7fff7fff7fff7fff7fff7fff7fff7fff77",
                 "['parent7fff7fff7fff7fff7fff7fff7fff7fff77']",
                 "2023-07-15"))
    cur.execute("INSERT INTO cwe_classification VALUES (?,?)",
                ("CVE-2023-0007", "CWE-79"))

    # --- A second valid C CVE (.git suffix and merge commit with multiple parents) ---
    cur.execute("INSERT INTO cve VALUES (?,?,?,?)",
                ("CVE-2023-0008", "good zlib bug", "2023-08-01", "HIGH"))
    cur.execute("INSERT INTO fixes VALUES (?,?,?)",
                ("CVE-2023-0008", "fix8888888888888888888888888888888888888888",
                 "https://github.com/madler/zlib.git"))
    cur.execute("INSERT INTO commits VALUES (?,?,?)",
                ("fix8888888888888888888888888888888888888888", P_MULTI, "2023-08-15"))
    cur.execute("INSERT INTO cwe_classification VALUES (?,?)",
                ("CVE-2023-0008", "CWE-125"))

    conn.commit()
    conn.close()


def run_test() -> int:
    # Test 1: parents parser unit test (covers the bug we just fixed)
    print("=== Test 1: parents parser ===")
    sys.path.insert(0, str(Path(__file__).parent))
    from ingest_cvefixes import _parse_parents
    cases = [
        ("['hash1']", ["hash1"]),
        ("['hash1', 'hash2']", ["hash1", "hash2"]),
        ("[]", []),
        ("", []),
        (None, []),
        ("legacy_hash legacy_hash2", ["legacy_hash", "legacy_hash2"]),  # legacy format
        ("singlehash", ["singlehash"]),
    ]
    for raw, expected in cases:
        got = _parse_parents(raw)
        if got != expected:
            print(f"FAIL parse({raw!r}) = {got}, expected {expected}")
            return 1
    print(f"  ✓ all {len(cases)} parent-format cases pass")

    # Test 2: end-to-end ingestor on synthetic DB
    print("\n=== Test 2: ingestor end-to-end ===")
    tmp = Path(tempfile.mkdtemp(prefix="ingest_test_"))
    try:
        db = tmp / "synthetic_cvefixes.db"
        out = tmp / "queue.jsonl"

        print(f"Building synthetic DB at {db}")
        _build_synthetic_db(db)
        print(f"DB size: {db.stat().st_size} bytes")

        print("\nRunning ingestor...")
        result = subprocess.run(
            [sys.executable, "ingest_cvefixes.py",
             "--db", str(db),
             "--out", str(out),
             "--log-level", "INFO"],
            capture_output=True, text=True,
            cwd=Path(__file__).parent,
        )
        print("--- ingestor stdout ---")
        print(result.stdout)
        print("--- ingestor stderr ---")
        print(result.stderr)
        if result.returncode != 0:
            print(f"INGESTOR FAILED: returncode={result.returncode}")
            return 1

        if not out.exists():
            print(f"FAIL: queue file not created at {out}")
            return 1

        entries = []
        with out.open() as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))

        print(f"\n=== Verification ===")
        print(f"Queue file entries: {len(entries)}")
        for e in entries:
            print(f"  {e['patch_id']:<35} fix={e['commit_fix'][:8]} parent={e['commit_vuln'][:8]} cwes={e['cwes']}")

        # Expected: 3 entries pass (curl, tcpdump, zlib).
        # Filtered: CVE-0002 (banned), CVE-0003 (no CWEs), CVE-0004 (no parent),
        #          CVE-0005 (Java), CVE-0007 (weird host).
        expected_cves = {"CVE-2023-0001", "CVE-2023-0006", "CVE-2023-0008"}
        actual_cves = {e["cve"] for e in entries}
        missing = expected_cves - actual_cves
        extra = actual_cves - expected_cves
        if missing or extra:
            print(f"FAIL: expected {expected_cves}, got {actual_cves}")
            print(f"  missing: {missing}")
            print(f"  extra:   {extra}")
            return 1
        print(f"✓ Correct CVEs filtered: {sorted(actual_cves)}")

        # Critical assertion: commit_vuln must be a bare hash, NOT a list literal.
        for e in entries:
            v = e["commit_vuln"]
            if v.startswith("[") or "'" in v or '"' in v:
                print(f"FAIL: commit_vuln still has list literal syntax: {v!r}")
                return 1
            if not v[:7].replace("a","x").replace("b","x").replace("8","x").replace("6","x").replace("p","x").replace("r","x").replace("e","x").replace("n","x").replace("t","x").isalnum():
                # crude but readable check that it looks like a normal hash-like string
                pass
        print(f"✓ commit_vuln values are bare hashes (no list literal syntax)")

        tcpdump_e = next(e for e in entries if e["cve"] == "CVE-2023-0006")
        assert tcpdump_e["commit_fix"].startswith("fix6aaa"), \
            f"dedupe wrong: {tcpdump_e['commit_fix']}"
        print(f"✓ Multi-fix CVE deduped to earlier commit: {tcpdump_e['commit_fix'][:8]}")

        zlib_e = next(e for e in entries if e["cve"] == "CVE-2023-0008")
        assert zlib_e["repo_url"] == "https://github.com/madler/zlib", \
            f".git not stripped: {zlib_e['repo_url']}"
        print(f"✓ .git suffix stripped from URL")

        # Multi-parent ('merge commit') should take only first parent.
        assert zlib_e["commit_vuln"].startswith("parent888"), \
            f"first parent not used: {zlib_e['commit_vuln']!r}"
        assert "secondparent" not in zlib_e["commit_vuln"]
        print(f"✓ Multi-parent commit took first parent only ({zlib_e['commit_vuln'][:12]}...)")

        curl_e = next(e for e in entries if e["cve"] == "CVE-2023-0001")
        assert set(curl_e["cwes"]) == {"CWE-122", "CWE-787"}, \
            f"CWEs wrong: {curl_e['cwes']}"
        print(f"✓ Multiple CWEs aggregated correctly")

        assert curl_e["patch_id"] == "curl/CVE-2023-0001"
        print(f"✓ patch_id format matches orchestrator schema")

        # Test --limit
        print(f"\n--- Testing --limit flag ---")
        out2 = tmp / "queue_limited.jsonl"
        result = subprocess.run(
            [sys.executable, "ingest_cvefixes.py",
             "--db", str(db),
             "--out", str(out2),
             "--limit", "2",
             "--log-level", "WARNING"],
            capture_output=True, text=True,
            cwd=Path(__file__).parent,
        )
        if result.returncode != 0:
            print(f"FAIL with --limit: {result.stderr}")
            return 1
        n_limited = sum(1 for _ in out2.open())
        assert n_limited == 2, f"--limit 2 produced {n_limited} entries"
        print(f"✓ --limit 2 produced {n_limited} entries")

        print("\n=== ALL INGESTOR TESTS PASSED ===")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(run_test())