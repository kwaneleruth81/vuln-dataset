"""
ingest_cvefixes.py — Convert a CVEfixes SQLite dump into a work-queue JSONL.

Reads metadata only (cve, fixes, commits, cwe_classification, repository
tables), filters to C-language repos with a usable fix commit, derives
commit_vuln as the parent of commit_fix, and emits one queue row per CVE
in the format consumed by build_dataset.py.

Usage:
  python3 ingest_cvefixes.py \
      --db    ~/.cache/vuln_dataset/cvefixes/CVEfixes.db \
      --out   queue_full.jsonl \
      --limit 500 \
      --ban   "torvalds/linux,gcc-mirror/gcc"

Notes on robustness:
  * If a CVE has multiple fix commits, we take the chronologically earliest
    one (CVEfixes' commits.author_date). One CVE → one queue row.
  * CVEfixes stores commit parents as a Python list literal serialized as
    a string: "['hash1', 'hash2']". We parse this with ast.literal_eval,
    falling back to space-separated parsing for older CVEfixes versions
    that use a bare string format.
  * CVEfixes' language tagging lives in repository.repo_language; the
    ingestor probes for whichever column name exists.
  * Repo URLs are normalized: strip trailing .git, strip trailing slash,
    lowercase the host. Avoids duplicate clones from cosmetic differences.
"""

from __future__ import annotations

import argparse
import ast
import json
import logging
import sqlite3
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("ingest_cvefixes")


DEFAULT_BANNED = {
    "torvalds/linux",
    "linux/linux",
    "gcc-mirror/gcc",
    "llvm/llvm-project",
    "chromium/chromium",
    "openbsd/src",
    "freebsd/freebsd-src",
    "netbsd/src",
}


def _table_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    cur = conn.execute(f"PRAGMA table_info({table})")
    return [row[1].lower() for row in cur.fetchall()]


def _has_column(conn: sqlite3.Connection, table: str, col: str) -> bool:
    return col.lower() in _table_columns(conn, table)


def _parse_parents(raw: str) -> list[str]:
    """Parse CVEfixes commits.parents field into a list of commit hashes.

    CVEfixes stores parents as a Python list literal serialized as a string:
      "['hash1', 'hash2']"   - merge commit
      "['hash1']"            - normal commit
      "[]"                   - root commit (no parents)
      ""                     - missing data
      "hash1"                - older CVEfixes: bare string
      "hash1 hash2"          - older CVEfixes: space-separated

    Returns list of hash strings (possibly empty)."""
    if not raw:
        return []
    raw = raw.strip()
    if not raw:
        return []

    # Modern CVEfixes (v1.0.x): Python list literal.
    if raw.startswith("[") and raw.endswith("]"):
        try:
            parsed = ast.literal_eval(raw)
            if isinstance(parsed, list):
                return [str(p).strip() for p in parsed if p]
        except (SyntaxError, ValueError):
            pass

    # Legacy CVEfixes: bare string, possibly space-separated.
    return [p for p in raw.split() if p]


def _normalize_repo_url(raw: str) -> str | None:
    if not raw:
        return None
    u = raw.strip()
    if not u or u in ("None", "null"):
        return None
    u = u.rstrip("/")
    if u.endswith(".git"):
        u = u[:-4]
    if u.startswith("http://"):
        u = "https://" + u[len("http://"):]
    valid_hosts = ("github.com/", "gitlab.com/", "bitbucket.org/")
    lower = u.lower()
    matched = None
    for host in valid_hosts:
        if host in lower:
            matched = host
            break
    if matched is None:
        return None
    idx = lower.index(matched)
    head = u[:idx + len(matched)].lower()
    tail = u[idx + len(matched):]
    parts = tail.split("/")
    if len(parts) < 2:
        return None
    return head + parts[0] + "/" + parts[1]


def _patch_id(repo_url: str, cve_id: str) -> str:
    short = repo_url.rstrip("/").rsplit("/", 1)[-1]
    return f"{short}/{cve_id}"


def _is_banned(repo_url: str, banned: set[str]) -> bool:
    lower = repo_url.lower()
    for pat in banned:
        if pat.lower() in lower:
            return True
    return False


def _detect_language_column(conn: sqlite3.Connection) -> tuple[str, str] | None:
    candidates = [
        ("repository",   "repo_language"),
        ("repository",   "main_language"),
        ("repository",   "language"),
    ]
    for table, col in candidates:
        try:
            if _has_column(conn, table, col):
                return (table, col)
        except sqlite3.OperationalError:
            continue
    return None


def _build_query(conn: sqlite3.Connection, language_filter: bool) -> tuple[str, bool]:
    q = """
        SELECT
            f.cve_id            AS cve_id,
            f.hash              AS fix_hash,
            COALESCE(c.parents, '') AS fix_parents,
            COALESCE(c.author_date, '') AS author_date,
            f.repo_url          AS repo_url,
            (SELECT GROUP_CONCAT(cw.cwe_id, ',')
                FROM cwe_classification cw
                WHERE cw.cve_id = f.cve_id) AS cwes
    """
    lang = _detect_language_column(conn)
    if lang:
        table, col = lang
        if table == "repository":
            q += f", r.{col} AS language\n"
            q += f"FROM fixes f\n"
            q += f"JOIN commits c ON c.hash = f.hash\n"
            q += f"LEFT JOIN repository r ON r.repo_url = f.repo_url\n"
        else:
            q += f"FROM fixes f\n"
            q += f"JOIN commits c ON c.hash = f.hash\n"
    else:
        q += f"FROM fixes f\n"
        q += f"JOIN commits c ON c.hash = f.hash\n"
    q += """
        WHERE f.repo_url IS NOT NULL
          AND f.repo_url != ''
          AND f.hash IS NOT NULL
          AND f.hash != ''
    """
    return q, lang is not None


@dataclass
class QueueEntry:
    patch_id: str
    repo_url: str
    commit_vuln: str
    commit_fix: str
    cve: str
    cwes: list[str]


def _process_row(row: dict, banned: set[str], require_c: bool,
                 stats: dict) -> QueueEntry | None:
    if require_c:
        lang = (row.get("language") or "").strip().lower()
        if lang and lang not in ("c", "c language"):
            stats["lang_not_c"] += 1
            return None

    norm_url = _normalize_repo_url(row.get("repo_url", ""))
    if norm_url is None:
        stats["bad_repo_url"] += 1
        return None

    if _is_banned(norm_url, banned):
        stats["banned"] += 1
        return None

    raw_cwes = row.get("cwes") or ""
    cwes = [c.strip() for c in raw_cwes.split(",") if c.strip().startswith("CWE-")]
    if not cwes:
        stats["no_cwes"] += 1
        return None

    # CVEfixes stores parents as a Python list literal. Use the parser.
    parents = _parse_parents(row.get("fix_parents") or "")
    if not parents:
        stats["no_parent"] += 1
        return None
    commit_vuln = parents[0]
    if not commit_vuln or len(commit_vuln) < 7:
        stats["no_parent"] += 1
        return None

    fix_hash = row["fix_hash"]
    if not fix_hash or len(fix_hash) < 7:
        stats["bad_fix_hash"] += 1
        return None

    return QueueEntry(
        patch_id=_patch_id(norm_url, row["cve_id"]),
        repo_url=norm_url,
        commit_vuln=commit_vuln,
        commit_fix=fix_hash,
        cve=row["cve_id"],
        cwes=cwes,
    )


def _dedupe_per_cve(entries: list[QueueEntry], rows_with_dates: dict[tuple[str, str], str]) -> list[QueueEntry]:
    by_cve: dict[str, list[QueueEntry]] = defaultdict(list)
    for e in entries:
        by_cve[e.cve].append(e)

    kept: list[QueueEntry] = []
    for cve, group in by_cve.items():
        if len(group) == 1:
            kept.append(group[0])
            continue
        def _key(e: QueueEntry) -> tuple:
            d = rows_with_dates.get((e.cve, e.commit_fix), "")
            return (d == "", d, e.commit_fix)
        group.sort(key=_key)
        kept.append(group[0])
    return kept


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db",    required=True, type=Path)
    ap.add_argument("--out",   required=True, type=Path)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--ban",   default="")
    ap.add_argument("--no-c-filter", action="store_true")
    ap.add_argument("--log-level", default="INFO")
    args = ap.parse_args()

    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    if not args.db.exists():
        log.error("DB not found: %s", args.db)
        return 1

    banned = set(DEFAULT_BANNED)
    if args.ban:
        banned.update(p.strip() for p in args.ban.split(",") if p.strip())
    log.info("ban list: %d patterns", len(banned))

    conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    required_tables = ("cve", "fixes", "commits", "cwe_classification")
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    actual_tables = {r[0].lower() for r in cur.fetchall()}
    missing = [t for t in required_tables if t not in actual_tables]
    if missing:
        log.error("CVEfixes DB missing required tables: %s", missing)
        return 1
    log.info("schema OK: %d tables found", len(actual_tables))

    query, has_lang = _build_query(conn, language_filter=not args.no_c_filter)
    require_c = has_lang and not args.no_c_filter
    if not has_lang and not args.no_c_filter:
        log.warning("Could not detect language column. Running without C-language filter.")
    elif require_c:
        log.info("C-language filter enabled (column found)")

    log.info("running extraction query (this may take a minute)...")
    rows = conn.execute(query).fetchall()
    log.info("query returned %d (CVE, fix) rows", len(rows))

    stats = defaultdict(int)
    entries: list[QueueEntry] = []
    rows_with_dates: dict[tuple[str, str], str] = {}
    for r in rows:
        d = dict(r)
        rows_with_dates[(d["cve_id"], d["fix_hash"])] = d.get("author_date", "")
        e = _process_row(d, banned, require_c, stats)
        if e:
            entries.append(e)

    log.info("after row-level filtering: %d entries", len(entries))
    log.info("filter breakdown:")
    for k, v in sorted(stats.items(), key=lambda x: -x[1]):
        log.info("    %-15s %d", k, v)

    entries = _dedupe_per_cve(entries, rows_with_dates)
    log.info("after dedupe-per-CVE: %d entries", len(entries))

    if args.limit and len(entries) > args.limit:
        entries.sort(key=lambda e: e.cve)
        entries = entries[:args.limit]
        log.info("limit applied: %d entries", len(entries))

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w") as f:
        for e in entries:
            f.write(json.dumps({
                "patch_id":   e.patch_id,
                "repo_url":   e.repo_url,
                "commit_vuln": e.commit_vuln,
                "commit_fix":  e.commit_fix,
                "cve":        e.cve,
                "cwes":       e.cwes,
            }) + "\n")

    cwe_counts: dict[str, int] = defaultdict(int)
    project_counts: dict[str, int] = defaultdict(int)
    for e in entries:
        for c in e.cwes:
            cwe_counts[c] += 1
        proj = e.repo_url.rsplit("/", 1)[-1]
        project_counts[proj] += 1

    log.info("=" * 50)
    log.info("queue written: %s (%d entries)", args.out, len(entries))
    log.info("top 10 projects:")
    for proj, n in sorted(project_counts.items(), key=lambda x: -x[1])[:10]:
        log.info("    %-30s %d", proj, n)
    log.info("top 10 CWEs:")
    for cwe, n in sorted(cwe_counts.items(), key=lambda x: -x[1])[:10]:
        log.info("    %-15s %d", cwe, n)

    return 0


if __name__ == "__main__":
    sys.exit(main())