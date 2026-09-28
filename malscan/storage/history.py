"""Scan history, kept in SQLite.

Every scan is recorded so you can go back to it, compare, or export. What is
stored is the analysis output and the hashes, never the file itself. Keeps the
database harmless to hang on to and small enough to browse.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from malscan.config import CONFIG

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scanned_at    TEXT    NOT NULL,
    filename      TEXT    NOT NULL,
    file_size     INTEGER NOT NULL,
    file_type     TEXT,
    file_label    TEXT,
    md5           TEXT,
    sha1          TEXT,
    sha256        TEXT    NOT NULL,
    fuzzy_hash    TEXT,
    imphash       TEXT,
    verdict       TEXT    NOT NULL,
    probability   REAL    NOT NULL,
    confidence    REAL    NOT NULL,
    engine        TEXT,
    model_name    TEXT,
    scan_ms       INTEGER,
    rule_hits     INTEGER DEFAULT 0,
    max_severity  INTEGER DEFAULT 0,
    packer        TEXT,
    is_pe         INTEGER DEFAULT 0,
    entropy       REAL,
    features      TEXT,
    factors       TEXT,
    rules         TEXT,
    anomalies     TEXT,
    notes         TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_sha256     ON scans(sha256);
CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON scans(scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_verdict    ON scans(verdict);
"""


class ScanHistory:
    def __init__(self, db_path: Path | None = None):
        self.db_path = Path(db_path or CONFIG.db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # Streamlit reruns handlers on several threads, so serialise writes
        # rather than sharing one connection across them.
        self._lock = threading.Lock()
        self._init_schema()

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=15, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(SCHEMA)

    # ------------------------------------------------------------------
    def add(self, scan) -> int:
        """Persist a ScanResult. Returns the new row id."""
        r = scan
        payload = (
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            r.filename,
            r.features_result.size,
            r.features_result.file_type.category,
            r.features_result.file_type.label,
            r.features_result.hashes.get("md5", ""),
            r.features_result.hashes.get("sha1", ""),
            r.features_result.hashes.get("sha256", ""),
            r.features_result.fuzzy_hash,
            r.features_result.pe.imphash,
            r.prediction.verdict,
            float(r.prediction.probability),
            float(r.prediction.confidence),
            r.prediction.engine,
            r.prediction.model_name,
            int(r.duration_ms),
            len(r.features_result.rule_matches),
            int(r.features_result.features.get("rule_max_severity", 0)),
            r.features_result.pe.packer,
            int(r.features_result.file_type.is_pe),
            float(r.features_result.features.get("entropy_overall", 0.0)),
            json.dumps(r.features_result.features),
            json.dumps([
                {
                    "feature": c.feature,
                    "description": c.description,
                    "group": c.group,
                    "value": c.display_value,
                    "contribution": round(c.contribution, 5),
                    "direction": c.direction,
                }
                for c in r.contributions
            ]),
            json.dumps(r.features_result.rule_matches),
            json.dumps(r.features_result.pe.anomalies),
            json.dumps(r.prediction.notes),
        )

        with self._lock, self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO scans (
                    scanned_at, filename, file_size, file_type, file_label,
                    md5, sha1, sha256, fuzzy_hash, imphash,
                    verdict, probability, confidence, engine, model_name,
                    scan_ms, rule_hits, max_severity, packer, is_pe, entropy,
                    features, factors, rules, anomalies, notes
                ) VALUES (""" + ",".join("?" * 26) + ")",
                payload,
            )
            return int(cur.lastrowid)

    # ------------------------------------------------------------------
    def recent(self, limit: int = 100, verdict: str | None = None,
               search: str | None = None) -> list[dict]:
        sql = "SELECT * FROM scans"
        clauses, params = [], []
        if verdict and verdict != "All":
            clauses.append("verdict = ?")
            params.append(verdict)
        if search:
            clauses.append("(filename LIKE ? OR sha256 LIKE ? OR md5 LIKE ?)")
            like = f"%{search}%"
            params += [like, like, like]
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            return [dict(row) for row in conn.execute(sql, params)]

    def get(self, scan_id: int) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            return dict(row) if row else None

    def by_hash(self, sha256: str) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scans WHERE sha256 = ? ORDER BY id DESC", (sha256,)
            )
            return [dict(r) for r in rows]

    def delete(self, scan_id: int) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))

    def clear(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM scans")

    # ------------------------------------------------------------------
    def stats(self) -> dict:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) c FROM scans").fetchone()["c"]
            if not total:
                return {
                    "total": 0, "by_verdict": {}, "by_type": {}, "unique_files": 0,
                    "avg_scan_ms": 0, "avg_probability": 0.0, "top_rules": [],
                    "daily": [], "recent_malicious": 0,
                }

            by_verdict = {
                r["verdict"]: r["c"]
                for r in conn.execute(
                    "SELECT verdict, COUNT(*) c FROM scans GROUP BY verdict"
                )
            }
            by_type = {
                r["file_type"]: r["c"]
                for r in conn.execute(
                    "SELECT file_type, COUNT(*) c FROM scans "
                    "GROUP BY file_type ORDER BY c DESC"
                )
            }
            agg = conn.execute(
                "SELECT COUNT(DISTINCT sha256) u, AVG(scan_ms) ms, "
                "AVG(probability) p FROM scans"
            ).fetchone()
            daily = [
                {"date": r["d"], "count": r["c"], "malicious": r["m"]}
                for r in conn.execute(
                    "SELECT substr(scanned_at,1,10) d, COUNT(*) c, "
                    "SUM(CASE WHEN verdict='Malicious' THEN 1 ELSE 0 END) m "
                    "FROM scans GROUP BY d ORDER BY d"
                )
            ]
            # Materialised inside the `with`: the cursor is dead once the
            # connection closes, so it cannot be iterated further down.
            rule_rows = conn.execute(
                "SELECT rules FROM scans WHERE rule_hits > 0 "
                "ORDER BY id DESC LIMIT 500"
            ).fetchall()

        counter: dict[str, int] = {}
        for row in rule_rows:
            try:
                for m in json.loads(row["rules"] or "[]"):
                    counter[m["name"]] = counter.get(m["name"], 0) + 1
            except (json.JSONDecodeError, KeyError, TypeError):
                continue
        top_rules = sorted(counter.items(), key=lambda kv: -kv[1])[:12]

        return {
            "total": total,
            "by_verdict": by_verdict,
            "by_type": by_type,
            "unique_files": agg["u"] or 0,
            "avg_scan_ms": round(agg["ms"] or 0),
            "avg_probability": round(agg["p"] or 0.0, 4),
            "top_rules": [{"rule": k, "count": v} for k, v in top_rules],
            "daily": daily,
            "recent_malicious": by_verdict.get("Malicious", 0),
        }

    def export_rows(self) -> list[dict]:
        """Flat rows suitable for a CSV download."""
        columns = [
            "id", "scanned_at", "filename", "file_size", "file_type", "sha256",
            "md5", "verdict", "probability", "confidence", "engine",
            "model_name", "scan_ms", "rule_hits", "max_severity", "packer",
            "entropy",
        ]
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT {','.join(columns)} FROM scans ORDER BY id DESC"
            )
            return [dict(r) for r in rows]


_history: ScanHistory | None = None
_lock = threading.Lock()


def get_history() -> ScanHistory:
    global _history
    if _history is None:
        with _lock:
            if _history is None:
                _history = ScanHistory()
    return _history
