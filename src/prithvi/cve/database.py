"""SQLite-based CVE database."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS cve (
    cve_id TEXT PRIMARY KEY,
    severity TEXT NOT NULL,
    description TEXT,
    published TEXT
);

CREATE TABLE IF NOT EXISTS affected_packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL REFERENCES cve(cve_id),
    package_name TEXT NOT NULL,
    version_start TEXT,
    version_end TEXT,
    ecosystem TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_affected_pkg
    ON affected_packages(package_name, ecosystem);
"""


@dataclass(frozen=True)
class CVERecord:
    """A CVE record with affected package info."""

    cve_id: str
    severity: str
    description: str
    package_name: str
    version_start: str | None
    version_end: str | None
    ecosystem: str


class CVEDatabase:
    """SQLite CVE database for local vulnerability lookups."""

    def __init__(self, db_path: str | Path | None = None):
        if db_path is None:
            db_dir = Path.home() / ".prithvi"
            db_dir.mkdir(parents=True, exist_ok=True)
            db_path = db_dir / "cve.db"
        self.db_path = Path(db_path)
        self._conn: sqlite3.Connection | None = None

    def _connect(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path))
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(SCHEMA)
        return self._conn

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def insert_cve(
        self,
        cve_id: str,
        severity: str,
        description: str,
        published: str,
        affected: list[dict],
    ) -> None:
        """Insert a CVE and its affected packages."""
        conn = self._connect()
        conn.execute(
            "INSERT OR REPLACE INTO cve "
            "(cve_id, severity, description, published) "
            "VALUES (?, ?, ?, ?)",
            (cve_id, severity, description, published),
        )
        for pkg in affected:
            conn.execute(
                "INSERT INTO affected_packages "
                "(cve_id, package_name, version_start, "
                "version_end, ecosystem) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    cve_id, pkg["name"],
                    pkg.get("version_start"),
                    pkg.get("version_end"),
                    pkg["ecosystem"],
                ),
            )
        conn.commit()

    def lookup(self, package_name: str, ecosystem: str) -> list[CVERecord]:
        """Find CVEs affecting a given package."""
        conn = self._connect()
        rows = conn.execute(
            """
            SELECT c.cve_id, c.severity, c.description,
                   ap.package_name, ap.version_start, ap.version_end, ap.ecosystem
            FROM cve c
            JOIN affected_packages ap ON c.cve_id = ap.cve_id
            WHERE ap.package_name = ? AND ap.ecosystem = ?
            """,
            (package_name, ecosystem),
        ).fetchall()

        return [
            CVERecord(
                cve_id=r[0],
                severity=r[1],
                description=r[2],
                package_name=r[3],
                version_start=r[4],
                version_end=r[5],
                ecosystem=r[6],
            )
            for r in rows
        ]

    @property
    def cve_count(self) -> int:
        """Return the number of CVEs in the database."""
        conn = self._connect()
        return conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
