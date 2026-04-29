from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RecordResult:
    is_duplicate: bool
    ref_count: int


class FingerprintDb:
    def __init__(self, db_path: str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self._init_schema()

    def close(self) -> None:
        self.conn.close()

    def _init_schema(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS fingerprints (
                digest BLOB PRIMARY KEY,
                chunk_length INTEGER NOT NULL,
                first_seen_path TEXT NOT NULL,
                first_seen_offset INTEGER NOT NULL,
                ref_count INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS chunk_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_path TEXT NOT NULL,
                chunk_index INTEGER NOT NULL,
                chunk_offset INTEGER NOT NULL,
                chunk_length INTEGER NOT NULL,
                digest BLOB NOT NULL,
                is_duplicate INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(digest) REFERENCES fingerprints(digest)
            )
            """
        )
        self.conn.commit()

    def record_digest(
        self,
        digest: bytes,
        chunk_length: int,
        source_path: str,
        chunk_index: int,
        chunk_offset: int,
    ) -> RecordResult:
        row = self.conn.execute(
            "SELECT ref_count FROM fingerprints WHERE digest = ?",
            (digest,),
        ).fetchone()

        if row is None:
            self.conn.execute(
                """
                INSERT INTO fingerprints (
                    digest, chunk_length, first_seen_path, first_seen_offset, ref_count
                ) VALUES (?, ?, ?, ?, 1)
                """,
                (digest, chunk_length, source_path, chunk_offset),
            )
            is_duplicate = False
            ref_count = 1
        else:
            ref_count = int(row[0]) + 1
            self.conn.execute(
                """
                UPDATE fingerprints
                SET ref_count = ?, updated_at = CURRENT_TIMESTAMP
                WHERE digest = ?
                """,
                (ref_count, digest),
            )
            is_duplicate = True

        self.conn.execute(
            """
            INSERT INTO chunk_events (
                source_path, chunk_index, chunk_offset, chunk_length, digest, is_duplicate
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (source_path, chunk_index, chunk_offset, chunk_length, digest, int(is_duplicate)),
        )
        self.conn.commit()
        return RecordResult(is_duplicate=is_duplicate, ref_count=ref_count)

