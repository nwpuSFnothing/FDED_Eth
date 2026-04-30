from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RecordResult:
    is_duplicate: bool
    ref_count: int


@dataclass(frozen=True)
class FileRun:
    id: int
    source_path: str
    total_bytes: int
    chunk_count: int
    chunk_mode: str
    created_at: str


@dataclass(frozen=True)
class ChunkEvent:
    chunk_index: int
    chunk_offset: int
    chunk_length: int
    digest: bytes


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
            CREATE TABLE IF NOT EXISTS file_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_path TEXT NOT NULL,
                total_bytes INTEGER NOT NULL,
                chunk_count INTEGER NOT NULL,
                chunk_mode TEXT NOT NULL,
                min_size INTEGER NOT NULL,
                avg_size INTEGER NOT NULL,
                max_size INTEGER NOT NULL,
                fixed_size INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS chunk_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER,
                source_path TEXT NOT NULL,
                chunk_index INTEGER NOT NULL,
                chunk_offset INTEGER NOT NULL,
                chunk_length INTEGER NOT NULL,
                digest BLOB NOT NULL,
                is_duplicate INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(run_id) REFERENCES file_runs(id),
                FOREIGN KEY(digest) REFERENCES fingerprints(digest)
            )
            """
        )
        columns = {
            str(row[1])
            for row in self.conn.execute("PRAGMA table_info(chunk_events)").fetchall()
        }
        if "run_id" not in columns:
            self.conn.execute("ALTER TABLE chunk_events ADD COLUMN run_id INTEGER")
        self.conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_chunk_events_run_order
            ON chunk_events(run_id, chunk_index)
            """
        )
        self.conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_file_runs_source_created
            ON file_runs(source_path, created_at)
            """
        )
        self.conn.commit()

    def create_file_run(
        self,
        source_path: str,
        total_bytes: int,
        chunk_count: int,
        chunk_mode: str,
        min_size: int,
        avg_size: int,
        max_size: int,
        fixed_size: int,
    ) -> int:
        cursor = self.conn.execute(
            """
            INSERT INTO file_runs (
                source_path, total_bytes, chunk_count, chunk_mode,
                min_size, avg_size, max_size, fixed_size
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_path,
                total_bytes,
                chunk_count,
                chunk_mode,
                min_size,
                avg_size,
                max_size,
                fixed_size,
            ),
        )
        self.conn.commit()
        return int(cursor.lastrowid)

    def record_digest(
        self,
        digest: bytes,
        chunk_length: int,
        source_path: str,
        chunk_index: int,
        chunk_offset: int,
        run_id: int | None = None,
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
                run_id, source_path, chunk_index, chunk_offset, chunk_length, digest, is_duplicate
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (run_id, source_path, chunk_index, chunk_offset, chunk_length, digest, int(is_duplicate)),
        )
        self.conn.commit()
        return RecordResult(is_duplicate=is_duplicate, ref_count=ref_count)

    def has_digest(self, digest: bytes) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM fingerprints WHERE digest = ?",
            (digest,),
        ).fetchone()
        return row is not None

    def record_trusted_duplicate(
        self,
        digest: bytes,
        chunk_length: int,
        source_path: str,
        chunk_index: int,
        chunk_offset: int,
        run_id: int | None = None,
    ) -> RecordResult:
        row = self.conn.execute(
            """
            UPDATE fingerprints
            SET ref_count = ref_count + 1, updated_at = CURRENT_TIMESTAMP
            WHERE digest = ?
            RETURNING ref_count
            """,
            (digest,),
        ).fetchone()
        if row is None:
            self.conn.rollback()
            raise KeyError(
                "FPGA reported HOT_HIT, but digest was not present in sqlite fingerprint table"
            )

        ref_count = int(row[0])
        self.conn.execute(
            """
            INSERT INTO chunk_events (
                run_id, source_path, chunk_index, chunk_offset, chunk_length, digest, is_duplicate
            ) VALUES (?, ?, ?, ?, ?, ?, 1)
            """,
            (run_id, source_path, chunk_index, chunk_offset, chunk_length, digest),
        )
        self.conn.commit()
        return RecordResult(is_duplicate=True, ref_count=ref_count)

    def get_hot_digests(self, limit: int) -> list[tuple[bytes, int]]:
        if limit <= 0:
            return []

        rows = self.conn.execute(
            """
            SELECT digest, ref_count
            FROM fingerprints
            ORDER BY ref_count DESC, updated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [(bytes(row[0]), int(row[1])) for row in rows]

    def list_file_runs(self, limit: int = 20) -> list[FileRun]:
        rows = self.conn.execute(
            """
            SELECT id, source_path, total_bytes, chunk_count, chunk_mode, created_at
            FROM file_runs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [
            FileRun(
                id=int(row[0]),
                source_path=str(row[1]),
                total_bytes=int(row[2]),
                chunk_count=int(row[3]),
                chunk_mode=str(row[4]),
                created_at=str(row[5]),
            )
            for row in rows
        ]

    def get_file_run(self, run_id: int) -> FileRun:
        row = self.conn.execute(
            """
            SELECT id, source_path, total_bytes, chunk_count, chunk_mode, created_at
            FROM file_runs
            WHERE id = ?
            """,
            (run_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"no file run with id {run_id}")
        return FileRun(
            id=int(row[0]),
            source_path=str(row[1]),
            total_bytes=int(row[2]),
            chunk_count=int(row[3]),
            chunk_mode=str(row[4]),
            created_at=str(row[5]),
        )

    def get_latest_file_run(self, source_path: str) -> FileRun:
        row = self.conn.execute(
            """
            SELECT id, source_path, total_bytes, chunk_count, chunk_mode, created_at
            FROM file_runs
            WHERE source_path = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (source_path,),
        ).fetchone()
        if row is None:
            raise KeyError(f"no file run for source path {source_path}")
        return FileRun(
            id=int(row[0]),
            source_path=str(row[1]),
            total_bytes=int(row[2]),
            chunk_count=int(row[3]),
            chunk_mode=str(row[4]),
            created_at=str(row[5]),
        )

    def get_run_chunks(self, run_id: int) -> list[ChunkEvent]:
        rows = self.conn.execute(
            """
            SELECT chunk_index, chunk_offset, chunk_length, digest
            FROM chunk_events
            WHERE run_id = ?
            ORDER BY chunk_index ASC
            """,
            (run_id,),
        ).fetchall()
        return [
            ChunkEvent(
                chunk_index=int(row[0]),
                chunk_offset=int(row[1]),
                chunk_length=int(row[2]),
                digest=bytes(row[3]),
            )
            for row in rows
        ]
