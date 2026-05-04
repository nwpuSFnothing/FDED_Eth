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


@dataclass(frozen=True)
class KvRun:
    id: int
    source_path: str
    request_id: str
    model_id: str
    total_bytes: int
    page_count: int
    tokens_per_page: int
    bytes_per_token: int
    created_at: str


@dataclass(frozen=True)
class KvPage:
    page_index: int
    token_start: int
    token_count: int
    page_length: int
    digest: bytes
    unique_block_id: int | None = None


@dataclass(frozen=True)
class UniqueKvBlock:
    id: int
    digest: bytes
    block_length: int
    dtype: str
    shape: str
    ref_count: int
    location: str
    hot_score: float
    last_access_step: int


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
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS kv_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_path TEXT NOT NULL,
                request_id TEXT NOT NULL,
                model_id TEXT NOT NULL,
                total_bytes INTEGER NOT NULL,
                page_count INTEGER NOT NULL,
                tokens_per_page INTEGER NOT NULL,
                bytes_per_token INTEGER NOT NULL,
                dtype TEXT NOT NULL,
                shape TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS kv_pages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                request_id TEXT NOT NULL,
                model_id TEXT NOT NULL,
                layer_id INTEGER NOT NULL,
                kv_kind TEXT NOT NULL,
                head_group INTEGER NOT NULL,
                page_index INTEGER NOT NULL,
                token_start INTEGER NOT NULL,
                token_count INTEGER NOT NULL,
                dtype TEXT NOT NULL,
                shape TEXT NOT NULL,
                page_length INTEGER NOT NULL,
                digest BLOB NOT NULL,
                unique_block_id INTEGER,
                is_duplicate INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(run_id) REFERENCES kv_runs(id),
                FOREIGN KEY(digest) REFERENCES fingerprints(digest),
                FOREIGN KEY(unique_block_id) REFERENCES unique_kv_blocks(id)
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS unique_kv_blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                digest BLOB NOT NULL UNIQUE,
                block_length INTEGER NOT NULL,
                dtype TEXT NOT NULL,
                shape TEXT NOT NULL,
                ref_count INTEGER NOT NULL DEFAULT 1,
                location TEXT NOT NULL DEFAULT 'COLD_FILE',
                hot_score REAL NOT NULL DEFAULT 0.0,
                last_access_step INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS kv_access_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                step INTEGER NOT NULL,
                request_id TEXT NOT NULL,
                run_id INTEGER,
                page_index INTEGER NOT NULL,
                unique_block_id INTEGER NOT NULL,
                cache_hit INTEGER NOT NULL,
                fpga_hot_hit INTEGER NOT NULL,
                policy TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(run_id) REFERENCES kv_runs(id),
                FOREIGN KEY(unique_block_id) REFERENCES unique_kv_blocks(id)
            )
            """
        )
        columns = {
            str(row[1])
            for row in self.conn.execute("PRAGMA table_info(chunk_events)").fetchall()
        }
        if "run_id" not in columns:
            self.conn.execute("ALTER TABLE chunk_events ADD COLUMN run_id INTEGER")
        kv_page_columns = {
            str(row[1])
            for row in self.conn.execute("PRAGMA table_info(kv_pages)").fetchall()
        }
        if "unique_block_id" not in kv_page_columns:
            self.conn.execute("ALTER TABLE kv_pages ADD COLUMN unique_block_id INTEGER")
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
        self.conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_kv_pages_run_order
            ON kv_pages(run_id, page_index)
            """
        )
        self.conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_kv_runs_request_created
            ON kv_runs(request_id, created_at)
            """
        )
        self.conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_unique_kv_blocks_score
            ON unique_kv_blocks(hot_score DESC, ref_count DESC, last_access_step DESC)
            """
        )
        self.conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_kv_access_events_order
            ON kv_access_events(step, request_id, page_index)
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

    def create_kv_run(
        self,
        source_path: str,
        request_id: str,
        model_id: str,
        total_bytes: int,
        page_count: int,
        tokens_per_page: int,
        bytes_per_token: int,
        dtype: str,
        shape: str,
    ) -> int:
        cursor = self.conn.execute(
            """
            INSERT INTO kv_runs (
                source_path, request_id, model_id, total_bytes, page_count,
                tokens_per_page, bytes_per_token, dtype, shape
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_path,
                request_id,
                model_id,
                total_bytes,
                page_count,
                tokens_per_page,
                bytes_per_token,
                dtype,
                shape,
            ),
        )
        self.conn.commit()
        return int(cursor.lastrowid)

    def record_kv_page(
        self,
        run_id: int,
        request_id: str,
        model_id: str,
        layer_id: int,
        kv_kind: str,
        head_group: int,
        page_index: int,
        token_start: int,
        token_count: int,
        dtype: str,
        shape: str,
        page_length: int,
        digest: bytes,
        is_duplicate: bool,
        unique_block_id: int | None = None,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO kv_pages (
                run_id, request_id, model_id, layer_id, kv_kind, head_group,
                page_index, token_start, token_count, dtype, shape,
                page_length, digest, unique_block_id, is_duplicate
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                request_id,
                model_id,
                layer_id,
                kv_kind,
                head_group,
                page_index,
                token_start,
                token_count,
                dtype,
                shape,
                page_length,
                digest,
                unique_block_id,
                int(is_duplicate),
            ),
        )
        self.conn.commit()

    def record_unique_kv_block(
        self,
        digest: bytes,
        block_length: int,
        dtype: str,
        shape: str,
    ) -> UniqueKvBlock:
        row = self.conn.execute(
            """
            SELECT id, block_length, dtype, shape, ref_count, location, hot_score, last_access_step
            FROM unique_kv_blocks
            WHERE digest = ?
            """,
            (digest,),
        ).fetchone()
        if row is None:
            cursor = self.conn.execute(
                """
                INSERT INTO unique_kv_blocks (
                    digest, block_length, dtype, shape, ref_count
                ) VALUES (?, ?, ?, ?, 1)
                """,
                (digest, block_length, dtype, shape),
            )
            self.conn.commit()
            return UniqueKvBlock(
                id=int(cursor.lastrowid),
                digest=digest,
                block_length=block_length,
                dtype=dtype,
                shape=shape,
                ref_count=1,
                location="COLD_FILE",
                hot_score=0.0,
                last_access_step=0,
            )

        ref_count = int(row[4]) + 1
        self.conn.execute(
            """
            UPDATE unique_kv_blocks
            SET ref_count = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (ref_count, int(row[0])),
        )
        self.conn.commit()
        return UniqueKvBlock(
            id=int(row[0]),
            digest=digest,
            block_length=int(row[1]),
            dtype=str(row[2]),
            shape=str(row[3]),
            ref_count=ref_count,
            location=str(row[5]),
            hot_score=float(row[6]),
            last_access_step=int(row[7]),
        )

    def get_unique_kv_block(self, unique_block_id: int) -> UniqueKvBlock:
        row = self.conn.execute(
            """
            SELECT id, digest, block_length, dtype, shape, ref_count,
                   location, hot_score, last_access_step
            FROM unique_kv_blocks
            WHERE id = ?
            """,
            (unique_block_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"no unique KV block with id {unique_block_id}")
        return UniqueKvBlock(
            id=int(row[0]),
            digest=bytes(row[1]),
            block_length=int(row[2]),
            dtype=str(row[3]),
            shape=str(row[4]),
            ref_count=int(row[5]),
            location=str(row[6]),
            hot_score=float(row[7]),
            last_access_step=int(row[8]),
        )

    def get_unique_kv_block_by_digest(self, digest: bytes) -> UniqueKvBlock | None:
        row = self.conn.execute(
            """
            SELECT id, digest, block_length, dtype, shape, ref_count,
                   location, hot_score, last_access_step
            FROM unique_kv_blocks
            WHERE digest = ?
            """,
            (digest,),
        ).fetchone()
        if row is None:
            return None
        return UniqueKvBlock(
            id=int(row[0]),
            digest=bytes(row[1]),
            block_length=int(row[2]),
            dtype=str(row[3]),
            shape=str(row[4]),
            ref_count=int(row[5]),
            location=str(row[6]),
            hot_score=float(row[7]),
            last_access_step=int(row[8]),
        )

    def record_kv_access(
        self,
        step: int,
        request_id: str,
        run_id: int | None,
        page_index: int,
        unique_block_id: int,
        cache_hit: bool,
        fpga_hot_hit: bool,
        policy: str,
        hot_score: float,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO kv_access_events (
                step, request_id, run_id, page_index, unique_block_id,
                cache_hit, fpga_hot_hit, policy
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                step,
                request_id,
                run_id,
                page_index,
                unique_block_id,
                int(cache_hit),
                int(fpga_hot_hit),
                policy,
            ),
        )
        self.conn.execute(
            """
            UPDATE unique_kv_blocks
            SET hot_score = ?, last_access_step = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (hot_score, step, unique_block_id),
        )
        self.conn.commit()

    def get_hot_kv_digests(self, limit: int) -> list[tuple[bytes, int, float]]:
        if limit <= 0:
            return []
        rows = self.conn.execute(
            """
            SELECT digest, ref_count, hot_score
            FROM unique_kv_blocks
            ORDER BY hot_score DESC, ref_count DESC, last_access_step DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [(bytes(row[0]), int(row[1]), float(row[2])) for row in rows]

    def get_kv_run(self, run_id: int) -> KvRun:
        row = self.conn.execute(
            """
            SELECT id, source_path, request_id, model_id, total_bytes, page_count,
                   tokens_per_page, bytes_per_token, created_at
            FROM kv_runs
            WHERE id = ?
            """,
            (run_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"no KV run with id {run_id}")
        return KvRun(
            id=int(row[0]),
            source_path=str(row[1]),
            request_id=str(row[2]),
            model_id=str(row[3]),
            total_bytes=int(row[4]),
            page_count=int(row[5]),
            tokens_per_page=int(row[6]),
            bytes_per_token=int(row[7]),
            created_at=str(row[8]),
        )

    def get_latest_kv_run(self, request_id: str) -> KvRun:
        row = self.conn.execute(
            """
            SELECT id, source_path, request_id, model_id, total_bytes, page_count,
                   tokens_per_page, bytes_per_token, created_at
            FROM kv_runs
            WHERE request_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (request_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"no KV run for request_id {request_id}")
        return KvRun(
            id=int(row[0]),
            source_path=str(row[1]),
            request_id=str(row[2]),
            model_id=str(row[3]),
            total_bytes=int(row[4]),
            page_count=int(row[5]),
            tokens_per_page=int(row[6]),
            bytes_per_token=int(row[7]),
            created_at=str(row[8]),
        )

    def get_kv_pages(self, run_id: int) -> list[KvPage]:
        rows = self.conn.execute(
            """
            SELECT page_index, token_start, token_count, page_length, digest, unique_block_id
            FROM kv_pages
            WHERE run_id = ?
            ORDER BY page_index ASC
            """,
            (run_id,),
        ).fetchall()
        return [
            KvPage(
                page_index=int(row[0]),
                token_start=int(row[1]),
                token_count=int(row[2]),
                page_length=int(row[3]),
                digest=bytes(row[4]),
                unique_block_id=None if row[5] is None else int(row[5]),
            )
            for row in rows
        ]
