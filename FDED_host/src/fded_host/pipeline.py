from __future__ import annotations

import argparse
import hashlib
import struct
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from time import perf_counter
from typing import Iterable

from .chunker import Chunk, fastcdc_chunks, fixed_size_chunks
from .config import (
    DEFAULT_AVG_CHUNK_SIZE,
    DEFAULT_DB_PATH,
    DEFAULT_FRAGMENT_SIZE,
    DEFAULT_FPGA_IP,
    DEFAULT_HOST_IP,
    DEFAULT_MAX_CHUNK_SIZE,
    DEFAULT_MIN_CHUNK_SIZE,
    DEFAULT_PORT,
    DEFAULT_RESULT_DIR,
    DEFAULT_WRITE_DIR,
)
from .fingerprint_db import FingerprintDb
from .fpga_client import FpgaUdpClient


@dataclass
class ProcessStats:
    run_id: int = 0
    input_path: str = ""
    chunk_mode: str = ""
    min_size: int = 0
    avg_size: int = 0
    max_size: int = 0
    fixed_size: int = 0
    total_chunks: int = 0
    unique_chunks: int = 0
    duplicate_chunks: int = 0
    total_bytes: int = 0
    written_unique_bytes: int = 0
    elapsed_seconds: float = 0.0
    read_seconds: float = 0.0
    chunk_seconds: float = 0.0
    fpga_seconds: float = 0.0
    verify_seconds: float = 0.0
    db_seconds: float = 0.0
    write_seconds: float = 0.0
    fpga_hot_hits: int = 0
    host_lookups: int = 0
    host_lookup_avoided: int = 0
    hot_table_loaded: int = 0
    hot_table_refreshes: int = 0
    digest_mode: str = "raw"
    fragment_size: int = 0
    fragment_hashes: int = 0
    large_chunks: int = 0

    @property
    def duplicate_ratio(self) -> float:
        if self.total_chunks == 0:
            return 0.0
        return self.duplicate_chunks / self.total_chunks

    @property
    def hot_hit_ratio(self) -> float:
        if self.total_chunks == 0:
            return 0.0
        return self.fpga_hot_hits / self.total_chunks

    @property
    def avg_fragments_per_chunk(self) -> float:
        if self.total_chunks == 0:
            return 0.0
        return self.fragment_hashes / self.total_chunks


@dataclass(frozen=True)
class LogicalHashResult:
    digest: bytes
    hot_hit: bool
    fragment_count: int


@dataclass(frozen=True)
class ResultPaths:
    png_path: Path
    md_path: Path


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Host-side CDC + FPGA SHA-256 pipeline.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    process = subparsers.add_parser("process-file", help="Chunk a file and hash chunks with the FPGA.")
    process.add_argument("input_file")
    process.add_argument("--db-path", default=DEFAULT_DB_PATH)
    process.add_argument("--fpga-ip", default=DEFAULT_FPGA_IP)
    process.add_argument("--host-ip", default=DEFAULT_HOST_IP)
    process.add_argument("--port", type=int, default=DEFAULT_PORT)
    process.add_argument("--timeout", type=float, default=5.0)
    process.add_argument("--chunk-mode", choices=("fixed", "cdc"), default="cdc")
    process.add_argument("--fixed-size", type=int, default=DEFAULT_AVG_CHUNK_SIZE)
    process.add_argument("--min-size", type=int, default=DEFAULT_MIN_CHUNK_SIZE)
    process.add_argument("--avg-size", type=int, default=DEFAULT_AVG_CHUNK_SIZE)
    process.add_argument("--max-size", type=int, default=DEFAULT_MAX_CHUNK_SIZE)
    process.add_argument("--fragment-size", type=int, default=DEFAULT_FRAGMENT_SIZE)
    process.add_argument("--digest-mode", choices=("raw", "hierarchical", "fpga-stream"), default="raw")
    process.add_argument("--start-seq", type=lambda value: int(value, 0), default=1)
    process.add_argument("--verify-local", action="store_true")
    process.add_argument("--load-hot-table", action="store_true")
    process.add_argument("--hot-limit", type=int, default=512)
    process.add_argument("--hot-refresh-interval-s", type=float, default=0.0)
    process.add_argument("--no-clear-hot-table", action="store_true")
    process.add_argument("--verify-hot-hit", action="store_true")
    process.add_argument("--print-chunks", action="store_true")
    process.add_argument("--result-dir", default=DEFAULT_RESULT_DIR)
    process.add_argument("--result-tag", default=None)
    process.add_argument("--write-dir", default=DEFAULT_WRITE_DIR)

    process_dir = subparsers.add_parser("process-dir", help="Process every file in a directory and export result tables.")
    process_dir.add_argument("input_dir")
    process_dir.add_argument("--pattern", default="*")
    process_dir.add_argument("--recursive", action="store_true")
    process_dir.add_argument("--db-path", default=DEFAULT_DB_PATH)
    process_dir.add_argument("--fpga-ip", default=DEFAULT_FPGA_IP)
    process_dir.add_argument("--host-ip", default=DEFAULT_HOST_IP)
    process_dir.add_argument("--port", type=int, default=DEFAULT_PORT)
    process_dir.add_argument("--timeout", type=float, default=5.0)
    process_dir.add_argument("--chunk-mode", choices=("fixed", "cdc"), default="cdc")
    process_dir.add_argument("--fixed-size", type=int, default=DEFAULT_AVG_CHUNK_SIZE)
    process_dir.add_argument("--min-size", type=int, default=DEFAULT_MIN_CHUNK_SIZE)
    process_dir.add_argument("--avg-size", type=int, default=DEFAULT_AVG_CHUNK_SIZE)
    process_dir.add_argument("--max-size", type=int, default=DEFAULT_MAX_CHUNK_SIZE)
    process_dir.add_argument("--fragment-size", type=int, default=DEFAULT_FRAGMENT_SIZE)
    process_dir.add_argument("--digest-mode", choices=("raw", "hierarchical", "fpga-stream"), default="raw")
    process_dir.add_argument("--start-seq", type=lambda value: int(value, 0), default=1)
    process_dir.add_argument("--verify-local", action="store_true")
    process_dir.add_argument("--load-hot-table", action="store_true")
    process_dir.add_argument("--hot-limit", type=int, default=512)
    process_dir.add_argument("--hot-refresh-interval-s", type=float, default=0.0)
    process_dir.add_argument("--no-clear-hot-table", action="store_true")
    process_dir.add_argument("--verify-hot-hit", action="store_true")
    process_dir.add_argument("--print-chunks", action="store_true")
    process_dir.add_argument("--result-dir", default=DEFAULT_RESULT_DIR)
    process_dir.add_argument("--result-tag", default=None)
    process_dir.add_argument("--write-dir", default=DEFAULT_WRITE_DIR)

    load_hot = subparsers.add_parser("load-hot-table", help="Load top-N sqlite digests into the FPGA hot table.")
    load_hot.add_argument("--db-path", default=DEFAULT_DB_PATH)
    load_hot.add_argument("--fpga-ip", default=DEFAULT_FPGA_IP)
    load_hot.add_argument("--host-ip", default=DEFAULT_HOST_IP)
    load_hot.add_argument("--port", type=int, default=DEFAULT_PORT)
    load_hot.add_argument("--timeout", type=float, default=5.0)
    load_hot.add_argument("--limit", type=int, default=512)
    load_hot.add_argument("--no-clear", action="store_true")

    clear_hot = subparsers.add_parser("clear-hot-table", help="Clear the FPGA hot digest table.")
    clear_hot.add_argument("--fpga-ip", default=DEFAULT_FPGA_IP)
    clear_hot.add_argument("--host-ip", default=DEFAULT_HOST_IP)
    clear_hot.add_argument("--port", type=int, default=DEFAULT_PORT)
    clear_hot.add_argument("--timeout", type=float, default=5.0)

    write_hot = subparsers.add_parser("write-hot-digest", help="Write one digest into an FPGA hot table slot.")
    write_hot.add_argument("--slot", type=int, required=True)
    write_hot.add_argument("--digest-hex", required=True)
    write_hot.add_argument("--fpga-ip", default=DEFAULT_FPGA_IP)
    write_hot.add_argument("--host-ip", default=DEFAULT_HOST_IP)
    write_hot.add_argument("--port", type=int, default=DEFAULT_PORT)
    write_hot.add_argument("--timeout", type=float, default=5.0)

    list_runs = subparsers.add_parser("list-runs", help="List recorded file processing runs.")
    list_runs.add_argument("--db-path", default=DEFAULT_DB_PATH)
    list_runs.add_argument("--limit", type=int, default=20)

    restore = subparsers.add_parser("restore-file", help="Restore one processed file from chunk storage.")
    restore.add_argument("--db-path", default=DEFAULT_DB_PATH)
    restore.add_argument("--run-id", type=int, default=None)
    restore.add_argument("--source-path", default=None)
    restore.add_argument("--output-file", required=True)
    restore.add_argument("--write-dir", default=DEFAULT_WRITE_DIR)

    kv_process = subparsers.add_parser("process-kv-file", help="Process a binary KVCache dump as logical KV pages.")
    kv_process.add_argument("input_file")
    kv_process.add_argument("--db-path", default=DEFAULT_DB_PATH)
    kv_process.add_argument("--fpga-ip", default=DEFAULT_FPGA_IP)
    kv_process.add_argument("--host-ip", default=DEFAULT_HOST_IP)
    kv_process.add_argument("--port", type=int, default=DEFAULT_PORT)
    kv_process.add_argument("--timeout", type=float, default=5.0)
    kv_process.add_argument("--fragment-size", type=int, default=DEFAULT_FRAGMENT_SIZE)
    kv_process.add_argument("--digest-mode", choices=("raw", "hierarchical", "fpga-stream"), default="hierarchical")
    kv_process.add_argument("--start-seq", type=lambda value: int(value, 0), default=1)
    kv_process.add_argument("--verify-local", action="store_true")
    kv_process.add_argument("--request-id", required=True)
    kv_process.add_argument("--model-id", default="unknown-model")
    kv_process.add_argument("--layer-id", type=int, default=0)
    kv_process.add_argument("--kv-kind", choices=("K", "V"), default="K")
    kv_process.add_argument("--head-group", type=int, default=0)
    kv_process.add_argument("--tokens-per-page", type=int, default=16)
    kv_process.add_argument("--bytes-per-token", type=int, required=True)
    kv_process.add_argument("--dtype", default="fp16")
    kv_process.add_argument("--shape", default="")
    kv_process.add_argument("--print-pages", action="store_true")
    kv_process.add_argument("--write-dir", default=DEFAULT_WRITE_DIR)

    kv_restore = subparsers.add_parser("restore-kv", help="Restore one processed KV run from unique block storage.")
    kv_restore.add_argument("--db-path", default=DEFAULT_DB_PATH)
    kv_restore.add_argument("--run-id", type=int, default=None)
    kv_restore.add_argument("--request-id", default=None)
    kv_restore.add_argument("--output-file", required=True)
    kv_restore.add_argument("--write-dir", default=DEFAULT_WRITE_DIR)

    return parser


def iter_chunks(args: argparse.Namespace, input_path: Path, data: bytes) -> Iterable[Chunk]:
    if args.chunk_mode == "fixed":
        return fixed_size_chunks(data, args.fixed_size)
    return fastcdc_chunks(str(input_path), data, args.min_size, args.avg_size, args.max_size)


def collect_input_files(input_dir: Path, pattern: str, recursive: bool) -> list[Path]:
    if recursive:
        files = [path for path in input_dir.rglob(pattern) if path.is_file()]
    else:
        files = [path for path in input_dir.glob(pattern) if path.is_file()]
    return sorted(files)


def build_result_paths(result_dir: str, result_tag: str | None) -> ResultPaths:
    base_dir = Path(result_dir).resolve()
    base_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    tag = result_tag or "run"
    safe_tag = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in tag)
    return ResultPaths(
        png_path=base_dir / f"{stamp}_{safe_tag}.png",
        md_path=base_dir / f"{stamp}_{safe_tag}.md",
    )


def write_unique_chunk(write_root: str, digest: bytes, data: bytes) -> int:
    chunk_dir = Path(write_root).resolve() / "chunks"
    chunk_dir.mkdir(parents=True, exist_ok=True)
    chunk_path = chunk_dir / f"{digest.hex()}.bin"
    if chunk_path.exists():
        return 0
    chunk_path.write_bytes(data)
    return len(data)


def reload_hot_table(
    args: argparse.Namespace,
    db: FingerprintDb,
    client: FpgaUdpClient,
) -> int:
    hot_digests = [digest for digest, _ref_count in db.get_hot_digests(args.hot_limit)]
    return client.load_hot_table(
        hot_digests,
        clear=not args.no_clear_hot_table,
    )


def aggregate_fragment_digests(
    chunk_length: int,
    fragment_size: int,
    fragment_digests: list[bytes],
) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(b"FDED_CHUNK_V1")
    hasher.update(struct.pack(">QII", chunk_length, fragment_size, len(fragment_digests)))
    for digest in fragment_digests:
        hasher.update(digest)
    return hasher.digest()


def split_fragments(data: bytes, fragment_size: int) -> Iterable[bytes]:
    if fragment_size <= 0:
        raise ValueError("fragment_size must be > 0")
    for offset in range(0, len(data), fragment_size):
        yield data[offset : offset + fragment_size]


def hash_logical_chunk(
    args: argparse.Namespace,
    client: FpgaUdpClient,
    seq_id: int,
    data: bytes,
) -> tuple[LogicalHashResult, int, float, float]:
    fpga_seconds = 0.0
    verify_seconds = 0.0

    if args.digest_mode == "fpga-stream":
        fpga_t0 = perf_counter()
        reply = client.hash_stream(seq_id, data, args.fragment_size)
        fpga_seconds += perf_counter() - fpga_t0
        if args.verify_local:
            verify_t0 = perf_counter()
            local_digest = client.expected_digest(data)
            if reply.digest != local_digest:
                raise ValueError("FPGA stream digest mismatch between FPGA and local hashlib")
            verify_seconds += perf_counter() - verify_t0
        data_per_packet = max(1, args.fragment_size - 9)
        fragment_count = max(1, (len(data) + data_per_packet - 1) // data_per_packet)
        return LogicalHashResult(reply.digest, reply.hot_hit, fragment_count), seq_id + 1, fpga_seconds, verify_seconds

    if args.digest_mode == "raw" or len(data) <= args.fragment_size:
        fpga_t0 = perf_counter()
        reply = client.hash_chunk(seq_id, data)
        fpga_seconds += perf_counter() - fpga_t0
        if args.verify_local:
            verify_t0 = perf_counter()
            local_digest = client.expected_digest(data)
            if reply.digest != local_digest:
                raise ValueError("logical chunk digest mismatch between FPGA and local hashlib")
            verify_seconds += perf_counter() - verify_t0
        return LogicalHashResult(reply.digest, reply.hot_hit, 1), seq_id + 1, fpga_seconds, verify_seconds

    fragment_digests: list[bytes] = []
    next_seq_id = seq_id
    for fragment in split_fragments(data, args.fragment_size):
        fpga_t0 = perf_counter()
        reply = client.hash_chunk(next_seq_id, fragment)
        fpga_seconds += perf_counter() - fpga_t0
        if args.verify_local:
            verify_t0 = perf_counter()
            local_digest = client.expected_digest(fragment)
            if reply.digest != local_digest:
                raise ValueError(
                    f"fragment seq_id 0x{next_seq_id:08x} digest mismatch between FPGA and local hashlib"
                )
            verify_seconds += perf_counter() - verify_t0
        fragment_digests.append(reply.digest)
        next_seq_id += 1

    verify_t0 = perf_counter()
    digest = aggregate_fragment_digests(
        chunk_length=len(data),
        fragment_size=args.fragment_size,
        fragment_digests=fragment_digests,
    )
    verify_seconds += perf_counter() - verify_t0
    return LogicalHashResult(digest, False, len(fragment_digests)), next_seq_id, fpga_seconds, verify_seconds


def process_one_file(
    args: argparse.Namespace,
    input_path: Path,
    db: FingerprintDb,
    load_hot_table: bool = True,
) -> ProcessStats:
    read_t0 = perf_counter()
    data = input_path.read_bytes()
    read_t1 = perf_counter()
    stats = ProcessStats(
        input_path=str(input_path),
        chunk_mode=args.chunk_mode,
        min_size=args.min_size,
        avg_size=args.avg_size,
        max_size=args.max_size,
        fixed_size=args.fixed_size,
        total_bytes=len(data),
        read_seconds=read_t1 - read_t0,
        digest_mode=args.digest_mode,
        fragment_size=args.fragment_size,
    )

    start_total = perf_counter()
    chunk_t0 = perf_counter()
    chunks = list(iter_chunks(args, input_path, data))
    chunk_t1 = perf_counter()
    stats.chunk_seconds = chunk_t1 - chunk_t0
    stats.run_id = db.create_file_run(
        source_path=str(input_path),
        total_bytes=len(data),
        chunk_count=len(chunks),
        chunk_mode=args.chunk_mode,
        min_size=args.min_size,
        avg_size=args.avg_size,
        max_size=args.max_size,
        fixed_size=args.fixed_size,
    )

    with FpgaUdpClient(
        fpga_ip=args.fpga_ip,
        host_ip=args.host_ip,
        port=args.port,
        timeout=args.timeout,
        max_data_len=args.fragment_size,
    ) as client:
        if load_hot_table and args.load_hot_table:
            stats.hot_table_loaded = reload_hot_table(args, db, client)
            stats.hot_table_refreshes += 1

        last_hot_refresh = perf_counter()

        next_seq_id = args.start_seq

        for chunk in chunks:
            if (
                args.load_hot_table
                and args.hot_refresh_interval_s > 0
                and perf_counter() - last_hot_refresh >= args.hot_refresh_interval_s
            ):
                stats.hot_table_loaded = reload_hot_table(args, db, client)
                stats.hot_table_refreshes += 1
                last_hot_refresh = perf_counter()

            seq_id = next_seq_id
            hash_result, next_seq_id, fpga_seconds, verify_seconds = hash_logical_chunk(
                args=args,
                client=client,
                seq_id=seq_id,
                data=chunk.data,
            )
            stats.fpga_seconds += fpga_seconds
            stats.verify_seconds += verify_seconds
            stats.fragment_hashes += hash_result.fragment_count
            if hash_result.fragment_count > 1:
                stats.large_chunks += 1
            if hash_result.hot_hit:
                stats.fpga_hot_hits += 1

            db_t0 = perf_counter()
            if hash_result.hot_hit:
                if args.verify_hot_hit:
                    stats.host_lookups += 1
                    if not db.has_digest(hash_result.digest):
                        raise ValueError(
                            f"chunk {chunk.index} FPGA HOT_HIT digest is absent from sqlite"
                        )
                else:
                    stats.host_lookup_avoided += 1
                record = db.record_trusted_duplicate(
                    digest=hash_result.digest,
                    chunk_length=chunk.length,
                    source_path=str(input_path),
                    chunk_index=chunk.index,
                    chunk_offset=chunk.offset,
                    run_id=stats.run_id,
                )
            else:
                stats.host_lookups += 1
                record = db.record_digest(
                    digest=hash_result.digest,
                    chunk_length=chunk.length,
                    source_path=str(input_path),
                    chunk_index=chunk.index,
                    chunk_offset=chunk.offset,
                    run_id=stats.run_id,
                )
            db_t1 = perf_counter()
            stats.db_seconds += db_t1 - db_t0
            stats.total_chunks += 1
            if record.is_duplicate:
                stats.duplicate_chunks += 1
            else:
                stats.unique_chunks += 1
                write_t0 = perf_counter()
                written = write_unique_chunk(args.write_dir, hash_result.digest, chunk.data)
                write_t1 = perf_counter()
                stats.write_seconds += write_t1 - write_t0
                stats.written_unique_bytes += written

            if args.print_chunks:
                status = "dup" if record.is_duplicate else "new"
                hot_status = "hot" if hash_result.hot_hit else "miss"
                print(
                    f"chunk={chunk.index:04d} offset={chunk.offset:08d} "
                    f"len={chunk.length:04d} seq=0x{seq_id:08x} {hot_status} {status} "
                    f"frags={hash_result.fragment_count} ref_count={record.ref_count} "
                    f"digest={hash_result.digest.hex()}"
                )

    stats.elapsed_seconds = perf_counter() - start_total
    return stats


def write_result_tables(
    stats_list: list[ProcessStats],
    result_paths: ResultPaths,
    args: argparse.Namespace,
) -> None:
    render_result_table_image(stats_list, result_paths.png_path, args)

    with result_paths.md_path.open("w", encoding="utf-8") as handle:
        handle.write("# FDED_host Test Results\n\n")
        handle.write("## Parameters\n\n")
        handle.write(f"- `chunk_mode`: `{args.chunk_mode}`\n")
        handle.write(f"- `fixed_size`: `{args.fixed_size}`\n")
        handle.write(f"- `min_size`: `{args.min_size}`\n")
        handle.write(f"- `avg_size`: `{args.avg_size}`\n")
        handle.write(f"- `max_size`: `{args.max_size}`\n")
        handle.write(f"- `digest_mode`: `{args.digest_mode}`\n")
        handle.write(f"- `fragment_size`: `{args.fragment_size}`\n")
        handle.write(f"- `fpga_ip`: `{args.fpga_ip}`\n")
        handle.write(f"- `host_ip`: `{args.host_ip}`\n")
        handle.write(f"- `port`: `{args.port}`\n")
        handle.write(f"- `timeout`: `{args.timeout}`\n")
        handle.write(f"- `verify_local`: `{args.verify_local}`\n\n")
        handle.write(f"- `load_hot_table`: `{args.load_hot_table}`\n")
        handle.write(f"- `hot_limit`: `{args.hot_limit}`\n")
        handle.write(f"- `hot_refresh_interval_s`: `{args.hot_refresh_interval_s}`\n")
        handle.write(f"- `verify_hot_hit`: `{args.verify_hot_hit}`\n")
        handle.write(f"- `write_dir`: `{args.write_dir}`\n\n")
        handle.write("## Results\n\n")
        handle.write("| run_id | input_path | bytes | chunks | unique | duplicate | unique_write_bytes | duplicate_ratio | digest_mode | fragment_size | fragment_hashes | large_chunks | avg_fragments | fpga_hot_hits | host_lookups | lookup_avoided | hot_hit_ratio | hot_loaded | hot_refreshes | elapsed_s | read_s | chunk_s | fpga_s | verify_s | db_s | write_s |\n")
        handle.write("|---:|---|---:|---:|---:|---:|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")
        for stats in stats_list:
            handle.write(
                f"| {stats.run_id} | {stats.input_path} | {stats.total_bytes} | {stats.total_chunks} | "
                f"{stats.unique_chunks} | {stats.duplicate_chunks} | {stats.written_unique_bytes} | "
                f"{stats.duplicate_ratio:.4f} | {stats.digest_mode} | {stats.fragment_size} | "
                f"{stats.fragment_hashes} | {stats.large_chunks} | {stats.avg_fragments_per_chunk:.4f} | "
                f"{stats.fpga_hot_hits} | "
                f"{stats.host_lookups} | {stats.host_lookup_avoided} | "
                f"{stats.hot_hit_ratio:.4f} | {stats.hot_table_loaded} | "
                f"{stats.hot_table_refreshes} | "
                f"{stats.elapsed_seconds:.4f} | "
                f"{stats.read_seconds:.4f} | {stats.chunk_seconds:.4f} | "
                f"{stats.fpga_seconds:.4f} | {stats.verify_seconds:.4f} | "
                f"{stats.db_seconds:.4f} | {stats.write_seconds:.4f} |\n"
            )


def fit_text(value: str, max_len: int) -> str:
    if len(value) <= max_len:
        return value
    if max_len <= 3:
        return value[:max_len]
    return value[: max_len - 3] + "..."


def render_result_table_image(
    stats_list: list[ProcessStats],
    output_path: Path,
    args: argparse.Namespace,
) -> None:
    from PIL import Image, ImageDraw, ImageFont

    title = "FDED_host Test Results"
    subtitle = (
        f"mode={args.chunk_mode} min={args.min_size} avg={args.avg_size} "
        f"max={args.max_size} digest={args.digest_mode} frag={args.fragment_size} "
        f"fpga={args.fpga_ip}:{args.port} write={args.write_dir}"
    )
    headers = ["file", "bytes", "chunks", "unique", "dup", "write_B", "dup_ratio", "frags", "large", "avg_frag", "hot", "lookups", "saved", "hot_ratio", "loads", "elapsed_s", "fpga_s", "db_s", "write_s"]
    rows = []
    for stats in stats_list:
        rows.append(
            [
                fit_text(Path(stats.input_path).name, 24),
                str(stats.total_bytes),
                str(stats.total_chunks),
                str(stats.unique_chunks),
                str(stats.duplicate_chunks),
                str(stats.written_unique_bytes),
                f"{stats.duplicate_ratio:.4f}",
                str(stats.fragment_hashes),
                str(stats.large_chunks),
                f"{stats.avg_fragments_per_chunk:.2f}",
                str(stats.fpga_hot_hits),
                str(stats.host_lookups),
                str(stats.host_lookup_avoided),
                f"{stats.hot_hit_ratio:.4f}",
                str(stats.hot_table_refreshes),
                f"{stats.elapsed_seconds:.4f}",
                f"{stats.fpga_seconds:.4f}",
                f"{stats.db_seconds:.4f}",
                f"{stats.write_seconds:.4f}",
            ]
        )

    try:
        font = ImageFont.truetype("consola.ttf", 18)
        title_font = ImageFont.truetype("consolab.ttf", 24)
    except OSError:
        font = ImageFont.load_default()
        title_font = ImageFont.load_default()

    temp_img = Image.new("RGB", (16, 16), "white")
    draw = ImageDraw.Draw(temp_img)

    cell_padding_x = 14
    cell_padding_y = 10
    row_height = 38
    table_top = 110
    left_margin = 24
    top_margin = 20

    col_widths: list[int] = []
    for col_idx, header in enumerate(headers):
        max_width = draw.textbbox((0, 0), header, font=font)[2]
        for row in rows:
            width = draw.textbbox((0, 0), row[col_idx], font=font)[2]
            if width > max_width:
                max_width = width
        col_widths.append(max_width + cell_padding_x * 2)

    table_width = sum(col_widths)
    width = max(1200, left_margin * 2 + table_width)
    height = table_top + row_height * (len(rows) + 1) + 30

    image = Image.new("RGB", (width, height), "#f7f8fa")
    draw = ImageDraw.Draw(image)

    draw.text((left_margin, top_margin), title, fill="#111111", font=title_font)
    draw.text((left_margin, top_margin + 38), subtitle, fill="#444444", font=font)

    x = left_margin
    y = table_top

    for idx, header in enumerate(headers):
        draw.rectangle((x, y, x + col_widths[idx], y + row_height), fill="#dbeafe", outline="#94a3b8", width=1)
        draw.text((x + cell_padding_x, y + cell_padding_y), header, fill="#111827", font=font)
        x += col_widths[idx]

    for row_idx, row in enumerate(rows, start=1):
        x = left_margin
        y = table_top + row_height * row_idx
        fill = "#ffffff" if row_idx % 2 == 1 else "#f1f5f9"
        for col_idx, value in enumerate(row):
            draw.rectangle((x, y, x + col_widths[col_idx], y + row_height), fill=fill, outline="#cbd5e1", width=1)
            draw.text((x + cell_padding_x, y + cell_padding_y), value, fill="#111827", font=font)
            x += col_widths[col_idx]

    image.save(output_path)


def print_stats(stats: ProcessStats) -> None:
    print(f"run_id        {stats.run_id}")
    print(f"file          {stats.input_path}")
    print(f"bytes         {stats.total_bytes}")
    print(f"chunks        {stats.total_chunks}")
    print(f"unique        {stats.unique_chunks}")
    print(f"duplicate     {stats.duplicate_chunks}")
    print(f"write_bytes   {stats.written_unique_bytes}")
    print(f"dup_ratio     {stats.duplicate_ratio:.4f}")
    print(f"digest_mode   {stats.digest_mode}")
    print(f"fragment_size {stats.fragment_size}")
    print(f"fragments     {stats.fragment_hashes}")
    print(f"large_chunks  {stats.large_chunks}")
    print(f"avg_fragments {stats.avg_fragments_per_chunk:.4f}")
    print(f"fpga_hot_hits {stats.fpga_hot_hits}")
    print(f"host_lookups  {stats.host_lookups}")
    print(f"lookup_saved  {stats.host_lookup_avoided}")
    print(f"hot_hit_ratio {stats.hot_hit_ratio:.4f}")
    print(f"hot_loaded    {stats.hot_table_loaded}")
    print(f"hot_refreshes {stats.hot_table_refreshes}")
    print(f"elapsed_s     {stats.elapsed_seconds:.4f}")
    print(f"read_s        {stats.read_seconds:.4f}")
    print(f"chunk_s       {stats.chunk_seconds:.4f}")
    print(f"fpga_s        {stats.fpga_seconds:.4f}")
    print(f"verify_s      {stats.verify_seconds:.4f}")
    print(f"db_s          {stats.db_seconds:.4f}")
    print(f"write_s       {stats.write_seconds:.4f}")


def process_file(args: argparse.Namespace) -> int:
    input_path = Path(args.input_file).resolve()
    db = FingerprintDb(args.db_path)
    try:
        stats = process_one_file(args, input_path, db)
    finally:
        db.close()

    result_paths = build_result_paths(args.result_dir, args.result_tag)
    write_result_tables([stats], result_paths, args)
    print_stats(stats)
    print(f"result_png    {result_paths.png_path}")
    print(f"result_md     {result_paths.md_path}")
    return 0


def process_dir(args: argparse.Namespace) -> int:
    input_dir = Path(args.input_dir).resolve()
    files = collect_input_files(input_dir, args.pattern, args.recursive)
    if not files:
        raise FileNotFoundError(f"no files matched in {input_dir} with pattern {args.pattern}")

    db = FingerprintDb(args.db_path)
    stats_list: list[ProcessStats] = []
    try:
        hot_table_loaded = 0
        hot_table_refreshes = 0
        if args.load_hot_table:
            with FpgaUdpClient(
                fpga_ip=args.fpga_ip,
                host_ip=args.host_ip,
                port=args.port,
                timeout=args.timeout,
            ) as client:
                hot_table_loaded = reload_hot_table(args, db, client)
                hot_table_refreshes = 1

        for file_path in files:
            print(f"\n=== processing {file_path.name} ===")
            stats = process_one_file(args, file_path, db, load_hot_table=False)
            if stats.hot_table_loaded == 0:
                stats.hot_table_loaded = hot_table_loaded
            stats.hot_table_refreshes += hot_table_refreshes
            print_stats(stats)
            stats_list.append(stats)
    finally:
        db.close()

    result_paths = build_result_paths(args.result_dir, args.result_tag)
    write_result_tables(stats_list, result_paths, args)
    print(f"\nresult_png    {result_paths.png_path}")
    print(f"result_md     {result_paths.md_path}")
    return 0


def load_hot_table(args: argparse.Namespace) -> int:
    db = FingerprintDb(args.db_path)
    try:
        hot_digests = db.get_hot_digests(args.limit)
    finally:
        db.close()

    with FpgaUdpClient(
        fpga_ip=args.fpga_ip,
        host_ip=args.host_ip,
        port=args.port,
        timeout=args.timeout,
    ) as client:
        if not args.no_clear:
            client.clear_hot_table()
            print("cleared hot table")

        for slot, (digest, ref_count) in enumerate(hot_digests):
            client.write_hot_digest(slot, digest)
            print(f"slot={slot:04d} ref_count={ref_count} digest={digest.hex()}")

    print(f"loaded {len(hot_digests)} hot digest(s)")
    return 0


def clear_hot_table(args: argparse.Namespace) -> int:
    with FpgaUdpClient(
        fpga_ip=args.fpga_ip,
        host_ip=args.host_ip,
        port=args.port,
        timeout=args.timeout,
    ) as client:
        client.clear_hot_table()
    print("cleared hot table")
    return 0


def write_hot_digest(args: argparse.Namespace) -> int:
    try:
        digest = bytes.fromhex(args.digest_hex)
    except ValueError as exc:
        raise SystemExit(f"invalid --digest-hex: {exc}") from exc

    with FpgaUdpClient(
        fpga_ip=args.fpga_ip,
        host_ip=args.host_ip,
        port=args.port,
        timeout=args.timeout,
    ) as client:
        client.write_hot_digest(args.slot, digest)

    print(f"wrote slot={args.slot} digest={digest.hex()}")
    return 0


def list_runs(args: argparse.Namespace) -> int:
    db = FingerprintDb(args.db_path)
    try:
        runs = db.list_file_runs(args.limit)
    finally:
        db.close()

    print("run_id  chunks  bytes      mode   created_at           source_path")
    for run in runs:
        print(
            f"{run.id:<7} {run.chunk_count:<7} {run.total_bytes:<10} "
            f"{run.chunk_mode:<6} {run.created_at:<19} {run.source_path}"
        )
    return 0


def restore_file(args: argparse.Namespace) -> int:
    if args.run_id is None and args.source_path is None:
        raise SystemExit("restore-file requires --run-id or --source-path")
    if args.run_id is not None and args.source_path is not None:
        raise SystemExit("use only one of --run-id or --source-path")

    db = FingerprintDb(args.db_path)
    try:
        if args.run_id is not None:
            file_run = db.get_file_run(args.run_id)
        else:
            source_path = str(Path(args.source_path).resolve())
            file_run = db.get_latest_file_run(source_path)
        chunks = db.get_run_chunks(file_run.id)
    finally:
        db.close()

    if len(chunks) != file_run.chunk_count:
        raise ValueError(
            f"run {file_run.id} expected {file_run.chunk_count} chunk event(s), got {len(chunks)}"
        )

    chunk_dir = Path(args.write_dir).resolve() / "chunks"
    output_path = Path(args.output_file).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    restored_bytes = 0

    with output_path.open("wb") as output:
        for chunk in chunks:
            chunk_path = chunk_dir / f"{chunk.digest.hex()}.bin"
            if not chunk_path.exists():
                raise FileNotFoundError(f"missing chunk data file: {chunk_path}")
            data = chunk_path.read_bytes()
            if len(data) != chunk.chunk_length:
                raise ValueError(
                    f"chunk {chunk.chunk_index} length mismatch: "
                    f"metadata={chunk.chunk_length}, file={len(data)}"
                )
            output.write(data)
            restored_bytes += len(data)

    if restored_bytes != file_run.total_bytes:
        raise ValueError(
            f"restored byte count mismatch: metadata={file_run.total_bytes}, restored={restored_bytes}"
        )

    print(f"restored_run  {file_run.id}")
    print(f"source_file   {file_run.source_path}")
    print(f"output_file   {output_path}")
    print(f"bytes         {restored_bytes}")
    print(f"chunks        {len(chunks)}")
    return 0


def process_kv_file(args: argparse.Namespace) -> int:
    input_path = Path(args.input_file).resolve()
    data = input_path.read_bytes()
    if args.tokens_per_page <= 0:
        raise ValueError("tokens_per_page must be > 0")
    if args.bytes_per_token <= 0:
        raise ValueError("bytes_per_token must be > 0")

    page_size = args.tokens_per_page * args.bytes_per_token
    pages = list(fixed_size_chunks(data, page_size))
    shape = args.shape or (
        f"bytes={len(data)},tokens_per_page={args.tokens_per_page},"
        f"bytes_per_token={args.bytes_per_token}"
    )

    db = FingerprintDb(args.db_path)
    stats = ProcessStats(
        input_path=str(input_path),
        chunk_mode="kv-page",
        fixed_size=page_size,
        total_bytes=len(data),
        digest_mode=args.digest_mode,
        fragment_size=args.fragment_size,
    )
    try:
        stats.run_id = db.create_kv_run(
            source_path=str(input_path),
            request_id=args.request_id,
            model_id=args.model_id,
            total_bytes=len(data),
            page_count=len(pages),
            tokens_per_page=args.tokens_per_page,
            bytes_per_token=args.bytes_per_token,
            dtype=args.dtype,
            shape=shape,
        )

        with FpgaUdpClient(
            fpga_ip=args.fpga_ip,
            host_ip=args.host_ip,
            port=args.port,
            timeout=args.timeout,
            max_data_len=args.fragment_size,
        ) as client:
            next_seq_id = args.start_seq
            start_total = perf_counter()
            for page in pages:
                hash_result, next_seq_id, fpga_seconds, verify_seconds = hash_logical_chunk(
                    args=args,
                    client=client,
                    seq_id=next_seq_id,
                    data=page.data,
                )
                stats.fpga_seconds += fpga_seconds
                stats.verify_seconds += verify_seconds
                stats.fragment_hashes += hash_result.fragment_count
                if hash_result.fragment_count > 1:
                    stats.large_chunks += 1

                db_t0 = perf_counter()
                record = db.record_digest(
                    digest=hash_result.digest,
                    chunk_length=page.length,
                    source_path=f"kv://{args.request_id}",
                    chunk_index=page.index,
                    chunk_offset=page.offset,
                    run_id=None,
                )
                db.record_kv_page(
                    run_id=stats.run_id,
                    request_id=args.request_id,
                    model_id=args.model_id,
                    layer_id=args.layer_id,
                    kv_kind=args.kv_kind,
                    head_group=args.head_group,
                    page_index=page.index,
                    token_start=page.index * args.tokens_per_page,
                    token_count=(page.length + args.bytes_per_token - 1) // args.bytes_per_token,
                    dtype=args.dtype,
                    shape=shape,
                    page_length=page.length,
                    digest=hash_result.digest,
                    is_duplicate=record.is_duplicate,
                )
                stats.db_seconds += perf_counter() - db_t0

                stats.total_chunks += 1
                if record.is_duplicate:
                    stats.duplicate_chunks += 1
                else:
                    stats.unique_chunks += 1
                    write_t0 = perf_counter()
                    stats.written_unique_bytes += write_unique_chunk(
                        args.write_dir,
                        hash_result.digest,
                        page.data,
                    )
                    stats.write_seconds += perf_counter() - write_t0

                if args.print_pages:
                    status = "dup" if record.is_duplicate else "new"
                    print(
                        f"kv_page={page.index:04d} layer={args.layer_id} kind={args.kv_kind} "
                        f"head_group={args.head_group} token_start={page.index * args.tokens_per_page} "
                        f"tokens={((page.length + args.bytes_per_token - 1) // args.bytes_per_token)} "
                        f"len={page.length} frags={hash_result.fragment_count} {status} "
                        f"digest={hash_result.digest.hex()}"
                    )

            stats.elapsed_seconds = perf_counter() - start_total
    finally:
        db.close()

    print("kv_run        " + str(stats.run_id))
    print(f"request_id    {args.request_id}")
    print(f"model_id      {args.model_id}")
    print(f"layer_id      {args.layer_id}")
    print(f"kv_kind       {args.kv_kind}")
    print(f"head_group    {args.head_group}")
    print(f"bytes         {stats.total_bytes}")
    print(f"pages         {stats.total_chunks}")
    print(f"unique        {stats.unique_chunks}")
    print(f"duplicate     {stats.duplicate_chunks}")
    print(f"write_bytes   {stats.written_unique_bytes}")
    print(f"digest_mode   {stats.digest_mode}")
    print(f"fragment_size {stats.fragment_size}")
    print(f"fragments     {stats.fragment_hashes}")
    print(f"large_pages   {stats.large_chunks}")
    print(f"avg_fragments {stats.avg_fragments_per_chunk:.4f}")
    print(f"elapsed_s     {stats.elapsed_seconds:.4f}")
    print(f"fpga_s        {stats.fpga_seconds:.4f}")
    print(f"db_s          {stats.db_seconds:.4f}")
    print(f"write_s       {stats.write_seconds:.4f}")
    return 0


def restore_kv(args: argparse.Namespace) -> int:
    if args.run_id is None and args.request_id is None:
        raise SystemExit("restore-kv requires --run-id or --request-id")
    if args.run_id is not None and args.request_id is not None:
        raise SystemExit("use only one of --run-id or --request-id")

    db = FingerprintDb(args.db_path)
    try:
        if args.run_id is not None:
            kv_run = db.get_kv_run(args.run_id)
        else:
            kv_run = db.get_latest_kv_run(args.request_id)
        pages = db.get_kv_pages(kv_run.id)
    finally:
        db.close()

    if len(pages) != kv_run.page_count:
        raise ValueError(
            f"KV run {kv_run.id} expected {kv_run.page_count} page(s), got {len(pages)}"
        )

    chunk_dir = Path(args.write_dir).resolve() / "chunks"
    output_path = Path(args.output_file).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    restored_bytes = 0
    with output_path.open("wb") as output:
        for page in pages:
            chunk_path = chunk_dir / f"{page.digest.hex()}.bin"
            if not chunk_path.exists():
                raise FileNotFoundError(f"missing KV block file: {chunk_path}")
            block = chunk_path.read_bytes()
            if len(block) != page.page_length:
                raise ValueError(
                    f"KV page {page.page_index} length mismatch: "
                    f"metadata={page.page_length}, file={len(block)}"
                )
            output.write(block)
            restored_bytes += len(block)

    if restored_bytes != kv_run.total_bytes:
        raise ValueError(
            f"restored KV byte count mismatch: metadata={kv_run.total_bytes}, restored={restored_bytes}"
        )

    print(f"restored_kv_run {kv_run.id}")
    print(f"request_id      {kv_run.request_id}")
    print(f"model_id        {kv_run.model_id}")
    print(f"source_file     {kv_run.source_path}")
    print(f"output_file     {output_path}")
    print(f"bytes           {restored_bytes}")
    print(f"pages           {len(pages)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.command == "process-file":
        return process_file(args)
    if args.command == "process-dir":
        return process_dir(args)
    if args.command == "load-hot-table":
        return load_hot_table(args)
    if args.command == "clear-hot-table":
        return clear_hot_table(args)
    if args.command == "write-hot-digest":
        return write_hot_digest(args)
    if args.command == "list-runs":
        return list_runs(args)
    if args.command == "restore-file":
        return restore_file(args)
    if args.command == "process-kv-file":
        return process_kv_file(args)
    if args.command == "restore-kv":
        return restore_kv(args)
    parser.error(f"unsupported command: {args.command}")
    return 2
