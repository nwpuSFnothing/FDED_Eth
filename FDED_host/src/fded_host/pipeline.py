from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from time import perf_counter
from typing import Iterable

from .chunker import Chunk, fastcdc_chunks, fixed_size_chunks
from .config import (
    DEFAULT_AVG_CHUNK_SIZE,
    DEFAULT_DB_PATH,
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

    @property
    def duplicate_ratio(self) -> float:
        if self.total_chunks == 0:
            return 0.0
        return self.duplicate_chunks / self.total_chunks


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
    process.add_argument("--start-seq", type=lambda value: int(value, 0), default=1)
    process.add_argument("--verify-local", action="store_true")
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
    process_dir.add_argument("--start-seq", type=lambda value: int(value, 0), default=1)
    process_dir.add_argument("--verify-local", action="store_true")
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


def process_one_file(args: argparse.Namespace, input_path: Path, db: FingerprintDb) -> ProcessStats:
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
    )

    start_total = perf_counter()
    chunk_t0 = perf_counter()
    chunks = list(iter_chunks(args, input_path, data))
    chunk_t1 = perf_counter()
    stats.chunk_seconds = chunk_t1 - chunk_t0

    with FpgaUdpClient(
        fpga_ip=args.fpga_ip,
        host_ip=args.host_ip,
        port=args.port,
        timeout=args.timeout,
        max_data_len=args.max_size,
    ) as client:
        for chunk in chunks:
            seq_id = args.start_seq + chunk.index
            fpga_t0 = perf_counter()
            reply = client.hash_chunk(seq_id, chunk.data)
            fpga_t1 = perf_counter()
            stats.fpga_seconds += fpga_t1 - fpga_t0
            if args.verify_local:
                verify_t0 = perf_counter()
                local_digest = client.expected_digest(chunk.data)
                if reply.digest != local_digest:
                    raise ValueError(
                        f"chunk {chunk.index} digest mismatch between FPGA and local hashlib"
                    )
                verify_t1 = perf_counter()
                stats.verify_seconds += verify_t1 - verify_t0

            db_t0 = perf_counter()
            record = db.record_digest(
                digest=reply.digest,
                chunk_length=chunk.length,
                source_path=str(input_path),
                chunk_index=chunk.index,
                chunk_offset=chunk.offset,
            )
            db_t1 = perf_counter()
            stats.db_seconds += db_t1 - db_t0
            stats.total_chunks += 1
            if record.is_duplicate:
                stats.duplicate_chunks += 1
            else:
                stats.unique_chunks += 1
                write_t0 = perf_counter()
                written = write_unique_chunk(args.write_dir, reply.digest, chunk.data)
                write_t1 = perf_counter()
                stats.write_seconds += write_t1 - write_t0
                stats.written_unique_bytes += written

            if args.print_chunks:
                status = "dup" if record.is_duplicate else "new"
                print(
                    f"chunk={chunk.index:04d} offset={chunk.offset:08d} "
                    f"len={chunk.length:04d} seq=0x{seq_id:08x} {status} "
                    f"ref_count={record.ref_count} digest={reply.digest.hex()}"
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
        handle.write(f"- `fpga_ip`: `{args.fpga_ip}`\n")
        handle.write(f"- `host_ip`: `{args.host_ip}`\n")
        handle.write(f"- `port`: `{args.port}`\n")
        handle.write(f"- `timeout`: `{args.timeout}`\n")
        handle.write(f"- `verify_local`: `{args.verify_local}`\n\n")
        handle.write(f"- `write_dir`: `{args.write_dir}`\n\n")
        handle.write("## Results\n\n")
        handle.write("| input_path | bytes | chunks | unique | duplicate | unique_write_bytes | duplicate_ratio | elapsed_s | read_s | chunk_s | fpga_s | verify_s | db_s | write_s |\n")
        handle.write("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")
        for stats in stats_list:
            handle.write(
                f"| {stats.input_path} | {stats.total_bytes} | {stats.total_chunks} | "
                f"{stats.unique_chunks} | {stats.duplicate_chunks} | {stats.written_unique_bytes} | "
                f"{stats.duplicate_ratio:.4f} | {stats.elapsed_seconds:.4f} | "
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
        f"max={args.max_size} fpga={args.fpga_ip}:{args.port} write={args.write_dir}"
    )
    headers = ["file", "bytes", "chunks", "unique", "dup", "write_B", "dup_ratio", "elapsed_s", "fpga_s", "db_s", "write_s"]
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
    print(f"file          {stats.input_path}")
    print(f"bytes         {stats.total_bytes}")
    print(f"chunks        {stats.total_chunks}")
    print(f"unique        {stats.unique_chunks}")
    print(f"duplicate     {stats.duplicate_chunks}")
    print(f"write_bytes   {stats.written_unique_bytes}")
    print(f"dup_ratio     {stats.duplicate_ratio:.4f}")
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
        for file_path in files:
            print(f"\n=== processing {file_path.name} ===")
            stats = process_one_file(args, file_path, db)
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
    parser.error(f"unsupported command: {args.command}")
    return 2
