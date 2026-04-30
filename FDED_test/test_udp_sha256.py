import argparse
import hashlib
import socket
import struct
import sys
from typing import Iterable, List, Optional, Sequence, Tuple

# python test_udp_sha256.py --suite



DEFAULT_FPGA_IP = "192.168.0.2"
DEFAULT_HOST_IP = "192.168.0.3"
DEFAULT_PORT = 8080
SEQ_ID_LEN = 4
MAX_UDP_PAYLOAD_LEN = 55
MAX_DATA_LEN = MAX_UDP_PAYLOAD_LEN - SEQ_ID_LEN
STATUS_LEN = 1
DIGEST_LEN = 32
EXPECTED_REPLY_LEN = SEQ_ID_LEN + STATUS_LEN + DIGEST_LEN
FLUSH_SEQ_ID = 0xFFFFFFFF
STATUS_MISS = 0x00
STATUS_HOT_HIT = 0x01
STATUS_ERROR = 0x80


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send UDP payload with seq_id to FPGA and verify returned SHA-256 digest."
    )
    parser.add_argument("--fpga-ip", default=DEFAULT_FPGA_IP)
    parser.add_argument("--host-ip", default=DEFAULT_HOST_IP)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--message", default=None)
    parser.add_argument("--hex", dest="hex_payload", default=None)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--suite", action="store_true")
    parser.add_argument("--list-cases", action="store_true")
    parser.add_argument(
        "--pipeline-lag",
        type=int,
        default=0,
        choices=(0, 1),
        help="Use 1 if FPGA returns the previous request's result.",
    )
    return parser.parse_args()


def build_payload(message: Optional[str], hex_payload: Optional[str]) -> bytes:
    if hex_payload is not None:
        try:
            payload = bytes.fromhex(hex_payload)
        except ValueError as exc:
            raise SystemExit(f"Invalid --hex payload: {exc}") from exc
    else:
        if message is None:
            message = "abc"
        payload = message.encode("utf-8")

    if len(payload) > MAX_DATA_LEN:
        raise SystemExit(
            f"Payload too long: {len(payload)} bytes. "
            f"Current protocol supports <= {MAX_DATA_LEN} data bytes "
            f"(4B seq_id + data <= {MAX_UDP_PAYLOAD_LEN}B)."
        )
    return payload


def get_suite_cases() -> List[Tuple[str, bytes]]:
    return [
        ("abc", b"abc"),
        ("single_zero", b"\x00"),
        ("empty", b""),
        ("hello", b"hello"),
        ("ascii_sentence", b"OpenAI FPGA SHA256"),
        ("binary_00_07", bytes(range(8))),
        ("len_51_A", b"A" * 51),
    ]


def format_payload_preview(payload: bytes) -> str:
    if len(payload) <= 32:
        return payload.hex()
    return f"{payload[:32].hex()}...({len(payload)}B)"


def build_request(seq_id: int, payload: bytes) -> bytes:
    return struct.pack(">I", seq_id) + payload


def parse_reply(reply: bytes) -> Tuple[int, int, bytes]:
    if len(reply) != EXPECTED_REPLY_LEN:
        raise ValueError(
            f"expected {EXPECTED_REPLY_LEN}B reply, got {len(reply)}B"
        )
    seq_id = struct.unpack(">I", reply[:SEQ_ID_LEN])[0]
    status = reply[SEQ_ID_LEN]
    digest = reply[SEQ_ID_LEN + STATUS_LEN:]
    return seq_id, status, digest


def expected_digest(payload: bytes) -> bytes:
    return hashlib.sha256(payload).digest()


def drain_socket(sock: socket.socket) -> int:
    drained = 0
    old_timeout = sock.gettimeout()
    sock.settimeout(0.0)
    try:
        while True:
            try:
                sock.recvfrom(2048)
                drained += 1
            except (BlockingIOError, socket.timeout):
                break
    finally:
        sock.settimeout(old_timeout)
    return drained


def recv_reply(sock: socket.socket) -> Optional[Tuple[bytes, Tuple[str, int]]]:
    try:
        return sock.recvfrom(2048)
    except socket.timeout:
        return None


def print_expected(seq_id: int, payload: bytes) -> None:
    print(f"seq    0x{seq_id:08x}")
    print(f"send   {len(payload)}B data")
    print(f"data   {format_payload_preview(payload)}")
    print(f"expect {expected_digest(payload).hex()}")


def verify_reply(
    expected_seq_id: int,
    expected_payload: bytes,
    reply: bytes,
    addr: Tuple[str, int],
) -> bool:
    print(f"recv   {len(reply)}B <- {addr[0]}:{addr[1]}")
    try:
        reply_seq_id, reply_status, reply_digest = parse_reply(reply)
    except ValueError as exc:
        print(f"result fail: {exc}")
        return False

    print(f"r-seq  0x{reply_seq_id:08x}")
    print(f"status 0x{reply_status:02x}")
    print(f"digest {reply_digest.hex()}")

    if reply_seq_id != expected_seq_id:
        print(
            f"result fail: expected seq 0x{expected_seq_id:08x}, got 0x{reply_seq_id:08x}"
        )
        return False

    if reply_status == STATUS_ERROR:
        print("result fail: FPGA returned error status")
        return False

    if reply_status not in (STATUS_MISS, STATUS_HOT_HIT):
        print(f"result fail: unknown FPGA status 0x{reply_status:02x}")
        return False

    if reply_digest != expected_digest(expected_payload):
        print("result fail: digest mismatch")
        return False

    print("result pass: seq and digest matched")
    return True


def one_test_direct(
    sock: socket.socket,
    fpga_ip: str,
    port: int,
    seq_id: int,
    payload: bytes,
    label: Optional[str] = None,
) -> bool:
    if label is not None:
        print(f"case   {label}")
    print_expected(seq_id, payload)
    sock.sendto(build_request(seq_id, payload), (fpga_ip, port))

    recv_result = recv_reply(sock)
    if recv_result is None:
        print("result timeout waiting for FPGA reply")
        return False

    reply, addr = recv_result
    return verify_reply(seq_id, payload, reply, addr)


def one_test_lag1(
    sock: socket.socket,
    fpga_ip: str,
    port: int,
    seq_id: int,
    payload: bytes,
    flush_seq_id: int,
    label: Optional[str] = None,
) -> bool:
    if label is not None:
        print(f"case   {label}")
    print_expected(seq_id, payload)
    sock.sendto(build_request(seq_id, payload), (fpga_ip, port))

    first_recv = recv_reply(sock)
    if first_recv is None:
        print("result timeout waiting for primer reply")
        return False

    stale_reply, stale_addr = first_recv
    print(f"prime  {len(stale_reply)}B <- {stale_addr[0]}:{stale_addr[1]}")
    try:
        stale_seq_id, stale_status, stale_digest = parse_reply(stale_reply)
        print(f"p-seq  0x{stale_seq_id:08x}")
        print(f"p-sts  0x{stale_status:02x}")
        print(f"p-dig  {stale_digest.hex()}")
    except ValueError as exc:
        print(f"prime  invalid reply: {exc}")

    sock.sendto(build_request(flush_seq_id, b""), (fpga_ip, port))
    second_recv = recv_reply(sock)
    if second_recv is None:
        print("result timeout waiting for aligned reply")
        return False

    reply, addr = second_recv
    return verify_reply(seq_id, payload, reply, addr)


def run_repeat(args: argparse.Namespace, payload: bytes) -> int:
    pass_count = 0

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(args.timeout)
        sock.bind((args.host_ip, args.port))
        drained = drain_socket(sock)
        if drained:
            print(f"drain  cleared {drained} queued packet(s)")

        for idx in range(args.repeat):
            seq_id = idx + 1
            if args.repeat > 1:
                print(f"\n=== test {idx + 1}/{args.repeat} ===")
            if args.pipeline_lag == 1:
                ok = one_test_lag1(
                    sock=sock,
                    fpga_ip=args.fpga_ip,
                    port=args.port,
                    seq_id=seq_id,
                    payload=payload,
                    flush_seq_id=FLUSH_SEQ_ID - idx,
                )
            else:
                ok = one_test_direct(
                    sock=sock,
                    fpga_ip=args.fpga_ip,
                    port=args.port,
                    seq_id=seq_id,
                    payload=payload,
                )
            if ok:
                pass_count += 1

    print(f"\nsummary {pass_count}/{args.repeat} passed")
    return 0 if pass_count == args.repeat else 1


def run_suite_direct(args: argparse.Namespace, cases: Sequence[Tuple[str, bytes]]) -> int:
    pass_count = 0
    total = len(cases)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(args.timeout)
        sock.bind((args.host_ip, args.port))
        drained = drain_socket(sock)
        if drained:
            print(f"drain  cleared {drained} queued packet(s)")

        for idx, (label, payload) in enumerate(cases, start=1):
            print(f"\n=== case {idx}/{total} ===")
            ok = one_test_direct(
                sock=sock,
                fpga_ip=args.fpga_ip,
                port=args.port,
                seq_id=idx,
                payload=payload,
                label=label,
            )
            if ok:
                pass_count += 1

    print(f"\nsuite summary {pass_count}/{total} passed")
    return 0 if pass_count == total else 1


def run_suite_lag1(args: argparse.Namespace, cases: Sequence[Tuple[str, bytes]]) -> int:
    pass_count = 0
    total = len(cases)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(args.timeout)
        sock.bind((args.host_ip, args.port))
        drained = drain_socket(sock)
        if drained:
            print(f"drain  cleared {drained} queued packet(s)")

        first_label, first_payload = cases[0]
        print("\n=== primer ===")
        print(f"case   {first_label}")
        print_expected(1, first_payload)
        sock.sendto(build_request(1, first_payload), (args.fpga_ip, args.port))

        primer_recv = recv_reply(sock)
        if primer_recv is None:
            print("result timeout waiting for primer reply")
            print(f"\nsuite summary {pass_count}/{total} passed")
            return 1

        stale_reply, stale_addr = primer_recv
        print(f"prime  {len(stale_reply)}B <- {stale_addr[0]}:{stale_addr[1]}")
        try:
            stale_seq_id, stale_status, stale_digest = parse_reply(stale_reply)
            print(f"p-seq  0x{stale_seq_id:08x}")
            print(f"p-sts  0x{stale_status:02x}")
            print(f"p-dig  {stale_digest.hex()}")
        except ValueError as exc:
            print(f"prime  invalid reply: {exc}")

        for idx in range(1, total):
            next_label, next_payload = cases[idx]
            expect_label, expect_payload = cases[idx - 1]
            expected_seq_id = idx

            print(f"\n=== case {idx}/{total} ===")
            print(f"case   {expect_label}")
            print(f"next   {next_label}")
            print(f"n-seq  0x{idx + 1:08x}")
            print(f"n-data {format_payload_preview(next_payload)}")
            print(f"expect {expected_digest(expect_payload).hex()}")

            sock.sendto(build_request(idx + 1, next_payload), (args.fpga_ip, args.port))
            recv_result = recv_reply(sock)
            if recv_result is None:
                print("result timeout waiting for FPGA reply")
                continue

            reply, addr = recv_result
            ok = verify_reply(expected_seq_id, expect_payload, reply, addr)
            if ok:
                pass_count += 1

        print(f"\n=== case {total}/{total} ===")
        print(f"case   {cases[-1][0]}")
        print(f"flush  seq=0x{FLUSH_SEQ_ID:08x}")
        sock.sendto(build_request(FLUSH_SEQ_ID, b""), (args.fpga_ip, args.port))
        last_recv = recv_reply(sock)
        if last_recv is None:
            print("result timeout waiting for FPGA reply")
        else:
            reply, addr = last_recv
            ok = verify_reply(total, cases[-1][1], reply, addr)
            if ok:
                pass_count += 1

    print(f"\nsuite summary {pass_count}/{total} passed")
    return 0 if pass_count == total else 1


def run_suite(args: argparse.Namespace, cases: Sequence[Tuple[str, bytes]]) -> int:
    if args.pipeline_lag == 1:
        return run_suite_lag1(args, cases)
    return run_suite_direct(args, cases)


def print_cases(cases: Iterable[Tuple[str, bytes]]) -> None:
    for label, payload in cases:
        print(f"{label:16} len={len(payload):2d} hex={format_payload_preview(payload)}")


def main() -> int:
    args = parse_args()
    cases = get_suite_cases()

    if args.list_cases:
        print_cases(cases)
        return 0

    if args.suite:
        return run_suite(args, cases)

    payload = build_payload(args.message, args.hex_payload)
    return run_repeat(args, payload)


if __name__ == "__main__":
    sys.exit(main())
