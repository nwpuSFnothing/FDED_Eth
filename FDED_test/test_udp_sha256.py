import argparse
import hashlib
import socket
import sys
from typing import Iterable, List, Optional, Sequence, Tuple


DEFAULT_FPGA_IP = "192.168.0.2"
DEFAULT_HOST_IP = "192.168.0.3"
DEFAULT_PORT = 8080
MAX_PAYLOAD_LEN = 55
EXPECTED_DIGEST_LEN = 32


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send UDP payload to FPGA and verify returned SHA-256 digest."
    )
    parser.add_argument(
        "--fpga-ip",
        default=DEFAULT_FPGA_IP,
        help=f"FPGA destination IP, default: {DEFAULT_FPGA_IP}",
    )
    parser.add_argument(
        "--host-ip",
        default=DEFAULT_HOST_IP,
        help=f"Local host IP bound by the socket, default: {DEFAULT_HOST_IP}",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"UDP port for send/receive, default: {DEFAULT_PORT}",
    )
    parser.add_argument(
        "--message",
        default=None,
        help="ASCII message to send. Ignored if --hex is provided.",
    )
    parser.add_argument(
        "--hex",
        dest="hex_payload",
        default=None,
        help="Hex payload to send, for example: 616263",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Receive timeout in seconds, default: 3.0",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="Number of times to repeat the same test, default: 1",
    )
    parser.add_argument(
        "--suite",
        action="store_true",
        help="Run the built-in multi-case test suite.",
    )
    parser.add_argument(
        "--list-cases",
        action="store_true",
        help="List built-in suite cases and exit.",
    )
    parser.add_argument(
        "--pipeline-lag",
        type=int,
        default=0,
        choices=(0, 1),
        help="Compensate a fixed response lag. Use 1 if FPGA returns the previous payload digest.",
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

    if len(payload) > MAX_PAYLOAD_LEN:
        raise SystemExit(
            f"Payload too long: {len(payload)} bytes. "
            f"Current FPGA design only supports <= {MAX_PAYLOAD_LEN} bytes."
        )

    return payload


def get_suite_cases() -> List[Tuple[str, bytes]]:
    return [
        ("abc", b"abc"),
        ("single_zero", b"\x00"),
        ("hello", b"hello"),
        ("ascii_sentence", b"OpenAI FPGA SHA256"),
        ("binary_00_07", bytes(range(8))),
        ("binary_ff_desc", bytes([0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA])),
        ("len_55_A", b"A" * 55),
    ]


def format_payload_preview(payload: bytes) -> str:
    if len(payload) <= 32:
        return payload.hex()
    return f"{payload[:32].hex()}...({len(payload)}B)"


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


def recv_digest(sock: socket.socket) -> Optional[Tuple[bytes, Tuple[str, int]]]:
    try:
        return sock.recvfrom(2048)
    except socket.timeout:
        return None


def print_result(payload: bytes, reply: bytes, addr: Tuple[str, int]) -> bool:
    expected = hashlib.sha256(payload).digest()
    print(f"expect {expected.hex()}")
    print(f"recv   {len(reply)}B <- {addr[0]}:{addr[1]}")
    print(f"digest {reply.hex()}")

    if len(reply) != EXPECTED_DIGEST_LEN:
        print(
            f"result fail: expected {EXPECTED_DIGEST_LEN}B digest, got {len(reply)}B"
        )
        return False

    if reply != expected:
        print("result fail: digest mismatch")
        return False

    print("result pass: digest matched")
    return True


def one_test_direct(
    sock: socket.socket,
    fpga_ip: str,
    port: int,
    payload: bytes,
    label: Optional[str] = None,
) -> bool:
    if label is not None:
        print(f"case   {label}")
    print(f"send   {len(payload)}B -> {fpga_ip}:{port}")
    print(f"data   {format_payload_preview(payload)}")

    sock.sendto(payload, (fpga_ip, port))
    recv_result = recv_digest(sock)
    if recv_result is None:
        print("result timeout waiting for FPGA reply")
        return False

    reply, addr = recv_result
    return print_result(payload, reply, addr)


def one_test_lag1(
    sock: socket.socket,
    fpga_ip: str,
    port: int,
    payload: bytes,
    flush_payload: bytes,
    label: Optional[str] = None,
) -> bool:
    if label is not None:
        print(f"case   {label}")
    print(f"send   {len(payload)}B -> {fpga_ip}:{port}")
    print(f"data   {format_payload_preview(payload)}")

    sock.sendto(payload, (fpga_ip, port))
    first_recv = recv_digest(sock)
    if first_recv is None:
        print("result timeout waiting for primer reply")
        return False

    stale_reply, stale_addr = first_recv
    print(f"prime  {len(stale_reply)}B <- {stale_addr[0]}:{stale_addr[1]}")
    print(f"prime-digest {stale_reply.hex()}")

    sock.sendto(flush_payload, (fpga_ip, port))
    second_recv = recv_digest(sock)
    if second_recv is None:
        print("result timeout waiting for aligned reply")
        return False

    reply, addr = second_recv
    return print_result(payload, reply, addr)


def run_repeat(args: argparse.Namespace, payload: bytes) -> int:
    pass_count = 0
    flush_payload = b"\x00"

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(args.timeout)
        sock.bind((args.host_ip, args.port))
        drained = drain_socket(sock)
        if drained:
            print(f"drain  cleared {drained} queued packet(s)")

        for idx in range(args.repeat):
            if args.repeat > 1:
                print(f"\n=== test {idx + 1}/{args.repeat} ===")
            if args.pipeline_lag == 1:
                ok = one_test_lag1(
                    sock=sock,
                    fpga_ip=args.fpga_ip,
                    port=args.port,
                    payload=payload,
                    flush_payload=flush_payload,
                )
            else:
                ok = one_test_direct(
                    sock=sock,
                    fpga_ip=args.fpga_ip,
                    port=args.port,
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
    primer_label, primer_payload = cases[0]
    flush_payload = b"\x00"

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(args.timeout)
        sock.bind((args.host_ip, args.port))
        drained = drain_socket(sock)
        if drained:
            print(f"drain  cleared {drained} queued packet(s)")

        print("\n=== primer ===")
        print(f"case   {primer_label}")
        print(f"send   {len(primer_payload)}B -> {args.fpga_ip}:{args.port}")
        print(f"data   {format_payload_preview(primer_payload)}")
        sock.sendto(primer_payload, (args.fpga_ip, args.port))

        first_recv = recv_digest(sock)
        if first_recv is None:
            print("result timeout waiting for primer reply")
            print(f"\nsuite summary {pass_count}/{total} passed")
            return 1

        stale_reply, stale_addr = first_recv
        print(f"prime  {len(stale_reply)}B <- {stale_addr[0]}:{stale_addr[1]}")
        print(f"prime-digest {stale_reply.hex()}")

        for idx in range(1, total):
            next_label, next_payload = cases[idx]
            curr_label, curr_payload = cases[idx - 1]

            print(f"\n=== case {idx}/{total} ===")
            print(f"case   {curr_label}")
            print(f"send   {len(next_payload)}B -> {args.fpga_ip}:{args.port}")
            print(f"data   {format_payload_preview(next_payload)}")

            sock.sendto(next_payload, (args.fpga_ip, args.port))
            recv_result = recv_digest(sock)
            if recv_result is None:
                print("result timeout waiting for FPGA reply")
                continue

            reply, addr = recv_result
            ok = print_result(curr_payload, reply, addr)
            if ok:
                pass_count += 1

        print(f"\n=== case {total}/{total} ===")
        print(f"case   {cases[-1][0]}")
        print(f"send   {len(flush_payload)}B -> {args.fpga_ip}:{args.port}")
        print(f"data   {format_payload_preview(flush_payload)}")

        sock.sendto(flush_payload, (args.fpga_ip, args.port))
        last_recv = recv_digest(sock)
        if last_recv is None:
            print("result timeout waiting for FPGA reply")
        else:
            reply, addr = last_recv
            ok = print_result(cases[-1][1], reply, addr)
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
