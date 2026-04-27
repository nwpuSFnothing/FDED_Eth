import argparse
import hashlib
import socket
import sys
from typing import Optional


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
        default="abc",
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
    return parser.parse_args()


def build_payload(message: str, hex_payload: Optional[str]) -> bytes:
    if hex_payload is not None:
        try:
            payload = bytes.fromhex(hex_payload)
        except ValueError as exc:
            raise SystemExit(f"Invalid --hex payload: {exc}") from exc
    else:
        payload = message.encode("utf-8")

    if len(payload) > MAX_PAYLOAD_LEN:
        raise SystemExit(
            f"Payload too long: {len(payload)} bytes. "
            f"Current FPGA design only supports <= {MAX_PAYLOAD_LEN} bytes."
        )

    return payload


def one_test(
    host_ip: str,
    fpga_ip: str,
    port: int,
    timeout: float,
    payload: bytes,
) -> bool:
    expected = hashlib.sha256(payload).digest()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.bind((host_ip, port))

        print(f"send   {len(payload)}B -> {fpga_ip}:{port}")
        print(f"data   {payload.hex()}")
        print(f"expect {expected.hex()}")

        sock.sendto(payload, (fpga_ip, port))

        try:
            reply, addr = sock.recvfrom(2048)
        except socket.timeout:
            print("result timeout waiting for FPGA reply")
            return False

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


def main() -> int:
    args = parse_args()
    payload = build_payload(args.message, args.hex_payload)

    pass_count = 0
    for idx in range(args.repeat):
        if args.repeat > 1:
            print(f"\n=== test {idx + 1}/{args.repeat} ===")
        ok = one_test(
            host_ip=args.host_ip,
            fpga_ip=args.fpga_ip,
            port=args.port,
            timeout=args.timeout,
            payload=payload,
        )
        if ok:
            pass_count += 1

    print(f"\nsummary {pass_count}/{args.repeat} passed")
    return 0 if pass_count == args.repeat else 1


if __name__ == "__main__":
    sys.exit(main())
