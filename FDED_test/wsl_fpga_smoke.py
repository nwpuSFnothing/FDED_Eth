#!/usr/bin/env python3
import argparse
import hashlib
import socket
import struct
import sys


DEFAULT_FPGA_IP = "192.168.0.2"
DEFAULT_BIND_IP = "0.0.0.0"
DEFAULT_PORT = 8080
EXPECTED_REPLY_LEN = 4 + 1 + 32
STATUS_NAMES = {
    0x00: "MISS",
    0x01: "HOT_HIT",
    0x02: "STREAM_ACK",
    0x80: "ERROR",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Minimal WSL UDP smoke test for the FPGA SHA-256 link."
    )
    parser.add_argument("--fpga-ip", default=DEFAULT_FPGA_IP)
    parser.add_argument("--bind-ip", default=DEFAULT_BIND_IP)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--message", default="abc")
    parser.add_argument("--hex", dest="hex_payload")
    parser.add_argument("--seq", type=lambda value: int(value, 0), default=1)
    parser.add_argument("--timeout", type=float, default=3.0)
    return parser.parse_args()


def make_payload(args: argparse.Namespace) -> bytes:
    if args.hex_payload is not None:
        try:
            return bytes.fromhex(args.hex_payload)
        except ValueError as exc:
            raise SystemExit(f"invalid --hex payload: {exc}") from exc
    return args.message.encode("utf-8")


def drain(sock: socket.socket) -> int:
    drained = 0
    old_timeout = sock.gettimeout()
    sock.settimeout(0.0)
    try:
        while True:
            try:
                sock.recvfrom(4096)
                drained += 1
            except (BlockingIOError, socket.timeout):
                return drained
    finally:
        sock.settimeout(old_timeout)


def parse_reply(reply: bytes) -> tuple[int, int, bytes]:
    if len(reply) != EXPECTED_REPLY_LEN:
        raise ValueError(f"expected {EXPECTED_REPLY_LEN} bytes, got {len(reply)}")
    seq = struct.unpack(">I", reply[:4])[0]
    status = reply[4]
    digest = reply[5:]
    return seq, status, digest


def main() -> int:
    args = parse_args()
    payload = make_payload(args)
    expected = hashlib.sha256(payload).digest()
    request = struct.pack(">I", args.seq) + payload

    print(f"bind   {args.bind_ip}:{args.port}")
    print(f"target {args.fpga_ip}:{args.port}")
    print(f"seq    0x{args.seq:08x}")
    print(f"send   {len(payload)}B")
    print(f"expect {expected.hex()}")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(args.timeout)
        sock.bind((args.bind_ip, args.port))
        drained = drain(sock)
        if drained:
            print(f"drain  {drained} stale packet(s)")

        sock.sendto(request, (args.fpga_ip, args.port))

        try:
            reply, addr = sock.recvfrom(4096)
        except socket.timeout:
            print("result timeout: no FPGA reply")
            return 1

    print(f"recv   {len(reply)}B <- {addr[0]}:{addr[1]}")
    try:
        reply_seq, status, digest = parse_reply(reply)
    except ValueError as exc:
        print(f"result fail: {exc}")
        print(f"raw    {reply.hex()}")
        return 1

    print(f"r-seq  0x{reply_seq:08x}")
    print(f"status 0x{status:02x} {STATUS_NAMES.get(status, 'UNKNOWN')}")
    print(f"digest {digest.hex()}")

    if reply_seq != args.seq:
        print("result fail: seq mismatch")
        return 1
    if status == 0x80:
        print("result fail: FPGA returned error status")
        return 1
    if digest != expected:
        print("result fail: digest mismatch")
        return 1

    print("result pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
