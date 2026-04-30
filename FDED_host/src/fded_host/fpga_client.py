from __future__ import annotations

import hashlib
import socket
import struct
from dataclasses import dataclass
from typing import Optional

from .config import (
    EXPECTED_REPLY_LEN,
    SEQ_ID_LEN,
    STATUS_ERROR,
    STATUS_HOT_HIT,
    STATUS_LEN,
    STATUS_MISS,
)


@dataclass(frozen=True)
class HashReply:
    seq_id: int
    status: int
    digest: bytes

    @property
    def hot_hit(self) -> bool:
        return self.status == STATUS_HOT_HIT


class FpgaUdpClient:
    def __init__(
        self,
        fpga_ip: str,
        host_ip: str,
        port: int,
        timeout: float = 5.0,
        max_data_len: int = 1468,
    ) -> None:
        self.fpga_ip = fpga_ip
        self.host_ip = host_ip
        self.port = port
        self.timeout = timeout
        self.max_data_len = max_data_len
        self.sock: Optional[socket.socket] = None

    def __enter__(self) -> "FpgaUdpClient":
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(self.timeout)
        self.sock.bind((self.host_ip, self.port))
        self.drain_socket()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def drain_socket(self) -> int:
        if self.sock is None:
            raise RuntimeError("socket is not open")
        drained = 0
        old_timeout = self.sock.gettimeout()
        self.sock.settimeout(0.0)
        try:
            while True:
                try:
                    self.sock.recvfrom(4096)
                    drained += 1
                except (BlockingIOError, socket.timeout):
                    break
        finally:
            self.sock.settimeout(old_timeout)
        return drained

    def hash_chunk(self, seq_id: int, payload: bytes) -> HashReply:
        if self.sock is None:
            raise RuntimeError("socket is not open")
        if len(payload) > self.max_data_len:
            raise ValueError(
                f"payload length {len(payload)} exceeds max_data_len {self.max_data_len}"
            )

        request = struct.pack(">I", seq_id) + payload
        self.sock.sendto(request, (self.fpga_ip, self.port))
        reply, _ = self.sock.recvfrom(4096)

        if len(reply) != EXPECTED_REPLY_LEN:
            raise ValueError(
                f"expected {EXPECTED_REPLY_LEN}B FPGA reply, got {len(reply)}B"
            )

        reply_seq = struct.unpack(">I", reply[:SEQ_ID_LEN])[0]
        status = reply[SEQ_ID_LEN]
        digest_offset = SEQ_ID_LEN + STATUS_LEN
        digest = reply[digest_offset:]
        if reply_seq != seq_id:
            raise ValueError(
                f"expected reply seq_id 0x{seq_id:08x}, got 0x{reply_seq:08x}"
            )
        if status == STATUS_ERROR:
            raise ValueError(f"FPGA returned error status for seq_id 0x{seq_id:08x}")
        if status not in (STATUS_MISS, STATUS_HOT_HIT):
            raise ValueError(
                f"unknown FPGA status 0x{status:02x} for seq_id 0x{seq_id:08x}"
            )
        return HashReply(seq_id=reply_seq, status=status, digest=digest)

    @staticmethod
    def expected_digest(payload: bytes) -> bytes:
        return hashlib.sha256(payload).digest()
