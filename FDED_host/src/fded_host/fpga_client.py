from __future__ import annotations

import hashlib
import socket
import struct
from dataclasses import dataclass
from typing import Iterable, Optional

from .config import (
    DIGEST_LEN,
    EXPECTED_REPLY_LEN,
    SEQ_ID_LEN,
    STATUS_ERROR,
    STATUS_HOT_HIT,
    STATUS_LEN,
    STATUS_MISS,
    STATUS_STREAM_ACK,
)

CTRL_MAGIC = b"FDED"
CTRL_MAGIC_SEQ = 0x46444544
CTRL_WRITE_SLOT = 0x10
CTRL_CLEAR = 0x11
CTRL_STREAM_START = 0x20
CTRL_STREAM_DATA = 0x21
CTRL_STREAM_END = 0x22
CTRL_STREAM_ABORT = 0x23
STREAM_HEADER_LEN = 13


@dataclass(frozen=True)
class HashReply:
    seq_id: int
    status: int
    digest: bytes

    @property
    def hot_hit(self) -> bool:
        return self.status == STATUS_HOT_HIT

    @property
    def stream_ack(self) -> bool:
        return self.status == STATUS_STREAM_ACK


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
        return self._parse_reply(reply, expected_seq_id=seq_id)

    def clear_hot_table(self) -> HashReply:
        return self._control_request(CTRL_MAGIC + bytes([CTRL_CLEAR]))

    def write_hot_digest(self, slot: int, digest: bytes) -> HashReply:
        if not (0 <= slot <= 0xFFFF):
            raise ValueError("slot must fit in 16 bits")
        if len(digest) != DIGEST_LEN:
            raise ValueError(f"digest must be {DIGEST_LEN} bytes")

        payload = (
            CTRL_MAGIC
            + bytes([CTRL_WRITE_SLOT])
            + struct.pack(">H", slot)
            + digest
        )
        return self._control_request(payload)

    def load_hot_table(self, digests: Iterable[bytes], clear: bool = True) -> int:
        if clear:
            self.clear_hot_table()

        loaded = 0
        for slot, digest in enumerate(digests):
            self.write_hot_digest(slot, digest)
            loaded += 1
        return loaded

    def hash_stream(self, stream_id: int, payload: bytes, fragment_size: int) -> HashReply:
        if self.sock is None:
            raise RuntimeError("socket is not open")
        if not (0 <= stream_id <= 0xFFFFFFFF):
            raise ValueError("stream_id must fit in 32 bits")
        if fragment_size <= 0:
            raise ValueError("fragment_size must be > 0")

        max_fragment_size = min(fragment_size, self.max_data_len - (STREAM_HEADER_LEN - SEQ_ID_LEN))
        if max_fragment_size <= 0:
            raise ValueError("fragment_size leaves no room for stream header")

        total_len = len(payload)
        offset = 0
        first_len = min(max_fragment_size, total_len)
        first = payload[offset : offset + first_len]
        offset += first_len

        reply = self._stream_request(CTRL_STREAM_START, stream_id, total_len, first, final=False)
        if not reply.stream_ack:
            raise ValueError(f"expected stream ACK for START, got status 0x{reply.status:02x}")

        if offset == total_len:
            return self._stream_request(CTRL_STREAM_END, stream_id, total_len, b"", final=True)

        while offset < total_len:
            part_len = min(max_fragment_size, total_len - offset)
            part = payload[offset : offset + part_len]
            offset += part_len
            is_final = offset == total_len
            op = CTRL_STREAM_END if is_final else CTRL_STREAM_DATA
            reply = self._stream_request(op, stream_id, total_len, part, final=is_final)
            if not is_final and not reply.stream_ack:
                raise ValueError(f"expected stream ACK for DATA, got status 0x{reply.status:02x}")
        return reply

    def _control_request(self, payload: bytes) -> HashReply:
        if self.sock is None:
            raise RuntimeError("socket is not open")

        self.sock.sendto(payload, (self.fpga_ip, self.port))
        reply, _ = self.sock.recvfrom(4096)
        return self._parse_reply(reply, expected_seq_id=CTRL_MAGIC_SEQ)

    def _stream_request(
        self,
        op: int,
        stream_id: int,
        total_len: int,
        data: bytes,
        final: bool,
    ) -> HashReply:
        if self.sock is None:
            raise RuntimeError("socket is not open")
        payload = (
            CTRL_MAGIC
            + bytes([op])
            + struct.pack(">II", stream_id, total_len)
            + data
        )
        if len(payload) > SEQ_ID_LEN + self.max_data_len:
            raise ValueError(
                f"stream packet length {len(payload)} exceeds max request length {SEQ_ID_LEN + self.max_data_len}"
            )
        self.sock.sendto(payload, (self.fpga_ip, self.port))
        reply, _ = self.sock.recvfrom(4096)
        parsed = self._parse_reply(reply, expected_seq_id=CTRL_MAGIC_SEQ)
        if final and parsed.stream_ack:
            raise ValueError("stream END returned ACK instead of final digest")
        return parsed

    def _parse_reply(self, reply: bytes, expected_seq_id: int) -> HashReply:
        if len(reply) != EXPECTED_REPLY_LEN:
            raise ValueError(
                f"expected {EXPECTED_REPLY_LEN}B FPGA reply, got {len(reply)}B"
            )

        reply_seq = struct.unpack(">I", reply[:SEQ_ID_LEN])[0]
        status = reply[SEQ_ID_LEN]
        digest_offset = SEQ_ID_LEN + STATUS_LEN
        digest = reply[digest_offset:]
        if reply_seq != expected_seq_id:
            raise ValueError(
                f"expected reply seq_id 0x{expected_seq_id:08x}, got 0x{reply_seq:08x}"
            )
        if status == STATUS_ERROR:
            raise ValueError(f"FPGA returned error status for seq_id 0x{expected_seq_id:08x}")
        if status not in (STATUS_MISS, STATUS_HOT_HIT, STATUS_STREAM_ACK):
            raise ValueError(
                f"unknown FPGA status 0x{status:02x} for seq_id 0x{expected_seq_id:08x}"
            )
        return HashReply(seq_id=reply_seq, status=status, digest=digest)

    @staticmethod
    def expected_digest(payload: bytes) -> bytes:
        return hashlib.sha256(payload).digest()
