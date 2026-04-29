from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from fastcdc import fastcdc
@dataclass(frozen=True)
class Chunk:
    index: int
    offset: int
    data: bytes

    @property
    def length(self) -> int:
        return len(self.data)


def fixed_size_chunks(data: bytes, chunk_size: int) -> Iterator[Chunk]:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be > 0")
    index = 0
    for offset in range(0, len(data), chunk_size):
        yield Chunk(index=index, offset=offset, data=data[offset : offset + chunk_size])
        index += 1


def fastcdc_chunks(
    file_path: str,
    data: bytes,
    min_size: int,
    avg_size: int,
    max_size: int,
) -> Iterator[Chunk]:
    if not (0 < min_size <= avg_size <= max_size):
        raise ValueError("expected 0 < min_size <= avg_size <= max_size")

    for index, chunk in enumerate(fastcdc(file_path, min_size, avg_size, max_size)):
        offset = int(chunk.offset)
        length = int(chunk.length)
        yield Chunk(index=index, offset=offset, data=data[offset : offset + length])
