from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class ManagedKvBlock:
    id: int
    digest: bytes
    ref_count: int
    hot_score: float = 0.0


@dataclass(frozen=True)
class KvAccessResult:
    unique_block_id: int
    source: str
    gpu_hit: bool
    host_cache_hit: bool
    cold_restore: bool
    fpga_hot_hit: bool
    hot_score: float
    gpu_evicted: int | None = None
    host_evicted: int | None = None


@dataclass
class KvBlockRuntimeStats:
    accesses: int = 0
    gpu_hits: int = 0
    host_cache_hits: int = 0
    cold_restores: int = 0
    gpu_promotions: int = 0
    gpu_evictions: int = 0
    host_evictions: int = 0
    fpga_hot_hits: int = 0
    hot_table_refreshes: int = 0
    gpu_allocated_bytes: int = 0
    gpu_reserved_bytes: int = 0

    @property
    def gpu_hit_ratio(self) -> float:
        if self.accesses == 0:
            return 0.0
        return self.gpu_hits / self.accesses

    @property
    def host_cache_hit_ratio(self) -> float:
        if self.accesses == 0:
            return 0.0
        return self.host_cache_hits / self.accesses

    @property
    def fpga_hot_hit_ratio(self) -> float:
        if self.accesses == 0:
            return 0.0
        return self.fpga_hot_hits / self.accesses


class KvBlockManager:
    """Pure-Python KV block manager model for GPU/Host/Cold placement."""

    def __init__(
        self,
        blocks: list[ManagedKvBlock],
        gpu_pages: int,
        host_cache_pages: int,
        fpga_hot_limit: int,
        hot_refresh_interval: int,
        policy: str,
        gpu_backend: str = "simulate",
        gpu_page_bytes: int = 4096,
        cuda_device: str = "cuda:0",
    ) -> None:
        if gpu_pages <= 0:
            raise ValueError("gpu_pages must be > 0")
        if host_cache_pages <= 0:
            raise ValueError("host_cache_pages must be > 0")
        if hot_refresh_interval <= 0:
            raise ValueError("hot_refresh_interval must be > 0")
        if fpga_hot_limit < 0:
            raise ValueError("fpga_hot_limit must be >= 0")
        if gpu_page_bytes <= 0:
            raise ValueError("gpu_page_bytes must be > 0")

        self.gpu_pages = gpu_pages
        self.host_cache_pages = host_cache_pages
        self.fpga_hot_limit = fpga_hot_limit
        self.hot_refresh_interval = hot_refresh_interval
        self.policy = policy
        self.gpu_page_bytes = gpu_page_bytes
        self.gpu_backend = create_gpu_backend(gpu_backend, gpu_page_bytes, cuda_device)
        self.stats = KvBlockRuntimeStats()

        self.block_stats: dict[int, dict[str, object]] = {}
        for block in blocks:
            self.block_stats[block.id] = {
                "digest": block.digest,
                "ref_count": block.ref_count,
                "access_count": 0,
                "last_access_step": 0,
                "hot_score": block.hot_score,
            }

        self.gpu_pool: dict[int, dict[str, object]] = {}
        self.host_cache: dict[int, dict[str, object]] = {}
        self.fpga_hot_digests: set[bytes] = set()

    def access(self, block: ManagedKvBlock, step: int) -> KvAccessResult:
        if self.stats.accesses % self.hot_refresh_interval == 0:
            self.refresh_fpga_hot_table()

        gpu_hit = block.id in self.gpu_pool
        host_cache_hit = block.id in self.host_cache
        fpga_hot_hit = block.digest in self.fpga_hot_digests
        source = "GPU_PAGE"
        gpu_evicted = None
        host_evicted = None

        if gpu_hit:
            self.stats.gpu_hits += 1
        elif host_cache_hit:
            self.stats.host_cache_hits += 1
            self.stats.gpu_promotions += 1
            source = "HOST_CACHE->GPU_PAGE"
        else:
            self.stats.cold_restores += 1
            self.stats.gpu_promotions += 1
            source = "COLD_FILE->GPU_PAGE"

        if not gpu_hit:
            gpu_evicted, host_evicted = self._promote_to_gpu(block.id)

        if fpga_hot_hit:
            self.stats.fpga_hot_hits += 1

        item = self.block_stats[block.id]
        access_count = int(item["access_count"]) + 1
        score = self._hot_score(
            access_count=access_count,
            ref_count=int(item["ref_count"]),
            last_access_step=int(item["last_access_step"]),
            current_step=step,
        )
        item["access_count"] = access_count
        item["last_access_step"] = step
        item["hot_score"] = score
        gpu_handle = self.gpu_pool[block.id].get("gpu_handle") if gpu_hit else self.gpu_backend.allocate(block.id)
        self.gpu_pool[block.id] = {
            "digest": block.digest,
            "access_count": access_count,
            "last_access_step": step,
            "hot_score": score,
            "gpu_handle": gpu_handle,
        }
        self.stats.gpu_allocated_bytes = self.gpu_backend.allocated_bytes()
        self.stats.gpu_reserved_bytes = self.gpu_backend.reserved_bytes()
        self.stats.accesses += 1

        return KvAccessResult(
            unique_block_id=block.id,
            source=source,
            gpu_hit=gpu_hit,
            host_cache_hit=host_cache_hit,
            cold_restore=not gpu_hit and not host_cache_hit,
            fpga_hot_hit=fpga_hot_hit,
            hot_score=score,
            gpu_evicted=gpu_evicted,
            host_evicted=host_evicted,
        )

    def refresh_fpga_hot_table(self) -> None:
        ranked = sorted(
            self.block_stats.values(),
            key=lambda item: (float(item["hot_score"]), int(item["ref_count"])),
            reverse=True,
        )
        self.fpga_hot_digests = {
            bytes(item["digest"]) for item in ranked[: self.fpga_hot_limit]
        }
        self.stats.hot_table_refreshes += 1

    def _promote_to_gpu(self, block_id: int) -> tuple[int | None, int | None]:
        gpu_evicted = None
        host_evicted = None
        if len(self.gpu_pool) >= self.gpu_pages:
            victim_id, victim = min(
                self.gpu_pool.items(),
                key=lambda item: float(item[1]["hot_score"]),
            )
            del self.gpu_pool[victim_id]
            self.gpu_backend.release(victim_id)
            self.stats.gpu_evictions += 1
            gpu_evicted = victim_id
            if victim_id not in self.host_cache:
                victim = {key: value for key, value in victim.items() if key != "gpu_handle"}
                host_evicted = self._insert_host_cache(victim_id, victim)

        if block_id in self.host_cache:
            del self.host_cache[block_id]
        return gpu_evicted, host_evicted

    def _insert_host_cache(self, block_id: int, state: dict[str, object]) -> int | None:
        host_evicted = None
        if len(self.host_cache) >= self.host_cache_pages:
            victim_id, _victim = min(
                self.host_cache.items(),
                key=lambda item: float(item[1]["hot_score"]),
            )
            del self.host_cache[victim_id]
            self.stats.host_evictions += 1
            host_evicted = victim_id
        self.host_cache[block_id] = state
        return host_evicted

    def _hot_score(
        self,
        access_count: int,
        ref_count: int,
        last_access_step: int,
        current_step: int,
    ) -> float:
        age = max(0, current_step - last_access_step)
        if self.policy == "lru":
            return float(last_access_step)
        if self.policy == "lfu":
            return float(access_count)
        return access_count * 4.0 + ref_count * 1.5 + last_access_step * 0.05 - age * 0.02


class GpuPageBackend(Protocol):
    def allocate(self, block_id: int) -> object:
        ...

    def release(self, block_id: int) -> None:
        ...

    def allocated_bytes(self) -> int:
        ...

    def reserved_bytes(self) -> int:
        ...


class SimulatedGpuBackend:
    def __init__(self, page_bytes: int) -> None:
        self.page_bytes = page_bytes
        self.pages: set[int] = set()

    def allocate(self, block_id: int) -> object:
        self.pages.add(block_id)
        return None

    def release(self, block_id: int) -> None:
        self.pages.discard(block_id)

    def allocated_bytes(self) -> int:
        return len(self.pages) * self.page_bytes

    def reserved_bytes(self) -> int:
        return self.allocated_bytes()


class TorchCudaGpuBackend:
    def __init__(self, page_bytes: int, device: str) -> None:
        try:
            import torch
        except ImportError as exc:
            raise RuntimeError("torch-cuda backend requires PyTorch to be installed") from exc
        if not torch.cuda.is_available():
            raise RuntimeError("torch-cuda backend requested, but torch.cuda.is_available() is False")

        self.torch = torch
        self.page_bytes = page_bytes
        self.device = device
        self.pages: dict[int, object] = {}

    def allocate(self, block_id: int) -> object:
        tensor = self.torch.empty((self.page_bytes,), dtype=self.torch.uint8, device=self.device)
        self.pages[block_id] = tensor
        return tensor

    def release(self, block_id: int) -> None:
        self.pages.pop(block_id, None)

    def allocated_bytes(self) -> int:
        return int(self.torch.cuda.memory_allocated())

    def reserved_bytes(self) -> int:
        return int(self.torch.cuda.memory_reserved())


def create_gpu_backend(
    backend: str,
    page_bytes: int,
    cuda_device: str,
) -> GpuPageBackend:
    if backend == "simulate":
        return SimulatedGpuBackend(page_bytes)
    if backend == "torch-cuda":
        return TorchCudaGpuBackend(page_bytes, cuda_device)
    raise ValueError(f"unsupported gpu_backend: {backend}")
