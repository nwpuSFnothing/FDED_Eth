# FDED_host

Host-side Python project for:

- CDC chunking on the host
- UDP hashing requests to the FPGA
- sqlite3 fingerprint indexing

## Dependency

Install the FastCDC package first:

```bash
pip install fastcdc
```

## Structure

- `main.py`: CLI entry point
- `src/fded_host/chunker.py`: fixed-size and FastCDC chunkers
- `src/fded_host/fpga_client.py`: UDP client for the FPGA SHA-256 service
- `src/fded_host/fingerprint_db.py`: sqlite3 fingerprint index
- `src/fded_host/kv_block_manager.py`: pure-Python KV block manager model for GPU/Host/Cold placement
- `src/fded_host/pipeline.py`: file processing pipeline
- `data/fingerprints.db`: default sqlite database

## Quick Start

```bash
python main.py process-file sample.bin --fpga-ip 192.168.0.2 --host-ip 192.168.0.3
```

Use CDC mode:

```bash
python main.py process-file sample.bin --chunk-mode cdc --min-size 512 --avg-size 1024 --max-size 1468
```

Current default `max-size` is `1468`, matching the verified stable FPGA UDP payload limit for real hash data in your current setup.

The current `cdc` mode uses the `fastcdc` Python package directly.

## Hierarchical Digest Mode

The FPGA UDP path still hashes one payload per request. To test logical chunks larger than the stable UDP payload limit without changing the FPGA, use Host-side fragment aggregation:

```bash
python main.py process-file sample.bin --chunk-mode fixed --fixed-size 8192 --digest-mode hierarchical --fragment-size 1468
```

In `hierarchical` mode, chunks larger than `--fragment-size` are split on the Host. Each fragment is hashed by the FPGA, then the Host computes the logical chunk fingerprint as:

```text
SHA256("FDED_CHUNK_V1" + chunk_length + fragment_size + fragment_count + fragment_digest...)
```

Chunks that fit in one fragment keep the existing raw FPGA SHA-256 digest. This mode is intended for KVCache/page-level experiments where the logical page size should not be limited by Ethernet MTU.

## FPGA Stream Digest Mode

After rebuilding and downloading a bitstream that includes the stream protocol, use `fpga-stream` to make the FPGA compute the standard SHA-256 digest over the full logical chunk across multiple UDP packets:

```bash
python main.py process-file sample.bin --chunk-mode fixed --fixed-size 16384 --digest-mode fpga-stream --fragment-size 1468 --verify-local --print-chunks
```

In this mode, the Host sends `"FDED"` stream control packets:

```text
"FDED"[4B] + op[1B] + stream_id[4B] + total_len[4B] + data
```

The FPGA keeps SHA-256 state across `STREAM_START`, `STREAM_DATA`, and `STREAM_END`. The final digest returned by `STREAM_END` is expected to match `hashlib.sha256(full_chunk)`.

## KVCache Offline Simulation

Process a binary KVCache dump as structure-aware logical KV pages:

```bash
python main.py process-kv-file kv_dump.bin --request-id req001 --model-id llama-demo --layer-id 0 --kv-kind K --head-group 0 --tokens-per-page 16 --bytes-per-token 4096 --digest-mode hierarchical --fragment-size 1468 --verify-local --print-pages
```

Restore the logical KV page sequence from unique block storage:

```bash
python main.py restore-kv --request-id req001 --output-file restored_kv_dump.bin
```

This first offline mode has no NumPy dependency. It treats the input as a binary KV tensor dump and records page metadata in `kv_runs` and `kv_pages`, including request/model/layer/KV kind/head group/token range/digest. Later `.npz` or runtime integrations can reuse the same mapping tables.

## KVCache Runtime Simulation

The current prototype does not use CUDA or a real LLM runtime directly. It models the online indirection layer with a simulated GPU KV page pool:

```text
logical KV page -> unique KV block -> GPU_PAGE, HOST_CACHE, or COLD_FILE
```

After `process-kv-file`, run a trace-driven cache and hot-table simulation:

```bash
python main.py simulate-kv-runtime --request-id req001 --gpu-pages 16 --cache-pages 64 --fpga-hot-limit 512 --policy inference-hot
```

Without `--trace-file`, the simulator scans the recorded logical KV pages in order. Use `--repeat N` to replay the page sequence multiple times. A CSV trace can provide at least:

```text
step,page_index
0,0
1,1
2,0
```

The simulator records `kv_access_events` and updates `unique_kv_blocks.hot_score`. Each logical access must end in `GPU_PAGE`; misses are promoted from `HOST_CACHE` or restored from `COLD_FILE`. It reports:

- `gpu_hit_ratio`: simulated GPU KV page pool hits
- `host_hit_ratio`: simulated Host cache hits before GPU promotion
- `cold_restores`: logical page accesses restored from cold unique-block storage
- `fpga_hot_hit_ratio`: simulated hit ratio against the top scored digest set
- `gpu_evictions`: unique blocks removed from the simulated GPU page pool
- `host_evictions`: unique blocks removed from the simulated Host cache

By default, `GPU_PAGE` is simulated. To allocate real CUDA memory with PyTorch:

```bash
python main.py simulate-kv-runtime --request-id req001 --gpu-backend torch-cuda --gpu-pages 16 --gpu-page-bytes 65536 --cache-pages 64 --fpga-hot-limit 512
```

`--gpu-page-bytes` controls the number of CUDA bytes allocated per promoted KV block. This is still not a real LLM runtime integration, but the GPU page pool now uses actual CUDA tensors when `--gpu-backend torch-cuda` is selected.

## Hot Table Flow

Load the current sqlite top-N fingerprints into the FPGA hot digest table:

```bash
python main.py load-hot-table --db-path data/fingerprints.db --limit 512
```

Run an experiment and load the hot table before chunk processing starts:

```bash
python main.py process-file sample.bin --load-hot-table --hot-limit 512 --verify-hot-hit
```

Refresh the FPGA hot table periodically during processing:

```bash
python main.py process-file sample.bin --load-hot-table --hot-limit 512 --hot-refresh-interval-s 10
```

Useful counters in the console, Markdown, and PNG results:

- `fpga_hot_hits`: chunks reported as `HOT_HIT` by FPGA
- `host_lookups`: sqlite duplicate-decision lookups still performed by Host
- `lookup_saved`: sqlite duplicate-decision lookups skipped because FPGA returned `HOT_HIT`
- `hot_hit_ratio`: `fpga_hot_hits / chunks`
- `hot_loaded`: number of digests loaded into the FPGA hot table before processing
- `hot_refreshes`: number of hot table load/refresh operations

The FPGA hot table is updated only when Host sends control packets: `write-hot-digest`, `clear-hot-table`, `load-hot-table`, `process-file/process-dir --load-hot-table`, or a periodic refresh triggered by `--hot-refresh-interval-s`. Normal hash requests only query the table; they do not insert new digests by themselves.
