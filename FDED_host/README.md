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
