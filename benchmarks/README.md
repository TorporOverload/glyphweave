# GlyphWeave Benchmark Suite

This benchmark suite measures data from six dimensions, writes raw data (`results/raw/*.csv` + `*.txt`) and creates Figures based on the raw data (`results/figures/*.pdf` + `*.png`). The benchmarks are organized into six categories:

## Setup
- `uv sync --group bench`
- WinFsp installed.

## Run everything
`uv run python -m benchmarks.run_all`

## run on a large corpus
`uv run python -m benchmarks.run_all --only search --latency-corpus "path/to/corpus-large"`

## single benchmarks
- `uv run python -m benchmarks.run_all --only fuse,unlock`
- `uv run python -m benchmarks.bench_vault_unlock`
- `--quick` shrinks sizes/repeats for a smoke run.

## Benchmarks
1. `bench_fuse_throughput`: MB/s vs file size, in-process + real mount, escalates to failure.
2. `bench_search_latency`: latency vs corpus size (persisted, resumable vault); times hit queries plus zero-result "miss" queries borrowed from `labels.json` (verified empty at run time).
3. `bench_vault_unlock`: KDF/bootstrap breakdown + KDF sweep + first mount.
4. `bench_concurrent_access`: max concurrency at 100% correctness (escalates to failure).
5. `bench_search_accuracy`: precision/recall/MAP + specificity, by scope & script; PR curve rendered via scikit-learn (`PrecisionRecallDisplay`).
6. `bench_db_size`: on-disk footprint vs corpus size: vault decomposed into blobs / DB snapshot / events / metadata (stacked to the vault total), the live working database (`vault.db`), and storage-overhead ratios vs raw corpus bytes.