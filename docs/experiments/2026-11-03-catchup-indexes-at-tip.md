<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Catch-up pass rate with node.db's indexes kept at tip

Date: 2026-11-03, run 13:34Z to 13:53Z
Compiler: cc (Ubuntu 14.2.0-4ubuntu2~24.04.1) 14.2.0, `-O3 -march=x86-64-v3 -g -std=c23`
CPU: AMD Ryzen 9 7950X3D 16-Core Processor, Linux 6.8.0-139-generic, shared `devbuild` slot
SQLite: 3.49.0 (vendored)

## Question

A catch-up pass over more than `NODE_DB_CATCHUP_BULK_THRESHOLD` (50000)
blocks used to run in turbo mode whenever it ran: it dropped node.db's 19
secondary indexes, set `synchronous=OFF` and rebuilt the indexes at the end.
On a node that serves its tip, wallet, explorer and recovery queries read
node.db while that pass runs. The pass now asks the registered main_state:
when `is_initial_block_download()` is false, the pass keeps the indexes and
`synchronous=NORMAL`. Boot replay and tools, which register no main_state,
keep turbo mode. This record measures what keeping the indexes costs.

## Method

The attached harness,
[`2026-11-03-catchup-indexes-at-tip-measure.patch`](./2026-11-03-catchup-indexes-at-tip-measure.patch),
adds a bench to the `node_db_catchup_service` group that runs instead of the
tests when `NDC_BENCH_DIR` is set.

- It writes 60000 synthetic blocks to block files under `NDC_BENCH_DIR`. Each
  block has 8 transactions with 4 P2PKH outputs each, and each
  non-coinbase transaction spends output 0 of the transaction before it.
- For each node.db location (`NDC_BENCH_DIR` and `NDC_BENCH_DB_DIR`), it
  opens a fresh node.db per mode and times two calls of
  `node_db_catchup_service_run` with the monotonic clock:
  - walk 1 indexes heights 1 to 60000 into the empty node.db;
  - walk 2 deletes the projection tip key and walks the same heights again
    over the existing rows.
- Mode `turbo` registers no main_state, as boot replay does. Mode
  `indexes-kept` registers a main_state whose tip reads as current, so
  `is_initial_block_download()` is false.
- Turbo times include the end-of-pass rebuild of the 19 indexes. Every walk
  ends with all 19 indexes in `sqlite_master`.

Block files were on tmpfs in both cases. node.db was on tmpfs
(`/dev/shm`) in the first row pair and on ext4 on NVMe (88% full) in the
second. Other writers were active on the host during the disk rows, so
those rows are noisy.

Rerun from the commit that adds this record:

```sh
git apply docs/experiments/2026-11-03-catchup-indexes-at-tip-measure.patch
mkdir -p /dev/shm/claude-catchup-bench "$DISK_DIR"
NDC_BENCH_DIR=/dev/shm/claude-catchup-bench NDC_BENCH_DB_DIR="$DISK_DIR" \
  devbuild --wait --project z23 make t-fast-exact ONLY=node_db_catchup_service \
  T_FAST_EXACT_ARGS=--no-cache
```

## Results

Raw output of one run, with the disk directory written as `$DISK_DIR`:

```text
catchup-bench: built=1 blocks=60000 txs=8 outs=4 ms=1155
catchup-bench: db=/dev/shm/claude-catchup-bench mode=turbo walk=1 blocks=60000 ms=14946 blk_per_s=4014 indexes=19
catchup-bench: db=/dev/shm/claude-catchup-bench mode=turbo walk=2 blocks=60000 ms=23870 blk_per_s=2514 indexes=19
catchup-bench: db=/dev/shm/claude-catchup-bench mode=indexes-kept walk=1 blocks=60000 ms=25862 blk_per_s=2320 indexes=19
catchup-bench: db=/dev/shm/claude-catchup-bench mode=indexes-kept walk=2 blocks=60000 ms=31199 blk_per_s=1923 indexes=19
catchup-bench: db=$DISK_DIR mode=turbo walk=1 blocks=60000 ms=104452 blk_per_s=574 indexes=19
catchup-bench: db=$DISK_DIR mode=turbo walk=2 blocks=60000 ms=82467 blk_per_s=728 indexes=19
catchup-bench: db=$DISK_DIR mode=indexes-kept walk=1 blocks=60000 ms=395646 blk_per_s=152 indexes=19
catchup-bench: db=$DISK_DIR mode=indexes-kept walk=2 blocks=60000 ms=426736 blk_per_s=141 indexes=19
```

| node.db on | Walk | Turbo (before) | Indexes kept (after) | After / before |
|---|---|---|---|---|
| tmpfs | 1, empty node.db | 4014 blk/s | 2320 blk/s | 0.58 |
| tmpfs | 2, existing rows | 2514 blk/s | 1923 blk/s | 0.76 |
| ext4 on NVMe | 1, empty node.db | 574 blk/s | 152 blk/s | 0.26 |
| ext4 on NVMe | 2, existing rows | 728 blk/s | 141 blk/s | 0.19 |

## Conclusion

Keeping the indexes costs 1.3 to 1.7 times the pass time with node.db in
memory, and 3.8 to 5.2 times on disk, where index pages and `fsync` dominate.
Initial block download keeps turbo mode, so only a node that is already
serving its tip and falls more than 50000 blocks behind in node.db pays
this cost. In exchange, its queries keep their indexes for the whole pass.

## Next experiment

Measure an indexes-kept pass with a larger page cache. A larger WAL
autocheckpoint was not tried: it widens the power-loss window for the
wallet rows that node.db also holds.
