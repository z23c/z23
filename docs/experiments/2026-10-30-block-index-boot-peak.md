# Block-index flat load: boot memory peak

Date: 2026-10-30
Compiler: cc (Ubuntu 14.2.0-4ubuntu2~24.04.1) 14.2.0
CPU: AMD Ryzen 9 7950X3D 16-Core Processor

## Question

`load_block_index_flat` maps the whole flat index file (172 B per row) and
builds a `struct block_index` arena (216 B per row) while it reads the rows.
Both are resident at the same time. On a 4 GB Android device the boot
transient sets the process high-water mark, so any resident flat-file pages
that are no longer needed raise it.

## Change

Both row passes (`bil_flat_insert_rows`, `bil_flat_link_rows`) read the mapping
front to back. Every 64K rows each pass now calls
`platform_read_mapping_release_below`, which applies `madvise(MADV_DONTNEED)`
to the page-aligned prefix already consumed. The mapping stays valid: the link
pass faults the pages it needs back in from the file, one 64K-row window at a
time. The 48-byte embedded integrity header sits at the start of the file
(`payload_off=48`), so the first release drops its page; that page was already
copied, so the release is harmless. The anchor trailer after the rows lies beyond
the row region and is never released. Rows, order and error handling are
unchanged.

`posix_madvise(POSIX_MADV_DONTNEED)` is a no-op in glibc and is not used.
Non-Linux builds keep the previous behaviour.

Readers of the mapping that were preserved: the insert pass, the link pass,
and the anchor trailer applied after both (`mapping.data + input.expected`).
`block_index_flat_save_inplace` and the flat probe open their own descriptors
and mappings and do not share this one.

## Measurement

`test_block_index_loader` case `bil_flat_boot_peak_case` writes a flat file of
`ZCL_BLOCK_INDEX_PEAK_ROWS` rows (default 140000) in a forked child, then loads
it in a second forked child and prints
`[peak] flat load rows=<n> growth_kib=<k>`, where `growth_kib` is the child's
`VmHWM` after the load minus its `VmRSS` before it. The case fails if the child
does not load every row or does not link each row to its height-1 parent.

Rerun:

```sh
ZCL_BLOCK_INDEX_PEAK_ROWS=1000000 devbuild --wait make -j16 t-fast ONLY=block_index_loader
```

Rows: 1,000,000 (file 172 MB). Three runs each on one host, same fixture generator.

| Loader | Run 1 (KiB) | Run 2 (KiB) | Run 3 (KiB) | Mean (MiB) |
|---|---|---|---|---|
| parent (`origin/main`) | 396148 | 396700 | 396176 | 387.0 |
| released prefix | 234616 | 234992 | 234232 | 229.1 |

Peak growth falls by 157.9 MiB (40.8 percent), against the 164 MiB of
mapped rows; the remainder is the arena and the
hash table. The parent loader's logs are `old{1,2,3}.log` and the new loader's
are `new{1,2,3}.log`, kept outside the repository.

Scaled linearly to the 3.3 M rows of the production index this is about
520 MiB less peak. The
Android figure is not measured here.
