# Sub-second holdings read baseline

Copyright 2026 Rhett Creighton – Apache License 2.0.

## Intention

Make the existing vault surface answer canonical ZCL and ZSLP holdings without
mixing token units, and establish a bounded RPC primitive for observing a
co-located legacy wallet. Canonical and legacy custody remain separate; no
combined balance is claimed.

## Environment

- Local time: `2026-08-29T21:21:20-04:00`
- UTC: `2026-08-30T01:21:20+00:00`
- Compiler: `cc (GCC) 16.1.1 20260430`
- CPU: `AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics`
- Base commit: `c11dce87600afcbef9368ce8c0de4779e6221410`

## Result

One hundred warm `build/bin/z23 vault list` process invocations against the
running local node completed with 87.229 ms median, 97.128 ms p99, 98.030 ms
maximum, and 87.179 ms mean wall latency. The running legacy wallet's
`z_gettotalbalance` call completed in 14.235 ms and returned transparent
`0.00999662`, private `0.0197`, total `0.02969662` ZCL.

The canonical token projection now emits one bounded item per token ID with
base units, UTXO count, ticker, name, and decimals. It does not emit a
cross-token zatoshi total. Missing metadata, an unbuilt ledger, or more than 64
held token IDs produces an explicit undetermined result instead of a partial
or false zero.

The legacy RPC transport now accepts an explicit 1–60000 ms send/receive
budget while its existing API retains the five-second compatibility default.
This is a prerequisite for a foreground-independent legacy observation cache;
the current change does not claim a complete legacy ZSLP inventory.

## Verification

- C23 node build: PASS
- `make -j16 t-fast ONLY=vault_read`: 1/1 PASS, 0 skips
- `make -j16 t-fast ONLY=vault_dispatch`: 1/1 PASS, 0 skips
- `make -j16 t-fast ONLY=test_rpc`: 7/7 PASS, 0 skips
- `make lint-fast`: 23 gates PASS
- `make check-api-reference-generated`: PASS

