# ADR-0009: File-size baseline raises for the native-portability wave

- **Status:** Accepted 2026-08-26.
- **Deciders:** Project maintainer.
- **Related:**
  [`0006-always-sync-spine-file-size-raises.md`](./0006-always-sync-spine-file-size-raises.md),
  [`0008-seed-floor-declaration-file-size-raises.md`](./0008-seed-floor-declaration-file-size-raises.md),
  `tools/scripts/file_size_ceiling_baseline.txt`,
  `tools/scripts/file_size_ceiling_lib_drift_count.txt`.

---

## Context

The E1 file-size ceiling (`tools/scripts/check_file_size_ceiling.sh`)
ratchets both of its tiers: the ENFORCED tier (`app/` + `config/src/`)
per-file, and the WARN tier (`lib/`/`domain/`/`src/`) by violation count.
Raising either requires an ADR.

The native-build work landed on 2026-08-26 — chiefly the macOS portability
merge 91eb601a0 ("build: run z23 natively on macOS") plus the hot-swap
integrity lane 168b25bb5 ("hotswap: check a module before running it ...")
— crossed several ratchet lines. Because those commits were pushed while
the gate viewed a different tree shape than the one they produced, tip
`386b6746c` fails `check-file-size-ceiling` as committed; every later push
inherits that failure until it is reconciled.

### ENFORCED tier (per-file records)

Newly oversized (recorded at current LOC, the gate's last resort):

| File | LOC |
| --- | --- |
| `app/services/src/package_lifecycle.c` | 803 |
| `config/src/boot_background_workers.c` | 801 |
| `config/src/consensus_state_snapshot_export.c` | 803 |

Grew past recorded baselines (records raised):

| File | Was | Now | Δ |
| --- | --- | --- | --- |
| `app/services/src/build_fabric_worker.c` | 860 | 877 | +17 |
| `config/src/boot.c` | 4278 | 4280 | +2 |
| `config/src/boot_index.c` | 851 | 854 | +3 |
| `config/src/boot_mint_anchor.c` | 808 | 809 | +1 |

All enforced-tier movement traces to 91eb601a0's platform branches
(macOS build variants and runtime guards added wholesale inside existing
units rather than behind per-platform seams).

### WARN tier (count valve)

91eb601a0 grew 27 baselined lib/domain files past their recorded lines
and hot-swap work added two new oversized ones
(`lib/hotswap/src/hotswap_elf_probe.c`, `lib/session/src/agent_broker.c`),
so drift = 29 against a recorded ceiling of 22. Reviewed and accepted:
`file_size_ceiling_lib_drift_count.txt` raised 22 → 29. Per-file WARN
prints stay visible; tightening opportunities listed by the gate output
remain open for future shrink-only passes.

---

## Decision

Accept the drift described above as one reviewable step: three new
enforced records, four enforced raises, and the warn-tier count raise.
This is reconciliation with already-pushed reality, not license for new
growth: every touched record remains shrink-only going forward, and the
next content touch to any of these files should reduce its line count,
never extend it.

## Consequences

- `make lint` / the pre-push gate pass again on trees built from tip.
- The ratchet bit-shape is unchanged; only recorded numbers move once.
- Future macOS/Windows platform additions should prefer per-platform seam
  files over inline branches so this does not recur.
