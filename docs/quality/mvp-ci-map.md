# MVP CI map — each MVP.md criterion → its mechanical check → status

AGENTS.md P1 priority: **CI-enforce the MVP criteria.** This document is the
mapping behind `make mvp` (the reporter, `tools/scripts/mvp_scoreboard.sh`).

`make mvp` prints an HONEST 8/8 scoreboard. For each of the 8 operator
acceptance criteria in [`docs/MVP.md`](../MVP.md) it runs the ONE
mechanically-runnable check that proves it and prints a per-criterion verdict
line: **PASS / FAIL / BLOCKED(reason)**.

## The contract (cannot false-green)

- **PASS** is earned ONLY when the criterion's check actually RAN and PASSED
  at the **full operator-claim** level. The MRS counts only these.
- **BLOCKED(reason)** — the criterion's full claim REQUIRES a resource that is
  absent: a **synced running node**, **Tor egress**, **`~/.zcash-params`**, or
  a **live `zclassicd` oracle**. The hermetic slice may still run as evidence,
  but the criterion is reported BLOCKED — **never silently skipped-as-pass,
  never green.**
- **FAIL** — a check that is *supposed* to pass (a hermetic slice) regressed,
  OR the false-green guard fired (a `ZCL_TEST_ONLY` selector vanished, so the
  focused subset's sentinel was not printed / the run timed out). A FAIL is
  printed loudly and counted in the summary.

The three **synced-node-dependent** criteria — **C3** (cold-start sync to tip),
**C6** (168h soak), **C8** (consensus parity over the soak window) — CANNOT
pass until the node holds a clean synced tip on the **sovereign foundation** and
accrues a clean window. Re-run this reporter against the live node
(`zcl-rpc getblockchaininfo`, `z23 status`) rather than trusting a
pinned verdict here — no hermetic slice can stand in for "a fresh node
reached the real ~3.15M-block tip in <10min" or "168h clean wall-clock". The
reporter probes the live node: when `blocks != headers` (not at tip) the
synced-node criteria are BLOCKED with the live height named in the reason.

`make mvp` is a **status reporter, not a build gate** — it exits 0 even with
BLOCKED criteria (the honest state of a node not yet past a resource gate),
so it is wired into `make ci` as a VISIBLE report without breaking the build.
The build-FATAL regression protection for the hermetic slices lives in
`make ci-mvp-gates` (already in `make ci`); the scoreboard's FAIL is the
human-readable echo of the same regression.

## The map

| # | MVP.md criterion | Mechanical check `make mvp` runs | Full-claim resource |
|---|---|---|---|
| C1 | Single-binary install on clean Ubuntu/Debian | `ci_symbol_floor_gate.sh` (portability GLIBC/GLIBCXX/CXXABI floor) + built-binary existence | full claim = real `make install` + `systemctl --user start` → `make ci-install-linger` (a `mvp-verify` member) |
| C2 | Tor onion bootstrap in <60s | `test_zcl` slice `ZCL_TEST_ONLY=onion_slice` (<60s budget + v3 address format) + Tor-egress probe | real <60s over Tor needs egress → `make mvp-onion-local` |
| C3 | Cold-start sync to tip in <10 min | `test_zcl` slice `ZCL_TEST_ONLY=cold_start` (sync FSM → at_tip, ~7s) | real <10min sync to the ~3.15M-block tip needs a serving peer + a **fresh** node → `make mvp-coldstart-to-tip-local` / `make mvp-coldstart-to-tip-stopwatch` (see `FORWARD_PLAN.md` #1 item 1) |
| C4 | Receive shielded payment end-to-end | `test_zcl` slices `shielded_receive` + `shielded_receive_persist` (params-free RECEIVE half: note→ivk→z-balance→durable reopen) + `~/.zcash-params` probe | full Groth16 t→z send+decrypt needs ~770MB proving params → `make test-shielded-payment` |
| C5 | List + sell file via store | `test_zcl` slices `store_e2e` + `store_e2e_shielded` (in-process store + seeded note + ivk-decrypt + memo-bound) | full list→shielded-pay→.onion file transfer needs a live serving node + a real buyer (see `FORWARD_PLAN.md` §B) |
| C6 | 7-day soak, zero operator intervention | `soak_evidence.sh judge` over accumulated samples (MET=PASS, NOT_MET=FAIL, INSUFFICIENT=BLOCKED), GATED on the live node being synced+accruing | 168h clean wall-clock with gap ≤1, exact same-height hash, complete security posture, continuous evidence, and no intervention — judge with `make soak-evidence-report` |
| C7 | Recover from kill -9 in <2 min | `test_zcl` slices `kill9` (node.db SIGKILL UTXO-atomicity) + `chain_advance_atomicity` | full-binary kill-9 → peer-tip recovery → `make test-crash-bootstrap` + `make test-two-node-peer-tip` (mvp-verify members; isolated regtest, no synced mainnet needed) |
| C8 | Consensus parity with zclassicd | `test_zcl` slice `parity_slice` (mismatch-detection machinery: consistent set→0, injected outpoint→DETECTED) | 0 byte-mismatches vs a live `zclassicd` oracle over the soak window; needs an EXACT reference (`gettxoutsetinfo` is height-only) + the soak window |

Run `make mvp` or `tools/mvp_gate.sh` for the current PASS/FAIL/BLOCKED verdict
per criterion — never trust a pinned verdict in this file.

## Current scoreboard

Run `make mvp` for the current numbers — the live MRS, per-criterion
PASS/FAIL/BLOCKED, and the soak judge verdict are not duplicated here.

## How the false-green guard works

Each hermetic slice runs FOCUSED via `ZCL_TEST_ONLY=<selector>` under
`ZCL_STRESS_TESTS=1`, with the SAME guard `make ci-mvp-gates` uses: `test.c`
returns early ONLY on a selector match, printing a unique sentinel
(`=== <name> subset complete: N failure(s) ===`). If the selector is
renamed/removed, the FULL suite runs instead and the sentinel is NOT printed
— `run_slice` turns that into a loud **FAIL**, not a fake PASS. A 120s
per-slice timeout bounds the call so a vanished selector can't run the
multi-minute full suite (or hang on the non-hermetic onion test); a timeout
also maps to FAIL. (Verified: pointing C8 at a bogus selector reports C8 FAIL,
MRS unchanged at 4/8, FAIL=1 — never green.)

## Files

- `tools/scripts/mvp_scoreboard.sh` — the reporter (run by `make mvp`).
- `tools/scripts/cold_start_to_tip_probe.sh` — the full C3 local proof harness.
  Every run, including setup SKIPs and sync seams, writes
  `build/c3-probe/<run>/proof.json` plus `summary.txt` and the probe log tail;
  `build/c3-probe/latest.txt` points at the newest evidence directory.
- `Makefile` target `mvp` — `make mvp`; also invoked as a visible non-fatal
  report at the end of `make ci`.
- `docs/MVP.md` — the 8 criteria (source of truth for the claims).
- `Makefile` target `ci-mvp-gates` — the build-FATAL hermetic slice gates
  (the regression floor; the scoreboard's PASS/FAIL echoes these).
