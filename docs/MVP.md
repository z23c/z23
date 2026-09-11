# z23 — MVP target

**MVP = "someone we don't know can run z23 + use it for a week
without intervention."** Eight binary acceptance criteria, each with
a verification target. The MVP Readiness Score (MRS) is the count of passing
criteria; MVP is achieved at 8/8.

`make commons-demo` runs the whole journey on one machine and writes what it
measured; `make commons-multihost-acceptance` runs it across two machines and
then takes the publisher offline.

![what the commons demo measured](assets/z23-term-commons-proof.svg)

Read the conditions with the numbers: two isolated nodes, a regtest chain, one
peer over the node's own authenticated overlay — not a swarm, not the open
internet. Both nodes share a physical host, so this is node independence, not
hardware independence.

## Acceptance criteria

| # | Criterion | How we verify | Status |
|---|---|---|---|
| 1 | **Single-binary install on clean Ubuntu/Debian** | Target: clean container, `make install && systemctl --user start zclassic23`, exit 0 — **hermetic proxy: `make ci-install`** (not in the `make ci` target): drives the real `make install` (the two binaries + the systemd `--user` unit) to a throwaway `/tmp` prefix, starts ONE node FROM that prefix as a fully isolated regtest node (unique `/tmp` datadir + 39xxx non-live ports + `-connect=39999` dead sink, via the audited `tools/scripts/isolated_node_env.sh`), polls RPC readiness, asserts the installed binary answers + bound only non-live ports, and cleans up. Also in the one-command local aggregate `make mvp-verify` (locally-verified, not hermetic-✅). The clean-OS half of the claim is proven WITHOUT docker (docker is never used in this project). The portability floor is a **hermetic gate IN `make ci`**: **`make ci-symbol-floor`** (`tools/scripts/ci_symbol_floor_gate.sh`) statically asserts via `objdump -T`/`ldd` that every dep resolves and the binary's max required symbol in each family stays ≤ the one documented floor **`GLIBC_2.38`** (`tools/scripts/ci_symbol_floor_gate.sh:45`). The C++ ABI is not a second floor but an absence requirement: the gate asks for the max required symbol in the `GLIBCXX_` and `CXXABI_` families and fails if either answers at all (`ci_symbol_floor_gate.sh:86-89`), because this C23 node links no C++ runtime. So a regression that pulls a newer glibc symbol, or any C++ ABI symbol at all, fails the build loud. The FULL operator claim — a real `make install` + a real `systemctl --user start` bringing the installed binary up to serve RPC — passes via **`make ci-install-linger`** (`tools/scripts/ci_install_linger_gate.sh`): it `make install`s to a throwaway `/tmp` prefix, starts an **isolated linger unit `zclassic23-citest`** (distinct name / `/tmp` datadir / 3906x non-live ports / dead-sink connect / `-nolegacyimport`; torn down on exit; the live `zclassic23` unit is never touched), and asserts the unit is active + the installed binary answers `getblockcount`. No docker, ever. A `make mvp-verify` member. | ✅ |
| 2 | **Tor onion bootstrap in <60s** | `z23 core network onion status` returns `bootstrap_state=ready` within 60s of start — test: `tests/harness/src/test_onion_bootstrap.c` (`make ci-stress`; needs Tor egress; measured **53s** on a host with egress). The onion is live by hand but its <60s timing isn't measured by default CI. Also runnable via `make mvp-onion-local` (bundled in `make mvp-verify`), which probes for Tor egress and SKIPs cleanly when absent — locally-verified, not hermetic-✅. It needs real Tor network egress (an isolated runner without it would burn the 90s poll then fail), so it lives in `make ci-stress`, not the hermetic `make ci`. `make mvp-onion-local` (a `make mvp-verify` member) run-passes the full claim on this host — `onion_bootstrap MVP #2 bootstrap_state=ready in <60s` — the local operator proof. | ✅ |
| 3 | **Cold-start sync to tip in <10 min** | Fresh datadir → `z23 core sync status` reports `phase=ready` within 10 min on 100 Mbps link — test: `tests/harness/src/test_cold_start_sync.c` (**CI slice: `make ci-mvp-gates`** — drives the sync FSM to `at_tip` in ~7s; does **not** download/validate a real 3M-block chain). The assisted-seed sub-proof is `make mvp-coldstart-local`: fixture-gated operator bundle (`block_index.bin` + `utxo-seed-*.snapshot`), fresh `/tmp` datadir, `-load-snapshot-at-own-height`, and >1M UTXOs body-digest verified and installed in <90s (`make mvp-coldstart-local` passes the bundle seed-integrity proof in ~17s: `count=1344903`, body SHA3 OK). That proves byte integrity and operational seeding, not sovereign state provenance. The full C3 proof command is `make mvp-coldstart-to-tip-local`: same bundle, fresh datadir, dial a serving z23 peer, and reach that peer's captured tip within the 10-minute MVP budget. Legacy `consensus_snapshot.db` import remains only a checkpoint-height fallback; above-checkpoint peer snapshots are intentionally refused because there is no in-binary root. A snapshot-only node dialing a live serving peer does not reach `at_tip` on its own, because the snapshot import path sets `coins_best_block` without seeding `coins_kv` / `coins_applied_height`; the full tip-probe harness uses the bundle path to close that gap. The genuinely-wiped counterpart (no bundle, no snapshot flag at all — just the binary's own boot pipeline, `tools/scripts/cold_start_to_tip_stopwatch.sh` / `make mvp-coldstart-to-tip-stopwatch`) is the harness [`FORWARD_PLAN.md`](./work/FORWARD_PLAN.md) §5 item 1 names as the remaining gap: it wipes a `/tmp` datadir, dials a real serving peer, and gates on `dumpstate reducer_frontier`'s `hstar` reaching `network_tip` — never on "the FSM says at_tip" — printing a real `WALL_CLOCK_SECONDS=<n>` stopwatch on PASS (`ZCL_BIN=`/`ZCL_PEER=` override which binary/peer it times; SKIPs cleanly with no peer). On 2026-09-09 the harness ran end-to-end on this host three times (P2P peers 127.0.0.1:8033 + devfleet + soak, file service 127.0.0.1:18034): verdict SEAM every time — the ROM fold covers 0→~3.09M in ~150 s, then the remaining ~150k-block tail crawls at ~98 received bodies/s with a ~12% request-timeout rate on loopback, where ~420/s sustained is needed to make the budget. Peer count does not move the number (one peer and three peers produce the same signature), so this is a tail body-download throughput seam, not peer starvation; the tail-seam analysis lives in [`work/fresh-start-seam.md`](./work/fresh-start-seam.md). **Nothing outside prose records any of those 2026-09-09 runs**: the collector ledger (`~/.local/state/zclassic23-c3-stopwatch/history.jsonl`) holds no row of any verdict for 2026-09-09, and no `build/c3-stopwatch/20260909T*` artifact directory exists on disk. That applies equally to the PASS later the same day — 336 s, reproduced at 371 s, against a dedicated fixture peer — written into this cell by commit `c3c485d5d3` and **withdrawn here** on the same ground; the 2026-09-09 blocks in [`work/fresh-start-seam.md`](./work/fresh-start-seam.md) §0 and the timing note in [`work/stopwatch-gates.md`](./work/stopwatch-gates.md) are marked withdrawn for it too. What the ledger does say is the opposite. Its newest row is 2026-09-08 20:08 UTC, `verdict=fail`, `no_pass_streak=77`; its newest `verdict=pass` is 2026-08-21 at `wall_clock_seconds=515` against `final_network_tip=3224124`; 14 of its 240 recorded runs passed. That 515 s pass is real evidence that the wipe path can reach network tip inside the 600 s budget, but it is three weeks stale and predates the SEAM runs above, so it does not carry the current claim. Whether the SEAM is a serving-capacity limit of a busy node rather than a requester-side defect is an open reading, not a settled one. The "complete shielded-history gates" condition is satisfied by construction on this path: a genuinely wiped datadir performs no import, and the reducer's fail-closed shielded-completeness holds (utxo_apply holding Sapling/Sprout spends under incomplete history) would have stopped the fold — the evidence they never fired is the 2026-08-21 ledger row itself, whose `final_hstar=3224132` cleared `final_network_tip=3224124`. **C3 therefore stands at ◐, and its remaining condition is one row, not one run:** a wipe-to-tip stopwatch recorded by `tools/scripts/c3_stopwatch_run_and_record.sh` that lands `verdict=pass` with `wall_clock_seconds` under the 600 s budget against the executable currently serving, judged by `make c3-stopwatch-report`. Until that row exists the assisted-seed sub-proof above is the strongest C3 evidence in the tree, and it proves seeding, not sovereign wipe-to-tip. A durable evidence ledger for both this stopwatch and its network-disruption-recovery sibling (PROOF B) — periodic collect/judge split, `make c3-stopwatch-report` / `make netdisrupt-stopwatch-report` — is documented in [`work/stopwatch-gates.md`](./work/stopwatch-gates.md). | ◐ |
| 4 | **Receive shielded payment end-to-end** | Test wallet receives 1 ZCL to a z-addr, balance reflects within 2 blocks — test: `tests/harness/src/test_shielded_payment_gate.c` (`make ci-stress`; needs `~/.zcash-params`). With the params present the gate builds a real Sapling proof, the t→z tx enters mempool (`value_balance == -2000000` zatoshi, `tests/harness/src/test_shielded_payment_gate.c:714`), and the wallet decrypts the note back to a 0.02000000 ZCL shielded balance (`:750`). The 1.25 ZCL figure belongs to the receive-only gates, not to this one. The params-free RECEIVE half (note→ivk→z-balance) is hermetically gated in `make ci-mvp-gates` (`make mvp-shielded-receive`) and re-run in `make mvp-verify`. The full send+receive path lives in `make ci-stress` (the ~770 MB `~/.zcash-params` fixture isn't in the default `make ci` runner), so it isn't hermetic-gated. The FULL claim passes via `make test-shielded-payment` (a `make mvp-verify` member) on a params-provisioned host — real Groth16 t→z built → entered mempool → wallet decrypt **0.02000000 ZCL** (2,000,000 zatoshi) — the local operator proof. The params-free RECEIVE half stays a hermetic `make ci` regression floor; `make mvp-shielded-receive-persist` (note→node.db→reopen→z-balance) guards persistence in `make ci-mvp-gates`. | ✅ |
| 5 | **List + sell file via store** | Operator lists product → buyer pays shielded → buyer receives file — tests: `tests/harness/src/test_store_e2e_gate.c` via **CI slice: `make ci-mvp-gates`**. The legacy `store_e2e` selector proves in-process store persistence, memo-bound reconcile, token credit, dedupe, and token-gated binary file bytes. The `store_e2e_shielded` selector adds the real shielded-payment teeth: a Sapling output is encrypted to a merchant wallet, `wallet_try_sapling_decrypt` recovers value+memo params-free, the recovered note is persisted, and `db_store_received_payment_for_memo` credits only the matching `ZCL23ORDER:<order_id>` memo while the legacy address+amount finder over-counts a same-address wrong-order payment. Still ◐: this is hermetic/in-process, not yet a full live buyer over the store/onion/file-transfer path. **2026-09-10, lane `storelive` audit — the remaining gap is a named owner gate, not lane work.** A buyer node cannot reach a seller node's store at all today, and the blocker is structural in three independent places: the HTTPS listener answers `405 Method Not Allowed` to every non-GET/HEAD request before any routing happens (`core/modules/net/src/https_server.c:826`); the `STORE` flavor is absent from that listener's dispatch table entirely — `ZCL_HTTPS_DISPATCH_STORE` expands to a comment (`core/modules/net/src/https_server.c:924-926`) and every site handler it *does* dispatch is called with a `NULL, 0` body (`:933`, `:947`, `:961`), so no request body could reach the handler even if the row were admitted; and the only transport that reaches `store_handle_request` is the in-process onion dynhost callback (`core/modules/net/src/onion_service.c:1197-1202` — there is no `bind`/`accept` for it anywhere), whose outbound client is GET-only with no method or body argument (`core/modules/net/src/tor_fetch.c:21-34` → `dynhost_client_fetch(addr, 80, path, cb, ctx, timeout)`), while order creation requires POST (`engine/controllers/src/store_controller.c:254-260`, the `strcmp(method, "POST")` at `:256`). Discovery of the two facts a remote buyer needs is no longer a gap: `token_id` and `content_hash` are both emitted unconditionally by `store_product_json` (`contexts/explorer/views/src/store_view.c:362-385`), which serves the GET-only JSON twins `/store.json`, `/store/products.json` and `/store/products/:id.json` routed at `engine/controllers/src/store_controller.c:191-236` — reachable by the GET-only onion client, so the expected SHA3-256 need not be passed out of band. **C5 is therefore ◐ BLOCKED(owner: core unseal)** — the decision is the owner's: either unseal `core/modules/net` for a request-bearing loopback/HTTPS `STORE` dispatch (fail-closed — loopback peer plus regtest or an explicit operator flag that is refused by name on mainnet, with the refusal pinned by a test), or extend the `vendor/tor` dynhost client with a method + body so a buyer can POST over the seller's onion. **A third blocker was found on 2026-09-10 and has since been fixed; the record stays because the rung-A proof rested on it.** The merchant leaf `app.store.list-product` used to open `node.db` directly in the short-lived CLI process (`sn_open_db`, `engine/controllers/src/store_native_handlers.c:170`, whose `node_db_open_runtime` call is at `:189` and whose list-product call site is `:612`), and `node.db` is under a deliberate single-owner lease, so a second process was refused with `DATABASE_OWNERSHIP_CONFLICT: canonical database owner already holds path=<datadir>/node.db` (`engine/models/src/database_owner_lease.c:318-324`). The refusal the operator actually met was `STORE_NOT_INITIALISED` — the response quoted in commit `9893049675` — because `sn_open_db` then answered that one code both for a missing `node.db` and for one it could not open. The same fix split them, so the codes in the tree today read differently from that reproduction: `STORE_NOT_INITIALISED` now means only that no `node.db` file exists at all (`:182-185`), while a database that exists but will not open answers `STORE_DB_UNOPENABLE` (`:189-194`). No product could be listed through the shipped CLI while the node was running — reproduced live 2026-09-10 on a fresh isolated regtest datadir, unconditional, not a lock that clears with retry (60 s of bounded retry, every attempt refused). The buyer leaves were unaffected because they proxy the `storebuy_*` RPCs and run inside the node (`contexts/market/controllers/src/store_buyer_controller.c:475-479`); it was the merchant half that was stranded. The fix landed the same day (commit `9893049675`, *Let a merchant list a product while the node is running* — `git log -S node_db_owner_lease_probe -- engine/controllers/src/store_native_handlers.c` and `-S sn_list_through_node` both resolve to it; the later `89c7b63919` only renamed the refusal a non-answering node produces to `STORE_NODE_UNREACHABLE`): the leaf now probes the lease and sends a LIVE-lease listing to the node over the `storesell_list_product` RPC instead of opening the database (`store_native_handlers.c:785-801`, RPC registered at `engine/controllers/src/store_sell_controller.c:143`), writes an idle datadir in-process exactly as before, and refuses an unreadable lease rather than racing it. `tools/scripts/store_sell_operator_proof.sh` calls `app store list-product` against its own booted node at `:702`, so `make test-store-operator-proof` — the "rung A" full-binary operator proof named at the top of this cell — is no longer blocked by the lease; this cell records no run of it since the fix, so rung A is unproven here rather than impossible. C5's slice gates (`store_e2e`, `store_e2e_shielded`) are hermetic and in-process, so they are untouched and remain the regression floor. Two things still stand between C5 and ✅: a recorded rung-A run of `make test-store-operator-proof`, and the remote buyer-to-seller transport, which still needs the owner decision above. | ◐ |
| 6 | **7-day soak with zero operator intervention** | Live node + synthetic load for 168h: no manual restarts, RSS plateau. **Hermetic proxy: `make soak-ci`** (not in `make ci`) exercises scoring mechanics only. Real evidence comes from `make soak-7day` and `make soak-evidence-report` (`MET\|NOT_MET\|INSUFFICIENT`). Live status: `docs/HANDOFF.md` / `z23 status`. A soak window counts only when it runs on a sovereign, exact-same-height-parity candidate with gap ≤1, complete security posture, continuous evidence, and zero manual restarts; one-block lookahead or process uptime alone never earns C6. | ◐ |
| 7 | **Recover from `kill -9` in <2 min** | kill -9 mid-block, restart, caught up to peer-tip within 2 min — in-process unit `tests/harness/src/test_kill9_recovery.c` (**CI slice: `make ci-mvp-gates`** — proves `node.db` atomic UTXO recovery after SIGKILL) **plus** the full-binary harness `make test-crash-bootstrap` (not in the `make ci` target) which spawns a real isolated regtest node and proves clean **boot recovery** under a real process-group `SIGKILL` (seed 30 → kill-9 → recover 30 → mine 31 → kill-9 → recover → 32, `height_regress: 0`) **plus** the two-node harness `make test-two-node-peer-tip` (miner A + follower B on disjoint platform/ports/datadirs): A mines 10 → B syncs over native P2P → kill-9 B, A mines +5, restart B → **B recovers and catches up to peer-tip 15**. Both full-binary harnesses are bundled in the one-command local aggregate `make mvp-verify`. `generate` forward-progress: a fresh on-demand node self-seeds the genesis anchor (copy-proven `generate 5` → tip 5, rejects=0), so `test-two-node-peer-tip` passes end-to-end (A mines 10 → B syncs → kill-9 B → A +5 → B recovers to peer-tip 15 via P2P re-sync; A never restarts). The single-node restart-durability keystone (`341020c05`): a fresh node that mined N blocks, was kill-9'd, and rebooted to a NULL active tip restores the durable finalized tip via a forward-only genesis-root seed (canonical-genesis-anchored + `coins_applied>=tip` gated + mainnet-no-op), instead of stranding at `h=-1`. `make test-crash-bootstrap` passes end-to-end (seed 30 → kill-9 → recover → mine 31 → kill-9 → recover, **`height_regress: 0`**), so the SINGLE-node kill/restart recovery teeth are asserted. The FULL kill-9 recovery claim passes via `make test-crash-bootstrap` (full-binary boot recovery, `height_regress: 0`) + `make test-two-node-peer-tip` (B recovers to peer-tip 15 over native P2P) — both `make mvp-verify` members; the hermetic `node.db` SQLite-atomicity slice stays the `make ci` regression floor. Live deploy of the keystone binary to the mainnet datadir remains owner-gated (wipe+cold-import). | ✅ |
| 8 | **Consensus parity with zclassicd** | Continuous diff service: 0 mismatches over the 7-day soak window. Service exists (`engine/services/src/utxo_parity_service.c`, wired via `boot_utxo_parity.c`), default ON when a `zclassicd` oracle resolves, diffing UTXO/tip at the supervised 60s `chain.utxo_parity_poll` cadence; quiet no-op with no daemon; force off with `ZCL_PARITY_ORACLE=0`. Read-only observer — cannot touch consensus/tip/liveness. Drift persists `utxo_drift_detected` (surfaced via `z23 dumpstate utxo_parity`) and pages via the wired Condition. **CI slice: `make ci-mvp-gates`** (`make mvp-parity-slice`, `tests/harness/src/test_parity_slice.c`) drives the service against an in-process fixture with a paired control — consistent set → 0 mismatches (MATCH), injected extra outpoint → DETECTED (DRIFT). The COARSE production branch (`exact=false` — what the live `zclassicd` oracle actually hits, since `gettxoutsetinfo` returns height only) has hermetic coverage too: C1 same-height → MATCH with empty remote SHA3 (bucketed in `coarse_checks`, never a byte-MATCH), C2 height-skew → LOCAL_ONLY (never DRIFT), C3 a coarse confirmation CLEARS a stale exact-drift flag so it stops paging. The exact tier is the **standing replay canary** (`make replay-canary-anchor` / `make replay-canary-genesis`, RUNBOOK): a full-history replay through the HEAD reducer with an explicit empty `-paramsdir`, asserting embedded-key shielded validation, zero consensus rejects, the byte-exact UTXO SHA3 checkpoint at anchor 3,056,758, tip bestblock/txouts/total_amount equal to zclassicd's `gettxoutsetinfo`, **and — the 2026-08-01 byte-exact tier (d) — the node's served UTXO SHA3-256 commitment equal to `--legacy-utxo-commitment`'s SHA3 over zclassicd's OWN chainstate serialization** (height skew mid-run is a named `exact_tier=skew` skip, never silent; coarse agreement is not set equality). **The canary ledger is the C8 gate in `tools/mvp_gate.sh`** — a fresh (≤7d) from=genesis PASS whose source identity and artifact hash match the executable currently serving, plus a live coarse match, earns C8. A fresh FAIL is a consensus-grade alarm; a mismatched, stale, or absent PASS is a named gap. Evidence must accumulate on the linger cadence (`make install-replay-canary`) rather than rest on one old run. ◐ until a matching fresh genesis PASS accumulates. | ◐ |

**Legend:** ☐ unmet / not gated · ◐ a gate runs green for a **slice or proxy**
of the criterion (real, automated regression protection — but not the full
operator-acceptance claim) · ✅ the **full operator claim** run-passes
end-to-end via the **local operator proof** on this machine — the relevant
`make mvp-verify` member / linger-service gate (`make ci-install-linger`,
`make mvp-onion-local`, `make test-shielded-payment`, `make test-crash-bootstrap`
+ `make test-two-node-peer-tip`, …). The MRS counts only ✅.

**MRS = the count of ✅ criteria above** (8/8 = MVP achieved). Current MRS:
`z23 milestone` (REST `GET /api/v1/milestone`) or
[`docs/HANDOFF.md`](./HANDOFF.md) — this file does not track a live count.

**Advancing a criterion (agent/operator loop).** One loop per cell: run the
cell's full-proof harness (or its ledger collector, e.g.
`tools/scripts/c3_stopwatch_run_and_record.sh`), keep the artifact directory
it prints regardless of verdict, judge the ledger where one exists
(`make c3-stopwatch-report`, `make netdisrupt-stopwatch-report`,
`make soak-evidence-report`), and only then edit the cell: record the run's
date, verdict, measured number and artifact path, and flip the status column
only when the cell's own stated gate condition is met — a ◐ cell names its
remaining condition in prose; meet that condition, not a convenient
substitute. Never delete a failure record to make room for a PASS: append
the new run, so the failure history stays visible beside it. When a full
claim is blocked on an owner decision (sealed core, `vendor/tor`, deploy,
custody), say so in the cell and name the decision — a named owner gate is
the honest ◐ state, not a reason to weaken the claim.

**C1, C2, C4, C7** each have a FULL operator claim that run-passes, via their
`make mvp-verify` members — `ci-install-linger` (real `make install` +
`systemctl --user start`), `mvp-onion-local` (real onion `<60s`),
`test-shielded-payment` (real Groth16 t→z + decrypt 0.02 ZCL), and
`test-crash-bootstrap` + `test-two-node-peer-tip` (kill-9 recovery). Remaining
◐ criteria: **C3** (the wipe-to-tip stopwatch needs a fresh ledger row at
`verdict=pass` inside the 600 s budget; the newest one on record is
2026-08-21 at 515 s), **C5** (hermetic real ivk-decrypt + memo-bound store
slice exists; a recorded rung-A operator run and the remote buyer transport
are still needed), **C6** (needs a clean 168h
soak window on sovereign state — see `docs/HANDOFF.md` for current accrual),
**C8** (needs a fresh replay-canary from=genesis PASS — the exact-tier
gate in `tools/mvp_gate.sh` — accumulated on the linger cadence).
The hermetic `make ci` gates remain the regression floor that keeps every ✅
honest between operator runs.

The `ci-mvp-gates` wiring includes **twelve hermetic gates** (◐ /
supporting) that run and pass (not SKIP) under `make ci` and block the build
(`Makefile:8613-8625`) — **#3** cold-start sync FSM (~7s), **#5** store
end-to-end proxy, **#5b** real ivk-decrypt + memo-bound store proof, **#7**
kill-9 SQLite-atomicity recovery (~4-8s), a supporting
`chain_advance_atomicity` fork test, #2/#4/#4b/#8 slices, a reducer-forward
gate, a `destruction_drill` recovery gate (destroy the datadir → restore from
backup → rescan → SPEND, `Makefile:8625`), and the
**"it works" gate** `reducer_ingest` (`test_reducer_block_ingest_gate.c`,
`make mvp-it-works`) — mines one real regtest Equihash (48,5) block and drives
it through the **reducer front door** (`reducer_ingest_block`, the same entry
live intake uses) on production stage defaults, asserting the authoritative tip
advances by exactly 1 with a consistent UTXO commitment. It is teeth-verified
(fails if the reducer cannot finalize forward — the live-wedge failure mode) but
is supporting infrastructure, not a numbered criterion, so the MRS is unchanged.
Each gate runs FOCUSED via `ZCL_TEST_ONLY` under `ZCL_STRESS_TESTS=1` and is
guarded against false-green fall-through (a vanished selector fails the gate
loudly instead of silently running the full suite). That is real regression
protection for a *slice* of each criterion — but none proves the full operator
claim (a real 3M-block sync, a real shielded purchase, a full-binary restart to
peer-tip), so they are ◐, not ✅.

Soak (#6) and parity (#8) both need live forward progress on sovereign
state — see [`docs/HANDOFF.md`](./HANDOFF.md) for current accrual. C6 counts
only from an exact-parity, complete-security-posture candidate with zero
manual restarts; one-block lookahead or process uptime alone never earns it.
#6's `make ci-stress` soak proxy intentionally lives outside `make ci` because
the bounded soak spawns a real isolated node.

**Update rule:** consistent with this project's **local-only CI** (CI = `make`
on this machine, never a paid/hosted runner) and the **never-docker** policy,
◐ → ✅ when a criterion's **full** operator claim **run-passes end-to-end** via
the **local operator proof** — the relevant `make mvp-verify` member or
linger-service gate (`make ci-install-linger`, `make mvp-onion-local`,
`make test-shielded-payment`, `make test-crash-bootstrap` +
`make test-two-node-peer-tip`, …) — actually RUNNING and PASSING (not a
slice, not a SKIP) on this host. A slice/proxy gate earns ◐; a member that
SKIPs for a missing local dependency (params / Tor egress / fixture) stays ◐
until that dependency is present and it run-passes; a wall-clock claim (#6's
168h soak) earns ✅ only when the window actually completes clean. Hermetic
`make ci` gates remain the regression floor (they keep every ✅ honest between
operator runs), but ✅ is no longer reserved to them — the inherently
non-hermetic operator claims (real `systemctl --user start`, real Tor, real
Groth16 params, real soak) are proven by the local linger-service operator
proofs instead.

**THE plan to drive MRS to 8/8 is [`docs/work/FORWARD_PLAN.md`](./work/FORWARD_PLAN.md).**
The node also exposes its own live milestone summary via `z23 milestone`,
REST `GET /api/v1/milestone`; that command renders
ASCII `systems`, `goals`, and `subgoals` bars from live node health plus this
MVP table, while counting only ✅ criteria toward strict MRS. The same payload
includes `operator_proofs` (`zcl.mvp_operator_proofs.v1`), a machine-readable
copy of each criterion's proof command, CI regression floor, and current blocker.

**MVP achieved when:** MRS = 8/8.

## Why these and not others

- **Operator UX over feature breadth.** ZNAM, ZMSG, Market, Swaps,
  P2P games are great features, but they don't define MVP. MVP is
  "the chain works, payments work, the operator can leave it
  alone." Differentiated features come after MVP.
- **Decentralized commerce as the headline value.** The store flow
  (criterion 5) is the wedge that makes z23 different from
  any other Zcash node — pay via shielded, receive via .onion.
- **Soak time as the hardest gate.** Criterion 6 (7-day uninterrupted
  operation) is what proves we're past firefighting. MVP requires a clean
  168h window with zero operator intervention — measure it with
  `make soak-evidence-report` (VERDICT=MET), never a hand estimate.
