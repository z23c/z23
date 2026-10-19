# Z23 Operator Runbook

Use this page to diagnose a node symptom, distinguish a temporary condition
from a fault, and find the matching recovery procedure. Start with
[High-Availability First Check](#high-availability-first-check).

You need a built `build/bin/z23`, access to the node's RPC (remote procedure
call) interface, and its datadir (data directory). Run commands from the
checkout root. Examples using `~/.zclassic-c23` assume that datadir; substitute
your configured path if it differs. Service commands assume the checked-in
`z23-node.service` user unit is installed. Recovery, deployment, and timer
changes require the operator's authority.

## Soak / chaos harnesses

Run `make test-crash-bootstrap` (C7 kill-9) and `make soak-ci` (C6 soak proxy)
to exercise a real but fully isolated node. For the isolation contract, build
caveat, output/verdict reading, and the operational forms (`make soak-7day` =
MVP #6), see [`CHAOS_HARNESS.md`](./quality/CHAOS_HARNESS.md).

### Nightly simulator sweep

`make chaos` runs the `tools/sim/scenarios/*.scenario` corpus. Count the
scenarios with `ls tools/sim/scenarios/*.scenario | wc -l`. It is excluded
from `make ci` because it requires an extra whole-program link; see the
comment beside `ci:` in the Makefile.

| Target | Work |
|--------|------|
| `make simnet-nightly` | Scenario corpus, bounded `make wire-sweep`, `make sim-fast`, and the additional checks in the target |
| `make simnet-fuzz-sweep` | Longer seeded wire sweep |

`tools/scripts/simnet_nightly.sh` runs the first target and optionally the
second. It writes a JSON (structured text) status file and dated logs, as
does `tools/scripts/background_quality_lane.sh`.

A lane groups work under one operating role, such as a background quality
job or a node instance. The installed fuzz/test/coverage/simnet services enter
through
`tools/scripts/quality_job_guard.sh`. They clean-skip when any active user
service name contains `mint`, leaving the last verdict untouched, and retain
the newest eight dated logs per lane, bounded to 1 GiB total per lane while
always preserving the newest verdict (`ZCL_QUALITY_LOG_KEEP` and
`ZCL_QUALITY_LOG_MAX_BYTES` override those limits). A failed mint-state query
also skips rather than guessing that the host is idle.

The timer is an owner-gated installation, not a default checkout step:

1. Have the operator install the unit files from
   `platform/deploy/z23-simnet-nightly.timer` and
   `platform/deploy/z23-simnet-nightly.service`, with the service's
   checkout paths configured for this host.
2. To include the longer sweep, set
   `Environment=ZCL_SIMNET_NIGHTLY_FUZZ_SWEEP=1` in a service drop-in.
3. Enable the installed timer:
   ```bash
   systemctl --user enable --now z23-simnet-nightly.timer
   ```
4. Read the latest status at
   `~/.local/state/zclassic23-quality/status/simnet_nightly.json`, or
   `$ZCL_QUALITY_STATE_DIR/status/simnet_nightly.json` if overridden.

The timer runs daily at 03:10 with up to five minutes of jitter. The fuzz
timer is hourly; the test-suite timer runs at `*:20:00` each hour.

---

## High-Availability First Check

For a live node, run these read-only probes before deciding to restart:

```bash
build/bin/z23 agentops
build/bin/z23 agent
build/bin/z23 agentliveness
build/bin/z23 peerincidents
```

| Probe | What to read |
|-------|--------------|
| `agentops` | Preferred transport, diagnostic commands, lane safety, runtime availability, and next architecture work |
| `agent` | Compact live health packet |
| `agentliveness` | Whether the lane, supervisor tree, and background quality lanes are alive |
| `peerincidents` | Reconnect storms, duplicate hosts, bootstrap usefulness, and disconnect reasons |

P2P means peer-to-peer network communication; a handshaked peer has completed
the protocol greeting.

Do not restart on a single stale-looking field if these probes show active
services, handshaked peers, and bounded mirror lag. Drill down with
`build/bin/z23 getmirrorstatus`,
`build/bin/z23 dumpstate reducer_frontier`, and
`build/bin/z23 dumpstate peer_lifecycle` only when the first-call JSON
names a concrete problem.

---

## Benign log patterns at tip

Tip means the latest connected block; a projection is state derived from block
data. On a node holding tip and finalizing forward, these patterns look
alarming but are **expected**. Mental model: the served tip and every derived
projection
(headers, bodies, scripts, proofs, coins) converge a few seconds *after* each
block lands; most "noise" is one stage briefly observing a frontier another
hasn't caught up to. This self-resolves next tick — sustained firing across many
consecutive blocks is the real signal. Do **not** restart until a pattern
crosses its **real-alarm** threshold.

| Pattern | Meaning (emitted by) | Benign? | Real alarm if |
|---------|----------------------|---------|---------------|
| **header-resync WARN storm** — `staged.header_admit/validate_headers stalled …`, `condition:header_stall_at_height … action=kick_headers`, `Peer …: all N headers rejected` | At tip, duplicate headers can trigger this path and a precautionary re-request. "All N rejected" alone does not distinguish duplicates from invalid headers. `staged_sync_supervisor.c:134,141`, `header_stall_at_height.c:74`, `msg_headers.c:1541` | Yes | `validate_headers stalled` repeats with `failed>0` climbing (genuine validation failures, not dups), or `header_stall_at_height` keeps firing with `age` growing for minutes while `peer_max` stays well above your height. Cross-check height vs zclassicd. |
| **have_data_missing race** — `EV_BLOCK_REJECTED … tip_finalize … reason=have_data_missing` / `block_missing` | A block (or tip's H+1 lookahead) has a header but its body hasn't finished `body_persist → script_validate → utxo_apply`. A canonical header successor can finalize without its body; otherwise finalize returns `JOB_IDLE` (cursor unchanged, txn rolled back) and retries next tick. `tip_finalize_stage.c:397,440,471` | Yes | The SAME height stays `have_data_missing` for many consecutive ticks (minutes) — a body that never arrives. Confirm via `z23 core sync status` (body frontier not advancing) + `tip_advance_age_seconds` climbing. |
| **"database is locked" transient** — SQLite `SQLITE_BUSY`/`SQLITE_LOCKED` retries | Stage writers (chain-state cursor, body persist, tx index, explorer projections) share one SQLite WAL (write-ahead log) for `node.db`; under a write burst two briefly contend and retry within `busy_timeout`. Bounded retry loop `chain_state_service.c:163-199`; `sqlite3_busy_timeout` on hot writers e.g. `snapshot_controller_import.c:246`. The bulk SQLite projection catchup is one of those writers and does **not** abort on the first busy: after each batch COMMIT it retries its `BEGIN IMMEDIATE` up to `NODE_DB_CATCHUP_REOPEN_MAX_ATTEMPTS` (6, ≈60 s at the 10 s busy timeout) with backoff, logging `catchup: reopen busy, retry k/n` per retry before the unchanged fail-closed abort, while `db_maintenance` yields its wal/analyze/vacuum tick (`db_maintenance: deferred, catchup active`) for up to `DB_MAINT_MAX_CATCHUP_DEFERRALS` (8) consecutive ticks so the two are not fighting for the same lock | Yes (retry succeeds) | The exhausted-retry surface appears (`last_persist_locked` set / "bounded retry exhausted"), or `database is locked` coincides with two live `z23` PIDs on one datadir (real second-instance — see Boot Failure). A bloated WAL (>100 MB) can sustain contention — force a checkpoint (see "Disk > 99% Full"). |
| **bg-validation undo-data-missing** — `[bg-valid] h=…: N non-coinbase tx(s) NOT script-verified (undo missing) — block advances, not fully verified` | Snapshot/fast-sync blocks carry no undo data for the pre-snapshot range; scripts were verified at connect time, only optional historical re-verify is skipped. Skip count tallied for honesty. `bg_validation_verify_block.c:422-429`; `health_controller.c:210` | Yes (expected post-snapshot) | `[bg-valid] script verification FAILED h=…` (`bg_validation_verify_block.c:407`) appears, or the skip count grows for blocks connected normally (with undo data), not just the pre-snapshot range. |
| **crash-only auto-reindex** — `[boot] crash-only recovery: post-restore tip-above-extent … requesting -reindex-chainstate; restarting …` then `… consuming auto-reindex request — rebuilding the UTXO set from block data` | A kill-9 mid-connect left the derived tip above the validated on-disk extent. blocks/ + wallet are the only durable truth and the UTXO (unspent transaction output) set is derived, so the node bounded-requests a rebuild and restarts. Never deletes blocks/ or wallet; max 3 attempts per identical finding. `boot_crashonly.c:23`; `boot_crashonly_handle_unrecoverable()`; `boot_auto_reindex.c` | Yes (strictly safer self-heal) | `[boot] crash-only recovery EXHAUSTED: the IDENTICAL post-restore finding …` (`boot_crashonly_handle_unrecoverable()`) — blocks/ genuinely can't back the tip (real corrupt-block-data), or the same anchor keeps requesting a reindex without converging. |
| **rpc-unreachable during deploy** — monitors / `mirror_status` show `rpc-unreachable` / connection-refused briefly around `make deploy` / restart | The process is down then re-opening the datadir, rebuilding the index map, binding RPC; the port isn't answering yet. `deploy_verify.sh` runs the captured service executable's offline `core node bootstatus` leaf and reports its typed `zcl.core_bootstatus.v1` result (or the named `NO_BOOT_STATUS` refusal) directly from `boot_status.json`; it never infers boot state from log prose. The dev hot-swap wrapper and C-native `agentdeployguard deploy-dev` both refuse to start or restart the dev lane when `auto_reindex_request` is already pending unless `ZCL_DEV_ALLOW_AUTO_REINDEX_DEPLOY=1` is set, so routine code deploys do not accidentally consume the marker and enter a long pre-RPC rebuild. The native guard also exits nonzero on refusal, so automation does not need `jq` to stop safely. Control tooling budgets ~90s (`rpc_ready(c23, 90)` `zcl-nodectl.c:568`). `tools/deploy_verify.sh`; `tools/dev/deploy-dev-lane.sh`; `agent_interface_controller.c`; `legacy_mirror_sync_service.c:270,299,516`; `mirror_divergence_locator.c:7` | Yes (expected restart gap) | RPC stays unreachable well past the readiness budget with no typed boot status (boot did not start or the beacon is unreadable), typed `stage` or `progress_current` stops advancing for a long interval, or `rpc-unreachable` appears while the process is **up and stable** after READY (a bind/auth problem). |
| **block-not-finalized-by-reducer single event** — one `EV_BLOCK_REJECTED … tip_finalize precondition_failed …` / reason `block-not-finalized-by-reducer` right as a new tip arrives | The reducer ingested the block but finalize's one-block lookahead hasn't seen the successor yet, so a read-back momentarily answers no; a reorg cursor-rewind also emits this. `tip_finalize_stage.c:440`; `reducer_ingest_service.c:183` (read-back), recovery classification at `repair_controller_rebuild.c:281,298` | Yes | The SAME height keeps emitting `block-not-finalized-by-reducer` across many ticks (tip never finalizes — the live-wedge mode), or an `EV_BLOCK_REJECTED` carries a hard consensus reason (script/proof failure from `script_validate_stage.c`/`proof_validate_stage.c`, or `bad-txns-*`). |
| **`tip_stale` during a slow block** — `/api/health` / `healthcheck` stays `healthy=true`, `serving=true`, and reports `status.warning_reasons="tip_stale"` | `tip_stale = (now - tip->nTime) > 600` (`node_health_service.c`). Target interval is 2.5 min; Poisson variance puts honest gaps past 600s, so a synced node can report this several times a day. | Yes (chain is slow, not the node — peer height matches, `tip_lag=0`) | `tip_stale` persists while peer heights are ahead of the node, `tip_lag` grows, or `status.blocking_reason` becomes non-null — a genuine stall, see "Tip Regressed / Stuck on Wrong Fork". |

---

## BIP30 Stale Coinbase Wedge — fixed structurally

BIP30 is the rule rejecting duplicate transaction outputs that are still
unspent. BIP34 puts the block height in the coinbase transaction, the block's
mining reward transaction.

**Symptoms:** tip frozen (`tip_advance_age_seconds` climbing, gap > 0) while
legacy peers advance; `node.log` repeats `bad-txns-BIP30` / `csr-tip-commit-rejected`
at `tip+1`.

**Shape:** after a kill-9 mid-connect the UTXO set lands at `tip+1`+ while the
cursor rewinds, so a retry sees the block's own outputs already present and
false-rejects it as BIP30 (post-BIP34 coinbase txids are height-unique).

**It self-heals on restart — no manual unwedge.** The cure is structural:
`connect_block.c` tolerates a same-height self-write for every vtx (full
script/proof validation still runs); `chain_evidence_reconstruct.c` treats a
coins-cursor lag/overshoot as recoverable (tip publishes as `LOCAL_IMPORT`);
`chain_evidence_controller.c` re-derives any stale freeze on boot.

**Diagnose, read-only:**
```bash
build/bin/z23 agent
build/bin/z23 dumpstate chain_advance_coordinator
build/bin/z23 getblockcount
```

If genuinely stuck, `z23 dumpstate chain_evidence` names the precise reason
(a blocker, never a silent halt). Recovery is `systemctl --user restart z23-node`
(or `make deploy` for a new binary).

**Do not** manually delete UTXO ranges or bypass BIP30 — the fix is bounded to a
same-height self-write; a different-height duplicate is still a hard rejection.

---

## Disk > 99% Full

**Symptoms:** `EV_DISK_CRITICAL`, node may refuse new blocks, SQLite writes fail.

**Diagnose:**
```bash
df -h "$HOME/.zclassic-c23"
du -sh ~/.zclassic-c23/*
build/bin/z23 dumpstate disk_monitor
```

**Fix:**
1. Prune old debug logs: `rm -f ~/.zclassic-c23/debug.log.old*`
2. Remove stale peer data: `rm -f ~/.zclassic-c23/peers.dat.bak`
3. If the WAL is bloated (>100MB), force checkpoint:
   ```bash
   sqlite3 ~/.zclassic-c23/node.db 'PRAGMA wal_checkpoint(TRUNCATE);'
   ```
4. If block files consume >5GB and you don't need full history, enable block pruning (`engine/services/src/block_pruning_service.c`).
5. Move datadir to larger volume: stop node, `mv ~/.zclassic-c23 /mnt/bigger/`, symlink or use `-datadir=`.

**Prevention:** Set `ZCL_WAL_MAX_BYTES=104857600` (100MB cap, auto-checkpoint). Monitor `zcl_disk_free_bytes` in Grafana with alert at 1GB.

---

## Peer Misbehaving / Banned

**Symptoms:** `EV_PEER_MISBEHAVE` / `EV_PEER_BANNED`. Peer count dropping.

**Diagnose:**
```bash
build/bin/z23 getpeerinfo
build/bin/z23 dumpstate peer_lifecycle
build/bin/z23 core network peers list
build/bin/z23 core network peers incidents
build/bin/z23 ops timeline
```

**Fix:**
1. If a specific peer is spamming bad blocks/txs, remove its addnode entry:
   ```bash
   build/bin/zcl-rpc addnode "IP:PORT" "remove"
   ```
2. If legitimate peers are getting banned (false positive), check whether the node's chain is correct:
   ```bash
   build/bin/z23 getblockchaininfo
   # Compare height with a known-good explorer
   ```
3. If your node is on a stale fork, see **Tip Regressed / Stuck on Wrong Fork**.

**Prevention:** Monitor `zcl_peer_offences_total` rate in Grafana. A sudden spike in `invalid_block` offences usually means your node or the peers are on a bad chain.

---

## Public Node Strength

**Symptoms:** synced but public P2P looks weak: peers stay `connecting`, no
completed legacy-compatible or Z23 handshakes, or watchdog repeats
`PEER_FLOOR`, `HEADER_STALL`, or `STATE_STUCK`.

**Diagnose:** these read-only native JSON calls cover the P2P/advance picture:
```bash
build/bin/z23 agent
build/bin/z23 getnetworkinfo
build/bin/z23 getpeerinfo
build/bin/z23 healthcheck
build/bin/z23 peerincidents
build/bin/z23 dumpstate peer_lifecycle
build/bin/z23 dumpstate chain_advance_coordinator
build/bin/z23 dumpstate legacy_mirror
```

`peerincidents` is the preferred no-jq entry point. If the running node is one
deploy behind and does not expose the direct RPC yet, the native CLI path
falls back through `dumpstate peer_lifecycle incidents` and marks the response
with `compatibility_fallback=true` while preserving the
`zcl.peer_incidents.v2` schema.

**Fix:**
1. **No completed handshakes:** check outbound reachability and peer quality before restarting.
   ```bash
   ss -tlnp | grep 8033
   build/bin/zcl-rpc addnode "IP:8033" "onetry"
   # peer_lifecycle incidents: inspect primary_host_issue, top_host_incidents,
   # then duplicate_host_groups/top_incidents for raw peer rows
   ```
2. **External IP missing or wrong:** set `-externalip=<public-ip>[:p2p-port]`
   in the service environment and verify it appears in
   `getnetworkinfo.localaddresses`. Include `:p2p-port` when the public port
   differs from the local listen port. For public reachability,
   `inbound_handshake_seen=true` or `inbound_handshaked_connections > 0` is
   stronger evidence than outbound-only handshakes.
3. **Only `connecting` peers:** prefer fresh addnodes from known ZClassic
   peers. The compact peer incident view shows `primary_issue_class`,
   `primary_issue_next_action`, `primary_host_issue`, and `top_host_incidents`
   first, then reconnect pressure, reconnect cadence
   (`last_reconnect_interval_secs` and host min/max/latest intervals),
   duplicate host groups, current open/handshaked duplicate groups, direction,
   handshake age, advertised height, service summary, `bootstrap_readiness`,
   `fast_sync_readiness`, and whether a peer is currently useful for bootstrap.
   The full `peer_lifecycle.sources[]` view shows whether failures concentrate
   in `addnode`, `addrman`, `manual`, `zcl23_db`, or `inbound`; the coordinator
   dump distinguishes TCP failures (`addnode_tcp_failures`) from post-connect
   protocol/handshake failures (`addnode_protocol_failures`).
4. **Coordinator blocked or waiting:** use
   `dumpstate chain_advance_coordinator` first. `initialized=true` plus
   `has_connman=true`, `has_main_state=true`, `has_node_db=true` confirm the
   coordinator is wired into live P2P, chainstate, and persistence. `authority`
   must stay `local_consensus_validation`; `selected_source` shows the best
   input, `selected_source_trust`/`sources[].trust` explain its trust class,
   and `sources[].selectable=false` with `selection_blocker` explains why a
   source was excluded before score ranking. `activation_allowed=false` or a
   non-empty `blocker` explains why the node refuses to advance.
5. **Legacy advisory active:** legacy data may be used only as
   `candidate_source=legacy_advisory`. Read the mirror fields as three separate
   facts: `mirror_monitor_running` means the z23 monitor loop is alive,
   `zclassicd_rpc_transport_reachable` means the C++ RPC answered at the
   HTTP/JSON-RPC layer, and `legacy_oracle_usable` means it supplied a usable
   height/hash oracle. `rpc error -28: Activating best chain...` should be
   `zclassicd_rpc_transport_reachable=true` and `legacy_oracle_usable=false`.
   When `active_source=p2p` or another native source and
   `candidate_blocker_scope=advisory_only`, the node is not blocked by the
   legacy oracle. Treat `candidate_blocker_scope=active_or_safety`,
   `unsafe_overrides_total > 0`, `last_override_safe=false`, or a non-empty
   `active_blocker` as actionable. Inspect `legacy_advisory_blocker`,
   `candidate_blocker`, `last_blocker_code`, `stuck_reason`, `stalls_total`,
   `blockers_total`, `unsafe_overrides_total`, `last_override_scope`,
   `zclassicd_rpc_error_code`, `zclassicd_rpc_error_message`, and `last_error`.
   `consensus_authority` must stay `local_consensus_validation`;
   `candidate_trust` describes candidate data, not a co-authority.
6. **When not to restart:** if `chain_advance.decision` is `use_source` or `wait` with a clear reason, `lag <= 1`, and peer lifecycle shows active handshakes, leave it running. Restarting resets peer reputation and can make reachability look worse for a few minutes.

**Prevention:** Alert when `handshaked_connections == 0` for 5 minutes, `peer_lifecycle.timeout` rises quickly, `chain_advance.decision == "blocked"`, `candidate_blocker_scope == "active_or_safety"`, or `unsafe_overrides_total > 0`.

---

## Wallet Backup Failed

**Symptoms:** `EV_WALLET_BACKUP_FAILED`. `z23 core status` shows the wallet backup warning.

Backups are written to **`$HOME/wallet_backups`**, NOT inside the datadir —
the service refuses to back up into the source directory, because a copy that
dies with the datadir is not a backup (`engine/composition/src/boot.c`, and
`wallet_backup_start` returns `-21` on a same-directory config).

**Diagnose:**
```bash
build/bin/z23 healthcheck full
ls -la ~/.zclassic-c23/node.db
# The real backup destination
ls -lt ~/wallet_backups/wallet_backup_*.sqlite* | head
# What the last run verified, and which tables the source did not have
build/bin/z23 ops state --subsystem=wallet_backup
```

`ops state --subsystem=wallet_backup` reports `last_tables_verified` out of
`wallet_table_count`: the service compares row counts for every wallet table,
so a backup that dropped `wallet_sapling_keys` fails instead of reporting
success. `last_missing_tables` names tables the SOURCE did not have — not a
failure, but worth reading before you rely on that file.

**Fix:**
1. If the backup directory doesn't exist: `mkdir -p -m 700 ~/wallet_backups`
2. If permissions: `chmod 700 ~/wallet_backups`
3. If disk full: see **Disk > 99% Full** above.
4. Force one now (plan/commit — the first call writes nothing):
   ```bash
   build/bin/z23 core wallet backup now
   build/bin/z23 core wallet backup now --input='{"confirm":true}'
   ```

**Prevention:** The built-in backup service runs automatically. Verify after first boot by checking for `EV_WALLET_BACKUP` events.

**Restoring one:** see [Wallet Restore](#wallet-restore) below.

---

## Wallet Restore

**Symptoms:** node.db is gone, corrupt, or on a machine that no longer exists,
and you have a file under `~/wallet_backups/`.

**Stop the node first.** `<datadir>/zclassic23.pid` is the single-writer lock;
`core wallet restore` refuses with `DATADIR_LOCKED` while a node holds it, and
that refusal is protecting you.

```bash
systemctl --user stop z23-node

# 1. Rehearse. This runs the whole merge in a transaction, rolls it back, and
#    prints exactly what a commit would do — per table, rows in the backup,
#    rows that would land, rows that would collide, rows the schema rejects.
build/bin/z23 core wallet restore \
  --input='{"from":"'"$HOME"'/wallet_backups/wallet_backup_<ts>.sqlite",
            "datadir":"'"$HOME"'/.zclassic-c23"}'

# 2. Commit it (copy commit_input from the plan, or add "confirm":true).
build/bin/z23 core wallet restore \
  --input='{"from":"...","datadir":"...","confirm":true}'

systemctl --user start z23-node

# 3. Rebuild what a row merge cannot: transparent history, then the Sapling
#    witnesses. A restored shielded note CANNOT BE SPENT until step 3b runs.
build/bin/z23 core wallet rescan
build/bin/z23 core wallet rescan-witnesses
```

Encrypted backups (`*.sqlite.enc`) are handled in place — set
`WALLET_BACKUP_PASSWORD` (or pass `"password"` in the input) and restore the
`.enc` file directly. To get a readable copy instead:

```bash
build/bin/z23 core wallet backup decrypt \
  --input='{"from":"...enc","to":"/tmp/wb.sqlite","confirm":true}'
```

**Read the report, don't skim it.** `collision_policy` is `keep-existing`: a
row whose primary key is already in the target is never overwritten, and is
counted under `rows_collided`. `rows_rejected` above zero means the target's
schema refused rows the backup held — a real integrity signal.
`manifest_mismatches` above zero means the file holds fewer rows than the
backup run recorded writing, i.e. it was truncated or damaged after the fact.

**If `core wallet rescan` reports 0 outputs found on a snapshot-bootstrapped
node, that is expected, not an empty wallet.** A snapshot import deliberately
clears `BLOCK_HAVE_DATA`, so there are no block bodies on disk to scan. Sync
full history (or import a `zclassicd` block index) before concluding anything
about the restored wallet's balance.

---

## Tip Regressed / Stuck on Wrong Fork

**Symptoms:** Height decreases or lags far behind network. `EV_REORG_START` with large depth. Peers disconnecting over chain mismatch.

**Diagnose:**
```bash
build/bin/z23 getblockchaininfo
build/bin/z23 getpeerinfo
# Compare your tip hash against a trusted peer or explorer
build/bin/z23 core sync status
build/bin/z23 core consensus integrity
```

**Fix:**
1. If tip is just behind (syncing): wait. Check `z23 core sync status` — `BLOCKS_DOWNLOAD` or `CONNECTING_BLOCKS` means sync in progress.
2. If tip regressed after a reorg:
   - Small (<10 blocks): normal, recovers automatically. Watch `EV_REORG_RECOVERY_COMPLETE`.
   - Large (>10 blocks): investigate whether peers agree on the fork:
     ```bash
     build/bin/z23 getpeerinfo
     ```
3. If stuck on a dead fork (no peers agree), use the native RPC client
   (`build/bin/z23 invalidateblock "BLOCK_HASH"` /
   `build/bin/z23 reconsiderblock "BLOCK_HASH"`) to drop a stale fork.
   Replace `BLOCK_HASH` with the block's actual hash.
4. Nuclear option (last resort): stop node, delete state, resync:
   ```bash
   systemctl --user stop z23-node
   rm -f ~/.zclassic-c23/node.db ~/.zclassic-c23/node.db-{wal,shm}
   rm -f ~/.zclassic-c23/block_index.bin{,.sha3}
   systemctl --user start z23-node
   # Node will rebuild from block files or snapshot sync (cold bootstrap is now --importblockindex then a normal boot).
   ```

**Prevention:** Run background validation (`-nobgvalidation` NOT set). Monitor
the `zcl_block_height` derivative: alert if zero for >10 minutes while peers
show higher heights.

---

## Node Stuck (Not Syncing)

**Symptoms:** Height frozen. `z23 core sync status` returns `IDLE` or `FAILED`. No blocks connecting.

**Diagnose:**
```bash
build/bin/z23 agent
build/bin/z23 getpeerinfo
build/bin/z23 getnetworkinfo
build/bin/z23 dumpstate peer_lifecycle
build/bin/z23 core sync status
build/bin/z23 core network peers list
```

**Fix:**
1. **Zero peers:** Network issue or all seeds down.
   ```bash
   # Add a known peer manually
   build/bin/zcl-rpc addnode "IP:PORT" "onetry"
   # Check firewall — P2P port 8033 must be reachable
   ss -tlnp | grep 8033
   ```
2. **Has peers but no blocks:** Peers may be stale or node is rejecting valid blocks.
   ```bash
   # Check recent events for reject reasons
   build/bin/zcl-rpc eventlog | grep -i reject
   build/bin/z23 ops logs --pattern='reject'
   build/bin/z23 core consensus report
   ```
3. **Sync state is FAILED:** restart — transient failures often clear:
   ```bash
   systemctl --user restart z23-node
   ```
4. **Stuck in SNAPSHOT_RECEIVE:** snapshot peer may have disconnected. Restart
   to retry from another peer:
   ```bash
   systemctl --user restart z23-node
   ```

**Prevention:** Monitor sync state. Alert on `FAILED` or height stalled >10 min.

---

## Shielded-History Wedge (anchor + nullifier backfill gap)

`H*` is the reducer's validated frontier. Sprout and Sapling are shielded
transaction protocols; an anchor is a note-tree root, and a nullifier records
a spent shielded note.

**Symptoms:** `H*` holds flat below the header tip on a node seeded from a
transparent-only artifact — the fold-from-checkpoint path
(`-refold-from-anchor` / `-load-verify-boot`, [`docs/node/SYNC.md`](node/SYNC.md) "Fold
from checkpoint") or a legacy `starterpack-<height>` release
([`docs/node/BOOTSTRAPPING.md`](node/BOOTSTRAPPING.md)). Both mark shielded history
below their seed height as empty rather than forging it, so a spend that
references an older root has nothing to verify against.

**Diagnose:**
```bash
build/bin/z23 status
build/bin/z23 dumpstate blocker
build/bin/z23 dumpstate reducer_frontier
```
Both `utxo_apply.anchor_backfill_gap` and `utxo_apply.nullifier_backfill_gap`
present together in `dumpstate blocker` confirm this diagnosis — the
transparent coin set is fine, but the Sprout and/or Sapling anchor/nullifier
history below the fold's activation cursor is incomplete.

**Fix — `-import-complete-shielded` (the operational cure):**
```bash
# Requires a co-located, synced zclassicd, left running (SYNC.md Method 3).
# Substitute real paths for these examples.
build/bin/z23 -datadir=/path/to/target-copy \
  -import-complete-shielded=/path/to/zclassicd-datadir
```
This borrows the **complete** historical Sprout+Sapling anchor and nullifier
set from the co-located `zclassicd` chainstate and, in one transaction,
atomically flips both `anchor_kv`/`nullifier_kv` activation cursors to 0 and
clears both blockers — `H*` then resumes climbing without a from-genesis
fold. It never touches mining/spend eligibility. The resulting verification posture
is `release_assisted`, not `sovereign`: Sapling's imported frontier is
byte-verified against the header-committed `hashFinalSaplingRoot`, but
Sprout has no header commitment and bottoms out at the operator's own
`zclassicd` chainstate bytes. Full data model, verification-asymmetry detail, and
`zclassicd`-source key layout:
[`docs/node/shielded-history-importer.md`](node/shielded-history-importer.md).

**Copy-prove first — never live surgery.** Prove the cure on a throwaway
copy and gate on H\* climbing past the wedge height (both blockers absent,
exact tip-hash parity vs `zclassicd`) before ever pointing the importer at a
canonical datadir:
```bash
tools/scripts/import-copy-prove.sh --src="$HOME/.zclassic-c23" \
  --chainstate-src="$HOME/.zclassic/chainstate"
```
The importer refuses `~/.zclassic-c23` and `~/.zclassic-c23-mint` as targets.
A green copy-prove run is the prerequisite for an operator-controlled cutover.

**Precondition — the bind guard needs a height coincidence, and it can be
unsatisfiable.** The importer's bind guard requires the `zclassicd` source's
**persisted on-disk** chainstate best-block to equal the target node's coins
island root *exactly*. `zclassicd` flushes its LevelDB chainstate only
periodically, so its persisted best-block usually lags its live RPC tip by tens
of thousands of blocks. If the wedged node's island root sits *below* the
`zclassicd` live tip but the persisted chainstate has already moved *past* it
(or never lands on it), the guard refuses (`source best-block bind FAILED:
source=<hash> target=<hash>`) — correctly, since importing future nullifiers
would reject valid forward spends. When this happens the
cure is **not applicable to that datadir**; do not force it. The reliable path
is then a **fresh full-history rebuild** (two-step `--importblockindex` +
genesis body-fold, which builds complete anchor+nullifier state with no gap)
and a service cutover to the fresh datadir — see [`docs/node/SYNC.md`](node/SYNC.md)
Method 3.

**Prevention:** this wedge is the expected next step after a transparent-only
seed, not a defect — run `-import-complete-shielded` once, right after the
transparent fold reaches its held frontier (while the height coincidence above
still holds); or seed from a v3 snapshot / full body-fold that carries complete
shielded state from the start.

---

## OP_RETURN Catalog Legacy State Refusal

**Symptoms:** `z23 dumpstate blocker` shows `op_return_index.legacy_state`
(BLOCKER_DEPENDENCY, raised/witnessed by the `op_return_index_legacy_state`
condition), and `dumpstate catalog_coverage` reports the `op_return_index`
row as `unavailable: op_return_index.legacy_state`. This means
`engine/models/src/op_return_index.c`'s `op_return_index_get_cursor()` found
a `legacy_v1` or `unknown` persisted cursor record — a shape this binary
correctly REFUSES to reinterpret as its current range-declared `v2` record
(never a silent reinterpretation of a foreign digest chain) — rather than an
actual read failure. The refusal logs its ERROR line at most once per hour
per connection (with an exponential SQLite re-check backoff capped at 15
minutes) instead of once per poll, and `catalog_completeness`'s own WARN is
equally throttled, so neither storms the log while the blocker stays named
and visible. **Fix:** `build/bin/z23 oprindex_rebuild`
(`op_return_index_truncate`)
drops the legacy record and re-derives the catalog from block bodies from
scratch; the blocker and both throttled log lines clear as soon as the next
read finds the fresh `v2` record.
## Blocker `tor.start_failed` (embedded Tor is not running)

An onion is a hidden-service address on the Tor privacy network.

**What it means:** this node needs an onion and the embedded Tor thread is
not running. A build linked with full Tor starts it by default; `-tor` remains
accepted, and `-no-tor` disables it where the operator lane permits that.
Either it never started
or it started and exited. The blocker's reason quotes the most specific
warning from this boot's `<datadir>/tor.log`, classified as one of
`port_in_use`, `datadir`, `config_invalid` or `exited`; any onion address in
the quoted line is replaced with `<onion>` before it reaches the blocker or
the log.

**Where you see it:** `z23 dumpstate blocker` lists `tor.start_failed`, and
the systemd status line carries `tor=failed(<reason>)` beside the readiness
legs — that is how you tell "Tor never came up" from `tor=starting`, which is
an ordinary slow bootstrap, and from a bare `descriptor=no`, which both states
produce.

**What the node does on its own:** the `tor_start_failed` condition
(`engine/conditions/src/tor_start_failed.c`) retries the start through the
same wrapper that boots Tor, at 5s, 15s, 45s, 135s and then every 5 minutes
for as long as the node runs. It never gives up. The blocker clears when Tor's
thread is running again. The commonest cause — `port_in_use` after a restart,
because the departing process still holds Tor's bootstrap SocksPort — clears
itself within seconds and needs no operator at all.

**Operator action, by reason:**

- `port_in_use` — something else holds Tor's bootstrap SocksPort (derived from
  `-port`; see `tor_write_torrc()` in `core/modules/net/src/tor_integration.c`).
  Usually a previous z23 instance that has not finished exiting. Confirm no
  second node is running against this datadir, then let the retry take it. If
  a foreign process owns the port permanently, free it or move this node's
  `-port`.
- `datadir` — `<datadir>/tor_data/` is not writable, or a stale `tor_data/lock`
  survived a hard kill by a different user. Fix the ownership/permissions; the
  node retires a stale lock itself on every start attempt.
- `config_invalid` — the generated torrc was rejected. Read the quoted line;
  this is genuinely a config problem and the retry will keep failing until it
  is fixed.
- `exited` — Tor stopped for a reason this node could not classify. Read
  `<datadir>/tor.log` directly.

**What it does NOT affect:** RPC, the HTTPS explorer, P2P and chain advance
are all independent of the onion. If any of those are also down while this
blocker stands, that is a separate fault — look at the boot log's
`[service-kernel] START FAILED service=<name>` lines, which name exactly which
frontend service refused and how long each one took.

---

## Onion-Seed Bootstrap (extending peer-discovery-of-last-resort)

**What it's for:** when DNS (Domain Name System) seeds (`nSeeds=0` today — see
`core/chainparams/src/chainparams.c`) and the hardcoded clearnet fixed-IP seeds are
both unreachable (churn, firewall, ISP blackhole), the node's remaining
bootstrap path is Tor: fetch `/directory.json` (its own .onion + advertised
clearnet IP/height) from one or more onion-directory seed nodes. Today the
binary ships exactly **one** hardcoded first-party onion seed
(`core/chainparams/src/chainparams.c` — search `kOnionSeeds`), a known single point
of failure: no second first-party address is currently available in this
repo/docs/deploy — do not add a fabricated one;
adding a dead hostname wastes a recovering node's bootstrap budget on a dead
lookup instead of helping.

**Operator zero-rebuild path (works today):** list additional `.onion` hosts
in `~/.config/zclassic23/onion-seeds`, one per line:

```
# comments start with '#'; blank lines are skipped
# Add known reachable directory hosts here, one hostname per line.
# Use real .onion addresses supplied by their operators.
```

Format rules: one hostname per line, `#`-prefixed comment lines and blank
lines are skipped, max 32 entries loaded. This file is read **before** the
hardcoded `kOnionSeeds` array, requires no rebuild, and takes effect on the
next onion-seed pass (boot-time discovery, and any time the
`peer_floor_violated` condition's peer-of-last-resort remedy fires — see
`engine/conditions/src/peer_floor_violated.c` / `connman_kick_onion_seeds()` in
`core/modules/net/src/connman.c`).

**When this fires automatically:** the `peer_floor_violated` condition
(`engine/conditions/src/peer_floor_violated.c`) detects when healthy outbound
peers stay below 3 for 60+ seconds. Its remedy is independent of whether the
legacy `zclassicd` oracle/mirror is reachable — that source is not consulted
by this decision at all. The deficit this condition detects is entirely on
the outbound side, so the remedy only ever dials for more outbound peers
(clearing addnode backoff, kicking seed discovery, and the onion-directory
fallback below) — it never disconnects inbound peers to chase an outbound
floor, so an inbound joiner keeps completing its handshake undisturbed. When
healthy outbound is exactly zero it additionally
calls `connman_kick_onion_seeds()` (the operator file above, then the
hardcoded `kOnionSeeds`, then any `.onion` peers discovered via on-chain ZSLP
scan). After 5 fast attempts without the tip resuming, the condition pages
once, then keeps re-arming the same remedy every 10 minutes indefinitely
(`cooldown_secs=600`, `cooldown_max_rearms=0`) — it never permanently gives up
while peers stay below the floor.

**Operator action:** if a node is repeatedly hitting `peer_floor_violated`
with no recovery, populate `~/.config/zclassic23/onion-seeds` with any known
reachable z23 .onion address(es) — no restart or rebuild required, the
next onion-seed pass picks the file up.

**Reading `/directory.json`:** `port` is the P2P port to dial that .onion on
(the second virtual port the node's onion forwards to its own `-port`
listener) — not the HTTP virtual port 80 the document itself is served over,
and not the chain's default port. `height` is the highest **connected** block
that node holds, which is what tells a fully-synced supplier from a useless
one. Either may be `null`, and `null` means the publisher genuinely does not
know — an ephemeral (non-`-onion-persist`) identity has no dialable P2P route
to advertise, and a row a node only heard about carries no height. A `null` is
information: it is never a stand-in for a default you should dial anyway.
A node that has installed a bundle but not yet connected any of those blocks
publishes `height: null` until the blocks connect — the same store backs the
`Block Height` figure on the node's own landing page, so the two always agree.

---

## RPC 429 (Rate Limited)

**Symptoms:** RPC clients get HTTP 429. The `zcl_rpc_requests_total` counter
climbs with `result="rate_limited_global"` or `result="rate_limited_per_ip"`.

**Diagnose:**
```bash
build/bin/z23 ops metrics # inspect rpc_rate_limited_global/per_ip
# Check current limits
echo "Global: ${ZCL_RPC_RPS:-50} rps, burst ${ZCL_RPC_BURST:-100}"
echo "Per-IP: ${ZCL_RPC_PER_IP_RPS:-5} rps, burst ${ZCL_RPC_PER_IP_BURST:-10}"
```

**Fix:**
1. Set `ZCL_RPC_PER_IP_RPS=20` and `ZCL_RPC_PER_IP_BURST=40` in
   `~/.config/zclassic23/env` to raise the service's per-IP budget,
   then restart:
   ```bash
   systemctl --user restart z23-node
   ```
2. Set `ZCL_RPC_RPS=200` and `ZCL_RPC_BURST=400` in that environment file
   to raise the service's global budget, then restart:
   ```bash
   systemctl --user restart z23-node
   ```
3. If a specific IP is flooding, it auto-bans after `ZCL_RPC_AUTH_FAIL_THRESHOLD` (default 5) auth failures. For non-auth flooding, the per-IP rate limit handles it.
4. Loopback (127.0.0.1) bypasses per-IP limits but still counts against global. If local tools fight for global budget, raise `ZCL_RPC_RPS`.

**Prevention:** Monitor those `zcl_rpc_requests_total` results in Grafana.
Right-size limits for your deployment.

---

## RPC Auth Failures / Unexpected Bans

**Symptoms:** Banned clients get HTTP 403; authentication failures get 401.
`zcl_rpc_auth_failures_total` is climbing.

**Diagnose:**
```bash
# Check if cookie file exists and is readable
ls -la ~/.zclassic-c23/.cookie
test -r ~/.zclassic-c23/.cookie
# Check if client is using the current cookie (rotates every 24h by default)
echo "Rotation interval: ${ZCL_RPC_COOKIE_ROTATE_SEC:-86400}s"
```

**Fix:**
1. If cookie file is stale or missing: restart node to regenerate.
2. If client caches the cookie: it must re-read `.cookie` on a 401. During rotation, both current and previous cookies are valid.
3. If IP is banned from too many auth failures:
   - Ban auto-expires after `ZCL_RPC_BAN_SECONDS` (default 3600s = 1hr).
   - To clear immediately: restart the node (ban table is in-memory).
4. If using `rpcuser`/`rpcpassword` instead of cookie: rotation doesn't apply, check credentials.

**Prevention:** Ensure clients re-read the `.cookie` file at least once per rotation interval.

---

## High Memory Usage

**Symptoms:** Process RSS (resident memory) growing unbounded.
Risk of an OOM (out-of-memory) kill.

**Diagnose:**
```bash
ps aux | grep z23 | grep -v grep
cat /proc/$(pgrep z23)/status | grep -E 'VmRSS|VmPeak'
build/bin/z23 core storage stats # inspect cache sizes
```

**Fix:**
1. If background validation consumes too much: disable with `-nobgvalidation` or restart (it auto-detects <8GB machines and reduces batch size).
2. If UTXO cache is large: the node batches flushes; a restart forces a flush and reclaims memory.
3. If mempool is bloated:
   ```bash
   build/bin/z23 getmempoolinfo
   # Mempool has configurable limits — check environment
   ```

**Prevention:** Monitor RSS externally (e.g. `node_exporter`). Background validation is the biggest consumer — disable on RAM-constrained machines.

---

## Boot Failure (Node Won't Start)

**Symptoms:** Service fails to start.
`journalctl --user -u z23-node` shows errors.

**Diagnose:**
```bash
journalctl --user -u z23-node --since "5 min ago" --no-pager
# Look for EV_BOOT_VALIDATION_FAILED or specific error messages
```

**Fix by error type:**

| Error | Fix |
|-------|-----|
| `database is locked` | Another instance is running. `pgrep z23`. Kill stale process. |
| `block index corrupt` | `EV_BLOCK_INDEX_CORRUPT`. Delete and rebuild: `rm ~/.zclassic-c23/block_index.bin{,.sha3}; systemctl --user restart z23-node` |
| `node.db corrupt` | Delete `node.db*`, restart — will rebuild from block files or snapshot. |
| `schema version mismatch` | Node was downgraded. Use the matching binary version or delete+resync. |
| `permission denied` | `chmod 700 ~/.zclassic-c23; chown -R $USER ~/.zclassic-c23` |
| `address already in use` | Port conflict. `ss -tlnp | grep 8033`. Change with `-port=` or stop conflicting service. |

**Prevention:** Don't run multiple instances against the same datadir. Use `-datadir=` for test instances.

---

## Boot on a slow disk: integrity is checked, but never on the boot thread

A node that was killed (or restarted) before it closed its stores cleanly has
no clean-close receipt for them, so their SQLite integrity check is owed. Both
owed checks — `node.db` and the `progress.kv` projection — are handed to one
paced background scan that starts **after** the node reaches READY and binds
RPC and P2P, instead of running on the boot thread. On rotational storage
the scan runs in slices under the same maintenance token WAL truncation and
projection compaction queue on, so it cannot monopolise the spindle; expect
`[projection_store] quick_check deferred …` at boot, `[boot] bg_quick_check
scanning target=…` every few seconds while it works, and
`[projection_store] quick_check done … result=ok` at the end. A scan that
finds corruption refuses further projection writes immediately, raises
`EV_OPERATOR_NEEDED`, and arms the quarantine, so the next start renames the
bad file aside and re-derives the projections — the same end state the
blocking check has always produced. A scan that never finishes (shutdown, or
a failed start) simply leaves the check owed and runs again next start; it is
never recorded as clean.

---

## Quick Reference: Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ZCL_RPC_RPS` | 50 | Global RPC rate limit (requests/sec) |
| `ZCL_RPC_BURST` | 100 | Global RPC burst bucket |
| `ZCL_RPC_PER_IP_RPS` | 5 | Per-IP RPC rate limit |
| `ZCL_RPC_PER_IP_BURST` | 10 | Per-IP burst bucket |
| `ZCL_RPC_AUTH_FAIL_THRESHOLD` | 5 | Auth failures before auto-ban |
| `ZCL_RPC_BAN_SECONDS` | 3600 | Ban duration (seconds) |
| `ZCL_RPC_COOKIE_ROTATE_SEC` | 86400 | Cookie rotation interval (0=disable) |
| `ZCL_WAL_MAX_BYTES` | 104857600 | SQLite WAL size cap (bytes) |
| `ZCL_METRICS_HTTP_ENABLE` | 0 | Expose /metrics Prometheus endpoint |

## Quick Reference: Key Events

| Event | Severity | Meaning |
|-------|----------|---------|
| `EV_DISK_CRITICAL` | Critical | Disk usage above critical threshold |
| `EV_BOOT_VALIDATION_FAILED` | Critical | Boot aborted — data corruption or config error |
| `EV_REORG_DISCONNECT_FAILED` | Critical | Reorg stuck — manual intervention likely needed |
| `EV_DB_TXN_LEAKED` | High | Database transaction not committed or rolled back |
| `EV_COINS_FLUSH_FAILED` | High | UTXO persistence failed — data loss risk |
| `EV_WALLET_BACKUP_FAILED` | High | Wallet backup did not complete |
| `EV_PEER_BANNED` | Medium | Peer auto-banned for misbehavior |
| `EV_CONSENSUS_REJECT_BLOCK` | Medium | Received invalid block from peer |
| `EV_REORG_START` | Medium | Chain reorganization in progress |
| `EV_DISK_LOW` | Warning | Disk usage approaching limit |
| `EV_IBD_THROTTLED` | Info | Initial block download rate-limited (saves bandwidth) |
| `EV_PEER_THROTTLED` | Info | Peer bandwidth throttled by token bucket |
