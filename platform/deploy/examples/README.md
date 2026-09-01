# deploy/examples — operator-specific unit files

Reference units from the original operator's machine. Unlike the portable
units in `deploy/` (which use `%h`), these hardcode operator paths or name
operator-specific peers. Copy and adapt before installing:

- `zclassicd-peer.service` — operator-specific example for a legacy C++
  `zclassicd` dev peer used as a drift/consensus oracle. The live/default
  unit name documented in CLAUDE.md and docs/SYNC.md is `zclassicd.service`;
  copy and rename this example if your host uses that name.
- `zclassic23-soak.service` / `.timer` — the OLDER 10-minute three-guarantees
  soak probe driving `tools/scripts/soak_assert.sh` against the MAIN node
  (hardcoded repo path). **Naming caution:** on the operator box the unit
  named `zclassic23-soak.service` is NOT this probe — it is the long-uptime
  soak NODE, committed here as `zclassic23-soak-node.service`.
- `zclassic23-soak-node.service` — the deployed long-uptime soak NODE
  (pinned binary at `~/.local/bin/zclassic23-soak`, datadir
  `~/.zclassic-c23-soak`, RPC 18242; installed on-box as
  `zclassic23-soak.service`). `make deploy` never touches its binary;
  re-pinning it is a conscious soak-clock re-baseline (see unit comments).
- `zclassic23-soak-evidence.{service,timer}` — hourly MVP-C6 evidence
  collector: `tools/scripts/soak_evidence.sh collect` appends one READ-ONLY
  JSON sample (soak/zclassicd heights, gap, NRestarts, ActiveEnterTimestamp,
  VmRSS, ok) to `~/.local/state/zclassic23-soak-evidence/evidence.jsonl`.
  An unreachable node is recorded as an `ok:false` line, never skipped —
  and the judge GATES on those holes (soak unreachable beyond the 1%
  budget = NOT_MET; a stale last sample caps MET at INSUFFICIENT, so a
  dead collector can never leave an evergreen green verdict). Judge the
  window with `make soak-evidence-report`; the unit's OnFailure= pages
  only when the lock-acquire or APPEND itself fails.
- `zclassic23-soak-evidence-onfailure.service` — `OnFailure=` arm for the
  collector; logs to the journal (`journalctl -t soak-evidence`).
- `zclassic23-replay-canary-nightly.{service,timer}` — nightly from-anchor
  replay canary driving `tools/scripts/replay_canary.sh --from=anchor`
  (~45 min). Replays bodies anchor(3,056,758)->tip through the HEAD reducer
  in an ISOLATED /tmp scratch datadir on 3905x ports and asserts zero
  consensus rejects, the anchor checkpoint passed without an integrity
  FATAL, and coarse UTXO stats == co-located zclassicd `gettxoutsetinfo`
  (RPC 8232, READ-ONLY). Verdict is the sentinel FILE
  `~/.local/state/zclassic23-canary/replay_canary_anchor.json`, written
  atomically only after every assertion passes — never exit-0-as-proof.
- `zclassic23-replay-canary-weekly.{service,timer}` — weekly from-genesis
  replay (genesis->tip, ~6 h, bg-validation ON). Same asserts plus full
  script coverage. This run dials the co-located zclassicd P2P
  (127.0.0.1:8034) via `-addnode` for bodies — the one real peer, read-only.
- `zclassic23-replay-canary-onfailure@.service` — templated `OnFailure=`
  arm; logs `CANARY FAILED` to the journal (`journalctl -t replay-canary`).
- `zcl-stopwatch-peer.service` — dedicated minimal serving peer (ports
  39070-39073) that the two stopwatch gates below dial as a read-only P2P
  client, kept separate from the canonical `zclassic23.service` (port 8033)
  so the 6-hourly stopwatch timers can never contend with or churn the
  live node.
- `zcl-c3-stopwatch-run@.service` / `zcl-c3-stopwatch.timer` — the C3
  wall-clock evidence collector: `tools/scripts/c3_stopwatch_run_and_record.sh`
  runs `tools/scripts/cold_start_to_tip_stopwatch.sh` (a genuinely-wiped
  `/tmp` datadir dialing `zcl-stopwatch-peer.service`) and appends one JSON
  line to `~/.local/state/zclassic23-c3-stopwatch/history.jsonl`. Same
  collect/judge split as the soak evidence collector: the wrapper always
  exits 0 once the ledger append succeeds, regardless of the run's own
  PASS/FAIL/SKIP/SEAM/STALLED-NAMED verdict; `make c3-stopwatch-report`
  judges the ledger's last line via `tools/scripts/stopwatch_evidence_judge.sh`.
  `OnFailure=` fires only on a lock/append failure.
- `zcl-netdisrupt-run@.service` / `zcl-netdisrupt-stopwatch.timer` —
  PROOF B, the network-disruption recovery collector:
  `tools/scripts/netdisrupt_stopwatch_run_and_record.sh` runs
  `tools/scripts/network_disruption_recovery_stopwatch.sh` against an
  already-running, already-at-tip client and a controllable upstream peer
  (SIGSTOP the peer, sleep `--cut-secs`, SIGCONT it, time the client's H*
  recovery back to `network_tip`), appending one JSON line to
  `~/.local/state/zclassic23-netdisrupt-stopwatch/history.jsonl`. Neither
  unit spawns a node — point the instance's optional
  `~/.config/zclassic23-stopwatch/<instance>.env` `EnvironmentFile=` at the
  client/upstream fixtures under test. `make netdisrupt-stopwatch-report`
  judges the ledger. The upstream is ALWAYS `SIGCONT`'d on exit (the
  script's own trap), even on a hard failure.
- `zcl-stopwatch-onfailure.service` — shared `OnFailure=` arm for both
  stopwatch run units; logs to the journal (`journalctl -t stopwatch-gate`).

## Replay-canary operational notes

- **Disk**: each canary run mints one scratch datadir on /tmp holding the
  chainstate + a copy of the LevelDB block index — budget ~50-80 GB
  transient. The harness runs a `df /tmp` preflight and REFUSES loudly if
  /tmp has < 80 GiB free. If /tmp is a small tmpfs, point the harness at a
  real-disk scratch root by sourcing it with a /tmp that has headroom, or
  provision tmpfs/disk accordingly. The cleanup trap removes the datadir on
  exit (including on SIGKILL of the group).
- **Port reservation**: the nightly uses 39050 base, the weekly 39060. The
  future nightly crash-soak (tenacity-roadmap item 7) should run at a
  DISJOINT calendar slot (~04:30) and on the RESERVED 39070 base. Distinct
  `ISO_KIND` mints distinct `/tmp/zcl23-replay-*` datadirs, so even an
  overlapping run is datadir-safe; the `ss(8)` LISTEN preflight in
  `isolated_mainnet_env.sh` is the backstop against port collision.
- **Read-only zclassicd**: the canary only ever READS zclassicd via
  `--importblockindex` (copies-then-strips the COPIED LOCK; never touches
  the source LOCK) and `gettxoutsetinfo` on RPC 8232. It never issues
  `stop`/`generate`.
- **Opt-in targets**: `make replay-canary-anchor` / `make replay-canary-genesis`
  run the same harness by hand. The hermetic verdict-logic gate
  (`test_replay_canary_verdict`) runs in `make ci` and red-fails on a
  seeded known-bad reducer before any green night can count.
- **Never exit-0-as-proof / never stale-file-as-proof**: the harness removes
  any prior sentinel at run start (`reset_verdict`), so a killed/OOM/timed-out
  run leaves NO sentinel — a reader that requires a fresh PASS resolves FAIL.
  The `make replay-canary-*` guard ALSO drops a marker before the run and
  requires the sentinel to be strictly newer than it (`-nt`), so a STALE PASS
  from a previous successful run can never be read as this run's proof. A
  "7 consecutive green nights" reading must likewise require each PASS sentinel
  to be FRESH for its night (compare `started_ts` / mtime to that night's run
  window), not merely present.
- **Elapsed-time band** (the named-defect guard): a from-anchor COMPLETE that
  is implausibly fast (the seed never applied → a stub "completed") or that
  silently degrades to a genesis-scale replay both FAIL with a typed reason
  (`elapsed_too_fast` / `elapsed_too_slow`) — the anchor band is centred on
  the ~45-min expectation (300 s floor, 5400 s ceiling), the genesis band on
  the ~6 h replay (3600 s floor, 28800 s ceiling).
