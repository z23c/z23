# Stopwatch gates — C3 and PROOF B wall-clock evidence

Two opt-in, periodic wall-clock proofs, each split the same way as
`tools/scripts/soak_evidence.sh`: a **collect** half that runs a real
stopwatch and durably records the outcome, and a **judge** half that reads
the ledger and prints a gate-able verdict. Neither runs inside `make ci` —
both need a live binary/peer/fixture, not hermetic fixtures.

## The two gates

| gate | proves | harness script | collect wrapper | ledger |
|------|--------|-----------------|------------------|--------|
| C3 | a genuinely-wiped fresh node reaches network tip within budget (`docs/MVP.md` criterion 3) | `tools/scripts/cold_start_to_tip_stopwatch.sh` | `tools/scripts/c3_stopwatch_run_and_record.sh` | `~/.local/state/zclassic23-c3-stopwatch/history.jsonl` |
| PROOF B | an already-at-tip node recovers from an upstream network outage within budget | `tools/scripts/network_disruption_recovery_stopwatch.sh` | `tools/scripts/netdisrupt_stopwatch_run_and_record.sh` | `~/.local/state/zclassic23-netdisrupt-stopwatch/history.jsonl` |

Both harnesses gate on the same real claim `cold_start_to_tip_stopwatch.sh`
already uses for C3: `dumpstate reducer_frontier`'s `hstar` (the reducer's
authoritative, provable tip) reaching `network_tip` (the best height any
handshake-complete peer advertised) — never "the sync FSM says at_tip".
Both share the same seven-way exit-code contract: `0` PASS, `1` FAIL, `2`
SKIP (a fixture was absent — not a verdict either way), `3` SEAM (real
forward/recovery progress but the budget expired), `4` STALLED-NAMED (no
progress, but an active named blocker off `dumpstate blocker` explains
why), `5` FRONTIER-BUSY-TIMEOUT (`dumpstate reducer_frontier` never yielded
a usable sample inside the busy-timeout window — an instrument failure, not
a claim about the node), and `6` READBACK-FAILED (no observed progress and
no named blocker, but the final frontier readback could not be taken;
"we could not observe" is not "we observed nothing happening"). The
collectors map all seven, plus `error` for anything else.

PROOF B additionally needs an already-running, already-at-tip client
(`--client-rpc=` / `--client-datadir=`) and a controllable upstream peer
process (`--upstream-pid-file=` or a bare `ZCL_ND_UPSTREAM_PID`). It never
spawns either node — it SIGSTOPs the upstream pid to simulate a clean
network partition (not a crash), sleeps `--cut-secs` (default 600s), then
SIGCONTs it and times how long the client's `hstar` takes to re-catch
`network_tip`. The upstream is **always** SIGCONT'd on exit, including on
a hard failure or Ctrl-C (an `EXIT`/`INT`/`TERM` trap) — the harness must
never leave a peer parked STOPped.

## Failure legibility

On any non-PASS verdict, both harnesses additionally capture into the same
`RUN_ID` artifact dir: `frontier.json` (raw `dumpstate reducer_frontier`),
`blocker.json` (raw `dumpstate blocker`), and `ops.log.tail.txt` (the typed
`ops logs` command against the live node if still RPC-reachable, else a
plain tail of `node.log`). A `bundle_capture_failed` field in `proof.json`
records when any piece could not be captured — never a silent drop.

## Collect half — never gates

`c3_stopwatch_run_and_record.sh` / `netdisrupt_stopwatch_run_and_record.sh`
run their harness once and append **one** JSON line
(`ts, verdict, exit_code, wall_clock_seconds, budget_seconds, peer,
node_bin, build_commit, artifact_dir, skip_reason, skip_class, skip_streak,
no_pass_streak` — PROOF B adds `cut_seconds`; C3 adds the fixture-shape and
`peer_precheck` fields) to
their ledger, `flock`-serialized the same way `soak_evidence.sh`
serializes its append. Same discipline as the soak collector: the wrapper
exits `0` once the append succeeds, **regardless** of the run's own
PASS/FAIL/SKIP/SEAM/STALLED-NAMED verdict — that verdict is recorded, not
paged. The only thing that makes a collect run itself fail is being unable
to lock or append the ledger line.

## Judge half — `stopwatch_evidence_judge.sh`

```bash
tools/scripts/stopwatch_evidence_judge.sh <history.jsonl> [--max-age-secs N]
```

Reads only the **last** line (a stopwatch run is a point-in-time proof,
not an accrual claim like the 168h soak window, so there is no window to
cover — only freshness). Prints one line:

```
stopwatch-judge: VERDICT=PASS|FAIL|STALE reason=... artifact=<dir>
```

plus one `SKIP_STREAK` report line (see the skip taxonomy above),
and exits `0`/`1`/`2` respectively. `PASS` requires the last run's verdict
to be exactly `pass` **and** fresh (age <= `--max-age-secs`, default
86400s = 24h). Any other recorded verdict (including `skip`) reads as
`FAIL`, never a silent pass. `STALE` — the timer-died case — fires when
the ledger is missing/empty/malformed, or the last sample is older than
`--max-age-secs`: a green run from last week must not keep reporting PASS
forever once the collector stops running.

## Skip taxonomy and the skip-streak alarm

A harness exits `2` (SKIP) for two completely different reasons: *"nothing
was configured, so there was nothing to prove"* and *"the fixture I need has
been dead for days"*. Both used to land in the ledger as the identical string
`"verdict":"skip"`, and nothing looked at them. That is how the C3 gate
recorded a skip on **every** scheduled run from 2026-07-28 06:02 onward with
no operator-visible signal: the judge grades a skip as `FAIL`, but nothing
ran the judge, and `tools/scripts/arch_score.sh` scores KPI1 off `tail -n 5`
of the ledger, so one surviving old pass held the architecture score at 85
for four consecutive skips (~30h at the 6h cadence).

### The class table

`app/services/include/services/stopwatch_skip_classes.def` is the one table.
Three consumers read it and none keeps a private copy:
`app/services/src/stopwatch_skip_watch.c` (the typed surface),
`tools/scripts/stopwatch_skip_class.sh` (sourced by the collector and the
judge). Add a `skip()` site to a harness, add its row there.

| class | threshold | why that threshold | example reasons |
|-------|-----------|--------------------|-----------------|
| `not_configured` | **0 — never alarms** | genuinely benign; the optional input was simply not supplied. Only PROOF B can reach it: the C3 collector always defaults `ZCL_PEER`, so *every* C3 skip is a defect in something. | `no valid --client-rpc …`, `no valid upstream PID …` |
| `config_error` | **1** | never self-heals — the next run produces the identical skip forever, so waiting a cycle buys no information | `node binary absent/not executable: …`, `invalid peer address: …`, `bundle fixture absent: …` |
| `fixture_absent` | **2** | can self-heal (a peer restarts), so one sample is a bouncing fixture, not evidence; still absent one full 6h interval later, it is gone | `serving peer not reachable: …`, `client RPC not reachable …`, `… is not a live process` |
| `harness_misuse` | **1** | structural, not reason-matched: the argv loops `exit 2` on an unknown flag *without* calling `skip()`, so no artifact and no reason are written. `rc=2` with no `artifact_dir` **is** the signature. Never self-heals. | an operator typo in a flag |
| `unclassified` | **2** | a reason this table does not know, or a ledger row written before `skip_reason` existed. Loud-ish on purpose — an unknown skip is a gap in the table, and the honest answer is to say so, not to assume it was benign. | anything new |

Why `2` and not some other number for the self-healing class: it is the
smallest streak that survives a full timer interval, and it fires **three
intervals (~18h) before the architecture score can move** — the alarm's whole
job is to precede the number changing. It also sits strictly inside the
judge's own 24h staleness window, so the two rungs never race to describe the
same hole: the streak means *"the collector ran and could not prove
anything"*, `STALE` means *"the collector stopped running"*. Do **not**
inherit a threshold from another prober — `node_slo_probe.sh` uses 10 because
it polls on a minutes cadence; 10 here would be 60 hours of silence.

There is deliberately no env knob to raise a threshold. An override would be
a supported way to silence this, which is the defect.

### Where the alarm shows up

- **Collect time** — `c3_stopwatch_run_and_record.sh` prints one `ALARM` line
  to **stderr** and to `logger -t stopwatch-gate` (the same syslog tag
  `zcl-stopwatch-onfailure.service` uses, so one grep finds both classes).
  The unit has `StandardError=journal`, so it lands in
  `journalctl --user -u zcl-c3-stopwatch-run@default.service` every 6h.
  Below threshold it prints a `WARN` instead; a benign class prints a `note`
  and never alarms.
- **Report time** — `make c3-stopwatch-report` /
  `make netdisrupt-stopwatch-report` print one extra `SKIP_STREAK` line on
  stdout and, on a crossing, one `ALARM` line on **stderr**.
- **Typed interface** — `z23 dumpstate stopwatch_evidence` (key `c3`
  or `netdisrupt`, or empty for both) reports `skip_streak`,
  `no_pass_streak`, `skip_class`, `alarm_threshold`, `alarm`, and a plain
  English `summary`, re-read from the ledger file on every call.

### It reports; it never grades

Six mechanisms keep the alarm off the score, listed strongest first:

1. `tools/scripts/arch_score.sh` gets a **zero-byte diff**.
2. The alarm is on **stderr**, and every scoring path discards stderr at the
   source (`arch_score.sh` runs
   `make -s c3-stopwatch-report 2>/dev/null | grep -q VERDICT=PASS`; the
   Makefile recipe captures stdout only). A fact that cannot physically reach
   the grader cannot flatter it.
3. The `ALARM` line contains **no `VERDICT=` token**, so even a consumer that
   merged the streams cannot read it as a verdict, and the recipes'
   FALSE-GREEN guard is unaffected.
4. The judge's `VERDICT` token and exit code come from the unchanged code
   path. The 12 pre-existing `--selftest` cases are the regression proof, and
   the new cases assert `(token, rc)` is byte-identical with and without an
   `ALARM`.
5. It is one-directional by construction: it can only *add* a line. There is
   no input under which it removes a `FAIL`, upgrades a verdict, or extends a
   window.
6. Streaks are **recomputed** from the ledger's `verdict` values by every
   consumer that acts on them, never read from the `skip_streak` field the
   collector records — a forged field cannot silence the detector either.

The collector records `skip_reason`, `peer_precheck`, `skip_class`,
`skip_streak` and `no_pass_streak` as additive ledger fields. `skip_reason`
in particular is the one that had been missing: the harness always wrote it
into its `proof.json`, but the ledger line did not carry it, so no
ledger-only consumer could tell a week-dead fixture from a typo.

### Regression guard

`make lint` runs `check-stopwatch-skip-detector`
(`tools/lint/check_stopwatch_skip_detector.sh`), which runs both shell
selftests with a false-green guard and cross-checks that the shell parser
sees exactly the class rows in the `.def`. The C half is the
`stopwatch_skip_watch` test group.

## What a C3 run records, and what it admits it cannot

Every C3 run leaves the SAME evidence set whatever its verdict — pass, seam,
stalled-named, readback-failed, skip. Capture used to be gated behind
`verdict != pass`, so a successful run left three files and threw away the
per-stage cost split that is the whole point of measuring; the one real PASS
artifact on disk (`build/c3-stopwatch/20260728T000207Z-2102851/`) is exactly
that shape. A baseline that only exists on failure is not a baseline.

Each artifact dir now carries, on every verdict:

- `samples.tsv` — the per-tick climb trace (t, unix, boot ordinal, H*,
  provable sample, network_tip, tip_ok, frontier_busy, blocker count/ids, and
  the node process's cumulative CPU/RSS/disk from `/proc`). Written DURING the
  run, so a harness killed at t=550s of a 600s budget still leaves the trace.
- `proof.json` → `phases[]` — one element per phase, each naming the source of
  its duration: `harness.*` elements are windows this harness bracketed itself,
  boot elements come from the node's own `[boot]` markers with `median_ms`
  joined from `dumpstate boot_timings`.
- `proof.json` → `phases[].block_body_payload_bytes_received` (on
  `harness.observed_sync` only) — **how many bytes the run actually moved**,
  measured as the delta of `download_bytes_received` between two reads of
  `dumpstate sync_monitor` at the two ends of the window the harness brackets.
  Read the accompanying `_scope` string before using the number: it counts
  successfully-parsed **block-body message payload** and nothing else — no
  `headers` messages, no version/verack handshake, no inv/getdata/getheaders, no
  tx relay, no addr, no compact blocks, not the 24-byte per-message header, and
  no TCP/IP framing. It is a **lower bound** on wire bytes, which is why it is
  not called `network_bytes`. The counter is cumulative per process and
  `dl_init()` resets it to 0, so a delta is emitted only when both ends were
  read on the same boot; a respawn inside the window yields `-1` plus a
  `scope=this_run` omitted-field row naming the reset, never a number computed
  across it.
- `proof.json` → `measured_identity` — the binary's baked `source_id_sha256`
  (read through `tools/scripts/source_identity_lib.sh`, the one canonical
  reader), the peer dialled, the precheck class, and the peer's advertised tip.
- `proof.json` → `omitted_fields[]` — every field the measurement brief asked
  for that the run did NOT record, **by name**, with the reason and the nearest
  honest substitute. `scope=structural` means nothing in this tree can source it
  (TOTAL wire bytes, bytes per boot-level phase, per-boot-phase
  CPU/disk/start/blocker/H*); `scope=this_run` means a source exists but this run
  lost the reading. Silent absence would read as "measured, and fine", which is
  how a baseline acquires a number nobody took.

  A reason string in this array is held to the same bar as a value. The
  `phases[].network_bytes` row previously explained itself with "the download
  manager's `total_bytes_received` reaches no dumper" — which was **false**;
  `sync_monitor_dump_state_json` had exposed it all along. The error came from
  checking only the three `net-*` dumpers this harness happened to capture
  (`connman`, `peer_lifecycle`, `network` — none of which carry bytes) and
  generalising from those three to every dumper. The row still stands, because
  total wire bytes really are unsourced, but it is now scoped to that claim and
  points at the measured block-body subset as its substitute. A wrong reason is
  the same defect class as a fabricated value, so the harness `--selftest` pins
  both the corrected scoping and the absence of the old claim.
- the full diagnostic bundle: `frontier.json`, `reducer_drive.json`,
  `reducer_stage_profile.json`, `boot_timings.json`, `stage-*.json`,
  `blocker.json`, `net-*.json`, `ops.log.tail.txt`, `node.log`.

### Proving the symmetry

`tools/scripts/stopwatch_artifact_symmetry_check.sh` drives the real harness
twice against a mock node it writes itself — once forced to PASS, once forced
to a non-pass — and compares the two artifact sets file by file and field by
field. It refuses a pass-vs-pass comparison, so the proof cannot go hollow.

```bash
make stopwatch-symmetry-selftest   # hermetic: mutation-tests the comparison, no node/network
make stopwatch-symmetry-prove      # end-to-end: two real harness runs vs a mock node
```

`--selftest` is the mutation matrix: it breaks each thing the comparison claims
to check and requires the comparison to go red, plus an untouched control that
must stay green. It also runs as a pre-flight inside
`mvp-coldstart-to-tip-stopwatch`, so the proof lane cannot quietly regain the
asymmetry between runs.

## Measured 2026-08-20 — the C3 lane needs two services, and where it stops

Three runs of `c3_stopwatch_run_and_record.sh` against binary `e8eaff43b`,
each a genuinely wiped datadir. They are recorded here because the three
differ only in which host served which half, and that alone moved the
result from H\* = 0 to H\* = 3,193,024. <!-- stale-ok: dated 2026-08-20 stopwatch measurement on a throwaway /tmp datadir, not a live-node tip claim -->

A wiped node needs BOTH of these before the instant-on checkpoint install is
even eligible, and they are separate services:

- a **file service** that advertises a `ROM_ARTIFACT_HEADER_SEED` artifact,
  so the node's validated header chain reaches the checkpoint height without
  crawling there from genesis;
- a **P2P peer** that completes a handshake, so `network_tip` exists at all
  and bodies can be fetched.

| run | `ZCL_PEER` | `ZCL_CS_FILE_PEER` | verdict | wall | final H\* | network tip |
|-----|-----------|--------------------|---------|------|-----------|-------------|
| 1 | `192.0.2.10:39070` | `192.0.2.10:39072` | STALLED-NAMED | 603 s | 0 | never observed (`-1`) |
| 2 | `127.0.0.1:8033` | `127.0.0.1:18034` | SEAM | 603 s | 192 | 3,222,327 |
| 3 | `127.0.0.1:8033` | `192.0.2.10:39072` | SEAM | 619 s | 3,193,024 | 3,222,352 |

Run 1 — the fixture host serves files but not P2P. `dumpstate peer_lifecycle`
recorded `attempted=1 connected=1 version_sent=1 version_received=0`: the TCP
connection was accepted and the remote never spoke, so no handshake completed
and `network_tip` stayed `-1` for the whole run. The header seed WAS advertised
and imported (3,206,819 entries, frontier h=3,206,674), the 513 MB bundle
validated byte-for-byte against the compiled ROM keystone, and the install then
refused at chain-binding predicate -3 because the full-Equihash pass record at
h=3,056,758 needs a header solution only a peer can backfill. The fold fell back
to genesis and `body_persist` held at height 0.

Run 2 — the live node serves P2P but advertises no header seed: it runs a binary
that predates `28e1aa1cb`, whose readdir cap hid `block_index.bin`. Discovery
logged `header-seed manifest not advertised (header chain via P2P)`; the install
deferred with `validated header chain has not yet reached checkpoint height
3056758 (header frontier h=0)`. In 603 s `header_admit` reached 194,442, so the
checkpoint was about 2.6 h of header crawl away. H\* reached 192.

Run 3 — P2P from the live node, header seed and bundle from the fixture host.
This is the lane that works, and the one that names the bottleneck:

- t = 125 s: H\* = 3,056,949 — bundle and header seed installed. <!-- stale-ok: dated 2026-08-20 stopwatch measurement on a throwaway /tmp datadir, not a live-node tip claim -->
- t = 125 s → 374 s: H\* climbs 3,056,949 → 3,193,024. That is 136,075 blocks
  in 249 s; `utxo_apply` reported 564.6–586.9 blocks/s over the same window.
- t = 374 s → 619 s: **H\* does not move once, for 245 s.**

At the rate it had just sustained, the remaining 29,328 blocks are about 54
seconds of work. The run does not end short because the fold is slow. It ends
short because the fold stops.

### The named bottleneck: a rewind ask the frontier is right to refuse

At the stall `dumpstate blocker` carries, in its own words:

- `tip_finalize.rewind_churn` — "tip_finalize cursor asked to rewind
  3193025->3193024 again with hstar pinned at 3193024 since the first rewind <!-- stale-ok: verbatim quote of the blocker text that one 2026-08-20 run emitted -->
  (3 consecutive asks) - projection-hole/reconcile livelock; refusing further
  rewinds so the ladder escalates instead of looping forever"
- `recovery_coordinator.no_applicable_rung` — "critical inconsistency unresolved
  but no cheap self-healing condition owns it"
- `sticky_escalator.resnapshot_no_base` and
  `sticky_escalator.refold_no_anchor_artifact` — both "A PERSON decides"
- `sync_rate_below_floor` — "fold rate 0.000 bps below floor 1.000 bps ...
  while peers connected and pending work exists"
- `chain.tip_behind_header_chain` — "body-missing-at-successor: tip=3193024
  best_valid_header=3222364 gap=29340"

and the condition engine reports `operator_needed
name=reducer_frontier_reconcile_light attempts=5 active_for=191s`. So the
sequence is: something reconciles the frontier row at 3,193,025 back to
3,193,024, `tip_finalize` refuses the fourth such ask (correctly — that guard is
what stops an infinite loop), the ladder escalates, and no rung owns the hole.
Nothing here is a rate problem and nothing here is fixed by waiting longer.

`reducer_frontier_reconcile_light` is the next owner. It is a separate change,
and it is not made here.

### One thing that was wrong, and is fixed

While the fold sat pinned, `header_repair_no_source` said "zclassicd oracle
unreachable and no connected peer can serve a P2P getdata re-fetch" — with
`peers=-1` in the log line — while the node was connected to `127.0.0.1:8033`
and accepting headers from it. `cure_request_peer_refetch()` returns `-1` for
"the target is not on the active chain, so I never asked the network"; the
caller tested `peers <= 0` and printed that as an absence of peers. The two are
now kept apart and the blocker names whichever actually held, carrying the real
connected-peer count. A refusal that names the wrong cause sends the recovery
ladder and the operator looking in the wrong place.
`lib/test/src/test_stale_validate_headers_repair_condition.c` holds the
regression: peers present, target off the active chain, and the blocker must not
claim there is no peer. Red before the change, green after.

### The external prerequisite, in the node's own words

The mission recipe for C3 starts with "mint a fresh near-tip bundle from a
producer session whose source identity matches the candidate". Asked directly,
on 2026-08-20, the canonical node says it cannot open that session at all:

```bash
zclassic23 -rpcport=18232 -datadir=~/.zclassic-c23 dumpstate bundle_exporter
```
```json
{"session_open":false,"qualified":false,
 "degradation_reason":"producer receipt begin: datadir session does not exactly
   match current running binary / source claim / source epoch / profile",
 "exports_ok":0,"exports_failed":0,
 "last_export_height":3056758,"generations":[3056758]}
```

That is the standing exporter refusing by name, not a missing feature. The
running process was started on 2026-08-15 07:48 from a binary built at 07:47,
so its source claim cannot equal any candidate committed since; the session
`config/src/consensus_state_producer_receipt.c` demands is exact, and it is
right to be. The one generation it has ever produced is the bundle it already
serves, and `dumpstate rom_seed` confirms that is the only artifact it
advertises — a 513,867,776-byte `consensus_bundle`, and no
`ROM_ARTIFACT_HEADER_SEED`, which is why the runs above had to take their
header seed from a second host.

So a cold client fetching from this node inherits a bundle whose height is
about 166,000 blocks behind where the node itself is, and must fold the
difference — which is the path that livelocks above. Re-opening the exporter
means restarting the canonical node onto a matching binary. That is the
operator's decision under AGENTS.md P0, not this lane's, and it is the exact
prerequisite C3 is waiting on.

## Running the reports

```bash
make c3-stopwatch-report           # judges ~/.local/state/zclassic23-c3-stopwatch/history.jsonl
make netdisrupt-stopwatch-report   # judges ~/.local/state/zclassic23-netdisrupt-stopwatch/history.jsonl
```

Both are false-green-guarded the same way `soak-evidence-report` is: if
the judge does not print a `VERDICT=` line at all (a crashed/no-op judge),
the recipe fails loud regardless of the judge's own exit code.

## Running the harnesses directly (manual / one-off)

```bash
make mvp-coldstart-to-tip-stopwatch          # C3, ZCL_BIN=/ZCL_PEER= override the target
make mvp-netdisrupt-recovery-stopwatch       # PROOF B, ZCL_ND_* override the client/upstream/timing
```

Both propagate exit codes `1`/`3`/`4` as a failing `make` recipe; a `2`
(SKIP) maps to a clean `exit 0` — a missing fixture is not itself a
verdict on the underlying claim.

## Periodic timers

`deploy/examples/zcl-stopwatch-peer.service` is a dedicated minimal
serving peer (ports 39070-39073) the C3 harness dials, kept separate from
the canonical `zclassic23.service` (port 8033) so these gates can never
contend with or churn the live node. `zcl-c3-stopwatch-run@.service` /
`.timer` and `zcl-netdisrupt-run@.service` / `.timer` run the two
collectors every 6h (offset 30 minutes apart); both `OnFailure=` into
`zcl-stopwatch-onfailure.service`, which fires only on a lock/append
failure, never on a legitimate non-PASS run verdict. See
`deploy/examples/README.md` for the full unit descriptions.
