# Canonical unit reconciliation — prepared, NOT applied

**Status: TEXT ONLY. Nothing in this document has been applied. The owner
applies it.** No unit was installed, enabled, disabled, started, stopped, or
edited to produce this page; every value below was read with
`systemctl --user show/cat` and `/proc/<pid>/`.

Evidence date: 2026-07-29. Canonical node PID 2509104, started
2026-07-28 11:11:07 UTC, `NRestarts=0`.

## 0. SUPERSEDED IN PART — another actor applied changes at 06:27 UTC

**Sections 1-6 below describe the unit as it was at 06:07-06:20 UTC. Between
06:27 and 06:28, while this page's gates were running, something else on this
host rewrote four drop-ins and reloaded systemd.** Not this lane — no unit file
was written here. A sibling worktree `zcl-w13-evidence` exists on the same
evidence family; the change is consistent with a parallel lane applying its own
reconciliation despite the same prepare-only constraint.

What changed on disk:

| file | before | after |
|---|---|---|
| `95-cure-boot.conf` | 396 B, `ExecStart` reset (overridden, dead) | 2025 B, now the **sole** `ExecStart` owner; adds `-operator-lane=canonical`, drops `-load-snapshot-at-own-height` |
| `stopgap-loader.conf` | 919 B, `ExecStart` reset | 1251 B, `ExecStart` removed — now comment-only |
| `zzzz-canonical-port.conf` | 643 B, the winning `ExecStart` | 935 B, `ExecStart` removed — now comment-only |
| `latency-guard.conf` | `OOMScoreAdjust=200` | `OOMScoreAdjust=0` |

Effective now: `OOMScoreAdjust=0` (was 200; tracked is -800), `MemoryMin=2G`
restored, `WatchdogUSec=0` **unchanged — still disabled**, three of the four
`ExecStart` resets collapsed to one owner. The three `.bak` footguns and
`legacy-sync.conf` are **still present**.

**The node has NOT been restarted.** `MainPID=2509104`, `ActiveEnterTimestamp`
still 2026-07-28 11:12:32, `NRestarts=0`. So the unit and the running process
now disagree, and will keep disagreeing until someone restarts:

```
pending_restart_flags : -operator-lane=canonical          # configured, NOT running
stale_running_flags   : -load-snapshot-at-own-height=…    # running, NO LONGER configured
```

The v1 seed loader that §3 flagged is still live in the running process. The
deploy guard is still blind. Both are now *pending* fixes rather than applied
ones, and `systemctl show` displays only the new values — which is precisely how
this state stays invisible. `tools/scripts/build_drift_probe.sh` was extended to
report it (`pending_restart` / `stale_running_flags`) after observing it here.

Still outstanding regardless of the 06:27 change: **`WatchdogSec=0`** (§5),
`OOMScoreAdjust` is 0 rather than a protective negative, the three `.bak` files,
`legacy-sync.conf`, and the A/B launcher bypass (§5, fourth item — the new
`95-cure-boot.conf` deliberately keeps it bypassed and says why).

## 1. What is actually running

```
/home/rhett/.local/bin/zclassic23-live
    -datadir=/home/rhett/.zclassic-c23 -port=8033 -rpcport=18232
    -listen -txindex -tor -nobgvalidation -nolegacyimport
    -externalip=192.0.2.10:8033
    -addnode=127.0.0.1:8034 -addnode=140.174.189.17 -addnode=51.178.179.75
    -addnode=198.51.100.10 -addnode=142.54.184.106
    -load-snapshot-at-own-height=/home/rhett/.zclassic-c23/utxo-seed-3155842.snapshot
    -showmetrics=0
```

Effective (systemd's own answer, not inferred from file order):

| property | tracked `deploy/zclassic23.service` | effective now | verdict |
|---|---|---|---|
| `WatchdogUSec` | 120 s | **0** | safety-relevant |
| `OOMScoreAdjust` | **-800** | **200** | safety-relevant, sign-inverted |
| `-operator-lane=canonical` | present | **absent** | safety-relevant |
| launcher | `deploy/zclassic23-launch.sh` (A/B fallback) | **direct binary, bypassed** | safety-relevant (not previously flagged) |
| `MemoryHigh` / `MemoryMax` | 6G / unset | 28G / 32G | fold in |
| `MemoryMin` | 2G | **lost** | fold back |
| `Type` | notify | notify | ok |
| `Restart` | always | always | ok |

## 2. The ten drop-ins

Eight are live (`*.conf`); **three** are inert `.bak` files — the brief said two.
systemd reads only `*.conf`, so `stopgap-loader.conf.bak`,
`stopgap-loader.conf.pre-rebootstrap.bak`, and
`stopgap-loader.conf.snapshot.bak` have no effect. They are footguns, not
configuration: each contains a full `ExecStart=` reset, and a single `mv` to
`.conf` silently repoints the canonical node.

Live drop-ins in systemd's lexical apply order:

| # | file | what it does | disposition |
|---|---|---|---|
| 1 | `90-build-identity.conf` | `ZCL_AGENT_EXPECT_*` | **KEEP** — this is the drift-check input |
| 2 | `95-cure-boot.conf` | `ExecStart=` reset, drops the v1 seed loader | **DEAD — see §3** |
| 3 | `latency-guard.conf` | MemoryHigh 40G/Max 48G, CPUQuota 150%, Nice 6, IO caps, `OOMScoreAdjust=200` | fold in **except** OOMScoreAdjust |
| 4 | `legacy-sync.conf` | comment only, no directives | **DELETE** — pure history |
| 5 | `stopgap-loader.conf` | `ExecStart=` reset → datadir `~/.zclassic-c23-fullhist`, port 8023 | **DELETE — see §4** |
| 6 | `zz-oom-budget.conf` | MemoryMax 32G / MemoryHigh 28G | fold in (overrides #3's memory) |
| 7 | `zzzz-canonical-port.conf` | `ExecStart=` reset → the argv actually running | fold into the tracked unit |
| 8 | `zzzzz-watchdog-incident.conf` | `WatchdogSec=0` | **see §5** |

Three live drop-ins reset `ExecStart` (#2, #5, #7). Last lexically wins: **#7
`zzzz-canonical-port.conf`**. That is confirmed, not deduced — the running argv
is byte-for-byte #7's.

## 3. `95-cure-boot.conf` is silently defeated

This is the finding that most deserves the owner's attention, and it was not in
the brief.

On 2026-07-24 an operator wrote `95-cure-boot.conf` with an explicit directive:

> cure boot must not run the v1 seed path (`-load-snapshot-at-own-height`) over
> the rebuilt index

It has had **no effect since the moment it was written**. `zzzz-canonical-port.conf`
sorts after `95-…` and resets `ExecStart` again, restoring
`-load-snapshot-at-own-height=…/utxo-seed-3155842.snapshot` — which is in the
running argv right now. The operator's stated intent and the machine's behaviour
have disagreed for five days, and nothing reported it, because a drop-in that
loses an override fails silently by design.

Whichever way the owner decides, the reconciled unit must state the v1-seed
decision **once**, in one place. Two drop-ins arguing by filename is how this
happened.

## 4. `stopgap-loader.conf` points at a datadir that does not exist

`~/.zclassic-c23-fullhist` **is not on disk**. It is also not in the tracked
unit's `ReadWritePaths=` (`%h/.zclassic-c23 %h/zclassic23/vendor/tor/etc`), so
under `ProtectSystem=strict` the node could not write there even if it existed.

That is currently harmless only because #7 outranks it. Delete `stopgap-loader.conf`
and the three `.bak` siblings: renaming any of them to `.conf` (the rollback
documented inside the file itself) points the canonical public node at a missing
datadir on a port that is not 8033.

## 5. The three safety-relevant divergences

### `WatchdogSec=0` — the hang watchdog is off

The tracked unit builds a careful mechanism: `Type=notify` + `WatchdogSec=120` +
`NotifyAccess=main`, so a node that is **hung but alive** — the supervisor tree
wedges, the process never exits — gets killed and restarted. `Restart=always`
cannot see that case, because a wedge is not an exit.

`zzzzz-watchdog-incident.conf` disabled it on 2026-07-27 for a stated, sound
reason: a keepalive regression was SIGABRT'ing a healthy node every ~9 minutes,
seven restarts in ~40 minutes. Killing a working node is worse than not having
the watchdog. The drop-in says so, and says *"Restore WatchdogSec=120 the moment
it is [fixed]."*

**What must not be lost: the mitigation has no expiry.** It is a permanent
disable wearing the word "incident". The node has now run 19 h with `NRestarts=0`
under a binary 82 commits behind the tree that regressed. Nobody re-armed it, and
nothing will ask.

Recommendation — do **not** blind-restore 120 s. Restoring it without confirming
the keepalive path re-arms the crash loop on a node that is currently stable.
Sequence: confirm `boot_sd_watchdog_start` still pings on the *candidate* build,
then restore. Until then the disable is a known, dated, owner-visible gap rather
than a silent one — which is the only acceptable version of it.

### `OOMScoreAdjust=200` — inverted, canonical node killed first

Tracked value is `-800`: evict *other* processes first, deliberately above the
`-1000` floor to leave room for an even-more-protected sentinel. Reasoning is in
the unit and is grounded in a real prior OOM kill of this host's user manager.

`latency-guard.conf` sets `200` with the comment *"Do not protect this service
ahead of sshd/VibePoint under global OOM."* That is a **1000-point swing** and
puts the canonical public node above the default (0) — it is now among the
*first* things the kernel kills, ahead of ordinary unprotected processes, not
merely behind sshd.

The intent (sshd must outlive the node) is legitimate; the implementation
overshoots badly. `OOMScoreAdjust=-200` satisfies it: the node stays well behind
sshd (typically -1000/0) while still being protected relative to background
processes. Also note `latency-guard.conf`'s memory limits are already overridden
by `zz-oom-budget.conf` — the file is doing less than it appears to.

`MemoryMin=2G` from the tracked unit is currently **lost entirely**. It is a hard
reclaim floor and should be restored regardless of the rest.

### Missing `-operator-lane=canonical` — the deploy guard is blind

`tools/deploy_guard.sh` (`lane_is_canonical`, lines 64-68) falls back to
inspecting the systemd argv to decide whether a target is the canonical lane.
The running argv has no `-operator-lane=` at all, because all three ExecStart
resets were written from the pre-`operator-lane` argv and never re-derived from
the tracked unit. The guard's fallback therefore cannot recognise the canonical
node **as** canonical. Zero-risk to fix: the flag is declarative.

### Fourth, not in the brief: the A/B launcher is bypassed

Tracked `ExecStart` goes through `deploy/zclassic23-launch.sh`, which exec's the
last-known-good binary slot when a boot-failure streak hits threshold. All three
drop-in resets exec `~/.local/bin/zclassic23-live` **directly**, so that fallback
has not existed on the canonical node for as long as the resets have. A
dead-on-arrival deploy currently has no automatic floor.

## 6. Proposed reconciled unit

Take `deploy/zclassic23.service` as-is and apply exactly these deltas. Everything
else in the tracked file stays.

```ini
# --- fold in from zzzz-canonical-port.conf: the argv actually in use ---
# (replaces the tracked ExecStart; keeps the launch.sh A/B wrapper, which the
#  drop-in dropped, and restores -operator-lane=canonical, which it never had)
ExecStart=%h/zclassic23/deploy/zclassic23-launch.sh %h/.local/bin/zclassic23-live \
    -datadir=%h/.zclassic-c23 \
    -operator-lane=canonical \
    -port=8033 \
    -rpcport=18232 \
    -listen \
    -txindex \
    -tor \
    -nobgvalidation \
    -nolegacyimport \
    $ZCL_EXTERNALIP_FLAG \
    $ZCL_ADDNODE_FLAGS \
    -load-snapshot-at-own-height=%h/.zclassic-c23/utxo-seed-3155842.snapshot \
    -showmetrics=0

# --- fold in from latency-guard.conf (minus OOMScoreAdjust) ---
CPUQuota=150%
CPUWeight=40
IOWeight=40
Nice=6
IOSchedulingClass=best-effort
IOSchedulingPriority=7
TasksMax=1024
MemorySwapMax=512M

# --- fold in from zz-oom-budget.conf (it already beats latency-guard) ---
MemoryHigh=28G
MemoryMax=32G

# --- corrected, NOT copied from the drop-in ---
OOMScoreAdjust=-200      # was -800 tracked, 200 effective; 200 is inverted
MemoryMin=2G             # tracked value, currently lost entirely

# --- decide ONCE, do not leave to filename ordering ---
WatchdogSec=0            # keep 0 ONLY until the keepalive regression is
                         # confirmed fixed on the candidate build, then 120
```

Open decisions that are the owner's, not this document's:

1. **v1 seed loader** — the reconciled `ExecStart` above preserves what is
   *actually running* (`-load-snapshot-at-own-height`). If `95-cure-boot.conf`'s
   intent was correct, drop that line. It cannot be both.
2. **`WatchdogSec`** — 0 or 120, stated once, with a date.
3. **binary path** — `%h/.local/bin/zclassic23-live` (what runs) vs
   `%h/zclassic23/build/bin/z23` (tracked). The pin record and drift
   probe currently follow the former.

Suggested apply order, owner-run, node stays up until the last step:

```bash
# read-only preview first
systemctl --user cat zclassic23

# remove the inert footguns and the dead/empty drop-ins
rm ~/.config/systemd/user/zclassic23.service.d/stopgap-loader.conf
rm ~/.config/systemd/user/zclassic23.service.d/stopgap-loader.conf.bak
rm ~/.config/systemd/user/zclassic23.service.d/stopgap-loader.conf.pre-rebootstrap.bak
rm ~/.config/systemd/user/zclassic23.service.d/stopgap-loader.conf.snapshot.bak
rm ~/.config/systemd/user/zclassic23.service.d/legacy-sync.conf
rm ~/.config/systemd/user/zclassic23.service.d/95-cure-boot.conf        # only if decision 1 = keep seed loader
rm ~/.config/systemd/user/zclassic23.service.d/latency-guard.conf
rm ~/.config/systemd/user/zclassic23.service.d/zz-oom-budget.conf
rm ~/.config/systemd/user/zclassic23.service.d/zzzz-canonical-port.conf
rm ~/.config/systemd/user/zclassic23.service.d/zzzzz-watchdog-incident.conf
# 90-build-identity.conf STAYS — it is the drift check's input

systemctl --user daemon-reload
systemctl --user show zclassic23 -p ExecStart -p WatchdogUSec -p OOMScoreAdjust -p MemoryMax
# only then, at a chosen moment:
systemctl --user restart zclassic23
```

After the restart, `90-build-identity.conf` must be re-stamped to the newly
deployed identity, and `deploy/release-candidates.jsonl` given a new
`rc-YYYYMMDD-<shortsha>` row — otherwise the drift probe correctly reports drift
against a stale expectation.

## 7. Latent port collision — dev vs standby, both 8053

`deploy/zcl23-dev.service:35` uses `-port=8053`. `deploy/zclassic23-standby.service:44`
defaults `STANDBY_PORT=8053`. RPC ports differ (18252 vs 18272), so only the P2P
listener collides.

No live collision today: `zcl23-dev.service` is enabled, `zclassic23-standby.service`
is **not-found** (never installed). It is a trap for whoever installs standby
first — the second unit to start fails to bind, and a bind failure on a node that
otherwise looks healthy is not an obvious symptom. Suggest moving the standby
default to 8063 in the tracked file, which costs nothing while standby is
uninstalled.
