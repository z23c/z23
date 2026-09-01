# Release candidate pin — naming a build so it cannot quietly change

A proof lane is only worth running if the thing under proof holds still. This
page defines the one record that says which build is under proof, and the one
probe that checks the box still agrees.

## The problem this solves

On 2026-07-28 the live binary `~/.local/bin/zclassic23-live` was replaced at
11:10 and the canonical unit restarted at 11:12. Nothing recorded it. The deploy
was reconstructed afterwards from file mtimes, and `docs/HANDOFF.md` went on
naming a build (`981a8d01e9a1fd35…`) that was not running and, as far as the
repository can tell, never was — that string does not resolve to a commit and
does not match the running binary's baked identity.

The expectation was stored. The ground truth was queryable. Nothing compared
them on a schedule.

## The candidate triple

A candidate is pinned by three values, because any one of them alone can be
satisfied by the wrong artifact:

| field | what it pins | why it is not enough alone |
|---|---|---|
| `commit` | the source revision | the same commit builds to different bytes under different flags |
| `source_id_sha256` | what the binary was compiled FROM (baked in, read via `agentbuild`) | survives a rebuild, so two different artifacts can share it |
| `artifact_sha256` | the exact bytes | says nothing about provenance on its own |

All three live in `platform/deploy/release-candidates.jsonl`, one JSON object per line,
append-only. The last line is the active pin unless `ZCL_DRIFT_PIN_TAG` names
another.

## Tag convention

```
rc-YYYYMMDD-<shortsha>
```

`YYYYMMDD` is the date the candidate was cut (UTC), `<shortsha>` is the 9-char
abbreviated commit. Example: `rc-20260728-75afb4361`.

Before this convention there were three ad-hoc tags
(`archive/crashonly-verb-selection`, `pre-S4-deploy-2026-05-22`,
`starterpack-3155842`) with no shared shape, and nothing in `Makefile`,
`tools/`, or `deploy/` ever created one.

Cutting a candidate is two steps, both owner-run:

```bash
git tag -a rc-20260728-75afb4361 -m 'proof lane candidate' 75afb4361
# then append the observed triple to platform/deploy/release-candidates.jsonl
```

`tools/release.sh` is deliberately left alone here: it refuses everything but
`--verify` by design, and that containment is not this page's to relax.

## `provenance` — how the row was obtained

- `observed-running` — the triple was read off a process that was already
  running (`/proc/<pid>/exe`). This is the honest label when a build predates
  the pin record, as `rc-20260728-75afb4361` does.
- `built-and-deployed` — the row was written by the deploy that produced it.

A row is a record of what was observed, never a wish. Do not hand-write one.

## Promotions have their own ledger

This page's ledger says which build is *under proof*. The separate, signed,
hash-chained ledger `platform/deploy/promotion-receipts.jsonl` records the act of
*promoting* one to the proof server — see
[`PROMOTION_RECEIPTS.md`](./PROMOTION_RECEIPTS.md). It is written by
`tools/scripts/promotion_receipt.sh` from `tools/ship.sh`, never by hand, and it
is the authority a local `proof-server/*` git tag never could be: tracked, so it
replicates; chained, so a rewrite is detectable; signed, so a third party can
check authorship offline.

## The probe

`tools/scripts/build_drift_probe.sh` compares the pin against reality every 5
minutes and appends to `~/.local/state/zclassic23-drift/build-drift-ledger.jsonl`
— outside the node process and outside every datadir, so the record survives a
crash.

```bash
tools/scripts/build_drift_probe.sh report    # human readable, no append
tools/scripts/build_drift_probe.sh collect   # append one ledger line
tools/scripts/build_drift_probe.sh assert    # exit 1 on drift, for a pager
```

It reports **four** verdicts rather than one, because they fail independently:

- `match` — the expectation the running process was STARTED with
  (`ZCL_AGENT_EXPECT_SOURCE_ID` from `/proc/<pid>/environ`) vs what it is running.
- `pin_match` — the checked-in candidate vs what it is running.
- `artifact_path_matches_running` — the file at `~/.local/bin/zclassic23-live`
  vs the inode the process is executing.
- `pending_restart` — the unit's *configured* `ExecStart` vs the running argv,
  reported as `pending_restart_flags` (configured but not running) and
  `stale_running_flags` (running but no longer configured).

That fourth verdict exists because editing a drop-in and reloading changes what
the unit *will* run without changing what it *is* running, and `systemctl show`
displays only the new value with no hint that the live process predates it. The
identity checks cannot see it — the binary is byte-identical on both sides.
Observed on this host at 2026-07-29 06:27:

```
"pending_restart":true,
"pending_restart_flags":"-operator-lane=canonical",
"stale_running_flags":"-load-snapshot-at-own-height=…/utxo-seed-3155842.snapshot"
```

`stale_running_flags` is the more dangerous direction: a flag *removed* from the
unit stays in effect until the restart, so an operator who deletes it and
reloads can believe it is gone while the node is still acting on it.

That last one is the one a path-based check cannot answer. `make agent-doctor`
fingerprints the file at the path, which is correct for "is my tree deployed"
and wrong for "what is running": a deploy that overwrites the binary under a
live process leaves the path showing the new build while the node keeps
executing the old one until the next restart. `/proc/<pid>/exe` is pinned by the
kernel to the executing inode, so that window is visible.

`tree_distance_commits` is reported but is not a drift verdict — a proof lane is
*supposed* to sit still while `main` moves. It is there so nobody has to guess
how far behind the candidate is.

## Reading the ledger

```bash
# last verdict
tail -1 ~/.local/state/zclassic23-drift/build-drift-ledger.jsonl

# every moment the running identity changed
grep -o '"running":"[0-9a-f]*"' ~/.local/state/zclassic23-drift/build-drift-ledger.jsonl \
  | uniq -c
```
