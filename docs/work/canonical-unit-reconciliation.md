# Systemd drop-in reconciliation

Procedure for finding out what a systemd unit is actually configured to run,
and actually running, once several `*.d/*.conf` drop-ins have accumulated on
top of a tracked unit file — and for folding them back into one file that
says what it means.

This is a read-first, act-later procedure. Every inspection step below is
safe to run against a live unit; nothing in this document installs, enables,
starts, stops, or edits a unit. Applying a reconciled unit is a separate,
deliberate step an operator takes after reviewing the diff.

## 1. Why drop-ins drift out from under a tracked unit

A long-running service accumulates drop-ins one at a time: an operator wants
to change one setting under time pressure, and editing
`<unit>.service.d/<name>.conf` is lower-friction than editing the tracked
unit file and going through review. Each individual drop-in is a reasonable
fix for the moment. The accumulated set, months later, is not something
anyone chose — it's an emergent, unreviewed merge of however many one-off
changes happened to land, in whatever order their filenames happen to sort.
Nobody wrote "the current config" anywhere; it only exists as systemd's
runtime merge of every fragment on disk.

## 2. Lexical order is the only authority

systemd applies `*.d/*.conf` files in **lexical filename order**, not
modification time and not the order changes were intended to take effect in.
When two drop-ins set the same directive, the one that sorts later wins —
full stop. A file named `zzzz-something.conf` outranks one named
`50-something-else.conf` even if the numbered file is far newer, and even if
its own comments say it is the current, authoritative setting. The filename
carries no semantic weight; only its sort position does.

Do not reconstruct the effective config by reading the directory in `ls`
order and reasoning about it by eye. Ask systemd directly:

```bash
systemctl [--user] cat <unit>     # every file, in the order systemd applies them
systemctl [--user] show <unit>    # the merged, effective property values
```

For any single property, `show` is the only value guaranteed correct. A
by-eye reconstruction is exactly the kind of exercise that silently drops a
drop-in nobody remembered existed.

## 3. Detecting an `ExecStart=` collision

`ExecStart=` has special merge semantics that make it the most common source
of drift:

- A **bare** `ExecStart=` line (nothing after the `=`) clears every
  `ExecStart=` set so far — by the base unit and by every earlier drop-in.
- A **non-empty** `ExecStart=` line, if nothing cleared first, is *appended*
  as an additional command to run in sequence — it does not replace the
  existing one.

So a drop-in that means to fully replace the command line must contain a
clearing line followed by the new one. To find every contender for what
actually runs:

```bash
grep -n '^ExecStart=' <unit>.d/*.conf
```

A drop-in with only a non-empty `ExecStart=` line (no clearing line before
it) is appending, not replacing — almost always a bug if the intent was to
override. A drop-in with a clearing line followed by a full command is a
genuine reset and a candidate winner. When more than one drop-in performs a
full reset, the winner is — again — whichever sorts last lexically, not
whichever reads as more recent or more deliberate. This is exactly how an
operator's explicit, well-commented directive in one drop-in gets silently
defeated by an unrelated `ExecStart=` reset in a later-sorting drop-in: the
losing drop-in's own comment can still claim to be in effect, and nothing
checks that claim against what systemd actually merged.

## 4. Effective config vs. the running process — read `/proc/<pid>/cmdline`

`systemctl show` reports the configuration that would apply on the **next**
start. If any drop-in changed since the unit was last (re)started, that is
not necessarily what the running process is doing right now. The two can
disagree indefinitely, silently, for as long as nobody restarts the unit —
and `systemctl show` gives no hint that this gap exists.

This is the single most valuable step in the whole procedure: never trust a
unit file, a drop-in, or `systemctl show`'s `ExecStart` property to describe
what a daemon is currently running. Only the running process's own argv can:

```bash
pid="$(systemctl [--user] show -p MainPID --value <unit>)"
tr '\0' '\n' < /proc/"$pid"/cmdline
```

When the effective config and the running argv disagree, record both
explicitly — a two-column "configured now / running now" note — rather than
reporting only whichever one the tool you happened to run shows. Which one
you get depends entirely on which question you asked.

## 5. Concurrent modification is a real hazard mid-reconciliation

Nothing stops another actor — a person, a cron job, a deploy script, a
different automation lane on the same host — from writing a new drop-in and
running `daemon-reload` (or restarting the unit) while a reconciliation is in
progress. A reconciliation is not a lock.

Treat every reconciliation snapshot as a claim about the state observed at
the moment it was captured, not a durable fact about the unit going forward.
Re-run the `show` / `cat` / `/proc/<pid>/cmdline` checks immediately before
acting on any of it — do not act on state read minutes or hours earlier
without re-checking — and say explicitly, in whatever the reconciliation
produces, that it is a point-in-time capture rather than a live guarantee.

## 6. Checklist

1. List drop-ins in `<unit>.service.d/` in lexical order (that is the apply
   order). Separate anything systemd will not read: it only loads `*.conf`,
   so a `.bak` or otherwise-renamed sibling has no effect today — but it is a
   footgun, because renaming it back to `.conf` later silently reactivates
   whatever it contains.
2. For each safety-relevant directive (`ExecStart`, `OOMScoreAdjust`,
   `WatchdogSec`, `MemoryMin`/`MemoryHigh`/`MemoryMax`, and anything else the
   unit depends on for correctness rather than convenience), grep every
   drop-in for that key and identify the lexically-last file that sets it.
   That file's value governs, regardless of what any other file's comments
   claim.
3. Cross-check each drop-in's own stated intent against what it actually
   does once later drop-ins are accounted for (§3). A directive can be fully
   defeated by an unrelated later drop-in — most commonly an `ExecStart`
   reset that happens to also revert something a different, still-intended
   drop-in changed — with zero signal that this happened.
4. Diff the effective config (`systemctl show`) against the tracked unit file
   in version control, property by property.
5. Get `MainPID` and read `/proc/<pid>/cmdline` to catch a pending-vs-running
   divergence (§4).
6. Propose one reconciled unit: fold every override that should persist
   directly into the tracked unit file, so intent lives in one place instead
   of racing filenames. Flag anything that is a policy decision rather than a
   mechanical merge (a numeric threshold, a feature flag, a safety trade-off)
   for the owner to state once, explicitly, with a date — not left implicit
   in whichever drop-in happens to sort last.
7. Apply deliberately: preview with `systemctl cat`, remove the drop-ins the
   reconciled unit now supersedes, `daemon-reload`, re-verify the effective
   properties, and only then restart. The running process still will not
   reflect the change until the restart happens (§4).
8. After the restart, update anything that fingerprints "what is currently
   deployed" — build-identity records, drift probes, release-candidate pins —
   or it keeps comparing the new, correct state against a stale expectation
   and reports drift that no longer exists.

## 7. Worked example: a dropped flag breaks a fallback silently

`tools/deploy_guard.sh` has a systemd fallback path (`guard_from_systemd`)
used when the native deploy-guard RPC is unavailable: it reads the unit's
effective `ExecStart` via `systemctl show`, extracts the `-operator-lane=`
argument, and refuses a canonical-lane action if that lane is declared
canonical — but also refuses if **no** lane is declared at all, since an
undeclared lane cannot be proven non-canonical. `-operator-lane=` is set
directly on the process command line (see `deploy/zclassic23.service`,
`deploy/zcl23-dev.service`, `deploy/zclassic23-standby.service`).

This is the general hazard from §3 in concrete form: if a drop-in performs an
`ExecStart` reset (§3) and the person writing it copied an older argv that
predates the `-operator-lane=` flag, the flag silently disappears from the
running unit. Nothing about that failure is loud — the unit keeps running
fine. The only visible effect is downstream: any tooling that depends on the
flag being present (here, the deploy guard's fallback) either misclassifies
the lane or fails closed. Any time a reconciliation touches a unit with an
`ExecStart` reset, check whether some other script parses that same
`ExecStart` for a flag, and confirm the flag survived the merge.

## 8. Worked example: a port default shared by two units

`deploy/zcl23-dev.service` and `deploy/zclassic23-standby.service` are
separate unit files meant to run on the same host at once, each with its own
datadir and port set. Both currently default their P2P listen port to
`8053` (`deploy/zcl23-dev.service:51`, and `STANDBY_PORT=8053` in
`deploy/zclassic23-standby.service` / `deploy/zclassic23-standby.env.example`).
Their RPC ports differ (`18252` vs `18272`), so only the P2P listener would
collide.

No collision is visible until both units are actually installed and started
on the same host — one unit binding to a port already in use is a bind
failure, not a crash with an obvious cause, and it's easy to read as
unrelated to the other unit entirely. This is the general lesson from
reconciling multiple units that share a deploy target: check every unit
meant to coexist for a default that assumes it's the only one running, not
just the unit currently in front of you.

## 9. Proposing a reconciled unit

Once §§1-6 have produced a full inventory (which drop-in governs which
directive, and why), write the reconciled unit as a diff against the tracked
file, not as a fresh file: keep every tracked directive that is not being
changed, and annotate each folded-in change with which drop-in it came from
and why. For example:

```ini
# --- folded in from a drop-in reset: <name>.conf ---
# (kept: the flag the drop-in dropped; corrected: the sign below)
ExecStart=<binary> \
    -operator-lane=canonical \
    ...

# --- corrected during reconciliation, not copied verbatim from any drop-in ---
OOMScoreAdjust=-200   # a drop-in had flipped this to a positive value —
                      # confirm the sign against the unit's own comments
                      # before trusting any drop-in's number
```

Call out every open decision the reconciliation surfaces but cannot resolve
on its own — a safety mitigation with no expiry date, a flag whose intended
value depends on a fix landing elsewhere, a choice between two binary paths
— as a numbered list for the owner, not folded silently into the proposed
unit. A reconciliation's job is to make every current override visible and
attributable in one place; it is not authorized to make the underlying
policy calls itself.
