<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Receiver deadline recovery

Source baseline: `1ee43086d0d727083c79b602e3a4681949a69fbe`.

The resident mail receiver's `deadline_s` bounds one drive. A normal exit
at that deadline has status zero. The systemd unit previously used
`Restart=on-failure`, so that exit left the receiver stopped while directives
could remain queued. The unit now uses `Restart=always`, retaining its
existing restart delay and start limit. An explicit `systemctl stop` still
stops the unit.

The fleet brief now reports `local receiver down: receive.lock free` when a
receiver lock file exists without a holder. It inserts the incident before
per-directive blockers, so a full blocker list cannot hide it. The regression
checks a queued directive, the down incident, an independently held worker
lock, and the absence of the incident when the receiver lock is held.

This is a local service and fixture contract. It does not claim that any
maintainer-host service has been restarted or that queued directives have
been delivered.
