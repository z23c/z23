<!-- Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 -->

# Flag registry action reuse control (2026-09-23 UTC)

The optional `check-flag-registry` lint cache uses an action key derived from
its tracked `.c`, `.h`, `.sh`, and `Makefile` path set and contents; `flags.def`;
every first-use pointer target emitted by the C23 parser; the checker binary;
Git, compiler, xargs, Bash, `/bin/sh`, and `/usr/bin/env` executable bytes;
compilation flag variables;
locale category variables, path, time zone, Git environment; the host OS; the
exact gate command; and the HEAD commit date used by expiry policy. The
checker's embedded selftest fixtures and harness are covered by the executable
and tracked shell source. A missing or unreadable input, or any `LD_*` or
`DYLD_*` loader override, disables reuse.

The candidate `53ee43a62397e6f1be4d1773988530a1350ed0b9` passed a cold
audit of this action under key
`e0e226a5584ac8a7ea72f3b363a594f927e1a4f72f3cf760e151ffc1e80acf5f`:
20.70 s real, 17.84 s user, 2.86 s system. A subsequent exact-input run
reused the PASS in 3.39 s real, 2.31 s user, 1.12 s system. Appending a
comment to `flags.def` forced a miss and a fresh PASS; the original bytes were
restored. An isolated record control showed that a contradictory observation
poisons the key and a later PASS cannot erase that refusal. The mandatory
`make lint` and landing proof remain cold.

This document changes no input to this action. Its own commit is the
successor-candidate control: a different Git SHA should reuse the eligible
PASS only if the complete action key remains byte-identical. The local packet
under `~/.local/state/development/z23-component-control-bbe3/` retains the
timed logs and exact action-key readout.

The v2 key closes two additional input holes found during the Linux proof
wait: it binds every `LC_*` value with NUL-delimited name/value pairs and
refuses loader overrides whose external library bytes are not bounded by the
action. Under the `77ba6764` main base, `LC_COLLATE=C` produced a different
key (`4242471a9d851dbb3b69130834018b065dd5b797ba1bdcd5322373774ce76239`)
from the ordinary environment (`91000b312da884f32229b6fecb31d6fc55302d2161f17ce1aaedd120ac2f1f4a`),
and `LD_PRELOAD` made the action uncacheable. The updated cold action took
20.04 s real, 17.44 s user, 2.58 s system; its exact-input hit took 3.27 s
real, 2.29 s user, 1.01 s system. The existing lint-cache selftest now also
asserts that a contradictory observation stays refused after a later PASS.

The v3 action domain additionally binds `/bin/sh`, which the C checker uses
for its Git capture, and `/usr/bin/env`, which dispatches the shell wrapper.
This retires v2 action records without invalidating the unrelated v2
whole-tree lint cache.
