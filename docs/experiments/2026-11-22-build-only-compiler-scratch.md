<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Compiler scratch and Makefile edit costs

## Why all objects move

The shared build-system fingerprint hashes the full root Makefile, the epoch
drivers and the zcc bootstrap catalog. The compile epoch combines that digest
with compiler identity, profile, effective compile flags and link inputs.
A Makefile edit selects a fresh directory under `build/obj/epochs/`. Make
then requests all 3,027 build-only objects. The epoch lease rechecks the
build-system identity. Keeping this rule covers target-specific flags, recipes
and dependency changes, including changes GNU Make evaluates indirectly.

The Linux scheduler gives each job without a caller-selected path a new disposable
`TMPDIR`. zcc binds that path for LTO, so even identical compiler invocations
missed across jobs. The native build-only object rule now selects a private
per-worktree compiler scratch path when the scheduler marks its own job
directory. Its SHA3-256 digest enters the epoch. zcc still preprocesses source
compiles and checks compiler, options, input contents and cached artifact integrity.

## Measurement

The measured worktree started at `53b6b2567e08919129c69cc686cb95af2fb8c1d8`.

Measurements on 2026-11-22 UTC used GCC 14.2.0, an AMD Ryzen 9 7950X3D and
`devbuild --wait make -j8 build-only`. The cold run began with an empty zcc
cache and a new object epoch. Vendor archives and bootstrap tools were already
available. Each row is one invocation. CPU is GNU time user plus system time
for Make and its children. Published counts include objects restored by zcc.
Hit and miss counts include only paths under `build/obj/epochs/`.

| Scenario | Wall seconds | CPU seconds | Published objects | zcc hits | Real compiles |
| --- | ---: | ---: | ---: | ---: | ---: |
| Cold build-only objects | 78.76 | 439.82 | 3027 | 0 | 3027 |
| Identical comment edit, ordinary job scratch | 70.84 | 451.24 | 3027 | 0 | 3027 |
| Identical comment edit, stable compiler scratch | 28.23 | 127.98 | 3027 | 3026 | 1 |
| Whitespace-only edit | 26.79 | 134.08 | 3027 | 3026 | 1 |
| Target-specific compiler flag | 25.89 | 130.52 | 3027 | 3025 | 2 |
| Warm no-op | 4.48 | 4.82 | 0 | 0 | 0 |
| Isolated C comment | 4.55 | 5.29 | 2 | 1 | 1 |
| Shared header comment | 12.72 | 74.00 | 1523 | 1522 | 1 |
| CSS input regenerating its tracked header | 7.10 | 9.11 | 11 | 0 | 11 |
| No-op following CSS regeneration | 4.54 | 4.85 | 0 | 0 | 0 |
| Comment edit after the source-edit sequence | 26.08 | 132.19 | 3027 | 3026 | 1 |
| C implementation string changed | 11.73 | 8.90 | 2 | 0 | 2 |
| Shared CRC header symbol changed | 7.45 | 6.51 | 8 | 0 | 8 |
| Generated C translation unit changed | 6.17 | 6.47 | 2 | 0 | 2 |
| No-op after generated C change | 5.97 | 6.22 | 0 | 0 | 0 |

The paired runs used identical source. All 3,027 object SHA-256 values matched.
For a whitespace-only source-identity change, the 3,026 other objects matched
the cold manifest. A Makefile flag renamed the CRC32C function in one object.
The stale LTO object failed to link against the new symbol. The rebuilt object
linked and returned `e3069283` for `123456789`. The generated CSS appeared in
a materialized consumer on the first build. Its rebuild set equalled the
depfile-derived consumers plus the source-identity object. Regenerating an
included Makefile caused a real restart and retained the same scratch digest
and compile epoch through the final recipe.

Separate steps changed the CRC implementation string and shared-header symbol.
The new string appeared in the materialized object and the
header symbol changed in the consuming object. Editing the guest-kernel stub
template regenerated its C translation unit and published the new LTO symbol.

The test used isolated source edits in one worktree. This measurement covers
the Linux native cached build-only path. Verified proof execution has its own
cache policy. Shared-host load and queue wait vary between runs.
