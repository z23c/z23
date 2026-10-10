<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Publication hold compatibility barrier

A producer predating publication holds accepted integer-priority held rows,
ignored the unfamiliar hold field, and omitted it when rewriting the queue.
Held rows now serialize `priority_seq` as `"held:<priority>"`; unheld rows
retain the integer representation. Ordering remains the decoded numeric priority.
The marker is accepted only with a unique boolean `publication_hold:true` and
canonical positive decimal priority in `1..seq`. Signs, whitespace, leading
zeros, suffixes, overflow, embedded NUL, contradictory holds, and duplicate
members refuse queue loading. The JSON decoder rejects decoded U+0000.

Legacy integer held rows remain readable for migration. Every serialization
upgrades them, including an idempotent hold operation. Until a legacy held row
is rewritten by this implementation, old producers can still discard its hold.
The barrier refuses legacy queue rewriting and publication; it does not claim
that a legacy step makes no other state changes before parsing the queue.

## Exact legacy executable experiment

Base: `6e84381bc1987be68f343ae0ed5c670acc5e9adc`.
The executable `build/bin/z23-dev` in the canonical checkout, SHA-256
`928d92e756c0ee8a1701913aeade7c51dd49e4c236dea661318d654de24b6e86`,
was invoked with `dev land status` under an isolated `XDG_STATE_HOME`.
A queued row with sequence 490, priority 490, attempt 1, a valid tip and
worktree, and `publication_hold:true` returned success (exit 0). Changing only
priority to `"held:490"` returned `QUEUE_READ_FAILED` (exit 1).
Exact queue bytes remained unchanged (`cmp` exit 0).
Control queue SHA-256:
`d3942c4d00e0dda752a55eb3e8e1d1ca522d1750598adc29d49571f1b2143b0c`.
Guarded queue SHA-256:
`9c287e7175bd6ab96307d0ef39dda5ce9b3a2e4cf769212b8a95eb25f4a8ea38`.
This was a read-only isolated status experiment, with no active queue access.

Evidence is retained beneath
`build/held-priority-evidence/` in the isolated lane.

## Executed qualification

Native admission `3678959-78171144-1791619756169883003` completed with exit 0.
The existing prebuilt native cyclomatic-complexity and long-function gates
passed. The canonical command `make -j8 t-fast-exact ONLY=dev_land` passed
one cold registered group with zero failures, skips, unobserved cases, or
load-flaky passes; measured test body time was 200574 ms. This is focused
qualification, not a full matrix or publication proof.

Executed source SHA-256 before and after the run matched:

- `tools/command/native_dev_land.c`:
  `af1eaeebe1ae4f8da0b015bca95cd95e276d5ef179bcd8393d4ed2ea13ed6e19`.
- `tests/harness/src/test_dev_land.c`:
  `5a6e2e2bac13d75db8e112a397416a26832ef9ef77ccd287abb933aaa6fc3015`.

Regression coverage observes strict malformed-marker refusal, missing/false
and duplicate hold refusal, integer-hold migration through idempotent hold,
duplicate submission, other-row rewrites, retained guards during proof and
publication refusal, and integer encoding after release.

The first cheap check rejected `dl_encode_row` complexity 16. Argument
validation and bounded priority formatting were grouped into a preparation
helper; the cap and baseline were unchanged. Admission
`3017387-78094783-1791618992562535406` passed both mechanical gates but was
stopped before test execution to restore the existing synthetic proof controls
in the new fixtures. Completed build objects were retained.

Admission `3109766-78108347-1791619128203983899` failed the existing
attest-only byte-preservation fixture on both its initial attempt and the
canonical runner's automatic alone retry: expected 259 bytes, observed 260.
Its raw file reader did not terminate the buffer, while a later fixture write
used `strlen`. Adding the missing terminator preserved every byte comparison
and removed the incidental uninitialized-byte write. The new guarded-priority
cases passed in that failed run. Failure and interruption logs remain in the
same evidence packet. No paid provider calls were made.
