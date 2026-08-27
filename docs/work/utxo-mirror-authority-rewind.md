<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# UTXO mirror authority-rewind recovery experiment

`coins_applied_height` and `utxos_mirror_height` are both next-height cursors.
A mirror cursor one above the authority frontier is therefore a real authority
rewind, normally caused by a one-block reorganization. It is not an off-by-one
encoding difference. The mirror must stay quarantined because the reducer
deletes the losing branch's causal delta during unwind; decrementing only the
cursor would falsely certify losing-branch rows as current.

There is no owner-gated, copy-first mirror rebuild command. The planned
`ops.recovery.rebuild` leaf is not implemented and must not be represented as a
recovery path. Until that gap is closed, recovery remains an owner action on a
copy, followed by normal deployment qualification. No canonical datadir should
be edited directly.

## Designed acceptance

1. Stop an isolated fixture node and make a descriptor-bound copy of its whole
   datadir, preserving the original.
2. Reproduce a one-block authority rewind on the copy and prove the mirror
   enters `QUARANTINED` without changing its rows or cursor.
3. Rebuild only the derived `utxos`, address, wallet-UTXO, commitment, and
   mirror-cursor state from one read transaction over the copied
   `progress.kv`; never write `coins`, reducer logs, wallet keys, or chain
   authority.
4. Prove the copied authority and projection have equal row counts and equal
   commitments at the same next-height cursor. Run the state-auditor and
   authority-projection audit twice with no mismatch.
5. Restart the copied fixture, catch up through another block, and prove the
   incremental delta path resumes without a wholesale rebuild or blocker.
6. Only after this experiment is repeatable, expose it as an owner-authorized
   plan/commit native command that creates and reports the backup before any
   mutation. Production activation remains a separate owner decision.

The direct unit regression in `test_utxo_mirror_sync` covers the current
fail-closed invariant, including a same-height frontier rebound on a different
branch. It intentionally does not claim recovery is implemented.
