<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue read-only payment review failure

Date: 2026-09-27. The dedicated Ledger Blue ran signed ZCL Wallet 0.2.1.
Its receive screen was steady, EXIT worked, and the owner compared all 35
characters of `t1RAmKL4KFauUXGswvMvk66aS5UL33ck1Uz` with Z23's result.

Z23 then submitted a synthetic, unsigned v4 transaction with one transparent
input and two standard outputs through the new C23 host review driver. The
driver preflighted the complete wire and requested a read-only three-pass
review. Before an output was confirmed, USB replies stopped. The owner
reported a steady screen whose EXIT button did not respond. The host driver
at that point did not log each APDU, so the first failing instruction is
unknown. No payment signing instruction exists in this app; no transaction
was signed. The owner restarted the Blue normally and confirmed the home
screen. Z23 deleted Wallet, Sign Test, and Probe through the authenticated
manager channel. The final authenticated catalog reported zero apps.

The USB/UI handoff is one plausible cause: Wallet 0.2.1 could call
`UX_DISPLAY` during APDU processing before transmitting a reply. Stack
exhaustion or an SDK event-state fault remain possible. There is no hardware
trace that distinguishes these explanations. Wallet 0.2.2 moves screen
redraw after `io_exchange(... | IO_RETURN_AFTER_TX, sent)` and before the
next receive. The SDK's `io_exchange` implementation waits until the prior
reply reaches `APDU_IDLE` and returns on that flag. This change has not been
tested on the Blue.

The host driver records the failing instruction and status on later USB
attempts. Its software-model test confirms exact output boundaries, both
touch acknowledgements, a completed replay, changed-wire rejection, wrong
protocol rejection, and refusal abort. Clang 22.1.6 Debug with address and
undefined-behavior sanitizers and GCC Release each passed all 22 host tests.
Two independent ARM builds of Wallet 0.2.2 from patched SDK trees produced
the same `.text` image SHA-256:
`eeffd48f17b85f7cbf3df1b73ca35a6b173e4054d0d7cd88a525ad67ecf60321`.
The ARM image has 24,832 bytes of `.text`, zero initialized `.data`, and
4,236 bytes of `.bss` including its 2,048-byte stack reservation. The
largest named stack path is 648 bytes; the accounting excludes BOLOS frames.
The installer rejects 0.2.0 and 0.2.1 payment-review images and does not
accept 0.2.2. The Blue has no ZCL app installed after this experiment.

The next experiment must isolate the first failing APDU and verify that the
owner can leave each displayed screen. A read-only transaction review remains
separate from payment approval, prevout provenance, fee verification, change
recognition, and signing.
