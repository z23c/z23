<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# ZCL token and script-hash review facts

Recorded: 2026-09-26T08:37:25-04:00 (2026-09-26T12:37:25Z)

The next signing interface needs to distinguish ordinary transparent
outputs from token metadata and script-hash outputs before it can present a
meaningful approval. The existing transaction parser already bounds and
counts output scripts. A separate host parser reports exact 23-byte P2SH scripts, OP_RETURN
outputs, and an SLP marker only when the first output starts with OP_RETURN
followed by a four-byte `SLP\0` push. All four data-push length encodings
permitted by the [SLP token-type-1 specification](https://github.com/simpleledger/slp-specifications/blob/master/slp-token-type-1.md)
are recognized.

This reports wire facts, not a valid ZSLP transfer or a multisig policy. A
P2SH output reveals only a script hash; its redeem script and threshold are
unknown. An SLP marker does not prove the token fields, input lineage, or
amounts. The Blue's current review protocol does not return these new facts,
so `--blue` continues to verify its existing structural summary and ZIP-243
digest while the script facts are host observations.

The host fixture test covers direct and PUSHDATA1/2/4 marker pushes, a
modified marker, exact P2SH detection, and a modified P2SH opcode. Clang
Debug with sanitizers and GCC Release each passed all ten local Ledger
tests. The 4,118-byte ZIP-243 vector remained parseable and produced the
previously pinned digest `63d18534de5f2d1c9e169b73f9c783718adbef5c8a7d55b5e7a37affa1dd3ff3`.
No device command or signing request was sent in this experiment. The
separate module leaves the pinned Blue review image and its build inputs
unchanged.

Shielded multisig requires a Sapling spend authorization protocol as well
as a threshold ceremony and transaction review. [ZIP 312](https://zips.z.cash/zip-0312)
specifies a FROST Jubjub ciphersuite for Sapling signatures. Z23 has not
implemented that protocol or established that its transaction-builder and
wallet state meet the prerequisites. A next test must compare a C23
Sapling signature verifier with published vectors and ZCL consensus before
placing threshold key material on the Blue.
