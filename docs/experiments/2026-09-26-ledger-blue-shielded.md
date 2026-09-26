<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# ZCL Sapling transaction review groundwork

Recorded: 2026-09-26T05:51:15-04:00 (2026-09-26T09:51:15Z)

## Question

Can a dependency-free C23 component parse ZCL Sapling-v4 transaction
structure within bounded memory before a Blue app gains any signing command?

## Result

`apps/zcl-ledger/src/zcl_tx_review.c` parses a complete v4 transaction with
group ID `0x892f2085`. It handles transparent inputs and outputs, the Sapling
value balance, fixed-size SpendDescription and OutputDescription vectors,
optional Sprout JoinSplits, and conditional binding signatures. The maximum
input is 2 MiB. Public output values and their sum are constrained to
ZCL's 21 million coin monetary range. Count encodings must be canonical,
every field must fit in the supplied byte span, and trailing bytes fail.

The same source compiled with Clang 22.1.6 as C23 for `arm-none-eabi` at
`-O2 -Wall -Wextra -Werror -pedantic`. Its ARM object had 3,092 text bytes,
zero initialized data bytes, and zero BSS bytes according to `llvm-size`.
Clang Debug with address and undefined-behavior sanitizers and GCC 16.1.1
Release each passed five local host tests, including the transaction review
test. The review test covers a ZCL mainnet v4 coinbase copied from the node's
wire-evidence corpus, Sapling spend/output and Sprout JoinSplit layouts,
truncation at every byte of that coinbase, noncanonical counts, version and
group rejection, trailing data, negative value balance, and excessive public
value.

The `zcl-tx-review --json` command successfully parsed a 29-byte minimal v4
wire sample and returned zero counts with `shielded_details_verified:false`
and `signing_ready:false`. This confirms the CLI output path, not the
validity of that sample as a consensus transaction.

## Limits and next experiments

The component does not verify zero-knowledge proofs, signatures, branch IDs,
UTXO ownership, fee, or Sapling note contents. It cannot display a Sapling
recipient or amount from ciphertext alone. The Blue fixture still has no
seed-derived key or signing command. No physical Blue interaction occurred
for this change.

The next device experiment is to validate a signed C23 app install using the
revised firmware-version hash, then exercise a bounded no-key transaction
review protocol on the Blue. A signing experiment must follow only after the
Blue can show a meaningful transaction summary, the host and device agree
on the exact transaction digest, and the necessary Sapling key derivation and
RedJubjub operations have independent test vectors. The proving work remains
on the Z23 host.

## Offline Blue review app build

Recorded: 2026-09-26T06:01:07-04:00 (2026-09-26T10:01:07Z)

The review-only Blue app compiled with Clang 22.1.6 C23 and the ARM GCC
16.1.1 linker against the locally reviewed Blue SDK. Its linked ELF used
15,624 text bytes, zero initialized data bytes, and 6,132 BSS bytes
(`arm-none-eabi-size`). The app.hex SHA-256 was
`2a300591d5647d416a0504f7105bf4eb627a6e1ac6de63e827d919f9cacf788d`.
Clang Debug with address and undefined-behavior sanitizers and GCC 16.1.1
Release each passed six local host tests. The new APDU test covers the
Blue's in-place request/reply buffer, minimal transaction parsing, state
transitions, and bounds. No Blue USB or touchscreen test occurred while the
owner was away.

The Blue app's USB result is a structural summary, not a transaction
approval or Sapling payment. Its fixed touchscreen does not identify the
recipient, amount, fee, or digest. A future signing app must verify these
details, bind the user's approval to a specific digest, and pass independent
cryptographic vectors before it can request key operations.

## Exact-byte transport binding

Recorded: 2026-09-26T06:04:03-04:00 (2026-09-26T10:04:03Z)

The review protocol now returns SHA-256 of all transaction bytes alongside
the same 44-byte summary. Blue computes it with the firmware hash syscall;
the host independently computes it with OpenSSL 3. The host fails if either
the identity, summary, or digest differs. A fixed 29-byte wire vector's
SHA-256 is
`0ba4f12d34aa8160563ce2e34b462bc391c78ebb371c4ae572c546c1eadeebfd`,
verified with `sha256sum` and pinned in the APDU test. This digest checks the
USB transport's exact bytes; it is not the ZIP-243 signature hash. The
updated ARM image still has 15,624 text bytes, zero initialized data bytes,
and 6,132 BSS bytes. Its app.hex SHA-256 is
`85bc430c918ed15cbf9a329f6fc0e43d31e37d0a0b8836d86f3c3c4310c3834e`.
No physical Blue test occurred.
