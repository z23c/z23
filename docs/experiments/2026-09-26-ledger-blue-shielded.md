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
