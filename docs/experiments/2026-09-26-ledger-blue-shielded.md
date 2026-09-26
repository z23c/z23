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

## Live signed review and synthetic Sapling fixture

Recorded: 2026-09-26T07:33:38-04:00 (2026-09-26T11:33:38Z)

The connected dedicated test Blue reported BOLOS 2.1.1 and target
`0x31010004`. Z23 established a CA-authenticated secure channel using the
previously enrolled `Z23` CA. The signed install of the pinned 15,616-byte
`ZCL Review` image returned success at create, load, and commit. The owner
confirmed the icon appeared, its screen stayed steady, and EXIT returned to
home. `zcl-ledger app-info` reported `ZCL Review` version `0.1.0` while
the app was open.

A 1,425-byte synthetic Sapling-v4 fixture had one 384-byte spend description,
one 948-byte output description, and zeroed proof and signature fields. Its
SHA-256 was
`cffdc5b7a7473cd62d4a77bf63ac5f6951b7368735f361acc5603a2d798f658b`.
The host command
`zcl-tx-review --json --blue /dev/hidraw1 /tmp/zcl-sapling-review-fixture.bin`
reported one Sapling spend, one Sapling output, and `blue_parsed:true`.
The Blue returned the same structural summary and exact-byte SHA-256 as the
host parser. The fixture's zeroed proofs and signatures are not a valid
payment. The app has no key or signing operation; this test did not create,
approve, or broadcast a transaction.

The owner reopened `ZCL Review` after the test and confirmed it went directly
to the steady review screen without a `Non genuine application` warning, then
EXIT returned to home. This observes the locally signed image on this Blue;
it does not imply Ledger certification or approval of any ZCL payment.

## Nano S Sapling signer reference and ZIP-243 review

Recorded: 2026-09-26T07:53:14-04:00 (2026-09-26T11:53:14Z)

Zondax's [Nano S/S+/X Sapling app](https://github.com/Zondax/ledger-zcash)
is a concrete reference for a host prover and device signer. Its
[workflow](https://github.com/Zondax/ledger-zcash/blob/main/docs/zcash_workflow.md)
places transaction construction and Sapling proofs on the host. The device
checks the resulting transaction, computes the signature hash, and produces
RedJubjub spend authorization signatures. The
[APDU specification](https://github.com/Zondax/ledger-zcash/blob/main/docs/APDUSPEC.md)
separately defines extraction of a proof generating key and extraction of
spend signatures after check-and-sign. The
[device source](https://github.com/Zondax/ledger-zcash/blob/main/app/src/crypto.c)
shows that the proof key sent to the host includes `ak` and `nsk`, together
with `rcv` and `alpha`; the spend authorization secret stays on the device.
This reference therefore does not keep every sensitive Sapling key on the
device. Z23 must define and test that disclosure boundary before adding a
proving protocol. The Zondax host builder uses Rust; it is a protocol
reference, not a language dependency for Z23's C23 implementation.

The review-only Blue app now uses a streaming personalized BLAKE2b-256
implementation through the Blue firmware's hash syscall to compute the
[ZIP-243](https://zips.z.cash/zip-0243) shielded SIGHASH_ALL digest. The C23
host computes the same digest independently. The official ZIP-243 vector 1
transaction (4,118 bytes, branch `0x76b809bb`) gave
`63d18534de5f2d1c9e169b73f9c783718adbef5c8a7d55b5e7a37affa1dd3ff3`.
The fixture test checks that changing the final binding signature does not
change the digest, while changing a hashed transaction byte or branch ID does.

Clang 22.1.6 Debug with address and undefined-behavior sanitizers and GCC
16.1.1 Release each passed seven local host tests. The Blue app built with
Clang 22.1.6 C23 and the ARM GCC 16.1.1 linker: 19,968 text bytes, zero
initialized data bytes, and 6,132 BSS bytes. The extracted text image SHA-256
was `9de444a3179520d7edf6a60e67417ef5e57942eb3d04d53e73fa1a7f69ad7528`.
The host CPU was AMD Ryzen 7 PRO 8840U. No physical Blue interaction occurred
for version 0.2.0 at the time of this record. It has no key derivation,
approval UI, proof verification, signing command, or transaction broadcast.
