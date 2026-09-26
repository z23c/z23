<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# ZCL transparent address codec for Ledger public keys

Recorded: 2026-09-26T04:03:40-04:00 (2026-09-26T08:03:40Z)

## Question

Can the C23 Ledger host reject invalid compressed secp256k1 public keys and
independently encode ZCL mainnet transparent P2PKH addresses?

## Method and evidence

The input vector was the compressed secp256k1 generator
`0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798`.
An OpenSSL command-line SHA-256 then RIPEMD-160 pipeline produced the known
20-byte hash `751e76e8199196d454941c45d1b3a323f1433bd6`. The mainnet prefix
`1cb8` comes from `core/chainparams/src/chainparams.c`. The double SHA-256
checksum of that 22-byte payload began `6911d5f8`; independent integer
Base58 conversion produced `t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs`.
The opposite compressed-key parity produced hash
`adde4c73c7b9cee17da6c7b3e2b2eea1a0dcbe67`, checksum `8b609c09`, and
address `t1ZiwD6uYW8ku8DSCM4f11BwsDateqtG7yz`.

The C23 host validates the curve point with OpenSSL 3 before hashing. A local
test checks both vectors and rejects wrong prefixes, off-curve points, and
null arguments. Clang 22.1.6 Debug with address and undefined behavior
sanitizers passed 3/3 tests; GCC 16.1.1 Release passed 3/3 tests. Both builds
used `-std=c23 -Wall -Wextra -Werror -pedantic`. The CLI printed the first
expected address. No speed benchmark was run.

## Scope

This is public-key address validation only. The Blue app still has no key
access and cannot provide a public key or sign any ZCL transaction. Live
device address derivation and Sapling transaction signing remain unverified.

Ledger's archived [Blue Bitcoin app at commit
`e588c642`](https://github.com/LedgerHQ/app-bitcoin-legacy/tree/e588c642431da26f4656c998be229ceb4fd805e4)
contains a `COIN=zclassic` variant with BIP44 coin type 147 and the same
transparent address prefixes. Its transaction parser has a ZClassic Sapling
branch ID and zero placeholders for shielded spend and output hashes. This is
evidence for transparent-input signing under Sapling transaction rules, not
evidence for shielded Sapling spend or output signing. The archived app also
depends on a separate Bitcoin app and has not been built for this Blue.
