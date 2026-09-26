<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue fixed-message signing self-test

Recorded: 2026-09-26T08:06:36-04:00 (2026-09-26T12:06:36Z)

## Question

Can a dedicated Blue derive a fixed ZCL transparent key and produce a real
ECDSA signature that a C23 host independently verifies, without exposing the
secret or accepting a payment-shaped command?

## Offline result

The new `ZCL Sign Test` app derives only `m/44'/147'/0'/0/0` with the Blue
firmware's BIP32 syscall. A touchscreen tap arms one signing operation. The
USB command has no payload. It signs only the SHA-256 digest of
`Z23 ZCL Blue signing self-test v1` and returns the compressed public key
and DER signature. The host verifies ECDSA on secp256k1 before deriving a
ZCL transparent address. A second signature requires a second tap.

The app's private key buffer, chain code, and initialized key structure are
cleared in a `FINALLY` block after every APDU, including a firmware exception.
The app accepts no arbitrary message, digest, derivation path, transaction,
or network address. Its output cannot authorize a ZCL payment or Sapling
spend. The touchscreen makes the test purpose and fixed path visible.

Clang 22.1.6 Debug with address and undefined-behavior sanitizers and GCC
16.1.1 Release passed eight local tests each. The new host verification test
generates a secp256k1 key, signs the fixed digest, verifies the response,
and rejects altered signatures, invalid public-key prefixes, and malformed
lengths. On an AMD Ryzen 7 PRO 8840U, the Blue firmware app compiled with
Clang 22.1.6 C23 and linked with ARM GCC 16.1.1: 12,544 text bytes, zero
initialized data bytes, and 2,140 BSS bytes. The extracted text image SHA-256
was `0fc38931f3344715090953538495c9648b3e475621853ac4c2dc7e568874590b`.

No physical Blue signing result had occurred at the time of this record.
The device syscall behavior, touchscreen tap, and signature still require a
live test. The signer has no transaction parser, approval screen for a
recipient or amount, Sapling derivation, proof checks, or transaction signing.
