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

## First Blue test and derivation permission correction

Recorded: 2026-09-26T08:18:14-04:00 (2026-09-26T12:18:14Z)

The dedicated Blue reported BOLOS 2.1.1 at its home screen. Z23 installed
the signed, pinned 12,544-byte image through the owner-controlled CA. The
owner confirmed the app opened on a steady screen with both buttons. The
identity APDU returned `5a434c07029000`; before the touchscreen tap, the
sign command returned `6985`. After the tap, the sign command returned `6804`
and no public key or signature. The app remained responsive, and EXIT was
available. In the Blue SDK, low exception value `4` is
`EXCEPTION_SECURITY`.

The installer had set BOLOS derive-path metadata to a one-byte zero curve
mask. The open-source Ledger Blue loader encodes secp256k1 as curve mask
`01` and appends the allowed BIP32 path under install tag `04`. Z23 now uses
that exact narrow permission for `ZCL Sign Test` while preserving the old
metadata for review-only apps. A new host test checks the complete tag bytes
for both cases. Clang Debug sanitizers and GCC Release each passed nine local
tests after the correction. The host CLI now exposes a device status word
instead of collapsing it into a generic error. Whether the corrected metadata
resolves the security exception remains a live test question.

## Corrected permission: physical signing result

Recorded: 2026-09-26T08:20:43-04:00 (2026-09-26T12:20:43Z)

Z23 deleted the failed test app from the Blue at its home screen and
reinstalled the same SHA-256-pinned image with the narrow secp256k1 derivation
permission. The owner opened the app and confirmed its screen was steady.
Before approval, the sign APDU returned `6985`. After one tap of SIGN TEST,
`zcl-blue-sign-test --json /dev/hidraw1` returned `ok:true`,
`signature_verified:true`, `transaction_signed:false`, and the expected
`m/44'/147'/0'/0/0` path. The returned public key was compressed secp256k1,
and the corresponding transparent address was
`t1RAmKL4KFauUXGswvMvk66aS5UL33ck1Uz`. This is a seed-derived signature
over the app's fixed, non-transaction test message. The owner confirmed that
the screen stayed steady and EXIT returned to the Blue home screen.
Transaction review,
transaction signing, and Sapling operations remain unimplemented in this app.
