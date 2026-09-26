<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue custom CA signing experiment

Recorded: 2026-09-26T05:01:29-04:00 (2026-09-26T09:01:29Z)

## Question

Can a locally controlled secp256k1 key sign a pinned C23 Blue app so BOLOS
opens it without its non-genuine application warning?

## Offline evidence

Ledger's open loader sends manager command `0x12` to enroll a named CA public
key and app commit command `0x09` with a DER ECDSA signature. Its reset
command is `0x13`. Ledger's newer open OS source verifies the signature
against a full application SHA-256 digest that omits firmware version bytes
for a normal app. The initial C23 implementation followed that newer format.
The local private key remains in an owner-only file outside the repository.

The original app-hash test matched a separately calculated SHA-256 vector
`62e25d7a114109bda7b2705df31c3e277dd8159e3f00a7303b49c7d10b4db2ff`.
The CA test generated a key, rejected overwrite and loose permissions,
verified a digest signature, and rejected the same signature against a
changed digest. Clang 22.1.6 Debug sanitizer and GCC 16.1.1 Release each
passed 4/4 host tests. The cyclomatic complexity gate passed with cap 15 and
no new baseline pin.

## Limits

The first live enrollment attempt established a secure channel and verified
Blue target `0x31010004`. BOLOS rejected the subsequent encrypted CA command
`0x12` with status `6985` while the device was in normal mode. The Blue
returned to its home screen. No CA was enrolled and no signed app has been
opened. Ledger's Blue firmware 2.1 announcement states that CA management
requires Recovery mode. The warning removal remains unverified. Enrolling a
CA changes the Blue's Genuine Check behavior until the CA and apps installed
through it are removed, as Ledger's developer guidance states.

## Recovery-mode and signed-install follow-up

Recorded: 2026-09-26T05:34:17-04:00 (2026-09-26T09:34:17Z)

The user entered the Blue's Recovery mode and approved enrollment of the
`Z23` public key. The enrollment command returned success. A subsequent
channel authenticated by the matching local key completed the encrypted
target query, proving that the device accepted that CA for manager access.
The CA-authenticated delete of `ZCL Fixture` returned success; the user
confirmed its icon disappeared.

Three signed installs of the pinned fixture image returned `6986` at the
final commit, after slot creation, code loading, parameter loading, and CRC
checks had succeeded. The same result occurred in Recovery mode and after a
normal restart. Normalizing ECDSA signatures to low-S did not change the
device result. No signed icon appeared. The Blue remained responsive at its
home screen. No private key or recovery material was sent to the device.

Ledger's open Blue loader tag `0.1.22` (2019-01-02) includes the target's
firmware version bytes after the target ID in the SHA-256 preimage when the
target ID's low nibble exceeds 3. The connected Blue target is `0x31010004`.
The previous C23 hash omitted those bytes. The installer now reads the
version from the authenticated `0x10` response, validates its length and
printable form, and includes its exact bytes in the signed hash. The test
vector for target `0x31010004`, version `2.1.1`, a zeroed 20-byte create
payload, and image bytes `0102030405` is
`28fc9aaeb6bd1d715e87983355ae99625e19c0654b126e00fee5eaff75f50402`.
This was independently calculated with `xxd` and `sha256sum`. Clang 22.1.6
Debug with AddressSanitizer and UndefinedBehaviorSanitizer, and GCC 16.1.1
Release, each passed the four local host tests. No device install using this
revised hash has been attempted. The cyclomatic complexity gate passed with
cap 15 and no new baseline pin.
