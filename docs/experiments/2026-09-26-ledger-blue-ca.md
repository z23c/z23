<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue custom CA signing experiment

Recorded: 2026-09-26T05:01:29-04:00 (2026-09-26T09:01:29Z)

## Question

Can a locally controlled secp256k1 key sign a pinned C23 Blue app so BOLOS
opens it without its non-genuine application warning?

## Offline evidence

Ledger's open loader sends manager command `0x12` to enroll a named CA public
key and app commit command `0x09` with a DER ECDSA signature. Its reset
command is `0x13`. Ledger's open OS source verifies the signature against
the full application SHA-256 digest. For a normal app, that digest covers
the target ID, the 20-byte create-app fields, and loaded image bytes. Firmware
version bytes are included for firmware upgrades only. Z23's C23 manager
implements those operations and keeps the private key in an owner-only local
file outside the repository.

The app-hash test matches a separately calculated SHA-256 vector
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
