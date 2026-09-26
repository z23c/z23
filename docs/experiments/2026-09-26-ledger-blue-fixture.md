<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue public-key fixture

Recorded: 2026-09-26T04:39:35-04:00 (2026-09-26T08:39:35Z)

## Question

Can a C23 Blue app answer a public-key APDU without key derivation or a UI
refresh, and can the C23 host validate the exact reply and ZCL address?

## Evidence

The `ZCL Fixture` source contains the fixed compressed secp256k1 generator
point. The app does not call a seed or signing syscall. Its APDU handler
answers protocol probe `A5 01 00 00 00` and public-key request
`A5 02 00 00 00`; the display is initialized before either request.

Two separate Blue SDK trees produced identical 11,520-byte app images with
SHA-256
`f10bc366c6eacbeb58c6362dca3915193d4b76477c898630e79e096ae99ae4c6`.
`arm-none-eabi-size -A` reported `.text` 11,520 bytes, `.data` 0 bytes, and
`.bss` 2,032 bytes. The host encoder maps the fixture key to
`t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs`.

Clang 22.1.6 Debug with address and undefined-behavior sanitizers and GCC
16.1.1 Release both passed 3/3 host tests on an AMD Ryzen 7 PRO 8840U.
The tests reject modified fixture protocol bytes and status bytes. The host
returned `wrong_app` against BOLOS 2.1.1. The installer rejected the prior
failed `ZCL Address` binary by SHA-256 before opening USB. A secure-channel
check verified Blue target `0x31010004`.

The connected dedicated test Blue accepted the `ZCL Fixture` install command.
The user confirmed that the app screen was steady and EXIT returned to the
home screen. After reopening it, the C23 host received the exact public key
over USB and returned
`{"ok":true,"fixture":true,"address":"t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs","wallet_address":false}`.
The user confirmed that the screen remained steady after the APDU and EXIT
still returned to the home screen.
The BOLOS warning for a non-genuine custom application remains.

## Limits

The fixture is a public constant, not a device-derived wallet address. No
device seed was accessed, and no transaction was signed or broadcast. The
successful fixture exchange isolates the earlier address prototype's APDU
failure from basic USB transport and host address encoding, but does not
identify whether key derivation or its UI refresh caused that failure.
