<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# ZCL Fixture for Ledger Blue

This C23 test app sends the fixed, public secp256k1 generator point over USB.
The corresponding ZCL transparent address is
`t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs`. This address is a public test
fixture. It is not derived from the Blue's seed and must not be used as a
wallet deposit address. The app has no key derivation or signing command.

The app displays `PUBLIC TEST KEY ONLY` and an EXIT button. Its APDU commands
are `A5 01 00 00 00` for protocol `ZCL` version 3, capability `0x80`, and
`A5 02 00 00 00` for the 33-byte fixture public key. Both append status
`9000` on success. The host validates the complete replies and the resulting
address before reporting success.

Build using the same open-source, C23-patched Blue SDK and ARM toolchain as
the [ZCL Probe](../device-blue/README.md). The build rejects images with
initialized `.data`. The installer accepts only the reviewed binary SHA-256
`f10bc366c6eacbeb58c6362dca3915193d4b76477c898630e79e096ae99ae4c6`.
Build artifacts are local and are not committed.

With the Blue on its home screen, install the pinned image using
`zcl-blue-install /dev/hidrawN app.bin`. Open `ZCL Fixture` on the Blue,
confirm that the display and EXIT work, then reopen it and run
`zcl-ledger fixture-address --json /dev/hidrawN`. The JSON includes
`"fixture":true` and `"wallet_address":false`. If the app is unresponsive,
try `zcl-ledger quit /dev/hidrawN`; an acknowledged quit still requires
confirmation that BOLOS answers. From BOLOS, remove it with
`zcl-blue-install /dev/hidrawN --delete-fixture`.

Blue warns `Non genuine application` when opening an app without a trusted
Ledger signature. This app does not suppress or bypass that warning.
