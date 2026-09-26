<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# ZCL Ledger transport experiment

This standalone C23 program exchanges a read-only app-info command with a
Ledger USB HID device. It uses Linux `hidraw` directly and does not need Ledger
Wallet, Ledger Live, Python, or a network connection at runtime. It does not
derive addresses, sign transactions, install an app, or access recovery words.
It is the host transport boundary for [issue #56](https://github.com/z23c/z23/issues/56).

## Build and test

```sh
cmake -S apps/zcl-ledger -B build/zcl-ledger -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=clang
cmake --build build/zcl-ledger
ctest --test-dir build/zcl-ledger --output-on-failure
```

To query an unlocked device, identify its `hidraw` path with `lsusb` and
`/sys/class/hidraw/*/device/uevent`, then run:

```sh
build/zcl-ledger/zcl-ledger app-info /dev/hidraw1
```

The path is an example. The command checks Ledger's USB vendor ID before
sending the app-info APDU. It rejects malformed responses and does not report
success merely because the USB exchange succeeded.

## Limits

The transport follows Ledger's [HID framing](https://github.com/LedgerHQ/ledgercomm/blob/master/ledgercomm/interfaces/hid_device.py)
and uses the read-only `B0 01 00 00 00` app-info command from
[Ledger's client](https://github.com/LedgerHQ/ledger-live/blob/develop/libs/ledgerjs/packages/hw-app-btc/src/getAppAndVersion.ts).
The build requires ISO C23 and contains no Rust. Ledger's
[developer guide](https://developers.ledger.com/docs/device-app/beginner/vscode-extension)
states that custom apps cannot be sideloaded onto a retail Nano X. Ledger's
[Blue-specific legacy Bitcoin app](https://github.com/LedgerHQ/app-bitcoin-legacy/tree/blue-final-release)
contains a ZClassic variant; it has not been built or installed here. A
connected Blue running BOLOS 2.1.1 answered the read-only app-info command,
but no ZClassic app was visible on its touchscreen. See the
[Blue experiment](../../docs/experiments/2026-09-26-ledger-blue-discovery.md).
