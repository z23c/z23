<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# ZCL Ledger transport experiment

This standalone C23 host communicates with Ledger Blue over Linux `hidraw`.
It reads app information, probes the ZCL device app, exits a running app, and
installs or deletes the reviewed no-key ZCL Probe image through the Blue's
secure channel. It does not need Ledger Live, Python, Rust, or a network
connection at runtime. It does not derive addresses, sign transactions, or
access recovery words.

## Build and test

```sh
cmake -S apps/zcl-ledger -B build/zcl-ledger -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=clang
cmake --build build/zcl-ledger
ctest --test-dir build/zcl-ledger --output-on-failure
```

Find accessible Ledger HID interfaces without Ledger Live:

```sh
build/zcl-ledger/zcl-ledger devices
build/zcl-ledger/zcl-ledger devices --json
```

The Blue exposes more than one HID interface. Query the app interface of an
unlocked device by its explicit path:

```sh
build/zcl-ledger/zcl-ledger app-info /dev/hidraw1
build/zcl-ledger/zcl-ledger app-info --json /dev/hidraw1
```

After the [ZCL Probe device app](device-blue/README.md) is installed and open,
`zcl-ledger probe --json /dev/hidrawN` checks its exact version 1 capability
reply. Version 1 reports address and signing capabilities as false. The probe
cannot succeed against BOLOS or a different app.

To exit a running Blue app from USB, including one whose touchscreen is
unresponsive, use `zcl-ledger quit /dev/hidrawN`. This sends Ledger's
`B0 A7 00 00 00` quit command. On the connected Blue, it returned success and
the app-info command then reported BOLOS 2.1.1.

The separate `zcl-blue-install` executable uses OpenSSL 3's open-source C
crypto implementation for the Blue's secp256k1 and AES secure channel. It
checks the Blue's USB product ID, verifies the session's device certificate,
checks an encrypted target-ID response, and accepts only the pinned ZCL Probe
binary. `--channel-only` checks the secure channel without installing. The
installer currently targets the connected Blue v2 (`0x31010004`). See the
[device app instructions](device-blue/README.md) for the exact build and
install commands.

The path is an example. `devices --json` returns an `ok` boolean and a
`devices` array of objects with `path`, `model`, `vendor_id`, and `product_id`.
`app-info --json` returns `ok`, `name`, and `version` on success, or `ok: false`
with a stable `error` code on failure. Both commands use exit status zero for
success and nonzero for failure. App-info checks Ledger's USB vendor ID before
sending its read-only APDU. It rejects malformed responses and does not report
success merely because the USB exchange succeeded. Neither command requests
keys, addresses, or signatures.

`app-info --json` error codes are `open_failed`, `not_ledger`,
`no_app_info_response`, `device_status`, and `invalid_app_info`. Device
discovery can return `device_scan_failed`. Each Blue HID interface is listed;
the caller selects the one that answers app-info.

## Limits

The transport follows Ledger's [HID framing](https://github.com/LedgerHQ/ledgercomm/blob/master/ledgercomm/interfaces/hid_device.py)
and uses the read-only `B0 01 00 00 00` app-info command from
[Ledger's client](https://github.com/LedgerHQ/ledger-live/blob/develop/libs/ledgerjs/packages/hw-app-btc/src/getAppAndVersion.ts).
The build requires ISO C23 and contains no Rust. Ledger's
[developer guide](https://developers.ledger.com/docs/device-app/beginner/vscode-extension)
states that custom apps cannot be sideloaded onto a retail Nano X. Ledger's
[Blue-specific legacy Bitcoin app](https://github.com/LedgerHQ/app-bitcoin-legacy/tree/blue-final-release)
contains a ZClassic variant; it has not been built or installed here. The
installed ZCL Probe proves only host-device communication, app display, exit,
and secure loading. It provides no ZCL address or transaction signing.
