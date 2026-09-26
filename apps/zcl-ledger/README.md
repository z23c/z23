<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# ZCL Ledger transport experiment

This standalone C23 host communicates with Ledger Blue over Linux `hidraw`.
It reads app information, probes the ZCL device app, and
installs or deletes the reviewed no-key ZCL Probe or ZCL Fixture images through
the Blue's secure channel. It does not need Ledger Live, Python, Rust, or a
network connection at runtime. The host can encode a transparent address from
a public key supplied separately or by the public fixture app. It does not
derive device keys or addresses, sign transactions, or access recovery words.

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

Exit ZCL Fixture with its touchscreen EXIT button. Z23 rejects the `quit`
command before opening USB: the Blue acknowledged a USB quit request during
a live test, then froze until a user restart. Confirm the Blue's home screen
and a BOLOS app-info reply before sending manager commands.

The separate `zcl-blue-install` executable uses OpenSSL 3's open-source C
crypto implementation for the Blue's secp256k1 and AES secure channel. It
checks the Blue's USB product ID, verifies the session's device certificate,
checks an encrypted target-ID response, and accepts only the pinned ZCL Probe
or ZCL Fixture binary. `--channel-only` checks the secure channel without
installing. The installer targets the connected Blue v2 (`0x31010004`). See the
[device app instructions](device-blue/README.md) for the exact build and
install commands.

The optional [user controlled Blue CA](BLUE_CA.md) can sign reviewed apps
with a locally held key. It changes the device's trust configuration and is
documented separately from the unsigned diagnostic apps.

## Sapling transaction structure review

`zcl-tx-review` parses a raw ZCL Sapling-v4 transaction file without opening
USB. It reports transparent input and output counts, total public output
value, Sapling spend and output counts, Sprout JoinSplit count, value balance,
lock time, and expiry height. The parser requires canonical CompactSize
lengths, checks public value ranges, bounds all arrays and scripts, and
rejects trailing or truncated bytes.

```sh
build/zcl-ledger/zcl-tx-review --json transaction.bin
# After a separately reviewed ZCL Review app is installed and open:
build/zcl-ledger/zcl-tx-review --json --blue /dev/hidrawN transaction.bin
```

The JSON fields `shielded_details_verified` and `signing_ready` are always
`false`. Sapling output recipients and amounts are encrypted in the wire
transaction; this structural parser does not decrypt them or verify proofs,
signatures, ownership, fee, or consensus validity. It has no key access.
The optional `--blue` mode sends at most 4,096 transaction bytes to the
[ZCL Review app](device-blue-review/README.md), verifies its review-only
identity, and requires its structural summary and transaction SHA-256 digest
to match the host's values. This checks the exact bytes received by the Blue;
it is not the ZIP-243 signing digest or a device approval.
`blue_parsed` is true only after that comparison succeeds. A synthetic
one-spend, one-output fixture passed this comparison on a dedicated Blue.
The app has no signing command or transaction approval screen. Without `--blue`, the CLI sends
nothing over USB and `blue_parsed` is false.

The [ZCL Fixture](device-blue-fixture/README.md) tests an exact public-key
reply and host address encoding without touching the device seed. Run
`zcl-ledger fixture-address --json /dev/hidrawN` while that app is open.
Its result is explicitly marked as a fixture, never as a wallet address.

The path is an example. `devices --json` returns an `ok` boolean and a
`devices` array of objects with `path`, `model`, `vendor_id`, and `product_id`.
`app-info --json` returns `ok`, `name`, and `version` on success, or `ok: false`
with a stable `error` code on failure. Both commands use exit status zero for
success and nonzero for failure. App-info checks Ledger's USB vendor ID before
sending its read-only APDU. It rejects malformed responses and does not report
success merely because the USB exchange succeeded. Neither command requests
keys, addresses, or signatures.

To independently encode a ZCL mainnet transparent address from a 33-byte
compressed secp256k1 public key, run:

```sh
build/zcl-ledger/zcl-ledger address-from-pubkey \
  0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
```

This example prints `t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs`. The command
checks the public key is on secp256k1, then computes SHA-256, RIPEMD-160, the
ZCL mainnet P2PKH prefix, and Base58Check. It uses no device or private key.
It is a validation component for later device-derived public keys, not a
Ledger address derivation command.

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
and secure loading. The fixture app tests a public constant, not wallet
derivation or transaction signing.
