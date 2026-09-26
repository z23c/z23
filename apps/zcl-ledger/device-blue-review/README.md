<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# ZCL Review for Ledger Blue

This C23 app accepts up to 4,096 bytes of a raw ZCL Sapling-v4 transaction
over USB and returns a structural summary. It counts transparent inputs and
outputs, Sapling spends and outputs, and Sprout JoinSplits. It also reports
the public output total, value balance, lock time, and expiry height. The
touchscreen says `NO KEYS OR SIGNING` and has an EXIT button. The app has no
key derivation, approval, or signing command. Its screen does not display
transaction details, so its response is not user authorization of a payment.

Build with the reviewed Blue SDK and an ISO C23 compiler:

```sh
make -C apps/zcl-ledger/device-blue-review \
  BOLOS_SDK=/path/to/blue-sdk \
  ARM_INCLUDE_DIR=/path/to/arm-none-eabi/include \
  GCCPATH=/path/to/toolchain/bin/ \
  CLANGPATH=/path/to/clang/bin/
```

The build checks for an empty `.data` section. The host's `zcl-tx-review`
command can compare the app's reply to its own parser using
`--blue /dev/hidrawN`, once a separately reviewed image is installed and
open. The install path has not accepted this image in a live test. Running
the host command without `--blue` only parses a local file.

Protocol commands use CLA `A5`, P1/P2 zero, and one-byte `Lc`:

| INS | Request | Successful response before `9000` |
| --- | --- | --- |
| `01` | Empty | `ZCL`, protocol version `04`, review-only capability `40` |
| `10` | Two-byte little-endian transaction length | Empty |
| `11` | Transaction chunk | Empty |
| `12` | Empty | 44-byte little-endian structural summary |
| `13` | Empty | Empty; clears pending review |

Each chunk is at most 220 bytes from the host CLI. An invalid size or
truncated transaction fails. `12` consumes the pending review even if the
transaction is invalid. The summary fields and limitations are documented in
the [host guide](../README.md).
