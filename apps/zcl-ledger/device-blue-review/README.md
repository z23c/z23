<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# ZCL Review for Ledger Blue

This C23 app accepts up to 4,096 bytes of a raw ZCL Sapling-v4 transaction
over USB and returns a structural summary and SHA-256 digest of the exact
transaction bytes. It counts transparent inputs and
outputs, Sapling spends and outputs, and Sprout JoinSplits. It also reports
the public output total, value balance, lock time, and expiry height. The
touchscreen says `NO KEYS OR SIGNING` and has an EXIT button. The app has no
key derivation, approval, or signing command. Given an explicit consensus
branch ID, it also computes the ZIP-243 shielded SIGHASH_ALL digest. Its screen does not display
transaction details, so its response is not user authorization of a payment.

Build with the reviewed Blue SDK and an ISO C23 compiler:

```sh
make -C apps/zcl-ledger/device-blue-review \
  BOLOS_SDK=/path/to/blue-sdk \
  ARM_INCLUDE_DIR=/path/to/arm-none-eabi/include \
  GCCPATH=/path/to/toolchain/bin/ \
  CLANGPATH=/path/to/clang/bin/
```

The build checks for an empty `.data` section. Extract the 19,968-byte code
image and check its SHA-256 before installing:

```sh
llvm-objcopy -O binary --only-section=.text \
  apps/zcl-ledger/device-blue-review/bin/app.elf /tmp/zcl-review.bin
sha256sum /tmp/zcl-review.bin
```

The pinned image hash is
`9de444a3179520d7edf6a60e67417ef5e57942eb3d04d53e73fa1a7f69ad7528`.
Install only on the dedicated test Blue at its home screen using
`zcl-blue-install /dev/hidrawN --ca-install CA_KEY_FILE /tmp/zcl-review.bin`.
If the signed install is rejected, the unsigned install command is
`zcl-blue-install /dev/hidrawN /tmp/zcl-review.bin`; Blue will show its
non-genuine application warning when the app opens. EXIT returns to home.
Remove it from home using `zcl-blue-install /dev/hidrawN --ca-delete-review
CA_KEY_FILE` for a signed install, or `--delete-review` for an unsigned one.

The host's `zcl-tx-review`
command can compare the app's reply to its own parser using
`--blue /dev/hidrawN`, once a separately reviewed image is installed and
open. The earlier version 0.1.0 signed image installed on the dedicated Blue running BOLOS 2.1.1,
and a synthetic one-spend, one-output Sapling fixture returned a matching
summary and exact-byte digest. The owner confirmed the signed app opened
without BOLOS's non-genuine warning and exited normally. This is a structural
review test only. Version 0.2.0 has passed offline tests but has not been
installed or tested on the physical Blue. Running
the host command without `--blue` only parses a local file.

Protocol commands use CLA `A5`, P1/P2 zero, and one-byte `Lc`:

| INS | Request | Successful response before `9000` |
| --- | --- | --- |
| `01` | Empty | `ZCL`, protocol version `06`, review-only capability `40` |
| `10` | Two-byte little-endian transaction length | Empty |
| `11` | Transaction chunk | Empty |
| `12` | Empty | 44-byte little-endian structural summary, then 32-byte SHA-256 digest |
| `13` | Empty | Empty; clears pending review |
| `14` | Four-byte little-endian consensus branch ID | 32-byte ZIP-243 shielded SIGHASH_ALL digest |

Each chunk is at most 220 bytes from the host CLI. An invalid size or
truncated transaction fails. `12` consumes the pending review even if the
transaction is invalid. `14` requires a complete transaction and leaves it
pending for `12`; the caller must supply a branch ID valid for the transaction's
height. The app does not check that relationship. Neither digest is a device
approval. The summary fields and limitations are documented in
the [host guide](../README.md).
