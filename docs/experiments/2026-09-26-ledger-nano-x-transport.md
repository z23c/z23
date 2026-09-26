<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Nano X read-only transport check

Date: 2026-09-26T01:58:59-04:00 (2026-09-26T05:58:59Z)

## Question

Can a C23 host program exchange a read-only APDU with the connected Nano X
without Ledger Wallet, and can it distinguish transport success from valid
application metadata?

## Method and observations

- Linux enumerated USB `2c97:0004` as Ledger Nano X and exposed `/dev/hidraw1`.
- Clang 22.1.6 compiled the standalone C23 program with `-Wall -Wextra
  -Werror -pedantic`. The Debug build used address and undefined-behavior
  sanitizers. The local HID framing test passed.
- GCC 16.1.1 compiled the Release build with the same warning flags, and its
  HID framing test passed.
- The C23 program sent `B0 01 00 00 00` directly over `hidraw`. The device
  returned status `9000` and 15 metadata bytes:
  `01 05 4f 4c 4f 53 00 07 2e 32 2e 34 2d 36 00`.
- Ledger's `ledgercomm` Python HID transport independently returned the same
  status and metadata bytes. The metadata contains embedded NUL bytes in the
  name and version fields, so the C23 parser rejects it.

The direct USB exchange worked. The observed response does not establish that
a ZCL app is installed or that address derivation or transaction signing is
available. No signing command, private key, or recovery phrase was used.

## Next test

Run the same host command against a deterministic ZCL device app in Speculos.
Then define and test address verification and a transparent transaction review
protocol before implementing signatures. Verify each protocol response against
fixed public fixtures and malformed-input cases.
