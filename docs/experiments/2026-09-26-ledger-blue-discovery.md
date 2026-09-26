<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue USB and ZClassic app discovery

Date: 2026-09-26T02:33:22-04:00 (2026-09-26T06:33:22Z)

## Question

Can the C23 Z23 Ledger host communicate with the connected Ledger Blue, and
is a ZClassic device app already installed?

## Method and observations

- After reconnecting the Blue with a data cable, Linux enumerated USB
  `2c97:0000`, identified the product as `Blue`, and exposed `/dev/hidraw1`
  and `/dev/hidraw2`.
- The C23 `zcl-ledger app-info /dev/hidraw1` command returned `BOLOS 2.1.1`.
  The command on `/dev/hidraw2` did not receive an app-info response.
- The user inspected the Blue touchscreen and reported no ZClassic app.
- Ledger's open-source `ledgerblue.listApps` sent its read-only `E0 DE 00 00`
  app-list command without a secure channel. BOLOS returned `6D00`, so this
  experiment did not obtain an independent software app inventory.
- Ledger's `app-bitcoin-legacy` `blue-final-release` branch has a
  `COIN=zclassic` variant and a Blue-specific ZClassic icon. A local build
  attempt with the public `blue-secure-sdk` `blue-r21.1` tag failed: that SDK
  does not provide the `ux.h` header required by the app branch, and its
  Makefile's `/usr/include` path selected host headers during cross-compilation.
  No device app binary was produced or installed.

The Blue's USB transport works. The ZClassic app is absent by touchscreen
inspection, and the available historical app source has not yet been built
against a matching Blue SDK. No signing command or key operation was sent.

## Next test

Identify a public SDK revision matching the Blue 2.1.1 firmware and historical
ZClassic app, build the app reproducibly, and test it against fixed public
fixtures before considering installation. Keep the host and any new device
code in C23. Verify the complete app and dependency code before execution.
