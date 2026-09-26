<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# ZCL Probe for Ledger Blue

This C23 application targets Ledger Blue BOLOS 2.1.x (`0x31000004`). Its Blue
screen says “No keys or signing.” Its declared installation flags are `0x00`.
It does not derive keys, display ZCL addresses, or sign transactions. It proves
the device application and host command boundary before custody code is added.

## Build

Use Ledger's Apache-2.0 `blue-secure-sdk` tag `blue-r21.1` at commit
`3c710b4c62ad847599a2deb0932a50dd1ae4bdff`. Apply
[`blue-sdk-c23.patch`](blue-sdk-c23.patch) to that exact clean tree. The patch
selects the ARM target headers, updates the SDK's C dialect, and fixes
strict-build and USB parsing defects. It retains Ledger's upstream license.
Set `BOLOS_SDK` to the patched tree, `ARM_INCLUDE_DIR` to the ARM Newlib
headers, and `CLANGPATH` and `GCCPATH` to the respective compiler directory
prefixes. Then run:

```sh
make -C apps/zcl-ledger/device-blue
```

The build requires Clang with ARM `-fropi` support and an ARM GCC linker. It
uses `-std=c23 -Wall -Wextra -Werror -pedantic`. The app binary and HEX file
appear under `apps/zcl-ledger/device-blue/bin/`. No Python or Rust is used by
this build. Do not install this development app on a Blue holding funds.

## APDU

The app accepts only `A5 01 00 00 00`. Its seven-byte reply is
`5A 43 4C 01 00 90 00`: ASCII `ZCL`, protocol version 1, zero capabilities,
and success status. All other instructions are rejected. Z23's C23 host
parses the exact reply through `zcl-ledger probe [--json] /dev/hidrawN`.

## Installation status

This repository does not yet contain a C23 Blue secure-channel installer.
The app has been cross-compiled and checked for byte-for-byte reproducibility,
but has not been run in an emulator or installed on a physical Blue. Build
success does not establish runtime behavior or wallet safety.
