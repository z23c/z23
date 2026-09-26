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
uses `-std=c23 -Wall -Wextra -Werror -pedantic`. The ELF and HEX files appear
under `apps/zcl-ledger/device-blue/bin/`. No Python or Rust is used by this
build. Do not install this development app on a Blue holding funds.

## APDU

The app accepts only `A5 01 00 00 00`. Its seven-byte reply is
`5A 43 4C 01 00 90 00`: ASCII `ZCL`, protocol version 1, zero capabilities,
and success status. All other instructions are rejected. Z23's C23 host
parses the exact reply through `zcl-ledger probe [--json] /dev/hidrawN`.

## Install on the tested Blue v2

Generate the code section as a raw binary and check its SHA-256:

```sh
llvm-objcopy -O binary --only-section=.text \
  apps/zcl-ledger/device-blue/bin/app.elf /tmp/zcl-probe.bin
sha256sum /tmp/zcl-probe.bin
```

The reviewed 11,520-byte image has SHA-256
`b38704d3476ac9914dde5d816de88930ed705bdd53246903419c1cb96211eb33`.
The installer rejects any other image. Build the C23 host and check the
secure channel before installing:

```sh
cmake -S apps/zcl-ledger -B build/zcl-ledger -DCMAKE_C_COMPILER=clang
cmake --build build/zcl-ledger
build/zcl-ledger/zcl-blue-install /dev/hidraw1 --channel-only
build/zcl-ledger/zcl-blue-install /dev/hidraw1 /tmp/zcl-probe.bin
```

Use the app interface reported by `zcl-ledger devices`; `/dev/hidraw1` is
only the path observed on the tested laptop. If the running app cannot be
exited through its touchscreen, restart the Blue using its side button. To
remove the probe from the Blue dashboard, run
`zcl-blue-install /dev/hidrawN --delete`.

The first installed build flashed repeatedly because it redrew the whole
screen on every ticker event and did not forward button events. It was exited
through USB and deleted. The corrected build was installed on the connected
Blue v2, answered the version-1 probe, displayed a steady screen, and exited
through its touchscreen. This confirms the no-key probe only; wallet custody
and ZCL transaction behavior remain unimplemented.

The Blue displays “Non genuine application” when this locally loaded app
opens because Ledger has not signed it. This warning comes from BOLOS, not
from the app UI. A custom developer certificate changes the device's trust
configuration and can affect Ledger's genuine check; it is not enrolled by
this installer. The current independent install preserves the firmware
warning rather than disguising the app's provenance.
