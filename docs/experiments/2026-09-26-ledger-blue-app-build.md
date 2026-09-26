<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Blue C23 app build

Recorded: 2026-09-26T03:27:09-04:00 (2026-09-26T07:27:09Z)

## Question

Can a no-key ZCL device app compile under strict C23 for the connected Blue's
BOLOS 2.1.x target, with reproducible image bytes?

## Method

The app was built against two separate clones of Ledger's `blue-secure-sdk`
commit `3c710b4c62ad847599a2deb0932a50dd1ae4bdff` after applying the
repository's `blue-sdk-c23.patch`. Clang 22.1.6 compiled C23 for ARMv6-M with
`-Wall -Wextra -Werror -pedantic`; `arm-none-eabi-gcc` 16.2.0 linked it. The
image was not sent to the connected device.

## Results

- Both builds succeeded without compiler or linker diagnostics.
- Both builds produced the same `app.hex` SHA-256:
  `08496a2a84977f9371ce4ddc1cc93965b02b3781053c1e2488690f509f6456e6`.
- The ELF size was 11,016 bytes of text and 2,032 bytes of BSS.
- Clang 22.1.6 Debug with sanitizers and GCC 16.1.1 Release passed the host's
  `ledger-hid` test, including exact probe-response rejection cases.

The build validates source compatibility and image reproducibility. It does
not validate execution on the Blue. The missing C23 secure-channel installer
is the next test boundary. Once available, install only after reviewing the
loader, confirming the Blue model and firmware, and comparing the displayed
image hash on-device.
