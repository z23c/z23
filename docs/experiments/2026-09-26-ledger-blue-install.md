<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue C23 secure install and UI recovery

Recorded: 2026-09-26T03:51:35-04:00 (2026-09-26T07:51:35Z)

## Question

Can Z23 install a no-key C23 app on the connected Ledger Blue v2 without
Ledger Live or a Python loader, then run and exit it reliably?

## Method

The connected Blue reported BOLOS 2.1.1 on Linux USB HID. Its secure-channel
target ID was `0x31010004`; `0x31000004` returned status `6484`. The C23 host
performed the Blue V2 certificate exchange, verified the ephemeral device
certificate, derived the SCPv3 AES keys with OpenSSL 3.6.3, and queried the
target ID through an encrypted APDU. The host checked the app image SHA-256
before loading. Device source was cross-compiled with Clang 22.1.6 for ARMv6-M
and linked with `arm-none-eabi-gcc` 16.2.0. Two separate patched SDK trees
produced byte-identical corrected HEX and binary images. The host was built
and tested with Clang 22.1.6 Debug plus address/undefined sanitizers and GCC
16.1.1 Release, both with C23, `-Wall -Wextra -Werror -pedantic`. The CPU model
was not recorded for this functional test; no speed benchmark was run.

## Observations

- Initial `E0 04` using `0x31000004` returned `6484`. The Blue v2 target
  `0x31010004` completed the handshake and encrypted target-ID query.
- The first app creation command included an API-level byte and returned
  `6700`. The Blue accepted the 21-byte legacy creation command without it.
- The first 11,008-byte app image was accepted and answered the exact ZCL
  probe APDU, but its screen flashed repeatedly and the side power button
  did not exit the app. A USB bus reset restored the USB interface but did not
  stop the app. The Blue accepted `B0 A7 00 00 00`, returned to BOLOS 2.1.1,
  and accepted a secure-channel deletion of the app.
- The first UI handler redrew the screen on every ticker event and omitted
  button-event forwarding. The corrected handler forwards ticker and button
  events through the SDK without periodic redraw.
- The corrected binary was 11,520 bytes, SHA-256
  `b38704d3476ac9914dde5d816de88930ed705bdd53246903419c1cb96211eb33`.
  Both independent builds produced the same HEX SHA-256
  `f0631ed55f574ecb0ba1dfae7966c3cac9a9ce32d0a9ad626e40e702ad72826b`.
- The corrected image was installed. The device displayed a steady ZCL Probe
  screen and its touchscreen EXIT button returned to BOLOS 2.1.1. The host
  `app-info` command independently reported BOLOS after exit.
- BOLOS displayed “Non genuine application” each time the locally loaded app
  opened. The app was not signed by Ledger; the warning is expected for this
  installation path.
- Clang Debug and GCC Release host builds each passed both local tests:
  HID framing and secure-channel sign, verify, ECDH, encryption, and MAC
  rejection.

## Limits

The UI observation was made on one physical Ledger Blue v2. The initial
flashing build shows that compilation and APDU success do not validate the
screen or controls. The current image accesses no keys and cannot derive a ZCL
address or sign a transaction. The first device certificate is accepted under
Ledger's custom-authority development flow; this is not a manufacturer
attestation. The balance and seed status of the connected Blue were not
established.
