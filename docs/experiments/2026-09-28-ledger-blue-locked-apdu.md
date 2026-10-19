<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue address APDU after PIN loss

Date: 2026-09-28T17:41:17Z (2026-09-28T13:41:17-04:00).
Host CPU: AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics.
Host compiler: Clang 22.1.6. ARM compiler: arm-none-eabi-gcc 16.2.0.

## Question

Can the wallet disclose a receive public key if PIN validation ends between
successful startup and a host read-only address APDU? Does it show the locked
state and erase the shared USB buffer on rejection?

## Method and result

The SDK-stub loop test starts with valid PIN state and a ready receive
account, then ends PIN validation when it delivers the address APDU. The
pre-fix test failed at `test_blue_wallet_startup.c:428`: the reply length
was 35 bytes instead of the required two-byte status. A second injected
test lets the first PIN check pass, then ends validation before the response;
the first fix still returned 35 bytes and failed at
`test_blue_wallet_startup.c:455`. The corrected device
loop rejects locked requests other than a read-only app identity query,
checks PIN state again before replying, returns only `0x6985`, erases the
entire shared request and reply buffer,
and shows DEVICE LOCKED. The test checks the status-only reply, zeroed
buffer tail, locked screen, and functional EXIT. The previous payment test
now explicitly begins after successful PIN-validated startup, then injects
PIN loss inside the payment command.

The final full serial Release suite passed 57/57 in 17.14 seconds. The serial
sanitized Debug suite passed 57/57 in 14.38 seconds with LeakSanitizer
disabled because this runner's ptrace environment prevents its startup.
The first implementation exceeded the unchanged cyclomatic cap of 15 in
`answer_command` (M=16); moving APDU dispatch into `handle_command` made the
complexity gate pass without changing its limit or baseline.

## Image and memory

The uninstalled Wallet 0.3.24 image uses the pinned Blue SDK revision
`3c710b4c62ad847599a2deb0932a50dd1ae4bdff` and reviewed SDK patch
SHA-256
`4919fd81ba7a3a80880065aaf7898c2edd603b2586f6086a88570c73996019f6`.
Its `.text` is 47,360 bytes, `.data` is zero, and `.bss` is 5,120 bytes.
The largest named app path uses 1,088 bytes plus a 512-byte margin within
the 2,048-byte stack reservation. The largest named signer path is the
public-key hash at 1,048 bytes plus that margin. BOLOS frames are excluded.
The `.text` SHA-256 is
`ab3f13f40926ce0a5689b31ae3fc07366ee41583a1e76e3b6a39c449cd0cf0e1`.
The Intel HEX SHA-256 is
`f0cf390f315983faf741b3967cc1a647639372d8c4a100ddad2f81950d8a0507`.

An independent source snapshot was made from `git archive` of signed parent
`cb3cd994853c3e10d64011bd250d9f5cd4528d81` with the working patch
applied. A separate copy of the pinned SDK built the snapshot with the same
ARM toolchain. The `.text` binary and Intel HEX matched the first build byte
for byte. This tests build repeatability on one host and compiler toolchain.

## Limit

The image has not been installed on a physical Blue. The SDK stubs do not
prove BOLOS PIN-state timing, touchscreen behavior, or app startup and exit.
The physical install block remains in place after Wallet 0.3.4 froze on
opening. This change does not enable Sapling signing or establish a verified
chain tip.
