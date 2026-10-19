<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue account revocation after PIN loss

Date: 2026-09-28T18:18:07Z (2026-09-28T14:18:07-04:00).
Host CPU: AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics.
Host compiler: Clang 22.1.6. ARM compiler: arm-none-eabi-gcc 16.2.0.

## Question

If PIN validation ends and then returns while the same app process remains
open, can it reuse derived account hashes, answer an address APDU, or begin
a payment? Does an idle receive screen notice the lock? What remains in app
RAM after EXIT?

## Method and result

The SDK-stub loop test starts a valid account, drops PIN validation before
one address APDU, restores it before a second address and payment APDU, and
checks all three replies. The old loop failed at
`test_blue_wallet_startup.c:488`: it returned a 35-byte address reply after
validation returned. Wallet 0.3.25 clears the two account hashes, public
key, and receive address when it observes PIN loss; later address and
payment APDUs return only `0x6985` until a new app launch derives the
account again.

A second red test failed at `test_blue_wallet_startup.c:540`: an idle PIN
loss left RECEIVE ZCL on screen. The corrected ticker route revokes the
account once and shows DEVICE LOCKED. The payment UI tests inject loss at
the SIGN ZCL touch, before a signing request, inside the signer, during
both timer clears, and before redraw. Each route clears the account hashes.
The integrated app-loop test drives a complete synthetic transparent review,
then loses PIN validation at SIGN ZCL; the screen changes to DEVICE LOCKED,
approval is cleared, and a later address request remains rejected.

The integrated app-loop test first failed at
`test_blue_wallet_integrated_loop.c:403` when payment-screen EXIT left the
receive account in app RAM. Both EXIT buttons now use the same cleanup path.
Normal EXIT and exception teardown erase the account hashes, public key,
receive address, and shared APDU buffer. The Cortex-M0 wallet emulator
checks that the account was ready before EXIT and that these public account
fields are zero afterward. The full serial Release suite passed 57/57 in
42.69 seconds. The serial sanitized Debug suite passed 57/57 in 18.33
seconds with LeakSanitizer disabled because this runner's ptrace environment
prevents its startup.

## Image and memory

The uninstalled Wallet 0.3.25 image uses the pinned Blue SDK revision
`3c710b4c62ad847599a2deb0932a50dd1ae4bdff` and reviewed SDK patch
SHA-256
`4919fd81ba7a3a80880065aaf7898c2edd603b2586f6086a88570c73996019f6`.
Its `.text` is 48,384 bytes, `.data` is zero, and `.bss` is 5,120 bytes.
The largest named app path uses 1,088 bytes plus a 512-byte margin within
the 2,048-byte stack reservation. The largest named signer path is the
public-key hash at 1,048 bytes plus that margin. BOLOS frames are excluded.
The `.text` SHA-256 is
`38ff70405802ab6084e8baa7df8e6e3b86c8f82755f7ba11fb1eaf819b8807c8`.
The Intel HEX SHA-256 is
`e154a247cc7bff6655ad82d888432bc166d7159f72f86f3ce05362fd7bb37279`.

An independent source snapshot was made from `git archive` of signed parent
`44237ef8c87831474ee88118b3da56c890b58177` with the working patch
applied. A separate copy of the pinned SDK built the snapshot with the same
ARM toolchain. The `.text` binary and Intel HEX matched the first build byte
for byte. This tests repeatability on one host and compiler toolchain.

## Limit

The image has not been installed on a physical Blue. SDK stubs and Cortex-M0
emulation cannot prove BOLOS PIN-state timing, touchscreen behavior, or
physical startup and exit. The physical Wallet install block remains after
0.3.4 froze on opening. This change does not enable Sapling signing or
establish a verified chain tip.
