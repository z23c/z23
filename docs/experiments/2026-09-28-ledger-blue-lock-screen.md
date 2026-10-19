<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue lock screen after PIN loss

Date: 2026-09-28T17:33:58Z (2026-09-28T13:33:58-04:00).
Host CPU: AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics.
Host compiler: Clang 22.1.6. ARM compiler: arm-none-eabi-gcc 16.2.0.

## Question

After the payment layer rejects an APDU because PIN validation ended, does
the app loop replace its stale receive screen with an explicit locked state?
Do USB reset, suspend, and review timeout take the same route?

## Method and result

The SDK-stub loop test made the payment command end PIN validation after
startup. Before the change, the rejected-payment assertion failed in
`test_blue_wallet_startup.c:410`: the app redrew RECEIVE ZCL. That initial
red run also had PIN validation disabled at startup by the preceding test;
the later 0.3.24 regression resets it and confirms loss during the command.
The corrected
loop shows DEVICE LOCKED and UNLOCK THEN REOPEN, keeps EXIT functional, and
does not leave the payment review visible. The reply contains only `0x6985`.
The same test ends PIN validation during USB reset, USB suspend, and timeout,
then checks the lock screen and EXIT. Startup tests now distinguish a locked
Blue from an unlocked address-derivation failure.

The full serial Release suite passed 57/57 in 11.30 seconds. The serial
sanitized Debug suite passed 57/57 in 14.68 seconds with LeakSanitizer
disabled because this runner's ptrace environment prevents its startup.
The repository fast lint passed 33/33 gates in 31.077 seconds.

## Image and memory

The uninstalled Wallet 0.3.23 image uses the pinned Blue SDK revision
`3c710b4c62ad847599a2deb0932a50dd1ae4bdff` and reviewed SDK patch
SHA-256
`4919fd81ba7a3a80880065aaf7898c2edd603b2586f6086a88570c73996019f6`.
Its `.text` is 47,104 bytes, `.data` is zero, and `.bss` is 5,120 bytes.
The largest named app path uses 1,080 bytes plus a 512-byte margin within
the 2,048-byte stack reservation. The largest named signer path is the
public-key hash at 1,040 bytes plus that margin. BOLOS frames are excluded.
The `.text` SHA-256 is
`866fa4d214f7c35d97afd23c121a161a65bbd64f2bfad5c4cf18093b9e2270a3`.
The Intel HEX SHA-256 is
`183b3b58803042bc87a8d0244a1bc59b38acde9cea85c77e2f0ac0c247cdd4b2`.

An independent source snapshot was made from `git archive` of signed parent
`2daf487b233233e40a554a683742f07f2a2d4a8e` with the working patch
applied. A separate copy of the pinned SDK built the snapshot with the same
ARM toolchain. The `.text` binary and Intel HEX matched the first build byte
for byte. This tests build repeatability on one host and compiler toolchain.

## Limit

The image has not been installed on a physical Blue. The SDK stubs do not
prove BOLOS lock timing, touchscreen behavior, or app startup and exit.
The physical install block remains in place after Wallet 0.3.4 froze on
opening. This change does not enable Sapling signing or establish a verified
chain tip.
