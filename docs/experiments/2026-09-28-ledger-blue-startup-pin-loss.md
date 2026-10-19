<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue receive-account startup after PIN loss

Date: 2026-09-28T16:33:43Z (2026-09-28T12:33:43-04:00).
Host CPU: AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics.
Host compiler: Clang 22.1.6. ARM compiler: arm-none-eabi-gcc 16.2.0.

## Question

Can the Blue show a ready receive address and enable payment account hashes
after PIN validation ends during internal public-key generation or hashing?

## Method and result

The SDK-stub startup test changes PIN validation during the second BIP32
keypair generation. Before the fix, the app still displayed the ready receive
screen; the test failed at `test_blue_wallet_startup.c:535`. The corrected
startup checks PIN validation after keypair generation and after the internal
account hash. A second fault injection ends validation during that hash.
Both cases now display ADDRESS UNAVAILABLE, leave the account hashes unset,
erase the boot key material and displayed address, and retain a working EXIT
button. The focused Release test passed.

A separate SDK-stub test throws a BOLOS exception after the second keypair
has written private material. Before the final cleanup was added, the test
failed at `test_blue_wallet_startup.c:556` because the boot workspace still
contained key bytes. The final app cleanup now erases that workspace. The
corrected focused Release test passed.
The full serial Release suite on the combined correction passed 57/57 in
123.59 seconds. The full serial sanitized Debug suite passed 57/57 in
273.71 seconds with LeakSanitizer disabled because this runner's ptrace
environment prevents its startup. An earlier sanitized run under concurrent
lint load timed out in the M0 Sapling emulator; the final serial run passed
that emulator in 25.49 seconds without changing its limits.

## Image and memory

The uninstalled Wallet 0.3.21 image built with the pinned Blue SDK revision
and reviewed C23 patch. `.text` is 46,848 bytes, `.data` is zero, and `.bss`
is 5,120 bytes. This adds 256 bytes of `.text` over 0.3.20 without changing
static RAM or the measured stack peaks. The largest named app path uses
1,096 bytes plus the 512-byte intermediate-frame margin, within the
2,048-byte stack reservation. The largest named signer path is the public-key
hash at 1,056 bytes plus that margin. BOLOS frames are excluded from the
stack checker. The `.text` SHA-256 is
`3b1feff3fabb89afad229227e9ecbe699f6cbb4a5975c299c04d1a5e50c44248`.
The Intel HEX SHA-256 is
`6ce96fc61dd51da2b4eb9318a2d8d78eb86571a18ce27d37fefd9a18b7dcfa8b`.

An independent source snapshot was made from `git archive` of signed parent
`126e858d846031ce664272bcaf724ed7a252e2cb` with this exact working
patch applied. It built against a separately cloned SDK at revision
`3c710b4c62ad847599a2deb0932a50dd1ae4bdff` with reviewed patch SHA-256
`4919fd81ba7a3a80880065aaf7898c2edd603b2586f6086a88570c73996019f6`.
Its `.text` binary and Intel HEX file matched the first build byte for byte.
Both builds used the same ARM toolchain and host; this does not test compiler
diversity.

All 33 fast lint gates passed in 433.400 seconds, above their 75-second soft
budget on this shared host. The unchanged consensus-core seal matched 554
files and 80 sections. The Markdown link check scanned 518 documents and
947 local targets. The inline-path check scanned 518 tracked documents with
12 baselined findings and no new findings before this experiment was staged.

## Limit

The image has not been installed on a physical Blue. SDK stubs do not prove
the timing of PIN state changes in BOLOS or physical app startup and EXIT.
The PIN checks cannot make BOLOS operations atomic. This change does not
enable Sapling signing or establish a verified chain tip.
