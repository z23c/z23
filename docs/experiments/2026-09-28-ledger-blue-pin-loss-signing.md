<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue PIN loss during signing

Date: 2026-09-28T16:17:59Z (2026-09-28T12:17:59-04:00).
Host CPU: AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics.
Host compiler: Clang 22.1.6. ARM compiler: arm-none-eabi-gcc 16.2.0.

## Question

If Blue PIN validation ends after the signing command begins, can the wallet
still return an ECDSA signature? Does failure erase the key workspace and
reply buffers?

## Method and result

The SDK-stub test changes the PIN-validation result during public-key
generation, public-key hashing, and ECDSA. Before the correction, the
derivation case returned success and the focused CTest failed at
`test_blue_wallet_signer_device.c:151`. The corrected signer checks PIN
validation after derivation, just before ECDSA, and after the signing syscall.
The test requires no ECDSA call after the first two losses, no signature reply
after the last loss, a zero reported length, and erased signer workspace and
reply bytes on failure. The focused Release and sanitized Debug tests passed.
The full serial Release suite passed 57/57 in 57.10 seconds. The full serial
sanitized Debug suite passed 57/57 in 205.99 seconds with LeakSanitizer
disabled because this runner's ptrace environment prevents its startup.

## Image and memory

The uninstalled Wallet 0.3.20 image built with the pinned Blue SDK revision
and reviewed C23 patch. `.text` is 46,592 bytes, `.data` is zero, and `.bss`
is 5,120 bytes. The largest named app path uses 1,096 bytes plus the
512-byte intermediate-frame margin, within the 2,048-byte stack reservation.
The largest named signer path is the public-key hash at 1,056 bytes plus that
margin. The stack checker excludes BOLOS frames. The `.text` SHA-256 is
`fc896779cf948385742b737dc3188f2479207be06f92a78a13d02fff00c79548`.
The Intel HEX SHA-256 is
`8a203ebfeb0aaf7ae6ac4b2f5aa581e94c8e1cd384e0a429d9fe3642618d3858`.

An independent source snapshot was made from `git archive` of parent
`a79911fcee29d2bb1c1f46c276809d11bc369f88` with this exact working
patch applied. It built against a separately cloned SDK at revision
`3c710b4c62ad847599a2deb0932a50dd1ae4bdff` with reviewed patch SHA-256
`4919fd81ba7a3a80880065aaf7898c2edd603b2586f6086a88570c73996019f6`.
Its `.text` binary and Intel HEX file matched the first build byte for byte.
Both builds used the same ARM toolchain and host; this does not test compiler
diversity.

All 33 fast lint gates passed in 271.802 seconds, above their 75-second soft
budget on this shared host. The unchanged consensus-core seal matched 554
files and 80 sections. The Markdown link check scanned 517 documents and
946 local targets. The inline-path check scanned 517 documents with 12
baselined findings and no new findings.

## Limit

The candidate has not been installed on a physical Blue. SDK stubs cannot
prove that PIN state changes during these BOLOS calls on device or that a
physical app opens and exits correctly. The check cannot make the PIN state
atomic across BOLOS calls. This work does not enable Sapling signing or
establish a verified chain tip.
