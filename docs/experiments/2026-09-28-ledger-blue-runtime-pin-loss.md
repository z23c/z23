<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue PIN loss during payment review

Date: 2026-09-28T17:16:55Z (2026-09-28T13:16:55-04:00).
Host CPU: AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics.
Host compiler: Clang 22.1.6. ARM compiler: arm-none-eabi-gcc 16.2.0.

## Question

After the Blue has opened a payment review, can PIN validation end while
the Wallet still approves signing or returns a signature? Does the screen
retain a stale review, and does a rejected APDU retain signature bytes?

## Method and result

The SDK-stub UI test ends PIN validation before the SIGN ZCL touch, before
the signing APDU, during the signer callback, during each of two timer clears,
and before a review redraw. Before the fix, the first case retained signing
approval and failed at `test_blue_wallet_device_ui.c:734`. The old redraw
also left the review visible and failed at
`test_blue_wallet_device_ui.c:802`. The corrected Wallet checks PIN state at
the touch approval boundary, before and after payment APDU processing,
after timer clear, after completion cleanup, and before showing a review page.
The completion-clear test first failed at `test_blue_wallet_device_ui.c:815`:
a mock signature was returned after PIN validation ended in that later
callback. A PIN rejection returns
`0x6985`, erases the full reply capacity, clears the reported reply length,
and aborts the review and signing timer. A redraw shows REVIEW ENDED. The
injected signer may produce a mock signature before PIN loss; the Wallet
rejects and erases that reply instead of returning it.

The focused Release UI test passed. The full serial Release suite passed
57/57 in 12.20 seconds on the final source. The full serial sanitized Debug
suite passed 57/57 in 14.25 seconds with LeakSanitizer disabled because this
runner's ptrace environment prevents its startup.

## Image and memory

The uninstalled Wallet 0.3.22 image built with the pinned Blue SDK revision
and reviewed C23 patch. `.text` is 47,360 bytes, `.data` is zero, and `.bss`
is 5,120 bytes. This adds 512 bytes of `.text` over 0.3.21 without changing
static RAM or the checked stack peaks. The largest named app path uses
1,096 bytes plus the 512-byte intermediate-frame margin, within the
2,048-byte stack reservation. The largest named signer path is the public-key
hash at 1,056 bytes plus that margin. BOLOS frames are excluded from the
stack checker. The `.text` SHA-256 is
`178d0e3ece26df54418377c7877bbf3e6a495b68db072fe6718ac18d1417a35a`.
The Intel HEX SHA-256 is
`d9d00b88d1c921a9d2af2ffa71050dd99a3cf36dcdf0a8c07cbc0124149b1ad2`.

An independent source snapshot was made from `git archive` of signed parent
`04884b02a3b42978bdda2f4ff370a4428f10e716` with this exact working
patch applied. It built against a separately cloned SDK at revision
`3c710b4c62ad847599a2deb0932a50dd1ae4bdff` with reviewed patch SHA-256
`4919fd81ba7a3a80880065aaf7898c2edd603b2586f6086a88570c73996019f6`.
Its `.text` binary and Intel HEX file matched the first build byte for byte.
Both builds used the same ARM toolchain and host; this does not test compiler
diversity.

## Limit

The image has not been installed on a physical Blue. SDK stubs cannot prove
BOLOS lock timing, physical touchscreen behavior, or app startup and exit.
PIN validation is checked at defined boundaries rather than atomically
across BOLOS calls. This change does not enable Sapling signing or establish
a verified chain tip.
