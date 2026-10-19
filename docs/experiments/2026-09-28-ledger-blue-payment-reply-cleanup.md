<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue payment reply cleanup

Date: 2026-09-28T14:39:36Z (2026-09-28T10:39:36-04:00).
Host CPU: AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics.
Host compiler: Clang 22.1.6. ARM compiler: arm-none-eabi-gcc 16.2.0.

## Question

After a payment command returns a short response, does the shared Blue USB
buffer retain bytes from the previous request? Does a rejected command leave
its reply storage unchanged?

## Method

The portable test fills a 32-byte shared request/reply buffer with `0xa5`,
sends a five-byte status request, and checks that only the six declared
response bytes remain. It then sends a malformed request in the same buffer
and checks that all 32 bytes are zero. Before the fix, the first check failed
at `test_blue_payment_review.c:650`: bytes beyond the response retained the
old marker. The existing 10,000-case APDU mutation test now requires zero
bytes through the declared reply capacity after every response, and still
checks that eight guard bytes beyond capacity remain unchanged. The simulated
device loop checks that a successful `BEGIN` has erased all shared APDU bytes
after its two-byte status word.

The handler now rejects a nominal success if its declared reply length exceeds
capacity. On any failure with a valid storage layout it aborts the review,
erases the full reply capacity, and sets the length to zero. On success it
erases the tail after the declared reply. The request and reply may still be
the same external USB buffer. Rejected storage aliases take the separate
pre-parse abort path, which avoids writing through device-owned state.

## Measured image and limits

The uninstalled Wallet 0.3.19 image built with the pinned Blue SDK patch and
C23 ARM tools. `.text` is 46,592 bytes, `.data` is zero, and `.bss` is 5,120
bytes. The largest named payment path uses 1,080 bytes after the 512-byte
intermediate-frame margin, within the 2,048-byte app stack reservation. This
is 16 bytes more than 0.3.18; BOLOS frames are excluded from the checker.
The `.text` SHA-256 is
`d77d5cbb661f5cecfad4cd789c61b8afedfbbf73d56d1a4157acd6b3426b1571`.
The Intel HEX SHA-256 is
`b0c606dda78b440975c71bb352ed64ac9856656ba8029712e5727e5f582e6674`.
An independent source snapshot was made from `git archive` of signed parent
`5338a328a8ba19bf12527733c68938e419373fe7` with the exact Wallet
working patch applied. It built against a separately patched SDK copy whose
reviewed patch hash was
`4919fd81ba7a3a80880065aaf7898c2edd603b2586f6086a88570c73996019f6`.
Its `.text` binary and Intel HEX file matched the first build byte for byte
and had the same SHA-256 values. Both builds used the same ARM toolchain and
host; this does not test compiler diversity.

The portable Release payment-review and simulated-device-loop tests passed
2/2. Their sanitized Debug run passed 2/2 with LeakSanitizer disabled because
this runner's ptrace environment makes LeakSanitizer fail before the tests.
The full serial Release suite passed 57/57 in 55.30 seconds; the full serial
sanitized Debug suite passed 57/57 in 43.69 seconds with the same
LeakSanitizer setting.
All 33 fast lint gates passed in 89.288 seconds, above their 75-second soft
budget on this shared host. The unchanged consensus-core seal matched 554
files and 80 sections. The Markdown link check scanned 513 documents and
941 local targets; the inline-path check scanned 513 documents with 12
baselined findings and no new findings.

## Limit

The image is not installed. Host tests and the SDK link do not prove that the
Blue's BOLOS USB loop, touchscreen, or exit behavior works on the physical
device. This cleanup does not enable Sapling signing or establish a verified
chain tip.
