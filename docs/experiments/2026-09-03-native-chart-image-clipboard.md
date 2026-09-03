<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Native chart image clipboard

## Intent

Make copying a C23 chart an immediate, visible native-window action without a
browser, script runtime, or intermediate file.

## Environment

- Local time: `2026-09-03T14:48:32-04:00`
- UTC: `2026-09-03T18:48:32+00:00`
- Compiler: `GCC 16.1.1 20260430`
- CPU: `AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics`
- Desktop backend: dynamically loaded X11
- Source chart: 1120×680 packed RGB8

## Method

The native window copied its current medium-text chart through the `C` input
path. An independent X11 clipboard client requested `TARGETS`, then requested
the advertised image payloads. Byte counts and headers were observed without
writing a screenshot file.

## Result

- Advertised compatibility target: `image/bmp`
- Clipboard payload: `2,284,854` bytes
- Expected payload: `54 + (1120 × 3 × 680) = 2,284,854` bytes
- Signature: `42 4d` (`BM`)
- Encoded width: `1120`
- Encoded height: `680`
- Pixel format: `24` bits per pixel
- Focused presentation acceptance: `test_qr`, 1/1 group passed
- Production C23 build: passed, maximum runtime ABI `GLIBC_2.38`

The exact size, header, dimensions, format, and independent clipboard readback
matched. The copy control also uses a pure resize-aware hit test, and successful
copy changes the control to `COPIED! PASTE NOW` while keeping the window open.

The first live test exposed only BMP. Although the bytes were exact, common
Linux paste targets did not accept that clipboard flavor. The corrected path
advertises `image/png` first and retains BMP as fallback. The in-memory PNG
encoder has independent signature, chunk, CRC, stored-DEFLATE, short-buffer,
and RGB/RGBA round-trip coverage; `test_test_png_writer` passed 1/1 group.

The corrected live readback advertised both `image/png` and `image/bmp`. An
independent request for `image/png` returned `2,285,718` bytes beginning with
the exact PNG signature and an IHDR declaring width `1120`, height `680`,
8-bit samples, and RGB color type `2`.
