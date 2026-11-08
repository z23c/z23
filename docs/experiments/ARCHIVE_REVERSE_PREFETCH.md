<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Archive reverse prefetch

History archive validation reads headers from tip to genesis. Its reader uses
one-mebibyte reverse windows as an advisory hint, rather than advising the
whole file in ascending order. Header and ancestry validation remain required.

The window size is a hypothesis. Measure archive-open elapsed time and page
faults on the target Android device against the same archive before accepting
a performance claim. The focused archive fixtures exercise valid, corrupt,
truncated, and cancelled reads; mapping coverage checks boundary handling.

On 2026-11-08, an Android Pixel test used the same archive, 20 synthetic keys,
and checkpoint 521782 in A-B-B-A order. A used the Stop candidate; B added
reverse prefetch. Both used the same NDK compiler and normalized build flags.
Elapsed time from flat-index load completion to DISCOVER was 192, 46, 51, and
216 seconds respectively. This interval includes work beyond archive open;
it is not a full-sync or CPU benchmark. The test did not flush caches. A1
started after an unclean marker; the other runs followed clean exits.

Peak resident memory for B1, B2, and A2 was 1,856,456, 1,872,328, and
1,838,532 KiB. Battery temperature rose from 32.6 C before B1 to 36.6 C
after A2. All four Stop operations exited successfully and preserved the
wallet fingerprint and checkpoint. These observations support further
measurement; they do not isolate every source of the elapsed-time difference.

The device reported Pixel 3 and SDM845. Both binaries used Android NDK r30,
clang 21.0.0, API 35, `-O3`, `armv8-a` and ThinLTO; the normalized flags
SHA-256 was `c232846768e06f19c918bd8817ba7daf057f9f8dd551ef67ed02985613d138a9`.
A used source 44b4 plus Stop diff
`1f32bd8785fbfd618a40a250af5adcc65d7a62f1a5d8b3e068eb863c97ea0e2e`
and binary SHA-256
`5b011e10b1f9fff3404d7c49ff5de2535ce672f593cb19dc8517f87004aa8f83`.
B used tracked diff `1c92252e97e9598d9758f175e4cc5568fdc399e9d25b8602329b7567bdbbe7d6`
against 44b4, including the test-only fixture correction, and binary SHA-256
`bce8c308625462c05bd462a7ac5c02e16bef76683257fc8bd5b023ba53c7095e`.
