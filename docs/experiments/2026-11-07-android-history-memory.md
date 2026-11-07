<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Android compact history index memory

On 2026-11-07T06:11:49Z, a Pixel 3 (Snapdragon 845, Android API 35,
arm64-v8a) ran the existing block-index test harness against a public index
containing 3,310,291 rows. Loading the index, checking contiguous selected
parents through height 3,309,900, and constructing the active-chain array took
10,637 ms. Peak resident memory was 817,488 KiB (798.33 MiB).

This measurement supports reusing the compact index for a bounded history
experiment on this device. It does not establish wallet migration readiness.

## Reproduction identity

- Source base: 876beb8dcfb010479e24f62492b8dee2eb7631c7.
- Test-only patch SHA256: 50078599b66d3f90f298a8a4d73e71acb7288b1c0bb2d2a6cca566a62ec45ed8.
- Compiler: Android Clang 21.0.0, build 16134705, r574158c; NDK r30, API 35.
- Runner SHA256: 03360caa90649c9b6f677fd52d239d4ab0efabf126ce43e0157d6655fafce4d4.
- Input: 569,370,663 bytes, BIIE v2 envelope with ZCLI payload.
- Input SHA256: d525b48750f0f86b08f9fbd3b1ab824f0ae610efcfb17e6a808cb29ec2bdda35.
- Selected endpoint: 00000bba7bfe991c575002333e8839f67e86bd1ee96d033e5741bb62bda887df.
- Run log SHA256: 62ca543b94ff0ffcad32f908468b66fa4bf126ada2142d0701f7c3cb8d4eb0a9.

The ordinary harness selected exactly the block-index-loader group, with one
job, a 900-second timeout, caching disabled and an isolated temporary directory.
The opt-in fixture supplied the input directory, row count, endpoint height,
endpoint hash and input size. The cold group passed 1/1 in 83.9 seconds, with
zero failures, cached results, self-skips or unobserved-environment results.
The narrower 10,637-ms measurement covers index loading and chain selection.

## Observations and limits

| Observation | KiB |
| --- | ---: |
| Resident memory before loading | 21,652 |
| Resident memory after loading | 811,640 |
| Peak resident memory | 817,488 |
| Resident memory after main-state cleanup | 720,496 |

The input digest and metadata were unchanged after execution. The run used a
private, nonconcurrently written directory under a root shell. Its path checks
do not prove race-free binding against a hostile process with the same UID.
The experiment did not use the installed wallet or modify its databases.

The harness process does not reproduce combined app and node memory pressure,
Android foreground survival, wallet scanning, or an authenticated migration.
Cleanup memory is not a zero-leak measurement: the block-index arena remains
allocated for process lifetime. The cache digest identifies bytes; it is not
consensus or ancestry authority. Subsequent loader and wallet changes were not
part of this measured source and need their own correctness checks.

The production compact loader is `load_block_index_flat`.
<!-- claim: symbol-present load_block_index_flat engine/services/src/block_index_loader.c # compact index loader -->

## Complete archive check on a server

On 2026-11-07, the authenticated archive loader checked 3,309,988 index rows
and the selected header ancestry through height 3,309,900 against real public
block files from a completed, quiescent FULL replay. The archive check took
99,733 ms on an AMD Ryzen 9 7950X3D with GCC 14.2.0
(Ubuntu 14.2.0-4ubuntu2~24.04.1). The cold loader test group passed 1/1 in
110.8 seconds, with no skips, cached results or unobserved environment inputs.

| Observation | KiB |
| --- | ---: |
| Resident memory before archive loading | 29,424 |
| Resident memory after archive validation | 822,152 |
| Process peak resident memory | 1,822,708 |
| Resident memory after main-state cleanup | 730,744 |

The runner SHA256 was
`99658a97a66afe27c548cda65528af440b6bbff7af5658e0bf64ff103eeea124`.
The run log SHA256 was
`ddfe15743d684f7d5e28385dfcdf83fe2acbae566f049f4291724082d9d41712`.
The source included the archive and terminal-install changes on base
`876beb8dcfb010479e24f62492b8dee2eb7631c7`, before the H3309900 checkpoint bake.

This workload reads full headers from block files as well as the compact
index. Its process peak is not a phase-specific allocation measurement and
cannot be compared directly with the Pixel index-only result. The larger
peak requires a separate combined app and node measurement on the phone;
this server result does not establish Android survival or migration latency.
