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

## Complete archive check on the Pixel

On 2026-11-07, the same Pixel 3 checked 3,309,988 index rows and full
header ancestry through height 3,309,900. The archive phase took 212,410 ms;
the cold loader group passed 1/1 in 302.6 seconds with no skips, cached
results or unobserved environment inputs. Android Clang 21.0.0 from NDK r30
compiled the API 35 runner from source
`8a75fb5bbae216f9411acec998f813929c57be9f`.

| Observation | KiB |
| --- | ---: |
| Resident memory before archive loading | 25,240 |
| Resident memory after archive validation | 815,248 |
| Process peak resident memory | 1,746,624 |
| Resident memory after main-state cleanup | 723,844 |

Runner SHA256:
`dd2a6ede14b3dd95157d6a2c10e2efc3b54b6f886485e71727fb862d8830c757`.
Run log SHA256:
`c6830395985f92cdeccaa9481475926ae11699bc340a268bad4f43194095c8f6`.
The public input inventory digest was
`900e4f1013a06f545938ee03962ac973a6c201bfafdcebae1ed3b291060e0cb2`.
Android thermal status changed from 0 to 1. This is not a clock-rate
measurement. An earlier attempt used the wrong working directory, failed
relative-path fixtures, and was terminated; it is excluded from the pass.

This isolated root-shell experiment did not open the installed wallet.
Combined app memory pressure, foreground survival and wallet readiness
remain separate acceptance requirements.

## App-owned installation handoff

On 2026-11-07, the full Android app host test target passed with the
one-time installation handoff, cancellation guards and installing status.
The same operations fixture passed on the Pixel as UID 0, including its
wrong-owner refusal assertions. The fixture launches itself as a mock node;
it does not install a production snapshot or prove wallet readiness.

The measured app source was the base above plus patch SHA256
`e8705a4346b3a68e107ca5085cee1f133c51a7eccdc2b975ed53d2e1f7d0fced`.
Host log SHA256:
`de42790257a4e9a3e8bf5e45ae3f0647ec96397bcbbe0e80da9818762771c788`.
Pixel runner SHA256:
`048cee9a36d14c456fc531ea3d1420d1a7be2cf108f77841f38f34e9495b1dcc`.
Pixel log SHA256:
`cd0b944d46dc76610503eba7685b8a4576f3eb848978d16790b57b0ba0d415d8`.
Subsequent fixture helper extraction preserves these production bytes;
its exact test source requires separate qualification.

The extracted fixture subsequently passed on both the host and Pixel on
2026-11-07. Its cumulative code patch SHA256 was
`da6abb2f488f4de5981742a0a7604634f2986e00d5c4076c2b94555b08534d49`.
Host operations log SHA256:
`8ca82d630506013f5d14d9c934b099866cb77cbe655dc6103097faa81a28faf8`.
Pixel runner SHA256:
`f622112c752da3f638da1320f12b87131c1824f416b081fea2ce44f32e89d058`.
Pixel log SHA256:
`8da82aeaf91698c18753e673a2f5746a435b5dd936bc7cd2b3b29002674fdf7a`.
The complexity gate also passed without changing its limits or baseline.

## Terminal installation with an authenticated history bridge

On 2026-11-07, an isolated host installed the complete production-sized
bundle at height 3,309,900 using the authenticated public history archive.
The terminal command exited 0 and reported H*=3,309,900; the applied height <!-- stale-ok: immutable 2026-11-07 isolated installation result -->
was 3,309,901. Wall time was 8 minutes 33.68 seconds and peak resident memory
was 1,904,496 KiB while other work was running. This is one concurrent-load
observation, not an isolated performance benchmark.

The tested binary SHA256 was
`0e9027b16fc4478eedc5ce73e4d9d24fb8eaef668f1efae26f34b91850cfd598`.
Its recorded source identity was
`58c10bb8da88f513cbf61dfa90435c054105b54f0dc2db32cb02c2d813f294e6`.
The selected-chain binding passed with the archive-backed temporary ancestry
bridge; the install retained the existing frontier and publication checks.

A fresh boot restored the installed island and loaded a synthetic wallet with
100 keys. History loading was still in progress at the observation; wallet
readiness and completed replay were not established. This host experiment
used an isolated datadir and did not exercise a real wallet. The repaired
path has not been verified on the phone.

Host: AMD Ryzen 9 7950X3D; compiler: GCC 14.2.0 (Ubuntu
14.2.0-4ubuntu2~24.04.1). This measurement predates the subsequent helper
extraction; that source requires its own qualification.
