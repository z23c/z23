# Android proving parameters in the APK

Copyright 2026 Rhett Creighton - Apache License 2.0

Date: 2026-10-31 (UTC). Host: r1, AMD Ryzen 9 7950X3D, `cc` 14.2.0, NDK r30, build-tools 35.0.0.
Base: `0c02d98643`. No phone measurement was taken (see Not measured).

## Intention

A shielded send needs `sapling-spend.params` (47,958,396 bytes) and `sapling-output.params`
(3,592,860 bytes). Fetching them from a third party would show that the phone holds a wallet, so
the APK carries them. `apps/z23android` now packs both as uncompressed assets, copies them once
to a private directory, verifies the pinned SHA-256 of the copy and starts the node with
`-paramsdir`. A pure function refuses a send unless the copy is verified, the node reports that it
can prove and the phone is not hot.

## What changed

- `params.sha256` pins both files; `make check-params` (a dependency of `make apk`) fails with a
  message when `PARAMS_DIR` (default `vendor/params`, git-ignored like `vendor/cross`) lacks a
  file or a hash differs.
- `make apk` stages the files under `assets/params` and runs `aapt ... -A assets -0 params`.
- `params.c`: pinned table, `zapp_params_present` (a size-only look for the UI and for choosing
  node arguments, never a permission), `zapp_params_arg`, and `zapp_prover_allowed`.
- `params_install.c`: `zapp_params_install` first reads every existing file and compares its
  SHA-256 with the pin; only a complete match returns OK without opening the source. Anything else,
  a same-size corrupt copy included, is removed and replaced: copy to `files/params.tmp`, `fsync`,
  read back, SHA-256 against the pin, rename each file, `fsync` the directory, rename the directory
  to `files/params`, `fsync` the parent. On any failure no pinned file remains under
  `files/params`, including when the parent `fsync` fails after the rename (the renamed directory's
  files are removed); the directory stays only if it holds a file this code did not create. A stale
  `params.tmp` is discarded on the next run. `zapp_params_verify` is the read-only check. The
  hash is the `zsha256` package already used by `apps/zcl-ledger`.
- `params_job.c`: runs the install on a detached thread over descriptors the caller opened. It
  owns and closes them, holds no JNI, asset manager or caller memory, and reports by
  `zapp_params_job_state` (IDLE, COPYING, VERIFIED, FAILED with a reason). Nothing is called back.
  The install gets duplicates made with `F_DUPFD_CLOEXEC`. A start refused because a copy runs, or
  because the thread cannot start, closes its descriptors and changes neither the state nor the
  files.
- `params_android.c`: on the caller's thread, opens each asset with
  `AAsset_openFileDescriptor64` (valid only for uncompressed assets), marks them close-on-exec
  so a node spawned during the copy does not inherit them, and hands them to the job.
- `zapp_prover_allowed(thermal, params_verified, probe, ...)` passes only when the copy of this
  process was verified, `probe->status` returns `ZAPP_PROVING_ARMED`, and the thermal status is
  below 3. It is a refusal before a send; a copy is not paused for heat.
- `operations.c`: `spawn_node` appends `-paramsdir=<files>/params` when both files are present at
  their pinned size; the node applies its own SHA-512 pin on load.
- `make preview-apk` leaves the parameters out unless `PREVIEW_PARAMS=1`; `make apk` packs them
  (`PACK_PARAMS=1`, the default).

Not wired: nothing calls `zapp_params_prepare_async` or `zapp_prover_allowed` yet, and the proving
probe has no implementation. The node-side status call is being added by another change (the node
loads the Sapling pair lazily at the first proof and reports a status); the probe becomes one RPC
to the running node mapped onto `enum zapp_proving`. No restart flow is built.

## Findings about the node (core/ is out of bounds for this lane)

1. The node does verify what it loads. `core/modules/sapling/src/params_init.c:242-255`
   (`params_read_pinned`) reads each file and compares its SHA-512 with a compiled-in pin; the
   spend and output pins are used at `:331-347` (first load) and `:508-521` (late load). The
   native prover does not: `core/modules/sapling/src/sapling_prover_native.c:402-418`
   (`zclassic_init_zksnark_params`) only checks that the path and hash arguments are non-null and
   that both proving keys are resident. The prover self-test then proves and verifies a bundle
   against the published verifying keys.
2. **The two-file asset set cannot arm proving; this is a design correction.** Both load paths
   demand the whole four-file set. First load: `params_init.c:362-367` fails with
   "sprout-groth16.params unusable" (725,523,612 bytes). Late load, the path a node booted
   without parameters takes: `:486-535` checks `sprout-verifying.key` (`:498`) and then
   `sprout-groth16.params` (`:535`) and returns false before keeping the Sapling keys, by the
   rule in the comment at `:478-482` that half a set does not support the claim. The boot gate
   `engine/composition/src/boot_params_gate.c:49-72` also treats any of the four missing as the
   "embedded verifying keys only" state and reports `shielded_spend_unavailable`. The Sapling
   prover never reads the Sprout files (`sapling_prover_native.c` mentions them only in the
   non-null check at `:405-411`).

   Consequence: with only the two Sapling files in `-paramsdir`, the node still cannot prove.
   The options are (a) a core/ change, through `core/UNSEAL.md`, that lets the late load accept
   the Sapling pair on its own, keeping both SHA-512 pins and the embedded-prefix check at
   `:545-560`; (b) shipping `sprout-groth16.params` (725 MB), which is not practical for an APK.
   `sprout-verifying.key` is 1,449 bytes and could ship either way. This change makes the app side
   correct and tested; option (a) is a decision for the owner.

## Measurements

APK size, same node binary, `make apk` and `make preview-apk` on r1, after the review fixes:

| build | `z23.apk` bytes |
| --- | ---: |
| base `0c02d98643` | 17,363,569 |
| preview without parameters (this code) | 17,375,857 |
| `make apk` with parameters | 68,928,274 |
| parameters alone (apk minus preview) | 51,552,417 |

The two files total 51,551,256 bytes. Both packages are the same code, so the 1,161 byte
remainder is zip headers and signature data for the two entries and is not itemized.
In an earlier pair of builds the difference exceeded the file sizes by 13,449 bytes; `unzip -v` of
that pair shows `libz23android.so` compressed from 485,991 to 498,901 bytes (+12,910), so nearly
all of it was app code, not zip overhead. The preview's +12,288 bytes over the base: 10,784 are the compressed `libz23android.so`
(496,775 against 485,991) and the other 1,504 are not itemized. `unzip -v` of the parameter build:
both assets `Stored`, 0% compression, CRC-checked; `apksigner verify` passes and
`zipalign -c -P 16 4` passes for both packages. The preview package holds no `assets/`.

Release build: the Makefile has one packaging path, with no minification or resource
shrinking. `aapt -0 params` keeps the assets stored, `jar uf` only adds `classes.dex` and `lib`,
and `zipalign` and `apksigner` do not recompress. `preview-apk` passes `PACK_PARAMS=0` unless
`PREVIEW_PARAMS=1`, so a preview carries no parameters and needs no `vendor/params`.

Copy on the host (`zapp_params_install` through a directory source, real files, four runs, each
including write, `fsync`, read-back hash and renames; page cache warm, caches could not be
dropped without privilege):

| run | wall | peak RSS |
| --- | ---: | ---: |
| 1 | 2.68 s | 2.3 MB |
| 2 | 3.40 s | 2.6 MB |
| 3 | 3.10 s | 2.6 MB |
| 4 | 2.02 s | 2.6 MB |

Peak memory is the 1 MiB copy buffer plus process baseline. A source with one flipped byte
returns the hash result in 1.5 s and leaves an empty `files` directory.

Gate checks, each run against the real build: `PARAMS_DIR=/nonexistent` stops with "Proving
parameters not found"; a flipped byte in `sapling-output.params` prints `FAILED` for that file and
stops; a deleted `sapling-spend.params` stops; the correct directory passes.

## Tests and mutants

`tests/params_test.c` (in `make -C apps/z23android test`) uses small fixtures through the
`zapp_params_install_set` seam and a source whose bytes begin after a 4,097 byte prefix (as in an
APK entry). `-Wl,--wrap=fsync` counts flushes and fails the Nth one; `-Wl,--wrap=write` fails writes
after a byte limit. It covers: success with byte-identical private (0600) copies and no leftovers;
the destination directory absent while files are staged; flipped byte in the source for either
file; wrong length; absent asset; an interrupted `.tmp` and a wrong-size `params` directory
restarting cleanly; an already verified directory not reopening the source; a same-size corrupt
installed copy (either file) that `zapp_params_present_set` accepts, `zapp_params_verify_set`
rejects and install replaces from the source; a failing flush at each of the four points (both
files, the staging directory, the parent after the rename), a write error at three byte limits and a
source shorter than its claimed range, each returning `ZAPP_PARAMS_IO` with nothing left behind and
a later install succeeding; the job reporting VERIFIED and FAILED by polling, closing each descriptor it was given exactly
once and freeing its record, reading only close-on-exec descriptors, refusing a second start
while a worker is held inside its first flush, and keeping the earlier VERIFIED or FAILED outcome
and the files when the thread cannot start (a wrapped `pthread_create`); a foreign file in
`files/params` surviving a failed install while the pinned files do not; `-paramsdir` produced only for a complete
directory and refused when the buffer is too small; the pinned table equal to `params.sha256` and
to the documented sizes; and `zapp_prover_allowed` over every thermal status -1 to 6 with a stub
node probe returning armed, unavailable and unknown, an unverified copy never asking the node.
`tests/operations_test.c` starts a stand-in node through `spawn_node` and requires exactly five
arguments without parameters, with one file, or with a wrong-size file, and the sixth
`-paramsdir=<files>/params` only with both files at the pinned size.

Mutants of the sources (one edit each, host build of `params_test` or `operations_test`); every one
turns the test red:

- the five the review named: file `fsync` result ignored, parent `fsync` result ignored, write
  errors ignored, a short read treated as end of file, no discard after an IO failure;
- also: staging directory `fsync` result ignored; install accepting a present copy without hashing;
  the renamed directory kept when the parent `fsync` fails; skip the hash comparison; ignore the
  asset offset; keep a stale `.tmp`; drop the length check; publish without read-back; thermal
  threshold 4 instead of 3; ignore the copy gate; ignore the node status; ignore the node saying
  unavailable; presence ignoring size; wrong pinned hash; wrong pinned size; the node argument
  without presence; the job leaving descriptors open; the job always reporting VERIFIED;
- `params_job.c`: descriptors closed only when no record was allocated; the running guard removed;
  a second close of each descriptor; the worker's record not freed; a refused start's record not
  freed; a failed thread start marking FAILED; the duplicate made without close-on-exec;
- `operations.c`: the `argv[5]` assignment removed; `-paramsdir` added when the files are absent.

## Not measured

Nothing below has run on a phone.

- Phone copy and verify time, peak memory and thermal state. `params_android.c` compiles in the NDK
  build but has not executed; neither has `params_job.c` on bionic, nor the use of one
  `AAsset_openFileDescriptor64` descriptor duplicated and read at an offset from another thread.
- The proving probe: there is no implementation, and the node's status call is not in this tree.
- A node run that loads these files, for the reason in finding 2.
- The thermal refusal and the send screen, which nothing calls yet.
