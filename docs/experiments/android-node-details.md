<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Android node details

On 2026-11-14, the node-details change was tested against source
`d5f7089a3559629272e5cce917d7bf71a1e7a47f`, with reviewed source diff
SHA-256 `9dd3a94a9834dc09a5ad83f02365c8c4435f264ba6ebb5cf4b426c1f2d648e8f`.
The admitted `make -j4 -C apps/z23android test-host` passed. Its Home tests
covered status states, the two-block tolerance, unknown values, preview, layout
and exclusion of planted wallet and assistant strings. The first host run
failed because the layout test still expected three phone-card children; the
test was corrected to check all four and the next run passed.

An admitted CMake Android arm64 API 35 native build and link passed with NDK
r30, its Clang 21 toolchain and probe/fixture options off. The selected pinned
Android crypto archive had SHA-256
`59d9b24cc3418c4ebb710d0c9361ccf08dac4aa58987a0cdf5c9c1edc38a0149`;
the tracked vendor inputs and OpenSSL build scripts matched the earlier
`4fcd8da60c28bcb6060e03b6baf1f829af09e6e8` build. The CMake
`Z23_CRYPTO` cache option selected that archive, and the matching generated
headers were supplied through the C compiler include flags.

This is host and cross-compile evidence. A reviewed, landed package still
requires portrait device inspection of the Home action, details, Back and
notification behavior. No device installation or physical UI result is
claimed by these checks.

The native check used the existing CMake target with the selected archive and
headers:
Run these commands inside the host devbuild admission rail.

```sh
make -C apps/z23android prepare-quirc BUILD_DIR=../../build/node-details-check
cmake -S apps/z23android -B build/node-details-check/native \
  -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_ROOT/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-35 -DZ23_ANDROID_API=35 \
  -DZ23_QUIRC_DIR="$PWD/build/node-details-check/quirc" \
  -DZ23_CRYPTO="$ANDROID_CRYPTO" -DCMAKE_C_FLAGS="-I$ANDROID_CRYPTO_INCLUDE" \
  -DZ23_DEVKEY_PROBE=OFF -DZAPP_SHARE_FIXTURE=OFF -DZ23_PREVIEW_PARAMS=OFF \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build/node-details-check/native --parallel 4
```

The NDK, archive and header variables above represent the retained inputs
identified by version and digest in this record.

The first native candidate verification did not qualify: its complexity gate
reported three functions above the existing cap, and a stale replay-tool
depfile made the selector fall back to the universal set. That invalid run was
stopped after the failure. The formatter, action dispatch and test cases were
split without changing the cap or assertions; the complexity check then
passed. Rebuilding the existing `skycombat-model-replay` target refreshed the
depfile and the selector returned a closed 42-group selection. After the
repair, `test-host` and the Android native compile and link passed again.
