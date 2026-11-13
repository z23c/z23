<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Android peer version probe build

The standalone peer version probe previously entered node vendor setup and its
Android link requested a separate pthread library. The standalone target now
avoids node-only bootstrapping and uses Android libc for threads.

On 2026-11-13, the Android ARM64 target built successfully with NDK r30 and
API 35 through the normal development build admission. The output was an
AArch64 Android PIE with SHA-256
`9053d9dbf54d367ba68f9ed91eb693fefe3fdd641501a4c1dd189e5689d1ba47`.
This build result alone does not establish a peer exchange.

The original Android target link failed because `-lpthread` was unavailable;
an earlier attempt entered unrelated vendor setup. The successful command was:

```sh
ANDROID_NDK_ROOT="$NDK_ROOT" DEVBUILD_CLASS=normal devbuild --wait --project z23 make p2p-version-probe ZCL_TARGET=android-arm64 BIN_DIR="$OUTPUT_DIR"
```

The Makefile SHA-256 was
`3fca9f021050e2354242f3a9f6df6e6b3286d0286c8859802eea7e244a2544f5`.
A non-author reviewed the target classification and platform link change and
accepted it. A subsequent phone peer probe passed; build success alone does
not establish persistent node connectivity.
