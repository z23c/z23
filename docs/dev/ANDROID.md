<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Android ARM64 development

The Android target builds a native C23 command-line executable using the
Android NDK and Bionic. The experimental native Android app packages this
executable; it does not replace Android. The default target is Android 15
(API 35). See the [app build and install guide](../../apps/z23android/README.md).
<!-- claim: symbol-present android-arm64 Makefile # Android cross target -->

## Build on Linux

Install Android NDK r30, Android platform-tools, a host C23 compiler,
GNU make, CMake, autoconf, automake, libtool, pkg-config, and standard
Unix build tools. Set the NDK location to your installation:

```sh
git clone --recurse-submodules https://github.com/z23c/z23.git
cd z23
export ANDROID_NDK_ROOT=/path/to/android-ndk-r30
make -j4 ZCL_TARGET=android-arm64 z23
```

On managed development hosts, run the make command through the installed
build-admission command. The first build fetches and builds the pinned
dependencies. Target archives are separate from host archives. Host tools
generate source; the NDK compiles the Android executable.
<!-- claim: symbol-present ZCL_CROSS_TRIPLE Makefile # target archive selection -->
<!-- claim: symbol-present HOST_CC Makefile # native generators -->

The binary audit requires an ARM64 PIE with the Android linker, Bionic libc,
and no dynamic dependencies beyond libc, libm, and libdl. C++ runtime symbols
are rejected.
<!-- claim: symbol-present /system/bin/linker64 tools/scripts/check_c23_node_binary.sh # Android ELF audit -->

## Run over USB

Enable USB debugging, connect the phone, and accept its debugging prompt.
Rooted debugging is not needed for these commands. Select a device with
`adb -s SERIAL` if more than one is attached.

```sh
adb devices
adb push build/bin/z23 /data/local/tmp/z23
adb shell chmod 755 /data/local/tmp/z23
adb shell /data/local/tmp/z23 --version
adb shell /data/local/tmp/z23 discover help
```

For a bounded local startup check, use a separate empty data directory.
This deliberately connects only to a closed loopback port:

```sh
adb shell mkdir -p /data/local/tmp/z23-smoke
adb shell 'timeout -s INT -k 45 30 /data/local/tmp/z23 -datadir=/data/local/tmp/z23-smoke -operator-lane=test -no-tor -bind=127.0.0.1 -connect=127.0.0.1:1 -nolegacyimport -legacyoracle=off'
```

While that command runs, inspect it from another terminal:

```sh
adb shell /data/local/tmp/z23 status -datadir=/data/local/tmp/z23-smoke
```

The timeout intentionally requests shutdown. Confirm `Shutdown complete.`
in its output; a timeout exit status alone does not establish clean shutdown.
An empty offline chain is not evidence of synchronization or wallet readiness.

## Scope and qualification

The native app has been launched on an Android device. A successful ADB-shell
run alone does not qualify the app, camera scanning, chat, background service
lifecycle, or hardware-backed wallet custody. The desktop GUI is separate
from the Android activity. See the [app guide](../../apps/z23android/README.md)
for its current limitations.

Android thread joins retain exclusive ownership of joinable handles across
timeouts. Android CPU affinity supports the calling thread only; attempts
to place another thread are refused.
<!-- claim: symbol-present platform_thread_join_until platform/modules/platform/include/platform/thread_compat.h # bounded join adapter -->
<!-- claim: symbol-present ENOTSUP platform/modules/util/src/cpu_topology.c # foreign thread affinity refusal -->

Device evidence and focused test commands are recorded in
[Android ARM64 acceptance](../experiments/2026-10-28-android-arm64.md).
The explicit `android-acceptance-device` make target runs the C23 thread and
affinity checks on the selected device; ordinary builds do not invoke ADB.
<!-- claim: symbol-present android-acceptance-device platform/modules/platform/tests/android_acceptance.mk # explicit hardware test entry point -->
