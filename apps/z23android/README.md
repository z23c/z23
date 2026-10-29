<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->
# Z23 Android

This experimental native C23 app runs on arm64 Android 15 (API 35) or later.
It starts a full node using Tor and an app-private persistent onion identity.
Use the app's node status to check synchronization; a running process alone
does not prove that the chain is synchronized. Root access and bootloader
unlocking are not required to install the app.

## Build on Linux

Install the Linux build prerequisites and Android NDK r30 described in the
[Android ARM64 guide](../../docs/dev/ANDROID.md). Also install an Android SDK
with platform 35 and build-tools 35.0.0, a JDK with `keytool` and `jar`, and
CMake 3.22 or newer. Set these paths to your installations:

```sh
export ANDROID_NDK_ROOT=/path/to/android-ndk-r30
export ANDROID_SDK_ROOT=/path/to/android-sdk
export JAVA_HOME=/path/to/jdk
```

From the repository root, build the Android node and its pinned dependencies,
then package the app:

```sh
make -j4 ZCL_TARGET=android-arm64 z23
cd apps/z23android
make apk SDK_ROOT="$ANDROID_SDK_ROOT" ANDROID_NDK_ROOT="$ANDROID_NDK_ROOT" JAVA_HOME="$JAVA_HOME"
```

On managed development hosts, use the host's build admission command for
both builds. The APK is `build/android-app/z23.apk` at the repository root.
The app build creates `build/android-app/development.keystore` if it does not
exist. Preserve this key securely: Android requires the same signing key to
install an update over an existing app. This development key is not a
production signing process. Preserve and back up wallet state before updates.

## Install and open

Enable USB debugging, connect the device, and accept the debugging prompt.
Select the intended device from `adb devices` and set its serial:

```sh
"$ANDROID_SDK_ROOT/platform-tools/adb" devices
export ANDROID_SERIAL=YOUR_DEVICE_SERIAL
make install SDK_ROOT="$ANDROID_SDK_ROOT" ANDROID_NDK_ROOT="$ANDROID_NDK_ROOT" JAVA_HOME="$JAVA_HOME" ANDROID_SERIAL="$ANDROID_SERIAL"
make launch SDK_ROOT="$ANDROID_SDK_ROOT" ANDROID_SERIAL="$ANDROID_SERIAL"
```

Run these commands from `apps/z23android`. `make install` builds the APK before
installing it. The node stores its data in the app's private storage.

## Current limits

The main screen shows balance, synchronization status and the conversation.
Details contains node controls, fleet invitations, QR codes and diagnostic
output. Failed balance refreshes retain the last value with a stale label;
an unavailable balance is not displayed as zero.

Chat refreshes a bounded read-only node summary before asking the paired
assistant. The summary includes synchronization text, balance and availability
flags. It excludes keys, addresses and raw RPC output. This summary and the
question are sent to the configured assistant through the laptop bridge.
Chat cannot execute wallet operations or spend funds.
While an answer is pending, Send becomes Stop reply. Cancellation closes the
client connection and discards late answers. It does not stop the full node
or establish that remote model generation stopped. Cancellation during the
initial node refresh waits for the bounded observation commands to finish.

## Voice architecture

Voice conversation is planned, not yet operational. The intended flow is
microphone capture, transcription, a node-grounded answer and spoken playback.
The Android app remains C23. Its controller owns the conversation lifecycle;
audio adapters own capture and playback, and the existing authenticated bridge
owns transport. Model inference belongs on a paired fleet machine to preserve
phone resources for node validation.

Recording must start with an explicit user action, show its state, and stop
when cancelled or the app leaves the foreground. Audio queues and utterances
must be bounded. Cancellation must discard late replies. Network or model
failure must leave text input available. No microphone button is exposed until
capture, transcription and playback work together on the device.

Qwen speech generation needs a qualified native backend and measured response
latency. A generated WAV alone does not establish a natural conversation.
Device acceptance includes microphone permission denial, cancellation,
disconnects, stale node data, audible replies and concurrent node progress.

The app uses Android widgets and the system keyboard. Camera scanning, chat,
and fleet operations still require device qualification. Chat requires a
separate laptop bridge and a verified connection. Background operation and
hardware-backed wallet custody are not qualified.

The [isolated shielded transaction experiment](../../docs/experiments/2026-10-28-pixel-shielded-api.md)
describes the existing regtest API demonstration and its evidence. It is not
an app setup or a mainnet payment guide.
