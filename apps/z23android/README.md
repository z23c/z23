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

Chat refreshes a bounded read-only node summary before asking the private
model on the paired laptop host. The summary includes synchronization text,
balance and availability flags. It excludes keys, addresses and raw RPC
output. Up to 32 earlier exchanges, at most 4 KB, travel as separate turns
with a constant system message, so the model server reuses their cached
prefix instead of re-reading the whole conversation for every question. When
the history fills, the oldest exchanges are dropped down to half its size at
once, which keeps the remaining prefix unchanged for many turns.
Chat cannot execute wallet operations or spend funds.
While an answer is pending, Send becomes Stop reply. Cancellation closes the
client connection and discards late answers. It does not stop the full node
or establish that remote model generation stopped. Cancellation during the
initial node refresh waits for the bounded observation commands to finish.

## Private voice and fleet host

A laptop connected over USB runs the private assistant. The C23 host
`z23-speech-bridge` starts three local `llama-server` processes (chat,
speech recognition and speech synthesis), relays phone requests over an
`adb reverse` loopback tunnel, and probes fleet hosts over SSH. Audio,
questions and answers stay on the laptop and phone; nothing is sent to a
cloud service. Model weights are external inputs and are not bundled in the
repository or APK.

### Build llama.cpp and the host

Build [llama.cpp](https://github.com/ggml-org/llama.cpp) with
`-DGGML_VULKAN=ON` (Vulkan headers and SPIR-V headers required). The measured
build is commit `2e0d86b`. Then, from the repository root:

```sh
make -C apps/z23android speech-bridge speech-probe
make -C apps/z23android test
```

On managed hosts, prefix builds and tests with `devbuild --wait`. The host
binary is `build/android-app/z23-speech-bridge`.

### Pinned models

Place these files, verified with `sha256sum -c`, in one models directory.
They come from `unsloth/Qwen3.5-4B-GGUF` revision
`e87f176479d0855a907a41277aca2f8ee7a09523`, `unslothai/Qwen3-ASR-0.6B-GGUF`
revision `9045ad9c16021af1f08a4862a9a13d56177eec24` and
`mradermacher/Qwen3-TTS-12Hz-0.6B-Base-GGUF` revision
`0762b31e9cd99274d49dca4e895bd81863134f08`. Review each model card and
license before downloading. The 0.6B speech model synthesizes at 0.77 times
real time on the measured laptop against 0.96 for the 1.7B model, which leaves
headroom for gapless streamed answers.

```text
00fe7986ff5f6b463e62455821146049db6f9313603938a70800d1fb69ef11a4  Qwen3.5-4B-Q4_K_M.gguf
bca259818b50ca7c4c05e9bdb35a5dc04fa039653a6d6f3f0f331f96f6aa1971  Qwen3-ASR-0.6B-Q8_0.gguf
41a342b5e4c514e968cb756de6cd1b7be39eff43c44c57a2ef5fc6522e36603d  mmproj-Qwen3-ASR-0.6B-Q8_0.gguf
59b28b4ab6a1c4e24e6701fc871a427c1fb3e8333f0ed5cebec3bb67a699ae8e  Qwen3-TTS-12Hz-0.6B-Base.Q8_0.gguf
202c1fbf3a0f00b7586ca45b8328d696cc6cd980c3798979eaa4fefe8efd8320  Qwen3-TTS-12Hz-0.6B-Base.mmproj-Q8_0.gguf
```

### Run and pair

```sh
mkdir -p -m 700 "$HOME/.cache/z23-voice/host"
build/android-app/z23-speech-bridge --dir "$HOME/.cache/z23-voice/host" \
  --llama-server /path/to/llama.cpp/build/bin/llama-server --models /path/to/models \
  --speaker voice.wav --fleet r1=host1.example,r2=host2.example \
  --adb "$ANDROID_SDK_ROOT/platform-tools/adb" --serial "$ANDROID_SERIAL" \
  --app org.z23.nativeapp
```

`--speaker` is a short mono WAV of the voice to imitate; without it the
synthesized voice varies between answers. `--fleet` lists SSH destinations
that accept non-interactive key login; the host runs only a fixed read-only
status command on each and reports block height against `zclassicd`.

On first start the host prints a six-character pairing code and opens the app
with a pairing offer. Accept on the phone only if it shows the same code. The
host keeps its port and token in `--dir`, so later restarts reconnect without
another pairing. The token reaches `adb` on standard input, not in laptop process arguments;
on the phone it is briefly visible to shell and root in the arguments of the
`am` command. The app stores it privately as `speech-bridge.json`.

### Use

Press **Talk** and ask a question; recording ends after a pause of about
0.8 seconds, or press **Done talking**. The answer appears in the
conversation and is spoken sentence by sentence; **Stop speaking** interrupts
it and ends the conversation. After each spoken answer the app listens again:
ask a follow-up within 6 seconds, or stay quiet to end the conversation. A
conversation holds at most eight spoken exchanges. It stops at a start or stop
proposal, which waits for a tap on screen, and when an answer cannot be spoken.
When no speech starts within 8 seconds of pressing **Talk**, listening stops.
Typed questions use the same private model. **Refresh fleet** probes every
host. “Start node” and “stop node” create proposals that require **Confirm
start** or **Confirm stop** on screen. The assistant cannot run commands,
change hosts or spend funds.

### Developer notes

- Host tests run on Linux with `make -C apps/z23android test HOST_CC=clang
  BUILD_DIR=../../build/android-voice`. `preview-apk` needs `NODE_BIN`,
  `ANDROID_NDK_ROOT`, `SDK_ROOT` and `JAVA_HOME`; without them it stops before
  building and leaves any previous APK in place.
- The host defaults to `--app org.z23.nativeapp`. Pass
  `--app org.z23.voicepreview` when testing the preview package, or the pairing
  offer reopens the production app.
- Android app data directories are mode `0771` and owned by the app group;
  private-directory checks allow group write only for the app's own group.
- A relaunch with `FLAG_ACTIVITY_CLEAR_TASK` creates the new activity before
  the old one is destroyed; the newest activity takes over the native UI.
- Each capture logs its level floor and peak under logcat tag `z23`, and each
  spoken answer logs its playback length and the number and length of gaps
  where audio ran out before the answer ended. The host logs the elapsed
  milliseconds of every operation and, for streamed answers, the time to the
  first text and the first audio. On the measured Pixel,
  speech from a laptop speaker peaked at mean levels of 417-556 over a floor
  of 10-12.
- Heights in the fleet summary and the phone status use thousands separators.
  In four sampled answers about a fleet at height 2950000, the chat model
  misread raw digits once (as 29,500,000) and copied grouped digits correctly
  every time.

### Measured latency

Measured 2026-10-29 on an AMD Ryzen 7 PRO 8840U with Radeon 780M graphics
(Vulkan, RADV) and a Pixel over USB, for a 2-second spoken fleet question with
streamed answers: recognition 0.23 s, first answer text 1.2-2.2 s, first audio
4.8-5.9 s after the host receives the question, and 5.6-6.5 s from the end of
speech to the first sound on the phone. Chat and synthesis share the
integrated GPU, so the first chunk is synthesized mostly after chat finishes.
Two answers of 15.8 s and 22.0 s played with 2 gaps totaling 0.52 s and with
no gaps. Four synthesized sentences transcribed back to their input text
except one compound word. These are single observations, not guarantees.
Recognition accuracy and speech quality are otherwise unqualified.

With earlier exchanges sent as separate turns, chat re-reads 285-347 prompt
tokens per question (0.80-0.96 s) instead of 669-734 tokens that grew with the
conversation (1.75-1.84 s). Over six later answers the first text arrived in
1.1-1.3 s and first audio in 4.4-5.2 s after the host received the question; in
three of them the first sound came 5.4-5.7 s after the end of speech.

In one live conversation the app answered a question, heard a follow-up spoken
1.0 s after the first answer ended and answered it, then ended after 6 seconds
of silence. The two answers played 18.1 s and 19.3 s with one gap each, of
1.46 s and 0.38 s.

`make -C apps/z23android preview-apk` builds a separate
`org.z23.voicepreview` package with debugging enabled for testing. That
preview is separate from the production `org.z23.nativeapp` package and its
private state; it does not establish production readiness.

The app uses Android widgets and the system keyboard. Camera scanning, chat,
and fleet operations still require device qualification. Chat and voice
require the paired laptop host. Background operation and
hardware-backed wallet custody are not qualified.

The [isolated shielded transaction experiment](../../docs/experiments/2026-10-28-pixel-shielded-api.md)
describes the existing regtest API demonstration and its evidence. It is not
an app setup or a mainnet payment guide.
