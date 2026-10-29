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

The main screen shows one line for the node, one for the fleet, **Talk** and
the conversation, newest exchange first. The node line says whether the node
is stopped, starting, waiting for peers, catching up (height of target) or in
sync, with its peer count. The fleet line repeats the paired host's cached
fleet headline, read every 60 seconds without probing the hosts again; while a
laptop host is paired it reads "Fleet · checking" until the first report, so
the screen does not shift under a tap when the report arrives. When
the conversation buffer fills, whole older exchanges are dropped first.
**More** holds typed questions, the host connection, each fleet host,
synchronization detail, balance, **Stop node** and fleet invitations. Each host
row gives the host's state and height and adds free disk only below 50 GB;
blockers are left to the voice assistant. A host counts as in sync within two
blocks of its `zclassicd` unless it reports itself not synced. Command
output reaches the screen only as plain sentences; a JSON error shows its
message alone, and audio failures show one sentence while their cause goes to
logcat. The app runs only two read-only node commands, the node status and
the wallet balance, besides starting, stopping and joining a fleet. Failed
balance refreshes keep the last value, labelled as possibly out of date; an
unavailable balance is not displayed as zero.

**Start node** records the choice in the app's private state, and the app
starts the node each time it opens until **Stop node** clears the choice.
**Stop node** shows while the node runs or while that choice is saved, so a
node that keeps exiting on its own can still be turned off.
Closing or leaving the app does not stop the node.
After **Stop node** the node line reads "Node stopping" until the node has
saved its data and exited. The app finds a node left by an earlier app process
through the node's pid file and its first argument, this `-datadir`: it shows
that node as running, refuses a second start and stops that node on request.
The preview package never runs a node: it has no **Start node** button,
answers a spoken start request without proposing one, and states that it is
separate from the main node. When no current fleet report arrives, the fleet
line says so and **More** labels the last report as old.

Chat refreshes a bounded read-only node summary before asking the private
model on the paired laptop host. The summary includes synchronization text,
balance and availability flags. It excludes keys, addresses and raw RPC
output. It travels as data labelled as this phone's own node, apart from the
fleet hosts, followed by the question. Only answers from the model join the
history; error messages and answers made on the phone do not. Up to 32 earlier
exchanges, at most 4 KB, travel as separate turns with a constant system
message, so the model server reuses their cached prefix instead of re-reading
the whole conversation for every question. When the history fills, the oldest
exchanges are dropped down to half its size at once, which keeps the remaining
prefix unchanged for many turns.
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
license before downloading. With the laptop GPU clocked up, the 0.6B speech
model synthesizes at 0.77 times real time against 0.96 for the 1.7B model,
which leaves headroom for gapless streamed answers. At the GPU's lowest clock
it is more than twice as slow as playback; see the power level under
[Measured latency](#measured-latency).

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
that accept non-interactive key login; the host runs only two fixed read-only
commands on them: a status command on each host, reported as block height
against `zclassicd`, and `z23 core sync blockers` on one configured host, either
when a question names it and asks about its blockers or problems, or when the
chat model asks for that host's report.

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
- The phone screen shows plain sentences only; inspect a running phone node
  over adb instead. `adb forward tcp:28443 tcp:8443`, then
  `curl -sk https://127.0.0.1:28443/api/status` reads the node status;
  `/api/v1/sync/detail`, `/api/v1/peers`, `/api/v1/bootstrap` and
  `/api/v1/syncstate` read sync detail, peers, bootstrap state and sync
  state. The phone node listens on P2P 8033, RPC 18232, HTTPS 8443, file
  service 18034 and Tor SOCKS 19999.
- `org.z23.nativeapp` is not debuggable, so `run-as` refuses it. For the
  preview package, pipe a script: `adb shell 'run-as org.z23.voicepreview sh
  -s' < script.sh`. A `run-as … sh -c '…'` command passed through `adb shell`
  is split again by the device shell, and parts of it run outside the app
  sandbox.
- Never uninstall either package to reinstall it: uninstalling deletes the
  node data directory and the app's pairing state. `adb install -r` keeps
  them, given the same signing key.
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

Those gaps came from chunk lengths: each chunk is synthesized while the audio
before it plays, and a second chunk could hold up to 160 bytes after a first
chunk of at most 32. In the 1.46 s case the second chunk took 4.49 s to
synthesize. Each later chunk is now at most 32 bytes plus a quarter of the text
already spoken, which keeps synthesis ahead of playback up to 0.8 of real time
when the first chunk is full, and a forced split after the first chunk ends at
a word rather than at a short clause. Over 84 recorded answers this gives 5.2
chunks per answer instead of 3.7, with 2.0 chunk boundaries inside a clause
instead of 0.6. Ten recorded answers were replayed through the speech server
with both rules interleaved; over the five synthesized at normal speed under
both, gaps fell from 5.2 s to 1.8 s. In six live answers of 13.4-26.8 s with
the new rule, four had one gap each of 0.24-1.28 s; the GPU clock was not
recorded. Two later answers of 10.5 s and 11.4 s, synthesized with the GPU at
1.4-2.4 GHz, played without a gap.

Synthesis speed depends on the integrated GPU clock. Under the `auto` power
level, seven of eight identical requests ran with the GPU at its lowest clock,
800 MHz, and took 2.2-2.3 times real time; the eighth reached 1.8-2.7 GHz and
took 0.66. Half of the replayed answers ran at 2.2-2.5 times real time and left
gaps of 10-28 s under every rule.

Answer quality was sampled on 2026-10-29 with five questions about a fleet of
three hosts and a stopped phone node, six answers each at temperature 0.6. An
answer failed when it tied the phone node to a fleet host, named a control that
does not exist, stated a requested fact wrongly or skipped the question. With
the phone node labelled apart from the fleet and the question last, 24 of 30
answers passed, against 20 of 30 with the question inside the node data under a
per-question instruction; answers that confused the phone node with the fleet
or named a missing control fell from 10 to 5, and the prompt shrank from
346-349 to 322-325 tokens. Most remaining misses suggest starting the phone
node to fix a fleet host.

The fleet observations carry at most one blocker per host. When the model could
only choose to request a host's full blocker report, it did so for 3 of 18
questions about the blockers of r1, r2 and the Mac, and all 9 answers about r2
across three runs said nothing else was wrong while its report listed four more
blockers. The host now runs `z23 core sync blockers` itself when a question
names a host and asks about its blockers or problems, and adds at most six of
them to the request. Over 15 such answers on 2026-10-29, five for each host,
every r1 answer named both of its blockers and every r2 answer named its four
standing blockers, omitting a transient one the report also showed. The report
took 0.82-0.99 s on r1 and r2; the Mac's node accepted the connection without
answering, so its report ended at the 5-second limit and the answer used its
status line. Over that run and an earlier one, 16 answers about r1 and r2 had a
report: 12 ran while the GPU clock peaked above 2.3 GHz, and 11 of those gave
first audio 4.3-6.1 s after the host received the question, against 3.4-5.6 s
for the three answers without a report that peaked above 2.3 GHz. The twelfth
and the four whose clock stayed at 800 MHz took 12.7-14.6 s. Before the guide
stated that only an operator on the host clears blockers, 2 of 10 answers with
a report suggested a control for a blocker; afterwards none of 16 new questions
did. A question repeated on the phone after that change returned the earlier
answer from the conversation word for word, suggestion included; the host now
leaves an earlier exchange with the same question out of the history it sends.
Two of 10 answers about r2 with a report still said its blockers keep it from
syncing. The two heights of a host come from separate commands, so a host that
reports itself synced can read one block behind its `zclassicd`; such a gap of
up to two blocks now counts as in sync.

`make -C apps/z23android preview-apk` builds a separate
`org.z23.voicepreview` package with debugging enabled for testing, written to
`z23-preview.apk` beside the production APK. That
preview is separate from the production `org.z23.nativeapp` package and its
private state; it does not establish production readiness.

The app uses Android widgets and the system keyboard. Camera scanning, chat,
and fleet operations still require device qualification. Chat and voice
require the paired laptop host. Background operation and
hardware-backed wallet custody are not qualified.

The [isolated shielded transaction experiment](../../docs/experiments/2026-10-28-pixel-shielded-api.md)
describes the existing regtest API demonstration and its evidence. It is not
an app setup or a mainnet payment guide.
