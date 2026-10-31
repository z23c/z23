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

## Sapling proving parameters

A shielded send needs `sapling-spend.params` and `sapling-output.params`. They ship inside the
package as uncompressed assets, so a phone never asks a third party for them and no download
reveals that it holds a wallet. The two files are build inputs kept out of git, like
`vendor/cross`: place them in `vendor/params` (or pass `PARAMS_DIR=<dir>`). `make apk` runs
`check-params` first and refuses to build when a file is missing or does not match the SHA-256
sums in `params.sha256`, which are the sums in
[Getting started](../../docs/node/GETTING_STARTED.md). They add
about 51.6 MB to the package.

A preview build (`make preview-apk`) runs no node and leaves the files out, so it needs neither
the files nor `check-params`. Pass `PREVIEW_PARAMS=1` to pack them into a wallet preview.

State today: the code exists and is tested on a Linux host, but nothing in the app calls it yet and
it has not run on a phone. `params_android.c` opens the packaged files on the caller's thread and
`params_job.c` verifies and copies them on a worker thread to `files/params`: existing files are
read and checked against their pinned SHA-256 first, a copy that differs (also at the same size) is
replaced from the package, and each new file goes to `files/params.tmp`, is flushed, read back and
checked before the directory is renamed into place. After a failed copy no pinned file remains
under `files/params` (the directory stays only if it holds a file this code did not create). A start
that is refused or whose thread cannot start changes nothing: the earlier outcome and files stand.
The result is read by polling `zapp_params_job_state`; no callback runs and the worker
touches no JNI. The node is started with `-paramsdir=<files>/params` when both files are present
at their pinned size; the node checks its own pin when it loads them.

`zapp_prover_allowed` is the refusal before a send, not part of the copy. It passes only when the
copy was verified, the node reports through `zapp_proving_probe` that it can prove, and the
thermal status is below 3 (severe). A copy took 2.0 to 3.4 seconds on the Linux host and has not been timed on a phone; it is not
paused for heat. The
probe has no implementation yet. Two files alone do not arm proving in the node today (see the
experiment record), so a send cannot be enabled until the node loads the Sapling pair on its own.

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

## Home and layouts

The app can be the phone's Home. Its manifest has a second intent filter
(`MAIN`, `HOME`, `DEFAULT`) and `singleTask` launch mode. Choosing Z23 as Home
is the owner's decision in Android's own Home settings; the app never changes
that role. The app hides the system bars (a swipe from the edge shows them
briefly) and the keyboard still works in text fields.

The Home screen shows the phone card (node line and sync status), a Z23 apps section, and tiles for Scan, Assistant and Wallet. The Wallet tile shows no amount: Home does not read the balance, and the balance appears only on the wallet screen, which a later change adds. A fixed bar with **Apps** and
**Settings** sits under the layout on every layout. The Z23
apps section is built from the launcher list: every installed launchable
package whose name starts with `org.z23.`, except the base app
`org.z23.nativeapp` and `org.z23.voicepreview*`, and that is signed with the
same key as this app; any other app stays in the plain app list. Each card opens
the launcher activity it was listed for.
Back from any screen returns Home; Back on Home does nothing. When Z23 is the
Home app, the Home button returns to Home from Apps and Settings (measured on a Pixel 3, Android 15);
on the Assistant it leaves the screen as it is, so use Back there. **Assistant**
opens the voice and fleet screen described below. **Scan** (also under More in
the assistant) shows the camera full screen with **Cancel**; Back also cancels and
shows nothing. A scanned fleet invitation opens the assistant with its review
under More, and a scanned laptop pairing code opens the pairing review there, the
same as an offer over USB. A clip, author or rater address, or other text, is shown
on Home with the notice, selectable, up to 255 bytes (a clip address, 128 hex digits, and an
author or rater address, 64, fit in full; longer text is cut). A code that looks like a pairing
code or an invitation but cannot be read is never shown; Home says so instead. Nothing scanned is opened, followed
or paid without a tap.

Home is drawn from two data documents, so the look changes without an app
release:

- Cards: typed JSON, `zcl.phone_card.v1`, `zcl.z23_app_card.v1` and
  `zcl.app_card.v1`. They carry no token, plan, pairing offer, key or path.
- A layout recipe, `zcl.layout_recipe.v1` (see `docs/spec/short-video-network.md`
  section 5.4), plus an optional `theme` of `background`, `text`, `muted` and
  `accent`, each `#rrggbb`. Containers: `pager_vertical`, `list`, `grid`;
  arrangements `row`, `column`, `stack`; leaves `video`, `image`, `text`,
  `counter`, `action`, `avatar`. A container with `"card": "<kind>"` repeats
  its children once per card of that kind and is omitted when there is none.
  An `action` names only an action id (`scan`, `assistant`, `apps`, `settings`, or
  `launch` with `"field": "label"` inside an app card); a layout cannot name a
  URL or a method. Limits: 64 KiB, 8 levels, 256 nodes. An unknown primitive, a
  bad colour or a document over a limit refuses the whole layout; unknown
  fields are ignored.

Two layouts are built in, `default` (black) and `classic` (light, with the
list of other apps). **Settings** switches between them and remembers the
choice in the app's private files. To use your own layout, put it at
`Android/data/<package>/files/layouts/home.json` (shared storage, for example
with `adb push`); the app re-reads it when it resumes. An invalid file shows a
notice with the reason and the built-in layout. Delete the file to return to a
built-in layout.

The apps list, the **Android home settings** entry and the footer **Apps** and
**Settings** buttons are drawn by app code, not by the layout, so a bad layout
never hides them. To stop using Z23 as Home, open **Settings**, then
**Android home settings**, and choose another Home app.

## Current limits

The Assistant screen shows one line for the node, one for the fleet, **Talk** and
the conversation, newest exchange first. The node line says whether the node
is stopped, starting, waiting for peers, catching up (height of target) or in
sync, with its peer count. The fleet line repeats the paired host's cached
fleet headline, read every 60 seconds without probing the hosts again; while a
laptop host is paired it reads "Fleet · checking" until the first report, so
the screen does not shift under a tap when the report arrives. While a laptop
host is paired and voice is idle, a button under **Talk** offers one question
for the current state: why the node waits for peers, how long it needs to
catch up, which hosts need attention, what is wrong with the first host out of
sync, else how the fleet is. Once a question is answered, the button offers
the next one in that order instead of repeating it, so "Which hosts need
attention?" leads to "What is wrong with r1?", which fetches that host's
blocker report; with nothing new to ask it disappears. A voice status
line stays above it; only the default hint gives way. Tapping it asks it as a
typed question, and it never suggests starting, stopping or joining. When
the conversation buffer fills, whole older exchanges are dropped first.
**More** holds typed questions, the host connection, each fleet host,
synchronization detail, **Stop node** and fleet invitations. Each host
row gives the host's state and height and adds free disk only below 50 GB;
blockers are left to the voice assistant. A host whose node gives no height
reads "node not answering", and one that does not answer the probe reads "host
not answering". A host counts as in sync within two blocks of its `zclassicd`
unless it reports itself not synced. A host whose `zclassicd` height is unknown
cannot be compared, so it is not counted even when it reports itself synced; its
row reads "reports synced but zclassicd height unknown, not counted in sync",
and the headline count and the spoken answer use that one rule. The laptop
tells the model which text describes the fleet hosts and which the phone's own
node, whose buttons (**Start node**, **Stop node**, **Talk**, **More**,
**Confirm**) are never advice for a fleet host, and removes a spoken lead-in
such as "the observation says" or "the host blockers tool returned" before the owner hears it, even when
the lead-in spans two spoken chunks: only the trailing words that may still grow into one wait for
the next chunk. A host label such as r1 keeps its lower case where a lead-in is cut.
The model does not read the screen rows. It gets one verdict line per host from
the same rule as the headline ("in sync", "not in sync: N blocks behind", "not
counted in sync: <reason>") with no heights, so it has no numbers to compare;
a host one block ahead of its `zclassicd` reads "in sync". Command
output reaches the screen only as plain sentences; a JSON error shows its
message alone, and audio failures show one sentence while their cause goes to
logcat. The app runs one read-only node command, the node status, besides starting, stopping and joining a fleet. The wallet balance is read on no surface: Home shows a Wallet tile with no amount, the assistant gets no wallet field, and a balance question, typed or spoken, gets one plain sentence that the wallet is shown only on the wallet screen. The synchronization line adds only what the node line leaves out: the blocks still to go, or that the node has every block its peers report.

Under the fleet list in **More**, **Host** selects one fleet host, **Show errors**
lists its last five `ERROR` log lines from the past 24 hours (`z23 ops logs`, read-only) and
**Restart node** shows what a restart of its `z23-node.service` would do (`z23 ops node restart`
without confirmation; nothing changes). Only then does **Confirm restart** appear; it restarts the
unit with the plan id that step returned. The laptop host maps the phone's request to one of three
fixed commands on a host from its own `--fleet` list, accepts a plan id once, for its host, for 280
seconds, and answers anything else with a refusal. The restart leaf refuses on hosts that are not
Linux. Confirm restart needs a host whose `z23` has `ops node restart`.

**Start node** records the choice in the app's private state, and the app
starts the node each time it opens until **Stop node** clears the choice.
**Stop node** shows while the node runs or while that choice is saved, so a
node that keeps exiting on its own can still be turned off.
Android 15 cuts the network of a hidden app and of the node it started, so
while the Start node choice is saved the app opens the system dialog that lets
Z23 run in the background: once each time the app process starts and after
each new start, by button or confirmed voice request, until the owner allows
it. The node keeps its peers while hidden only with that permission.
Closing or leaving the app does not stop the node. While the node runs, the app keeps a low-importance "Z23 node" notification: it belongs to a foreground
service, the only Java class in the package, which `dexgen.c` writes as `classes.dex` during `make apk`.
Without it Android kills the hidden app and the node with it. Denying the notification permission hides
the notification but keeps the service. While the app is hidden it
stops checking the node and fleet, which keep running; it checks the node again
as soon as it shows, and the fleet once its last report is a minute old.
After **Stop node** the node line reads "Node stopping" until the node has
saved its data and exited. The app finds a node left by an earlier app process
through the node's pid file and its first argument, this `-datadir`: it shows
that node as running, refuses a second start and stops that node on request.
The preview package never runs a node: it has no **Start node** button,
answers a spoken start request without proposing one, and states that it is
separate from the main node. When no current fleet report arrives, the fleet
line says so and **More** labels the last report as old.

Chat refreshes a bounded read-only node summary before asking the private
model on the paired laptop host. The summary includes synchronization text and the node running flag. It excludes the wallet, keys, addresses and raw RPC
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

Thermal pace. `thermal.c` maps the Android thermal status to a node pace with
hysteresis: NONE and LIGHT give normal pace, MODERATE and SEVERE give gentle
pace, and CRITICAL or above pauses the node. A paused node leaves the pause at
MODERATE or below, and returns to normal pace only at LIGHT or below. `zapp_thermal_start`
registers the platform listener through the NDK thermal API. The app registers it when it
starts and keeps it while hidden, because the foreground service keeps the process alive. When the pace
changes the app replaces the one-word file `pace` (`normal`, `gentle` or `pause`) in the node data
directory by writing a temporary file, syncing it and renaming it; the first status after start always
writes, replacing a file left by an earlier run. A missing file means normal. The main status line shows what the node reports, not what the app wrote: it reads
"Syncing gently · phone is warm" when the node status carries pace `gentle` and "Sync paused · phone is
cooling down" for `pause`. A node that does not apply the pace file reports no pace, so the plain node
line stays.

The phone caps the node's block-index cache at 32 MiB (`ZCL_BIP_PAGE_CACHE_KIB=32768`) to lower memory pressure.

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
when a question names it and asks why or about its blockers or problems, or
when the chat model asks for that host's report.

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
Typed questions and the question under **Talk** send the same request to the
private model, with the same fleet tool, and show the answer without speaking
it. **Refresh fleet** probes every
host. “Start node” and “stop node” create proposals that require **Confirm
start** or **Confirm stop** on screen. The assistant cannot run commands,
change hosts or spend funds.

### Developer notes

- Host tests run on Linux with `make -C apps/z23android test HOST_CC=clang
  BUILD_DIR=../../build/android-voice`. `preview-apk` needs `NODE_BIN`,
  `ANDROID_NDK_ROOT`, `SDK_ROOT` and `JAVA_HOME`; without them it stops before
  building and leaves any previous APK in place. The proving parameters are not a
  prerequisite: a preview leaves them out unless `PREVIEW_PARAMS=1` (then
  `vendor/params` or `PARAMS_DIR` must hold them, as for `make apk`).
- A developer sees why the phone node is stuck without root: the app forwards
  the node console log's boot stage changes, `[boot]` timings, warnings,
  errors and failures, Tor bootstrap progress and peer handshakes to logcat,
  at most 20 lines a second. `adb logcat -s z23node` shows them. Lines naming
  keys, seeds or mnemonics are never forwarded.
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

The first spoken chunk of an answer ends at the first clause end (a comma,
semicolon, colon, sentence end, or a dash between words) once it holds 4 words,
or at a word break after 10 words when none has come, instead of at a 32-byte
cap. Speech can start before the first sentence is complete. Later chunks keep
the rule above, and typed answers are not spoken. The change to time to first
audio has not been measured.

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

With a fixed three-host fleet served by a stand-in `ssh`, three answers to
each of five questions on 2026-10-29: the guide that leads with how many hosts
are in sync gave a wrong count in 0 of 6 answers about the whole fleet, against
2 of 6 when it led with how many match `zclassicd`; a question asking why
about a named host fetched its blocker report in 3 of 3 answers, against 0 of 3.
Answers still named a cause the observations do not give in 8 of 9, against 7
of 9, and none of 6 answers about r2 listed the four blockers its report held.
Once host rows said "node not answering" instead of "height unknown" and the
guide said to name an in-sync host's blockers when asked, the same fleet gave a
cause the observations do not give in 4 of 9 answers, all low disk; all 3
answers on why the Mac's height was unknown said its node was not answering,
and 1 of 6 answers about r2 listed its four blockers.

Typed questions once went without the fleet tool and its guide. On the live
fleet on 2026-10-29, with r2 in sync, r1's `zclassicd` height unknown and the
Mac's node not answering at 23 GB free, 20 answers each to "Which hosts need
attention?" from Qwen3.5-4B named both r1 and the Mac in 4 of 20 without the
guide and 19 of 20 with it; one answer with the guide gave low disk as the
reason the Mac's node was not answering.

On the live fleet on 2026-10-29, six fleet questions asked twice before and
after the grounding change, with the phone's text "Start the node to begin
synchronization." in the request as the app sends it: 2 of 12 answers told the
owner to start the node for the Mac, 1 used "the observations show", and 4
contradicted the host rows or themselves (for example two of three hosts in
sync with r2 called not in sync); afterwards 0 of 12 suggested a phone control
for a host, 1 said "the host blockers tool returned", and 2 called r1 out of
sync for a one-block lead the two-block rule counts as in sync. The headline
was not captured per answer, so the last two counts compare answers with the
rule, not with the headline.

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

## Scanning QR codes

The Scan action reads one QR code with the camera and shows what it is without opening, fetching or paying anything. A fleet invitation goes to the join review. A laptop pairing code goes to the same six-digit review as an offer over USB, and the token is never shown. A clip, author or rater address, or any other text, is shown with a sentence saying nothing was done.

On the laptop, `z23-speech-bridge --qr-window PATH` (an absolute path to `z23-qr-window`) also shows the pairing descriptor as a QR code in a window titled `Z23 pairing` with the six-digit code. The descriptor arrives on the window's standard input, never in its arguments. `make qr-window` builds `$(BUILD_DIR)/z23-qr-window` against X11. `make test` builds the same program without X11 and checks its `--dump` output, a binary PBM, against decoded payloads.
