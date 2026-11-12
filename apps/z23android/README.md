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

For updates, set `KEYSTORE` to the securely preserved key outside the build
directory and set `EXPECTED_SIGNER_SHA256` to the existing app signing
certificate's 64 hexadecimal SHA-256 digits. The build refuses a missing key
and rejects an APK whose signer differs. An unset expected digest permits a
new disposable development key; it cannot update an app signed by another key.

## Sapling proving parameters

A shielded send needs `sapling-spend.params` and `sapling-output.params`. They ship inside the
package as uncompressed assets, so a phone never asks a third party for them and no download
reveals that it holds a wallet. The two files are build inputs kept out of git, like
`vendor/cross`: place them in `vendor/params` (or pass `PARAMS_DIR=<dir>`). `make apk` runs
`check-params` first and refuses to build when a file is missing or does not match the SHA-256
sums in `params.sha256`, which are the sums in
[Getting started](../../docs/node/GETTING_STARTED.md). They add
about 51.6 MB to the package.

A preview build (`make preview-apk`) runs no node and by default leaves the files out, so it needs neither
the files nor `check-params`. It does not start a missing-parameter copy or poll for node status at launch. Pass `PREVIEW_PARAMS=1`
to pack them for intentional parameter-copy testing in a preview; that variant retains the startup copy.
<!-- claim: symbol-present Z23_PREVIEW_PARAMS apps/z23android/CMakeLists.txt # packaged preview build flag -->
<!-- claim: symbol-present observe_node apps/z23android/controller.c # preview does not poll node status -->

State today: the node app starts the copy at launch (`zapp_params_launch`, once per process unless the
last attempt failed) and tests cover it on a Linux host; it has not run on a phone. `params_android.c` opens the packaged files on the caller's thread and
`params_job.c` verifies and copies them on a worker thread to `files/params`: existing files are
read and checked against their pinned SHA-256 first, a copy that differs (also at the same size) is
replaced from the package, and each new file goes to `files/params.tmp`, is flushed, read back and
checked before the directory is renamed into place. After a failed copy no pinned file remains
under `files/params` (the directory stays only if it holds a file this code did not create). A start
that is refused or whose thread cannot start changes nothing: the earlier outcome and files stand.
The result is read by polling `zapp_params_job_state`; no callback runs and the worker
touches no JNI. The node is always started with `-paramsdir=<files>/params`: it looks for the files at its first
proof, so a start before the copy ends needs no restart. The node checks its own pin when it loads them.

`zapp_prover_allowed` is the refusal before a send, not part of the copy. It passes only when the
copy was verified, the node reports through `zapp_proving_probe` that it can prove, and the
thermal status is below 3 (severe). A copy took 2.0 to 3.4 seconds on the Linux host and has not been timed on a phone; it is not
paused for heat. The probe is one `getwalletinfo` call (`zapp_proving_over_rpc`), and
`zapp_controller_prover_ready` reports the copy state and the probe in one plain sentence. The Send
screen calls it on a worker thread every tick while a review is open and every 15 seconds after a yes; the
review shows no Send button, and that sentence, until it says ready.

A payment goes on in the background. When the owner confirms with the screen lock and the commit starts, the shell
returns to the wallet screen at once. The flow stays in the app process (the foreground node service keeps it
alive) and `zapp_send_progress` gives the one line the wallet screen draws: "Sending X ZCL to <8>…<6>: building the
payment (about 2 min)", then "…: waiting to leave the phone", then "Sent X ZCL", or "Payment not sent: <cause>.
Your coins were not spent." when the node says nothing was sent, or "Payment status unknown: it may have been sent.
Check History before paying again." when it gave no usable answer. When the payment leaves the phone or fails, one
notification is posted on the "Payments" channel ("Payment sent", "Payment not sent" or "Payment status
unknown"); it is VISIBILITY_PRIVATE and its public version on the lock screen reads only "Z23 payment update", with no
amount or address anywhere. `zapp_send_progress_dismiss` clears a finished line.

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

### One-time state installation

A private one-time complete-state install request uses `node/install-bundle.request`
containing `install` followed by a newline and `node/install-bundle.sqlite`. Both
must be owner-private regular files. Start consumes the request before launching
installation. The retained `node/install-bundle.consumed` prevents another
launch; it does not attest that installation succeeded. An interrupted or
refused install can require recovery on the next normal start.

## Home and layouts

The app can be the phone's Home. Its manifest has a second intent filter
(`MAIN`, `HOME`, `DEFAULT`) and `singleTask` launch mode. Choosing Z23 as Home
is the owner's decision in Android's own Home settings; the app never changes
that role. The app hides the system bars (a swipe from the edge shows them
briefly) and the keyboard still works in text fields. A screen with a text field
(the assistant, the wallet, Send and setup) ends above the keyboard while it is
open, so the focused field scrolls into view. A tap reaches a button only where
that button is on screen (`view_hit.c`, tested by `tests/view_hit_test.c`): a
button scrolled out of its page never takes a tap meant for the fixed bar over it.

The Home screen shows the phone card (one plain status line: Node stopped, Stopping…, Starting your node… until a height has been seen, then Your node is running but has not replied yet, Catching up with the blocks to go, Can't confirm it's up to date with the reason (only 1 peer, no peers, peer count unknown, no new block for N min), No peer has reported a block height yet, Block N, waiting for other computers when the node has a height but no peer reference, or Checking the chain when its height is unknown, or Up to date; and a Start node or Stop node button, hidden while the node stops). The status line always takes two lines and the button keeps its place while hidden (the layout field `"lines"`), so the tiles below never move when the status wraps or the node stops. The Wallet, Receive, Scan and Assistant tiles come next, followed by installed Z23 apps. Receive opens the existing Receive page directly, including Copy address and Share request, without opening Funds first.
<!-- claim: symbol-present go_page apps/z23android/shell.c # Home Receive opens the existing Receive page directly -->
Back from the Home shortcut returns Home, including after a share round trip; Back from Receive opened inside the wallet still returns to Funds.
<!-- claim: symbol-present receive_from_home apps/z23android/shell.c # Home Receive Back returns Home without changing the wallet Receive Back destination -->
The Wallet tile shows no amount: Home does not read the balance, and the balance appears only on the wallet screens, which the Wallet tile opens. A fixed bar with **Apps** and
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
the assistant) shows the camera full screen with the line "Point your camera at a QR code." and **Cancel**; Back also cancels and
shows nothing. When camera access is off for good, the scan screen shows **Open settings** and **Paste instead** in place of the camera; no permission dialog is shown and nothing waits. A scanned fleet invitation opens the assistant with its review
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
  A signed Z23 app card and the base app's plain card also carry `version_name`
  when nonempty and `version_code` when PackageManager reports it. This is install
  metadata, not source identity or proof that an update activated.
  <!-- claim: symbol-present zapp_home_app_card apps/z23android/home.c # version metadata on signed Z23 and base-app cards -->
- A layout recipe, `zcl.layout_recipe.v1` (see `docs/spec/short-video-network.md`
  section 5.4), plus an optional `theme` of `background`, `text`, `muted` and
  `accent`, each `#rrggbb`. Containers: `pager_vertical`, `list`, `grid`;
  arrangements `row`, `column`, `stack`; leaves `video`, `image`, `text`,
  `counter`, `action`, `avatar`. A container with `"card": "<kind>"` repeats
  its children once per card of that kind and is omitted when there is none.
  An `action` names only an action id (`wallet`, `receive`, `scan`, `assistant`, `apps`, `settings`, or
  `launch` with `"field": "label"` inside an app card); a layout cannot name a
  URL or a method. A `text` or `action` may name `"lines"` (0 to 20): it is
  then exactly that many lines tall and keeps its place while its text is
  empty; `"max_lines"` only cuts a longer text, and an empty one takes no
  space. Limits: 64 KiB, 8 levels, 256 nodes. An unknown primitive, a
  bad colour or a document over a limit refuses the whole layout; unknown
  fields are ignored.

Two layouts are built in, `default` (black) and `classic` (light, with the
list of other apps). **Settings** switches between them and remembers the
choice in the app's private files. To use your own layout, put it at
`Android/data/<package>/files/layouts/home.json` (shared storage, for example
with `adb push`); the app re-reads it when it resumes. The folder lives in the app-specific external storage, which other apps cannot read; shared storage ignores file modes, so the protection is that location, `O_NOFOLLOW`, regular files only and a 64 KiB cap, not a mode. A link is not followed. An invalid file shows a
notice with the reason and the built-in layout. Delete the file to return to a
built-in layout.

The apps list, the **Android home settings** entry and the footer **Apps** and
**Settings** buttons are drawn by app code, not by the layout, so a bad layout
never hides them. The Apps screen uses text labels only and does not load or draw
installed-app icons; camera previews, QR codes and other functional media are unaffected.
The current base app's launcher entry appears first with its installed version.
It is retained even when other apps fill the 256-entry limit first. Signed Z23
rows also show the installed `versionName` and `versionCode` from PackageManager,
or the numeric code alone when the name is empty. Version metadata helps check an
APK update or rollback, but does not establish in-process hot swapping.
<!-- claim: symbol-present zapp_home_app_slot apps/z23android/home.c # retain the base app when the launcher list reaches capacity -->
<!-- claim: symbol-present zapp_home_app_compare apps/z23android/home.c # the current base app appears first with its installed version -->
<!-- claim: symbol-present add_app_row apps/z23android/shell.c # text-only installed-app rows -->
<!-- claim: symbol-present zapp_home_version_line apps/z23android/home.c # Apps shows installed version metadata -->
To stop using Z23 as Home, open **Settings**, then
**Android home settings**, and choose another Home app.

## Current limits

The Assistant screen shows one line for the node, one for the fleet, **Talk** and
the conversation, newest exchange first. The node line says whether the node
is stopped, starting, waiting for peers, behind (height of target) or in sync,
with its peer count. It says "in sync" only within two blocks of the highest
height the node has heard of from a peer or the paired fleet, and only with
proof the chain is live: two or more peers, or a fleet height that agrees. With
fewer peers, or a tip that has not moved for more than 15 minutes (about six
block times), it reads "Height N · only 1 peer, cannot confirm it is current"
instead. One rule in `hosts.c` decides the node line and the sentence under
More. The fleet line repeats the paired host's cached
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
logcat. Outside the wallet screens the app runs one read-only node command, `core status`, besides starting, stopping and joining a fleet. The wallet screens run five more, all through the command line, and a payment runs `core wallet security unlock`, `core wallet shielded send` (plan, then commit) and `core wallet security lock` on the owner's tap: `core wallet summary`, `core wallet fleet status`, `core wallet shielded latest`, `core wallet history` (a page, or one transaction with `--txid`) and, on a New address tap only, `core wallet shielded receive`. Every command has a limit (15 seconds for a read; a payment step and a wallet setup step get their own, longer limits): a command that has not answered by then, even one still between fork and exec that never reached the node program, is killed by its own process id and then by the process group it made, reaped, and logged with its command words and its pid, and its caller gets a failure. The wallet balance is shown only on the wallet screens: Home shows a Wallet tile with no amount, the assistant gets no wallet field, and a balance question, typed or spoken, gets one plain sentence that the wallet is shown only on the wallet screens. The synchronization line adds only what the node line leaves out: the blocks still to go, or that the node has every block its peers report. The first time a node starts and the app is not yet exempt from battery optimization, it shows one line saying why and then the system dialog; it asks once and records that the dialog was started in the file `battery_prompt_asked` in its private files, so a Deny is not asked again.

A fleet height counts as evidence only while the report is no more than 180
seconds old (its `observed_at`).

The phone node always runs in private mode: it starts with `-onlynet=onion
-bind=127.0.0.1`, so it dials only Tor onion peers, resolves no DNS seed, and
never falls back to clearnet. Its dial targets are the built-in onion seeds of
the chain parameters, the onion directory those seeds publish, and
the fleet onion peers (`-addnode=<56 characters>.onion:<port>`) that the paired
laptop host names in an `onion` field of its fleet report. The app keeps those
in `fleet-onion-peers` beside the node data and passes only entries that pass
a strict `.onion:port` check. With fewer than two onion peers the node line
reads "Private · waiting for onion peers (1 of 2)".

Under the fleet list in **More**, **Host** selects one fleet host, **Show errors**
lists its last five `ERROR` log lines from the past 24 hours (`z23 ops logs`, read-only), and **Plugins**
runs the fixed read-only `z23 plugin list` command on that host. It shows up to eight plugin names,
current and last-good generation prefixes and slot health. Each plugin also shows up to two other
stored generation prefixes and a count of any others; omitted plugins are counted too. **Copy IDs**
copies the full current and last-good IDs of the plugins shown, not the additional saved generations,
through the same sensitive clipboard and best-effort clearing after a minute used by Copy address. An oversize
reply is refused rather than truncated. This is an inventory scan, not a fresh signature
verification; it does not fetch, install, switch or load
plugin code. The isolated voice preview also offers **Host** and **Plugins**, but not **Show errors**
or the restart controls. The Assistant reserves three lines for live status so a fleet report does not
move **More**, and **Plugins** stays visible while its read runs.
<!-- claim: symbol-present plugins_text apps/z23android/bridge/host_ops.c # bounded read-only plugin inventory -->
<!-- claim: symbol-present copy_plugin_ids apps/z23android/android_main.c # Copy IDs uses the protected clipboard without changing plugin state -->
<!-- claim: symbol-present node_widgets apps/z23android/native_ui.c # reserved status lines keep More in place -->
<!-- claim: symbol-present render_ops apps/z23android/native_ui.c # Plugins remains visible during its read -->
**Restart node** shows what a restart of its `z23-node.service` would do (`z23 ops node restart`
without confirmation; nothing changes). Only then does **Confirm restart** appear; it restarts the
unit with the plan id that step returned. The laptop host maps the phone's request to one of four
fixed commands on a host from its own `--fleet` list, accepts a plan id once, for its host, for 280
seconds, and answers anything else with a refusal. The restart leaf refuses on hosts that are not
Linux. Confirm restart needs a host whose `z23` has `ops node restart`.

**Start node** records the choice in the app's private state, and the app
starts the node each time it opens until **Stop node** clears the choice.
**Stop node** shows while the node runs or while that choice is saved, so a
node that keeps exiting on its own can still be turned off.
A tap shows at once what it does: Start node and Stop node put "Starting your
node…" or "Stopping your node…" in the notice bar until the node line shows the
result, or the reason when the node did not start or stop, and the fleet and
pairing taps say the same beside their controls. That line beside the controls is
cleared when the owner closes More or leaves the assistant, and a scan outcome
shown on Home, the wallet or Send does not stay there, so an old failure is never
shown as current; the keyboard's action key in the invitation field reviews the
invitation. A tap the app does not take
says why in that bar (another action still running, the app still opening,
nothing waiting to be confirmed), never a bare refusal. The owner's actions run
on one thread and the node status is read on another, so a status read that
waits for its command limit never holds back a tap.
Android 15 cuts the network of a hidden app and of the node it started, so
while the Start node choice is saved the app opens the system dialog that lets
Z23 run in the background: once each time the app process starts and after
each new start, by button or confirmed voice request, until the owner allows
it. The node keeps its peers while hidden only with that permission.
Closing or leaving the app does not stop the node. While the node runs, the app keeps a low-importance "Z23 node" notification: it belongs to a foreground
service, one of the three Java classes in the package (the others are the `KeyPrompt` callback of the wallet key prompt and editor actions, and the internal `ShareActivity`, which call native code); `dexgen.c` writes all three as `classes.dex` during `make apk`.
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
line stays. When gentle pace is catching up, Home shows blocks left and says it is keeping the phone cool.

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

On start the host prints a six-character pairing code and opens the app
with a pairing offer. Accept on the phone only if it shows the same code. Each
offer starts a new pairing with a fresh secret; the secret of the earlier pairing
stops working on the host at once and on the phone when the new one is stored.
The host keeps its port and the current secret in `--dir/pairing-secret`; without `--adb` a
restart reconnects, and with `--adb` every start makes a new offer. A `host-token` left by the
earlier protocol travelled in the clear: the host removes it at start and never uses it. To
pair by hand with a new secret, stop the host, delete `--dir/pairing-secret` and start it.
The secret reaches `adb` on standard input, not in laptop
process arguments; on the phone it is briefly visible to shell and root in the
arguments of the `am` command. The app stores it privately as `speech-bridge.json`.
The app reads the offer only when the adb shell, root or the app itself launched it (`Activity.getLaunchedFromUid`); an offer sent by another app, or from a launch whose uid cannot be read, is dropped with one log line (tag `z23`, no offer content), and scanning the laptop QR code still pairs.

For camera-free pairing of an isolated preview, add `--pair-file` to the
`z23-speech-bridge` command. The host writes `pairing.json` into the preview's
app-specific external files directory through `adb` standard input, then relaunches
the preview. The next launch reads and removes that file and shows the same six-digit
review. The `am` command carries no descriptor or token, and no camera or launch UID is
needed. Other apps cannot read that app-specific external directory on Android 15.
Do not use this restart mode on a production node; use the ordinary host offer or QR
pairing there. The default pairing behavior is unchanged.
<!-- claim: symbol-present usb_pairing apps/z23android/android_main.c # one-time camera-free USB pairing import -->
<!-- claim: symbol-present zapp_host_offer_pairing apps/z23android/bridge/host.c # pair-file keeps the descriptor on adb standard input -->

### Bridge authentication

The phone reaches the host on loopback port 8770, where another app on the phone
can also listen. The pairing secret is never sent. Protocol 2 (`bridge_auth.c`)
authenticates both sides with HMAC-SHA3-256 keyed by the secret:

1. The host sends a fresh random nonce NS.
2. The phone answers with its own fresh nonce NC and nothing else.
3. The host proves the secret with a tag over NS and NC. The phone checks it
   first; a server that fails receives no request and no secret.
4. The phone sends the request with a tag over NS, NC and the request digest.
5. Every host line (events and the final reply) carries a tag over NS, NC, the
   request digest and its index, and the phone parses nothing it has not
   verified. A reply cannot be replayed to another connection or request.

The descriptor is `{"v":2,"port":N,"token":"<64 hex>"}`. A phone with an older
pairing, or an older host, is refused with a message telling the owner to pair
again; there is no fallback to the earlier scheme. The channel is not encrypted:
a program that can reach the real host and relays between it and the phone can read the
traffic, but it cannot alter, replay or forge it.

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
  BUILD_DIR=../../build/android-voice`. `preview-apk` omits the node binary and
  needs `ANDROID_NDK_ROOT`, `SDK_ROOT` and `JAVA_HOME`; without them it stops before
  building and leaves any previous APK in place. The proving parameters are not a
  prerequisite: a preview leaves them out unless `PREVIEW_PARAMS=1` (then
  `vendor/params` or `PARAMS_DIR` must hold them, as for `make apk`).
- A developer sees why the phone node is stuck without root: the app forwards
  the node console log's boot stage changes, `[boot]` timings, Tor bootstrap
  progress and peer handshakes to logcat as written, at most 20 lines a second.
  A warning, error or failure that is not one of those is forwarded as its level,
  its `[domain]` and its function name only (`ERROR [native.wallet] wnh_send()`),
  never its text, which can carry an address, a transaction id or an amount.
  `adb logcat -s z23node` shows them. Lines naming keys, seeds or mnemonics are
  never forwarded. Completed shutdown stages also emit an allowlisted stage name
  and decimal duration, without the source message or other fields.
- The host defaults to `--app org.z23.nativeapp`. Pass `--app` with the exact
  preview package or the pairing offer reopens the production app. `PREVIEW_APP_ID`
  defaults to `org.z23.voicepreview`; `PREVIEW_APP_ID=org.z23.voicepreview.<feature>`
  builds a separate feature preview without uninstalling another preview.
  Suffixes contain lowercase letters, digits and underscores.
  <!-- claim: symbol-present PREVIEW_APP_ID apps/z23android/Makefile # isolated feature preview package identity -->
- The phone screen shows plain sentences only; inspect a running phone node
  over adb instead. The app starts the node with `-private-listeners`, so it
  binds loopback only: P2P 127.0.0.1:8033 (the onion service forwards to it),
  RPC 127.0.0.1:18232 and Tor SOCKS 127.0.0.1:19999. The HTTPS explorer and its
  HTTP redirect (8443, 8080), the file service (18034), ROM seeding, the NAT
  probe, the beta6 side listener and the RPC TLS listener do not start, so nothing on the Wi-Fi reaches
  the phone and the HTTP status routes (`/api/status`, `/api/v1/peers`, ...)
  are not served there. The onion answers 404 for `/observation.json` (`-observation=0`), so a stranger
  cannot fingerprint the phone. `adb logcat -s z23node` shows the node log; the app's
  own commands use the loopback RPC with the credentials in its private data
  directory. The node also starts with `-walletbackup=0`: it keeps no hourly cleartext copies of the wallet's
  transaction and note tables under its home, because on the phone the recovery words are the backup if the key is lost.
- The node and every command the app runs get `XDG_STATE_HOME=<files>/state`
  (and `HOME` set to the same directory when the app process has none) and
  `TMPDIR=<files>/tmp`, where `<files>` is the app files directory with its
  links resolved. Android names that directory through `/data/user/0`, a link
  the system keeps to `/data/data`, and the node refuses a state root with a
  link among its parents, so under that name `fleet join` could not record
  the fleet root in `z23/dev/fleet/operator.pub` and the node could not read
  it. The node data directory keeps the name Android gives.
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
private state; it contains no node binary and does not establish production readiness.

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

## Sending

A scanned payment code opens a review; nothing is sent from a scan. `wallet_send.c` is the send flow as a pure state machine: events in, typed actions out. `wallet_send_screen.c` carries the actions out on a worker thread through typed node, device key and host interfaces, and turns the machine into the review lines and progress the renderer draws.

- Sending needs a tap on the review of the exact plan. The tap starts one operation that authenticates the owner for that use, unwraps the wallet secret and unlocks the wallet; the Keystore key needs a credential or strong biometric for every use, so no earlier authentication counts and the app remembers none. Any change to the amount, address or memo makes a new review, a new plan and a new idempotency key (the key a request derives, see One key per request).
- The key is made before the plan is requested, because the node binds it into the plan token.
- The commit carries the fee of the plan the owner tapped; the node refuses a commit without it.
- The key accepts the device PIN, pattern or password as well as a strong biometric (`AUTH_BIOMETRIC_STRONG | AUTH_DEVICE_CREDENTIAL`), so anyone who knows the device PIN can approve a payment. The payment prompt reads "Authorise this payment" and the unlock prompt "Unlock this wallet", and a payment never opens under the unlock prompt. An unwrap reads the stored key's policy before it shows a prompt and opens the blob only for a hardware key that requires authentication with no validity window; any other key reports `not_hardware` or `not_per_use`. The manifest declares `USE_BIOMETRIC`, without which `BiometricPrompt.authenticate` throws and every key use fails closed with `error`.
- An unknown commit is final. Only the node error code `SEND_REFUSED_KEY_RELEASED` (the key was released) proves that nothing was sent and allows Retry on the same review and key, with a new tap and a new authentication. `FEE_CHANGED` returns to a new review with a new key. Every other answer, `WALLET_RPC_ERROR` and a missing answer included, is the unknown result: the flow ends, offers no retry and points to History. The mapping is pinned in `wallet_send_screen.h` and tested.
- Device key statuses are mapped by `wss_key_status_of_devkey`: a lost or unusable key (`invalidated`, `not_found`, `corrupt`, `old_format`, `not_hardware`, `not_per_use`) says to restore from the recovery phrase and offers no retry; `declined` and `no_screen_lock` offer Retry.
- While the wallet may be open the screen cannot be left or destroyed: `wss_end` and `wss_destroy` return false until the lock is confirmed, and ticks keep asking for it. Polls, gate reads and locks are coalesced in the worker queue so a blocked node call cannot starve a lock. When no worker thread can be started the flow fails before any commit; nothing runs on the UI thread.
- A running commit is never failed by a timer. The screen stays on "Building the payment" until the node answers and the wallet is locked right after the answer. The unlock lasts at most 300 seconds, long enough for a phone proof of about 101 seconds.
- No tap is accepted while a lock is owed, so a late lock answer can never close the unlock of a newer send.
- A second scan does not open while a send is in progress. The commit carries the plan that was tapped, only while its ticket is current; actions of an ended flow are dropped.
- The memo is shown as data in its own labelled field. Control characters, line breaks and bidirectional marks are written out as `<U+XXXX>`, so a memo cannot imitate a review line.
- A scanned text with a payment scheme or the shape of an address that the parser refuses is shown as a refusal and never as plain text, even with control bytes around it.
- The wallet is unlocked only inside the send and locked on every way out. The passphrase goes to `core wallet security unlock` on standard input and is cleansed on every path.
- The screen is protected with `FLAG_SECURE` and obscured-touch filtering before anything is shown, and shows nothing if either is refused. Send must be drawn as an Android View, because touches are read natively and obscured-touch filtering works only on Views.
- Neither module logs. `make test-wallet-send` runs the directed tests, 100000 or more random event sequences against a model of the rules (commit only after tap and authentication on the same plan, no key committed twice unless refused, no unlock while a lock is owed), the screen over fakes including a real worker thread, and a check that the sources call no logging function.
- Ticks are required while a lock is owed. After a failed lock the screen may be left, but `wss_end` stays false and only `wss_on_tick` asks for the lock again, so whichever code shows Home (the shell does, through `zapp_send_ui_tick`) keeps calling `wss_on_tick` until `wss_end` returns true; otherwise the wallet stays open until the node timer.

### Send wiring

The Send screen (`wallet_send_ui.c`, Android Views, built only by the NDK build) is wired to the app as follows.

- **Scan to Send.** The controller classifies a scanned code and holds a payment code in the one-slot `pay_stash.c`, which only the shell may empty (`make test-wallet-send` checks that no Home file takes from it). Home sees only the kind. A payment code from Home, from Send, or refused by the parser opens Send. Funds **Send** opens Send, which offers **Scan code**, the address field with its keyboard open, **Paste address** when the clipboard holds an address or payment code that the scan parser accepts (`wss_paste_offered`), **Use this address** and **Back**; the camera starts only from **Scan code**. The clipboard is read when Send opens and when the window regains focus, once for each new clip whether or not it holds text that fits (`wss_clip_check`; its description's timestamp tells clips apart), so the system notice that an app read the clipboard comes once per clip; **Paste address** reads it again at the tap and opens what it holds now. When the balance is known to be 0, Send shows "You have 0 ZCL to send. Receive some first." with **Receive** and **Back**, and no address or amount steps: from Funds at once (`wallet_screens_spendable`, a reading of at most 30 seconds with the private amounts shown), otherwise once the node's summary answers. While that page is shown the balance is read again every 15 seconds, so the line stays. A locked wallet's hidden balance is unknown, never 0. A refused or unusable scan, or a refused camera, stays on Send with its reason, **Scan again** and the address field; the typed address goes through the same parser as a scan, and what was typed stays in the field when the page is redrawn. An address named without an amount opens the amount page: To and the address, "Available: <spendable> ZCL", **Max**, the amount field with its keyboard open, **Set amount** and **Cancel**. The balance is read when the page opens and again 15 seconds after the last reading, whether or not that reading gave a balance, so a hidden balance is not asked for on every tick; a reading older than 30 seconds is not shown. **Max** asks the node for a plan of the whole spendable balance under a throwaway key, which is never committed, and sets the amount to that balance less the fee the plan quotes (`wss_max_amount`), so the new amount gets its own plan, review and tap; when the fee takes it all or the node gives no plan, the page says so and sets nothing. On a review, **Max** sets the amount to the reviewed spendable balance less that review's fee. The keyboard opens once each time a page with a field comes up (`wss_keyboard_due`) and is put away when the next page has none. The keyboard's action key presses the button of its field: **Use this address** from the address field, **Set amount** (or **Change amount**) from the amount field; a set amount puts the keyboard away. Nothing drops to Home. Camera access that is off for good opens the scan screen with **Open settings** and **Paste instead** in place of the camera; **Paste instead** returns to Send.
- **Node steps.** `wallet_send_node.c` builds each request as JSON on the node's standard input (`core wallet security unlock`, `core wallet shielded send` for the plan and for the commit) and reads each reply by exact shape. The summary and fleet reads and `core wallet shielded latest` use the existing wallet commands; the address check is the node's `validateaddress` over loopback, and an address is accepted only when the reply says `isvalid` true. Node message text never reaches the screen: errors are typed codes and the screen shows its own wording. Plan and commit send the same `wallet_scope`, sender, recipient, amount text (`1.25000000`), memo and idempotency key, so the plan token the node binds matches.
- **`wallet_scope`.** Mainnet is `prod`; testnet and regtest are `test`. The node's send handler only requires one of `dev`, `prod` or `test` (`wallet_money_scope_valid`); `wallet_money_scope_for_lane` maps the operator lane to `test`.
- **Gate.** Send is refused when the summary says the wallet is not encrypted, when the summary refuses sending, or when `core wallet fleet status` reports `refuses_send` true, is missing, or is not exactly the documented shape. A node that is not in a fleet allows Send, and the review says "Not checked by your fleet". A refusal names its cause from the verdict: `disagree` says the fleet disagrees with this node about the latest block, and `unchecked`, which the node reports when it cannot read the fleet root its join recorded, says the fleet has not been checked yet and that sending waits until the node can read it.
- **Commit.** The commit is asked for once and given at least 300 seconds (`ZAPP_WALLET_COMMIT_MIN_MS`); the command layer's 15 second limit applies to reads only. A killed or silent commit is the unknown result: no retry button and no second commit. After a commit the screen never says "Sent": it says the node has the payment and that History shows when it leaves the phone. There is no node command that reports the private route, so the route poll reports nothing and the flow ends at that sentence with **Done**.
- **Device key.** `wallet_send_device.c` opens the wallet secret under `ZAPP_DEVKEY_PURPOSE_PAYMENT` on a worker attached to the JVM, once per payment, never on the UI thread. The sealed blob is `wallet_key.blob` in the app's private files, and the passphrase for `core wallet security unlock` is the hex of the 32-byte secret. Wallet setup writes that blob (see Wallet setup); a phone without it fails a payment with the lost-key sentence before any commit.
- **Leaving.** The Send screen cannot be left while a payment is being built or the wallet may be open. A pause or stop during authentication does not cancel and does not navigate: the system credential screen pauses the app, and the prompt's result completes the payment; only the Cancel button ends an authentication. Once the commit has started, leaving locks the wallet when the node answers and never cancels or repeats the commit.
- **Re-creation.** The manifest handles every configuration change itself (`uiMode`, `screenLayout`, `smallestScreenSize`, `density`, `keyboard`, `navigation` and the rest), so a theme or window change does not recreate the activity. When the system does destroy it anyway, `wallet_send_keeper.c` retires a flow that is authenticating, committing or holds an outcome the owner has not closed with Done; the next activity adopts that flow, shows its progress or outcome, and refuses a second payment beside it (the same code scanned again starts nothing). Each flow owns its node and device-key adapters, released when its screen is freed, so a worker that outlives the activity never uses reset state. The controller's detach does not stop the node, so a commit in flight when the activity is destroyed keeps running; its result is what the adopted flow shows. A flow that is only in review is dropped.
- **One key per request.** The idempotency key is derived, not random: the first 16 bytes of SHA3-256 over `z23-pay-v1`, the wallet id, the address, the amount in zatoshi and the memo (`send_key.c`), written as 32 lowercase hex characters. The wallet id is 32 random bytes made once in `<files>/wallet_id` (mode 0600, written through a temporary file and renamed into place without replacing; a file of another size is never replaced, and the send fails closed). Scanning the same code again, after Back, a re-created activity, a restart or a reinstall that keeps the files, reaches the node with the same key, so its send-once table answers while it holds the record (the node deletes a committed record 90 days after its creation and an unresolved one after 365 days, by its own clock, and it replays a committed payment only while its wallet still holds the transaction; after that, or after its clock jumps forward past those limits, the same code is a new payment, and it is still sent only after a full review and a new authentication): a replay of a committed payment shows **Already paid** with the transaction id and the time the phone received the node's committed answer ("Your node confirmed this payment: Today 10:00", in the phone's time zone; the node's reply carries no time of its own). A rescan answered from the screen's memory shows that stored time, never the current time; an unknown or in-progress answer shows the unknown wording ("It is not known whether this payment was sent... Check History"), with no retry. While the screen lives it also remembers the last outcome of the request and shows it at once, without a plan, an authentication or a commit. **Pay again** is drawn only on Already paid. It starts a full review and a new authentication under a new random key, and it is never offered while an earlier attempt is unknown or held. A changed fee re-plans the same request under the same derived key. A different amount, memo or address is a different request with a different key.
- **Payment stash.** The stash is emptied when a scan begins, when the payment is taken, on Back during decoding (also when the dismissed scan finishes) and on destroy.
- **Known limit.** The sender is the wallet's latest shielded address (`core wallet shielded latest`), which spends account-wide together with the receive lane.
- Tests: `wallet_send_node_test.c` (reply shapes, commit code table, gate, full flows over a fake runner), `wallet_send_device_test.c` (every device key status, payment purpose, the unlock purpose for Show private balance, one prompt per payment), `wallet_reveal_test.c` (Show private balance over a fake device key, node and host: the window, cancelled and refused prompts, an unconfirmed unlock, leaving, and no lock under a payment in flight), `pay_stash_test.c`, the send runner cases in `wallet_run_test.c`, and `test_native_api_contract.c` in the harness (plan then commit of 1.25 through the real handler).

## Wallet setup

A phone opens Home on a cold launch. In the default and classic layouts, Wallet, Receive, Scan and Assistant precede the phone node card; the card still shows node status, synchronization and the node control. An active setup left open resumes after Activity recreation; the Wallet and Receive tiles open setup until it is finished. The screen offers exactly two choices: **Create a new wallet** and **Restore from words**. The app's node never makes a wallet on its own: the app removes `ZCL_WALLET_PASSPHRASE`, `ZCL_ALLOW_PLAINTEXT_WALLET`, `ZCL_RECOVERY_PHRASE` and `ZCL_WALLET_NO_PHRASE_BACKUP` from the environment of every process it starts, and starts the node with no wallet argument, so a node without a wallet runs without keys (no spending) until setup ends.

- **Create.** The phone wraps a new wallet passphrase with per-use hardware authentication, then pauses the node before preparing recovery words. The native prepare command durably records the public wallet identity and a fixed scan floor before the words are shown. The node stays paused while creation is pending. The app sends the words, passphrase and public creation nonce over standard input to commit; no words or passphrase are written by the app. After the matching commit and word confirmation, it restarts the node only if the owner still wants it on. If setup is interrupted, the owner can enter the saved words and authenticate the existing key to resume the same pending creation. An unknown or mismatched status keeps the key and does not claim completion.

- **Backup.** The words appear once, next to the start height the node recorded, on a window with `FLAG_SECURE`, the recents thumbnail off, overlays hidden, the accessibility readout of sensitive data off and obscured touches dropped; the screen draws nothing when any protection is refused. The text is not selectable. The words leave the view tree when the app goes to the background. The app asks for three words at random positions and, once the check is on screen, shows, for each, four words to tap: the right one in a random slot and three different decoys from the BIP39 list (`setup_wordlist.c`, compared with the wallet's own list by `make test-setup`); a wrong tap is counted and offers new decoys for that position; `wallet_setup_done` is written, off the UI thread, only when they match and the reply carried a start height; a mismatch keeps the owner on the check with **Show the words again**. The app holds the words in memory until then and never writes them.
- **Restore.** The owner types the words and, optionally, the block height where the wallet began. With a height the app asks the running node for that block's hash and passes the pair as the birthday; without one, or when the node does not answer, the wallet reads the whole chain. Before anything else the app checks each word against the BIP39 English list and the phrase checksum on the phone; a word off the list or a checksum that does not match keeps the owner on the form with the typed words and names the word by its position, never the word itself, with no screen-lock prompt and no node stop. The node is then stopped, `core wallet recovery restore --input=-` runs with `confirm`, `shielded_only` and the same wrapped passphrase, and the node starts again. The screen then reports "Read through block S of T" from `core wallet summary` and says when no starting block was used.
- **Failure.** A prepare or commit that gives no usable answer leaves the wrapped key and pending setup in place. The app checks native status before another commit and never treats an unknown or mismatched nonce as success. The owner can re-enter saved words and authenticate the same key to continue; no recovery words are stored by the app.
- **State.** The app keeps the wrapped key, setup kind, confirmation and public creation nonce in private storage. The native pending record is authoritative; a missing, malformed or mismatched status stays unknown and never discards the key. Confirmed setup is recorded before opening the wallet. Recovery words are not persisted by the app.
- **Refusals.** A setup command that never started (a node running, a failed spawn, the app not ready) answers with the typed code `NOT_RUN`, so the app discards the key it wrapped and restarts the node; a command that ran and gave no usable answer keeps the key.
- **Fields.** The word fields are private text fields (no suggestions, password variation, incognito keyboard, no autofill, no long-press menu), pinned by `setup_field.h` and `make test-setup`. The visible-password variation keeps the words readable and does not by itself block copy or cut, so the fields also disable long click and hide the cursor (set on the input fields, checked by `make test-setup`) so the platform shows no insertion handle with Paste; the handle behaviour follows the Android source and is not verified on a device.
- **Limit.** The words are drawn through Java TextView objects whose copies of the text the app cannot wipe.

`make test-setup` runs the words, state, node-adapter and wizard tests and the static checks that the setup modules log and write nothing.

## Wallet screens

Wallet files are never backed up or transferred (cloud backup and device transfer exclude every storage domain, including device-protected storage), and suggestions and personalised learning are off in every text field. The node notification is secret on the lock screen: each notification sets `VISIBILITY_SECRET`, which also covers an existing install whose notification channel keeps its older lock screen setting (Android does not change a channel after it is created).

The Wallet tile on Home opens **Funds**: **Receive** and **History** stay above the changing balance and status lines; **Send** appears after a ready balance is received. It shows the **Balance** (the amount spendable now), the amount still pending (one note arrives whole in the confirmations it needs; of several, the line says when the next arrives), a **Public** line only when public funds exist, a line for mined coins that are still maturing, amounts written without trailing zeros ("25 ZCL"), one line of synchronization state, one line of fleet state ("Not checked by your fleet" unless the fleet status is exactly the documented reply; "sending waits until they agree" appears only when the node reports `refuses_send`, a machine one or more blocks behind on this chain counts as agreeing, and a machine that last reported another chain at a lower height is reported with the words "sending is not held back"). While a payment is being built or has just ended, the one line the send flow gives (`zapp_send_progress`, for example "Sending 1.5 ZCL to zs1abcde…uvwxyz: building the payment (about 2 min)", later "Sent 1.5 ZCL" or "Payment not sent: …") is drawn under the balance. It is read when Funds opens, whenever the screen is drawn again after the app returns, and on every refresh tick, and nothing is drawn when no payment is in flight. A line that no longer begins "Sending " has ended and has a **Dismiss** button that clears it from the send flow; a payment in flight cannot be dismissed. **Send** opens the camera scan screen and nothing else. While Funds is in front it asks the node again every 10 seconds. It displays amounts only after a live summary explicitly reports wallet readiness and available balance; an unavailable, malformed or legacy reply hides any prior amounts and disables Send. A pending wallet shows “Updating wallet history” and the node’s available sync position without amounts. A silent or stopped node shows its status and no cached amount; Receive remains available. The existing sealed balance is retained but is not displayed without current authority. The balance is kept in the file `wallet_balance_sealed` in the app files directory (mode 0600, opened without following links, written to a temporary file, flushed and renamed over the old one), sealed with AES-256-GCM under the balance key: a key of its own in AndroidKeyStore (`z23.wallet.balance-key.v1`, made on first use, never exported) that asks for no screen lock and that Keystore refuses while the phone is locked. The wallet key, which asks for the screen lock at every use, takes no part, and no amount is written as plain text. It is written from a summary the node gave whose balance was read while the wallet was locked or from a wallet without encryption, at most once a minute when unchanged; never from a wallet unlocked for the owner (Show private balance or a payment, which may show amounts the lock hides) or when the node is silent, and a summary that hides the private amounts deletes it. Creating or restoring a wallet writes no synthetic balance: Funds waits for an observed summary, since a payment may arrive after the recovery words are displayed and before setup finishes. The sealed body holds the three lines, the time and a hash of `wallet_key.blob` that names the wallet, and the seal is bound to the file format and that name. A wallet whose key file was set aside or replaced never matches it: a file that does not open, is of another format or version, belongs to another wallet or has no key file beside it is deleted when Funds opens, and so is the plain text `wallet_balance_cache` of earlier builds. The synchronization line reads the summary's `current` and `blocks_behind`, so a node that is not current never reads "Up to date".

**Show private balance.** A locked wallet hides its private balance, and Funds says so. When the summary reports the wallet as encrypted and locked with its private amounts hidden, Funds draws **Show private balance**. A tap asks for the screen lock through the device key, with the same unwrap and unlock request as a payment (`wss_unlock_node`) but under the unlock prompt ("Unlock this wallet", `ZAPP_DEVKEY_PURPOSE_UNLOCK`) instead of the payment prompt, and the node unlocks for 120 seconds (`WRV_WINDOW_SECONDS`); Funds then reads the summary again and the private lines appear. A cancelled prompt, a missing screen lock, a lost key or a refused unlock leaves the wallet locked and says so in one sentence, and the button asks again. The wallet is locked again when the window ends, when the owner leaves the wallet screens and when the app goes out of view (`wallet_reveal.c`, ticked with the send flow, so a lock that fails is asked for again). A payment in flight (`zapp_send_busy`) is never locked under: the request is refused while one runs, and when one starts inside the window this view drops its lock and the payment, which holds its own unlock, locks the wallet when it ends. The balance read while unlocked stays in memory only and follows the rules of every other wallet line; it is never written to the balance file.

**Make private.** Public funds are visible to everyone, so Funds draws **Make private** under the public line when the public balance is above the default fee (0.0001 ZCL, `WALLET_VIEW_FEE_FLOOR_ZAT`) and sending is allowed, the same gate as Send. A tap opens the Send screen on a sweep of one public address into the wallet's own newest private address (`wss_begin_sweep`; the node command is `core wallet shielded shield`). The app names no destination and no amount: the plan request (`shieldplan`, `wallet_sweep.c`) holds the wallet scope and the idempotency key only, and the node answers with the address it picked, the coins, the total, the fee, what arrives, the coins left for a later sweep (`remaining_inputs`) and the coinbase still maturing (`maturing_zat`). The review says "Move 0.1 ZCL from your public address into your private balance. Fee 0.0001 ZCL." with a plain note for the coins left behind. The tap on **Make private** asks for the screen lock and unlocks through the path of Send (`ws_step`, `wss_unlock_node`), then commits (`shieldcommit`) with what the plan quoted and the key of this review. A retry of the same review replays under the same key and never pays twice; a commit whose answer is missing is final and is never repeated. The sweep counts as a payment in flight for `zapp_send_busy`, so the node stop guard and the Show private balance relock respect it. When it ends, Funds says "Done. It shows in your private balance after the next block." Tests: `wallet_sweep_test.c` (plan, review, authentication, commit, replay, refusals, request shapes, busy), the `shieldplan` and `shieldcommit` cases in `wallet_run_test.c`, and the Make private cases in `wallet_screens_test.c` and `wallet_view_test.c`.

When the node is stopped, Receive can read a persisted shielded address from the confirmed wallet through the read-only recovery status; a locked seed remains locked. The stopped-node read refuses a held datadir, and setup changes invalidate its result. Before a cold start, the app can read that address in the background and hold it in memory while the node starts; a live node reply replaces it. Starting wallet setup invalidates the held address, and Stop cancels an in-progress start. A displayed address remains while the confirmed wallet identity is unchanged. The persisted row does not by itself prove spendability.

**Receive** shows a QR code in the middle, the address in groups of four characters, **Copy address**, **New address**, then the notes and an optional amount in ZCL, so the code and the main action are on the first screen. The keyboard's action key on the amount field sets the amount as **Set amount** does. A set amount puts the keyboard away and scrolls the page back to its top, where the code now carries the amount. The request remains in memory across navigation and app pauses while the confirmed wallet identity and address match; New address or a change of identity or address clears it. It is not saved across process restarts. A refused amount keeps the keyboard on the field with what was typed. Back on every wallet page (Home on Funds) and Share request on Receive are pinned under the scrolling content (`wallet_item_pinned`), so those actions stay on screen however long the page or its feedback is. The code is the bare address, or `zclassic:<address>?amount=<decimal>` once an amount is set, built by `zapp_payment_receive_code` from integer zatoshi and read back through the payment code parser before it is drawn. Opening Receive never makes a key: the live node and stopped-wallet status select the same account by child index and key identifier, then show its latest durable address reservation, or its default address when no reservation exists. If the account or reservation cannot be checked safely, no address or New address button is offered; Retry checks again without making a reservation. The reply names only the address, not whether it has received a payment, so the screen makes no claim about reuse. A node without that command is told apart from an error, and Receive offers **New address**. The address remains the same until another reservation is recorded. A reservation may be recorded even if a **New address** request fails before its reply reaches the app; it does not prove that the address was delivered. Only that tap makes an address, through `core wallet shielded receive`. A node without that command gets the sentence "This build cannot make a new address." and no **New address** button; the app never falls back to `core wallet shielded address`, which creates a new spending key, and a wallet holds at most 256 of them (`MAX_SAPLING_KEYS`). **Copy address** puts the bare address on the clipboard through `ClipboardManager.setPrimaryClip` in `secure_window.c`, marked sensitive (`android.content.extra.IS_SENSITIVE`) so the system hides it in its clipboard preview, and says "Address copied. It clears after a minute." After 60 seconds a detached thread calls `clearPrimaryClip`, but only while the clipboard still holds the clip the app put there (the clip description timestamp is compared); a clip copied since is left alone. From Android 10 an app can read the clipboard only while it has focus, so a read refused in the background is logged once, is never taken for "cleared", and is tried again every 10 seconds for up to six hours, which clears the clip within seconds of the app coming back to the front. If the system ends the app before the clear, or the app stays in the background for those six hours, the address can stay on the clipboard. If the clipboard refuses, the screen says "Could not copy the address." and the log names the failed step, never the address. If the node refuses to make an address, the screen says that no address was made and to check that the node is running. No public address is offered.

A plain-text note explains that the request can be shared as text or with a photo or video, and that the recipient is chosen in Android's share sheet. **Share request: text** opens Android's share sheet directly with the current Receive code as `text/plain`. It does not open the media picker, grant a media URI, or choose a recipient. The pinned **Share request: media** action opens the system image/video picker. Android's chooser asks for the recipient. The optional title **Choose recipient** is supplied for platforms that display it; Android may use its own heading. After the owner chooses an item, the app opens Android's share sheet with that media URI and the current Receive code, granting read access to the chosen recipient. The owner chooses the recipient and whether to send anything. Cancelling the picker says that nothing was sent. A completed chooser action is reported without claiming delivery. Other chooser results say only that the sheet closed and that Android does not confirm whether anything was sent, because Android 15 uses the same result for cancellation and an ordinary recipient launch. The app never claims that a transfer completed. Returning to the app reopens Receive and checks the request again without retaining balance or history data while another app is shown. That notice appears under the Receive title, survives address refreshes and temporary node silence, and changing the amount or address clears it. No payment, publication or network fetch is performed by either step. The pending code is wiped after each result and is never logged. This is Android's direct-share path, not Clips networking; the design document does not provide a working Clips network today.
For isolated preview acceptance, `ZAPP_SHARE_FIXTURE=ON` supplies a regtest Receive request. It is off by default and uses no keys or funds.
<!-- claim: symbol-present share_request_items apps/z23android/wallet_screens.c # Receive explains media and recipient choice in plain text -->
<!-- claim: symbol-present ZAPP_SHARE_FIXTURE apps/z23android/CMakeLists.txt # opt-in regtest share acceptance fixture -->
<!-- claim: symbol-present start_share apps/z23android/share.c # optional recipient title is supplied for platforms that display it -->
<!-- claim: symbol-present zapp_share_begin apps/z23android/share.c # user-selected media and Receive code sharing -->
<!-- claim: symbol-present zapp_share_result apps/z23android/share.c # Android share-sheet result and pending-code wipe -->

**History** lists sent, received and internal transactions, ten per page by cursor, each row left aligned with the amount first and larger and, under it, the kind, the privacy, the state and the date. An entry is called private only when the node reports `fully_shielded` true on it (every input and output shielded) and public when it reports false; null or a missing field makes no claim of privacy, because a payment between a private and a public address is not private in either direction. An empty page reads "No transactions yet." only when the summary shows the node current and every block scanned; while the wallet is still scanning it says so, a node that is not current says so, and when no summary was read it reads "None found so far.". Tapping a row shows the transaction id and the memo of that transaction on request. A reply that is not exactly the documented frame is an error, not an empty wallet; a field that is missing or of another type reads "unknown". A memo is written by another person, so it is drawn in its own panel under a heading that says so, every control, separator, bidirectional and zero-width character is shown as `<U+XXXX>`, every invalid byte as `<xNN>`, and a memo that does not fit the room is marked as cut. Text on the wallet screens cannot be selected. The sharing actions are **Copy address** and **Share request** on Receive (see above).

Every wallet screen sets `FLAG_SECURE`, obscured-touch filtering, `Window.setHideOverlayWindows` (so another app cannot draw over a code that takes no tap; the `HIDE_OVERLAY_WINDOWS` permission is in the manifest), `Activity.setRecentsScreenshotEnabled(false)` and `setAccessibilityDataSensitive` on the decor view (so an accessibility service that does not declare access to sensitive data cannot read the balance or a memo) through the window on the UI thread and reads back what the platform lets it read before it shows anything, so it is blank in Recents and screenshots; the platform has no public getter for the overlay setting, so it is confirmed by the held `HIDE_OVERLAY_WINDOWS` permission and a call that raised nothing. If any protection cannot be confirmed, or a protection is missing from the window's set, the screen shows one sentence that names which protection the phone refused and no wallet data. Touches that arrive while another window draws over the app, a screen dimmer for one, are dropped in the shell for as long as a wallet screen is shown, as well as in the window gate, and the screen then says that another app is drawing over it until a tap reaches it. The wallet commands run through the command line, never on the UI thread and never on the controller's worker, with at most one thread for each kind of command (six in all): a request made while its kind runs replaces the one waiting, and a **New address** tap made while an address is being made is ignored.

Wallet data lives only in `wallet_screens.c`, in the copy of the current screen that `wallet_ui.c` draws from and, for the balance lines alone, sealed in the `wallet_balance_sealed` file described under Funds. The two copies in memory are wiped when the owner leaves a wallet screen, when the app goes out of view (a memo detail does not stay on screen under the Home button) and when the app is destroyed. Going out of view wipes the data and queues Home but keeps `FLAG_SECURE` and touch filtering in force, so a capture of the window taken before Home is drawn shows nothing; the shell removes them on the first refresh tick after the app returns (`wallet_screens_settle`), once Home is on screen, and the refresh timer is stopped while the app is out of view. The reply buffer of each command and the strings in its parsed tree are overwritten before they are freed, and the JSON reader overwrites the block of a string that outgrows it. Numbers in a freed parse tree are not overwritten, and the Android views hold a copy of the text they draw until they are removed. Wallet data never reaches the app view, a card, a notification, Home, the assistant context or a log. It leaves Receive only through the owner's explicit Copy address or Share request action. `make test-wallet` checks on the host that the behaviour holds, that after the screens close the memo (one longer than 63 bytes, so that the reader grew its string), the amounts, the address, the transaction id and the fleet name planted in their replies are in neither the heap nor the program's data, that the files which make Home, the assistant and the controller include none of the wallet headers, and that the command layer passes only a valid cursor or transaction id on the command line. `wallet_ui.c` and `shell.c` use the Android API and are compiled by `make native` but not run on the host; their drawing, the window flag read-back, the lifecycle wipe, the protection kept through a pause and its release on the first tick, and the refresh timer are unproved until a device run. The host checks the screens' side of the pause and the settle (data gone, protection kept until settled or closed, a reply that lands after the pause dropped) and that every window protection is required, over fake window operations. The overlay, accessibility and recents calls are checked only by a device run.

## Fleet invitation review

Scan or paste the manager's invitation. The app verifies its signature and
expiry without joining, then shows the phone name and full manager public key.
Compare that key with the manager before tapping **Join fleet**. Joining checks
the invitation again and creates a return code for the manager to admit.

The return code appears as a QR code with **Copy code**. It is saved privately
and remains available after an app restart. If saving fails, the app says to
show or copy the code now. Copying uses the protected clipboard and its existing
expiry behavior. A return code alone does not mean the phone has been admitted;
the manager must accept it before the fleet connection is complete.

A manager may also provide a sealed machine code. Review shows the computer
name and manager key; **Connect** imports
the verified record and schedules its onion connection. A scheduled dial is
not proof of a handshake or admission. If the import succeeds but the dial
cannot be scheduled, the app says so and offers another Connect attempt.

### Play a local Sky Combat build

The paired laptop host can offer its own explicitly selected Sky Combat binary.
Start the host yourself with an absolute path, for example:

```sh
build/android-app/z23-speech-bridge --dir /path/to/private/bridge-dir \
  --game /absolute/path/to/z23-skycombat --game-only
```

Pair the phone through the existing protocol-2 pairing route, then tap **Play**.
Touch the left half to fly, the lower right to fire and upper right to boost;
Android Back ends the session. The game runs on the host and sends rendered PNG
frames. It advances only in bounded steps requested by the phone. Pausing the
app also leaves Play. A dropped request stops the child; if the phone disappears
between requests, the host closes it after 15 seconds without a successful
request. One session runs at a time and each authenticated call carries its
random session identifier. Failed or uncertain steps are never retried.

The host takes a private executable snapshot when Play starts and identifies
those bytes by SHA-256 in every reply. This is an executable image identity,
not a source or ancestry claim. Relative assets are not included in this
snapshot; the current procedural game can be exercised, but edited asset
bundles need a separate complete artifact binding. It neither downloads nor
executes a Commons package. The game agent protocol's 640×360 and 1 MiB PNG
ceilings fit the existing image and bridge limits. The connection requires the
paired host and a display capable of running the game; a headless test does not
qualify actual phone display, touch, or host graphics.

`make test-game` runs the host lifecycle and phone decoder/control fixtures.
