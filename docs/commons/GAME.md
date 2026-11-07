<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Sky Combat — the game in this repo

`apps/skycombat/` ships an aerial combat game in a cyberpunk city with
one local player, four AI aircraft and a single view following the local
aircraft. Guns, powerups and aircraft AI are wired into that executable.
It is the owner's own game (Apache-2.0, imported from
`full-node-firewall-fly-over`) rewritten here as C23 that compiles under the
repo's own-code flags. It is an application, not part of the node: it links
nothing from `core/` or `engine/`, and the node binary links nothing from it.

## Build and run

```
make game          # links build/bin/z23-skycombat  (needs X11 + GL headers)
make game-check    # compiles the game and raylib to objects only, no window
./build/bin/z23-skycombat
```

For a bounded launch health check on Linux, macOS or Windows, run the same
native game binary with a frame count:

```bash
./build/bin/z23-skycombat --qa-frames=120
```

On Windows use `build/bin/z23-skycombat.exe --qa-frames=120`. This opens the
normal game window, completes exactly 120 rendered frames, cleans up and exits
0. `N` must be canonical decimal in `--qa-frames=N`, from 1 through 3600;
zero, negative, nonnumeric, overflowing, leading-zero and unknown or duplicate arguments
exit 2 before any window opens. Window initialization failure or closing the
window before the requested frames complete exits 1. With no argument the
game remains interactive. A health check still needs a working native display
and graphics driver, and its own watchdog for a stalled driver or process.

```bash
# No display (ssh, a server, a CI box): run under a virtual display.
xvfb-run -a build/bin/z23-skycombat --qa-frames=120
# The Preview: line from the app build step, wrapped the same way.
xvfb-run -a <that command>
```

Both are **opt-in**: the default build, `build-only`, the push proof and every
lint gate ignore them, so a headless or header-less host is never blocked by
the game. `make game` probes for the platform headers first and, if they are
missing, prints one typed line — `game_platform_headers_missing: <what>` — and
exits 2 instead of a wall of compiler errors. `make game-check` needs no
window and is what a headless gate box proves. These game-only goals build no
node vendor archive or embedded Tor archive; mixed game and node goals retain
the node's vendor and Tor prerequisites.

The playable simulation and its mixed update/draw entrypoint compile with
`-ffp-contract=off`. Their sources also set `STDC FP_CONTRACT OFF` on Clang;
GCC enforces the build flag. Simulation raymath helpers are local to those
objects, so rendering's external helpers cannot change their rounding.
Dedicated view sources, cosmetic world generation and raylib keep their
existing floating-point policy. This removes contraction as a replay
difference; native math-library results can still differ between platforms.

QA frame limits can be combined with the pinned HUD option in either argument
order. All options are validated before window setup.

## Agent resident transport

POSIX `--resident NONCE --agent [--seed=UINT32]` uses a private stream socket
at fd 3. NONCE is exactly 64 lowercase hex characters. Windows refuses with
`RESIDENT_UNSUPPORTED_WINDOWS`; `--agent-stdio` remains available.
Diagnostics use stderr in both modes; cleanup restores stdout.

Frames reuse the native `resident_result_header` ABI from
`platform/modules/platform/include/platform/resident_launch.h`:
`z23-res-run-v1`, launch nonce, payload length,
then JSON. Input is at most 4096 bytes (optional trailing LF); replies at most
2 MiB. Both transports use the v1 IDs and budgets below. Fragment waits pump
window events without simulation ticks.

The five-byte `READY` payload precedes `InitWindow` and proves protocol entry
only: require a successful first observe for rendering. Init failure closes
the channel and exits. STOP is exactly 16 magic bytes `z23-res-stop-v1` plus
65 nonce bytes including NUL: 81 bytes, no length/padding. It is handled before
the rest of a run header. EOF closes cleanly. The parent retains image/nonce
authority and its watchdog.

Seed is canonical decimal 0..4294967295 (default 1), applied to libc and raylib
after window initialization, before systems. Replay determinism requires
separate qualification.

<!-- claim: symbol-present sky_resident_read apps/skycombat/src/agent_resident.c # native child framing -->

## Agent stdio session

Launch the same game with `--agent-stdio` and private stdin/stdout pipes.
Ordinary game and renderer logs go to stderr; stdout contains one JSON reply
per request line. This option cannot be combined with `--qa-frames`.
It does not add a listener, plugin permission, or remote execution authority.

```json
{"v":1,"id":1,"op":"observe","capture":true}
{"v":1,"id":2,"op":"step","frames":60,"input":{"move_x":0.5,"move_y":0,"camera_x":0,"fire_guns":false,"speed_boost":false,"throttle":true},"capture":true}
{"v":1,"id":3,"op":"close"}
```

Each LF-terminated request is at most 4096 bytes. Version 1 uses ASCII field
names and operations; unknown fields, duplicate decoded keys, invalid types,
nonfinite axes and axes outside [-1,1] are refused without simulation advance.
Step requires 1–120 frames and an input object. Omitted input fields are neutral;
capture defaults to false. Each step uses the maintained simulation with fixed
1/60-second ticks and local-player controls, bypassing hardware polling and
keyboard fallbacks. Guns are held on each requested tick; boost triggers on a
rising edge between accepted step inputs, on the first tick only. `throttle`
uses the existing normal-throttle control. Observe renders without advancing.
Window events are pumped while waiting, without ticking the simulation.

IDs are integers from 0 through 4294967295, strictly increasing within this
process session. A fully validated fresh request consumes its ID before
execution, including subsequent capture, window or frame-budget failure.
Validation failures do not consume IDs. Duplicate/stale IDs return
`STALE_REQUEST_ID` without executing or capturing. Every reply reports
`accepted_id` (initially null), `id`, `ok`, simulation `frame` and `time`, and
the current player's position, yaw, speed and health. Errors include a named
`error`. Never blindly retry an uncertain step: use a higher-ID observe to
reconcile its frame/state. Restarting the game creates a new simulation;
broker session identity and executable/source binding remain the broker's
responsibility. At the maximum ID, EOF can close the session.

The agent viewport is 960×540 logical pixels. Capture reads the final composited
frame including HUD before swap, refuses physical readbacks above 1920×1080,
then uses raylib's existing RGBA resampler to fit within 640×360 while preserving aspect ratio
with integer rounding, without upscaling. PNG replies contain
`png:{width,height,bytes,base64}` with actual encoded dimensions. PNG is capped
at 1 MiB and the JSON reply at 2 MiB. Capture failures return no image, never a
previous frame. A failed capture after a step still reports the advanced frame.
The resampler's allocation and resize result are checked directly; the void
`ImageResize` wrapper does not expose resize failure.
There is no full-resolution capture option in v1.

Sessions allow at most 4096 requests and 36000 simulation ticks. EOF, close and
window cancellation end the session and clean up game/window resources;
controls are ephemeral to each step. Partial or oversized lines refuse and
close. Output failures exit unsuccessfully. A caller must drain stdout and
retain its own process/graphics-driver watchdog. The QA shim checks protocol
wiring and cleanup, not actual physics or pixels; real-display qualification
is separate and does not establish phone hosting or cross-platform replay.

<!-- claim: symbol-present sky_agent_run apps/skycombat/src/agent_session.c # bounded stdio session -->
<!-- claim: symbol-present game_agent_frame apps/skycombat/src/sky_combat_multiplayer_ultimate.c # maintained frame adapter -->

The explicit Linux real-display client is built with `make skycombat-agent-client`;
it is not run by generic tests. It uses private pipes to the actual game and
checks observe, neutral/turn steps, refused requests and close. Saved PNGs are
checked for complete RGBA8/stored-DEFLATE structure, checksums and raster size,
not merely a PNG header. This validates the current encoder profile, not every
PNG format. With Xvfb installed, an example admitted, bounded invocation is:

```sh
# Set sky_output to a new, owned mode-0700 directory in sanctioned scratch.
devbuild --wait --project z23 --class normal \
  build/bin/z23_bounded_run 30000 /usr/bin/xvfb-run -a \
  -s '-screen 0 960x540x24' /usr/bin/env LIBGL_ALWAYS_SOFTWARE=1 \
  "$PWD/build/bin/skycombat-agent-client" "$PWD/build/bin/z23-skycombat" "$sky_output"
```

Build the game and bounded runner first using their native targets. The client
takes absolute game/output paths; a failed case still reaps its child. Keep
actual renderer, executable identity and output evidence with the result.
Successful Linux software rendering does not qualify macOS, Windows or phones.

<!-- claim: symbol-present skycombat-agent-client Makefile # opt-in real-display fixture target -->

## Signed plugin package

`make plugin-skycombat` packs the game as a signed z23 plugin. It depends on
`make game` and the full `z23` binary, then runs:

```sh
z23 plugin pack build/bin/z23-skycombat --name=skycombat --version=<git describe> \
  --interface=1 --cap=ui.panel --key=$PLUGIN_KEY --dir=build/plugins/skycombat
```

`PLUGIN_KEY` names a 0600, 32-byte key file made with `z23 plugin keygen <file>`.
The target refuses by name when it is unset and never writes a key into the
tree. The output is `build/plugins/skycombat/skycombat`, `skycombat.plugin.json`
and `skycombat.plugin.sig`.

**Not runnable yet.** `z23 plugin run skycombat` is blocked until the plugin
sandbox grants `ui.panel` and the game can reach a GPU from inside it; today
the sandbox refuses `ui.panel`, so the signed package can be installed and
verified but not run. Running the game still uses `./build/bin/z23-skycombat`.

**Static linking.** `plugin run` expects a static ELF (`docs/dev/PLUGINS.md`).
`plugin pack` does not check that, so a dynamically linked game still packs.
A static link of the game needs static GL and X11 libraries (libGL, libXrandr,
libXi, libXcursor) plus the Xrandr, XInput2 and Xcursor headers, which most
distributions do not ship; check the binary with `readelf -l` before you
distribute it.

## Pinned data-only HUD

`--hud-part=<64-hex-SHA-256>:<file>` selects a HUDX expression part. The game
reads and admits it once at startup, using the initial screen/player/match
snapshot. Its assembled recipe replaces the built-in HUD each frame; values
and layout stay at that snapshot until an explicitly requested reload. No automatic per-frame file reads. FPS and input-debug overlays remain
owned and drawn by the host.
Omitting the option preserves the built-in HUD. A file/pin/schema/evaluation/
drawing refusal prints its reason once and uses the built-in HUD. Malformed
options exit 2 before opening a window. This admits inert data, never native code.

This complete example creates a red 320-pixel square HUD part:

```sh
printf '%b' \
 'HUDX\000\000\040\000\001\000\000\000\005\000\001\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000' \
 '\001\000\377\377\377\377\377\377\000\000\000\000\000\000\000\000' \
 '\001\000\377\377\377\377\377\377\001\000\000\000\000\000\000\000' \
 '\011\000\000\000\001\000\377\377\000\000\000\000\000\000\000\000' \
 '\001\000\377\377\377\377\377\377\100\001\000\000\000\000\000\000' \
 '\001\000\377\377\377\377\377\377\377\000\000\377\000\000\000\000' \
 '\001\000\002\000\000\000\000\000\003\000\003\000\004\000\000\000\000\000\377\377\000\000\000\000' > /tmp/sky-hud-red.bin
pin=$(sha256sum /tmp/sky-hud-red.bin | awk '{print $1}')
./build/bin/z23-skycombat "--hud-part=$pin:/tmp/sky-hud-red.bin"
```

The file is 136 bytes. RECT/RECT_LINES use recipe geometry and RGBA colour;
TEXT uses its anchor/alignment. TEXT_BOX draws only a box in its RGBA colour, using the measured text width,
integer centre rounding, horizontal padding and height. A following TEXT
operation supplies the label. Text is copied from
the counted arena to a bounded NUL-terminated buffer for raylib.

Press **F7** to switch between the admitted recipe and the built-in HUD.
Switching retains the captured recipe and reads neither file, so you can
compare both displays without restarting. F7 does nothing until a recipe
has been admitted.

To reload during play, add the second option `--hud-pin-file=<file>` after
`--hud-part`. Press **F6** to re-read the pin and part and assemble a recipe
using the current screen/player/match snapshot. The pin file must contain
exactly 64 hex digits, optionally followed by one LF; filenames or extra
whitespace are refused. Startup still uses the inline pin. Without the second
option F6 does nothing. A refused reload prints one typed reason and preserves
the complete previous HUD; a successful reload can also recover from a refused
startup. Reloading while the built-in HUD is selected keeps that selection;
press F7 to show the newly admitted recipe. This is a single-thread frame-boundary change, not native code loading.

After each F6 reload attempt, the game shows a five-second notice below the
FPS/input overlay: green **HUD updated** on success, or an orange **HUD kept**
with a short refusal reason. A successful update while the built-in HUD is
selected offers **F7 to show**; that hint follows your current selection.
The latest attempt replaces the previous notice. It expires after five seconds
of positive finite frame time. The admitted HUD and display choice remain
unchanged on refusal; detailed diagnostics still go to stderr. Ordinary frames
and F7 do not create a notice.

For the red square above, start a reloadable session:

```sh
printf '%s\n' "$pin" > /tmp/sky-hud.pin
./build/bin/z23-skycombat "--hud-part=$pin:/tmp/sky-hud-red.bin" \
  --hud-pin-file=/tmp/sky-hud.pin
```

While it runs, the following changes the 136-byte example to a blue square.
Then press F6:

```sh
cp /tmp/sky-hud-red.bin /tmp/sky-hud-next.bin
printf '\377\377\000\000' | dd of=/tmp/sky-hud-next.bin bs=1 seek=104 conv=notrunc status=none
sha256sum /tmp/sky-hud-next.bin | awk '{print $1}' > /tmp/sky-hud-next.pin
mv /tmp/sky-hud-next.bin /tmp/sky-hud-red.bin
mv /tmp/sky-hud-next.pin /tmp/sky-hud.pin
```

The two replacements are not one atomic filesystem operation. Press F6 after
both finish; if a concurrent edit exposes a mismatched pair, SHA admission
refuses it and retains the previous recipe. The captured recipe stays fixed
between key presses; neither file is reopened for ordinary frames.

## Controls

Gamepad (ASTRO C40 / PlayStation layout; the mapping is locked in
`include/sky_combat/models/input_model.h`): left stick flies, inverted; right
stick aims the camera; **R2** fires guns; **L2** fires missiles; **L1/R1**
barrel-roll; **gas** boosts; **brake** throttles up. Keyboard, used when no
pad is connected: **WASD** or the **arrow keys** fly, **space** boosts, **left
ctrl** fires guns, **left shift** throttles up. The playable binary acts
on fly, boost, throttle and guns; missiles and barrel rolls are in the input
model but not yet bound in it.

## Playable scope and incomplete integration

The selected entrypoint is `apps/skycombat/src/sky_combat_multiplayer_ultimate.c`,
chosen by `SKYCOMBAT_GAME_MAIN` and the `SKYCOMBAT_GAME_SRCS` link closure in
the Makefile. Imported demo mains and model APIs are available source, not
additional features of `build/bin/z23-skycombat`. This is one local player
with four AI aircraft in a single view; it does not provide local split-screen.

The match starts once after rule configuration. Each live tick snapshots team
kill totals and advances the timer. On reaching the score or time limit, scores freeze
and the winner remains fixed. Normal shutdown finishes an unfinished match.
An ended-match screen, a new-round flow and match save/reopen are not wired.
These ledger guarantees do not imply that aircraft simulation stops at match end.

Building entry is not yet wired: the playable link closure excludes the
building system. The main draws a cyberpunk city but does not update ground
AI. Neither imported building APIs nor other demos establish those features
in this executable.

Sky Combat is single-machine today. The playable link closure has no network
transport. This document promises no fleet service integration or delivery lane.

## What is proved, and what is not

`make t-fast ONLY=skycombat_models` runs the headless model tests
(`tests/harness/src/test_skycombat_models.c`): the aircraft physics step,
weapon cooldown and wing selection, pickup reservations, match lifecycle and
world bounds, with fixed inputs and private shims for seven raylib drawing,
random and time calls. An additive check reads this public launch document
and refuses obsolete scope claims. Rendering, physical input devices and the
window itself have no automatic test in this group.

`make t-fast-exact ONLY=skycombat_qa_frames` checks the strict argument parser
and executes the actual playable entrypoint against an inert window/drawing
fixture. It proves pre-window refusal, exact frame termination, early-close
failure and the unchanged interactive selection. The fixture does not qualify
GPU rendering, input devices or a real window; the bounded command above is
the native launch check.

The `skycombat_expr` group also captures recipe drawing calls and verifies
startup admission, option refusals and fallback selection without a window.
Input devices, GPU pixels and the window itself have no automatic test.

`make t-fast-exact ONLY=skycombat_fp_contract` builds and tests the actual
game aircraft object without window-system headers. Its known-answer yaw
step rounds to zero with separate binary32 operations; contraction preserves
a nonzero residual. The test also checks the explicit fused reference, so
the input's ability to distinguish those policies is asserted.

## Licences

The game is Apache-2.0 (`LICENSE` at the repo root) and every imported file
carries the repo header. raylib is vendored under `vendor/raylib/` under its
own zlib licence, origin commit and digests pinned — see the dependency
section of [BUILD.md](../dev/BUILD.md). No submodule, no package manager, no system
raylib. Source files that could never compile upstream (headers that exist
nowhere, SDL2/GLUT/GLEW demos, the GDB-proof pipeline) were not imported; the
import commit for `apps/skycombat` names each one.
