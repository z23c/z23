<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Sky Combat — the game in this repo

`apps/skycombat/` is Sky Combat: a five-player split-screen aerial combat game
in a cyberpunk city — aircraft with guns, powerups, ground AI, enterable
buildings, match rules. It is the owner's own game (Apache-2.0, imported from
`full-node-firewall-fly-over`) rewritten here as C23 that compiles under the
repo's own-code flags. It is an application, not part of the node: it links
nothing from `core/` or `engine/`, and the node binary links nothing from it.

## Build and run

```
make game          # links build/bin/z23-skycombat  (needs X11 + GL headers)
make game-check    # compiles the game and raylib to objects only, no window
./build/bin/z23-skycombat
```

Both are **opt-in**: the default build, `build-only`, the push proof and every
lint gate ignore them, so a headless or header-less host is never blocked by
the game. `make game` probes for the platform headers first and, if they are
missing, prints one typed line — `game_platform_headers_missing: <what>` — and
exits 2 instead of a wall of compiler errors. `make game-check` needs no
window and is what a headless gate box proves.

## Controls

Gamepad (ASTRO C40 / PlayStation layout; the mapping is locked in
`include/sky_combat/models/input_model.h`): left stick flies, inverted; right
stick aims the camera; **R2** fires guns; **L2** fires missiles; **L1/R1**
barrel-roll; **gas** boosts; **brake** throttles up. Keyboard, used when no
pad is connected: **WASD** or the **arrow keys** fly, **space** boosts, **left
ctrl** fires guns, **left shift** throttles up. The split-screen binary acts
on fly, boost, throttle and guns; missiles and barrel rolls are in the input
model but not yet bound in it.

## Fleet-vs-fleet: not yet wired

Sky Combat is single-machine today. Fleet-vs-fleet play arrives through the
`game` stream service being built in lane fleetgame1. Nothing in this
directory talks to that service yet, and the binary has no network code.

## What is proved, and what is not

`make t-fast ONLY=skycombat_models` runs the headless model tests
(`tests/harness/src/test_skycombat_models.c`): the aircraft physics step,
weapon cooldown and world bounds, with fixed inputs and a small shim standing
in for the seven raylib drawing and time calls the models make. Rendering,
input devices and the window itself have no automatic test.

## Licences

The game is Apache-2.0 (`LICENSE` at the repo root) and every imported file
carries the repo header. raylib is vendored under `vendor/raylib/` under its
own zlib licence, origin commit and digests pinned — see the dependency
section of [BUILD.md](BUILD.md). No submodule, no package manager, no system
raylib. Source files that could never compile upstream (headers that exist
nowhere, SDL2/GLUT/GLEW demos, the GDB-proof pipeline) were not imported; the
import commit for `apps/skycombat` names each one.
