<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# SkyCombat complete-game source and peer build

Date: 2026-09-24. This experiment freezes the complete game source at commit
`255990bfdc48e0c7e6f966aa2e8d6e678b25ca40`, tree
`5688c2a49474d6ff91e56aba378471cead0db7dc`. The owner previously
accepted a preview of that commit's game executable SHA-256
`9a7a46565f2414bd8ccb5c9ee6ebb7c60b951ea690177f958123993091e4082c`
and frame SHA-256
`38fd50456fb394a84df18956cc2d13cc56daf55163f0caa560f82a1b309873e4`.
This run tests whether the complete game source builds and renders outside the
original checkout. It does not create a Commons candidate, publication, DEV
acceptance, or full acceptance.

## Frozen inputs and local reproduction

The source archive includes `apps/skycombat`, vendored raylib, `Makefile`, and
the root license from the exact commit. The standalone `qualify.mk` is the
game section of that commit's Makefile with explicit C23, Linux, build-output,
and compiler defaults. It leaves the game's compile flags, source closure,
platform-header refusal, raylib configuration, and link libraries unchanged.
These commands reproduce its input roots:

```bash
out=test-tmp/skycombat-fullgame-20260924
mkdir -p "$out/source"
git archive --format=tar -o "$out/source.tar" \
  255990bfdc48e0c7e6f966aa2e8d6e678b25ca40 \
  apps/skycombat vendor/raylib Makefile LICENSE
tar -xf "$out/source.tar" -C "$out/source"
{
  printf '%s\n' 'CC := gcc' 'AR := ar' 'BUILD_DIR := build' \
    'BIN_DIR := build/bin' 'ZCL_C_STD := c23' 'ZCL_HOST_OS := Linux' \
    'ZCL_WARN_STRINGOP_OVERFLOW := -Wno-stringop-overflow' 'FORCE:'
  sed -n '2634,2785p' "$out/source/Makefile"
} > "$out/source/qualify.mk"
sha256sum "$out/source.tar" "$out/source/qualify.mk"
(cd "$out/source" && make -s -f qualify.mk -j4 game && \
  sha256sum build/bin/z23-skycombat)
```

| Local item | SHA-256 or result |
| --- | --- |
| Source archive | `56b4ebc8d6fbbb9ec351a164512aa1a55c4ce0c8364a867716ee1f1a9670f165` |
| Standalone recipe | `85ba171a0109427bfb5a85771bb2f72686bf5903a8543c8d80e19acc9b033fab` |
| GCC 16.1.1 executable | `9a7a46565f2414bd8ccb5c9ee6ebb7c60b951ea690177f958123993091e4082c` |

The local host was an AMD Ryzen 7 PRO 8840U with GCC 16.1.1 20260430. The
standalone build completed in 5.78 s elapsed and matched the owner's exact
accepted executable bytes. That binds the frozen complete-game source and
build recipe to the accepted local preview artifact. It does not by itself
prove gameplay correctness or authorize publication.

## Independent peer verdicts

Both consenting development peers received and hash-checked the exact source
archive and standalone recipe. The first peer's GCC 14.2.0 build refused at
the platform-header gate before compilation: it lacked Xrandr, XInput2, and
Xcursor development headers. No source or executable verdict follows from
that refusal.

The second peer had GCC 14.2.0 and the required Linux headers. It ran the
same recipe with `CC=gcc-14` and `-j2` and produced executable SHA-256
`9b8ff8ec0b72d1bb0c3120b5c3a8349e20c6bb1effe28887cf7df484e8561f18`.
The returned executable and initial build log hash-checked locally; the log
SHA-256 is
`f160d57ab394e7dfee2f80be8bf7e435ed9c4c88b7f92cab242d75dc47ed6b29`.
A second fresh build with separate output directories produced the same peer
executable hash. Its build log SHA-256 is
`c3b123e038b7081a2948770b14baf4b07253b02720adf838fb26cebc1330f582`.

The peer ran its executable under Xvfb at 1920×1080 with Mesa llvmpipe, then
captured one frame. The frame SHA-256 is
`4f1d7031693a7d040a6e8734c248daf5544efa853552b4932cc2db1e406cf9d6`;
the game log SHA-256 is
`3609175e563711f109ff994981ebe20960644a267fa4f90698b9f031b0ab688e`.
The frame visibly contains the city, aircraft, score, timer, and HUD. The log
records successful OpenGL initialization and five aircraft. This is an
independent peer render observation, not a second owner acceptance. Different
compiler cohorts and software rendering do not imply byte-identical
executables or frames.

The measured fresh peer rebuild used an AMD Ryzen 9 7950X3D 16-Core
Processor, GCC 14.2.0, and `-j2`. It took 4.51 s wall, 8.29 s user CPU and
0.52 s system CPU, at 195% CPU use. `/usr/bin/time -v` reported maximum
resident set size 223,424 KiB, 2,152 filesystem input blocks, and 19,608
filesystem output blocks. Its measurement file SHA-256 is
`baf41e1d9b9a65ca6cc2b86d3f37a556e070f0f3488af86b0c8d7428201e668a`.
The initial peer build and Xvfb run were not separately resource-profiled.

The second peer had resident canonical and development node processes. No
before/during node-health sample was taken for this experiment, so its
effect on node synchronization, RPC latency, and peer health is unobserved.
No further load was sent after discovering that gap. Native mail sequence
468 reported the exact inputs, outputs, cost, and observation limit.

## Release boundary

The prior Commons package root
`9a2c62d39213dd36a2e05ca064ac011d100ff429f92eecedd2f2682307495acc`
contains an aircraft component control, not this complete game. The complete
game now has local byte-exact reproduction and an independent GCC 14 build
and render, but no exact Commons candidate, package publication, or local
acceptance receipt. The next release-critical step is to represent the full
game and its approved binary identity as one exact candidate in the real
lifecycle, then run its mandatory proof and receiver acceptance gates.
