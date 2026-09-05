# raylib (vendored, trimmed)

Origin: https://github.com/raysan5/raylib @ `550dd0e` ("6.1-dev"), zlib licence — see `LICENSE`.
Kept: the five renderer modules `rcore/rshapes/rtext/rtextures/rmodels`, the headers they need
(`raylib.h`, `raymath.h`, `rlgl.h`, `config.h`, `rgestures.h`, `rcamera.h`), one platform backend
(`platforms/rcore_desktop_rgfw.c`) and the eight single-file dependencies those actually `#include`
(`glad.h`, `stb_image_resize2.h`, `stb_perlin.h`, `rprand.h`, `RGFW/RGFW.h`, `RGFW/deps/minigamepad.h`, plus
`fix_win32_compatibility.h`/`win32_clipboard.h` for the Windows build). Dropped: audio (raudio,
miniaudio, dr_*, jar_*, qoa), every model file format (cgltf, tinyobj, m3d, vox, par_shapes), every
image file format (stb_image, qoi, pep), glfw, sdl, drm, android, web and the software rasteriser.
Why RGFW and not glfw: RGFW is a single pure-C header on Linux, Windows and macOS, so the desktop
backend needs no Objective-C source and no second build system; z23 already pins RGFW separately at
`vendor/rgfw/` for `lib/presentation`, and the two copies stay independent because raylib's backend
is written against the RGFW revision raylib bundles.
Local patches under `-std=c2x`: none. Every build knob is passed as `-D` from the Makefile (`make
game`, `make game-check`) because raylib's `config.h` guards each one with `#ifndef`, so the vendored
files stay byte-identical to upstream and `sha256sum --check vendor/raylib/SHA256SUMS` proves it.
