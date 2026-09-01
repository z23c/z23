# zhello

The smallest prompt-to-pixel loop in the Commons: one `make zhello`
opens a native window on this host and prints the wall-clock timestamp
of the first frame it presented.

Strict C23, two translation units, no node objects, no third-party
library beyond the vendored single-header RGFW windowing layer
(Cocoa on macOS, X11 loaded at runtime on Linux, Win32 on Windows).
Rendering is software RGBA — no OpenGL, no Metal, no GPU API — so the
same painter runs in a window on a desk and in a headless CI step.

## Run it

```sh
make zhello                          # build, open the window, animate
make zhello ZHELLO_ARGS=--seconds=2  # same, but exits by itself
make zhello-selftest                 # headless: no window, exits 0
```

Windowed mode draws an animated gradient with a square bouncing inside
it until Esc, the close button, or `--seconds=S`. Its first log line is
the mission metric:

```sh
zhello 2026-08-28T00:33:36.709Z present frame 0 in 117.7 ms
    (window created 80.6 ms, first present 117.7 ms after launch)
```

## Self-test

`zhello --frames=N` never calls RGFW. It renders N logical frames at a
fixed 60 Hz cadence, folds each presented frame into a digest, prints
the per-frame present time, and exits 0 — so a machine without a
WindowServer still proves the frame code runs. The run fails if the
animation does not move (identical digests) or the canvas is not
opaque.

## Layout

- `include/zhello/zhello.h` — canvas, bounce state, painter API
- `src/zhello.c` — the painter; no windowing API, deterministic in its
  inputs
- `app/main.c` — RGFW driver plus the headless self-test mode

The per-host link inputs (Cocoa frameworks, X11-at-runtime, Win32) live
in the GUI-packages block of the top-level `Makefile`, not in the source.
zhello is the template of record: `make new-app NAME=myapp` stamps a new
application out of this package — same two files, same targets, your name —
and registers it in the gitignored `config/gui_apps.mk`, which is what puts
`make myapp`, `make myapp-selftest` and `make myapp-app` on the build. The
whole journey, with this host's measured latencies, is
[`docs/MACOS_GUI_QUICKSTART.md`](../../../../docs/MACOS_GUI_QUICKSTART.md).
On a macOS host nothing but the Apple command-line tools is needed:

```sh
cc -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
    -Icontexts/commons/packages/zhello/include -Ivendor/rgfw \
    contexts/commons/packages/zhello/src/zhello.c contexts/commons/packages/zhello/app/main.c \
    -framework Cocoa -framework CoreGraphics \
    -framework QuartzCore -framework CoreVideo -o zhello
```
