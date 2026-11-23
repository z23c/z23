<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# platform/modules/gui

A small C23 window and widget layer: one window presents either a **CPU
framebuffer** (wallet and ordinary UI) or a **GPU surface** (an OpenGL context
for games), with one event model. No C++, no toolkit, no JavaScript, no web
view. The node never links it (the Makefile filters this module out of
`LIB_SRCS`); `apps/z23wallet/` and the `gui` test group build it.

## Three public headers

| Header | What it holds |
| --- | --- |
| `gui/window.h` | windows, events (keyboard, mouse incl. relative mode, wheel, resize, DPI, focus, timers, wake), CPU and GL surfaces, clipboard, fullscreen, headless hooks and the script runner |
| `gui/draw.h` | XRGB8888 primitives, clip stack, UTF-8 helpers, Inter text (stb_truetype) with a bounded glyph cache |
| `gui/ui.h` | the widget tree, builder, layout, painting, input, theme, bound data |

## Backends

* **Win32** (`window_win32.c`): user32 + gdi32 only. Per-monitor DPI v2,
  `WM_CHAR` UTF-16 joined to scalars, zero idle CPU (`MsgWaitForMultipleObjectsEx`),
  `SetDIBitsToDevice` blits of dirty rectangles, UTF-16 clipboard, raw-input
  relative mouse, fullscreen. `window_win32_gl.c` creates a WGL context through
  `opengl32.dll` loaded at run time (a CPU-only program never loads it).
* **Headless** (`window_headless.c`): a memory framebuffer on a virtual clock,
  event injection and a line script (`size`, `scale`, `move`, `click`, `dclick`,
  `wheel`, `key`, `text`, `paste`, `wait`, `until-idle`, `shot`). Deterministic;
  what the land proof runs.
* **X11**: designed (dlopen `libX11`, XIM, selections) and landable alone as lane
  M1x; not in milestone 1. On Linux `--backend=auto` therefore fails with a clear
  message unless headless is requested.

## GPU surface and games (interface now, games later)

`gui_window_open` with `surface = GUI_SURFACE_GL` creates a hidden-or-visible
window with a WGL context (`gui_gl_make_current`, `gui_gl_swap`,
`gui_gl_set_swap_interval`, `gui_gl_proc`, `gui_gl_available`). A window is CPU or
GL for its life: GDI and GL are never mixed on one window. Milestone 1 proves
creation and clear on Windows with `platform/modules/gui/tests/gui_gl_windows_acceptance.c`
(prints `SKIP gui_gl_smoke: <reason>` and exits 0 where no GL exists).

How `apps/skycombat` moves over later (lane M7): add
`apps/skycombat/platform/rcore_desktop_z23.c`, which implements raylib's platform
contract over this layer (`InitPlatform` = `gui_window_open` GL 3.3 core plus
`rlLoadExtensions(gui_gl_proc)`, `PollInputEvents` drains `gui_window_wait(0)`,
`SwapScreenBuffer` = `gui_gl_swap`, `GetTime` = `gui_now_ns`, cursor and clipboard
and fullscreen forwarders, `DisableCursor` = `GUI_MOUSE_RELATIVE`, `SetTargetFPS`
= swap interval), one `#elif defined(PLATFORM_DESKTOP_Z23)` in `rcore.c`, and
`skycombat.mk` switches `-DPLATFORM_DESKTOP_RGFW` to `-DPLATFORM_DESKTOP_Z23`.
That replaces raylib's `src/platforms/rcore_desktop_rgfw.c` and its private RGFW
copy (`vendor/raylib/src/external/RGFW`), so window and input code lives only here.
Needed first: `wglCreateContextAttribsARB` (3.3 core), GLX/EGL, XInput and evdev
gamepads (`GUI_EV_GAMEPAD` is reserved, never emitted in M1).

## One document model, no scripting

`struct gui_tree` is THE document model. Screens are built in C against the
builder API today (`gui_box`, `gui_text`, `gui_button`, `gui_input`, `gui_table`,
`gui_progress`, `gui_dialog`, `gui_attr`, `gui_flag`); the tree it produces is
exactly what a later strict markup parser (`.zui`) would produce, checked by
comparing the canonical `gui_tree_dump` text. Decision:

* A small declarative, script-free markup is the right authoring format for
  agents; it is lane **M6a**: closed element and attribute vocabulary equal to
  the builder API, fixed style tokens (no CSS, no URLs, no expressions), bounded
  parsing (64 KiB, 1024 nodes, depth 16, attribute 256 bytes), an unknown
  element or attribute rejects the whole document with line:col, the parser does
  no I/O, and a script-free HTML exporter turns the same tree into HTML so there
  is one model for native rendering and export, not two.
* Behaviour is bound by action NAME. M1 to M5 resolve names through static C
  tables per screen. **M6b** lets confined Commons plugins (interface 2, `ui.panel`
  capability, `docs/commons/PLUGIN_APPS.md`) handle non-custody names with
  `{action, field values}` on stdin and a bounded reply that the M6a parser
  validates. Documents and plugins are untrusted input; no network, no file
  access except declared capabilities; custody actions (send, keys, backup,
  encrypt) are reserved names a plugin can never register.
* The explorer's `ui_present_document` / `zcl_present_model_v1` is NOT the base:
  it is inert, display-only and paginated into at most 16 bitmap pages with at
  most 4 fields and 4 actions and no retained interactive state. A later adapter
  can lower a `zcl_present_model_v1` into a `gui_tree`.

## Limits and honest gaps (milestone 1)

* Text coverage is Basic Latin (the vendored Inter subsets); other code points
  draw `?`. A later font lane adds a C23 subsetter. UI strings are ASCII.
* Reserved, not implemented: `GUI_QR` (M2), `GUI_TABS`, `GUI_MENU`, scrolling
  boxes, word-wise double-click selection (double-click selects all), IME
  composition, accessibility provider, light theme.
* `-ffp-contract=off` is required for byte-identical goldens; goldens are pinned
  on Linux x86_64. Pixel hashes are not asserted on Windows.
