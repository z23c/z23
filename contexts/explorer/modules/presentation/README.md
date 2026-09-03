# libzclpresentation

`contexts/explorer/modules/presentation` is the reusable C23 native-window layer for ZClassic23.
It accepts one bounded, tightly packed RGB/RGBA bitmap and presents it through
the operating system's native window surface. QR deposits are the first
consumer; charts, Metaverse property views, and reviewed ZCode/App output can
render into the same pixel contract without acquiring wallet, network,
filesystem, or process-launch authority.

The stable window surface is `include/presentation/presentation.h`. The
renderer-neutral agent surface is
`contexts/explorer/modules/presentation/include/presentation/model.h`: a closed,
bounded document for status, tables, progress, charts, timelines, code diffs,
evidence graphs, choices, confirmations, forms, canvases, and QR cards. Its
wire format carries inert text, fractions, graph edges, exact-root labels, and
bounded action IDs—never callbacks, executable names, paths, sockets, wallet
objects, or native handles. A returned action is only an observation; the full
node must independently recheck its root and policy before acting.

Models larger than one fixed viewport are deterministically partitioned into
at most 16 pre-rendered pages. Page Up/Down, arrow keys, Home/End, and the mouse
wheel select among those inert bitmaps inside the display host; pagination is
local visual state and never becomes a software-authority event. The fixed
layout makes the same bounded item sequence produce the same page count and
pixels independently of window size, while aspect-fit scaling and clipping
remain backend concerns.

Chart points are real bounded fractions, not decorative labels:
`numerator/denominator` must be valid and the native compositor draws that
exact proportion. The deterministic text companion emits the same fraction,
so a visual bar and its accessible/exported form cannot disagree.
Timeline events render on one deterministic vertical sequence, with each
event's existing semantic status providing its visible marker color. Event
labels and values remain inert model text and are preserved verbatim in the
plain-text companion.
Evidence-graph nodes may refer only to an earlier graph node in the same
bounded model. The compositor derives indentation and connectors from that
closed parent chain; forward references, cycles, and non-node parents fail
before pixels or input events exist. The text companion names the same exact
one-based parent item.

A choice instrument contains one to four radio-style rows and exactly the same
number of `select` actions. Each row ID must equal the action ID at the same
index, so the visible numbered option and returned bounded action cannot drift.
At most one row may describe the initial selection. The event remains an inert
ID; the full node independently rechecks every fact and policy before acting.

A form instrument contains one to four uniquely identified fields and exactly
two actions in the safe order `Cancel`, then `Submit`. Printable Basic Latin is
edited directly in the native window; Tab traverses editable fields and then
the two visibly focused actions. Required empty fields keep Submit local and
visibly invalid, while read-only values cannot receive focus or change. Only a
successful Submit returns the ordered ID/value pairs. The caller independently
revalidates that the nonce-bound returned model differs from the opening model
only in editable values before exposing them to the full node. The host still
executes nothing and owns no authority.

A canvas instrument is one bounded 2D placement decision, not an arbitrary
drawing or callback surface. It contains one editable selected point and up to
three immutable reference points, all expressed as renderer-neutral thousandths
from `(0,0)` through `(1000,1000)`. Mouse clicks or arrow keys move only the
orange point; Shift+arrow makes one-unit adjustments. Tab reaches harmless
Cancel before explicit Submit. The host returns only that point's ID and exact
normalized coordinates, and the caller rejects any change to reference points,
labels, actions, roots, or other model bytes.

`contexts/explorer/views/src/ui_present_document.c` is the only model-to-window compositor.
It owns validation, every rendered page, QR specialization, application icon,
window title, exact copy text, and action count for the duration of one native
call. The resident host and the portable same-binary compatibility child both
consume that exact document, so neither launch path can silently drop later
pages or invent separate QR, branding, or action behavior.

Action-only interactive models always open with one visible two-tone action
focus ring. Tab and Shift-Tab wrap through the bounded action row; Enter or
Space returns the focused action, while number keys retain direct exact
selection. Forms instead open on their first editable field and traverse fields
before actions. Moving focus is display-local state and never returns an action
or grants authority.
Canvases open on the editable point, then traverse Cancel and Submit using the
same safe focus order.
Canonical publication confirmations place `Cancel - make no change` at index
zero, so the initial focus and a bare Enter are harmless; confirmation requires
one deliberate focus move or the visibly numbered second action.

The companion `include/presentation/canvas.h` is a bounded caller-owned RGB canvas
with clipped rectangles, lines, alpha logo blits, and embedded Basic Latin
text. It is the reusable layer for deposit cards, current balances, metadata,
and small software-rendered graphs. RGFW is a private implementation detail,
pinned under `vendor/rgfw`; callers never include its header. The backend uses
Win32 on Windows, Cocoa on macOS, and dynamically loaded X11 on Linux. Those are
OS/desktop APIs, not application dependencies. Rendering is software-only and
does not require OpenGL, GTK, Qt, libqrencode, Python, or a browser.

An opt-in caller-rendered copy control maps through the same aspect-fit
geometry as chart hover input. Clicking it or pressing `C` encodes the current
source bitmap as a 24-bit BMP entirely in memory, writes the native image
clipboard, and leaves the window open. Success changes both the button pixels
and title immediately. The bounded encoder can also report or fill the exact
BMP byte count in a caller-owned buffer without touching a file or clipboard.

The full binary's resident boundary is
`contexts/explorer/views/src/ui_present_host.c`. On Linux it binds a mode-0600 filesystem
AF_UNIX endpoint inside a validated mode-0700 per-user runtime directory,
accepts only same-UID peers, binds every reply to a fresh 128-bit request
nonce, and forks disposable window workers from one warm same-binary parent.
It never opens the canonical datadir. QR cards and renderer-neutral models share this transport without
changing their separate deterministic compositors. The first software blit is
acknowledged separately from a later numbered action/dismissal event.
One 16-slot table owns every display-only and interactive worker. Capacity
exhaustion is a named refusal on Linux; it cannot escape into the detached
cold launcher. An unresolved interactive request ID is busy and cannot be
replaced by a display update, so the original exact decision channel remains
intact.
Non-interactive models with the same bounded request ID replace only their
prior display worker, so an agent can publish live reproduction/progress
frames without accumulating windows or putting authority in the visual
process. The replacement worker renders first, then the host retires the old
owned worker before acknowledging the new frame. This keeps display-server
teardown outside the new window's creation path without acknowledging while a
stale prior frame remains. Child ownership is reaped before replacement,
preventing PID reuse from redirecting the replacement signal. Linux display
workers also bind a
parent-death signal before creating a window, so a crashed resident host cannot
leave orphan instruments behind; the authoritative caller can resubmit the
same exact request ID and latest inert progress frame to a fresh host. The event
carries no authority: the calling
node or agent command must recheck the exact root, authentication, capability,
local policy, and plan/commit state. This early-dispatch host code path opens
no Internet socket or canonical datadir and calls no wallet, package execution,
publication, deployment, or consensus surface. Other desktop platforms retain
the existing same-binary native cold path while the
resident transport is ported; the renderer/model library itself remains
cross-linked on Linux, Windows, and macOS.

The canvas embeds a Basic-Latin-only Noto Sans subset (SIL OFL 1.1) and uses a
pinned stb_truetype snapshot (MIT/public domain) for antialiased software text.
Both are source-controlled under `vendor/typography`; neither adds a runtime or
system dependency.

The library and example build with:

```sh
make presentation-lib
make presentation-demo
make presentation-relaunch
make presentation-desktop-install   # Linux, per-user application identity
make presentation-portability
```

`presentation-relaunch` is the visual edit loop: it incrementally rebuilds
only stale package objects, replaces the prior demo window, and returns to the
developer immediately. Whole-node LTO and the full test suite remain release
gates, not per-pixel iteration steps.

Linux task managers associate the stable
`org.zclassic.ZClassic23` `WM_CLASS` with the packaged desktop entry and SVG.
The install target publishes those two files to the operator's per-user data
directory; it is not a runtime dependency and the presentation ABI itself does
not gain filesystem access.

`presentation-portability` performs strict native compilation and, when the
installed MinGW compiler is present, a strict Windows cross-link. Hosted
portability CI repeats the link on Linux, Windows, and macOS.

ZCode boundary: audited built-ins such as Metaverse may call this library
directly. Fetched/third-party ZCode remains out-of-process by project policy;
its future broker may translate an explicitly granted local-presentation
capability into this ABI, but packages do not receive RGFW, process launch, or
raw desktop handles.
