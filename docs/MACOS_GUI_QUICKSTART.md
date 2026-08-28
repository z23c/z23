# macOS GUI quickstart

A fresh Mac, Apple's command-line tools, and nothing else: clone, scaffold a
graphical application, see your change on screen, and ship a `.app` that
another machine can rebuild byte for byte. No Xcode, no package manager, no
project file — the app is C23 you can read in one sitting, and the build is
`make`.

The template of record is [`packages/zhello`](../packages/zhello/README.md):
one native window, an animated canvas, and a headless selftest that proves the
frame code without a window. `make new-app` turns that shape into your own
application. Everything on this page is one pass through that journey.

| Step | Command | Section |
| --- | --- | --- |
| Install the one dependency | `xcode-select --install` | [What you need](#what-you-need) |
| Get and arm the checkout | `git clone … && make setup` | [Get the checkout](#get-the-checkout) |
| Create your app | `make new-app NAME=myapp` | [Scaffold it](#scaffold-it) |
| See it on screen | `make myapp` | [Run it](#run-it) |
| Prove it headless | `make myapp-selftest` | [Run it](#run-it) |
| Change something, see it again | edit, then `make myapp` | [Edit and see](#edit-and-see) |
| Ship a `.app` | `make myapp-app` | [Ship it](#ship-it) |
| Prove the `.app` reproduces | `tools/lint/check_app_bundle_reproducible.sh --bin …` | [Ship it](#ship-it) |

Commands are written `myapp`; substitute the name you chose.

## What you need

```bash
xcode-select --install
```

That is the whole list: Apple's Clang, linker, `make` and `codesign`. The
window layer is the vendored single-header
[`RGFW`](https://github.com/ColleagueRiley/RGFW) checkout under `vendor/rgfw/`,
which speaks Cocoa on this host; rendering is software RGBA, so there is no
Metal or OpenGL dependency and nothing to configure. Full Xcode, Homebrew,
Python and a Linux VM are all unnecessary — the project bans the last two
outright.

Confirm the host is what the page assumes:

```bash
clang --version          # Apple clang, arm64 or any current macOS target
uname -s                 # Darwin
```

## Get the checkout

```bash
git clone <your-fork-or-mirror>
cd z23
make setup
make doctor
```

`make setup` is idempotent: it arms the in-tree git hooks, writes
`compile_commands.json`, and creates the gitignored caches. `make doctor` names
anything this host is still missing with the exact line that installs it. A
second checkout of the same repository (a worktree) needs its gitignored
`vendor/` archives copied in before it can link — `tools/scripts/worktree_init.sh`
does that and tells you what is still missing; see
[Troubleshooting](#troubleshooting).

One honest cost lands here, before your first goal on a from-empty clone: the
build checks for the vendored archives under `vendor/lib/` and, missing them,
builds them from pinned sources before doing anything else. Your GUI app links
none of it — only Cocoa — but today's parse asks for it all the same, so the
first command on a new clone pays a one-time minutes-scale vendor build. Copy a
primed checkout's `vendor/` in first and the whole journey below is
seconds-scale instead; that is what `tools/scripts/worktree_init.sh` does for a
worktree.

## Scaffold it

```bash
make new-app NAME=myapp
```

The name becomes the package (`packages/myapp/`), the make targets, the C
symbol prefix and the header guard, so it must be a lowercase C identifier:
`^[a-z][a-z0-9_]*$`. The command finishes in well under a second and prints
the next three commands.

What it does:

- copies `packages/zhello` to `packages/myapp`, renaming `zhello` → `myapp` in
  the sources, the header guard, the log strings, the usage text and the README
  — your app *is* the template under its own name, not a fork of it;
- appends one registration block to `config/gui_apps.mk`, which the top-level
  `Makefile` `-include`s. That file is gitignored on purpose: a scaffolded app
  is your content, not tree content. Registering the app there *is* the whole
  build integration — the Makefile generates the `<name>`, `<name>-selftest`,
  `<name>-clean` and `<name>-app` targets from the list, so no manual Makefile
  edit exists to get wrong.

What it refuses: an existing package directory, a name that is already
registered, a name that would shadow a make target (`lint`, `clean`,
`install`, …), and `zhello` itself. Refusal is the idempotence: a half-written
scaffold is never left behind, because the tree is transformed in a staging
directory and moved into place only when complete.

## Run it

```bash
make myapp              # build, open a window, animate until Esc or close
make myapp MYAPP_ARGS=--seconds=2   # same, and exit by itself
make myapp-selftest     # headless: renders 120 frames, no window, exits 0
```

The windowed run's first log line is the number that matters — the moment your
code reached the screen:

```text
myapp 2026-08-28T03:25:49.986Z present frame 0 in 113.6 ms
    (window created 79.4 ms, first present 113.6 ms after launch)
```

`--frames=N` never calls the window system at all: it renders N frames, folds
each into a digest, and fails if the image stops moving or the canvas is not
opaque. That is the CI path, and it is what `make myapp-selftest` runs — a
machine with no WindowServer still proves the frame code runs.

## Edit and see

The loop is one command. Open `packages/<name>/src/<name>.c` — the painter,
two palette stops and a bouncing square, no windowing code — change something,
and re-run:

```bash
make myapp-selftest     # digest changes: the edit reached the pixels
make myapp              # see it on screen
```

Because a GUI app's parse is deliberately tiny (see
[Measured on one host](#measured-on-one-host)), the rebuild you wait for is the
recompile of one file, not a scan of a tree. The whole program is two
translation units: the painter, and the driver under `packages/<name>/app/`,
which owns the window and the selftest and is the only file that mentions the
windowing layer. Its shape is
[`packages/zhello/app/main.c`](../packages/zhello/app/main.c).

## Ship it

```bash
make myapp-app
open build/app-bundle/Myapp.app --args --seconds=2
```

`<name>-app` wraps the binary you just built in the minimal launchable macOS
bundle — `Contents/{MacOS/<exe>,Info.plist,PkgInfo}`, ad-hoc signed with the
timestamp server off, because arm64 macOS refuses to execute an unsigned binary
at all. The `.app` display name is the capitalized package name; set
`<name>_APP_TITLE` in `config/gui_apps.mk` to change it.

Reproducibility is a property you can check, not a claim you have to believe.
Two runs of the bundler over the same binary must produce byte-identical
trees, signature included:

```bash
tools/lint/check_app_bundle_reproducible.sh --bin build/bin/myapp \
    --probe-args '--frames=12 --quiet' --probe-expect 'selftest: OK frames=12'
```

The `--probe-expect` string is whatever your app prints on a successful
headless run; the bundled executable must print it and exit 0, which is also
the check that the signature actually launches rather than being killed by the
kernel. The same gate with no arguments proves the default subject; the lint
umbrella runs that form on every push
(`tools/lint/check_app_bundle_reproducible.sh`).

## Measured on one host

Wall times from one Apple Silicon Mac, one warm checkout, one commit in late
August 2026 — durations are per host and per commit, so re-measure rather than
quote them later. Each line is the `time` of exactly the command shown, run in
the order listed, on a checkout that already had its `vendor/` archives and its
compile cache warm (see [Get the checkout](#get-the-checkout) for the one-time
cost a from-empty clone pays before any of this).

| Journey step | Command | Wall |
| --- | --- | --- |
| Scaffold | `make new-app NAME=zdemo` | 0.3 s |
| First build, headless proof | `make zdemo-selftest` | 1.0 s |
| Re-run, nothing to rebuild | `make zdemo-selftest` | 0.3 s |
| Edit the painter, see it again | `make zdemo-selftest` | 1.0 s |
| Window on screen, 2 s auto-exit | `make zdemo ZDEMO_ARGS=--seconds=2` | 2.2 s, first pixel ~110 ms in |
| Bundle it | `make zdemo-app` | 0.3 s |
| Launch the bundled binary | `…/Zdemo.app/Contents/MacOS/zdemo --frames=60` | 0.4 s |
| Launch from the Dock/Finder | `open build/app-bundle/Zdemo.app --args --seconds=2` | returns immediately; app self-exits |
| Prove the bundle reproduces | `check_app_bundle_reproducible.sh --bin …` | 1.0 s |
| Template still green | `make zhello-selftest` | 0.4 s |

Read the table as: the work that is yours — scaffold, build, see, ship — is
under two seconds; everything else on a line is your app running. The step the
table leaves out is the from-empty-clone vendor build described above, and a
second checkout skips it with a copy.

Two numbers explain why the loop feels the way it does, both measured with
`make -n` (parse only, nothing built):

| Parse | Goal | Wall |
| --- | --- | --- |
| Lean parse (the set a GUI app belongs to) | `make -n zdemo-selftest` | 0.2 s |
| Full authoritative parse (the node, the tests) | `make -n dev-bin` | 11 s |

The lean set exists for goals that build and stamp nothing whole-tree, and the
generated GUI targets are in it on purpose: an app that is two compiles and a
link should not pay for a scan it cannot consume. A goal that is *not* in the
set — or a first run on a cold checkout, which also bootstraps the in-tree
compile cache and generated view headers — costs seconds more; that is the
tree being thorough, not the scaffold being slow.

## Troubleshooting

**`make myapp` prints `No rule to make target 'myapp'`.** The app is not
registered. Check that `config/gui_apps.mk` contains `GUI_APPS += myapp` —
`make new-app` writes it, a hand-edit or a sync that dropped the gitignored
file removes it. Re-run `make new-app NAME=myapp`; it refuses to overwrite your
sources, but it does not re-register either, so add the line by hand or delete
`packages/myapp` and scaffold again.

**The parse takes ~11 s for every command.** Your goal fell out of the lean
set, so make is doing the authoritative parse: it captures the whole-tree
source identity, probes pkg-config, and imports four object depfile graphs.
Building a GUI app should not do that — check the goal spelling (`myapp`,
`myapp-selftest`, `myapp-app`, `build/bin/myapp`) and that
`config/gui_apps.mk` registers the app, which is what puts the generated
targets in the lean set.

**A second checkout fails to link, or `make` restarts itself complaining about
missing `vendor/lib`.** Git carries only `vendor/lib/libsecp256k1.a`; every
other archive and the generated OpenSSL/zlib headers under `vendor/include/`
are build products of `make vendor`. In a fresh worktree run
`tools/scripts/worktree_init.sh`, which copies the archives from the checkout
that built them and names anything still missing; failing that,
`cp -a <primed-checkout>/vendor/include vendor/` and
`cp -a <primed-checkout>/vendor/lib vendor/`, or `make vendor` to build from
pinned sources. GUI apps themselves need no vendor archive — they link against
Cocoa — but the parse that reaches them checks.

**Test runs die with a stack-size error, or ASan aborts at startup.** The test
runners set a large *finite* stack (1 GiB) rather than `ulimit -s unlimited`,
because ASan with an unlimited stack intermittently aborts at startup
(google/sanitizers#856). Run tests through `make t-fast ONLY=<group>` and
`make test-parallel`, which set it for you; see [`BUILD.md`](BUILD.md).

**Your new file trips the file-size ceiling.** The enforced ceiling is on
`app/**/*.c` (800 lines); a GUI package's sources live under `packages/`, so
they are outside it, but the discipline is the same one rule everywhere: a
file that wants to grow past that is two files. See
[`DEFENSIVE_CODING.md`](DEFENSIVE_CODING.md) for the ratchet and its baseline.

**`The application can't be opened` on another Mac, or after a download.**
arm64 macOS refuses unsigned binaries, and a file that arrived over the
network carries a quarantine attribute the signature does not remove. Rebuild
the bundle on that machine (`make myapp-app`) or clear the attribute with
`xattr -dr com.apple.quarantine Myapp.app`; the ad-hoc signature is what makes
the bundle runnable, not what makes it trusted.

**You edited `packages/zhello` to make your app and now `make zhello-selftest`
fails.** Put it back: zhello is the template of record, the reference every
new app is stamped from, and its selftest is the proof that the template still
works. `git checkout -- packages/zhello`, then scaffold.
