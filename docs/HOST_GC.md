# Host garbage collector

`tools/scripts/host_gc.sh` reclaims disk space on a maintainer host that runs
many lane/unit/train worktrees, dev-proof generations, and compiler caches.
It is DRY-RUN by default: nothing is removed, moved, or killed unless invoked
with `--apply`.

```
tools/scripts/host_gc.sh              # dry run, every category
tools/scripts/host_gc.sh --status     # one screen of host hygiene facts
tools/scripts/host_gc.sh --only zcc   # dry run, one category
tools/scripts/host_gc.sh --apply      # actually reclaim
```

## Installing the hourly sweep

`host_gc.sh` reads `worktree_gc.sh` from its own directory at run time, so
the two scripts must live side by side wherever the timer invokes them from
— and never inside a checkout, because a `git worktree remove` or a lane
teardown can delete the very file the timer is mid-execution on.
`tools/scripts/install_host_gc.sh` copies both scripts to
`~/.local/lib/z23/tools/` and writes `zclassic23-host-gc.timer` /
`.service` into `~/.config/systemd/user/`, pointed at the installed copy,
running hourly at a fixed offset with jitter. It only writes under those two
directories and reloads the user systemd manager; it never touches a
datadir, a checkout, or a live node, and rerunning it just rewrites the same
install.

This lane never runs the installer — installing units or reloading systemd
on the host that built this change is out of scope for a worktree lane and
is left to whoever lands it.

## Categories

Each category is independently selectable with `--only <name>`:

| category   | what it reaps |
|------------|----------------|
| `ccache`   | trims the C compiler cache to its configured cap |
| `zcc`      | trims the zcc compile cache to its configured cap; if no evictor binary can be found (checked at `ZCL_HOST_GC_ZCC_BIN`, on `PATH`, and at the installed copy) it names every path it tried instead of silently skipping |
| `z23p`     | reaps dead dev-proof generations. A generation whose own lock/pid marker names a process that is still alive is kept regardless of age; one whose marker names a dead pid is reaped regardless of age; anything else follows the age floor |
| `tmp`      | registered worktrees found under `/tmp` via `git worktree list` |
| `tmplitter`| unregistered `/tmp` entries with no worktree behind them at all — throwaway test fixtures `tmp`'s worktree-list walk never sees |
| `journal`  | vacuums the user journal; prints (never runs) the root-owned system journal command |
| `binbak`   | quarantines aged `~/bin/*.bak-*` |
| `testtmp`  | stale test scratch left inside an otherwise-idle worktree |
| `orphan`   | warns about parentless processes whose checkout was deleted |
| `deadexec` | warns about user systemd units whose `ExecStart` is missing or points inside a `build/` tree |
| `worktree` | merged+clean named worktrees, delegated to `worktree_gc.sh --apply` |
| `units`    | worktrees under `~/.z23/units` and `~/.z23/lanes` (and, via the same rule, landed trains under `~/.z23/trains` other than the newest) that are **patch-equivalent** to `main` — see below |
| `scratch`  | dated/named scratch dirs under the scratch root with no owning worktree left; `.gc_keep` (one basename per line) pins a dir open-endedly |
| `pressure` | not a sweep — reports free-space percentage and, below the low floor, halves every age floor above for this run; below the critical floor also lists the largest directories under `$GC_HOME` |

### Why `units` uses `git cherry`, not ancestry

`worktree_gc.sh` already reaps a merged, clean, named worktree by asking git
whether its HEAD is an **ancestor** of `main`. That question has the wrong
answer for every worktree this project actually lands through: a unit or
lane's commits are cherry-picked (`-x`) into a train, so the worktree's HEAD
is never an ancestor of `main` even after the identical patch has landed.
`git cherry main HEAD` asks the right question instead — it compares patch
IDs, not commit identity, so a cherry-picked HEAD reads as fully applied
(no `+` line) exactly like a fast-forward merge would. A worktree is only
reaped once it is also idle long enough, unlocked, not the current
directory of any live process, clean, has no `refs/review/<name>` left, and
— for `git cherry` to answer at all — carries no unlanded (`+`) commits.

### Fixture mode

Every host-global path and external binary `host_gc.sh` reads is indirected
through a `ZCL_HOST_GC_*` environment variable (see
`engine/composition/flags.def` for the full, closed list). That is what lets
`tools/scripts/host_gc_selftest.sh` exercise every category — including
`--apply` — against a throwaway fixture tree under `./test-tmp` and never
against `$HOME`, the real `/proc`, or the real checkout. Run it directly, or
via `make check-host-gc-selftest`.

## Safety rules

- Every destructive helper calls `is_protected()`/`refuse_if_protected()` on
  the exact, `realpath -m`-resolved path immediately before acting on it —
  after classification, so a bug in a classifier cannot reach a protected
  tree. Protected trees include `~/.zclassic*`, `~/.zcash-params`, `~/.ssh`,
  `~/.config/zclassic23`, wallet backups, the checkout itself, and the
  sweep's own state/quarantine directory.
- Nothing destructive is unrecoverable in one step: most categories move
  content into a dated quarantine directory (`~/.local/state/server-cleanup/
  quarantine/<date>/<category>/`) rather than deleting outright, and
  quarantine itself only expires after its own TTL.
- `--check-protected <path>` answers the protection predicate directly and
  exits, so a gate can assert the guarantee against the actual predicate
  rather than grepping the source for tree names.
