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
| `z23p`     | reaps dead dev-proof generations on the disk pool **and on its tmpfs twin** (`/dev/shm/z23p`, or `ZCL_HOST_GC_RAM_ROOT`), the twin through `z23 ops host gc` when a binary is available and through the same classifier when none is. A generation whose own lock/pid marker names a process that is still alive is kept regardless of age; one whose marker names a dead pid is reaped regardless of age; anything else follows the age floor |
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
| `wtbuild`  | `build/` output inside every idle registered worktree (no process inside, nothing under `build/` changed for `--wt-build-idle-h=N`, default 12 h, 2 h below the low-disk floor), plus that worktree's idle `test-tmp/`. Deleted, not quarantined — build output is reproducible. Kept: `scratch`, `handoff`, `devverify`, `clang-facts`, any name containing `stopwatch`, `acceptance`, `evidence` or `receipt`, hidden build state, and a `build/bin` any user unit's `ExecStart` points into (all of `bin` when the unit list cannot be read) |
| `landtmp`  | the landing worktree's `test-tmp/` children, only when `queue.jsonl` is empty, `step.lock` is free (held by the sweep for the removal itself), and no process is inside the landing worktree; otherwise a named `SKIP` |
| `landed`   | clean (submodules included), fully landed (`git cherry` against `origin/main`), unlocked, idle > 24 h registered worktrees outside the units/lanes/trains/landing directories. **Opt-in**: reported only, unless `--reap-landed-worktrees`; each removal first appends path, commit and branch to `landed_worktrees.tsv` in the state directory |
| `lowdisk`  | not a sweep — below the low-disk floor after a full run, posts one `problem` row to the dev agent mail leaf (`--ref=host-gc`) naming the five largest directories two levels under `$HOME` (bounded `du`, datadirs never walked; `/` written as `>` so the body carries no path), at most once per 6 h |

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

### Proof pools and warm donors

`tools/dev/dev_proof.c` creates a proof pool beside every checkout it
proves from (`<checkout parent>/.z23p`), so lanes, the landing worktree and
scratch checkouts each grow their own. `z23p` sweeps the default pool, its
tmpfs twin, and every other `.z23p` pool that `git worktree list` names.

In each pool the newest idle generation carrying
`build/.proof-build-complete` is kept per build identity (the marker's
`root`, `compiler`, `flags`, `environment` and `build_graph`), at most two
per pool, newest first: it is the warm donor the next proof of that
identity seeds its build from. The native engine (`z23 ops host gc`)
applies the same rule and counts a kept donor as `in_use`. Every other
generation is classified as before.

### Where the logic lives

`host_gc.sh` is the authoritative whole-host sweep: it is what the hourly
unit runs, and it delegates only the tmpfs proof pool to the native
`ops.host.gc` engine in `tools/command/host_gc_sweep.c`. The worktree
build, landing scratch, landed-worktree and low-disk categories are host
janitor glue over files, git and `/proc`, so they live in the script next
to the categories they share helpers with. Their knobs are command-line
options (`--wt-build-idle-h=N`, `--reap-landed-worktrees`) rather than new
`ZCL_HOST_GC_*` variables, and the landing state directory and the
`z23-dev` binary are derived from the existing home and `z23` seams.

### Fixture mode

Every host-global path and external binary `host_gc.sh` reads is indirected
through a `ZCL_HOST_GC_*` environment variable (see
`engine/composition/flags.def` for the full, closed list). That is what lets
`tools/scripts/host_gc_selftest.sh` exercise every category — including
`--apply` — against a throwaway fixture tree under `./test-tmp` and never
against `$HOME`, the real `/proc`, or the real checkout. Free space is
injected through a `df` stub, and `systemctl` and `z23-dev` are stubs too,
so no verdict depends on the state of the machine running it and no run can
post real mail. Run it directly, or via `make check-host-gc-selftest`.

## Safety rules

- Every destructive helper calls `is_protected()`/`refuse_if_protected()` on
  the exact, `realpath -m`-resolved path immediately before acting on it —
  after classification, so a bug in a classifier cannot reach a protected
  tree. Protected trees include `~/.zclassic*`, `~/.zcash-params`, `~/.ssh`,
  `~/.config/zclassic23`, wallet backups, the checkout itself, the sweep's
  own state/quarantine directory, QEDC trees (`github/qedc*`, `.qedc`,
  `qedc-lanes`), and other sessions' `/tmp/claude-*` directories.
- Nothing destructive is unrecoverable in one step: most categories move
  content into a dated quarantine directory (`~/.local/state/server-cleanup/
  quarantine/<date>/<category>/`) rather than deleting outright, and
  quarantine itself only expires after its own TTL.
- `--check-protected <path>` answers the protection predicate directly and
  exits, so a gate can assert the guarantee against the actual predicate
  rather than grepping the source for tree names.
