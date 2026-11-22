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
`~/.local/lib/z23/tools/` and writes `z23-host-gc.timer` /
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
| `units`    | worktrees under `~/.z23/units` and `~/.z23/lanes` (and, via the same rule, landed trains under `~/.z23/trains` other than the newest) that are **patch-equivalent** to `main` — see below. It then hands the lane roots (`ZCL_HOST_GC_LANE_ROOTS`, colon-separated, default `~/.z23/units`, `~/.z23/lanes` and `~/development/lanes/z23`; missing roots skipped quietly) to `z23 ops host gc` with `age_days` from `ZCL_HOST_GC_LANE_AGE_D` (7, halved under low disk, never 0), so every clean lane idle that long is removed and a branch lane keeps its branch. Bytes are counted under `units`; one `lanes:` line reports reapable, idle branch lanes (branches kept), too young, in use and need review. A clean lane on a branch is reapable once its index and build output have both been idle `age_days` and everything git ignores in it is disposable build output; a lane with uncommitted work, a half-done git operation or unreadable occupancy is kept. The main checkout, the land queue trees and proof pools are not default roots, and a configured root that holds or sits inside the main checkout or the state trees is dropped by name. With no `z23` that has the `ops host gc` verb the sweep prints `SKIP lanes:` and nothing else changes. `ZCL_HOST_GC_PROC` (procfs fixture) is honoured from the environment only, never request input |
| `scratch`  | dated/named scratch dirs with no owning worktree left, under two roots: the state scratch root and the per-project development-scratch root devbuild and lanes use (`~/.cache/development-scratch/z23`, `ZCL_HOST_GC_DEVSCRATCH_DIR`, empty disables). Same rules on both: older than `ZCL_HOST_GC_SCRATCH_MIN_AGE_D` (7 d, halved under low disk), not pinned in `<root>/.gc_keep` (one basename per line), no process cwd or open fd inside, not a registered git worktree, nothing written inside within the age floor. `land-inbox` and `quarantine` are never swept, and `development-builds` is not a scratch root (its own 1-day policy and job locks). Quarantined by rename, reaped later by the quarantine TTL |
| `ramscratch` | the test runner's tmpfs scratch root (`/dev/shm/z23-scratch`, `ZCL_HOST_GC_RAM_SCRATCH_DIR`, empty disables). The runner removes `<hash>.<rand>` only after a green run, keeps it on purpose after a failure, and a killed run never gets to; nothing else bounds it, and on 2026-11-22 it held 47 GB and 100% of the tmpfs (273 entries older than a day), failing every tmpfs-using test with "No space left on device". Same live-use rules as `scratch` (no process cwd or open fd inside, nothing written inside within the age floor, `.gc_keep` honoured), one extra: only direct children that are real directories. Age floor `ZCL_HOST_GC_RAM_SCRATCH_MIN_AGE_H` (6 h, matching `z23p`: outlasts any run plus its triage, far shorter than disk's days because RAM is the scarcer resource), halved when the **tmpfs itself** is under the pressure floor (measured on the root, not on `$GC_HOME`). **Deleted in place, never quarantined** (a quarantine on RAM would only move the pressure): owner write permission is restored inside each entry (`chmod -R u+w`, which skips symlinks met in the tree) before `rm -rf`, which never follows a link out of the entry. The root must be an absolute path with no symlink in it, on a `tmpfs` or `ramfs` mount per `$ZCL_HOST_GC_PROC/mounts`, else the sweep names the refusal and does nothing |
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

### What the native sweep removes

`z23 ops host gc` removes only clean worktrees and pins unique commits first;
dirty worktrees are listed, never removed.

A worktree is clean when `git status --porcelain --untracked-files=all` is
empty, so untracked files and untracked nested repositories count as dirty.
A clean detached worktree whose HEAD is held by a `refs/remotes/origin/*` or
`refs/archive/*` ref is removed once it is older than `floor_hours`. A clean
detached worktree whose HEAD is held by no such ref is removed only when
`age_days` (default 7, `0` keeps it) is set and its gitdir `index` (or `HEAD`)
is that old, and only after `refs/archive/wt/<name>` was created and read back;
if that fails it stays and counts as `kept_on_failure`. `<name>` is the path
below `$HOME` with every character outside `[A-Za-z0-9_-]` replaced by `_` and
leading `_` removed; a name already bound to another commit gets a `-<n>`
suffix. Ignored files are build output by repository policy and go with the
worktree.

A clean worktree on a branch (not detached) is removed when `age_days` is set
and both its gitdir `index` (or `HEAD`) and its build output (`build/`,
`build/bin`, `test-tmp/`) are that old; the branch is left untouched and
counts as `branch_kept`. Recover it with `git worktree add <dir> <branch>`.
A younger one, or one whose build output changed more recently, is
`too_young`.

Such a lane is kept for review instead when:

- anything git ignores in it is not reproducible output. Only `build/`,
  `test-tmp/`, `.cache/`, `.codeindex/`, `.zcl_test_render/` and `vendor/`
  go with a lane; a local database, a `.zvcs/` commit log, an env or key
  file, or any other ignored path keeps it;
- another registered worktree sits inside it;
- its gitdir holds a half-done rebase, merge, cherry-pick, revert, bisect or
  sequencer run, a sparse-checkout file or `refs/worktree` refs;
- a tracked file carries an `assume-unchanged` or `skip-worktree` index
  flag, which can hide an edit from `git status`;
- its branch is unborn, or `age_days` is `0`.

A branch lane does not need the whole process inventory. Every process the
sweeping user can read is read, and none may be inside the lane,
but a listed process that cannot be read (a kernel thread, a root daemon, the
privileged half of an ssh or gpg session) does not hold it: nothing is lost
when such a lane goes, and it only became eligible after a week idle. Every
other removal still needs the whole inventory, and a process listing that
itself failed refuses branch lanes too. Without this rule a non-root timer
refused every lane on a host with one ssh session.

The content checks run when the lane is classified and again immediately
before it is removed; a lane that changed in between is kept and named in
`refusals` as `changed_since_classified`. The build clock is a hint beside
the index clock: a directory mtime moves only when an entry is added,
removed or replaced in it. A separate clone placed inside one of the
disposable directories is not detected.

Not preserved: the worktree's own reflog, `config.worktree`, and the gitdir
of a submodule checked out inside it. A disposable pool keeps its old rule:
a copy on a branch there is never removed.

The land receiver pool (`<state root>/land-remote`, one detached copy per lane
from `dev land receive`) is added to the verb's default pools whenever it
exists. It has no sibling lock and no process open on it, so the queue decides:
a copy is kept as `locked` while a queued or inflight land row has the copy's
HEAD as its tip; a terminal row (landed, failed, conflict, fenced, cancelled)
no longer holds it, and an unreadable queue or HEAD holds every copy. The usual
floor, process, age and unique-HEAD rules then apply: a copy is removed only
after `floor_hours` (default 6, above the longest queued-to-landed time in
the landing ledger, 4.0 h of 2497 landings) and, because its HEAD is
unlanded or rebased, after `age_days` idle, pinned under `refs/archive/wt`
first. Explicit `roots` replace the defaults and do not add this pool.

A dirty worktree is reported under `needs_review` as `{path, idle_days,
dirty_count}`. A worktree is also kept when it is locked, in use by a live
process, a warm donor, or named by a systemd user unit file
(`~/.config/systemd/user/*.service|.timer|.path`; `%h`, `~`, `$HOME` and
`${HOME}` are expanded before matching; drop-ins are not read). If the unit
files cannot be read whole, nothing is removed.

```
z23 ops host gc --apply=false
z23 ops host gc --input="{\"roots\":[\"$HOME/.z23/lanes\"],\"age_days\":14,\"apply\":false}"
z23 ops host gc --age_days=0 --apply=false          # unique commits are kept
```

Recover a pinned worktree with `git worktree add <dir> refs/archive/wt/<name>`.

### Where the logic lives

`host_gc.sh` is the authoritative whole-host sweep: it is what the hourly
unit runs, and it delegates the tmpfs proof pool and the lane roots to the
native `ops.host.gc` engine in `tools/command/host_gc_sweep.c`. The worktree
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

## Inactive compile epochs in one checkout

On Linux, the installed `z23` can inspect generated epochs without starting a build. Give
an absolute, canonical checkout path; this mode only examines that checkout's
known build profiles. It leaves current, leased and uncertain epochs alone.
First inspect the dry-run report:

```sh
z23 ops host gc --checkout="$PWD" --epoch_keep=1
```

`epoch_keep` defaults to 3; 1 retains the current generation and protected
ones. After reviewing the report, use the same command with `--apply=true` to
reclaim eligible generated epochs. `estimated_logical_path_bytes` counts path sizes, not
physical blocks saved (hardlinks may share blocks). A nonzero
`profiles_refused` or `partial_possible` means cleanup could not be completed;
inspect the checkout and rerun after resolving the condition. Interrupted
retirements are kept as `.gc-...` plus a producer-session marker for retry.

The report's `producer_compatible` describes the producer script currently in
that checkout. If false, the report is preview-only and apply refuses: upgrade
the checkout before reclaiming its epochs. The protocol marker identifies a
cooperating producer; it is not an authentication or trust assertion.
