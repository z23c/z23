/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: host garbage collection over dev-proof/lane WORKTREE POOLS, as a
 *          transport-neutral engine the ops.host.gc leaf projects into JSON.
 *
 * WHAT A POOL IS. A pool is one directory whose immediate children are
 * `git worktree add`-registered worktrees of a single repository — the
 * dev-proof generation pools built by tools/dev/dev_proof.c (the disk pool
 * under <checkout parent>/.z23p and its tmpfs twin under
 * platform_ram_scratch_root()/z23p). Nothing else is a pool, and nothing
 * outside a pool is ever a removal candidate.
 *
 * THE DELETION PATH IS TWO STEPS, and the first is `git worktree remove
 * --force` executed by git itself through the spawn seam (util/spawn.h):
 * git refuses a path that is not a registered worktree of the repo it is
 * asked about, so a classifier bug cannot reach an arbitrary directory.
 *
 * Git alone is not enough. It unregisters the worktree whether or not it
 * managed to delete the directory, and one read-only directory inside a
 * dead generation is enough to stop the delete. What is left is a tree
 * git no longer lists — invisible to every later sweep, and on the tmpfs
 * pool a permanent RAM leak. So when the directory is still there after
 * git returns, the engine finishes the removal itself through the one
 * shared tree walker (util/file_tree_ops.h), and only after re-proving
 * BOTH of the things git was relied on for: the path is still strictly
 * under this pool's own root, and it is still not a protected path. Read
 * those two re-checks as the load-bearing safety property of the file.
 * A directory that still cannot be removed is named in refusals[] with the
 * errno text; an unregistered directory is never left unnamed.
 *
 * A CANDIDATE IS KEPT, never removed, when ANY of these holds — the reason
 * is reported per class so an operator can see WHY nothing moved:
 *   locked       git itself was told to keep it (`git worktree lock`)
 *   in_use       the directory, or something under it, is a live process's
 *                cwd or an open file descriptor's target
 *   too_young    its mtime is younger than the age floor
 *   need_review  git says it carries a branch or uncommitted content; a dirty
 *                worktree (untracked files and nested repositories included)
 *                is listed in report->reviews and never removed
 *
 * A clean detached worktree whose HEAD no refs/remotes/origin or refs/archive
 * ref holds is removed only with age_days > 0 and an index idle that long, and
 * only after refs/archive/wt/<name> was created and read back. A systemd user
 * unit file naming a worktree (absolute, %h, ~ or $HOME) keeps it as in_use;
 * unit files that cannot be read whole keep every worktree.
 * The lock and in-use tests run BEFORE the age floor deliberately: all four
 * are keeps, and an operator reading "in use" learns more than "too young".
 *
 * DISPOSABLE POOLS. A pool the caller marks `disposable` (an explicit roots
 * entry only; no default pool is) holds remote-gate lane copies, which are
 * build outputs of commits that live elsewhere. There a dirty worktree is
 * classified by idle time like a clean one (its dirty_count is still
 * reported); a copy whose sibling flock <path>.lock another process holds is
 * kept as `locked`, and the removal itself runs holding that flock; an
 * unregistered directory with the gate-copy shape (a .git FILE naming a
 * worktree administrative directory that is gone, plus a sibling .lock) is
 * `orphaned`, counted in `registered`, and removed under the same rules; and
 * <path>.bundle, <path>.prime.log and <path>.lock are unlinked with the copy
 * (regular files only, never through a symlink). Locks, in-use, protected
 * paths and unique-HEAD archive pinning are unchanged.
 *
 * REFUSALS ARE NAMED. A protected path (a canonical datadir by name, a
 * directory that actually holds chain data, the checkout itself, $HOME, /)
 * is never swept and never silently skipped: it is refused by name into
 * report->refusals with the reason that fired. Fail closed.
 */

#ifndef ZCL_TOOLS_HOST_GC_SWEEP_H
#define ZCL_TOOLS_HOST_GC_SWEEP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    HOST_GC_PATH_CAP = 512,
    HOST_GC_NAME_CAP = 32,
    HOST_GC_REASON_CAP = 48,
    HOST_GC_MAX_POOLS = 8,
    HOST_GC_MAX_REFUSALS = 32,
    HOST_GC_MAX_CANDIDATES = 512,
    HOST_GC_DEFAULT_FLOOR_HOURS = 6,
    HOST_GC_DEFAULT_AGE_DAYS = 7,
    HOST_GC_MAX_REVIEWS = 64
};

/* One pool the caller asked to sweep. `name` is the class label carried in
 * the report; `path` is the pool directory. */
struct host_gc_pool {
    char name[HOST_GC_NAME_CAP];
    char path[HOST_GC_PATH_CAP];
    bool disposable;   /* gate-copy pool: dirty idle copies are reapable (see below) */
};

/* Per-class outcome. registered is the number of worktrees of the pool's own
 * repository that live under the pool; the five keep counters plus reapable
 * partition it exactly. */
struct host_gc_class {
    char name[HOST_GC_NAME_CAP];
    char path[HOST_GC_PATH_CAP];
    char repo[HOST_GC_PATH_CAP];
    bool present;
    bool disposable;
    int registered;
    int reapable;
    int too_young;
    int in_use;
    int locked;
    int need_review;
    int orphaned;           /* unregistered gate-copy dirs (counted in registered) */
    int unique_archived;    /* HEAD pinned under refs/archive/wt, then removed */
    int kept_on_failure;    /* the pin failed: worktree stands */
    uint64_t bytes_reclaimable;
    uint64_t bytes_reclaimed;
};

struct host_gc_refusal {
    char path[HOST_GC_PATH_CAP];
    char reason[HOST_GC_REASON_CAP];
};

/* A dirty worktree the sweep left alone, for a person to decide. */
struct host_gc_review {
    char path[HOST_GC_PATH_CAP];
    int idle_days;                    /* -1 unknown */
    int dirty_count;                  /* lines of git status */
};

struct host_gc_request {
    bool apply;                       /* false = classify only, remove nothing */
    int floor_hours;                  /* keep anything younger than this */
    int age_days;                     /* idle days before a unique HEAD is pinned and removed; 0 = keep */
    char unit_dir[HOST_GC_PATH_CAP];  /* systemd user units; "" = $HOME default */
    struct host_gc_pool pools[HOST_GC_MAX_POOLS];
    size_t npools;
    char home[HOST_GC_PATH_CAP];      /* protection root; "" = $HOME */
    char proc_root[HOST_GC_PATH_CAP]; /* "" = native host inventory; explicit = procfs fixture */
    int64_t now;                      /* 0 = ask the wall clock */
};

struct host_gc_report {
    struct host_gc_class classes[HOST_GC_MAX_POOLS];
    size_t nclasses;
    struct host_gc_refusal refusals[HOST_GC_MAX_REFUSALS];
    size_t nrefusals;
    struct host_gc_review reviews[HOST_GC_MAX_REVIEWS];
    size_t nreviews;
    bool truncated;                   /* more candidates than the cap */
};

/* Fill `req` with the production defaults: $HOME, native inventory, the 6h floor, and
 * the two dev-proof generation pools (disk and RAM). Returns false only when
 * $HOME is absent or too long to hold a pool path, in which case the caller
 * must refuse rather than sweep an unanchored tree. */
bool host_gc_defaults(struct host_gc_request *req);

/* Classify every registered worktree under every requested pool and, when
 * req->apply, remove exactly the reapable ones through git. Returns false
 * only on an allocation failure; a pool that does not exist, or that is
 * refused, is reported, not an error. */
bool host_gc_run(const struct host_gc_request *req,
                 struct host_gc_report *report);

/* The protection predicate, exposed so a test can ask it about a path it
 * must never touch. Returns true when `path` is protected and writes the
 * reason that fired into `reason`. */
bool host_gc_path_protected(const struct host_gc_request *req,
                            const char *repo, const char *path,
                            char *reason, size_t reason_cap);

/* The protected-leaf table itself, read-only, so a caller (a test, chiefly)
 * can assert "every protected leaf is refused by name" by walking the same
 * table the sweep enforces against, rather than re-typing the live datadir
 * names as a literal of its own. `host_gc_protected_leaf(i)` returns NULL
 * once `i >= host_gc_protected_leaf_count()`. */
size_t host_gc_protected_leaf_count(void);
const char *host_gc_protected_leaf(size_t i);

#endif /* ZCL_TOOLS_HOST_GC_SWEEP_H */
