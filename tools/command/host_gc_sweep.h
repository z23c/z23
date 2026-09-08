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
 * THE ONLY DELETION PATH is `git worktree remove --force` executed by git
 * itself through the spawn seam (util/spawn.h). This engine contains no
 * unlink(), no rmdir(), and no recursive delete of any kind: git refuses a
 * path that is not a registered worktree of the repo it is asked about, so
 * a classifier bug cannot reach an arbitrary directory. Read that as the
 * load-bearing safety property of the whole file.
 *
 * A CANDIDATE IS KEPT, never removed, when ANY of these holds — the reason
 * is reported per class so an operator can see WHY nothing moved:
 *   locked       git itself was told to keep it (`git worktree lock`)
 *   in_use       the directory, or something under it, is a live process's
 *                cwd or an open file descriptor's target
 *   too_young    its mtime is younger than the age floor
 *   need_review  git says it carries a branch or uncommitted content
 * The lock and in-use tests run BEFORE the age floor deliberately: all four
 * are keeps, and an operator reading "in use" learns more than "too young".
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
    HOST_GC_DEFAULT_FLOOR_HOURS = 6
};

/* One pool the caller asked to sweep. `name` is the class label carried in
 * the report; `path` is the pool directory. */
struct host_gc_pool {
    char name[HOST_GC_NAME_CAP];
    char path[HOST_GC_PATH_CAP];
};

/* Per-class outcome. registered is the number of worktrees of the pool's own
 * repository that live under the pool; the five keep counters plus reapable
 * partition it exactly. */
struct host_gc_class {
    char name[HOST_GC_NAME_CAP];
    char path[HOST_GC_PATH_CAP];
    char repo[HOST_GC_PATH_CAP];
    bool present;
    int registered;
    int reapable;
    int too_young;
    int in_use;
    int locked;
    int need_review;
    uint64_t bytes_reclaimable;
    uint64_t bytes_reclaimed;
};

struct host_gc_refusal {
    char path[HOST_GC_PATH_CAP];
    char reason[HOST_GC_REASON_CAP];
};

struct host_gc_request {
    bool apply;                       /* false = classify only, remove nothing */
    int floor_hours;                  /* keep anything younger than this */
    struct host_gc_pool pools[HOST_GC_MAX_POOLS];
    size_t npools;
    char home[HOST_GC_PATH_CAP];      /* protection root; "" = $HOME */
    char proc_root[HOST_GC_PATH_CAP]; /* "" = /proc */
    int64_t now;                      /* 0 = ask the wall clock */
};

struct host_gc_report {
    struct host_gc_class classes[HOST_GC_MAX_POOLS];
    size_t nclasses;
    struct host_gc_refusal refusals[HOST_GC_MAX_REFUSALS];
    size_t nrefusals;
    bool truncated;                   /* more candidates than the cap */
};

/* Fill `req` with the production defaults: $HOME, /proc, the 6h floor, and
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

#endif /* ZCL_TOOLS_HOST_GC_SWEEP_H */
