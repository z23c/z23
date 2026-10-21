/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the host-GC worktree-pool sweep engine declared in
 *          command/host_gc_sweep.h. Read that header first: it carries the
 *          pool definition, the keep rules, and the single-deletion-path
 *          guarantee this file implements. The protection predicate and the
 *          path plumbing live in host_gc_paths.c.
 *
 * PROCESS RULE. git runs only through zcl_spawn_capture() (util/spawn.h).
 * No popen(), no system(), and no shell command string anywhere in this
 * translation unit. The one recursive delete it can reach is the tree
 * walker every other caller in this project uses, util/file_tree_ops.h's
 * zcl_tree_remove(), and it is reachable only from hg_finish_removal() —
 * read that function's comment for why git alone is not enough.
 */

#include "command/host_gc_priv.h"

#include "platform/time_compat.h"
#include "platform/os_proc.h"
#include "platform/file_metadata.h"
#include "util/file_tree_ops.h"
#include "util/path_util.h"
#include "util/safe_alloc.h"
#include "util/spawn.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum {
    HG_GIT_TIMEOUT_MS = 120000,
    HG_LIST_CAP = 262144,
    HG_STATUS_CAP = 4096,
    HG_REPO_PROBE_MAX = 32,
    HG_DIRTY_CAP = 65536,
    HG_UNITS_CAP = 4 * 1024 * 1024,
    HG_REF_NAME_MAX = 200,
    HG_PIN_TRIES = 100
};

/* One removal candidate: a registered worktree of the pool's repository.
 * `occupied` is filled by the single /proc pass. */
struct hg_cand {
    char path[HOST_GC_PATH_CAP];
    size_t cls;
    bool detached;
    bool locked;
    bool occupied;
    bool donor;       /* kept: newest complete generation of its identity */
    int dirty;        /* lines of `git status`; -1 unknown */
};

struct hg_scan {
    struct hg_cand *cands;
    size_t n;
    size_t cap;
    bool truncated;
    bool process_inventory_complete;
};

static int hg_git(const char *dir, const char *const args[], char *out,
                  size_t out_cap)
{
    const char *argv[16];
    size_t n = 0;
    argv[n++] = "git";
    if (dir && dir[0]) {
        argv[n++] = "-C";
        argv[n++] = dir;
    }
    for (size_t i = 0; args[i] && n + 1 < sizeof(argv) / sizeof(argv[0]); i++)
        argv[n++] = args[i];
    argv[n] = NULL;
    if (out && out_cap)
        out[0] = '\0';
    return zcl_spawn_capture(argv, out, out_cap, HG_GIT_TIMEOUT_MS);
}

static int64_t hg_now(const struct host_gc_request *req)
{
    return req->now ? req->now : platform_time_wall_unix();
}

/* mtime age in seconds. A path that cannot be stat()ed reads as 0 — too
 * young to touch, the fail-safe direction. */
static int64_t hg_age_secs(const char *path, int64_t now)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return 0;
    if (now <= (int64_t)st.st_mtime)
        return 0;
    return now - (int64_t)st.st_mtime;
}

static void hg_refuse(struct host_gc_report *report, const char *path,
                      const char *reason)
{
    struct host_gc_refusal *r;
    for (size_t i = 0; i < report->nrefusals; i++)
        if (strcmp(report->refusals[i].path, path) == 0)
            return;
    if (report->nrefusals >= HOST_GC_MAX_REFUSALS)
        return;
    r = &report->refusals[report->nrefusals];
    if (hg_copy(r->path, sizeof(r->path), path) &&
        hg_copy(r->reason, sizeof(r->reason), reason))
        report->nrefusals++;
}

/* ------------------------------------------------- worktree enumeration */

/* NUL-terminate the current line of `p` and return the next one. */
static char *hg_next_line(char *p)
{
    char *nl = strchr(p, '\n');
    if (!nl)
        return NULL;
    *nl = '\0';
    return nl + 1;
}


/* Ask git, from inside one worktree of the pool, for every worktree of the
 * repository that owns it. The FIRST porcelain entry is the main worktree,
 * so this also answers "which repository owns this pool" without a second
 * call and without the caller ever naming a repository itself — the removal
 * below can then only ever be addressed to the pool's own repo. */
static bool hg_list_worktrees(const char *child, char *buf, size_t cap,
                              char *repo, size_t repo_cap)
{
    static const char *const args[] = { "worktree", "list", "--porcelain",
                                        NULL };
    char first[HOST_GC_PATH_CAP];
    const char *end;
    size_t n;
    if (hg_git(child, args, buf, cap) != 0)
        return false;
    if (strncmp(buf, "worktree ", 9) != 0)
        return false;
    end = strchr(buf, '\n');
    n = (end ? (size_t)(end - buf) : strlen(buf)) - 9;
    if (n + 1 > sizeof(first))
        return false;
    memcpy(first, buf + 9, n);
    first[n] = '\0';
    return hg_copy(repo, repo_cap, first);
}

/* Which repository owns this pool? Ask git from inside a pool child, and
 * keep asking until one child answers.
 *
 * A single child is not enough. A pool accumulates directories whose
 * worktree registration is already gone (the administrative gitdir was
 * pruned while the checkout stayed on disk); `git worktree list` inside one
 * of those fails, and readdir order decides which child is tried first. A
 * one-child probe therefore made the entire pool report
 * `no_repo_behind_pool` — sweeping nothing — depending on nothing but
 * directory order. Bounded so a pool full of stale directories cannot turn
 * one sweep into hundreds of git invocations.
 */
static bool hg_pool_repo(const char *pool, char *buf, size_t cap, char *repo,
                         size_t repo_cap, bool *saw_child)
{
    DIR *d = opendir(pool);
    struct dirent *e;
    int tried = 0;
    bool found = false;
    *saw_child = false;
    if (!d)
        return false;
    while (!found && tried < HG_REPO_PROBE_MAX && (e = readdir(d)) != NULL) {
        struct stat st;
        char child[HOST_GC_PATH_CAP];
        if (e->d_name[0] == '.')
            continue;
        if (!zcl_path_join(child, sizeof(child), pool, e->d_name))
            continue;
        if (stat(child, &st) != 0 || !S_ISDIR(st.st_mode))
            continue;
        *saw_child = true;
        tried++;
        found = hg_list_worktrees(child, buf, cap, repo, repo_cap);
    }
    (void)closedir(d);
    return found;
}

/* The administrative directory a linked worktree's .git file names. */
static bool hg_gitdir(const char *wt, char *out, size_t cap)
{
    char dotgit[HOST_GC_PATH_CAP];
    char line[HOST_GC_PATH_CAP];
    FILE *f;
    if (!zcl_path_join(dotgit, sizeof(dotgit), wt, ".git"))
        return false;
    f = fopen(dotgit, "r");
    if (!f)
        return false;
    if (!fgets(line, (int)sizeof(line), f))
        line[0] = '\0';
    (void)fclose(f);
    hg_strip(line);
    if (strncmp(line, "gitdir: ", 8) != 0)
        return false;
    return hg_copy(out, cap, line + 8);
}

/* git prints `locked` in the porcelain listing; the on-disk marker is read
 * as well so a git too old to print it still cannot lose a lock. Either
 * source saying "locked" keeps the worktree. */
static bool hg_locked_on_disk(const char *wt)
{
    char gitdir[HOST_GC_PATH_CAP];
    char marker[HOST_GC_PATH_CAP];
    struct stat st;
    return hg_gitdir(wt, gitdir, sizeof(gitdir)) &&
           zcl_path_join(marker, sizeof(marker), gitdir, "locked") &&
           stat(marker, &st) == 0;
}

static void hg_push_cand(struct hg_scan *scan, size_t cls, const char *path,
                         bool detached, bool locked)
{
    struct hg_cand *c;
    if (scan->n >= scan->cap) {
        scan->truncated = true;
        return;
    }
    c = &scan->cands[scan->n];
    if (!hg_copy(c->path, sizeof(c->path), path))
        return;
    c->cls = cls;
    c->detached = detached;
    c->locked = locked || hg_locked_on_disk(path);
    c->occupied = false;
    c->donor = false;
    c->dirty = 0;
    scan->n++;
}

/* One porcelain record. Only a worktree strictly UNDER the pool is ever a
 * candidate: the pool directory itself and every worktree elsewhere in the
 * repository are invisible to this sweep. */
static void hg_take_record(struct hg_scan *scan, size_t cls, const char *pool,
                           const char *path, bool detached, bool locked,
                           int *registered)
{
    if (!path[0] || strcmp(path, pool) == 0 || !hg_under(pool, path))
        return;
    (*registered)++;
    hg_push_cand(scan, cls, path, detached, locked);
}

static void hg_parse_worktrees(struct hg_scan *scan, size_t cls,
                               const char *pool, char *buf, int *registered)
{
    char path[HOST_GC_PATH_CAP];
    bool detached = false, locked = false;
    char *line = buf;
    path[0] = '\0';
    while (line) {
        char *next = hg_next_line(line);
        if (strncmp(line, "worktree ", 9) == 0) {
            hg_take_record(scan, cls, pool, path, detached, locked, registered);
            detached = false;
            locked = false;
            if (!hg_copy(path, sizeof(path), line + 9))
                path[0] = '\0';
        } else if (strcmp(line, "detached") == 0) {
            detached = true;
        } else if (strncmp(line, "locked", 6) == 0) {
            locked = true;
        }
        line = next;
    }
    hg_take_record(scan, cls, pool, path, detached, locked, registered);
}

/* ------------------------------------------------------- occupancy pass */

#if !defined(_WIN32)
static void hg_mark_target(struct hg_scan *scan, const char *target)
{
    if (!target || target[0] != '/')
        return;
    for (size_t i = 0; i < scan->n; i++)
        if (!scan->cands[i].occupied && hg_under(scan->cands[i].path, target))
            scan->cands[i].occupied = true;
}
#endif /* !defined(_WIN32) */

static bool hg_mark_link(struct hg_scan *scan, const char *link, bool fd)
{
#if defined(_WIN32)
    (void)scan; (void)link; (void)fd;
    return false;
#else
    char target[PATH_MAX];
    ssize_t n = readlink(link, target, sizeof(target));
    if (n < 0) return fd && errno == ENOENT;
    if (n == 0 || (size_t)n >= sizeof(target)) return false;
    target[n] = '\0';
    hg_mark_target(scan, target);
    return true;
#endif
}

static bool hg_mark_fds(struct hg_scan *scan, const char *procdir)
{
    char fddir[HOST_GC_PATH_CAP];
    if (!zcl_path_join(fddir, sizeof(fddir), procdir, "fd")) return false;
    DIR *d = opendir(fddir);
    if (!d) return false;
    bool complete = true;
    for (;;) {
        errno = 0;
        struct dirent *e = readdir(d);
        if (!e) { if (errno) complete = false; break; }
        if (e->d_name[0] == '.') continue;
        char link[HOST_GC_PATH_CAP * 2];
        if (!zcl_path_join(link, sizeof(link), fddir, e->d_name) ||
            !hg_mark_link(scan, link, true)) complete = false;
    }
    if (closedir(d) != 0) complete = false;
    return complete;
}

static bool hg_mark_process(struct hg_scan *scan, const char *procdir)
{
    char cwd[HOST_GC_PATH_CAP * 2];
    bool complete = zcl_path_join(cwd, sizeof(cwd), procdir, "cwd") &&
                    hg_mark_link(scan, cwd, false);
    if (!hg_mark_fds(scan, procdir)) complete = false;
    struct stat st;
    /* A vanished process cannot retain a live cwd/fd; all other failures
     * remain unknown, including permissions and partial inventories. */
    if (!complete && lstat(procdir, &st) != 0 && errno == ENOENT) return true;
    return complete;
}

#if defined(__APPLE__)
static void hg_native_path(const char *path, void *opaque)
{
    hg_mark_target(opaque, path);
}
#endif

static void hg_mark_occupied(const struct host_gc_request *req,
                             struct hg_scan *scan)
{
#if defined(__APPLE__)
    if (!req->proc_root[0]) {
        scan->process_inventory_complete = os_proc_visit_paths(hg_native_path, scan);
        return;
    }
#endif
    const char *root = req->proc_root[0] ? req->proc_root : "/proc";
    DIR *d = opendir(root);
    scan->process_inventory_complete = d != NULL;
    if (!d) return;
    for (;;) {
        errno = 0;
        struct dirent *e = readdir(d);
        if (!e) { if (errno) scan->process_inventory_complete = false; break; }
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        char procdir[HOST_GC_PATH_CAP];
        if (!zcl_path_join(procdir, sizeof(procdir), root, e->d_name) ||
            !hg_mark_process(scan, procdir)) scan->process_inventory_complete = false;
    }
    if (closedir(d) != 0) scan->process_inventory_complete = false;
}

/* ------------------------------------------------------------ warm donors */

/* A generation whose build finished carries the marker tools/dev/dev_proof.c
 * writes (build/.proof-build-complete, zcl.proof_build_complete.v1): the
 * checkout root, when the build completed, and the four build-identity
 * digests. The newest such generation of an identity is the WARM DONOR the
 * next proof of that identity seeds its objects from instead of building
 * cold, so reaping it by age alone made the next landing pay a whole cold
 * build. The newest idle, unlocked, complete generation of each identity is
 * therefore kept — at most HG_DONOR_MAX per pool, newest first — and counted
 * as in_use: it is reserved for a use the /proc pass cannot see. Every
 * other generation is classified exactly as before. */
enum {
    HG_DONOR_MAX = 2,
    HG_IDENTITY_FIELDS = 5,
    HG_DONOR_KEY_CAP = HG_IDENTITY_FIELDS * HOST_GC_PATH_CAP
};

static const char hg_marker_rel[] = "build/.proof-build-complete";
static const char hg_marker_schema[] = "zcl.proof_build_complete.v1";
static const char *const hg_identity_field[HG_IDENTITY_FIELDS] = {
    "root=", "compiler=", "flags=", "environment=", "build_graph="
};

struct hg_marker {
    char key[HG_DONOR_KEY_CAP];
    int64_t completed;
};

static int hg_identity_index(const char *line)
{
    for (int i = 0; i < HG_IDENTITY_FIELDS; i++)
        if (strncmp(line, hg_identity_field[i],
                    strlen(hg_identity_field[i])) == 0)
            return i;
    return -1;
}

/* One `key=value` marker line: an identity field lands in its slot of the
 * key, `completed=` in m->completed; anything else is ignored. */
static void hg_marker_line(struct hg_marker *m, char *slots, unsigned *seen,
                           const char *line)
{
    int i = hg_identity_index(line);
    if (i >= 0) {
        if (hg_copy(slots + (size_t)i * HOST_GC_PATH_CAP, HOST_GC_PATH_CAP,
                    line + strlen(hg_identity_field[i])))
            *seen |= 1u << i;
        return;
    }
    if (strncmp(line, "completed=", 10) == 0)
        m->completed = strtoll(line + 10, NULL, 10);
}

/* The identity key: the five slots joined by newlines, so two generations
 * share a key exactly when every field matches. */
static bool hg_marker_key(struct hg_marker *m, const char *slots)
{
    size_t used = 0;
    for (int i = 0; i < HG_IDENTITY_FIELDS; i++) {
        const char *v = slots + (size_t)i * HOST_GC_PATH_CAP;
        int n = snprintf(m->key + used, sizeof(m->key) - used, "%s\n", v);
        if (n < 0 || (size_t)n >= sizeof(m->key) - used)
            return false;
        used += (size_t)n;
    }
    return true;
}

/* Read one generation's marker. False (and completed = 0) when there is
 * none, it is another schema, or any field is missing. */
static bool hg_marker_read(const char *wt, struct hg_marker *m)
{
    char path[HOST_GC_PATH_CAP], line[HOST_GC_PATH_CAP];
    char slots[HG_IDENTITY_FIELDS * HOST_GC_PATH_CAP] = { 0 };
    unsigned seen = 0;
    bool ok;
    FILE *f;
    m->completed = 0;
    if (!zcl_path_join(path, sizeof(path), wt, hg_marker_rel))
        return false;
    f = fopen(path, "r");
    if (!f)
        return false;
    ok = fgets(line, (int)sizeof(line), f) != NULL;
    if (ok) {
        hg_strip(line);
        ok = strcmp(line, hg_marker_schema) == 0;
    }
    while (ok && fgets(line, (int)sizeof(line), f)) {
        hg_strip(line);
        hg_marker_line(m, slots, &seen, line);
    }
    (void)fclose(f);
    ok = ok && seen == (1u << HG_IDENTITY_FIELDS) - 1 && m->completed > 0 &&
         hg_marker_key(m, slots);
    if (!ok)
        m->completed = 0;
    return ok;
}

/* May candidate i still become a donor of class `cls`: complete, not yet a
 * donor, and of an identity no donor chosen so far already covers? */
static bool hg_donor_eligible(const struct hg_scan *scan,
                              const struct hg_marker *marks, size_t cls,
                              size_t i, const size_t *chosen, size_t nchosen)
{
    if (scan->cands[i].cls != cls || marks[i].completed <= 0 ||
        scan->cands[i].donor)
        return false;
    for (size_t k = 0; k < nchosen; k++)
        if (strcmp(marks[chosen[k]].key, marks[i].key) == 0)
            return false;
    return true;
}

/* Each round takes the newest eligible generation of the pool; an identity
 * already covered is no longer eligible, so every pick is the newest of its
 * own identity and the picks come newest first. */
static void hg_pick_donors(struct hg_scan *scan, const struct hg_marker *marks,
                           size_t cls)
{
    size_t chosen[HG_DONOR_MAX];
    size_t nchosen = 0;
    while (nchosen < HG_DONOR_MAX) {
        size_t best = SIZE_MAX;
        for (size_t i = 0; i < scan->n; i++)
            if (hg_donor_eligible(scan, marks, cls, i, chosen, nchosen) &&
                (best == SIZE_MAX || marks[i].completed > marks[best].completed))
                best = i;
        if (best == SIZE_MAX)
            return;
        scan->cands[best].donor = true;
        chosen[nchosen++] = best;
    }
}

/* Without memory for the comparison, every complete generation is kept:
 * the fail-safe direction for a keep rule is to keep. */
static void hg_mark_all_complete(struct hg_scan *scan)
{
    struct hg_marker one;
    for (size_t i = 0; i < scan->n; i++)
        if (!scan->cands[i].occupied && hg_marker_read(scan->cands[i].path, &one))
            scan->cands[i].donor = true;
}

static void hg_mark_donors(struct hg_scan *scan, size_t nclasses)
{
    struct hg_marker *marks;
    if (scan->n == 0)
        return;
    marks = zcl_calloc(scan->n, sizeof(*marks), "host_gc donor markers");
    if (!marks) {
        hg_mark_all_complete(scan);
        return;
    }
    for (size_t i = 0; i < scan->n; i++)
        if (scan->cands[i].occupied || scan->cands[i].locked ||
            !hg_marker_read(scan->cands[i].path, &marks[i]))
            marks[i].completed = 0;
    for (size_t cls = 0; cls < nclasses; cls++)
        hg_pick_donors(scan, marks, cls);
    free(marks);
}

/* ------------------------------------------------------- classification */

/* Lines `git status` reports: tracked changes and every untracked file,
 * which includes an untracked nested repository. 0 is clean; -1 is unknown
 * and is never clean. */
static int hg_dirty_count(const char *wt)
{
    static const char *const args[] = { "--no-optional-locks", "status",
                                        "--porcelain",
                                        "--untracked-files=all", NULL };
    char *out = zcl_malloc(HG_DIRTY_CAP, "host_gc status");
    int n = 0;
    if (!out)
        return -1;
    if (hg_git(wt, args, out, HG_DIRTY_CAP) != 0)
        n = -1;
    else
        for (const char *p = out; *p; p++)
            n += *p == '\n';
    if (n == 0 && out[0] != '\0')
        n = 1;
    free(out);
    return n;
}

/* Seconds since the gitdir index (HEAD when there is none) changed. */
static int64_t hg_idle_secs(const char *wt, int64_t now)
{
    static const char *const files[] = { "index", "HEAD" };
    char gitdir[HOST_GC_PATH_CAP], file[HOST_GC_PATH_CAP];
    struct stat st;
    if (!hg_gitdir(wt, gitdir, sizeof(gitdir)))
        return -1;
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++)
        if (zcl_path_join(file, sizeof(file), gitdir, files[i]) &&
            stat(file, &st) == 0)
            return now > (int64_t)st.st_mtime ? now - (int64_t)st.st_mtime : 0;
    return -1;
}

/* ------------------------------------------------------ unique HEADs */

/* A clean detached worktree whose HEAD no other ref holds is the only thing
 * the sweep removes that git could not give back. Its HEAD is pinned under
 * refs/archive/wt/<name> first, and the worktree is removed only when the
 * ref reads back. A clean committed tree is wholly held by that ref. */

static bool hg_head_sha(const char *wt, char *sha, size_t cap)
{
    static const char *const args[] = { "rev-parse", "--verify", "HEAD",
                                        NULL };
    if (hg_git(wt, args, sha, cap) != 0)
        return false;
    hg_strip(sha);
    return sha[0] != '\0';
}

/* True unless HEAD is contained in a refs/remotes/origin or refs/archive
 * ref. An unanswerable question reads as unique, the direction that keeps. */
static bool hg_head_unique(const char *wt)
{
    char sha[HG_STATUS_CAP], out[HG_STATUS_CAP];
    const char *args[] = { "for-each-ref", "--count=1", "--format=%(refname)",
                           "--contains", sha, "refs/remotes/origin",
                           "refs/archive", NULL };
    if (!hg_head_sha(wt, sha, sizeof(sha)))
        return true;
    return hg_git(wt, args, out, sizeof(out)) != 0 || out[0] == '\0';
}

static bool hg_name_char(char c)
{
    return (unsigned)((c | 0x20) - 'a') < 26u ||
           (unsigned)(c - '0') < 10u || c == '_' || c == '-';
}

static const char *hg_home(const struct host_gc_request *req)
{
    const char *home = getenv("HOME");
    return req->home[0] ? req->home : (home ? home : "");
}

/* The path below $HOME with every character outside [A-Za-z0-9_-] mapped to
 * '_' and leading '_' stripped (update-ref refuses a leading '.'). */
static bool hg_ref_name(const char *home, const char *path, char *out,
                        size_t cap)
{
    const char *p = path;
    size_t n = 0, skip;
    if (home[0] && strcmp(home, path) != 0 && hg_under(home, path))
        p = path + strlen(home);
    for (; *p; p++) {
        if (n + 1 >= cap)
            return false;
        out[n++] = hg_name_char(*p) ? *p : '_';
    }
    out[n] = '\0';
    skip = strspn(out, "_");
    memmove(out, out + skip, n - skip + 1);
    return out[0] != '\0' && out[0] != '-' && strlen(out) <= HG_REF_NAME_MAX;
}

static bool hg_ref_holds(const char *repo, const char *ref, const char *sha,
                         int *rc)
{
    const char *args[] = { "rev-parse", "--verify", "-q", ref, NULL };
    char cur[HG_STATUS_CAP];
    *rc = hg_git(repo, args, cur, sizeof(cur));
    hg_strip(cur);
    return *rc == 0 && strcmp(cur, sha) == 0;
}

/* Create refs/archive/wt/<name> at sha and read it back. A name bound to a
 * different commit is never overwritten: the next free <name>-<n> is used. */
static bool hg_pin_name(const char *repo, const char *name, const char *sha)
{
    char ref[HOST_GC_PATH_CAP + 32], out[HG_STATUS_CAP];
    const char *upd[] = { "update-ref", ref, sha, "", NULL };
    int rc;
    for (int n = 0; n < HG_PIN_TRIES; n++) {
        (void)snprintf(ref, sizeof(ref), n ? "refs/archive/wt/%s-%d"
                                           : "refs/archive/wt/%s", name, n);
        if (hg_ref_holds(repo, ref, sha, &rc))
            return true;
        if (rc == 0)
            continue;
        return rc == 1 && hg_git(repo, upd, out, sizeof(out)) == 0 &&
               hg_ref_holds(repo, ref, sha, &rc);
    }
    return false;
}

static bool hg_pin_head(const struct host_gc_request *req, const char *repo,
                        const char *wt)
{
    char sha[HG_STATUS_CAP], name[HOST_GC_PATH_CAP];
    return hg_ref_name(hg_home(req), wt, name, sizeof(name)) &&
           hg_head_sha(wt, sha, sizeof(sha)) && hg_pin_name(repo, name, sha);
}

/* -------------------------------------------------------- systemd units */

static bool hg_unit_file(const char *name)
{
    static const char *const suffix[] = { ".service", ".timer", ".path" };
    size_t len = strlen(name);
    for (size_t i = 0; i < sizeof(suffix) / sizeof(suffix[0]); i++) {
        size_t s = strlen(suffix[i]);
        if (len > s && strcmp(name + len - s, suffix[i]) == 0)
            return true;
    }
    return false;
}

/* False when the file cannot be read whole. */
static bool hg_append_unit(const char *path, char *text, size_t *used)
{
    FILE *f = fopen(path, "r");
    bool whole;
    if (!f)
        return errno == ENOENT;
    *used += fread(text + *used, 1, HG_UNITS_CAP - 2 - *used, f);
    text[(*used)++] = '\n';
    whole = fgetc(f) == EOF && !ferror(f);
    (void)fclose(f);
    return whole;
}

/* The user unit files, or false when they cannot be read whole. An absent
 * directory is an empty answer. */
static bool hg_units_text(const struct host_gc_request *req, char **text)
{
    char dir[HOST_GC_PATH_CAP], file[HOST_GC_PATH_CAP];
    struct dirent *e;
    size_t used = 0;
    bool ok = true;
    DIR *d;
    *text = zcl_calloc(1, HG_UNITS_CAP, "host_gc unit text");
    if (req->unit_dir[0] ? !hg_copy(dir, sizeof(dir), req->unit_dir)
                         : !zcl_path_join(dir, sizeof(dir), hg_home(req),
                                          ".config/systemd/user"))
        ok = false;
    d = ok && *text ? opendir(dir) : NULL;
    if (ok && *text && !d)
        ok = errno == ENOENT;
    while (d && ok && (e = readdir(d)) != NULL)
        if (hg_unit_file(e->d_name) &&
            zcl_path_join(file, sizeof(file), dir, e->d_name))
            ok = hg_append_unit(file, *text, &used);
    if (d)
        (void)closedir(d);
    return ok && *text;
}

static bool hg_path_char(char c)
{
    return hg_name_char(c) || c == '.' || c == '/';
}

static bool hg_names_exact(const char *text, const char *path)
{
    size_t len = strlen(path);
    for (const char *p = strstr(text, path); p; p = strstr(p + 1, path))
        if ((p == text || p[-1] == '-' || !hg_path_char(p[-1])) &&
            !hg_path_char(p[len]))
            return true;
    return false;
}

/* True when `text` names `path` as a whole path, absolute or relative to the
 * home directory the way systemd spells it (%h, ~, $HOME). */
static bool hg_text_names(const char *text, const char *path,
                          const char *home)
{
    static const char *const forms[] = { "%h", "~", "$HOME", "${HOME}" };
    char alt[HOST_GC_PATH_CAP + 8];
    if (hg_names_exact(text, path))
        return true;
    if (!home[0] || !strcmp(home, path) || !hg_under(home, path))
        return false;
    for (size_t i = 0; i < sizeof(forms) / sizeof(forms[0]); i++)
        if (snprintf(alt, sizeof(alt), "%s%s", forms[i],
                     path + strlen(home)) < (int)sizeof(alt) &&
            hg_names_exact(text, alt))
            return true;
    return false;
}

/* A worktree a user unit file names is in use. When the unit files cannot
 * be read whole, every candidate is: nothing is removed. */
static void hg_mark_units(const struct host_gc_request *req,
                          struct hg_scan *scan)
{
    char *text = NULL;
    bool ok = hg_units_text(req, &text);
    for (size_t i = 0; i < scan->n; i++)
        if (!ok || hg_text_names(text, scan->cands[i].path, hg_home(req)))
            scan->cands[i].occupied = true;
    free(text);
}

enum hg_verdict {
    HG_KEEP_LOCKED,
    HG_KEEP_IN_USE,
    HG_KEEP_DONOR,
    HG_KEEP_TOO_YOUNG,
    HG_KEEP_NEEDS_REVIEW,
    HG_ARCHIVE_UNIQUE,
    HG_REAPABLE
};

/* A clean detached worktree is reapable when its HEAD lives elsewhere, and
 * when it does not, only with age_days on and idle that long (its HEAD is
 * then pinned first). Anything dirty is kept and recorded for a human. */
static enum hg_verdict hg_classify_content(const struct host_gc_request *req,
                                           struct hg_cand *c, int64_t now)
{
    c->dirty = hg_dirty_count(c->path);
    if (c->dirty != 0 || !c->detached)
        return HG_KEEP_NEEDS_REVIEW;
    if (!hg_head_unique(c->path))
        return HG_REAPABLE;
    if (req->age_days > 0 &&
        hg_idle_secs(c->path, now) >= (int64_t)req->age_days * 86400)
        return HG_ARCHIVE_UNIQUE;
    return HG_KEEP_NEEDS_REVIEW;
}

/* The keep rules, in the order host_gc_sweep.h documents, plus the warm
 * donor keep (see hg_mark_donors). Lock and occupancy come first because
 * both outrank the age floor as an explanation; every verdict below
 * REAPABLE is a keep, and a donor is counted as in_use. */
static enum hg_verdict hg_classify(const struct host_gc_request *req,
                                   struct hg_cand *c, int64_t now)
{
    int64_t floor_s =
        (int64_t)(req->floor_hours > 0 ? req->floor_hours : 0) * 3600;
    if (c->locked)
        return HG_KEEP_LOCKED;
    if (c->occupied)
        return HG_KEEP_IN_USE;
    if (c->donor)
        return HG_KEEP_DONOR;
    if (hg_age_secs(c->path, now) < floor_s)
        return HG_KEEP_TOO_YOUNG;
    return hg_classify_content(req, c, now);
}

static void hg_count(struct host_gc_class *cls, enum hg_verdict v)
{
    switch (v) {
    case HG_KEEP_LOCKED: cls->locked++; break;
    case HG_KEEP_IN_USE:
    case HG_KEEP_DONOR: cls->in_use++; break;
    case HG_KEEP_TOO_YOUNG: cls->too_young++; break;
    case HG_KEEP_NEEDS_REVIEW: cls->need_review++; break;
    case HG_ARCHIVE_UNIQUE: cls->unique_archived++; cls->reapable++; break;
    case HG_REAPABLE: cls->reapable++; break;
    }
}

/* STEP ONE OF THE DELETION PATH. git is asked to remove a worktree of the
 * pool's OWN repository, and refuses anything that is not one. */
static bool hg_reap(const char *repo, const char *wt)
{
    const char *args[] = { "worktree", "remove", "--force", "--", wt, NULL };
    char out[HG_STATUS_CAP];
    return hg_git(repo, args, out, sizeof(out)) == 0;
}

static bool hg_exists(const char *path)
{
    return platform_file_shape_read(path) != PLATFORM_FILE_SHAPE_MISSING;
}

/* Drop the administrative record of a worktree whose directory is gone.
 * Only needed after this engine finished a removal git did not. */
static void hg_prune(const char *repo)
{
    static const char *const args[] = { "worktree", "prune", NULL };
    char out[HG_STATUS_CAP];
    (void)hg_git(repo, args, out, sizeof(out));
}

/* The operating system's own words for a failure. Every failure message
 * util/file_tree_ops.c builds ends with ": <strerror text>", and a refusal
 * already carries the path in a field of its own, so the tail is the only
 * part worth a reason's 48 bytes. */
static const char *hg_why(const struct zcl_result *r)
{
    const char *colon = strrchr(r->message, ':');
    if (!colon || !colon[1])
        return r->message;
    return colon[1] == ' ' ? colon + 2 : colon + 1;
}

/* STEP TWO, AND WHY IT HAS TO EXIST. `git worktree remove` deletes the
 * directory first and unregisters the worktree afterwards — unconditionally,
 * even when the delete failed. One read-only directory of test scratch
 * inside a dead generation is enough to make the delete fail, and the
 * generation is then unregistered AND still on disk: `git worktree list`
 * no longer names it, so no later sweep can ever classify it again. On the
 * tmpfs pool that is a permanent RAM leak — four 2-3 GB generations
 * survived an apply that had already reported them reclaimed.
 *
 * This is the only place the engine deletes on its own, so it re-proves
 * what it was relying on git for: the path is still strictly under THIS
 * pool's root, and it is still not a protected path. Read-only directories
 * are made writable first, because that is the obstacle that produced the
 * leak. Anything still standing afterwards is named in refusals[] with the
 * errno text — never dropped in silence, because an unregistered directory
 * nobody names is exactly the leak this function exists to close. */
static bool hg_finish_removal(const struct host_gc_request *req,
                              struct host_gc_report *report,
                              const struct host_gc_class *cls,
                              const char *path)
{
    char reason[HOST_GC_REASON_CAP];
    struct zcl_result rm;

    if (!hg_under(cls->path, path) || strcmp(path, cls->path) == 0) {
        hg_refuse(report, path, "outside_pool_root");
        return false;
    }
    if (host_gc_path_protected(req, cls->repo, path, reason,
                               sizeof(reason))) {
        hg_refuse(report, path, reason);
        return false;
    }
    hg_grant_write(path);
    rm = zcl_tree_remove(path);
    if (!hg_exists(path)) {
        hg_prune(cls->repo);
        return true;
    }
    (void)snprintf(reason, sizeof(reason), "remove_failed:%s",
                   rm.ok ? "still_present" : hg_why(&rm));
    hg_refuse(report, path, reason);
    return false;
}

static void hg_act(const struct host_gc_request *req,
                   struct host_gc_report *report, struct host_gc_class *cls,
                   const struct hg_cand *c, enum hg_verdict v)
{
    uint64_t bytes = hg_dir_bytes(c->path);
    bool gone;
    cls->bytes_reclaimable += bytes;
    if (!req->apply)
        return;
    if (v == HG_ARCHIVE_UNIQUE && !hg_pin_head(req, cls->repo, c->path)) {
        cls->unique_archived--;
        cls->kept_on_failure++;
        cls->reapable--;
        cls->need_review++;
        return;
    }
    gone = hg_reap(cls->repo, c->path) && !hg_exists(c->path);
    if (!gone)
        gone = hg_finish_removal(req, report, cls, c->path);
    if (gone) {
        cls->bytes_reclaimed += bytes;
        return;
    }
    /* Nothing moved, and the refusal above says why. The generation stands;
     * report it as needing a human rather than counting a reclaim that
     * never happened. */
    cls->reapable--;
    cls->need_review++;
}

/* A dirty worktree is never touched; it is listed so a person decides. */
static void hg_note_review(struct host_gc_report *report,
                           const struct hg_cand *c, int64_t now)
{
    struct host_gc_review *r;
    int64_t idle = hg_idle_secs(c->path, now);
    if (report->nreviews >= HOST_GC_MAX_REVIEWS) {
        report->truncated = true;
        return;
    }
    r = &report->reviews[report->nreviews];
    if (!hg_copy(r->path, sizeof(r->path), c->path))
        return;
    r->idle_days = idle < 0 ? -1 : (int)(idle / 86400);
    r->dirty_count = c->dirty > 0 ? c->dirty : 0;
    report->nreviews++;
}

/* ------------------------------------------------------------- per pool */

static bool hg_pool_open(const struct host_gc_request *req,
                         struct host_gc_report *report,
                         struct host_gc_class *cls, char *buf, size_t cap)
{
    char reason[HOST_GC_REASON_CAP];
    bool saw_child = false;
    struct stat st;
    if (host_gc_path_protected(req, "", cls->path, reason, sizeof(reason))) {
        hg_refuse(report, cls->path, reason);
        return false;
    }
    if (stat(cls->path, &st) != 0 || !S_ISDIR(st.st_mode))
        return false;
    cls->present = true;
    /* An EMPTY pool is the normal steady state, not a refusal: there is no
     * worktree to ask which repository owns the pool, and nothing to sweep.
     * A pool that HAS children but where no child answers a git question is
     * different — something is there that this engine cannot classify, so
     * it is refused by name rather than skipped in silence. */
    if (!hg_pool_repo(cls->path, buf, cap, cls->repo, sizeof(cls->repo),
                      &saw_child)) {
        if (saw_child)
            hg_refuse(report, cls->path, "no_repo_behind_pool");
        return false;
    }
    return true;
}

static void hg_settle(const struct host_gc_request *req,
                      struct host_gc_report *report, struct hg_scan *scan,
                      int64_t now)
{
    for (size_t i = 0; i < scan->n; i++) {
        struct hg_cand *c = &scan->cands[i];
        struct host_gc_class *cls = &report->classes[c->cls];
        char reason[HOST_GC_REASON_CAP];
        enum hg_verdict v;
        if (host_gc_path_protected(req, cls->repo, c->path, reason,
                                   sizeof(reason))) {
            hg_refuse(report, c->path, reason);
            cls->need_review++;
            continue;
        }
        v = hg_classify(req, c, now);
        if (!scan->process_inventory_complete && v >= HG_ARCHIVE_UNIQUE) {
            hg_refuse(report, c->path, "process_inventory_incomplete");
            v = HG_KEEP_NEEDS_REVIEW;
        }
        hg_count(cls, v);
        if (v == HG_KEEP_NEEDS_REVIEW && c->dirty != 0)
            hg_note_review(report, c, now);
        if (v >= HG_ARCHIVE_UNIQUE)
            hg_act(req, report, cls, c, v);
    }
}

static void hg_seed_classes(const struct host_gc_request *req,
                            struct host_gc_report *report)
{
    report->nclasses =
        req->npools < HOST_GC_MAX_POOLS ? req->npools : HOST_GC_MAX_POOLS;
    for (size_t i = 0; i < report->nclasses; i++) {
        (void)hg_copy(report->classes[i].name,
                      sizeof(report->classes[i].name), req->pools[i].name);
        (void)hg_copy(report->classes[i].path,
                      sizeof(report->classes[i].path), req->pools[i].path);
    }
}

bool host_gc_run(const struct host_gc_request *req,
                 struct host_gc_report *report)
{
    struct hg_scan scan = {.cap = HOST_GC_MAX_CANDIDATES};
    char *buf;
    int64_t now;

    if (!req || !report)
        return false;
    memset(report, 0, sizeof(*report));
    now = hg_now(req);
    scan.cands = zcl_calloc(HOST_GC_MAX_CANDIDATES, sizeof(*scan.cands),
                            "host_gc candidates");
    buf = zcl_malloc(HG_LIST_CAP, "host_gc worktree listing");
    if (!scan.cands || !buf) {
        free(scan.cands);
        free(buf);
        return false;
    }
    hg_seed_classes(req, report);
    for (size_t i = 0; i < report->nclasses; i++) {
        struct host_gc_class *cls = &report->classes[i];
        if (hg_pool_open(req, report, cls, buf, HG_LIST_CAP))
            hg_parse_worktrees(&scan, i, cls->path, buf, &cls->registered);
    }
    hg_mark_occupied(req, &scan);
    hg_mark_donors(&scan, report->nclasses);
    hg_mark_units(req, &scan);
    hg_settle(req, report, &scan, now);
    report->truncated = scan.truncated;
    free(scan.cands);
    free(buf);
    return true;
}

/* The RAM pool root is read straight from ZCL_RAM_SCRATCH_ROOT rather than
 * through platform_ram_scratch_root(), which refuses when the tmpfs is
 * low on free space — exactly the moment a sweep is most needed. Same
 * variable name, so a live proof and this sweep can never disagree about
 * which tmpfs holds the pool. */
bool host_gc_defaults(struct host_gc_request *req)
{
    const char *home = getenv("HOME");
    const char *ram = getenv("ZCL_RAM_SCRATCH_ROOT");
    if (!req)
        return false;
    memset(req, 0, sizeof(*req));
    req->floor_hours = HOST_GC_DEFAULT_FLOOR_HOURS;
    req->age_days = HOST_GC_DEFAULT_AGE_DAYS;
    if (!home || home[0] != '/' ||
        !hg_copy(req->home, sizeof(req->home), home))
        return false;
    if (!hg_copy(req->pools[0].name, sizeof(req->pools[0].name), "z23p") ||
        !zcl_path_join(req->pools[0].path, sizeof(req->pools[0].path), home,
                 "github/.z23p"))
        return false;
    if (!hg_copy(req->pools[1].name, sizeof(req->pools[1].name), "z23p-ram") ||
        !zcl_path_join(req->pools[1].path, sizeof(req->pools[1].path),
                 (ram && ram[0] == '/') ? ram : "/dev/shm", "z23p"))
        return false;
    req->npools = 2;
    return true;
}
