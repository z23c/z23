/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Seed a cold code index from the nearest sibling checkout's published generation instead of rescanning the whole tree.
 *
 * The first `code` query in a fresh worktree pays a full deterministic index
 * build: measured on this repository, 10.6 s and 427 MB of RSS against 0.22 s
 * once the store exists. Every lane and train worktree on a build host pays it
 * separately, and they are all checkouts of the SAME repository, differing from
 * one another by a handful of files.
 *
 * The bytes that cost those seconds — the scan of every source file into
 * symbol, reference and per-file shard rows — depend on nothing but the source
 * bytes themselves, and codeindex_merkle.c already proves per file whether two
 * checkouts hold the same bytes. So a sibling's published generation is a valid
 * starting point for this one, and the only work left is the files that
 * actually differ. That is exactly what codeindex_incremental.c already does
 * for a single checkout across an edit; this file supplies it a donor.
 *
 * ── VERIFY, DON'T TRUST (the same rule codeindex_fetch.c states) ──
 * A donor is bytes, never authority. It is adopted only after:
 *   - its image passes the owner-controlled private-inode checks a canonical
 *     open applies (a group-writable or shared-link image is declined);
 *   - its store_format and ci_schema_version equal THIS binary's constants;
 *   - its sealed file inventory matches this checkout's live inventory path for
 *     path, which is what makes a donor from a different repository — or the
 *     same repository with a file added or removed — decline itself;
 *   - the checks are re-run against the STAGED COPY, so what is refreshed and
 *     published is the bytes that were verified, not the bytes that were
 *     inspected — and the staged pass is always the row-by-row comparison,
 *     never the sealed-root shortcut that ranking candidates is allowed to
 *     take.
 * The refreshed generation then has to pass `codeindex_is_stale` like any
 * other, in codeindex_build.c, before it is published. Any failure here returns
 * false and the caller performs the ordinary cold build: seeding is a cache of
 * work and never a weakening of what the index is allowed to answer.
 *
 * ── Finding the donors ──
 * Only git's own worktree registry is consulted: `<root>/.git` is the shared
 * directory in a main checkout and, in a linked worktree, a file naming that
 * worktree's admin directory whose `commondir` entry points back at the shared
 * one; `<common>/worktrees/<name>/gitdir` then names each sibling. This is the
 * same record `git worktree list --porcelain` prints, read directly because a
 * lookup does not justify widening this module's capability reach to
 * CAP_PROCESS. Nothing else is examined — the filesystem is never searched for
 * things that look like checkouts.
 *
 * ── What is NOT restamped ──
 * `dep_root_sha3` stays the donor's. It describes the depfile bytes the
 * `includes` rows in this image were parsed from, and those rows ride along
 * verbatim; rewriting it to this checkout's observation would make the record
 * disagree with the rows it seals. `dep_stat_root_sha3` — which IS part of the
 * freshness predicate and is a statement about local build artifacts rather
 * than about any row — is restamped to this checkout's observation by
 * ci_build_store_incremental, exactly as it is on an ordinary incremental
 * publication.
 */

#include "codeindex_priv.h"

#include "codeindex/codeindex_merkle.h"

#include "util/safe_alloc.h"

#include <stdio.h>
#include <string.h>

#if !defined(_WIN32)

#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* Donor kinds, reported verbatim in the seeding diagnostic. */
#define CI_SEED_KIND_MAIN    "the main checkout"
#define CI_SEED_KIND_SIBLING "a sibling worktree"

enum {
    /* A build host accumulates registry entries for worktrees that no longer
     * exist, so the candidate list is generous — a dead entry costs one failed
     * open. */
    CI_SEED_MAX_DONORS = 128,
    /* Opening a candidate generation and comparing it is the one part of the
     * search that scales with the size of the repository, so only this many
     * candidates get that far. The search must not cost what the build it
     * avoids costs. */
    CI_SEED_MAX_COMPARISONS = 16,
    /* A donor is only worth adopting while replacing its differing rows stays
     * cheaper than the deterministic cold build. Bound it by a share of the
     * inventory, with a floor so a small tree is never excluded by rounding. */
    CI_SEED_CHANGED_SHARE = 4,
    CI_SEED_CHANGED_FLOOR = 64,
};

struct ci_seed_donor {
    char        root[CI_PATH_MAX];
    const char *kind;
};

struct ci_seed_candidates {
    struct ci_seed_donor items[CI_SEED_MAX_DONORS];
    int                  count;
};

/* ── git's worktree registry, read as the plain files it is ───────────── */

/* One short single-line git record (a path). Trailing newline and carriage
 * return are stripped; anything longer than a path, unreadable, or replaced by
 * a symlink is simply not a record we will use. */
static bool seed_read_record(const char *path, char *out, size_t cap)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    char buf[CI_PATH_MAX];
    ssize_t got = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (got <= 0) return false;
    buf[got] = '\0';
    char *newline = strchr(buf, '\n');
    if (newline) *newline = '\0';
    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\r' || buf[len - 1] == ' '))
        buf[--len] = '\0';
    if (len == 0 || len + 1 > cap) return false;
    memcpy(out, buf, len + 1);
    return true;
}

/* "<checkout>/.git" → "<checkout>". A registry entry without that shape does
 * not name a checkout this seeding path can read a code index out of. */
static bool seed_checkout_of_gitdir(const char *gitdir, char out[CI_PATH_MAX])
{
    static const char tail[] = "/.git";
    const size_t tail_len = sizeof(tail) - 1;
    size_t len = strlen(gitdir);
    if (len <= tail_len || strcmp(gitdir + len - tail_len, tail) != 0)
        return false;
    size_t keep = len - tail_len;
    if (keep + 1 > CI_PATH_MAX) return false;
    memcpy(out, gitdir, keep);
    out[keep] = '\0';
    return true;
}

/* A linked worktree's `.git` file names its admin directory; that directory's
 * `commondir` entry names the shared git directory, absolute or relative to
 * the admin directory. */
static bool seed_common_dir_of_link(const char *dot_git, char out[CI_PATH_MAX])
{
    static const char prefix[] = "gitdir: ";
    char line[CI_PATH_MAX], relative[CI_PATH_MAX], commondir[CI_PATH_MAX];
    if (!seed_read_record(dot_git, line, sizeof(line)) ||
        strncmp(line, prefix, sizeof(prefix) - 1) != 0)
        return false;
    const char *admin = line + sizeof(prefix) - 1;
    if (admin[0] != '/') return false;
    int n = snprintf(commondir, sizeof(commondir), "%s/commondir", admin);
    if (n <= 0 || (size_t)n >= sizeof(commondir)) return false;
    if (!seed_read_record(commondir, relative, sizeof(relative))) return false;
    n = relative[0] == '/'
        ? snprintf(out, CI_PATH_MAX, "%s", relative)
        : snprintf(out, CI_PATH_MAX, "%s/%s", admin, relative);
    return n > 0 && (size_t)n < CI_PATH_MAX;
}

/* This checkout's shared git directory, or false when the checkout is not part
 * of a git worktree set this path can read. */
static bool seed_common_dir(const char *root, char out[CI_PATH_MAX])
{
    char dot_git[CI_PATH_MAX];
    int n = snprintf(dot_git, sizeof(dot_git), "%s/.git", root);
    if (n <= 0 || (size_t)n >= sizeof(dot_git)) return false;
    struct stat st;
    if (lstat(dot_git, &st) != 0) return false;
    if (S_ISDIR(st.st_mode)) {
        n = snprintf(out, CI_PATH_MAX, "%s", dot_git);
        return n > 0 && (size_t)n < CI_PATH_MAX;
    }
    if (!S_ISREG(st.st_mode)) return false;
    return seed_common_dir_of_link(dot_git, out);
}

/* Directory identity, so "is this candidate the checkout we are seeding?"
 * survives a relative root, a symlinked path, or a bind mount. */
static bool seed_same_directory(const char *left, const char *right)
{
    struct stat a, b;
    return stat(left, &a) == 0 && stat(right, &b) == 0 &&
           a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

static void seed_push_donor(struct ci_seed_candidates *cands, const char *root,
                            const char *self, const char *kind)
{
    if (cands->count >= CI_SEED_MAX_DONORS) return;
    if (seed_same_directory(root, self)) return;
    for (int i = 0; i < cands->count; i++)
        if (strcmp(cands->items[i].root, root) == 0) return;
    ci_cpy(cands->items[cands->count].root,
           sizeof(cands->items[cands->count].root), root);
    cands->items[cands->count].kind = kind;
    cands->count++;
}

static void seed_collect_worktrees(const char *common, const char *self,
                                   struct ci_seed_candidates *cands)
{
    char registry[CI_PATH_MAX];
    int n = snprintf(registry, sizeof(registry), "%s/worktrees", common);
    if (n <= 0 || (size_t)n >= sizeof(registry)) return;
    DIR *dir = opendir(registry);
    if (!dir) return;
    const struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        char record[CI_PATH_MAX], gitdir[CI_PATH_MAX], checkout[CI_PATH_MAX];
        n = snprintf(record, sizeof(record), "%s/%s/gitdir", registry,
                     entry->d_name);
        if (n <= 0 || (size_t)n >= sizeof(record)) continue;
        if (!seed_read_record(record, gitdir, sizeof(gitdir))) continue;
        if (!seed_checkout_of_gitdir(gitdir, checkout)) continue;
        seed_push_donor(cands, checkout, self, CI_SEED_KIND_SIBLING);
    }
    closedir(dir);
}

static void seed_collect_donors(const char *root,
                                struct ci_seed_candidates *cands)
{
    char common[CI_PATH_MAX], main_checkout[CI_PATH_MAX];
    if (!seed_common_dir(root, common)) return;
    /* The shared git directory lives inside the main checkout, so its parent
     * IS that checkout. Taken as a path rather than by trimming a "/.git"
     * suffix, because `commondir` legitimately spells it relatively (git
     * writes "../.." there) and a candidate that turns out not to be a
     * checkout simply has no index.kv to open. */
    int n = snprintf(main_checkout, sizeof(main_checkout), "%s/..", common);
    if (n > 0 && (size_t)n < sizeof(main_checkout))
        seed_push_donor(cands, main_checkout, root, CI_SEED_KIND_MAIN);
    seed_collect_worktrees(common, root, cands);
}

/* ── reading one donor's published generation ─────────────────────────── */

/* The private owner-controlled inode discipline a canonical open applies:
 * ours, no group/other write, and for the image itself a single-linked
 * non-empty regular file. */
static bool seed_inode_is_private(int fd, bool directory)
{
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_uid != geteuid() ||
        (st.st_mode & (S_IWGRP | S_IWOTH)))
        return false;
    if (directory) return S_ISDIR(st.st_mode);
    return S_ISREG(st.st_mode) && st.st_nlink == 1 && st.st_size > 0;
}

static int seed_open_image(const char *donor_root)
{
    char derived[CI_PATH_MAX];
    int n = snprintf(derived, sizeof(derived), "%s/.codeindex", donor_root);
    if (n <= 0 || (size_t)n >= sizeof(derived)) return -1;
    int dirfd = open(derived, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0) return -1;
    if (!seed_inode_is_private(dirfd, true)) {
        close(dirfd);
        return -1;
    }
    int fd = openat(dirfd, "index.kv", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    close(dirfd);
    if (fd < 0) return -1;
    if (!seed_inode_is_private(fd, false)) {
        close(fd);
        return -1;
    }
    return fd;
}

static bool seed_meta_equals(struct ci_store *store, const char *key,
                             const char *expect, size_t expect_len)
{
    char value[64];
    size_t len = 0;
    bool found = false;
    if (expect_len > sizeof(value)) return false;
    if (!ci_store_meta_get(store, key, value, sizeof(value), &len, &found))
        return false;
    return found && len == expect_len && memcmp(value, expect, expect_len) == 0;
}

/* A generation this exact binary could have produced. A store written by a
 * different derived layout is not repaired and not adopted. */
static bool seed_generation_matches_binary(struct ci_store *store)
{
    return seed_meta_equals(store, "store_format", CI_STORE_FORMAT,
                            sizeof(CI_STORE_FORMAT) - 1) &&
           seed_meta_equals(store, "ci_schema_version", CI_SCHEMA_VERSION,
                            sizeof(CI_SCHEMA_VERSION) - 1);
}

/* Compare a candidate generation against this checkout's live Merkle leaves.
 * Returns the number of files whose sealed content digest differs, or -1 when
 * the candidate cannot describe this checkout at all: a different inventory
 * (a foreign repository, or one with a file added or removed) is declined
 * here, because replacing rows cannot add or remove them. */
static int seed_distance(struct ci_store *store,
                         const struct ci_merkle_leaf *current,
                         int current_count, struct ci_merkle_leaf *scratch)
{
    if (!seed_generation_matches_binary(store)) return -1;
    bool inventory_same = false;
    int changed = ci_store_diff_merkle_leaves(store, current, current_count,
                                              scratch, current_count,
                                              &inventory_same);
    return inventory_same ? changed : -1;
}

/* How far is this donor from describing THIS checkout? Zero when its sealed
 * source Merkle root equals the one codeindex_merkle.c just computed here —
 * one 32-byte comparison that settles inventory and content together, and the
 * ordinary case on a build host where every lane worktree starts at the same
 * base. Otherwise the number of files whose sealed content digest differs, or
 * -1 when the donor cannot describe this checkout at all: a different
 * inventory (a foreign repository, or one with a file added or removed) is
 * declined here, because replacing rows cannot add or remove them. */
static int seed_donor_distance(struct ci_store *donor,
                               const struct ci_merkle_leaf *current,
                               int current_count,
                               struct ci_merkle_leaf *scratch,
                               const uint8_t merkle_root[32])
{
    if (!seed_generation_matches_binary(donor)) return -1;
    if (seed_meta_equals(donor, "source_merkle_root_sha3",
                         (const char *)merkle_root, 32))
        return 0;
    bool inventory_same = false;
    int changed = ci_store_diff_merkle_leaves(donor, current, current_count,
                                              scratch, current_count,
                                              &inventory_same);
    return inventory_same ? changed : -1;
}

/* An absent or unusable image is not a candidate that was compared: it costs
 * one failed open and must not spend the comparison budget below. */
enum { CI_SEED_NO_GENERATION = -2 };

static int seed_candidate_distance(const char *donor_root,
                                   const struct ci_merkle_leaf *current,
                                   int current_count,
                                   struct ci_merkle_leaf *scratch,
                                   const uint8_t merkle_root[32])
{
    int fd = seed_open_image(donor_root);
    if (fd < 0) return CI_SEED_NO_GENERATION;
    /* Takes ownership of the descriptor on success and on failure alike. */
    struct ci_store *donor = ci_store_open_readonly_fd(fd);
    if (!donor) return CI_SEED_NO_GENERATION;
    int distance = seed_donor_distance(donor, current, current_count, scratch,
                                       merkle_root);
    ci_store_close(donor);
    return distance;
}

static int seed_changed_limit(int current_count)
{
    int share = current_count / CI_SEED_CHANGED_SHARE;
    return share > CI_SEED_CHANGED_FLOOR ? share : CI_SEED_CHANGED_FLOOR;
}

/* The nearest reconcilable donor, or -1. Nearest is fewest differing files —
 * that is exactly the count of files the refresh has to rescan, so it is the
 * cost being minimized and not a proxy for it. A donor that seals this exact
 * tree ends the search. Each candidate's image is opened once, and only the
 * first CI_SEED_MAX_COMPARISONS readable ones are compared at all, because
 * that comparison is the part of the search whose cost grows with the
 * repository. */
static int seed_choose_donor(const struct ci_seed_candidates *cands,
                             const struct ci_merkle_leaf *current,
                             int current_count,
                             struct ci_merkle_leaf *scratch,
                             const uint8_t merkle_root[32])
{
    const int limit = seed_changed_limit(current_count);
    int best = -1, examined = 0, best_distance = -1;
    for (int i = 0;
         i < cands->count && examined < CI_SEED_MAX_COMPARISONS; i++) {
        int distance = seed_candidate_distance(cands->items[i].root, current,
                                               current_count, scratch,
                                               merkle_root);
        if (distance == CI_SEED_NO_GENERATION) continue;
        /* One generation was opened and compared: that is the cost this
         * budget exists to bound, so it counts even when it declines. */
        examined++;
        if (distance == 0) return i;
        if (distance < 0 || distance > limit) continue;
        if (best < 0 || distance < best_distance) {
            best = i;
            best_distance = distance;
        }
    }
    return best;
}
/* ── refreshing the staged copy onto this checkout ────────────────────── */

/* Re-verify the STAGED bytes and replace the rows of every file that differs.
 * The diff is recomputed here rather than carried over from donor selection so
 * the rows that get replaced are derived from the image actually staged. */
static bool seed_write_receipt(struct ci_store *staged, const char *kind,
                               int refreshed)
{
    char files[24];
    int n = snprintf(files, sizeof(files), "%d", refreshed);
    return n > 0 && (size_t)n < sizeof(files) &&
           ci_store_meta_set(staged, "build_seed_donor", kind, strlen(kind)) &&
           ci_store_meta_set(staged, "build_seed_files", files, (size_t)n);
}

static bool seed_refresh_staged(const char *root, int stagefd,
                                const struct ci_merkle_leaf *current,
                                int current_count,
                                struct ci_merkle_leaf *scratch,
                                const uint8_t dep_stat[32],
                                const uint8_t merkle_root[32],
                                const char *kind, int *refreshed)
{
    struct ci_store *staged = ci_store_open_rw_fd(stagefd);
    if (!staged) return false;
    /* Deliberately the row-by-row comparison and never the sealed-root
     * shortcut donor RANKING is allowed to take: what gets published is
     * verified against the rows it actually holds. */
    int changed = seed_distance(staged, current, current_count, scratch);
    bool ok = changed >= 0 &&
              ci_build_store_incremental(root, staged, scratch, changed,
                                         dep_stat, merkle_root) &&
              seed_write_receipt(staged, kind, changed);
    ci_store_close(staged);
    if (ok) *refreshed = changed;
    return ok;
}

static bool seed_copy_donor(const char *donor_root, int stagefd)
{
    int image_fd = seed_open_image(donor_root);
    if (image_fd < 0) return false;
    bool ok = ci_copy_image_fd(image_fd, stagefd);
    close(image_fd);
    return ok;
}

static bool seed_stage_posix(const char *root, int stagefd,
                             const struct ci_merkle_leaf *current,
                             int current_count, const uint8_t dep_stat[32],
                             const uint8_t merkle_root[32],
                             struct ci_seed_outcome *outcome)
{
    struct ci_seed_candidates *cands =
        zcl_calloc(1, sizeof(*cands), "ci_seed_donors");
    struct ci_merkle_leaf *scratch =
        zcl_calloc((size_t)current_count, sizeof(*scratch), "ci_seed_changed");
    int best = -1, refreshed = 0;
    bool ok = cands != NULL && scratch != NULL;
    if (ok) {
        seed_collect_donors(root, cands);
        best = seed_choose_donor(cands, current, current_count, scratch,
                                 merkle_root);
        ok = best >= 0;
    }
    ok = ok && seed_copy_donor(cands->items[best].root, stagefd) &&
         seed_refresh_staged(root, stagefd, current, current_count, scratch,
                             dep_stat, merkle_root, cands->items[best].kind,
                             &refreshed);
    if (ok) {
        outcome->seeded = true;
        outcome->files_refreshed = refreshed;
        ci_cpy(outcome->donor_kind, sizeof(outcome->donor_kind),
               cands->items[best].kind);
    }
    free(cands);
    free(scratch);
    return ok;
}

#endif /* !_WIN32 */

/* A generation patched in place descends from whatever produced it, but the
 * file count in a seeding receipt describes ONE publication. Clearing it keeps
 * the receipt a statement about the generation that carries it rather than an
 * inherited claim no later publication re-earned. */
void ci_seed_receipt_clear(struct ci_store *store)
{
    if (!store) return;
    (void)ci_store_meta_set(store, "build_seed_donor", "", 0);
    (void)ci_store_meta_set(store, "build_seed_files", "", 0);
}

/* One public definition above the platform split (check-arm-symbol-single).
 * The native Windows publisher does not stage through an integer descriptor,
 * so there is no Windows arm to dispatch to and a cold build there stays a
 * cold build. */
bool ci_seed_stage_generation(const char *root, int stagefd,
                              const struct ci_merkle_leaf *current,
                              int current_count, const uint8_t dep_stat[32],
                              const uint8_t merkle_root[32],
                              struct ci_seed_outcome *outcome)
{
    if (!outcome) return false;
    memset(outcome, 0, sizeof(*outcome));
    if (!root || !root[0] || stagefd < 0 || !current || current_count <= 0 ||
        !dep_stat || !merkle_root)
        return false;
#if defined(_WIN32)
    return false;
#else
    return seed_stage_posix(root, stagefd, current, current_count, dep_stat,
                            merkle_root, outcome);
#endif
}
