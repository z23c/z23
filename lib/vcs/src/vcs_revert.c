/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * vcs_revert — the vcs_revert() worktree-restore facility, split out of
 * vcs.c. Every symbol here (the two-phase stage/commit plan, its diff
 * collector, and mkdir_parents, its only caller) is reached exclusively
 * through vcs_revert(); none of it is touched by vcs_open/vcs_close,
 * vcs_snapshot, vcs_status, or vcs_log, and it shares no file-scope state
 * with vcs.c beyond the two declarations in vcs_repo_priv.h. */

#if !defined(_WIN32)
#define _GNU_SOURCE

#include "vcs/vcs.h"
#include "vcs/vcs_object.h"
#include "vcs/vcs_seal.h"

#include "vcs_repo_priv.h"
#include "vcs_walk.h"

#include "base/hex.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Create parent directories of <repo>/<relpath>. Sole caller:
 * revert_stage_op(), below. */
static bool mkdir_parents(const char *repo, const char *relpath)
{
    char full[VCS_FA_PATH_MAX];
    int n = snprintf(full, sizeof(full), "%s/%s", repo, relpath);
    if (n <= 0 || (size_t)n >= sizeof(full))
        LOG_FAIL("vcs", "path too long");
    /* Walk components, mkdir each dir up to (not including) the final name. */
    for (char *p = full + strlen(repo) + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(full, 0755) != 0 && errno != EEXIST) {
                *p = '/';
                LOG_FAIL("vcs", "mkdir %s: %s", full, strerror(errno));
            }
            *p = '/';
        }
    }
    return true;
}

/* ── revert ──────────────────────────────────────────────────────── */

/* One planned worktree mutation. For a write op, `tmp` names the phase-1
 * staged temp file (heap, sitting beside `full` on the same filesystem) once
 * staged, and is consumed (set NULL) when phase 2 renames it into place. For a
 * delete op only `relpath`/`full` are used. Deferring application (rather than
 * writing as the diff is walked) is what lets the restore be all-or-nothing:
 * every target file's bytes are staged and validated before a single one is
 * moved into the live worktree. */
struct revert_op {
    bool     is_delete;
    char    *relpath;   /* tracked path relative to the repo root */
    char    *full;      /* absolute destination path */
    char    *tmp;       /* staged temp path (writes only; NULL until staged) */
    uint32_t mode;      /* target file mode (writes only) */
    uint8_t  blob[32];  /* target blob object id (writes only) */
};

struct revert_plan {
    struct vcs_repo  *r;
    struct revert_op *ops;
    size_t            count;
    size_t            cap;
    bool              err;    /* collection-time failure (alloc / bad path) */
};

/* Free the plan's heap. When unlink_temps is true, any still-staged temp (a
 * write not yet renamed into place) is removed so a failure leaves nothing
 * behind. Committed writes have already NULLed their tmp, so they are skipped. */
static void revert_plan_free(struct revert_plan *p, bool unlink_temps)
{
    for (size_t i = 0; i < p->count; i++) {
        struct revert_op *op = &p->ops[i];
        if (unlink_temps && op->tmp)
            (void)unlink(op->tmp);
        free(op->tmp);
        free(op->full);
        free(op->relpath);
    }
    free(p->ops);
    p->ops = NULL;
    p->count = p->cap = 0;
}

/* Diff callback: a = current worktree, b = target. Records the mutation that
 * moves the worktree toward the target WITHOUT applying it. */
static void revert_collect_cb(enum vcs_diff_kind kind, const struct vcs_entry *a,
                              const struct vcs_entry *b, void *user)
{
    struct revert_plan *p = user;
    if (p->err) return;

    const struct vcs_entry *e;    /* the path-bearing side */
    bool is_delete;
    if (kind == VCS_DIFF_REMOVED) {
        /* present in current, absent in target -> delete (if tracked). */
        if (vcs_path_ignored(a->path))
            return;
        e = a;
        is_delete = true;
    } else {
        /* ADDED or MODIFIED in target -> write target content. */
        if (!b) { p->err = true; return; }
        e = b;
        is_delete = false;
    }

    if (p->count == p->cap) {
        size_t ncap = p->cap ? p->cap * 2 : 32;
        struct revert_op *no =
            zcl_realloc(p->ops, ncap * sizeof(*no), "vcs_revert_ops");
        if (!no) { p->err = true; return; }
        p->ops = no;
        p->cap = ncap;
    }
    struct revert_op *op = &p->ops[p->count];
    memset(op, 0, sizeof(*op));
    op->is_delete = is_delete;
    op->relpath = zcl_strdup(e->path, "vcs_revert_relpath");
    if (!op->relpath) { p->err = true; return; }
    char full[VCS_FA_PATH_MAX];
    int n = snprintf(full, sizeof(full), "%s/%s", p->r->root, e->path);
    if (n <= 0 || (size_t)n >= sizeof(full)) {
        free(op->relpath);
        p->err = true;
        return;
    }
    op->full = zcl_strdup(full, "vcs_revert_full");
    if (!op->full) { free(op->relpath); p->err = true; return; }
    if (!is_delete) {
        op->mode = e->mode;
        memcpy(op->blob, e->blob, 32);
    }
    p->count++;   /* only after both allocations succeed */
}

/* Phase 1: stage a write op's target bytes into a temp file beside op->full
 * (same filesystem) and fsync it, WITHOUT renaming into place. On success
 * op->tmp names the staged temp. On ANY failure the temp is cleaned and false
 * is returned with op->tmp left NULL — the live worktree is untouched. */
static bool revert_stage_op(struct vcs_repo *r, struct revert_op *op)
{
    uint8_t *content = NULL;
    size_t clen = 0;
    if (vcs_object_get(r->root, op->blob, VCS_TAG_BLOB, &content, &clen) != 0)
        LOG_FAIL("vcs", "load blob for %s", op->relpath);
    if (!mkdir_parents(r->root, op->relpath)) {
        free(content);
        LOG_FAIL("vcs", "mkdir parents for %s", op->relpath);
    }

    static _Atomic uint64_t g_seq = 0;
    uint64_t seq = atomic_fetch_add(&g_seq, 1);
    char tmp[VCS_FA_PATH_MAX];
    int tn = snprintf(tmp, sizeof(tmp), "%s.zvcstmp.%ld.%llu", op->full,
                      (long)getpid(), (unsigned long long)seq);
    if (tn <= 0 || (size_t)tn >= sizeof(tmp)) {
        free(content);
        LOG_FAIL("vcs", "tmp path too long for %s", op->relpath);
    }
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        free(content);
        LOG_FAIL("vcs", "open tmp %s: %s", tmp, strerror(errno));
    }
    size_t off = 0;
    while (off < clen) {
        ssize_t w = write(fd, content + off, clen - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            close(fd); unlink(tmp); free(content);
            LOG_FAIL("vcs", "write tmp %s", tmp);
        }
        off += (size_t)w;
    }
    free(content);
    if (fsync(fd) != 0) { close(fd); unlink(tmp); LOG_FAIL("vcs", "fsync tmp %s", tmp); }
    close(fd);
    op->tmp = zcl_strdup(tmp, "vcs_revert_tmp");
    if (!op->tmp) { unlink(tmp); LOG_FAIL("vcs", "strdup tmp path"); }
    return true;
}

/* Phase 2: put a staged write into place (rename) or apply a delete. A
 * same-filesystem rename is near-atomic and effectively cannot fail here; a
 * failure returns false and leaves the caller to report VCS_EPARTIAL. */
static bool revert_commit_op(struct revert_op *op)
{
    if (op->is_delete) {
        if (unlink(op->full) != 0 && errno != ENOENT)
            LOG_FAIL("vcs", "unlink %s: %s", op->full, strerror(errno));
        return true;
    }
    if (rename(op->tmp, op->full) != 0)
        LOG_FAIL("vcs", "rename %s -> %s: %s", op->tmp, op->full, strerror(errno));
    free(op->tmp);
    op->tmp = NULL;   /* consumed by the rename: no temp left to clean up */
    /* Restore permission bits (best-effort; a failure is non-fatal). */
    if (chmod(op->full, (mode_t)(op->mode & 0777)) != 0) { /* tolerate */ }
    return true;
}

int vcs_revert(struct vcs_repo *r, const uint8_t target_commit[32],
               const struct vcs_revert_relink_ops *relink,
               uint8_t out_new_commit[32])
{
    if (!r || !target_commit || !out_new_commit)
        LOG_ERR("vcs", "null arg to revert");

    /* Load the target manifest. */
    struct vcs_commit tc;
    if (!load_commit_by_id(r->root, target_commit, &tc))
        LOG_ERR("vcs", "load target commit");
    struct vcs_manifest target;
    if (!manifest_load(r->root, tc.tree_hash, &target))
        LOG_ERR("vcs", "load target manifest");

    /* Seal pre-check, BEFORE any worktree file is touched. A full revert
     * converges the worktree to exactly the target manifest over tracked,
     * non-ignored paths, so the sealset the target manifest produces is the
     * same one vcs_snapshot() below will (authoritatively, and consuming any
     * token) recompute once the write has happened. Without this pre-check a
     * revert refused for touching a sealed path would still have silently
     * overwritten that sealed file's on-disk bytes with unauthorized content
     * before vcs_snapshot() got a chance to say no — this mirrors
     * vcs_snapshot's own vcs_seal_check() guard (see there), just moved
     * earlier and non-consuming (vcs_seal_peek) so a legitimately
     * token-authorized revert still lets vcs_snapshot() spend the token
     * exactly once. */
    char **seal_globs = NULL;
    size_t n_seal_globs = 0;
    if (!vcs_seal_load_globs(r->root, &seal_globs, &n_seal_globs)) {
        vcs_manifest_free(&target);
        LOG_ERR("vcs", "load globs (revert seal pre-check)");
    }
    uint8_t target_sealset[32];
    bool tsh = vcs_sealset_hash(&target, seal_globs, n_seal_globs, target_sealset);
    vcs_seal_free_globs(seal_globs, n_seal_globs);
    if (!tsh) {
        vcs_manifest_free(&target);
        LOG_ERR("vcs", "sealset_hash (revert seal pre-check)");
    }
    enum vcs_seal_result presr = vcs_seal_peek(r->idx, target_sealset);
    if (presr == VCS_SEAL_REFUSED) {
        vcs_manifest_free(&target);
        return VCS_REFUSED;
    }
    if (presr != VCS_SEAL_OK) {
        vcs_manifest_free(&target);
        LOG_ERR("vcs", "seal pre-check error");
    }

    /* Current worktree manifest. */
    struct vcs_manifest cur;
    if (!vcs_manifest_build(r->root, r->idx, &cur)) {
        vcs_manifest_free(&target);
        LOG_ERR("vcs", "build current manifest");
    }

    /* Plan the restore (writes + deletes), then apply it in two phases so it is
     * all-or-nothing over the write set. A mid-restore failure must leave the
     * worktree in its pre-revert state, never a half-applied hybrid matching
     * neither the pre-revert tree nor the target.
     *
     * Phase 1 stages every target file's bytes to a temp beside its
     * destination (same filesystem) and fsyncs; if ANY stage fails, the temps
     * are removed and the worktree is returned untouched. Phase 2 renames each
     * staged temp into place and applies deletes. A same-filesystem rename is
     * near-atomic and effectively cannot fail after a successful stage; if one
     * somehow does, the caller is told exactly which paths already flipped and
     * the call reports VCS_EPARTIAL (a partial, honestly-named state) rather
     * than pretending the revert was clean. */
    struct revert_plan plan = { .r = r };
    vcs_manifest_diff(&cur, &target, revert_collect_cb, &plan);
    vcs_manifest_free(&cur);
    vcs_manifest_free(&target);
    if (plan.err) {
        revert_plan_free(&plan, true);
        LOG_ERR("vcs", "plan worktree restore");
    }

    /* Phase 1 — stage every write. The live worktree stays untouched until the
     * whole write set has been staged and validated. */
    for (size_t i = 0; i < plan.count; i++) {
        if (plan.ops[i].is_delete) continue;
        if (!revert_stage_op(r, &plan.ops[i])) {
            revert_plan_free(&plan, true);   /* unlink every staged temp */
            LOG_ERR("vcs", "stage worktree restore (worktree left untouched)");
        }
    }

    /* Phase 2 — commit: rename staged temps into place, then apply deletes. */
    size_t committed = 0;
    for (size_t i = 0; i < plan.count; i++) {
        if (!revert_commit_op(&plan.ops[i])) {
            /* Near-impossible on a single filesystem. Name the mutations that
             * already flipped [0,committed) plus the one that failed, so the
             * partial state is recoverable and honestly reported. */
            LOG_WARN("vcs", "partial worktree restore — %zu of %zu mutation(s) "
                     "already applied before a phase-2 failure:",
                     committed, plan.count);
            for (size_t k = 0; k < committed; k++)
                LOG_WARN("vcs", "  %s: %s",
                         plan.ops[k].is_delete ? "deleted" : "wrote",
                         plan.ops[k].relpath);
            LOG_WARN("vcs", "  FAILED on %s: %s",
                     plan.ops[i].is_delete ? "delete" : "write",
                     plan.ops[i].relpath);
            revert_plan_free(&plan, true);   /* unlink any not-yet-renamed temps */
            return VCS_EPARTIAL;
        }
        committed++;
    }
    revert_plan_free(&plan, true);   /* frees heap; committed temps already NULL */

    /* Record the restoration as a forward commit. */
    char taskref[64];
    char hex[65];
    zcl_hex_encode(target_commit, 32, hex);
    snprintf(taskref, sizeof(taskref), "revert:%.16s", hex);
    struct vcs_snapshot_meta meta = {0};
    meta.verdict_status = tc.verdict_status;
    meta.phase = "revert";
    meta.generation_sha256 = tc.generation_sha256;
    meta.task_ref = taskref;
    int sr = vcs_snapshot(r, &meta, out_new_commit);
    if (sr != VCS_OK)
        return sr;  /* propagate VCS_REFUSED / VCS_ERR */

    /* Binary-generation relink half. The source revert + forward
     * commit above already stand — append-only, never undone — regardless of
     * what happens below. */
    if (relink && relink->activate_generation) {
        static const uint8_t zero32[32] = {0};
        if (memcmp(tc.generation_sha256, zero32, 32) != 0) {
            if (!relink->activate_generation(tc.generation_sha256, relink->ctx))
                return VCS_EPARTIAL;
        }
    }
    return VCS_OK;
}

#else /* _WIN32 */

/* vcs.c's own Windows branch defines vcs_revert() as an unconditional
 * refusal and never reaches this file's POSIX worktree-restore code. ISO C
 * forbids an empty translation unit under -Wpedantic -Werror. */
typedef int vcs_revert_win32_no_op_placeholder;

#endif /* _WIN32 */
