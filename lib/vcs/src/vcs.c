/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * vcs — the ZVCS façade implementation. See vcs/vcs.h. */

#if !defined(_WIN32)
#define _GNU_SOURCE
#endif

#include "vcs/vcs.h"
#include "vcs/vcs_object.h"
#include "vcs/vcs_seal.h"

#include "vcs_priv.h"
#include "vcs_walk.h"

#include "platform/time_compat.h"
#include "storage/event_log.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <errno.h>
#if !defined(_WIN32)
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#endif

#define VCS_FA_PATH_MAX 4096

struct vcs_repo {
    char              root[VCS_FA_PATH_MAX];
    struct vcs_index *idx;
    event_log_t      *log;
};

#if !defined(_WIN32)

/* ── small filesystem helpers ────────────────────────────────────── */

static int read_whole_file(const char *repo, const char *relpath,
                           uint8_t **out, size_t *out_len)
{
    *out = NULL;
    *out_len = 0;
    char full[VCS_FA_PATH_MAX];
    int n = snprintf(full, sizeof(full), "%s/%s", repo, relpath);
    if (n <= 0 || (size_t)n >= sizeof(full))
        LOG_ERR("vcs", "path too long");
    int fd = open(full, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        LOG_ERR("vcs", "open %s: %s", full, strerror(errno));
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 0) {
        close(fd);
        LOG_ERR("vcs", "fstat %s", full);
    }
    size_t len = (size_t)st.st_size;
    uint8_t *buf = NULL;
    if (len > 0) {
        buf = zcl_malloc(len, "vcs_read_file");
        if (!buf) { close(fd); LOG_ERR("vcs", "malloc %zu", len); }
        size_t off = 0;
        while (off < len) {
            ssize_t r = read(fd, buf + off, len - off);
            if (r < 0) { if (errno == EINTR) continue; free(buf); close(fd); LOG_ERR("vcs", "read"); }
            if (r == 0) break;
            off += (size_t)r;
        }
        if (off != len) { free(buf); close(fd); LOG_ERR("vcs", "short read"); }
    }
    close(fd);
    *out = buf;
    *out_len = len;
    return 0;
}

/* Create parent directories of <repo>/<relpath>. */
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

/* ── manifest object store (addressed by structural tree_hash) ───── */

static bool manifest_store(const char *repo, const struct vcs_manifest *m,
                           uint8_t out_tree_hash[32])
{
    if (!vcs_manifest_tree_hash(m, out_tree_hash))
        LOG_FAIL("vcs", "tree_hash");
    uint8_t *ser = NULL;
    size_t serlen = 0;
    if (!vcs_manifest_serialize(m, &ser, &serlen))
        LOG_FAIL("vcs", "serialize manifest");
    bool ok = vcs_object_put_addressed(repo, out_tree_hash, ser, serlen);
    free(ser);
    if (!ok)
        LOG_FAIL("vcs", "put manifest object");
    return true;
}

static bool manifest_load(const char *repo, const uint8_t tree_hash[32],
                          struct vcs_manifest *out)
{
    uint8_t *ser = NULL;
    size_t serlen = 0;
    if (vcs_object_load_raw(repo, tree_hash, &ser, &serlen) != 0)
        LOG_FAIL("vcs", "load manifest object");
    bool parsed = vcs_manifest_parse(ser, serlen, out);
    free(ser);
    if (!parsed)
        LOG_FAIL("vcs", "parse manifest object");
    /* recompute-never-trust: re-derive tree_hash and verify it addresses this
     * object. */
    uint8_t got[32];
    if (!vcs_manifest_tree_hash(out, got) || memcmp(got, tree_hash, 32) != 0) {
        vcs_manifest_free(out);
        LOG_FAIL("vcs", "manifest tree_hash mismatch (corruption)");
    }
    return true;
}

bool vcs_tree_load(const char *repo_root, const uint8_t tree_hash[32],
                   struct vcs_manifest *out)
{
    if (!repo_root || !tree_hash || !out)
        LOG_FAIL("vcs", "null arg to tree_load");
    return manifest_load(repo_root, tree_hash, out);
}

static bool load_commit_by_id(const char *repo, const uint8_t commit_id[32],
                              struct vcs_commit *out)
{
    uint8_t *pre = NULL;
    size_t prelen = 0;
    if (vcs_object_get(repo, commit_id, VCS_TAG_COMMIT, &pre, &prelen) != 0)
        LOG_FAIL("vcs", "load commit object");
    bool ok = vcs_commit_parse_preimage(pre, prelen, out);
    free(pre);
    if (!ok)
        LOG_FAIL("vcs", "parse commit preimage");
    return true;
}

/* ── open / close ────────────────────────────────────────────────── */

struct vcs_repo *vcs_open(const char *repo_root)
{
    if (!repo_root || !repo_root[0])
        LOG_NULL("vcs", "null repo_root");
    if (!vcs_object_store_init(repo_root))
        LOG_NULL("vcs", "object store init failed");

    struct vcs_repo *r = zcl_calloc(1, sizeof(*r), "vcs_repo");
    if (!r)
        LOG_NULL("vcs", "calloc vcs_repo");
    int n = snprintf(r->root, sizeof(r->root), "%s", repo_root);
    if (n <= 0 || (size_t)n >= sizeof(r->root)) { free(r); LOG_NULL("vcs", "root too long"); }

    r->idx = vcs_index_open(repo_root);
    if (!r->idx) { free(r); LOG_NULL("vcs", "index open failed"); }

    char logpath[VCS_FA_PATH_MAX];
    int ln = snprintf(logpath, sizeof(logpath), "%s/.zvcs/commits.log", repo_root);
    if (ln <= 0 || (size_t)ln >= sizeof(logpath)) {
        vcs_index_close(r->idx); free(r); LOG_NULL("vcs", "log path too long");
    }
    r->log = event_log_open(logpath);
    if (!r->log) {
        vcs_index_close(r->idx); free(r); LOG_NULL("vcs", "commits.log open failed");
    }
    return r;
}

void vcs_close(struct vcs_repo *r)
{
    if (!r) return;
    if (r->log) event_log_close(r->log);
    if (r->idx) vcs_index_close(r->idx);
    free(r);
}

struct vcs_index *vcs_repo_index(struct vcs_repo *r) { return r ? r->idx : NULL; }
const char *vcs_repo_root(struct vcs_repo *r) { return r ? r->root : NULL; }

/* ── snapshot ────────────────────────────────────────────────────── */

/* Ensure every blob referenced by the manifest is in the selected object
 * store, reading bytes only from the scanned source root. */
static bool put_manifest_blobs(const char *scan_root, const char *store_root,
                               const struct vcs_manifest *m)
{
    for (size_t i = 0; i < m->count; i++) {
        if (vcs_object_has(store_root, m->entries[i].blob))
            continue;
        uint8_t *content = NULL;
        size_t clen = 0;
        if (read_whole_file(scan_root, m->entries[i].path, &content, &clen) != 0)
            LOG_FAIL("vcs", "read blob %s", m->entries[i].path);
        uint8_t got[32];
        bool ok = vcs_object_put(store_root, content, clen, VCS_TAG_BLOB, got);
        free(content);
        if (!ok)
            LOG_FAIL("vcs", "put blob %s", m->entries[i].path);
        if (memcmp(got, m->entries[i].blob, 32) != 0)
            LOG_FAIL("vcs", "blob changed under snapshot: %s", m->entries[i].path);
    }
    return true;
}

static void fill_fixed(char *dst, size_t cap, const char *src)
{
    memset(dst, 0, cap);
    if (src) {
        size_t l = strlen(src);
        if (l >= cap) l = cap - 1;
        memcpy(dst, src, l);
    }
}

static int tree_capture_from(const char *scan_root, struct vcs_index *idx,
                             const char *store_root,
                             uint8_t out_tree_hash[32])
{
    if (!scan_root || !idx || !store_root || !out_tree_hash)
        LOG_ERR("vcs", "null arg to tree_capture");
    struct vcs_manifest first, second, checked;
    if (!vcs_manifest_build(scan_root, idx, &first))
        LOG_ERR("vcs", "build source manifest");
    if (!put_manifest_blobs(scan_root, store_root, &first)) {
        vcs_manifest_free(&first);
        LOG_ERR("vcs", "store source blobs");
    }
    uint8_t first_root[32], second_root[32];
    if (!manifest_store(store_root, &first, first_root)) {
        vcs_manifest_free(&first);
        LOG_ERR("vcs", "store source manifest");
    }
    vcs_manifest_free(&first);
    if (!vcs_manifest_build(scan_root, idx, &second))
        LOG_ERR("vcs", "rebuild source manifest");
    bool stable = vcs_manifest_tree_hash(&second, second_root) &&
                  memcmp(first_root, second_root, 32) == 0;
    vcs_manifest_free(&second);
    if (!stable)
        LOG_ERR("vcs", "source changed during tree capture");
    if (!manifest_load(store_root, first_root, &checked))
        LOG_ERR("vcs", "source manifest readback failed");
    vcs_manifest_free(&checked);
    memcpy(out_tree_hash, first_root, 32);
    return VCS_OK;
}
int vcs_tree_capture(struct vcs_repo *r, uint8_t out_tree_hash[32])
{
    if (!r || !out_tree_hash)
        LOG_ERR("vcs", "null arg to tree_capture");
    return tree_capture_from(r->root, r->idx, r->root, out_tree_hash);
}

int vcs_tree_capture_path(const char *repo_root, uint8_t out_tree_hash[32])
{
    return vcs_tree_capture_into(repo_root, repo_root, out_tree_hash);
}

int vcs_tree_capture_into(const char *scan_root, const char *object_store_root,
                          uint8_t out_tree_hash[32])
{
    if (!scan_root || !scan_root[0] || !object_store_root ||
        !object_store_root[0] || !out_tree_hash)
        LOG_ERR("vcs", "null arg to tree_capture_into");
    if (!vcs_object_store_init(scan_root) ||
        !vcs_object_store_init(object_store_root))
        LOG_ERR("vcs", "source object store init failed");
    struct vcs_index *idx = vcs_index_open(scan_root);
    if (!idx)
        LOG_ERR("vcs", "source index open failed");
    int result = tree_capture_from(scan_root, idx, object_store_root,
                                   out_tree_hash);
    vcs_index_close(idx);
    return result;
}

int vcs_snapshot(struct vcs_repo *r, const struct vcs_snapshot_meta *meta,
                 uint8_t out_commit_id[32])
{
    if (!r || !meta || !out_commit_id)
        LOG_ERR("vcs", "null arg to snapshot");

    struct vcs_manifest m;
    if (!vcs_manifest_build(r->root, r->idx, &m))
        LOG_ERR("vcs", "build manifest");

    if (!put_manifest_blobs(r->root, r->root, &m)) {
        vcs_manifest_free(&m);
        LOG_ERR("vcs", "put blobs");
    }

    uint8_t tree_hash[32];
    if (!manifest_store(r->root, &m, tree_hash)) { vcs_manifest_free(&m); LOG_ERR("vcs", "store manifest"); }

    /* Seal check over the sealed-path set. */
    char **globs = NULL;
    size_t nglobs = 0;
    if (!vcs_seal_load_globs(r->root, &globs, &nglobs)) { vcs_manifest_free(&m); LOG_ERR("vcs", "load globs"); }
    uint8_t sealset[32];
    bool sh = vcs_sealset_hash(&m, globs, nglobs, sealset);
    vcs_seal_free_globs(globs, nglobs);
    vcs_manifest_free(&m);
    if (!sh)
        LOG_ERR("vcs", "sealset_hash");

    enum vcs_seal_result sr = vcs_seal_check(r->idx, sealset);
    if (sr == VCS_SEAL_REFUSED)
        return VCS_REFUSED;
    if (sr != VCS_SEAL_OK)
        LOG_ERR("vcs", "seal check error");

    /* Build the commit record. */
    struct vcs_commit c;
    memset(&c, 0, sizeof(c));
    c.version = VCS_COMMIT_VERSION;
    bool have_parent = false;
    if (!vcs_index_ref_get(r->idx, "HEAD", c.parent, &have_parent))
        LOG_ERR("vcs", "ref_get HEAD");
    if (!have_parent)
        memset(c.parent, 0, 32);
    memcpy(c.tree_hash, tree_hash, 32);
    memcpy(c.sealset_hash, sealset, 32);
    if (meta->generation_sha256) memcpy(c.generation_sha256, meta->generation_sha256, 32);
    c.verdict_status = meta->verdict_status;
    fill_fixed(c.phase, sizeof(c.phase), meta->phase);
    c.elapsed_ms = meta->elapsed_ms;
    if (meta->failure_hash) memcpy(c.failure_hash, meta->failure_hash, 32);
    fill_fixed(c.agent_id, sizeof(c.agent_id), meta->agent_id);
    fill_fixed(c.session_id, sizeof(c.session_id), meta->session_id);
    fill_fixed(c.task_ref, sizeof(c.task_ref), meta->task_ref);
    c.committed_at = platform_time_wall_unix();

    uint8_t record[VCS_COMMIT_RECORD_BYTES];
    if (!vcs_commit_serialize(&c, record))
        LOG_ERR("vcs", "serialize commit");
    uint8_t commit_id[32];
    if (!vcs_commit_id(&c, commit_id))
        LOG_ERR("vcs", "commit_id");

    /* Append the durable commit record, then store the by-id object. */
    if (event_log_append(r->log, EV_VCS_COMMIT, record, sizeof(record)) == UINT64_MAX)
        LOG_ERR("vcs", "append commits.log");
    uint8_t pre[VCS_COMMIT_PREIMAGE_BYTES];
    if (!vcs_commit_preimage(&c, pre))
        LOG_ERR("vcs", "commit preimage");
    uint8_t obj_id[32];
    if (!vcs_object_put(r->root, pre, sizeof(pre), VCS_TAG_COMMIT, obj_id))
        LOG_ERR("vcs", "put commit object");
    if (memcmp(obj_id, commit_id, 32) != 0)
        LOG_ERR("vcs", "commit id mismatch");

    /* Advance HEAD / anchor / seal_pin in one transaction. */
    if (!vcs_index_begin(r->idx))
        LOG_ERR("vcs", "index begin");
    bool ok = vcs_index_ref_set_in_tx(r->idx, "HEAD", commit_id) &&
              vcs_index_anchor_put_in_tx(r->idx, commit_id, c.generation_sha256,
                                         c.verdict_status) &&
              vcs_index_seal_pin_set_in_tx(r->idx, sealset);
    if (ok) ok = vcs_index_commit(r->idx);
    else vcs_index_rollback(r->idx);
    if (!ok)
        LOG_ERR("vcs", "index update");

    memcpy(out_commit_id, commit_id, 32);
    return VCS_OK;
}

/* ── status ──────────────────────────────────────────────────────── */

struct status_ctx {
    vcs_diff_cb cb;
    void       *user;
    size_t      n;
};

static void status_diff_cb(enum vcs_diff_kind kind, const struct vcs_entry *a,
                           const struct vcs_entry *b, void *user)
{
    struct status_ctx *s = user;
    s->n++;
    if (s->cb) s->cb(kind, a, b, s->user);
}

int vcs_status(struct vcs_repo *r, vcs_diff_cb cb, void *user,
               size_t *out_nchanges)
{
    if (out_nchanges) *out_nchanges = 0;
    if (!r)
        LOG_ERR("vcs", "null repo");

    struct vcs_manifest cur;
    if (!vcs_manifest_build(r->root, r->idx, &cur))
        LOG_ERR("vcs", "build current manifest");

    struct vcs_manifest head;
    vcs_manifest_init(&head);
    uint8_t head_id[32];
    bool have_head = false;
    if (!vcs_index_ref_get(r->idx, "HEAD", head_id, &have_head)) {
        vcs_manifest_free(&cur);
        LOG_ERR("vcs", "ref_get HEAD");
    }
    if (have_head) {
        struct vcs_commit hc;
        if (!load_commit_by_id(r->root, head_id, &hc) ||
            !manifest_load(r->root, hc.tree_hash, &head)) {
            vcs_manifest_free(&cur);
            LOG_ERR("vcs", "load HEAD manifest");
        }
    }

    struct status_ctx s = { cb, user, 0 };
    vcs_manifest_diff(&head, &cur, status_diff_cb, &s);

    vcs_manifest_free(&head);
    vcs_manifest_free(&cur);
    if (out_nchanges) *out_nchanges = s.n;
    return VCS_OK;
}

/* ── log (newest-first) ──────────────────────────────────────────── */

struct log_collect {
    struct vcs_commit *cs;
    uint8_t (*ids)[32];
    size_t count;
    size_t cap;
    bool err;
};

static bool log_stream_cb(uint64_t offset, enum event_log_type type,
                          const void *payload, size_t len, void *user)
{
    (void)offset;
    struct log_collect *lc = user;
    if (type != EV_VCS_COMMIT || len != VCS_COMMIT_RECORD_BYTES)
        return true;
    struct vcs_commit c;
    bool self_ok = false;
    if (!vcs_commit_deserialize((const uint8_t *)payload, len, &c, &self_ok) ||
        !self_ok)
        return true;
    if (lc->count == lc->cap) {
        size_t ncap = lc->cap ? lc->cap * 2 : 64;
        struct vcs_commit *ncs = zcl_realloc(lc->cs, ncap * sizeof(*ncs), "vcs_log_cs");
        uint8_t (*nids)[32] = zcl_realloc(lc->ids, ncap * 32, "vcs_log_ids");
        if (!ncs || !nids) { lc->err = true; if (ncs) lc->cs = ncs; if (nids) lc->ids = nids; return false; }
        lc->cs = ncs;
        lc->ids = nids;
        lc->cap = ncap;
    }
    lc->cs[lc->count] = c;
    vcs_commit_id(&c, lc->ids[lc->count]);
    lc->count++;
    return true;
}

int vcs_log(struct vcs_repo *r, size_t limit, vcs_log_cb cb, void *user)
{
    if (!r || !cb)
        LOG_ERR("vcs", "null arg to log");
    struct log_collect lc = {0};
    if (event_log_stream(r->log, 0, log_stream_cb, &lc) != 0 || lc.err) {
        free(lc.cs); free(lc.ids);
        LOG_ERR("vcs", "stream commits.log");
    }
    size_t emitted = 0;
    for (size_t i = lc.count; i > 0; i--) {
        if (limit && emitted >= limit) break;
        if (!cb(&lc.cs[i - 1], lc.ids[i - 1], user)) break;
        emitted++;
    }
    free(lc.cs);
    free(lc.ids);
    return VCS_OK;
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
#else
bool vcs_tree_load(const char *repo_root, const uint8_t tree_hash[32],
                   struct vcs_manifest *out)
{
    if (!repo_root || !tree_hash || !out) return false;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_object_load_raw(repo_root, tree_hash, &wire, &wire_len) != 0)
        return false;
    bool ok = vcs_manifest_parse(wire, wire_len, out);
    free(wire);
    uint8_t checked[32];
    if (!ok || !vcs_manifest_tree_hash(out, checked) ||
        memcmp(checked, tree_hash, 32) != 0) {
        if (ok) vcs_manifest_free(out);
        return false;
    }
    return true;
}
struct vcs_repo *vcs_open(const char *root) { (void)root; return NULL; }
void vcs_close(struct vcs_repo *repo) { free(repo); }
struct vcs_index *vcs_repo_index(struct vcs_repo *repo)
{ return repo ? repo->idx : NULL; }
const char *vcs_repo_root(struct vcs_repo *repo)
{ return repo ? repo->root : NULL; }
static int vcs_windows_refuse_hash(uint8_t out[32])
{ if (out) memset(out, 0, 32); return VCS_REFUSED; }
int vcs_tree_capture(struct vcs_repo *repo, uint8_t out[32])
{ (void)repo; return vcs_windows_refuse_hash(out); }
int vcs_tree_capture_path(const char *root, uint8_t out[32])
{ (void)root; return vcs_windows_refuse_hash(out); }
int vcs_tree_capture_into(const char *scan, const char *store, uint8_t out[32])
{ (void)scan; (void)store; return vcs_windows_refuse_hash(out); }
int vcs_snapshot(struct vcs_repo *repo, const struct vcs_snapshot_meta *meta,
                 uint8_t out[32])
{ (void)repo; (void)meta; return vcs_windows_refuse_hash(out); }
int vcs_status(struct vcs_repo *repo, vcs_diff_cb cb, void *user,
               size_t *changes)
{ (void)repo; (void)cb; (void)user; if (changes) *changes = 0; return VCS_REFUSED; }
int vcs_log(struct vcs_repo *repo, size_t limit, vcs_log_cb cb, void *user)
{ (void)repo; (void)limit; (void)cb; (void)user; return VCS_REFUSED; }
int vcs_revert(struct vcs_repo *repo, const uint8_t target[32],
               const struct vcs_revert_relink_ops *relink, uint8_t out[32])
{ (void)repo; (void)target; (void)relink; return vcs_windows_refuse_hash(out); }
#endif
