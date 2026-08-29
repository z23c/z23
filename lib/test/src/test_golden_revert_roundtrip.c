/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_golden_revert_roundtrip — Wave 4.3 golden test: the full
 * source+binary revert round-trip, end to end against a sandbox ZVCS repo
 * and the REAL native dev_activation transactional engine (fake in-memory
 * service ops — no systemctl, no /proc, no process exec — but real
 * filesystem/hash/atomic-rename mechanics, same fake-ops harness pattern as
 * lib/test/src/test_dev_activation.c).
 *
 * Golden flow (t_golden_revert_roundtrip):
 *   1. Stage + activate generation A (dev_activation_run, ACTIVATE mode,
 *      fake ops) and snapshot the sandbox source tree binding
 *      generation_sha256 = sha_A.
 *   2. Edit the source tree, stage + activate generation B, snapshot binding
 *      generation_sha256 = sha_B.
 *   3. vcs_revert(..., target = commit A, relink ops that call the REAL
 *      dev_activation_activate_generation(sha_A, ...) against the same
 *      sandbox) and assert:
 *        a. worktree files are byte-identical to state A
 *        b. the sandbox gen_root/current symlink resolves to gen-<sha_A hex>
 *        c. a NEW forward commit exists, binding generation_sha256 = sha_A
 *        d. append-only: commit B is still in the log, HEAD advanced to the
 *           new forward commit
 *        e. the zcl.agent_dev_deploy.v1 state file reflects generation A
 *   4. H*-unaffected: the file set the revert actually touched contains no
 *      sealed core/ path (vcs_seal_path_matches over the default globs).
 *
 * Sealed-path investigation (t_golden_revert_seal_guard): before this wave,
 * vcs_revert() wrote the target manifest's content into the worktree BEFORE
 * vcs_snapshot()'s internal seal check ran, so a revert that would touch a
 * sealed path without a valid unseal token still corrupted the sealed
 * file's on-disk bytes even though the operation ultimately reported
 * VCS_REFUSED (no commit landed, but the worktree was already mutated).
 * lib/vcs/src/vcs.c now runs a non-consuming seal pre-check
 * (vcs_seal_peek(), lib/vcs/src/vcs_seal.c) against the TARGET manifest
 * before touching a single worktree file. This test proves both halves:
 * the unauthorized case refuses with the worktree byte-for-byte untouched,
 * and a token-authorized case still succeeds exactly as vcs_snapshot's own
 * (consuming) guard would allow it. */

/* realpath() needs __USE_MISC; -D_POSIX_C_SOURCE=200809L alone does not
 * declare it. Without this the TU only builds by accident of the glibc
 * fortify inline at -O3. */
#define _DEFAULT_SOURCE

#include "test/test_core.h"

#include "dev_activation.h"
#include "json/json.h"

#include "vcs/vcs.h"
#include "vcs/vcs_commit.h"
#include "vcs/vcs_index.h"
#include "vcs/vcs_manifest.h"
#include "vcs/vcs_seal.h"

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* ── fake dev_activation ops (subset of test_dev_activation.c's harness,
 * happy-path only — this golden test drives the transaction, not its
 * failure modes, which test_dev_activation.c already covers) ──────── */

struct fake_ctx {
    char gen_root[PATH_MAX];
    bool service_up;
    int  stop_calls, start_calls;
};

static bool fake_current_gen(struct fake_ctx *c, char *out, size_t out_sz)
{
    char link[PATH_MAX];
    snprintf(link, sizeof(link), "%s/current", c->gen_root);
    char tgt[PATH_MAX];
    ssize_t n = readlink(link, tgt, sizeof(tgt) - 1);
    if (n <= 0)
        return false;
    tgt[n] = 0;
    snprintf(out, out_sz, "%s", tgt);
    return true;
}

static int fk_stop(void *ctx)
{
    struct fake_ctx *c = ctx;
    c->stop_calls++;
    c->service_up = false;
    return 0;
}

static int fk_start(void *ctx)
{
    struct fake_ctx *c = ctx;
    c->start_calls++;
    c->service_up = true;
    return 0;
}

static int fk_reload(void *ctx) { (void)ctx; return 0; }
static int fk_reset(void *ctx) { (void)ctx; return 0; }

static int fk_active(void *ctx)
{
    struct fake_ctx *c = ctx;
    return c->service_up ? 0 : 1;
}

static int fk_main_pid(void *ctx, long *pid_out)
{
    (void)ctx;
    *pid_out = 4242;
    return 0;
}

static int fk_running_exe(void *ctx, long pid, char *out, size_t out_sz)
{
    struct fake_ctx *c = ctx;
    (void)pid;
    char gen[80];
    if (!fake_current_gen(c, gen, sizeof(gen)))
        return -1;
    snprintf(out, out_sz, "%s/%s/zclassic23-dev", c->gen_root, gen);
    return 0;
}

static int fk_preflight(void *ctx, const char *cand_bin, const char *commit)
{
    (void)ctx; (void)cand_bin; (void)commit;
    return 0;
}

static int fk_probe(void *ctx, const char *gen_id, const char *commit)
{
    (void)ctx; (void)gen_id; (void)commit;
    return 0;
}

static void fake_ops_init(struct dev_activation_ops *ops, struct fake_ctx *c)
{
    memset(ops, 0, sizeof(*ops));
    ops->service_stop = fk_stop;
    ops->service_start = fk_start;
    ops->service_daemon_reload = fk_reload;
    ops->service_reset_failed = fk_reset;
    ops->service_active = fk_active;
    ops->service_main_pid = fk_main_pid;
    ops->running_exe = fk_running_exe;
    ops->preflight = fk_preflight;
    ops->activation_probe = fk_probe;
    ops->ctx = c;
}

/* ── sandbox helpers (same shape as test_dev_activation.c) ──────────── */

struct sandbox {
    char  home[PATH_MAX];
    char  datadir[PATH_MAX];
    char  gen_root[PATH_MAX];
    /* The ZVCS SOURCE repo root — deliberately a SEPARATE directory from
     * `home` (a sibling, never nested under it). dev_activation's gen_root
     * and datadir live under `home` and are full of binary blobs and a
     * `current` symlink into a generation directory; if the ZVCS repo were
     * rooted at `home` too, vcs_manifest_build() would try to track that
     * whole tree as ordinary source, and a symlink-to-directory entry
     * breaks the generic file-content walk. Real-world usage has the same
     * separation: the git checkout (ZVCS source repo) and the dev-lane
     * state under $HOME (generation store + datadir) are different trees. */
    char  src[PATH_MAX];
    char *saved_home;
};

static void sandbox_enter(struct sandbox *sb, const char *tag)
{
    char rel[PATH_MAX];
    test_make_tmpdir(rel, sizeof(rel), "golden_revert", tag);
    if (!realpath(rel, sb->home))
        snprintf(sb->home, sizeof(sb->home), "%s", rel);
    snprintf(sb->datadir, sizeof(sb->datadir), "%s/.zclassic-c23-dev", sb->home);
    snprintf(sb->gen_root, sizeof(sb->gen_root), "%s/lib/gens", sb->home);
    char srcrel[PATH_MAX];
    char srctag[128];
    snprintf(srctag, sizeof(srctag), "%s_src", tag);
    test_make_tmpdir(srcrel, sizeof(srcrel), "golden_revert", srctag);
    if (!realpath(srcrel, sb->src))
        snprintf(sb->src, sizeof(sb->src), "%s", srcrel);
    const char *h = getenv("HOME");
    sb->saved_home = h ? strdup(h) : NULL;
    setenv("HOME", sb->home, 1);
    setenv("ZCL_DEV_ACTIVATION_VERIFY_TIMEOUT_S", "0", 1);
}

static void sandbox_exit(struct sandbox *sb)
{
    if (sb->saved_home) {
        setenv("HOME", sb->saved_home, 1);
        free(sb->saved_home);
    } else {
        unsetenv("HOME");
    }
    unsetenv("ZCL_DEV_ACTIVATION_VERIFY_TIMEOUT_S");
    test_rm_rf_recursive(sb->home);
    test_rm_rf_recursive(sb->src);
}

static bool write_fake_binary(const char *path, char fill)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    char buf[256];
    memset(buf, fill, sizeof(buf));
    fwrite(buf, 1, sizeof(buf), f);
    fclose(f);
    return chmod(path, 0755) == 0;
}

static void base_request(struct dev_activation_request *req, struct sandbox *sb,
                         const char *artifact)
{
    memset(req, 0, sizeof(*req));
    req->repo_root = sb->home;
    req->artifact_path = artifact;
    req->build_commit = "goldencommit";
    req->source_identity =
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    req->build_type = "fast";
    req->gen_root = sb->gen_root;
    req->datadir = sb->datadir;
    req->unit = "zcl23-dev.service";
    req->rpcport = 18252;
    req->mode = DEV_ACTIVATION_MODE_ACTIVATE;
}

static bool read_link_str(const char *link, char *out, size_t out_sz)
{
    ssize_t n = readlink(link, out, out_sz - 1);
    if (n <= 0)
        return false;
    out[n] = 0;
    return true;
}

static bool hex_to_bytes32(const char *hex, uint8_t out[32])
{
    if (strlen(hex) != 64)
        return false;
    for (int i = 0; i < 32; i++) {
        char b[3] = { hex[2 * i], hex[2 * i + 1], 0 };
        char *end = NULL;
        long v = strtol(b, &end, 16);
        if (end != b + 2)
            return false;
        out[i] = (uint8_t)v;
    }
    return true;
}

/* Write content to <dir>/<rel>, creating parent dirs. */
static bool gw_write(const char *dir, const char *rel, const char *content)
{
    char full[PATH_MAX];
    snprintf(full, sizeof(full), "%s/%s", dir, rel);
    for (char *p = full + strlen(dir) + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            /* 0700: the object store verifies its own directories are
             * owner-only, so a fixture that pre-creates .zvcs at the
             * ordinary 0755 makes vcs_open refuse the repo outright. */
            mkdir(full, 0700);
            *p = '/';
        }
    }
    FILE *f = fopen(full, "wb");
    if (!f)
        return false;
    size_t n = content ? strlen(content) : 0;
    if (n)
        fwrite(content, 1, n, f);
    fclose(f);
    return true;
}

static char *gw_read(const char *dir, const char *rel, size_t *out_len)
{
    char full[PATH_MAX];
    snprintf(full, sizeof(full), "%s/%s", dir, rel);
    FILE *f = fopen(full, "rb");
    if (!f)
        return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return NULL; }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = '\0';
    if (out_len) *out_len = rd;
    return buf;
}

static bool gw_file_matches(const char *dir, const char *rel, const char *expect)
{
    size_t n = 0;
    char *got = gw_read(dir, rel, &n);
    if (!got) return false;
    bool ok = (n == strlen(expect)) && memcmp(got, expect, n) == 0;
    free(got);
    return ok;
}

static bool gw_file_exists(const char *dir, const char *rel)
{
    char full[PATH_MAX];
    snprintf(full, sizeof(full), "%s/%s", dir, rel);
    struct stat st;
    return stat(full, &st) == 0;
}

/* Read a whole file into buf; returns byte count or 0. */
static size_t read_whole(const char *path, char *buf, size_t buf_sz)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return 0;
    size_t n = fread(buf, 1, buf_sz - 1, f);
    fclose(f);
    buf[n] = 0;
    return n;
}

/* ── relink ops: calls the REAL activation-by-sha revert hook ───────── */

struct relink_ctx {
    struct sandbox            *sb;
    struct dev_activation_ops *ops;
    struct dev_activation_result last;
    int calls;
    int rc;
};

static bool relink_activate(const uint8_t gen_sha256[32], void *ctxp)
{
    struct relink_ctx *ctx = ctxp;
    ctx->calls++;
    struct dev_activation_request req;
    char placeholder[PATH_MAX];
    /* artifact_path is unused by dev_activation_activate_generation (no
     * build/re-stage happens — see tools/dev/dev_activation.h) but
     * base_request() wants a value; reuse any path under the sandbox. */
    snprintf(placeholder, sizeof(placeholder), "%s/cand_A", ctx->sb->home);
    base_request(&req, ctx->sb, placeholder);
    ctx->rc = dev_activation_activate_generation(gen_sha256, &req, ctx->ops,
                                                  &ctx->last);
    return ctx->rc == DEV_ACTIVATION_OK;
}

/* Collect every commit id vcs_log() walks (append-only proof). */
#define LOG_ID_MAX 64
struct log_ids {
    uint8_t ids[LOG_ID_MAX][32];
    size_t  count;
};

static bool log_id_collect_cb(const struct vcs_commit *c,
                              const uint8_t commit_id[32], void *user)
{
    (void)c;
    struct log_ids *lc = user;
    if (lc->count < LOG_ID_MAX)
        memcpy(lc->ids[lc->count], commit_id, 32);
    lc->count++;
    return true;
}

static bool log_ids_contains(const struct log_ids *lc, const uint8_t id[32])
{
    size_t n = lc->count < LOG_ID_MAX ? lc->count : LOG_ID_MAX;
    for (size_t i = 0; i < n; i++)
        if (memcmp(lc->ids[i], id, 32) == 0)
            return true;
    return false;
}

struct captured_commit {
    struct vcs_commit c;
    uint8_t            id[32];
    bool                got;
};

static bool capture_first_commit(const struct vcs_commit *c,
                                 const uint8_t commit_id[32], void *user)
{
    struct captured_commit *cap = user;
    cap->c = *c;
    memcpy(cap->id, commit_id, 32);
    cap->got = true;
    return false; /* newest-first: stop after the first */
}

/* Diff-collection to prove the revert touched no sealed path. */
struct touched_paths {
    char paths[32][256];
    size_t count;
};

static void touched_cb(enum vcs_diff_kind kind, const struct vcs_entry *a,
                       const struct vcs_entry *b, void *user)
{
    (void)kind;
    struct touched_paths *tp = user;
    const struct vcs_entry *e = b ? b : a;
    if (!e || tp->count >= 32)
        return;
    snprintf(tp->paths[tp->count], sizeof(tp->paths[tp->count]), "%s", e->path);
    tp->count++;
}

/* ── golden test 1: source+binary revert round-trip ─────────────────── */

static int t_golden_revert_roundtrip(void)
{
    int failures = 0;
    TEST("golden revert roundtrip: source+binary revert restores generation A") {
        struct sandbox sb;
        sandbox_enter(&sb, "roundtrip");

        /* Seed source state A. */
        ASSERT(gw_write(sb.src, "src/app.c", "int app_version(void){return 1;}\n"));
        ASSERT(gw_write(sb.src, "README.md", "state A\n"));

        struct fake_ctx c = {0};
        snprintf(c.gen_root, sizeof(c.gen_root), "%s", sb.gen_root);
        struct dev_activation_ops ops;
        fake_ops_init(&ops, &c);

        /* Stage + activate generation A. */
        char artA[PATH_MAX];
        snprintf(artA, sizeof(artA), "%s/cand_A", sb.home);
        ASSERT(write_fake_binary(artA, 'A'));
        struct dev_activation_request reqA;
        base_request(&reqA, &sb, artA);
        struct dev_activation_result resA;
        ASSERT_EQ(dev_activation_run(&reqA, &ops, &resA), DEV_ACTIVATION_OK);
        uint8_t shaA[32];
        ASSERT(hex_to_bytes32(resA.candidate_sha256, shaA));
        char expect_genA[96];
        snprintf(expect_genA, sizeof(expect_genA), "gen-%s", resA.candidate_sha256);
        ASSERT_STR_EQ(resA.running_generation, expect_genA);

        /* Snapshot source state A, binding generation_sha256 = sha_A. */
        struct vcs_repo *r = vcs_open(sb.src);
        ASSERT(r != NULL);
        struct vcs_snapshot_meta metaA = {0};
        metaA.phase = "golden_a";
        metaA.generation_sha256 = shaA;
        metaA.task_ref = "golden-a";
        uint8_t cA[32];
        ASSERT_EQ(vcs_snapshot(r, &metaA, cA), VCS_OK);

        /* Edit source -> state B (modify + add a file). */
        ASSERT(gw_write(sb.src, "src/app.c", "int app_version(void){return 2;}\n"));
        ASSERT(gw_write(sb.src, "src/new.c", "void extra_b(void){}\n"));
        ASSERT(gw_write(sb.src, "README.md", "state B\n"));

        /* Stage + activate generation B. */
        char artB[PATH_MAX];
        snprintf(artB, sizeof(artB), "%s/cand_B", sb.home);
        ASSERT(write_fake_binary(artB, 'B'));
        struct dev_activation_request reqB;
        base_request(&reqB, &sb, artB);
        struct dev_activation_result resB;
        ASSERT_EQ(dev_activation_run(&reqB, &ops, &resB), DEV_ACTIVATION_OK);
        uint8_t shaB[32];
        ASSERT(hex_to_bytes32(resB.candidate_sha256, shaB));
        char expect_genB[96];
        snprintf(expect_genB, sizeof(expect_genB), "gen-%s", resB.candidate_sha256);
        ASSERT_STR_EQ(resB.running_generation, expect_genB);

        struct vcs_snapshot_meta metaB = {0};
        metaB.phase = "golden_b";
        metaB.generation_sha256 = shaB;
        metaB.task_ref = "golden-b";
        uint8_t cB[32];
        ASSERT_EQ(vcs_snapshot(r, &metaB, cB), VCS_OK);

        /* Capture the current worktree manifest (state B) and the log
         * before reverting, so we can prove append-only + no sealed touch
         * after the revert. */
        struct vcs_manifest before_m;
        ASSERT(vcs_manifest_build(sb.src, vcs_repo_index(r), &before_m));
        struct log_ids before_log = {0};
        ASSERT_EQ(vcs_log(r, 0, log_id_collect_cb, &before_log), VCS_OK);
        ASSERT(log_ids_contains(&before_log, cA));
        ASSERT(log_ids_contains(&before_log, cB));

        /* Revert to A with relink ops that activate the real generation by
         * its SHA-256 against the same sandbox. */
        struct relink_ctx rctx = { &sb, &ops, {0}, 0, 0 };
        struct vcs_revert_relink_ops relink_ops = { relink_activate, &rctx };
        uint8_t cr[32];
        int rrc = vcs_revert(r, cA, &relink_ops, cr);
        ASSERT_EQ(rrc, VCS_OK);
        ASSERT_EQ(rctx.calls, 1);
        ASSERT_EQ(rctx.rc, DEV_ACTIVATION_OK);
        ASSERT_STR_EQ(rctx.last.running_generation, expect_genA);

        /* (a) worktree files byte-equal state A. */
        ASSERT(gw_file_matches(sb.src, "src/app.c",
                               "int app_version(void){return 1;}\n"));
        ASSERT(gw_file_matches(sb.src, "README.md", "state A\n"));
        ASSERT(!gw_file_exists(sb.src, "src/new.c"));

        /* (b) sandbox `current` symlink -> gen-<sha_A>. */
        char cur[PATH_MAX], link[PATH_MAX];
        snprintf(link, sizeof(link), "%s/current", sb.gen_root);
        ASSERT(read_link_str(link, cur, sizeof(cur)));
        ASSERT_STR_EQ(cur, expect_genA);

        /* (c) the new forward commit binds sha_A. */
        struct captured_commit cap = {0};
        ASSERT_EQ(vcs_log(r, 1, capture_first_commit, &cap), VCS_OK);
        ASSERT(cap.got);
        ASSERT(memcmp(cap.id, cr, 32) == 0);
        ASSERT(memcmp(cap.c.generation_sha256, shaA, 32) == 0);

        /* (d) append-only: B's commit is still present, log grew by exactly
         * one, and HEAD advanced to the new forward commit. */
        struct log_ids after_log = {0};
        ASSERT_EQ(vcs_log(r, 0, log_id_collect_cb, &after_log), VCS_OK);
        ASSERT_EQ(after_log.count, before_log.count + 1);
        for (size_t i = 0; i < before_log.count; i++)
            ASSERT(log_ids_contains(&after_log, before_log.ids[i]));
        ASSERT(log_ids_contains(&after_log, cr));
        uint8_t head[32];
        bool have_head = false;
        ASSERT(vcs_index_ref_get(vcs_repo_index(r), "HEAD", head, &have_head));
        ASSERT(have_head);
        ASSERT(memcmp(head, cr, 32) == 0);

        /* (e) deploy-state JSON reflects generation A coherently. */
        char statepath[PATH_MAX], js[8192];
        snprintf(statepath, sizeof(statepath), "%s/agent-deploy.json", sb.datadir);
        size_t jn = read_whole(statepath, js, sizeof(js));
        ASSERT(jn > 0);
        struct json_value dv = {0};
        ASSERT(json_read(&dv, js, jn));
        ASSERT_STR_EQ(json_get_str(json_get(&dv, "schema")),
                      "zcl.agent_dev_deploy.v1");
        ASSERT_STR_EQ(json_get_str(json_get(&dv, "running_generation")),
                      expect_genA);
        ASSERT_STR_EQ(json_get_str(json_get(&dv, "current_generation")),
                      expect_genA);
        ASSERT_STR_EQ(json_get_str(json_get(&dv, "activation_status")),
                      "active");
        json_free(&dv);

        /* H*-unaffected: the touched-path set contains no sealed core/
         * (or other default-sealed-glob) path. */
        struct vcs_manifest after_m;
        ASSERT(vcs_manifest_build(sb.src, vcs_repo_index(r), &after_m));
        struct touched_paths tp = {0};
        vcs_manifest_diff(&before_m, &after_m, touched_cb, &tp);
        ASSERT(tp.count > 0);  /* the revert actually changed something */
        char **globs = NULL;
        size_t nglobs = 0;
        ASSERT(vcs_seal_load_globs(sb.src, &globs, &nglobs));
        for (size_t i = 0; i < tp.count; i++)
            ASSERT(!vcs_seal_path_matches(tp.paths[i], globs, nglobs));
        vcs_seal_free_globs(globs, nglobs);
        vcs_manifest_free(&before_m);
        vcs_manifest_free(&after_m);

        vcs_close(r);
        sandbox_exit(&sb);
        PASS();
    } _test_next:;
    return failures;
}

/* ── golden test 2: sealed-path revert guard ─────────────────────────
 * Wave 4.3 investigation finding: before this wave, vcs_revert() had NO
 * seal pre-check — it wrote the target manifest's content into the
 * worktree unconditionally, then relied on vcs_snapshot()'s own seal check
 * (which runs strictly AFTER that write) to refuse the commit. A refusal
 * there stopped the commit but NOT the already-completed worktree
 * mutation: an unauthorized revert could silently overwrite a sealed
 * file's on-disk bytes with content from the target commit, even though
 * the whole operation reported VCS_REFUSED. lib/vcs/src/vcs.c now runs a
 * non-consuming vcs_seal_peek() against the TARGET manifest before doing
 * any worktree write, mirroring vcs_snapshot's guard but early enough to
 * refuse with the worktree completely untouched. */
static int t_golden_revert_seal_guard(void)
{
    int failures = 0;
    TEST("golden revert: sealed-path revert is refused with the worktree untouched") {
        struct sandbox sb;
        sandbox_enter(&sb, "sealguard");

        ASSERT(gw_write(sb.src, ".zvcs/sealed_paths", "sealed/\n"));
        ASSERT(gw_write(sb.src, "sealed/consensus.txt", "RULE=X\n"));
        ASSERT(gw_write(sb.src, "readme.txt", "hi\n"));

        struct vcs_repo *r = vcs_open(sb.src);
        ASSERT(r != NULL);

        /* First snapshot ever: no pin yet, always accepted. Pins
         * sealset(X). Capture that sealset now, while the worktree still
         * has the X content, for the later token-authorized case. */
        struct vcs_manifest seed_m;
        ASSERT(vcs_manifest_build(sb.src, vcs_repo_index(r), &seed_m));
        char **globs = NULL;
        size_t nglobs = 0;
        ASSERT(vcs_seal_load_globs(sb.src, &globs, &nglobs));
        uint8_t sealset_x[32];
        ASSERT(vcs_sealset_hash(&seed_m, globs, nglobs, sealset_x));
        vcs_seal_free_globs(globs, nglobs);
        vcs_manifest_free(&seed_m);

        struct vcs_snapshot_meta meta = {0};
        meta.phase = "seed";
        uint8_t c_seed[32];
        ASSERT_EQ(vcs_snapshot(r, &meta, c_seed), VCS_OK);

        /* An authorized sealed edit (token granted first): sealed file
         * X -> Y, pin becomes sealset(Y). */
        ASSERT(gw_write(sb.src, "sealed/consensus.txt", "RULE=Y\n"));
        struct vcs_manifest y_m;
        ASSERT(vcs_manifest_build(sb.src, vcs_repo_index(r), &y_m));
        globs = NULL; nglobs = 0;
        ASSERT(vcs_seal_load_globs(sb.src, &globs, &nglobs));
        uint8_t sealset_y[32];
        ASSERT(vcs_sealset_hash(&y_m, globs, nglobs, sealset_y));
        vcs_seal_free_globs(globs, nglobs);
        vcs_manifest_free(&y_m);
        ASSERT(vcs_seal_grant_unseal(vcs_repo_index(r), sealset_y));
        uint8_t c_y[32];
        ASSERT_EQ(vcs_snapshot(r, &meta, c_y), VCS_OK);
        ASSERT(gw_file_matches(sb.src, "sealed/consensus.txt", "RULE=Y\n"));

        /* Negative case: revert back to c_seed (sealset X) with NO token.
         * Must refuse, and the sealed file must be COMPLETELY untouched
         * (still Y) — the pre-check fired before any worktree write. */
        uint8_t cr_bad[32];
        int rc_bad = vcs_revert(r, c_seed, NULL, cr_bad);
        ASSERT_EQ(rc_bad, VCS_REFUSED);
        ASSERT(gw_file_matches(sb.src, "sealed/consensus.txt", "RULE=Y\n"));
        ASSERT(gw_file_matches(sb.src, "readme.txt", "hi\n"));

        /* HEAD did not move: the refused revert recorded nothing. */
        uint8_t head[32];
        bool have_head = false;
        ASSERT(vcs_index_ref_get(vcs_repo_index(r), "HEAD", head, &have_head));
        ASSERT(have_head);
        ASSERT(memcmp(head, c_y, 32) == 0);

        /* Positive case: grant the token authorizing exactly sealset_x (the
         * revert target's sealset), then revert again. Must succeed exactly
         * as an equivalent vcs_snapshot() would have — the pre-check does
         * not consume the token twice or otherwise block a legitimately
         * authorized sealed revert. */
        ASSERT(vcs_seal_grant_unseal(vcs_repo_index(r), sealset_x));
        uint8_t cr_ok[32];
        int rc_ok = vcs_revert(r, c_seed, NULL, cr_ok);
        ASSERT_EQ(rc_ok, VCS_OK);
        ASSERT(gw_file_matches(sb.src, "sealed/consensus.txt", "RULE=X\n"));
        have_head = false;
        ASSERT(vcs_index_ref_get(vcs_repo_index(r), "HEAD", head, &have_head));
        ASSERT(have_head);
        ASSERT(memcmp(head, cr_ok, 32) == 0);

        /* Token was one-shot: a further unauthorized sealed revert refuses
         * again. */
        ASSERT(gw_write(sb.src, "sealed/consensus.txt", "RULE=Z\n"));
        struct vcs_manifest z_m;
        ASSERT(vcs_manifest_build(sb.src, vcs_repo_index(r), &z_m));
        globs = NULL; nglobs = 0;
        ASSERT(vcs_seal_load_globs(sb.src, &globs, &nglobs));
        uint8_t sealset_z[32];
        ASSERT(vcs_sealset_hash(&z_m, globs, nglobs, sealset_z));
        vcs_seal_free_globs(globs, nglobs);
        vcs_manifest_free(&z_m);
        ASSERT(vcs_seal_grant_unseal(vcs_repo_index(r), sealset_z));
        uint8_t c_z[32];
        ASSERT_EQ(vcs_snapshot(r, &meta, c_z), VCS_OK);

        uint8_t cr_again[32];
        int rc_again = vcs_revert(r, c_seed, NULL, cr_again);
        ASSERT_EQ(rc_again, VCS_REFUSED);
        ASSERT(gw_file_matches(sb.src, "sealed/consensus.txt", "RULE=Z\n"));

        vcs_close(r);
        sandbox_exit(&sb);
        PASS();
    } _test_next:;
    return failures;
}

int test_golden_revert_roundtrip(void)
{
    int failures = 0;
    failures += t_golden_revert_roundtrip();
    failures += t_golden_revert_seal_guard();
    printf("=== golden_revert_roundtrip: %d failures ===\n", failures);
    return failures;
}
