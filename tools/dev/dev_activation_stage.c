/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev_activation_stage.c — candidate staging (immutable content-addressed
 * generations, rollback-generation import) and the byte-compatible
 * zcl.agent_dev_deploy.v1 deploy-state writer for the native dev-lane
 * activation engine. Split from dev_activation.c along the staging /
 * deploy-state seam (file-size ceiling). No process exec.
 */

#define _GNU_SOURCE

#include "dev_activation.h"
#include "dev_activation_internal.h"

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)

#include "storage/boot_auto_reindex.h"
#include "platform/directory_compat.h"
#include "platform/os_proc.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef ZCL_TESTING
static void (*g_stage_after_hash_hook)(void *) = NULL;
static void *g_stage_after_hash_hook_ctx = NULL;

void dev_activation_stage_test_set_after_hash_hook(void (*hook)(void *),
                                                   void *ctx)
{
    g_stage_after_hash_hook = hook;
    g_stage_after_hash_hook_ctx = ctx;
}

static void dev_stage_run_after_hash_hook(void)
{
    void (*hook)(void *) = g_stage_after_hash_hook;
    void *ctx = g_stage_after_hash_hook_ctx;
    g_stage_after_hash_hook = NULL;
    g_stage_after_hash_hook_ctx = NULL;
    if (hook)
        hook(ctx);
}
#else
static void dev_stage_run_after_hash_hook(void) { }
#endif

static _Atomic uint64_t g_stage_directory_sequence;

/* ── staging: immutable content-addressed generation ─────────────────── */

static bool dev_write_manifest(const char *path, const char *generation,
                               const char *sha, const char *build_commit,
                               const char *source_id_sha256,
                               const char *build_type, const char *source)
{
    if (!dev_activation_source_id_valid(source_id_sha256))
        LOG_FAIL("dev-activation", "manifest source_id_sha256 is invalid");
    char e_commit[256], e_source_id[80], e_type[64], e_src[PATH_MAX];
    dev_activation_json_escape(build_commit, e_commit, sizeof(e_commit));
    dev_activation_json_escape(source_id_sha256, e_source_id,
                               sizeof(e_source_id));
    dev_activation_json_escape(build_type, e_type, sizeof(e_type));
    dev_activation_json_escape(source, e_src, sizeof(e_src));
    char now[32];
    dev_activation_iso_utc_now(now);
    char wire[8192];
    int n = snprintf(
        wire, sizeof(wire),
        "{\n"
        "  \"schema\": \"zcl.dev_binary_generation.v1\",\n"
        "  \"generation\": \"%s\",\n"
        "  \"sha256\": \"%s\",\n"
        "  \"source_id_sha256\": \"%s\",\n"
        "  \"build_commit\": \"%s\",\n"
        "  \"build_type\": \"%s\",\n"
        "  \"source_artifact\": \"%s\",\n"
        "  \"created_at_utc\": \"%s\"\n"
        "}\n",
        generation, sha, e_source_id, e_commit, e_type, e_src, now);
    if (n <= 0 || (size_t)n >= sizeof(wire))
        LOG_FAIL("dev-activation", "manifest overflow");
    struct platform_private_file manifest;
    platform_private_file_init(&manifest);
    bool ok = platform_private_file_create(path, &manifest) &&
              platform_private_file_write_at(&manifest, wire, (size_t)n, 0) &&
              platform_private_file_truncate(&manifest, (uint64_t)n) &&
              platform_private_file_flush(&manifest);
    platform_private_file_close(&manifest);
    if (!ok) {
        (void)platform_private_file_unlink_missing_ok(path);
        LOG_FAIL("dev-activation", "manifest durable write %s: %s", path,
                 strerror(errno));
    }
    return true;
}

static bool dev_stage_snapshot_equal(
    const struct platform_positioned_file_snapshot *a,
    const struct platform_positioned_file_snapshot *b)
{
    return a->size == b->size && a->volume == b->volume &&
           a->file_low == b->file_low && a->file_high == b->file_high &&
           a->modified_seconds == b->modified_seconds &&
           a->modified_nanoseconds == b->modified_nanoseconds &&
           a->changed_seconds == b->changed_seconds &&
           a->changed_nanoseconds == b->changed_nanoseconds;
}

/* Copy one stable executable snapshot into a create-only private destination.
 * The source and destination remain handle-bound throughout the transaction;
 * pathname replacement cannot substitute bytes after validation. */
bool dev_activation_install_file(const char *src, const char *dst, mode_t mode)
{
    struct platform_positioned_file in;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&in);
    if (!platform_positioned_file_open(&in, src) ||
        !platform_positioned_file_snapshot(&in, &before) ||
        !platform_positioned_file_is_executable(&in)) {
        platform_positioned_file_close(&in);
        LOG_FAIL("dev-activation", "install open %s: %s", src, strerror(errno));
    }
    struct platform_private_file out;
    platform_private_file_init(&out);
    if (!platform_private_file_create(dst, &out)) {
        platform_positioned_file_close(&in);
        LOG_FAIL("dev-activation", "install create %s: %s", dst,
                 strerror(errno));
    }
    char buf[65536];
    bool ok = true;
    uint64_t offset = 0;
    while (ok && offset < before.size) {
        size_t chunk = before.size - offset > sizeof(buf)
                           ? sizeof(buf) : (size_t)(before.size - offset);
        int64_t got = platform_positioned_file_read(&in, buf, chunk, offset);
        ok = got == (int64_t)chunk &&
             platform_private_file_write_at(&out, buf, chunk, offset);
        offset += chunk;
    }
    ok = ok && platform_positioned_file_snapshot(&in, &after) &&
         dev_stage_snapshot_equal(&before, &after) &&
         platform_private_file_truncate(&out, before.size) &&
         platform_private_file_flush(&out) &&
         platform_private_file_mark_executable(&out);
    platform_positioned_file_close(&in);
    platform_private_file_close(&out);
    if (!ok)
        LOG_FAIL("dev-activation", "install copy %s -> %s failed", src, dst);
    (void)mode;
    return true;
}

/* Stage the candidate: sha the artifact, build gen-<sha> immutably. Sets
 * candidate_* fields. Idempotent on an existing matching generation; refuses a
 * quarantined generation. */
int dev_activation_stage_candidate(struct dev_activation_txn *txn)
{
    struct dev_activation_result *r = txn->result;
    struct platform_positioned_file artifact;
    platform_positioned_file_init(&artifact);
    bool artifact_executable =
        platform_positioned_file_open(&artifact, txn->req->artifact_path) &&
        platform_positioned_file_is_executable(&artifact);
    platform_positioned_file_close(&artifact);
    if (!artifact_executable) {
        fprintf(stderr, "[dev-activation] artifact missing/not executable: %s\n",
                txn->req->artifact_path);
        return DEV_ACTIVATION_E_STAGE;
    }
    if (!dev_activation_sha256_file(txn->req->artifact_path,
                                    txn->candidate_sha_hex))
        return DEV_ACTIVATION_E_STAGE;
    dev_stage_run_after_hash_hook();
    snprintf(r->candidate_sha256, sizeof(r->candidate_sha256), "%s",
             txn->candidate_sha_hex);
    int n = snprintf(txn->candidate_generation,
                     sizeof(txn->candidate_generation), "gen-%s",
                     txn->candidate_sha_hex);
    if (n <= 0 || (size_t)n >= sizeof(txn->candidate_generation))
        return DEV_ACTIVATION_E_STAGE;
    snprintf(r->candidate_generation, sizeof(r->candidate_generation), "%s",
             txn->candidate_generation);
    if (!dev_activation_join(txn->candidate_dir, sizeof(txn->candidate_dir),
                  txn->gen_root, txn->candidate_generation))
        return DEV_ACTIVATION_E_STAGE;
    n = snprintf(txn->candidate_bin, sizeof(txn->candidate_bin),
                 "%s/zclassic23-dev", txn->candidate_dir);
    if (n <= 0 || (size_t)n >= sizeof(txn->candidate_bin))
        return DEV_ACTIVATION_E_STAGE;

    char reject_marker[PATH_MAX];
    n = snprintf(reject_marker, sizeof(reject_marker), "%s/%s.json",
                 txn->rejected_dir, txn->candidate_generation);
    if (n > 0 && (size_t)n < sizeof(reject_marker) &&
        access(reject_marker, F_OK) == 0) {
        fprintf(stderr, "[dev-activation] candidate %s is quarantined\n",
                txn->candidate_generation);
        return DEV_ACTIVATION_E_STAGE;
    }

    enum platform_directory_probe_result candidate_probe =
        platform_directory_probe_real(txn->candidate_dir);
    if (candidate_probe == PLATFORM_DIRECTORY_PROBE_OK) {
        /* Immutable collision: an existing gen dir must carry the same sha. */
        char have[65];
        if (access(txn->candidate_bin, X_OK) != 0 ||
            !dev_activation_sha256_file(txn->candidate_bin, have) ||
            strcmp(have, txn->candidate_sha_hex) != 0) {
            fprintf(stderr, "[dev-activation] immutable generation collision: %s\n",
                    txn->candidate_dir);
            return DEV_ACTIVATION_E_STAGE;
        }
        char staged_source_id[65];
        dev_activation_generation_source_id(
            txn, txn->candidate_generation, staged_source_id);
        if (strcmp(staged_source_id, txn->req->source_identity) != 0) {
            fprintf(stderr,
                    "[dev-activation] immutable generation source identity "
                    "mismatch: %s\n",
                    txn->candidate_dir);
            return DEV_ACTIVATION_E_STAGE;
        }
        return DEV_ACTIVATION_OK; /* already staged, byte-identical */
    }

    if (candidate_probe != PLATFORM_DIRECTORY_PROBE_MISSING)
        return DEV_ACTIVATION_E_STAGE;
    char tmpl[PATH_MAX];
    bool made_tmpdir = false;
    for (unsigned int attempt = 0; attempt < 64 && !made_tmpdir; attempt++) {
        uint64_t sequence = atomic_fetch_add_explicit(
            &g_stage_directory_sequence, 1, memory_order_relaxed);
        n = snprintf(tmpl, sizeof(tmpl), "%s/.candidate.%llu.%llu",
                     txn->gen_root,
                     (unsigned long long)os_proc_current_pid(),
                     (unsigned long long)sequence);
        if (n <= 0 || (size_t)n >= sizeof(tmpl))
            break;
        made_tmpdir = platform_private_directory_create(tmpl);
        if (!made_tmpdir && errno != EEXIST)
            break;
    }
    if (!made_tmpdir) {
        LOG_ERR("dev-activation", "candidate mkdtemp: %s", strerror(errno));
        return DEV_ACTIVATION_E_STAGE;
    }
    const char *tmpdir = tmpl;
    char tmp_bin[PATH_MAX], tmp_manifest[PATH_MAX];
    if (!dev_activation_join(tmp_bin, sizeof(tmp_bin), tmpdir,
                             "zclassic23-dev") ||
        !dev_activation_join(tmp_manifest, sizeof(tmp_manifest), tmpdir,
                             "manifest.json")) {
        (void)platform_private_directory_remove_empty(tmpdir);
        return DEV_ACTIVATION_E_STAGE;
    }
    char copied_sha[65];
    if (!dev_activation_install_file(txn->req->artifact_path, tmp_bin, 0555) ||
        !dev_activation_sha256_file(tmp_bin, copied_sha) ||
        strcmp(copied_sha, txn->candidate_sha_hex) != 0 ||
        !dev_write_manifest(tmp_manifest, txn->candidate_generation,
                            txn->candidate_sha_hex, txn->req->build_commit,
                            txn->req->source_identity,
                            txn->req->build_type, txn->req->artifact_path)) {
        (void)platform_private_file_unlink_missing_ok(tmp_bin);
        (void)platform_private_file_unlink_missing_ok(tmp_manifest);
        (void)platform_private_directory_remove_empty(tmpdir);
        return DEV_ACTIVATION_E_STAGE;
    }
#if !defined(_WIN32)
    /* The manifest is sealed here, but the DIRECTORY is not: publishing it
     * proves sole ownership by requiring mode 0700, so a staging directory
     * already sealed to 0555 could never be published at all. The
     * directory is sealed below, once it has landed at its final name. */
    (void)chmod(tmp_manifest, 0444);
#endif
    if (!platform_private_directory_publish_no_clobber(
            tmpdir, txn->candidate_dir)) {
        (void)platform_private_file_unlink_missing_ok(tmp_bin);
        (void)platform_private_file_unlink_missing_ok(tmp_manifest);
        (void)platform_private_directory_remove_empty(tmpdir);
        if (access(txn->candidate_bin, X_OK) != 0) {
            LOG_ERR("dev-activation", "candidate publish failed: %s",
                    strerror(errno));
            return DEV_ACTIVATION_E_STAGE;
        }
    } else {
#if !defined(_WIN32)
        /* Sealed only now, and only for the directory this call
         * published: the loser of a publish race must not re-mode the
         * winner's generation. */
        (void)chmod(txn->candidate_dir, 0555);
#endif
    }
    if (!platform_private_parent_flush(txn->gen_root)) {
        LOG_ERR("dev-activation", "generation parent flush failed: %s",
                strerror(errno));
        return DEV_ACTIVATION_E_STAGE;
    }
    char published_sha[65];
    if (!dev_activation_sha256_file(txn->candidate_bin, published_sha) ||
        strcmp(published_sha, txn->candidate_sha_hex) != 0) {
        LOG_ERR("dev-activation",
                "published generation artifact digest mismatch: %s",
                txn->candidate_dir);
        return DEV_ACTIVATION_E_STAGE;
    }
    char published_source_id[65];
    dev_activation_generation_source_id(
        txn, txn->candidate_generation, published_source_id);
    if (strcmp(published_source_id, txn->req->source_identity) != 0) {
        LOG_ERR("dev-activation",
                "published generation source identity mismatch: %s",
                txn->candidate_dir);
        return DEV_ACTIVATION_E_STAGE;
    }
    return DEV_ACTIVATION_OK;
}

/* Reattach a pre-existing plain binary only when an already-imported immutable
 * generation carries an authoritative source ID. This no-exec staging layer
 * cannot ask an unbound legacy binary for its baked identity, so it never
 * mints a new legacy manifest by guessing from the current worktree. */
static bool dev_import_existing(struct dev_activation_txn *txn,
                                const char *existing)
{
    if (access(existing, X_OK) != 0)
        return false;
    char sha[65];
    if (!dev_activation_sha256_file(existing, sha))
        return false;
    char generation[DEV_GEN_ID_MAX];
    int n = snprintf(generation, sizeof(generation), "legacy-%s", sha);
    if (n <= 0 || (size_t)n >= sizeof(generation))
        return false;
    char dir[PATH_MAX];
    if (!dev_activation_join(dir, sizeof(dir), txn->gen_root, generation))
        return false;
    if (platform_directory_probe_real(dir) != PLATFORM_DIRECTORY_PROBE_OK) {
        fprintf(stderr,
                "[dev-activation] refusing unbound legacy rollback binary: "
                "%s\n", existing);
        return false;
    }
    char bound_source_id[65];
    dev_activation_generation_source_id(txn, generation, bound_source_id);
    if (!bound_source_id[0])
        return false;
    char generation_bin[PATH_MAX], generation_sha[65];
    n = snprintf(generation_bin, sizeof(generation_bin),
                 "%s/zclassic23-dev", dir);
    if (n <= 0 || (size_t)n >= sizeof(generation_bin) ||
        !dev_activation_sha256_file(generation_bin, generation_sha) ||
        strcmp(generation_sha, sha) != 0)
        return false;
    if (!dev_activation_link_generation(txn, "current", generation) ||
        !dev_activation_link_generation(txn, "last-good", generation))
        return false;
    return dev_activation_refresh_compat_link(txn);
}

void dev_activation_ensure_rollback(struct dev_activation_txn *txn)
{
    dev_activation_refresh_gen_state(txn);
    if (txn->current_generation[0] != 0) {
        (void)dev_activation_refresh_compat_link(txn);
        return;
    }
    struct platform_positioned_file compat;
    platform_positioned_file_init(&compat);
    bool compat_executable =
        platform_positioned_file_open(&compat, txn->compat_bin) &&
        platform_positioned_file_is_executable(&compat);
    platform_positioned_file_close(&compat);
    if (compat_executable)
        (void)dev_import_existing(txn, txn->compat_bin);
    dev_activation_refresh_gen_state(txn);
}


/* ── deploy-state (zcl.agent_dev_deploy.v1) ──────────────────────────── */

static int dev_gen_name_cmp(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static void dev_emit_rejected(const struct dev_activation_txn *txn, FILE *f)
{
    fputc('[', f);
    DIR *d = opendir(txn->rejected_dir);
    if (!d) {
        fputc(']', f);
        return;
    }
    char *names[256];
    size_t count = 0;
    struct dirent *e;
    while ((e = readdir(d)) && count < 256) {
        size_t len = strlen(e->d_name);
        if (len <= 5 || strncmp(e->d_name, "gen-", 4) != 0)
            continue;
        if (strcmp(e->d_name + len - 5, ".json") != 0)
            continue;
        char *nm = zcl_malloc(len - 4, "dev-activation rejected name");
        if (!nm)
            continue;
        memcpy(nm, e->d_name, len - 5);
        nm[len - 5] = 0;
        names[count++] = nm;
    }
    closedir(d);
    qsort(names, count, sizeof(names[0]), dev_gen_name_cmp);
    for (size_t i = 0; i < count; i++) {
        char esc[96];
        dev_activation_json_escape(names[i], esc, sizeof(esc));
        fprintf(f, "%s\"%s\"", i ? "," : "", esc);
        free(names[i]);
    }
    fputc(']', f);
}

bool dev_activation_write_deploy_state(struct dev_activation_txn *txn)
{
    const struct dev_activation_request *req = txn->req;
    struct dev_activation_result *r = txn->result;
    if (!dev_activation_mkdir_p(req->datadir))
        return false;
    dev_activation_refresh_gen_state(txn);
    bool rollback_available = txn->last_good_generation[0] != 0;

    char tmp[PATH_MAX];
    int n = snprintf(tmp, sizeof(tmp), "%s.XXXXXX", txn->deploy_state);
    if (n <= 0 || (size_t)n >= sizeof(tmp))
        LOG_FAIL("dev-activation", "deploy-state tmp overflow");
    int fd = mkstemp(tmp);
    if (fd < 0)
        LOG_FAIL("dev-activation", "deploy-state mkstemp: %s", strerror(errno));
    FILE *f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        (void)unlink(tmp);
        LOG_FAIL("dev-activation", "deploy-state fdopen: %s", strerror(errno));
    }

    char now[32];
    dev_activation_iso_utc_now(now);
    char e_commit[256], e_source_id[80], e_type[64];
    char e_artifact[PATH_MAX], e_bin[PATH_MAX];
    char e_root[PATH_MAX], e_cand[96], e_cur[96], e_run[96], e_lg[96], e_prev[96];
    char e_act[64], e_rb[64], e_lock[PATH_MAX], e_ddir[PATH_MAX];
    char e_vstat[64], e_vdetail[512], e_capsule[512];
    dev_activation_json_escape(req->build_commit, e_commit, sizeof(e_commit));
    dev_activation_json_escape(req->source_identity, e_source_id,
                               sizeof(e_source_id));
    dev_activation_json_escape(req->build_type, e_type, sizeof(e_type));
    dev_activation_json_escape(req->artifact_path, e_artifact, sizeof(e_artifact));
    dev_activation_json_escape(txn->compat_bin, e_bin, sizeof(e_bin));
    dev_activation_json_escape(txn->gen_root, e_root, sizeof(e_root));
    dev_activation_json_escape(r->candidate_generation, e_cand, sizeof(e_cand));
    dev_activation_json_escape(txn->current_generation, e_cur, sizeof(e_cur));
    dev_activation_json_escape(r->running_generation, e_run, sizeof(e_run));
    dev_activation_json_escape(txn->last_good_generation, e_lg, sizeof(e_lg));
    dev_activation_json_escape(txn->previous_generation, e_prev, sizeof(e_prev));
    dev_activation_json_escape(r->activation_status, e_act, sizeof(e_act));
    dev_activation_json_escape(r->rollback_status, e_rb, sizeof(e_rb));
    dev_activation_json_escape(txn->lock_path, e_lock, sizeof(e_lock));
    dev_activation_json_escape(req->datadir, e_ddir, sizeof(e_ddir));
    dev_activation_json_escape(r->verify_status, e_vstat, sizeof(e_vstat));
    dev_activation_json_escape(r->verify_detail, e_vdetail, sizeof(e_vdetail));
    dev_activation_json_escape(r->failure_capsule, e_capsule, sizeof(e_capsule));

    fprintf(f, "{\n");
    fprintf(f, "  \"schema\": \"zcl.agent_dev_deploy.v1\",\n");
    fprintf(f, "  \"deployed_at_utc\": \"%s\",\n", now);
    fprintf(f, "  \"source_id_sha256\": \"%s\",\n", e_source_id);
    /* Optional Git trace metadata only. */
    fprintf(f, "  \"build_commit\": \"%s\",\n", e_commit);
    fprintf(f, "  \"build_type\": \"%s\",\n", e_type);
    fprintf(f, "  \"build_artifact\": \"%s\",\n", e_artifact);
    fprintf(f, "  \"installed_binary\": \"%s\",\n", e_bin);
    fprintf(f, "  \"generation_root\": \"%s\",\n", e_root);
    fprintf(f, "  \"candidate_generation\": \"%s\",\n", e_cand);
    fprintf(f, "  \"candidate_sha256\": \"%s\",\n", r->candidate_sha256);
    fprintf(f, "  \"current_generation\": \"%s\",\n", e_cur);
    fprintf(f, "  \"running_generation\": \"%s\",\n", e_run);
    fprintf(f, "  \"last_good_generation\": \"%s\",\n", e_lg);
    fprintf(f, "  \"previous_generation\": \"%s\",\n", e_prev);
    fprintf(f, "  \"rollback_available\": %s,\n",
            rollback_available ? "true" : "false");
    fprintf(f, "  \"activation_status\": \"%s\",\n", e_act);
    fprintf(f, "  \"rollback_status\": \"%s\",\n", e_rb);
    fprintf(f, "  \"activation_lock\": \"%s\",\n", e_lock);
    fprintf(f, "  \"activation_lock_held\": %s,\n",
            txn->lock_held ? "true" : "false");
    fprintf(f, "  \"rejected_generations\": ");
    dev_emit_rejected(txn, f);
    fprintf(f, ",\n");
    fprintf(f, "  \"service\": \"%s\",\n", req->unit);
    fprintf(f, "  \"datadir\": \"%s\",\n", e_ddir);
    fprintf(f, "  \"rpcport\": %d,\n", req->rpcport);
    fprintf(f, "  \"verify_status\": \"%s\",\n", e_vstat);
    fprintf(f, "  \"verify_detail\": \"%s\",\n", e_vdetail);
    fprintf(f, "  \"failure_capsule\": \"%s\",\n", e_capsule);
    /* Record the REAL crash-only auto-reindex sentinel state, matching
     * deploy-dev-lane.sh:write_deploy_state (a pending marker is a JSON bool
     * true; a TERMINAL/absent/malformed marker is not pending). The anchor and
     * count are emitted as bare-integer strings when a well-formed marker
     * exists, empty strings otherwise. */
    int32_t ar_anchor = 0;
    int ar_count = 0;
    bool ar_have = boot_auto_reindex_status(req->datadir, &ar_anchor, &ar_count);
    bool ar_pending = ar_have && ar_count > 0;
    fprintf(f, "  \"auto_reindex_pending\": %s,\n",
            ar_pending ? "true" : "false");
    if (ar_have) {
        fprintf(f, "  \"auto_reindex_anchor\": \"%d\",\n", (int)ar_anchor);
        fprintf(f, "  \"auto_reindex_count\": \"%d\"\n", ar_count);
    } else {
        fprintf(f, "  \"auto_reindex_anchor\": \"\",\n");
        fprintf(f, "  \"auto_reindex_count\": \"\"\n");
    }
    fprintf(f, "}\n");
    if (fclose(f) != 0) {
        (void)unlink(tmp);
        LOG_FAIL("dev-activation", "deploy-state fclose: %s", strerror(errno));
    }
    if (rename(tmp, txn->deploy_state) != 0) {
        (void)unlink(tmp);
        LOG_FAIL("dev-activation", "deploy-state rename: %s", strerror(errno));
    }
    return true;
}


#endif /* ZCL_DEV_BUILD || ZCL_TESTING */
