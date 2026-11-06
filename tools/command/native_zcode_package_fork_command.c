/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: personal package copies — zcode.package.fork and
 * zcode.package.version.save/list/restore.
 *
 * A fork is the existing verified checkout of a persisted release plus a
 * ZVCS repository in the copy whose first commit records the parent release
 * id. Versions are ordinary append-only ZVCS snapshots and source-only
 * reverts. Every mutating leaf plans first: without confirm it returns a
 * plan_id bound to the exact inputs and copy state; with that plan_id and
 * confirm:true it re-derives the plan and acts. Nothing here builds,
 * executes, signs or publishes. */

#include "command/native_command.h"
#include "command/native_zcode_package_copy.h"

#include "base/hex.h"
#include "json/json.h"
#include "sha3/sha3.h"
#include "vcs/package_checkout.h"
#include "vcs/package_store.h"
#include "vcs/vcs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define ZPC_PATH_MAX 4400
/* Bounded so a full page fits the leaf's response budget: one version row
 * is about 300 bytes, and the list budget is 8 KiB. */
#define ZPC_LIST_DEFAULT 20
#define ZPC_LIST_MAX 20
#define ZPC_CHANGED_PATHS_SHOWN 16
#define ZPC_CHANGED_PATH_BYTES 1536

static const uint8_t k_zpc_zero[32];

/* ── shared helpers ─────────────────────────────────────────────────── */

void zcl_package_copy_fail(struct zcl_command_reply *reply, const char *code,
                           bool mutated, const char *message,
                           const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "execute", false,
                           mutated, message, evidence ? evidence : "");
}

const char *zcl_package_copy_str(const struct json_value *input,
                                 const char *key)
{
    const struct json_value *v = input ? json_get(input, key) : NULL;
    const char *s = v && v->type == JSON_STR ? json_get_str(v) : NULL;
    return s && s[0] ? s : NULL;
}

const char *zcl_package_copy_datadir(const struct json_value *input,
                                     struct zcl_command_reply *reply,
                                     const char *command)
{
    const char *datadir = zcl_package_copy_str(input, "datadir");
    if (!datadir)
        datadir = zcl_native_command_datadir();
    if (datadir && datadir[0])
        return datadir;
    zcl_package_copy_fail(reply, "MISSING_DATADIR", false,
                          "no datadir given (input datadir or --datadir)",
                          command);
    return NULL;
}

bool zcl_package_copy_confirmed(const struct json_value *input)
{
    const struct json_value *v = input ? json_get(input, "confirm") : NULL;
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

bool zcl_package_copy_plan_matches(const struct json_value *input,
                                   const uint8_t want[32],
                                   struct zcl_command_reply *reply,
                                   const char *command)
{
    const char *hex = zcl_package_copy_str(input, "plan_id");
    uint8_t got[32];
    if (!hex) {
        zcl_package_copy_fail(reply, "PLAN_ID_REQUIRED", false,
                              "confirm needs the plan_id the plan call "
                              "returned", command);
        return false;
    }
    if (!zcl_hex_decode(hex, got, 32) || memcmp(got, want, 32) != 0) {
        zcl_package_copy_fail(reply, "PLAN_MISMATCH", false,
                              "the inputs or the copy changed since that "
                              "plan; run the plan again", hex);
        return false;
    }
    return true;
}

void zcl_package_copy_push_root(struct json_value *obj, const char *key,
                                const uint8_t root[32])
{
    char hex[65];
    zcl_hex_encode(root, 32, hex);
    (void)json_push_kv_str(obj, key, hex);
}

static void zpc_hash_text(struct sha3_256_ctx *ctx, const char *text)
{
    sha3_256_write(ctx, (const unsigned char *)text, strlen(text) + 1u);
}

/* ── the copy's history ─────────────────────────────────────────────── */

struct zpc_walk {
    struct zcl_package_copy *copy;
    bool broken;
    uint8_t expect[32];
    struct vcs_commit oldest;
};

static bool zpc_walk_cb(const struct vcs_commit *c, const uint8_t id[32],
                        void *user)
{
    struct zpc_walk *w = user;
    struct zcl_package_copy *copy = w->copy;
    if (copy->versions > 0 && memcmp(w->expect, id, 32) != 0) {
        w->broken = true;
        return false;
    }
    if (copy->versions == 0) {
        memcpy(copy->head_version, id, 32);
        memcpy(copy->head_tree, c->tree_hash, 32);
    }
    memcpy(w->expect, c->parent, 32);
    memcpy(copy->fork_version, id, 32);
    memcpy(copy->fork_tree, c->tree_hash, 32);
    w->oldest = *c;
    copy->versions++;
    return true;
}

/* The root commit must carry phase "fork" and task_ref
 * "zcode.fork:<64 lowercase hex>" and nothing after it. */
static bool zpc_fork_record(const struct vcs_commit *root,
                            uint8_t parent_release[32])
{
    const size_t prefix = strlen(ZCL_PACKAGE_COPY_FORK_PREFIX);
    char hex[65];
    if (memcmp(root->parent, k_zpc_zero, 32) != 0 ||
        strncmp(root->phase, ZCL_PACKAGE_COPY_FORK_PHASE,
                sizeof(root->phase)) != 0 ||
        strncmp(root->task_ref, ZCL_PACKAGE_COPY_FORK_PREFIX, prefix) != 0 ||
        root->task_ref[prefix + 64u] != '\0')
        return false;
    memcpy(hex, root->task_ref + prefix, 64);
    hex[64] = '\0';
    return zcl_hex_decode_lower(hex, parent_release, 32);
}

bool zcl_package_copy_open(const char *dir, struct zcl_package_copy *copy,
                           struct zcl_command_reply *reply,
                           const char *command)
{
    char log_path[ZPC_PATH_MAX];
    struct stat st;
    memset(copy, 0, sizeof(*copy));
    int n = snprintf(log_path, sizeof(log_path), "%s/.zvcs/commits.log",
                     dir ? dir : "");
    if (!dir || n <= 0 || (size_t)n >= sizeof(log_path) ||
        stat(log_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        zcl_package_copy_fail(reply, "NOT_A_PACKAGE_COPY", false,
                              "dir has no version history; make a copy with "
                              "zcode package fork first",
                              dir ? dir : command);
        return false;
    }
    copy->repo = vcs_open(dir);
    struct zpc_walk walk = {.copy = copy};
    bool ok = copy->repo &&
              vcs_log(copy->repo, 0, zpc_walk_cb, &walk) == VCS_OK &&
              !walk.broken && copy->versions > 0 &&
              zpc_fork_record(&walk.oldest, copy->parent_release);
    if (!ok) {
        zcl_package_copy_close(copy);
        zcl_package_copy_fail(reply, "COPY_HISTORY_INVALID", false,
                              "the copy's version chain is broken or its "
                              "fork record is missing or altered", dir);
    }
    return ok;
}

void zcl_package_copy_close(struct zcl_package_copy *copy)
{
    if (copy && copy->repo) {
        vcs_close(copy->repo);
        copy->repo = NULL;
    }
}

bool zcl_package_copy_unsaved(struct zcl_package_copy *copy, size_t *changes)
{
    *changes = 0;
    return vcs_status(copy->repo, NULL, NULL, changes) == VCS_OK;
}

/* ── zcode package fork ─────────────────────────────────────────────── */

struct zpc_fork {
    const char *datadir;
    const char *destination;
    struct vcs_package_release release;
    uint8_t release_id[32];
    uint8_t plan_id[32];
};

static bool zpc_fork_resolve(const struct json_value *input,
                             struct zpc_fork *f,
                             struct zcl_command_reply *reply,
                             const char *command)
{
    static const char *const codes[] = {
        "", "FORK_ROOT_UNKNOWN", "FORK_ROOT_AMBIGUOUS", "RELEASES_UNREADABLE",
    };
    static const char *const messages[] = {
        "", "no persisted release has this release id or package root",
        "several releases carry this package root; pass the release id",
        "the persisted releases could not be read",
    };
    const char *root_hex = zcl_package_copy_str(input, "root");
    uint8_t root[32];
    if (!root_hex || !zcl_hex_decode(root_hex, root, 32)) {
        zcl_package_copy_fail(reply, "BAD_ROOT", false,
                              "root must be 64 hex characters", command);
        return false;
    }
    enum zcl_package_copy_lookup found = zcl_package_copy_find_release(
        f->datadir, root, &f->release, f->release_id);
    if (found != ZCL_PACKAGE_COPY_FOUND) {
        zcl_package_copy_fail(reply, codes[found], false, messages[found],
                              root_hex);
        return false;
    }
    if (vcs_package_release_verify(&f->release) != VCS_PACKAGE_RELEASE_OK) {
        zcl_package_copy_fail(reply, "FORK_PARENT_INVALID", false,
                              "the stored release envelope does not verify",
                              root_hex);
        return false;
    }
    return true;
}

static bool zpc_fork_inputs(const struct zcl_command_request *request,
                            struct zcl_command_reply *reply,
                            struct zpc_fork *f, const char *command)
{
    struct stat st;
    f->datadir = zcl_package_copy_datadir(request->input, reply, command);
    f->destination = zcl_package_copy_str(request->input, "destination");
    if (!f->datadir)
        return false;
    if (!f->destination) {
        zcl_package_copy_fail(reply, "MISSING_DESTINATION", false,
                              "destination is required", command);
        return false;
    }
    if (stat(f->destination, &st) == 0) {
        zcl_package_copy_fail(reply, "DESTINATION_EXISTS", false,
                              "a fork is made beneath an absent destination",
                              f->destination);
        return false;
    }
    if (!zpc_fork_resolve(request->input, f, reply, command))
        return false;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    zpc_hash_text(&ctx, "zcl.zcode_package_fork.plan.v1");
    sha3_256_write(&ctx, f->release_id, 32);
    sha3_256_write(&ctx, f->release.package_root, 32);
    zpc_hash_text(&ctx, f->destination);
    sha3_256_finalize(&ctx, f->plan_id);
    return true;
}

static void zpc_fork_describe(struct json_value *data,
                              const struct zpc_fork *f, const char *stage)
{
    (void)json_push_kv_str(data, "stage", stage);
    zcl_package_copy_push_root(data, "plan_id", f->plan_id);
    zcl_package_copy_push_root(data, "parent_release_root", f->release_id);
    zcl_package_copy_push_root(data, "parent_package_root",
                               f->release.package_root);
    (void)json_push_kv_str(data, "name", f->release.name);
    (void)json_push_kv_str(data, "semver", f->release.semver);
    (void)json_push_kv_str(data, "destination", f->destination);
}

/* Checkout, then the fork record as the copy's first commit. */
static bool zpc_fork_commit(struct zpc_fork *f,
                            struct zcl_command_reply *reply,
                            uint8_t version[32],
                            struct vcs_package_checkout_metrics *metrics)
{
    struct vcs_package_store *store = vcs_package_store_open(
        f->datadir, vcs_package_store_quota_bytes());
    if (!store) {
        zcl_package_copy_fail(reply, "NO_STORE", false,
                              "the package store failed to open", f->datadir);
        return false;
    }
    enum vcs_package_checkout_result result = vcs_package_checkout(
        store, f->release.package_root, f->destination, metrics);
    vcs_package_store_close(store);
    if (result != VCS_PACKAGE_CHECKOUT_OK) {
        zcl_package_copy_fail(reply, "FORK_CHECKOUT_REFUSED", false,
                              vcs_package_checkout_result_string(result),
                              f->destination);
        return false;
    }
    char task_ref[96], release_hex[65];
    zcl_hex_encode(f->release_id, 32, release_hex);
    (void)snprintf(task_ref, sizeof(task_ref), "%s%s",
                   ZCL_PACKAGE_COPY_FORK_PREFIX, release_hex);
    const struct vcs_snapshot_meta meta = {
        .phase = ZCL_PACKAGE_COPY_FORK_PHASE, .task_ref = task_ref,
    };
    struct vcs_repo *repo = vcs_open(f->destination);
    bool ok = repo && vcs_snapshot(repo, &meta, version) == VCS_OK;
    vcs_close(repo);
    if (!ok)
        zcl_package_copy_fail(reply, "FORK_RECORD_FAILED", true,
                              "the package was checked out but its fork "
                              "record was not written; remove the "
                              "destination and fork again", f->destination);
    return ok;
}

void zcl_native_handle_zcode_package_fork(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *command = "zcode.package.fork";
    struct zpc_fork f;
    memset(&f, 0, sizeof(f));
    if (!request || !reply || !zpc_fork_inputs(request, reply, &f, command))
        return;
    if (!zcl_package_copy_confirmed(request->input)) {
        zpc_fork_describe(&reply->data, &f, "plan");
        (void)json_push_kv_str(&reply->data, "next",
                               "repeat with this plan_id and confirm:true");
        return;
    }
    uint8_t version[32];
    struct vcs_package_checkout_metrics metrics = {0};
    if (!zcl_package_copy_plan_matches(request->input, f.plan_id, reply,
                                       command) ||
        !zpc_fork_commit(&f, reply, version, &metrics))
        return;
    zpc_fork_describe(&reply->data, &f, "commit");
    zcl_package_copy_push_root(&reply->data, "version", version);
    (void)json_push_kv_int(&reply->data, "files", metrics.files);
    (void)json_push_kv_int(&reply->data, "bytes", (int64_t)metrics.bytes);
    (void)json_push_kv_bool(&reply->data, "executed", false);
    reply->error.mutated = true;
}

/* ── zcode package version save ─────────────────────────────────────── */

struct zpc_changes {
    struct sha3_256_ctx ctx;
    struct json_value paths;
    size_t count;
    size_t shown;
    size_t shown_bytes;
};

static void zpc_change_cb(enum vcs_diff_kind kind, const struct vcs_entry *a,
                          const struct vcs_entry *b, void *user)
{
    struct zpc_changes *ch = user;
    const struct vcs_entry *e = b ? b : a;
    uint8_t tag = (uint8_t)kind;
    if (!e)
        return;
    sha3_256_write(&ch->ctx, &tag, 1);
    zpc_hash_text(&ch->ctx, e->path);
    sha3_256_write(&ch->ctx, b ? b->blob : k_zpc_zero, 32);
    ch->count++;
    size_t len = strlen(e->path);
    if (ch->shown < ZPC_CHANGED_PATHS_SHOWN &&
        ch->shown_bytes + len <= ZPC_CHANGED_PATH_BYTES) {
        struct json_value path;
        ch->shown++;
        ch->shown_bytes += len;
        json_init(&path);
        json_set_str(&path, e->path);
        (void)json_push_back(&ch->paths, &path);
        json_free(&path);
    }
}

void zcl_native_handle_zcode_package_version_save(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *command = "zcode.package.version.save";
    struct zcl_package_copy copy;
    if (!request || !reply ||
        !zcl_package_copy_open(zcl_package_copy_str(request->input, "dir"),
                               &copy, reply, command))
        return;
    struct zpc_changes ch = {.count = 0};
    uint8_t plan_id[32], version[32];
    json_init(&ch.paths);
    json_set_array(&ch.paths);
    sha3_256_init(&ch.ctx);
    zpc_hash_text(&ch.ctx, "zcl.zcode_package_version_save.plan.v1");
    sha3_256_write(&ch.ctx, copy.head_version, 32);
    bool ok = vcs_status(copy.repo, zpc_change_cb, &ch, NULL) == VCS_OK;
    sha3_256_finalize(&ch.ctx, plan_id);
    if (!ok || ch.count == 0) {
        zcl_package_copy_fail(reply, ok ? "VERSION_NO_CHANGES" : "STATUS_FAILED",
                              false, ok ? "nothing changed since the saved "
                                          "version" : "status scan failed",
                              command);
    } else if (!zcl_package_copy_confirmed(request->input)) {
        (void)json_push_kv_str(&reply->data, "stage", "plan");
        zcl_package_copy_push_root(&reply->data, "plan_id", plan_id);
        zcl_package_copy_push_root(&reply->data, "version", copy.head_version);
        (void)json_push_kv_int(&reply->data, "changes", (int64_t)ch.count);
        (void)json_push_kv(&reply->data, "changed_paths", &ch.paths);
        (void)json_push_kv_bool(&reply->data, "changed_paths_truncated",
                                ch.count > ch.shown);
    } else if (zcl_package_copy_plan_matches(request->input, plan_id, reply,
                                             command)) {
        const struct vcs_snapshot_meta meta = {.phase = "save"};
        if (vcs_snapshot(copy.repo, &meta, version) != VCS_OK) {
            zcl_package_copy_fail(reply, "VERSION_SAVE_FAILED", false,
                                  "the snapshot was refused or failed",
                                  command);
        } else {
            (void)json_push_kv_str(&reply->data, "stage", "commit");
            zcl_package_copy_push_root(&reply->data, "version", version);
            zcl_package_copy_push_root(&reply->data, "previous_version",
                                       copy.head_version);
            (void)json_push_kv_int(&reply->data, "changes", (int64_t)ch.count);
            reply->error.mutated = true;
        }
    }
    json_free(&ch.paths);
    zcl_package_copy_close(&copy);
}

/* ── zcode package version list ─────────────────────────────────────── */

struct zpc_rows {
    struct json_value rows;
};

static bool zpc_row_cb(const struct vcs_commit *c, const uint8_t id[32],
                       void *user)
{
    struct zpc_rows *r = user;
    struct json_value row;
    char phase[sizeof(c->phase) + 1u];
    (void)snprintf(phase, sizeof(phase), "%.*s", (int)sizeof(c->phase),
                   c->phase);
    json_init(&row);
    json_set_object(&row);
    zcl_package_copy_push_root(&row, "version", id);
    zcl_package_copy_push_root(&row, "previous_version", c->parent);
    zcl_package_copy_push_root(&row, "tree", c->tree_hash);
    (void)json_push_kv_str(&row, "kind", phase);
    (void)json_push_kv_int(&row, "saved_at", c->committed_at);
    (void)json_push_back(&r->rows, &row);
    json_free(&row);
    return true;
}

static size_t zpc_list_limit(const struct json_value *input)
{
    const struct json_value *v = input ? json_get(input, "limit") : NULL;
    int64_t limit = v ? json_get_int(v) : ZPC_LIST_DEFAULT;
    if (limit <= 0)
        limit = ZPC_LIST_DEFAULT;
    return (size_t)(limit < ZPC_LIST_MAX ? limit : ZPC_LIST_MAX);
}

void zcl_native_handle_zcode_package_version_list(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *command = "zcode.package.version.list";
    struct zcl_package_copy copy;
    if (!request || !reply ||
        !zcl_package_copy_open(zcl_package_copy_str(request->input, "dir"),
                               &copy, reply, command))
        return;
    struct zpc_rows r;
    size_t limit = zpc_list_limit(request->input);
    json_init(&r.rows);
    json_set_array(&r.rows);
    if (vcs_log(copy.repo, limit, zpc_row_cb, &r) != VCS_OK) {
        zcl_package_copy_fail(reply, "COPY_HISTORY_INVALID", false,
                              "the version log could not be read", command);
    } else {
        (void)json_push_kv_int(&reply->data, "count", (int64_t)copy.versions);
        zcl_package_copy_push_root(&reply->data, "head_version",
                                   copy.head_version);
        zcl_package_copy_push_root(&reply->data, "fork_version",
                                   copy.fork_version);
        zcl_package_copy_push_root(&reply->data, "parent_release_root",
                                   copy.parent_release);
        (void)json_push_kv(&reply->data, "versions", &r.rows);
        (void)json_push_kv_bool(&reply->data, "truncated",
                                copy.versions > limit);
    }
    json_free(&r.rows);
    zcl_package_copy_close(&copy);
}

/* ── zcode package version restore ──────────────────────────────────── */

struct zpc_find {
    const uint8_t *target;
    bool found;
};

static bool zpc_find_cb(const struct vcs_commit *c, const uint8_t id[32],
                        void *user)
{
    struct zpc_find *f = user;
    (void)c;
    f->found = memcmp(id, f->target, 32) == 0;
    return !f->found;
}

/* Refusals before any plan: unknown version, unsaved work, no-op. */
static bool zpc_restore_admit(struct zcl_package_copy *copy,
                              const uint8_t target[32],
                              struct zcl_command_reply *reply,
                              const char *command)
{
    struct zpc_find find = {.target = target};
    size_t changes = 0;
    if (vcs_log(copy->repo, 0, zpc_find_cb, &find) != VCS_OK ||
        !find.found) {
        zcl_package_copy_fail(reply, "VERSION_UNKNOWN", false,
                              "version is not in this copy's history",
                              command);
        return false;
    }
    if (!zcl_package_copy_unsaved(copy, &changes) || changes > 0) {
        zcl_package_copy_fail(reply, "VERSION_UNSAVED_CHANGES", false,
                              "save or discard the unsaved changes first",
                              command);
        return false;
    }
    if (memcmp(target, copy->head_version, 32) == 0) {
        zcl_package_copy_fail(reply, "VERSION_ALREADY_CURRENT", false,
                              "the copy is already at that version", command);
        return false;
    }
    return true;
}

static void zpc_restore_run(const struct zcl_command_request *request,
                            struct zcl_command_reply *reply,
                            struct zcl_package_copy *copy,
                            const uint8_t target[32], const char *command)
{
    uint8_t plan_id[32], version[32];
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    zpc_hash_text(&ctx, "zcl.zcode_package_version_restore.plan.v1");
    sha3_256_write(&ctx, copy->head_version, 32);
    sha3_256_write(&ctx, target, 32);
    sha3_256_finalize(&ctx, plan_id);
    if (!zcl_package_copy_confirmed(request->input)) {
        (void)json_push_kv_str(&reply->data, "stage", "plan");
        zcl_package_copy_push_root(&reply->data, "plan_id", plan_id);
        zcl_package_copy_push_root(&reply->data, "version", copy->head_version);
        zcl_package_copy_push_root(&reply->data, "restore_to", target);
        return;
    }
    if (!zcl_package_copy_plan_matches(request->input, plan_id, reply,
                                       command))
        return;
    if (vcs_revert(copy->repo, target, NULL, version) != VCS_OK) {
        zcl_package_copy_fail(reply, "VERSION_RESTORE_FAILED", false,
                              "the restore was refused or failed", command);
        return;
    }
    (void)json_push_kv_str(&reply->data, "stage", "commit");
    zcl_package_copy_push_root(&reply->data, "version", version);
    zcl_package_copy_push_root(&reply->data, "restored_from", target);
    zcl_package_copy_push_root(&reply->data, "previous_version",
                               copy->head_version);
    reply->error.mutated = true;
}

void zcl_native_handle_zcode_package_version_restore(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *command = "zcode.package.version.restore";
    struct zcl_package_copy copy;
    uint8_t target[32];
    if (!request || !reply)
        return;
    const char *hex = zcl_package_copy_str(request->input, "version");
    if (!hex || !zcl_hex_decode(hex, target, 32)) {
        zcl_package_copy_fail(reply, "BAD_VERSION",
                              false, "version must be 64 hex characters",
                              command);
        return;
    }
    if (!zcl_package_copy_open(zcl_package_copy_str(request->input, "dir"),
                               &copy, reply, command))
        return;
    if (zpc_restore_admit(&copy, target, reply, command))
        zpc_restore_run(request, reply, &copy, target, command);
    zcl_package_copy_close(&copy);
}
