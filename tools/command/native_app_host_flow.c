/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Exact kept snapshot -> explicit consent -> bounded hosting window. */
#define _POSIX_C_SOURCE 200809L
#include "command/native_app_host_flow.h"
#include "command/native_app_host_controller.h"
#include "command/native_app_host_view.h"
#include "command/native_app_scratch.h"
#include "command/native_command.h"
#include "command/native_app_share_command.h"
#include "command/native_app_receive_command.h"
#include "command/native_zcode_package_copy.h"
#include "command/app_selection.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "crypto/sha256.h"
#include "platform/rng.h"
#include "vcs/bundle_carry.h"
#include "vcs/package_share.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
struct ahf_identity { char name[160], semver[160], version[65], package[65], publisher[67], release[65]; };
static bool ahf_identity(struct ahf_identity *out, const struct zcl_app_share_identity *id)
{
    return an_scratch_copy_text(out->name, sizeof(out->name), id->name, false) && an_scratch_copy_text(out->semver, sizeof(out->semver), id->semver, false) &&
        an_scratch_copy_text(out->version, sizeof(out->version), id->version, false) && an_scratch_copy_text(out->package, sizeof(out->package), id->package, false) &&
        an_scratch_copy_text(out->publisher, sizeof(out->publisher), id->publisher, false) && an_scratch_copy_text(out->release, sizeof(out->release), id->release, false);
}
static bool ahf_confirm(struct app_confirm *v, const struct ahf_identity *id,
                        app_confirm_presenter presenter, void *ctx)
{
    v->window_title = "Share a link?";
    zcl_present_model_init_v1(&v->model, ZCL_PRESENT_MODEL_STATUS_CARD);
    (void)snprintf(v->model.request_id, sizeof(v->model.request_id), "app-host-confirm");
    (void)snprintf(v->model.title, sizeof(v->model.title), "Share this kept version?");
    (void)snprintf(v->model.summary, sizeof(v->model.summary), "Review all pages before sharing.");
    v->model.action_count = 4;
    app_confirm_action(&v->model.actions[0], ZCL_PRESENT_ACTION_CANCEL, "cancel", "Cancel");
    app_confirm_action(&v->model.actions[1], ZCL_PRESENT_ACTION_SELECT, "back", "Back");
    app_confirm_action(&v->model.actions[2], ZCL_PRESENT_ACTION_SELECT, "next", "Next");
    app_confirm_action(&v->model.actions[3], ZCL_PRESENT_ACTION_CONFIRM, "share", "Share link");
    char why[256];
    return app_confirm_field(&v->model, "App: ", id->name) &&
        app_confirm_field(&v->model, "Version: ", id->semver) &&
        app_confirm_field(&v->model, "Saved version: ", id->version) &&
        app_confirm_field(&v->model, "Package: ", id->package) &&
        app_confirm_field(&v->model, "Publisher: ", id->publisher) &&
        app_confirm_field(&v->model, "Release: ", id->release) &&
        app_confirm_field(&v->model, "Availability: ", "Anyone with the link can receive this version while this window stays open, for up to 24 hours.") &&
        app_confirm_field(&v->model, "Recipient: ", "In Z23: My Apps > Discover apps > Open a shared app. Paste the link. No account needed.") &&
        app_confirm_prepare(v, why, sizeof(why)) && app_confirm_show(v, presenter, ctx, why, sizeof(why));
}
static bool ahf_file_same(const struct stat *a, const struct stat *b)
{ return a->st_dev == b->st_dev && a->st_ino == b->st_ino; }
static bool ahf_file_bound(struct an_scratch *scratch, int fd, const struct stat *st)
{
    struct stat held, named;
    return fstat(fd, &held) == 0 && ahf_file_same(st, &held) && held.st_size == st->st_size &&
        fstatat(scratch->root, "carrier.z23share", &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        ahf_file_same(st, &named) && an_scratch_bound(scratch);
}
static bool ahf_verify_carrier(const struct ahf_identity *id, const uint8_t *bytes, size_t n)
{
    struct vcs_package_share *share = zcl_calloc(1, sizeof(*share), "app.host.verify");
    const char *reason = NULL; uint8_t release[32], package[32], publisher[33];
    bool ok = share && zcl_hex_decode_lower(id->release, release, 32) &&
        zcl_hex_decode_lower(id->package, package, 32) && zcl_hex_decode_lower(id->publisher, publisher, 33) &&
        vcs_package_share_load(share, bytes, n, &reason) && !strcmp(share->release.name, id->name) &&
        !memcmp(share->release_id, release, 32) && !memcmp(share->release.package_root, package, 32) &&
        !memcmp(share->release.publisher_pubkey, publisher, 33);
    if (share) { vcs_package_share_cleanup(share); free(share); }
    return ok;
}
static bool ahf_carrier(struct an_scratch *scratch, const struct ahf_identity *id,
                        char sha[65], uint64_t *size)
{
    if (!an_scratch_bound(scratch)) return false;
    int fd = openat(scratch->root, "carrier.z23share", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    struct stat st; bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == geteuid() &&
        st.st_size > 0 && (uint64_t)st.st_size <= VCS_BUNDLE_MAX_BYTES && ahf_file_bound(scratch, fd, &st);
    size_t n = ok ? (size_t)st.st_size : 0;
    uint8_t *bytes = ok ? zcl_malloc(n, "app.host.carrier") : NULL;
    ok = ok && bytes && an_scratch_read_exact(fd, bytes, n) && ahf_file_bound(scratch, fd, &st);
    close(fd);
    ok = ok && ahf_verify_carrier(id, bytes, n);
    if (ok) { struct sha256_ctx h; uint8_t digest[32]; sha256_init(&h); sha256_write(&h, bytes, n);
        sha256_finalize(&h, digest); zcl_hex_encode(digest, 32, sha); *size = n; }
    free(bytes); return ok;
}
static struct json_value *ahf_existing_facts(struct zcl_command_reply *reply)
{
    for (size_t i = 0; i < reply->data.num_children; i++)
        if (reply->data.keys[i] && !strcmp(reply->data.keys[i], "failure_facts"))
            return &reply->data.children[i];
    return NULL;
}
/* Added recovery stays within the command error wire budget. Preserve
 * already-present signer facts and never truncate a path into a false one. */
static bool ahf_fact(struct json_value *facts, const char *key, const char *value)
{
    if (!facts || !value) return false;
    if (json_get(facts, key)) return true;
    struct json_value scalar; json_init(&scalar); json_set_str(&scalar, value);
    size_t used = json_write(facts, NULL, 0), value_bytes = json_write(&scalar, NULL, 0);
    bool fits = scalar.type == JSON_STR && used && value_bytes && used <= 1460u &&
        strlen(key) <= 1460u - used && value_bytes <= 1460u - used - strlen(key) &&
        value_bytes + strlen(key) + 6u <= 1460u - used;
    json_free(&scalar);
    return fits && json_push_kv_str(facts, key, value);
}
static void ahf_failure(struct zcl_command_reply *reply, const char *code,
    const char *message, const char *path, const struct ahf_identity *id, bool mutated)
{
    if (reply->status == ZCL_COMMAND_STATUS_PASSED)
        zcl_package_copy_fail(reply, code, mutated, message, "app.library");
    else reply->error.mutated |= mutated; /* preserve a previous signer failure */
    if (!mutated) return;
    struct json_value created; json_init(&created); json_set_object(&created);
    struct json_value *facts = ahf_existing_facts(reply); if (!facts) facts = &created;
    if (facts->type != JSON_OBJ) { json_free(&created); return; }
    bool omitted = false;
    if (id) {
        omitted |= !ahf_fact(facts, "app", id->name); omitted |= !ahf_fact(facts, "saved_version", id->version);
        omitted |= !ahf_fact(facts, "package_root", id->package); omitted |= !ahf_fact(facts, "publisher", id->publisher);
        omitted |= !ahf_fact(facts, "release_id", id->release);
    }
    (void)path; /* scratch path is attached only when cleanup is unconfirmed */
    size_t bytes = json_write(facts, NULL, 0);
    if (omitted && bytes && bytes <= 1470u && !json_get(facts, "details_unavailable"))
        (void)json_push_kv_bool(facts, "details_unavailable", true);
    if (facts == &created) (void)json_push_kv(&reply->data, "failure_facts", &created);
    json_free(&created);
}
static bool ahf_scratch_field(const char *key)
{
    return key && (!strcmp(key, "output") || !strcmp(key, "share_file") ||
        !strcmp(key, "private_path") || !strcmp(key, "cleanup_path"));
}
static bool ahf_same_path(const char *value, const char *scratch, const char *output)
{ return value && ((!strcmp(value, scratch)) || (!strcmp(value, output))); }
static void ahf_cleanup_completed(struct zcl_command_reply *reply, const char *scratch, const char *output)
{
    struct json_value *facts = ahf_existing_facts(reply);
    if (facts && facts->type == JSON_OBJ) {
        for (size_t i = 0; i < facts->num_children; ++i) {
            struct json_value *v = &facts->children[i];
            if (ahf_scratch_field(facts->keys[i]) && v->type == JSON_STR &&
                ahf_same_path(json_get_str(v), scratch, output)) json_set_null(v);
        }
        if (!json_get(facts, "cleanup_completed") && json_write(facts, NULL, 0) <= 1470u)
            (void)json_push_kv_bool(facts, "cleanup_completed", true);
    }
    /* A signer error may have copied a bounded prefix of the temporary output
     * into evidence; remove only the exact output or its full-buffer prefix. */
    size_t n = strlen(reply->error.evidence);
    bool exact = n && !strcmp(reply->error.evidence, output);
    bool truncated = n == sizeof(reply->error.evidence) - 1u && !strncmp(output, reply->error.evidence, n);
    if (exact || truncated) {
        (void)snprintf(reply->error.evidence, sizeof(reply->error.evidence), "app.library");
        if (!strcmp(reply->error.code, "SHARE_FILE_WRITE"))
            (void)snprintf(reply->error.message, sizeof(reply->error.message),
                "The release is kept, but its temporary share file could not be created.");
    }
}
static void ahf_cleanup_unconfirmed(struct zcl_command_reply *reply, const char *path)
{
    struct json_value created; json_init(&created); json_set_object(&created);
    struct json_value *facts = ahf_existing_facts(reply); if (!facts) facts = &created;
    if (facts->type == JSON_OBJ) {
        size_t used = json_write(facts, NULL, 0);
        if (used && used <= 1420u && !json_get(facts, "cleanup_unconfirmed"))
            (void)json_push_kv_bool(facts, "cleanup_unconfirmed", true);
        if (!ahf_fact(facts, "cleanup_path", path) && !json_get(facts, "details_unavailable") &&
            json_write(facts, NULL, 0) <= 1470u)
            (void)json_push_kv_bool(facts, "details_unavailable", true);
        if (facts == &created) (void)json_push_kv(&reply->data, "failure_facts", &created);
    }
    json_free(&created);
}
#if defined(ZCL_TESTING)
/* Exercise the production failure composition with explicit cleanup outcome. */
void zcl_test_app_host_failure_facts(struct zcl_command_reply *reply, const char *scratch,
                                     const char *path, bool cleanup_unconfirmed)
{
    struct ahf_identity id = {0};
    (void)snprintf(id.name, sizeof(id.name), "owner/app");
    memset(id.version, 'a', 64); memset(id.package, 'b', 64); memset(id.release, 'c', 64);
    memset(id.publisher, 'd', 66);
    ahf_failure(reply, "HOST_UNAVAILABLE", "The host failed.", NULL, &id, true);
    if (cleanup_unconfirmed) ahf_cleanup_unconfirmed(reply, scratch);
    else ahf_cleanup_completed(reply, scratch, path);
}
#endif
static struct an_scratch *ahf_scratch(const char *datadir, struct zcl_command_reply *reply)
{
    char anchor[AG_PATH], token[33]; uint8_t random[16];
    if (!app_receive_profile_validate(datadir, anchor, sizeof(anchor), reply)) return NULL;
    if (!rng_host_fill(random, sizeof(random))) {
        zcl_package_copy_fail(reply, "RNG_UNAVAILABLE", false, "Cannot prepare private sharing.", "app.library"); return NULL;
    }
    zcl_hex_encode(random, sizeof(random), token);
    struct an_scratch *scratch = zcl_calloc(1, sizeof(*scratch), "app.host.scratch");
    if (!scratch) { zcl_package_copy_fail(reply, "OUT_OF_MEMORY", false, "Cannot prepare private sharing.", "app.library"); return NULL; }
    if (an_scratch_create(scratch, anchor, token)) return scratch;
    bool created = scratch->created, clean = created && an_scratch_cleanup(scratch, true);
    if (!created) { if (scratch->root >= 0) close(scratch->root); if (scratch->parent >= 0) close(scratch->parent); }
    ahf_failure(reply, "TEMP_UNAVAILABLE", "Cannot prepare private sharing.",
                NULL, NULL, created && !clean);
    if (created && !clean) ahf_cleanup_unconfirmed(reply, scratch->path);
    free(scratch); return NULL;
}
/* Stop pressed while still connecting: the link never existed. Say so.
 * Stays PASSED (a user cancel) and keeps the was_available fact, but never
 * returns silently: if the notice cannot be shown the reply fails closed. */
static bool ahf_never_ready_notice(const struct ahf_identity *identity,
    app_confirm_presenter presenter, void *ctx, struct zcl_command_reply *reply)
{
    struct app_confirm *v = zcl_calloc(1, sizeof(*v), "app.host.never_ready");
    char why[256] = {0};
    if (v) {
        zcl_present_model_init_v1(&v->model, ZCL_PRESENT_MODEL_STATUS_CARD);
        v->window_title = "Share a link";
        (void)snprintf(v->model.request_id, sizeof(v->model.request_id), "app-host-never-ready");
        (void)snprintf(v->model.title, sizeof(v->model.title), "The link never became available.");
        (void)snprintf(v->model.summary, sizeof(v->model.summary),
            "Sharing stopped before the private link was ready. Once this node is fully started, open My Apps and try Share a link again.");
        v->model.action_count = 4;
        app_confirm_action(&v->model.actions[0], ZCL_PRESENT_ACTION_CANCEL, "close", "Close");
        app_confirm_action(&v->model.actions[1], ZCL_PRESENT_ACTION_SELECT, "back", "Back");
        app_confirm_action(&v->model.actions[2], ZCL_PRESENT_ACTION_SELECT, "next", "Next");
        app_confirm_action(&v->model.actions[3], ZCL_PRESENT_ACTION_CONFIRM, "done", "Done");
    }
    bool shown = v && app_confirm_field(&v->model, "App: ", identity->name) &&
        app_confirm_field(&v->model, "Saved version: ", identity->semver) &&
        app_confirm_prepare(v, why, sizeof(why)) && app_confirm_show(v, presenter, ctx, why, sizeof(why));
    if (v) { app_confirm_free(v); free(v); }
    if (shown) return true;
    ahf_failure(reply, "HOST_NEVER_READY", "Sharing stopped before the link became available.", NULL, identity, true);
    return false;
}
static bool ahf_host(struct an_scratch *scratch, const struct ahf_identity *identity,
    const char *self, app_confirm_presenter presenter, void *ctx,
    struct zcl_command_reply *reply, struct app_host_job_result *result, bool *retain)
{
    char sha[65] = {0}; uint64_t size = 0;
    if (!ahf_carrier(scratch, identity, sha, &size)) {
        ahf_failure(reply, "CARRIER_INVALID", "The signed sharing file could not be verified.", scratch->path, identity, true); return false;
    }
    struct app_host_job_args args = {.self_path = self, .scratch_path = scratch->path,
        .scratch_dev = (uint64_t)scratch->dev, .scratch_ino = (uint64_t)scratch->ino,
        .name = identity->name, .release_root = identity->release, .package_root = identity->package,
        .publisher = identity->publisher, .carrier_sha256 = sha, .carrier_size = size,
        .network = zcl_native_command_network(), .duration_ms = 86400000u};
    struct app_host_owner *owner = app_host_owner_start(&args);
    if (!owner) { ahf_failure(reply, "HOST_UNAVAILABLE", "Cannot start sharing.", scratch->path, identity, true); return false; }
    char why[256]; bool shown = app_host_view_run(owner, presenter, ctx, why, sizeof(why));
    app_host_owner_stop(owner);
    if (!app_host_owner_join(owner, result)) {
        *retain = true; ahf_failure(reply, "HOST_CLEANUP_UNKNOWN", "Sharing stopped could not be confirmed.", NULL, identity, true);
        ahf_cleanup_unconfirmed(reply, scratch->path); return false;
    }
    app_host_owner_free(owner);
    if (!shown || result->outcome == APP_HOST_FAILED ||
        (!result->ready && result->outcome != APP_HOST_STOPPED)) {
        ahf_failure(reply, "HOST_UNAVAILABLE", "Sharing ended unexpectedly or could not start.", scratch->path, identity, true); return false;
    }
    /* A stop after the link was available stays a plain success. */
    if (!result->ready) return ahf_never_ready_notice(identity, presenter, ctx, reply);
    return true;
}
static void ahf_success(struct zcl_command_reply *reply, const struct ahf_identity *identity,
                        const struct app_host_job_result *result)
{
    json_free(&reply->data); json_init(&reply->data); json_set_object(&reply->data);
    bool described = json_push_kv_str(&reply->data, "host_status", result->outcome == APP_HOST_EXPIRED ? "expired" : "stopped") &&
        json_push_kv_bool(&reply->data, "was_available", result->ready) &&
        json_push_kv_str(&reply->data, "app", identity->name) &&
        json_push_kv_str(&reply->data, "saved_version", identity->version) &&
        json_push_kv_str(&reply->data, "package_root", identity->package) &&
        json_push_kv_str(&reply->data, "publisher", identity->publisher) &&
        json_push_kv_str(&reply->data, "release_id", identity->release);
    if (!described) ahf_failure(reply, "RESULT_UNAVAILABLE", "Sharing completed, but its result could not be described.",
                               NULL, identity, true);
    reply->error.mutated = true;
}
static struct zcl_app_share_session *ahf_approved(const struct app_selection *selection,
    const char *path, struct ahf_identity *identity, app_confirm_presenter presenter,
    void *ctx, struct zcl_command_reply *reply)
{
    struct zcl_app_share_session *session = zcl_app_share_prepare(selection->app, path, selection, reply);
    if (!session) return NULL;
    struct zcl_app_share_identity borrowed; zcl_app_share_identity(session, &borrowed);
    if (!ahf_identity(identity, &borrowed)) {
        ahf_failure(reply, "IDENTITY_UNAVAILABLE", "Cannot describe the selected version.", "app.library", NULL, false);
        zcl_app_share_dispose(session); return NULL;
    }
    struct app_confirm *confirm = zcl_calloc(1, sizeof(*confirm), "app.host.confirm");
    if (!confirm || !ahf_confirm(confirm, identity, presenter, ctx)) {
        ahf_failure(reply, "CONFIRMATION_UNAVAILABLE", "Cannot display sharing confirmation.", "app.library", NULL, false);
        if (confirm) { app_confirm_free(confirm); free(confirm); }
        zcl_app_share_dispose(session); return NULL;
    }
    bool approved = confirm->confirmed;
    app_confirm_free(confirm); free(confirm);
    if (!approved) {
        (void)json_push_kv_str(&reply->data, "status", "canceled");
        zcl_app_share_dispose(session); return NULL;
    }
    return session;
}
static void ahf_finish(struct an_scratch *scratch, const char *path, bool committed, bool retain,
    const struct ahf_identity *identity, const struct app_host_job_result *result,
    struct zcl_command_reply *reply)
{
    if (retain) return; /* owner and scratch remain alive when join/reap is unknown */
    bool clean = an_scratch_cleanup(scratch, true);
    if (clean && reply->status != ZCL_COMMAND_STATUS_PASSED) ahf_cleanup_completed(reply, scratch->path, path);
    if (!clean) {
        ahf_failure(reply, "TEMP_CLEANUP_FAILED", "Private sharing cleanup could not be confirmed.",
                    NULL, committed ? identity : NULL, true);
        ahf_cleanup_unconfirmed(reply, scratch->path);
    }
    free(scratch);
    if (clean && committed && reply->status == ZCL_COMMAND_STATUS_PASSED)
        ahf_success(reply, identity, result);
}


#endif

void app_host_flow(const struct app_selection *selection, const char *self,
    app_confirm_presenter presenter, void *ctx, struct zcl_command_reply *reply)
{
#if !defined(_WIN32)
    if (!reply) return;
    if (!selection || !self || self[0] != '/') {
        zcl_package_copy_fail(reply, "BAD_INPUT", false, "Select a saved app to share.", "app.library"); return;
    }
    struct an_scratch *scratch = ahf_scratch(selection->datadir, reply);
    if (!scratch) return;
    struct ahf_identity identity = {0}; bool committed = false, retain = false;
    char path[AG_PATH] = {0};
    struct zcl_app_share_session *session = NULL;
    struct app_host_job_result result = {0};
    int n = snprintf(path, sizeof(path), "%s/carrier.z23share", scratch->path);
    if (n <= 0 || (size_t)n >= sizeof(path)) {
        ahf_failure(reply, "TEMP_UNAVAILABLE", "The private sharing path is too long.", scratch->path, NULL, false); goto cleanup;
    }
    session = ahf_approved(selection, path, &identity, presenter, ctx, reply);
    if (!session) goto cleanup;
    if (!an_scratch_bound(scratch)) {
        ahf_failure(reply, "TEMP_REPLACED", "Private sharing storage changed.", scratch->path, NULL, false); goto cleanup;
    }
    zcl_app_share_commit(session, reply); committed = reply->status == ZCL_COMMAND_STATUS_PASSED;
    if (!committed) goto cleanup;
    (void)ahf_host(scratch, &identity, self, presenter, ctx, reply, &result, &retain);
cleanup:
    zcl_app_share_dispose(session);
    ahf_finish(scratch, path, committed, retain, &identity, &result, reply);
#else
    (void)selection; (void)self; (void)presenter; (void)ctx; if (reply) zcl_package_copy_fail(reply, "HOST_UNAVAILABLE", false, "Link sharing is unavailable on this platform.", "app.library");
#endif
}
