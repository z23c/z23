/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: app.seed — publish an in-repo app as a self-contained package
 * release under the owner's own key, so a copy of it (and a friend's
 * received copy) holds everything its build reads.
 *
 * The tree is composed by command/app_seed.h in private scratch: apps/<app>
 * with its own Makefile (the package entrypoint app.build runs) and the
 * checkout files its zcode-seed.def maps; the tree's print-app-closure must
 * name only files it holds. vcs_package_prepare derives the manifest,
 * recipe and unsigned release there, exactly as a publish does, with the
 * owner's publisher key (~/.z23/zcode_publisher.key, made 0600 by confirm on first
 * use) at its next sequence. No hex crosses any boundary: the wires go in memory to
 * zcl_native_zcode_local_publication_commit, the lifecycle
 * zcode.package.publish.commit uses.
 *
 * Plan (writes nothing; a missing owner key is only announced, and made
 * by confirm) returns the package
 * root, the file count, the release id and a plan_id. When this owner
 * already holds a release of the same package root in this datadir, that
 * release is the answer: confirm writes nothing and says existing:true, so
 * re-seeding the same checkout returns the same release and package root.
 * Otherwise confirm signs the release id inside the key module and
 * publishes. AUTH_OWNER: the owner's key signs, so MCP refuses this leaf. */

#include "command/native_command.h"

#include "command/app_seed.h"
#include "command/native_app_seed_installed.h"
#include "command/native_app_personalize_command.h"
#include "command/native_devagent.h"
#include "command/native_zcode_package_copy.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/path_compat.h"
#include "platform/temp_directory.h"
#include "plugin/plugin_dist.h"
#include "sha3/sha3.h"
#include "util/file_tree_ops.h"
#include "vcs/package_accept.h"
#include "vcs/package_prepare.h"
#include "vcs/package_publish.h"
#include "vcs/package_release.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ASC_COMMAND "app.seed"
#define ASC_PATH 4400
#define ASC_PLAN_DOMAIN "zcl.app_seed.plan.v1"

struct asc {
    const struct json_value *input;
    struct zcl_command_reply *reply;
    const char *datadir;
    const char *app;
    char source[ASC_PATH];
    char stage[PLATFORM_TEMP_PATH_MAX];
    char key_path[ASC_PATH];
    bool key_created;
    bool key_pending; /* no owner key yet: the confirm half makes it */
    char chain_id[VCS_PACKAGE_RELEASE_CHAIN_ID_MAX + 1u];
    struct vcs_package_prepare_options options;
    struct vcs_package_prepared prepared;
    bool prepared_live;
    size_t mapped;
    size_t closure;
    bool unconfined;
    bool existing;
    uint64_t existing_sequence;
    uint8_t release_id[32];
    uint8_t plan_id[32];
};

static void asc_fail(struct asc *s, const char *code, bool mutated,
                     const char *message, const char *evidence)
{
    zcl_package_copy_fail(s->reply, code, mutated, message, evidence);
}

/* ── inputs ──────────────────────────────────────────────────────────── */

/* `source`, else the checkout the command runs in. */
static bool asc_source(struct asc *s)
{
    const char *given = zcl_package_copy_str(s->input, "source");
    bool ok = given ? given[0] == '/' &&
                          platform_directory_canonical_real(
                              given, s->source, sizeof(s->source))
                    : zcl_devagent_checkout_root(NULL, s->source,
                                                 sizeof(s->source));
    if (!ok)
        asc_fail(s, "SOURCE_UNKNOWN", false, "source must be the absolute "
                 "directory of a z23 checkout, or run inside one",
                 given ? given : "(cwd)");
    return ok;
}

static bool asc_inputs(struct asc *s)
{
    s->app = zcl_package_copy_str(s->input, "app");
    if (!app_seed_name_valid(s->app)) {
        asc_fail(s, "BAD_APP", false, "app must be the name of a directory "
                 "under apps/: 1..64 of [a-z0-9_-]", s->app ? s->app : "");
        return false;
    }
    s->datadir = zcl_package_copy_datadir(s->input, s->reply, ASC_COMMAND);
    if (!s->datadir || !asc_source(s))
        return false;
    if (!vcs_package_accept_chain_id(s->chain_id, sizeof(s->chain_id))) {
        asc_fail(s, "NO_CHAIN", false, "no active chain is selected",
                 ASC_COMMAND);
        return false;
    }
    s->options.chain_id = s->chain_id;
    s->options.reward_address = "";
    return true;
}

/* Read-only: the owner's existing key, if any. A missing key sets
 * key_pending and stands a placeholder public key in for the plan, so the
 * plan half creates nothing under $HOME. */
static bool asc_owner_probe(struct asc *s)
{
    char hex[67];
    bool exists = false;
    if (!app_personalize_key_probe(s->reply, s->key_path, sizeof(s->key_path),
                                   hex, &exists))
        return false;
    s->key_pending = !exists;
    if (exists &&
        !zcl_hex_decode_lower(hex, s->options.publisher_pubkey,
                              sizeof(s->options.publisher_pubkey))) {
        asc_fail(s, "PUBLISHER_KEY_REFUSED", false, "the owner's publisher "
                 "key must be a private (0600) 32-byte key file", s->key_path);
        return false;
    }
    if (!exists) {
        memset(s->options.publisher_pubkey, 0,
               sizeof(s->options.publisher_pubkey));
        s->options.publisher_pubkey[0] = 0x02;
        s->options.publisher_pubkey[sizeof(s->options.publisher_pubkey) - 1u] =
            0x01;
    }
    return zcl_package_copy_next_sequence(s->datadir,
                                          s->options.publisher_pubkey,
                                          &s->options.publisher_sequence,
                                          s->reply);
}

/* Confirm half only: make the owner's key (an existing one is reused
 * unchanged), then the real public key and sequence replace the plan's
 * placeholder. */
static bool asc_owner_create(struct asc *s)
{
    return zcl_package_copy_owner_key(s->key_path, sizeof(s->key_path),
                                      s->options.publisher_pubkey,
                                      &s->key_created, s->reply,
                                      ASC_COMMAND) &&
           zcl_package_copy_next_sequence(s->datadir,
                                          s->options.publisher_pubkey,
                                          &s->options.publisher_sequence,
                                          s->reply);
}

/* ── the tree and its release ────────────────────────────────────────── */

static bool asc_stage(struct asc *s)
{
    struct app_seed_stage st;
    if (!platform_temp_directory_create("z23-app-seed-", s->stage,
                                        sizeof(s->stage))) {
        asc_fail(s, "STAGE_FAILED", false, "private staging directory could "
                 "not be created", ASC_COMMAND);
        return false;
    }
    if (app_seed_stage(s->source, s->app, s->stage, &st)) {
        s->mapped = st.mapped;
        s->closure = st.closure;
        s->unconfined = st.unconfined;
        return true;
    }
    asc_fail(s, st.code, false, "the app could not be staged as a "
             "self-contained package", st.why);
    return false;
}

static bool asc_prepare(struct asc *s)
{
    char detail[256] = "";
    s->options.dir = s->stage;
    vcs_package_prepared_init(&s->prepared);
    s->prepared_live = true;
    enum vcs_package_prepare_error e =
        vcs_package_prepare(&s->options, &s->prepared, detail, sizeof(detail));
    if (e == VCS_PACKAGE_PREPARE_OK) {
        memcpy(s->release_id, s->prepared.signing_digest, 32);
        return true;
    }
    asc_fail(s, "PACKAGE_INVALID", false, "the staged app does not prepare "
             "as a package", detail[0] ? detail
                                       : vcs_package_prepare_error_string(e));
    return false;
}

static bool asc_same_release(const struct asc *s,
                             const struct vcs_package_release *r)
{
    return memcmp(r->package_root, s->prepared.package_root, 32) == 0 &&
           memcmp(r->publisher_pubkey, s->options.publisher_pubkey,
                  VCS_PACKAGE_RELEASE_PUBKEY_BYTES) == 0;
}

/* This owner's persisted release of the same package root, if any. */
static bool asc_existing(struct asc *s)
{
    char zcode_dir[ASC_PATH];
    size_t count = 0, skipped = 0;
    struct vcs_package_release *all = zcl_calloc(
        VCS_PACKAGE_PUBLISH_MAX_RELEASES, sizeof(*all), "app.seed.releases");
    bool ok = all && snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode",
                              s->datadir) < (int)sizeof(zcode_dir) &&
              vcs_package_publish_load_releases(
                  zcode_dir, all, VCS_PACKAGE_PUBLISH_MAX_RELEASES, &count,
                  &skipped);
    for (size_t i = 0; ok && !s->existing && i < count; i++) {
        if (asc_same_release(s, &all[i]) &&
            vcs_package_release_id(&all[i], s->release_id) ==
                VCS_PACKAGE_RELEASE_OK) {
            s->existing = true;
            s->existing_sequence = all[i].publisher_sequence;
        }
    }
    free(all);
    if (!ok)
        asc_fail(s, "RELEASES_UNREADABLE", false, "persisted releases could "
                 "not be read", s->datadir);
    return ok;
}

static void asc_plan_id(struct asc *s)
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)ASC_PLAN_DOMAIN,
                   sizeof(ASC_PLAN_DOMAIN));
    sha3_256_write(&sha, (const uint8_t *)s->app, strlen(s->app) + 1u);
    sha3_256_write(&sha, s->prepared.package_root, 32);
    /* Without a key the release id is not known yet: it is left out. */
    if (!s->key_pending)
        sha3_256_write(&sha, s->release_id, 32);
    sha3_256_finalize(&sha, s->plan_id);
}

static bool asc_derive(struct asc *s)
{
    if (!asc_inputs(s) || !asc_stage(s) || !asc_owner_probe(s) ||
        !asc_prepare(s) || (!s->key_pending && !asc_existing(s)))
        return false;
    asc_plan_id(s);
    return true;
}

/* Confirm of a plan made before the owner had a key: the plan matched
 * without one, so make the key now and prepare the release under it. */
static bool asc_rederive(struct asc *s)
{
    vcs_package_prepared_free(&s->prepared);
    s->prepared_live = false;
    s->key_pending = false;
    return asc_owner_create(s) && asc_prepare(s) && asc_existing(s);
}

/* ── replies ─────────────────────────────────────────────────────────── */

static void asc_describe(struct asc *s, const char *stage)
{
    struct json_value *d = &s->reply->data;
    char fingerprint[VCS_PACKAGE_RELEASE_PUBKEY_BYTES * 2u + 1u];
    zcl_hex_encode(s->options.publisher_pubkey,
                   VCS_PACKAGE_RELEASE_PUBKEY_BYTES, fingerprint);
    (void)json_push_kv_str(d, "stage", stage);
    (void)json_push_kv_str(d, "app", s->app);
    (void)json_push_kv_str(d, "source", s->source);
    zcl_package_copy_push_root(d, "package_root", s->prepared.package_root);
    if (s->key_pending)
        (void)json_push_kv_str(d, "release_id", "");
    else
        zcl_package_copy_push_root(d, "release_id", s->release_id);
    (void)json_push_kv_int(d, "file_count",
                           (int64_t)s->prepared.manifest.count);
    (void)json_push_kv_int(d, "mapped_files", (int64_t)s->mapped);
    (void)json_push_kv_int(d, "closure_files", (int64_t)s->closure);
    (void)json_push_kv_str(d, "confinement",
                           s->unconfined ? "unconfined" : "landlock");
    (void)json_push_kv_bool(d, "existing", s->existing);
    (void)json_push_kv_int(d, "publisher_sequence",
                           (int64_t)(s->existing
                                         ? s->existing_sequence
                                         : s->options.publisher_sequence));
    (void)json_push_kv_str(d, "publisher", s->key_pending ? "" : fingerprint);
    if (s->key_pending)
        (void)json_push_kv_str(d, "key_note", "a new publisher key will be "
                               "created at the key_path, 0600, when you "
                               "confirm; the fingerprint is shown then");
    (void)json_push_kv_str(d, "key_path", s->key_path);
    (void)json_push_kv_bool(d, "key_created", s->key_created);
    zcl_package_copy_push_root(d, "plan_id", s->plan_id);
}

static void asc_next(struct asc *s)
{
    char next[160];
    char hex[65];
    zcl_hex_encode(s->release_id, 32, hex);
    (void)snprintf(next, sizeof(next), "zcode package adopt with root %s",
                   hex);
    (void)json_push_kv_str(&s->reply->data, "next", next);
}

/* ── confirm ─────────────────────────────────────────────────────────── */

static bool asc_signed_wire(struct asc *s, uint8_t **wire, size_t *wire_len)
{
    uint8_t pubkey[VCS_PACKAGE_RELEASE_PUBKEY_BYTES];
    struct plugin_dist_published why;
    struct vcs_package_release *r = &s->prepared.release;
    bool ok = plugin_dist_release_key_sign(s->key_path, s->release_id, pubkey,
                                           r->signature, &why) ==
                  PLUGIN_DIST_OK &&
              memcmp(pubkey, s->options.publisher_pubkey, sizeof(pubkey)) ==
                  0 &&
              vcs_package_release_verify(r) == VCS_PACKAGE_RELEASE_OK &&
              vcs_package_release_serialize(r, wire, wire_len) ==
                  VCS_PACKAGE_RELEASE_OK;
    if (!ok)
        asc_fail(s, "SEED_SIGNATURE_INVALID", false, "the owner's key did not "
                 "give a valid release signature", s->key_path);
    return ok;
}

/* The publication's own reply: its refusal becomes this leaf's, verbatim;
 * on success its result word is carried over. */
static void asc_published(struct asc *s, const struct zcl_command_reply *pub)
{
    if (pub->status != ZCL_COMMAND_STATUS_PASSED) {
        s->reply->status = pub->status;
        s->reply->exit_code = pub->exit_code;
        s->reply->error = pub->error;
        return;
    }
    const char *result = json_get_str(json_get(&pub->data, "result"));
    asc_describe(s, "commit");
    (void)json_push_kv_str(&s->reply->data, "result",
                           result ? result : "published");
    asc_next(s);
    s->reply->error.mutated = pub->error.mutated;
}

static void asc_publish(struct asc *s)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    struct zcl_command_reply *pub =
        zcl_calloc(1, sizeof(*pub), "app.seed.publication");
    if (!pub) {
        asc_fail(s, "ALLOCATION_FAILED", false, "publication reply "
                 "allocation failed", ASC_COMMAND);
        return;
    }
    if (!asc_signed_wire(s, &wire, &wire_len)) {
        free(pub);
        return;
    }
    const struct json_value *day = json_get(s->input, "day");
    const struct zcl_native_local_publication publication = {
        .datadir = s->datadir, .source_directory = s->stage,
        .release_wire = wire, .release_wire_len = wire_len,
        .manifest_wire = s->prepared.manifest_wire,
        .manifest_wire_len = s->prepared.manifest_wire_len,
        .recipe_wire = s->prepared.recipe_wire,
        .recipe_wire_len = s->prepared.recipe_wire_len,
        .has_day = day != NULL, .day = day ? json_get_int(day) : 0,
        /* AUTH_OWNER: the owner's own key, a deliberate local step. */
        .owner_local = true,
    };
    zcl_command_reply_init(pub, "zcl.zcode_package_publish.v1");
    zcl_native_zcode_local_publication_commit(&publication, pub);
    free(wire);
    asc_published(s, pub);
    zcl_command_reply_free(pub);
    free(pub);
}

static void asc_confirm(struct asc *s)
{
    if (!zcl_package_copy_plan_matches(s->input, s->plan_id, s->reply,
                                       ASC_COMMAND))
        return;
    if (s->key_pending && !asc_rederive(s))
        return;
    if (!s->existing) {
        asc_publish(s);
        return;
    }
    asc_describe(s, "commit");
    asc_next(s);
    s->reply->error.mutated = false;
}

void zcl_native_handle_app_seed(const struct zcl_command_request *request,
                                struct zcl_command_reply *reply)
{
    struct asc *s = request && reply
                        ? zcl_calloc(1, sizeof(*s), "app.seed.state")
                        : NULL;
    if (!s) {
        if (reply)
            zcl_package_copy_fail(reply, "ALLOCATION_FAILED", false,
                                  "app.seed state allocation failed",
                                  ASC_COMMAND);
        return;
    }
    s->input = request->input;
    s->reply = reply;
    if (asc_derive(s)) {
        if (zcl_package_copy_confirmed(request->input)) {
            asc_confirm(s);
        } else {
            asc_describe(s, "plan");
            (void)json_push_kv_str(&reply->data, "next", "repeat with this "
                                   "plan_id and confirm:true to publish");
        }
    }
    if (s->prepared_live)
        vcs_package_prepared_free(&s->prepared);
    if (s->stage[0]) {
        struct zcl_result rm = zcl_tree_remove(s->stage);
        if (!rm.ok)
            fprintf(stderr, "[app.seed] could not remove %s: %s\n", s->stage,
                    rm.message);
    }
    free(s);
}

/* The native coordinator passes only the two identities already consented. */
static bool asc_installed_shape(const struct json_value *input)
{
    if (!input || input->type != JSON_OBJ || input->num_children != 2) return false;
    unsigned seen = 0;
    for (size_t i = 0; i < input->num_children; ++i) {
        unsigned bit = !strcmp(input->keys[i], "app") ? 1u :
                       !strcmp(input->keys[i], "datadir") ? 2u : 0u;
        if (!bit || (seen & bit) || input->children[i].type != JSON_STR) return false;
        seen |= bit;
    }
    return seen == 3u;
}

static bool asc_installed_inputs(struct asc *s, const struct app_installed_source *source)
{
    if (!source || !asc_installed_shape(s->input)) {
        asc_fail(s, "BAD_INPUT", false, "Retained source and exactly app/datadir strings are required.", ASC_COMMAND);
        return false;
    }
    s->app = zcl_package_copy_str(s->input, "app");
    s->datadir = zcl_package_copy_str(s->input, "datadir");
    if (!app_seed_name_valid(s->app) || strcmp(s->app, source->app) ||
        !platform_path_is_absolute(s->datadir)) {
        asc_fail(s, "INSTALLED_BINDING_INVALID", false,
            "App must match retained source and datadir must be explicitly absolute.", ASC_COMMAND);
        return false;
    }
    if (!vcs_package_accept_chain_id(s->chain_id, sizeof(s->chain_id))) {
        asc_fail(s, "NO_CHAIN", false, "No active chain is selected.", ASC_COMMAND);
        return false;
    }
    s->options.chain_id = s->chain_id;
    s->options.reward_address = "";
    s->unconfined = true; /* No build sandbox ran; do not report landlock. */
    return true;
}

static bool asc_installed_matches(struct asc *s, const struct app_installed_source *source)
{
    if (!memcmp(s->prepared.package_root, source->package_root, 32) &&
        !memcmp(s->prepared.recipe_root, source->recipe_root, 32)) return true;
    asc_fail(s, "INSTALLED_CONTENT_CHANGED", s->key_created,
        "Prepared package or recipe differs from consented installed source.", ASC_COMMAND);
    return false;
}

/* Staging can take time. Recheck the native consent's identity immediately
 * before entering the existing owner lifecycle, without creating a key. */
static bool asc_installed_owner_before(struct asc *s,
    const struct app_seed_installed_owner *owner)
{
    if (!owner || !owner->key_path || !owner->publisher) {
        asc_fail(s, "BAD_INPUT", false, "The consented publishing identity is required.", ASC_COMMAND);
        return false;
    }
    char path[ASC_PATH], publisher[67]; bool exists = false;
    if (!app_personalize_key_probe(s->reply, path, sizeof(path), publisher, &exists)) return false;
    if (exists == owner->exists && !strcmp(path, owner->key_path) &&
        !strcmp(publisher, owner->publisher)) return true;
    asc_fail(s, "PUBLISHER_CHANGED", false,
        "The publishing identity changed during source reconstruction; review a fresh request.", ASC_COMMAND);
    return false;
}

/* A key appearing after the absent-key probe is not the key this invocation
 * was authorized to create. Existing keys must still be the displayed one. */
static bool asc_installed_owner_after(struct asc *s,
    const struct app_seed_installed_owner *owner)
{
    char publisher[67];
    zcl_hex_encode(s->options.publisher_pubkey, VCS_PACKAGE_RELEASE_PUBKEY_BYTES, publisher);
    bool same = !strcmp(s->key_path, owner->key_path) &&
        (owner->exists ? !strcmp(publisher, owner->publisher) : s->key_created);
    if (same) return true;
    asc_fail(s, "PUBLISHER_CHANGED", true,
        "The acquired publishing identity differs from consent; nothing was signed or published.", ASC_COMMAND);
    return false;
}

static bool asc_installed_derive(struct asc *s, const struct app_installed_source *source,
    char *scratch, size_t scratch_cap, bool *owner_attempted,
    const struct app_seed_installed_owner *owner)
{
    if (!asc_installed_inputs(s, source)) return false;
    char why[256];
    if (!app_installed_source_stage(source, scratch, scratch_cap,
                                    s->stage, sizeof(s->stage), why, sizeof(why))) {
        asc_fail(s, "INSTALLED_SOURCE_INVALID", false, why, ASC_COMMAND);
        return false;
    }
    memcpy(s->source, s->stage, strlen(s->stage) + 1);
    if (!asc_installed_owner_before(s, owner)) return false;
    *owner_attempted = true;
    if (!asc_owner_create(s) || !asc_installed_owner_after(s, owner) ||
        !asc_prepare(s) || !asc_installed_matches(s, source) ||
        !asc_existing(s)) return false;
    asc_plan_id(s);
    return true;
}

static void asc_installed_retire(struct asc *s, const char *scratch, bool owner_attempted)
{
    s->reply->error.mutated |= s->key_created ||
        (owner_attempted && s->reply->status != ZCL_COMMAND_STATUS_PASSED);
    if (s->prepared_live) vcs_package_prepared_free(&s->prepared);
    if (!scratch[0]) return;
    struct zcl_result rm = zcl_tree_remove(scratch);
    if (!rm.ok) {
        fprintf(stderr, "[app.seed installed] retained %s: %s\n", scratch, rm.message);
        asc_fail(s, "STAGE_CLEANUP_FAILED", true,
            "Private installed-source scratch could not be removed; retain and inspect it.", scratch);
    }
}

void app_seed_installed_commit(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, const struct app_installed_source *source,
    const struct app_seed_installed_owner *owner)
{
    if (!reply) return;
    struct asc *s = request ? zcl_calloc(1, sizeof(*s), "app.seed.installed.state") : NULL;
    if (!s) {
        zcl_package_copy_fail(reply, "ALLOCATION_FAILED", false,
            "Installed seed state could not be initialized.", ASC_COMMAND);
        return;
    }
    s->input = request->input;
    s->reply = reply;
    char scratch[PLATFORM_TEMP_PATH_MAX] = {0};
    bool owner_attempted = false;
    if (asc_installed_derive(s, source, scratch, sizeof(scratch), &owner_attempted, owner)) {
        if (s->existing) {
            asc_describe(s, "commit");
            asc_next(s);
        } else asc_publish(s);
    }
    asc_installed_retire(s, scratch, owner_attempted);
    free(s);
}
