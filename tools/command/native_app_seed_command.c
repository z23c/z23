/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: app.seed — publish an in-repo app as a self-contained package
 * release under the owner's own key, so a copy of it (and a friend's
 * received copy) holds everything its build reads.
 *
 * The tree is composed by command/app_seed.h in private scratch: apps/<app>,
 * the checkout files its zcode-seed.def maps, and app.mk as the Makefile
 * app.build runs. vcs_package_prepare derives the manifest, recipe and
 * unsigned release there, exactly as a publish does, with the owner's
 * publisher key (~/.z23/zcode_publisher.key, made 0600 on first use) at its
 * next sequence. No hex crosses any boundary: the wires go in memory to
 * zcl_native_zcode_local_publication_commit, the lifecycle
 * zcode.package.publish.commit uses.
 *
 * Plan (writes nothing but the owner key on first use) returns the package
 * root, the file count, the release id and a plan_id. When this owner
 * already holds a release of the same package root in this datadir, that
 * release is the answer: confirm writes nothing and says existing:true, so
 * re-seeding the same checkout returns the same release and package root.
 * Otherwise confirm signs the release id inside the key module and
 * publishes. AUTH_OWNER: the owner's key signs, so MCP refuses this leaf. */

#include "command/native_command.h"

#include "command/app_seed.h"
#include "command/native_devagent.h"
#include "command/native_zcode_package_copy.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/directory_compat.h"
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
    char chain_id[VCS_PACKAGE_RELEASE_CHAIN_ID_MAX + 1u];
    struct vcs_package_prepare_options options;
    struct vcs_package_prepared prepared;
    bool prepared_live;
    size_t mapped;
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

/* The owner's key is made only once the app has staged, so an unknown or
 * unstageable app leaves $HOME untouched. */
static bool asc_owner(struct asc *s)
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
    sha3_256_write(&sha, s->release_id, 32);
    sha3_256_finalize(&sha, s->plan_id);
}

static bool asc_derive(struct asc *s)
{
    if (!asc_inputs(s) || !asc_stage(s) || !asc_owner(s) || !asc_prepare(s) ||
        !asc_existing(s))
        return false;
    asc_plan_id(s);
    return true;
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
    zcl_package_copy_push_root(d, "release_id", s->release_id);
    (void)json_push_kv_int(d, "file_count",
                           (int64_t)s->prepared.manifest.count);
    (void)json_push_kv_int(d, "mapped_files", (int64_t)s->mapped);
    (void)json_push_kv_bool(d, "existing", s->existing);
    (void)json_push_kv_int(d, "publisher_sequence",
                           (int64_t)(s->existing
                                         ? s->existing_sequence
                                         : s->options.publisher_sequence));
    (void)json_push_kv_str(d, "publisher", fingerprint);
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
