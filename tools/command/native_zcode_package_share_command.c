/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: zcode.package.share — publish a personal copy's saved head as a
 * new release whose envelope parent is the forked release — plus the
 * persisted-release lookup and the lineage rows zcode.commons.lineage shows.
 *
 * Share never reads the live worktree for publication: the saved head tree
 * is materialized from the copy's ZVCS store into private scratch and the
 * existing vcs_package_prepare derives the manifest, recipe and unsigned
 * release there. The fork record is checked first: the recorded fork tree
 * must prepare to the parent release's own package root. The publisher
 * secret never enters share; the caller signs the returned digest offline and
 * the signed envelope goes through zcl_native_zcode_local_publication_commit,
 * the same lifecycle zcode.package.publish.commit uses.
 *
 * zcode.package.bundle.sign is the same flow for an owner with no offline signer:
 * an AUTH_OWNER leaf (MCP refuses it, so an agent never signs) that signs
 * with the owner's own release key file, the format plugin publish
 * --release-key reads, kept at ~/.z23/zcode_publisher.key and made 0600 on
 * first use. Signing happens inside plugin_dist_release_key_sign; the secret
 * never reaches this file. Either confirm can also write one .z23share file
 * (native_zcode_package_bundle.h) that a friend receives with no node. */

#include "command/native_command.h"
#include "command/native_zcode_package_bundle.h"
#include "command/native_zcode_package_copy.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/temp_directory.h"
#include "plugin/plugin_dist.h"
#include "plugin/plugin_pack.h"
#include "util/file_tree_ops.h"
#include "vcs/package_accept.h"
#include "vcs/package_prepare.h"
#include "vcs/package_publish.h"
#include "vcs/package_release.h"
#include "vcs/package_store.h"
#include "vcs/vcs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define ZPS_PATH_MAX 4400
#define ZPS_KEY_LEAF "zcode_publisher.key"

/* ── persisted releases ─────────────────────────────────────────────── */

struct zps_releases {
    struct vcs_package_release *items;
    size_t count;
};

static bool zps_releases_load(const char *datadir, struct zps_releases *out)
{
    char zcode_dir[ZPS_PATH_MAX];
    size_t skipped = 0;
    int n = snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode", datadir);
    out->count = 0;
    out->items = NULL;
    if (n <= 0 || (size_t)n >= sizeof(zcode_dir))
        return false;
    out->items = zcl_calloc(VCS_PACKAGE_PUBLISH_MAX_RELEASES,
                            sizeof(*out->items), "zcode.package.releases");
    if (!out->items)
        return false;
    if (vcs_package_publish_load_releases(zcode_dir, out->items,
                                          VCS_PACKAGE_PUBLISH_MAX_RELEASES,
                                          &out->count, &skipped))
        return true;
    free(out->items);
    out->items = NULL;
    return false;
}

static bool zps_release_id(const struct vcs_package_release *r,
                           uint8_t id[32])
{
    return vcs_package_release_id(r, id) == VCS_PACKAGE_RELEASE_OK;
}

enum zcl_package_copy_lookup zcl_package_copy_find_release(
    const char *datadir, const uint8_t root[32],
    struct vcs_package_release *release_out, uint8_t release_id_out[32])
{
    struct zps_releases all;
    size_t by_package = 0;
    uint8_t id[32];
    if (!zps_releases_load(datadir, &all))
        return ZCL_PACKAGE_COPY_IO;
    for (size_t i = 0; i < all.count; i++) {
        const struct vcs_package_release *r = &all.items[i];
        if (!zps_release_id(r, id))
            continue;
        if (memcmp(id, root, 32) == 0) {
            *release_out = *r;
            memcpy(release_id_out, id, 32);
            free(all.items);
            return ZCL_PACKAGE_COPY_FOUND;
        }
        if (memcmp(r->package_root, root, 32) == 0 && by_package++ == 0) {
            *release_out = *r;
            memcpy(release_id_out, id, 32);
        }
    }
    free(all.items);
    if (by_package == 1)
        return ZCL_PACKAGE_COPY_FOUND;
    return by_package ? ZCL_PACKAGE_COPY_AMBIGUOUS : ZCL_PACKAGE_COPY_UNKNOWN;
}

static void zps_lineage_row(struct json_value *rows,
                            const struct vcs_package_release *r,
                            const uint8_t id[32],
                            const struct zps_releases *all)
{
    struct json_value row;
    uint8_t other[32];
    json_init(&row);
    json_set_object(&row);
    zcl_package_copy_push_root(&row, "release_root", id);
    (void)json_push_kv_str(&row, "name", r->name);
    (void)json_push_kv_str(&row, "semver", r->semver);
    (void)json_push_kv_int(&row, "publisher_sequence",
                           (int64_t)r->publisher_sequence);
    (void)json_push_kv_bool(&row, "has_parent", r->has_parent);
    if (r->has_parent)
        zcl_package_copy_push_root(&row, "parent_release_root",
                                   r->parent_root);
    for (size_t i = 0; r->has_parent && i < all->count; i++) {
        if (zps_release_id(&all->items[i], other) &&
            memcmp(other, r->parent_root, 32) == 0) {
            zcl_package_copy_push_root(&row, "parent_package_root",
                                       all->items[i].package_root);
            break;
        }
    }
    (void)json_push_back(rows, &row);
    json_free(&row);
}

bool zcl_package_copy_lineage_releases(const char *datadir,
                                       const uint8_t package_root[32],
                                       struct json_value *data)
{
    struct zps_releases all;
    struct json_value rows;
    uint8_t id[32];
    if (!zps_releases_load(datadir, &all))
        return false;
    json_init(&rows);
    json_set_array(&rows);
    for (size_t i = 0; i < all.count; i++) {
        const struct vcs_package_release *r = &all.items[i];
        if (memcmp(r->package_root, package_root, 32) == 0 &&
            zps_release_id(r, id))
            zps_lineage_row(&rows, r, id, &all);
    }
    (void)json_push_kv_int(data, "release_count", (int64_t)json_size(&rows));
    (void)json_push_kv(data, "releases", &rows);
    json_free(&rows);
    free(all.items);
    return true;
}

/* ── zcode package share ────────────────────────────────────────────── */

/* The offline signer's inputs; only zcode.package.share reads them, so the
 * owner's sign leaf neither declares nor accepts them. */
struct zps_offline {
    const char *publisher_pubkey;
    const char *signature_hex;
};

struct zps_share {
    struct zps_offline offline;
    const struct json_value *input;
    struct zcl_command_reply *reply;
    const char *command;
    bool local_key;
    bool key_created;
    char key_path[ZPS_PATH_MAX];
    const char *output;
    char output_buf[ZPS_PATH_MAX];
    const char *dir;
    const char *datadir;
    struct zcl_package_copy copy;
    struct vcs_package_release parent;
    uint8_t parent_id[32];
    struct vcs_package_prepare_options options;
    char chain_id[VCS_PACKAGE_RELEASE_CHAIN_ID_MAX + 1u];
    char scratch[PLATFORM_TEMP_PATH_MAX];
    struct vcs_package_prepared prepared;
    bool prepared_live;
    uint8_t release_id[32];
};

static const char k_zps_command[] = "zcode.package.share";
static const char k_zps_sign[] = "zcode.package.bundle.sign";

static void zps_scratch_remove(char scratch[PLATFORM_TEMP_PATH_MAX])
{
    if (scratch[0])
        (void)zcl_tree_remove(scratch);
    scratch[0] = '\0';
}

/* Materialize one saved tree into fresh private scratch and prepare it. */
static bool zps_prepare_tree(struct zps_share *s, const uint8_t tree[32],
                             struct vcs_package_prepared *out)
{
    char detail[256] = {0};
    vcs_package_prepared_init(out);
    if (!platform_temp_directory_create("z23-share-", s->scratch,
                                        sizeof(s->scratch)) ||
        vcs_tree_materialize(s->dir, tree, s->scratch,
                             VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES, 0) != VCS_OK) {
        zcl_package_copy_fail(s->reply, "SHARE_MATERIALIZE_FAILED", false,
                              "a saved version could not be rebuilt from "
                              "the copy's store", s->dir);
        return false;
    }
    s->options.dir = s->scratch;
    if (vcs_package_prepare(&s->options, out, detail, sizeof(detail)) !=
        VCS_PACKAGE_PREPARE_OK) {
        zcl_package_copy_fail(s->reply, "SHARE_PREPARE_REFUSED", false,
                              "the saved version is not a valid package",
                              detail);
        return false;
    }
    return true;
}

static bool zps_pubkey_input(struct zps_share *s)
{
    const char *pubkey = s->offline.publisher_pubkey;
    if (pubkey && zcl_hex_decode(pubkey, s->options.publisher_pubkey,
                                 VCS_PACKAGE_RELEASE_PUBKEY_BYTES))
        return true;
    zcl_package_copy_fail(s->reply, "BAD_PUBLISHER_PUBKEY", false,
                          "publisher_pubkey must be 66 hex characters",
                          s->command);
    return false;
}

/* The share file goes to output, or for sign to <dir>.z23share beside the
 * copy; an existing path is refused before anything is signed. */
static bool zps_output(struct zps_share *s)
{
    struct stat st;
    size_t len = strlen(s->dir);
    while (len > 1 && s->dir[len - 1] == '/')
        len--;
    s->output = zcl_package_copy_str(s->input, "output");
    if (!s->output && s->local_key) {
        int n = snprintf(s->output_buf, sizeof(s->output_buf), "%.*s%s",
                         (int)len, s->dir, ZCL_PACKAGE_BUNDLE_SUFFIX);
        s->output = n > 0 && (size_t)n < sizeof(s->output_buf)
                        ? s->output_buf : NULL;
    }
    if (s->local_key && !s->output) {
        zcl_package_copy_fail(s->reply, "BAD_OUTPUT", false,
                              "name the share file with output", s->dir);
        return false;
    }
    if (s->output && stat(s->output, &st) == 0) {
        zcl_package_copy_fail(s->reply, "OUTPUT_EXISTS", false,
                              "the share file is written to a new path; "
                              "name another output", s->output);
        return false;
    }
    return true;
}

static bool zps_inputs(struct zps_share *s)
{
    s->dir = zcl_package_copy_str(s->input, "dir");
    s->datadir = zcl_package_copy_datadir(s->input, s->reply, s->command);
    if (!s->datadir || (!s->local_key && !zps_pubkey_input(s)))
        return false;
    if (!vcs_package_accept_chain_id(s->chain_id, sizeof(s->chain_id))) {
        zcl_package_copy_fail(s->reply, "NO_CHAIN", false,
                              "no active chain is selected", s->command);
        return false;
    }
    s->options.chain_id = s->chain_id;
    s->options.reward_address =
        zcl_package_copy_str(s->input, "reward_address");
    return zcl_package_copy_open(s->dir, &s->copy, s->reply, s->command) &&
           zps_output(s);
}

/* The owner's publisher key: the release key file plugin publish
 * --release-key reads, under ~/.z23 and made 0600 on first use the way
 * plugin dev makes its key. Only its public key is read here. */
bool zcl_package_copy_owner_key(
    char *key_path, size_t key_path_cap,
    uint8_t pubkey[VCS_PACKAGE_RELEASE_PUBKEY_BYTES], bool *created,
    struct zcl_command_reply *reply, const char *command)
{
    char store[ZPS_PATH_MAX], made_hex[PLUGIN_HEX_PUBLIC_KEY + 1];
    struct plugin_dist_published why;
    const char *home = getenv("HOME");
    int n = home && home[0] == '/'
                ? snprintf(store, sizeof(store), "%s/.z23", home) : -1;
    int m = n > 0 && (size_t)n < sizeof(store)
                ? snprintf(key_path, key_path_cap, "%s/%s", store,
                           ZPS_KEY_LEAF)
                : -1;
    if (m <= 0 || (size_t)m >= key_path_cap || !zcl_mkdir_p(store, 0700).ok) {
        zcl_package_copy_fail(reply, "PUBLISHER_KEY_UNAVAILABLE", false,
                              "HOME must be an absolute directory where "
                              "~/.z23 can hold the owner's key", command);
        return false;
    }
    enum plugin_status made = plugin_keygen(key_path, made_hex);
    *created = made == PLUGIN_OK;
    if ((made == PLUGIN_OK || made == PLUGIN_ERR_KEY_EXISTS) &&
        plugin_dist_release_key_sign(key_path, NULL, pubkey, NULL, &why) ==
            PLUGIN_DIST_OK)
        return true;
    zcl_package_copy_fail(reply, "PUBLISHER_KEY_REFUSED", false,
                          "the owner's publisher key must be a private "
                          "(0600) 32-byte key file", key_path);
    return false;
}

static bool zps_local_key(struct zps_share *s)
{
    return zcl_package_copy_owner_key(s->key_path, sizeof(s->key_path),
                                      s->options.publisher_pubkey,
                                      &s->key_created, s->reply, s->command);
}

/* Saved, changed, and the recorded parent is a persisted, valid release. */
static bool zps_admit(struct zps_share *s)
{
    size_t changes = 0;
    if (!zcl_package_copy_unsaved(&s->copy, &changes) || changes > 0) {
        zcl_package_copy_fail(s->reply, "SHARE_UNSAVED_CHANGES", false,
                              "save the copy's changes with zcode package "
                              "version save before sharing", s->dir);
        return false;
    }
    if (memcmp(s->copy.head_tree, s->copy.fork_tree, 32) == 0) {
        zcl_package_copy_fail(s->reply, "SHARE_NO_CHANGES", false,
                              "the saved version is the forked package "
                              "unchanged", s->dir);
        return false;
    }
    if (zcl_package_copy_find_release(s->datadir, s->copy.parent_release,
                                      &s->parent, s->parent_id) !=
            ZCL_PACKAGE_COPY_FOUND ||
        memcmp(s->parent_id, s->copy.parent_release, 32) != 0 ||
        vcs_package_release_verify(&s->parent) != VCS_PACKAGE_RELEASE_OK) {
        zcl_package_copy_fail(s->reply, "SHARE_PARENT_UNKNOWN", false,
                              "the forked release is not persisted here or "
                              "does not verify", s->datadir);
        return false;
    }
    return true;
}

/* The recorded fork tree must still be exactly the parent's package. */
static bool zps_fork_untampered(struct zps_share *s)
{
    struct vcs_package_prepared fork;
    s->options.publisher_sequence = 1;
    bool prepared = zps_prepare_tree(s, s->copy.fork_tree, &fork);
    bool same = prepared &&
                memcmp(fork.package_root, s->parent.package_root, 32) == 0;
    vcs_package_prepared_free(&fork);
    zps_scratch_remove(s->scratch);
    if (prepared && !same)
        zcl_package_copy_fail(s->reply, "COPY_TAMPERED", false,
                              "the copy's fork record does not match the "
                              "package of the release it names", s->dir);
    return same;
}

bool zcl_package_copy_next_sequence(
    const char *datadir, const uint8_t pubkey[VCS_PACKAGE_RELEASE_PUBKEY_BYTES],
    uint64_t *sequence, struct zcl_command_reply *reply)
{
    char zcode_dir[ZPS_PATH_MAX];
    size_t replayed = 0;
    uint64_t latest = 0;
    uint8_t latest_id[32];
    struct vcs_package_accept *accept = vcs_package_accept_new();
    (void)snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode", datadir);
    bool ok = accept && vcs_package_publish_replay(zcode_dir, accept,
                                                   &replayed);
    if (ok && !vcs_package_accept_lookup(accept, pubkey, &latest, latest_id))
        latest = 0;
    vcs_package_accept_free(accept);
    *sequence = latest + 1u;
    if (!ok)
        zcl_package_copy_fail(reply, "RELEASES_UNREADABLE", false,
                              "persisted releases could not be replayed",
                              datadir);
    return ok;
}

static bool zps_next_sequence(struct zps_share *s)
{
    return zcl_package_copy_next_sequence(s->datadir,
                                          s->options.publisher_pubkey,
                                          &s->options.publisher_sequence,
                                          s->reply);
}

/* Prepare the saved head and point its envelope at the forked release. */
static bool zps_prepare_head(struct zps_share *s)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    s->prepared_live = true;
    if (!zps_prepare_tree(s, s->copy.head_tree, &s->prepared))
        return false;
    struct vcs_package_release *r = &s->prepared.release;
    r->has_parent = true;
    memcpy(r->parent_root, s->parent_id, 32);
    bool ok = zps_release_id(r, s->release_id) &&
              vcs_package_release_serialize(r, &wire, &wire_len) ==
                  VCS_PACKAGE_RELEASE_OK &&
              wire_len > VCS_PACKAGE_RELEASE_SIGNATURE_BYTES;
    free(s->prepared.release_body);
    s->prepared.release_body = wire;
    s->prepared.release_body_len =
        ok ? wire_len - VCS_PACKAGE_RELEASE_SIGNATURE_BYTES : 0;
    memcpy(s->prepared.signing_digest, s->release_id, 32);
    if (!ok)
        zcl_package_copy_fail(s->reply, "SHARE_RELEASE_INVALID", false,
                              "the release envelope did not validate",
                              s->dir);
    else if (memcmp(s->prepared.package_root, s->parent.package_root, 32) == 0) {
        zcl_package_copy_fail(s->reply, "SHARE_NO_CHANGES", false,
                              "the saved version prepares to the parent's "
                              "package root", s->dir);
        ok = false;
    }
    return ok;
}

static void zps_describe(struct zps_share *s, const char *stage)
{
    struct json_value *data = &s->reply->data;
    (void)json_push_kv_str(data, "stage", stage);
    zcl_package_copy_push_root(data, "plan_id", s->release_id);
    zcl_package_copy_push_root(data, "parent_release_root", s->parent_id);
    zcl_package_copy_push_root(data, "parent_package_root",
                               s->parent.package_root);
    zcl_package_copy_push_root(data, "version", s->copy.head_version);
    (void)json_push_kv_str(data, "name", s->prepared.release.name);
    (void)json_push_kv_str(data, "semver", s->prepared.release.semver);
    (void)json_push_kv_int(data, "publisher_sequence",
                           (int64_t)s->prepared.release.publisher_sequence);
}

/* The one command the owner runs next: sign confirms its own plan; a share
 * plan (which an agent may run) names the owner's local signer. */
static void zps_next(struct zps_share *s)
{
    char next[ZPS_PATH_MAX * 2u + 512u], plan[65];
    zcl_hex_encode(s->release_id, 32, plan);
    if (s->local_key)
        (void)snprintf(next, sizeof(next),
                       "check the name, version and publisher fingerprint, "
                       "then: z23 zcode package bundle sign --input='{\"dir\":\"%s\","
                       "\"output\":\"%s\",\"plan_id\":\"%s\","
                       "\"confirm\":true}'", s->dir, s->output, plan);
    else
        (void)snprintf(next, sizeof(next),
                       "sign signing_digest offline, then repeat with "
                       "plan_id, signature_hex and confirm:true; or the "
                       "owner (never an agent) signs with their own local "
                       "key: z23 zcode package bundle sign --input='{\"dir\":\"%s\"}'",
                       s->dir);
    (void)json_push_kv_str(&s->reply->data, "next", next);
}

static void zps_push_fingerprint(struct zps_share *s)
{
    char fingerprint[VCS_PACKAGE_RELEASE_PUBKEY_BYTES * 2u + 1u];
    zcl_hex_encode(s->options.publisher_pubkey,
                   VCS_PACKAGE_RELEASE_PUBKEY_BYTES, fingerprint);
    (void)json_push_kv_str(&s->reply->data, "publisher_fingerprint",
                           fingerprint);
}

static void zps_plan_reply(struct zps_share *s)
{
    char *body = zcl_malloc(s->prepared.release_body_len * 2u + 1u,
                            "zcode.package.share.body");
    if (!body) {
        zcl_package_copy_fail(s->reply, "ALLOC", false,
                              "release body buffer", s->command);
        return;
    }
    zcl_hex_encode(s->prepared.release_body, s->prepared.release_body_len,
                   body);
    zps_describe(s, "plan");
    zcl_package_copy_push_root(&s->reply->data, "package_root",
                               s->prepared.package_root);
    zcl_package_copy_push_root(&s->reply->data, "signing_digest",
                               s->release_id);
    (void)json_push_kv_str(&s->reply->data, "release_body_hex", body);
    zps_push_fingerprint(s);
    if (s->local_key) {
        (void)json_push_kv_str(&s->reply->data, "key_path", s->key_path);
        (void)json_push_kv_bool(&s->reply->data, "key_created",
                                s->key_created);
    }
    if (s->output)
        (void)json_push_kv_str(&s->reply->data, "output", s->output);
    zps_next(s);
    free(body);
}

/* A local signature from the owner's key, or the offline signature_hex. */
static bool zps_signature(struct zps_share *s, uint8_t *signature)
{
    uint8_t pubkey[VCS_PACKAGE_RELEASE_PUBKEY_BYTES];
    struct plugin_dist_published why;
    if (!s->local_key) {
        const char *hex = s->offline.signature_hex;
        return hex && zcl_hex_decode(hex, signature,
                                     VCS_PACKAGE_RELEASE_SIGNATURE_BYTES);
    }
    return plugin_dist_release_key_sign(s->key_path, s->release_id, pubkey,
                                        signature, &why) == PLUGIN_DIST_OK &&
           memcmp(pubkey, s->options.publisher_pubkey, sizeof(pubkey)) == 0;
}

static bool zps_signed_wire(struct zps_share *s, uint8_t **wire,
                            size_t *wire_len)
{
    struct vcs_package_release *r = &s->prepared.release;
    if (!zps_signature(s, r->signature) ||
        vcs_package_release_verify(r) != VCS_PACKAGE_RELEASE_OK ||
        vcs_package_release_serialize(r, wire, wire_len) !=
            VCS_PACKAGE_RELEASE_OK) {
        zcl_package_copy_fail(s->reply, "SHARE_SIGNATURE_INVALID", false,
                              s->local_key
                                  ? "the owner's local key did not give a "
                                    "valid signature over signing_digest"
                                  : "signature_hex must be the publisher's "
                                    "compact low-S signature over "
                                    "signing_digest",
                              s->local_key ? s->key_path : s->command);
        return false;
    }
    return true;
}

/* One .z23share file and the one share line a friend needs. */
static void zps_share_file(struct zps_share *s, const uint8_t *wire,
                           size_t wire_len)
{
    const struct zcl_package_bundle_wires wires = {
        .release = wire, .release_len = wire_len,
        .manifest = s->prepared.manifest_wire,
        .manifest_len = s->prepared.manifest_wire_len,
        .recipe = s->prepared.recipe_wire,
        .recipe_len = s->prepared.recipe_wire_len,
    };
    char line[ZPS_PATH_MAX + 512u], root[65], fingerprint[67];
    if (!zcl_package_bundle_write(s->output, s->dir, s->copy.head_tree,
                                  &wires, s->reply))
        return;
    zcl_hex_encode(s->prepared.package_root, 32, root);
    zcl_hex_encode(s->options.publisher_pubkey,
                   VCS_PACKAGE_RELEASE_PUBKEY_BYTES, fingerprint);
    (void)snprintf(line, sizeof(line),
                   "share %s %s root=%s publisher=%s file=%s",
                   s->prepared.release.name, s->prepared.release.semver,
                   root, fingerprint, s->output);
    (void)json_push_kv_str(&s->reply->data, "share_file", s->output);
    (void)json_push_kv_str(&s->reply->data, "share_line", line);
}

static void zps_commit(struct zps_share *s)
{
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (!zcl_package_copy_plan_matches(s->input, s->release_id, s->reply,
                                       s->command) ||
        !zps_signed_wire(s, &wire, &wire_len))
        return;
    const struct json_value *day = json_get(s->input, "day");
    const struct zcl_native_local_publication publication = {
        .datadir = s->datadir, .source_directory = s->scratch,
        .release_wire = wire, .release_wire_len = wire_len,
        .manifest_wire = s->prepared.manifest_wire,
        .manifest_wire_len = s->prepared.manifest_wire_len,
        .recipe_wire = s->prepared.recipe_wire,
        .recipe_wire_len = s->prepared.recipe_wire_len,
        .has_day = day != NULL, .day = day ? json_get_int(day) : 0,
    };
    zcl_native_zcode_local_publication_commit(&publication, s->reply);
    if (s->reply->status == ZCL_COMMAND_STATUS_PASSED) {
        zcl_package_copy_push_root(&s->reply->data, "parent_release_root",
                                   s->parent_id);
        zcl_package_copy_push_root(&s->reply->data, "parent_package_root",
                                   s->parent.package_root);
        zcl_package_copy_push_root(&s->reply->data, "version",
                                   s->copy.head_version);
        zps_push_fingerprint(s);
        if (s->output)
            zps_share_file(s, wire, wire_len);
    }
    free(wire);
}

/* Everything both plan and confirm re-derive, in order. */
static bool zps_ready(struct zps_share *s)
{
    return zps_inputs(s) && zps_admit(s) &&
           (!s->local_key || zps_local_key(s)) && zps_fork_untampered(s) &&
           zps_next_sequence(s) && zps_prepare_head(s);
}

/* share (offline signature) and sign (the owner's local key, offline NULL)
 * differ only in where the publisher key and signature come from. */
static void zps_run(const struct zcl_command_request *request,
                    struct zcl_command_reply *reply, const char *command,
                    const struct zps_offline *offline)
{
    if (!request || !reply)
        return;
    struct zps_share *s = zcl_calloc(1, sizeof(*s), command);
    if (!s) {
        zcl_package_copy_fail(reply, "ALLOC", false, "share state", command);
        return;
    }
    s->input = request->input;
    s->reply = reply;
    s->command = command;
    s->local_key = offline == NULL;
    if (offline)
        s->offline = *offline;
    if (zps_ready(s)) {
        if (zcl_package_copy_confirmed(s->input))
            zps_commit(s);
        else
            zps_plan_reply(s);
    }
    if (s->prepared_live)
        vcs_package_prepared_free(&s->prepared);
    zps_scratch_remove(s->scratch);
    zcl_package_copy_close(&s->copy);
    free(s);
}

void zcl_native_handle_zcode_package_share(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const struct json_value *input = request ? request->input : NULL;
    const struct zps_offline offline = {
        .publisher_pubkey = zcl_package_copy_str(input, "publisher_pubkey"),
        .signature_hex = zcl_package_copy_str(input, "signature_hex"),
    };
    zps_run(request, reply, k_zps_command, &offline);
}

void zcl_native_handle_zcode_package_bundle_sign(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    zps_run(request, reply, k_zps_sign, NULL);
}
