/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: app.share, `z23 app share skycombat-1` (see
 * command/native_app_front_door.h). AUTH_OWNER: it runs the owner leaf
 * zcode.package.bundle.sign as an inner call, which skips MCP policy.
 *
 * A copy keeps its release's name ("skycombat/skycombat"), whose publisher
 * half is bound to the origin's key; the Commons refuses another key's
 * release under it (publisher-namespace-conflict). So share publishes the
 * copy under the namespace the owner's own key owns: "k" and 16 hex of the
 * key's fingerprint digest (zcl_app_publisher_namespace), rewriting only
 * the name value of zcode-package.json.
 *
 * Plan: only plan halves. It reads the owner's key when it exists (never
 * makes one: the sign plan would), names the target name, runs the save
 * plan for unsaved edits or, for a clean copy already under the owner's
 * namespace, the sign plan. The plan_id binds the copy's head, those plan
 * ids, the target name (or "no-key") and the output path.
 *
 * Confirm: makes the key if missing, renames the package if needed, saves
 * once when there are edits or a rename, then signs and writes
 * NAME.z23share. A rename changes the package root, so the copy's earlier
 * build is stale until the next `z23 app build`. */

#include "command/native_command.h"

#include "command/app_copy_build.h"
#include "command/native_app_compose.h"
#include "command/native_app_front_door.h"
#include "command/native_zcode_package_bundle.h"
#include "command/native_zcode_package_copy.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "util/authority_receipt.h"
#include "plugin/plugin_dist.h"
#include "plugin/plugin_pack.h"
#include "util/file_io.h"
#include "util/file_tree_ops.h"
#include "util/path_util.h"
#include "vcs/package_release.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ZSH_COMMAND "app.share"
#define ZSH_DOMAIN "zcl.app_share.plan.v1"
#define ZSH_SAVE_LEAF "zcode.package.version.save"
#define ZSH_SIGN_LEAF "zcode.package.bundle.sign"
#define ZSH_META "zcode-package.json"
#define ZSH_META_MAX (64u << 10)
#define ZSH_NAME_MAX (VCS_PACKAGE_RELEASE_NAME_MAX + 1u)

struct zsh {
    const struct json_value *input;
    struct zcl_command_reply *reply;
    const char *datadir;
    const char *name;
    char dir[APP_COPY_BUILD_PATH];
    char output[APP_COPY_BUILD_PATH];
    char store[APP_COPY_BUILD_PATH];    /* ~/.z23 */
    char key_path[APP_COPY_BUILD_PATH]; /* ~/.z23/zcode_publisher.key */
    char head[65];
    bool dirty;
    bool have_key;
    uint8_t pubkey[VCS_PACKAGE_RELEASE_PUBKEY_BYTES];
    char old_name[ZSH_NAME_MAX];
    char new_name[ZSH_NAME_MAX]; /* "" until the key is known */
    bool rename;
    char inner_plan[65];
    uint8_t plan_id[32];
};

/* ── the copy, the key and the name ──────────────────────────────────── */

/* The copy, its head and whether it has unsaved edits; the copy is closed
 * again before any inner leaf opens it. */
static bool zsh_state(struct zsh *z)
{
    struct zcl_package_copy copy;
    size_t changes = 0;
    if (!app_copy_build_dir(z->datadir, z->name, z->dir, sizeof(z->dir),
                            z->reply) ||
        !zcl_package_copy_open(z->dir, &copy, z->reply, ZSH_COMMAND))
        return false;
    bool ok = zcl_package_copy_unsaved(&copy, &changes);
    zcl_hex_encode(copy.head_version, 32, z->head);
    zcl_package_copy_close(&copy);
    if (!ok)
        zcl_package_copy_fail(z->reply, "STATUS_FAILED", false,
                              "the copy's status scan failed", z->dir);
    z->dirty = changes > 0;
    return ok;
}

static bool zsh_output(struct zsh *z)
{
    char cwd[APP_COPY_BUILD_PATH], leaf[96];
    const char *given = zcl_package_copy_str(z->input, "output");
    const char *base = strrchr(z->dir, '/');
    struct stat st;
    (void)snprintf(leaf, sizeof(leaf), "%s%s", base ? base + 1 : z->dir,
                   ZCL_PACKAGE_BUNDLE_SUFFIX);
    bool ok = given ? snprintf(z->output, sizeof(z->output), "%s", given) > 0
                    : getcwd(cwd, sizeof(cwd)) &&
                          zcl_path_join(z->output, sizeof(z->output), cwd,
                                        leaf);
    if (!ok || z->output[0] != '/') {
        zcl_package_copy_fail(z->reply, "BAD_OUTPUT", false, "output must "
                              "be an absolute path", given ? given : leaf);
        return false;
    }
    if (stat(z->output, &st) == 0) {
        zcl_package_copy_fail(z->reply, "OUTPUT_EXISTS", false, "a share "
                              "file is never overwritten; move it or name "
                              "another output", z->output);
        return false;
    }
    return true;
}

/* The key bundle.sign uses; its public half when the file exists. Reading
 * never makes a key. */
static bool zsh_key_read(struct zsh *z)
{
    const char *home = getenv("HOME");
    struct plugin_dist_published why;
    struct stat st;
    if (!home || home[0] != '/' ||
        !zcl_path_join(z->store, sizeof(z->store), home, ".z23") ||
        !zcl_path_join(z->key_path, sizeof(z->key_path), z->store,
                       "zcode_publisher.key")) {
        zcl_package_copy_fail(z->reply, "PUBLISHER_KEY_UNAVAILABLE", false,
                              "HOME must be an absolute directory where "
                              "~/.z23 can hold the owner's key", ZSH_COMMAND);
        return false;
    }
    z->have_key = stat(z->key_path, &st) == 0 &&
                  plugin_dist_release_key_sign(z->key_path, NULL, z->pubkey,
                                               NULL, &why) == PLUGIN_DIST_OK;
    return true;
}

static bool zsh_meta_path(const struct zsh *z, char *out, size_t cap)
{
    return zcl_path_join(out, cap, z->dir, ZSH_META);
}

/* The package name now, and the one it publishes under. */
static bool zsh_names(struct zsh *z)
{
    char path[APP_COPY_BUILD_PATH], ns[ZCL_APP_NAMESPACE_LEN];
    char *text = NULL;
    size_t len = 0;
    struct json_value meta;
    json_init(&meta);
    bool ok = zsh_meta_path(z, path, sizeof(path)) &&
              zcl_read_whole_file_text(path, ZSH_META_MAX, &text, &len,
                                       ZSH_COMMAND) &&
              json_read(&meta, text, len);
    const struct json_value *v = ok ? json_get(&meta, "name") : NULL;
    const char *name = v && v->type == JSON_STR ? json_get_str(v) : NULL;
    const char *slash = name ? strchr(name, '/') : NULL;
    ok = slash && strlen(name) < sizeof(z->old_name);
    if (ok)
        (void)snprintf(z->old_name, sizeof(z->old_name), "%s", name);
    if (ok && z->have_key && zcl_app_publisher_namespace(z->pubkey, ns))
        (void)snprintf(z->new_name, sizeof(z->new_name), "%s%s", ns, slash);
    json_free(&meta);
    free(text);
    if (!ok)
        zcl_package_copy_fail(z->reply, "PACKAGE_INVALID", false, "the "
                              "copy's zcode-package.json has no package "
                              "name", z->dir);
    z->rename = !z->new_name[0] || strcmp(z->new_name, z->old_name) != 0;
    return ok;
}

/* Rewrite only the name value: the first "<old>" after the "name" key. */
static bool zsh_rename(struct zsh *z)
{
    char path[APP_COPY_BUILD_PATH], quoted[ZSH_NAME_MAX + 2u];
    char *text = NULL, *out = NULL;
    size_t len = 0;
    (void)snprintf(quoted, sizeof(quoted), "\"%s\"", z->old_name);
    bool ok = zsh_meta_path(z, path, sizeof(path)) &&
              zcl_read_whole_file_text(path, ZSH_META_MAX, &text, &len,
                                       ZSH_COMMAND);
    char *key = ok ? strstr(text, "\"name\"") : NULL;
    char *at = key ? strstr(key, quoted) : NULL;
    size_t old_len = strlen(quoted), new_len = strlen(z->new_name) + 2u;
    if (at)
        out = zcl_malloc(len - old_len + new_len + 1u, "app.share.meta");
    if (out) {
        size_t head = (size_t)(at - text);
        memcpy(out, text, head);
        (void)snprintf(out + head, new_len + 1u, "\"%s\"", z->new_name);
        memcpy(out + head + new_len, at + old_len, len - head - old_len + 1u);
        ok = authority_receipt_write_atomic(z->dir, ZSH_META,
                                            (const uint8_t *)out,
                                            len - old_len + new_len, NULL, 0);
    }
    ok = ok && out;
    free(out);
    free(text);
    if (!ok)
        zcl_package_copy_fail(z->reply, "RENAME_FAILED", false, "the package "
                              "name in zcode-package.json could not be "
                              "rewritten", path);
    return ok;
}

/* ── plan ────────────────────────────────────────────────────────────── */

static bool zsh_leaf_input(struct zsh *z, bool sign, struct json_value *in)
{
    const char *kv[] = {"dir", z->dir, "datadir", sign ? z->datadir : NULL,
                        "output", sign ? z->output : NULL};
    return zcl_app_input(in, kv, 6) && (!sign || zcl_app_input_day(z->input, in));
}

/* The plan half the copy allows now: the save plan for unsaved edits, or
 * the sign plan for a clean copy already under the owner's namespace. */
static bool zsh_plan(struct zsh *z, struct zcl_command_reply *inner)
{
    struct json_value in;
    bool save = z->dirty, sign = !z->dirty && z->have_key && !z->rename;
    const char *leaf = save ? ZSH_SAVE_LEAF : ZSH_SIGN_LEAF;
    z->inner_plan[0] = '\0';
    if (!save && !sign) {
        zcl_command_reply_init(inner, "zcl.app_share.inner.v1");
    } else if (!zcl_app_inner_call_built(leaf, &in,
                                         zsh_leaf_input(z, sign, &in),
                                         inner)) {
        zcl_app_inner_fail(z->reply, inner, false);
        zcl_command_reply_free(inner);
        return false;
    } else if (zcl_app_inner_str(inner, "plan_id")) {
        (void)snprintf(z->inner_plan, sizeof(z->inner_plan), "%s",
                       zcl_app_inner_str(inner, "plan_id"));
    }
    const char *parts[] = {z->dir, z->head, z->output, z->inner_plan,
                           z->new_name[0] ? z->new_name : "no-key"};
    zcl_app_plan_id(ZSH_DOMAIN, parts, 5, z->plan_id);
    return true;
}

static void zsh_plan_reply(struct zsh *z, const struct zcl_command_reply *in)
{
    struct json_value *d = &z->reply->data;
    char next[APP_COPY_BUILD_PATH + 160], as[ZSH_NAME_MAX + 32];
    const char *slash = strchr(z->old_name, '/');
    (void)snprintf(as, sizeof(as), "%s%s",
                   z->new_name[0] ? z->new_name : "<your new key>",
                   z->new_name[0] ? "" : slash);
    (void)json_push_kv_str(d, "stage", "plan");
    (void)json_push_kv_str(d, "copy", z->name);
    (void)json_push_kv_str(d, "output", z->output);
    (void)json_push_kv_str(d, "name", z->old_name);
    (void)json_push_kv_str(d, "publishes_as", as);
    (void)json_push_kv_bool(d, "saves_first", z->dirty || z->rename);
    (void)json_push_kv_bool(d, "makes_key", !z->have_key);
    zcl_app_push_publisher(d, zcl_app_inner_str(in, "publisher_fingerprint"));
    zcl_package_copy_push_root(d, "plan_id", z->plan_id);
    (void)json_push_kv_bool(d, "executed", false);
    if (zcl_app_hint(next, sizeof(next),
                     zcl_package_copy_str(z->input, "datadir"),
                     "share %s --yes", z->name))
        (void)json_push_kv_str(d, "next", next);
}

/* ── confirm ─────────────────────────────────────────────────────────── */

/* Make the key bundle.sign would make on first use, then read it. */
static bool zsh_key_make(struct zsh *z)
{
    char made[PLUGIN_HEX_PUBLIC_KEY + 1];
    if (z->have_key)
        return true;
    if (zcl_mkdir_p(z->store, 0700).ok)
        (void)plugin_keygen(z->key_path, made);
    if (!zsh_key_read(z))
        return false;
    if (!z->have_key)
        zcl_package_copy_fail(z->reply, "PUBLISHER_KEY_REFUSED", false,
                              "the owner's publisher key must be a private "
                              "(0600) 32-byte key file", z->key_path);
    return z->have_key;
}

/* The friend opens the file in their own datadir, so that command carries
 * none. A rename changes the package root, and app.run.copy refuses the old
 * image as STALE_BUILD instead of planning a build, so the owner is told to
 * rebuild before opening the copy again. */
static void zsh_commit_next(const struct zsh *z, char *next, size_t cap)
{
    char friend_cmd[96], build[APP_COPY_BUILD_PATH + 64];
    (void)zcl_app_hint(friend_cmd, sizeof(friend_cmd), NULL,
                       "open FILE.z23share");
    if (!z->rename ||
        !zcl_app_hint(build, sizeof(build),
                      zcl_package_copy_str(z->input, "datadir"), "build %s",
                      z->name))
        (void)snprintf(next, cap, "send the file; your friend runs: %s",
                       friend_cmd);
    else
        (void)snprintf(next, cap, "send the file; your friend runs: %s; "
                       "your copy now publishes as %s; run %s before opening "
                       "it again", friend_cmd, z->new_name, build);
}

static void zsh_commit_reply(struct zsh *z, const struct zcl_command_reply *s)
{
    struct json_value *d = &z->reply->data;
    char line[APP_COPY_BUILD_PATH + 192], brief[ZCL_APP_SHORT_FINGERPRINT_LEN];
    char next[APP_COPY_BUILD_PATH + 512];
    const char *full = zcl_app_inner_str(s, "publisher_fingerprint");
    const char *keys[] = {"name", "semver", "release_id", "package_root",
                          "version", "share_file"};
    (void)json_push_kv_str(d, "stage", "commit");
    (void)json_push_kv_str(d, "copy", z->name);
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
        if (zcl_app_inner_str(s, keys[i]))
            (void)json_push_kv_str(d, keys[i], zcl_app_inner_str(s, keys[i]));
    zcl_app_push_publisher(d, full);
    (void)json_push_kv_bool(d, "renamed", z->rename);
    if (!full || !zcl_app_short_fingerprint(full, brief))
        (void)snprintf(brief, sizeof(brief), "?");
    (void)snprintf(line, sizeof(line), "share %s %s publisher %s file %s",
                   z->new_name,
                   zcl_app_inner_str(s, "semver")
                       ? zcl_app_inner_str(s, "semver") : "",
                   brief, z->output);
    (void)json_push_kv_str(d, "share_line", line);
    zsh_commit_next(z, next, sizeof(next));
    (void)json_push_kv_str(d, "next", next);
    (void)json_push_kv_bool(d, "executed", false);
}

/* One save of the edits and the rename together. */
static bool zsh_save(struct zsh *z, struct zcl_command_reply *inner)
{
    struct json_value in;
    bool ok = false;
    if (zsh_leaf_input(z, false, &in)) {
        ok = zcl_app_inner_plan_confirm(ZSH_SAVE_LEAF, &in, inner);
    } else {
        zcl_command_reply_init(inner, "zcl.app_share.inner.v1");
        zcl_package_copy_fail(inner, "ALLOC", false, "inner input",
                              ZSH_SAVE_LEAF);
    }
    json_free(&in);
    return ok;
}

static bool zsh_prepare_name(struct zsh *z)
{
    bool made = !z->have_key;
    if (!zsh_key_make(z) || !zsh_names(z) || (z->rename && !zsh_rename(z))) {
        z->reply->error.mutated = made && z->have_key;
        return false;
    }
    return true;
}

static void zsh_commit(struct zsh *z)
{
    struct json_value in;
    struct zcl_command_reply inner;
    if (!zcl_package_copy_plan_matches(z->input, z->plan_id, z->reply,
                                       ZSH_COMMAND) ||
        !zsh_prepare_name(z))
        return;
    bool mutated = z->rename;
    if (z->dirty || z->rename) {
        if (!zsh_save(z, &inner)) {
            zcl_app_inner_fail(z->reply, &inner, mutated);
            zcl_command_reply_free(&inner);
            return;
        }
        zcl_command_reply_free(&inner);
        mutated = true;
    }
    bool ok = false;
    if (zsh_leaf_input(z, true, &in)) {
        ok = zcl_app_inner_plan_confirm(ZSH_SIGN_LEAF, &in, &inner);
    } else {
        zcl_command_reply_init(&inner, "zcl.app_share.inner.v1");
        zcl_package_copy_fail(&inner, "ALLOC", false, "inner input",
                              ZSH_SIGN_LEAF);
    }
    json_free(&in);
    if (ok)
        zsh_commit_reply(z, &inner);
    else
        zcl_app_inner_fail(z->reply, &inner, mutated);
    zcl_command_reply_free(&inner);
}

void zcl_native_handle_app_share(const struct zcl_command_request *request,
                                 struct zcl_command_reply *reply)
{
    struct zcl_command_reply inner;
    struct zsh *z = request && reply
                        ? zcl_calloc(1, sizeof(*z), "app.share.state")
                        : NULL;
    if (!z) {
        if (reply)
            zcl_package_copy_fail(reply, "ALLOC", false, "app.share state",
                                  ZSH_COMMAND);
        return;
    }
    z->input = request->input;
    z->reply = reply;
    z->name = zcl_package_copy_str(request->input, "copy");
    z->datadir = zcl_package_copy_datadir(request->input, reply, ZSH_COMMAND);
    if (z->datadir && zsh_state(z) && zsh_output(z) && zsh_key_read(z) &&
        zsh_names(z) && zsh_plan(z, &inner)) {
        if (zcl_package_copy_confirmed(request->input))
            zsh_commit(z);
        else
            zsh_plan_reply(z, &inner);
        zcl_command_reply_free(&inner);
    }
    free(z);
}
