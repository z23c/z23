/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: app.share and app.receive, the front door's share-by-file pair
 * (command/native_app_front_door.h). Both are AUTH_OWNER: they run owner
 * leaves as inner calls, which skip MCP policy.
 *
 * app.share: save if the copy has unsaved edits (zcode.package.version.save),
 * then zcode.package.bundle.sign, which writes NAME.z23share. The plan runs
 * only plan halves; it never runs the sign plan while the owner has no key
 * yet, because that plan makes the key. Its plan_id binds the copy's head,
 * the save or sign plan id and the output path.
 *
 * app.receive: zcode.package.bundle.verify, then the receive plan into the
 * first free <datadir>/copies/<name>-<n>. Confirm receives trusting exactly
 * the publisher and package root the verify read from the file (never a
 * value the caller typed), then builds (app.build) and opens
 * (app.run.copy) that build's image. */

#include "command/native_command.h"

#include "command/app_copy_build.h"
#include "command/native_app_compose.h"
#include "command/native_app_front_door.h"
#include "command/native_zcode_package_bundle.h"
#include "command/native_zcode_package_copy.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "util/path_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ZSH_SHARE "app.share"
#define ZSH_RECEIVE "app.receive"
#define ZSH_SHARE_DOMAIN "zcl.app_share.plan.v1"
#define ZSH_RECEIVE_DOMAIN "zcl.app_receive.plan.v1"
#define ZSH_SAVE_LEAF "zcode.package.version.save"
#define ZSH_SIGN_LEAF "zcode.package.bundle.sign"
#define ZSH_KEY_LEAF ".z23/zcode_publisher.key"

/* A fresh object input {k0: v0, k1: v1, ...}; NULL values are left out. */
static bool zsh_input(struct json_value *in, const char *const *kv, size_t n)
{
    json_init(in);
    json_set_object(in);
    for (size_t i = 0; i + 1u < n; i += 2)
        if (kv[i + 1] && !json_push_kv_str(in, kv[i], kv[i + 1]))
            return false;
    return true;
}

/* Run `path` on an input that was (built) or could not be built: `out` is
 * always initialized, and the input is always freed. */
static bool zsh_call(const char *path, struct json_value *in, bool built,
                     struct zcl_command_reply *out)
{
    bool ok = false;
    if (built) {
        ok = zcl_app_inner_call(path, in, out, NULL);
    } else {
        zcl_command_reply_init(out, "zcl.app_share.inner.v1");
        zcl_package_copy_fail(out, "ALLOC", false, "inner input", path);
    }
    json_free(in);
    return ok;
}

/* Copy a reply's day input (an integer) into an inner input. */
static bool zsh_day(const struct json_value *from, struct json_value *in)
{
    const struct json_value *day = json_get(from, "day");
    return !day || day->type != JSON_INT ||
           json_push_kv_int(in, "day", json_get_int(day));
}

static void zsh_short(struct json_value *d, const char *full)
{
    char brief[ZCL_APP_SHORT_FINGERPRINT_LEN];
    if (!full)
        return;
    (void)json_push_kv_str(d, "publisher_fingerprint", full);
    if (zcl_app_short_fingerprint(full, brief))
        (void)json_push_kv_str(d, "publisher", brief);
}

/* ── app.share ───────────────────────────────────────────────────────── */

struct zsh {
    const struct json_value *input;
    struct zcl_command_reply *reply;
    const char *datadir;
    const char *name;
    char dir[APP_COPY_BUILD_PATH];
    char output[APP_COPY_BUILD_PATH];
    char head[65];
    bool dirty;
    bool have_key;
    char inner_plan[65];
    uint8_t plan_id[32];
};

/* The copy, its head and whether it has unsaved edits; the copy is closed
 * again before any inner leaf opens it. */
static bool zsh_state(struct zsh *z)
{
    struct zcl_package_copy copy;
    size_t changes = 0;
    if (!app_copy_build_dir(z->datadir, z->name, z->dir, sizeof(z->dir),
                            z->reply) ||
        !zcl_package_copy_open(z->dir, &copy, z->reply, ZSH_SHARE))
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

static bool zsh_key_exists(void)
{
    const char *home = getenv("HOME");
    char path[APP_COPY_BUILD_PATH];
    struct stat st;
    return home && home[0] == '/' &&
           zcl_path_join(path, sizeof(path), home, ZSH_KEY_LEAF) &&
           stat(path, &st) == 0;
}

static bool zsh_leaf_input(struct zsh *z, bool sign, struct json_value *in)
{
    const char *kv[] = {"dir", z->dir, "datadir", z->datadir,
                        "output", sign ? z->output : NULL};
    return zsh_input(in, kv, 6) && (!sign || zsh_day(z->input, in));
}

/* The plan half of the first step (save, or sign when the key exists). */
static bool zsh_plan(struct zsh *z, struct zcl_command_reply *inner)
{
    struct json_value in;
    const char *leaf = z->dirty ? ZSH_SAVE_LEAF : ZSH_SIGN_LEAF;
    bool run = z->dirty || z->have_key;
    z->inner_plan[0] = '\0';
    if (!run)
        zcl_command_reply_init(inner, "zcl.app_share.inner.v1");
    if (run) {
        if (!zsh_call(leaf, &in, zsh_leaf_input(z, !z->dirty, &in), inner)) {
            zcl_app_inner_fail(z->reply, inner, false);
            zcl_command_reply_free(inner);
            return false;
        }
        (void)snprintf(z->inner_plan, sizeof(z->inner_plan), "%s",
                       zcl_app_inner_str(inner, "plan_id")
                           ? zcl_app_inner_str(inner, "plan_id") : "");
    }
    const char *parts[] = {z->dir, z->head, z->output, leaf, z->inner_plan,
                           z->have_key ? "key" : "no-key"};
    zcl_app_plan_id(ZSH_SHARE_DOMAIN, parts, 6, z->plan_id);
    return true;
}

static void zsh_plan_reply(struct zsh *z, const struct zcl_command_reply *in)
{
    struct json_value *d = &z->reply->data;
    char next[160];
    (void)json_push_kv_str(d, "stage", "plan");
    (void)json_push_kv_str(d, "copy", z->name);
    (void)json_push_kv_str(d, "output", z->output);
    (void)json_push_kv_bool(d, "saves_first", z->dirty);
    (void)json_push_kv_bool(d, "makes_key", !z->have_key);
    const char *v = zcl_app_inner_str(in, "name");
    if (v)
        (void)json_push_kv_str(d, "name", v);
    zsh_short(d, zcl_app_inner_str(in, "publisher_fingerprint"));
    zcl_package_copy_push_root(d, "plan_id", z->plan_id);
    (void)json_push_kv_bool(d, "executed", false);
    (void)snprintf(next, sizeof(next), "z23 app share %s --yes", z->name);
    (void)json_push_kv_str(d, "next", next);
}

static void zsh_commit_reply(struct zsh *z, const struct zcl_command_reply *s)
{
    struct json_value *d = &z->reply->data;
    char line[APP_COPY_BUILD_PATH + 192], brief[ZCL_APP_SHORT_FINGERPRINT_LEN];
    const char *full = zcl_app_inner_str(s, "publisher_fingerprint");
    const char *keys[] = {"name", "semver", "release_id", "package_root",
                          "version", "share_file"};
    (void)json_push_kv_str(d, "stage", "commit");
    (void)json_push_kv_str(d, "copy", z->name);
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
        if (zcl_app_inner_str(s, keys[i]))
            (void)json_push_kv_str(d, keys[i], zcl_app_inner_str(s, keys[i]));
    zsh_short(d, full);
    (void)json_push_kv_bool(d, "saved_first", z->dirty);
    if (!full || !zcl_app_short_fingerprint(full, brief))
        (void)snprintf(brief, sizeof(brief), "?");
    (void)snprintf(line, sizeof(line), "share %s %s publisher %s file %s",
                   zcl_app_inner_str(s, "name") ? zcl_app_inner_str(s, "name")
                                                : z->name,
                   zcl_app_inner_str(s, "semver")
                       ? zcl_app_inner_str(s, "semver") : "",
                   brief, z->output);
    (void)json_push_kv_str(d, "share_line", line);
    (void)json_push_kv_str(d, "next", "send the file; your friend runs: z23 "
                           "app open FILE.z23share");
    (void)json_push_kv_bool(d, "executed", false);
}

static void zsh_commit(struct zsh *z)
{
    struct json_value in;
    struct zcl_command_reply inner;
    bool mutated = false;
    if (!zcl_package_copy_plan_matches(z->input, z->plan_id, z->reply,
                                       ZSH_SHARE))
        return;
    if (z->dirty) {
        bool built = zsh_leaf_input(z, false, &in) &&
                     json_push_kv_str(&in, "plan_id", z->inner_plan) &&
                     json_push_kv_bool(&in, "confirm", true);
        if (!zsh_call(ZSH_SAVE_LEAF, &in, built, &inner)) {
            zcl_app_inner_fail(z->reply, &inner, false);
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
                                  ZSH_SHARE);
        return;
    }
    z->input = request->input;
    z->reply = reply;
    z->name = zcl_package_copy_str(request->input, "copy");
    z->datadir = zcl_package_copy_datadir(request->input, reply, ZSH_SHARE);
    z->have_key = zsh_key_exists();
    if (z->datadir && zsh_state(z) && zsh_output(z) && zsh_plan(z, &inner)) {
        if (zcl_package_copy_confirmed(request->input))
            zsh_commit(z);
        else
            zsh_plan_reply(z, &inner);
        zcl_command_reply_free(&inner);
    }
    free(z);
}

/* ── app.receive ─────────────────────────────────────────────────────── */

struct zrv {
    const struct json_value *input;
    struct zcl_command_reply *reply;
    const char *datadir;
    const char *file;
    struct zcl_command_reply verify;
    bool verify_live;
    char name[ZCL_PACKAGE_ADOPT_NAME_MAX + 1u];
    char dest[APP_COPY_BUILD_PATH];
    char receive_plan[65];
    uint8_t plan_id[32];
};

static bool zrv_receive_input(struct zrv *z, struct json_value *in)
{
    const char *kv[] = {"file", z->file, "destination", z->dest,
                        "datadir", z->datadir};
    return zsh_input(in, kv, 6) && zsh_day(z->input, in);
}


/* Verify, name the copy, and run the receive plan. */
static bool zrv_plan(struct zrv *z)
{
    struct json_value in;
    struct zcl_command_reply inner;
    const char *kv[] = {"file", z->file};
    z->verify_live = true;
    if (!zsh_call("zcode.package.bundle.verify", &in, zsh_input(&in, kv, 2),
                  &z->verify)) {
        zcl_app_inner_fail(z->reply, &z->verify, false);
        return false;
    }
    if (!zcl_package_copy_pick_name(z->datadir,
                                    zcl_app_inner_str(&z->verify, "name"),
                                    z->name, z->dest, sizeof(z->dest),
                                    z->reply))
        return false;
    bool ok = zsh_call("zcode.package.bundle.receive", &in,
                       zrv_receive_input(z, &in), &inner);
    const char *plan = ok ? zcl_app_inner_str(&inner, "plan_id") : NULL;
    if (plan)
        (void)snprintf(z->receive_plan, sizeof(z->receive_plan), "%s", plan);
    else
        zcl_app_inner_fail(z->reply, &inner, false);
    zcl_command_reply_free(&inner);
    const char *parts[] = {z->file, z->datadir, z->dest, z->receive_plan,
                           zcl_app_inner_str(&z->verify,
                                             "publisher_fingerprint"),
                           zcl_app_inner_str(&z->verify, "package_root")};
    zcl_app_plan_id(ZSH_RECEIVE_DOMAIN, parts, 6, z->plan_id);
    return plan != NULL;
}

static void zrv_describe(struct zrv *z, const char *stage)
{
    struct json_value *d = &z->reply->data;
    const char *keys[] = {"name", "semver", "release_id", "package_root",
                          "parent_release_root"};
    (void)json_push_kv_str(d, "stage", stage);
    (void)json_push_kv_str(d, "file", z->file);
    (void)json_push_kv_str(d, "copy", z->name);
    (void)json_push_kv_str(d, "destination", z->dest);
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
        if (zcl_app_inner_str(&z->verify, keys[i]))
            (void)json_push_kv_str(d, keys[i],
                                   zcl_app_inner_str(&z->verify, keys[i]));
    zsh_short(d, zcl_app_inner_str(&z->verify, "publisher_fingerprint"));
}

static bool zrv_copy_input(struct zrv *z, struct json_value *in)
{
    const char *kv[] = {"copy", z->name, "datadir", z->datadir};
    return zsh_input(in, kv, 4);
}

/* app.run.copy plan, then its confirm accepting exactly the planned image.
 * `out` is always initialized. */
static bool zrv_open(struct zrv *z, struct zcl_command_reply *out)
{
    struct json_value in;
    bool built = zrv_copy_input(z, &in);
    if (!built) {
        json_free(&in);
        zcl_command_reply_init(out, "zcl.app_receive.inner.v1");
        zcl_package_copy_fail(out, "ALLOC", false, "inner input", z->name);
        return false;
    }
    bool ok = zcl_app_inner_call("app.run.copy", &in, out, NULL);
    const char *image = ok ? zcl_app_inner_str(out, "image_sha3") : NULL;
    const char *plan = ok ? zcl_app_inner_str(out, "plan_id") : NULL;
    ok = image && plan && json_push_kv_str(&in, "image_sha3", image) &&
         json_push_kv_bool(&in, "accept_execution", true) &&
         json_push_kv_str(&in, "plan_id", plan) &&
         json_push_kv_bool(&in, "confirm", true);
    if (ok || out->status == ZCL_COMMAND_STATUS_PASSED) {
        zcl_command_reply_free(out);
        if (ok) {
            ok = zcl_app_inner_call("app.run.copy", &in, out, NULL);
        } else {
            zcl_command_reply_init(out, "zcl.app_receive.inner.v1");
            zcl_package_copy_fail(out, "OPEN_PLAN_INCOMPLETE", false,
                                  "the open plan named no image", z->name);
        }
    }
    json_free(&in);
    return ok;
}

/* app.build plan then confirm for the received copy. */
static bool zrv_build(struct zrv *z, struct zcl_command_reply *out)
{
    struct json_value in;
    bool ok = false;
    if (zrv_copy_input(z, &in)) {
        ok = zcl_app_inner_plan_confirm("app.build", &in, out);
    } else {
        zcl_command_reply_init(out, "zcl.app_receive.inner.v1");
        zcl_package_copy_fail(out, "ALLOC", false, "inner input", z->name);
    }
    json_free(&in);
    return ok;
}

/* Receive trusting exactly what the verify read from the file. */
static bool zrv_keep(struct zrv *z, struct zcl_command_reply *out)
{
    struct json_value in;
    const char *who = zcl_app_inner_str(&z->verify, "publisher_fingerprint");
    const char *root = zcl_app_inner_str(&z->verify, "package_root");
    bool built = who && root && zrv_receive_input(z, &in) &&
                 json_push_kv_str(&in, "trust_publisher", who) &&
                 json_push_kv_str(&in, "trust_root", root) &&
                 json_push_kv_str(&in, "plan_id", z->receive_plan) &&
                 json_push_kv_bool(&in, "confirm", true);
    if (!who || !root)
        json_init(&in);
    return zsh_call("zcode.package.bundle.receive", &in, built, out);
}

static void zrv_commit(struct zrv *z)
{
    struct zcl_command_reply inner;
    if (!zcl_package_copy_plan_matches(z->input, z->plan_id, z->reply,
                                       ZSH_RECEIVE))
        return;
    bool kept = zrv_keep(z, &inner);
    bool ok = kept;
    if (ok) {
        zcl_command_reply_free(&inner);
        ok = zrv_build(z, &inner);
    }
    if (ok) {
        zcl_command_reply_free(&inner);
        ok = zrv_open(z, &inner);
    }
    if (!ok) {
        zcl_app_inner_fail(z->reply, &inner, kept);
        zcl_command_reply_free(&inner);
        return;
    }
    zrv_describe(z, "commit");
    const struct json_value *pid = json_get(&inner.data, "pid");
    if (pid && pid->type == JSON_INT)
        (void)json_push_kv_int(&z->reply->data, "pid", json_get_int(pid));
    (void)json_push_kv_str(&z->reply->data, "image_sha3",
                           zcl_app_inner_str(&inner, "image_sha3"));
    (void)json_push_kv_bool(&z->reply->data, "executed", true);
    zcl_command_reply_free(&inner);
}

void zcl_native_handle_app_receive(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    struct zrv *z = request && reply
                        ? zcl_calloc(1, sizeof(*z), "app.receive.state")
                        : NULL;
    if (!z) {
        if (reply)
            zcl_package_copy_fail(reply, "ALLOC", false, "app.receive state",
                                  ZSH_RECEIVE);
        return;
    }
    z->input = request->input;
    z->reply = reply;
    z->file = zcl_package_copy_str(request->input, "file");
    z->datadir = zcl_package_copy_datadir(request->input, reply, ZSH_RECEIVE);
    if (z->datadir && !z->file)
        zcl_package_copy_fail(reply, "BAD_FILE", false, "file names the "
                              ".z23share file to open", "");
    else if (z->datadir && zrv_plan(z)) {
        if (zcl_package_copy_confirmed(request->input)) {
            zrv_commit(z);
        } else {
            char next[APP_COPY_BUILD_PATH + 32];
            zrv_describe(z, "plan");
            zcl_package_copy_push_root(&reply->data, "plan_id", z->plan_id);
            (void)json_push_kv_bool(&reply->data, "executed", false);
            (void)snprintf(next, sizeof(next), "z23 app open %s --yes",
                           z->file);
            (void)json_push_kv_str(&reply->data, "next", next);
        }
    }
    if (z->verify_live)
        zcl_command_reply_free(&z->verify);
    free(z);
}
