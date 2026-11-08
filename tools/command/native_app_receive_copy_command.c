/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: app.receive-copy, `z23 app open FILE.z23share` (see
 * command/native_app_front_door.h). AUTH_OWNER: it runs the owner leaf
 * zcode.package.bundle.receive as an inner call, which skips MCP policy.
 *
 * Plan: zcode.package.bundle.verify, then the receive plan into the first
 * free <datadir>/copies/<name>-<n>; nothing is written. Confirm receives
 * trusting exactly the publisher and package root the verify read from the
 * file (never a value the caller typed), then builds (app.build) and opens
 * (app.run.copy) that build's exact image. A file that does not verify
 * stops at the plan and keeps nothing. */

#include "command/native_command.h"

#include "command/app_copy_build.h"
#include "command/native_app_compose.h"
#include "command/native_zcode_package_copy.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "util/file_tree_ops.h"
#include "util/path_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ZRV_COMMAND "app.receive-copy"
#define ZRV_DOMAIN "zcl.app_receive.plan.v1"
#define ZRV_OBSERVATION_MAX 4096u


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
    size_t observation_bytes;
};

static bool zrv_observe(struct zrv *z, const char *key, const char *command,
    const struct zcl_command_reply *inner, const struct zcl_app_observation_field *fields, size_t count)
{
    struct json_value snapshot;
    bool ok = zcl_app_observation(&snapshot, command, inner, fields, count, ZRV_OBSERVATION_MAX);
    size_t n = ok ? json_write(&snapshot, NULL, 0) : 0;
    ok = ok && n <= ZRV_OBSERVATION_MAX - z->observation_bytes &&
        json_push_kv(&z->reply->data, key, &snapshot);
    if (ok) z->observation_bytes += n;
    json_free(&snapshot);
    if (!ok) zcl_package_copy_fail(z->reply, "OBSERVATION_UNAVAILABLE", true,
        "The operation changed local state but its bounded observation could not be retained; inspect the copy before retrying.", z->dest);
    return ok;
}

static const struct zcl_app_observation_field zrv_receive_fields[] = {
    {"stage", JSON_STR}, {"destination", JSON_STR}, {"version", JSON_STR},
    {"release_id", JSON_STR}, {"package_root", JSON_STR},
    {"publisher_fingerprint", JSON_STR}, {"executed", JSON_BOOL}
};
static const struct zcl_app_observation_field zrv_build_fields[] = {
    {"stage", JSON_STR}, {"copy", JSON_STR}, {"version", JSON_STR},
    {"package_root", JSON_STR}, {"env_root", JSON_STR}, {"dependency_root", JSON_STR},
    {"record_id", JSON_STR}, {"image_sha3", JSON_STR}, {"executed", JSON_BOOL}
};
static const struct zcl_app_observation_field zrv_open_fields[] = {
    {"stage", JSON_STR}, {"copy_dir", JSON_STR}, {"head_version", JSON_STR},
    {"package_root", JSON_STR}, {"image_sha3", JSON_STR}, {"pid", JSON_INT},
    {"start_token", JSON_STR}, {"mapped_proof", JSON_STR},
    {"settled_alive", JSON_BOOL}, {"executed", JSON_BOOL}
};

static bool zrv_receive_input(struct zrv *z, struct json_value *in)
{
    const char *kv[] = {"file", z->file, "destination", z->dest,
                        "datadir", z->datadir};
    return zcl_app_input(in, kv, 6) && zcl_app_input_day(z->input, in);
}


/* Verify, name the copy, and run the receive plan. */
static bool zrv_plan(struct zrv *z)
{
    struct json_value in;
    struct zcl_command_reply inner;
    const char *kv[] = {"file", z->file};
    z->verify_live = true;
    if (!zcl_app_inner_call_built("zcode.package.bundle.verify", &in,
                                  zcl_app_input(&in, kv, 2),
                  &z->verify)) {
        zcl_app_inner_fail(z->reply, &z->verify, false);
        return false;
    }
    if (!zcl_package_copy_pick_name(z->datadir,
                                    zcl_app_inner_str(&z->verify, "name"),
                                    z->name, z->dest, sizeof(z->dest),
                                    z->reply))
        return false;
    bool ok = zcl_app_inner_call_built("zcode.package.bundle.receive", &in,
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
    zcl_app_plan_id(ZRV_DOMAIN, parts, 6, z->plan_id);
    return plan != NULL;
}

static void zrv_describe(struct zrv *z, const char *stage)
{
    struct json_value *d = &z->reply->data;
    const char *keys[] = {"name", "semver", "release_id", "package_root",
                          "parent_release_root"};
    (void)json_push_kv_str(d, "stage", stage);
    (void)json_push_kv_str(d, "file", z->file);
    if (!json_get(d, "copy")) (void)json_push_kv_str(d, "copy", z->name);
    if (!json_get(d, "destination")) (void)json_push_kv_str(d, "destination", z->dest);
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
        if (zcl_app_inner_str(&z->verify, keys[i]))
            (void)json_push_kv_str(d, keys[i],
                                   zcl_app_inner_str(&z->verify, keys[i]));
    zcl_app_push_publisher(d, zcl_app_inner_str(&z->verify, "publisher_fingerprint"));
}

static bool zrv_copy_input(struct zrv *z, struct json_value *in)
{
    const char *kv[] = {"copy", z->name, "datadir", z->datadir};
    return zcl_app_input(in, kv, 4);
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
    return zcl_app_inner_call_built("zcode.package.bundle.receive", &in, built, out);
}

static bool zrv_describe_kept(struct zrv *z)
{
    return json_push_kv_str(&z->reply->data, "copy", z->name) &&
        json_push_kv_str(&z->reply->data, "destination", z->dest) &&
        json_push_kv_bool(&z->reply->data, "received", true);
}

static void zrv_open_binding(struct zrv *z, const struct zcl_command_reply *build,
                             const struct zcl_command_reply *opened)
{
    const char *version = zcl_app_inner_str(build, "version");
    const char *head = zcl_app_inner_str(opened, "head_version");
    const char *package = zcl_app_inner_str(build, "package_root");
    const char *opened_package = zcl_app_inner_str(opened, "package_root");
    (void)json_push_kv_bool(&z->reply->data, "build_matches_open",
        version && head && package && opened_package &&
        !strcmp(version, head) && !strcmp(package, opened_package));
}

static void zrv_open_result(struct zrv *z, struct zcl_command_reply *inner, bool ok)
{
    const struct json_value *pid = json_get(&inner->data, "pid");
    const struct json_value *executed = json_get(&inner->data, "executed");
    if (pid && pid->type == JSON_INT) (void)json_push_kv(&z->reply->data, "pid", pid);
    if (executed && executed->type == JSON_BOOL) (void)json_push_kv(&z->reply->data, "executed", executed);
    if (!ok) { zcl_app_inner_fail(z->reply, inner, true); return; }
    if (!executed || executed->type != JSON_BOOL || !json_get_bool(executed)) {
        zcl_package_copy_fail(z->reply, "OBSERVATION_UNAVAILABLE", true,
            "The open result did not retain a valid execution observation; inspect the copy before retrying.", z->dest);
        return;
    }
    if (!zrv_observe(z, "open_observation", "app.run.copy", inner, zrv_open_fields,
                     sizeof(zrv_open_fields) / sizeof(zrv_open_fields[0]))) return;
    zrv_describe(z, "commit");
    (void)json_push_kv_str(&z->reply->data, "image_sha3", zcl_app_inner_str(inner, "image_sha3"));
}
static void zrv_build_open(struct zrv *z)
{
    struct zcl_command_reply inner, build;
    if (!zrv_build(z, &build)) {
        zcl_app_inner_fail(z->reply, &build, true); zcl_command_reply_free(&build); return;
    }
    bool saved_build = json_push_kv(&z->reply->data, "build", &build.data);
    (void)json_push_kv_bool(&z->reply->data, "build_metadata_complete", saved_build);
    if (!zrv_observe(z, "build_observation", "app.build", &build, zrv_build_fields,
                     sizeof(zrv_build_fields) / sizeof(zrv_build_fields[0]))) {
        zcl_command_reply_free(&build); return;
    }
    (void)json_push_kv_bool(&z->reply->data, "open_attempted", true);
    bool ok = zrv_open(z, &inner);
    if (ok) zrv_open_binding(z, &build, &inner);
    zcl_command_reply_free(&build);
    zrv_open_result(z, &inner, ok); zcl_command_reply_free(&inner);
}
static void zrv_commit(struct zrv *z)
{
    struct zcl_command_reply inner;
    char copies[APP_COPY_BUILD_PATH];
    if (!zcl_package_copy_plan_matches(z->input, z->plan_id, z->reply,
                                       ZRV_COMMAND))
        return;
    /* The copy is made beneath an existing <datadir>/copies. */
    if (!zcl_path_join(copies, sizeof(copies), z->datadir, "copies") ||
        !zcl_mkdir_p(copies, 0700).ok) {
        zcl_package_copy_fail(z->reply, "COPIES_DIR_FAILED", false,
                              "<datadir>/copies could not be made",
                              z->datadir);
        return;
    }
    if (!zrv_keep(z, &inner)) {
        zcl_app_inner_fail(z->reply, &inner, false); zcl_command_reply_free(&inner); return;
    }
    bool described = zrv_describe_kept(z) && zrv_observe(z, "receive_observation",
            "zcode.package.bundle.receive", &inner, zrv_receive_fields,
            sizeof(zrv_receive_fields) / sizeof(zrv_receive_fields[0]));
    zcl_command_reply_free(&inner);
    if (!described) {
        if (z->reply->status == ZCL_COMMAND_STATUS_PASSED)
            zcl_package_copy_fail(z->reply, "ALLOC", true,
                                  "the copy was kept but its result could not be described", z->dest);
        return;
    }
    zrv_build_open(z);
}

void zcl_native_handle_app_receive_copy(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    struct zrv *z = request && reply
                        ? zcl_calloc(1, sizeof(*z), "app.receive.state")
                        : NULL;
    if (!z) {
        if (reply)
            zcl_package_copy_fail(reply, "ALLOC", false, "app.receive state",
                                  ZRV_COMMAND);
        return;
    }
    z->input = request->input;
    z->reply = reply;
    z->file = zcl_package_copy_str(request->input, "file");
    z->datadir = zcl_package_copy_datadir(request->input, reply, ZRV_COMMAND);
    if (z->datadir && !z->file)
        zcl_package_copy_fail(reply, "BAD_FILE", false, "file names the "
                              ".z23share file to open", "");
    else if (z->datadir && zrv_plan(z)) {
        if (zcl_package_copy_confirmed(request->input)) {
            zrv_commit(z);
        } else {
            char next[2 * APP_COPY_BUILD_PATH + 32];
            zrv_describe(z, "plan");
            zcl_package_copy_push_root(&reply->data, "plan_id", z->plan_id);
            (void)json_push_kv_bool(&reply->data, "executed", false);
            if (zcl_app_hint(next, sizeof(next),
                             zcl_package_copy_str(request->input, "datadir"),
                             "open %s --yes", z->file))
                (void)json_push_kv_str(&reply->data, "next", next);
        }
    }
    if (z->verify_live)
        zcl_command_reply_free(&z->verify);
    if (zcl_package_copy_confirmed(request->input) &&
        (reply->status == ZCL_COMMAND_STATUS_PASSED || reply->error.mutated))
        zcl_app_bound_committed_result(request, reply, ZRV_COMMAND);
    free(z);
}
