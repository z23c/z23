/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: app.receive-copy, `z23 app open FILE.z23share` (see
 * command/native_app_front_door.h). AUTH_OWNER: it runs the owner leaf
 * zcode.package.bundle.receive as an inner call, which skips MCP policy.
 *
 * Plan: zcode.package.bundle.verify, then the receive plan into the first
 * free <datadir>/copies/<name>-<n>; nothing is written. Confirm receives
 * trusting exactly the publisher and package root the verify read from the
 * file (never a value the caller typed), then builds (app.build) and opens
 * (app.run.copy) that build's exact image. Tasks packages instead use their
 * native zcode.use recipe and file a task preview offer without executing it.
 * A file that does not verify stops at the plan and keeps nothing. */

#include "command/native_command.h"

#include "command/app_copy_build.h"
#include "command/native_app_compose.h"
#include "command/native_app_receive_copy.h"
#include "command/native_zcode_package_copy.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "services/package_lifecycle.h"
#include "services/package_resident.h"
#include "vcs/package_publish.h"
#include "vcs/package_release.h"
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
    {"record_id", JSON_STR}, {"image_sha3", JSON_STR}, {"executed", JSON_BOOL},
    {"cache_hit", JSON_BOOL}, {"make_ran", JSON_BOOL}, {"confinement", JSON_STR}
};
static const struct zcl_app_observation_field zrv_open_fields[] = {
    {"stage", JSON_STR}, {"copy_dir", JSON_STR}, {"head_version", JSON_STR},
    {"package_root", JSON_STR}, {"image_sha3", JSON_STR}, {"pid", JSON_INT},
    {"start_token", JSON_STR}, {"mapped_proof", JSON_STR},
    {"settled_alive", JSON_BOOL}, {"executed", JSON_BOOL}
};
static const struct zcl_app_observation_field zrv_use_fields[] = {
    {"active_root", JSON_STR}, {"build_receipt_id", JSON_STR},
    {"installed", JSON_BOOL}, {"receipt_reused", JSON_BOOL}
};
static const struct zcl_app_observation_field zrv_offer_fields[] = {
    {"offer_revision", JSON_INT}, {"preview_root", JSON_STR},
    {"preview_receipt", JSON_STR}, {"preview_program", JSON_STR},
    {"has_kept_program", JSON_BOOL}, {"dismissed", JSON_BOOL}
};

static bool zrv_receive_input(struct zrv *z, struct json_value *in)
{
    const char *kv[] = {"file", z->file, "destination", z->dest,
                        "datadir", z->datadir};
    return zcl_app_input(in, kv, 6) && zcl_app_input_day(z->input, in);
}


static bool zrv_same_identity(const struct zcl_command_reply *verified,
                              const struct zcl_command_reply *planned)
{
    const char *keys[] = {"publisher_fingerprint", "release_id", "package_root"};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        const char *a = zcl_app_inner_str(verified, keys[i]);
        const char *b = zcl_app_inner_str(planned, keys[i]);
        if (!a || !b || !*a || !*b || strcmp(a, b)) return false;
    }
    return true;
}

static bool zrv_accept_plan(struct zrv *z, const struct zcl_command_reply *inner)
{
    const char *plan = zcl_app_inner_str(inner, "plan_id");
    if (!plan) {
        zcl_app_inner_fail(z->reply, inner, false);
        return false;
    }
    if (!zrv_same_identity(&z->verify, inner)) {
        zcl_package_copy_fail(z->reply, "RELEASE_IDENTITY_MISMATCH", false,
                              "File identity changed; review the signed file again before confirming.", ZRV_COMMAND);
        return false;
    }
    (void)snprintf(z->receive_plan, sizeof(z->receive_plan), "%s", plan);
    return true;
}
#if defined(ZCL_TESTING)
bool zcl_test_receive_plan_accept(const struct zcl_command_reply *verified,
                                  const struct zcl_command_reply *planned,
                                  struct zcl_command_reply *result)
{
    struct zrv z = {.reply = result, .verify = *verified};
    return zrv_accept_plan(&z, planned);
}
#endif

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
    bool accepted = ok ? zrv_accept_plan(z, &inner) : false;
    if (!ok) zcl_app_inner_fail(z->reply, &inner, false);
    zcl_command_reply_free(&inner);
    if (!accepted) return false;
    const char *parts[] = {z->file, z->datadir, z->dest, z->receive_plan,
                           zcl_app_inner_str(&z->verify,
                                             "publisher_fingerprint"),
                           zcl_app_inner_str(&z->verify, "package_root")};
    zcl_app_plan_id(ZRV_DOMAIN, parts, 6, z->plan_id);
    return accepted;
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

/* Offer a plan only; the caller must inspect the kept copy and resolve the error. */
static void zrv_build_recovery(struct zrv *z)
{
    struct json_value in;
    bool ok = zrv_copy_input(z, &in);
    char wire[sizeof(z->reply->next[0].input_json)];
    size_t n = ok ? json_write(&in, wire, sizeof(wire)) : 0;
    if (n && n < sizeof(wire) &&
        zcl_command_reply_add_next(z->reply, "app.build", wire,
            "Inspect the received copy and resolve the reported prerequisite, then plan a build of its saved version."))
        (void)snprintf(z->reply->error.next_action, sizeof(z->reply->error.next_action),
            "Resolve the reported build error, then use app.build to plan a build of the retained copy. Do not receive it again.");
    json_free(&in);
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

static bool zrv_open_offer(struct zrv *z, const struct zcl_command_reply *inner)
{
    static const char *const keys[] = {
        "next", "preview_root", "preview_receipt", "preview_program",
        "artifact_sha3"
    };
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        const struct json_value *value = json_get(&inner->data, keys[i]);
        if (!value) continue;
        if (value->type != JSON_STR ||
            !json_push_kv(&z->reply->data, keys[i], value)) {
            zcl_package_copy_fail(z->reply, "OBSERVATION_UNAVAILABLE", true,
                "The open succeeded but its preview action could not be retained; inspect the copy before retrying.", z->dest);
            return false;
        }
    }
    return true;
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
    if (!zrv_open_offer(z, inner)) return;
    if (!zrv_observe(z, "open_observation", "app.run.copy", inner, zrv_open_fields,
                     sizeof(zrv_open_fields) / sizeof(zrv_open_fields[0]))) return;
    zrv_describe(z, "commit");
    (void)json_push_kv_str(&z->reply->data, "image_sha3", zcl_app_inner_str(inner, "image_sha3"));
}
static bool zrv_tasks_package(struct zrv *z)
{
    char base[ZCL_PACKAGE_COPY_BASE_MAX + 1u];
    const char *name = zcl_app_inner_str(&z->verify, "name");
    return name && (zcl_package_copy_name_base(name, base),
                    strcmp(base, "ztasks") == 0);
}

static const struct vcs_package_release *zrv_best_release(
    const struct vcs_package_release *all, size_t count, const uint8_t package[32])
{
    const struct vcs_package_release *selected = NULL;
    for (size_t i = 0; i < count; ++i) {
        const struct vcs_package_release *candidate = &all[i];
        if (memcmp(candidate->package_root, package, 32) == 0 &&
            (!selected || candidate->publisher_sequence > selected->publisher_sequence))
            selected = candidate;
    }
    return selected;
}

static bool zrv_selected_release(struct zrv *z)
{
    const char *root = zcl_app_inner_str(&z->verify, "package_root");
    const char *expected = zcl_app_inner_str(&z->verify, "release_id");
    uint8_t package[32], expected_id[32], selected_id[32];
    char dir[APP_COPY_BUILD_PATH];
    int n = snprintf(dir, sizeof(dir), "%s/zcode", z->datadir);
    size_t count = 0, skipped = 0;
    struct vcs_package_release *all = zcl_calloc(VCS_PACKAGE_PUBLISH_MAX_RELEASES,
        sizeof(*all), "app.receive.releases");
    bool ok = root && expected && zcl_hex_decode_lower(root, package, 32) &&
        zcl_hex_decode_lower(expected, expected_id, 32) && all && n > 0 &&
        (size_t)n < sizeof(dir) && vcs_package_publish_load_releases(dir, all,
            VCS_PACKAGE_PUBLISH_MAX_RELEASES, &count, &skipped);
    const struct vcs_package_release *selected = ok ?
        zrv_best_release(all, count, package) : NULL;
    ok = ok && selected &&
        vcs_package_release_id(selected, selected_id) == VCS_PACKAGE_RELEASE_OK &&
        memcmp(selected_id, expected_id, 32) == 0;
    free(all);
    if (ok) return true;
    zcl_package_copy_fail(z->reply, "RELEASE_IDENTITY_MISMATCH", true,
        "A different signed release would be selected for this package root; inspect competing releases before building.",
        expected ? expected : z->dest);
    return false;
}

static bool zrv_use_plan(struct zrv *z, struct json_value *in, char use_plan[65])
{
    const char *root = zcl_app_inner_str(&z->verify, "package_root");
    const char *kv[] = {"name_or_root", root, "datadir", z->datadir};
    if (!root) return false;
    if (!zcl_app_input(in, kv, 4)) {
        zcl_package_copy_fail(z->reply, "ALLOC", true, "Tasks install input", z->dest);
        return false;
    }
    struct zcl_command_reply plan;
    if (!zcl_app_inner_call("zcode.use", in, &plan, NULL)) {
        zcl_app_inner_fail(z->reply, &plan, true);
        zcl_command_reply_free(&plan);
        return false;
    }
    const char *plan_id = zcl_app_inner_str(&plan, "plan_id");
    if (plan_id && strlen(plan_id) == 64)
        (void)snprintf(use_plan, 65, "%s", plan_id);
    zcl_command_reply_free(&plan);
    if (use_plan[0]) return true;
    zcl_package_copy_fail(z->reply, "PLAN_ID_MISSING", true,
                          "Tasks install returned no usable plan ID", z->dest);
    return false;
}

static bool zrv_receipt_identity(struct zrv *z, const char active_root[65],
    const char receipt_id[65])
{
    const char *package = zcl_app_inner_str(&z->verify, "package_root");
    const char *recipe = zcl_app_inner_str(&z->verify, "recipe_root");
    uint8_t expected_package[32], expected_recipe[32], active[32], id[32];
    struct vcs_package_build_receipt receipt;
    bool ok = package && recipe && zcl_hex_decode_lower(package, expected_package, 32) &&
        zcl_hex_decode_lower(recipe, expected_recipe, 32) &&
        zcl_hex_decode_lower(active_root, active, 32) &&
        zcl_hex_decode_lower(receipt_id, id, 32) &&
        package_lifecycle_receipt_read(z->datadir, id, &receipt).ok &&
        memcmp(active, expected_package, 32) == 0 &&
        memcmp(receipt.package_root, expected_package, 32) == 0 &&
        memcmp(receipt.recipe_root, expected_recipe, 32) == 0;
    if (ok) return true;
    zcl_package_copy_fail(z->reply, "RELEASE_IDENTITY_MISMATCH", true,
        "The installed receipt does not match the signed package and recipe; the preview was not offered.",
        zcl_app_inner_str(&z->verify, "release_id"));
    return false;
}

static bool zrv_use_commit(struct zrv *z, struct json_value *in,
    char active_root[65], char receipt_id[65])
{
    struct zcl_command_reply use;
    if (!zcl_app_inner_call("zcode.use", in, &use, NULL)) {
        zcl_app_inner_fail(z->reply, &use, true);
        if (strcmp(use.error.code, "BUILD_FAILED") == 0)
            zrv_build_recovery(z);
        zcl_command_reply_free(&use);
        return false;
    }
    const char *active = zcl_app_inner_str(&use, "active_root");
    const struct json_value *steps = json_get(&use.data, "steps");
    size_t count = json_size(steps);
    const struct json_value *last = count ? json_at(steps, count - 1u) : NULL;
    const char *receipt = last ? json_get_str(json_get(last, "build_receipt_id")) : NULL;
    const struct json_value *reused = json_get(last, "receipt_reused");
    if (active) (void)snprintf(active_root, 65, "%s", active);
    if (receipt) (void)snprintf(receipt_id, 65, "%s", receipt);
    struct zcl_command_reply normalized;
    zcl_command_reply_init(&normalized, "zcl.zcode_use.v1");
    bool ok = active_root[0] && receipt_id[0] &&
        zrv_receipt_identity(z, active_root, receipt_id) && reused &&
        json_copy_checked(&normalized.data, &use.data) &&
        json_push_kv_str(&normalized.data, "build_receipt_id", receipt_id) &&
        json_push_kv(&normalized.data, "receipt_reused", reused) &&
        zrv_observe(z, "build_observation", "zcode.use", &normalized,
            zrv_use_fields, sizeof(zrv_use_fields) / sizeof(zrv_use_fields[0]));
    zcl_command_reply_free(&normalized);
    zcl_command_reply_free(&use);
    return ok;
}

static int64_t zrv_offer_revision(struct zrv *z)
{
    struct json_value in;
    const char *status_kv[] = {"action", "offer-status", "datadir", z->datadir};
    if (!zcl_app_input(&in, status_kv, 4)) {
        zcl_package_copy_fail(z->reply, "ALLOC", true, "Tasks offer-state input", z->dest);
        json_free(&in);
        return -1;
    }
    struct zcl_command_reply status;
    if (!zcl_app_inner_call("app.tasks", &in, &status, NULL)) {
        zcl_app_inner_fail(z->reply, &status, true);
        zcl_command_reply_free(&status);
        json_free(&in);
        return -1;
    }
    const struct json_value *revision = json_get(&status.data, "offer_revision");
    int64_t expected = revision && revision->type == JSON_INT ? json_get_int(revision) : -1;
    zcl_command_reply_free(&status);
    json_free(&in);
    if (expected >= 0) return expected;
    zcl_package_copy_fail(z->reply, "OFFER_STATE_UNAVAILABLE", true,
        "Tasks did not return its current offer revision", z->dest);
    return -1;
}

static bool zrv_offer_matches(const struct zcl_command_reply *offer, const char *root,
                              const char *receipt, const char *digest)
{
    const char *got_root = zcl_app_inner_str(offer, "preview_root");
    const char *got_receipt = zcl_app_inner_str(offer, "preview_receipt");
    const char *program = zcl_app_inner_str(offer, "preview_program");
    const char *got_digest = zcl_app_inner_str(offer, "artifact_sha3");
    return got_root && got_receipt && program && !strcmp(got_root, root) &&
        !strcmp(got_receipt, receipt) && !strcmp(program, "bin/ztasks") &&
        (!digest || (got_digest && !strcmp(got_digest, digest)));
}
static bool zrv_offer_receipt(struct zrv *z, const char *active_root, const char *receipt_id,
                              const char *digest, bool add_executed)
{
    bool ok;
    int64_t expected = zrv_offer_revision(z);
    if (expected < 0) return false;
    struct json_value offer_in;
    json_init(&offer_in);
    json_set_object(&offer_in);
    ok = json_push_kv_str(&offer_in, "action", "offer") &&
        json_push_kv_str(&offer_in, "datadir", z->datadir) &&
        json_push_kv_str(&offer_in, "preview_root", active_root) &&
        json_push_kv_str(&offer_in, "preview_receipt", receipt_id) &&
        json_push_kv_str(&offer_in, "preview_program", "bin/ztasks") &&
        json_push_kv_int(&offer_in, "expected_offer_revision", expected);
    if (!ok) {
        zcl_package_copy_fail(z->reply, "ALLOC", true, "Tasks offer input", z->dest);
        json_free(&offer_in);
        return false;
    }
    struct zcl_command_reply offer;
    if (!zcl_app_inner_call("app.tasks", &offer_in, &offer, NULL)) {
        zcl_app_inner_fail(z->reply, &offer, true);
        zcl_command_reply_free(&offer);
        json_free(&offer_in);
        return false;
    }
    ok = zrv_offer_matches(&offer, active_root, receipt_id, digest) &&
        zrv_observe(z, "preview_offer", "app.tasks", &offer, zrv_offer_fields,
        sizeof(zrv_offer_fields) / sizeof(zrv_offer_fields[0])) &&
        json_push_kv_bool(&z->reply->data, "preview_offered", true) &&
        (!add_executed || json_push_kv_bool(&z->reply->data, "executed", false));
    zcl_command_reply_free(&offer);
    json_free(&offer_in);
    return ok;
}

static bool zrv_offer_tasks(struct zrv *z)
{
    struct json_value in; json_init(&in); json_set_object(&in);
    char use_plan[65] = "", active_root[65] = "", receipt_id[65] = "";
    bool ok = zrv_selected_release(z) && zrv_use_plan(z, &in, use_plan) &&
        json_push_kv_str(&in, "plan_id", use_plan) &&
        zrv_use_commit(z, &in, active_root, receipt_id);
    json_free(&in);
    return ok && zrv_offer_receipt(z, active_root, receipt_id, NULL, true);
}

bool app_receive_tasks_recipe(const struct zcl_command_reply *receive, const struct json_value *build)
{
    const char *name = receive ? zcl_app_inner_str(receive, "name") : NULL;
    const struct json_value *data = json_get(build, "data");
    char base[ZCL_PACKAGE_COPY_BASE_MAX + 1u];
    return name && (zcl_package_copy_name_base(name, base), !strcmp(base, "ztasks")) &&
        json_get_bool(json_get(data, "recipe_build"));
}
static bool zrv_exact_release(struct zrv *z)
{
    const char *id_hex = zcl_app_inner_str(&z->verify, "release_id");
    const char *name = zcl_app_inner_str(&z->verify, "name");
    const char *recipe_hex = zcl_app_inner_str(&z->verify, "recipe_root");
    uint8_t id[32], actual[32], recipe[32]; struct vcs_package_release release;
    return id_hex && name && recipe_hex && zcl_hex_decode_lower(id_hex, id, 32) &&
        zcl_hex_decode_lower(recipe_hex, recipe, 32) &&
        zcl_package_copy_find_release(z->datadir, id, &release, actual) == ZCL_PACKAGE_COPY_FOUND &&
        !memcmp(actual, id, 32) && !strcmp(release.name, name) &&
        !memcmp(release.recipe_root, recipe, 32) && vcs_package_release_verify(&release) == VCS_PACKAGE_RELEASE_OK;
}
static bool zrv_built_artifact(struct zrv *z, const struct json_value *data)
{
    const char *root = json_get_str(json_get(data, "preview_root"));
    const char *receipt = json_get_str(json_get(data, "preview_receipt"));
    const char *program = json_get_str(json_get(data, "preview_program"));
    const char *digest = json_get_str(json_get(data, "artifact_sha3"));
    uint8_t root_id[32], receipt_id[32]; struct package_resident_artifact artifact;
    return root && receipt && program && digest && !strcmp(program, "bin/ztasks") &&
        zcl_hex_decode_lower(root, root_id, 32) && zcl_hex_decode_lower(receipt, receipt_id, 32) &&
        zrv_receipt_identity(z, root, receipt) &&
        package_resident_artifact_read(z->datadir, root_id, receipt_id, program, &artifact).ok &&
        !strcmp(artifact.accepted.image_sha3_hex, digest);
}
static struct zrv *zrv_received_owner(const char *datadir, struct zcl_command_reply *receive)
{
    if (!datadir || !receive) return NULL;
    struct zrv *z = zcl_calloc(1, sizeof(*z), "app.receive.tasks-offer");
    if (!z) {
        zcl_package_copy_fail(receive, "OUT_OF_MEMORY", true,
            "The received copy was kept but its Tasks offer could not be prepared.", "app.receive");
        return NULL;
    }
    z->datadir = datadir; z->reply = receive;
    const char *destination = zcl_package_copy_str(&receive->data, "destination");
    if (destination) (void)snprintf(z->dest, sizeof(z->dest), "%s", destination);
    zcl_command_reply_init(&z->verify, "zcl.app_receive.verified.v1");
    bool ok = destination && json_copy_checked(&z->verify.data, &receive->data) &&
        zrv_exact_release(z) && zrv_selected_release(z);
    if (ok) return z;
    if (receive->status == ZCL_COMMAND_STATUS_PASSED)
        zcl_package_copy_fail(receive, "RELEASE_IDENTITY_MISMATCH", true,
            "The Tasks release could not be verified for this received copy.", z->dest);
    zcl_command_reply_free(&z->verify); free(z); return NULL;
}
bool app_receive_tasks_preflight(const char *datadir, struct zcl_command_reply *receive)
{
    struct zrv *z = zrv_received_owner(datadir, receive);
    if (!z) return false;
    zcl_command_reply_free(&z->verify); free(z); return true;
}
bool app_receive_tasks_offer(const char *datadir, struct zcl_command_reply *receive,
                             const struct json_value *build)
{
    if (!datadir || !receive || !app_receive_tasks_recipe(receive, build)) return false;
    struct zrv *z = zrv_received_owner(datadir, receive);
    if (!z) return false;
    const struct json_value *data = json_get(build, "data");
    bool ok = zrv_built_artifact(z, data);
    if (ok) ok = zrv_offer_receipt(z, json_get_str(json_get(data, "preview_root")),
                                   json_get_str(json_get(data, "preview_receipt")),
                                   json_get_str(json_get(data, "artifact_sha3")), false);
    if (ok) ok = json_push_kv_str(&receive->data, "preview_next", "Open Tasks to try or keep the offered update.");
    if (!ok && receive->status == ZCL_COMMAND_STATUS_PASSED)
        zcl_package_copy_fail(receive, "RELEASE_IDENTITY_MISMATCH", true,
            "The Tasks preview could not be bound to the verified release and artifact.", z->dest);
    zcl_command_reply_free(&z->verify); free(z); return ok;
}

static void zrv_build_open(struct zrv *z)
{
    if (zrv_tasks_package(z)) {
        if (!zrv_offer_tasks(z) && z->reply->status == ZCL_COMMAND_STATUS_PASSED)
            zcl_package_copy_fail(z->reply, "OBSERVATION_UNAVAILABLE", true,
                "Tasks was kept but its build or preview offer could not be verified", z->dest);
        return;
    }
    struct zcl_command_reply inner, build;
    if (!zrv_build(z, &build)) {
        zcl_app_inner_fail(z->reply, &build, true);
        zrv_build_recovery(z);
        zcl_command_reply_free(&build); return;
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
            char next[4 * APP_COPY_BUILD_PATH + 160], plan_hex[65];
            zcl_hex_encode(z->plan_id, sizeof(z->plan_id), plan_hex);
            zrv_describe(z, "plan");
            zcl_package_copy_push_root(&reply->data, "plan_id", z->plan_id);
            (void)json_push_kv_bool(&reply->data, "executed", false);
            if (zcl_app_hint(next, sizeof(next),
                             z->datadir,
                             "open %s --plan-id=%s --yes", z->file, plan_hex))
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
