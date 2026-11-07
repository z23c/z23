/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: app.copy and app.save, the first two front-door composites
 * (command/native_app_front_door.h).
 *
 * app.copy (AUTH_OWNER). The release to copy is the datadir's parentless
 * release whose name's last segment is the app ("skycombat/skycombat" for
 * skycombat), the newest publisher sequence first; a tie between two
 * publishers is AMBIGUOUS_RELEASE. With none, the app.seed leaf (found by
 * name at run time, so this file builds without it) makes one; with no
 * app.seed the copy is SEED_UNAVAILABLE. Then zcode.package.adopt makes
 * <datadir>/copies/<app>-<n> and its adopt record. Plan runs only plan
 * halves (adopt plan, or app.seed plan) and writes nothing but the owner
 * key the seed plan makes on first use (reported as key_created); its plan_id
 * binds the inner plan id, so confirm re-plans and refuses PLAN_MISMATCH
 * when anything moved.
 *
 * app.save (AUTH_OPERATOR) is zcode.package.version.save addressed by copy
 * name, run with the caller's own plan_id and confirm. */

#include "command/native_command.h"

#include "command/app_copy_build.h"
#include "command/native_app_compose.h"
#include "command/native_app_front_door.h"
#include "command/native_zcode_package_copy.h"

#include "base/hex.h"
#include "config/command_catalog.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "vcs/package_publish.h"
#include "vcs/package_release.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ZAC_COMMAND "app.copy"
#define ZAC_PLAN_DOMAIN "zcl.app_copy.plan.v1"
#define ZAC_PATH 4400

struct zac {
    const struct json_value *input;
    struct zcl_command_reply *reply;
    const char *datadir;
    const char *app;
    struct vcs_package_release release;
    char release_hex[65];
    bool have_release;
    bool ambiguous;
    struct json_value inner_in;   /* the adopt or seed input */
    struct zcl_command_reply inner; /* its plan reply */
    bool inner_live;
    char inner_plan[65];
    uint8_t plan_id[32];
};

static bool zac_app_valid(const char *app)
{
    size_t n = app ? strlen(app) : 0;
    if (n == 0 || n > ZCL_PACKAGE_COPY_BASE_MAX)
        return false;
    for (size_t i = 0; i < n; i++) {
        char c = app[i];
        bool alnum = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
        if (!alnum && (i == 0 || (c != '-' && c != '_' && c != '.')))
            return false;
    }
    return true;
}

/* Is r a parentless release of this app, and newer than the best so far? */
static void zac_consider(struct zac *z, const struct vcs_package_release *r)
{
    char base[ZCL_PACKAGE_COPY_BASE_MAX + 1u];
    uint8_t id[32];
    if (r->has_parent || vcs_package_release_id(r, id) != VCS_PACKAGE_RELEASE_OK)
        return;
    zcl_package_copy_name_base(r->name, base);
    if (strcmp(base, z->app) != 0)
        return;
    if (z->have_release &&
        r->publisher_sequence == z->release.publisher_sequence &&
        memcmp(r->publisher_pubkey, z->release.publisher_pubkey,
               sizeof(r->publisher_pubkey)) != 0)
        z->ambiguous = true;
    if (z->have_release &&
        r->publisher_sequence <= z->release.publisher_sequence)
        return;
    z->release = *r;
    z->have_release = true;
    z->ambiguous = false;
    zcl_hex_encode(id, 32, z->release_hex);
}

static bool zac_find(struct zac *z)
{
    char dir[ZAC_PATH];
    size_t count = 0, skipped = 0;
    int n = snprintf(dir, sizeof(dir), "%s/zcode", z->datadir);
    struct vcs_package_release *all =
        zcl_calloc(VCS_PACKAGE_PUBLISH_MAX_RELEASES, sizeof(*all),
                   "app.copy.releases");
    bool ok = all && n > 0 && (size_t)n < sizeof(dir) &&
              vcs_package_publish_load_releases(
                  dir, all, VCS_PACKAGE_PUBLISH_MAX_RELEASES, &count,
                  &skipped);
    for (size_t i = 0; ok && i < count; i++)
        zac_consider(z, &all[i]);
    free(all);
    if (!ok)
        zcl_package_copy_fail(z->reply, "RELEASES_UNREADABLE", false,
                              "the datadir's releases could not be read",
                              z->datadir);
    else if (z->ambiguous)
        zcl_package_copy_fail(z->reply, "AMBIGUOUS_RELEASE", false,
                              "two publishers' releases of this app have the "
                              "same sequence; adopt one by root with "
                              "zcode package adopt", z->app);
    return ok && !z->ambiguous;
}

/* The inner plan: adopt the found release, or seed one. */
static bool zac_inner_plan(struct zac *z)
{
    bool absent = false;
    const char *path = z->have_release ? "zcode.package.adopt" : "app.seed";
    json_init(&z->inner_in);
    json_set_object(&z->inner_in);
    if (!json_push_kv_str(&z->inner_in, z->have_release ? "root" : "app",
                          z->have_release ? z->release_hex : z->app) ||
        !json_push_kv_str(&z->inner_in, "datadir", z->datadir)) {
        zcl_package_copy_fail(z->reply, "ALLOC", false, "inner input",
                              ZAC_COMMAND);
        return false;
    }
    z->inner_live = true;
    if (zcl_app_inner_call(path, &z->inner_in, &z->inner, &absent) &&
        zcl_app_inner_str(&z->inner, "plan_id")) {
        (void)snprintf(z->inner_plan, sizeof(z->inner_plan), "%s",
                       zcl_app_inner_str(&z->inner, "plan_id"));
        const char *parts[] = {z->app, z->datadir, path, z->inner_plan};
        zcl_app_plan_id(ZAC_PLAN_DOMAIN, parts, 4, z->plan_id);
        return true;
    }
    if (absent) {
        zcl_package_copy_fail(z->reply, "SEED_UNAVAILABLE", false,
                              "this datadir has no release of the app and "
                              "this z23 has no app.seed leaf to make one",
                              z->app);
        (void)snprintf(z->reply->error.next_action,
                       sizeof(z->reply->error.next_action),
                       "open a friend's copy with z23 app open "
                       "FILE.z23share, or update z23");
        return false;
    }
    zcl_app_inner_fail(z->reply, &z->inner, false);
    if (!z->have_release)
        (void)snprintf(z->reply->error.next_action,
                       sizeof(z->reply->error.next_action),
                       "seeding failed; open a friend's copy with z23 app "
                       "open FILE.z23share instead");
    return false;
}

/* The seed plan makes the owner's publisher key on first use (the package
 * root and plan_id derive from it); carry that fact to the front door. */
static void zac_push_key(struct json_value *d,
                         const struct zcl_command_reply *from)
{
    const struct json_value *made = json_get(&from->data, "key_created");
    if (!made || made->type != JSON_BOOL)
        return;
    (void)json_push_kv_bool(d, "key_created", json_get_bool(made));
    if (zcl_app_inner_str(from, "key_path"))
        (void)json_push_kv_str(d, "key_path",
                               zcl_app_inner_str(from, "key_path"));
}

static void zac_describe(struct zac *z, const char *stage,
                         const struct zcl_command_reply *from)
{
    struct json_value *d = &z->reply->data;
    static const char *const keys[] = {"copy_name", "copy", "name", "semver",
                                       "package_root"};
    (void)json_push_kv_str(d, "stage", stage);
    (void)json_push_kv_str(d, "app", z->app);
    (void)json_push_kv_bool(d, "seed", !z->have_release);
    if (z->have_release)
        (void)json_push_kv_str(d, "release_root", z->release_hex);
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        const char *v = zcl_app_inner_str(from, keys[i]);
        if (v)
            (void)json_push_kv_str(d, keys[i], v);
    }
    zcl_app_push_publisher(d, zcl_app_inner_str(from, "publisher"));
    zac_push_key(d, from);
    (void)json_push_kv_bool(d, "executed", false);
}

static void zac_plan_reply(struct zac *z)
{
    char next[ZAC_PATH + 160];
    zac_describe(z, "plan", &z->inner);
    zcl_package_copy_push_root(&z->reply->data, "plan_id", z->plan_id);
    if (zcl_app_hint(next, sizeof(next),
                     zcl_package_copy_str(z->input, "datadir"),
                     "copy %s --yes (or run it in a terminal and answer y)",
                     z->app))
        (void)json_push_kv_str(&z->reply->data, "next", next);
}

/* Seed confirm, then the seeded release's adopt plan as the inner plan. */
static bool zac_seed_then_plan(struct zac *z)
{
    if (!json_push_kv_str(&z->inner_in, "plan_id", z->inner_plan) ||
        !json_push_kv_bool(&z->inner_in, "confirm", true))
        return false;
    zcl_command_reply_free(&z->inner);
    if (!zcl_app_inner_call("app.seed", &z->inner_in, &z->inner, NULL)) {
        zcl_app_inner_fail(z->reply, &z->inner, false);
        return false;
    }
    const char *id = zcl_app_inner_str(&z->inner, "release_id");
    uint8_t raw[32];
    struct vcs_package_release r;
    if (!id || zcl_package_copy_find_release(z->datadir,
                                             zcl_hex_decode(id, raw, 32)
                                                 ? raw : (uint8_t[32]){0},
                                             &r, raw) !=
                   ZCL_PACKAGE_COPY_FOUND) {
        zcl_package_copy_fail(z->reply, "SEED_RELEASE_MISSING", true,
                              "app.seed passed but its release is not in "
                              "the datadir", id ? id : z->app);
        return false;
    }
    z->release = r;
    z->have_release = true;
    zcl_hex_encode(raw, 32, z->release_hex);
    json_free(&z->inner_in);
    zcl_command_reply_free(&z->inner);
    z->inner_live = false;
    return zac_inner_plan(z);
}

static void zac_confirm(struct zac *z)
{
    bool seeded = !z->have_release;
    if (!zcl_package_copy_plan_matches(z->input, z->plan_id, z->reply,
                                       ZAC_COMMAND))
        return;
    if (seeded && !zac_seed_then_plan(z)) {
        z->reply->error.mutated = true;
        return;
    }
    if (!json_push_kv_str(&z->inner_in, "plan_id", z->inner_plan) ||
        !json_push_kv_bool(&z->inner_in, "confirm", true))
        return;
    zcl_command_reply_free(&z->inner);
    if (!zcl_app_inner_call("zcode.package.adopt", &z->inner_in, &z->inner,
                            NULL)) {
        zcl_app_inner_fail(z->reply, &z->inner, seeded);
        return;
    }
    char hint[ZAC_PATH + 96], next[2 * ZAC_PATH + 160];
    zac_describe(z, "commit", &z->inner);
    (void)json_push_kv_bool(&z->reply->data, "seeded", seeded);
    if (zcl_app_hint(hint, sizeof(hint),
                     zcl_package_copy_str(z->input, "datadir"), "save %s",
                     zcl_app_inner_str(&z->inner, "copy_name")) &&
        snprintf(next, sizeof(next), "edit the files in %s, then: %s",
                 zcl_app_inner_str(&z->inner, "copy"), hint) <
            (int)sizeof(next))
        (void)json_push_kv_str(&z->reply->data, "next", next);
    z->reply->error.mutated = true;
}

void zcl_native_handle_app_copy(const struct zcl_command_request *request,
                                struct zcl_command_reply *reply)
{
    struct zac *z = request && reply
                        ? zcl_calloc(1, sizeof(*z), "app.copy.state")
                        : NULL;
    if (!z) {
        if (reply)
            zcl_package_copy_fail(reply, "ALLOC", false, "app.copy state",
                                  ZAC_COMMAND);
        return;
    }
    z->input = request->input;
    z->reply = reply;
    z->app = zcl_package_copy_str(request->input, "app");
    z->datadir = zcl_package_copy_datadir(request->input, reply, ZAC_COMMAND);
    if (z->datadir && !zac_app_valid(z->app))
        zcl_package_copy_fail(reply, "BAD_APP", false, "app is a lowercase "
                              "name such as skycombat", z->app ? z->app : "");
    else if (z->datadir && zac_find(z) && zac_inner_plan(z)) {
        if (zcl_package_copy_confirmed(request->input))
            zac_confirm(z);
        else
            zac_plan_reply(z);
    }
    if (z->inner_live) {
        zcl_command_reply_free(&z->inner);
        json_free(&z->inner_in);
    }
    free(z);
}

/* ── app.save ───────────────────────────────────────────────────────── */

void zcl_native_handle_app_save(const struct zcl_command_request *request,
                                struct zcl_command_reply *reply)
{
    static const char path[] = "zcode.package.version.save";
    char dir[APP_COPY_BUILD_PATH], why[256] = "";
    struct json_value in;
    if (!request || !reply)
        return;
    const char *copy = zcl_package_copy_str(request->input, "copy");
    const char *datadir =
        zcl_package_copy_datadir(request->input, reply, "app.save");
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(zcl_command_catalog(), path, NULL);
    if (!datadir ||
        !app_copy_build_dir(datadir, copy, dir, sizeof(dir), reply))
        return;
    json_init(&in);
    json_set_object(&in);
    const char *plan = zcl_package_copy_str(request->input, "plan_id");
    bool ok = json_push_kv_str(&in, "dir", dir) &&
              (!plan || json_push_kv_str(&in, "plan_id", plan)) &&
              (!zcl_package_copy_confirmed(request->input) ||
               json_push_kv_bool(&in, "confirm", true));
    if (!ok || !spec || !spec->handler ||
        !zcl_command_registry_input_validate(spec, &in, why, sizeof(why))) {
        zcl_package_copy_fail(reply, "SAVE_UNAVAILABLE", false,
                              "the version save leaf could not be run", why);
    } else {
        const struct zcl_command_request inner = {
            .input = &in, .spec = spec, .invoked_name = spec->path,
        };
        spec->handler(&inner, reply);
        (void)json_push_kv_str(&reply->data, "copy_name", copy);
    }
    json_free(&in);
}
