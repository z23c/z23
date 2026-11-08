/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: verify a public catalog offer before asking to receive an app. */
#include "command/native_command.h"
#include "command/native_app_compose.h"
#include "command/native_app_front_door.h"
#include "command/native_app_offer.h"
#include "command/native_dev_land_remote_shared.h"
#include "command/native_zcode_package_copy.h"
#include "command/app_image.h"
#include "base/safe_alloc.h"
#include "base/hex.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "platform/rng.h"
#include "platform/private_directory.h"
#include "platform/toolchain.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define AG_COMMAND "app.get"
#define AG_PATH 4400
#define AG_ATTEMPTS 4u
#define AG_BUDGET_MS 300000

static bool ag_hex(const char *text, size_t bytes);

static bool ag_same_identity(const struct zcl_app_offer *a, const struct zcl_app_offer *b)
{
    return !strcmp(a->name, b->name) && !strcmp(a->root, b->root) &&
           !strcmp(a->publisher, b->publisher);
}

static bool ag_copy_data(struct json_value *out, const struct json_value *in,
                         const char *key)
{
    const struct json_value *v = json_get(in, key);
    return !v || json_push_kv(out, key, v);
}

struct ag_one;
static bool ag_observation(const struct ag_one *s, const struct json_value *build,
                           const char *opened, struct zcl_app_rebuild *r);

static bool ag_hash(const char *path, const struct zcl_app_offer *offer)
{
    struct stat st;
    char sha[65];
    return lstat(path, &st) == 0 && S_ISREG(st.st_mode) &&
           st.st_size == offer->size && zcl_dlr_file_sha256(path, sha) &&
           !strcmp(sha, offer->sha256);
}

/* Only call after this invocation created the exclusive private directory. */
static bool ag_cleanup(const char *dir, const char *path,
                       struct zcl_command_reply *reply, bool mutated)
{
    bool removed = unlink(path) == 0 || errno == ENOENT;
    if (removed && rmdir(dir) == 0) return true;
    zcl_package_copy_fail(reply, "TEMP_CLEANUP_FAILED", mutated,
                          "private get directory could not be removed", dir);
    return false;
}

static bool ag_fetch(const struct zcl_app_offer_row *row, const char *path,
                     int64_t timeout_s, struct zcl_command_reply *out)
{
    struct json_value in;
    const struct zcl_app_offer *o = &row->offer;
    const char *kv[] = {"root", o->carrier, "sha256", o->sha256,
                        "out", path, "peer", o->onion};
    bool built = zcl_app_input(&in, kv, 8) &&
                 json_push_kv_int(&in, "size", o->size) &&
                 json_push_kv_int(&in, "timeout_s", timeout_s);
    bool ok = built && zcl_app_offer_call(ZCL_APP_OFFER_BUNDLE_FETCH, &in, out);
    json_free(&in);
    if (!built) zcl_command_reply_init(out, "zcl.app_get.inner.v1");
    return ok;
}

static bool ag_list(struct zcl_command_reply *reply,
                    const struct zcl_app_offer_row *rows, size_t count)
{
    struct json_value lines;
    json_init(&lines);
    json_set_array(&lines);
    size_t identities = 0;
    for (size_t i = 0; i < count; i++) {
        bool seen = false;
        for (size_t j = 0; j < i; j++)
            if (ag_same_identity(&rows[i].offer, &rows[j].offer)) { seen = true; break; }
        if (seen) continue;
        char line[512], age[32], shortfp[20];
        zcl_app_offer_age(rows[i].created_at, platform_time_wall_unix(), age, sizeof(age));
        if (!zcl_app_short_fingerprint(rows[i].offer.publisher, shortfp)) { json_free(&lines); return false; }
        int n = snprintf(line, sizeof(line), "%s %s %.16s %s ago",
                         rows[i].offer.name, shortfp, rows[i].offer.root, age);
        struct json_value item;
        json_init(&item);
        json_set_str(&item, line);
        bool ok = n > 0 && (size_t)n < sizeof(line) && json_push_back(&lines, &item);
        json_free(&item);
        if (!ok) { json_free(&lines); return false; }
        identities++;
    }
    bool ok = json_push_kv(&reply->data, "lines", &lines) &&
              json_push_kv_int(&reply->data, "count", (int64_t)identities);
    json_free(&lines);
    return ok;
}

struct ag_one {
    const struct zcl_app_offer_row *row;
    const char *datadir, *token;
    const struct json_value *input;
    struct zcl_command_reply *reply;
    char dir[AG_PATH], path[AG_PATH], receive_plan[65];
    uint8_t plan[32];
    struct zcl_command_reply inner;
    bool created;
};

static bool ag_stage(struct ag_one *s, int64_t timeout_s)
{
    int n = snprintf(s->dir, sizeof(s->dir), "%s/.app-get-%s", s->datadir, s->token);
    if (n <= 0 || (size_t)n >= sizeof(s->dir) ||
        snprintf(s->path, sizeof(s->path), "%s/offer.z23share", s->dir) >= (int)sizeof(s->path) ||
        !platform_private_directory_create(s->dir)) {
        zcl_package_copy_fail(s->reply, "TEMP_UNAVAILABLE", false, "cannot create private get directory", AG_COMMAND);
        return false;
    }
    s->created = true;
    bool fetched = ag_fetch(s->row, s->path, timeout_s, &s->inner);
    if (!fetched) zcl_app_inner_fail(s->reply, &s->inner, false);
    zcl_command_reply_free(&s->inner);
    if (!fetched) return false;
    if (!ag_hash(s->path, &s->row->offer)) {
        zcl_package_copy_fail(s->reply, "SHA256_MISMATCH", false, "fetched bytes do not match the offer", AG_COMMAND);
        return false;
    }
    return true;
}

static bool ag_receive_plan(struct ag_one *s)
{
    struct json_value in;
    const char *kv[] = {"file", s->path, "datadir", s->datadir};
    bool built = zcl_app_input(&in, kv, 4);
    bool ok = zcl_app_inner_call_built("app.receive-copy", &in, built, &s->inner);
    const char *root = ok ? zcl_app_inner_str(&s->inner, "package_root") : NULL;
    const char *pub = ok ? zcl_app_inner_str(&s->inner, "publisher_fingerprint") : NULL;
    const char *plan = ok ? zcl_app_inner_str(&s->inner, "plan_id") : NULL;
    if (!ok || !root || !pub || !plan || strlen(plan) != 64) {
        if (ok) zcl_package_copy_fail(s->reply, "MALFORMED_INNER", false, "receive plan omitted verified identity or plan id", AG_COMMAND);
        else zcl_app_inner_fail(s->reply, &s->inner, false);
        return false;
    }
    if (strcmp(root, s->row->offer.root) || strcmp(pub, s->row->offer.publisher)) {
        zcl_package_copy_fail(s->reply, strcmp(root, s->row->offer.root) ? "ROOT_MISMATCH" : "PUBLISHER_MISMATCH",
                              false, "verified app identity differs from the advertised identity", AG_COMMAND);
        return false;
    }
    (void)snprintf(s->receive_plan, sizeof(s->receive_plan), "%s", plan);
    const struct zcl_app_offer *o = &s->row->offer;
    return vcs_app_get_recurring_plan(o, s->row->post_id, s->row->host,
                                      s->receive_plan, s->datadir, s->token,
                                      s->plan);
}

static bool ag_plan_reply(struct ag_one *s)
{
    bool ok = true;
    const char *keys[] = {"name", "semver", "publisher", "publisher_fingerprint", "package_root", "copy", "destination"};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
        ok = ag_copy_data(&s->reply->data, &s->inner.data, keys[i]) && ok;
    ok = ok && json_push_kv_str(&s->reply->data, "sha256", s->row->offer.sha256) &&
         json_push_kv_str(&s->reply->data, "offer_id", s->row->post_id) &&
         json_push_kv_str(&s->reply->data, "token", s->token) &&
         json_push_kv_bool(&s->reply->data, "public_build_reporting", true) &&
         json_push_kv_bool(&s->reply->data, "pin_received_carrier", true) &&
         json_push_kv_bool(&s->reply->data, "public_hosting_if_ready", true) &&
         json_push_kv_bool(&s->reply->data, "recurring_hosting", true) &&
         json_push_kv_int(&s->reply->data, "hosting_ttl_seconds", 86400) &&
         zcl_package_copy_push_root(&s->reply->data, "plan_id", s->plan) &&
         json_push_kv_bool(&s->reply->data, "executed", false);
    if (!ok) zcl_package_copy_fail(s->reply, "ALLOC", false, "cannot describe get plan", AG_COMMAND);
    return ok;
}

static bool ag_record_field(const struct json_value *build, const char *key, const uint8_t expected[32])
{
    uint8_t value[32]; const char *s = zcl_package_copy_str(build, key);
    return ag_hex(s, 32) && zcl_hex_decode_lower(s, value, sizeof(value)) && !memcmp(value, expected, sizeof(value));
}

static bool ag_record_keys(const struct json_value *build, uint8_t package[32],
                           uint8_t environment[32], uint8_t dependency[32])
{
    if (!build || build->type != JSON_OBJ) return false;
    const char *version = zcl_package_copy_str(build, "version");
    const char *pkg = zcl_package_copy_str(build, "package_root"), *env = zcl_package_copy_str(build, "env_root"), *dep = zcl_package_copy_str(build, "dependency_root");
    return ag_hex(version, 32) && ag_hex(pkg, 32) && ag_hex(env, 32) && ag_hex(dep, 32) &&
        zcl_hex_decode_lower(pkg, package, 32) && zcl_hex_decode_lower(env, environment, 32) &&
        zcl_hex_decode_lower(dep, dependency, 32);
}

static bool ag_load_record(const struct json_value *build, const char *opened,
                           struct app_image_build *rec, uint8_t record[32])
{
    const char *store = zcl_package_copy_str(build, "record_store");
    uint8_t package[32], environment[32], dependency[32];
    if (!store || !ag_record_keys(build, package, environment, dependency)) return false;
    bool hit = false;
    if (!app_image_build_load(store, package, environment, dependency, rec, &hit).ok || !hit ||
        !app_image_build_id(rec, record).ok || !ag_record_field(build, "record_id", record) ||
        !ag_record_field(build, "closure_root", rec->closure_root) || !ag_record_field(build, "image_sha3", rec->image_sha3)) return false;
    uint8_t opened_hash[32];
    return ag_hex(opened, 32) && zcl_hex_decode_lower(opened, opened_hash, 32) && !memcmp(opened_hash, rec->image_sha3, 32);
}

static bool ag_observation(const struct ag_one *s, const struct json_value *build,
                           const char *opened, struct zcl_app_rebuild *r)
{
    struct app_image_build rec; uint8_t record[32];
    if (!ag_load_record(build, opened, &rec, record)) return false;
    const char *version = zcl_package_copy_str(build, "version");
    memset(r, 0, sizeof(*r));
    (void)snprintf(r->publisher, sizeof(r->publisher), "%s", s->row->offer.publisher);
    (void)snprintf(r->release_root, sizeof(r->release_root), "%s", s->row->offer.root);
    (void)snprintf(r->version, sizeof(r->version), "%s", version);
    zcl_hex_encode(rec.package_root, 32, r->package_root); zcl_hex_encode(rec.closure_root, 32, r->closure);
    zcl_hex_encode(rec.env_root, 32, r->environment); zcl_hex_encode(rec.dependency_root, 32, r->dependency);
    zcl_hex_encode(rec.image_sha3, 32, r->image); zcl_hex_encode(record, 32, r->record);
    return platform_toolchain_canonical_target(r->target, sizeof(r->target));
}

static void ag_rebuild_post(struct json_value *data, const struct zcl_app_rebuild *r)
{
    char text[ZCL_APP_OFFER_TEXT_MAX + 1u];
    if (!zcl_app_rebuild_format(r, text, sizeof(text))) {
        (void)json_push_kv_str(data, "rebuild_report", "unavailable: invalid observation"); return;
    }
    struct json_value in; struct zcl_command_reply post;
    const char *kv[] = {"room", "apps", "scope", "public", "kind", "result", "text", text};
    bool built = zcl_app_input(&in, kv, 8) && json_push_kv_int(&in, "ttl", 2592000);
    bool posted = built && zcl_app_offer_call(ZCL_APP_OFFER_BOARD_POST, &in, &post);
    json_free(&in);
    if (!built) zcl_command_reply_init(&post, "zcl.app_rebuild.post.v1");
    const char *id = posted ? zcl_app_inner_str(&post, "id") : NULL;
    if (!ag_hex(id, 32)) {
        (void)json_push_kv_str(data, "rebuild_report", "publication unconfirmed; retry the observation");
        (void)json_push_kv_str(data, "rebuild_retry_text", text);
        char retry[ZCL_APP_OFFER_TEXT_MAX + 160u];
        int n = snprintf(retry, sizeof(retry), "z23 fleet board post --kind=result --scope=public --room=apps --ttl=2592000 --text='%s'", text);
        if (n > 0 && (size_t)n < sizeof(retry)) (void)json_push_kv_str(data, "rebuild_retry", retry);
        zcl_command_reply_free(&post); return;
    }
    (void)json_push_kv_str(data, "rebuild_report", "published");
    (void)json_push_kv_str(data, "rebuild_post_id", id);
    zcl_command_reply_free(&post);
}

static void ag_rebuild_report(struct ag_one *s, const struct json_value *build, const char *image)
{
    struct zcl_app_rebuild r; struct json_value *data = &s->reply->data;
    const struct json_value *made = json_get(build, "make_ran");
    if (!made || made->type != JSON_BOOL || !ag_observation(s, build, image, &r)) {
        (void)json_push_kv_str(data, "rebuild_report", "unavailable: build evidence could not be verified");
        (void)json_push_kv_str(data, "rebuild_count_status", "incomplete: build evidence unavailable"); return;
    }
    if (json_get_bool(made)) ag_rebuild_post(data, &r);
    else (void)json_push_kv_str(data, "rebuild_report", "not published: cached image");
    struct zcl_command_reply why; size_t count = 0;
    if (zcl_app_rebuild_count(&r, &count, &why)) {
        (void)json_push_kv_int(data, "matching_rebuild_keys", (int64_t)count);
        (void)json_push_kv_str(data, "rebuild_count_status", "local snapshot; global count unknown");
    } else {
        (void)json_push_kv_str(data, "rebuild_count_status", "incomplete: board query unavailable or capped");
    }
    zcl_command_reply_free(&why);
}

static bool ag_open_matches(const struct zcl_command_reply *inner)
{
    const struct json_value *match = json_get(&inner->data, "build_matches_open");
    return match && match->type == JSON_BOOL && json_get_bool(match);
}

static bool ag_host_offer_matches(const struct zcl_command_reply *inner,
                                  const struct zcl_app_offer *o,
                                  const char *host, const char *endpoint)
{
    const char *root = zcl_app_inner_str(inner, "root"), *sha = zcl_app_inner_str(inner, "sha256");
    const char *onion = zcl_app_inner_str(inner, "onion");
    const struct json_value *size = json_get(&inner->data, "size");
    const struct json_value *pinned = json_get(&inner->data, "pinned");
    return root && sha && !strcmp(root, o->carrier) && !strcmp(sha, o->sha256) &&
        size && size->type == JSON_INT && json_get_int(size) == o->size &&
        pinned && pinned->type == JSON_BOOL && json_get_bool(pinned) &&
        (!onion || !host || !strcmp(onion, host) || !strcmp(onion, endpoint));
}

static bool ag_host_response(const struct json_value *data, const char *expected_carrier)
{
    const struct json_value *ok = json_get(data, "ok"), *enabled = json_get(data, "enabled");
    const struct json_value *generation = json_get(data, "generation");
    const char *host = json_get_str(json_get(data, "host"));
    const char *carrier = json_get_str(json_get(data, "carrier"));
    return ok && ok->type == JSON_BOOL && json_get_bool(ok) && ag_hex(host, 32) &&
        carrier && expected_carrier && !strcmp(carrier, expected_carrier) &&
        enabled && enabled->type == JSON_BOOL && json_get_bool(enabled) &&
        generation && generation->type == JSON_INT && json_get_int(generation) > 0;
}

#ifdef ZCL_TESTING
bool zcl_app_get_host_reply_valid_for_testing(const struct json_value *data, const char *carrier)
{
    return ag_host_response(data, carrier);
}
#endif

static void ag_host_report_failure(struct ag_one *s)
{
    if (s->reply->status == ZCL_COMMAND_STATUS_PASSED) {
        zcl_package_copy_fail(s->reply, "HOSTING_RESULT_UNAVAILABLE", true,
            "the copy was kept but the hosting outcome could not be reported", AG_COMMAND);
        return;
    }
    s->reply->error.mutated = true;
    size_t n = strlen(s->reply->error.message);
    if (n < sizeof(s->reply->error.message))
        (void)snprintf(s->reply->error.message + n, sizeof(s->reply->error.message) - n,
                       "; hosting outcome could not be reported");
}

static void ag_host_enabled(struct ag_one *s, const char *host, const char *carrier,
                            const struct json_value *generation)
{
    struct json_value *data = &s->reply->data;
    char status[4600], stop[4700], h[72], c[76], g[48];
    (void)snprintf(h, sizeof(h), "--host=%s", host);
    (void)snprintf(c, sizeof(c), "--carrier=%s", carrier);
    (void)snprintf(g, sizeof(g), "--generation=%lld", (long long)json_get_int(generation));
    bool hints = zcl_app_hint(status, sizeof(status), s->datadir, "host status %s %s", h, c) &&
                 zcl_app_hint(stop, sizeof(stop), s->datadir, "host stop %s %s %s", h, c, g);
    bool reported = json_push_kv_str(data, "hosting_host", host) &&
        json_push_kv_str(data, "hosting_carrier", carrier) &&
        json_push_kv_int(data, "hosting_generation", json_get_int(generation)) &&
        json_push_kv_str(data, "hosting_status", "recurring hosting enabled; advertisement waits for node readiness");
    if (hints) {
        reported = json_push_kv_str(data, "hosting_status_command", status) && reported;
        reported = json_push_kv_str(data, "hosting_stop_command", stop) && reported;
    }
    if (!reported) ag_host_report_failure(s);
}

static void ag_host_unconfirmed(struct ag_one *s)
{
    struct json_value *data = &s->reply->data;
    char retry[4900], root[72], publisher[80], offer[73];
    (void)snprintf(root, sizeof(root), "--root=%s", s->row->offer.root);
    (void)snprintf(publisher, sizeof(publisher), "--publisher=%s", s->row->offer.publisher);
    (void)snprintf(offer, sizeof(offer), "--offer=%s", s->row->post_id);
    bool reported = json_push_kv_str(data, "hosting_status", "carrier pinned; recurring hosting unconfirmed");
    if (zcl_app_hint(retry, sizeof(retry), s->datadir, "get %s %s %s %s",
                     s->row->offer.name, root, publisher, offer))
        reported = json_push_kv_str(data, "hosting_retry", retry) && reported;
    reported = json_push_kv_str(data, "hosting_retry_note", "a new confirmed get retries setup and fetches the carrier again") && reported;
    if (!reported) ag_host_report_failure(s);
}

static void ag_host_enable(struct ag_one *s)
{
    char text[ZCL_APP_OFFER_TEXT_MAX + 1u], plan[65];
    zcl_hex_encode(s->plan, 32, plan);
    bool formatted = zcl_app_offer_format(&s->row->offer, text, sizeof(text));
    const char *kv[] = {"offer", text, "post_id", s->row->post_id, "post_host", s->row->host,
        "receive_plan", s->receive_plan, "datadir", s->datadir, "token", s->token, "plan_id", plan};
    struct json_value in; struct zcl_command_reply inner;
    bool built = formatted && zcl_app_input(&in, kv, 14) && json_push_kv_bool(&in, "confirm", true);
    if (!formatted) json_init(&in);
    bool ok = built && zcl_app_offer_call(ZCL_APP_HOST_ENABLE, &in, &inner);
    json_free(&in); if (!built) zcl_command_reply_init(&inner, "zcl.app_host_enable.v1");
    const char *host = ok ? zcl_app_inner_str(&inner, "host") : NULL;
    const char *carrier = ok ? zcl_app_inner_str(&inner, "carrier") : NULL;
    const struct json_value *generation = ok ? json_get(&inner.data, "generation") : NULL;
    ok = ok && ag_host_response(&inner.data, s->row->offer.carrier);
    if (ok) ag_host_enabled(s, host, carrier, generation);
    else ag_host_unconfirmed(s);
    zcl_command_reply_free(&inner);
}

static void ag_rehost(struct ag_one *s)
{
    struct json_value *data = &s->reply->data;
    if (!ag_hash(s->path, &s->row->offer)) {
        (void)json_push_kv_str(data, "hosting_status", "no pin attempted: staged carrier changed"); return;
    }
    struct json_value in; struct zcl_command_reply inner;
    const char *kv[] = {"file", s->path};
    bool built = zcl_app_input(&in, kv, 2);
    bool ok = built && zcl_app_offer_call(ZCL_APP_OFFER_BUNDLE_OFFER, &in, &inner);
    json_free(&in); if (!built) zcl_command_reply_init(&inner, "zcl.app_get.host.v1");
    if (!ok || !ag_host_offer_matches(&inner, &s->row->offer, NULL, NULL)) {
        (void)json_push_kv_str(data, "hosting_status", "not advertised: carrier pin was refused or unconfirmed; storage may have changed");
        (void)json_push_kv_str(data, "hosting_retry", "check node hosting and get the app again to offer its carrier");
        zcl_command_reply_free(&inner); return;
    }
    zcl_command_reply_free(&inner);
    ag_host_enable(s);
}

static bool ag_result_observations(struct ag_one *s, const struct json_value *data)
{
    bool ok = true;
    const char *observations[] = {"receive_observation", "build_observation", "open_observation"};
    size_t bytes = 0;
    for (size_t i = 0; ok && i < sizeof(observations) / sizeof(observations[0]); ++i) {
        const struct json_value *v = json_get(data, observations[i]);
        size_t n = v && v->type == JSON_OBJ ? json_write(v, NULL, 0) : 0;
        ok = n && n <= 4096u - bytes && json_push_kv(&s->reply->data, observations[i], v);
        if (ok) bytes += n;
    }
    const struct json_value *receive = json_get(json_get(data, "receive_observation"), "data");
    const struct json_value *version = json_get(receive, "version");
    const char *name = zcl_package_copy_str(data, "name");
    ok = ok && name && version && version->type == JSON_STR &&
        json_push_kv_str(&s->reply->data, "name", name) &&
        json_push_kv(&s->reply->data, "version", version);
    return ok;
}
static bool ag_commit_result(struct ag_one *s, struct zcl_command_reply *inner)
{
    const char *copy = zcl_app_inner_str(inner, "copy");
    const char *image = zcl_app_inner_str(inner, "image_sha3");
    const struct json_value *executed = json_get(&inner->data, "executed");
    const struct json_value *pid = json_get(&inner->data, "pid");
    if (!copy || !ag_hex(image, 32) || !executed || executed->type != JSON_BOOL ||
        !json_get_bool(executed) || (pid && pid->type != JSON_INT)) {
        zcl_package_copy_fail(s->reply, "MALFORMED_INNER", true,
                              "receive completed without a valid copy, image or execution result", AG_COMMAND);
        return false;
    }
    bool ok = true;
    const char *keys[] = {"copy", "destination", "pid", "image_sha3", "executed", "open_attempted"};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
        ok = ag_copy_data(&s->reply->data, &inner->data, keys[i]) && ok;
    ok = ok && ag_result_observations(s, &inner->data);
    if (ok && ag_open_matches(inner))
        ag_rebuild_report(s, json_get(&inner->data, "build"), image);
    else if (ok) {
        (void)json_push_kv_str(&s->reply->data, "rebuild_report", "unavailable: opened version differs from build");
        (void)json_push_kv_str(&s->reply->data, "rebuild_count_status", "incomplete: build evidence unavailable");
    }
    if (!ok) zcl_package_copy_fail(s->reply, "ALLOC", true, "cannot describe received app", AG_COMMAND);
    return ok;
}

static bool ag_commit(struct ag_one *s)
{
    if (!zcl_package_copy_plan_matches(s->input, s->plan, s->reply, AG_COMMAND)) return false;
    struct json_value in;
    const char *kv[] = {"file", s->path, "datadir", s->datadir};
    bool built = zcl_app_input(&in, kv, 4) && json_push_kv_str(&in, "plan_id", s->receive_plan) &&
                 json_push_kv_bool(&in, "confirm", true);
    struct zcl_command_reply inner;
    bool ok = zcl_app_inner_call_built("app.receive-copy", &in, built, &inner);
    if (!ok) {
        zcl_app_inner_fail(s->reply, &inner, false);
        (void)zcl_app_copy_recovery(&s->reply->data, &inner.data);
        (void)ag_copy_data(&s->reply->data, &inner.data, "copy");
        (void)ag_copy_data(&s->reply->data, &inner.data, "destination");
        (void)ag_copy_data(&s->reply->data, &inner.data, "received");
        (void)ag_copy_data(&s->reply->data, &inner.data, "open_attempted");
        (void)ag_copy_data(&s->reply->data, &inner.data, "executed");
        (void)ag_copy_data(&s->reply->data, &inner.data, "pid");
        const struct json_value *build = json_get(&inner.data, "build");
        if (build) {
            (void)json_push_kv(&s->reply->data, "build", build);
            ag_rebuild_report(s, build, zcl_package_copy_str(build, "image_sha3"));
        }
    }
    else ok = ag_commit_result(s, &inner);
    const struct json_value *received = json_get(&inner.data, "received");
    if (received && received->type == JSON_BOOL && json_get_bool(received)) ag_rehost(s);
    zcl_command_reply_free(&inner);
    return ok && s->reply->status == ZCL_COMMAND_STATUS_PASSED;
}

static bool ag_plan_one(const struct zcl_app_offer_row *row, const char *datadir,
                        const struct json_value *input, const char *token, int64_t timeout_s,
                        struct zcl_command_reply *reply)
{
    struct ag_one s = {.row = row, .datadir = datadir, .input = input, .token = token, .reply = reply};
    if (!ag_stage(&s, timeout_s)) {
        if (s.created) (void)ag_cleanup(s.dir, s.path, reply, false);
        return false;
    }
    bool ok = ag_receive_plan(&s);
    if (ok) ok = zcl_package_copy_confirmed(input) ? ag_commit(&s) : ag_plan_reply(&s);
    zcl_command_reply_free(&s.inner);
    return ag_cleanup(s.dir, s.path, reply, zcl_package_copy_confirmed(input) && (ok || reply->error.mutated)) && ok;
}

static bool ag_hex(const char *text, size_t bytes)
{
    uint8_t value[33];
    return text && strlen(text) == bytes * 2u && bytes <= sizeof(value) &&
           zcl_hex_decode_lower(text, value, bytes);
}

struct ag_request {
    const struct json_value *input;
    struct zcl_command_reply *reply;
    const char *name, *root, *publisher, *offer, *datadir;
    char token[33];
    struct zcl_app_offer_row *rows;
    size_t count;
};

static bool ag_no_name_fields(const struct ag_request *r)
{
    const char *keys[] = {"root", "publisher", "offer_id", "token", "plan_id", "confirm"};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
        if (json_get(r->input, keys[i])) return true;
    return false;
}

static bool ag_validate(struct ag_request *r)
{
    if (!r->name && ag_no_name_fields(r)) {
        zcl_package_copy_fail(r->reply, "BAD_INPUT", false,
                              "an app name is required for selection or confirmation", AG_COMMAND);
        return false;
    }
    bool confirmed = zcl_package_copy_confirmed(r->input);
    if ((confirmed && !ag_hex(r->offer, 32)) ||
        (r->offer && (!ag_hex(r->offer, 32) || (!r->root && !confirmed))) ||
        !!r->root != !!r->publisher ||
        (r->root && (!ag_hex(r->root, 32) || !ag_hex(r->publisher, 33)))) {
        zcl_package_copy_fail(r->reply, "BAD_IDENTITY", false,
            "supply both full lowercase root and publisher, or neither", AG_COMMAND);
        return false;
    }
    return true;
}

static bool ag_token(struct ag_request *r)
{
    const char *given = zcl_package_copy_str(r->input, "token");
    uint8_t bytes[16];
    if (zcl_package_copy_confirmed(r->input)) {
        if (!given || !ag_hex(given, 16)) {
            zcl_package_copy_fail(r->reply, "BAD_TOKEN", false, "confirm requires its plan token", AG_COMMAND);
            return false;
        }
        (void)snprintf(r->token, sizeof(r->token), "%s", given);
    } else {
        if (given || !rng_host_fill(bytes, sizeof(bytes))) {
            zcl_package_copy_fail(r->reply, "BAD_TOKEN", false, "cannot create a fresh plan token", AG_COMMAND);
            return false;
        }
        zcl_hex_encode(bytes, sizeof(bytes), r->token);
    }
    return true;
}

static void ag_ambiguous(struct ag_request *r, const struct zcl_app_offer *a,
                         const struct zcl_app_offer *b)
{
    char first[512], second[512];
    int x = snprintf(first, sizeof(first), "z23 app get %s --root=%s --publisher=%s",
                     r->name, a->root, a->publisher);
    int y = snprintf(second, sizeof(second), "z23 app get %s --root=%s --publisher=%s",
                     r->name, b->root, b->publisher);
    zcl_package_copy_fail(r->reply, "AMBIGUOUS", false,
                          "multiple app identities match; select an exact root and publisher", AG_COMMAND);
    if (x > 0 && (size_t)x < sizeof(first)) (void)json_push_kv_str(&r->reply->data, "choice_a", first);
    if (y > 0 && (size_t)y < sizeof(second)) (void)json_push_kv_str(&r->reply->data, "choice_b", second);
}

static const struct zcl_app_offer *ag_identity(struct ag_request *r)
{
    const struct zcl_app_offer *identity = NULL;
    for (size_t i = 0; i < r->count; i++) {
        const struct zcl_app_offer *o = &r->rows[i].offer;
        if (strcmp(o->name, r->name) || (r->root &&
            (strcmp(o->root, r->root) || strcmp(o->publisher, r->publisher)))) continue;
        if (identity && !ag_same_identity(identity, o)) {
            ag_ambiguous(r, identity, o); return NULL;
        }
        identity = o;
    }
    if (!identity) zcl_package_copy_fail(r->reply, "NOT_IN_CATALOG", false, "no matching signed offer held by this node", AG_COMMAND);
    return identity;
}

static void ag_limit(struct ag_request *r, const struct zcl_app_offer *identity,
                     const struct zcl_app_offer_row *row)
{
    char next[768];
    int n = snprintf(next, sizeof(next), "z23 app get %s --root=%s --publisher=%s --offer=%s",
                     r->name, identity->root, identity->publisher, row->post_id);
    zcl_package_copy_fail(r->reply, "ATTEMPT_LIMIT", false,
                          "automatic endpoint limit reached; select another offer", AG_COMMAND);
    if (n > 0 && (size_t)n < sizeof(next)) (void)json_push_kv_str(&r->reply->data, "next_offer", next);
}

static bool ag_attempt(struct ag_request *r, const struct zcl_app_offer_row *row,
                       int64_t timeout_s, struct zcl_command_error *last)
{
    struct zcl_command_reply attempt;
    zcl_command_reply_init(&attempt, "zcl.app_get.v1");
    bool ok = ag_plan_one(row, r->datadir, r->input, r->token, timeout_s, &attempt);
    if (ok) {
        if (!json_copy_checked(&r->reply->data, &attempt.data))
            zcl_package_copy_fail(r->reply, "ALLOC", zcl_package_copy_confirmed(r->input), "copying result", AG_COMMAND);
    } else {
        *last = attempt.error;
        if (zcl_package_copy_confirmed(r->input))
            (void)json_copy_checked(&r->reply->data, &attempt.data);
    }
    zcl_command_reply_free(&attempt); return ok;
}

static void ag_attempts(struct ag_request *r, const struct zcl_app_offer *identity)
{
    size_t attempted = 0;
    int64_t deadline = platform_time_monotonic_ms() + AG_BUDGET_MS;
    struct zcl_command_error last = {0};
    for (size_t i = 0; i < r->count; i++) {
        if (!ag_same_identity(identity, &r->rows[i].offer)) continue;
        if (r->offer && strcmp(r->offer, r->rows[i].post_id)) continue;
        int64_t remaining = deadline - platform_time_monotonic_ms();
        if (remaining <= 0) {
            zcl_package_copy_fail(r->reply, "FETCH_TIMEOUT", false, "total endpoint fetch budget expired", AG_COMMAND);
            return;
        }
        if (attempted == AG_ATTEMPTS) { ag_limit(r, identity, &r->rows[i]); return; }
        attempted++;
        if (ag_attempt(r, &r->rows[i], (remaining + 999) / 1000, &last)) return;
        if (zcl_package_copy_confirmed(r->input) || r->offer ||
            strcmp(last.code, "TEMP_CLEANUP_FAILED") == 0) break;
    }
    if (attempted && last.code[0])
        zcl_command_reply_fail(r->reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                               last.code, "execute", last.retryable, last.mutated, last.message, last.evidence);
    else zcl_package_copy_fail(r->reply, "OFFER_UNAVAILABLE", false, "no matching endpoint could be verified", AG_COMMAND);
}

void zcl_native_handle_app_get(const struct zcl_command_request *request,
                               struct zcl_command_reply *reply)
{
    struct ag_request r = {.input = request ? request->input : NULL, .reply = reply};
    r.name = zcl_package_copy_str(r.input, "name");
    r.root = zcl_package_copy_str(r.input, "root");
    r.publisher = zcl_package_copy_str(r.input, "publisher");
    r.offer = zcl_package_copy_str(r.input, "offer_id");
    r.datadir = zcl_package_copy_datadir(r.input, reply, AG_COMMAND);
    if (!r.datadir || !ag_validate(&r)) return;
    r.rows = zcl_calloc(ZCL_APP_OFFER_ROWS_MAX, sizeof(*r.rows), "app.get.catalog");
    if (!r.rows) { zcl_package_copy_fail(reply, "ALLOC", false, "catalog allocation", AG_COMMAND); return; }
    struct zcl_command_reply why;
    if (!zcl_app_offer_catalog(r.rows, ZCL_APP_OFFER_ROWS_MAX, &r.count, &why)) {
        zcl_app_inner_fail(reply, &why, false);
        zcl_command_reply_free(&why); free(r.rows); return;
    }
    zcl_command_reply_free(&why);
    if (!r.name) {
        if (!ag_list(reply, r.rows, r.count)) zcl_package_copy_fail(reply, "ALLOC", false, "catalog output", AG_COMMAND);
    } else if (ag_token(&r)) {
        const struct zcl_app_offer *identity = ag_identity(&r);
        if (identity) ag_attempts(&r, identity);
    }
    free(r.rows);
    if (zcl_package_copy_confirmed(request->input) &&
        (reply->status == ZCL_COMMAND_STATUS_PASSED || reply->error.mutated))
        zcl_app_bound_committed_result(request, reply, AG_COMMAND);
}
