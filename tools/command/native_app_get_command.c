/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: verify a public catalog offer before asking to receive an app. */
#include "command/native_command.h"
#include "command/native_app_compose.h"
#include "command/native_app_front_door.h"
#include "command/native_app_offer.h"
#include "command/native_app_get_stage.h"
#include "command/native_app_network_row.h"
#include "command/native_app_fetch_progress.h"
#include "command/native_dev_land_remote_shared.h"
#include "command/native_zcode_package_copy.h"
#include "command/app_image.h"
#include "base/safe_alloc.h"
#include "base/hex.h"
#include "json/json.h"
#include "vcs/bundle_carry.h"
#include "platform/time_compat.h"
#include "platform/rng.h"
#include "platform/private_directory.h"
#include "platform/directory_compat.h"
#include "platform/directory_transaction.h"
#include <fcntl.h>
#include "platform/toolchain.h"
#include <dirent.h>
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
    /* Set by the fetch worker so a caller that could not show the
     * download window can still use the fetch that already ran. */
    bool fetch_ran, fetch_ok;
    int64_t fetch_timeout_s;
};

struct ag_private_stage {
    struct platform_directory_transaction dir;
    int parent;
    char anchor[AG_PATH], leaf[48];
};
#if !defined(_WIN32)
static bool ag_same_stat(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && S_ISDIR(a->st_mode) && S_ISDIR(b->st_mode);
}
#endif
static bool ag_private_bound(const struct ag_private_stage *p, const char *path)
{
#if defined(_WIN32)
    (void)p; (void)path; return false;
#else
    struct stat parent, parent_path, held, named, full;
    return fstat(p->parent, &parent) == 0 && lstat(p->anchor, &parent_path) == 0 &&
        ag_same_stat(&parent, &parent_path) && fstat((int)p->dir.native, &held) == 0 &&
        fstatat(p->parent, p->leaf, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        lstat(path, &full) == 0 && ag_same_stat(&held, &named) && ag_same_stat(&held, &full);
#endif
}
static bool ag_private_create(struct ag_private_stage *p, struct ag_one *s, const char *anchor)
{
    memset(p, 0, sizeof(*p)); p->parent = -1; platform_directory_transaction_init(&p->dir);
#if defined(_WIN32)
    (void)s; (void)anchor; return false;
#else
    if (strlen(anchor) >= sizeof(p->anchor)) return false;
    memcpy(p->anchor, anchor, strlen(anchor) + 1);
    int n = snprintf(p->leaf, sizeof(p->leaf), ".app-get-%s", s->token);
    int d = snprintf(s->dir, sizeof(s->dir), "%s/%s", anchor, p->leaf);
    int f = snprintf(s->path, sizeof(s->path), "%s/offer.z23share", s->dir);
    if (n <= 0 || (size_t)n >= sizeof(p->leaf) || d <= 0 || (size_t)d >= sizeof(s->dir) ||
        f <= 0 || (size_t)f >= sizeof(s->path)) return false;
    p->parent = open(anchor, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if (p->parent < 0 || fstat(p->parent, &st) || st.st_uid != geteuid() || (st.st_mode & 022)) return false;
    if (mkdirat(p->parent, p->leaf, 0700) != 0) return false;
    s->created = true; /* later failures can leave the exclusive child behind */
    return fsync(p->parent) == 0 &&
        platform_directory_transaction_bootstrap_child(anchor, p->leaf, false, &p->dir) == PLATFORM_DIRECTORY_OK &&
        ag_private_bound(p, s->dir);
#endif
}
static bool ag_private_cleanup(struct ag_private_stage *p, struct ag_one *s)
{
    bool ok = false;
#if defined(_WIN32)
    (void)s;
#else
    if (s->created && ag_private_bound(p, s->dir)) {
        int fd = (int)p->dir.native;
        ok = (unlinkat(fd, "offer.z23share", 0) == 0 || errno == ENOENT) &&
            ag_private_bound(p, s->dir) && unlinkat(p->parent, p->leaf, AT_REMOVEDIR) == 0 && fsync(p->parent) == 0;
    }
#endif
    platform_directory_transaction_close(&p->dir);
    if (p->parent >= 0) close(p->parent);
    return ok;
}
struct app_private_stage {
    struct ag_private_stage private;
    struct ag_one one;
    char token[33];
};
bool app_private_stage_open(const char *anchor, struct app_private_stage **out,
                            struct zcl_command_reply *reply)
{
    if (!out || !reply) return false;
    *out = NULL;
    struct app_private_stage *s = zcl_calloc(1, sizeof(*s), "app-private-stage");
    uint8_t random[16];
    if (!s || !anchor || !rng_host_fill(random, sizeof(random))) {
        free(s); zcl_package_copy_fail(reply, "TEMP_UNAVAILABLE", false, "Cannot create private staging.", AG_COMMAND); return false;
    }
    zcl_hex_encode(random, sizeof(random), s->token);
    s->one.token = s->token;
    if (!ag_private_create(&s->private, &s->one, anchor)) {
        bool cleaned = s->one.created && ag_private_cleanup(&s->private, &s->one);
        if (!s->one.created) { platform_directory_transaction_close(&s->private.dir); if (s->private.parent >= 0) close(s->private.parent); }
        zcl_package_copy_fail(reply, "TEMP_UNAVAILABLE", s->one.created && !cleaned, "Cannot safely create private staging.", s->one.dir);
        free(s); return false;
    }
    *out = s; return true;
}
const char *app_private_stage_path(const struct app_private_stage *s)
{ return s ? s->one.path : NULL; }
bool app_private_stage_matches(const struct app_private_stage *s, const char *sha256, int64_t size)
{
    if (!s || !sha256 || strlen(sha256) != 64 || size < 0) return false;
    struct zcl_app_offer expected = {0};
    memcpy(expected.sha256, sha256, 65); expected.size = size;
    return ag_private_bound(&s->private, s->one.dir) && ag_hash(s->one.path, &expected);
}
bool app_private_stage_close(struct app_private_stage *s)
{
    if (!s) return false;
    bool ok = ag_private_cleanup(&s->private, &s->one); free(s); return ok;
}

/* An interrupted get (Ctrl-C, crash, kill) leaves its private staging
 * directory <datadir>/.app-get-<token> behind and nothing in-process ever
 * removes it. Sweep only an exact-shaped orphan: a ".app-get-" + 32-hex
 * token name, a directory owned by this euid and private (0700), holding
 * nothing beyond the staged carrier, and cold for a full day — a live get
 * (one fetch budget plus its build) can never look that old, so no
 * concurrent staging is touched. Anything else (short or non-hex names,
 * links, permissive modes, extra content, young dirs) is left alone, and
 * a directory that will not empty is left whole. Best effort: a sweep
 * that cannot run never fails the get. */
#define AG_ORPHAN_AGE_S ((int64_t)24 * 60 * 60)
static bool ag_orphan_leaf(const char *name)
{
    return strlen(name) == 41 && strncmp(name, ".app-get-", 9) == 0 &&
           ag_hex(name + 9, 16);
}
static void ag_orphan_sweep(const char *datadir)
{
#if defined(_WIN32)
    (void)datadir;
#else
    DIR *dir = opendir(datadir);
    if (!dir) return;
    int fd = dirfd(dir);
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        struct stat st;
        char carrier[64];
        if (!ag_orphan_leaf(entry->d_name) ||
            fstatat(fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0 ||
            !S_ISDIR(st.st_mode) || st.st_uid != geteuid() ||
            (st.st_mode & 07777) != 0700 ||
            platform_time_wall_unix() - (int64_t)st.st_mtime < AG_ORPHAN_AGE_S)
            continue;
        (void)snprintf(carrier, sizeof(carrier), "%s/offer.z23share",
                       entry->d_name);
        (void)unlinkat(fd, carrier, 0);
        (void)unlinkat(fd, entry->d_name, AT_REMOVEDIR); /* only if empty */
    }
    closedir(dir);
#endif
}

/* ag_stage outcome: the carrier is staged and hash-verified (AG_STAGED),
 * the download window was closed so nothing is received (AG_CANCELED), or
 * the fetch or verification failed and the reply says why (AG_FAILED). */
enum ag_stage_result { AG_STAGED, AG_CANCELED, AG_FAILED };
/* ag_stage_fetch outcome: staged, canceled by the download window, or
 * failed with the refusal already forwarded to the reply. */
enum ag_stage_fetch { AG_FETCH_STAGED, AG_FETCH_CANCELED, AG_FETCH_FAILED };
static enum ag_stage_fetch ag_stage_fetch(struct ag_one *s, int64_t timeout_s);

static enum ag_stage_result ag_stage(struct ag_one *s, int64_t timeout_s)
{
    int n = snprintf(s->dir, sizeof(s->dir), "%s/.app-get-%s", s->datadir, s->token);
    if (n <= 0 || (size_t)n >= sizeof(s->dir) ||
        snprintf(s->path, sizeof(s->path), "%s/offer.z23share", s->dir) >= (int)sizeof(s->path) ||
        !platform_private_directory_create(s->dir)) {
        zcl_package_copy_fail(s->reply, "TEMP_UNAVAILABLE", false, "cannot create private get directory", AG_COMMAND);
        return AG_FAILED;
    }
    s->created = true;
    enum ag_stage_fetch fetched = ag_stage_fetch(s, timeout_s);
    if (fetched != AG_FETCH_STAGED) return fetched == AG_FETCH_CANCELED ? AG_CANCELED : AG_FAILED;
    if (!ag_hash(s->path, &s->row->offer)) {
        zcl_package_copy_fail(s->reply, "SHA256_MISMATCH", false, "fetched bytes do not match the offer", AG_COMMAND);
        return AG_FAILED;
    }
    return AG_STAGED;
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
static const struct json_value *ag_rebuild_envelope(const struct json_value *wire, const char *command)
{
    const char *actual = zcl_package_copy_str(wire, "command"), *status = zcl_package_copy_str(wire, "status");
    const struct json_value *ok = json_get(wire, "ok"), *data = json_get(wire, "data");
    return actual && !strcmp(actual, command) && status && !strcmp(status, "passed") &&
        ok && ok->type == JSON_BOOL && json_get_bool(ok) && data && data->type == JSON_OBJ ? data : NULL;
}
enum app_get_rebuild_state app_get_rebuild_prepare(const struct zcl_app_offer_row *row,
    const struct json_value *wire, const struct json_value *open_wire, struct zcl_app_rebuild *observation)
{
    const struct json_value *data = ag_rebuild_envelope(wire, "app.build"), *made = json_get(data, "make_ran");
    const struct json_value *opened = ag_rebuild_envelope(open_wire, "app.open");
    const char *image = zcl_package_copy_str(opened, "image_sha3");
    const char *version = zcl_package_copy_str(data, "version"), *open_version = zcl_package_copy_str(opened, "version");
    const char *package = zcl_package_copy_str(data, "package_root"), *open_package = zcl_package_copy_str(opened, "package_root");
    if (!row || !observation || !data || !opened || !made || made->type != JSON_BOOL)
        return APP_GET_REBUILD_INVALID;
    if (!version || !open_version || strcmp(version, open_version) || !package || !open_package || strcmp(package, open_package))
        return APP_GET_REBUILD_INVALID;
    struct ag_one s = {.row = row};
    if (!ag_observation(&s, data, image, observation)) return APP_GET_REBUILD_INVALID;
    return json_get_bool(made) ? APP_GET_REBUILD_FRESH : APP_GET_REBUILD_CACHED;
}
bool app_get_rebuild_publish(const struct zcl_app_rebuild *observation, struct zcl_command_reply *reply)
{
    if (!observation || !reply) return false;
    ag_rebuild_post(&reply->data, observation);
    const char *status = zcl_package_copy_str(&reply->data, "rebuild_report");
    const char *id = zcl_package_copy_str(&reply->data, "rebuild_post_id");
    const char *retry = zcl_package_copy_str(&reply->data, "rebuild_retry_text");
    if (!status || (!strcmp(status, "published") ? !ag_hex(id, 32) : !retry)) {
        app_get_rebuild_result_unavailable(reply);
        return false;
    }
    struct zcl_command_reply why; size_t count = 0;
    bool counted = zcl_app_rebuild_count(observation, &count, &why);
    bool described = counted ? json_push_kv_int(&reply->data, "matching_rebuild_keys", (int64_t)count) &&
        json_push_kv_str(&reply->data, "rebuild_count_status", "local snapshot; global count unknown") :
        json_push_kv_str(&reply->data, "rebuild_count_status", "incomplete: board query unavailable or capped");
    zcl_command_reply_free(&why);
    if (!described) app_get_rebuild_result_unavailable(reply);
    return described;
}
void app_get_rebuild_result_unavailable(struct zcl_command_reply *reply)
{
    if (!reply) return;
    struct json_value facts; json_init(&facts); json_set_object(&facts);
    const char *keys[] = {"rebuild_report", "rebuild_post_id", "rebuild_retry_text"};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        const struct json_value *value = json_get(&reply->data, keys[i]);
        if (value) (void)json_push_kv(&facts, keys[i], value);
    }
    (void)json_push_kv(&reply->data, "failure_facts", &facts); json_free(&facts);
    zcl_package_copy_fail(reply, "REBUILD_RESULT_UNAVAILABLE", true,
        "the copy remains; the public report may have been posted, so inspect before retrying", AG_COMMAND);
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
            "the received copy remains; hosting may already be enabled, so inspect hosting before retrying", AG_COMMAND);
        return;
    }
    s->reply->error.mutated = true;
    size_t n = strlen(s->reply->error.message);
    if (n < sizeof(s->reply->error.message))
        (void)snprintf(s->reply->error.message + n, sizeof(s->reply->error.message) - n,
                       "; hosting outcome could not be reported");
}
static void ag_host_failure_facts(struct zcl_command_reply *reply, const char *host,
    const char *carrier, int64_t generation)
{
    struct json_value *facts = NULL;
    for (size_t i = 0; i < reply->data.num_children; ++i)
        if (!strcmp(reply->data.keys[i], "failure_facts")) facts = &reply->data.children[i];
    if (!facts) {
        struct json_value empty; json_init(&empty); json_set_object(&empty);
        bool added = json_push_kv(&reply->data, "failure_facts", &empty); json_free(&empty);
        if (!added) return;
        facts = &reply->data.children[reply->data.num_children - 1];
    }
    if (facts->type != JSON_OBJ) return;
    (void)(json_push_kv_bool(facts, "hosting_enabled", true) &&
        json_push_kv_str(facts, "hosting_host", host) &&
        json_push_kv_str(facts, "hosting_carrier", carrier) &&
        json_push_kv_int(facts, "hosting_generation", generation));
}
void app_get_host_result_unavailable(struct zcl_command_reply *reply)
{
    if (!reply) return;
    const char *host = zcl_package_copy_str(&reply->data, "hosting_host");
    const char *carrier = zcl_package_copy_str(&reply->data, "hosting_carrier");
    const struct json_value *generation = json_get(&reply->data, "hosting_generation");
    bool enabled = ag_hex(host, 32) && ag_hex(carrier, 32) && generation &&
        generation->type == JSON_INT && json_get_int(generation) > 0;
    char saved_host[65] = {0}, saved_carrier[65] = {0}; int64_t saved_generation = 0;
    if (enabled) {
        memcpy(saved_host, host, sizeof(saved_host)); memcpy(saved_carrier, carrier, sizeof(saved_carrier));
        saved_generation = json_get_int(generation);
    }
    struct ag_one s = {.reply = reply};
    ag_host_report_failure(&s);
    if (enabled) ag_host_failure_facts(reply, saved_host, saved_carrier, saved_generation);
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
    if (!hints || !reported) {
        ag_host_report_failure(s);
        ag_host_failure_facts(s->reply, host, carrier, json_get_int(generation));
    }
}
#ifdef ZCL_TESTING
void zcl_test_app_get_host_enabled(const char *datadir, const char *host, const char *carrier,
    struct zcl_command_reply *reply)
{
    struct ag_one s = {.datadir = datadir, .reply = reply};
    struct json_value generation; json_init(&generation); json_set_int(&generation, 1);
    ag_host_enabled(&s, host, carrier, &generation); json_free(&generation);
}
#endif

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
        if (!json_push_kv_str(data, "hosting_status", "no pin attempted: staged carrier changed"))
            ag_host_report_failure(s);
        return;
    }
    struct json_value in; struct zcl_command_reply inner;
    const char *kv[] = {"file", s->path};
    bool built = zcl_app_input(&in, kv, 2);
    bool ok = built && zcl_app_offer_call(ZCL_APP_OFFER_BUNDLE_OFFER, &in, &inner);
    json_free(&in); if (!built) zcl_command_reply_init(&inner, "zcl.app_get.host.v1");
    if (!ok || !ag_host_offer_matches(&inner, &s->row->offer, NULL, NULL)) {
        bool reported = json_push_kv_str(data, "hosting_status", "not advertised: carrier pin was refused or unconfirmed; storage may have changed") &&
            json_push_kv_str(data, "hosting_retry", "check node hosting and get the app again to offer its carrier");
        if (!reported) ag_host_report_failure(s);
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
    struct ag_one s = {.row = row, .datadir = datadir, .input = input, .token = token,
        .reply = reply, .fetch_timeout_s = timeout_s};
    enum ag_stage_result staged = ag_stage(&s, timeout_s);
    if (staged == AG_CANCELED) return ag_cleanup(s.dir, s.path, reply, false);
    if (staged == AG_FAILED) {
        zcl_command_reply_free(&s.inner);
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

static bool ag_row_bounded(const struct zcl_app_offer_row *r)
{
    const struct zcl_app_offer *o = &r->offer;
    return memchr(o->name, 0, sizeof(o->name)) && memchr(o->root, 0, sizeof(o->root)) &&
        memchr(o->publisher, 0, sizeof(o->publisher)) && memchr(o->carrier, 0, sizeof(o->carrier)) &&
        memchr(o->sha256, 0, sizeof(o->sha256)) && memchr(o->onion, 0, sizeof(o->onion)) &&
        memchr(r->post_id, 0, sizeof(r->post_id)) && memchr(r->host, 0, sizeof(r->host)) &&
        ag_hex(r->post_id, 32) && ag_hex(r->host, 32) && zcl_app_offer_valid(o);
}
static bool ag_stage_identity(const struct ag_one *s, struct app_receive_identity *identity)
{
    const char *release = zcl_app_inner_str(&s->inner, "release_id");
    const char *root = zcl_app_inner_str(&s->inner, "package_root");
    const char *publisher = zcl_app_inner_str(&s->inner, "publisher_fingerprint");
    return ag_hex(release, 32) && ag_hex(root, 32) && ag_hex(publisher, 33) &&
        zcl_hex_decode_lower(release, identity->release_id, 32) &&
        zcl_hex_decode_lower(root, identity->package_root, 32) &&
        zcl_hex_decode_lower(publisher, identity->publisher, 33);
}
static void ag_consume_host(struct ag_one *s, struct ag_private_stage *private, bool host_original)
{
    if (!host_original || s->reply->status != ZCL_COMMAND_STATUS_PASSED) return;
    if (ag_private_bound(private, s->dir)) ag_rehost(s);
    else zcl_package_copy_fail(s->reply, "TEMP_CHANGED", s->reply->error.mutated,
        "the private staging directory changed before hosting", AG_COMMAND);
}
static bool ag_progress_fetch(void *work)
{
    struct ag_one *s = work;
    s->fetch_ran = true;
    return s->fetch_ok = ag_fetch(s->row, s->path,
        s->fetch_timeout_s > 0 ? s->fetch_timeout_s : AG_BUDGET_MS / 1000, &s->inner);
}
/* Forward the fetch worker's own refusal; nothing may override it. */
static void ag_fetch_refused(struct ag_one *s)
{
    zcl_app_inner_fail(s->reply, &s->inner, false);
    zcl_command_reply_free(&s->inner);
}
/* The window could not be shown. The worker may already have fetched, and
   that outcome — not a second fetch — is the honest one. */
static bool ag_unshown_fetch(struct ag_one *s)
{
    return s->fetch_ran ? s->fetch_ok : ag_progress_fetch(s);
}
/* The confirmed half re-fetches the carrier with no output of its own for
 * up to the whole fetch budget. Surface the same bounded download window
 * the Discover room shows (app_fetch_progress_run), so the wait is visible
 * and closing the window cancels before any receive plan runs. A caller
 * that cannot show the window keeps the plain silent fetch instead of
 * failing the get. */
#ifdef ZCL_TESTING
/* Injected only by tests; NULL shows the default native download window. */
static app_confirm_presenter ag_confirm_presenter;
static void *ag_confirm_presenter_context;
#endif
static enum ag_stage_fetch ag_confirmed_fetch(struct ag_one *s)
{
    enum app_fetch_progress_result result;
#ifdef ZCL_TESTING
    result = app_fetch_progress_run(ag_progress_fetch, s,
        ag_confirm_presenter, ag_confirm_presenter_context);
#else
    result = app_fetch_progress_run(ag_progress_fetch, s, NULL, NULL);
#endif
    if (result == APP_FETCH_CLOSED) {
        zcl_command_reply_free(&s->inner);
        if (json_push_kv_str(&s->reply->data, "status", "canceled")) return AG_FETCH_CANCELED;
        zcl_package_copy_fail(s->reply, "ALLOC", false, "Cannot report that the download was closed.", AG_COMMAND);
        return AG_FETCH_FAILED;
    }
    if (result == APP_FETCH_UNAVAILABLE) result = ag_unshown_fetch(s) ? APP_FETCH_OK : APP_FETCH_FAILED;
    if (result != APP_FETCH_OK) ag_fetch_refused(s);
    return result == APP_FETCH_OK ? AG_FETCH_STAGED : AG_FETCH_FAILED;
}
static enum ag_stage_fetch ag_stage_fetch(struct ag_one *s, int64_t timeout_s)
{
    if (!zcl_package_copy_confirmed(s->input)) {
        if (ag_fetch(s->row, s->path, timeout_s, &s->inner)) return AG_FETCH_STAGED;
        ag_fetch_refused(s);
        return AG_FETCH_FAILED;
    }
    return ag_confirmed_fetch(s);
}
#ifdef ZCL_TESTING
void zcl_test_app_get_confirm_presenter(app_confirm_presenter presenter, void *context)
{
    ag_confirm_presenter = presenter;
    ag_confirm_presenter_context = context;
}
#endif
static enum app_fetch_progress_result ag_run_fetch(struct ag_one *s, bool progress,
    app_confirm_presenter presenter, void *presenter_context)
{
    return progress ? app_fetch_progress_run(ag_progress_fetch, s, presenter, presenter_context) :
        (ag_progress_fetch(s) ? APP_FETCH_OK : APP_FETCH_FAILED);
}
static bool ag_fetch_ready(struct ag_one *s, enum app_fetch_progress_result result)
{
    if (result == APP_FETCH_CLOSED) {
        zcl_command_reply_free(&s->inner);
        if (json_push_kv_str(&s->reply->data, "status", "canceled")) return true;
        zcl_package_copy_fail(s->reply, "ALLOC", false, "Cannot report that the download was closed.", AG_COMMAND);
        return false;
    }
    if (result == APP_FETCH_UNAVAILABLE) {
        zcl_command_reply_free(&s->inner);
        zcl_package_copy_fail(s->reply, "FETCH_PROGRESS_UNAVAILABLE", false, "Cannot display download progress.", AG_COMMAND);
        return false;
    }
    return result == APP_FETCH_OK;
}
static bool ag_staged_identity(struct ag_one *s, struct ag_private_stage *private,
    struct app_receive_identity *identity)
{
    if (!ag_private_bound(private, s->dir) || !ag_hash(s->path, &s->row->offer)) {
        zcl_package_copy_fail(s->reply, "SHA256_MISMATCH", false, "fetched bytes or staging identity changed", AG_COMMAND); return false;
    }
    if (!ag_receive_plan(s)) return false;
    if (!ag_stage_identity(s, identity)) {
        zcl_package_copy_fail(s->reply, "MALFORMED_INNER", false, "verified receive identity is incomplete", AG_COMMAND); return false;
    }
    if (!ag_private_bound(private, s->dir)) {
        zcl_package_copy_fail(s->reply, "TEMP_CHANGED", false, "the private staging directory changed", AG_COMMAND); return false;
    }
    return true;
}
static bool ag_consume_staged(struct ag_one *s, struct ag_private_stage *private,
    app_get_stage_consumer consumer, void *context, bool progress, app_confirm_presenter presenter, void *presenter_context)
{
    struct zcl_command_reply *reply = s->reply;
    enum app_fetch_progress_result result = ag_run_fetch(s, progress, presenter, presenter_context);
    if (result == APP_FETCH_CLOSED || result == APP_FETCH_UNAVAILABLE) return ag_fetch_ready(s, result);
    bool ok = result == APP_FETCH_OK;
    if (!ok) zcl_app_inner_fail(reply, &s->inner, false);
    zcl_command_reply_free(&s->inner);
    struct app_receive_identity identity;
    if (ok) ok = ag_staged_identity(s, private, &identity);
    bool host_original = false;
    if (ok) ok = consumer(context, s->path, &identity, reply, &host_original);
    if (ok) ag_consume_host(s, private, host_original);
    if (!ok && reply->status == ZCL_COMMAND_STATUS_PASSED)
        zcl_package_copy_fail(reply, "CONSUMER_FAILED", reply->error.mutated, "staged carrier consumer failed", AG_COMMAND);
    if (reply->status != ZCL_COMMAND_STATUS_PASSED) ok = false;
    zcl_command_reply_free(&s->inner);
    return ok;
}
static bool ag_consume_one(const struct zcl_app_offer_row *row, const char *dir, const char *anchor,
    app_get_stage_consumer consumer, void *context, struct zcl_command_reply *reply,
    bool progress, app_confirm_presenter presenter, void *presenter_context)
{
    uint8_t random[16]; char token[33];
    if (!rng_host_fill(random, sizeof(random))) {
        zcl_package_copy_fail(reply, "BAD_TOKEN", false, "cannot create a fresh staging token", AG_COMMAND); return false;
    }
    zcl_hex_encode(random, sizeof(random), token);
    struct ag_one s = {.row = row, .datadir = dir, .token = token, .reply = reply};
    struct ag_private_stage private;
    if (!ag_private_create(&private, &s, anchor)) {
        bool cleaned = s.created && ag_private_cleanup(&private, &s);
        if (!s.created) { platform_directory_transaction_close(&private.dir); if (private.parent >= 0) close(private.parent); }
        zcl_package_copy_fail(reply, "TEMP_UNAVAILABLE", s.created && !cleaned,
            "cannot safely create private staging", s.dir);
        return false;
    }
    bool ok = ag_consume_staged(&s, &private, consumer, context, progress, presenter, presenter_context);
    if (!ag_private_cleanup(&private, &s)) {
        zcl_package_copy_fail(reply, "TEMP_CLEANUP_FAILED", true,
            "private staging could not be safely removed", s.dir); return false;
    }
    return ok;
}
/* Stage only parent-verified bytes after the network child is reaped. */
static bool ag_write_owned_bytes(struct ag_private_stage *p, struct ag_one *s,
                                 const uint8_t *bytes, size_t len)
{
#if defined(_WIN32)
    (void)p; (void)s; (void)bytes; (void)len; return false;
#else
    if (!bytes || !len || !ag_private_bound(p, s->dir)) return false;
    int fd = openat((int)p->dir.native, "offer.z23share",
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, bytes + off, len - off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        off += (size_t)n;
    }
    bool ok = off == len && fsync(fd) == 0;
    if (close(fd) != 0) ok = false;
    return ok && ag_private_bound(p, s->dir) && ag_hash(s->path, &s->row->offer);
#endif
}
/* Integration must run Receive plan on the staged path, decode its independently
 * verified release/root/publisher into app_receive_identity, recheck stage binding,
 * and invoke the existing synchronous consumer. Cleanup failure remains primary
 * TEMP_CLEANUP_FAILED with mutated=true, preserving post-commit recovery facts.
 * Never accept a child-provided path, skip the plan, or launch the consumer before
 * parent-side size/SHA and the staged-file hash both match the selected offer. */

/* Receive verification and consumer use the same retained stage. */
static bool ag_consume_verified_bytes(struct ag_one *s, struct ag_private_stage *private,
    const uint8_t *bytes, size_t len, app_get_bytes_consumer consumer, void *context)
{
    struct zcl_command_reply *reply = s->reply;
    if (len != (size_t)s->row->offer.size ||
        !ag_write_owned_bytes(private, s, bytes, len)) {
        zcl_package_copy_fail(reply, "SHA256_MISMATCH", false,
            "verified carrier or private staging changed", AG_COMMAND);
        return false;
    }
    bool ok = ag_receive_plan(s);
    struct app_receive_identity identity;
    if (ok && !ag_stage_identity(s, &identity)) {
        zcl_package_copy_fail(reply, "MALFORMED_INNER", false,
            "verified receive identity is incomplete", AG_COMMAND); ok = false;
    }
    if (ok && !ag_private_bound(private, s->dir)) {
        zcl_package_copy_fail(reply, "TEMP_CHANGED", false,
            "the private staging directory changed", AG_COMMAND); ok = false;
    }
    if (ok) ok = consumer(context, s->path, &identity, reply);
    if (!ok && reply->status == ZCL_COMMAND_STATUS_PASSED)
        zcl_package_copy_fail(reply, "CONSUMER_FAILED", reply->error.mutated,
            "staged carrier consumer failed", AG_COMMAND);
    if (reply->status != ZCL_COMMAND_STATUS_PASSED) ok = false;
    zcl_command_reply_free(&s->inner);
    return ok;
}

/* Typed bytes entry does not perform RPC, rehost or implicitly confirm. */
static bool ag_bytes_valid(const struct zcl_app_offer_row *selected, const char *datadir,
    const uint8_t *bytes, size_t len, app_get_bytes_consumer consumer)
{
    return selected && consumer && datadir && datadir[0] == '/' && ag_row_bounded(selected) && bytes &&
        selected->offer.size > 0 && len <= VCS_BUNDLE_MAX_BYTES && len == (size_t)selected->offer.size;
}
bool app_get_stage_consume_bytes(const struct zcl_app_offer_row *selected,
    const char *datadir, const uint8_t *bytes, size_t len,
    app_get_bytes_consumer consumer, void *context, struct zcl_command_reply *reply)
{
    if (!reply) return false;
    char anchor[AG_PATH];
    if (!ag_bytes_valid(selected, datadir, bytes, len, consumer)) {
        zcl_package_copy_fail(reply, "BAD_INPUT", false,
            "a selected offer, absolute profile and exact carrier are required", AG_COMMAND);
        return false;
    }
    if (!app_receive_profile_validate(datadir, anchor, sizeof(anchor), reply)) return false;
    ag_orphan_sweep(anchor); /* room staging lives beside the profile, not the datadir */
    uint8_t random[16]; char token[33];
    if (!rng_host_fill(random, sizeof(random))) {
        zcl_package_copy_fail(reply, "BAD_TOKEN", false, "cannot create a fresh staging token", AG_COMMAND);
        return false;
    }
    zcl_hex_encode(random, sizeof(random), token);
    struct ag_one s = {.row = selected, .datadir = datadir, .token = token, .reply = reply};
    struct ag_private_stage private;
    if (!ag_private_create(&private, &s, anchor)) {
        bool cleaned = s.created && ag_private_cleanup(&private, &s);
        if (!s.created) { platform_directory_transaction_close(&private.dir); if (private.parent >= 0) close(private.parent); }
        zcl_package_copy_fail(reply, "TEMP_UNAVAILABLE", s.created && !cleaned,
            "cannot safely create private staging", s.dir);
        return false;
    }
    bool ok = ag_consume_verified_bytes(&s, &private, bytes, len, consumer, context);
    if (!ag_private_cleanup(&private, &s)) {
        zcl_package_copy_fail(reply, "TEMP_CLEANUP_FAILED", true,
            "private staging could not be safely removed", s.dir); return false;
    }
    return ok;
}

static bool ag_find_selected(const struct zcl_app_offer_row *selected,
    struct zcl_app_offer_row *row, struct zcl_command_reply *reply)
{
    struct zcl_command_reply why;
    bool ok = zcl_app_offer_exact(selected->post_id, row, &why);
    if (!ok) zcl_app_inner_fail(reply, &why, false);
    zcl_command_reply_free(&why);
    if (!ok) return false;
    if (app_network_row_equal(selected, row)) return true;
    zcl_package_copy_fail(reply, "OFFER_CHANGED", false, "the selected advertisement is no longer present", AG_COMMAND);
    return false;
}
static bool ag_stage_consume(const struct zcl_app_offer_row *selected, const char *datadir,
    app_get_stage_consumer consumer, void *context, struct zcl_command_reply *reply,
    bool progress, app_confirm_presenter presenter, void *presenter_context)
{
    if (!reply) return false;
    char anchor[AG_PATH];
    if (!selected || !consumer || !datadir || datadir[0] != '/' ||
        !ag_row_bounded(selected)) {
        zcl_package_copy_fail(reply, "BAD_INPUT", false, "a valid selected offer and absolute datadir are required", AG_COMMAND); return false;
    }
    if (!app_receive_profile_validate(datadir, anchor, sizeof(anchor), reply)) return false;
    ag_orphan_sweep(anchor); /* room staging lives beside the profile, not the datadir */
    struct zcl_app_offer_row *row = zcl_calloc(1, sizeof(*row), "app.get.offer");
    if (!row) { zcl_package_copy_fail(reply, "ALLOC", false, "offer allocation", AG_COMMAND); return false; }
    bool ok = ag_find_selected(selected, row, reply);
    if (ok) ok = ag_consume_one(row, datadir, anchor, consumer, context, reply, progress, presenter, presenter_context);
    free(row); return ok;
}
bool app_get_stage_consume(const struct zcl_app_offer_row *selected, const char *datadir,
    app_get_stage_consumer consumer, void *context, struct zcl_command_reply *reply)
{ return ag_stage_consume(selected, datadir, consumer, context, reply, false, NULL, NULL); }
bool app_get_stage_consume_progress(const struct zcl_app_offer_row *selected, const char *datadir,
    app_get_stage_consumer consumer, void *context, struct zcl_command_reply *reply, app_confirm_presenter presenter, void *presenter_context)
{ return ag_stage_consume(selected, datadir, consumer, context, reply, true, presenter, presenter_context); }

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
    /* zcl_app_hint embeds -datadir, so the suggested command still works
     * when the shell is not in the node's datadir. */
    char first[4900], second[4900];
    bool x = zcl_app_hint(first, sizeof(first), r->datadir,
                          "get %s --root=%s --publisher=%s",
                          r->name, a->root, a->publisher);
    bool y = zcl_app_hint(second, sizeof(second), r->datadir,
                          "get %s --root=%s --publisher=%s",
                          r->name, b->root, b->publisher);
    zcl_package_copy_fail(r->reply, "AMBIGUOUS", false,
                          "multiple app identities match; select an exact root and publisher", AG_COMMAND);
    if (x) (void)json_push_kv_str(&r->reply->data, "choice_a", first);
    if (y) (void)json_push_kv_str(&r->reply->data, "choice_b", second);
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
    char next[4900];
    bool built = zcl_app_hint(next, sizeof(next), r->datadir,
                              "get %s --root=%s --publisher=%s --offer=%s",
                              r->name, identity->root, identity->publisher,
                              row->post_id);
    zcl_package_copy_fail(r->reply, "ATTEMPT_LIMIT", false,
                          "automatic endpoint limit reached; select another offer", AG_COMMAND);
    if (built) (void)json_push_kv_str(&r->reply->data, "next_offer", next);
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

static bool ag_load_rows(struct ag_request *r)
{
    size_t capacity = r->offer ? 1 : ZCL_APP_OFFER_ROWS_MAX;
    r->rows = zcl_calloc(capacity, sizeof(*r->rows), "app.get.catalog");
    if (!r->rows) { zcl_package_copy_fail(r->reply, "ALLOC", false, "catalog allocation", AG_COMMAND); return false; }
    struct zcl_command_reply why;
    bool found = r->offer ? zcl_app_offer_exact(r->offer, r->rows, &why) :
        zcl_app_offer_catalog(r->rows, capacity, &r->count, &why);
    if (!found) zcl_app_inner_fail(r->reply, &why, false);
    zcl_command_reply_free(&why);
    if (found && r->offer) r->count = 1;
    return found;
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
    ag_orphan_sweep(r.datadir);
    if (!ag_load_rows(&r)) { free(r.rows); return; }
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
