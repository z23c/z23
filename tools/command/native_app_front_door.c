/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the `z23 app` front door (see native_app_front_door.h): one
 * plain command per journey step. It runs a leaf's plan half, prints it,
 * asks one y/N (or takes --yes), and runs the confirm half with the plan's
 * own plan_id. With no terminal and no --yes it plans only. */

#include "command/native_app_front_door.h"
#include "command/app_selection.h"
#include "command/native_app_launch.h"

#include "command/native_app_compose.h"
#include "command/native_command.h"
#include "command/native_zcode_package_bundle.h"

#include "base/hex.h"
#include "base/log_level.h"
#include "util/util.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "sha3/sha3.h"
#include "util/path_util.h"
#include "util/str_suffix.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define FD_FINGERPRINT_DOMAIN "zcl.app_fingerprint.v1"
#define FD_PATH 4400
#define FD_COPIES_MAX 16u

/* One front-door verb: the leaf it runs and the input key of its target. */
struct fd_verb {
    const char *verb;
    const char *path;
    const char *key;
    bool opens; /* the confirm also accepts the planned image */
};

static const struct fd_verb k_fd_verbs[] = {
    {"copy", "app.copy", "app", false},
    {"save", "app.save", "copy", false},
    {"build", "app.build", "copy", false},
    {"share", "app.share-copy", "copy", false},
    {"receive", "app.receive-copy", "file", false},
    {"publish", "app.publish", "copy", false},
    {"get", "app.get", "name", false},
    {"open", "app.run.copy", "copy", true},
};

/* ── the short fingerprint ───────────────────────────────────────────── */

/* The first 8 bytes of SHA3-256(domain 0x00 || key) as 16 hex. */
static void fd_key_digest_hex(const uint8_t key[33], char hex[17])
{
    uint8_t digest[32];
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const uint8_t *)FD_FINGERPRINT_DOMAIN,
                   sizeof(FD_FINGERPRINT_DOMAIN));
    sha3_256_write(&ctx, key, 33);
    sha3_256_finalize(&ctx, digest);
    zcl_hex_encode(digest, 8, hex);
}

bool zcl_app_publisher_namespace(const uint8_t key[33],
                                 char out[ZCL_APP_NAMESPACE_LEN])
{
    char hex[17];
    if (!key)
        return false;
    fd_key_digest_hex(key, hex);
    (void)snprintf(out, ZCL_APP_NAMESPACE_LEN, "k%s", hex);
    return true;
}

bool zcl_app_short_fingerprint(const char *pubkey_hex,
                               char out[ZCL_APP_SHORT_FINGERPRINT_LEN])
{
    uint8_t key[33];
    char hex[17];
    out[0] = '\0';
    if (!pubkey_hex || strlen(pubkey_hex) != 66 ||
        !zcl_hex_decode(pubkey_hex, key, sizeof(key)))
        return false;
    fd_key_digest_hex(key, hex);
    (void)snprintf(out, ZCL_APP_SHORT_FINGERPRINT_LEN, "%.4s-%.4s-%.4s-%.4s",
                   hex, hex + 4, hex + 8, hex + 12);
    return true;
}

/* ── app.list copies ─────────────────────────────────────────────────── */

static bool fd_row_named(const struct json_value *rows, const char *name)
{
    for (size_t i = 0; i < json_size(rows); i++) {
        const struct json_value *n = json_get(json_at(rows, i), "name");
        if (n && n->type == JSON_STR && strcmp(json_get_str(n), name) == 0)
            return true;
    }
    return false;
}

static void fd_push_row(struct json_value *rows, const char *name,
                        const char *status)
{
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    bool ok = json_push_kv_str(&row, "name", name) &&
              (!status || json_push_kv_str(&row, "status", status));
    if (ok)
        (void)json_push_back(rows, &row);
    json_free(&row);
}

/* Adopted copies through the zcode.copies reader. */
static void fd_adopted_rows(const char *datadir, struct json_value *rows)
{
    struct json_value in;
    struct zcl_command_reply r;
    json_init(&in);
    json_set_object(&in);
    if (!json_push_kv_str(&in, "datadir", datadir)) {
        json_free(&in);
        return;
    }
    if (zcl_app_inner_call("zcode.copies", &in, &r, NULL)) {
        const struct json_value *got = json_get(&r.data, "copies");
        for (size_t i = 0; got && i < json_size(got) &&
                           json_size(rows) < FD_COPIES_MAX;
             i++) {
            const struct json_value *n = json_get(json_at(got, i), "name");
            const struct json_value *s = json_get(json_at(got, i), "status");
            if (n && n->type == JSON_STR && s && s->type == JSON_STR)
                fd_push_row(rows, json_get_str(n), json_get_str(s));
        }
    }
    zcl_command_reply_free(&r);
    json_free(&in);
}

void zcl_app_list_copies(const char *datadir, struct json_value *data)
{
    struct json_value rows;
    struct platform_directory_list dirs = {0};
    char path[FD_PATH];
    struct stat st;
    json_init(&rows);
    json_set_array(&rows);
    int n = datadir ? snprintf(path, sizeof(path), "%s/copies", datadir) : -1;
    if (n > 0 && (size_t)n < sizeof(path)) {
        fd_adopted_rows(datadir, &rows);
        if (stat(path, &st) == 0 &&
            platform_directory_list_real_sorted(path, &dirs)) {
            for (size_t i = 0; i < dirs.count &&
                               json_size(&rows) < FD_COPIES_MAX;
                 i++)
                if (!fd_row_named(&rows, dirs.entries[i].name))
                    fd_push_row(&rows, dirs.entries[i].name, NULL);
            platform_directory_list_free(&dirs);
        }
    }
    (void)json_push_kv(data, "copies", &rows);
    json_free(&rows);
}

/* ── running one verb ────────────────────────────────────────────────── */

struct fd_run {
    const struct zcl_app_front_door *door;
    const struct fd_verb *verb;
    FILE *out;
    const char *datadir;
    char target[FD_PATH];
    struct json_value in;
    struct zcl_command_reply reply;
};

static const char *fd_str(const struct fd_run *r, const char *key)
{
    return zcl_app_inner_str(&r->reply, key);
}

static bool fd_is_copy(const char *datadir, const char *name)
{
    char path[FD_PATH];
    struct stat st;
    int n = snprintf(path, sizeof(path), "%s/copies/%s", datadir, name);
    return name[0] && name[0] != '.' && !strchr(name, '/') && n > 0 &&
           (size_t)n < sizeof(path) && stat(path, &st) == 0 &&
           S_ISDIR(st.st_mode);
}

/* open: a share file is a receive, a copy is the copy open; NULL is a
 * catalog app (the public app.open, untouched). */
static const struct fd_verb *fd_pick(const char *verb, const char *target,
                                     const char *datadir)
{
    if (strcmp(verb, "open") == 0 &&
        zcl_str_has_suffix(target, ZCL_PACKAGE_BUNDLE_SUFFIX))
        verb = "receive";
    else if (strcmp(verb, "open") == 0 && !fd_is_copy(datadir, target))
        return NULL;
    for (size_t i = 0; i < sizeof(k_fd_verbs) / sizeof(k_fd_verbs[0]); i++)
        if (strcmp(k_fd_verbs[i].verb, verb) == 0)
            return &k_fd_verbs[i];
    return NULL;
}

/* A share file is named to the leaf by its absolute path. */
static bool fd_target(struct fd_run *r)
{
    const char *t = r->door->target;
    if (strcmp(r->verb->key, "file") != 0 || t[0] == '/') {
        (void)snprintf(r->target, sizeof(r->target), "%s", t);
        return true;
    }
    char cwd[FD_PATH];
    struct stat st;
    bool ok = getcwd(cwd, sizeof(cwd)) &&
              zcl_path_join(r->target, sizeof(r->target), cwd, t) &&
              stat(r->target, &st) == 0 && S_ISREG(st.st_mode);
    if (!ok)
        (void)fprintf(r->out, "z23 app %s: no such file: %s (give the path of "
                      "the .z23share file you were sent)\n", r->door->verb, t);
    return ok;
}

static void fd_print_host_generation(struct fd_run *r, const char *prefix)
{
    const struct json_value *generation = json_get(&r->reply.data, "hosting_generation");
    if (generation && generation->type == JSON_INT)
        (void)fprintf(r->out, "%shosting_generation: %lld\n", prefix, (long long)json_get_int(generation));
}

static void fd_partial_data(struct fd_run *r)
{
    static const char *const keys[] = {"copy", "destination", "rebuild_report", "rebuild_retry",
                                       "hosting_status", "hosting_host", "hosting_carrier",
                                       "hosting_status_command", "hosting_stop_command", "hosting_retry", "hosting_retry_note"};
    const struct json_value *pid = json_get(&r->reply.data, "pid");
    if (pid && pid->type == JSON_INT && json_get_int(pid) > 0)
        (void)fprintf(r->out, "opened %s pid %lld\n",
                      fd_str(r, "copy") ? fd_str(r, "copy") : r->target,
                      (long long)json_get_int(pid));
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i)
        if (fd_str(r, keys[i])) (void)fprintf(r->out, "%s: %s\n", keys[i], fd_str(r, keys[i]));
    fd_print_host_generation(r, "");
}

static void fd_build_recovery_hint(struct fd_run *r)
{
    for (size_t i = 0; i < r->reply.next_count; ++i) {
        const struct zcl_command_next *next = &r->reply.next[i];
        if (strcmp(next->command, "app.build") != 0) continue;
        struct json_value input; json_init(&input);
        bool parsed = json_read(&input, next->input_json, strlen(next->input_json)) && input.type == JSON_OBJ;
        const char *copy = parsed ? json_get_str(json_get(&input, "copy")) : NULL;
        const char *datadir = parsed ? json_get_str(json_get(&input, "datadir")) : NULL;
        char hint[2 * FD_PATH + 64];
        if (copy && copy[0] && datadir && datadir[0] &&
            zcl_app_hint(hint, sizeof(hint), datadir, "build %s", copy))
            (void)fprintf(r->out, "next: %s\n", hint);
        json_free(&input);
    }
}

static int fd_refused(struct fd_run *r)
{
    const struct zcl_command_error *e = &r->reply.error;
    (void)fprintf(r->out, "z23 app %s %s: %s: %s%s%s%s\n", r->door->verb,
                  r->door->target, e->code[0] ? e->code : "FAILED",
                  e->message, e->evidence[0] ? " (" : "", e->evidence,
                  e->evidence[0] ? ")" : "");
    if (e->next_action[0])
        (void)fprintf(r->out, "next: %s\n", e->next_action);
    fd_build_recovery_hint(r);
    if (!strcmp(e->code, "RECIPE_RELEASE_REQUIRED")) {
        char hint[2 * FD_PATH + 64];
        if (zcl_app_hint(hint, sizeof(hint), r->datadir, "share %s", r->target))
            (void)fprintf(r->out, "next: %s\n", hint);
    }
    const char *offer_hint = fd_str(r, "next_offer");
    if (offer_hint) (void)fprintf(r->out, "next: %s\n", offer_hint);
    const char *first = fd_str(r, "choice_a"), *second = fd_str(r, "choice_b");
    if (first) (void)fprintf(r->out, "choice: %s\n", first);
    if (second) (void)fprintf(r->out, "choice: %s\n", second);
    fd_partial_data(r);
    if (e->mutated)
        (void)fprintf(r->out, "note: an earlier step already changed "
                      "something; the message above says what is left\n");
    return r->reply.exit_code ? (int)r->reply.exit_code
                              : (int)ZCL_COMMAND_EXIT_FAILED;
}

/* The plan's human lines: whatever of these keys the leaf returned. */
static void fd_print_plan(struct fd_run *r)
{
    static const char *const keys[] = {
        "name", "semver", "publisher", "publisher_fingerprint", "release_id",
        "package_root", "publishes_as", "copy_name", "copy", "destination",
        "changes", "cache_hit", "image_sha3", "output", "saves_first",
        "makes_key", "seed", "room", "offer_schema", "source",
        "source_projection", "installed_image", "key_path", "key_will_create"};
    (void)fprintf(r->out, "z23 app %s %s\n", r->door->verb, r->door->target);
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        const struct json_value *v = json_get(&r->reply.data, keys[i]);
        if (v && v->type == JSON_STR)
            (void)fprintf(r->out, "  %s: %s\n", keys[i], json_get_str(v));
        else if (v && v->type == JSON_INT)
            (void)fprintf(r->out, "  %s: %lld\n", keys[i],
                          (long long)json_get_int(v));
        else if (v && v->type == JSON_BOOL)
            (void)fprintf(r->out, "  %s: %s\n", keys[i],
                          json_get_bool(v) ? "yes" : "no");
    }
}

static void fd_question(const struct fd_run *r, char *q, size_t cap)
{
    const char *name = fd_str(r, "name") ? fd_str(r, "name") : r->target;
    const char *who = fd_str(r, "publisher") ? fd_str(r, "publisher") : "?";
    const char *v = r->door->verb;
    if (strcmp(r->verb->verb, "receive") == 0 ||
        strcmp(r->verb->verb, "get") == 0)
        (void)snprintf(q, cap, "Keep, build and run %s %s from publisher %s "
                       "(full %s), package root %s, as %s%s?", name,
                       fd_str(r, "semver") ? fd_str(r, "semver") : "", who,
                       fd_str(r, "publisher_fingerprint")
                           ? fd_str(r, "publisher_fingerprint") : "?",
                       fd_str(r, "package_root") ? fd_str(r, "package_root")
                                                 : "?",
                       fd_str(r, "copy") ? fd_str(r, "copy") : "a copy",
                       strcmp(r->verb->verb, "get") == 0 ? "; a fresh build will be reported publicly; pin the carrier and renew public offers while this node runs; stopping hosting leaves the pin and existing offers until expiry" : "");
    else if (strcmp(r->verb->verb, "copy") == 0)
        (void)snprintf(q, cap, "Make your own copy of %s as %s?", r->target,
                       fd_str(r, "copy_name") ? fd_str(r, "copy_name")
                                              : "a new copy");
    else if (r->verb->opens)
        (void)snprintf(q, cap, "Run %s's build %.16s?", r->target,
                       fd_str(r, "image_sha3") ? fd_str(r, "image_sha3") : "");
    else
        (void)snprintf(q, cap, "%c%s %s?", (char)(v[0] - 'a' + 'A'), v + 1,
                       r->target);
}

static bool fd_confirm_offer(struct fd_run *r, const char *offer)
{
    if (r->door->offer_id) return strcmp(r->door->offer_id, offer) == 0;
    return json_push_kv_str(&r->in, "offer_id", offer);
}

static const char *fd_binding(struct fd_run *r, const char *key, size_t len)
{
    const char *value = fd_str(r, key);
    return value && strlen(value) == len ? value : NULL;
}

static bool fd_confirm_binding(struct fd_run *r)
{
    bool published = strcmp(r->verb->verb, "publish") == 0;
    bool getting = strcmp(r->verb->verb, "get") == 0;
    if (!published && !getting) return true;
    const char *token = fd_binding(r, "token", 32);
    if (!token || !json_push_kv_str(&r->in, "token", token)) return false;
    if (!getting) return true;
    const char *offer = fd_binding(r, "offer_id", 64);
    return offer && fd_confirm_offer(r, offer);
}

/* The confirm input: the plan's own plan_id, and for an open its image. */
static bool fd_confirm_input(struct fd_run *r)
{
    const char *plan = fd_str(r, "plan_id"), *image = fd_str(r, "image_sha3");
    if (!plan || strlen(plan) != 64 || (r->verb->opens && !image)) return false;
    return json_push_kv_str(&r->in, "plan_id", plan) &&
           json_push_kv_bool(&r->in, "confirm", true) && fd_confirm_binding(r) &&
           (!r->verb->opens || (json_push_kv_bool(&r->in, "accept_execution", true) &&
                                json_push_kv_str(&r->in, "image_sha3", image)));
}

static void fd_print_done(struct fd_run *r)
{
    static const char *const keys[] = {
        "copy", "share_line", "publisher_fingerprint", "package_root",
        "post_id", "public_link", "image_sha3", "image_path", "log", "next",
        "rebuild_report", "rebuild_count_status", "rebuild_retry", "hosting_status", "hosting_host",
        "hosting_carrier", "hosting_status_command", "hosting_stop_command", "hosting_retry", "hosting_retry_note"};
    const struct json_value *pid = json_get(&r->reply.data, "pid");
    if (pid && pid->type == JSON_INT)
        (void)fprintf(r->out, "opened %s pid %lld\n",
                      fd_str(r, "copy") ? fd_str(r, "copy") : r->target,
                      (long long)json_get_int(pid));
    else
        (void)fprintf(r->out, "done: z23 app %s %s\n", r->door->verb,
                      r->door->target);
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
        if (fd_str(r, keys[i]))
            (void)fprintf(r->out, "  %s: %s\n", keys[i], fd_str(r, keys[i]));
    fd_print_host_generation(r, "  ");
    if (fd_str(r, "preview"))
        (void)fprintf(r->out, "  %s\n", fd_str(r, "preview"));
    const struct json_value *offered = json_get(&r->reply.data, "preview_offered");
    if (offered && offered->type == JSON_BOOL && json_get_bool(offered)) {
        char hint[FD_PATH + 512];
        if (zcl_app_hint(hint, sizeof(hint), r->door->datadir, "open %s", "tasks"))
            (void)fprintf(r->out, "  next: %s\n", hint);
        (void)fprintf(r->out, "  In Tasks, choose More / Undo, then Updates. Try update asks permission before running.\n");
    }
    const struct json_value *count = json_get(&r->reply.data, "matching_rebuild_keys");
    if (count && count->type == JSON_INT)
        (void)fprintf(r->out, "  matching signing keys: %lld (self-reported builds)\n", (long long)json_get_int(count));
}

/* The confirm made the owner's signing key on first use: say so once. */
static void fd_key_note(struct fd_run *r)
{
    const struct json_value *made = json_get(&r->reply.data, "key_created");
    if (!made || made->type != JSON_BOOL || !json_get_bool(made) ||
        !fd_str(r, "key_path"))
        return;
    (void)fprintf(r->out, "made your signing key at %s (first use); it signs "
                  "what you share, so back it up\n", fd_str(r, "key_path"));
}

static int fd_plan_only(struct fd_run *r)
{
    char hint[FD_PATH + 512];
    /* Keep the identity consumed by a no-terminal plan in its retry. */
    bool built;
    if (!strcmp(r->verb->key, "file")) {
        const char *plan = fd_str(r, "plan_id");
        built = plan && strlen(plan) == 64 &&
            zcl_app_hint(hint, sizeof(hint), r->door->datadir,
                         "%s %s --plan-id=%s --yes", r->door->verb, r->door->target, plan);
    } else if (r->door->root && r->door->publisher && r->door->offer_id)
        built = zcl_app_hint(hint, sizeof(hint), r->door->datadir,
                             "%s %s --root=%s --publisher=%s --offer=%s --yes",
                             r->door->verb, r->door->target, r->door->root,
                             r->door->publisher, r->door->offer_id);
    else if (r->door->root && r->door->publisher)
        built = zcl_app_hint(hint, sizeof(hint), r->door->datadir,
                             "%s %s --root=%s --publisher=%s --yes",
                             r->door->verb, r->door->target, r->door->root,
                             r->door->publisher);
    else
        built = zcl_app_hint(hint, sizeof(hint), r->door->datadir,
                             "%s %s --yes", r->door->verb, r->door->target);
    if (!built) {
        (void)fprintf(r->out, "nothing changed; cannot render a safe retry. Run this command in a terminal and review the plan again.\n");
        return 0;
    }
    (void)fprintf(r->out, "nothing changed (no terminal to ask). next: %s\n", hint);
    return 0;
}


/* Plan printed; now plan-only, a no, or the confirm. */
static int fd_decide(struct fd_run *r)
{
    char q[1024];
    const char *changed = "nothing changed";
    if (r->door->confirm.mode == ZCL_CLI_CONFIRM_PLAN_ONLY) return fd_plan_only(r);
    fd_question(r, q, sizeof(q));
    if (!zcl_cli_confirm_ask(&r->door->confirm, q)) {
        (void)fprintf(r->out, "%s\n", changed);
        return 1;
    }
    if (!fd_confirm_input(r)) {
        (void)fprintf(r->out, "z23 app %s: the plan returned no plan_id\n",
                      r->door->verb);
        return (int)ZCL_COMMAND_EXIT_INTERNAL;
    }
    zcl_command_reply_free(&r->reply);
    if (!zcl_app_inner_call(r->verb->path, &r->in, &r->reply, NULL))
        return fd_refused(r);
    /* Closing the download window cancels a confirmed get before Receive:
     * the leaf still answers PASSED, but its data carries status "canceled"
     * and nothing was received, so the decline's outcome is the truth.
     * Other verbs can also report a canceled confirm half; their wording
     * stays verb-neutral. */
    const struct json_value *status = json_get(&r->reply.data, "status");
    if (status && status->type == JSON_STR &&
        strcmp(json_get_str(status), "canceled") == 0) {
        bool get = strcmp(r->door->verb, "get") == 0;
        (void)fprintf(r->out,
                      "z23 app %s %s: %s\n%s\n", r->door->verb,
                      r->door->target,
                      get ? "download window closed; nothing was received"
                          : "canceled before completion; nothing changed",
                      changed);
        return 1;
    }
    fd_key_note(r);
    fd_print_done(r);
    return 0;
}

static int fd_run_verb(struct fd_run *r)
{
    json_init(&r->in);
    json_set_object(&r->in);
    if (!fd_target(r) ||
        !json_push_kv_str(&r->in, r->verb->key, r->target) ||
        !json_push_kv_str(&r->in, "datadir", r->datadir) ||
        (r->door->root && !json_push_kv_str(&r->in, "root", r->door->root)) ||
        (r->door->publisher && !json_push_kv_str(&r->in, "publisher", r->door->publisher)) ||
        (r->door->offer_id && !json_push_kv_str(&r->in, "offer_id", r->door->offer_id))) {
        json_free(&r->in);
        return (int)ZCL_COMMAND_EXIT_INVALID;
    }
    bool planned = zcl_app_inner_call(r->verb->path, &r->in, &r->reply, NULL);
    const char *plan = planned ? fd_str(r, "plan_id") : NULL;
    int rc;
    if (!planned) rc = fd_refused(r);
    else if (r->door->plan_id && (!plan || strcmp(plan, r->door->plan_id))) {
        (void)fprintf(r->out, "z23 app %s: the reviewed file plan changed; review the file again.\n", r->door->verb);
        rc = (int)ZCL_COMMAND_EXIT_INVALID;
    } else { fd_print_plan(r); rc = fd_decide(r); }
    zcl_command_reply_free(&r->reply);
    json_free(&r->in);
    return rc;
}

static bool fd_plan_valid(struct fd_run *r)
{
    const char *plan = r->door->plan_id;
    if (!plan) return true;
    uint8_t decoded[32];
    if (!strcmp(r->verb->key, "file") && strlen(plan) == 64 &&
        zcl_hex_decode(plan, decoded, sizeof(decoded))) return true;
    (void)fprintf(r->out, "z23 app %s: invalid file plan id; review the file again.\n", r->door->verb);
    return false;
}

static bool fd_prepare_verb(struct fd_run *r)
{
    const struct zcl_app_front_door *door = r->door;
    r->verb = fd_pick(door->verb, door->target, r->datadir);
    if (!r->verb) {
        (void)fprintf(r->out, "z23 app %s %s: not a copy under %s/copies, a .z23share file or a front-door verb\n",
                      door->verb, door->target, r->datadir);
        return false;
    }
    return fd_plan_valid(r);
}

int zcl_app_front_door_run(const struct zcl_app_front_door *door)
{
    struct fd_run r = {.door = door};
    if (!door || !door->verb || !door->target || !door->target[0])
        return (int)ZCL_COMMAND_EXIT_INVALID;
    r.out = door->out ? door->out : stdout;
    r.datadir = door->datadir && door->datadir[0]
                    ? door->datadir : zcl_native_command_datadir();
    if (!r.datadir || !r.datadir[0]) {
        (void)fprintf(r.out, "z23 app %s: no datadir (pass --datadir)\n",
                      door->verb);
        return (int)ZCL_COMMAND_EXIT_INVALID;
    }
    if (!fd_prepare_verb(&r)) return (int)ZCL_COMMAND_EXIT_INVALID;
    /* A person at a terminal wants the result lines, not INFO logs: quiet
     * the floor for this one command unless -loglevel was given, then put
     * it back so no other caller in the process sees the change. */
    const char *asked = GetArg("-loglevel", NULL);
    const enum zcl_log_level prior = zcl_log_level_get();
    const bool quiet = (!asked || !asked[0]) && prior < ZCL_LOG_WARN;
    if (quiet) zcl_log_level_set(ZCL_LOG_WARN);
    const int rc = fd_run_verb(&r);
    if (quiet) zcl_log_level_set(prior);
    return rc;
}

/* ── the argv hook ───────────────────────────────────────────────────── */

static const char *fd_verb_of(const char *path)
{
    static const char *const map[][2] = {
        {"app.copy", "copy"},   {"app.save", "save"},
        {"app.build", "build"}, {"app.share", "share"},
        {"app.receive", "receive"}, {"app.open", "open"},
        {"app.publish", "publish"}, {"app.get", "get"},
        {"app.run.copy", "open"}};
    for (size_t i = 0; i < sizeof(map) / sizeof(map[0]); i++)
        if (strcmp(map[i][0], path) == 0)
            return map[i][1];
    return NULL;
}

static int fd_selector_word(const char *w, const char **root,
                            const char **publisher, const char **offer)
{
    const char **slot = NULL;
    size_t n = 0;
    if (strncmp(w, "--root=", 7) == 0) { slot = root; n = 7; }
    else if (strncmp(w, "--publisher=", 12) == 0) { slot = publisher; n = 12; }
    else if (strncmp(w, "--offer=", 8) == 0) { slot = offer; n = 8; }
    if (!slot) return 0;
    if (*slot || !w[n]) return -1;
    *slot = w + n;
    return 1;
}

static bool fd_plan_word(const char *verb, const char *word, const char **plan)
{
    if (strcmp(verb, "open") && strcmp(verb, "receive")) return false;
    if (strncmp(word, "--plan-id", 9)) return false;
    *plan = *plan || word[9] != '=' ? "" : word + 10;
    return true;
}

/* One target, optional file plan pin, and at most one --yes / -y. */
static bool fd_words(const char *const *words, size_t count, size_t consumed,
                     const char *verb, const char **target, bool *yes,
                     const char **root, const char **publisher, const char **offer, const char **plan)
{
    *target = NULL;
    *yes = false;
    *root = NULL;
    *publisher = NULL;
    *offer = NULL;
    *plan = NULL;
    for (size_t i = consumed; i < count; i++) {
        const char *w = words[i];
        if (strcmp(w, "--yes") == 0 || strcmp(w, "-y") == 0) {
            if (*yes)
                return false;
            *yes = true;
        } else if (fd_plan_word(verb, w, plan)) {
            continue;
        } else {
            int selector = strcmp(verb, "get") == 0
                               ? fd_selector_word(w, root, publisher, offer) : 0;
            if (selector < 0) return false;
            if (selector > 0) continue;
            if (w[0] == '-' || *target) return false;
            *target = w;
        }
    }
    return *target != NULL && (!!*root == !!*publisher) && (!*offer || *root);
}

/* The launcher owns catalog alias resolution and all unreadable-selection
 * refusals. Only an absent selection permits the CLI copy fallback. */
static bool fd_open_native_priority(const char *name, bool *catalog)
{
    *catalog = false;
    if (app_selection_route_reserved(name)) return true;
    struct app_launch_env env; char why[256];
    if (!app_launch_env_from_process(&env, why, sizeof(why))) return true;
    struct app_launch_registry registry;
    app_launch_registry_load(&env, &registry);
    if (registry.config_error[0]) return true;
    const struct app_launch_entry *entry = app_launch_registry_find(&registry, name);
    if (!entry) return false;
    *catalog = true;
    struct app_selection selection;
    return app_selection_load(env.state_dir, entry->id, &selection) != APP_SELECTION_ABSENT;
}

static bool fd_catalog_lines(const struct json_value *lines)
{
    if (!lines || lines->type != JSON_ARR) return false;
    for (size_t i = 0; i < json_size(lines); i++)
        if (!json_get_str(json_at(lines, i))) return false;
    for (size_t i = 0; i < json_size(lines); i++)
        (void)fprintf(stdout, "%s\n", json_get_str(json_at(lines, i)));
    if (json_size(lines) == 0)
        (void)fprintf(stdout, "No app offers held by this node.\n");
    return true;
}

static int fd_catalog(const char *datadir)
{
    struct zcl_app_front_door door = {.verb = "get", .target = "", .datadir = datadir};
    struct fd_run r = {.door = &door, .out = stdout, .datadir = datadir};
    json_init(&r.in);
    json_set_object(&r.in);
    if (datadir && !json_push_kv_str(&r.in, "datadir", datadir)) {
        json_free(&r.in);
        return (int)ZCL_COMMAND_EXIT_INTERNAL;
    }
    bool ok = zcl_app_inner_call("app.get", &r.in, &r.reply, NULL);
    int rc = 0;
    if (!ok) rc = fd_refused(&r);
    else {
        const struct json_value *lines = json_get(&r.reply.data, "lines");
        if (!fd_catalog_lines(lines)) {
            (void)fprintf(stdout, "z23 app get: MALFORMED_INNER: catalog lines are invalid\n");
            rc = (int)ZCL_COMMAND_EXIT_INTERNAL;
        }
    }
    zcl_command_reply_free(&r.reply);
    json_free(&r.in);
    return rc;
}

static bool fd_open_routes(const struct zcl_command_spec *spec, const char *verb,
                           const char *target, const char *datadir, bool *protected)
{
    bool copy_open = strcmp(spec->path, "app.run.copy") == 0;
    *protected = false;
    if (!copy_open && strcmp(spec->path, "app.open") == 0) {
        bool catalog = false;
        bool priority = fd_open_native_priority(target, &catalog);
        *protected = priority || catalog;
        if (priority) return false;
    }
    if (strcmp(verb, "open") == 0 && !copy_open && datadir &&
        !zcl_str_has_suffix(target, ZCL_PACKAGE_BUNDLE_SUFFIX) &&
        !fd_is_copy(datadir, target)) return false;
    return true;
}

/* ZIP is an archive, not a signed share. Only the human CLI gets guidance;
 * catalog names and existing app copies keep their normal routing priority. */
static bool fd_zip_suffix(const char *verb, const char *target)
{
    size_t len = strlen(target);
    if (strcmp(verb, "open") || len < 4 || target[len - 4] != '.') return false;
    return (target[len - 3] == 'z' || target[len - 3] == 'Z') &&
        (target[len - 2] == 'i' || target[len - 2] == 'I') &&
        (target[len - 1] == 'p' || target[len - 1] == 'P');
}
static bool fd_zip_guidance(const char *verb, const char *target, bool protected)
{
    if (protected || !fd_zip_suffix(verb, target)) return false;
    struct stat st;
    if (stat(target, &st) != 0 || !S_ISREG(st.st_mode)) return false;
    (void)fprintf(stdout, "Extract the ZIP, then open the .z23share file inside if present with z23 app open.\n");
    return true;
}

static bool fd_route_guidance(const char *plan, const char *verb, const char *target, bool protected)
{
    if (plan) {
        (void)fprintf(stdout, "z23 app %s: the pinned file route is unavailable; review the file again.\n", verb);
        return true;
    }
    return fd_zip_guidance(verb, target, protected);
}

bool zcl_app_front_door_try(const struct zcl_command_spec *spec,
                            const char *const *words, size_t count,
                            size_t consumed, const char *datadir, int *rc)
{
    if (spec && rc && strcmp(spec->path, "app.get") == 0 && count == consumed) {
        const char *dd = datadir && datadir[0] ? datadir : zcl_native_command_datadir();
        *rc = fd_catalog(dd);
        return true;
    }
    const char *verb = spec ? fd_verb_of(spec->path) : NULL;
    const char *target = NULL;
    const char *root = NULL, *publisher = NULL, *offer = NULL, *plan = NULL;
    bool yes = false;
    if (!verb || !rc || !fd_words(words, count, consumed, verb, &target, &yes,
                                  &root, &publisher, &offer, &plan))
        return false;
    const char *dd = datadir && datadir[0] ? datadir
                                           : zcl_native_command_datadir();
    bool protected = false;
    if (!fd_open_routes(spec, verb, target, dd, &protected)) {
        if (fd_route_guidance(plan, verb, target, protected)) { *rc = (int)ZCL_COMMAND_EXIT_INVALID; return true; }
        return false;
    }
    const struct zcl_app_front_door door = {
        .verb = verb, .target = target, .datadir = dd,
        .root = root, .publisher = publisher,
        .offer_id = offer, .plan_id = plan,
        .confirm = zcl_cli_confirm_resolve(yes), .out = stdout,
    };
    *rc = zcl_app_front_door_run(&door);
    return true;
}

/* ── --yes on a leaf that asks nothing ───────────────────────────────── */

bool zcl_app_front_door_ignores_flag(const struct zcl_command_spec *spec,
                                     const char *flag_key)
{
    return spec && flag_key && strncmp(spec->path, "app.", 4) == 0 &&
           spec->confirmation == ZCL_COMMAND_CONFIRM_NONE &&
           (strcmp(flag_key, "yes") == 0 || strcmp(flag_key, "y") == 0);
}
