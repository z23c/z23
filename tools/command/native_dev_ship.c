/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.fleet.ship (alias dev.ship) — the preflight and plan of a
 *          fleet deploy, natively.
 *
 * This is the first phase of moving tools/ship.sh onto a C23 leaf. It owns
 * the decisions ship.sh makes before it builds anything, in ship.sh's order,
 * so the first refusal class is the same one ship.sh dies with:
 *
 *   1. targets      --targets is local, remote or both (default both).
 *   2. hosts        ZCL_SHIP_HOSTS (fallback ZCL_SHIP_REMOTE), each a valid
 *                   SSH destination, no repeats; the ZCL_SHIP_PROOF_SERVER
 *                   host is skipped on a bare run, refused when the targets
 *                   were named, and admitted with ZCL_SHIP_ALLOW_PROOF_SERVER=1.
 *   3. checkout     the working tree is clean.
 *   4. origin/main  fetched; HEAD is not behind it. HEAD ahead of it is a
 *                   refusal here: ship.sh pushes first, this leaf never does.
 *   5. source id    tools/dev/source-identity.sh capture, the same tool.
 *   6. gate stamp   $HOME/.cache/zcl-ship/<source_id>.passed; banked only
 *                   under --skip_gate with a valid id and the stamp present.
 *   7. schema       git diff --name-only over ship.sh's four persistent-
 *                   schema pathspecs, against origin/main (the dry-run
 *                   baseline ship.sh uses), and ship.sh's exit-code contract:
 *                   0 no change, 1 changed and not accepted, 2 changed and
 *                   accepted with --accept_one_way (rollback disarmed).
 *
 * A host is reported by its configured SSH alias only. A destination that
 * is an address (it holds '@' or '.') is reported as target-<n>, its
 * position in ZCL_SHIP_HOSTS; no destination string reaches a refusal.
 *
 * --dry_run returns the plan with verdict ready or refuse. Without it a
 * refusal fails with its class as evidence, and a ready plan is BLOCKED:
 * this phase builds, stages and restarts nothing; tools/ship.sh still does.
 * The leaf runs git and the source identity tool through util/spawn.h with
 * argv only, never a shell; its one write is ship.sh's own `git fetch`. */

#include "command/native_command.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "util/spawn.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define SHIP_SCHEMA "zcl.dev_ship.v1"
#define SHIP_PATH 4096
#define SHIP_MAX_HOSTS 32
#define SHIP_DEST_MAX 256
#define SHIP_NAME_MAX 64
#define SHIP_OID 41
#define SHIP_GIT_TIMEOUT_MS 60000
#define SHIP_FETCH_TIMEOUT_MS 120000
#define SHIP_SOURCE_ID_TIMEOUT_MS 300000
#define SHIP_SCHEMA_BYTES 8192

static const char *const ship_schema_pathspecs[] = {
    "engine/models/src/database*.c",
    "engine/models/include/models/database*.h",
    "engine/models/src/schema_migration.c",
    "engine/models/include/models/schema_migration.h",
};

/* ship_one_way_schema_decision's return codes, unchanged. */
enum ship_one_way {
    SHIP_ONE_WAY_NONE = 0,
    SHIP_ONE_WAY_REFUSE = 1,
    SHIP_ONE_WAY_ACCEPT = 2,
};

struct ship_host {
    char dest[SHIP_DEST_MAX]; /* never emitted */
    char name[SHIP_NAME_MAX];
    bool redacted;
};

struct ship_plan {
    char root[SHIP_PATH];
    bool dry_run, skip_gate, accept_one_way;
    bool want_local, want_remote, local_first, targets_explicit;
    struct ship_host hosts[SHIP_MAX_HOSTS];
    size_t host_count;
    char proof_skipped[SHIP_NAME_MAX];
    bool proof_promoted;
    char refusal[40];
    char refusal_message[320];
    bool checkout_ok, dirty, fetch_ok, origin_present;
    char head[SHIP_OID];
    char origin[SHIP_OID];
    long behind, ahead;
    char source_id[65];
    bool stamp_present, gate_banked;
    char stamp_at[40];
    bool schema_known;
    enum ship_one_way one_way;
    char schema_files[SHIP_SCHEMA_BYTES];
    size_t schema_count;
};

/* ── small helpers ───────────────────────────────────────────────────────── */

static void ship_trim(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1]))
        s[--n] = '\0';
}

static bool ship_is_hex(const char *s, size_t len)
{
    if (strlen(s) != len)
        return false;
    for (size_t i = 0; i < len; i++)
        if (!isdigit((unsigned char)s[i]) && (s[i] < 'a' || s[i] > 'f'))
            return false;
    return true;
}

__attribute__((format(printf, 3, 4)))
static void ship_refuse(struct ship_plan *p, const char *cls,
                        const char *fmt, ...)
{
    va_list ap;
    if (p->refusal[0])
        return;
    (void)snprintf(p->refusal, sizeof(p->refusal), "%s", cls);
    va_start(ap, fmt);
    (void)vsnprintf(p->refusal_message, sizeof(p->refusal_message), fmt, ap);
    va_end(ap);
}

static bool ship_input_bool(const struct json_value *input, const char *key)
{
    const struct json_value *v = input ? json_get(input, key) : NULL;
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

static const char *ship_input_str(const struct json_value *input,
                                  const char *key)
{
    const struct json_value *v = input ? json_get(input, key) : NULL;
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

/* One git command in `root`, argv only. Returns the exit status, or -1 when
 * the launch failed or the deadline killed it. */
static int ship_git(const char *root, const char *const *args, char *out,
                    size_t cap, int timeout_ms)
{
    const char *argv[16];
    char sink[2];
    size_t n = 0;
    bool timed_out = false;
    argv[n++] = "git";
    argv[n++] = "-C";
    argv[n++] = root;
    for (size_t i = 0; args[i]; i++) {
        if (n + 2 > sizeof(argv) / sizeof(argv[0]))
            return -1;
        argv[n++] = args[i];
    }
    argv[n] = NULL;
    int rc = zcl_spawn_capture_observed(argv, out ? out : sink,
                                        out ? cap : sizeof(sink), timeout_ms,
                                        &timed_out);
    if (out)
        ship_trim(out);
    return timed_out ? -1 : rc;
}

static bool ship_git_oid(const char *root, const char *const *args,
                         char out[SHIP_OID])
{
    char buf[128];
    if (ship_git(root, args, buf, sizeof(buf), SHIP_GIT_TIMEOUT_MS) != 0 ||
        !ship_is_hex(buf, SHIP_OID - 1))
        return false;
    memcpy(out, buf, SHIP_OID);
    return true;
}

static long ship_git_count(const char *root, const char *range)
{
    char buf[64];
    const char *args[] = { "rev-list", "--count", range, NULL };
    if (ship_git(root, args, buf, sizeof(buf), SHIP_GIT_TIMEOUT_MS) != 0 ||
        !buf[0] || strspn(buf, "0123456789") != strlen(buf))
        return -1;
    return strtol(buf, NULL, 10);
}

/* ── 1. targets ──────────────────────────────────────────────────────────── */

static bool ship_target_token(struct ship_plan *p, const char *tok)
{
    if (strcmp(tok, "local") == 0) {
        p->local_first = p->local_first || !p->want_remote;
        p->want_local = true;
        return true;
    }
    if (strcmp(tok, "remote") == 0) {
        p->want_remote = true;
        return true;
    }
    return false;
}

/* ship.sh: TARGETS="${arg#*=}" with commas read as spaces. */
static bool ship_parse_targets(struct ship_plan *p, const char *text)
{
    char buf[128];
    char *save = NULL;
    bool any = false;
    if (!text) {
        p->want_local = p->want_remote = p->local_first = true;
        return true;
    }
    if (strlen(text) >= sizeof(buf))
        return false;
    (void)snprintf(buf, sizeof(buf), "%s", text);
    p->targets_explicit = true;
    for (char *tok = strtok_r(buf, ", \t", &save); tok;
         tok = strtok_r(NULL, ", \t", &save)) {
        if (!ship_target_token(p, tok))
            return false;
        any = true;
    }
    return any;
}

/* ── 2. hosts ────────────────────────────────────────────────────────────── */

/* ship_valid_host: non-empty, no leading '-', only [A-Za-z0-9._@-]. */
static bool ship_valid_dest(const char *s)
{
    if (!s[0] || s[0] == '-' || strlen(s) >= SHIP_DEST_MAX)
        return false;
    for (const char *c = s; *c; c++)
        if (!isalnum((unsigned char)*c) && !strchr("._@-", *c))
            return false;
    return true;
}

/* A configured SSH alias is a name; anything holding '@' or '.' may be an
 * address and is reported by its position instead. */
static void ship_display_name(const char *dest, size_t index,
                              char name[SHIP_NAME_MAX], bool *redacted)
{
    bool alias = isalpha((unsigned char)dest[0]) &&
                 strlen(dest) < SHIP_NAME_MAX &&
                 strspn(dest, "abcdefghijklmnopqrstuvwxyz"
                              "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") ==
                     strlen(dest);
    *redacted = !alias;
    if (alias)
        (void)snprintf(name, SHIP_NAME_MAX, "%s", dest);
    else
        (void)snprintf(name, SHIP_NAME_MAX, "target-%zu", index);
}

static bool ship_host_seen(const struct ship_plan *p, const char *dest)
{
    for (size_t i = 0; i < p->host_count; i++)
        if (strcmp(p->hosts[i].dest, dest) == 0)
            return true;
    return false;
}

/* One ZCL_SHIP_HOSTS entry, in ship.sh's loop order. False = refused. */
static bool ship_admit_host(struct ship_plan *p, const char *dest,
                            size_t index, const char *proof, bool allow)
{
    char name[SHIP_NAME_MAX];
    bool redacted = false;
    if (!ship_valid_dest(dest)) {
        ship_refuse(p, "invalid_host",
                    "ZCL_SHIP_HOSTS entry %zu is not a valid SSH destination",
                    index);
        return false;
    }
    if (ship_host_seen(p, dest)) {
        ship_refuse(p, "duplicate_host",
                    "ZCL_SHIP_HOSTS entry %zu repeats an earlier target",
                    index);
        return false;
    }
    ship_display_name(dest, index, name, &redacted);
    bool is_proof = proof && proof[0] && strcmp(dest, proof) == 0;
    if (is_proof && !allow && p->targets_explicit) {
        ship_refuse(p, "proof_server_targeted",
                    "%s is the immutable proof server; promote deliberately "
                    "with ZCL_SHIP_ALLOW_PROOF_SERVER=1", name);
        return false;
    }
    if (is_proof && !allow) {
        (void)snprintf(p->proof_skipped, sizeof(p->proof_skipped), "%s", name);
        return true;
    }
    if (p->host_count == SHIP_MAX_HOSTS) {
        ship_refuse(p, "too_many_hosts",
                    "ZCL_SHIP_HOSTS names more than %d targets",
                    SHIP_MAX_HOSTS);
        return false;
    }
    struct ship_host *h = &p->hosts[p->host_count++];
    (void)snprintf(h->dest, sizeof(h->dest), "%s", dest);
    (void)snprintf(h->name, sizeof(h->name), "%s", name);
    h->redacted = redacted;
    p->proof_promoted = p->proof_promoted || is_proof;
    return true;
}

static void ship_parse_hosts(struct ship_plan *p)
{
    const char *raw = getenv("ZCL_SHIP_HOSTS");
    const char *proof = getenv("ZCL_SHIP_PROOF_SERVER");
    const char *allow_env = getenv("ZCL_SHIP_ALLOW_PROOF_SERVER");
    bool allow = allow_env && strcmp(allow_env, "1") == 0;
    char *buf, *save = NULL;
    size_t index = 0;
    if (!raw || !raw[0])
        raw = getenv("ZCL_SHIP_REMOTE");
    if (!raw || !raw[0]) {
        ship_refuse(p, "remote_hosts_unset",
                    "remote target needs ZCL_SHIP_HOSTS (space-separated SSH "
                    "aliases)");
        return;
    }
    buf = zcl_strdup(raw, "dev_ship_hosts");
    if (!buf) {
        ship_refuse(p, "internal", "out of memory reading ZCL_SHIP_HOSTS");
        return;
    }
    for (char *tok = strtok_r(buf, " \t\n", &save); tok;
         tok = strtok_r(NULL, " \t\n", &save)) {
        if (!ship_admit_host(p, tok, ++index, proof, allow))
            break;
    }
    free(buf);
}

/* ── 3-4. checkout and origin/main ──────────────────────────────────────── */

static void ship_origin_facts(struct ship_plan *p)
{
    const char *fetch[] = { "fetch", "-q", "origin", "main", NULL };
    const char *origin[] = { "rev-parse", "--verify", "-q", "origin/main",
                             NULL };
    char range[2 * SHIP_OID + 16];
    p->fetch_ok =
        ship_git(p->root, fetch, NULL, 0, SHIP_FETCH_TIMEOUT_MS) == 0;
    p->origin_present = ship_git_oid(p->root, origin, p->origin);
    if (!p->origin_present)
        return;
    (void)snprintf(range, sizeof(range), "%s..%s", p->head, p->origin);
    p->behind = ship_git_count(p->root, range);
    (void)snprintf(range, sizeof(range), "%s..%s", p->origin, p->head);
    p->ahead = ship_git_count(p->root, range);
}

static void ship_checkout_refusals(struct ship_plan *p)
{
    if (!p->checkout_ok) {
        ship_refuse(p, "not_a_checkout",
                    "root is not a readable git checkout with a commit");
        return;
    }
    if (p->dirty)
        ship_refuse(p, "dirty_tree",
                    "working tree is dirty — ship what is committed, not "
                    "what is lying around");
    if (p->origin_present && p->behind != 0)
        ship_refuse(p, "behind_origin",
                    "HEAD is %ld commit(s) behind origin/main — rebase "
                    "before shipping", p->behind);
    if (p->origin_present && p->ahead != 0)
        ship_refuse(p, "ahead_origin",
                    "HEAD is %ld commit(s) ahead of origin/main — dev.ship "
                    "does not push; land the commits on origin/main first",
                    p->ahead);
}

static void ship_checkout_facts(struct ship_plan *p)
{
    char status[4096];
    const char *porcelain[] = { "status", "--porcelain", NULL };
    const char *head[] = { "rev-parse", "--verify", "-q", "HEAD", NULL };
    p->behind = p->ahead = -1;
    p->checkout_ok =
        ship_git(p->root, porcelain, status, sizeof(status),
                 SHIP_GIT_TIMEOUT_MS) == 0 &&
        ship_git_oid(p->root, head, p->head);
    if (p->checkout_ok) {
        p->dirty = status[0] != '\0';
        ship_origin_facts(p);
    }
    ship_checkout_refusals(p);
}

/* ── 5-6. source id and gate stamp ──────────────────────────────────────── */

static void ship_source_id(struct ship_plan *p)
{
    char tool[SHIP_PATH + 64], out[256];
    bool timed_out = false;
    const char *argv[] = { tool, "capture", NULL };
    (void)snprintf(tool, sizeof(tool), "%s/tools/dev/source-identity.sh",
                   p->root);
    int rc = zcl_spawn_capture_in_dir_observed(argv, p->root, out, sizeof(out),
                                               SHIP_SOURCE_ID_TIMEOUT_MS,
                                               &timed_out);
    ship_trim(out);
    if (rc == 0 && !timed_out && ship_is_hex(out, 64))
        memcpy(p->source_id, out, sizeof(p->source_id));
}

/* The stamp holds ship.sh's `date -u +%Y-%m-%dT%H:%M:%SZ`; anything else
 * is reported as present without a time. */
static void ship_read_stamp(const char *path, char out[40])
{
    char line[64] = "";
    FILE *fp = fopen(path, "r");
    if (!fp)
        return;
    if (!fgets(line, sizeof(line), fp))
        line[0] = '\0';
    (void)fclose(fp);
    ship_trim(line);
    if (line[0] && strlen(line) < 40 &&
        strspn(line, "0123456789-:TZ") == strlen(line))
        (void)snprintf(out, 40, "%s", line);
}

static void ship_gate(struct ship_plan *p)
{
    const char *home = getenv("HOME");
    char path[SHIP_PATH + 128];
    struct stat st;
    if (!p->source_id[0] || !home || home[0] != '/')
        return;
    if (snprintf(path, sizeof(path), "%s/.cache/zcl-ship/%s.passed", home,
                 p->source_id) >= (int)sizeof(path))
        return;
    p->stamp_present = stat(path, &st) == 0 && S_ISREG(st.st_mode);
    if (p->stamp_present)
        ship_read_stamp(path, p->stamp_at);
    p->gate_banked = p->skip_gate && p->stamp_present;
}

/* ── 7. persistent-schema one-way detection ─────────────────────────────── */

static enum ship_one_way ship_one_way_decision(size_t changed, bool accept)
{
    if (changed == 0)
        return SHIP_ONE_WAY_NONE;
    return accept ? SHIP_ONE_WAY_ACCEPT : SHIP_ONE_WAY_REFUSE;
}

static void ship_schema(struct ship_plan *p)
{
    const char *args[] = { "diff", "--name-only", p->origin, p->head, "--",
                           ship_schema_pathspecs[0], ship_schema_pathspecs[1],
                           ship_schema_pathspecs[2], ship_schema_pathspecs[3],
                           NULL };
    if (!p->origin_present)
        return;
    int rc = ship_git(p->root, args, p->schema_files,
                      sizeof(p->schema_files), SHIP_GIT_TIMEOUT_MS);
    if (rc != 0 || strlen(p->schema_files) + 1 >= sizeof(p->schema_files)) {
        p->schema_files[0] = '\0';
        return;
    }
    p->schema_known = true;
    for (const char *c = p->schema_files; *c; c++)
        p->schema_count += *c == '\n';
    p->schema_count += p->schema_files[0] != '\0';
    p->one_way = ship_one_way_decision(p->schema_count, p->accept_one_way);
}

/* ── plan JSON ──────────────────────────────────────────────────────────── */

static const char *ship_one_way_name(const struct ship_plan *p)
{
    static const char *const names[] = { "none", "would_refuse",
                                         "forward_only_accepted" };
    return p->schema_known ? names[p->one_way] : "unknown";
}

static void ship_push_str_or_null(struct json_value *obj, const char *key,
                                  const char *s)
{
    struct json_value null;
    if (s && s[0]) {
        (void)json_push_kv_str(obj, key, s);
        return;
    }
    json_init(&null);
    json_set_null(&null);
    (void)json_push_kv(obj, key, &null);
}

static void ship_attach(struct json_value *obj, const char *key,
                        struct json_value *child)
{
    (void)json_push_kv(obj, key, child);
    json_free(child);
}

static void ship_push_array_str(struct json_value *arr, const char *s)
{
    struct json_value v;
    json_init(&v);
    json_set_str(&v, s);
    (void)json_push_back(arr, &v);
    json_free(&v);
}

static void ship_emit_targets(const struct ship_plan *p, struct json_value *d)
{
    struct json_value targets, hosts;
    json_init(&targets);
    json_set_array(&targets);
    if (p->want_local && p->local_first)
        ship_push_array_str(&targets, "local");
    if (p->want_remote)
        ship_push_array_str(&targets, "remote");
    if (p->want_local && !p->local_first)
        ship_push_array_str(&targets, "local");
    ship_attach(d, "targets", &targets);
    json_init(&hosts);
    json_set_array(&hosts);
    for (size_t i = 0; i < p->host_count; i++) {
        struct json_value h;
        json_init(&h);
        json_set_object(&h);
        (void)json_push_kv_str(&h, "name", p->hosts[i].name);
        (void)json_push_kv_bool(&h, "redacted", p->hosts[i].redacted);
        (void)json_push_back(&hosts, &h);
        json_free(&h);
    }
    ship_attach(d, "hosts", &hosts);
    ship_push_str_or_null(d, "proof_server_skipped", p->proof_skipped);
    (void)json_push_kv_bool(d, "proof_server_promoted", p->proof_promoted);
}

static void ship_emit_checkout(const struct ship_plan *p, struct json_value *d)
{
    struct json_value c;
    json_init(&c);
    json_set_object(&c);
    (void)json_push_kv_bool(&c, "readable", p->checkout_ok);
    (void)json_push_kv_bool(&c, "dirty", p->dirty);
    ship_push_str_or_null(&c, "head", p->head);
    (void)json_push_kv_bool(&c, "fetched", p->fetch_ok);
    ship_push_str_or_null(&c, "origin_main", p->origin);
    (void)json_push_kv_int(&c, "behind", p->behind);
    (void)json_push_kv_int(&c, "ahead", p->ahead);
    ship_attach(d, "checkout", &c);
}

static void ship_emit_gate(const struct ship_plan *p, struct json_value *d)
{
    struct json_value g;
    ship_push_str_or_null(d, "source_id", p->source_id);
    json_init(&g);
    json_set_object(&g);
    (void)json_push_kv_bool(&g, "skip_requested", p->skip_gate);
    (void)json_push_kv_bool(&g, "stamp_present", p->stamp_present);
    ship_push_str_or_null(&g, "stamp_at", p->stamp_at);
    (void)json_push_kv_bool(&g, "banked", p->gate_banked);
    (void)json_push_kv_str(&g, "action",
                           p->gate_banked ? "reuse_banked"
                                          : "run_lint_and_full_suite");
    ship_attach(d, "gate", &g);
}

static void ship_emit_schema(const struct ship_plan *p, struct json_value *d)
{
    struct json_value s, files;
    char buf[SHIP_SCHEMA_BYTES];
    char *save = NULL;
    json_init(&s);
    json_set_object(&s);
    (void)json_push_kv_str(&s, "baseline", "origin/main");
    (void)json_push_kv_bool(&s, "advisory", true);
    (void)json_push_kv_str(&s, "verdict", ship_one_way_name(p));
    if (p->schema_known)
        (void)json_push_kv_int(&s, "decision_rc", (int64_t)p->one_way);
    (void)json_push_kv_bool(&s, "accept_one_way", p->accept_one_way);
    json_init(&files);
    json_set_array(&files);
    (void)snprintf(buf, sizeof(buf), "%s", p->schema_files);
    for (char *line = strtok_r(buf, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save))
        ship_push_array_str(&files, line);
    ship_attach(&s, "files", &files);
    ship_attach(d, "schema_one_way", &s);
}

static void ship_emit_refusal(const struct ship_plan *p, struct json_value *d)
{
    struct json_value r, not_checked;
    static const char *const unported[] = {
        "prepare_tools", "tor_archives", "dev_artifact_names",
        "remote_reachability_cpu_glibc",
    };
    (void)json_push_kv_str(d, "verdict", p->refusal[0] ? "refuse" : "ready");
    if (p->refusal[0]) {
        json_init(&r);
        json_set_object(&r);
        (void)json_push_kv_str(&r, "class", p->refusal);
        (void)json_push_kv_str(&r, "message", p->refusal_message);
        ship_attach(d, "refusal", &r);
    } else {
        ship_push_str_or_null(d, "refusal", NULL);
    }
    json_init(&not_checked);
    json_set_array(&not_checked);
    for (size_t i = 0; i < sizeof(unported) / sizeof(unported[0]); i++)
        ship_push_array_str(&not_checked, unported[i]);
    ship_attach(d, "not_checked", &not_checked);
}

static void ship_screen_hosts(const struct ship_plan *p, char *out,
                              size_t cap)
{
    size_t used = 0;
    out[0] = '\0';
    for (size_t i = 0; i < p->host_count && used < cap; i++) {
        int n = snprintf(out + used, cap - used, "%s%s", i ? " " : "",
                         p->hosts[i].name);
        if (n < 0)
            return;
        used += (size_t)n;
    }
}

static void ship_screen(const struct ship_plan *p, struct json_value *d)
{
    char screen[1024], hosts[512];
    const char *mode = p->dry_run ? "dry run" : "plan only";
    if (p->refusal[0]) {
        (void)snprintf(screen, sizeof(screen),
                       "dev ship (%s): REFUSE %s: %s", mode, p->refusal,
                       p->refusal_message);
    } else {
        ship_screen_hosts(p, hosts, sizeof(hosts));
        (void)snprintf(screen, sizeof(screen),
                       "dev ship (%s): READY %.12s -> %s%s%s [%s]; source "
                       "%.16s; gate %s; schema %s. Phase 1 plans only: "
                       "tools/ship.sh still builds and deploys.",
                       mode, p->head, p->want_local ? "local" : "",
                       p->want_local && p->want_remote ? " + " : "",
                       p->want_remote ? "remote" : "", hosts,
                       p->source_id[0] ? p->source_id : "unavailable",
                       p->gate_banked ? "banked" : "will run lint + full suite",
                       ship_one_way_name(p));
    }
    (void)json_push_kv_str(d, "screen", screen);
}

static void ship_emit(const struct ship_plan *p, struct json_value *d)
{
    (void)json_push_kv_int(d, "phase", 1);
    (void)json_push_kv_bool(d, "dry_run", p->dry_run);
    ship_emit_refusal(p, d);
    ship_emit_targets(p, d);
    ship_emit_checkout(p, d);
    ship_emit_gate(p, d);
    ship_emit_schema(p, d);
    (void)json_push_kv_str(d, "deploy", "not_ported");
    ship_screen(p, d);
}

/* ── handler ────────────────────────────────────────────────────────────── */

static bool ship_resolve_root(struct ship_plan *p, const char *given)
{
    const char *args[] = { "rev-parse", "--show-toplevel", NULL };
    struct stat st;
    if (given) {
        if (given[0] != '/' || strlen(given) >= sizeof(p->root) ||
            stat(given, &st) != 0 || !S_ISDIR(st.st_mode))
            return false;
        (void)snprintf(p->root, sizeof(p->root), "%s", given);
        return true;
    }
    return ship_git(".", args, p->root, sizeof(p->root),
                    SHIP_GIT_TIMEOUT_MS) == 0 &&
           p->root[0] == '/';
}

static bool ship_read_input(struct ship_plan *p,
                            const struct json_value *input,
                            struct zcl_command_reply *reply)
{
    p->dry_run = ship_input_bool(input, "dry_run");
    p->skip_gate = ship_input_bool(input, "skip_gate");
    p->accept_one_way = ship_input_bool(input, "accept_one_way");
    if (!ship_parse_targets(p, ship_input_str(input, "targets"))) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "INVALID_INPUT",
                               "normalize", false, false,
                               "targets is a comma- or space-separated list "
                               "of local and remote",
                               "input.targets");
        return false;
    }
    if (!ship_resolve_root(p, ship_input_str(input, "root"))) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "INVALID_INPUT",
                               "normalize", false, false,
                               "root must be an absolute checkout directory, "
                               "or omitted inside a git checkout",
                               "input.root");
        return false;
    }
    return true;
}

static void ship_finish(const struct ship_plan *p,
                        struct zcl_command_reply *reply)
{
    char evidence[64];
    if (p->dry_run) {
        reply->status = ZCL_COMMAND_STATUS_PASSED;
        return;
    }
    if (p->refusal[0]) {
        (void)snprintf(evidence, sizeof(evidence), "refusal.class=%s",
                       p->refusal);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "SHIP_REFUSED",
                               "preflight", false, false, p->refusal_message,
                               evidence);
        return;
    }
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                           ZCL_COMMAND_EXIT_BLOCKED, "SHIP_DEPLOY_NOT_PORTED",
                           "plan", false, false,
                           "dev ship phase 1 plans only: rerun with "
                           "--dry_run for the plan; tools/ship.sh (make ship) "
                           "builds and deploys",
                           "phase=1");
    (void)zcl_command_reply_add_next(reply, "dev.fleet.ship",
                                     "{\"dry_run\":true}",
                                     "print the preflight and plan");
}

void zcl_native_handle_dev_ship(const struct zcl_command_request *request,
                                struct zcl_command_reply *reply)
{
    struct ship_plan *p;
    if (!reply)
        return;
    p = zcl_calloc(1, sizeof(*p), "dev_ship_plan");
    if (!p) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "INTERNAL",
                               "plan", true, false,
                               "out of memory allocating the ship plan",
                               "calloc");
        return;
    }
    if (ship_read_input(p, request ? request->input : NULL, reply)) {
        if (p->want_remote)
            ship_parse_hosts(p);
        ship_checkout_facts(p);
        if (p->checkout_ok) {
            ship_source_id(p);
            ship_gate(p);
            ship_schema(p);
        }
        ship_emit(p, &reply->data);
        ship_finish(p, reply);
    }
    free(p);
}
