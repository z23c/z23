/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: z23-lab-peer, the continuous loop between independent labs, as a
 * typed C23 tool. It only COMPOSES existing authorities (dev land send /
 * reverify_offer / qualify_offer, fleet bundle offer / fetch, fleet board
 * post / list); it adds no store, wire format or quorum rule.
 *
 *   offer   --lane=DIR --commit=SHA --state=DIR [--room=lab] [--agent=NAME]
 *       dev land send (bundle + offer manifest) -> fleet bundle offer (Tor
 *       package swarm) -> fleet board post offer "lab-offer v1 root= size=
 *       onion= offer=<manifest json>"; one row appended to STATE/offers.tsv.
 *       A post that would exceed the board's 2048-byte text cap is refused
 *       (OFFER_TEXT_TOO_LONG) and nothing is posted.
 *   verify  --state=DIR --repo=DIR --authors=FILE [--room=lab] [--max=N]
 *       board list -> for each offer post from an allowlisted key that is
 *       unexpired, well-formed and not yet handled: fleet bundle fetch ->
 *       dev land reverify_offer -> a signed receipt (or a typed refusal) posted
 *       as kind result with ref = the offer post. STATE/handled.tsv makes a post
 *       processed once; a failed fetch is retryable, three attempts in all.
 *   collect --state=DIR [--room=lab] [--require=1]
 *       board list -> the verdict=ok receipts answering each offers.tsv row
 *       -> STATE/receipts/<post>-<host12>.json -> dev land qualify_offer ->
 *       STATE/qualified.tsv. SHADOW MODE: it never submits to or changes the
 *       land queue; the only dev land leaf it runs is qualify_offer.
 *
 * One JSON document per run on stdout (zcl.lab_peer.v1); exit 0 when the run
 * completed (items may have failed), 2 on a usage error.
 *
 * A tool, not a node leaf, for the reasons tools/engine_unit.c gives: it
 * launches programs. Every child goes through zcl_spawn_capture* with an argv
 * (no shell); --z23= and --z23dev= name the programs so a test runs the whole
 * tool against fakes. Fetched bytes are never executed here: the only step
 * that builds offered code is reverify_offer, under local policy. Everything
 * is bounded: posts read, text, file sizes, receipts per offer.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "json/json.h"
#include "platform/clock.h"
#include "util/spawn.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

enum {
    LP_PATH = 1024,
    LP_NAME = 64,
    LP_BUF = 1 << 20,        /* one child's stdout, one state file */
    LP_TEXT_MAX = 2048,      /* FLEET_BOARD_TEXT_MAX */
    LP_OFFER_JSON = 2048,    /* the offer manifest, on one line */
    LP_RECEIPT_JSON = 1200,  /* a receipt (~520 bytes) on one line */
    LP_SIZE_MAX = 5242880,   /* the largest bundle a lab fetches */
    LP_POSTS_MAX = 200,
    LP_VERIFY_MAX = 50,
    LP_KEYS_MAX = 256,
    LP_ROWS_MAX = 256,
    LP_RECEIPTS_MAX = 32,    /* qualify_offer's list cap */
    LP_ATTEMPTS = 3,         /* fetch attempts before a post is given up */
    LP_QUICK_S = 60,
    LP_FETCH_S = 300,
    LP_CX_S = 2400,
    LP_ONION_LEN = 62
};

enum lp_opt {
#define LP_OPTS(X)                                                           \
    X(LANE, "lane", NULL) X(COMMIT, "commit", NULL) X(STATE, "state", NULL)  \
    X(ROOM, "room", "lab") X(AGENT, "agent", "lab-peer")                     \
    X(REPO, "repo", NULL) X(AUTHORS, "authors", NULL) X(MAX, "max", "10")    \
    X(REQUIRE, "require", "1") X(Z23, "z23", "z23")                          \
    X(Z23DEV, "z23dev", "z23-dev")
#define X(id, name, dflt) LP_O_##id,
    LP_OPTS(X)
#undef X
        LP_O_COUNT
};

static const char *const k_opt_names[LP_O_COUNT] = {
#define X(id, name, dflt) name,
    LP_OPTS(X)
#undef X
};
static const char *const k_opt_defaults[LP_O_COUNT] = {
#define X(id, name, dflt) dflt,
    LP_OPTS(X)
#undef X
};

struct lp_ctx {
    const char *v[LP_O_COUNT];
    char state[PATH_MAX];
    int64_t now;
    char authors[LP_KEYS_MAX][65];
    int n_authors;
    struct json_value items;
    int n_items, n_ok, n_refused, n_failed, n_skipped;
};

static char g_child[LP_BUF]; /* the last child's stdout */
static char g_file[LP_BUF];  /* the last state file read */
static char g_out[LP_BUF];   /* the document printed */

/* ── small helpers ─────────────────────────────────────────────────────── */

__attribute__((format(printf, 3, 4))) static bool
lp_fmt(char *dst, size_t cap, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    const int n = vsnprintf(dst, cap, fmt, ap);
    va_end(ap);
    return n >= 0 && (size_t)n < cap;
}

static bool lp_hex(const char *s, size_t n)
{
    if (!s || strlen(s) != n)
        return false;
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    return true;
}

static bool lp_commit(const char *s)
{
    return lp_hex(s, 40) || lp_hex(s, 64);
}

/* [A-Za-z0-9._-], 1..max, not starting with a dot: safe in a file name, a
 * TSV field and a one-line post. */
static bool lp_name(const char *s, size_t max)
{
    if (!s || !s[0] || strlen(s) > max || s[0] == '.')
        return false;
    for (const char *p = s; *p; p++) {
        const char c = *p;
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') || c == '.' || c == '_' || c == '-'))
            return false;
    }
    return true;
}

/* A refusal code: [A-Z0-9_], 1..64. Anything else is not echoed. */
static bool lp_code_ok(const char *s)
{
    if (!s || !s[0] || strlen(s) > 64)
        return false;
    for (const char *p = s; *p; p++)
        if (!((*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == '_'))
            return false;
    return true;
}

static bool lp_onion(const char *s)
{
    if (!s || strlen(s) != LP_ONION_LEN || strcmp(s + 56, ".onion") != 0)
        return false;
    for (int i = 0; i < 56; i++)
        if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= '2' && s[i] <= '7')))
            return false;
    return true;
}

/* Decimal 1..hi with no sign, space or leading zero. */
static bool lp_decimal(const char *s, int64_t hi, int64_t *out)
{
    if (!s || !s[0] || strlen(s) > 18 || s[0] == '0')
        return false;
    int64_t v = 0;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9')
            return false;
        v = v * 10 + (*p - '0');
    }
    if (v < 1 || v > hi)
        return false;
    *out = v;
    return true;
}

static const char *lp_str(const struct json_value *obj, const char *key)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

static bool lp_has_prefix(const char *s, const char *prefix)
{
    return s && strncmp(s, prefix, strlen(prefix)) == 0;
}

/* The file's bytes in g_file, NUL-terminated; false when unreadable or over
 * the cap (never a truncated read). */
static bool lp_read(const char *path, size_t *len_out)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    const size_t n = fread(g_file, 1, sizeof(g_file) - 1, f);
    const bool whole = feof(f) && !ferror(f);
    (void)fclose(f);
    g_file[n] = '\0';
    if (len_out)
        *len_out = n;
    return whole;
}

static bool lp_write(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    const size_t n = strlen(text);
    const bool ok = fwrite(text, 1, n, f) == n;
    return fclose(f) == 0 && ok;
}

static bool lp_append(const char *path, const char *line)
{
    FILE *f = fopen(path, "ab");
    if (!f)
        return false;
    bool ok = fputs(line, f) >= 0 && fflush(f) == 0 && fsync(fileno(f)) == 0;
    ok = (fclose(f) == 0) && ok;
    return ok;
}

/* Re-serialises JSON text on one line; false when it is not JSON, not an
 * object, or does not fit. */
static bool lp_compact(const char *raw, char *out, size_t cap)
{
    struct json_value v;
    json_init(&v);
    bool ok = json_read(&v, raw, strlen(raw)) && v.type == JSON_OBJ;
    if (ok)
        ok = json_write(&v, out, cap) < cap;
    json_free(&v);
    return ok && !strchr(out, '\n') && !strchr(out, '\t');
}

/* ── children ──────────────────────────────────────────────────────────── */

/* Runs one program from argv (no shell); its stdout is parsed into root. True
 * when it ran to completion and printed one JSON document. */
static bool lp_run(const char *const argv[], const char *cwd, int timeout_s,
                   struct json_value *root)
{
    bool timed_out = false;
    json_init(root);
    const int rc = zcl_spawn_capture_in_dir_observed(
        argv, cwd, g_child, sizeof(g_child), timeout_s * 1000, &timed_out);
    if (rc < 0 || timed_out)
        return false;
    return json_read(root, g_child, strlen(g_child));
}

/* The data object of an ok reply, else NULL. */
static const struct json_value *lp_data(const struct json_value *root)
{
    const struct json_value *ok = json_get(root, "ok");
    if (!ok || ok->type != JSON_BOOL || !json_get_bool(ok))
        return NULL;
    return json_get(root, "data");
}

/* A refusal's typed code in out (never free text), or fallback. */
static const char *lp_err_code(const struct json_value *root, const char *fallback,
                               char *out, size_t cap)
{
    const char *c = lp_str(json_get(root, "error"), "code");
    if (!lp_code_ok(c) || !lp_fmt(out, cap, "%s", c))
        (void)lp_fmt(out, cap, "%s", fallback);
    return out;
}

/* ── options, state, output ────────────────────────────────────────────── */

static bool lp_parse_args(struct lp_ctx *c, int argc, char **argv)
{
    bool seen[LP_O_COUNT] = {false};
    for (int i = 0; i < LP_O_COUNT; i++)
        c->v[i] = k_opt_defaults[i];
    for (int i = 2; i < argc; i++) {
        const char *eq = strchr(argv[i], '=');
        int hit = -1;
        if (!lp_has_prefix(argv[i], "--") || !eq || !eq[1])
            return false;
        for (int o = 0; o < LP_O_COUNT; o++)
            if (strlen(k_opt_names[o]) == (size_t)(eq - argv[i] - 2) &&
                strncmp(argv[i] + 2, k_opt_names[o], (size_t)(eq - argv[i] - 2)) == 0)
                hit = o;
        if (hit < 0 || seen[hit])
            return false;
        seen[hit] = true;
        c->v[hit] = eq + 1;
    }
    return true;
}

static bool lp_mkdir(const char *path)
{
    return mkdir(path, 0700) == 0 || errno == EEXIST;
}

/* STATE and its subdirectories; c->state becomes absolute. */
static bool lp_state_init(struct lp_ctx *c)
{
    static const char *const k_sub[] = {"in", "out", "receipts"};
    char sub[LP_PATH + 16];
    if (!c->v[LP_O_STATE] || !lp_mkdir(c->v[LP_O_STATE]) ||
        !realpath(c->v[LP_O_STATE], c->state))
        return false;
    for (size_t i = 0; i < sizeof(k_sub) / sizeof(k_sub[0]); i++)
        if (!lp_fmt(sub, sizeof(sub), "%s/%s", c->state, k_sub[i]) ||
            !lp_mkdir(sub))
            return false;
    return true;
}

/* One run at a time per state dir. */
static bool lp_lock(const struct lp_ctx *c)
{
    char path[LP_PATH + 16];
    if (!lp_fmt(path, sizeof(path), "%s/lock", c->state))
        return false;
    const int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    return fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) == 0; /* held to exit */
}

static void lp_item(struct lp_ctx *c, const char *id, const char *status,
                    const char *code)
{
    struct json_value o;
    json_init(&o);
    json_set_object(&o);
    (void)json_push_kv_str(&o, "id", id ? id : "");
    (void)json_push_kv_str(&o, "status", status);
    (void)json_push_kv_str(&o, "code", code ? code : "");
    (void)json_push_back(&c->items, &o);
    json_free(&o);
    c->n_items++;
    if (strcmp(status, "ok") == 0)
        c->n_ok++;
    else if (strcmp(status, "refused") == 0)
        c->n_refused++;
    else if (strcmp(status, "skipped") == 0)
        c->n_skipped++;
    else
        c->n_failed++;
}

static void lp_items_init(struct lp_ctx *c)
{
    json_init(&c->items);
    json_set_array(&c->items);
}

/* The one document of the run. */
static void lp_emit(const struct lp_ctx *c, const char *cmd, bool ok,
                    const char *code)
{
    struct json_value d, counts;
    json_init(&d);
    json_init(&counts);
    json_set_object(&d);
    json_set_object(&counts);
    (void)json_push_kv_str(&d, "schema", "zcl.lab_peer.v1");
    (void)json_push_kv_str(&d, "command", cmd);
    (void)json_push_kv_bool(&d, "ok", ok);
    (void)json_push_kv_str(&d, "code", code ? code : "");
    (void)json_push_kv_int(&counts, "items", c->n_items);
    (void)json_push_kv_int(&counts, "ok", c->n_ok);
    (void)json_push_kv_int(&counts, "refused", c->n_refused);
    (void)json_push_kv_int(&counts, "failed", c->n_failed);
    (void)json_push_kv_int(&counts, "skipped", c->n_skipped);
    (void)json_push_kv(&d, "counts", &counts);
    (void)json_push_kv(&d, "items", &c->items);
    if (json_write(&d, g_out, sizeof(g_out)) >= sizeof(g_out))
        (void)snprintf(g_out, sizeof(g_out),
                       "{\"schema\":\"zcl.lab_peer.v1\",\"ok\":false,"
                       "\"code\":\"OUTPUT_TOO_LARGE\"}");
    (void)puts(g_out);
    json_free(&counts);
    json_free(&d);
}

static int lp_usage(void)
{
    (void)fputs(
        "usage: z23-lab-peer offer --lane=DIR --commit=SHA --state=DIR "
        "[--room=lab] [--agent=NAME]\n"
        "       z23-lab-peer verify --state=DIR --repo=DIR --authors=FILE "
        "[--room=lab] [--max=N]\n"
        "       z23-lab-peer collect --state=DIR [--room=lab] [--require=1]\n"
        "       (--z23=PROGRAM --z23dev=PROGRAM name the CLIs; see "
        "tools/lab_peer.c)\n",
        stderr);
    return 2;
}

/* ── offer ─────────────────────────────────────────────────────────────── */

struct lp_made {
    char name[LP_NAME + 1];
    char bundle[LP_PATH + 64];
    char offer_path[LP_PATH + 80];
    char sha[65], commit[65], base[65];
    char offer_json[LP_OFFER_JSON];
    char root[65], onion[LP_ONION_LEN + 1];
    int64_t size;
    char text[LP_TEXT_MAX + 512];
    char post_id[65];
};

static const char *lp_basename(const char *path)
{
    const char *s = strrchr(path, '/');
    return s ? s + 1 : path;
}

/* Reads the offer manifest the send wrote: one-line copy, base, and the checks
 * that it names this commit and bundle. NULL when fine, else a code. */
static const char *lp_offer_manifest(struct lp_made *m)
{
    struct json_value doc;
    const char *code = "OFFER_MANIFEST_BAD";
    json_init(&doc);
    if (lp_read(m->offer_path, NULL) && json_read(&doc, g_file, strlen(g_file)) &&
        lp_compact(g_file, m->offer_json, sizeof(m->offer_json))) {
        const char *base = lp_str(&doc, "base");
        const bool same = lp_str(&doc, "commit") &&
                          strcmp(lp_str(&doc, "commit"), m->commit) == 0 &&
                          lp_str(&doc, "bundle_sha256") &&
                          strcmp(lp_str(&doc, "bundle_sha256"), m->sha) == 0;
        if (lp_commit(base) && same && lp_fmt(m->base, sizeof(m->base), "%s", base))
            code = NULL;
    }
    json_free(&doc);
    return code;
}

/* Step 1: dev land send, in the lane worktree. */
static const char *lp_offer_send(const struct lp_ctx *c, struct lp_made *m,
                                 char *why, size_t why_cap)
{
    char lane_arg[LP_NAME + 16], commit_arg[96], out_arg[LP_PATH + 96];
    struct json_value root;
    const char *code = "OFFER_SEND_FAILED";
    if (!lp_fmt(lane_arg, sizeof(lane_arg), "--lane=%s", m->name) ||
        !lp_fmt(commit_arg, sizeof(commit_arg), "--commit=%s",
                c->v[LP_O_COMMIT]) ||
        !lp_fmt(m->bundle, sizeof(m->bundle), "%s/out/%s-%.12s.bundle", c->state,
                m->name, c->v[LP_O_COMMIT]) ||
        !lp_fmt(m->offer_path, sizeof(m->offer_path), "%s.offer.json", m->bundle) ||
        !lp_fmt(out_arg, sizeof(out_arg), "--bundle_out=%s", m->bundle))
        return "OFFER_PATH_TOO_LONG";
    const char *const argv[] = {c->v[LP_O_Z23DEV], "dev", "land", "send",
                                commit_arg, lane_arg, "--precheck=skip", out_arg,
                                NULL};
    if (lp_run(argv, c->v[LP_O_LANE], LP_CX_S, &root)) {
        const struct json_value *d = lp_data(&root);
        const char *sha = lp_str(d, "bundle_sha256");
        if (!d)
            (void)lp_err_code(&root, code, why, why_cap);
        else if (lp_hex(sha, 64) && lp_fmt(m->sha, sizeof(m->sha), "%s", sha) &&
                 lp_fmt(m->commit, sizeof(m->commit), "%s", c->v[LP_O_COMMIT]))
            code = lp_offer_manifest(m);
    }
    json_free(&root);
    return code;
}

/* Step 2: put the bundle on the Tor package swarm. */
static const char *lp_offer_swarm(const struct lp_ctx *c, struct lp_made *m)
{
    char file_arg[LP_PATH + 96];
    struct json_value root;
    const char *code = "OFFER_SWARM_FAILED";
    if (!lp_fmt(file_arg, sizeof(file_arg), "--file=%s", m->bundle))
        return "OFFER_PATH_TOO_LONG";
    const char *const argv[] = {c->v[LP_O_Z23], "fleet", "bundle", "offer",
                                file_arg, NULL};
    if (lp_run(argv, NULL, LP_QUICK_S, &root)) {
        const struct json_value *d = lp_data(&root);
        const struct json_value *size = d ? json_get(d, "size") : NULL;
        const char *sha = lp_str(d, "sha256");
        if (size && size->type == JSON_INT && json_get_int(size) > 0 &&
            json_get_int(size) <= LP_SIZE_MAX && sha && strcmp(sha, m->sha) == 0 &&
            lp_hex(lp_str(d, "root"), 64) && lp_onion(lp_str(d, "onion")) &&
            lp_fmt(m->root, sizeof(m->root), "%s", lp_str(d, "root")) &&
            lp_fmt(m->onion, sizeof(m->onion), "%s", lp_str(d, "onion"))) {
            m->size = json_get_int(size);
            code = NULL;
        }
    }
    json_free(&root);
    return code;
}

/* Step 3: the post text; refused over the board's cap. */
static const char *lp_offer_text(struct lp_made *m)
{
    const int n = snprintf(m->text, sizeof(m->text),
                           "lab-offer v1 root=%s size=%lld onion=%s offer=%s",
                           m->root, (long long)m->size, m->onion, m->offer_json);
    return n < 0 || n > LP_TEXT_MAX ? "OFFER_TEXT_TOO_LONG" : NULL;
}

static const char *lp_offer_post(const struct lp_ctx *c, struct lp_made *m)
{
    char room[96], agent[96];
    struct json_value root;
    const char *code = "OFFER_POST_FAILED";
    if (!lp_fmt(room, sizeof(room), "--room=%s", c->v[LP_O_ROOM]) ||
        !lp_fmt(agent, sizeof(agent), "--agent=%s", c->v[LP_O_AGENT]))
        return "OFFER_POST_FAILED";
    const char *const argv[] = {c->v[LP_O_Z23], "fleet", "board", "post", "offer",
                                m->text, room, agent, NULL};
    if (lp_run(argv, NULL, LP_QUICK_S, &root)) {
        const char *id = lp_str(lp_data(&root), "id");
        if (lp_hex(id, 64) && lp_fmt(m->post_id, sizeof(m->post_id), "%s", id))
            code = NULL;
    }
    json_free(&root);
    return code;
}

static bool lp_offer_record(const struct lp_ctx *c, const struct lp_made *m)
{
    char path[LP_PATH + 16], row[4 * LP_PATH];
    return lp_fmt(path, sizeof(path), "%s/offers.tsv", c->state) &&
           lp_fmt(row, sizeof(row), "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
                  m->post_id, m->name, m->commit, m->base, m->sha, m->root,
                  m->bundle, m->offer_path) &&
           lp_append(path, row);
}

static bool lp_offer_args(const struct lp_ctx *c, struct lp_made *m)
{
    struct stat st;
    char real[PATH_MAX];
    if (!c->v[LP_O_LANE] || !c->v[LP_O_COMMIT] || !c->v[LP_O_STATE] ||
        !lp_commit(c->v[LP_O_COMMIT]) || !lp_name(c->v[LP_O_ROOM], 32) ||
        !lp_name(c->v[LP_O_AGENT], 32) || stat(c->v[LP_O_LANE], &st) != 0 ||
        !S_ISDIR(st.st_mode) || !realpath(c->v[LP_O_LANE], real))
        return false;
    return lp_fmt(m->name, sizeof(m->name), "%s", lp_basename(real)) &&
           lp_name(m->name, LP_NAME);
}

static int lp_cmd_offer(struct lp_ctx *c)
{
    static struct lp_made m;
    char why[80] = "";
    const char *code;
    if (!lp_offer_args(c, &m) || !lp_state_init(c))
        return lp_usage();
    if (!lp_lock(c)) {
        lp_emit(c, "offer", false, "LOCKED");
        return 0;
    }
    lp_items_init(c);
    code = lp_offer_send(c, &m, why, sizeof(why));
    code = code ? code : lp_offer_swarm(c, &m);
    code = code ? code : lp_offer_text(&m);
    code = code ? code : lp_offer_post(c, &m);
    if (!code && !lp_offer_record(c, &m))
        code = "OFFER_RECORD_FAILED";
    if (why[0] && code && strcmp(code, "OFFER_SEND_FAILED") == 0)
        code = why;
    lp_item(c, m.post_id, code ? "failed" : "ok", code);
    lp_emit(c, "offer", code == NULL, code);
    return 0;
}

/* ── verify ────────────────────────────────────────────────────────────── */

struct lp_parsed {
    char root[65], onion[LP_ONION_LEN + 1], sha[65], commit[65], base[65];
    char size_s[16];
    int64_t size;
    char offer_json[LP_OFFER_JSON + 1];
};

/* Takes "key=" then a value up to the next space (or, with rest, the end of
 * the text) off *p, then the one space after it. */
static bool lp_take(const char **p, const char *key, bool rest, char *out,
                    size_t cap)
{
    const size_t kl = strlen(key);
    if (strncmp(*p, key, kl) != 0)
        return false;
    const char *v = *p + kl;
    const char *end = rest ? v + strlen(v) : strchr(v, ' ');
    if (!end || end == v || (size_t)(end - v) >= cap)
        return false;
    memcpy(out, v, (size_t)(end - v));
    out[end - v] = '\0';
    *p = rest ? end : end + 1;
    return true;
}

/* The manifest inside a post: schema and hex shapes, consistent fields. */
static bool lp_parse_manifest(struct lp_parsed *o, const char *json)
{
    struct json_value doc;
    json_init(&doc);
    bool ok = json_read(&doc, json, strlen(json)) && doc.type == JSON_OBJ &&
              lp_str(&doc, "schema") &&
              strcmp(lp_str(&doc, "schema"), "zcl.dev_land_offer.v1") == 0 &&
              lp_commit(lp_str(&doc, "commit")) &&
              lp_commit(lp_str(&doc, "base")) &&
              lp_hex(lp_str(&doc, "bundle_sha256"), 64) &&
              lp_name(lp_str(&doc, "lane"), LP_NAME);
    if (ok)
        ok = lp_fmt(o->commit, sizeof(o->commit), "%s", lp_str(&doc, "commit")) &&
             lp_fmt(o->base, sizeof(o->base), "%s", lp_str(&doc, "base")) &&
             lp_fmt(o->sha, sizeof(o->sha), "%s", lp_str(&doc, "bundle_sha256")) &&
             lp_compact(json, o->offer_json, sizeof(o->offer_json));
    json_free(&doc);
    return ok;
}

/* Strict parse of `lab-offer v1 root=<64hex> size=<n> onion=<v3> offer=<json>`. */
static bool lp_parse_offer(const char *text, struct lp_parsed *o)
{
    const char *p = text + strlen("lab-offer v1 ");
    char json[LP_OFFER_JSON + 1];
    memset(o, 0, sizeof(*o));
    if (strlen(text) > LP_TEXT_MAX || !lp_take(&p, "root=", false, o->root, 65) ||
        !lp_hex(o->root, 64) || !lp_take(&p, "size=", false, o->size_s, 16) ||
        !lp_decimal(o->size_s, LP_SIZE_MAX, &o->size) ||
        !lp_take(&p, "onion=", false, o->onion, sizeof(o->onion)) ||
        !lp_onion(o->onion) || !lp_take(&p, "offer=", true, json, sizeof(json)))
        return false;
    return lp_parse_manifest(o, json);
}

static void lp_load_authors(struct lp_ctx *c)
{
    size_t len;
    c->n_authors = 0;
    if (!lp_read(c->v[LP_O_AUTHORS], &len))
        return;
    for (char *line = strtok(g_file, "\n"); line && c->n_authors < LP_KEYS_MAX;
         line = strtok(NULL, "\n")) {
        char key[65];
        if (strlen(line) != 64)
            continue;
        for (int i = 0; i < 64; i++)
            key[i] = (char)(line[i] >= 'A' && line[i] <= 'F' ? line[i] + 32 : line[i]);
        key[64] = '\0';
        if (lp_hex(key, 64))
            memcpy(c->authors[c->n_authors++], key, 65);
    }
}

static bool lp_author_ok(const struct lp_ctx *c, const char *host)
{
    for (int i = 0; i < c->n_authors; i++)
        if (host && strcmp(c->authors[i], host) == 0)
            return true;
    return false;
}

/* handled.tsv: id, verdict, code, seconds. Final when ok/refused/failed;
 * retries counts the retry rows. */
static bool lp_handled(const struct lp_ctx *c, const char *id, int *retries)
{
    char path[LP_PATH + 16], key[72];
    bool final = false;
    *retries = 0;
    if (!lp_fmt(path, sizeof(path), "%s/handled.tsv", c->state) ||
        !lp_fmt(key, sizeof(key), "%s\t", id) || !lp_read(path, NULL))
        return false;
    for (const char *l = g_file; l && *l; l = strchr(l, '\n') ? strchr(l, '\n') + 1 : NULL) {
        if (strncmp(l, key, strlen(key)) != 0)
            continue;
        if (lp_has_prefix(l + strlen(key), "retry\t"))
            (*retries)++;
        else
            final = true;
    }
    return final;
}

static void lp_handled_row(const struct lp_ctx *c, const char *id,
                           const char *verdict, const char *code, int64_t t0)
{
    char path[LP_PATH + 16], row[256];
    if (lp_fmt(path, sizeof(path), "%s/handled.tsv", c->state) &&
        lp_fmt(row, sizeof(row), "%s\t%s\t%s\t%lld\n", id, verdict,
               code ? code : "", (long long)(clock_now_wall_ms() / 1000 - t0)))
        (void)lp_append(path, row);
}

/* Step 5: fetch into STATE/in/<id>.bundle. */
static bool lp_fetch(const struct lp_ctx *c, const struct lp_parsed *o,
                     const char *bundle)
{
    char root[96], sha[96], size[48], out[LP_PATH + 96], peer[96];
    struct json_value r;
    if (!lp_fmt(root, sizeof(root), "--root=%s", o->root) ||
        !lp_fmt(sha, sizeof(sha), "--sha256=%s", o->sha) ||
        !lp_fmt(size, sizeof(size), "--size=%lld", (long long)o->size) ||
        !lp_fmt(out, sizeof(out), "--out=%s", bundle) ||
        !lp_fmt(peer, sizeof(peer), "--peer=%s", o->onion))
        return false;
    (void)unlink(bundle); /* fetch never overwrites; a stale partial is ours */
    const char *const argv[] = {c->v[LP_O_Z23], "fleet", "bundle", "fetch", root,
                                sha, size, out, peer, "--timeout_s=300", NULL};
    const bool ok = lp_run(argv, NULL, LP_FETCH_S + 30, &r) && lp_data(&r) &&
                    access(bundle, R_OK) == 0;
    json_free(&r);
    return ok;
}

/* Step 6: reverify; true on a pass with the one-line receipt in line, else
 * code holds the typed refusal (and *retry is set for a non-answer). */
static bool lp_reverify(const struct lp_ctx *c, const char *bundle,
                        const char *offer, const char *receipt, char *line,
                        size_t line_cap, char *code, bool *retry)
{
    char b[LP_PATH + 96], o[LP_PATH + 96], r[LP_PATH + 96], repo[LP_PATH + 16];
    struct json_value root;
    *retry = false;
    if (!lp_fmt(b, sizeof(b), "--bundle=%s", bundle) ||
        !lp_fmt(o, sizeof(o), "--offer=%s", offer) ||
        !lp_fmt(r, sizeof(r), "--receipt_out=%s", receipt) ||
        !lp_fmt(repo, sizeof(repo), "--repo=%s", c->v[LP_O_REPO]))
        return *retry = true, false;
    (void)unlink(receipt);
    const char *const argv[] = {c->v[LP_O_Z23DEV], "dev", "land", "reverify_offer",
                                b, o, repo, r, NULL};
    if (!lp_run(argv, NULL, LP_CX_S + 60, &root)) {
        *retry = true;
        json_free(&root);
        return false;
    }
    bool ok = lp_data(&root) != NULL;
    if (!ok)
        (void)lp_err_code(&root, "REVERIFY_REFUSED", code, 65);
    else if (!lp_read(receipt, NULL) || !lp_compact(g_file, line, line_cap))
        ok = false, *retry = true;
    json_free(&root);
    return ok;
}

/* Step 6b: the signed result, ref = the offer post. */
static bool lp_post_result(const struct lp_ctx *c, const char *id,
                           const char *text)
{
    char ref[96], room[96], agent[96];
    struct json_value r;
    if (!lp_fmt(ref, sizeof(ref), "--ref=%s", id) ||
        !lp_fmt(room, sizeof(room), "--room=%s", c->v[LP_O_ROOM]) ||
        !lp_fmt(agent, sizeof(agent), "--agent=%s", c->v[LP_O_AGENT]))
        return false;
    const char *const argv[] = {c->v[LP_O_Z23], "fleet", "board", "post", "result",
                                text, ref, room, agent, NULL};
    const bool ok = lp_run(argv, NULL, LP_QUICK_S, &r) && lp_data(&r);
    json_free(&r);
    return ok;
}

/* A retryable failure: a retry row, or the final failed row on the last try. */
static void lp_fail(struct lp_ctx *c, const char *id, const char *code,
                    int prior, int64_t t0)
{
    const bool last = prior + 1 >= LP_ATTEMPTS;
    lp_handled_row(c, id, last ? "failed" : "retry", code, t0);
    lp_item(c, id, last ? "failed" : "retry", code);
}

struct lp_paths {
    char offer[LP_PATH + 64], bundle[LP_PATH + 64], receipt[LP_PATH + 64];
};

static bool lp_stage(const struct lp_ctx *c, const char *id,
                     const struct lp_parsed *o, struct lp_paths *p)
{
    return lp_fmt(p->offer, sizeof(p->offer), "%s/in/%s.offer.json", c->state, id) &&
           lp_fmt(p->bundle, sizeof(p->bundle), "%s/in/%s.bundle", c->state, id) &&
           lp_fmt(p->receipt, sizeof(p->receipt), "%s/in/%s.receipt.json", c->state,
                  id) &&
           lp_write(p->offer, o->offer_json);
}

/* Fetch, reverify, post, record: one offer post. */
static void lp_process(struct lp_ctx *c, const char *id, const struct lp_parsed *o,
                       int prior)
{
    static char line[LP_RECEIPT_JSON + 1], text[LP_TEXT_MAX + 1024];
    char code[72] = "";
    struct lp_paths p;
    bool retry;
    const int64_t t0 = clock_now_wall_ms() / 1000;
    if (!lp_stage(c, id, o, &p) || !lp_fetch(c, o, p.bundle)) {
        lp_fail(c, id, "FETCH_FAILED", prior, t0);
        return;
    }
    const bool ok = lp_reverify(c, p.bundle, p.offer, p.receipt, line,
                                sizeof(line), code, &retry);
    if (retry) {
        lp_fail(c, id, "REVERIFY_NO_RESULT", prior, t0);
        return;
    }
    const int n = ok ? snprintf(text, sizeof(text),
                                "lab-receipt v1 offer=%s verdict=ok receipt=%s", id, line)
                     : snprintf(text, sizeof(text),
                                "lab-receipt v1 offer=%s verdict=refused code=%s", id,
                                code);
    if (n < 0 || n > LP_TEXT_MAX || !lp_post_result(c, id, text)) {
        lp_fail(c, id, "RESULT_POST_FAILED", prior, t0);
        return;
    }
    lp_handled_row(c, id, ok ? "ok" : "refused", ok ? "" : code, t0);
    lp_item(c, id, ok ? "ok" : "refused", ok ? "" : code);
}

/* Why a post is not ours to process (NULL: process it). "" is ignored
 * silently: not an offer. */
static const char *lp_gate(const struct lp_ctx *c, const struct json_value *post,
                           int *prior)
{
    const char *id = lp_str(post, "id"), *text = lp_str(post, "text");
    const struct json_value *exp = json_get(post, "expires_at");
    *prior = 0;
    if (!lp_str(post, "kind") || strcmp(lp_str(post, "kind"), "offer") != 0 ||
        !lp_has_prefix(text, "lab-offer v1 "))
        return "";
    if (!lp_author_ok(c, lp_str(post, "host")))
        return "HOST_NOT_ALLOWED";
    if (!lp_hex(id, 64))
        return "BAD_POST_ID";
    if (exp && exp->type == JSON_INT && json_get_int(exp) > 0 &&
        json_get_int(exp) <= c->now)
        return "EXPIRED";
    if (lp_handled(c, id, prior))
        return "ALREADY_HANDLED";
    return NULL;
}

static bool lp_list_posts(const struct lp_ctx *c, const char *kind,
                          struct json_value *root, const struct json_value **posts)
{
    char room[96], limit[32], kind_arg[32];
    if (!lp_fmt(room, sizeof(room), "--room=%s", c->v[LP_O_ROOM]) ||
        !lp_fmt(limit, sizeof(limit), "--limit=%d", LP_POSTS_MAX) ||
        !lp_fmt(kind_arg, sizeof(kind_arg), "--kind=%s", kind))
        return false;
    const char *const argv[] = {c->v[LP_O_Z23], "fleet", "board", "list", room,
                                kind_arg, limit, NULL};
    if (!lp_run(argv, NULL, LP_QUICK_S, root))
        return false;
    *posts = json_get(lp_data(root), "posts");
    return *posts && (*posts)->type == JSON_ARR;
}

static bool lp_verify_args(struct lp_ctx *c, int64_t *max)
{
    return c->v[LP_O_STATE] && c->v[LP_O_REPO] && c->v[LP_O_AUTHORS] &&
           lp_name(c->v[LP_O_ROOM], 32) && lp_name(c->v[LP_O_AGENT], 32) &&
           lp_decimal(c->v[LP_O_MAX], LP_VERIFY_MAX, max);
}

static void lp_verify_post(struct lp_ctx *c, const struct json_value *post,
                           int *done)
{
    struct lp_parsed o;
    int prior;
    const char *why = lp_gate(c, post, &prior);
    const char *id = lp_str(post, "id");
    if (why && !why[0])
        return;
    if (why) {
        lp_item(c, id, "skipped", why);
    } else if (!lp_parse_offer(lp_str(post, "text"), &o)) {
        lp_item(c, id, "skipped", "OFFER_MALFORMED");
    } else {
        (*done)++;
        lp_process(c, id, &o, prior);
    }
}

static int lp_cmd_verify(struct lp_ctx *c)
{
    struct json_value root;
    const struct json_value *posts;
    int64_t max;
    int done = 0;
    if (!lp_verify_args(c, &max) || !lp_state_init(c))
        return lp_usage();
    if (!lp_lock(c)) {
        lp_emit(c, "verify", false, "LOCKED");
        return 0;
    }
    lp_load_authors(c);
    lp_items_init(c);
    if (!lp_list_posts(c, "offer", &root, &posts)) {
        json_free(&root);
        lp_emit(c, "verify", false, "BOARD_LIST_FAILED");
        return 0;
    }
    for (size_t i = 0; i < json_size(posts) && i < LP_POSTS_MAX && done < max; i++)
        lp_verify_post(c, json_at(posts, i), &done);
    lp_emit(c, "verify", true, "");
    json_free(&root);
    return 0;
}

/* ── collect ───────────────────────────────────────────────────────────── */

struct lp_row {
    char id[65], lane[LP_NAME + 1], commit[65], offer[LP_PATH + 80];
};

/* "lab-receipt v1 offer=<id> verdict=ok receipt=<json>": the json, or NULL. */
static const char *lp_receipt_text(const char *text, const char *id)
{
    char head[160];
    if (!lp_fmt(head, sizeof(head), "lab-receipt v1 offer=%s verdict=ok receipt=", id) ||
        !lp_has_prefix(text, head))
        return NULL;
    return text + strlen(head);
}

/* Writes one receipt file for a post; appends its path to list. */
static bool lp_save_receipt(const struct lp_ctx *c, const struct lp_row *r,
                            const struct json_value *post, char *list,
                            size_t cap, int *n)
{
    char path[LP_PATH + 96], one[LP_RECEIPT_JSON + 2];
    const char *host = lp_str(post, "host");
    const char *json = lp_receipt_text(lp_str(post, "text"), r->id);
    if (!json || !lp_hex(host, 64) || *n >= LP_RECEIPTS_MAX ||
        !lp_fmt(path, sizeof(path), "%s/receipts/%s-%.12s.json", c->state, r->id,
                host) ||
        strstr(list, path) || !lp_compact(json, one, sizeof(one) - 1))
        return false;
    (void)strcat(one, "\n");
    if (!lp_write(path, one))
        return false;
    const size_t used = strlen(list);
    if (!lp_fmt(list + used, cap - used, "%s%s", used ? "," : "", path))
        return list[used] = '\0', false;
    (*n)++;
    return true;
}

struct lp_qual {
    char verdict[72], signers[LP_RECEIPTS_MAX * 66], rejected[LP_RECEIPTS_MAX * 72];
    int64_t qualified;
};

static void lp_join(char *dst, size_t cap, const char *piece)
{
    const size_t used = strlen(dst);
    (void)lp_fmt(dst + used, cap - used, "%s%s", used ? "," : "", piece);
}

static void lp_qual_lists(const struct json_value *d, struct lp_qual *q)
{
    const struct json_value *s = d ? json_get(d, "signers") : NULL;
    const struct json_value *rej = d ? json_get(d, "rejected") : NULL;
    for (size_t i = 0; s && s->type == JSON_ARR && i < json_size(s); i++)
        if (json_at(s, i)->type == JSON_STR && lp_hex(json_get_str(json_at(s, i)), 64))
            lp_join(q->signers, sizeof(q->signers), json_get_str(json_at(s, i)));
    for (size_t i = 0; rej && rej->type == JSON_ARR && i < json_size(rej); i++) {
        const char *code = lp_str(json_at(rej, i), "code");
        if (lp_code_ok(code))
            lp_join(q->rejected, sizeof(q->rejected), code);
    }
}

static void lp_qual_fill(const struct json_value *root, struct lp_qual *q)
{
    const struct json_value *data = json_get(root, "data");
    const struct json_value *n = data ? json_get(data, "qualified") : NULL;
    const char *ev = lp_str(json_get(root, "error"), "evidence");
    const char *eq = ev ? strstr(ev, "qualified=") : NULL;
    const char *verdict = lp_str(data, "verdict");
    if (lp_data(root))
        (void)lp_fmt(q->verdict, sizeof(q->verdict), "%s",
                     verdict ? verdict : "ready");
    else
        (void)lp_err_code(root, "QUALIFY_REFUSED", q->verdict, sizeof(q->verdict));
    if (n && n->type == JSON_INT)
        q->qualified = json_get_int(n);
    else if (eq)
        q->qualified = atoi(eq + strlen("qualified="));
    lp_qual_lists(data, q);
}

/* Step 7. A refusal (QUALIFY_SHORT) still carries the count in its evidence. */
static void lp_qualify(const struct lp_ctx *c, const struct lp_row *r,
                       const char *list, struct lp_qual *q)
{
    static char recs[LP_RECEIPTS_MAX * (LP_PATH + 96) + 16];
    char offer[LP_PATH + 96], req[40];
    struct json_value root;
    memset(q, 0, sizeof(*q));
    (void)lp_fmt(q->verdict, sizeof(q->verdict), "QUALIFY_NO_REPLY");
    if (!lp_fmt(offer, sizeof(offer), "--offer=%s", r->offer) ||
        !lp_fmt(recs, sizeof(recs), "--receipts=%s", list) ||
        !lp_fmt(req, sizeof(req), "--require=%s", c->v[LP_O_REQUIRE]))
        return;
    const char *const argv[] = {c->v[LP_O_Z23DEV], "dev", "land", "qualify_offer",
                                offer, recs, req, NULL};
    if (lp_run(argv, NULL, LP_QUICK_S, &root))
        lp_qual_fill(&root, q);
    json_free(&root);
}

/* One offers.tsv line: post id, lane, commit, base, bundle sha, root, bundle
 * path, offer path. */
static bool lp_row_parse(char *line, struct lp_row *r)
{
    char *f[8];
    int k = 0;
    for (char *p = line; k < 8;) {
        char *tab = strchr(p, '\t');
        f[k++] = p;
        if (!tab)
            break;
        *tab = '\0';
        p = tab + 1;
    }
    return k == 8 && lp_hex(f[0], 64) && lp_name(f[1], LP_NAME) &&
           lp_commit(f[2]) && f[7][0] == '/' &&
           lp_fmt(r->id, sizeof(r->id), "%s", f[0]) &&
           lp_fmt(r->lane, sizeof(r->lane), "%s", f[1]) &&
           lp_fmt(r->commit, sizeof(r->commit), "%s", f[2]) &&
           lp_fmt(r->offer, sizeof(r->offer), "%s", f[7]);
}

static int lp_collect_rows(const struct lp_ctx *c, struct lp_row *rows)
{
    char path[LP_PATH + 16];
    int n = 0;
    if (!lp_fmt(path, sizeof(path), "%s/offers.tsv", c->state) ||
        !lp_read(path, NULL))
        return 0;
    for (char *l = strtok(g_file, "\n"); l && n < LP_ROWS_MAX; l = strtok(NULL, "\n"))
        if (lp_row_parse(l, &rows[n]))
            n++;
    return n;
}

/* The receipts answering one offer, qualified, and its qualified.tsv row. */
static void lp_collect_one(struct lp_ctx *c, const struct lp_row *r,
                           const struct json_value *posts, const char *tmp)
{
    static char list[LP_RECEIPTS_MAX * (LP_PATH + 96) + 16];
    char row[2 * LP_RECEIPTS_MAX * 72 + 512];
    struct lp_qual q = {.verdict = "NO_RECEIPTS"};
    int n = 0;
    list[0] = '\0';
    for (size_t i = 0; i < json_size(posts) && i < LP_POSTS_MAX; i++) {
        const struct json_value *p = json_at(posts, i);
        const char *kind = lp_str(p, "kind"), *ref = lp_str(p, "ref");
        if (kind && ref && strcmp(kind, "result") == 0 && strcmp(ref, r->id) == 0)
            (void)lp_save_receipt(c, r, p, list, sizeof(list), &n);
    }
    if (n > 0)
        lp_qualify(c, r, list, &q);
    if (lp_fmt(row, sizeof(row), "%s\t%s\t%s\t%lld\t%s\t%s\n", r->lane, r->commit,
               q.verdict, (long long)q.qualified, q.signers, q.rejected))
        (void)lp_append(tmp, row);
    lp_item(c, r->id, n == 0 ? "skipped" : strcmp(q.verdict, "ready") == 0 ? "ok"
                                                                          : "refused",
            q.verdict);
}

static int lp_cmd_collect(struct lp_ctx *c)
{
    static struct lp_row rows[LP_ROWS_MAX];
    struct json_value root;
    const struct json_value *posts;
    char tmp[LP_PATH + 32], fin[LP_PATH + 32];
    int64_t require;
    if (!c->v[LP_O_STATE] || !lp_name(c->v[LP_O_ROOM], 32) ||
        !lp_decimal(c->v[LP_O_REQUIRE], 16, &require) || !lp_state_init(c))
        return lp_usage();
    if (!lp_lock(c)) {
        lp_emit(c, "collect", false, "LOCKED");
        return 0;
    }
    lp_items_init(c);
    const int n = lp_collect_rows(c, rows);
    if (!lp_list_posts(c, "result", &root, &posts) ||
        !lp_fmt(tmp, sizeof(tmp), "%s/qualified.tsv.tmp", c->state) ||
        !lp_fmt(fin, sizeof(fin), "%s/qualified.tsv", c->state) || !lp_write(tmp, "")) {
        json_free(&root);
        lp_emit(c, "collect", false, "BOARD_LIST_FAILED");
        return 0;
    }
    for (int i = 0; i < n; i++)
        lp_collect_one(c, &rows[i], posts, tmp);
    const bool renamed = rename(tmp, fin) == 0;
    lp_emit(c, "collect", renamed, renamed ? "" : "QUALIFIED_WRITE_FAILED");
    json_free(&root);
    return 0;
}

int main(int argc, char **argv)
{
    static struct lp_ctx c;
    if (argc < 2 || !lp_parse_args(&c, argc, argv))
        return lp_usage();
    c.now = clock_now_wall_ms() / 1000;
    if (strcmp(argv[1], "offer") == 0)
        return lp_cmd_offer(&c);
    if (strcmp(argv[1], "verify") == 0)
        return lp_cmd_verify(&c);
    if (strcmp(argv[1], "collect") == 0)
        return lp_cmd_collect(&c);
    return lp_usage();
}
