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
 *       base check (one git fetch if --repo lacks it, else BASE_UNKNOWN, retry) -> dev land reverify_offer -> a signed receipt (or a typed refusal) posted
 *       as kind result with ref = the offer post. STATE/handled.tsv makes a post
 *       processed once; a failed fetch is retryable, three attempts in all.
 *       --check=cx (the default; nothing is passed) runs reverify_offer's split
 *       check only, so a general offer is refused REVERIFY_NOT_A_SPLIT;
 *       --check=verify passes --check=verify (make agent-verify ONLY=@changed
 *       behind the admission rail) and waits LP_VERIFY_S + LP_VERIFY_MARGIN_S.
 *       Any other value is a usage error (exit 2). collect takes the same
 *       option and passes --check=verify (or gate) to qualify_offer, which then counts
 *       agent_verify receipts instead of cx_check ones.
 *       --check=gate passes --check=gate: full lint (with the land queue's lint
 *       preparation) plus agent-verify, so a signed receipt covers what the
 *       land queue's gate runs; it waits LP_GATE_S + LP_VERIFY_MARGIN_S, and
 *       collect counts only receipts whose checks carry lint and agent_verify.
 *   collect --state=DIR [--room=lab] [--require=1]
 *       board list -> the verdict=ok receipts answering each offers.tsv row
 *       -> STATE/receipts/<post>-<host12>.json -> dev land qualify_offer ->
 *       STATE/qualified.tsv. SHADOW MODE: it never submits to or changes the
 *       land queue; the only dev land leaf it runs is qualify_offer.
 *   shadow  --state=DIR [--dry-run] ...   see tools/lab_peer_shadow.c
 *
 * One JSON document per run on stdout (zcl.lab_peer.v1): exit 0 when the run
 * completed (items may have failed), 1 when it stopped on a typed code (ok
 * false: a board listing, state read or write failed, a refused offer), 2 on a
 * usage error. A child that exits nonzero has failed, whatever its JSON says;
 * only its ok:false reply is read, for the typed refusal code. Board listings
 * follow the list cursor up to a fixed page cap; "truncated" reports a cap hit.
 * State is never read fail-open: a missing ledger is empty, an unreadable one
 * stops the run. offer is idempotent, so a rerun after any partial run converges.
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

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "json/json.h"
#include "lab_peer_shadow.h"
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
    LP_PAGES_MAX = 5,        /* board pages followed per listing */
    LP_MERGED_MAX = 1000,    /* posts kept from those pages */
    LP_ATTEMPTS = 3,         /* fetch attempts before a post is given up */
    LP_QUICK_S = 60,
    LP_FETCH_S = 300,
    LP_CX_S = 2400,
    LP_VERIFY_S = 3600,      /* reverify_offer --check=verify default --timeout_s */
    LP_GATE_S = 7200,        /* --check=gate default --timeout_s: lint plus agent-verify */
    LP_VERIFY_MARGIN_S = 300, /* admission wait and signing around that bound */
    LP_ONION_LEN = 62
};

enum lp_opt {
#define LP_OPTS(X)                                                           \
    X(LANE, "lane", NULL) X(COMMIT, "commit", NULL) X(STATE, "state", NULL)  \
    X(ROOM, "room", "lab") X(AGENT, "agent", "lab-peer")                     \
    X(REPO, "repo", NULL) X(AUTHORS, "authors", NULL) X(MAX, "max", "10")    \
    X(REQUIRE, "require", "1") X(Z23, "z23", "z23")                          \
    X(CHECK, "check", NULL)                                                  \
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
    bool oom;              /* a result document could not be built */
    bool truncated;        /* the board listing hit its page cap */
    const char *stop;      /* typed code that ends the run (persistence) */
};

static char g_child[LP_BUF];   /* the last child's stdout */
static char g_file[LP_BUF];    /* the last state file read */
static char g_out[LP_BUF];     /* the document printed */
static char g_handled[LP_BUF]; /* handled.tsv, loaded once per verify run */
static char g_qual[LP_BUF];    /* qualified.tsv as it will be written */
static char g_seen[LP_MERGED_MAX][65]; /* offer ids met this verify run */
static size_t g_n_seen;

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

enum { LP_RD_OK, LP_RD_MISSING, LP_RD_ERR };

/* Reads path into buf, NUL-terminated. MISSING is only ENOENT: a read error, or
 * a file over the cap, is ERR, so a truncated read is never taken as whole. */
static int lp_read_into(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return errno == ENOENT ? LP_RD_MISSING : LP_RD_ERR;
    const size_t n = fread(buf, 1, cap - 1, f);
    const bool whole = feof(f) && !ferror(f);
    (void)fclose(f);
    buf[n] = '\0';
    return whole ? LP_RD_OK : LP_RD_ERR;
}

/* The state file in g_file. */
static int lp_read(const char *path)
{
    return lp_read_into(path, g_file, sizeof(g_file));
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

static bool lp_ok_true(const struct json_value *root)
{
    const struct json_value *ok = json_get(root, "ok");
    return ok && ok->type == JSON_BOOL && json_get_bool(ok);
}

/* The data object of an ok reply, else NULL. */
static const struct json_value *lp_data(const struct json_value *root)
{
    return lp_ok_true(root) ? json_get(root, "data") : NULL;
}

/* Runs one program from argv (no shell); its stdout is parsed into root. True
 * when it ran to completion and printed one JSON document. */
static bool lp_run(const char *const argv[], const char *cwd, int timeout_s,
                   struct json_value *root)
{
    bool timed_out = false;
    json_init(root);
    const int rc = zcl_spawn_capture_in_dir_observed(
        argv, cwd, g_child, sizeof(g_child), timeout_s * 1000, &timed_out);
    if (rc < 0 || timed_out || !json_read(root, g_child, strlen(g_child)))
        return false;
    /* A nonzero exit is a failure. Its typed refusal (ok:false plus
     * error.code) is still read by the caller; a nonzero exit that claims
     * ok:true is contradictory and is never trusted. */
    if (rc != 0 && lp_ok_true(root)) {
        json_free(root);
        json_init(root);
        return false;
    }
    return true;
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

/* --check: absent or "cx" (reverify_offer's split check, no flag passed) or
 * "verify" (its general agent-verify check) or "gate" (full lint plus
 * agent-verify); anything else is a usage error. */
static bool lp_check_ok(const char *v)
{
    return !v || strcmp(v, "cx") == 0 || strcmp(v, "verify") == 0 ||
           strcmp(v, "gate") == 0;
}

/* The --check flag passed through to reverify_offer and qualify_offer:
 * "--check=verify", "--check=gate", or NULL for cx (nothing is passed). */
static const char *lp_check_flag(const struct lp_ctx *c)
{
    const char *v = c->v[LP_O_CHECK];
    if (v && strcmp(v, "verify") == 0)
        return "--check=verify";
    return v && strcmp(v, "gate") == 0 ? "--check=gate" : NULL;
}

/* How long a reverify_offer child may run: the mode's own --timeout_s default
 * plus the admission and signing margin. */
static int lp_reverify_wait_s(const struct lp_ctx *c)
{
    const char *flag = lp_check_flag(c);
    if (!flag)
        return LP_CX_S + 60;
    return (strcmp(flag, "--check=gate") == 0 ? LP_GATE_S : LP_VERIFY_S) +
           LP_VERIFY_MARGIN_S;
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
    if (!json_push_kv_str(&o, "id", id ? id : "") ||
        !json_push_kv_str(&o, "status", status) ||
        !json_push_kv_str(&o, "code", code ? code : "") ||
        !json_push_back(&c->items, &o))
        c->oom = true;
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

/* The counts object of the run's document. */
static bool lp_counts(const struct lp_ctx *c, struct json_value *counts)
{
    json_init(counts);
    json_set_object(counts);
    return json_push_kv_int(counts, "items", c->n_items) &&
           json_push_kv_int(counts, "ok", c->n_ok) &&
           json_push_kv_int(counts, "refused", c->n_refused) &&
           json_push_kv_int(counts, "failed", c->n_failed) &&
           json_push_kv_int(counts, "skipped", c->n_skipped);
}

/* Builds the run's document into g_out; false when it could not be built. */
static bool lp_build(const struct lp_ctx *c, const char *cmd, bool ok,
                     const char *code)
{
    struct json_value d, counts;
    json_init(&d);
    json_set_object(&d);
    json_init(&counts);
    bool built = !c->oom && lp_counts(c, &counts) &&
                 json_push_kv_str(&d, "schema", "zcl.lab_peer.v1") &&
                 json_push_kv_str(&d, "command", cmd) &&
                 json_push_kv_bool(&d, "ok", ok) &&
                 json_push_kv_str(&d, "code", code ? code : "") &&
                 json_push_kv_bool(&d, "truncated", c->truncated) &&
                 json_push_kv(&d, "counts", &counts) &&
                 json_push_kv(&d, "items", &c->items) &&
                 json_write(&d, g_out, sizeof(g_out)) < sizeof(g_out);
    json_free(&counts);
    json_free(&d);
    return built;
}

/* Prints the run's one document and returns the exit code: 0 when the run
 * completed, 1 when it was stopped (ok false) or could not report. */
static int lp_done(const struct lp_ctx *c, const char *cmd, bool ok,
                   const char *code)
{
    if (!lp_build(c, cmd, ok, code)) {
        (void)puts("{\"schema\":\"zcl.lab_peer.v1\",\"ok\":false,"
                   "\"code\":\"OUT_OF_MEMORY_OR_OUTPUT_TOO_LARGE\"}");
        return 1;
    }
    (void)puts(g_out);
    return ok ? 0 : 1;
}

static int lp_usage(void)
{
    (void)fputs(
        "usage: z23-lab-peer offer --lane=DIR --commit=SHA --state=DIR "
        "[--room=lab] [--agent=NAME]\n"
        "       z23-lab-peer verify --state=DIR --repo=DIR --authors=FILE "
        "[--room=lab] [--max=N] [--check=cx|verify|gate]\n"
        "       z23-lab-peer collect --state=DIR [--room=lab] [--require=1]\n"
        "       (--z23=PROGRAM --z23dev=PROGRAM name the CLIs; see "
        "tools/lab_peer.c)\n",
        stderr);
    return 2;
}

/* ── board listing ─────────────────────────────────────────────────────── */

/* 0: the page is the last; >0: the next cursor; -1: truncated, no usable cursor. */
static int64_t lp_next_cursor(const struct json_value *root,
                              const struct json_value *data)
{
    const struct json_value *page = json_get(data, "_page");
    if (!page)
        page = json_get(root, "_page");
    const struct json_value *t = json_get(page, "truncated");
    const struct json_value *n = json_get(page, "next_cursor");
    if (!t || t->type != JSON_BOOL || !json_get_bool(t))
        return 0;
    return n && n->type == JSON_INT && json_get_int(n) > 0 ? json_get_int(n) : -1;
}

/* Copies one page's posts into dst up to LP_MERGED_MAX; at the cap the run is
 * marked truncated. NULL, or a code when a copy could not be made. */
static const char *lp_merge(struct lp_ctx *c, struct json_value *dst,
                            const struct json_value *src)
{
    for (size_t i = 0; i < json_size(src); i++) {
        if (json_size(dst) >= LP_MERGED_MAX) {
            c->truncated = true;
            return NULL;
        }
        if (!json_push_back(dst, json_at(src, i)))
            return "OUT_OF_MEMORY";
    }
    return NULL;
}

struct lp_listq {
    char room[96], limit[32], kind[32];
};

/* One page at cursor: its posts are merged into posts and *next is the cursor
 * after it. NULL, or the typed code of a failed listing. */
static const char *lp_list_page(struct lp_ctx *c, const struct lp_listq *q,
                                int64_t cursor, struct json_value *posts,
                                int64_t *next)
{
    char cur[32];
    const char *argv[10] = {c->v[LP_O_Z23], "fleet", "board", "list", q->room,
                            q->kind, q->limit, NULL, NULL, NULL};
    struct json_value root;
    if (cursor > 0 && lp_fmt(cur, sizeof(cur), "--cursor=%lld", (long long)cursor))
        argv[7] = cur;
    if (!lp_run(argv, NULL, LP_QUICK_S, &root)) {
        json_free(&root);
        return "BOARD_LIST_FAILED";
    }
    const struct json_value *data = lp_data(&root);
    const struct json_value *arr = json_get(data, "posts");
    const char *err = arr && arr->type == JSON_ARR ? lp_merge(c, posts, arr)
                                                   : "BOARD_LIST_FAILED";
    *next = lp_next_cursor(&root, data);
    json_free(&root);
    return err;
}

/* The room's posts of one kind, following the list cursor page by page up to
 * LP_PAGES_MAX pages; a cap or an unusable cursor sets c->truncated. posts is
 * an initialised array. NULL, or the typed code of a failed listing. */
static const char *lp_list_posts(struct lp_ctx *c, const char *kind,
                                 struct json_value *posts)
{
    struct lp_listq q;
    int64_t cursor = 0, next = 0;
    if (!lp_fmt(q.room, sizeof(q.room), "--room=%s", c->v[LP_O_ROOM]) ||
        !lp_fmt(q.limit, sizeof(q.limit), "--limit=%d", LP_POSTS_MAX) ||
        !lp_fmt(q.kind, sizeof(q.kind), "--kind=%s", kind))
        return "BOARD_LIST_FAILED";
    for (int page = 0; page < LP_PAGES_MAX; page++) {
        const char *err = lp_list_page(c, &q, cursor, posts, &next);
        if (err || next == 0 || c->truncated)
            return err;
        if (next < 0 || next <= cursor || page + 1 == LP_PAGES_MAX)
            c->truncated = true;
        if (c->truncated)
            return NULL;
        cursor = next;
    }
    return NULL;
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
    const char *note; /* why a rerun skipped a step: ALREADY_OFFERED, POST_REUSED */
};

static const char *lp_basename(const char *path)
{
    const char *s = strrchr(path, '/');
    return s ? s + 1 : path;
}

/* Reads the offer manifest at m->offer_path: one-line copy, sha and base, and
 * the check that it names this commit (and, with expect_sha, that bundle).
 * NULL when fine, else a code. */
static const char *lp_offer_manifest(struct lp_made *m, const char *expect_sha)
{
    struct json_value doc;
    const char *code = "OFFER_MANIFEST_BAD";
    json_init(&doc);
    if (lp_read(m->offer_path) == LP_RD_OK &&
        json_read(&doc, g_file, strlen(g_file)) &&
        lp_compact(g_file, m->offer_json, sizeof(m->offer_json))) {
        const char *base = lp_str(&doc, "base"), *sha = lp_str(&doc, "bundle_sha256");
        const char *commit = lp_str(&doc, "commit");
        const bool same = commit && strcmp(commit, m->commit) == 0 &&
                          lp_hex(sha, 64) &&
                          (!expect_sha || strcmp(sha, expect_sha) == 0);
        if (lp_commit(base) && same && lp_fmt(m->base, sizeof(m->base), "%s", base) &&
            lp_fmt(m->sha, sizeof(m->sha), "%s", sha))
            code = NULL;
    }
    json_free(&doc);
    return code;
}

/* A rerun after a send that never reached the post: both files of the earlier
 * send and a manifest naming this commit are reused as they are. Anything
 * less (one file, a bad manifest) is removed so the send runs again. */
static bool lp_offer_reuse(struct lp_made *m)
{
    if (access(m->bundle, R_OK) == 0 && access(m->offer_path, R_OK) == 0 &&
        lp_offer_manifest(m, NULL) == NULL)
        return true;
    (void)unlink(m->bundle);
    (void)unlink(m->offer_path);
    return false;
}

/* Step 1: dev land send, in the lane worktree. */
static const char *lp_offer_send(const struct lp_ctx *c, struct lp_made *m,
                                 char *why, size_t why_cap)
{
    char lane_arg[LP_NAME + 16], commit_arg[96], out_arg[LP_PATH + 96];
    struct json_value root;
    const char *code = "OFFER_SEND_FAILED";
    if (lp_offer_reuse(m))
        return NULL;
    if (!lp_fmt(lane_arg, sizeof(lane_arg), "--lane=%s", m->name) ||
        !lp_fmt(commit_arg, sizeof(commit_arg), "--commit=%s", m->commit) ||
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
        else if (lp_hex(sha, 64))
            code = lp_offer_manifest(m, sha);
    }
    json_free(&root);
    return code;
}

/* Step 2: put the bundle on the Tor package swarm (offering twice is the
 * same root, so a rerun is safe). */
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

/* A post with exactly this text already on the board (posted by an earlier
 * run that never recorded it): reuse it rather than post a duplicate. */
static const char *lp_offer_publish(struct lp_ctx *c, struct lp_made *m)
{
    struct json_value posts;
    const char *err;
    json_init(&posts);
    json_set_array(&posts);
    err = lp_list_posts(c, "offer", &posts);
    for (size_t i = 0; !err && i < json_size(&posts); i++) {
        const struct json_value *p = json_at(&posts, i);
        const char *id = lp_str(p, "id"), *text = lp_str(p, "text");
        if (lp_hex(id, 64) && text && strcmp(text, m->text) == 0 &&
            lp_fmt(m->post_id, sizeof(m->post_id), "%s", id))
            m->note = "POST_REUSED";
    }
    json_free(&posts);
    if (err)
        return "OFFER_BOARD_LIST_FAILED";
    return m->note ? NULL : lp_offer_post(c, m);
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

/* offers.tsv already holds this lane and commit: 1 with its post id in m, 0 if
 * not, -1 when the file cannot be read (a rerun must not guess). */
static int lp_offer_recorded(const struct lp_ctx *c, struct lp_made *m)
{
    char path[LP_PATH + 16], key[LP_NAME + 64];
    if (!lp_fmt(path, sizeof(path), "%s/offers.tsv", c->state) ||
        !lp_fmt(key, sizeof(key), "\t%s\t%s\t", m->name, m->commit))
        return -1;
    const int rd = lp_read(path);
    if (rd != LP_RD_OK)
        return rd == LP_RD_MISSING ? 0 : -1;
    for (const char *l = g_file; l && *l; l = strchr(l, '\n') ? strchr(l, '\n') + 1 : NULL) {
        const char *tab = strchr(l, '\t');
        char id[65];
        if (tab && tab - l == 64 && strncmp(tab, key, strlen(key)) == 0 &&
            lp_fmt(id, sizeof(id), "%.64s", l) && lp_hex(id, 64) &&
            lp_fmt(m->post_id, sizeof(m->post_id), "%s", id))
            return 1;
    }
    return 0;
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
           lp_name(m->name, LP_NAME) &&
           lp_fmt(m->commit, sizeof(m->commit), "%s", c->v[LP_O_COMMIT]);
}

/* The whole offer, written so a rerun converges after any partial run: an
 * offers.tsv row ends it, an earlier send's files are reused, a post already
 * on the board is reused, and each step is idempotent. */
static const char *lp_offer_run(struct lp_ctx *c, struct lp_made *m, char *why,
                                size_t why_cap)
{
    if (!lp_fmt(m->bundle, sizeof(m->bundle), "%s/out/%s-%.12s.bundle", c->state,
                m->name, m->commit) ||
        !lp_fmt(m->offer_path, sizeof(m->offer_path), "%s.offer.json", m->bundle))
        return "OFFER_PATH_TOO_LONG";
    const int seen = lp_offer_recorded(c, m);
    if (seen < 0)
        return "OFFERS_UNREADABLE";
    if (seen > 0) {
        m->note = "ALREADY_OFFERED";
        return NULL;
    }
    const char *code = lp_offer_send(c, m, why, why_cap);
    code = code ? code : lp_offer_swarm(c, m);
    code = code ? code : lp_offer_text(m);
    code = code ? code : lp_offer_publish(c, m);
    if (!code && !lp_offer_record(c, m))
        code = "OFFER_RECORD_FAILED";
    if (why[0] && code && strcmp(code, "OFFER_SEND_FAILED") == 0)
        code = why;
    return code;
}

static int lp_cmd_offer(struct lp_ctx *c)
{
    static struct lp_made m;
    char why[80] = "";
    if (!lp_offer_args(c, &m) || !lp_state_init(c))
        return lp_usage();
    if (!lp_lock(c))
        return lp_done(c, "offer", false, "LOCKED");
    lp_items_init(c);
    const char *code = lp_offer_run(c, &m, why, sizeof(why));
    lp_item(c, m.post_id, code ? "failed" : "ok", code ? code : m.note);
    return lp_done(c, "offer", code == NULL, code);
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

/* The allowlist: one 64-hex key per line, anything else ignored. An unreadable
 * file or one with no key at all stops the run (every post would be skipped
 * for a reason the operator should see). */
static const char *lp_load_authors(struct lp_ctx *c)
{
    c->n_authors = 0;
    if (!c->v[LP_O_AUTHORS] || lp_read(c->v[LP_O_AUTHORS]) != LP_RD_OK)
        return "AUTHORS_UNREADABLE";
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
    return c->n_authors > 0 ? NULL : "AUTHORS_EMPTY";
}

static bool lp_author_ok(const struct lp_ctx *c, const char *host)
{
    for (int i = 0; i < c->n_authors; i++)
        if (host && strcmp(c->authors[i], host) == 0)
            return true;
    return false;
}

/* handled.tsv (id, verdict, code, seconds) is read once per run into
 * g_handled. A missing file is an empty ledger; an unreadable or oversized one
 * stops the run, so a post is never reprocessed on a guess. */
static const char *lp_load_handled(const struct lp_ctx *c)
{
    char path[LP_PATH + 16];
    if (!lp_fmt(path, sizeof(path), "%s/handled.tsv", c->state))
        return "HANDLED_UNREADABLE";
    const int rd = lp_read_into(path, g_handled, sizeof(g_handled));
    if (rd == LP_RD_MISSING)
        g_handled[0] = '\0';
    return rd == LP_RD_ERR ? "HANDLED_UNREADABLE" : NULL;
}

/* Final when the ledger has an ok/refused/failed row for id; retries counts
 * its retry rows. */
static bool lp_handled(const char *id, int *retries)
{
    char key[72];
    bool final = false;
    *retries = 0;
    if (!lp_fmt(key, sizeof(key), "%s\t", id))
        return false;
    for (const char *l = g_handled; l && *l; l = strchr(l, '\n') ? strchr(l, '\n') + 1 : NULL) {
        if (strncmp(l, key, strlen(key)) != 0)
            continue;
        if (lp_has_prefix(l + strlen(key), "retry\t"))
            (*retries)++;
        else
            final = true;
    }
    return final;
}

/* One ledger row. A row that cannot be written stops the run. */
static void lp_handled_row(struct lp_ctx *c, const char *id, const char *verdict,
                           const char *code, int64_t t0)
{
    char path[LP_PATH + 16], row[256];
    if (!lp_fmt(path, sizeof(path), "%s/handled.tsv", c->state) ||
        !lp_fmt(row, sizeof(row), "%s\t%s\t%s\t%lld\n", id, verdict,
                code ? code : "", (long long)(clock_now_wall_ms() / 1000 - t0)) ||
        !lp_append(path, row))
        c->stop = "HANDLED_WRITE_FAILED";
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

/* One git command in --repo, by argv (no shell); true on exit 0 in time. */
static bool lp_git(const struct lp_ctx *c, int timeout_s, const char *a,
                   const char *b, const char *d)
{
    char out[256];
    bool to = false;
    const char *const argv[] = {"git", "-C", c->v[LP_O_REPO], a, b, d, NULL};
    return zcl_spawn_capture_observed(argv, out, sizeof(out), timeout_s * 1000, &to) == 0 && !to;
}

/* Step 5b: the base must be in --repo; a stale repo gets one origin fetch. */
static bool lp_have_base(const struct lp_ctx *c, const char *base)
{
    char rev[80];
    if (!lp_fmt(rev, sizeof(rev), "%s^{commit}", base))
        return false;
    if (lp_git(c, LP_QUICK_S, "cat-file", "-e", rev))
        return true;
    (void)lp_git(c, LP_FETCH_S, "fetch", "--quiet", "origin");
    return lp_git(c, LP_QUICK_S, "cat-file", "-e", rev);
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
    /* cx: the NULL slot ends argv, so the argv is byte-identical to before. */
    const char *const argv[] = {c->v[LP_O_Z23DEV], "dev", "land", "reverify_offer",
                                b, o, repo, r, lp_check_flag(c),
                                NULL};
    const int wait_s = lp_reverify_wait_s(c);
    if (!lp_run(argv, NULL, wait_s, &root)) {
        *retry = true;
        json_free(&root);
        return false;
    }
    bool ok = lp_data(&root) != NULL;
    if (!ok)
        (void)lp_err_code(&root, "REVERIFY_REFUSED", code, 65);
    else if (lp_read(receipt) != LP_RD_OK || !lp_compact(g_file, line, line_cap))
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
    if (!lp_stage(c, id, o, &p)) {
        c->stop = "STATE_WRITE_FAILED";
        return;
    }
    if (!lp_fetch(c, o, p.bundle)) {
        lp_fail(c, id, "FETCH_FAILED", prior, t0);
        return;
    }
    if (!lp_have_base(c, o->base)) {
        lp_fail(c, id, "BASE_UNKNOWN", prior, t0);
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
    if (lp_handled(id, prior))
        return "ALREADY_HANDLED";
    return NULL;
}


static bool lp_verify_args(struct lp_ctx *c, int64_t *max)
{
    return c->v[LP_O_STATE] && c->v[LP_O_REPO] && c->v[LP_O_AUTHORS] &&
           lp_check_ok(c->v[LP_O_CHECK]) &&
           lp_name(c->v[LP_O_ROOM], 32) && lp_name(c->v[LP_O_AGENT], 32) &&
           lp_decimal(c->v[LP_O_MAX], LP_VERIFY_MAX, max);
}

/* True the first time this run meets id; a repeat (a post listed twice) is
 * never processed again, even when its ledger row is a retry: one attempt
 * per offer per run, so a duplicate cannot spend the retry budget. */
static bool lp_first_in_run(const char *id)
{
    for (size_t i = 0; i < g_n_seen; i++)
        if (strcmp(g_seen[i], id) == 0)
            return false;
    if (g_n_seen < LP_MERGED_MAX)
        (void)snprintf(g_seen[g_n_seen++], sizeof(g_seen[0]), "%s", id);
    return true;
}

static void lp_verify_post(struct lp_ctx *c, const struct json_value *post,
                           int *done)
{
    struct lp_parsed o;
    int prior;
    /* The ledger is re-read for every post, under the run lock (one run per
     * state dir at a time, so no other run appends meanwhile): an id handled
     * earlier in this run, e.g. listed twice, is never processed again. */
    c->stop = lp_load_handled(c);
    if (c->stop)
        return;
    const char *why = lp_gate(c, post, &prior);
    const char *id = lp_str(post, "id");
    if (why && !why[0])
        return;
    if (lp_hex(id, 64) && !lp_first_in_run(id)) {
        lp_item(c, id, "skipped", "DUPLICATE_IN_RUN");
    } else if (why) {
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
    struct json_value posts;
    int64_t max;
    int done = 0;
    if (!lp_verify_args(c, &max) || !lp_state_init(c))
        return lp_usage();
    if (!lp_lock(c))
        return lp_done(c, "verify", false, "LOCKED");
    lp_items_init(c);
    json_init(&posts);
    json_set_array(&posts);
    c->stop = lp_load_authors(c);
    c->stop = c->stop ? c->stop : lp_load_handled(c);
    c->stop = c->stop ? c->stop : lp_list_posts(c, "offer", &posts);
    for (size_t i = 0; !c->stop && i < json_size(&posts) && done < max; i++)
        lp_verify_post(c, json_at(&posts, i), &done);
    json_free(&posts);
    return lp_done(c, "verify", c->stop == NULL, c->stop);
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

/* Writes one receipt file for a post and appends its path to list: 1 saved,
 * 0 not a receipt for this offer (or a repeat host), -1 when it could not be
 * written (never skipped silently). */
static int lp_save_receipt(const struct lp_ctx *c, const struct lp_row *r,
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
        return 0;
    /* lp_compact filled at most sizeof(one) - 2 bytes, so the newline and
     * its terminator fit. */
    const size_t len = strlen(one);
    one[len] = '\n';
    one[len + 1] = '\0';
    if (!lp_write(path, one))
        return -1;
    const size_t used = strlen(list);
    if (!lp_fmt(list + used, cap - used, "%s%s", used ? "," : "", path)) {
        list[used] = '\0';
        return -1;
    }
    (*n)++;
    return 1;
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
                                offer, recs, req,
                                lp_check_flag(c), NULL};
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

static bool lp_row_seen(const struct lp_row *rows, int n, const char *id)
{
    for (int i = 0; i < n; i++)
        if (strcmp(rows[i].id, id) == 0)
            return true;
    return false;
}

/* The offers of offers.tsv, one per post id (a repeated id is one offer). A
 * missing file is no offers; an unreadable one is -1. A malformed line is
 * reported as a skipped item, not dropped silently. */
static int lp_collect_rows(struct lp_ctx *c, struct lp_row *rows)
{
    char path[LP_PATH + 16];
    int n = 0;
    if (!lp_fmt(path, sizeof(path), "%s/offers.tsv", c->state))
        return -1;
    const int rd = lp_read(path);
    if (rd != LP_RD_OK)
        return rd == LP_RD_MISSING ? 0 : -1;
    for (char *l = strtok(g_file, "\n"); l; l = strtok(NULL, "\n")) {
        struct lp_row r;
        if (!lp_row_parse(l, &r))
            lp_item(c, "", "skipped", "OFFERS_ROW_BAD");
        else if (!lp_row_seen(rows, n, r.id) && n < LP_ROWS_MAX)
            rows[n++] = r;
        else if (n >= LP_ROWS_MAX)
            c->truncated = true;
    }
    return n;
}

/* qualified.tsv is one row per offer post id: post, lane, commit, verdict,
 * qualified, signers, rejected. g_qual starts as the old file minus the rows
 * of the offers this run re-derives; each offer then adds its fresh row. */
static bool lp_qual_add(const char *s, size_t n)
{
    const size_t used = strlen(g_qual);
    if (used + n >= sizeof(g_qual))
        return false;
    memcpy(g_qual + used, s, n);
    g_qual[used + n] = '\0';
    return true;
}

static const char *lp_qual_keep(const struct lp_ctx *c, const struct lp_row *rows,
                                int n)
{
    char path[LP_PATH + 16];
    g_qual[0] = '\0';
    if (!lp_fmt(path, sizeof(path), "%s/qualified.tsv", c->state))
        return "QUALIFIED_UNREADABLE";
    const int rd = lp_read(path);
    if (rd != LP_RD_OK)
        return rd == LP_RD_MISSING ? NULL : "QUALIFIED_UNREADABLE";
    for (const char *l = g_file; *l;) {
        const char *nl = strchr(l, '\n');
        const size_t len = nl ? (size_t)(nl - l) + 1 : strlen(l);
        bool redone = false;
        for (int i = 0; i < n && !redone; i++)
            redone = len > 64 && l[64] == '\t' && strncmp(l, rows[i].id, 64) == 0;
        if (!redone && !lp_qual_add(l, len))
            return "QUALIFIED_TOO_LARGE";
        l += len;
    }
    return NULL;
}

static bool lp_qual_write(const struct lp_ctx *c)
{
    char tmp[LP_PATH + 32], fin[LP_PATH + 32];
    return lp_fmt(tmp, sizeof(tmp), "%s/qualified.tsv.tmp", c->state) &&
           lp_fmt(fin, sizeof(fin), "%s/qualified.tsv", c->state) &&
           lp_write(tmp, g_qual) && rename(tmp, fin) == 0;
}

/* The receipts answering one offer, qualified, and its qualified.tsv row. */
static const char *lp_collect_one(struct lp_ctx *c, const struct lp_row *r,
                                  const struct json_value *posts)
{
    static char list[LP_RECEIPTS_MAX * (LP_PATH + 96) + 16];
    char row[2 * LP_RECEIPTS_MAX * 72 + 640];
    struct lp_qual q = {.verdict = "NO_RECEIPTS"};
    int n = 0;
    bool write_failed = false;
    list[0] = '\0';
    for (size_t i = 0; i < json_size(posts); i++) {
        const struct json_value *p = json_at(posts, i);
        const char *kind = lp_str(p, "kind"), *ref = lp_str(p, "ref");
        if (kind && ref && strcmp(kind, "result") == 0 && strcmp(ref, r->id) == 0)
            write_failed |= lp_save_receipt(c, r, p, list, sizeof(list), &n) < 0;
    }
    if (write_failed)
        (void)lp_fmt(q.verdict, sizeof(q.verdict), "RECEIPT_WRITE_FAILED");
    else if (n > 0)
        lp_qualify(c, r, list, &q);
    lp_item(c, r->id,
            write_failed ? "failed" : n == 0 ? "skipped"
                                     : strcmp(q.verdict, "ready") == 0 ? "ok" : "refused",
            q.verdict);
    if (!lp_fmt(row, sizeof(row), "%s\t%s\t%s\t%s\t%lld\t%s\t%s\n", r->id, r->lane,
                r->commit, q.verdict, (long long)q.qualified, q.signers, q.rejected) ||
        !lp_qual_add(row, strlen(row)))
        return "QUALIFIED_TOO_LARGE";
    return NULL;
}

static int lp_cmd_collect(struct lp_ctx *c)
{
    static struct lp_row rows[LP_ROWS_MAX];
    struct json_value posts;
    int64_t require;
    if (!c->v[LP_O_STATE] || !lp_name(c->v[LP_O_ROOM], 32) ||
        !lp_check_ok(c->v[LP_O_CHECK]) ||
        !lp_decimal(c->v[LP_O_REQUIRE], 16, &require) || !lp_state_init(c))
        return lp_usage();
    if (!lp_lock(c))
        return lp_done(c, "collect", false, "LOCKED");
    lp_items_init(c);
    json_init(&posts);
    json_set_array(&posts);
    const int n = lp_collect_rows(c, rows);
    c->stop = n < 0 ? "OFFERS_UNREADABLE" : NULL;
    c->stop = c->stop ? c->stop : lp_list_posts(c, "result", &posts);
    c->stop = c->stop ? c->stop : lp_qual_keep(c, rows, n);
    for (int i = 0; !c->stop && i < n; i++)
        c->stop = lp_collect_one(c, &rows[i], &posts);
    if (!c->stop && !lp_qual_write(c))
        c->stop = "QUALIFIED_WRITE_FAILED";
    json_free(&posts);
    return lp_done(c, "collect", c->stop == NULL, c->stop);
}

int main(int argc, char **argv)
{
    static struct lp_ctx c;
    if (argc >= 2 && strcmp(argv[1], "shadow") == 0)
        return lab_peer_shadow_main(argc, argv);
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
