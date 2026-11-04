/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: dev.land.intake, the lead's hand intake of READY posts as one leaf.
 * For each READY post on the board (or in a saved list, posts_file) it gives
 * one typed verdict: ACCEPT_FOR_QUEUE, REFUSE(reason) or CONFLICT(with=id).
 *
 * A READY post that offers a bundle reads
 *   READY root=<64hex> sha256=<64hex> size=<n> [peer=<v3 onion>] free text
 * (a READY post without sha256 is REFUSE(no_bundle)). Checks, in order:
 *   1 the post signature (fleet_board_post_verify over the listed fields)
 *   2 the author key is in the allow file (one 64-hex key per line, as
 *     z23-lab-peer's --authors)
 *   3 the bundle: <bundle_dir>/<sha256>.bundle is used when present, else
 *     fetched by the fleet.bundle.fetch leaf; its sha256 is recomputed
 *   4 scope: no path under core/, engine/reducer/, contexts/wallet/ or a
 *     prefix of the optional deny file, against origin/main (three-dot diff)
 *   5 git merge-tree --write-tree against origin/main, then pairwise against
 *     the earlier accepted posts of the batch (oldest first; the later post
 *     of a conflicting pair gets CONFLICT(with=<the earlier id>)).
 * Git work runs in a private bare scratch repository under bundle_dir that
 * borrows the checkout's objects (alternates) and is removed on every path:
 * the checkout gets no ref and no object. Without commit=true nothing but
 * bundle_dir's fetched bundles is written. commit=true first returns the plan
 * (plan_id over the verdicts); with that plan_id and confirm=true it hands
 * each ACCEPT_FOR_QUEUE bundle to dev.land.receive and posts one result reply
 * (ref = the READY post) per post through fleet.board.post. */

#include "command/native_command.h"
#include "command/native_dev_batch.h"
#include "command/native_dev_land_remote_shared.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "util/spawn.h"
#include "session/fleet_board_proto.h"
#include "sha3/sha3.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

enum { IN_MAX = 32, IN_PATH = 1024, IN_LINE = 128, IN_LIST = 64, IN_OUT = 262144 };

struct in_list {
    char v[IN_LIST][IN_LINE];
    int n;
};

struct in_post {
    char id[65], host[65], agent[FLEET_BOARD_AGENT_MAX + 1];
    char room[FLEET_BOARD_ROOM_MAX + 1];
    char root[65], sha256[65], peer[128], size[16];
    char bundle[IN_PATH], tip[41], lane[IN_PATH], commit[41];
    char step[320]; /* operator_step: what a person must do when we cannot fetch */
    int idx;        /* refs/intake/<idx> in the scratch repository */
    int64_t created;
    char verdict[24]; /* ACCEPT_FOR_QUEUE | REFUSE | CONFLICT */
    char reason[48], with[17];
    bool live;
    int submitted; /* -1 not tried, 0 failed, 1 queued */
};

struct in_ctx {
    char repo[IN_PATH], bundle_dir[IN_PATH], scratch[IN_PATH + 16];
    bool board; /* posts come from the live board (show can re-read a post) */
    char main_sha[41], *out;
    struct in_list allow, deny;
    struct in_post posts[IN_MAX];
    int n;
};

static void in_set(struct in_post *p, const char *verdict, const char *reason)
{
    p->live = false;
    (void)snprintf(p->verdict, sizeof(p->verdict), "%s", verdict);
    (void)snprintf(p->reason, sizeof(p->reason), "%s", reason);
}

static void in_refuse(struct in_post *p, const char *reason)
{
    in_set(p, "REFUSE", reason);
}

/* ── lists ─────────────────────────────────────────────────────────────── */

static void in_list_load(const char *path, struct in_list *l)
{
    struct db_text t = {0};
    size_t pos = 0, len;
    const char *line;
    l->n = 0;
    if (!path[0] || !db_text_load(path, &t))
        return;
    while (l->n < IN_LIST && db_next_line(&t, &pos, &line, &len)) {
        while (len && (line[len - 1] == '\r' || line[len - 1] == ' '))
            len--;
        if (!len || line[0] == '#' || len >= IN_LINE)
            continue;
        memcpy(l->v[l->n], line, len);
        l->v[l->n++][len] = '\0';
    }
    db_text_free(&t);
}

static bool in_allowed(const struct in_list *l, const char *host)
{
    for (int i = 0; i < l->n; i++)
        if (!strcasecmp(l->v[i], host))
            return true;
    return false;
}

static bool in_denied(const struct in_ctx *x, const char *path)
{
    static const char *const fixed[] = {"core/", "engine/reducer/",
                                        "contexts/wallet/"};
    for (size_t i = 0; i < sizeof(fixed) / sizeof(fixed[0]); i++)
        if (!strncmp(path, fixed[i], strlen(fixed[i])))
            return true;
    for (int i = 0; i < x->deny.n; i++)
        if (!strncmp(path, x->deny.v[i], strlen(x->deny.v[i])))
            return true;
    return false;
}

/* ── the post ──────────────────────────────────────────────────────────── */

static void in_str(char *dst, size_t cap, const struct json_value *j,
                   const char *key)
{
    const char *s = json_get_str(json_get(j, key));
    (void)snprintf(dst, cap, "%s", s ? s : "");
}

static bool in_sig_hex(const struct json_value *j, struct fleet_board_post *p)
{
    static const struct {
        const char *key;
        size_t off, len;
    } f[] = {{"id", offsetof(struct fleet_board_post, id), 32},
             {"ref", offsetof(struct fleet_board_post, ref), 32},
             {"host", offsetof(struct fleet_board_post, host_pubkey), 32},
             {"signature", offsetof(struct fleet_board_post, signature), 64}};
    char tmp[160];
    for (size_t i = 0; i < sizeof(f) / sizeof(f[0]); i++) {
        in_str(tmp, sizeof(tmp), j, f[i].key);
        if (!zcl_hex_decode_lower(tmp, (uint8_t *)p + f[i].off, f[i].len))
            return false;
    }
    in_str(tmp, sizeof(tmp), j, "supersedes");
    return !tmp[0] || zcl_hex_decode_lower(tmp, p->supersedes, 32);
}

/* Rebuild the signed struct from a board row (list or show) and verify it.
 * receipt, slug, title and supersedes are signed too, so they are read when
 * the row carries them; a row that lacks one the post has fails verification
 * (the caller then re-reads the post by id). */
static bool in_sig_ok(const struct json_value *j, const char *text)
{
    struct fleet_board_post p;
    char tmp[160];
    memset(&p, 0, sizeof(p));
    in_str(tmp, sizeof(tmp), j, "kind");
    if (!fleet_board_kind_from_name(tmp, &p.kind))
        return false;
    in_str(tmp, sizeof(tmp), j, "scope");
    if (!fleet_board_scope_from_name(tmp, &p.scope) ||
        strlen(text) > FLEET_BOARD_WIKI_TEXT_MAX)
        return false;
    p.created_at = (uint64_t)json_get_int(json_get(j, "created_at"));
    p.ttl = (uint32_t)json_get_int(json_get(j, "ttl"));
    p.text_len = (uint32_t)strlen(text);
    memcpy(p.text, text, p.text_len + 1);
    in_str(p.room, sizeof(p.room), j, "room");
    in_str(p.agent, sizeof(p.agent), j, "agent");
    in_str(p.receipt, sizeof(p.receipt), j, "receipt");
    in_str(p.slug, sizeof(p.slug), j, "slug");
    in_str(p.title, sizeof(p.title), j, "title");
    return in_sig_hex(j, &p) && fleet_board_post_verify(&p) == FLEET_BOARD_OK;
}

static bool in_hex_n(const char *s, size_t n)
{
    uint8_t b[32];
    return strlen(s) == n && zcl_hex_decode_lower(s, b, n / 2);
}

/* The value of the first `key=` token after READY, or false. */
static bool in_token(const char *text, const char *key, char *out, size_t cap)
{
    size_t kl = strlen(key);
    for (const char *p = text; *p;) {
        const char *e = p;
        while (*e && *e != ' ' && *e != '\n')
            e++;
        if ((size_t)(e - p) > kl && !strncmp(p, key, kl) && p[kl] == '=') {
            size_t vl = (size_t)(e - p) - kl - 1;
            if (vl >= cap)
                return false;
            memcpy(out, p + kl + 1, vl);
            out[vl] = '\0';
            return true;
        }
        p = *e ? e + 1 : e;
    }
    return false;
}

static bool in_is_ready(const char *text)
{
    return !strncmp(text, "READY", 5) && (!text[5] || text[5] == ' ');
}

static bool in_sub(void (*fn)(const struct zcl_command_request *,
                              struct zcl_command_reply *),
                   const char *path, const char *schema,
                   const struct json_value *input, struct json_value *data);

/* The row's signature, else (live board only) the whole post by id through
 * fleet.board.show, which carries every signed field. On a pass `src` is the
 * verified row. */
static bool in_verified(const struct in_ctx *x, const struct json_value *j,
                        struct json_value *shown, const struct json_value **src)
{
    struct json_value q;
    bool ok;
    *src = j;
    if (in_sig_ok(j, json_get_str(json_get(j, "text"))))
        return true;
    if (!x->board)
        return false;
    json_init(&q);
    json_set_object(&q);
    (void)json_push_kv_str(&q, "id", json_get_str(json_get(j, "id")));
    ok = in_sub(zcl_native_handle_fleet_board_show, "fleet.board.show",
                "zcl.fleet_board_post.v1", &q, shown) &&
         in_sig_ok(shown, json_get_str(json_get(shown, "text")));
    json_free(&q);
    *src = shown;
    return ok;
}

/* "READY <lane path> <40 hex commit> text" (the live form) or
 * "READY ... sha256=<64hex> [root= size= peer=]" (a bundle on the swarm). */
static void in_bundle_form(const char *text, struct in_post *p)
{
    const char *lane = text[5] ? text + 6 : text + 5, *end = strchr(lane, ' ');
    size_t n = end ? (size_t)(end - lane) : 0;
    if (lane[0] == '/' && n > 1 && n < sizeof(p->lane) && end[1] &&
        strlen(end + 1) >= 40) {
        memcpy(p->lane, lane, n);
        p->lane[n] = '\0';
        memcpy(p->commit, end + 1, 40);
        p->commit[40] = '\0';
        if (in_hex_n(p->commit, 40) && (!end[41] || end[41] == ' '))
            return;
        p->lane[0] = p->commit[0] = '\0';
    }
    if (!in_token(text, "sha256", p->sha256, sizeof(p->sha256)) ||
        !in_hex_n(p->sha256, 64)) {
        in_refuse(p, "no_bundle");
        return;
    }
    (void)in_token(text, "root", p->root, sizeof(p->root));
    (void)in_token(text, "size", p->size, sizeof(p->size));
    (void)in_token(text, "peer", p->peer, sizeof(p->peer));
}

/* One listed post. Unsigned/foreign/bundle-less posts get their verdict here. */
static void in_ingest(struct in_ctx *x, const struct json_value *j)
{
    struct in_post *p;
    struct json_value shown;
    const struct json_value *src;
    const char *text = json_get_str(json_get(j, "text"));
    if (!text || !in_is_ready(text) || x->n >= IN_MAX)
        return;
    p = &x->posts[x->n++];
    memset(p, 0, sizeof(*p));
    p->submitted = -1;
    p->live = true;
    json_init(&shown);
    if (!in_verified(x, j, &shown, &src)) {
        in_str(p->id, sizeof(p->id), j, "id");
        in_refuse(p, "bad_signature");
        json_free(&shown);
        return;
    }
    in_str(p->id, sizeof(p->id), src, "id");
    in_str(p->host, sizeof(p->host), src, "host");
    in_str(p->agent, sizeof(p->agent), src, "agent");
    in_str(p->room, sizeof(p->room), src, "room");
    p->created = json_get_int(json_get(src, "created_at"));
    if (!in_allowed(&x->allow, p->host))
        in_refuse(p, "author_not_allowed");
    else
        in_bundle_form(json_get_str(json_get(src, "text")), p);
    json_free(&shown);
}

static int in_cmp(const void *a, const void *b)
{
    const struct in_post *x = a, *y = b;
    if (x->created != y->created)
        return x->created < y->created ? -1 : 1;
    return strcmp(x->id, y->id);
}

/* ── sub-leaf calls ────────────────────────────────────────────────────── */

typedef void (*in_handler)(const struct zcl_command_request *,
                           struct zcl_command_reply *);

/* Run a sibling leaf in process; true on a passed reply. data (when not
 * NULL) receives a copy of reply.data. */
static bool in_sub(in_handler fn, const char *path, const char *schema,
                   const struct json_value *input, struct json_value *data)
{
    struct zcl_command_request rq;
    struct zcl_command_reply rp;
    bool ok;
    memset(&rq, 0, sizeof(rq));
    rq.input = input;
    rq.spec = zcl_command_registry_find(zcl_command_catalog(), path, NULL);
    zcl_command_reply_init(&rp, schema);
    fn(&rq, &rp);
    ok = rp.status == ZCL_COMMAND_STATUS_PASSED;
    if (data)
        json_copy(data, &rp.data);
    zcl_command_reply_free(&rp);
    return ok;
}

/* The board list (room, since) or the saved posts_file, into doc. */
static bool in_load(const struct json_value *in, struct json_value *doc)
{
    const char *file = db_opt_str(in, "posts_file"), *room = db_opt_str(in, "room");
    struct json_value query;
    struct db_text t = {0};
    bool ok;
    if (file[0]) {
        ok = db_text_load(file, &t) && t.n && json_read(doc, t.p, t.n);
        db_text_free(&t);
        return ok;
    }
    json_init(&query);
    json_set_object(&query);
    (void)json_push_kv_str(&query, "room", room[0] ? room : "fleet");
    (void)json_push_kv_int(&query, "limit", 200);
    if (json_get(in, "since"))
        (void)json_push_kv_int(&query, "since", json_get_int(json_get(in, "since")));
    ok = in_sub(zcl_native_handle_fleet_board_list, "fleet.board.list",
                "zcl.fleet_board_list.v1", &query, doc);
    json_free(&query);
    return ok;
}

static void in_collect(struct in_ctx *x, const struct json_value *in,
                       struct zcl_command_reply *reply, bool *ok)
{
    struct json_value doc;
    const struct json_value *list;
    const char *want = db_opt_str(in, "id");
    json_init(&doc);
    x->board = !db_opt_str(in, "posts_file")[0];
    *ok = in_load(in, &doc);
    list = json_get(&doc, "posts");
    if (!list && doc.type == JSON_ARR)
        list = &doc;
    *ok = *ok && list;
    if (!*ok)
        db_refuse(reply, "NO_POSTS", "collect",
                  "the board list (or posts_file) could not be read");
    for (size_t i = 0; *ok && i < json_size(list); i++) {
        const struct json_value *j = json_at(list, i);
        if (!want[0] || !strncmp(json_get_str(json_get(j, "id")), want, strlen(want)))
            in_ingest(x, j);
    }
    json_free(&doc);
}

/* ── bundle and git ────────────────────────────────────────────────────── */

static bool in_have_sha(struct in_post *p)
{
    char hex[SHA256_OUTPUT_SIZE * 2 + 1];
    return zcl_dlr_file_sha256(p->bundle, hex) && !strcmp(hex, p->sha256);
}

static void in_fetch(struct in_ctx *x, struct in_post *p)
{
    struct json_value q;
    bool ok;
    if (p->commit[0])
        return; /* lane form: no bundle to fetch */
    (void)snprintf(p->bundle, sizeof(p->bundle), "%s/%s.bundle", x->bundle_dir,
                   p->sha256);
    if (access(p->bundle, R_OK) != 0) {
        if (!in_hex_n(p->root, 64) || !p->size[0]) {
            in_refuse(p, "no_bundle");
            return;
        }
        json_init(&q);
        json_set_object(&q);
        (void)json_push_kv_str(&q, "root", p->root);
        (void)json_push_kv_str(&q, "sha256", p->sha256);
        (void)json_push_kv_int(&q, "size", atoll(p->size));
        (void)json_push_kv_str(&q, "out", p->bundle);
        if (p->peer[0])
            (void)json_push_kv_str(&q, "peer", p->peer);
        ok = in_sub(zcl_native_handle_fleet_bundle_fetch, "fleet.bundle.fetch",
                    "zcl.fleet_bundle_fetch.v1", &q, NULL);
        json_free(&q);
        if (!ok) {
            in_refuse(p, "fetch_failed");
            return;
        }
    }
    if (!in_have_sha(p))
        in_refuse(p, "bundle_sha_mismatch");
}

static int in_git(const struct in_ctx *x, const char *const *args)
{
    return db_git(x->scratch, args, x->out, IN_OUT);
}

static bool in_scratch(struct in_ctx *x)
{
    char tmpl[IN_PATH + 16], obj[IN_PATH + 8], alt[IN_PATH + 64];
    const char *init[] = {"init", "-q", "--bare", NULL};
    const char *objs[] = {"rev-parse", "--path-format=absolute", "--git-path",
                          "objects", NULL};
    const char *mainv[] = {"rev-parse", "--verify", "origin/main^{commit}", NULL};
    FILE *f;
    (void)snprintf(tmpl, sizeof(tmpl), "%s/.intake-XXXXXX", x->bundle_dir);
    if (!mkdtemp(tmpl))
        return false;
    (void)snprintf(x->scratch, sizeof(x->scratch), "%s", tmpl);
    if (in_git(x, init) != 0 || !db_git_line(x->repo, objs, obj, sizeof(obj)) ||
        !db_git_line(x->repo, mainv, x->main_sha, sizeof(x->main_sha)))
        return false;
    (void)snprintf(alt, sizeof(alt), "%s/objects/info/alternates", x->scratch);
    f = fopen(alt, "w");
    if (!f)
        return false;
    (void)fprintf(f, "%s\n", obj);
    return fclose(f) == 0;
}

/* The live READY form names a lane on the poster's host and a commit. When
 * that lane is a repository here (the poster is this box, or shares its
 * filesystem) its objects join the scratch repository as a second alternate
 * and the commit becomes refs/intake/<i>: nothing is copied or run. Any
 * other host holds the commit where this leaf cannot reach: that is a typed
 * operator_step (the bridge reached it over ssh, which this leaf never does),
 * and the swarm form below is the way to avoid the step. */
static void in_import_lane(struct in_ctx *x, struct in_post *p, int i)
{
    char common[IN_PATH], alt[IN_PATH + 64], obj[IN_PATH + 16], ref[48];
    const char *cd[] = {"rev-parse", "--path-format=absolute", "--git-common-dir",
                        NULL};
    const char *has[] = {"cat-file", "-e", NULL, NULL};
    char spec[64];
    const char *upd[] = {"update-ref", ref, p->commit, NULL};
    FILE *f;
    (void)snprintf(spec, sizeof(spec), "%s^{commit}", p->commit);
    has[2] = spec;
    (void)snprintf(ref, sizeof(ref), "refs/intake/%d", i);
    if (!db_git_line(p->lane, cd, common, sizeof(common)) ||
        snprintf(obj, sizeof(obj), "%s/objects", common) >= (int)sizeof(obj)) {
        in_refuse(p, "needs_operator_step");
        (void)snprintf(p->step, sizeof(p->step),
                       "the lane is not on this host: on the poster's host run `git bundle "
                       "create B.bundle origin/main..%.12s` and `z23 fleet bundle offer "
                       "--file=B.bundle`, then re-post READY with root=, sha256= and size=",
                       p->commit);
        return;
    }
    (void)snprintf(alt, sizeof(alt), "%s/objects/info/alternates", x->scratch);
    f = fopen(alt, "a");
    if (!f || fprintf(f, "%s\n", obj) < 0 || fclose(f) != 0 ||
        in_git(x, has) != 0 || in_git(x, upd) != 0) {
        in_refuse(p, "commit_not_in_lane");
        return;
    }
    (void)snprintf(p->tip, sizeof(p->tip), "%s", p->commit);
    (void)snprintf(p->bundle, sizeof(p->bundle), "%s/%s.bundle", x->bundle_dir,
                   p->commit);
}

/* Exactly one head, fetched into refs/intake/<i>; its tip into p->tip. */
static void in_import(struct in_ctx *x, struct in_post *p, int i)
{
    p->idx = i;
    if (p->commit[0]) {
        in_import_lane(x, p, i);
        return;
    }
    const char *heads[] = {"bundle", "list-heads", p->bundle, NULL};
    char spec[64], ref[64], *nl;
    const char *fetch[] = {"fetch", "-q", p->bundle, spec, NULL};
    const char *rev[] = {"rev-parse", "--verify", ref, NULL};
    char *sp;
    if (in_git(x, heads) != 0 || !(nl = strchr(x->out, '\n')) || nl[1] ||
        !(sp = strchr(x->out, ' '))) {
        in_refuse(p, "bad_bundle");
        return;
    }
    *nl = '\0';
    (void)snprintf(ref, sizeof(ref), "refs/intake/%d", i);
    (void)snprintf(spec, sizeof(spec), "%s:%s", sp + 1, ref);
    if (in_git(x, fetch) != 0 || !db_git_line(x->scratch, rev, p->tip, sizeof(p->tip)))
        in_refuse(p, "bad_bundle");
}

static void in_scope(struct in_ctx *x, struct in_post *p)
{
    char range[96];
    const char *diff[] = {"-c", "core.quotepath=false", "diff", "--no-renames",
                          "--name-only", range, NULL};
    size_t pos = 0;
    (void)snprintf(range, sizeof(range), "%s...%s", x->main_sha, p->tip);
    if (in_git(x, diff) != 0 || strlen(x->out) >= IN_OUT - 1) {
        in_refuse(p, "diff_failed");
        return;
    }
    while (x->out[pos]) {
        char *nl = strchr(x->out + pos, '\n');
        size_t len = nl ? (size_t)(nl - (x->out + pos)) : strlen(x->out + pos);
        char path[IN_PATH];
        if (len >= sizeof(path)) {
            in_refuse(p, "path_too_long");
            return;
        }
        memcpy(path, x->out + pos, len);
        path[len] = '\0';
        if (path[0] == '"' || in_denied(x, path)) {
            in_refuse(p, path[0] == '"' ? "odd_path" : "denied_path");
            return;
        }
        pos += len + (nl ? 1u : 0u);
    }
}

/* 0 clean, 1 conflict, -1 error. */
static int in_merge(struct in_ctx *x, const char *a, const char *b)
{
    const char *mt[] = {"merge-tree", "--write-tree", a, b, NULL};
    int rc = in_git(x, mt);
    return rc == 0 ? 0 : (rc == 1 ? 1 : -1);
}

static void in_conflicts(struct in_ctx *x)
{
    for (int i = 0; i < x->n; i++) {
        struct in_post *p = &x->posts[i];
        int rc;
        if (!p->live)
            continue;
        rc = in_merge(x, x->main_sha, p->tip);
        if (rc != 0) {
            if (rc > 0)
                in_set(p, "CONFLICT", "origin_main");
            else
                in_refuse(p, "merge_tree_failed");
            (void)snprintf(p->with, sizeof(p->with), "%s", "origin/main");
            continue;
        }
        for (int j = 0; j < i; j++) {
            const struct in_post *q = &x->posts[j];
            if (strcmp(q->verdict, "ACCEPT_FOR_QUEUE") ||
                (rc = in_merge(x, q->tip, p->tip)) == 0)
                continue;
            in_set(p, rc > 0 ? "CONFLICT" : "REFUSE",
                   rc > 0 ? "batch" : "merge_tree_failed");
            memcpy(p->with, q->id, 12);
            p->with[12] = '\0';
            break;
        }
        if (p->live)
            in_set(p, "ACCEPT_FOR_QUEUE", "");
    }
}

static void in_checks(struct in_ctx *x)
{
    for (int i = 0; i < x->n; i++)
        if (x->posts[i].live)
            in_fetch(x, &x->posts[i]);
    for (int i = 0; i < x->n; i++)
        if (x->posts[i].live)
            in_import(x, &x->posts[i], i);
    for (int i = 0; i < x->n; i++)
        if (x->posts[i].live)
            in_scope(x, &x->posts[i]);
    in_conflicts(x);
}

/* ── commit ────────────────────────────────────────────────────────────── */

static void in_plan_id(const struct in_ctx *x, char out[65])
{
    struct sha3_256_ctx c;
    unsigned char d[32];
    sha3_256_init(&c);
    sha3_256_write(&c, (const unsigned char *)"z23.dev_intake.plan.v1\n", 23);
    for (int i = 0; i < x->n; i++) {
        char line[256];
        int n = snprintf(line, sizeof(line), "%s %s %s %s %s\n", x->posts[i].id,
                         x->posts[i].verdict, x->posts[i].reason,
                         x->posts[i].with, x->posts[i].tip);
        sha3_256_write(&c, (const unsigned char *)line, (size_t)n);
    }
    sha3_256_finalize(&c, d);
    for (size_t i = 0; i < 32; i++)
        (void)snprintf(out + 2 * i, 3, "%02x", d[i]);
}

static void in_text(const struct in_post *p, char *out, size_t cap)
{
    if (!strcmp(p->verdict, "ACCEPT_FOR_QUEUE"))
        (void)snprintf(out, cap, "intake ACCEPT_FOR_QUEUE %s", p->submitted == 1 ? "queued" : "not queued");
    else if (p->with[0])
        (void)snprintf(out, cap, "intake CONFLICT(with=%s): rebase and re-post READY", p->with);
    else
        (void)snprintf(out, cap, "intake REFUSE(%s)", p->reason);
}

/* A lane-form post has no bundle yet: cut one (refs/intake/<i> since origin/main)
 * for dev.land.receive. A swarm-form post already has its fetched bundle. */
static bool in_mkbundle(const struct in_ctx *x, const struct in_post *p)
{
    char ref[48], base[48];
    const char *mk[] = {"bundle", "create", p->bundle, ref, base, NULL};
    if (!p->commit[0])
        return true;
    (void)snprintf(ref, sizeof(ref), "refs/intake/%d", p->idx);
    (void)snprintf(base, sizeof(base), "^%s", x->main_sha);
    return in_git(x, mk) == 0;
}

static void in_apply_one(struct in_ctx *x, struct in_post *p)
{
    struct json_value q;
    char text[160];
    if (!strcmp(p->verdict, "ACCEPT_FOR_QUEUE")) {
        json_init(&q);
        json_set_object(&q);
        (void)json_push_kv_str(&q, "bundle", p->bundle);
        (void)snprintf(text, sizeof(text), "intake-%.12s", p->id);
        (void)json_push_kv_str(&q, "lane", text);
        (void)json_push_kv_str(&q, "checkout", x->repo);
        p->submitted = in_mkbundle(x, p) && in_sub(zcl_native_handle_dev_land_remote,
                              "dev.land.receive", "zcl.land.v1", &q, NULL) ? 1 : 0;
        json_free(&q);
    }
    in_text(p, text, sizeof(text));
    json_init(&q);
    json_set_object(&q);
    (void)json_push_kv_str(&q, "kind", "result");
    (void)json_push_kv_str(&q, "text", text);
    (void)json_push_kv_str(&q, "ref", p->id);
    (void)json_push_kv_str(&q, "room", p->room[0] ? p->room : "fleet");
    (void)json_push_kv_str(&q, "agent", "intake");
    (void)in_sub(zcl_native_handle_fleet_board_post, "fleet.board.post",
                 "zcl.fleet_board_post_id.v1", &q, NULL);
    json_free(&q);
}

/* ── output ────────────────────────────────────────────────────────────── */

static void in_row(struct json_value *arr, const struct in_post *p)
{
    struct json_value r;
    char typed[96];
    if (!strcmp(p->verdict, "REFUSE"))
        (void)snprintf(typed, sizeof(typed), "REFUSE(%s)", p->reason);
    else if (!strcmp(p->verdict, "CONFLICT"))
        (void)snprintf(typed, sizeof(typed), "CONFLICT(with=%s)", p->with);
    else
        (void)snprintf(typed, sizeof(typed), "%s", p->verdict);
    json_init(&r);
    json_set_object(&r);
    (void)json_push_kv_str(&r, "id", p->id);
    (void)json_push_kv_str(&r, "agent", p->agent);
    (void)json_push_kv_str(&r, "verdict", typed);
    (void)json_push_kv_str(&r, "code", p->verdict);
    (void)json_push_kv_str(&r, "reason", p->reason);
    (void)json_push_kv_str(&r, "with", p->with);
    (void)json_push_kv_str(&r, "tip", p->tip);
    if (p->step[0])
        (void)json_push_kv_str(&r, "operator_step", p->step);
    if (p->submitted >= 0)
        (void)json_push_kv_bool(&r, "queued", p->submitted == 1);
    (void)json_push_back(arr, &r);
    json_free(&r);
}

static void in_publish(const struct in_ctx *x, struct zcl_command_reply *reply,
                       bool commit, bool applied, const char *plan)
{
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (int i = 0; i < x->n; i++)
        in_row(&arr, &x->posts[i]);
    (void)json_push_kv_str(&reply->data, "leaf", "dev.land.intake");
    (void)json_push_kv_str(&reply->data, "base", x->main_sha);
    (void)json_push_kv_bool(&reply->data, "commit", commit);
    (void)json_push_kv_bool(&reply->data, "applied", applied);
    (void)json_push_kv_str(&reply->data, "plan_id", plan);
    (void)json_push_kv(&reply->data, "verdicts", &arr);
    json_free(&arr);
}

static bool in_inputs(struct in_ctx *x, const struct json_value *in,
                      struct zcl_command_reply *reply)
{
    const char *repo = db_opt_str(in, "repo"), *bd = db_opt_str(in, "bundle_dir");
    if (!repo[0] && !getcwd(x->repo, sizeof(x->repo)))
        return false;
    if (repo[0])
        (void)snprintf(x->repo, sizeof(x->repo), "%s", repo);
    (void)snprintf(x->bundle_dir, sizeof(x->bundle_dir), "%s", bd);
    if (x->repo[0] != '/' || bd[0] != '/') {
        db_refuse(reply, "BAD_PATH", "input",
                  "repo (default: current directory) and bundle_dir must be absolute");
        return false;
    }
    in_list_load(db_opt_str(in, "allow"), &x->allow);
    in_list_load(db_opt_str(in, "deny"), &x->deny);
    if (x->allow.n == 0) {
        db_refuse(reply, "ALLOW_EMPTY", "input",
                  "allow must name a file with at least one author key");
        return false;
    }
    return true;
}

static void in_run(struct in_ctx *x, const struct json_value *in,
                   struct zcl_command_reply *reply)
{
    bool commit = db_opt_flag(in, "commit"), ok = true, go;
    char plan[65];
    in_collect(x, in, reply, &ok);
    if (!ok)
        return;
    qsort(x->posts, (size_t)x->n, sizeof(x->posts[0]), in_cmp);
    if (x->n > 0 && !in_scratch(x))
        db_refuse(reply, "SCRATCH_FAILED", "git",
                  "bundle_dir or the checkout's origin/main is not usable");
    else {
        in_checks(x);
        in_plan_id(x, plan);
        go = commit && db_opt_flag(in, "confirm") &&
             !strcmp(db_opt_str(in, "plan_id"), plan);
        for (int i = 0; go && i < x->n; i++)
            in_apply_one(x, &x->posts[i]);
        in_publish(x, reply, commit, go, plan);
    }
}

/* The scratch repository is ours alone: .intake-XXXXXX under bundle_dir. */
static void in_rm(const char *dir)
{
    const char *argv[] = {"rm", "-rf", "--", dir, NULL};
    char out[64];
    (void)zcl_spawn_capture(argv, out, sizeof(out), 60000);
}

void zcl_native_handle_dev_intake(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply)
{
    const struct json_value *in = request ? request->input : NULL;
    struct in_ctx *x;
    if (!reply)
        return;
    if (!in) {
        db_refuse(reply, "BAD_INPUT", "input", "dev.land.intake needs input");
        return;
    }
    x = zcl_calloc(1, sizeof(*x), "dev.land.intake");
    if (!x)
        return;
    x->out = zcl_malloc(IN_OUT, "dev_intake_out");
    if (x->out && in_inputs(x, in, reply))
        in_run(x, in, reply);
    if (x->scratch[0])
        in_rm(x->scratch);
    free(x->out);
    free(x);
}
