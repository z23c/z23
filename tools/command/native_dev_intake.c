/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: dev.land.intake, the lead's hand intake of READY posts as one leaf.
 * For each READY post on the board (or in a saved list, posts_file) it gives
 * one typed verdict: ACCEPT_FOR_QUEUE, REFUSE(reason) or CONFLICT(with=id).
 *
 * A READY post that offers a bundle reads
 *   READY root=<64hex> sha256=<64hex> size=<n> [peer=<v3 onion>] free text
 * (a READY post without sha256 is REFUSE(no_bundle); bundle_sha256= is read as
 * sha256=, as `dev land send --bundle_out` prints it). Checks, in order:
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

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "command/native_command.h"
#include "command/native_dev_batch.h"
#include "command/native_dev_land_remote_shared.h"

#include "base/cleanse.h"
#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/directory_compat.h"
#include "platform/private_file.h"
#include "platform/state_root.h"
#include "platform/temp_directory.h"
#include "platform/time_compat.h"
#include "util/spawn.h"
#include "session/fleet_board_proto.h"
#include "sha3/sha3.h"
#include "fleet_enrol.h"

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

/* IN_MAX live posts per run; ANSWERED posts are only reported, so they get
 * their own room (IN_CAP slots in all). IN_PAGES board pages of 200 rows. */
enum {
    IN_MAX = 32, IN_CAP = 96, IN_ANS = 256, IN_PAGES = 5, IN_PAGE_ROWS = 200,
    IN_PATH = 1024, IN_LINE = 128, IN_LIST = 64, IN_OUT = 262144
};

/* An intake result reply already on the board: its ref and short id. */
struct in_ans {
    char ref[65], id[13];
};

struct in_list {
    char v[IN_LIST][IN_LINE];
    int n;
    char author[IN_LINE]; /* a "result_author=" line's value; not an entry */
};

static const char in_author_tag[] = "result_author=";
static const char in_author_remedy[] =
    "intake cannot tell which READY posts it already answered; add a line "
    "result_author=<this node's 64 lowercase hex board host key> to the allow "
    "file";

struct in_post {
    char id[65], host[65], agent[FLEET_BOARD_AGENT_MAX + 1];
    char room[FLEET_BOARD_ROOM_MAX + 1];
    char root[65], sha256[65], peer[128], size[16];
    char bundle[IN_PATH], tip[41], lane[IN_PATH], commit[41];
    char step[320]; /* operator_step: what a person must do when we cannot fetch */
    int idx;        /* refs/intake/<idx> in the scratch repository */
    int64_t created;
    char verdict[24]; /* ACCEPT_FOR_QUEUE | REFUSE | CONFLICT | ANSWERED */
    char reason[48], with[17];
    char queue_error[64]; /* the dev.land.receive code when it refused */
    bool live;
    int submitted; /* -1 not tried, 0 failed, 1 queued */
};

struct in_ctx {
    char repo[IN_PATH], bundle_dir[IN_PATH], scratch[IN_PATH + 16];
    bool board; /* posts come from the live board (show can re-read a post) */
    char main_sha[41], *out;
    struct in_list allow, deny;
    struct in_post posts[IN_CAP];
    int n;
    int active;      /* posts that are not ANSWERED, at most IN_MAX */
    int skipped;     /* READY posts read but not taken for want of room */
    bool truncated;  /* skipped > 0, or the board had pages past the cap */
    bool board_more; /* the board had older posts past IN_PAGES pages */
    bool by_id;      /* one post asked for by id=: results do not answer it */
    struct in_ans ans[IN_ANS];
    int nans;
    bool ans_cut;      /* more valid result replies than IN_ANS were on the board */
    char author[65];   /* the one key whose result replies answer; "" = none */
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

/* A "result_author=" line is never an allow entry; the first one is kept. */
static bool in_list_author_line(struct in_list *l, const char *line, size_t len)
{
    size_t tag = sizeof(in_author_tag) - 1;
    if (strncmp(line, in_author_tag, tag))
        return false;
    if (!l->author[0]) {
        memcpy(l->author, line + tag, len - tag);
        l->author[len - tag] = '\0';
    }
    return true;
}

static void in_list_load(const char *path, struct in_list *l)
{
    struct db_text t = {0};
    size_t pos = 0, len;
    const char *line;
    l->n = 0;
    l->author[0] = '\0';
    if (!path[0] || !db_text_load(path, &t))
        return;
    while (l->n < IN_LIST && db_next_line(&t, &pos, &line, &len)) {
        while (len && (line[len - 1] == '\r' || line[len - 1] == ' '))
            len--;
        if (!len || line[0] == '#' || len >= IN_LINE)
            continue;
        if (in_list_author_line(l, line, len))
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

typedef void (*in_handler)(const struct zcl_command_request *,
                           struct zcl_command_reply *);

/* A failed sub-leaf call: its error code, message and next step. */
struct in_err {
    char code[64], message[192], step[256];
};

static bool in_sub_err(in_handler fn, const char *path, const char *schema,
                       const struct json_value *input, struct json_value *data,
                       struct in_err *err);

static bool in_sub(in_handler fn, const char *path, const char *schema,
                   const struct json_value *input, struct json_value *data)
{
    return in_sub_err(fn, path, schema, input, data, NULL);
}

/* Test seams (the board list and the board post); NULL is the real leaf. */
static in_handler g_in_list_hook, g_in_post_hook;

void zcl_dev_intake_hooks_for_test(in_handler list, in_handler post);
void zcl_dev_intake_hooks_for_test(in_handler list, in_handler post)
{
    g_in_list_hook = list;
    g_in_post_hook = post;
}

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

/* A READY post with no usable bundle: say what the poster must add. */
static void in_no_bundle(struct in_post *p)
{
    in_refuse(p, "no_bundle");
    (void)snprintf(p->step, sizeof(p->step),
                   "the post names no fetchable bundle: run `z23 fleet bundle "
                   "offer --file=B.bundle`, then re-post READY with root=, "
                   "sha256= and size= from the offer (bundle_sha256= is read "
                   "as sha256=)");
}

/* The bundle hash: sha256=<64hex>, or bundle_sha256= as `dev land send
 * --bundle_out` prints it. */
static bool in_sha_token(const char *text, struct in_post *p)
{
    return (in_token(text, "sha256", p->sha256, sizeof(p->sha256)) ||
            in_token(text, "bundle_sha256", p->sha256, sizeof(p->sha256))) &&
           in_hex_n(p->sha256, 64);
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
    if (!in_sha_token(text, p)) {
        in_no_bundle(p);
        return;
    }
    (void)in_token(text, "root", p->root, sizeof(p->root));
    (void)in_token(text, "size", p->size, sizeof(p->size));
    (void)in_token(text, "peer", p->peer, sizeof(p->peer));
}

/* Is there fleet state on this box to read? A box with no resolvable state
 * root, or no fleet directory under it, is unarmed: nothing is created and
 * nothing is revoked. A fleet directory that exists is armed. */
static bool in_fleet_dir_exists(void)
{
    char root[FLEET_ENROL_PATH_MAX], dir[FLEET_ENROL_PATH_MAX + 8];
    if (!platform_state_root_existing(root, sizeof(root)))
        return false;
    int n = snprintf(dir, sizeof(dir), "%s/fleet", root);
    return n > 0 && (size_t)n < sizeof(dir) && !platform_private_path_absent(dir);
}

/* The reader's fleet root: the operator it joined, else its own fleet key.
 * Read-only: an unarmed box is left untouched (present false). Once the
 * fleet directory exists, an unreadable pin or key is a failure, never
 * absence. */
static bool in_fleet_root(uint8_t root[32], bool *present)
{
    uint8_t seed[FLEET_ENROL_SEED_BYTES], own_pub[FLEET_ENROL_PUBKEY_BYTES];
    bool joined = false, own = false;
    const char *why = NULL;
    *present = false;
    if (!in_fleet_dir_exists())
        return true;
    if (!fleet_enrol_operator_read_existing(root, &joined, &why))
        return false;
    if (!fleet_enrol_key_read_existing(seed, own_pub, &own, &why) && !joined) {
        memory_cleanse(seed, sizeof seed);
        return false;
    }
    memory_cleanse(seed, sizeof seed);
    if (!joined)
        memcpy(root, own_pub, 32);
    *present = joined || own;
    return true;
}

enum in_rev { IN_REV_NO, IN_REV_YES, IN_REV_UNREADABLE };

/* Does the reader's fleet head revoke this author key (fleet_head_revokes
 * is the one authority)? No fleet root or no head file: not revoked. A head
 * or root that exists but cannot be read: IN_REV_UNREADABLE (fail closed).
 * A host that is not a 64-hex key cannot name a revoked key. A post's host
 * is the node's signing key (the DHT online key), the "signer" class of a
 * roster row, not the box key; head minting (fleet_head_mint via the enrol command) adds every signer bound
 * to a revoked box to the head's set, so matching the host against that set
 * is the right test. A head sequence record whose head file is gone is torn
 * (BAD), so it is unreadable here, never "no head". */
static enum in_rev in_author_revoked(const char *host)
{
    uint8_t root[32], key[32];
    bool present = false, revoked;
    struct fleet_head *head;
    enum fleet_head_state state;
    if (strlen(host) != 64 || !zcl_hex_decode(host, key, 32))
        return IN_REV_NO;
    if (!in_fleet_root(root, &present)) {
        LOG_WARN("intake", "fleet root unreadable; refusing the author");
        return IN_REV_UNREADABLE;
    }
    if (!present)
        return IN_REV_NO;
    head = zcl_malloc(sizeof *head, "intake-fleet-head");
    if (!head) {
        LOG_WARN("intake", "no memory for the fleet head; refusing the author");
        return IN_REV_UNREADABLE;
    }
    state = fleet_head_load_existing(root, head, NULL);
    revoked = state == FLEET_HEAD_OK && fleet_head_revokes(head, key);
    free(head);
    if (state == FLEET_HEAD_BAD) {
        LOG_WARN("intake", "fleet head unreadable; refusing the author");
        return IN_REV_UNREADABLE;
    }
    return revoked ? IN_REV_YES : IN_REV_NO;
}

/* Refuse an author the fleet head revokes; false when the post may go on. */
static bool in_refuse_revoked(struct in_post *p)
{
    enum in_rev r = in_author_revoked(p->host);
    if (r == IN_REV_NO)
        return false;
    if (r == IN_REV_UNREADABLE) {
        in_refuse(p, "fleet_head_unreadable");
        return true;
    }
    char shortid[13];
    memcpy(shortid, p->host, 12); /* host is 64 hex here */
    shortid[12] = '\0';
    in_refuse(p, "author_revoked");
    (void)snprintf(p->step, sizeof(p->step),
                   "author key %s is revoked by the fleet head; its "
                   "bundle is not taken",
                   shortid);
    return true;
}

/* The short id of an intake result already answering this post, or NULL.
 * An explicit id= asks for the answer again, so it is never answered. */
static const char *in_answer_of(const struct in_ctx *x, const char *id)
{
    if (x->by_id)
        return NULL;
    for (int i = 0; i < x->nans; i++)
        if (!strcmp(x->ans[i].ref, id))
            return x->ans[i].id;
    return NULL;
}

/* An already answered post gets the typed ANSWERED verdict and no work. */
static bool in_set_answered(struct in_ctx *x, struct in_post *p)
{
    const char *by = in_answer_of(x, p->id);
    char reason[sizeof(p->reason)];
    if (!by)
        return false;
    (void)snprintf(reason, sizeof(reason), "result=%s", by);
    in_set(p, "ANSWERED", reason);
    x->active--;
    return true;
}

/* A verified post's fields and its first verdict: time, author, answered,
 * revocation, then the bundle form. */
static void in_judge(struct in_ctx *x, struct in_post *p,
                     const struct json_value *src)
{
    int64_t ttl = json_get_int(json_get(src, "ttl"));
    struct fleet_board_post timed = {0};
    in_str(p->id, sizeof(p->id), src, "id");
    in_str(p->host, sizeof(p->host), src, "host");
    in_str(p->agent, sizeof(p->agent), src, "agent");
    in_str(p->room, sizeof(p->room), src, "room");
    p->created = json_get_int(json_get(src, "created_at"));
    timed.kind = FLEET_BOARD_KIND_NOTE;
    timed.created_at = (uint64_t)p->created;
    timed.ttl = ttl > 0 && ttl <= UINT32_MAX ? (uint32_t)ttl : 0;
    if (fleet_board_post_check_time(&timed, platform_time_wall_unix()) != FLEET_BOARD_OK)
        in_refuse(p, "post_expired_or_invalid_time");
    else if (!in_allowed(&x->allow, p->host))
        in_refuse(p, "author_not_allowed");
    else if (!in_set_answered(x, p) && !in_refuse_revoked(p))
        in_bundle_form(json_get_str(json_get(src, "text")), p);
}

/* One listed post. Unsigned/foreign/bundle-less posts get their verdict here. */
static void in_ingest(struct in_ctx *x, const struct json_value *j)
{
    struct in_post *p;
    struct json_value shown;
    const struct json_value *src;
    const char *text = json_get_str(json_get(j, "text"));
    if (!text || !in_is_ready(text))
        return;
    if (x->n >= IN_CAP || x->active >= IN_MAX) {
        x->skipped++; /* read, not taken: the reply says so */
        x->truncated = true;
        return;
    }
    p = &x->posts[x->n++];
    x->active++;
    memset(p, 0, sizeof(*p));
    p->submitted = -1;
    p->live = true;
    json_init(&shown);
    if (!in_verified(x, j, &shown, &src)) {
        in_str(p->id, sizeof(p->id), j, "id");
        in_refuse(p, "bad_signature");
    } else
        in_judge(x, p, src);
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

/* Run a sibling leaf in process; true on a passed reply. data (when not
 * NULL) takes ownership of reply.data; err (when not NULL) receives the
 * error of a reply that did not pass. */
static bool in_sub_err(in_handler fn, const char *path, const char *schema,
                       const struct json_value *input, struct json_value *data,
                       struct in_err *err)
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
    if (data) {
        json_free(data);
        *data = rp.data;
        json_init(&rp.data);
    }
    if (!ok && err) {
        (void)snprintf(err->code, sizeof(err->code), "%s", rp.error.code);
        (void)snprintf(err->message, sizeof(err->message), "%s", rp.error.message);
        (void)snprintf(err->step, sizeof(err->step), "%s", rp.error.next_action);
    }
    zcl_command_reply_free(&rp);
    return ok;
}

static void in_err_set(struct in_err *err, const char *code, const char *message)
{
    if (!err)
        return;
    (void)snprintf(err->code, sizeof(err->code), "%s", code);
    (void)snprintf(err->message, sizeof(err->message), "%s", message);
    err->step[0] = '\0';
}

/* A page cursor: the last row's time and id, moving strictly backward. */
static bool in_page_cursor(const struct json_value *page, int64_t prior_at,
                           const char *prior_id, int64_t *at, char id[65])
{
    const struct json_value *t = json_get(page, "next_created_at");
    const char *nid = json_get_str(json_get(page, "next_id"));
    if (!t || t->type != JSON_INT || json_get_int(t) <= 0 || !nid ||
        !in_hex_n(nid, 64))
        return false;
    if (prior_id[0] && json_get_int(t) > prior_at)
        return false;
    if (prior_id[0] && json_get_int(t) == prior_at && strcmp(nid, prior_id) >= 0)
        return false;
    *at = json_get_int(t);
    memcpy(id, nid, 65);
    return true;
}

/* One list reply: its rows join `posts`; the cursor moves to the next page. */
static bool in_page_take(const struct json_value *page, int64_t *at, char id[65],
                         struct json_value *posts, bool *more, struct in_err *err)
{
    const struct json_value *rows = json_get(page, "posts");
    const struct json_value *m = json_get(page, "has_more");
    int64_t next_at = 0;
    char next_id[65];
    if (!rows || rows->type != JSON_ARR || !m || m->type != JSON_BOOL) {
        in_err_set(err, "BOARD_PAGE_INVALID",
                   "the board list reply has no posts array or no has_more, "
                   "so its completeness is unknown");
        return false;
    }
    for (size_t i = 0; i < json_size(rows); i++) {
        if (!json_push_back(posts, json_at(rows, i))) {
            in_err_set(err, "BOARD_PAGE_INCOMPLETE", "could not retain every board row");
            return false;
        }
    }
    *more = json_get_bool(m);
    if (!*more)
        return true;
    if (!in_page_cursor(page, *at, id, &next_at, next_id)) {
        in_err_set(err, "BOARD_CURSOR_INVALID",
                   "the board list reply has_more but no usable next cursor");
        return false;
    }
    *at = next_at;
    memcpy(id, next_id, 65);
    return true;
}

/* One board page (room, since, and the cursor of the page before it). */
static bool in_page_read(in_handler list, const struct json_value *in, int64_t *at,
                         char id[65], struct json_value *posts, bool *more,
                         struct in_err *err)
{
    const char *room = db_opt_str(in, "room");
    struct json_value q, page;
    bool ok;
    json_init(&q);
    json_set_object(&q);
    ok = json_push_kv_str(&q, "room", room[0] ? room : "fleet") &&
         json_push_kv_int(&q, "limit", IN_PAGE_ROWS);
    if (ok && json_get(in, "since"))
        ok = json_push_kv_int(&q, "since", json_get_int(json_get(in, "since")));
    if (ok && id[0])
        ok = json_push_kv_int(&q, "before_created_at", *at) &&
             json_push_kv_str(&q, "before_id", id);
    if (!ok) {
        in_err_set(err, "BOARD_QUERY_INCOMPLETE", "could not prepare the board page query");
        json_free(&q);
        return false;
    }
    json_init(&page);
    ok = in_sub_err(list, "fleet.board.list", "zcl.fleet_board_list.v1", &q,
                    &page, err) &&
         in_page_take(&page, at, id, posts, more, err);
    json_free(&page);
    json_free(&q);
    return ok;
}

/* The live board, every page up to IN_PAGES, into a posts array. more is true
 * when the board still had older posts at the cap. A failed page keeps its
 * error in err and fails the whole read: a partial board is not a board. */
static bool in_load_board(const struct json_value *in, struct json_value *doc,
                          struct in_err *err, bool *more)
{
    in_handler list = g_in_list_hook ? g_in_list_hook : zcl_native_handle_fleet_board_list;
    char id[65] = "";
    int64_t at = 0;
    bool ok = true;
    json_set_array(doc);
    *more = false;
    for (int page = 0; ok && page < IN_PAGES; page++) {
        ok = in_page_read(list, in, &at, id, doc, more, err);
        if (ok && !*more)
            break;
    }
    if (!ok && !err->code[0])
        in_err_set(err, "BOARD_LIST_FAILED", "fleet.board.list did not pass");
    return ok;
}

/* The board list (room, since) or the saved posts_file, into doc. */
static bool in_load(const struct json_value *in, struct json_value *doc,
                    struct in_err *err, bool *more)
{
    const char *file = db_opt_str(in, "posts_file");
    struct db_text t = {0};
    bool ok;
    *more = false;
    if (!file[0])
        return in_load_board(in, doc, err, more);
    ok = db_text_load(file, &t) && t.n && json_read(doc, t.p, t.n);
    db_text_free(&t);
    return ok;
}

/* Is this row a result reply by the intake operator's own key? Only that key
 * answers: another allowed host must not be able to silence a helper's READY
 * by signing a result that names it. With no result author configured no row
 * qualifies. The reply must also carry a good signature from an allowed key. */
static bool in_result_row_ok(const struct in_ctx *x, const struct json_value *j)
{
    const char *text = json_get_str(json_get(j, "text"));
    char kind[16], agent[FLEET_BOARD_AGENT_MAX + 1], host[65];
    if (!text || !x->author[0])
        return false;
    in_str(kind, sizeof(kind), j, "kind");
    in_str(agent, sizeof(agent), j, "agent");
    in_str(host, sizeof(host), j, "host");
    return !strcmp(kind, "result") && !strcmp(agent, "intake") &&
           !strcasecmp(host, x->author) && in_allowed(&x->allow, host) &&
           in_sig_ok(j, text);
}

/* An intake result already on the board answers the READY post it refs. */
static void in_note_result(struct in_ctx *x, const struct json_value *j)
{
    struct in_ans *a;
    char ref[65];
    if (!in_result_row_ok(x, j))
        return;
    in_str(ref, sizeof(ref), j, "ref");
    if (!in_hex_n(ref, 64))
        return;
    if (x->nans >= IN_ANS) {
        x->ans_cut = true;
        x->truncated = true;
        return;
    }
    a = &x->ans[x->nans];
    memcpy(a->ref, ref, sizeof(a->ref));
    in_str(a->id, sizeof(a->id), j, "id");
    x->nans++;
}

/* The listed rows: results first (they answer), then the READY posts. */
static void in_take_posts(struct in_ctx *x, const struct json_value *list,
                          const char *want, bool more)
{
    for (size_t i = 0; i < json_size(list); i++)
        in_note_result(x, json_at(list, i));
    for (size_t i = 0; i < json_size(list); i++) {
        const struct json_value *j = json_at(list, i);
        if (!want[0] || !strncmp(json_get_str(json_get(j, "id")), want, strlen(want)))
            in_ingest(x, j);
    }
    x->board_more = more;
    x->truncated = x->truncated || more;
}

/* The refusal for a list that could not be read: the board's own code,
 * message and next step; NO_POSTS only for an unreadable posts_file. */
static void in_load_refuse(struct zcl_command_reply *reply, const struct in_err *err)
{
    if (!err->code[0]) {
        db_refuse(reply, "NO_POSTS", "collect",
                  "the board list (or posts_file) could not be read");
        return;
    }
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                           ZCL_COMMAND_EXIT_BLOCKED, err->code, "collect", false,
                           false, err->message[0] ? err->message : err->code,
                           "fleet.board.list");
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "%s",
                   err->step[0]
                       ? err->step
                       : "run `z23 fleet board list --room=fleet` to see the "
                         "same error and fix it, or pass posts_file=<saved "
                         "list>, then rerun");
}

static void in_collect(struct in_ctx *x, const struct json_value *in,
                       struct zcl_command_reply *reply, bool *ok)
{
    struct json_value doc;
    const struct json_value *list;
    struct in_err err = {{0}, {0}, {0}};
    const char *want = db_opt_str(in, "id");
    bool more = false;
    json_init(&doc);
    x->board = !db_opt_str(in, "posts_file")[0];
    x->by_id = want[0] != '\0';
    *ok = in_load(in, &doc, &err, &more);
    list = json_get(&doc, "posts");
    if (!list && doc.type == JSON_ARR)
        list = &doc;
    *ok = *ok && list;
    if (!*ok)
        in_load_refuse(reply, &err);
    else
        in_take_posts(x, list, want, more);
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
            in_no_bundle(p);
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
    if (!platform_temp_directory_create_under(x->bundle_dir, ".intake-", tmpl,
                                              sizeof(tmpl)))
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

static bool in_lane_syntax(const char *lane)
{
    size_t n = strlen(lane);
    return !strstr(lane, "/../") && !(n >= 3 && !strcmp(lane + n - 3, "/.."));
}

static bool in_lane_valid(const char *lane)
{
    char resolved[PATH_MAX], top[IN_PATH], root[PATH_MAX];
    const char *home = getenv("HOME");
    const char *args[] = {"rev-parse", "--show-toplevel", NULL};
    if (!home || snprintf(root, sizeof(root), "%s/development/lanes/z23", home) >= (int)sizeof(root))
        return false;
    char canonical_root[PATH_MAX];
    if (!platform_directory_canonical_real(root, canonical_root, sizeof(canonical_root)))
        return false;
    size_t n = strlen(canonical_root);
    if (!platform_directory_canonical_real(lane, resolved, sizeof(resolved)) || strcmp(resolved, lane) ||
        strncmp(resolved, canonical_root, n) || resolved[n] != '/')
        return false;
    return db_git_line(lane, args, top, sizeof(top)) && !strcmp(top, lane);
}

/* The live READY form names a lane on the poster's host and a commit. When
 * that lane is a repository here (the poster is this box, or shares its
 * filesystem) its objects join the scratch repository as a second alternate
 * and the commit becomes refs/intake/<i>: nothing is copied or run. Any
 * other host holds the commit where this leaf cannot reach: that is a typed
 * operator_step (the bridge reached it over ssh, which this leaf never does),
 * and the swarm form below is the way to avoid the step. */
static void in_lane_remote(struct in_post *p)
{
    in_refuse(p, "needs_operator_step");
    (void)snprintf(p->step, sizeof(p->step),
                   "the lane is not on this host: on the poster's host run `git bundle "
                   "create B.bundle origin/main..%.12s` and `z23 fleet bundle offer "
                   "--file=B.bundle`, then re-post READY with root=, sha256= and size=",
                   p->commit);
}

static void in_import_lane(struct in_ctx *x, struct in_post *p, int i)
{
    char common[IN_PATH], alt[IN_PATH + 64], obj[IN_PATH + 16], ref[48];
    const char *cd[] = {"rev-parse", "--path-format=absolute", "--git-common-dir",
                        NULL};
    const char *has[] = {"cat-file", "-e", NULL, NULL};
    char spec[64];
    const char *upd[] = {"update-ref", ref, p->commit, NULL};
    FILE *f;
    if (!in_lane_syntax(p->lane)) {
        in_refuse(p, "invalid_lane");
        return;
    }
    if (access(p->lane, F_OK) != 0) {
        if (errno == ENOENT)
            in_lane_remote(p);
        else
            in_refuse(p, "invalid_lane");
        return;
    }
    if (!in_lane_valid(p->lane)) {
        in_refuse(p, "invalid_lane");
        return;
    }
    (void)snprintf(spec, sizeof(spec), "%s^{commit}", p->commit);
    has[2] = spec;
    (void)snprintf(ref, sizeof(ref), "refs/intake/%d", i);
    if (!db_git_line(p->lane, cd, common, sizeof(common)) ||
        snprintf(obj, sizeof(obj), "%s/objects", common) >= (int)sizeof(obj)) {
        in_refuse(p, "invalid_lane");
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

static void in_batch_conflicts(struct in_ctx *x, struct in_post *p, int i)
{
    for (int j = 0; j < i; j++) {
        const struct in_post *q = &x->posts[j];
        int rc;
        if (strcmp(q->verdict, "ACCEPT_FOR_QUEUE") ||
            (rc = in_merge(x, q->tip, p->tip)) == 0)
            continue;
        in_set(p, rc > 0 ? "CONFLICT" : "REFUSE",
               rc > 0 ? "batch" : "merge_tree_failed");
        memcpy(p->with, q->id, 12);
        p->with[12] = '\0';
        break;
    }
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
        in_batch_conflicts(x, p, i);
        if (p->live)
            in_set(p, "ACCEPT_FOR_QUEUE", "");
    }
}

/* A post whose tip is already part of origin/main has nothing to land. */
static void in_landed(struct in_ctx *x)
{
    for (int i = 0; i < x->n; i++) {
        struct in_post *p = &x->posts[i];
        const char *anc[] = {"merge-base", "--is-ancestor", p->tip, x->main_sha, NULL};
        if (!p->live || !p->tip[0] || in_git(x, anc) != 0)
            continue;
        in_set(p, "ANSWERED", "on_main");
        x->active--;
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
    in_landed(x);
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
    if (!strcmp(p->verdict, "ACCEPT_FOR_QUEUE") && p->queue_error[0])
        (void)snprintf(out, cap, "intake ACCEPT_FOR_QUEUE not queued (%s)", p->queue_error);
    else if (!strcmp(p->verdict, "ACCEPT_FOR_QUEUE"))
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

/* Hand one accepted bundle to dev.land.receive; a refusal keeps its code. */
static void in_queue(struct in_ctx *x, struct in_post *p)
{
    struct json_value q;
    struct in_err err = {{0}, {0}, {0}};
    char lane[32];
    p->submitted = 0;
    if (!in_mkbundle(x, p)) {
        (void)snprintf(p->queue_error, sizeof(p->queue_error), "%s", "bundle_cut_failed");
        return;
    }
    json_init(&q);
    json_set_object(&q);
    (void)json_push_kv_str(&q, "bundle", p->bundle);
    (void)snprintf(lane, sizeof(lane), "intake-%.12s", p->id);
    (void)json_push_kv_str(&q, "lane", lane);
    (void)json_push_kv_str(&q, "checkout", x->repo);
    if (in_sub_err(zcl_native_handle_dev_land_remote, "dev.land.receive",
                   "zcl.land.v1", &q, NULL, &err))
        p->submitted = 1;
    else
        (void)snprintf(p->queue_error, sizeof(p->queue_error), "%s",
                       err.code[0] ? err.code : "receive_failed");
    json_free(&q);
}

static void in_apply_one(struct in_ctx *x, struct in_post *p)
{
    struct json_value q;
    char text[160];
    if (!strcmp(p->verdict, "ANSWERED"))
        return; /* already has its result: nothing is posted twice */
    if (!strcmp(p->verdict, "ACCEPT_FOR_QUEUE"))
        in_queue(x, p);
    in_text(p, text, sizeof(text));
    json_init(&q);
    json_set_object(&q);
    (void)json_push_kv_str(&q, "kind", "result");
    (void)json_push_kv_str(&q, "text", text);
    (void)json_push_kv_str(&q, "ref", p->id);
    (void)json_push_kv_str(&q, "room", p->room[0] ? p->room : "fleet");
    (void)json_push_kv_str(&q, "agent", "intake");
    (void)in_sub(g_in_post_hook ? g_in_post_hook : zcl_native_handle_fleet_board_post, "fleet.board.post",
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
    else if (!strcmp(p->verdict, "ANSWERED"))
        (void)snprintf(typed, sizeof(typed), "ANSWERED(%s)", p->reason);
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
    if (p->queue_error[0])
        (void)json_push_kv_str(&r, "queue_error", p->queue_error);
    (void)json_push_back(arr, &r);
    json_free(&r);
}

/* A run that did not see or take every READY post says so and says what to
 * do: it is never a complete-looking answer. */
static void in_publish_truncation(const struct in_ctx *x,
                                  struct zcl_command_reply *reply)
{
    char step[320];
    (void)json_push_kv_bool(&reply->data, "truncated", x->truncated);
    (void)json_push_kv_int(&reply->data, "skipped", x->skipped);
    if (!x->truncated)
        return;
    (void)snprintf(step, sizeof(step),
                   "%d READY post(s) were read but not taken (a run takes %d)%s%s: "
                   "rerun with id=<post id prefix> for one post, or since=<unix "
                   "time> to read newer posts",
                   x->skipped, IN_MAX,
                   x->board_more ? ", and older board pages were not read" : "",
                   x->ans_cut ? ", and result replies past the first 256 were "
                                "not recorded, so a READY they answer may be "
                                "answered again" : "");
    (void)json_push_kv_str(&reply->data, "next_step", step);
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
    in_publish_truncation(x, reply);
    if (!x->author[0] && !commit && !x->truncated)
        (void)json_push_kv_str(&reply->data, "next_step", in_author_remedy);
}

/* The key whose result replies count as answers: result_author=<64 hex> as an
 * input, else a "result_author=<64 hex>" line in the allow file. Absent: none
 * (every READY is processed again). A malformed value refuses the run. */
static bool in_author_load(struct in_ctx *x, const struct json_value *in,
                           struct zcl_command_reply *reply)
{
    const char *v = db_opt_str(in, "result_author");
    x->author[0] = '\0';
    if (!v[0])
        v = x->allow.author;
    if (!v[0])
        return true;
    if (!in_hex_n(v, 64)) {
        db_refuse(reply, "BAD_RESULT_AUTHOR", "input",
                  "result_author must be the intake operator's 64 lowercase "
                  "hex host key, as the board prints it");
        return false;
    }
    (void)snprintf(x->author, sizeof(x->author), "%s", v);
    return true;
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
    if (!in_author_load(x, in, reply))
        return false;
    if (x->allow.n == 0) {
        db_refuse(reply, "ALLOW_EMPTY", "input",
                  "allow must name a file with at least one author key");
        return false;
    }
    if (!x->author[0] && db_opt_flag(in, "commit")) {
        db_refuse(reply, "RESULT_AUTHOR_REQUIRED", "input", in_author_remedy);
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
    if (!x) {
        db_refuse(reply, "NO_MEMORY", "intake", "cannot allocate intake context");
        return;
    }
    x->out = zcl_malloc(IN_OUT, "dev_intake_out");
    if (!x->out)
        db_refuse(reply, "NO_MEMORY", "intake", "cannot allocate intake output buffer");
    else if (in_inputs(x, in, reply))
        in_run(x, in, reply);
    if (x->scratch[0])
        in_rm(x->scratch);
    free(x->out);
    free(x);
}
