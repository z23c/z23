/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_dev_intake: dev.land.intake (tools/command/native_dev_intake.c) on a lab of
 * lane clones and signed READY posts saved to a posts_file. A good post is
 * ACCEPT_FOR_QUEUE, a post with a broken signature, a foreign author or a
 * core/ path is REFUSE, two posts adding the same file differently give the
 * later one CONFLICT(with=<the earlier id>), and a run without commit (or
 * with commit but no confirm) leaves the checkout's refs untouched and
 * reports applied=false. */

#include "test/test_dev_batch_fixture.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "platform/state_root.h"
#include "platform/time_compat.h"
#include "crypto/ed25519.h"
#include "session/fleet_board_proto.h"
#include "fleet_enrol.h"

#include "command/native_dev_land_remote_shared.h"

#include <unistd.h>

struct di {
    struct dbf f;
    char bdir[800], allow[900], posts[900];
    uint8_t seed[32], pk[32];
    char pkhex[65];
    char ids[12][65];
};

static bool di_bundle(struct di *d, const char *lane, const char *file,
                      const char *text, char sha[65])
{
    char path[900], tmp[1000], dst[1000];
    const char *mk[] = {"bundle", "create", tmp, "HEAD", "^origin/main", NULL};
    char hex[SHA256_OUTPUT_SIZE * 2 + 1];
    char head[41];
    if (!dbf_lane(&d->f, lane, NULL, path, head) ||
        !dbf_commit_file(path, file, text))
        return false;
    (void)snprintf(tmp, sizeof(tmp), "%s/%s.tmp", d->bdir, lane);
    if (!dbf_git(path, mk) || !zcl_dlr_file_sha256(tmp, hex))
        return false;
    (void)snprintf(dst, sizeof(dst), "%s/%s.bundle", d->bdir, hex);
    (void)snprintf(sha, 65, "%s", hex);
    return rename(tmp, dst) == 0;
}

/* One signed READY post as a board-list row; flip=true breaks the text after
 * signing. Returns the id in ids[slot]. */
struct di_spec {
    int slot;
    uint64_t at;
    const char *text, *receipt;
    bool omit_receipt, flip;
    uint8_t kind;      /* 0 is a note */
    const char *agent; /* NULL is "lab" */
    const char *ref;   /* 64 hex of the post answered, or NULL */
    const uint8_t *seed, *pk; /* another signer than the lab key, or NULL */
};

static void di_post_s(struct di *d, struct json_value *arr, const struct di_spec *sp)
{
    struct fleet_board_post p;
    struct json_value r;
    char text[256], hex[129];
    const char *agent = sp->agent ? sp->agent : "lab";
    int slot = sp->slot;
    const uint8_t *pk = sp->pk ? sp->pk : d->pk;
    memset(&p, 0, sizeof(p));
    p.kind = sp->kind ? sp->kind : FLEET_BOARD_KIND_NOTE;
    p.scope = FLEET_BOARD_SCOPE_PUBLIC;
    p.created_at = sp->at;
    p.ttl = 86400;
    (void)snprintf(p.room, sizeof(p.room), "fleet");
    (void)snprintf(p.agent, sizeof(p.agent), "%s", agent);
    (void)snprintf(text, sizeof(text), "%s", sp->text);
    (void)snprintf(p.receipt, sizeof(p.receipt), "%s", sp->receipt);
    p.text_len = (uint32_t)strlen(text);
    memcpy(p.text, text, p.text_len + 1);
    if (sp->ref)
        (void)zcl_hex_decode_lower(sp->ref, p.ref, 32);
    (void)fleet_board_post_sign(&p, sp->seed ? sp->seed : d->seed, pk);
    zcl_hex_encode(p.id, 32, d->ids[slot]);
    if (sp->flip)
        text[strlen(text) - 1] = 'X';
    json_init(&r);
    json_set_object(&r);
    (void)json_push_kv_str(&r, "id", d->ids[slot]);
    (void)json_push_kv_str(&r, "kind", fleet_board_kind_name(p.kind));
    (void)json_push_kv_int(&r, "created_at", (int64_t)sp->at);
    (void)json_push_kv_int(&r, "ttl", 86400);
    zcl_hex_encode(p.ref, 32, hex);
    (void)json_push_kv_str(&r, "ref", hex);
    zcl_hex_encode(pk, 32, hex);
    (void)json_push_kv_str(&r, "host", hex);
    zcl_hex_encode(p.signature, 64, hex);
    (void)json_push_kv_str(&r, "signature", hex);
    (void)json_push_kv_str(&r, "agent", agent);
    (void)json_push_kv_str(&r, "scope", "public");
    (void)json_push_kv_str(&r, "room", "fleet");
    if (!sp->omit_receipt && sp->receipt[0])
        (void)json_push_kv_str(&r, "receipt", sp->receipt);
    (void)json_push_kv_str(&r, "text", text);
    (void)json_push_back(arr, &r);
    json_free(&r);
}

static void di_post_r(struct di *d, struct json_value *arr, int slot,
                      uint64_t at, const char *text_in, const char *receipt,
                      bool omit_receipt, bool flip)
{
    struct di_spec sp = {.slot = slot, .at = at, .text = text_in,
                         .receipt = receipt, .omit_receipt = omit_receipt,
                         .flip = flip};
    di_post_s(d, arr, &sp);
}

static void di_post(struct di *d, struct json_value *arr, int slot,
                    uint64_t at, const char *sha, bool flip)
{
    char text[128];
    (void)snprintf(text, sizeof(text), "READY sha256=%s size=1 fixture", sha);
    di_post_r(d, arr, slot, at, text, "", false, flip);
}

static bool di_write_posts(struct di *d, const struct json_value *arr)
{
    static char buf[131072];
    struct json_value doc;
    bool ok;
    json_init(&doc);
    json_set_object(&doc);
    (void)json_push_kv(&doc, "posts", arr);
    ok = json_write(&doc, buf, sizeof(buf)) < sizeof(buf) && dbf_put(d->posts, buf);
    json_free(&doc);
    return ok;
}

/* The reader's fleet state lives under the lab, never the developer's own:
 * HOME and XDG_STATE_HOME point into the lab while a case runs. */
static char g_di_xdg[4096], g_di_home[4096];

static void di_env_on(const struct di *d)
{
    const char *x = getenv("XDG_STATE_HOME"), *h = getenv("HOME");
    char st[1000];
    (void)snprintf(g_di_xdg, sizeof(g_di_xdg), "%s", x ? x : "");
    (void)snprintf(g_di_home, sizeof(g_di_home), "%s", h ? h : "");
    (void)snprintf(st, sizeof(st), "%s/state", d->f.root);
    (void)setenv("XDG_STATE_HOME", st, 1);
    (void)setenv("HOME", d->f.home, 1);
}

static void di_env_off(void)
{
    if (g_di_xdg[0])
        (void)setenv("XDG_STATE_HOME", g_di_xdg, 1);
    else
        (void)unsetenv("XDG_STATE_HOME");
    if (g_di_home[0])
        (void)setenv("HOME", g_di_home, 1);
    else
        (void)unsetenv("HOME");
}

/* Seal a head by operator 0x5a that revokes `revoked` (or nothing when NULL)
 * and make that operator this reader's trusted root. */
static bool di_head_import(uint64_t seq, const uint8_t *revoked)
{
    uint8_t seed[32], sk[32], pub[32];
    char line[FLEET_ENROL_HEAD_TEXT_MAX];
    struct fleet_head out;
    bool replaced = false;
    const char *why = NULL;
    memset(seed, 0x5a, 32);
    ed25519_keypair(pub, sk, seed);
    return fleet_enrol_operator_write(pub, &why) &&
           fleet_head_mint(seq, platform_time_wall_unix(), revoked, revoked ? 1 : 0,
                           seed, pub, line, sizeof(line), &why) &&
           fleet_head_import(line, pub, false, &out, &replaced, &why);
}

static void di_run(struct di *d, bool commit, struct zcl_command_reply *reply,
                   char *dump, size_t cap)
{
    const char *pairs[] = {"posts_file", d->posts, "repo", d->f.mainco,
                           "bundle_dir", d->bdir, "allow", d->allow, NULL};
    const char *flags[] = {"commit", NULL};
    di_env_on(d);
    dbf_call(zcl_native_handle_dev_intake, &d->f, pairs, commit ? flags : NULL,
             reply, dump, cap);
    di_env_off();
}

/* The same run on a box that resolves no state root at all: neither
 * XDG_STATE_HOME nor HOME is set while the leaf runs. */
static void di_run_bare(struct di *d, struct zcl_command_reply *reply,
                        char *dump, size_t cap)
{
    const char *pairs[] = {"posts_file", d->posts, "repo", d->f.mainco,
                           "bundle_dir", d->bdir, "allow", d->allow, NULL};
    di_env_on(d);
    (void)unsetenv("XDG_STATE_HOME");
    (void)unsetenv("HOME");
    dbf_call(zcl_native_handle_dev_intake, &d->f, pairs, NULL, reply, dump, cap);
    di_env_off();
}

/* The lab's fleet state directory, which an unarmed read must never make. */
static void di_fleet_dir(const struct di *d, char *out, size_t cap)
{
    (void)snprintf(out, cap, "%s/state/z23/dev/fleet", d->f.root);
}

static bool di_refs(const struct di *d, char *out, size_t cap)
{
    const char *argv[] = {"git", "-C", d->f.mainco, "for-each-ref", NULL};
    return zcl_spawn_capture(argv, out, cap, 30000) == 0;
}

/* The lab key is allowed and is the named result author (the allow-file line
 * is the only way an operator can name one from the command line). */
static bool di_allow_default(const struct di *d)
{
    char p[900];
    (void)snprintf(p, sizeof(p), "# allowed\n%s\nresult_author=%s\n", d->pkhex,
                   d->pkhex);
    return dbf_put(d->allow, p);
}

static bool di_setup(struct di *d)
{
    memset(d, 0, sizeof(*d));
    if (!dbf_setup(&d->f, "intake"))
        return false;
    (void)snprintf(d->bdir, sizeof(d->bdir), "%s/bundles", d->f.root);
    (void)snprintf(d->allow, sizeof(d->allow), "%s/allow.txt", d->f.root);
    (void)snprintf(d->posts, sizeof(d->posts), "%s/posts.json", d->f.root);
    if (!dbf_mkdirs(d->bdir))
        return false;
    memset(d->seed, 7, 32);
    {
        uint8_t sk[32];
        ed25519_keypair(d->pk, sk, d->seed);
        memcpy(d->seed, sk, 32);
    }
    zcl_hex_encode(d->pk, 32, d->pkhex);
    return di_allow_default(d);
}

/* ── the helper hand-off: READY form, board paging, receive refusals ────── */

extern void zcl_dev_intake_hooks_for_test(dbf_handler list, dbf_handler post);

static struct json_value g_di_pg[8];
static int g_di_pn, g_di_calls, g_di_nposts;
enum di_cur { DI_CUR_OK, DI_CUR_NO_HAS_MORE, DI_CUR_MISSING, DI_CUR_REPEAT, DI_CUR_RISING,
              DI_ROW_OOM, DI_QUERY_OOM };
static enum di_cur g_di_cur;
static bool g_di_list_fail;
static char g_di_before[8][80], g_di_ptext[256];

/* The next cursor of page i, bent by g_di_cur on the second page. */
static void di_stub_cursor(struct zcl_command_reply *rp, int i)
{
    int src = g_di_cur == DI_CUR_REPEAT && i == 1 ? 0 : i;
    const struct json_value *last =
        json_at(&g_di_pg[src], json_size(&g_di_pg[src]) - 1);
    int64_t at = json_get_int(json_get(last, "created_at"));
    if (g_di_cur == DI_CUR_RISING && i == 1)
        at += 1000;
    (void)json_push_kv_int(&rp->data, "next_created_at", at);
    (void)json_push_kv_str(&rp->data, "next_id", json_get_str(json_get(last, "id")));
}

static void di_stub_list(const struct zcl_command_request *rq,
                         struct zcl_command_reply *rp)
{
    int i = g_di_calls++;
    const char *b = json_get_str(json_get(rq->input, "before_id"));
    if (i < 8)
        (void)snprintf(g_di_before[i], sizeof(g_di_before[i]), "%s", b ? b : "");
    if (g_di_list_fail || i >= g_di_pn) {
        zcl_command_reply_fail(rp, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               "BOARD_PAGE_METADATA_MISSING", "serialize", false,
                               false,
                               "board reply lacks has_more; completeness is "
                               "unknown. Upgrade the node.",
                               "fleet.board.list");
        return;
    }
    (void)json_push_kv(&rp->data, "posts", &g_di_pg[i]);
    if (g_di_cur == DI_CUR_NO_HAS_MORE && i == 0)
        return;
    (void)json_push_kv_bool(&rp->data, "has_more", i + 1 < g_di_pn);
    if (i + 1 >= g_di_pn || (g_di_cur == DI_CUR_MISSING && i == 1))
        return;
    di_stub_cursor(rp, i);
    if (i == 0 && g_di_cur == DI_ROW_OOM)
        zcl_alloc_fault_fail_next("json_copy_children");
    if (i == 0 && g_di_cur == DI_QUERY_OOM)
        zcl_alloc_fault_fail_next("json_set_str");
}

static void di_stub_post(const struct zcl_command_request *rq,
                         struct zcl_command_reply *rp)
{
    const char *t = json_get_str(json_get(rq->input, "text"));
    (void)rp;
    g_di_nposts++;
    (void)snprintf(g_di_ptext, sizeof(g_di_ptext), "%s", t ? t : "");
}

static void di_stub_reset(void)
{
    for (int i = 0; i < 8; i++)
        json_free(&g_di_pg[i]);
    memset(g_di_pg, 0, sizeof(g_di_pg));
    memset(g_di_before, 0, sizeof(g_di_before));
    g_di_pn = g_di_calls = g_di_nposts = 0;
    g_di_list_fail = false;
    g_di_cur = DI_CUR_OK;
    g_di_ptext[0] = '\0';
    zcl_dev_intake_hooks_for_test(NULL, NULL);
}

static void di_stub_on(void)
{
    zcl_dev_intake_hooks_for_test(di_stub_list, di_stub_post);
}

struct di_opts {
    bool file;         /* read d->posts instead of the (stubbed) board */
    int mode;          /* 0 read only, 1 commit, 2 commit and confirm */
    const char *plan, *id, *author;
};

static void di_pair(const char **p, int *n, const char *k, const char *v)
{
    p[(*n)++] = k;
    p[(*n)++] = v;
    p[*n] = NULL;
}

static void di_call(struct di *d, const struct di_opts *o,
                    struct zcl_command_reply *reply, char *dump, size_t cap)
{
    const char *pairs[16] = {NULL}, *flags[3] = {NULL};
    int n = 0;
    di_pair(pairs, &n, "repo", d->f.mainco);
    di_pair(pairs, &n, "bundle_dir", d->bdir);
    di_pair(pairs, &n, "allow", d->allow);
    if (o->file)
        di_pair(pairs, &n, "posts_file", d->posts);
    if (o->plan)
        di_pair(pairs, &n, "plan_id", o->plan);
    if (o->author)
        di_pair(pairs, &n, "result_author", o->author);
    if (o->id)
        di_pair(pairs, &n, "id", o->id);
    if (o->mode >= 1)
        flags[0] = "commit";
    if (o->mode >= 2)
        flags[1] = "confirm";
    di_env_on(d);
    dbf_call(zcl_native_handle_dev_intake, &d->f, pairs, flags, reply, dump, cap);
    di_env_off();
}

/* The plan, then the confirmed commit against the same board. */
static void di_apply(struct di *d, struct di_opts o,
                     struct zcl_command_reply *reply, char *dump, size_t cap)
{
    char plan[65] = "";
    const char *at;
    o.mode = 1;
    di_call(d, &o, reply, dump, cap);
    at = strstr(dump, "\"plan_id\":\"");
    if (at)
        (void)snprintf(plan, sizeof(plan), "%.64s", at + 11);
    zcl_command_reply_free(reply);
    o.mode = 2;
    o.plan = plan;
    di_call(d, &o, reply, dump, cap);
}

static int di_count(const char *s, const char *needle)
{
    int n = 0;
    for (const char *p = strstr(s, needle); p; p = strstr(p + 1, needle))
        n++;
    return n;
}

static void di_row_text(char *out, size_t cap, const char *sha, const char *extra)
{
    (void)snprintf(out, cap,
                   "READY good 1111111111111111111111111111111111111111 "
                   "bundle_sha256=%s%s", sha, extra);
}

#define DI_ROOT0 " root=0000000000000000000000000000000000000000000000000000000000000000 size=1"

static int di_case_ready_line(struct di *d, const char *sha)
{
    int failures = 0;
    struct zcl_command_reply reply;
    struct di_opts o = {.file = true};
    struct json_value arr;
    char dump[16384], text[320];
    uint64_t now = (uint64_t)platform_time_wall_unix();

    TEST("intake: the READY line dev land send prints, plus root= and size=, "
         "is ACCEPT_FOR_QUEUE") {
        di_row_text(text, sizeof(text), sha, DI_ROOT0);
        json_init(&arr);
        json_set_array(&arr);
        di_post_r(d, &arr, 0, now, text, "", false, false);
        ASSERT(di_write_posts(d, &arr));
        json_free(&arr);
        di_call(d, &o, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "\"verdict\":\"ACCEPT_FOR_QUEUE\"") != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("intake: the bare printed line is REFUSE(no_bundle) and the step "
         "names root=, sha256= and size=") {
        di_row_text(text, sizeof(text),
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "");
        json_init(&arr);
        json_set_array(&arr);
        di_post_r(d, &arr, 0, now, text, "", false, false);
        ASSERT(di_write_posts(d, &arr));
        json_free(&arr);
        di_call(d, &o, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "REFUSE(no_bundle)") != NULL);
        ASSERT(strstr(dump, "\"operator_step\":\"") != NULL);
        ASSERT(strstr(dump, "root=") != NULL);
        ASSERT(strstr(dump, "sha256=") != NULL);
        ASSERT(strstr(dump, "size=") != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }
_test_next:;
    return failures;
}

static void di_page_row(struct di *d, struct json_value *page, int slot, int k)
{
    char text[64];
    (void)snprintf(text, sizeof(text), "READY nobundle-%d", k);
    di_post_r(d, page, slot, (uint64_t)platform_time_wall_unix() + 100 - (uint64_t)k,
              text, "", false, false);
}

static int di_case_board_error(struct di *d)
{
    int failures = 0;
    struct zcl_command_reply reply;
    struct di_opts o = {0};
    char dump[4096];

    TEST("intake: a failed board read keeps its code and next step, not NO_POSTS") {
        g_di_list_fail = true;
        di_stub_on();
        di_call(d, &o, &reply, dump, sizeof(dump));
        ASSERT_STR_EQ(reply.error.code, "BOARD_PAGE_METADATA_MISSING");
        ASSERT(strstr(reply.error.message, "has_more") != NULL);
        ASSERT(reply.error.next_action[0] != '\0');
        zcl_command_reply_free(&reply);
        PASS();
    }
_test_next:;
    di_stub_reset();
    return failures;
}

static int di_case_board_pages(struct di *d)
{
    int failures = 0;
    struct zcl_command_reply reply;
    struct di_opts o = {0};
    static char dump[65536];

    TEST("intake: a two-page board is read to the end") {
        for (int i = 0; i < 2; i++) {
            json_init(&g_di_pg[i]);
            json_set_array(&g_di_pg[i]);
        }
        di_page_row(d, &g_di_pg[0], 0, 0);
        di_page_row(d, &g_di_pg[0], 1, 1);
        di_page_row(d, &g_di_pg[1], 2, 2);
        g_di_pn = 2;
        di_stub_on();
        di_call(d, &o, &reply, dump, sizeof(dump));
        ASSERT_EQ(g_di_calls, 2);
        ASSERT_STR_EQ(g_di_before[1], d->ids[1]);
        ASSERT_EQ(di_count(dump, "REFUSE(no_bundle)"), 3);
        ASSERT(strstr(dump, "\"truncated\":false") != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }
_test_next:;
    di_stub_reset();
    return failures;
}

static int di_case_page_cap(struct di *d)
{
    int failures = 0;
    struct zcl_command_reply reply;
    struct di_opts o = {0};
    static char dump[65536];

    TEST("intake: a board still has_more at the page cap is truncated, not silent") {
        for (int i = 0; i < 8; i++) {
            json_init(&g_di_pg[i]);
            json_set_array(&g_di_pg[i]);
            di_page_row(d, &g_di_pg[i], 0, i);
        }
        g_di_pn = 8;
        di_stub_on();
        di_call(d, &o, &reply, dump, sizeof(dump));
        ASSERT_EQ(g_di_calls, 5);
        ASSERT(strstr(dump, "\"truncated\":true") != NULL);
        ASSERT(strstr(dump, "since=") != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }
_test_next:;
    di_stub_reset();
    return failures;
}

static int di_case_over_max(struct di *d)
{
    int failures = 0;
    struct zcl_command_reply reply;
    struct di_opts o = {.file = true};
    struct json_value arr;
    static char dump[65536];

    TEST("intake: more than 32 READY posts report truncated=true and a skipped count") {
        json_init(&arr);
        json_set_array(&arr);
        for (int i = 0; i < 34; i++)
            di_page_row(d, &arr, 0, i);
        ASSERT(di_write_posts(d, &arr));
        json_free(&arr);
        di_call(d, &o, &reply, dump, sizeof(dump));
        ASSERT_EQ(di_count(dump, "REFUSE(no_bundle)"), 32);
        ASSERT(strstr(dump, "\"truncated\":true") != NULL);
        ASSERT(strstr(dump, "\"skipped\":2") != NULL);
        ASSERT(strstr(dump, "id=") != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }
_test_next:;
    return failures;
}

static bool di_policy(struct di *d, const char *text)
{
    char st[1000], dir[1100], path[1200];
    di_env_on(d);
    bool ok = platform_state_root(st, sizeof(st));
    di_env_off();
    if (!ok || snprintf(dir, sizeof(dir), "%s/land", st) >= (int)sizeof(dir) ||
        snprintf(path, sizeof(path), "%s/receive-policy", dir) >= (int)sizeof(path))
        return false;
    if (!text)
        return unlink(path) == 0 || access(path, F_OK) != 0;
    return dbf_mkdirs(dir) && dbf_put(path, text);
}

/* dev.land.receive only takes a checkout that carries the three marker files
 * of the tree that owns the land queue; the lab's main checkout gets them
 * (untracked, so no ref moves). */
static bool di_markers(const struct di *d)
{
    static const char *const f[] = {"Makefile", "engine/composition/commands/root.def",
                                    "tools/dev/test_group_catalog.def"};
    char path[1000], dir[1000];
    for (size_t i = 0; i < sizeof(f) / sizeof(f[0]); i++) {
        (void)snprintf(path, sizeof(path), "%s/%s", d->f.mainco, f[i]);
        (void)snprintf(dir, sizeof(dir), "%s", path);
        *strrchr(dir, '/') = '\0';
        if (!dbf_mkdirs(dir) || !dbf_put(path, "# lab marker\n"))
            return false;
    }
    return true;
}

static int di_case_receive_refusal(struct di *d, const char *sha)
{
    int failures = 0;
    struct zcl_command_reply reply;
    struct di_opts o = {.file = true};
    struct json_value arr;
    static char dump[65536];
    char text[320];

    TEST("intake: a receive refusal carries its code in the result text and the row") {
        di_row_text(text, sizeof(text), sha, DI_ROOT0);
        json_init(&arr);
        json_set_array(&arr);
        di_post_r(d, &arr, 0, (uint64_t)platform_time_wall_unix(), text, "", false, false);
        ASSERT(di_write_posts(d, &arr));
        json_free(&arr);
        ASSERT(di_markers(d));
        ASSERT(di_policy(d, "require_receipts=1\n"));
        di_stub_on();
        di_apply(d, o, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "\"applied\":true") != NULL);
        ASSERT(strstr(dump, "\"queue_error\":\"RECEIVE_RECEIPTS_REQUIRED\"") != NULL);
        ASSERT_EQ(g_di_nposts, 1);
        ASSERT(strstr(g_di_ptext, "not queued (RECEIVE_RECEIPTS_REQUIRED)") != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }
_test_next:;
    (void)di_policy(d, NULL);
    di_stub_reset();
    return failures;
}

static int di_case_answered(struct di *d, const char *sha)
{
    int failures = 0;
    struct zcl_command_reply reply;
    struct di_opts o = {.file = true, .author = d->pkhex};
    struct json_value arr;
    static char dump[65536];
    char text[320];
    struct di_spec res = {.slot = 1, .text = "intake ACCEPT_FOR_QUEUE queued",
                          .receipt = "", .kind = FLEET_BOARD_KIND_RESULT,
                          .agent = "intake"};

    TEST("intake: a READY post that already has an intake result is ANSWERED, "
         "and a second run posts nothing") {
        di_row_text(text, sizeof(text), sha, DI_ROOT0);
        json_init(&arr);
        json_set_array(&arr);
        di_post_r(d, &arr, 0, (uint64_t)platform_time_wall_unix(), text, "", false, false);
        res.at = (uint64_t)platform_time_wall_unix() + 1;
        res.ref = d->ids[0];
        di_post_s(d, &arr, &res);
        ASSERT(di_write_posts(d, &arr));
        json_free(&arr);
        di_stub_on();
        di_apply(d, o, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "ANSWERED(result=") != NULL);
        ASSERT(strstr(dump, "ACCEPT_FOR_QUEUE\"") == NULL);
        ASSERT_EQ(g_di_nposts, 0);
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("intake: an explicit id= asks for the answer again") {
        o.id = d->ids[0];
        /* the policy refuses at once, so the lab queue is never touched */
        ASSERT(di_policy(d, "require_receipts=1\n"));
        di_apply(d, o, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "\"verdict\":\"ACCEPT_FOR_QUEUE\"") != NULL);
        ASSERT_EQ(g_di_nposts, 1);
        zcl_command_reply_free(&reply);
        PASS();
    }
_test_next:;
    (void)di_policy(d, NULL);
    di_stub_reset();
    return failures;
}

static int di_case_on_main(struct di *d, const char *sha)
{
    int failures = 0;
    struct zcl_command_reply reply;
    struct di_opts o = {.file = true};
    struct json_value arr;
    static char dump[65536];
    char text[320], bundle[1000], tip[41];
    const char *fetch[] = {"fetch", "-q", bundle, "HEAD", NULL};
    const char *setref[] = {"update-ref", "refs/remotes/origin/main", tip, NULL};

    TEST("intake: a READY post whose tip is already on origin/main is ANSWERED") {
        (void)snprintf(bundle, sizeof(bundle), "%s/%s.bundle", d->bdir, sha);
        ASSERT(dbf_git(d->f.mainco, fetch));
        ASSERT(dbf_rev(d->f.mainco, "FETCH_HEAD", tip));
        ASSERT(dbf_git(d->f.mainco, setref));
        di_row_text(text, sizeof(text), sha, DI_ROOT0);
        json_init(&arr);
        json_set_array(&arr);
        di_post_r(d, &arr, 0, (uint64_t)platform_time_wall_unix(), text, "", false, false);
        ASSERT(di_write_posts(d, &arr));
        json_free(&arr);
        di_stub_on();
        di_apply(d, o, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "ANSWERED(on_main)") != NULL);
        ASSERT_EQ(g_di_nposts, 0);
        zcl_command_reply_free(&reply);
        PASS();
    }
_test_next:;
    di_stub_reset();
    return failures;
}

/* One READY by the lab key plus one intake result row by `res`; a run with
 * result_author=`author` (or none). True when the READY was still processed:
 * a queue verdict, no ANSWERED, and exactly one result post. */
static bool di_seed_board(struct di *d, const char *sha, struct di_spec res)
{
    struct json_value arr;
    char text[320];
    bool ok;
    di_row_text(text, sizeof(text), sha, DI_ROOT0);
    json_init(&arr);
    json_set_array(&arr);
    di_post_r(d, &arr, 0, (uint64_t)platform_time_wall_unix(), text, "", false, false);
    res.slot = 1;
    res.at = (uint64_t)platform_time_wall_unix() + 1;
    res.ref = d->ids[0];
    res.kind = FLEET_BOARD_KIND_RESULT;
    di_post_s(d, &arr, &res);
    ok = di_write_posts(d, &arr);
    json_free(&arr);
    if (!ok || !di_policy(d, "require_receipts=1\n"))
        return false;
    g_di_nposts = 0;
    di_stub_on();
    return true;
}

static bool di_still_processed(struct di *d, const char *sha, struct di_spec res,
                               const char *author)
{
    struct zcl_command_reply reply;
    struct di_opts o = {.file = true, .author = author};
    static char dump[65536];
    bool ok = di_seed_board(d, sha, res);
    if (ok) {
        di_apply(d, o, &reply, dump, sizeof(dump));
        ok = strstr(dump, "\"verdict\":\"ACCEPT_FOR_QUEUE\"") != NULL &&
             strstr(dump, "ANSWERED") == NULL && g_di_nposts == 1;
        zcl_command_reply_free(&reply);
    }
    (void)di_policy(d, NULL);
    di_stub_reset();
    return ok;
}

/* The same board, run with commit: true when the READY is ANSWERED and not
 * one result was posted. */
static bool di_answered(struct di *d, const char *sha, struct di_spec res,
                        const char *author)
{
    struct zcl_command_reply reply;
    struct di_opts o = {.file = true, .author = author};
    static char dump[65536];
    bool ok = di_seed_board(d, sha, res);
    if (ok) {
        di_apply(d, o, &reply, dump, sizeof(dump));
        ok = strstr(dump, "ANSWERED(result=") != NULL &&
             strstr(dump, "ACCEPT_FOR_QUEUE") == NULL && g_di_nposts == 0;
        zcl_command_reply_free(&reply);
    }
    (void)di_policy(d, NULL);
    di_stub_reset();
    return ok;
}

static int di_case_forged_result(struct di *d, const char *sha)
{
    int failures = 0;
    uint8_t skb[32], pkb[32], skc[32], pkc[32], sd[32];
    char hexb[65], hexc[65], allow[400];
    struct di_spec res = {.text = "intake ACCEPT_FOR_QUEUE queued", .receipt = "",
                          .agent = "intake"};
    memset(sd, 0x42, 32);
    ed25519_keypair(pkb, skb, sd);
    memset(sd, 0x43, 32);
    ed25519_keypair(pkc, skc, sd);
    zcl_hex_encode(pkb, 32, hexb);
    zcl_hex_encode(pkc, 32, hexc);
    (void)snprintf(allow, sizeof(allow), "%s\n%s\n", d->pkhex, hexb);

    TEST("intake: a result row from another allowed host does not answer a READY") {
        ASSERT(dbf_put(d->allow, allow));
        res.seed = skb;
        res.pk = pkb;
        ASSERT(di_still_processed(d, sha, res, d->pkhex));
        PASS();
    }

    TEST("intake: a result row from a host outside the allow file does not answer") {
        res.seed = skc;
        res.pk = pkc;
        ASSERT(di_still_processed(d, sha, res, hexc));
        ASSERT(di_still_processed(d, sha, res, d->pkhex));
        PASS();
    }

    TEST("intake: a badly signed result row from the intake key does not answer") {
        res.seed = NULL;
        res.pk = NULL;
        res.flip = true;
        ASSERT(di_still_processed(d, sha, res, d->pkhex));
        PASS();
    }

    TEST("intake: a result row whose agent is not intake does not answer") {
        res.flip = false;
        res.agent = "lab";
        ASSERT(di_still_processed(d, sha, res, d->pkhex));
        PASS();
    }

    TEST("intake: a commit run with no result author is refused before any post") {
        struct zcl_command_reply reply;
        struct di_opts o = {.file = true, .mode = 1};
        static char dump[65536];
        res.agent = "intake";
        ASSERT(di_seed_board(d, sha, res));
        di_call(d, &o, &reply, dump, sizeof(dump));
        ASSERT_STR_EQ(reply.error.code, "RESULT_AUTHOR_REQUIRED");
        ASSERT(strstr(reply.error.message, "result_author=") != NULL);
        ASSERT_EQ(g_di_nposts, 0);
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("intake: a plan run with no result author works and names the remedy") {
        struct zcl_command_reply reply;
        struct di_opts o = {.file = true};
        static char dump[65536];
        di_call(d, &o, &reply, dump, sizeof(dump));
        ASSERT(reply.error.code[0] == '\0');
        ASSERT(strstr(dump, "\"verdict\":\"ACCEPT_FOR_QUEUE\"") != NULL);
        ASSERT(strstr(dump, "\"next_step\":\"intake cannot tell") != NULL);
        ASSERT(strstr(dump, "result_author=") != NULL);
        ASSERT_EQ(g_di_nposts, 0);
        zcl_command_reply_free(&reply);
        (void)di_policy(d, NULL);
        di_stub_reset();
        PASS();
    }

    TEST("intake: a malformed result_author refuses the run") {
        struct zcl_command_reply reply;
        struct di_opts o = {.file = true, .author = "nothex"};
        char dump[4096];
        di_call(d, &o, &reply, dump, sizeof(dump));
        ASSERT_STR_EQ(reply.error.code, "BAD_RESULT_AUTHOR");
        zcl_command_reply_free(&reply);
        PASS();
    }
_test_next:;
    (void)di_allow_default(d);
    return failures;
}

/* The operator's only route: a result_author= line in the allow file. */
static int di_case_author_line(struct di *d, const char *sha)
{
    int failures = 0;
    uint8_t skb[32], pkb[32], sd[32];
    char hexb[65], allow[400];
    struct di_spec res = {.text = "intake ACCEPT_FOR_QUEUE queued", .receipt = "",
                          .agent = "intake"};
    memset(sd, 0x42, 32);
    ed25519_keypair(pkb, skb, sd);
    zcl_hex_encode(pkb, 32, hexb);

    TEST("intake: a result_author= allow-file line makes the lab's result answer") {
        ASSERT(di_allow_default(d));
        ASSERT(di_answered(d, sha, res, NULL));
        PASS();
    }

    TEST("intake: an allow-file author naming another host leaves the READY open") {
        (void)snprintf(allow, sizeof(allow), "%s\n%s\nresult_author=%s\n",
                       d->pkhex, hexb, hexb);
        ASSERT(dbf_put(d->allow, allow));
        ASSERT(di_still_processed(d, sha, res, NULL));
        PASS();
    }

    TEST("intake: an allow file holding only a result_author= line is ALLOW_EMPTY") {
        struct zcl_command_reply reply;
        struct di_opts o = {.file = true};
        char dump[4096];
        (void)snprintf(allow, sizeof(allow), "result_author=%s\n", d->pkhex);
        ASSERT(dbf_put(d->allow, allow));
        di_call(d, &o, &reply, dump, sizeof(dump));
        ASSERT_STR_EQ(reply.error.code, "ALLOW_EMPTY");
        zcl_command_reply_free(&reply);
        PASS();
    }
_test_next:;
    (void)di_allow_default(d);
    return failures;
}

static void di_cap_pages(struct di *d, int n_rows)
{
    struct di_spec res = {.slot = 1, .text = "intake REFUSE x", .receipt = "",
                          .kind = FLEET_BOARD_KIND_RESULT, .agent = "intake",
                          .ref = d->ids[0]};
    uint64_t now = (uint64_t)platform_time_wall_unix();
    for (int p = 0; p < 2; p++) {
        json_init(&g_di_pg[p]);
        json_set_array(&g_di_pg[p]);
    }
    for (int k = 0; k < n_rows; k++) {
        res.at = now + 1000 - (uint64_t)k;
        di_post_s(d, &g_di_pg[k < n_rows / 2 ? 0 : 1], &res);
    }
    g_di_pn = 2;
}

static int di_case_answer_cap(struct di *d)
{
    int failures = 0;
    struct zcl_command_reply reply;
    struct di_opts o = {.author = d->pkhex};
    static char dump[65536];

    TEST("intake: more result replies than the answer table holds set truncated") {
        di_cap_pages(d, 260);
        di_stub_on();
        di_call(d, &o, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "\"truncated\":true") != NULL);
        ASSERT(strstr(dump, "result replies") != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("intake: result replies within the table do not set truncated") {
        di_stub_reset();
        di_cap_pages(d, 200);
        di_stub_on();
        di_call(d, &o, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "\"truncated\":false") != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }
_test_next:;
    di_stub_reset();
    return failures;
}

static int di_cursor_run(struct di *d, enum di_cur mode, const char *code)
{
    struct zcl_command_reply reply;
    struct di_opts o = {0};
    char dump[4096];
    int ok;
    for (int i = 0; i < 3; i++) {
        json_init(&g_di_pg[i]);
        json_set_array(&g_di_pg[i]);
        di_page_row(d, &g_di_pg[i], 0, i);
    }
    g_di_pn = 3;
    g_di_cur = mode;
    di_stub_on();
    di_call(d, &o, &reply, dump, sizeof(dump));
    ok = !strcmp(reply.error.code, code);
    if (mode == DI_ROW_OOM || mode == DI_QUERY_OOM) {
        ok = ok && !zcl_alloc_fault_armed_label() && g_di_calls == 1 && !g_di_nposts;
        zcl_alloc_fault_clear();
    }
    zcl_command_reply_free(&reply);
    di_stub_reset();
    return ok;
}

static int di_case_cursor(struct di *d)
{
    int failures = 0;

    TEST("intake: a repeating, rising or missing next cursor is BOARD_CURSOR_INVALID") {
        ASSERT(di_cursor_run(d, DI_CUR_REPEAT, "BOARD_CURSOR_INVALID"));
        ASSERT(di_cursor_run(d, DI_CUR_RISING, "BOARD_CURSOR_INVALID"));
        ASSERT(di_cursor_run(d, DI_CUR_MISSING, "BOARD_CURSOR_INVALID"));
        PASS();
    }

    TEST("intake: a page without has_more is BOARD_PAGE_INVALID") {
        ASSERT(di_cursor_run(d, DI_CUR_NO_HAS_MORE, "BOARD_PAGE_INVALID"));
        PASS();
    }

    TEST("intake: a failed row copy or continuation query refuses partial intake") {
        ASSERT(di_cursor_run(d, DI_ROW_OOM, "BOARD_PAGE_INCOMPLETE"));
        ASSERT(di_cursor_run(d, DI_QUERY_OOM, "BOARD_QUERY_INCOMPLETE"));
        PASS();
    }
_test_next:;
    return failures;
}

int test_dev_intake(void);
int test_dev_intake(void)
{
    int failures = 0;
    struct di d;
    struct zcl_command_reply reply;
    struct json_value arr;
    char dump[16384], shaA[65], shaB[65], shaC[65], shaD[65], shaE[65];
    char before[4096], after[4096];

    ASSERT(di_setup(&d));
    ASSERT(di_bundle(&d, "good", "src/ok.c", "int ok;\n", shaA));
    ASSERT(di_bundle(&d, "core", "core/x.c", "int x;\n", shaB));
    ASSERT(di_bundle(&d, "same1", "src/same.c", "int a;\n", shaC));
    ASSERT(di_bundle(&d, "same2", "src/same.c", "int b;\n", shaD));
    ASSERT(di_bundle(&d, "bad", "src/bad.c", "int z;\n", shaE));
    ASSERT(di_refs(&d, before, sizeof(before)));

    TEST("intake: the leaf is registered") {
        ASSERT(zcl_command_registry_find(zcl_command_catalog(), "dev.land.intake",
                                         NULL) != NULL);
        PASS();
    }

    TEST("intake: a good post is ACCEPT_FOR_QUEUE") {
        json_init(&arr);
        json_set_array(&arr);
        di_post(&d, &arr, 0, (uint64_t)platform_time_wall_unix() + 0, shaA, false);
        ASSERT(di_write_posts(&d, &arr));
        json_free(&arr);
        di_run(&d, false, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "\"verdict\":\"ACCEPT_FOR_QUEUE\"") != NULL);
        ASSERT(strstr(dump, "\"applied\":false") != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("intake: a bad signature and a core/ path are REFUSE") {
        json_init(&arr);
        json_set_array(&arr);
        di_post(&d, &arr, 1, (uint64_t)platform_time_wall_unix() + 1, shaE, true);
        di_post(&d, &arr, 2, (uint64_t)platform_time_wall_unix() + 2, shaB, false);
        ASSERT(di_write_posts(&d, &arr));
        json_free(&arr);
        di_run(&d, false, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "REFUSE(bad_signature)") != NULL);
        ASSERT(strstr(dump, "REFUSE(denied_path)") != NULL);
        ASSERT(strstr(dump, "ACCEPT_FOR_QUEUE") == NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("intake: an author outside the allow file is REFUSE") {
        json_init(&arr);
        json_set_array(&arr);
        di_post(&d, &arr, 3, (uint64_t)platform_time_wall_unix() + 3, shaA, false);
        ASSERT(di_write_posts(&d, &arr));
        json_free(&arr);
        ASSERT(dbf_put(d.allow, "# nobody\n11111111111111111111111111111111"
                                "11111111111111111111111111111111\n"));
        di_run(&d, false, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "REFUSE(author_not_allowed)") != NULL);
        zcl_command_reply_free(&reply);
        ASSERT(di_allow_default(&d));
        PASS();
    }

    TEST("intake: an author the fleet head revokes is REFUSE(author_revoked); "
         "an unreadable head fails closed; no head changes nothing") {
        uint8_t other[32];
        char hp[1100];
        json_init(&arr);
        json_set_array(&arr);
        di_post(&d, &arr, 5, (uint64_t)platform_time_wall_unix() + 5, shaA, false);
        ASSERT(di_write_posts(&d, &arr));
        json_free(&arr);

        memset(other, 0x11, sizeof(other));
        /* no fleet root and no head: behaviour unchanged */
        di_run(&d, false, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "\"verdict\":\"ACCEPT_FOR_QUEUE\"") != NULL);
        zcl_command_reply_free(&reply);
        /* ... and a read-only intake makes no fleet state */
        di_fleet_dir(&d, hp, sizeof(hp));
        ASSERT(access(hp, F_OK) != 0);

        /* a box that resolves no state root is the unarmed case too */
        di_run_bare(&d, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "\"verdict\":\"ACCEPT_FOR_QUEUE\"") != NULL);
        ASSERT(strstr(dump, "fleet_head_unreadable") == NULL);
        zcl_command_reply_free(&reply);

        /* a head that revokes someone else does not touch this author */
        di_env_on(&d);
        ASSERT(di_head_import(1, other));
        di_env_off();
        di_run(&d, false, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "\"verdict\":\"ACCEPT_FOR_QUEUE\"") != NULL);
        zcl_command_reply_free(&reply);

        di_env_on(&d);
        ASSERT(di_head_import(2, d.pk));
        ASSERT(fleet_enrol_state_path("roster.head", hp, sizeof(hp)));
        di_env_off();
        di_run(&d, false, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "REFUSE(author_revoked)") != NULL);
        ASSERT(strstr(dump, "ACCEPT_FOR_QUEUE") == NULL);
        ASSERT(strstr(dump, "author key ") != NULL);
        ASSERT(strstr(dump, d.pkhex) == NULL); /* the short id, never the key */
        zcl_command_reply_free(&reply);

        ASSERT(dbf_put(hp, "not a sealed head\n"));
        di_run(&d, false, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "REFUSE(fleet_head_unreadable)") != NULL);
        ASSERT(strstr(dump, "ACCEPT_FOR_QUEUE") == NULL);
        zcl_command_reply_free(&reply);

        /* a head file deleted while its sequence record remains is not
         * "no head": it is unreadable and fails closed */
        ASSERT(unlink(hp) == 0);
        di_run(&d, false, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "REFUSE(fleet_head_unreadable)") != NULL);
        ASSERT(strstr(dump, "ACCEPT_FOR_QUEUE") == NULL);
        zcl_command_reply_free(&reply);

        /* later cases start from a box with no fleet state again */
        {
            char st[1000], gone[1010];
            (void)snprintf(st, sizeof(st), "%s/state", d.f.root);
            (void)snprintf(gone, sizeof(gone), "%s.used", st);
            ASSERT(rename(st, gone) == 0);
        }
        PASS();
    }

    TEST("intake: two posts adding the same file differently CONFLICT") {
        char want[96];
        json_init(&arr);
        json_set_array(&arr);
        di_post(&d, &arr, 4, (uint64_t)platform_time_wall_unix() + 4, shaC, false);
        di_post(&d, &arr, 5, (uint64_t)platform_time_wall_unix() + 5, shaD, false);
        ASSERT(di_write_posts(&d, &arr));
        json_free(&arr);
        di_run(&d, false, &reply, dump, sizeof(dump));
        (void)snprintf(want, sizeof(want), "CONFLICT(with=%.12s)", d.ids[4]);
        ASSERT(strstr(dump, "\"verdict\":\"ACCEPT_FOR_QUEUE\"") != NULL);
        ASSERT(strstr(dump, want) != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("intake: the live READY form (lane path, commit, text) is ACCEPT_FOR_QUEUE") {
        char lane[900], head[41], text[512];
        ASSERT(dbf_lane(&d.f, "live", NULL, lane, head));
        ASSERT(dbf_commit_file(lane, "src/live.c", "int live;\n"));
        ASSERT(dbf_rev(lane, "HEAD", head));
        (void)snprintf(text, sizeof(text),
                       "READY %s %s Reject future timestamps; fresh base, lint pass.",
                       lane, head);
        json_init(&arr);
        json_set_array(&arr);
        di_post_r(&d, &arr, 6, (uint64_t)platform_time_wall_unix() + 6, text, "", false, false);
        (void)snprintf(text, sizeof(text),
                       "READY /nonexistent/other-host/lane %s remote lane", head);
        di_post_r(&d, &arr, 7, (uint64_t)platform_time_wall_unix() + 7, text, "", false, false);
        ASSERT(di_write_posts(&d, &arr));
        json_free(&arr);
        di_run(&d, false, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "\"verdict\":\"ACCEPT_FOR_QUEUE\"") != NULL);
        ASSERT(strstr(dump, head) != NULL);
        ASSERT(strstr(dump, "REFUSE(needs_operator_step)") != NULL);
        ASSERT(strstr(dump, "\"operator_step\":\"the lane is not on this host") != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("intake: traversal and repository subdirectories are refused") {
        char lane[900], head[41], text[1200];
        ASSERT(dbf_lane(&d.f, "hostile", NULL, lane, head));
        json_init(&arr);
        json_set_array(&arr);
        (void)snprintf(text, sizeof(text), "READY %s/../hostile %s traversal", lane, head);
        di_post_r(&d, &arr, 10, (uint64_t)platform_time_wall_unix(), text, "", false, false);
        (void)snprintf(text, sizeof(text), "READY %s/.. %s parent", lane, head);
        di_post_r(&d, &arr, 11, (uint64_t)platform_time_wall_unix(), text, "", false, false);
        ASSERT(di_write_posts(&d, &arr));
        json_free(&arr);
        di_run(&d, false, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "REFUSE(invalid_lane)") != NULL);
        ASSERT(strstr(dump, "ACCEPT_FOR_QUEUE") == NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("intake: outside-root repository and lane subdirectory are refused") {
        char lane[900], head[41], outside[900], sub[1000], text[1200];
        const char *clone[] = {"clone", "-q", d.f.origin, outside, NULL};
        ASSERT(dbf_lane(&d.f, "inside", NULL, lane, head));
        (void)snprintf(sub, sizeof(sub), "%s/sub", lane);
        ASSERT(dbf_mkdirs(sub));
        (void)snprintf(outside, sizeof(outside), "%s/outside", d.f.root);
        ASSERT(dbf_git(d.f.root, clone));
        json_init(&arr);
        json_set_array(&arr);
        (void)snprintf(text, sizeof(text), "READY %s %s outside", outside, head);
        di_post_r(&d, &arr, 10, (uint64_t)platform_time_wall_unix(), text, "", false, false);
        (void)snprintf(text, sizeof(text), "READY %s %s subdir", sub, head);
        di_post_r(&d, &arr, 11, (uint64_t)platform_time_wall_unix(), text, "", false, false);
        ASSERT(di_write_posts(&d, &arr));
        json_free(&arr);
        di_run(&d, false, &reply, dump, sizeof(dump));
        char *first = strstr(dump, "REFUSE(invalid_lane)");
        ASSERT(first != NULL);
        ASSERT(strstr(first + 1, "REFUSE(invalid_lane)") != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("intake: rename into core is refused") {
        char lane[900], head[41], text[1200], sha[65], tmp[1000], dst[1000];
        const char *mv[] = {"mv", "a.c", "core/a.c", NULL};
        const char *commit[] = {"commit", "-q", "-m", "rename", NULL};
        const char *bundle[] = {"bundle", "create", tmp, "HEAD", "^origin/main", NULL};
        char dir[1000];
        ASSERT(dbf_lane(&d.f, "rename", NULL, lane, head));
        (void)snprintf(dir, sizeof(dir), "%s/core", lane);
        ASSERT(dbf_mkdirs(dir));
        ASSERT(dbf_git(lane, mv));
        ASSERT(dbf_git(lane, commit));
        (void)snprintf(tmp, sizeof(tmp), "%s/rename.tmp", d.bdir);
        ASSERT(dbf_git(lane, bundle));
        ASSERT(zcl_dlr_file_sha256(tmp, sha));
        (void)snprintf(dst, sizeof(dst), "%s/%s.bundle", d.bdir, sha);
        ASSERT(rename(tmp, dst) == 0);
        (void)snprintf(text, sizeof(text), "READY sha256=%s size=1 rename", sha);
        json_init(&arr);
        json_set_array(&arr);
        di_post_r(&d, &arr, 10, (uint64_t)platform_time_wall_unix(), text, "", false, false);
        ASSERT(di_write_posts(&d, &arr));
        json_free(&arr);
        di_run(&d, false, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "REFUSE(denied_path)") != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("intake: expired signed post is refused") {
        json_init(&arr);
        json_set_array(&arr);
        di_post(&d, &arr, 10, 1000, shaA, false);
        ASSERT(di_write_posts(&d, &arr));
        json_free(&arr);
        di_run(&d, false, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "REFUSE(post_expired_or_invalid_time)") != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("intake: a post with a receipt verifies; a row missing it is bad_signature") {
        json_init(&arr);
        json_set_array(&arr);
        di_post_r(&d, &arr, 8, (uint64_t)platform_time_wall_unix() + 8, "READY sha256=0000000000000000000000000000000000000000000000000000000000000000 size=1 r",
                  "unit=intake gate=ok", false, false);
        ASSERT(di_write_posts(&d, &arr));
        json_free(&arr);
        di_run(&d, false, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "REFUSE(bad_signature)") == NULL);
        ASSERT(strstr(dump, "REFUSE(no_bundle)") != NULL || strstr(dump, "REFUSE(fetch_failed)") != NULL);
        zcl_command_reply_free(&reply);
        json_init(&arr);
        json_set_array(&arr);
        di_post_r(&d, &arr, 9, (uint64_t)platform_time_wall_unix() + 9, "READY sha256=0000000000000000000000000000000000000000000000000000000000000000 size=1 r",
                  "unit=intake gate=ok", true, false);
        ASSERT(di_write_posts(&d, &arr));
        json_free(&arr);
        di_run(&d, false, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "REFUSE(bad_signature)") != NULL);
        zcl_command_reply_free(&reply);
        PASS();
    }

    TEST("intake: without commit (or without confirm) nothing is changed") {
        di_run(&d, false, &reply, dump, sizeof(dump));
        zcl_command_reply_free(&reply);
        di_run(&d, true, &reply, dump, sizeof(dump));
        ASSERT(strstr(dump, "\"commit\":true") != NULL);
        ASSERT(strstr(dump, "\"applied\":false") != NULL);
        ASSERT(strstr(dump, "\"queued\"") == NULL);
        zcl_command_reply_free(&reply);
        ASSERT(di_refs(&d, after, sizeof(after)));
        ASSERT(strcmp(before, after) == 0);
        PASS();
    }

    /* the helper hand-off (the lab's origin/main moves in the last case) */
    failures += di_case_ready_line(&d, shaA);
    failures += di_case_board_error(&d);
    failures += di_case_board_pages(&d);
    failures += di_case_page_cap(&d);
    failures += di_case_over_max(&d);
    failures += di_case_receive_refusal(&d, shaA);
    failures += di_case_answered(&d, shaA);
    failures += di_case_forged_result(&d, shaA);
    failures += di_case_author_line(&d, shaA);
    failures += di_case_answer_cap(&d);
    failures += di_case_cursor(&d);
    failures += di_case_on_main(&d, shaA);

_test_next:;
    (void)test_rm_rf_recursive(d.f.root);
    if (failures == 0)
        printf("test_dev_intake: all passed\n");
    else
        printf("test_dev_intake: %d FAILED\n", failures);
    return failures;
}
