/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_lab_peer: whole runs of build/bin/z23-lab-peer against build/bin/
 * lab-peer-fake (tools/lab_peer_fake.c), a C program the test links twice as
 * fake-z23 and fake-z23dev (--z23=, --z23dev=). It records every argv and
 * prints canned JSON, so nothing reaches a node, the board, the swarm or a real
 * build, and no test starts a shell. Each case runs in its own temp dir.
 *
 * Scenarios: offer posts the exact text and records the row; an over-2048 text
 * refuses; an offer rerun converges (failed post, post already on the board,
 * already recorded); verify ignores a non-allowlisted host, a malformed root, a
 * mismatched offer JSON, an expired post and an already handled post; verify
 * posts ok and refused results with ref; a failed fetch is retried then given
 * up; the board list is followed across pages and a capped listing is reported;
 * a nonzero exit is a failure; unreadable or unwritable state, or an unreadable
 * allowlist, stops the run with a typed code; collect writes the receipts and
 * one qualified.tsv row per offer, ignores a refused or mismatched result, and
 * never calls a submit leaf.
 */

#include "test/test_core.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char LPT_BIN[] = "build/bin/z23-lab-peer";
static const char LPT_FAKE[] = "build/bin/lab-peer-fake";
static const char LPT_FUTURE[] = "4102444800";

struct lpt {
    char d[600];
    char resp[640], calls[640], state[640], lane[640], z23[640], z23dev[640];
    char authors[640], repo[640];
};

static char g_run[64 * 1024];

static void lpt_hex(char *out, char c, int n)
{
    memset(out, c, (size_t)n);
    out[n] = '\0';
}

static bool lpt_wf(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    const size_t n = strlen(text);
    const bool ok = fwrite(text, 1, n, f) == n;
    return fclose(f) == 0 && ok;
}

static bool lpt_file_has(const char *path, const char *needle)
{
    static char body[256 * 1024];
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    const size_t n = fread(body, 1, sizeof(body) - 1, f);
    (void)fclose(f);
    body[n] = '\0';
    return strstr(body, needle) != NULL;
}

static int lpt_count(const char *path, const char *needle)
{
    static char body[256 * 1024];
    int count = 0;
    FILE *f = fopen(path, "rb");
    if (!f)
        return 0;
    const size_t n = fread(body, 1, sizeof(body) - 1, f);
    (void)fclose(f);
    body[n] = '\0';
    for (const char *p = strstr(body, needle); p; p = strstr(p + 1, needle))
        count++;
    return count;
}

static bool lpt_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static bool lpt_run_has(const char *needle)
{
    return strstr(g_run, needle) != NULL;
}

/* The scratch dir, canned-reply dir, state dir, lane dir and the two fake
 * programs: symlinks to the C fake, which finds its files beside its own name. */
static bool lpt_setup(struct lpt *e, const char *tag)
{
    char rel[512], fake[700];
    test_make_tmpdir(rel, sizeof(rel), "lab_peer", tag);
    if (!test_abs_path(rel, e->d, sizeof(e->d)) || !test_abs_path(LPT_FAKE, fake, sizeof(fake)))
        return false;
    (void)snprintf(e->resp, sizeof(e->resp), "%s/resp", e->d);
    (void)snprintf(e->calls, sizeof(e->calls), "%s/calls.log", e->d);
    (void)snprintf(e->state, sizeof(e->state), "%s/state", e->d);
    (void)snprintf(e->lane, sizeof(e->lane), "%s/lane-x", e->d);
    (void)snprintf(e->z23, sizeof(e->z23), "%s/fake-z23", e->d);
    (void)snprintf(e->z23dev, sizeof(e->z23dev), "%s/fake-z23dev", e->d);
    (void)snprintf(e->authors, sizeof(e->authors), "%s/authors.txt", e->d);
    (void)snprintf(e->repo, sizeof(e->repo), "%s/repo", e->d);
    return mkdir(e->resp, 0700) == 0 && mkdir(e->lane, 0700) == 0 &&
           mkdir(e->repo, 0700) == 0 && mkdir(e->state, 0700) == 0 &&
           symlink(fake, e->z23) == 0 && symlink(fake, e->z23dev) == 0;
}

/* Writes resp.<key> (the fake's canned reply). */
static bool lpt_resp(const struct lpt *e, const char *key, const char *json)
{
    char path[800];
    (void)snprintf(path, sizeof(path), "%s/resp.%s", e->resp, key);
    return lpt_wf(path, json);
}

/* Runs the tool: subcommand, the two fake programs, then extras. Returns its
 * exit status; its stdout is in g_run. */
static int lpt_run(const struct lpt *e, const char *sub, const char *const extra[])
{
    char z23[700], z23dev[700];
    const char *argv[32];
    int n = 0;
    bool timed_out = false;
    (void)snprintf(z23, sizeof(z23), "--z23=%s", e->z23);
    (void)snprintf(z23dev, sizeof(z23dev), "--z23dev=%s", e->z23dev);
    argv[n++] = LPT_BIN;
    argv[n++] = sub;
    argv[n++] = z23;
    argv[n++] = z23dev;
    for (int i = 0; extra && extra[i] && n < 30; i++)
        argv[n++] = extra[i];
    argv[n] = NULL;
    return zcl_spawn_capture_observed(argv, g_run, sizeof(g_run), 120000, &timed_out);
}

struct lpt_ids {
    char root[65], sha[65], commit[41], base[41], onion[63];
    char manifest[3000], offer_text[4096];
};

static void lpt_ids(struct lpt_ids *i)
{
    char o[57];
    lpt_hex(i->root, 'c', 64);
    lpt_hex(i->sha, 'd', 64);
    lpt_hex(i->commit, 'e', 40);
    lpt_hex(i->base, '1', 40);
    lpt_hex(o, 'a', 56);
    (void)snprintf(i->onion, sizeof(i->onion), "%s.onion", o);
    (void)snprintf(i->manifest, sizeof(i->manifest),
                   "{\"schema\":\"zcl.dev_land_offer.v1\",\"commit\":\"%s\","
                   "\"base\":\"%s\",\"bundle_sha256\":\"%s\",\"lane\":\"lane-x\"}",
                   i->commit, i->base, i->sha);
    (void)snprintf(i->offer_text, sizeof(i->offer_text),
                   "lab-offer v1 root=%s size=1998 onion=%s offer=%s", i->root,
                   i->onion, i->manifest);
}

/* JSON string body: a quote becomes \". */
static void lpt_esc(char *out, size_t cap, const char *in)
{
    size_t n = 0;
    for (; *in && n + 3 < cap; in++) {
        if (*in == '"')
            out[n++] = '\\';
        out[n++] = *in;
    }
    out[n] = '\0';
}

/* Appends one post object to the list body. */
static void lpt_post(char *body, size_t cap, const char *id, const char *kind,
                     const char *ref, const char *host, const char *text,
                     const char *expires)
{
    char esc[8192];
    const size_t used = strlen(body);
    lpt_esc(esc, sizeof(esc), text);
    (void)snprintf(body + used, cap - used,
                   "%s{\"id\":\"%s\",\"kind\":\"%s\",\"ref\":\"%s\",\"host\":\"%s\","
                   "\"agent\":\"a\",\"room\":\"lab\",\"text\":\"%s\","
                   "\"created_at\":1,\"expires_at\":%s}",
                   used > 0 ? "," : "", id, kind, ref, host, esc, expires);
}

/* One board page: key suffix "" or ".cursorN"; next > 0 marks it truncated. */
static bool lpt_list_page(const struct lpt *e, const char *suffix, const char *posts, int next)
{
    char body[32 * 1024], key[80], page[96] = "";
    if (next > 0)
        (void)snprintf(page, sizeof(page),
                       ",\"_page\":{\"truncated\":true,\"next_cursor\":%d}", next);
    (void)snprintf(body, sizeof(body), "{\"ok\":true,\"data\":{\"posts\":[%s]%s}}", posts, page);
    (void)snprintf(key, sizeof(key), "fleet.board.list%s", suffix);
    return lpt_resp(e, key, body);
}

static bool lpt_list(const struct lpt *e, const char *posts)
{
    return lpt_list_page(e, "", posts, 0);
}

/* ── offer ─────────────────────────────────────────────────────────────── */

static bool lpt_send_resps(const struct lpt *e, const struct lpt_ids *i, const char *pad)
{
    char body[8192], off[8192], path[800], id[65];
    (void)snprintf(off, sizeof(off),
                   "{\"schema\":\"zcl.dev_land_offer.v1\",\"commit\":\"%s\","
                   "\"base\":\"%s\",\"bundle_sha256\":\"%s\",\"lane\":\"lane-x\"%s}\n",
                   i->commit, i->base, i->sha, pad);
    (void)snprintf(path, sizeof(path), "%s/offer.json", e->resp);
    (void)snprintf(body, sizeof(body), "{\"ok\":true,\"data\":{\"bundle_sha256\":\"%s\"}}",
                   i->sha);
    bool ok = lpt_wf(path, off) && lpt_resp(e, "dev.land.send", body);
    (void)snprintf(body, sizeof(body),
                   "{\"ok\":true,\"data\":{\"root\":\"%s\",\"sha256\":\"%s\","
                   "\"size\":1998,\"onion\":\"%s\"}}",
                   i->root, i->sha, i->onion);
    ok = ok && lpt_resp(e, "fleet.bundle.offer", body);
    lpt_hex(id, '7', 64);
    (void)snprintf(body, sizeof(body), "{\"ok\":true,\"data\":{\"id\":\"%s\"}}", id);
    return ok && lpt_resp(e, "fleet.board.post.offer", body) && lpt_list(e, "");
}

static int lpt_offer_run(const struct lpt *e, const struct lpt_ids *i)
{
    char lane[700], commit[100], state[700];
    (void)snprintf(lane, sizeof(lane), "--lane=%s", e->lane);
    (void)snprintf(commit, sizeof(commit), "--commit=%s", i->commit);
    (void)snprintf(state, sizeof(state), "--state=%s", e->state);
    const char *const extra[] = {lane, commit, state, NULL};
    return lpt_run(e, "offer", extra);
}

static int case_usage(void)
{
    int failures = 0;
    bool timed_out = false;
    const char *const none[] = {LPT_BIN, NULL};
    const char *const bad[] = {LPT_BIN, "verify", "--state=x", NULL};
    TEST_CASE("lab_peer: usage errors exit 2") {
        ASSERT_EQ(zcl_spawn_capture_observed(none, g_run, sizeof(g_run), 20000, &timed_out), 2);
        ASSERT_EQ(zcl_spawn_capture_observed(bad, g_run, sizeof(g_run), 20000, &timed_out), 2);
    } TEST_END
    return failures;
}

static int case_offer_posts_and_records(void)
{
    int failures = 0;
    struct lpt e;
    struct lpt_ids i;
    char needle[4300], row[700], tsv[800], id[65];
    TEST_CASE("lab_peer: offer posts the exact text and records the row") {
        lpt_ids(&i);
        lpt_hex(id, '7', 64);
        ASSERT(lpt_setup(&e, "offer") && lpt_send_resps(&e, &i, ""));
        const int rc = lpt_offer_run(&e, &i);
        (void)snprintf(needle, sizeof(needle), "\t%s\n", i.offer_text);
        ASSERT_EQ(rc, 0);
        ASSERT(lpt_run_has("\"ok\":true"));
        ASSERT(lpt_file_has(e.calls, needle));
        ASSERT_EQ(lpt_count(e.calls, "\toffer\n\tlab-offer v1 "), 1);
        ASSERT(lpt_file_has(e.calls, "\t--room=lab\n"));
        ASSERT(lpt_file_has(e.calls, "\t--precheck=skip\n"));
        ASSERT(lpt_file_has(e.calls, "\t--lane=lane-x\n"));
        (void)snprintf(tsv, sizeof(tsv), "%s/state/offers.tsv", e.d);
        (void)snprintf(row, sizeof(row), "%s\tlane-x\t%s\t%s\t%s\t%s\t", id, i.commit,
                       i.base, i.sha, i.root);
        ASSERT_EQ(lpt_count(tsv, row), 1);
        ASSERT(lpt_file_has(tsv, ".bundle\t"));
        ASSERT(lpt_file_has(tsv, ".bundle.offer.json\n"));
    } TEST_END
    return failures;
}

static int case_offer_too_long(void)
{
    int failures = 0;
    struct lpt e;
    struct lpt_ids i;
    char pad[2200], tsv[800];
    TEST_CASE("lab_peer: an over-2048 offer text refuses and posts nothing") {
        lpt_ids(&i);
        memcpy(pad, ",\"pad\":\"", 8);
        memset(pad + 8, 'x', 1700);
        memcpy(pad + 1708, "\"", 2);
        ASSERT(lpt_setup(&e, "offer_long") && lpt_send_resps(&e, &i, pad));
        const int rc = lpt_offer_run(&e, &i);
        (void)snprintf(tsv, sizeof(tsv), "%s/state/offers.tsv", e.d);
        ASSERT_EQ(rc, 1);
        ASSERT(lpt_run_has("OFFER_TEXT_TOO_LONG"));
        ASSERT(lpt_run_has("\"ok\":false"));
        ASSERT_EQ(lpt_count(e.calls, "\tpost\n"), 0);
        ASSERT(!lpt_exists(tsv));
    } TEST_END
    return failures;
}

static int case_offer_rerun_after_failed_post(void)
{
    int failures = 0;
    struct lpt e;
    struct lpt_ids i;
    char tsv[800], id[65];
    TEST_CASE("lab_peer: an offer rerun after a failed post converges") {
        lpt_ids(&i);
        lpt_hex(id, '7', 64);
        ASSERT(lpt_setup(&e, "offer_rerun") && lpt_send_resps(&e, &i, ""));
        ASSERT(lpt_resp(&e, "fleet.board.post.offer.1",
                        "{\"ok\":false,\"error\":{\"code\":\"POST_DOWN\"}}"));
        ASSERT(lpt_resp(&e, "fleet.board.post.offer.1.rc", "1"));
        const int first = lpt_offer_run(&e, &i);
        const bool first_failed = lpt_run_has("OFFER_POST_FAILED");
        const int second = lpt_offer_run(&e, &i);
        (void)snprintf(tsv, sizeof(tsv), "%s/state/offers.tsv", e.d);
        ASSERT_EQ(first, 1);
        ASSERT(first_failed);
        ASSERT_EQ(second, 0);
        ASSERT_EQ(lpt_count(e.calls, "\tsend\n"), 1);
        ASSERT_EQ(lpt_count(e.calls, "\toffer\n\tlab-offer v1 "), 2);
        ASSERT_EQ(lpt_count(tsv, id), 1);
    } TEST_END
    return failures;
}

static int case_offer_reuses_posted_text(void)
{
    int failures = 0;
    struct lpt e;
    struct lpt_ids i;
    char tsv[800], id[65], row[200], posts[8192] = "";
    TEST_CASE("lab_peer: an offer already on the board is recorded, not posted twice") {
        lpt_ids(&i);
        lpt_hex(id, '8', 64);
        ASSERT(lpt_setup(&e, "offer_reuse") && lpt_send_resps(&e, &i, ""));
        lpt_post(posts, sizeof(posts), id, "offer",
                 "0000000000000000000000000000000000000000000000000000000000000000",
                 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                 i.offer_text, LPT_FUTURE);
        ASSERT(lpt_list(&e, posts));
        const int rc = lpt_offer_run(&e, &i);
        (void)snprintf(tsv, sizeof(tsv), "%s/state/offers.tsv", e.d);
        (void)snprintf(row, sizeof(row), "%s\tlane-x\t", id);
        ASSERT_EQ(rc, 0);
        ASSERT(lpt_run_has("POST_REUSED"));
        ASSERT_EQ(lpt_count(e.calls, "\toffer\n\tlab-offer v1 "), 0);
        ASSERT_EQ(lpt_count(tsv, row), 1);
    } TEST_END
    return failures;
}

static int case_offer_rerun_when_recorded(void)
{
    int failures = 0;
    struct lpt e;
    struct lpt_ids i;
    TEST_CASE("lab_peer: an offer rerun after a recorded offer does nothing") {
        lpt_ids(&i);
        ASSERT(lpt_setup(&e, "offer_done") && lpt_send_resps(&e, &i, ""));
        ASSERT_EQ(lpt_offer_run(&e, &i), 0);
        ASSERT_EQ(lpt_offer_run(&e, &i), 0);
        ASSERT(lpt_run_has("ALREADY_OFFERED"));
        ASSERT_EQ(lpt_count(e.calls, "\tsend\n"), 1);
        ASSERT_EQ(lpt_count(e.calls, "\toffer\n\tlab-offer v1 "), 1);
    } TEST_END
    return failures;
}

/* ── verify ────────────────────────────────────────────────────────────── */

static bool lpt_verify_resps(const struct lpt *e)
{
    char path[800];
    (void)snprintf(path, sizeof(path), "%s/receipt.json", e->resp);
    return lpt_wf(path, "{\n \"schema\":\"zcl.dev_land_receipt.v1\",\n \"signer\":\"s\"\n}\n") &&
           lpt_resp(e, "fleet.bundle.fetch", "{\"ok\":true,\"data\":{\"written\":true}}") &&
           lpt_resp(e, "dev.land.reverify_offer", "{\"ok\":true,\"data\":{\"verdict\":\"ok\"}}") &&
           lpt_resp(e, "fleet.board.post.result",
                    "{\"ok\":true,\"data\":{\"id\":\"9999999999999999999999999999999999999999999999999999999999999999\"}}");
}

static int lpt_verify_run(const struct lpt *e)
{
    char state[700], repo[700], authors[700];
    (void)snprintf(state, sizeof(state), "--state=%s", e->state);
    (void)snprintf(repo, sizeof(repo), "--repo=%s", e->repo);
    (void)snprintf(authors, sizeof(authors), "--authors=%s", e->authors);
    const char *const extra[] = {state, repo, authors, "--max=10", NULL};
    return lpt_run(e, "verify", extra);
}

static bool lpt_authors(const struct lpt *e)
{
    char text[400], ha[65];
    lpt_hex(ha, 'a', 64);
    (void)snprintf(text, sizeof(text), "# keys\n%s\nnot-a-key\nabcd\n", ha);
    return lpt_wf(e->authors, text);
}

/* The offer text for the verify cases: root and sha are overridable. */
static void lpt_offer_post(char *body, size_t cap, char idc, const char *host,
                           const char *root, const char *sha, const char *expires)
{
    struct lpt_ids i;
    char id[65], text[4096];
    lpt_ids(&i);
    lpt_hex(id, idc, 64);
    (void)snprintf(text, sizeof(text),
                   "lab-offer v1 root=%s size=1998 onion=%s offer="
                   "{\"schema\":\"zcl.dev_land_offer.v1\",\"commit\":\"%s\","
                   "\"base\":\"%s\",\"bundle_sha256\":\"%s\",\"lane\":\"lane-x\"}",
                   root ? root : i.root, i.onion, i.commit, i.base,
                   sha ? sha : i.sha);
    lpt_post(body, cap, id, "offer", "0000000000000000000000000000000000000000000000000000000000000000",
             host, text, expires);
}

/* A verify env holding one good offer post (id of '1'). */
static bool lpt_verify_env(struct lpt *e, const char *tag)
{
    char posts[8 * 1024] = "", ha[65];
    lpt_hex(ha, 'a', 64);
    lpt_offer_post(posts, sizeof(posts), '1', ha, NULL, NULL, LPT_FUTURE);
    return lpt_setup(e, tag) && lpt_authors(e) && lpt_verify_resps(e) && lpt_list(e, posts);
}

static int case_verify_filters(void)
{
    int failures = 0;
    struct lpt e;
    char posts[16 * 1024] = "", ha[65], hb[65], short_root[64], short_sha[64], id6[65];
    char handled[800], seed[200];
    TEST_CASE("lab_peer: verify skips every post it must not process") {
        lpt_hex(ha, 'a', 64);
        lpt_hex(hb, 'b', 64);
        lpt_hex(short_root, 'c', 63);
        lpt_hex(short_sha, 'd', 63);
        lpt_hex(id6, '6', 64);
        ASSERT(lpt_setup(&e, "verify_filters") && lpt_authors(&e) && lpt_verify_resps(&e));
        lpt_offer_post(posts, sizeof(posts), '1', ha, NULL, NULL, LPT_FUTURE);
        lpt_offer_post(posts, sizeof(posts), '2', hb, NULL, NULL, LPT_FUTURE);
        lpt_offer_post(posts, sizeof(posts), '3', ha, short_root, NULL, LPT_FUTURE);
        lpt_offer_post(posts, sizeof(posts), '4', ha, NULL, short_sha, LPT_FUTURE);
        lpt_offer_post(posts, sizeof(posts), '5', ha, NULL, NULL, "1");
        lpt_offer_post(posts, sizeof(posts), '6', ha, NULL, NULL, LPT_FUTURE);
        lpt_post(posts, sizeof(posts),
                 "7777777777777777777777777777777777777777777777777777777777777777", "note",
                 "0000000000000000000000000000000000000000000000000000000000000000", ha,
                 "lab-offer v1 not an offer kind", LPT_FUTURE);
        (void)snprintf(handled, sizeof(handled), "%s/handled.tsv", e.state);
        (void)snprintf(seed, sizeof(seed), "%s\tok\t\t3\n", id6);
        ASSERT(lpt_list(&e, posts) && lpt_wf(handled, seed));
        const int rc = lpt_verify_run(&e);
        ASSERT_EQ(rc, 0);
        ASSERT(lpt_run_has("zcl.lab_peer.v1"));
        ASSERT_EQ(lpt_count(e.calls, "\tfetch\n"), 1);
        ASSERT_EQ(lpt_count(e.calls, "\tresult\n"), 1);
        ASSERT(lpt_run_has("HOST_NOT_ALLOWED"));
        ASSERT(lpt_run_has("OFFER_MALFORMED"));
        ASSERT(strstr(strstr(g_run, "OFFER_MALFORMED") + 1, "OFFER_MALFORMED") != NULL);
        ASSERT(lpt_run_has("EXPIRED"));
        ASSERT(lpt_run_has("ALREADY_HANDLED"));
        ASSERT(lpt_file_has(handled, "\tok\t\t"));
    } TEST_END
    return failures;
}

static int case_verify_posts_ok(void)
{
    int failures = 0;
    struct lpt e;
    char id[65], needle[800];
    TEST_CASE("lab_peer: verify posts the ok result with ref and never twice") {
        lpt_hex(id, '1', 64);
        ASSERT(lpt_verify_env(&e, "verify_ok"));
        ASSERT_EQ(lpt_verify_run(&e), 0);
        (void)snprintf(needle, sizeof(needle),
                       "\tlab-receipt v1 offer=%s verdict=ok receipt="
                       "{\"schema\":\"zcl.dev_land_receipt.v1\",\"signer\":\"s\"}\n", id);
        ASSERT(lpt_file_has(e.calls, needle));
        (void)snprintf(needle, sizeof(needle), "\t--ref=%s\n", id);
        ASSERT(lpt_file_has(e.calls, needle));
        ASSERT(lpt_file_has(e.calls, "\t--room=lab\n"));
        ASSERT(lpt_file_has(e.calls, "\t--repo="));
        ASSERT(lpt_file_has(e.calls, "\t--receipt_out="));
        ASSERT(lpt_file_has(e.calls, "\t--bundle="));
        ASSERT(lpt_file_has(e.calls, "\t--offer="));
        ASSERT_EQ(lpt_verify_run(&e), 0);
        ASSERT_EQ(lpt_count(e.calls, "\tfetch\n"), 1);
        ASSERT_EQ(lpt_count(e.calls, "\tresult\n"), 1);
    } TEST_END
    return failures;
}

static int case_verify_posts_refused(void)
{
    int failures = 0;
    struct lpt e;
    char id[65], needle[800], handled[800];
    TEST_CASE("lab_peer: verify posts a refused result with the typed code") {
        lpt_hex(id, '1', 64);
        ASSERT(lpt_verify_env(&e, "verify_refused"));
        ASSERT(lpt_resp(&e, "dev.land.reverify_offer",
                        "{\"ok\":false,\"error\":{\"code\":\"REVERIFY_CX_FAILED\",\"message\":\"m\"}}"));
        ASSERT(lpt_resp(&e, "dev.land.reverify_offer.rc", "1"));
        ASSERT_EQ(lpt_verify_run(&e), 0);
        (void)snprintf(needle, sizeof(needle),
                       "\tlab-receipt v1 offer=%s verdict=refused code=REVERIFY_CX_FAILED\n", id);
        ASSERT(lpt_file_has(e.calls, needle));
        (void)snprintf(handled, sizeof(handled), "%s/handled.tsv", e.state);
        (void)snprintf(needle, sizeof(needle), "%s\trefused\tREVERIFY_CX_FAILED\t", id);
        ASSERT(lpt_file_has(handled, needle));
    } TEST_END
    return failures;
}

static int case_verify_fetch_retry(void)
{
    int failures = 0;
    struct lpt e;
    char handled[800];
    TEST_CASE("lab_peer: a failed fetch is retried three times then given up") {
        ASSERT(lpt_verify_env(&e, "verify_retry"));
        ASSERT(lpt_resp(&e, "fleet.bundle.fetch", "{\"ok\":false,\"error\":{\"code\":\"FETCH_FAILED\"}}"));
        ASSERT(lpt_resp(&e, "fleet.bundle.fetch.rc", "1"));
        (void)snprintf(handled, sizeof(handled), "%s/handled.tsv", e.state);
        ASSERT_EQ(lpt_verify_run(&e), 0);
        ASSERT_EQ(lpt_count(handled, "\tretry\tFETCH_FAILED\t"), 1);
        ASSERT_EQ(lpt_verify_run(&e), 0);
        ASSERT_EQ(lpt_verify_run(&e), 0);
        ASSERT_EQ(lpt_count(e.calls, "\tfetch\n"), 3);
        ASSERT_EQ(lpt_count(handled, "\tretry\t"), 2);
        ASSERT_EQ(lpt_count(handled, "\tfailed\tFETCH_FAILED\t"), 1);
        ASSERT_EQ(lpt_verify_run(&e), 0);
        ASSERT_EQ(lpt_count(e.calls, "\tfetch\n"), 3);
        ASSERT_EQ(lpt_count(e.calls, "\tresult\n"), 0);
        ASSERT_EQ(lpt_count(e.calls, "\treverify_offer\n"), 0);
    } TEST_END
    return failures;
}

static int case_verify_follows_pages(void)
{
    int failures = 0;
    struct lpt e;
    char posts[8 * 1024] = "", ha[65];
    TEST_CASE("lab_peer: verify follows the board list cursor to the next page") {
        lpt_hex(ha, 'a', 64);
        ASSERT(lpt_verify_env(&e, "verify_pages"));
        lpt_offer_post(posts, sizeof(posts), '2', ha, NULL, NULL, LPT_FUTURE);
        ASSERT(lpt_list_page(&e, "", "", 1));
        ASSERT(lpt_list_page(&e, ".cursor1", posts, 0));
        ASSERT_EQ(lpt_verify_run(&e), 0);
        ASSERT(lpt_file_has(e.calls, "\t--cursor=1\n"));
        ASSERT_EQ(lpt_count(e.calls, "\tfetch\n"), 1);
        ASSERT(lpt_run_has("\"truncated\":false"));
    } TEST_END
    return failures;
}

static int case_verify_reports_truncation(void)
{
    int failures = 0;
    struct lpt e;
    TEST_CASE("lab_peer: a board listing that hits the page cap reports truncation") {
        ASSERT(lpt_verify_env(&e, "verify_trunc"));
        ASSERT(lpt_list_page(&e, "", "", 1));
        ASSERT(lpt_list_page(&e, ".cursor1", "", 2));
        ASSERT(lpt_list_page(&e, ".cursor2", "", 3));
        ASSERT(lpt_list_page(&e, ".cursor3", "", 4));
        ASSERT(lpt_list_page(&e, ".cursor4", "", 5));
        ASSERT_EQ(lpt_verify_run(&e), 0);
        ASSERT_EQ(lpt_count(e.calls, "\tlist\n"), 5);
        ASSERT(lpt_run_has("\"truncated\":true"));
    } TEST_END
    return failures;
}

static int case_verify_nonzero_exit(void)
{
    int failures = 0;
    struct lpt e;
    char handled[800];
    TEST_CASE("lab_peer: a nonzero child exit is a failure even if the reply says ok") {
        ASSERT(lpt_verify_env(&e, "verify_rc"));
        ASSERT(lpt_resp(&e, "fleet.board.post.result.rc", "3"));
        (void)snprintf(handled, sizeof(handled), "%s/handled.tsv", e.state);
        ASSERT_EQ(lpt_verify_run(&e), 0);
        ASSERT_EQ(lpt_count(handled, "\tretry\tRESULT_POST_FAILED\t"), 1);
        ASSERT_EQ(lpt_count(handled, "\tok\t"), 0);
        ASSERT_EQ(lpt_count(e.calls, "\tresult\n"), 0);
    } TEST_END
    return failures;
}

static int case_verify_handled_unreadable(void)
{
    int failures = 0;
    struct lpt e;
    char handled[800];
    TEST_CASE("lab_peer: an unreadable handled.tsv stops verify with a typed code") {
        ASSERT(lpt_verify_env(&e, "verify_unreadable"));
        (void)snprintf(handled, sizeof(handled), "%s/handled.tsv", e.state);
        ASSERT_EQ(mkdir(handled, 0700), 0);
        ASSERT_EQ(lpt_verify_run(&e), 1);
        ASSERT(lpt_run_has("HANDLED_UNREADABLE"));
        ASSERT_EQ(lpt_count(e.calls, "\tfetch\n"), 0);
        ASSERT_EQ(lpt_count(e.calls, "\tresult\n"), 0);
    } TEST_END
    return failures;
}

static int case_verify_handled_unwritable(void)
{
    int failures = 0;
    struct lpt e;
    TEST_CASE("lab_peer: an unwritable handled.tsv stops verify with a typed code") {
        ASSERT(lpt_verify_env(&e, "verify_unwritable"));
        ASSERT_EQ(lpt_verify_run(&e), 0); /* creates the lock; the ledger is written */
        char handled[800];
        (void)snprintf(handled, sizeof(handled), "%s/handled.tsv", e.state);
        ASSERT_EQ(unlink(handled), 0);
        ASSERT_EQ(chmod(e.state, 0500), 0);
        const int rc = lpt_verify_run(&e);
        (void)chmod(e.state, 0700);
        ASSERT(geteuid() == 0 || rc == 1);
        ASSERT(geteuid() == 0 || lpt_run_has("HANDLED_WRITE_FAILED"));
    } TEST_END
    return failures;
}

static int case_verify_authors_unreadable(void)
{
    int failures = 0;
    struct lpt e;
    TEST_CASE("lab_peer: a missing authors file stops verify with a typed code") {
        ASSERT(lpt_verify_env(&e, "verify_authors"));
        ASSERT_EQ(unlink(e.authors), 0);
        ASSERT_EQ(lpt_verify_run(&e), 1);
        ASSERT(lpt_run_has("AUTHORS_UNREADABLE"));
        ASSERT_EQ(lpt_count(e.calls, "\tfetch\n"), 0);
    } TEST_END
    return failures;
}

/* ── collect ───────────────────────────────────────────────────────────── */

static int lpt_collect_run(const struct lpt *e, const char *require)
{
    char state[700], req[32];
    (void)snprintf(state, sizeof(state), "--state=%s", e->state);
    (void)snprintf(req, sizeof(req), "--require=%s", require);
    const char *const extra[] = {state, req, NULL};
    return lpt_run(e, "collect", extra);
}

static void lpt_receipt_post(char *posts, size_t cap, char host_c, const char *id,
                             const char *offer, const char *verdict)
{
    char host[65], text[600];
    lpt_hex(host, host_c, 64);
    if (strcmp(verdict, "ok") == 0)
        (void)snprintf(text, sizeof(text),
                       "lab-receipt v1 offer=%s verdict=ok receipt={\"signer\":\"%c\"}",
                       offer, host_c);
    else
        (void)snprintf(text, sizeof(text),
                       "lab-receipt v1 offer=%s verdict=refused code=X", offer);
    lpt_post(posts, cap, id, "result", offer, host, text, LPT_FUTURE);
}

/* The collect env: one offers.tsv row (post of '1') and the result posts. */
static bool lpt_collect_env(struct lpt *e, const struct lpt_ids *i, const char *tag,
                            int rows)
{
    char posts[16 * 1024] = "", offer[65], other[65], pid[65], row[1200], path[800];
    char host[65], text[400], body[2048], ha[65], hb[65];
    lpt_hex(offer, '1', 64);
    lpt_hex(other, '2', 64);
    lpt_hex(ha, 'a', 64);
    lpt_hex(hb, 'b', 64);
    if (!lpt_setup(e, tag))
        return false;
    (void)snprintf(path, sizeof(path), "%s/offers.tsv", e->state);
    (void)snprintf(row, sizeof(row), "%s\tlane-x\t%s\t%s\t%s\t%s\t%s/b.bundle\t%s/o.json\n",
                   offer, i->commit, i->base, i->sha, i->root, e->d, e->d);
    lpt_hex(pid, '3', 64);
    lpt_receipt_post(posts, sizeof(posts), 'a', pid, offer, "ok");
    lpt_hex(pid, '4', 64);
    lpt_receipt_post(posts, sizeof(posts), 'b', pid, offer, "ok");
    lpt_hex(pid, '5', 64);
    lpt_receipt_post(posts, sizeof(posts), 'c', pid, offer, "refused");
    lpt_hex(pid, '6', 64);
    lpt_receipt_post(posts, sizeof(posts), 'a', pid, other, "ok");
    lpt_hex(pid, '8', 64);
    lpt_hex(host, 'd', 64);
    (void)snprintf(text, sizeof(text),
                   "lab-receipt v1 offer=%s verdict=ok receipt={\"signer\":\"d\"}", other);
    lpt_post(posts, sizeof(posts), pid, "result", offer, host, text, LPT_FUTURE);
    (void)snprintf(body, sizeof(body),
                   "{\"ok\":true,\"data\":{\"commit\":\"%s\",\"base\":\"%s\",\"required\":2,"
                   "\"qualified\":2,\"signers\":[\"%s\",\"%s\"],\"duplicates\":0,"
                   "\"verdict\":\"ready\",\"rejected\":[]}}",
                   i->commit, i->base, ha, hb);
    if (rows > 1) {
        char once[1200];
        (void)snprintf(once, sizeof(once), "%s", row);
        (void)snprintf(row + strlen(once), sizeof(row) - strlen(once), "%s", once);
    }
    if (!lpt_wf(path, row))
        return false;
    return lpt_list(e, posts) && lpt_resp(e, "dev.land.qualify_offer", body);
}

static int case_collect(void)
{
    int failures = 0;
    struct lpt_ids i;
    struct lpt e;
    char offer[65], row[1200], qual[800], rec[800], ha[65], hb[65];
    TEST_CASE("lab_peer: collect writes receipts and one qualified row, never submits") {
        lpt_ids(&i);
        lpt_hex(offer, '1', 64);
        lpt_hex(ha, 'a', 64);
        lpt_hex(hb, 'b', 64);
        ASSERT(lpt_collect_env(&e, &i, "collect", 1));
        ASSERT_EQ(lpt_collect_run(&e, "2"), 0);
        ASSERT(lpt_run_has("zcl.lab_peer.v1"));
        (void)snprintf(rec, sizeof(rec), "%s/receipts/%s-aaaaaaaaaaaa.json", e.state, offer);
        ASSERT(lpt_file_has(rec, "{\"signer\":\"a\"}"));
        (void)snprintf(rec, sizeof(rec), "%s/receipts/%s-bbbbbbbbbbbb.json", e.state, offer);
        ASSERT(lpt_file_has(rec, "{\"signer\":\"b\"}"));
        (void)snprintf(rec, sizeof(rec), "%s/receipts/%s-cccccccccccc.json", e.state, offer);
        ASSERT(!lpt_exists(rec));
        (void)snprintf(rec, sizeof(rec), "%s/receipts/%s-dddddddddddd.json", e.state, offer);
        ASSERT(!lpt_exists(rec));
        ASSERT_EQ(lpt_count(e.calls, "\tqualify_offer\n"), 1);
        ASSERT(lpt_file_has(e.calls, "\t--require=2\n"));
        ASSERT(lpt_file_has(e.calls, "-aaaaaaaaaaaa.json,"));
        ASSERT(lpt_file_has(e.calls, "-bbbbbbbbbbbb.json\n"));
        (void)snprintf(qual, sizeof(qual), "%s/qualified.tsv", e.state);
        (void)snprintf(row, sizeof(row), "%s\tlane-x\t%s\tready\t2\t%s,%s\t\n", offer,
                       i.commit, ha, hb);
        ASSERT(lpt_file_has(qual, row));
        ASSERT_EQ(lpt_count(e.calls, "submit"), 0);
        ASSERT_EQ(lpt_count(e.calls, "\tsend\n"), 0);
        ASSERT_EQ(lpt_count(e.calls, "\treceive\n"), 0);
        ASSERT_EQ(lpt_count(e.calls, "\tpost\n"), 0);
    } TEST_END
    return failures;
}

static int case_collect_upserts(void)
{
    int failures = 0;
    struct lpt_ids i;
    struct lpt e;
    char offer[65], other[65], row[1200], qual[800], seed[400], body[1024];
    TEST_CASE("lab_peer: collect keeps one qualified row per offer across runs") {
        lpt_ids(&i);
        lpt_hex(offer, '1', 64);
        lpt_hex(other, '9', 64);
        ASSERT(lpt_collect_env(&e, &i, "collect_upsert", 1));
        (void)snprintf(qual, sizeof(qual), "%s/qualified.tsv", e.state);
        (void)snprintf(seed, sizeof(seed), "%s\told-lane\t%s\tready\t1\t\t\n", other, i.commit);
        ASSERT(lpt_wf(qual, seed));
        ASSERT_EQ(lpt_collect_run(&e, "2"), 0);
        ASSERT_EQ(lpt_collect_run(&e, "2"), 0);
        (void)snprintf(row, sizeof(row), "%s\t", offer);
        ASSERT_EQ(lpt_count(qual, row), 1);
        ASSERT(lpt_file_has(qual, seed));
        /* a short quorum: the refusal's evidence still carries the count */
        (void)snprintf(body, sizeof(body),
                       "{\"ok\":false,\"error\":{\"code\":\"QUALIFY_SHORT\","
                       "\"evidence\":\"qualified=1 required=2 duplicates=0\"},"
                       "\"data\":{\"rejected\":[{\"receipt\":\"/x\",\"code\":\"RECEIPT_SIGNATURE_INVALID\"}]}}");
        ASSERT(lpt_resp(&e, "dev.land.qualify_offer", body));
        ASSERT(lpt_resp(&e, "dev.land.qualify_offer.rc", "1"));
        ASSERT_EQ(lpt_collect_run(&e, "2"), 0);
        (void)snprintf(row, sizeof(row), "%s\tlane-x\t%s\tQUALIFY_SHORT\t1\t\tRECEIPT_SIGNATURE_INVALID\n",
                       offer, i.commit);
        ASSERT(lpt_file_has(qual, row));
        (void)snprintf(row, sizeof(row), "%s\t", offer);
        ASSERT_EQ(lpt_count(qual, row), 1);
        ASSERT(!lpt_file_has(qual, "\tready\t2\t"));
        ASSERT(lpt_file_has(qual, seed));
    } TEST_END
    return failures;
}

static int case_collect_duplicate_offer_rows(void)
{
    int failures = 0;
    struct lpt_ids i;
    struct lpt e;
    char offer[65], qual[800], row[100];
    TEST_CASE("lab_peer: a repeated offers.tsv row is one offer") {
        lpt_ids(&i);
        lpt_hex(offer, '1', 64);
        ASSERT(lpt_collect_env(&e, &i, "collect_dup", 2));
        ASSERT_EQ(lpt_collect_run(&e, "2"), 0);
        (void)snprintf(qual, sizeof(qual), "%s/qualified.tsv", e.state);
        (void)snprintf(row, sizeof(row), "%s\t", offer);
        ASSERT_EQ(lpt_count(qual, row), 1);
        ASSERT_EQ(lpt_count(e.calls, "\tqualify_offer\n"), 1);
    } TEST_END
    return failures;
}

static int case_collect_offers_unreadable(void)
{
    int failures = 0;
    struct lpt_ids i;
    struct lpt e;
    char path[800];
    TEST_CASE("lab_peer: an unreadable offers.tsv stops collect with a typed code") {
        lpt_ids(&i);
        ASSERT(lpt_collect_env(&e, &i, "collect_unreadable", 1));
        (void)snprintf(path, sizeof(path), "%s/offers.tsv", e.state);
        ASSERT_EQ(unlink(path), 0);
        ASSERT_EQ(mkdir(path, 0700), 0);
        ASSERT_EQ(lpt_collect_run(&e, "2"), 1);
        ASSERT(lpt_run_has("OFFERS_UNREADABLE"));
        ASSERT_EQ(lpt_count(e.calls, "\tqualify_offer\n"), 0);
    } TEST_END
    return failures;
}

int test_lab_peer(void)
{
    int failures = 0;
    struct stat st;
    if (stat(LPT_BIN, &st) != 0 || stat(LPT_FAKE, &st) != 0) {
        printf("lab_peer: FAIL (%s and %s are required test prerequisites)\n", LPT_BIN,
               LPT_FAKE);
        return 1;
    }
    failures += case_usage();
    failures += case_offer_posts_and_records();
    failures += case_offer_too_long();
    failures += case_offer_rerun_after_failed_post();
    failures += case_offer_reuses_posted_text();
    failures += case_offer_rerun_when_recorded();
    failures += case_verify_filters();
    failures += case_verify_posts_ok();
    failures += case_verify_posts_refused();
    failures += case_verify_fetch_retry();
    failures += case_verify_follows_pages();
    failures += case_verify_reports_truncation();
    failures += case_verify_nonzero_exit();
    failures += case_verify_handled_unreadable();
    failures += case_verify_handled_unwritable();
    failures += case_verify_authors_unreadable();
    failures += case_collect();
    failures += case_collect_upserts();
    failures += case_collect_duplicate_offer_rows();
    failures += case_collect_offers_unreadable();
    return failures;
}
