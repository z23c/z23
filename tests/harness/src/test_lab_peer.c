/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_lab_peer: whole runs of build/bin/z23-lab-peer against two generated
 * sh fakes (--z23=, --z23dev=) that record every argv and print canned JSON,
 * so nothing reaches a node, the board, the swarm or a real build. Each case
 * runs in its own temp dir.
 *
 * Scenarios: offer posts the exact text and records the offers.tsv row; an
 * over-2048 text refuses with no post; verify ignores a non-allowlisted host, a
 * malformed root, a mismatched offer JSON, an expired post and an already
 * handled post (exactly one fetch for the one good post); verify posts an ok
 * and a refused result with ref; a failed fetch is retried then given up
 * (three attempts); collect writes the receipts and qualified.tsv, ignores a
 * refused or mismatched result, and never calls a submit leaf.
 */

#include "test/test_core.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define LPT_CHECK(name, expr)                                                \
    do {                                                                     \
        const bool lpt_ok_ = (expr);                                         \
        if (!lpt_ok_) failures++;                                            \
        printf("lab_peer: %s %s\n", lpt_ok_ ? "OK  " : "FAIL", (name));      \
    } while (0)

static const char LPT_BIN[] = "build/bin/z23-lab-peer";

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

/* The fake program: logs its argv one argument per line (tab-indented), looks
 * up resp.<a>.<b>.<c> (plus .<kind> for a board post) and prints it. A reply
 * containing "ok":true also performs the leaf's one side effect. */
static bool lpt_fake(const struct lpt *e, const char *path, const char *tag)
{
    char text[4096];
    (void)snprintf(
        text, sizeof(text),
        "#!/bin/sh\n"
        "D='%s'\n"
        "echo \"CALL %s\" >> \"%s\"\n"
        "for a in \"$@\"; do printf '\\t%%s\\n' \"$a\" >> \"%s\"; done\n"
        "k=\"$1.$2.$3\"\n"
        "if [ \"$k\" = fleet.board.post ]; then k=\"$k.$4\"; fi\n"
        "r=\"$D/resp.$k\"\n"
        "if [ ! -f \"$r\" ]; then echo '{\"ok\":false,\"error\":{\"code\":\"FAKE_NO_RESP\"}}'; exit 1; fi\n"
        "cat \"$r\"\n"
        "if grep -q '\"ok\":true' \"$r\"; then\n"
        "  for a in \"$@\"; do case \"$a\" in\n"
        "    --bundle_out=*) b=\"${a#--bundle_out=}\"; echo bundle > \"$b\"; cp \"$D/offer.json\" \"$b.offer.json\";;\n"
        "    --out=*) echo bundle > \"${a#--out=}\";;\n"
        "    --receipt_out=*) cp \"$D/receipt.json\" \"${a#--receipt_out=}\";;\n"
        "  esac; done\n"
        "fi\n"
        "exit 0\n",
        e->resp, tag, e->calls, e->calls);
    return lpt_wf(path, text) && chmod(path, 0755) == 0;
}

static bool lpt_setup(struct lpt *e, const char *tag)
{
    char rel[512];
    test_make_tmpdir(rel, sizeof(rel), "lab_peer", tag);
    if (!test_abs_path(rel, e->d, sizeof(e->d)))
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
           lpt_fake(e, e->z23, "z23") && lpt_fake(e, e->z23dev, "z23dev");
}

/* Writes resp.<key> (the fake's canned reply). */
static bool lpt_resp(const struct lpt *e, const char *key, const char *json)
{
    char path[800];
    (void)snprintf(path, sizeof(path), "%s/resp.%s", e->resp, key);
    return lpt_wf(path, json);
}

/* Runs the tool: subcommand, the two fake programs, then extras. */
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
                     long expires)
{
    char esc[8192];
    const size_t used = strlen(body);
    lpt_esc(esc, sizeof(esc), text);
    (void)snprintf(body + used, cap - used,
                   "%s{\"id\":\"%s\",\"kind\":\"%s\",\"ref\":\"%s\",\"host\":\"%s\","
                   "\"agent\":\"a\",\"room\":\"lab\",\"text\":\"%s\","
                   "\"created_at\":1,\"expires_at\":%ld}",
                   used > 40 ? "," : "", id, kind, ref, host, esc, expires);
}

static bool lpt_list(const struct lpt *e, const char *posts)
{
    char body[32 * 1024];
    (void)snprintf(body, sizeof(body), "{\"ok\":true,\"data\":{\"posts\":[%s]}}", posts);
    return lpt_resp(e, "fleet.board.list", body);
}

static bool lpt_send_resps(const struct lpt *e, const struct lpt_ids *i, const char *pad)
{
    char body[8192], off[8192];
    (void)snprintf(off, sizeof(off),
                   "{\"schema\":\"zcl.dev_land_offer.v1\",\"commit\":\"%s\","
                   "\"base\":\"%s\",\"bundle_sha256\":\"%s\",\"lane\":\"lane-x\"%s}\n",
                   i->commit, i->base, i->sha, pad);
    char path[800];
    (void)snprintf(path, sizeof(path), "%s/offer.json", e->resp);
    (void)snprintf(body, sizeof(body), "{\"ok\":true,\"data\":{\"bundle_sha256\":\"%s\"}}",
                   i->sha);
    bool ok = lpt_wf(path, off) && lpt_resp(e, "dev.land.send", body);
    (void)snprintf(body, sizeof(body),
                   "{\"ok\":true,\"data\":{\"root\":\"%s\",\"sha256\":\"%s\","
                   "\"size\":1998,\"onion\":\"%s\"}}",
                   i->root, i->sha, i->onion);
    ok = ok && lpt_resp(e, "fleet.bundle.offer", body);
    char id[65];
    lpt_hex(id, '7', 64);
    (void)snprintf(body, sizeof(body), "{\"ok\":true,\"data\":{\"id\":\"%s\"}}", id);
    return ok && lpt_resp(e, "fleet.board.post.offer", body);
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

static int case_offer_posts_and_records(void)
{
    int failures = 0;
    struct lpt e;
    struct lpt_ids i;
    char needle[4300], row[700], tsv[800], id[65];
    lpt_ids(&i);
    lpt_hex(id, '7', 64);
    if (!lpt_setup(&e, "offer") || !lpt_send_resps(&e, &i, ""))
        return 1;
    const int rc = lpt_offer_run(&e, &i);
    (void)snprintf(needle, sizeof(needle), "\t%s\n", i.offer_text);
    LPT_CHECK("offer: exit 0 and a document", rc == 0 && strstr(g_run, "\"ok\":true"));
    LPT_CHECK("offer: the exact post text is the argv text",
              lpt_file_has(e.calls, needle));
    LPT_CHECK("offer: posts kind offer in room lab once",
              lpt_count(e.calls, "\toffer\n\tlab-offer v1 ") == 1 &&
                  lpt_file_has(e.calls, "\t--room=lab\n"));
    LPT_CHECK("offer: send runs with the commit, lane name and skipped precheck",
              lpt_file_has(e.calls, "\t--precheck=skip\n") &&
                  lpt_file_has(e.calls, "\t--lane=lane-x\n"));
    (void)snprintf(tsv, sizeof(tsv), "%s/state/offers.tsv", e.d);
    (void)snprintf(row, sizeof(row), "%s\tlane-x\t%s\t%s\t%s\t%s\t", id, i.commit,
                   i.base, i.sha, i.root);
    LPT_CHECK("offers.tsv: one row with the post, lane, commit, base, sha, root",
              lpt_count(tsv, row) == 1 && lpt_file_has(tsv, ".bundle\t") &&
                  lpt_file_has(tsv, ".bundle.offer.json\n"));
    return failures;
}

static int case_offer_too_long(void)
{
    int failures = 0;
    struct lpt e;
    struct lpt_ids i;
    char pad[2200], tsv[800];
    lpt_ids(&i);
    memcpy(pad, ",\"pad\":\"", 8);
    memset(pad + 8, 'x', 1700);
    memcpy(pad + 1708, "\"", 2);
    if (!lpt_setup(&e, "offer_long") || !lpt_send_resps(&e, &i, pad))
        return 1;
    const int rc = lpt_offer_run(&e, &i);
    (void)snprintf(tsv, sizeof(tsv), "%s/state/offers.tsv", e.d);
    LPT_CHECK("offer: an over-2048 text exits 0 with the typed refusal",
              rc == 0 && strstr(g_run, "OFFER_TEXT_TOO_LONG") &&
                  strstr(g_run, "\"ok\":false"));
    LPT_CHECK("offer: an over-2048 text posts nothing and records nothing",
              lpt_count(e.calls, "\tpost\n") == 0 && !lpt_exists(tsv));
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

static int lpt_verify_run(const struct lpt *e, const char *max)
{
    char state[700], repo[700], authors[700], mx[32];
    (void)snprintf(state, sizeof(state), "--state=%s", e->state);
    (void)snprintf(repo, sizeof(repo), "--repo=%s", e->repo);
    (void)snprintf(authors, sizeof(authors), "--authors=%s", e->authors);
    (void)snprintf(mx, sizeof(mx), "--max=%s", max);
    const char *const extra[] = {state, repo, authors, mx, NULL};
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
                           const char *root, const char *sha, long expires)
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

static int case_verify_filters(void)
{
    int failures = 0;
    struct lpt e;
    char posts[16 * 1024] = "", ha[65], hb[65], short_root[64], short_sha[64], id6[65];
    char handled[800], calls_state[800];
    lpt_hex(ha, 'a', 64);
    lpt_hex(hb, 'b', 64);
    lpt_hex(short_root, 'c', 63);
    lpt_hex(short_sha, 'd', 63);
    lpt_hex(id6, '6', 64);
    if (!lpt_setup(&e, "verify_filters") || !lpt_authors(&e) || !lpt_verify_resps(&e))
        return 1;
    lpt_offer_post(posts, sizeof(posts), '1', ha, NULL, NULL, 4102444800L);
    lpt_offer_post(posts, sizeof(posts), '2', hb, NULL, NULL, 4102444800L);
    lpt_offer_post(posts, sizeof(posts), '3', ha, short_root, NULL, 4102444800L);
    lpt_offer_post(posts, sizeof(posts), '4', ha, NULL, short_sha, 4102444800L);
    lpt_offer_post(posts, sizeof(posts), '5', ha, NULL, NULL, 1L);
    lpt_offer_post(posts, sizeof(posts), '6', ha, NULL, NULL, 4102444800L);
    lpt_post(posts, sizeof(posts), "7777777777777777777777777777777777777777777777777777777777777777",
             "note", "0000000000000000000000000000000000000000000000000000000000000000", ha,
             "lab-offer v1 not an offer kind", 4102444800L);
    (void)snprintf(handled, sizeof(handled), "%s/handled.tsv", e.state);
    (void)snprintf(calls_state, sizeof(calls_state), "%s\tok\t\t3\n", id6);
    if (!lpt_list(&e, posts) || !lpt_wf(handled, calls_state))
        return 1;
    const int rc = lpt_verify_run(&e, "10");
    LPT_CHECK("verify: exit 0 with a document", rc == 0 && strstr(g_run, "zcl.lab_peer.v1"));
    LPT_CHECK("verify: exactly one fetch (the one good, allowlisted post)",
              lpt_count(e.calls, "\tfetch\n") == 1);
    LPT_CHECK("verify: exactly one result posted", lpt_count(e.calls, "\tresult\n") == 1);
    LPT_CHECK("verify: non-allowlisted host is skipped", strstr(g_run, "HOST_NOT_ALLOWED") != NULL);
    LPT_CHECK("verify: malformed root and mismatched offer JSON are skipped (2)",
              strstr(g_run, "OFFER_MALFORMED") != NULL &&
                  strstr(strstr(g_run, "OFFER_MALFORMED") + 1, "OFFER_MALFORMED") != NULL);
    LPT_CHECK("verify: an expired post is skipped", strstr(g_run, "EXPIRED") != NULL);
    LPT_CHECK("verify: an already handled post is skipped", strstr(g_run, "ALREADY_HANDLED") != NULL);
    LPT_CHECK("verify: the processed post is recorded in handled.tsv",
              lpt_file_has(handled, "\tok\t\t"));
    return failures;
}

static int case_verify_ok_and_refused(void)
{
    int failures = 0;
    struct lpt e;
    char posts[8 * 1024] = "", ha[65], id[65], needle[800], handled[800];
    lpt_hex(ha, 'a', 64);
    lpt_hex(id, '1', 64);
    if (!lpt_setup(&e, "verify_ok") || !lpt_authors(&e) || !lpt_verify_resps(&e))
        return 1;
    lpt_offer_post(posts, sizeof(posts), '1', ha, NULL, NULL, 4102444800L);
    if (!lpt_list(&e, posts))
        return 1;
    (void)lpt_verify_run(&e, "10");
    (void)snprintf(needle, sizeof(needle),
                   "\tlab-receipt v1 offer=%s verdict=ok receipt="
                   "{\"schema\":\"zcl.dev_land_receipt.v1\",\"signer\":\"s\"}\n", id);
    LPT_CHECK("verify: posts the ok result with the compacted receipt",
              lpt_file_has(e.calls, needle));
    (void)snprintf(needle, sizeof(needle), "\t--ref=%s\n", id);
    LPT_CHECK("verify: the result carries ref = the offer post and the room",
              lpt_file_has(e.calls, needle) && lpt_file_has(e.calls, "\t--room=lab\n"));
    LPT_CHECK("verify: reverify gets bundle, offer, repo and receipt_out",
              lpt_file_has(e.calls, "\t--repo=") && lpt_file_has(e.calls, "\t--receipt_out=") &&
                  lpt_file_has(e.calls, "\t--bundle=") && lpt_file_has(e.calls, "\t--offer="));
    (void)lpt_verify_run(&e, "10");
    LPT_CHECK("verify: a second run does not process the post again",
              lpt_count(e.calls, "\tfetch\n") == 1 && lpt_count(e.calls, "\tresult\n") == 1);

    /* a new post, refused by reverify */
    char id2[65];
    lpt_hex(id2, '2', 64);
    posts[0] = '\0';
    lpt_offer_post(posts, sizeof(posts), '2', ha, NULL, NULL, 4102444800L);
    if (!lpt_list(&e, posts) ||
        !lpt_resp(&e, "dev.land.reverify_offer",
                  "{\"ok\":false,\"error\":{\"code\":\"REVERIFY_CX_FAILED\",\"message\":\"m\"}}"))
        return failures + 1;
    (void)lpt_verify_run(&e, "10");
    (void)snprintf(needle, sizeof(needle),
                   "\tlab-receipt v1 offer=%s verdict=refused code=REVERIFY_CX_FAILED\n", id2);
    LPT_CHECK("verify: posts a refused result with the typed code", lpt_file_has(e.calls, needle));
    (void)snprintf(handled, sizeof(handled), "%s/handled.tsv", e.state);
    (void)snprintf(needle, sizeof(needle), "%s\trefused\tREVERIFY_CX_FAILED\t", id2);
    LPT_CHECK("verify: the refusal is recorded", lpt_file_has(handled, needle));
    return failures;
}

static int case_verify_fetch_retry(void)
{
    int failures = 0;
    struct lpt e;
    char posts[8 * 1024] = "", ha[65], handled[800];
    lpt_hex(ha, 'a', 64);
    if (!lpt_setup(&e, "verify_retry") || !lpt_authors(&e) || !lpt_verify_resps(&e))
        return 1;
    lpt_offer_post(posts, sizeof(posts), '1', ha, NULL, NULL, 4102444800L);
    if (!lpt_list(&e, posts) ||
        !lpt_resp(&e, "fleet.bundle.fetch", "{\"ok\":false,\"error\":{\"code\":\"FETCH_FAILED\"}}"))
        return 1;
    (void)snprintf(handled, sizeof(handled), "%s/handled.tsv", e.state);
    (void)lpt_verify_run(&e, "10");
    LPT_CHECK("verify: a failed fetch is a retryable row",
              lpt_count(handled, "\tretry\tFETCH_FAILED\t") == 1);
    (void)lpt_verify_run(&e, "10");
    (void)lpt_verify_run(&e, "10");
    LPT_CHECK("verify: three attempts, then given up",
              lpt_count(e.calls, "\tfetch\n") == 3 &&
                  lpt_count(handled, "\tretry\t") == 2 &&
                  lpt_count(handled, "\tfailed\tFETCH_FAILED\t") == 1);
    (void)lpt_verify_run(&e, "10");
    LPT_CHECK("verify: a given-up post is not fetched again, nothing posted",
              lpt_count(e.calls, "\tfetch\n") == 3 && lpt_count(e.calls, "\tresult\n") == 0 &&
                  lpt_count(e.calls, "\treverify_offer\n") == 0);
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
    lpt_post(posts, cap, id, "result",
             offer, host, text, 4102444800L);
}

static int case_collect(void)
{
    int failures = 0;
    struct lpt_ids i;
    struct lpt e;
    char posts[16 * 1024] = "", offer[65], other[65], pid[65], row[1200], path[800];
    char ha[65], hb[65], body[2048], qual[800], rec[800];
    lpt_ids(&i);
    lpt_hex(offer, '1', 64);
    lpt_hex(other, '2', 64);
    lpt_hex(ha, 'a', 64);
    lpt_hex(hb, 'b', 64);
    if (!lpt_setup(&e, "collect"))
        return 1;
    (void)snprintf(path, sizeof(path), "%s/offers.tsv", e.state);
    (void)snprintf(row, sizeof(row), "%s\tlane-x\t%s\t%s\t%s\t%s\t%s/b.bundle\t%s/o.json\n",
                   offer, i.commit, i.base, i.sha, i.root, e.d, e.d);
    lpt_hex(pid, '3', 64);
    lpt_receipt_post(posts, sizeof(posts), 'a', pid, offer, "ok");
    lpt_hex(pid, '4', 64);
    lpt_receipt_post(posts, sizeof(posts), 'b', pid, offer, "ok");
    lpt_hex(pid, '5', 64);
    lpt_receipt_post(posts, sizeof(posts), 'c', pid, offer, "refused");
    lpt_hex(pid, '6', 64);
    lpt_receipt_post(posts, sizeof(posts), 'a', pid, other, "ok");
    lpt_hex(pid, '8', 64);
    {
        char host[65], text[400];
        lpt_hex(host, 'd', 64);
        (void)snprintf(text, sizeof(text),
                       "lab-receipt v1 offer=%s verdict=ok receipt={\"signer\":\"d\"}", other);
        lpt_post(posts, sizeof(posts), pid, "result", offer, host, text, 4102444800L);
    }
    (void)snprintf(body, sizeof(body),
                   "{\"ok\":true,\"data\":{\"commit\":\"%s\",\"base\":\"%s\",\"required\":2,"
                   "\"qualified\":2,\"signers\":[\"%s\",\"%s\"],\"duplicates\":0,"
                   "\"verdict\":\"ready\",\"rejected\":[]}}",
                   i.commit, i.base, ha, hb);
    if (!lpt_wf(path, row) || !lpt_list(&e, posts) ||
        !lpt_resp(&e, "dev.land.qualify_offer", body))
        return 1;
    const int rc = lpt_collect_run(&e, "2");
    LPT_CHECK("collect: exit 0 with a document", rc == 0 && strstr(g_run, "zcl.lab_peer.v1"));
    (void)snprintf(rec, sizeof(rec), "%s/receipts/%s-aaaaaaaaaaaa.json", e.state, offer);
    LPT_CHECK("collect: writes the ok receipt of host a", lpt_file_has(rec, "{\"signer\":\"a\"}"));
    (void)snprintf(rec, sizeof(rec), "%s/receipts/%s-bbbbbbbbbbbb.json", e.state, offer);
    LPT_CHECK("collect: writes the ok receipt of host b", lpt_file_has(rec, "{\"signer\":\"b\"}"));
    (void)snprintf(rec, sizeof(rec), "%s/receipts/%s-cccccccccccc.json", e.state, offer);
    LPT_CHECK("collect: a refused result writes no receipt", !lpt_exists(rec));
    (void)snprintf(rec, sizeof(rec), "%s/receipts/%s-dddddddddddd.json", e.state, offer);
    LPT_CHECK("collect: a result naming another offer writes no receipt", !lpt_exists(rec));
    LPT_CHECK("collect: qualify runs once with require=2 and both receipts",
              lpt_count(e.calls, "\tqualify_offer\n") == 1 &&
                  lpt_file_has(e.calls, "\t--require=2\n") &&
                  lpt_file_has(e.calls, "-aaaaaaaaaaaa.json,") &&
                  lpt_file_has(e.calls, "-bbbbbbbbbbbb.json\n"));
    (void)snprintf(qual, sizeof(qual), "%s/qualified.tsv", e.state);
    (void)snprintf(row, sizeof(row), "lane-x\t%s\tready\t2\t%s,%s\t\n", i.commit, ha, hb);
    LPT_CHECK("collect: qualified.tsv has lane, commit, verdict, count and signers",
              lpt_file_has(qual, row));
    LPT_CHECK("collect: shadow mode, no submit, send or receive leaf is ever called",
              lpt_count(e.calls, "submit") == 0 && lpt_count(e.calls, "\tsend\n") == 0 &&
                  lpt_count(e.calls, "\treceive\n") == 0 &&
                  lpt_count(e.calls, "\tpost\n") == 0);

    /* a short quorum: the refusal's evidence still carries the count */
    (void)snprintf(body, sizeof(body),
                   "{\"ok\":false,\"error\":{\"code\":\"QUALIFY_SHORT\","
                   "\"evidence\":\"qualified=1 required=2 duplicates=0\"},"
                   "\"data\":{\"rejected\":[{\"receipt\":\"/x\",\"code\":\"RECEIPT_SIGNATURE_INVALID\"}]}}");
    if (!lpt_resp(&e, "dev.land.qualify_offer", body))
        return failures + 1;
    (void)lpt_collect_run(&e, "2");
    (void)snprintf(row, sizeof(row), "lane-x\t%s\tQUALIFY_SHORT\t1\t\tRECEIPT_SIGNATURE_INVALID\n",
                   i.commit);
    LPT_CHECK("collect: a short quorum is recorded with its count and rejected codes",
              lpt_file_has(qual, row));
    return failures;
}

static int case_usage(void)
{
    int failures = 0;
    bool timed_out = false;
    const char *const none[] = {LPT_BIN, NULL};
    const char *const bad[] = {LPT_BIN, "verify", "--state=x", NULL};
    LPT_CHECK("usage: no subcommand exits 2",
              zcl_spawn_capture_observed(none, g_run, sizeof(g_run), 20000, &timed_out) == 2);
    LPT_CHECK("usage: verify without --repo and --authors exits 2",
              zcl_spawn_capture_observed(bad, g_run, sizeof(g_run), 20000, &timed_out) == 2);
    return failures;
}

int test_lab_peer(void)
{
    int failures = 0;
    struct stat st;
    if (stat(LPT_BIN, &st) != 0) {
        printf("lab_peer: FAIL (%s is a required test prerequisite)\n", LPT_BIN);
        return 1;
    }
    failures += case_usage();
    failures += case_offer_posts_and_records();
    failures += case_offer_too_long();
    failures += case_verify_filters();
    failures += case_verify_ok_and_refused();
    failures += case_verify_fetch_retry();
    failures += case_collect();
    return failures;
}
