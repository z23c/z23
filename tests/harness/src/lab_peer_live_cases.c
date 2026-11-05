/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * lab_peer_live_cases: the lab-peer loop between two separate nodes, with the
 * REAL build/bin/z23-dev and build/bin/z23-lab-peer, on real throwaway git
 * repos. Each "node" has its own HOME (so its own dev proof signer key), its
 * own checkout (a clone of one local origin) and its own state directory.
 * Nothing leaves the machine: no network, no ssh, no real datadir or key.
 *
 * Real legs: node A runs "z23-lab-peer offer" (so a real "dev land send"
 * bundles the reviewed commit and writes the offer manifest; a first run that
 * stops at the stubbed swarm is rerun and reuses the bundle); node B runs
 * "dev land check_offer" and "dev land attest_offer" on the bytes it was
 * given and signs a receipt with its own key; "verify_offer_receipt" accepts
 * that receipt on B; a bundle with one flipped byte is refused with
 * OFFER_SHA_MISMATCH and writes no receipt; node A, with its own key, refuses
 * B's receipt as an unknown signer and "qualify_offer" counts none of it.
 *
 * Stubbed legs (lab-peer-fake as --z23=): the Tor package swarm
 * ("fleet bundle offer" / "fetch", which accept only a v3 onion peer) and the
 * board ("fleet board post" / "list"). The bytes B fetches are copied from A's
 * state directory. Not run here: "z23-lab-peer verify" and "collect" across
 * the two nodes, because a counting receipt needs "reverify_offer" (a real
 * build of the offered commit) and a signer on the dev binary's signers.allow.
 */

#include "test/test_core.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char LV_BIN[] = "build/bin/z23-lab-peer";
static const char LV_FAKE[] = "build/bin/lab-peer-fake";
static const char LV_DEV[] = "build/bin/z23-dev";

struct lv {
    char d[600], bin[700], dev[700], fake[700];
    char origin[700], a_home[700], a_repo[700], a_state[700], a_z23[700], a_resp[700];
    char b_home[700], b_repo[700], b_in[700];
    char commit[48], sha[72];
    char bundle[900], offer[900], b_bundle[800], b_offer[800], b_receipt[800];
};

static char g_lv_out[64 * 1024];
static char g_lv_home[1024], g_lv_xdg[1024];
static bool g_lv_home_set, g_lv_xdg_set;

#define LV_REQ(cond) do { if (!(cond)) { \
    printf("lab_peer_live: FAIL at %d (%s)\n%.600s\n", __LINE__, #cond, g_lv_out); \
    return false; } } while (0)

static bool lv_wf(const char *path, const void *data, size_t n)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    const bool ok = n == 0 || fwrite(data, 1, n, f) == n;
    return fclose(f) == 0 && ok;
}

static size_t lv_rf(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return 0;
    const size_t n = fread(buf, 1, cap - 1, f);
    (void)fclose(f);
    buf[n] = '\0';
    return n;
}

static bool lv_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

/* Copies src to dst; with flip, one byte in the middle is changed. */
static bool lv_copy(const char *src, const char *dst, bool flip)
{
    static char buf[256 * 1024];
    const size_t n = lv_rf(src, buf, sizeof(buf));
    if (n == 0 || n >= sizeof(buf) - 1)
        return false;
    if (flip)
        buf[n / 2] ^= 0x01;
    return lv_wf(dst, buf, n);
}

static void lv_env_save(void)
{
    const char *h = getenv("HOME"), *x = getenv("XDG_STATE_HOME");
    g_lv_home_set = h != NULL;
    g_lv_xdg_set = x != NULL;
    (void)snprintf(g_lv_home, sizeof(g_lv_home), "%s", h ? h : "");
    (void)snprintf(g_lv_xdg, sizeof(g_lv_xdg), "%s", x ? x : "");
}

static void lv_env_restore(void)
{
    if (g_lv_home_set)
        (void)setenv("HOME", g_lv_home, 1);
    else
        (void)unsetenv("HOME");
    if (g_lv_xdg_set)
        (void)setenv("XDG_STATE_HOME", g_lv_xdg, 1);
    else
        (void)unsetenv("XDG_STATE_HOME");
}

/* Acts as one node: its HOME holds the signer key; XDG_STATE_HOME must not
 * redirect that key to somewhere shared. */
static bool lv_node(const char *home)
{
    return setenv("HOME", home, 1) == 0 && unsetenv("XDG_STATE_HOME") == 0;
}

/* Runs argv; output in g_lv_out; the exit status, or -1 on a timeout. */
static int lv_spawn(const char *const argv[])
{
    bool to = false;
    const int rc = zcl_spawn_capture_observed(argv, g_lv_out, sizeof(g_lv_out), 120000, &to);
    return to ? -1 : rc;
}

/* git -C dir <args>; the first output line is left in g_lv_out. */
static bool lv_git(const char *dir, const char *const args[])
{
    const char *argv[24] = {"git", "-C", dir, "-c", "user.name=t", "-c", "user.email=t@t.t"};
    int n = 7;
    for (int i = 0; args[i] && n < 22; i++)
        argv[n++] = args[i];
    argv[n] = NULL;
    if (lv_spawn(argv) != 0)
        return false;
    char *nl = strchr(g_lv_out, '\n');
    if (nl)
        *nl = '\0';
    return true;
}

static void lv_paths(struct lv *e)
{
    (void)snprintf(e->origin, sizeof(e->origin), "%s/origin", e->d);
    (void)snprintf(e->a_home, sizeof(e->a_home), "%s/a-home", e->d);
    (void)snprintf(e->a_repo, sizeof(e->a_repo), "%s/lane-a", e->d);
    (void)snprintf(e->a_state, sizeof(e->a_state), "%s/a-state", e->d);
    (void)snprintf(e->a_z23, sizeof(e->a_z23), "%s/a-fake-z23", e->d);
    (void)snprintf(e->a_resp, sizeof(e->a_resp), "%s/resp", e->d);
    (void)snprintf(e->b_home, sizeof(e->b_home), "%s/b-home", e->d);
    (void)snprintf(e->b_repo, sizeof(e->b_repo), "%s/b-repo", e->d);
    (void)snprintf(e->b_in, sizeof(e->b_in), "%s/b-in", e->d);
    (void)snprintf(e->b_bundle, sizeof(e->b_bundle), "%s/x.bundle", e->b_in);
    (void)snprintf(e->b_offer, sizeof(e->b_offer), "%s/x.bundle.offer.json", e->b_in);
    (void)snprintf(e->b_receipt, sizeof(e->b_receipt), "%s/x.receipt.json", e->b_in);
}

/* The origin tree carries the marker files z23-dev needs to accept a
 * directory as a checkout. */
static bool lv_origin(const struct lv *e)
{
    char p[800];
    const char *const init[] = {"init", "-q", "-b", "main", NULL};
    const char *const add[] = {"add", "-A", NULL};
    const char *const commit[] = {"commit", "-q", "-m", "base", NULL};
    LV_REQ(mkdir(e->origin, 0700) == 0 && lv_git(e->origin, init));
    (void)snprintf(p, sizeof(p), "%s/engine", e->origin);
    LV_REQ(mkdir(p, 0700) == 0);
    (void)snprintf(p, sizeof(p), "%s/engine/composition", e->origin);
    LV_REQ(mkdir(p, 0700) == 0);
    (void)snprintf(p, sizeof(p), "%s/engine/composition/commands", e->origin);
    LV_REQ(mkdir(p, 0700) == 0);
    (void)snprintf(p, sizeof(p), "%s/engine/composition/commands/root.def", e->origin);
    LV_REQ(lv_wf(p, "", 0));
    (void)snprintf(p, sizeof(p), "%s/tools", e->origin);
    LV_REQ(mkdir(p, 0700) == 0);
    (void)snprintf(p, sizeof(p), "%s/tools/dev", e->origin);
    LV_REQ(mkdir(p, 0700) == 0);
    (void)snprintf(p, sizeof(p), "%s/tools/dev/test_group_catalog.def", e->origin);
    LV_REQ(lv_wf(p, "", 0));
    (void)snprintf(p, sizeof(p), "%s/Makefile", e->origin);
    LV_REQ(lv_wf(p, "", 0));
    return lv_git(e->origin, add) && lv_git(e->origin, commit);
}

static bool lv_clone(const char *origin, const char *dst)
{
    const char *const argv[] = {"git", "clone", "-q", origin, dst, NULL};
    LV_REQ(lv_spawn(argv) == 0);
    return true;
}

/* Two nodes: each a clone of the origin, its own HOME; A adds one commit. */
static bool lv_fixture(struct lv *e)
{
    char p[800];
    const char *const add[] = {"add", "f", NULL};
    const char *const commit[] = {"commit", "-q", "-m", "change", NULL};
    const char *const head[] = {"rev-parse", "HEAD", NULL};
    LV_REQ(lv_origin(e) && lv_clone(e->origin, e->a_repo) && lv_clone(e->origin, e->b_repo));
    LV_REQ(mkdir(e->a_home, 0700) == 0 && mkdir(e->b_home, 0700) == 0 &&
           mkdir(e->b_in, 0700) == 0 && mkdir(e->a_resp, 0700) == 0 &&
           symlink(e->fake, e->a_z23) == 0);
    (void)snprintf(p, sizeof(p), "%s/f", e->a_repo);
    LV_REQ(lv_wf(p, "one\n", 4) && lv_git(e->a_repo, add) && lv_git(e->a_repo, commit));
    LV_REQ(lv_git(e->a_repo, head) && strlen(g_lv_out) == 40);
    (void)snprintf(e->commit, sizeof(e->commit), "%s", g_lv_out);
    return true;
}

/* z23-lab-peer offer for node A, with the real z23-dev and the stubbed z23. */
static int lv_offer_run(const struct lv *e)
{
    char z23[760], dev[760], lane[760], commit[80], state[760];
    (void)snprintf(z23, sizeof(z23), "--z23=%s", e->a_z23);
    (void)snprintf(dev, sizeof(dev), "--z23dev=%s", e->dev);
    (void)snprintf(lane, sizeof(lane), "--lane=%s", e->a_repo);
    (void)snprintf(commit, sizeof(commit), "--commit=%s", e->commit);
    (void)snprintf(state, sizeof(state), "--state=%s", e->a_state);
    const char *const argv[] = {e->bin, "offer", z23, dev, lane, commit, state, NULL};
    return lv_spawn(argv);
}

/* Writes the canned replies the stubbed swarm and board give for A's offer. */
static bool lv_canned(const struct lv *e)
{
    char path[800], body[1024];
    (void)snprintf(path, sizeof(path), "%s/resp.fleet.bundle.offer", e->a_resp);
    (void)snprintf(body, sizeof(body),
                   "{\"ok\":true,\"data\":{\"root\":\"%.64s\",\"sha256\":\"%s\","
                   "\"size\":2048,\"onion\":\"%.56s.onion\"}}",
                   "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", e->sha,
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    LV_REQ(lv_wf(path, body, strlen(body)));
    return true;
}

static bool lv_canned_board(const struct lv *e)
{
    static const char list[] = "{\"ok\":true,\"data\":{\"posts\":[]}}";
    static const char post[] = "{\"ok\":true,\"data\":{\"id\":"
        "\"7777777777777777777777777777777777777777777777777777777777777777\"}}";
    char path[800];
    (void)snprintf(path, sizeof(path), "%s/resp.fleet.board.list", e->a_resp);
    LV_REQ(lv_wf(path, list, sizeof(list) - 1));
    (void)snprintf(path, sizeof(path), "%s/resp.fleet.board.post.offer", e->a_resp);
    LV_REQ(lv_wf(path, post, sizeof(post) - 1));
    return true;
}

/* The bundle sha256 the real send wrote in the offer manifest. */
static bool lv_read_sha(struct lv *e)
{
    static char text[4096];
    static const char key[] = "\"bundle_sha256\":\"";
    LV_REQ(lv_rf(e->offer, text, sizeof(text)) > 0);
    const char *p = strstr(text, key);
    LV_REQ(p != NULL && strlen(p + sizeof(key) - 1) > 64);
    (void)snprintf(e->sha, sizeof(e->sha), "%.64s", p + sizeof(key) - 1);
    return true;
}

/* Node A offers through the operator command. The first run has no swarm
 * reply, so it stops there; the real send already wrote the bundle, and the
 * rerun reuses it, then records the offer. */
static bool lv_offer(struct lv *e)
{
    char row[900];
    char c12[16];
    LV_REQ(lv_node(e->a_home) && lv_canned_board(e));
    LV_REQ(lv_offer_run(e) == 1);
    (void)snprintf(c12, sizeof(c12), "%.12s", e->commit);
    (void)snprintf(e->bundle, sizeof(e->bundle), "%s/out/lane-a-%s.bundle", e->a_state, c12);
    (void)snprintf(e->offer, sizeof(e->offer), "%s.offer.json", e->bundle);
    LV_REQ(lv_exists(e->bundle) && lv_read_sha(e) && lv_canned(e));
    LV_REQ(lv_offer_run(e) == 0);
    LV_REQ(strstr(g_lv_out, "\"ok\":true") != NULL);
    (void)snprintf(row, sizeof(row), "%s/offers.tsv", e->a_state);
    LV_REQ(lv_rf(row, g_lv_out, sizeof(g_lv_out)) > 0 && strstr(g_lv_out, e->commit) != NULL);
    return true;
}

/* A z23-dev "dev land <leaf> <args>" run; true when it exited 0. */
static bool lv_dev(const struct lv *e, const char *leaf, const char *a, const char *b,
                   const char *c, const char *d)
{
    const char *argv[12] = {e->dev, "dev", "land", leaf};
    int n = 4;
    const char *const more[] = {a, b, c, d};
    for (int i = 0; i < 4; i++)
        if (more[i])
            argv[n++] = more[i];
    argv[n] = NULL;
    return lv_spawn(argv) == 0;
}

/* Node B fetches (a file copy stands in for the swarm), checks and attests. */
static bool lv_receipt(struct lv *e)
{
    char bundle[900], offer[900], repo[760], out[900];
    LV_REQ(lv_node(e->b_home) && lv_copy(e->bundle, e->b_bundle, false) &&
           lv_copy(e->offer, e->b_offer, false));
    (void)snprintf(bundle, sizeof(bundle), "--bundle=%s", e->b_bundle);
    (void)snprintf(offer, sizeof(offer), "--offer=%s", e->b_offer);
    (void)snprintf(repo, sizeof(repo), "--repo=%s", e->b_repo);
    (void)snprintf(out, sizeof(out), "--receipt_out=%s", e->b_receipt);
    LV_REQ(lv_dev(e, "check_offer", bundle, offer, repo, NULL));
    LV_REQ(strstr(g_lv_out, "\"verdict\":\"ok\"") != NULL);
    LV_REQ(lv_dev(e, "attest_offer", bundle, offer, repo, out));
    LV_REQ(lv_exists(e->b_receipt));
    (void)snprintf(out, sizeof(out), "--receipt=%s", e->b_receipt);
    LV_REQ(lv_dev(e, "verify_offer_receipt", out, offer, NULL, NULL));
    LV_REQ(strstr(g_lv_out, "\"verdict\":\"ok\"") != NULL);
    return true;
}

/* A tampered bundle is refused by B and no receipt is written. */
static bool lv_tamper(const struct lv *e)
{
    char bundle[900], offer[900], repo[760], out[900], bad[800], rc[800];
    (void)snprintf(bad, sizeof(bad), "%s/bad.bundle", e->b_in);
    (void)snprintf(rc, sizeof(rc), "%s/bad.receipt.json", e->b_in);
    LV_REQ(lv_node(e->b_home) && lv_copy(e->bundle, bad, true));
    (void)snprintf(bundle, sizeof(bundle), "--bundle=%s", bad);
    (void)snprintf(offer, sizeof(offer), "--offer=%s", e->b_offer);
    (void)snprintf(repo, sizeof(repo), "--repo=%s", e->b_repo);
    (void)snprintf(out, sizeof(out), "--receipt_out=%s", rc);
    LV_REQ(!lv_dev(e, "attest_offer", bundle, offer, repo, out));
    LV_REQ(strstr(g_lv_out, "\"code\":\"OFFER_SHA_MISMATCH\"") != NULL);
    LV_REQ(!lv_exists(rc));
    return true;
}

/* Node A has its own key (it attests its own bundle first) and refuses B's
 * receipt as an unknown signer; qualify_offer counts nothing from it. */
static bool lv_cross(const struct lv *e)
{
    char bundle[900], offer[900], repo[760], out[900], own[800], recs[900];
    (void)snprintf(own, sizeof(own), "%s/a-own.receipt.json", e->d);
    (void)snprintf(bundle, sizeof(bundle), "--bundle=%s", e->bundle);
    (void)snprintf(offer, sizeof(offer), "--offer=%s", e->offer);
    (void)snprintf(repo, sizeof(repo), "--repo=%s", e->a_repo);
    (void)snprintf(out, sizeof(out), "--receipt_out=%s", own);
    LV_REQ(lv_node(e->a_home) && lv_dev(e, "attest_offer", bundle, offer, repo, out));
    (void)snprintf(out, sizeof(out), "--receipt=%s", e->b_receipt);
    LV_REQ(!lv_dev(e, "verify_offer_receipt", out, offer, NULL, NULL));
    LV_REQ(strstr(g_lv_out, "\"code\":\"RECEIPT_SIGNER_UNKNOWN\"") != NULL);
    (void)snprintf(recs, sizeof(recs), "--receipts=%s", e->b_receipt);
    LV_REQ(!lv_dev(e, "qualify_offer", offer, recs, NULL, NULL));
    LV_REQ(strstr(g_lv_out, "\"code\":\"QUALIFY_SHORT\"") != NULL);
    return true;
}

static bool lv_scenario(struct lv *e)
{
    LV_REQ(lv_fixture(e));
    LV_REQ(lv_offer(e));
    LV_REQ(lv_receipt(e));
    LV_REQ(lv_tamper(e));
    LV_REQ(lv_cross(e));
    return true;
}

int lab_peer_live_cases(void);
int lab_peer_live_cases(void)
{
    int failures = 0;
    struct lv e;
    struct stat st;
    memset(&e, 0, sizeof(e));
    if (stat(LV_BIN, &st) != 0 || stat(LV_FAKE, &st) != 0 || stat(LV_DEV, &st) != 0) {
        printf("lab_peer_live: FAIL (%s, %s and %s are required test prerequisites)\n", LV_BIN,
               LV_FAKE, LV_DEV);
        return 1;
    }
    TEST_CASE("lab_peer: two isolated nodes offer, re-check, receipt, refuse a tampered bundle") {
        char rel[512];
        test_make_tmpdir(rel, sizeof(rel), "lab_peer_live", "two");
        ASSERT(test_abs_path(rel, e.d, sizeof(e.d)));
        ASSERT(test_abs_path(LV_BIN, e.bin, sizeof(e.bin)) &&
               test_abs_path(LV_DEV, e.dev, sizeof(e.dev)) &&
               test_abs_path(LV_FAKE, e.fake, sizeof(e.fake)));
        lv_paths(&e);
        lv_env_save();
        const bool ok = lv_scenario(&e);
        lv_env_restore();
        (void)test_rm_rf_recursive(e.d);
        ASSERT(ok);
    } TEST_END
    return failures;
}
