/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_lab_peer_shadow: whole runs of "z23-lab-peer shadow" (tools/
 * lab_peer_shadow.c) on real throwaway git repos, one per stack, with the peer
 * child and z23 replaced by the lab-peer-fake program. No shell, no network.
 *
 * Scenarios: a finished stack whose gate committed an automatic fix is offered
 * at its FINAL tip, never its first commit (the root cause of the REVERIFY_LINT_FAILED
 * disagreements); a running, failed or unsubmitted gate is not offered; a
 * stack already offered is skipped and the bridge's earlier sha is shown;
 * --dry-run writes nothing; a live run offers one synthesized commit that
 * carries the tip's tree, records the bridge-format ledger row and, after
 * collect --check=gate, a shadow-compare.tsv row (agree and refused); a bad
 * option is a usage error.
 */

#include "test/test_core.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char LSH_BIN[] = "build/bin/z23-lab-peer";
static const char LSH_FAKE[] = "build/bin/lab-peer-fake";

struct lsh {
    char d[600], gates[640], root[640], state[640], peer[640], z23[640], calls[640], resp[640];
    char dev[700];
};

static char g_lsh_out[64 * 1024];

static bool lsh_wf(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    const size_t n = strlen(text);
    const bool ok = fwrite(text, 1, n, f) == n;
    return fclose(f) == 0 && ok;
}

static bool lsh_has(const char *path, const char *needle)
{
    static char body[64 * 1024];
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    const size_t n = fread(body, 1, sizeof(body) - 1, f);
    (void)fclose(f);
    body[n] = '\0';
    return strstr(body, needle) != NULL;
}

static bool lsh_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

/* git -C dir <args>; the first output line in out. */
static bool lsh_gitv(const char *dir, char *out, size_t cap, const char *const args[])
{
    const char *argv[24] = {"git", "-C", dir, "-c", "user.name=t", "-c", "user.email=t@t.t"};
    int n = 7;
    bool to = false;
    char *nl;
    for (int i = 0; args[i] && n < 22; i++)
        argv[n++] = args[i];
    argv[n] = NULL;
    if (zcl_spawn_capture_observed(argv, out, cap, 60000, &to) != 0 || to)
        return false;
    nl = strchr(out, '\n');
    if (nl)
        *nl = '\0';
    return true;
}

static bool lsh_head(const char *dir, char *out)
{
    const char *const a[] = {"rev-parse", "HEAD", NULL};
    return lsh_gitv(dir, out, 64, a);
}

static bool lsh_setup(struct lsh *e, const char *tag)
{
    char rel[512], fake[700];
    test_make_tmpdir(rel, sizeof(rel), "lab_peer_shadow", tag);
    if (!test_abs_path(rel, e->d, sizeof(e->d)) || !test_abs_path(LSH_FAKE, fake, sizeof(fake)))
        return false;
    (void)snprintf(e->gates, sizeof(e->gates), "%s/gates", e->d);
    (void)snprintf(e->root, sizeof(e->root), "%s/root", e->d);
    (void)snprintf(e->state, sizeof(e->state), "%s/state", e->d);
    (void)snprintf(e->peer, sizeof(e->peer), "%s/fake-peer", e->d);
    (void)snprintf(e->z23, sizeof(e->z23), "%s/fake-z23", e->d);
    (void)snprintf(e->calls, sizeof(e->calls), "%s/calls.log", e->d);
    (void)snprintf(e->resp, sizeof(e->resp), "%s/resp", e->d);
    return mkdir(e->gates, 0700) == 0 && mkdir(e->root, 0700) == 0 && mkdir(e->state, 0700) == 0 &&
           mkdir(e->resp, 0700) == 0 && symlink(fake, e->peer) == 0 && symlink(fake, e->z23) == 0;
}

/* A stack worktree z23-stacksN with `commits` commits beyond origin/main; tip
 * and bottom receive the shas. */
static bool lsh_repo(const struct lsh *e, const char *name, int commits, char tip[64], char bottom[64])
{
    char dir[700], msg[32], junk[256];
    const char *const init[] = {"init", "-q", "-b", "main", NULL};
    const char *const base[] = {"commit", "-q", "--allow-empty", "-m", "base", NULL};
    const char *const ref[] = {"update-ref", "refs/remotes/origin/main", "HEAD", NULL};
    (void)snprintf(dir, sizeof(dir), "%s/%s", e->root, name);
    if (mkdir(dir, 0700) != 0 || !lsh_gitv(dir, junk, sizeof(junk), init) ||
        !lsh_gitv(dir, junk, sizeof(junk), base) || !lsh_gitv(dir, junk, sizeof(junk), ref))
        return false;
    for (int i = 0; i < commits; i++) {
        (void)snprintf(msg, sizeof(msg), "stack commit %d", i);
        const char *const add[] = {"commit", "-q", "--allow-empty", "-m", msg, NULL};
        if (!lsh_gitv(dir, junk, sizeof(junk), add) || (i == 0 && !lsh_head(dir, bottom)))
            return false;
    }
    return lsh_head(dir, tip);
}

static bool lsh_gate(const struct lsh *e, const char *name, const char *log, const char *tip)
{
    char dir[700], path[800], json[160];
    (void)snprintf(dir, sizeof(dir), "%s/%s", e->gates, name);
    (void)snprintf(path, sizeof(path), "%s/run.log", dir);
    if (mkdir(dir, 0700) != 0 || !lsh_wf(path, log))
        return false;
    if (!tip)
        return true;
    (void)snprintf(path, sizeof(path), "%s/submit.json", dir);
    (void)snprintf(json, sizeof(json), "{\"data\":{\"tip\":\"%s\"}}", tip);
    return lsh_wf(path, json);
}

static int lsh_run(const struct lsh *e, const char *const extra[])
{
    char state[700], gates[700], root[700], peer[700], z23[700], handoff[700];
    const char *argv[24];
    int n = 0;
    bool to = false;
    (void)snprintf(state, sizeof(state), "--state=%s", e->state);
    (void)snprintf(gates, sizeof(gates), "--gates=%s", e->gates);
    (void)snprintf(root, sizeof(root), "--stacks-root=%s", e->root);
    (void)snprintf(peer, sizeof(peer), "--bin=%s", e->peer);
    (void)snprintf(z23, sizeof(z23), "--z23=%s", e->z23);
    (void)snprintf(handoff, sizeof(handoff), "--handoff-dir=%s", e->d);
    argv[n++] = LSH_BIN;
    argv[n++] = "shadow";
    argv[n++] = state;
    argv[n++] = gates;
    argv[n++] = root;
    argv[n++] = peer;
    argv[n++] = z23;
    argv[n++] = handoff;
    for (int i = 0; extra && extra[i] && n < 22; i++)
        argv[n++] = extra[i];
    argv[n] = NULL;
    return zcl_spawn_capture_observed(argv, g_lsh_out, sizeof(g_lsh_out), 120000, &to);
}

static const char LSH_DONE[] = "2026-11-03T09:00:00Z gating x\n2026-11-03T09:30:00Z submitted as #7\nrc=0\n";

static int case_final_tip(void)
{
    int failures = 0;
    struct lsh e;
    char tip[64], bottom[64], needle[200], p[800];
    const char *const dry[] = {"--dry-run", NULL};
    TEST_CASE("lab_peer shadow: a stack with an autofix commit offers its FINAL tip, not the first") {
        ASSERT(lsh_setup(&e, "tip") && lsh_repo(&e, "z23-stacks516", 3, tip, bottom));
        ASSERT(lsh_gate(&e, "z23-stacks516", LSH_DONE, tip));
        ASSERT_EQ(lsh_run(&e, dry), 0);
        (void)snprintf(needle, sizeof(needle), "\"action\":\"would_offer\",\"code\":\"SYNTH_SINGLE\",\"sha\":\"%s\"", tip);
        ASSERT(strstr(g_lsh_out, needle) != NULL);
        ASSERT(strstr(g_lsh_out, bottom) == NULL);
        (void)snprintf(p, sizeof(p), "%s/shadow-offered.tsv", e.state);
        ASSERT(!lsh_exists(p));
        (void)snprintf(p, sizeof(p), "%s/shadow.lock", e.state);
        ASSERT(!lsh_exists(p));
    } TEST_END
    return failures;
}

static int case_not_finished(void)
{
    int failures = 0;
    struct lsh e;
    char tip[64], bottom[64];
    const char *const dry[] = {"--dry-run", NULL};
    TEST_CASE("lab_peer shadow: a running, failed or unsubmitted gate is not offered") {
        ASSERT(lsh_setup(&e, "unfinished"));
        ASSERT(lsh_repo(&e, "z23-stacks1", 1, tip, bottom) && lsh_repo(&e, "z23-stacks2", 1, tip, bottom) &&
               lsh_repo(&e, "z23-stacks3", 1, tip, bottom));
        ASSERT(lsh_gate(&e, "z23-stacks1", "gating\nagent-verify started\n", NULL));
        ASSERT(lsh_gate(&e, "z23-stacks2", "gating\nSTOP: lint\nrc=1\n", NULL));
        ASSERT(lsh_gate(&e, "z23-stacks3", "gating\nrc=0\n", NULL));
        ASSERT_EQ(lsh_run(&e, dry), 0);
        ASSERT(strstr(g_lsh_out, "\"name\":\"z23-stacks1\",\"action\":\"skip\",\"code\":\"GATE_RUNNING\"") != NULL);
        ASSERT(strstr(g_lsh_out, "\"name\":\"z23-stacks2\",\"action\":\"skip\",\"code\":\"GATE_FAILED\"") != NULL);
        ASSERT(strstr(g_lsh_out, "\"name\":\"z23-stacks3\",\"action\":\"skip\",\"code\":\"NOT_SUBMITTED\"") != NULL);
        ASSERT(strstr(g_lsh_out, "would_offer") == NULL);
    } TEST_END
    return failures;
}

static int case_single_and_bridge(void)
{
    int failures = 0;
    struct lsh e;
    char tip[64], bottom[64], row[400], p[800], needle[300];
    const char *const dry[] = {"--dry-run", NULL};
    TEST_CASE("lab_peer shadow: one commit is offered as is; an offered tip is skipped; the bridge sha is shown") {
        ASSERT(lsh_setup(&e, "single") && lsh_repo(&e, "z23-stacks9", 1, tip, bottom));
        ASSERT(lsh_gate(&e, "z23-stacks9", LSH_DONE, NULL)); /* no submit.json: HEAD */
        ASSERT_EQ(lsh_run(&e, dry), 0);
        (void)snprintf(needle, sizeof(needle), "\"code\":\"SINGLE\",\"sha\":\"%s\"", tip);
        ASSERT(strstr(g_lsh_out, needle) != NULL);
        (void)snprintf(p, sizeof(p), "%s/shadow-offered.tsv", e.state);
        (void)snprintf(row, sizeof(row), "%064d\tz23-stacks9\t%s\t1\t0\n", 7, tip);
        ASSERT(lsh_wf(p, row));
        ASSERT_EQ(lsh_run(&e, dry), 0);
        ASSERT(strstr(g_lsh_out, "\"code\":\"ALREADY_OFFERED\"") != NULL);
        (void)snprintf(needle, sizeof(needle), "\"bridge\":\"%s\"", tip);
        ASSERT(strstr(g_lsh_out, needle) != NULL);
    } TEST_END
    return failures;
}

static int case_live(void)
{
    int failures = 0;
    struct lsh e;
    char tip[64], bottom[64], p[800], id[65], body[600], want[600];
    TEST_CASE("lab_peer shadow: a live run offers one commit with the tip tree and compares after collect --check=gate") {
        ASSERT(lsh_setup(&e, "live") && lsh_repo(&e, "z23-stacks516", 3, tip, bottom));
        ASSERT(lsh_gate(&e, "z23-stacks516", LSH_DONE, tip));
        (void)snprintf(id, sizeof(id), "%064d", 5);
        (void)snprintf(body, sizeof(body), "{\"ok\":true,\"items\":[{\"id\":\"%s\",\"status\":\"ok\",\"code\":\"\"}]}\n", id);
        (void)snprintf(p, sizeof(p), "%s/resp.peer.offer", e.resp);
        ASSERT(lsh_wf(p, body));
        (void)snprintf(body, sizeof(body), "{\"ok\":true,\"items\":[{\"id\":\"%s\",\"status\":\"ok\",\"code\":\"ready\"}]}\n", id);
        (void)snprintf(p, sizeof(p), "%s/resp.peer.collect", e.resp);
        ASSERT(lsh_wf(p, body));
        ASSERT_EQ(lsh_run(&e, NULL), 0);
        ASSERT(strstr(g_lsh_out, "\"action\":\"offered\"") != NULL);
        ASSERT(lsh_has(e.calls, "\t--check=gate\n"));
        ASSERT(!lsh_has(e.calls, bottom));
        (void)snprintf(p, sizeof(p), "%s/shadow-offered.tsv", e.state);
        (void)snprintf(want, sizeof(want), "%s\tz23-stacks516\t%s\t", id, tip);
        ASSERT(lsh_has(p, want));
        ASSERT(lsh_has(p, "\t0\n")); /* rc0: the count before the final verdict */
        (void)snprintf(p, sizeof(p), "%s/shadow-compare.tsv", e.state);
        (void)snprintf(want, sizeof(want), "%s\tz23-stacks516\t%s\tpass\tpass\tyes\n", id, tip);
        ASSERT(lsh_has(p, want));
        /* the commit handed to the peer is a new single commit, not the tip */
        ASSERT(lsh_has(e.calls, "\t--commit="));
        (void)snprintf(want, sizeof(want), "--commit=%s", tip);
        ASSERT(!lsh_has(e.calls, want));
        ASSERT_EQ(lsh_run(&e, NULL), 0); /* a rerun offers nothing twice */
        ASSERT(strstr(g_lsh_out, "ALREADY_OFFERED") != NULL);
    } TEST_END
    return failures;
}

static int case_refused(void)
{
    int failures = 0;
    struct lsh e;
    char tip[64], bottom[64], p[800], id[65], row[400], want[400];
    TEST_CASE("lab_peer shadow: a peer refusal is logged n/a, a peer failure disagrees with an r1 pass") {
        ASSERT(lsh_setup(&e, "refused") && lsh_repo(&e, "z23-stacks517", 1, tip, bottom));
        ASSERT(lsh_gate(&e, "z23-stacks517", "gating\nrc=0\n", NULL));
        (void)snprintf(id, sizeof(id), "%064d", 6);
        (void)snprintf(p, sizeof(p), "%s/shadow-offered.tsv", e.state);
        (void)snprintf(row, sizeof(row), "%s\tz23-stacks517\t%s\t1\t0\n", id, tip);
        ASSERT(lsh_wf(p, row));
        (void)snprintf(p, sizeof(p), "%s/resp.peer.collect", e.resp);
        ASSERT(lsh_wf(p, "{\"ok\":true,\"items\":[]}\n"));
        (void)snprintf(p, sizeof(p), "%s/resp.fleet.board.list", e.resp);
        (void)snprintf(row, sizeof(row), "x offer=%s verdict=refused code=REVERIFY_LINT_FAILED\n", id);
        ASSERT(lsh_wf(p, row));
        ASSERT_EQ(lsh_run(&e, NULL), 0);
        (void)snprintf(p, sizeof(p), "%s/shadow-compare.tsv", e.state);
        (void)snprintf(want, sizeof(want), "%s\tz23-stacks517\t%s\tpass\trefused:REVERIFY_LINT_FAILED\tn/a\n", id, tip);
        ASSERT(lsh_has(p, want));
    } TEST_END
    return failures;
}

static int case_usage(void)
{
    int failures = 0;
    struct lsh e;
    const char *const bad[] = {"--bogus=1", NULL};
    const char *const badcheck[] = {"--check=nope", NULL};
    TEST_CASE("lab_peer shadow: an unknown option or check is a usage error") {
        ASSERT(lsh_setup(&e, "usage"));
        ASSERT_EQ(lsh_run(&e, bad), 2);
        ASSERT_EQ(lsh_run(&e, badcheck), 2);
    } TEST_END
    return failures;
}

int test_lab_peer_shadow(void)
{
    int failures = 0;
    struct stat st;
    if (stat(LSH_BIN, &st) != 0 || stat(LSH_FAKE, &st) != 0) {
        printf("lab_peer_shadow: FAIL (%s and %s are required test prerequisites)\n", LSH_BIN, LSH_FAKE);
        return 1;
    }
    failures += case_final_tip();
    failures += case_not_finished();
    failures += case_single_and_bridge();
    failures += case_live();
    failures += case_refused();
    failures += case_usage();
    return failures;
}
