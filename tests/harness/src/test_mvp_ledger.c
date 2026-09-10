/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the MVP experiment ledger measures a synthetic session exactly —
 *          one API request's tokens counted once however many assistant
 *          lines carry it, a workflow agent attributed to its design, the
 *          orchestrator counted separately — refuses a malformed transcript
 *          line and an over-long line BY LINE NUMBER, refuses a ledger whose
 *          header moved, and renders the plan of record byte-for-byte as the
 *          shell stopgap it replaces did.
 *
 * NOT proven here: that build/bin/z23-mvp-ledger's argument parsing wires
 * every mode to these functions — that is one switch in
 * tools/dev/mvp_ledger_main.c, exercised by running the tool. This group
 * proves the measurement the CLI calls. */
#include "test/test_core.h"

#include "mvp_ledger.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── fixtures ─────────────────────────────────────────────────────────── */

static void mvl_write_file(const char *dir, const char *name, const char *body)
{
    char path[PATH_MAX];
    FILE *f;

    (void)snprintf(path, sizeof(path), "%s/%s", dir, name);
    f = fopen(path, "w");
    if (!f)
        return;
    (void)fputs(body, f);
    (void)fclose(f);
}

static void mvl_mkdir(const char *parent, const char *name)
{
    char path[PATH_MAX];

    (void)snprintf(path, sizeof(path), "%s/%s", parent, name);
    (void)mkdir(path, 0700);
}

/* One assistant line. `req` is the API request id: two lines sharing one id
 * are two content blocks of ONE request and must be charged once. */
static void mvl_assistant(char *out, size_t cap, const char *req,
                          const char *stamp, int in, int cc, int cr, int outt,
                          int think, const char *content)
{
    (void)snprintf(out, cap,
                   "{\"type\":\"assistant\",\"requestId\":\"%s\","
                   "\"timestamp\":\"%s\",\"message\":{\"role\":\"assistant\","
                   "\"model\":\"claude-opus-5\",\"usage\":{"
                   "\"input_tokens\":%d,\"cache_creation_input_tokens\":%d,"
                   "\"cache_read_input_tokens\":%d,\"output_tokens\":%d,"
                   "\"output_tokens_details\":{\"thinking_tokens\":%d}},"
                   "\"content\":[%s]}}\n",
                   req, stamp, in, cc, cr, outt, think, content);
}

static void mvl_reminder(char *out, size_t cap, long left)
{
    (void)snprintf(out, cap,
                   "{\"type\":\"attachment\",\"attachment\":{\"type\":"
                   "\"total_tokens_reminder\",\"text\":\"<total_tokens>%ld"
                   " tokens left</total_tokens>\"}}\n", left);
}

/* A three-agent session: a build lane whose first request is split across
 * two assistant lines, its verifier, one workflow (design) agent, and the
 * orchestrator's own transcript beside the directory. */
static void mvl_build_session(const char *root)
{
    char body[4096];
    char line[1024];
    char subs[PATH_MAX];
    char wf[PATH_MAX];

    mvl_mkdir(root, "sess");
    (void)snprintf(subs, sizeof(subs), "%s/sess/subagents", root);
    mvl_mkdir(root, "sess/subagents");
    mvl_mkdir(root, "sess/subagents/workflows");
    mvl_mkdir(root, "sess/subagents/workflows/wf_demo");
    (void)snprintf(wf, sizeof(wf), "%s/sess/subagents/workflows/wf_demo",
                   root);

    body[0] = '\0';
    (void)strcat(body, "{\"type\":\"user\",\"message\":{\"role\":\"user\"}}\n");
    mvl_assistant(line, sizeof(line), "r1", "2026-09-08T09:00:00.000Z",
                  10, 100, 1000, 50, 7,
                  "{\"type\":\"text\",\"text\":\"working\"},"
                  "{\"type\":\"tool_use\",\"name\":\"Bash\"}");
    (void)strcat(body, line);
    mvl_assistant(line, sizeof(line), "r1", "2026-09-08T09:00:05.000Z",
                  10, 100, 1000, 50, 7,
                  "{\"type\":\"tool_use\",\"name\":\"Read\"}");
    (void)strcat(body, line);
    mvl_reminder(line, sizeof(line), 1000000);
    (void)strcat(body, line);
    mvl_assistant(line, sizeof(line), "r2", "2026-09-08T09:10:00.000Z",
                  2, 200, 2000, 30, 3,
                  "{\"type\":\"text\",\"text\":\"READY at last\"}");
    (void)strcat(body, line);
    mvl_reminder(line, sizeof(line), 900000);
    (void)strcat(body, line);
    mvl_write_file(subs, "agent-a1.jsonl", body);
    mvl_write_file(subs, "agent-a1.meta.json",
                   "{\"description\":\"Lane alpha: build the thing\","
                   "\"model\":\"opus\"}\n");

    mvl_assistant(body, sizeof(body), "r9", "2026-09-08T09:20:00.000Z",
                  5, 50, 500, 20, 0,
                  "{\"type\":\"text\",\"text\":\"# VERDICT: LAND `"
                  "0123456789abcdef0123456789abcdef01234567`\"}");
    mvl_write_file(subs, "agent-a2.jsonl", body);
    mvl_write_file(subs, "agent-a2.meta.json",
                   "{\"description\":\"Verify alpha lane\"}\n");

    mvl_assistant(body, sizeof(body), "r5", "2026-09-08T09:05:00.000Z",
                  1, 10, 100, 5, 0,
                  "{\"type\":\"text\",\"text\":\"design note\"}");
    mvl_write_file(wf, "agent-a3.jsonl", body);
    mvl_write_file(wf, "agent-a3.meta.json",
                   "{\"agentType\":\"workflow-subagent\"}\n");

    mvl_assistant(body, sizeof(body), "r0", "2026-09-08T08:00:00.000Z",
                  3, 30, 300, 9, 0,
                  "{\"type\":\"tool_use\",\"name\":\"Task\"}");
    mvl_write_file(root, "sess.jsonl", body);
}

static const char k_plan[] =
"M00 Alpha milestone | done=alpha is done\n"
"  F01 Feature one\n"
"    L01 First loop | state=LANDED | loop=alpha | evidence="
    "0123456789abcdef0123456789abcdef01234567 | box=node1\n"
"    L02 Second loop | state=TRAIN | loop=beta | evidence=- | box=node1\n"
"    L02b Extra evidence | state=READY | loop=alpha | evidence=- | box=node1\n"
"    L03 Third loop | state=QUEUED | loop=- | evidence=- | box=-\n"
"M01 Beta milestone | done=beta is done\n"
"  F01 Feature one\n"
"    L01 Fourth loop | state=VERIFY_FIRST | loop=- | evidence=- | box=-\n"
"    L02 Fifth loop | state=DESIGNING | loop=wf_demo | evidence=wf_demo"
    " | box=node1\n"
"    L03 Sixth loop | state=IN-FLIGHT | loop=gamma | evidence=- | box=node1\n"
"M02 Gamma milestone | done=gamma is done\n"
"  F01 Feature one\n"
"    L01 Seventh loop | state=DROPPED | loop=- | evidence=- | box=-\n"
"    L02 Eighth loop | state=QUEUED | loop=- | evidence=- | box=-\n"
"    L03 Ninth loop | state=QUEUED | loop=- | evidence=- | box=-\n";

/* One row per evidence shape the experiment defines. Kept apart from k_plan
 * so the byte-for-byte progress render below stays pinned to twelve loops. */
static const char k_evidence_plan[] =
"M00 Evidence shapes | done=every shape is decided\n"
"  F01 Shapes\n"
"    L01 A commit | state=LANDED | loop=one | evidence="
    "0123456789abcdef0123456789abcdef01234567 | box=node1\n"
"    L02 A landed range | state=LANDED | loop=two | evidence="
    "9999999999..0123456789abcdef0123456789abcdef01234567 | box=node1\n"
"    L03 An unlanded range | state=LANDED | loop=three | evidence="
    "0123456789..bbbbbbbbbbbbbbbb | box=node1\n"
"    L04 A registered sweep | state=LANDED | loop=four | evidence="
    "ONLY=mvp_ledger | box=node1\n"
"    L05 A vanished sweep | state=LANDED | loop=five | evidence="
    "ONLY=ghost_group | box=node1\n"
"    L06 A doc path | state=LANDED | loop=six | evidence="
    "docs/DEVELOPING.md | box=node1\n"
"    L07 Two commits | state=LANDED | loop=seven | evidence="
    "0123456789abcdef0123456789abcdef01234567,fedcba9876543210 | box=node1\n"
"    L08 One commit still in flight | state=LANDED | loop=eight | evidence="
    "0123456789abcdef0123456789abcdef01234567,cccccccccccccccc | box=node1\n";

/* A test_group_catalog.def as `git show <ref>:…` hands it over. */
static const char k_catalog[] =
"/* Copyright 2026 Rhett Creighton - Apache License 2.0 */\n"
"ZCL_TEST_GROUP(mvp_ledger)\n"
"ZCL_TEST_GROUP(fleet_observe)\n";

/* Byte-for-byte the output of scratch/northstar/progress.sh on k_plan. */
static const char k_progress[] =
"       MILESTONE                                            12 LOOPS      "
"done   \xe2\x9c\x85 \xf0\x9f\x9a\x82 \xf0\x9f\x9f\xa1 \xe2\xac\x9c\n"
"\xf0\x9f\x94\xa7 M00 Alpha milestone                                     "
" \xe2\x96\x88\xe2\x96\x93\xc2\xb7  16%   1  1  0  1\n"
"\xf0\x9f\x94\xa7 M01 Beta milestone                                      "
" \xe2\x96\x92\xe2\x96\x92\xe2\x96\x91   0%   0  0  2  1\n"
"\xe2\xac\x9c M02 Gamma milestone                                     "
" \xc2\xb7\xc2\xb7x   0%   0  0  0  2\n"
"\nMVP  [\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88"
"\xe2\x96\x93\xe2\x96\x93\xe2\x96\x93\xe2\x96\x93\xe2\x96\x93"
"\xe2\x96\x92\xe2\x96\x92\xe2\x96\x92\xe2\x96\x92\xe2\x96\x92"
"\xe2\x96\x92\xe2\x96\x92\xe2\x96\x92\xe2\x96\x92\xe2\x96\x92"
"\xe2\x96\x91\xe2\x96\x91\xe2\x96\x91\xe2\x96\x91\xe2\x96\x91"
"\xe2\x96\x91\xe2\x96\x91\xe2\x96\x91\xe2\x96\x91\xe2\x96\x91"
"\xe2\x96\x91\xe2\x96\x91\xe2\x96\x91\xe2\x96\x91\xe2\x96\x91"
"\xe2\x96\x91\xe2\x96\x91\xe2\x96\x91\xe2\x96\x91\xe2\x96\x91"
"\xe2\x96\x91\xe2\x96\x91\xe2\x96\x91\xe2\x96\x91\xe2\x96\x91"
"\xe2\x96\x91\xe2\x96\x91\xe2\x96\x91] 2/9 verified (22%)\n"
"\xe2\x9c\x85 landed 1 \xc2\xb7 \xf0\x9f\x9a\x82 on a train 1 \xc2\xb7 "
"\xf0\x9f\x9f\xa1 ready/in-flight/designing 2 \xc2\xb7 \xe2\xac\x9c queued"
" or verify-first 4\n"
"legend: \xe2\x96\x88 landed  \xe2\x96\x93 on a train  \xe2\x96\x92"
" ready/in-flight/designing  \xe2\x96\x91 verify-first (capability may"
" already exist)  \xc2\xb7 queued\n";

static char *mvl_slurp(const char *path)
{
    FILE *f = fopen(path, "r");
    char *buf;
    size_t n;

    if (!f)
        return NULL;
    buf = calloc(1, 65536);
    if (!buf) {
        (void)fclose(f);
        return NULL;
    }
    n = fread(buf, 1, 65535, f);
    buf[n] = '\0';
    (void)fclose(f);
    return buf;
}

/* ── description and outcome vocabulary ───────────────────────────────── */

static int test_mvp_ledger_classify(void)
{
    int failures = 0;

    TEST("a description maps to exactly one (lane, kind) by the seven rules") {
        char lane[MVL_LANE_CAP], kind[MVL_KIND_CAP];
        struct mvl_names known = {0};

        ASSERT(mvl_names_alloc(&known, 8));
        ASSERT(mvl_names_add(&known, "hostgc"));
        ASSERT(mvl_names_add(&known, "landing"));
        mvl_classify_description("Lane hostgc: native host GC leaf", &known,
                                 lane, sizeof(lane), kind, sizeof(kind));
        ASSERT_STR_EQ(lane, "hostgc");
        ASSERT_STR_EQ(kind, "build");
        mvl_classify_description("Verify hostgc lane", &known, lane,
                                 sizeof(lane), kind, sizeof(kind));
        ASSERT_STR_EQ(lane, "hostgc");
        ASSERT_STR_EQ(kind, "verify");
        mvl_classify_description("Re-verify faillocator at 662861e", &known,
                                 lane, sizeof(lane), kind, sizeof(kind));
        ASSERT_STR_EQ(lane, "faillocator");
        ASSERT_STR_EQ(kind, "verify");
        mvl_classify_description("Assemble train 54", &known, lane,
                                 sizeof(lane), kind, sizeof(kind));
        ASSERT_STR_EQ(lane, "train54");
        ASSERT_STR_EQ(kind, "assemble");
        mvl_classify_description("Resume hostgc lane after the outage",
                                 &known, lane, sizeof(lane), kind,
                                 sizeof(kind));
        ASSERT_STR_EQ(lane, "hostgc");
        ASSERT_STR_EQ(kind, "build");
        mvl_names_free(&known);
        PASS();
    }

    TEST("a \"Fix …\" agent is attributed to the first word that names a "
         "lane that exists, and to none when no word does") {
        char lane[MVL_LANE_CAP], kind[MVL_KIND_CAP];
        struct mvl_names known = {0};

        ASSERT(mvl_names_alloc(&known, 8));
        ASSERT(mvl_names_add(&known, "hostgc"));
        ASSERT(mvl_names_add(&known, "landing"));
        mvl_classify_description("Fix the native landing machine", &known,
                                 lane, sizeof(lane), kind, sizeof(kind));
        ASSERT_STR_EQ(lane, "landing");
        ASSERT_STR_EQ(kind, "fix");
        mvl_classify_description("Resurrect hostgc after the crash", &known,
                                 lane, sizeof(lane), kind, sizeof(kind));
        ASSERT_STR_EQ(lane, "hostgc");
        ASSERT_STR_EQ(kind, "fix");
        /* No word names a lane: the work is still named, its lane is not
         * asserted. An English word must never be mistaken for a lane. */
        mvl_classify_description("Fix the broken gate", &known, lane,
                                 sizeof(lane), kind, sizeof(kind));
        ASSERT_STR_EQ(lane, "-");
        ASSERT_STR_EQ(kind, "fix");
        /* Without the lane set there is nothing to match against. */
        mvl_classify_description("Fix the native landing machine", NULL, lane,
                                 sizeof(lane), kind, sizeof(kind));
        ASSERT_STR_EQ(lane, "-");
        ASSERT_STR_EQ(kind, "fix");
        mvl_classify_description("Refresh generated metadata", &known, lane,
                                 sizeof(lane), kind, sizeof(kind));
        ASSERT_STR_EQ(lane, "-");
        ASSERT_STR_EQ(kind, "other");
        mvl_names_free(&known);
        PASS();
    }

    TEST("an outcome needs a sha, and markup between marker and sha is not "
         "part of the contract") {
        ASSERT_STR_EQ(mvl_match_outcome("LAND 0123456fabc done"), "LAND");
        ASSERT_STR_EQ(mvl_match_outcome("# VERDICT: LAND `0123456fabc`"),
                      "LAND");
        ASSERT_STR_EQ(mvl_match_outcome("FIX **0123456fabc**"), "FIX");
        ASSERT_STR_EQ(mvl_match_outcome("verdict FIX was written"), "-");
        ASSERT_STR_EQ(mvl_match_outcome("LAND soon"), "-");
        ASSERT_STR_EQ(mvl_match_outcome("wrote READY"), "READY");
        ASSERT_STR_EQ(mvl_match_outcome("BLOCKED on vendor"), "BLOCKED");
        ASSERT_STR_EQ(mvl_match_outcome("nothing to say"), "-");
        PASS();
    }

_test_next:;
    return failures;
}

/* ── the measured session ─────────────────────────────────────────────── */

static int test_mvp_ledger_agents(void)
{
    int failures = 0;

    TEST("a session measures to exact agents.tsv rows: one request charged "
         "once, the workflow agent attributed to its design, the "
         "orchestrator on its own row") {
        char tmp[PATH_MAX], sess[PATH_MAX], out[PATH_MAX];
        char err[MVL_ERR_CAP] = "";
        struct mvl_agents agents = {0};
        char *text;

        ASSERT(test_mkdtemp(tmp, sizeof(tmp), "mvpledger") != NULL);
        mvl_build_session(tmp);
        (void)snprintf(sess, sizeof(sess), "%s/sess", tmp);
        (void)snprintf(out, sizeof(out), "%s/agents.tsv", tmp);
        ASSERT(mvl_agents_alloc(&agents));
        ASSERT(mvl_scan_session(sess, NULL, &agents, err, sizeof(err)));
        ASSERT_EQ((int)agents.count, 4);
        ASSERT(mvl_write_agents(out, &agents, err, sizeof(err)));
        mvl_agents_free(&agents);

        text = mvl_slurp(out);
        ASSERT(text != NULL);
        ASSERT_STR_EQ(text,
"agent_id\tdescription\tlane\tkind\tmodel\tfirst_utc\tlast_utc\twall_s\t"
"turns\ttool_uses\ttokens_out\tthinking_tokens\ttokens_in\tinput_tokens\t"
"cache_creation_tokens\tcache_read_tokens\tharness_tokens\toutcome\n"
"a1\tLane alpha: build the thing\talpha\tbuild\tclaude-opus-5\t"
"2026-09-08T09:00:00.000Z\t2026-09-08T09:10:00.000Z\t600\t3\t2\t80\t10\t"
"3312\t12\t300\t3000\t100000\tREADY\n"
"a2\tVerify alpha lane\talpha\tverify\tclaude-opus-5\t"
"2026-09-08T09:20:00.000Z\t2026-09-08T09:20:00.000Z\t0\t1\t0\t20\t0\t555\t"
"5\t50\t500\t0\tLAND\n"
"a3\twf_demo\twf_demo\tdesign\tclaude-opus-5\t2026-09-08T09:05:00.000Z\t"
"2026-09-08T09:05:00.000Z\t0\t1\t0\t5\t0\t111\t1\t10\t100\t0\t-\n"
"sess\torchestrator session\torchestrator\torchestrator\tclaude-opus-5\t"
"2026-09-08T08:00:00.000Z\t2026-09-08T08:00:00.000Z\t0\t1\t1\t9\t0\t333\t"
"3\t30\t300\t0\t-\n");
        free(text);
        test_rm_rf_recursive(tmp);
        PASS();
    }

    TEST("agents.tsv round-trips: what is read back writes the same bytes") {
        char tmp[PATH_MAX], sess[PATH_MAX], a[PATH_MAX], b[PATH_MAX];
        char err[MVL_ERR_CAP] = "";
        struct mvl_agents agents = {0};
        char *first, *second;

        ASSERT(test_mkdtemp(tmp, sizeof(tmp), "mvpledger") != NULL);
        mvl_build_session(tmp);
        (void)snprintf(sess, sizeof(sess), "%s/sess", tmp);
        (void)snprintf(a, sizeof(a), "%s/a.tsv", tmp);
        (void)snprintf(b, sizeof(b), "%s/b.tsv", tmp);
        ASSERT(mvl_agents_alloc(&agents));
        ASSERT(mvl_scan_session(sess, NULL, &agents, err, sizeof(err)));
        ASSERT(mvl_write_agents(a, &agents, err, sizeof(err)));
        mvl_agents_free(&agents);

        ASSERT(mvl_agents_alloc(&agents));
        ASSERT(mvl_read_agents(a, &agents, err, sizeof(err)));
        ASSERT_EQ((int)agents.count, 4);
        ASSERT(mvl_write_agents(b, &agents, err, sizeof(err)));
        mvl_agents_free(&agents);

        first = mvl_slurp(a);
        second = mvl_slurp(b);
        ASSERT(first != NULL);
        ASSERT(second != NULL);
        ASSERT_STR_EQ(first, second);
        free(first);
        free(second);
        test_rm_rf_recursive(tmp);
        PASS();
    }

_test_next:;
    return failures;
}

/* ── refusals ─────────────────────────────────────────────────────────── */

static int test_mvp_ledger_refusals(void)
{
    int failures = 0;

    TEST("a malformed transcript line is refused by its line number, not "
         "skipped") {
        char tmp[PATH_MAX], path[PATH_MAX];
        char err[MVL_ERR_CAP] = "";
        struct mvl_agent agent;
        char body[2048];
        char line[1024];

        ASSERT(test_mkdtemp(tmp, sizeof(tmp), "mvpledger") != NULL);
        body[0] = '\0';
        (void)strcat(body, "{\"type\":\"user\"}\n");
        mvl_assistant(line, sizeof(line), "r1", "2026-09-08T09:00:00.000Z",
                      1, 1, 1, 1, 0, "{\"type\":\"text\",\"text\":\"x\"}");
        (void)strcat(body, line);
        (void)strcat(body, "{\"type\": not json at all\n");
        mvl_write_file(tmp, "t.jsonl", body);
        (void)snprintf(path, sizeof(path), "%s/t.jsonl", tmp);

        memset(&agent, 0, sizeof(agent));
        ASSERT(!mvl_scan_transcript(path, &agent, err, sizeof(err)));
        ASSERT(strstr(err, ":3:") != NULL);
        ASSERT(strstr(err, "mvl_bad_json") != NULL);
        test_rm_rf_recursive(tmp);
        PASS();
    }

    TEST("a one-megabyte single line is refused, so no input can grow the "
         "reader without bound") {
        char tmp[PATH_MAX], path[PATH_MAX];
        char err[MVL_ERR_CAP] = "";
        struct mvl_agent agent;
        char *big = calloc(1, 1024 * 1024 + 8);
        FILE *f;

        ASSERT(test_mkdtemp(tmp, sizeof(tmp), "mvpledger") != NULL);
        ASSERT(big != NULL);
        memset(big, 'a', 1024 * 1024);
        (void)snprintf(path, sizeof(path), "%s/big.jsonl", tmp);
        f = fopen(path, "w");
        ASSERT(f != NULL);
        (void)fputs("{\"type\":\"user\"}\n", f);
        (void)fputs(big, f);
        (void)fputs("\n", f);
        (void)fclose(f);
        free(big);

        memset(&agent, 0, sizeof(agent));
        ASSERT(!mvl_scan_transcript(path, &agent, err, sizeof(err)));
        ASSERT(strstr(err, ":2:") != NULL);
        ASSERT(strstr(err, "mvl_line_too_long") != NULL);
        test_rm_rf_recursive(tmp);
        PASS();
    }

    TEST("an append refuses a ledger whose header is not this build's") {
        char tmp[PATH_MAX], snap[PATH_MAX], kpi[PATH_MAX];
        char err[MVL_ERR_CAP] = "";
        struct mvl_plan plan = {0};
        struct mvl_agents agents = {0};
        struct mvl_kpi k = {0};

        ASSERT(test_mkdtemp(tmp, sizeof(tmp), "mvpledger") != NULL);
        mvl_write_file(tmp, "snapshots.tsv", "utc\tlanded\tmid\tnote\n");
        mvl_write_file(tmp, "kpi.tsv", "utc\tverified\tnote\n");
        (void)snprintf(snap, sizeof(snap), "%s/snapshots.tsv", tmp);
        (void)snprintf(kpi, sizeof(kpi), "%s/kpi.tsv", tmp);
        ASSERT(mvl_plan_alloc(&plan));
        ASSERT(mvl_agents_alloc(&agents));

        ASSERT(!mvl_append_snapshot(snap, &plan, &agents,
                                    "2026-09-08T00:00:00Z", "-", "-", err,
                                    sizeof(err)));
        ASSERT(strstr(err, ":1:") != NULL);
        ASSERT(strstr(err, "mvl_tsv_header") != NULL);
        ASSERT(!mvl_append_kpi(kpi, &k, "2026-09-08T00:00:00Z", "w", "-", err,
                               sizeof(err)));
        ASSERT(strstr(err, ":1:") != NULL);
        ASSERT(strstr(err, "mvl_tsv_header") != NULL);

        mvl_agents_free(&agents);
        mvl_plan_free(&plan);
        test_rm_rf_recursive(tmp);
        PASS();
    }

_test_next:;
    return failures;
}

/* ── the plan of record ───────────────────────────────────────────────── */

static int test_mvp_ledger_plan(void)
{
    int failures = 0;

    TEST("the plan parses to the 144-rule universe and renders byte-for-byte "
         "as the shell stopgap did") {
        char tmp[PATH_MAX], path[PATH_MAX];
        char err[MVL_ERR_CAP] = "";
        struct mvl_plan plan = {0};
        char render[8192];
        size_t n;

        ASSERT(test_mkdtemp(tmp, sizeof(tmp), "mvpledger") != NULL);
        mvl_write_file(tmp, "plan.md", k_plan);
        (void)snprintf(path, sizeof(path), "%s/plan.md", tmp);
        ASSERT(mvl_plan_alloc(&plan));
        ASSERT(mvl_parse_plan(path, &plan, err, sizeof(err)));
        ASSERT_EQ((int)plan.loop_count, 10);
        ASSERT_EQ((int)plan.universe, 9);
        ASSERT_EQ((int)plan.milestone_count, 3);
        ASSERT_STR_EQ(plan.loops[2].id, "M00.F01.L02b");
        ASSERT(!plan.loops[2].counted);
        ASSERT_STR_EQ(plan.loops[0].title, "First loop");

        n = mvl_render_progress(&plan, render, sizeof(render));
        ASSERT(n < sizeof(render));
        ASSERT_STR_EQ(render, k_progress);
        mvl_plan_free(&plan);
        test_rm_rf_recursive(tmp);
        PASS();
    }

    TEST("a loop line missing a required field is refused by line number") {
        char tmp[PATH_MAX], path[PATH_MAX];
        char err[MVL_ERR_CAP] = "";
        struct mvl_plan plan = {0};

        ASSERT(test_mkdtemp(tmp, sizeof(tmp), "mvpledger") != NULL);
        mvl_write_file(tmp, "bad.md",
                       "M00 A | done=x\n"
                       "  F01 F\n"
                       "    L01 Fine | state=QUEUED | loop=- | evidence=-\n"
                       "    L02 Broken | state=QUEUED | box=-\n");
        (void)snprintf(path, sizeof(path), "%s/bad.md", tmp);
        ASSERT(mvl_plan_alloc(&plan));
        ASSERT(!mvl_parse_plan(path, &plan, err, sizeof(err)));
        ASSERT(strstr(err, ":4:") != NULL);
        ASSERT(strstr(err, "mvl_plan_field") != NULL);
        mvl_plan_free(&plan);
        test_rm_rf_recursive(tmp);
        PASS();
    }

_test_next:;
    return failures;
}

/* ── the join and the KPI ─────────────────────────────────────────────── */

static int test_mvp_ledger_join(void)
{
    int failures = 0;

    TEST("agents join their lane's loops, a design workflow is split across "
         "the loops its evidence names, and ancestry decides landed") {
        char tmp[PATH_MAX], sess[PATH_MAX], plan_path[PATH_MAX];
        char err[MVL_ERR_CAP] = "";
        struct mvl_plan plan = {0};
        struct mvl_agents agents = {0};
        struct mvl_join joins[MVL_MAX_LOOPS];
        struct mvl_evidence_world world = {0};
        char anc[2][MVL_ID_CAP];

        ASSERT(test_mkdtemp(tmp, sizeof(tmp), "mvpledger") != NULL);
        mvl_build_session(tmp);
        mvl_write_file(tmp, "plan.md", k_plan);
        (void)snprintf(sess, sizeof(sess), "%s/sess", tmp);
        (void)snprintf(plan_path, sizeof(plan_path), "%s/plan.md", tmp);
        memset(anc, 0, sizeof(anc));
        (void)snprintf(anc[0], sizeof(anc[0]),
                       "0123456789abcdef0123456789abcdef01234567");
        ASSERT(mvl_plan_alloc(&plan));
        ASSERT(mvl_agents_alloc(&agents));
        ASSERT(mvl_parse_plan(plan_path, &plan, err, sizeof(err)));
        ASSERT(mvl_scan_session(sess, NULL, &agents, err, sizeof(err)));

        world.ancestry = (const char (*)[MVL_ID_CAP])anc;
        world.ancestry_count = 1;
        mvl_join_loops(&plan, &agents, NULL, &world, joins);
        /* M00.F01.L01 is lane alpha: its builder and its verifier. */
        ASSERT_EQ((int)joins[0].agents, 2);
        ASSERT_EQ((int)joins[0].verifier_rounds, 1);
        ASSERT_EQ((int)joins[0].tokens_out, 100);
        ASSERT_EQ((int)joins[0].tokens_in, 3867);
        ASSERT_EQ((int)joins[0].tool_uses, 2);
        ASSERT_EQ((int)joins[0].wall_s, 600);
        ASSERT_EQ(joins[0].landed, 1);
        ASSERT_STR_EQ(mvl_verified_by_name(joins[0].verified_by), "landed");
        /* M00.F01.L02 is lane beta: nobody worked it, and its evidence is
         * not a sha at all. */
        ASSERT_EQ((int)joins[1].agents, 0);
        ASSERT_EQ(joins[1].landed, 0);
        /* M01.F01.L02 names workflow wf_demo in its evidence. */
        ASSERT_EQ((int)joins[5].agents, 1);
        ASSERT_EQ((int)joins[5].tokens_out, 5);

        mvl_agents_free(&agents);
        mvl_plan_free(&plan);
        test_rm_rf_recursive(tmp);
        PASS();
    }

    TEST("a verifier's LAND verdict makes its lane's base loop count once, "
         "and a FIX verdict counts for nothing") {
        char tmp[PATH_MAX], scratch[PATH_MAX], plan_path[PATH_MAX];
        char err[MVL_ERR_CAP] = "";
        struct mvl_names lanes = {0};
        struct mvl_plan plan = {0};
        struct mvl_agents agents = {0};
        struct mvl_kpi kpi = {0};
        struct mvl_evidence_world world = {0};

        ASSERT(test_mkdtemp(tmp, sizeof(tmp), "mvpledger") != NULL);
        mvl_mkdir(tmp, "scratch");
        mvl_mkdir(tmp, "scratch/valpha2");
        mvl_mkdir(tmp, "scratch/vbeta");
        mvl_mkdir(tmp, "scratch/northstar");
        (void)snprintf(scratch, sizeof(scratch), "%s/scratch", tmp);
        mvl_write_file(tmp, "scratch/valpha2/VERDICT",
                       "LAND 0123456789abcdef0123456789abcdef01234567\n");
        mvl_write_file(tmp, "scratch/vbeta/VERDICT",
                       "FIX aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n");
        mvl_write_file(tmp, "plan.md", k_plan);
        (void)snprintf(plan_path, sizeof(plan_path), "%s/plan.md", tmp);

        ASSERT(mvl_names_alloc(&lanes, 8));
        ASSERT(mvl_verified_lanes(scratch, 0, &lanes, err, sizeof(err)));
        ASSERT_EQ((int)lanes.count, 1);
        ASSERT_STR_EQ(lanes.rows[0], "alpha");

        ASSERT(mvl_plan_alloc(&plan));
        ASSERT(mvl_agents_alloc(&agents));
        ASSERT(mvl_parse_plan(plan_path, &plan, err, sizeof(err)));
        world.verdict_lanes = &lanes;
        mvl_compute_kpi(&plan, &agents, &world, &kpi);
        /* alpha owns one base loop (L01) and one sub-row (L02b). */
        ASSERT_EQ((int)kpi.verified_loops, 1);
        ASSERT_EQ((int)kpi.verified_subrows, 1);
        /* Without an ancestry list nothing is landed, and "not asked" must
         * never be reported as a landing. */
        ASSERT_EQ((int)kpi.landed_loops, 0);
        mvl_names_free(&lanes);
        mvl_agents_free(&agents);
        mvl_plan_free(&plan);
        test_rm_rf_recursive(tmp);
        PASS();
    }

    TEST("TCU prices each token view exactly, in integer hundredths") {
        struct mvl_agents agents = {0};
        struct mvl_plan plan = {0};
        struct mvl_kpi kpi = {0};

        ASSERT(mvl_plan_alloc(&plan));
        ASSERT(mvl_agents_alloc(&agents));
        agents.rows[0].tokens_out = 1000;
        agents.rows[0].tokens_input = 1000;
        agents.rows[0].tokens_cache_creation = 1000;
        agents.rows[0].tokens_cache_read = 1000;
        agents.rows[0].tokens_in = 3000;
        agents.count = 1;
        mvl_compute_kpi(&plan, &agents, &(struct mvl_evidence_world){0}, &kpi);
        ASSERT_EQ((int)kpi.tokens_raw, 4000);
        ASSERT_EQ((int)kpi.tokens_out, 1000);
        /* 1000*5 + 1000*1 + 1000*1.25 + 1000*0.1 = 7350 */
        ASSERT_EQ((int)kpi.tcu, 7350);
        mvl_agents_free(&agents);
        mvl_plan_free(&plan);
        PASS();
    }

    TEST("kpi sums every --session's tokens into one denominator: one "
         "session matches the known single-session totals byte-identically, "
         "and scanning a second session into the same table sums exactly, "
         "not by adding two separately rounded per-session TCUs") {
        char tmp1[PATH_MAX], tmp2[PATH_MAX], sess1[PATH_MAX], sess2[PATH_MAX];
        char err[MVL_ERR_CAP] = "";
        struct mvl_plan plan = {0};
        struct mvl_agents agents = {0};
        struct mvl_kpi kpi = {0};
        struct mvl_evidence_world world = {0};

        ASSERT(test_mkdtemp(tmp1, sizeof(tmp1), "mvpledger") != NULL);
        ASSERT(test_mkdtemp(tmp2, sizeof(tmp2), "mvpledger") != NULL);
        mvl_build_session(tmp1);
        mvl_build_session(tmp2);
        (void)snprintf(sess1, sizeof(sess1), "%s/sess", tmp1);
        (void)snprintf(sess2, sizeof(sess2), "%s/sess", tmp2);

        ASSERT(mvl_plan_alloc(&plan));
        ASSERT(mvl_agents_alloc(&agents));

        /* One --session: byte-identical to the totals test_mvp_ledger_agents
         * proves agents.tsv carries for this fixture (tokens_out 80+20+5+9,
         * tokens_in 3312+555+111+333). */
        ASSERT(mvl_scan_session(sess1, NULL, &agents, err, sizeof(err)));
        ASSERT_EQ((int)agents.count, 4);
        mvl_compute_kpi(&plan, &agents, &world, &kpi);
        ASSERT_EQ((int)kpi.tokens_out, 114);
        ASSERT_EQ((int)kpi.tokens_raw, 4425);
        ASSERT_EQ((int)kpi.tcu, 1468);

        /* A second --session folds into the SAME agents table (exactly what
         * mvl_scan_with_lanes in mvp_ledger_main.c does once per repeated
         * flag), so the denominator sums both sessions' tokens before TCU is
         * priced once — not 1468+1468=2936, which is what adding two
         * independently-rounded per-session TCUs would give. */
        ASSERT(mvl_scan_session(sess2, NULL, &agents, err, sizeof(err)));
        ASSERT_EQ((int)agents.count, 8);
        mvl_compute_kpi(&plan, &agents, &world, &kpi);
        ASSERT_EQ((int)kpi.tokens_out, 228);
        ASSERT_EQ((int)kpi.tokens_raw, 8850);
        ASSERT_EQ((int)kpi.tcu, 2937);

        mvl_agents_free(&agents);
        mvl_plan_free(&plan);
        test_rm_rf_recursive(tmp1);
        test_rm_rf_recursive(tmp2);
        PASS();
    }

_test_next:;
    return failures;
}

/* ── what each evidence shape can prove ───────────────────────────────── */

static int test_mvp_ledger_evidence(void)
{
    int failures = 0;

    TEST("the shape of an evidence field decides what it can prove") {
        ASSERT_EQ((int)mvl_evidence_kind_of("-"), (int)MVL_EVIDENCE_NONE);
        ASSERT_EQ((int)mvl_evidence_kind_of(""), (int)MVL_EVIDENCE_NONE);
        ASSERT_EQ((int)mvl_evidence_kind_of("0123456789abcdef"),
                  (int)MVL_EVIDENCE_COMMIT);
        ASSERT_EQ((int)mvl_evidence_kind_of("0123456789,fedcba9876"),
                  (int)MVL_EVIDENCE_COMMIT);
        ASSERT_EQ((int)mvl_evidence_kind_of("35ce708789..9423aaece3"),
                  (int)MVL_EVIDENCE_RANGE);
        ASSERT_EQ((int)mvl_evidence_kind_of("ONLY=wallet_backup"),
                  (int)MVL_EVIDENCE_SWEEP);
        ASSERT_EQ((int)mvl_evidence_kind_of("docs/DEVELOPING.md"),
                  (int)MVL_EVIDENCE_OTHER);
        ASSERT_EQ((int)mvl_evidence_kind_of("wf_29284f91-171,wf_bdb64e24-7aa"),
                  (int)MVL_EVIDENCE_OTHER);
        /* Six hex characters are a word that happens to be hex, not a sha:
         * git's own shortest unambiguous abbreviation is seven. */
        ASSERT_EQ((int)mvl_evidence_kind_of("decade"),
                  (int)MVL_EVIDENCE_OTHER);
        PASS();
    }

    TEST("a sweep verifies when its group is registered at the ref, refuses "
         "by name when it is not, and a doc path never verifies") {
        char tmp[PATH_MAX], plan_path[PATH_MAX], cat_path[PATH_MAX];
        char err[MVL_ERR_CAP] = "";
        struct mvl_plan plan = {0};
        struct mvl_agents agents = {0};
        struct mvl_kpi kpi = {0};
        struct mvl_names groups = {0};
        struct mvl_evidence_world world = {0};
        char anc[2][MVL_ID_CAP];
        FILE *sink;

        ASSERT(test_mkdtemp(tmp, sizeof(tmp), "mvpledger") != NULL);
        mvl_write_file(tmp, "plan.md", k_evidence_plan);
        mvl_write_file(tmp, "catalog.def", k_catalog);
        (void)snprintf(plan_path, sizeof(plan_path), "%s/plan.md", tmp);
        (void)snprintf(cat_path, sizeof(cat_path), "%s/catalog.def", tmp);
        memset(anc, 0, sizeof(anc));
        (void)snprintf(anc[0], sizeof(anc[0]),
                       "0123456789abcdef0123456789abcdef01234567");
        (void)snprintf(anc[1], sizeof(anc[1]),
                       "fedcba9876543210fedcba9876543210fedcba98");

        ASSERT(mvl_names_alloc(&groups, 16));
        ASSERT(mvl_read_groups(cat_path, &groups, err, sizeof(err)));
        ASSERT_EQ((int)groups.count, 2);
        ASSERT(mvl_names_has(&groups, "mvp_ledger"));
        ASSERT(!mvl_names_has(&groups, "ghost_group"));

        ASSERT(mvl_plan_alloc(&plan));
        ASSERT(mvl_agents_alloc(&agents));
        ASSERT(mvl_parse_plan(plan_path, &plan, err, sizeof(err)));
        world.ancestry = (const char (*)[MVL_ID_CAP])anc;
        world.ancestry_count = 2;
        world.groups = &groups;

        ASSERT_STR_EQ(mvl_verified_by_name(
                          mvl_loop_verified_by(&plan.loops[0], &world)),
                      "landed");
        ASSERT_STR_EQ(mvl_verified_by_name(
                          mvl_loop_verified_by(&plan.loops[1], &world)),
                      "landed");
        /* `a..b` is proved by b alone; an unlanded b is not a landing. */
        ASSERT_STR_EQ(mvl_verified_by_name(
                          mvl_loop_verified_by(&plan.loops[2], &world)), "-");
        ASSERT_STR_EQ(mvl_verified_by_name(
                          mvl_loop_verified_by(&plan.loops[3], &world)),
                      "sweep");
        ASSERT_STR_EQ(mvl_verified_by_name(
                          mvl_loop_verified_by(&plan.loops[4], &world)),
                      "sweep_group_unregistered");
        ASSERT_STR_EQ(mvl_verified_by_name(
                          mvl_loop_verified_by(&plan.loops[5], &world)), "-");
        ASSERT_STR_EQ(mvl_verified_by_name(
                          mvl_loop_verified_by(&plan.loops[6], &world)),
                      "landed");
        /* Every sha of a list must be an ancestor: one still in flight
         * means the work the row cites is not all landed. */
        ASSERT_STR_EQ(mvl_verified_by_name(
                          mvl_loop_verified_by(&plan.loops[7], &world)), "-");

        mvl_compute_kpi(&plan, &agents, &world, &kpi);
        ASSERT_EQ((int)kpi.verified_loops, 4);
        ASSERT_EQ((int)kpi.landed_loops, 3);
        ASSERT_EQ((int)kpi.sweep_loops, 1);
        ASSERT_EQ((int)kpi.sweep_unregistered, 1);

        /* The refusal has to reach a reader, and name the plan line. */
        (void)snprintf(cat_path, sizeof(cat_path), "%s/refusals.txt", tmp);
        sink = fopen(cat_path, "w");
        ASSERT(sink != NULL);
        ASSERT_EQ((int)mvl_report_sweep_refusals(&plan, &world, plan_path,
                                                 sink), 1);
        (void)fclose(sink);
        {
            char *text = mvl_slurp(cat_path);

            ASSERT(text != NULL);
            ASSERT(strstr(text, ":7:") != NULL);
            ASSERT(strstr(text, "sweep_group_unregistered") != NULL);
            ASSERT(strstr(text, "ONLY=ghost_group") != NULL);
            free(text);
        }

        mvl_names_free(&groups);
        mvl_agents_free(&agents);
        mvl_plan_free(&plan);
        test_rm_rf_recursive(tmp);
        PASS();
    }

    TEST("without a catalog a sweep is not asked rather than refused, and "
         "without an ancestry a commit is not landed") {
        char tmp[PATH_MAX], plan_path[PATH_MAX];
        char err[MVL_ERR_CAP] = "";
        struct mvl_plan plan = {0};
        struct mvl_evidence_world world = {0};

        ASSERT(test_mkdtemp(tmp, sizeof(tmp), "mvpledger") != NULL);
        mvl_write_file(tmp, "plan.md", k_evidence_plan);
        (void)snprintf(plan_path, sizeof(plan_path), "%s/plan.md", tmp);
        ASSERT(mvl_plan_alloc(&plan));
        ASSERT(mvl_parse_plan(plan_path, &plan, err, sizeof(err)));
        ASSERT_STR_EQ(mvl_verified_by_name(
                          mvl_loop_verified_by(&plan.loops[0], &world)), "-");
        ASSERT_STR_EQ(mvl_verified_by_name(
                          mvl_loop_verified_by(&plan.loops[3], &world)),
                      "sweep_not_asked");
        ASSERT(!mvl_is_verified(mvl_loop_verified_by(&plan.loops[3], &world)));
        mvl_plan_free(&plan);
        test_rm_rf_recursive(tmp);
        PASS();
    }

_test_next:;
    return failures;
}

int test_mvp_ledger(void)
{
    int failures = 0;
    failures += test_mvp_ledger_classify();
    failures += test_mvp_ledger_agents();
    failures += test_mvp_ledger_refusals();
    failures += test_mvp_ledger_plan();
    failures += test_mvp_ledger_join();
    failures += test_mvp_ledger_evidence();
    return failures;
}
