/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Verify the resident plugin fetch job table: a job starts a bounded swarm
 * fetch, completes when the real engines deliver the root, then runs the same
 * plugin_dist_receive path `plugin fetch` uses. Every refusal from that path
 * arrives in the job status with its stable code, and the table, the active
 * count, the byte cap and the deadline are bounded. Peer handles are fixture
 * inputs; the image is inert and never executed. */
#include "test/plugin_dist_fixture.h"
#include "plugin/plugin_fetch_job.h"
#include "command/native_command.h"
#include "controllers/rpc_client.h"
#include "json/json.h"

#include <stdio.h>
#include <sys/stat.h>
#include <string.h>

struct pj {
    struct pd_fixture f;
    struct plugin_fetch_table *table;
    struct plugin_fetch_ctx ctx;
};

static bool pj_open(struct pj *p)
{
    memset(p, 0, sizeof(*p));
    p->table = plugin_fetch_table_new();
    if (!p->table || !pd_open(&p->f))
        return false;
    p->ctx = (struct plugin_fetch_ctx){
        .engine = p->f.receiver.engine, .store = p->f.receiver.store,
        .plugins_dir = p->f.plugins, .scratch_dir = p->f.scratch
    };
    return true;
}

static void pj_close(struct pj *p)
{
    plugin_fetch_table_free(p->table);
    pd_close(&p->f);
}

static void pj_request(struct plugin_fetch_request *rq, const uint8_t root[32])
{
    memset(rq, 0, sizeof(*rq));
    memcpy(rq->root, root, 32);
    rq->name = "demo";
}

/* Pump the engines and advance the table until the job is terminal. */
static bool pj_finish(struct pj *p, uint64_t job, struct plugin_fetch_view *v)
{
    for (uint64_t now = 2; now < 40; now++) {
        unsigned replies = 0;
        bool stopped = false;
        if (!pd_pump_tick(&p->f, now, 0, &replies, &stopped))
            return false;
        plugin_fetch_advance(p->table, &p->ctx, now);
        if (!plugin_fetch_status(p->table, job, v))
            return false;
        if (v->state == PLUGIN_FETCH_INSTALLED || v->state == PLUGIN_FETCH_FAILED)
            return true;
    }
    return false;
}

static bool pj_publish(struct pj *p, const char *leaf, const char *version, uint64_t seq,
                       struct plugin_pack_result *packed, struct plugin_dist_published *pub)
{
    return pd_pack(&p->f, leaf, version, packed) &&
           pd_publish(&p->f, leaf, seq, pub) == PLUGIN_DIST_OK;
}

static bool pj_begin_ok(struct pj *p, const uint8_t root[32], uint64_t *job)
{
    struct plugin_fetch_request rq;
    struct plugin_fetch_begin_result r;
    pj_request(&rq, root);
    plugin_fetch_begin(p->table, &p->ctx, &rq, 1, &r);
    *job = r.job;
    return r.status == PLUGIN_FETCH_BEGIN_OK && r.job != 0;
}

/* ---- 1. the whole journey -------------------------------------------- */
static int pj_journey(void)
{
    int failures = 0;
    struct pj p;
    TEST("plugin fetch job: swarm transfer then a pinned install as a new generation, never switching") {
        struct plugin_pack_result packed;
        struct plugin_dist_published pub;
        struct plugin_fetch_view v;
        uint64_t job = 0;
        ASSERT(pj_open(&p));
        ASSERT(pj_publish(&p, "packed1", "1.0.0", 1, &packed, &pub));
        ASSERT(pd_peers(&p.f));
        ASSERT(pd_keys(p.f.plugins, packed.public_key));
        ASSERT(pj_begin_ok(&p, pub.root, &job));
        ASSERT(plugin_fetch_status(p.table, job, &v));
        ASSERT_EQ(v.state, PLUGIN_FETCH_FETCHING);
        ASSERT(pj_finish(&p, job, &v));
        ASSERT_EQ(v.state, PLUGIN_FETCH_INSTALLED);
        ASSERT(strcmp(v.generation, packed.generation) == 0);
        ASSERT(!v.already_present);
        ASSERT(pd_generation_stored(&p.f, v.generation));
        ASSERT(pd_selection(&p.f, NULL));
        ASSERT(pd_scratch_empty(&p.f));
        /* Again: the root is local now, so the job installs from the store. */
        ASSERT(pj_begin_ok(&p, pub.root, &job));
        ASSERT(pj_finish(&p, job, &v));
        ASSERT_EQ(v.state, PLUGIN_FETCH_INSTALLED);
        ASSERT(v.already_present);
        ASSERT(pd_selection(&p.f, NULL));
        PASS();
    } _test_next:;
    pj_close(&p);
    return failures;
}

/* ---- 2. every plugin_dist refusal reaches the job status ---------------- */
static int pj_fail_with(struct pj *p, const uint8_t root[32], const char *code)
{
    struct plugin_fetch_view v;
    uint64_t job = 0;
    if (!pj_begin_ok(p, root, &job) || !pj_finish(p, job, &v))
        return 1;
    return v.state == PLUGIN_FETCH_FAILED && strcmp(v.code, code) == 0 &&
           v.next_action[0] && v.detail[0] ? 0 : 1;
}

static int pj_refusal_0(void)
{
    int failures = 0;
    struct pj p;
    TEST("plugin fetch job: an unpinned publisher is refused with its code and nothing is stored") {
        struct plugin_pack_result packed;
        struct plugin_dist_published pub;
        ASSERT(pj_open(&p));
        ASSERT(pj_publish(&p, "packed1", "1.0.0", 1, &packed, &pub));
        ASSERT(pd_peers(&p.f));
        ASSERT_EQ(pj_fail_with(&p, pub.root, "PLUGIN_DIST_PUBLISHER_UNPINNED"), 0);
        ASSERT(!pd_generation_stored(&p.f, packed.generation));
        ASSERT(pd_scratch_empty(&p.f));
        PASS();
    } _test_next:;
    pj_close(&p);
    return failures;
}

static int pj_refusal_1(void)
{
    int failures = 0;
    struct pj p;
    TEST("plugin fetch job: a changed image is refused with PLUGIN_DIST_IMAGE_HASH") {
        struct plugin_pack_result packed;
        struct plugin_dist_published pub;
        char exe[1400];
        ASSERT(pj_open(&p));
        ASSERT(pd_pack(&p.f, "packed1", "1.0.0", &packed));
        ASSERT(pd_path(exe, sizeof(exe), p.f.base, "packed1/demo"));
        chmod(exe, 0644);
        ASSERT(pd_write(exe, "tampered image\n", 15, 0644));
        plugin_dist_test_skip_source_check(true);
        enum plugin_dist_status ps = pd_publish(&p.f, "packed1", 1, &pub);
        plugin_dist_test_skip_source_check(false);
        ASSERT_EQ(ps, PLUGIN_DIST_OK);
        ASSERT(pd_peers(&p.f));
        ASSERT(pd_keys(p.f.plugins, packed.public_key));
        ASSERT_EQ(pj_fail_with(&p, pub.root, "PLUGIN_DIST_IMAGE_HASH"), 0);
        ASSERT(!pd_generation_stored(&p.f, packed.generation));
        PASS();
    } _test_next:;
    plugin_dist_test_skip_source_check(false);
    pj_close(&p);
    return failures;
}

static int pj_refusal_2(void)
{
    int failures = 0;
    struct pj p;
    TEST("plugin fetch job: a lower version is refused with PLUGIN_DIST_DOWNGRADE") {
        struct plugin_pack_result v1, v2;
        struct plugin_dist_published pub1;
        struct plugin_manifest m;
        int present = 0;
        ASSERT(pj_open(&p));
        ASSERT(pd_pack(&p.f, "packed1", "1.0.0", &v1));
        ASSERT(pd_pack(&p.f, "packed2", "2.0.0", &v2));
        ASSERT(pd_keys(p.f.plugins, v1.public_key));
        ASSERT_EQ(plugin_store_install(p.f.plugins, v2.manifest_path, &m, &present), PLUGIN_OK);
        ASSERT_EQ(plugin_store_switch(p.f.plugins, "demo", v2.generation), PLUGIN_OK);
        ASSERT_EQ(pd_publish(&p.f, "packed1", 1, &pub1), PLUGIN_DIST_OK);
        ASSERT(pd_peers(&p.f));
        ASSERT_EQ(pj_fail_with(&p, pub1.root, "PLUGIN_DIST_DOWNGRADE"), 0);
        ASSERT(!pd_generation_stored(&p.f, v1.generation));
        ASSERT(pd_selection(&p.f, v2.generation));
        PASS();
    } _test_next:;
    pj_close(&p);
    return failures;
}

static int pj_refusal_3(void)
{
    int failures = 0;
    struct pj p;
    TEST("plugin fetch job: an image over the cap is refused with PLUGIN_DIST_TOO_LARGE") {
        struct plugin_pack_result packed;
        struct plugin_dist_published pub;
        ASSERT(pj_open(&p));
        ASSERT(pj_publish(&p, "packed1", "1.0.0", 1, &packed, &pub));
        ASSERT(pd_peers(&p.f));
        ASSERT(pd_keys(p.f.plugins, packed.public_key));
        plugin_dist_test_set_image_max(8);
        int bad = pj_fail_with(&p, pub.root, "PLUGIN_DIST_TOO_LARGE");
        plugin_dist_test_set_image_max(0);
        ASSERT_EQ(bad, 0);
        PASS();
    } _test_next:;
    plugin_dist_test_set_image_max(0);
    pj_close(&p);
    return failures;
}

/* ---- 3. begin refusals and the byte cap ------------------------------- */
static int pj_begin_refusals(void)
{
    int failures = 0;
    struct pj p;
    TEST("plugin fetch job: begin names each refusal; a byte cap fails the job in the swarm") {
        struct plugin_pack_result packed;
        struct plugin_dist_published pub;
        struct plugin_fetch_request rq;
        struct plugin_fetch_begin_result r;
        struct plugin_fetch_view v;
        uint64_t unknown = 99;
        ASSERT(pj_open(&p));
        ASSERT(pj_publish(&p, "packed1", "1.0.0", 1, &packed, &pub));
        pj_request(&rq, pub.root);
        plugin_fetch_begin(p.table, &p.ctx, &rq, 1, &r);
        ASSERT_EQ(r.status, PLUGIN_FETCH_BEGIN_NO_PEERS);
        ASSERT(pd_peers(&p.f));
        rq.peers = &unknown;
        rq.peer_count = 1;
        plugin_fetch_begin(p.table, &p.ctx, &rq, 1, &r);
        ASSERT_EQ(r.status, PLUGIN_FETCH_BEGIN_UNKNOWN_PEER);
        rq.peers = NULL;
        rq.peer_count = 0;
        rq.name = "../x";
        plugin_fetch_begin(p.table, &p.ctx, &rq, 1, &r);
        ASSERT_EQ(r.status, PLUGIN_FETCH_BEGIN_ARGUMENT);
        rq.name = "demo";
        rq.max_bytes = PLUGIN_FETCH_BYTES_MAX + 1;
        plugin_fetch_begin(p.table, &p.ctx, &rq, 1, &r);
        ASSERT_EQ(r.status, PLUGIN_FETCH_BEGIN_ARGUMENT);
        rq.max_bytes = 0;
        rq.timeout_s = PLUGIN_FETCH_TIMEOUT_MAX_S + 1;
        plugin_fetch_begin(p.table, &p.ctx, &rq, 1, &r);
        ASSERT_EQ(r.status, PLUGIN_FETCH_BEGIN_ARGUMENT);
        struct plugin_fetch_ctx none = {0};
        rq.timeout_s = 0;
        plugin_fetch_begin(p.table, &none, &rq, 1, &r);
        ASSERT_EQ(r.status, PLUGIN_FETCH_BEGIN_NO_SWARM);
        /* Nothing above created a job or a download. */
        ASSERT(plugin_fetch_list(p.table, &v, 1) == 0);
        /* A cap smaller than the package: the engine fails the download. */
        rq.max_bytes = 100;
        plugin_fetch_begin(p.table, &p.ctx, &rq, 1, &r);
        ASSERT_EQ(r.status, PLUGIN_FETCH_BEGIN_OK);
        ASSERT(pj_finish(&p, r.job, &v));
        ASSERT_EQ(v.state, PLUGIN_FETCH_FAILED);
        ASSERT(strcmp(v.code, "PLUGIN_FETCH_SWARM_FAILED") == 0);
        ASSERT(strstr(v.detail, "byte") != NULL || strstr(v.detail, "limit") != NULL ||
               strstr(v.detail, "bound") != NULL || strstr(v.detail, "size") != NULL);
        PASS();
    } _test_next:;
    pj_close(&p);
    return failures;
}

/* ---- 4. concurrency, deadline and table bounds -------------------------- */
static void pj_root(uint8_t root[32], unsigned n)
{
    memset(root, 0x40, 32);
    root[0] = (uint8_t)n;
    root[1] = (uint8_t)(n >> 8);
}

static int pj_bounds(void)
{
    int failures = 0;
    struct pj p;
    TEST("plugin fetch job: active jobs, deadlines and the table are bounded; ids are not reused") {
        struct plugin_fetch_request rq;
        struct plugin_fetch_begin_result r, dup;
        struct plugin_fetch_view v, rows[PLUGIN_FETCH_TABLE_MAX + 4];
        uint8_t root[32];
        uint64_t first = 0, last = 0;
        ASSERT(pj_open(&p));
        ASSERT(pd_peers(&p.f));
        for (unsigned i = 1; i <= PLUGIN_FETCH_ACTIVE_MAX; i++) {
            pj_root(root, i);
            pj_request(&rq, root);
            rq.timeout_s = 5;
            plugin_fetch_begin(p.table, &p.ctx, &rq, 100, &r);
            ASSERT_EQ(r.status, PLUGIN_FETCH_BEGIN_OK);
            if (i == 1)
                first = r.job;
        }
        /* Same root again returns the running job. */
        pj_root(root, 1);
        pj_request(&rq, root);
        plugin_fetch_begin(p.table, &p.ctx, &rq, 100, &dup);
        ASSERT_EQ(dup.status, PLUGIN_FETCH_BEGIN_OK);
        ASSERT(dup.existing);
        ASSERT_EQ(dup.job, first);
        /* One more distinct root is over the active limit. */
        pj_root(root, 200);
        pj_request(&rq, root);
        plugin_fetch_begin(p.table, &p.ctx, &rq, 100, &r);
        ASSERT_EQ(r.status, PLUGIN_FETCH_BEGIN_BUSY);
        /* Before the deadline the jobs wait; at it they time out and free the slots. */
        plugin_fetch_advance(p.table, &p.ctx, 104);
        ASSERT(plugin_fetch_status(p.table, first, &v));
        ASSERT_EQ(v.state, PLUGIN_FETCH_FETCHING);
        plugin_fetch_advance(p.table, &p.ctx, 105);
        ASSERT(plugin_fetch_status(p.table, first, &v));
        ASSERT_EQ(v.state, PLUGIN_FETCH_FAILED);
        ASSERT(strcmp(v.code, "PLUGIN_FETCH_TIMEOUT") == 0);
        /* Many more jobs than slots: the table stays at its bound and drops the oldest. */
        for (unsigned i = 0; i < 3u * PLUGIN_FETCH_TABLE_MAX; i++) {
            pj_root(root, 300 + i);
            pj_request(&rq, root);
            rq.timeout_s = 1;
            plugin_fetch_begin(p.table, &p.ctx, &rq, 1000 + 10 * i, &r);
            ASSERT_EQ(r.status, PLUGIN_FETCH_BEGIN_OK);
            ASSERT(r.job > last);
            last = r.job;
            plugin_fetch_advance(p.table, &p.ctx, 1000 + 10 * i + 2);
        }
        ASSERT(plugin_fetch_list(p.table, rows, PLUGIN_FETCH_TABLE_MAX + 4) == PLUGIN_FETCH_TABLE_MAX);
        ASSERT_EQ(rows[0].job, last);
        ASSERT(!plugin_fetch_status(p.table, first, &v));
        PASS();
    } _test_next:;
    pj_close(&p);
    return failures;
}

/* ---- the CLI half: plugin fetch_remote against a scripted node ------------- */

static const char *const pjr_script_begin = "{\"ok\":true,\"job\":7,\"state\":\"fetching\"}";
static const char *const pjr_done =
    "{\"ok\":true,\"job\":7,\"state\":\"installed\",\"name\":\"demo\",\"generation\":\"g1\"}";
static const char *const pjr_running = "{\"ok\":true,\"job\":7,\"state\":\"fetching\"}";
/* What node_rpc_call hands back when a poll misses its deadline or the node is busy. */
static const char *const pjr_lost = "{\"code\":-32603,\"message\":\"RPC deadline expired reading the reply\"}";
static const char *const pjr_lost_bare = "{\"error\":{\"code\":-32603}}";

static const char *const *g_pjr_polls;
static size_t g_pjr_npolls, g_pjr_next, g_pjr_calls;

static char *pjr_hook(const char *method, const char *params)
{
    (void)params;
    g_pjr_calls++;
    if (strcmp(method, "plugin_fetch_begin") == 0)
        return strdup(pjr_script_begin);
    const char *answer = g_pjr_next < g_pjr_npolls ? g_pjr_polls[g_pjr_next++] : g_pjr_polls[g_pjr_npolls - 1];
    return strdup(answer);
}

static void pjr_run(const char *const *polls, size_t n, const char *wait, struct zcl_command_reply *r)
{
    char in_text[160];
    struct json_value in;
    g_pjr_polls = polls;
    g_pjr_npolls = n;
    g_pjr_next = g_pjr_calls = 0;
    (void)snprintf(in_text, sizeof(in_text),
                   "{\"root\":\"%064d\",\"name\":\"demo\",\"wait\":\"%s\"}", 1, wait);
    json_init(&in);
    (void)json_read(&in, in_text, strlen(in_text));
    struct zcl_command_request request = { .input = &in, .view = "normal" };
    zcl_command_reply_init(r, "zcl.plugin_test.v1");
    node_rpc_client_set_test_hook(pjr_hook);
    zcl_native_handle_plugin_fetch_remote(&request, r);
    node_rpc_client_set_test_hook(NULL);
    json_free(&in);
}

/* The cross-host defect: polls that missed the RPC deadline ended the wait with
 * an empty code and message while the job went on to install. */
static int pjr_case_0(void)
{
    int failures = 0;
    struct zcl_command_reply r;
    TEST_CASE("fetch_remote keeps waiting across failed polls and reports installed") {
        const char *const polls[] = { pjr_lost, pjr_lost_bare, pjr_running, pjr_lost, pjr_done };
        pjr_run(polls, 5, "30", &r);
        ASSERT_EQ(r.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(r.error.code, "");
        ASSERT_STR_EQ(r.error.message, "");
        ASSERT_STR_EQ(json_get_str(json_get(&r.data, "state")), "installed");
        zcl_command_reply_free(&r);
    } TEST_END
    return failures;
}

static int pjr_case_1(void)
{
    int failures = 0;
    struct zcl_command_reply r;
    TEST_CASE("fetch_remote with a node that never answers a poll fails with a code and a message") {
        const char *const polls[] = { pjr_lost };
        pjr_run(polls, 1, "60", &r);
        ASSERT_EQ(r.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(r.error.code, "PLUGIN_FETCH_POLL_FAILED");
        ASSERT(r.error.message[0] != '\0');
        ASSERT(strstr(r.error.message, "job 7") != NULL);
        ASSERT(strstr(r.error.next_action, "--job=7") != NULL);
        ASSERT(r.error.retryable);
        ASSERT(g_pjr_calls <= 12); /* bounded retries, not the whole wait */
        zcl_command_reply_free(&r);
    } TEST_END
    return failures;
}

static int pjr_case_2(void)
{
    int failures = 0;
    struct zcl_command_reply r;
    TEST_CASE("fetch_remote reports a job still running as ok when the wait runs out") {
        const char *const polls[] = { pjr_running };
        pjr_run(polls, 1, "1", &r);
        ASSERT_EQ(r.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(json_get_str(json_get(&r.data, "state")), "fetching");
        zcl_command_reply_free(&r);
    } TEST_END
    return failures;
}

static int pjr_case_3(void)
{
    int failures = 0;
    struct zcl_command_reply r;
    TEST_CASE("fetch_remote refusals and failed jobs never carry an empty code or message") {
        const char *const refused[] = { "{\"ok\":false,\"code\":\"\",\"message\":\"\"}" };
        pjr_run(refused, 1, "5", &r);
        ASSERT_EQ(r.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT(r.error.code[0] != '\0');
        ASSERT(r.error.message[0] != '\0');
        zcl_command_reply_free(&r);
        const char *const failed[] = { "{\"ok\":true,\"job\":7,\"state\":\"failed\",\"code\":\"\",\"detail\":\"\"}" };
        pjr_run(failed, 1, "5", &r);
        ASSERT_EQ(r.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT(r.error.code[0] != '\0');
        ASSERT(r.error.message[0] != '\0');
        zcl_command_reply_free(&r);
        const char *const stated[] = { "{\"ok\":true,\"job\":7,\"state\":\"failed\",\"code\":\"PLUGIN_FETCH_TIMEOUT\",\"detail\":\"too slow\"}" };
        pjr_run(stated, 1, "5", &r);
        ASSERT_STR_EQ(r.error.code, "PLUGIN_FETCH_TIMEOUT");
        ASSERT_STR_EQ(r.error.message, "too slow");
        zcl_command_reply_free(&r);
    } TEST_END
    return failures;
}

int test_plugin_fetch_job(void)
{
    int failures = 0;
    failures += pj_journey();
    failures += pj_refusal_0();
    failures += pj_refusal_1();
    failures += pj_refusal_2();
    failures += pj_refusal_3();
    failures += pj_begin_refusals();
    failures += pj_bounds();
    failures += pjr_case_0();
    failures += pjr_case_1();
    failures += pjr_case_2();
    failures += pjr_case_3();
    return failures;
}
