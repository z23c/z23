/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: prove a resident plugin can call the node over its control socket
 * under real `plugin run` supervision. The child is the fixture plugin
 * tests/harness/fixtures/plugin_hostcall_child.c, signed and installed through
 * the plugin store; the node side is the node-backed handler table over a small
 * fixture chain. A plugin that declares chain.read reads the chain tip; the
 * same image without the declaration is answered DENIED; wallet.request is
 * refused PLANNED even when declared; a missing handler table answers
 * UNAVAILABLE; a broken frame ends the stream and the child is restarted; the
 * per-child rate bound defers calls to the next window. */

#include "test/test_core.h"

#include "models/block.h"
#include "primitives/block.h"
#include "chain/chain.h"
#include "command/native_command.h"
#include "models/database.h"
#include "primitives/block.h"
#include "validation/chainstate.h"
#include "plugin/plugin_run.h"
#include "plugin/plugin_store.h"
#include "services/plugin_host_handlers.h"
#include "test/plugin_run_env.h"

#include <pthread.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if !defined(__linux__)
int test_plugin_run_hostcall(void)
{
    int failures = 0;
    printf("\n=== Plugin run host-call tests ===\n");
    TEST_CASE("host calls need confined plugin processes, which are Linux-only") {
        ASSERT(true);
    } TEST_END
    return failures;
}
#else

#define PRH_FIXTURE "build/fixtures/plugin_hostcall_child"
#define PRH_MARKER "HCC-VARIANT:"
#define PRH_TIP_HEIGHT 7

#define PRH_CHAIN_LEN (PRH_TIP_HEIGHT + 1)

struct prh_chain {
    char dir[256];
    struct sqlite3 *sdb;
    struct node_db ndb;
    struct active_chain active;
    bool active_ready;
    bool db_ready;
    struct block_index bi[PRH_CHAIN_LEN];
    uint8_t hash[PRH_CHAIN_LEN][32];
    struct plugin_host_node node;
    struct plugin_hostcall_handlers handlers;
};

static bool prh_authority(void *context, int64_t *height, uint8_t hash[32])
{
    const struct prh_chain *c = context;
    *height = PRH_TIP_HEIGHT;
    memcpy(hash, c->hash[PRH_TIP_HEIGHT], 32);
    return true;
}

static const uint8_t prh_sol[8] = {1, 2, 3, 4, 5, 6, 7, 8};

/* One header of the fixture chain: its prev link is the previous block's hash,
 * so every row's id is the real header hash and the links are consistent. */
static bool prh_make_row(struct prh_chain *c, struct node_db *rw, int h)
{
    struct block_header b;
    block_header_init(&b);
    if (h > 0)
        memcpy(b.hashPrevBlock.data, c->hash[h - 1], 32);
    memset(b.hashMerkleRoot.data, 0x40 + h, 32);
    b.nTime = 1700000000u + 150u * (uint32_t)h;
    b.nBits = 0x1f07ffff;
    memset(b.nNonce.data, 0x10 + h, 32);
    memcpy(b.nSolution, prh_sol, sizeof(prh_sol));
    b.nSolutionSize = sizeof(prh_sol);
    struct uint256 id;
    block_header_get_hash(&b, &id);
    memcpy(c->hash[h], id.data, 32);
    struct db_block row;
    memset(&row, 0, sizeof(row));
    memcpy(row.hash, id.data, 32);
    memcpy(row.prev_hash, b.hashPrevBlock.data, 32);
    memcpy(row.merkle_root, b.hashMerkleRoot.data, 32);
    memcpy(row.nonce, b.nNonce.data, 32);
    row.height = h;
    row.version = b.nVersion;
    row.time = b.nTime;
    row.bits = b.nBits;
    row.solution = (uint8_t *)prh_sol;
    row.solution_len = sizeof(prh_sol);
    row.status = 3;
    return db_block_save(rw, &row);
}

/* Rows for heights 0..tip, saved on a writable handle that is closed before
 * the read-only connection the handlers use is opened. */
static bool prh_save_chain(struct prh_chain *c)
{
    char path[300];
    snprintf(path, sizeof(path), "%s/node.db", c->dir);
    struct node_db rw;
    if (!node_db_open(&rw, path))
        return false;
    bool ok = true;
    for (int h = 0; ok && h < PRH_CHAIN_LEN; h++)
        ok = prh_make_row(c, &rw, h);
    node_db_close(&rw);
    return ok;
}

static bool prh_install_active(struct prh_chain *c)
{
    active_chain_init(&c->active);
    c->active_ready = true;
    for (int h = 0; h < PRH_CHAIN_LEN; h++) {
        struct block_index *bi = &c->bi[h];
        block_index_init(bi);
        memcpy(bi->hashBlock.data, c->hash[h], 32);
        bi->phashBlock = &bi->hashBlock;
        bi->nHeight = h;
        if (!active_chain_install_tip_slot(&c->active, bi))
            return false;
    }
    return true;
}

/* The served tip is block 7; its header row is what chain.tip reads the time
 * from. The node is bound to the calling thread, which must also poll the run. */
static bool prh_chain_open(struct prh_chain *c)
{
    memset(c, 0, sizeof(*c));
    if (!test_mkdtemp(c->dir, sizeof(c->dir), "prh") || !prh_save_chain(c))
        return false;
    if (zcl_native_node_db_open_readonly(c->dir, &c->sdb, &c->ndb, NULL, 0) != ZCL_NODE_DB_RO_OK)
        return false;
    c->db_ready = true;
    if (!prh_install_active(c) ||
        !plugin_host_node_init(&c->node, &c->ndb, &c->active, "hostcall").ok)
        return false;
    c->node.authority = prh_authority;
    c->node.authority_context = c;
    return plugin_host_node_handlers(&c->handlers, &c->node).ok;
}

static void prh_chain_close(struct prh_chain *c)
{
    if (c->db_ready)
        zcl_native_node_db_close_readonly(&c->sdb, &c->ndb);
    if (c->active_ready)
        active_chain_free(&c->active);
    char path[320];
    static const char *const sfx[] = {"", "-wal", "-shm"};
    for (size_t i = 0; i < 3; i++) {
        snprintf(path, sizeof(path), "%s/node.db%s", c->dir, sfx[i]);
        unlink(path);
    }
    rmdir(c->dir);
}

static uint64_t prh_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* Publish the fixture as plugin `name` in `mode` declaring `caps`, and run it. */
static struct plugin_run *prh_start(struct prt_env *e, const char *name, const char *mode,
                                    const char *caps,
                                    const struct plugin_hostcall_handlers *handlers,
                                    uint32_t per_second, uint32_t deadline_ms)
{
    size_t len = 0;
    char gen[PRT_HEX];
    unsigned char *img = prt_image_of(PRH_FIXTURE, PRH_MARKER, mode, "h1", &len);
    bool ok = img && prt_publish_bytes(e, name, img, len, caps, gen) &&
              plugin_store_switch(e->root, name, gen) == PLUGIN_OK;
    free(img);
    struct plugin_run_options o = {
        .root = e->root, .name = name,
        .ping_interval_ms = 40, .ping_deadline_ms = deadline_ms, .ping_miss_limit = 2,
        .backoff_initial_ms = 20, .backoff_max_ms = 2000, .stable_ms = 60000,
        .hostcall = handlers, .hostcall_per_second = per_second,
    };
    struct plugin_run *run = NULL;
    return ok && plugin_run_open(&o, &run, NULL) == PLUGIN_RUN_OK ? run : NULL;
}

/* Poll until the child has logged its host-call line or the time is up. */
static bool prh_outcome(struct plugin_run *run, char *line, size_t cap, unsigned timeout_ms)
{
    uint64_t end = prh_now_ms() + timeout_ms;
    struct plugin_run_info info;
    while (prh_now_ms() < end) {
        (void)plugin_run_poll(run);
        plugin_run_info_get(run, &info);
        if (strncmp(info.last_log, "hostcall ", 9) == 0) {
            snprintf(line, cap, "%s", info.last_log);
            return true;
        }
        struct timespec nap = {0, 5 * 1000 * 1000};
        nanosleep(&nap, NULL);
    }
    return false;
}

/* The log line for one plugin run, or an empty string. */
static bool prh_run_line(struct prt_env *e, const char *name, const char *caps,
                         const struct plugin_hostcall_handlers *handlers, char *line, size_t cap)
{
    struct plugin_run *run = prh_start(e, name, "tip", caps, handlers, 0, 2000);
    bool got = run && prh_outcome(run, line, cap, 8000);
    plugin_run_close(run);
    return got;
}

static bool prh_restarted(struct plugin_run *run, unsigned timeout_ms)
{
    uint64_t end = prh_now_ms() + timeout_ms;
    struct plugin_run_info info;
    while (prh_now_ms() < end) {
        (void)plugin_run_poll(run);
        plugin_run_info_get(run, &info);
        if (info.restarts >= 1)
            return true;
        struct timespec nap = {0, 5 * 1000 * 1000};
        nanosleep(&nap, NULL);
    }
    return false;
}

struct prh_ctx {
    struct prh_chain chain;
    struct prt_env env;
};

/* Status values in the fixture's log line: OK 0, DENIED 9, PLANNED 10, UNAVAILABLE 11. */
static int prh_case_vocabulary(void)
{
    int failures = 0;
    TEST_CASE("the capability vocabulary keeps its old bits and appends the host-call names") {
        static const char *const names[] = {
            "fs.read", "fs.write", "net.client", "net.server", "process.spawn", "clock",
            "ui.panel", "chain.read", "state", "events.append", "wallet.request"};
        for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); i++)
            ASSERT_STR_EQ(plugin_capability_name(i), names[i]);
        ASSERT(plugin_capability_name(sizeof(names) / sizeof(names[0])) == NULL);
    } TEST_END
    return failures;
}

static int prh_case_old_manifest(void)
{
    int failures = 0;
    TEST_CASE("an old manifest parses to the same capability bits and grants no host call") {
        static const char old_manifest[] =
            "{\"schema\":\"z23.plugin.v1\",\"name\":\"old\",\"version\":\"1.0.0\","
            "\"interface_version\":1,\"sha3_512\":\"%s\",\"capabilities\":[\"fs.read\",\"clock\"]}";
        char text[512], hex[PLUGIN_HEX_SHA3_512 + 1];
        memset(hex, 'a', PLUGIN_HEX_SHA3_512);
        hex[PLUGIN_HEX_SHA3_512] = '\0';
        int n = snprintf(text, sizeof(text), old_manifest, hex);
        struct plugin_manifest m;
        ASSERT_EQ(plugin_manifest_parse(text, (size_t)n, &m), PLUGIN_OK);
        ASSERT_EQ(m.capabilities, 0x21u); /* fs.read bit 0, clock bit 5 */
        ASSERT_EQ(plugin_hostcall_grants_from_manifest(m.capabilities), 0u);
    } TEST_END
    return failures;
}

static int prh_case_granted(struct prh_ctx *c)
{
    int failures = 0;
    char line[160];
    TEST_CASE("a plugin that declares chain.read reads the chain tip; wallet.request is PLANNED") {
        ASSERT(prh_run_line(&c->env, "granted", "\"chain.read\",\"wallet.request\"",
                            &c->chain.handlers, line, sizeof(line)));
        ASSERT_STR_EQ(line, "hostcall tip=0 height=7 wallet=10");
    } TEST_END
    return failures;
}

static int prh_case_denied(struct prh_ctx *c)
{
    int failures = 0;
    char line[160];
    TEST_CASE("the same image without chain.read is answered DENIED") {
        ASSERT(prh_run_line(&c->env, "ungranted", "\"clock\"", &c->chain.handlers, line,
                            sizeof(line)));
        ASSERT_STR_EQ(line, "hostcall tip=9 height=0 wallet=10");
    } TEST_END
    return failures;
}

static int prh_case_no_handlers(struct prh_ctx *c)
{
    int failures = 0;
    char line[160];
    TEST_CASE("no handler table answers a granted call UNAVAILABLE") {
        ASSERT(prh_run_line(&c->env, "nohandler", "\"chain.read\"", NULL, line, sizeof(line)));
        ASSERT_STR_EQ(line, "hostcall tip=11 height=0 wallet=10");
    } TEST_END
    return failures;
}

static int prh_case_broken_frame(struct prh_ctx *c)
{
    int failures = 0;
    TEST_CASE("a broken frame closes the control socket and the child is restarted") {
        struct plugin_run *run = prh_start(&c->env, "badframe", "badframe", "\"chain.read\"",
                                           &c->chain.handlers, 0, 300);
        ASSERT(run != NULL);
        /* The child reports how its control socket ended: eof=1 means the host
         * closed the stream on the framing violation, reply=0 that it did not
         * answer the frame. A host that kept the stream open would leave the
         * child reading until the ping-miss kill, and no line would arrive. */
        char line[160];
        ASSERT(prh_outcome(run, line, sizeof(line), 8000));
        ASSERT_STR_EQ(line, "hostcall badframe eof=1 reply=0");
        ASSERT(prh_restarted(run, 8000));
        plugin_run_close(run);
    } TEST_END
    return failures;
}

/* How many 12-byte writes a fresh stream socketpair queues before the next one
 * would block: the supervisor's replies fill its send side at the same count,
 * leaving the queue full with every reply accepted. 0 if it cannot be probed. */
static unsigned prh_probe_queue(void)
{
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0)
        return 0;
    uint8_t chunk[12] = {0};
    unsigned count = 0;
    while (send(pair[0], chunk, sizeof(chunk), MSG_DONTWAIT) == (ssize_t)sizeof(chunk))
        count++;
    close(pair[0]);
    close(pair[1]);
    return count;
}

struct prh_closer {
    struct plugin_run *run;
    atomic_bool done;
};

static void *prh_close_thread(void *arg)
{
    struct prh_closer *job = arg;
    plugin_run_close(job->run);
    atomic_store(&job->done, true);
    return NULL;
}

/* Close `run` on a helper thread so a wedged close fails the case instead of
 * hanging the suite: past the bound the child is killed, which unblocks any
 * write to it, and the thread is joined. Returns the milliseconds it took, or
 * a value past `bound_ms` when close had to be rescued. */
static uint64_t prh_timed_close(struct plugin_run *run, unsigned bound_ms)
{
    struct plugin_run_info info;
    plugin_run_info_get(run, &info);
    struct prh_closer job = {.run = run};
    atomic_init(&job.done, false);
    uint64_t t0 = prh_now_ms();
    pthread_t tid;
    if (pthread_create(&tid, NULL, prh_close_thread, &job) != 0)
        return UINT64_MAX;
    while (!atomic_load(&job.done) && prh_now_ms() - t0 < bound_ms) {
        struct timespec nap = {0, 5 * 1000 * 1000};
        nanosleep(&nap, NULL);
    }
    uint64_t took = prh_now_ms() - t0;
    if (!atomic_load(&job.done)) {
        if (info.pid > 0)
            (void)kill((pid_t)info.pid, SIGKILL);
        took = (uint64_t)bound_ms + 1;
    }
    (void)pthread_join(tid, NULL);
    return took;
}

static int prh_case_silent_reader(struct prh_ctx *c)
{
    int failures = 0;
    char line[160];
    TEST_CASE("a child that fills the reply queue and never reads cannot wedge close") {
        char mode[16];
        unsigned queue = prh_probe_queue();
        ASSERT(queue > 0);
        snprintf(mode, sizeof(mode), "flood:%u", queue);
        struct plugin_run *run = prh_start(&c->env, "flooder", mode, "\"chain.read\"",
                                           &c->chain.handlers, 100000, 60000);
        ASSERT(run != NULL);
        ASSERT(prh_outcome(run, line, sizeof(line), 8000));
        char want[64];
        snprintf(want, sizeof(want), "hostcall flooded n=%u", queue);
        ASSERT_STR_EQ(line, want);
        /* Let the pump answer every queued call so the send queue is full. */
        uint64_t end = prh_now_ms() + 400;
        while (prh_now_ms() < end) {
            (void)plugin_run_poll(run);
            struct timespec nap = {0, 5 * 1000 * 1000};
            nanosleep(&nap, NULL);
        }
        struct plugin_run_info info;
        plugin_run_info_get(run, &info);
        ASSERT_EQ(info.restarts, 0u);
        ASSERT(info.pid > 0);
        /* Grace is 300 ms; the stop frame may add its short send budget. */
        ASSERT(prh_timed_close(run, 5000) < 3000);
    } TEST_END
    return failures;
}

static int prh_case_slow_reader(struct prh_ctx *c)
{
    int failures = 0;
    TEST_CASE("one poll never serves a slow reader for longer than the pump budget") {
        char mode[16];
        /* More calls than the send queue holds: the host must wait for the child
         * to read, which it does one reply every 150 ms. Unbudgeted, the polls
         * that serve the backlog would each wait for every reply in turn. */
        unsigned calls = prh_probe_queue() + 100;
        snprintf(mode, sizeof(mode), "slow:%u", calls);
        struct plugin_run *run = prh_start(&c->env, "slowread", mode, "\"chain.read\"",
                                           &c->chain.handlers, 100000, 60000);
        ASSERT(run != NULL);
        uint64_t worst = 0, end = prh_now_ms() + 3000;
        bool logged = false;
        while (prh_now_ms() < end) {
            uint64_t t0 = prh_now_ms();
            (void)plugin_run_poll(run);
            if (prh_now_ms() - t0 > worst)
                worst = prh_now_ms() - t0;
            struct plugin_run_info info;
            plugin_run_info_get(run, &info);
            logged = logged || strncmp(info.last_log, "hostcall ", 9) == 0;
            struct timespec nap = {0, 5 * 1000 * 1000};
            nanosleep(&nap, NULL);
        }
        ASSERT(logged);
        ASSERT(worst < 1000);
        plugin_run_close(run);
    } TEST_END
    return failures;
}

static int prh_case_rate(struct prh_ctx *c)
{
    int failures = 0;
    char line[160];
    TEST_CASE("the per-child rate bound defers calls to the next one-second window") {
        struct plugin_run *run = prh_start(&c->env, "ratelimit", "paced", "\"chain.read\"",
                                           &c->chain.handlers, 1, 4000);
        ASSERT(run != NULL);
        ASSERT(prh_outcome(run, line, sizeof(line), 8000));
        /* paced=1: the child saw the second reply a full window after its first call */
        ASSERT_STR_EQ(line, "hostcall tip=0 height=7 wallet=10 paced=1");
        plugin_run_close(run);
    } TEST_END
    return failures;
}

int test_plugin_run_hostcall(void)
{
    int failures = 0;
    printf("\n=== Plugin run host-call tests ===\n");
    static struct prh_ctx c;
    bool ready = access(PRH_FIXTURE, X_OK) == 0 && prh_chain_open(&c.chain) &&
                 prt_env_open(&c.env);
    TEST_CASE("the fixture chain and the signed store are ready") {
        ASSERT(ready);
    } TEST_END
    if (!ready) {
        prh_chain_close(&c.chain);
        return failures;
    }
    failures += prh_case_vocabulary();
    failures += prh_case_old_manifest();
    failures += prh_case_granted(&c);
    failures += prh_case_denied(&c);
    failures += prh_case_no_handlers(&c);
    failures += prh_case_broken_frame(&c);
    failures += prh_case_rate(&c);
    failures += prh_case_silent_reader(&c);
    failures += prh_case_slow_reader(&c);
    prh_chain_close(&c.chain);
    prt_env_close(&c.env);
    return failures;
}
#endif
