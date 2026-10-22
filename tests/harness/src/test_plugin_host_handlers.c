/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: prove the node-backed plugin host-call handlers. Real frames go
 * through plugin_hostcall_dispatch against a small fixture chain held in an
 * in-memory node database: chain.tip and chain.header_by_height reply with
 * exact bytes, a height past the tip answers not-found, a missing capability
 * is refused before any handler runs, unwired methods stay UNAVAILABLE, and
 * log.write strips control bytes, enforces its text bound and rate limit. */

#include "test/test_core.h"

#include "base/serialize_le.h"
#include "core/serialize.h"
#include "models/block.h"
#include "models/database.h"
#include "plugin/plugin_hostcall.h"
#include "chain/chain.h"
#include "command/native_command.h"
#include "primitives/block.h"
#include "validation/chainstate.h"
#include "services/plugin_host_handlers.h"

#include <stdio.h>
#include <pthread.h>
#include <sqlite3.h>
#include <string.h>
#include <unistd.h>

#define PHH_CHAIN_LEN 5 /* one block beyond the served tip */
#define PHH_TIP 3
#define PHH_LINES 64

struct phh_fixture {
    char dir[256];
    struct sqlite3 *sdb;
    struct node_db ndb;
    struct active_chain chain;
    bool chain_ready;
    struct block_index bi[PHH_CHAIN_LEN];
    struct block_header fork_hdr;
    struct block_header hdr[PHH_CHAIN_LEN];
    uint8_t hash[PHH_CHAIN_LEN][32];
    struct plugin_host_node node;
    struct plugin_hostcall_handlers handlers;
    unsigned authority_calls;
    int64_t now_ms;
    char lines[PHH_LINES][PLUGIN_HOST_LOG_LINE_MAX];
    unsigned levels[PHH_LINES];
    unsigned line_count;
};

static bool phh_authority(void *c, int64_t *height, uint8_t hash[32])
{
    struct phh_fixture *f = c;
    f->authority_calls++;
    *height = PHH_TIP;
    memcpy(hash, f->hash[PHH_TIP], 32);
    return true;
}

static int64_t phh_now(void *c)
{
    return ((struct phh_fixture *)c)->now_ms;
}

static void phh_sink(void *c, unsigned level, const char *line)
{
    struct phh_fixture *f = c;
    if (f->line_count < PHH_LINES) {
        snprintf(f->lines[f->line_count], sizeof f->lines[0], "%s", line);
        f->levels[f->line_count] = level;
    }
    f->line_count++;
}

/* A node on the fixture's read-only connection, wired to the test seams. */
static bool phh_bind(struct phh_fixture *f, struct plugin_host_node *n, const char *name)
{
    if (!plugin_host_node_init(n, &f->ndb, &f->chain, name).ok)
        return false;
    n->authority = phh_authority;
    n->authority_context = f;
    n->now_ms = phh_now;
    n->now_context = f;
    n->log_sink = phh_sink;
    n->log_context = f;
    return true;
}

static const uint8_t phh_sol[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

static bool phh_save_row(struct node_db *ndb, const struct block_header *b,
                         const uint8_t id[32], int height, int status)
{
    struct db_block row;
    memset(&row, 0, sizeof row);
    memcpy(row.hash, id, 32);
    row.height = height;
    memcpy(row.prev_hash, b->hashPrevBlock.data, 32);
    row.version = b->nVersion;
    memcpy(row.merkle_root, b->hashMerkleRoot.data, 32);
    row.time = b->nTime;
    row.bits = b->nBits;
    memcpy(row.nonce, b->nNonce.data, 32);
    row.solution = (uint8_t *)phh_sol;
    row.solution_len = sizeof phh_sol;
    row.status = status;
    return db_block_save(ndb, &row);
}

enum { PHH_PLAIN = 0, PHH_FORK_LOSER = 1, PHH_FORK_STALE = 2 };

static bool phh_install_chain(struct phh_fixture *f)
{
    active_chain_init(&f->chain);
    f->chain_ready = true;
    for (int h = 0; h < PHH_CHAIN_LEN; h++) {
        struct block_index *bi = &f->bi[h];
        block_index_init(bi);
        memcpy(bi->hashBlock.data, f->hash[h], 32);
        bi->phashBlock = &bi->hashBlock;
        bi->nHeight = h;
        if (!active_chain_install_tip_slot(&f->chain, bi))
            return false;
    }
    return true;
}

/* Variant PHH_FORK_LOSER also stores a status-2 fork block at height 2.
 * Variant PHH_FORK_STALE stores ONLY a status-3 fork block at height 2, so the
 * database's connected row disagrees with the active chain. */
static bool phh_open_variant(struct phh_fixture *f, int variant)
{
    memset(f, 0, sizeof *f);
    if (!test_mkdtemp(f->dir, sizeof f->dir, "phh"))
        return false;
    char path[300];
    snprintf(path, sizeof path, "%s/node.db", f->dir);
    struct node_db rw;
    if (!node_db_open(&rw, path))
        return false;
    for (int h = 0; h < PHH_CHAIN_LEN; h++) {
        struct block_header *b = &f->hdr[h];
        block_header_init(b);
        if (h > 0)
            memcpy(b->hashPrevBlock.data, f->hash[h - 1], 32);
        memset(b->hashMerkleRoot.data, 0x40 + h, 32);
        b->nTime = 1700000000u + 150u * (uint32_t)h;
        b->nBits = 0x1f07ffff;
        memset(b->nNonce.data, 0x10 + h, 32);
        memcpy(b->nSolution, phh_sol, sizeof phh_sol);
        b->nSolutionSize = sizeof phh_sol;
        struct uint256 id;
        block_header_get_hash(b, &id);
        memcpy(f->hash[h], id.data, 32);
        if (h == 2 && variant != PHH_PLAIN) {
            struct block_header fork = *b;
            memset(fork.nNonce.data, 0xF0, 32);
            struct uint256 fid;
            block_header_get_hash(&fork, &fid);
            f->fork_hdr = fork;
            if (variant == PHH_FORK_STALE) {
                if (!phh_save_row(&rw, &fork, fid.data, h, 3))
                    return false;
                continue;
            }
            if (!phh_save_row(&rw, b, id.data, h, 3) ||
                !phh_save_row(&rw, &fork, fid.data, h, 2))
                return false;
            continue;
        }
        if (!phh_save_row(&rw, b, id.data, h, 3))
            return false;
    }
    node_db_close(&rw);
    if (zcl_native_node_db_open_readonly(f->dir, &f->sdb, &f->ndb, NULL, 0) != ZCL_NODE_DB_RO_OK)
        return false;
    if (!phh_install_chain(f))
        return false;
    f->now_ms = 1000;
    return phh_bind(f, &f->node, "explorer") && plugin_host_node_handlers(&f->handlers, &f->node).ok;
}

static bool phh_open(struct phh_fixture *f)
{
    return phh_open_variant(f, PHH_PLAIN);
}

static void phh_close(struct phh_fixture *f)
{
    zcl_native_node_db_close_readonly(&f->sdb, &f->ndb);
    if (f->chain_ready)
        active_chain_free(&f->chain);
    char path[320];
    static const char *const sfx[] = { "", "-wal", "-shm" };
    for (size_t i = 0; i < 3; i++) {
        snprintf(path, sizeof path, "%s/node.db%s", f->dir, sfx[i]);
        unlink(path);
    }
    rmdir(f->dir);
}

/* Encode a request, decode it, dispatch it, decode the reply. */
static enum plugin_hostcall_status phh_call(
    struct phh_fixture *f, uint16_t method, const uint8_t *payload, size_t n,
    uint32_t granted, uint8_t *reply, size_t cap, struct plugin_hostcall_frame *rep)
{
    uint8_t wire[PLUGIN_HOSTCALL_MAX_FRAME];
    size_t w = 0, used = 0, rl = 0, rc = 0;
    struct plugin_hostcall_frame req = { PLUGIN_HOSTCALL_KIND_REQUEST, 77u, method, payload, n };
    struct plugin_hostcall_frame dec;
    memset(rep, 0, sizeof *rep);
    if (plugin_hostcall_encode(&req, wire, sizeof wire, &w) != PLUGIN_HOSTCALL_OK ||
        plugin_hostcall_decode(wire, w, &dec, &used) != PLUGIN_HOSTCALL_OK || used != w)
        return PLUGIN_HOSTCALL_ERR_ARGUMENT;
    enum plugin_hostcall_status s = plugin_hostcall_dispatch(&dec, granted, &f->handlers, reply, cap, &rl);
    if (rl > 0 && plugin_hostcall_decode(reply, rl, rep, &rc) != PLUGIN_HOSTCALL_OK)
        return PLUGIN_HOSTCALL_ERR_ARGUMENT;
    return s;
}

static int phh_case_chain(void)
{
    int failures = 0;
    struct phh_fixture f;
    uint8_t reply[PLUGIN_HOSTCALL_MAX_FRAME];
    struct plugin_hostcall_frame rep;
    const uint32_t grant = PLUGIN_HOSTCALL_CAP_CHAIN_READ;

    TEST_CASE("chain.tip replies height, hash and time exactly") {
        ASSERT(phh_open(&f));
        ASSERT_EQ(phh_call(&f, PLUGIN_HOSTCALL_M_CHAIN_TIP, NULL, 0, grant, reply, sizeof reply, &rep),
                  PLUGIN_HOSTCALL_OK);
        uint8_t want[PLUGIN_HOST_TIP_REPLY_BYTES];
        zcl_write_u32_be(want, PHH_TIP);
        memcpy(want + 4, f.hash[PHH_TIP], 32);
        zcl_write_u32_be(want + 36, f.hdr[PHH_TIP].nTime);
        ASSERT_EQ(rep.kind, PLUGIN_HOSTCALL_KIND_REPLY);
        ASSERT_EQ(rep.id, 77u);
        ASSERT_EQ(rep.code, PLUGIN_HOSTCALL_OK);
        ASSERT_EQ(rep.payload_len, sizeof want);
        ASSERT(memcmp(rep.payload, want, sizeof want) == 0);
        phh_close(&f);
    } TEST_END
    return failures;
}

static int phh_case_chain_1(void)
{
    int failures = 0;
    struct phh_fixture f;
    uint8_t reply[PLUGIN_HOSTCALL_MAX_FRAME];
    struct plugin_hostcall_frame rep;
    const uint32_t grant = PLUGIN_HOSTCALL_CAP_CHAIN_READ;


    TEST_CASE("chain.header_by_height replies the exact serialized header") {
        ASSERT(phh_open(&f));
        for (uint32_t h = 0; h <= PHH_TIP; h++) {
            uint8_t req[4];
            zcl_write_u32_be(req, h);
            ASSERT_EQ(phh_call(&f, PLUGIN_HOSTCALL_M_CHAIN_HEADER_BY_HEIGHT, req, 4, grant, reply,
                               sizeof reply, &rep), PLUGIN_HOSTCALL_OK);
            struct byte_stream s;
            stream_init(&s, 256);
            ASSERT(block_header_serialize(&f.hdr[h], &s));
            bool same = rep.payload_len == s.size && memcmp(rep.payload, s.data, s.size) == 0;
            size_t want_len = s.size;
            stream_free(&s);
            ASSERT(same);
            ASSERT(want_len > BLOCK_HEADER_SIZE);
        }
        phh_close(&f);
    } TEST_END
    return failures;
}

static int phh_case_chain_2(void)
{
    int failures = 0;
    struct phh_fixture f;
    uint8_t reply[PLUGIN_HOSTCALL_MAX_FRAME];
    struct plugin_hostcall_frame rep;
    const uint32_t grant = PLUGIN_HOSTCALL_CAP_CHAIN_READ;


    TEST_CASE("chain.header_by_height past the tip is not found") {
        ASSERT(phh_open(&f));
        static const uint32_t past[] = { PHH_TIP + 1, PHH_TIP + 2, 0x7fffffffu, 0x80000000u, 0xffffffffu };
        for (size_t i = 0; i < sizeof past / sizeof past[0]; i++) {
            uint8_t req[4];
            zcl_write_u32_be(req, past[i]);
            ASSERT_EQ(phh_call(&f, PLUGIN_HOSTCALL_M_CHAIN_HEADER_BY_HEIGHT, req, 4, grant, reply,
                               sizeof reply, &rep), PLUGIN_HOSTCALL_OK);
            ASSERT_EQ(rep.code, PLUGIN_HOSTCALL_OK);
            ASSERT_EQ(rep.payload_len, 0u);
        }
        /* A payload that is not exactly four bytes is refused by the table. */
        uint8_t five[5] = { 0 };
        ASSERT_EQ(phh_call(&f, PLUGIN_HOSTCALL_M_CHAIN_HEADER_BY_HEIGHT, five, 5, grant, reply,
                           sizeof reply, &rep), PLUGIN_HOSTCALL_ERR_PAYLOAD);
        ASSERT_EQ(phh_call(&f, PLUGIN_HOSTCALL_M_CHAIN_TIP, five, 1, grant, reply,
                           sizeof reply, &rep), PLUGIN_HOSTCALL_ERR_PAYLOAD);
        phh_close(&f);
    } TEST_END
    return failures;
}

static int phh_case_chain_3(void)
{
    int failures = 0;
    struct phh_fixture f;
    uint8_t reply[PLUGIN_HOSTCALL_MAX_FRAME];
    struct plugin_hostcall_frame rep;


    TEST_CASE("a missing capability is denied before any handler runs") {
        ASSERT(phh_open(&f));
        uint8_t req[4];
        zcl_write_u32_be(req, 1);
        ASSERT_EQ(phh_call(&f, PLUGIN_HOSTCALL_M_CHAIN_TIP, NULL, 0, 0, reply, sizeof reply, &rep),
                  PLUGIN_HOSTCALL_DENIED);
        ASSERT_EQ(phh_call(&f, PLUGIN_HOSTCALL_M_CHAIN_HEADER_BY_HEIGHT, req, 4,
                           PLUGIN_HOSTCALL_CAP_STATE, reply, sizeof reply, &rep),
                  PLUGIN_HOSTCALL_DENIED);
        ASSERT_EQ(rep.code, PLUGIN_HOSTCALL_DENIED);
        ASSERT_EQ(rep.payload_len, 0u);
        ASSERT_EQ(f.authority_calls, 0u);
        phh_close(&f);
    } TEST_END
    return failures;
}

static int phh_case_chain_4(void)
{
    int failures = 0;
    struct phh_fixture f;
    uint8_t reply[PLUGIN_HOSTCALL_MAX_FRAME];
    struct plugin_hostcall_frame rep;


    TEST_CASE("state, event and wallet methods stay unavailable") {
        ASSERT(phh_open(&f));
        uint8_t kv[3] = { 1, 'k', 'v' };
        const uint32_t all = PLUGIN_HOSTCALL_CAP_CHAIN_READ | PLUGIN_HOSTCALL_CAP_STATE |
                             PLUGIN_HOSTCALL_CAP_EVENTS;
        ASSERT_EQ(phh_call(&f, PLUGIN_HOSTCALL_M_STATE_GET, kv, 2, all, reply, sizeof reply, &rep),
                  PLUGIN_HOSTCALL_ERR_UNAVAILABLE);
        ASSERT_EQ(phh_call(&f, PLUGIN_HOSTCALL_M_STATE_PUT, kv, 3, all, reply, sizeof reply, &rep),
                  PLUGIN_HOSTCALL_ERR_UNAVAILABLE);
        ASSERT_EQ(phh_call(&f, PLUGIN_HOSTCALL_M_EVENT_APPEND, kv, 3, all, reply, sizeof reply, &rep),
                  PLUGIN_HOSTCALL_ERR_UNAVAILABLE);
        phh_close(&f);
    } TEST_END
    return failures;
}

static int phh_case_chain_5(void)
{
    int failures = 0;
    struct phh_fixture f;
    struct plugin_hostcall_frame rep;
    const uint32_t grant = PLUGIN_HOSTCALL_CAP_CHAIN_READ;


    TEST_CASE("no handler writes past its reply room") {
        ASSERT(phh_open(&f));
        uint8_t guarded[PLUGIN_HOSTCALL_HEADER_BYTES + PLUGIN_HOST_TIP_REPLY_BYTES + 16];
        memset(guarded, 0xEE, sizeof guarded);
        /* Room one byte short of the tip reply: refused, nothing past the cap. */
        size_t cap = PLUGIN_HOSTCALL_HEADER_BYTES + PLUGIN_HOST_TIP_REPLY_BYTES - 1;
        ASSERT_EQ(phh_call(&f, PLUGIN_HOSTCALL_M_CHAIN_TIP, NULL, 0, grant, guarded, cap, &rep),
                  PLUGIN_HOSTCALL_ERR_HANDLER);
        for (size_t i = cap; i < sizeof guarded; i++)
            ASSERT_EQ(guarded[i], 0xEE);
        /* Room for the header but not the 140-byte header reply. */
        uint8_t req[4];
        zcl_write_u32_be(req, 2);
        ASSERT_EQ(phh_call(&f, PLUGIN_HOSTCALL_M_CHAIN_HEADER_BY_HEIGHT, req, 4, grant, guarded,
                           sizeof guarded, &rep), PLUGIN_HOSTCALL_ERR_HANDLER);
        phh_close(&f);
    } TEST_END
    return failures;
}

static int phh_case_log(void)
{
    int failures = 0;
    struct phh_fixture f;
    uint8_t reply[256];
    struct plugin_hostcall_frame rep;

    TEST_CASE("log.write strips control bytes and prefixes the plugin name") {
        ASSERT(phh_open(&f));
        static const uint8_t req[] = { PLUGIN_HOST_LOG_WARN, 'h', 'i', '\n', 0x00, 0x1b, '[', '3', '1', 'm',
                                       0x7f, ' ', 'x', '\r', 0x09 };
        ASSERT_EQ(phh_call(&f, PLUGIN_HOSTCALL_M_LOG_WRITE, req, sizeof req, 0, reply, sizeof reply, &rep),
                  PLUGIN_HOSTCALL_OK);
        ASSERT_EQ(rep.payload_len, 0u);
        ASSERT_EQ(f.line_count, 1u);
        ASSERT_STR_EQ(f.lines[0], "[plugin explorer] hi[31m x");
        ASSERT_EQ(f.levels[0], (unsigned)PLUGIN_HOST_LOG_WARN);
        /* Text that is only control bytes, and an unknown level, are refused. */
        static const uint8_t only_ctl[] = { PLUGIN_HOST_LOG_INFO, 0x01, '\n' };
        ASSERT_EQ(phh_call(&f, PLUGIN_HOSTCALL_M_LOG_WRITE, only_ctl, sizeof only_ctl, 0, reply,
                           sizeof reply, &rep), PLUGIN_HOSTCALL_ERR_HANDLER);
        static const uint8_t bad_level[] = { 9, 'a' };
        ASSERT_EQ(phh_call(&f, PLUGIN_HOSTCALL_M_LOG_WRITE, bad_level, sizeof bad_level, 0, reply,
                           sizeof reply, &rep), PLUGIN_HOSTCALL_ERR_HANDLER);
        ASSERT_EQ(f.line_count, 1u);
        phh_close(&f);
    } TEST_END
    return failures;
}

static int phh_case_log_6(void)
{
    int failures = 0;
    struct phh_fixture f;
    uint8_t reply[256];
    struct plugin_hostcall_frame rep;


    TEST_CASE("log.write enforces the text bound") {
        ASSERT(phh_open(&f));
        uint8_t req[1 + PLUGIN_HOST_LOG_TEXT_MAX + 1];
        memset(req, 'a', sizeof req);
        req[0] = PLUGIN_HOST_LOG_INFO;
        ASSERT_EQ(phh_call(&f, PLUGIN_HOSTCALL_M_LOG_WRITE, req, 1 + PLUGIN_HOST_LOG_TEXT_MAX, 0, reply,
                           sizeof reply, &rep), PLUGIN_HOSTCALL_OK);
        ASSERT_EQ(f.line_count, 1u);
        ASSERT_EQ(strlen(f.lines[0]), strlen("[plugin explorer] ") + PLUGIN_HOST_LOG_TEXT_MAX);
        ASSERT_EQ(phh_call(&f, PLUGIN_HOSTCALL_M_LOG_WRITE, req, sizeof req, 0, reply, sizeof reply, &rep),
                  PLUGIN_HOSTCALL_ERR_HANDLER);
        ASSERT_EQ(f.line_count, 1u);
        phh_close(&f);
    } TEST_END
    return failures;
}

static int phh_case_log_7(void)
{
    int failures = 0;
    struct phh_fixture f;
    uint8_t reply[256];
    struct plugin_hostcall_frame rep;


    TEST_CASE("log.write is rate limited per window") {
        ASSERT(phh_open(&f));
        static const uint8_t req[] = { PLUGIN_HOST_LOG_INFO, 'p', 'i', 'n', 'g' };
        for (unsigned i = 0; i < PLUGIN_HOST_LOG_BURST; i++)
            ASSERT_EQ(phh_call(&f, PLUGIN_HOSTCALL_M_LOG_WRITE, req, sizeof req, 0, reply, sizeof reply,
                               &rep), PLUGIN_HOSTCALL_OK);
        ASSERT_EQ(phh_call(&f, PLUGIN_HOSTCALL_M_LOG_WRITE, req, sizeof req, 0, reply, sizeof reply, &rep),
                  PLUGIN_HOSTCALL_ERR_HANDLER);
        ASSERT_EQ(f.line_count, PLUGIN_HOST_LOG_BURST);
        ASSERT_EQ(f.node.log_dropped, 1u);
        f.now_ms += PLUGIN_HOST_LOG_WINDOW_MS;
        ASSERT_EQ(phh_call(&f, PLUGIN_HOSTCALL_M_LOG_WRITE, req, sizeof req, 0, reply, sizeof reply, &rep),
                  PLUGIN_HOSTCALL_OK);
        ASSERT_EQ(f.line_count, PLUGIN_HOST_LOG_BURST + 1);
        phh_close(&f);
    } TEST_END
    return failures;
}

static int phh_case_log_8(void)
{
    int failures = 0;


    TEST_CASE("node init sanitizes the name and enforces the connection contract") {
        struct phh_fixture g;
        ASSERT(phh_open(&g));
        struct plugin_host_node n;
        ASSERT(plugin_host_node_init(&n, &g.ndb, &g.chain, "a\nb\x1b" "c").ok);
        ASSERT_STR_EQ(n.plugin, "abc");
        ASSERT(!plugin_host_node_init(&n, &g.ndb, &g.chain, "\n\x01").ok);
        ASSERT(!plugin_host_node_init(&n, NULL, &g.chain, "x").ok);
        ASSERT(!plugin_host_node_init(&n, &g.ndb, NULL, "x").ok);
        ASSERT(!plugin_host_node_handlers(NULL, &n).ok);
        /* A writable connection is refused. */
        struct node_db rw;
        char path[300];
        snprintf(path, sizeof path, "%s/rw.db", g.dir);
        ASSERT(node_db_open(&rw, path));
        ASSERT(!plugin_host_node_init(&n, &rw, &g.chain, "x").ok);
        node_db_close(&rw);
        unlink(path);
        phh_close(&g);
    } TEST_END
    return failures;
}

static int phh_header_status(struct phh_fixture *f, uint32_t height, struct plugin_hostcall_frame *rep,
                             uint8_t *reply, size_t cap)
{
    uint8_t req[4];
    zcl_write_u32_be(req, height);
    return (int)phh_call(f, PLUGIN_HOSTCALL_M_CHAIN_HEADER_BY_HEIGHT, req, 4, PLUGIN_HOSTCALL_CAP_CHAIN_READ,
                         reply, cap, rep);
}

static bool phh_reply_is_header(const struct plugin_hostcall_frame *rep, const struct block_header *h)
{
    struct byte_stream s;
    stream_init(&s, 256);
    bool same = block_header_serialize(h, &s) && rep->payload_len == s.size &&
                memcmp(rep->payload, s.data, s.size) == 0;
    stream_free(&s);
    return same;
}

static int phh_case_fork_loser(void)
{
    int failures = 0;
    struct phh_fixture f;
    uint8_t reply[PLUGIN_HOSTCALL_MAX_FRAME];
    struct plugin_hostcall_frame rep;
    TEST_CASE("header_by_height returns the canonical block when a fork block shares the height") {
        ASSERT(phh_open_variant(&f, PHH_FORK_LOSER));
        ASSERT_EQ(phh_header_status(&f, 2, &rep, reply, sizeof reply), (int)PLUGIN_HOSTCALL_OK);
        ASSERT(phh_reply_is_header(&rep, &f.hdr[2]));
        ASSERT(!phh_reply_is_header(&rep, &f.fork_hdr));
        phh_close(&f);
    } TEST_END
    return failures;
}

static int phh_case_fork_stale(void)
{
    int failures = 0;
    struct phh_fixture f;
    uint8_t reply[PLUGIN_HOSTCALL_MAX_FRAME];
    struct plugin_hostcall_frame rep;
    TEST_CASE("header_by_height never serves a connected fork row the active chain does not own") {
        ASSERT(phh_open_variant(&f, PHH_FORK_STALE));
        ASSERT_EQ(phh_header_status(&f, 2, &rep, reply, sizeof reply), (int)PLUGIN_HOSTCALL_OK);
        ASSERT_EQ(rep.payload_len, 0u);
        /* Neighbours on the chain are still served. */
        ASSERT_EQ(phh_header_status(&f, 3, &rep, reply, sizeof reply), (int)PLUGIN_HOSTCALL_OK);
        ASSERT(phh_reply_is_header(&rep, &f.hdr[3]));
        phh_close(&f);
    } TEST_END
    return failures;
}

struct phh_thread_job {
    struct phh_fixture *f;
    enum plugin_hostcall_status status;
};

static void *phh_thread_main(void *arg)
{
    struct phh_thread_job *j = arg;
    uint8_t reply[PLUGIN_HOSTCALL_MAX_FRAME];
    struct plugin_hostcall_frame rep;
    j->status = phh_call(j->f, PLUGIN_HOSTCALL_M_CHAIN_TIP, NULL, 0, PLUGIN_HOSTCALL_CAP_CHAIN_READ,
                         reply, sizeof reply, &rep);
    return NULL;
}

static int phh_case_thread(void)
{
    int failures = 0;
    struct phh_fixture f;
    TEST_CASE("handlers refuse a call from any thread but the one that built the node") {
        ASSERT(phh_open(&f));
        struct phh_thread_job job = { &f, PLUGIN_HOSTCALL_OK };
        pthread_t t;
        ASSERT(pthread_create(&t, NULL, phh_thread_main, &job) == 0);
        ASSERT(pthread_join(t, NULL) == 0);
        ASSERT_EQ(job.status, PLUGIN_HOSTCALL_ERR_HANDLER);
        ASSERT_EQ(f.authority_calls, 0u);
        phh_close(&f);
    } TEST_END
    return failures;
}

static int phh_case_two_plugins(void)
{
    int failures = 0;
    struct phh_fixture f;
    uint8_t reply[256];
    struct plugin_hostcall_frame rep;
    TEST_CASE("each plugin has its own log budget") {
        ASSERT(phh_open(&f));
        struct plugin_host_node other;
        struct plugin_hostcall_handlers other_h;
        ASSERT(phh_bind(&f, &other, "wallet-ui"));
        ASSERT(plugin_host_node_handlers(&other_h, &other).ok);
        static const uint8_t req[] = { PLUGIN_HOST_LOG_INFO, 'x' };
        for (unsigned i = 0; i < PLUGIN_HOST_LOG_BURST; i++)
            ASSERT_EQ(phh_call(&f, PLUGIN_HOSTCALL_M_LOG_WRITE, req, sizeof req, 0, reply, sizeof reply, &rep),
                      PLUGIN_HOSTCALL_OK);
        ASSERT_EQ(phh_call(&f, PLUGIN_HOSTCALL_M_LOG_WRITE, req, sizeof req, 0, reply, sizeof reply, &rep),
                  PLUGIN_HOSTCALL_ERR_HANDLER);
        /* The first plugin is exhausted; the second still logs a full burst. */
        struct plugin_hostcall_handlers first = f.handlers;
        f.handlers = other_h;
        for (unsigned i = 0; i < PLUGIN_HOST_LOG_BURST; i++)
            ASSERT_EQ(phh_call(&f, PLUGIN_HOSTCALL_M_LOG_WRITE, req, sizeof req, 0, reply, sizeof reply, &rep),
                      PLUGIN_HOSTCALL_OK);
        ASSERT_STR_EQ(f.lines[f.line_count - 1], "[plugin wallet-ui] x");
        ASSERT_EQ(other.log_dropped, 0u);
        ASSERT_EQ(f.node.log_dropped, 1u);
        f.handlers = first;
        phh_close(&f);
    } TEST_END
    return failures;
}

static int phh_case_c1(void)
{
    int failures = 0;
    struct phh_fixture f;
    uint8_t reply[256];
    struct plugin_hostcall_frame rep;
    TEST_CASE("log.write drops C1 controls and bad UTF-8 but keeps valid UTF-8") {
        ASSERT(phh_open(&f));
        /* a, U+0085 (C2 85), U+009B CSI (C2 9B), lone 0x9B, lone 0xC3, e-acute, euro, b */
        static const uint8_t req[] = { PLUGIN_HOST_LOG_INFO, 'a', 0xC2, 0x85, 0xC2, 0x9B, 0x9B, 0xC3,
                                       0xC3, 0xA9, 0xE2, 0x82, 0xAC, 'b' };
        ASSERT_EQ(phh_call(&f, PLUGIN_HOSTCALL_M_LOG_WRITE, req, sizeof req, 0, reply, sizeof reply, &rep),
                  PLUGIN_HOSTCALL_OK);
        ASSERT_EQ(f.line_count, 1u);
        ASSERT_STR_EQ(f.lines[0], "[plugin explorer] a\xC3\xA9\xE2\x82\xAC" "b");
        phh_close(&f);
    } TEST_END
    return failures;
}

int test_plugin_host_handlers(void)
{
    int failures = 0;
    printf("\n=== Plugin host-call node handler tests ===\n");
    failures += phh_case_chain();
    failures += phh_case_chain_1();
    failures += phh_case_chain_2();
    failures += phh_case_chain_3();
    failures += phh_case_chain_4();
    failures += phh_case_chain_5();
    failures += phh_case_log();
    failures += phh_case_log_6();
    failures += phh_case_log_7();
    failures += phh_case_log_8();
    failures += phh_case_fork_loser();
    failures += phh_case_fork_stale();
    failures += phh_case_thread();
    failures += phh_case_two_plugins();
    failures += phh_case_c1();
    return failures;
}
