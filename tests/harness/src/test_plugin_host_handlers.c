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
#include "primitives/block.h"
#include "services/plugin_host_handlers.h"

#include <stdio.h>
#include <string.h>

#define PHH_CHAIN_LEN 5 /* one block beyond the served tip */
#define PHH_TIP 3
#define PHH_LINES 64

struct phh_fixture {
    struct node_db ndb;
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

static bool phh_open(struct phh_fixture *f)
{
    memset(f, 0, sizeof *f);
    if (!node_db_open(&f->ndb, ":memory:"))
        return false;
    static const uint8_t sol[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    for (int h = 0; h < PHH_CHAIN_LEN; h++) {
        struct block_header *b = &f->hdr[h];
        block_header_init(b);
        if (h > 0)
            memcpy(b->hashPrevBlock.data, f->hash[h - 1], 32);
        memset(b->hashMerkleRoot.data, 0x40 + h, 32);
        b->nTime = 1700000000u + 150u * (uint32_t)h;
        b->nBits = 0x1f07ffff;
        memset(b->nNonce.data, 0x10 + h, 32);
        memcpy(b->nSolution, sol, sizeof sol);
        b->nSolutionSize = sizeof sol;
        struct uint256 id;
        block_header_get_hash(b, &id);
        memcpy(f->hash[h], id.data, 32);

        struct db_block row;
        memset(&row, 0, sizeof row);
        memcpy(row.hash, id.data, 32);
        row.height = h;
        memcpy(row.prev_hash, b->hashPrevBlock.data, 32);
        row.version = b->nVersion;
        memcpy(row.merkle_root, b->hashMerkleRoot.data, 32);
        row.time = b->nTime;
        row.bits = b->nBits;
        memcpy(row.nonce, b->nNonce.data, 32);
        row.solution = (uint8_t *)sol;
        row.solution_len = sizeof sol;
        row.status = 3;
        if (!db_block_save(&f->ndb, &row))
            return false;
    }
    if (!plugin_host_node_init(&f->node, &f->ndb, "explorer").ok)
        return false;
    f->node.authority = phh_authority;
    f->node.authority_context = f;
    f->node.now_ms = phh_now;
    f->node.now_context = f;
    f->node.log_sink = phh_sink;
    f->node.log_context = f;
    f->now_ms = 1000;
    return plugin_host_node_handlers(&f->handlers, &f->node).ok;
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
        node_db_close(&f.ndb);
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
        node_db_close(&f.ndb);
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
        node_db_close(&f.ndb);
    } TEST_END
    return failures;
}

static int phh_case_chain_3(void)
{
    int failures = 0;
    struct phh_fixture f;
    uint8_t reply[PLUGIN_HOSTCALL_MAX_FRAME];
    struct plugin_hostcall_frame rep;
    const uint32_t grant = PLUGIN_HOSTCALL_CAP_CHAIN_READ;


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
        node_db_close(&f.ndb);
    } TEST_END
    return failures;
}

static int phh_case_chain_4(void)
{
    int failures = 0;
    struct phh_fixture f;
    uint8_t reply[PLUGIN_HOSTCALL_MAX_FRAME];
    struct plugin_hostcall_frame rep;
    const uint32_t grant = PLUGIN_HOSTCALL_CAP_CHAIN_READ;


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
        node_db_close(&f.ndb);
    } TEST_END
    return failures;
}

static int phh_case_chain_5(void)
{
    int failures = 0;
    struct phh_fixture f;
    uint8_t reply[PLUGIN_HOSTCALL_MAX_FRAME];
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
        node_db_close(&f.ndb);
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
        node_db_close(&f.ndb);
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
        node_db_close(&f.ndb);
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
        node_db_close(&f.ndb);
    } TEST_END
    return failures;
}

static int phh_case_log_8(void)
{
    int failures = 0;


    TEST_CASE("node init sanitizes the plugin name and refuses null") {
        struct phh_fixture g;
        ASSERT(phh_open(&g));
        struct plugin_host_node n;
        ASSERT(plugin_host_node_init(&n, &g.ndb, "a\nb\x1b" "c").ok);
        ASSERT_STR_EQ(n.plugin, "abc");
        ASSERT(!plugin_host_node_init(&n, &g.ndb, "\n\x01").ok);
        ASSERT(!plugin_host_node_init(&n, NULL, "x").ok);
        ASSERT(!plugin_host_node_handlers(NULL, &n).ok);
        node_db_close(&g.ndb);
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
    return failures;
}
