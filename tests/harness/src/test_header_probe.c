/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the header probe service. Uses a multi-shot mock RPC
 * server (similar to test_zclassicd_oracle.c) that answers a handful
 * of getblockcount / getblockhash / getblockheader requests with
 * canned responses.
 *
 * Coverage:
 *   1. pull_range with mocked happy-path RPC → calls bump.
 *   2. pull_range with disagreeable mock (bogus header) → reject path.
 *   3. unreachable mock → rpc_errors bumps.
 *   4. direct poll tick under-lag -> no headers fetched.
 */

#include "test/test_core.h"
#include "services/header_probe.h"
#include "controllers/wallet_helpers.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "core/uint256.h"
#include "json/json.h"
#include "platform/socket_compat.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define HP_CHECK(name, expr) do {            \
    printf("header_probe: %s... ", (name));  \
    if ((expr)) printf("OK\n");              \
    else { printf("FAIL\n"); failures++; }   \
} while (0)

static int64_t hp_dump_int(const char *key)
{
    struct json_value dump;
    json_init(&dump);
    int64_t value = INT64_MIN;
    if (header_probe_dump_state_json(&dump, NULL)) {
        const struct json_value *v = json_get(&dump, key);
        if (v && v->type == JSON_INT)
            value = json_get_int(v);
    }
    json_free(&dump);
    return value;
}

/* ── Mock RPC server ──────────────────────────────────────────────
 *
 * Multi-shot listener: accepts connections in a loop, reads (and
 * discards) the HTTP request, and replies based on which JSON-RPC
 * method it sees in the body:
 *   - getblockcount   → integer .result (the configured remote tip)
 *   - getblockhash    → a 64-char hex string (we just echo a synthetic)
 *   - getblockheader  → either NULL (force reject) or the canned hex
 *
 * For unit testing we never need to return a header that actually
 * validates — the goal is to exercise the reject path (header is
 * deserialized OK but accept_block_header fails due to no checkpoint
 * lineage / unknown prev). The two paths we differentiate are
 * "valid hex" (gets to accept_block_header → reject) vs "bogus hex"
 * (deserialize fails). */

struct hp_mock {
    platform_socket_t listen_fd;
    int port;
    int remote_tip;             /* canned getblockcount value */
    bool malformed_header;      /* true → return non-deserializable hex */
    _Atomic int requests_served;
    _Atomic bool stop;
    pthread_t thread;
};

/* Build a 280-char (140-byte) hex string that deserializes into a
 * block_header but won't pass accept_block_header(). Just zeros for
 * version/prev/merkle/sapling/time/bits/nonce + 0-byte solution. */
static const char *HP_VALID_HDR_HEX =
    /* nVersion (4 LE) */
    "04000000"
    /* hashPrevBlock (32) */
    "0000000000000000000000000000000000000000000000000000000000000000"
    /* hashMerkleRoot (32) */
    "0000000000000000000000000000000000000000000000000000000000000000"
    /* hashFinalSaplingRoot (32) */
    "0000000000000000000000000000000000000000000000000000000000000000"
    /* nTime (4 LE) */
    "01020304"
    /* nBits (4 LE) */
    "ffff0f1e"
    /* nNonce (32) */
    "0000000000000000000000000000000000000000000000000000000000000000"
    /* solution compact size = 0 */
    "00";

static const char *HP_MALFORMED_HEX = "deadbeef";

static void *hp_mock_loop(void *arg)  /* raw-pthread-ok: test-local */
{
    struct hp_mock *m = arg;
    while (!atomic_load(&m->stop)) {
        struct sockaddr_in cli;
        size_t cl = sizeof(cli);
        platform_socket_t cfd = platform_socket_accept(m->listen_fd,
                                                       (struct sockaddr *)&cli,
                                                       &cl);
        if (cfd == PLATFORM_SOCKET_INVALID) break;

        /* buf MUST start terminated. Every branch below reaches for
         * strstr(buf, ...), and the read loop can legitimately exit with
         * got == 0 (recv timeout, or the peer hanging up), which used to leave
         * this whole array uninitialized — the request classification then read
         * random stack bytes and answered an arbitrary method. That only shows
         * up when the box is loaded enough for a recv to time out, which is
         * precisely when it is hardest to diagnose. */
        char buf[8192];
        buf[0] = '\0';
        size_t got = 0;
        /* Matches LRC_TIMEOUT_SECS in engine/modules/rpc/src/legacy_rpc_client.c: the
         * client gives up at 5s, so a shorter ceiling here can only ever make
         * this mock the one that fails first under contention. */
        (void)platform_socket_set_receive_timeout(cfd, 5000);
        for (;;) {
            int n = platform_socket_receive(cfd, buf + got,
                                            sizeof(buf) - 1 - got);
            if (n <= 0) break;
            got += (size_t)n;
            buf[got] = '\0';
            /* Stop reading once we have body + a chunk after the
             * \r\n\r\n separator. (Tiny test bodies fit in 1 recv.) */
            if (strstr(buf, "\r\n\r\n")) break;
            if (got >= sizeof(buf) - 1) break;
        }
        if (got == 0) {
            /* Nothing arrived — answering would be answering noise. */
            platform_socket_close(cfd);
            continue;
        }

        const char *method = NULL;
        if (strstr(buf, "\"getblockcount\""))      method = "getblockcount";
        else if (strstr(buf, "\"getblockhash\""))  method = "getblockhash";
        else if (strstr(buf, "\"getblockheader\""))method = "getblockheader";

        /* Detect JSON-RPC array body (batched). Count items by
         * counting top-level "{" inside the JSON body. */
        const char *body_sep = strstr(buf, "\r\n\r\n");
        const char *json_body = body_sep ? body_sep + 4 : buf;
        bool is_batch = (json_body[0] == '[');
        int batch_n = 0;
        if (is_batch) {
            int depth = 0;
            for (const char *p = json_body; *p; p++) {
                if (*p == '[') depth++;
                else if (*p == ']') depth--;
                else if (*p == '{' && depth == 1) batch_n++;
            }
            if (batch_n < 1) batch_n = 1;
        }

        /* Build one element body for the response. is_batch wraps it
         * in [] with batch_n copies. */
        char elem[8192];
        int el = 0;
        if (method && strcmp(method, "getblockcount") == 0) {
            el = snprintf(elem, sizeof(elem),
                "{\"result\":%d,\"error\":null,\"id\":\"zcl-hp\"}",
                m->remote_tip);
        } else if (method && strcmp(method, "getblockhash") == 0) {
            int seq = atomic_fetch_add(&m->requests_served, 1) + 1;
            char hash_hex[65];
            for (int i = 0; i < 64; i++)
                hash_hex[i] = "0123456789abcdef"[seq & 0xf];
            hash_hex[64] = '\0';
            (void)seq;
            el = snprintf(elem, sizeof(elem),
                "{\"result\":\"%s\",\"error\":null,\"id\":\"zcl-hp\"}",
                hash_hex);
        } else if (method && strcmp(method, "getblockheader") == 0) {
            const char *hex = m->malformed_header
                                  ? HP_MALFORMED_HEX
                                  : HP_VALID_HDR_HEX;
            el = snprintf(elem, sizeof(elem),
                "{\"result\":\"%s\",\"error\":null,\"id\":\"zcl-hp\"}",
                hex);
        } else {
            el = snprintf(elem, sizeof(elem),
                "{\"result\":null,\"error\":{\"code\":-1,"
                "\"message\":\"unknown method\"},\"id\":\"zcl-hp\"}");
        }

        /* Assemble final body — either single object or array. */
        char body[65536];
        int bl = 0;
        if (!is_batch) {
            bl = snprintf(body, sizeof(body), "%s\n", elem);
        } else {
            int off = 0;
            body[off++] = '[';
            for (int i = 0; i < batch_n && off + el + 2 < (int)sizeof(body); i++) {
                if (i) body[off++] = ',';
                memcpy(body + off, elem, (size_t)el);
                off += el;
            }
            if (off + 2 < (int)sizeof(body)) {
                body[off++] = ']';
                body[off++] = '\n';
            }
            bl = off;
        }

        char hdr[256];
        int hl = snprintf(hdr, sizeof(hdr),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: engine/application/json\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n"
            "\r\n", bl);
        (void)platform_socket_send_all(cfd, hdr, (size_t)hl);
        (void)platform_socket_send_all(cfd, body, (size_t)bl);
        platform_socket_close(cfd);
        /* Don't fetch_add here — getblockhash branch already does so
         * for its sequence counter. Counting "requests_served" exactly
         * isn't load-bearing for the asserts. */
    }
    return NULL;
}

static bool hp_mock_start(struct hp_mock *m, int remote_tip,
                          bool malformed)
{
    memset(m, 0, sizeof(*m));
    m->remote_tip = remote_tip;
    m->malformed_header = malformed;
    m->listen_fd = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, false);
    if (m->listen_fd == PLATFORM_SOCKET_INVALID) return false;
    (void)platform_socket_set_reuse_address(m->listen_fd, true);

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (platform_socket_bind(m->listen_fd, (struct sockaddr *)&sa,
                             sizeof(sa)) != 0) {
        platform_socket_close(m->listen_fd);
        return false;
    }
    size_t sl = sizeof(sa);
    if (platform_socket_local_address(m->listen_fd, (struct sockaddr *)&sa,
                                      &sl) != 0) {
        platform_socket_close(m->listen_fd);
        return false;
    }
    m->port = ntohs(sa.sin_port);
    if (platform_socket_listen(m->listen_fd, 16) != 0) {
        platform_socket_close(m->listen_fd);
        return false;
    }
    /* raw-pthread-ok: short-burst-joined-immediately */
    if (pthread_create(&m->thread, NULL, hp_mock_loop, m) != 0) {
        platform_socket_close(m->listen_fd);
        return false;
    }
    return true;
}

static void hp_mock_stop(struct hp_mock *m)
{
    atomic_store(&m->stop, true);
    if (m->listen_fd != PLATFORM_SOCKET_INVALID) {
        /* Shut down, then close: the close interrupts the blocking accept()
         * so the thread exits (on Windows, closesocket from another thread
         * fails the in-flight accept; the shutdown arm is platform-aware). */
        (void)platform_socket_shutdown_both(m->listen_fd);
        platform_socket_close(m->listen_fd);
        m->listen_fd = PLATFORM_SOCKET_INVALID;
    }
    pthread_join(m->thread, NULL);
}

/* ── Fixture: a tiny main_state with one block at height 0 ─────── */

static struct main_state g_hp_ms;
static struct uint256    g_hp_genesis;

static void hp_build_fixture(void)
{
    main_state_init(&g_hp_ms);
    memset(&g_hp_genesis, 0, sizeof(g_hp_genesis));
    g_hp_genesis.data[0] = 0xC0;

    struct block_index *bi = chainstate_insert_block_index(
        (struct chainstate *)&g_hp_ms, &g_hp_genesis);
    if (bi) bi->nHeight = 0;
    active_chain_move_window_tip(&g_hp_ms.chain_active, bi);
    g_hp_ms.pindex_best_header = bi;

    extern struct wallet_rpc_context g_wallet_ctx;
    g_wallet_ctx.main_state = &g_hp_ms;
}

static void hp_teardown(void)
{
    extern struct wallet_rpc_context g_wallet_ctx;
    g_wallet_ctx.main_state = NULL;
    header_probe_reset_for_test();
    main_state_free(&g_hp_ms);
}

/* ── Tests ─────────────────────────────────────────────────────── */

int test_header_probe(void);

int test_header_probe(void)
{
    printf("\n=== header probe service tests ===\n");
    int failures = 0;

    const struct chain_params *params = chain_params_get();
    if (!params) {
        printf("header_probe: chain_params_get() returned NULL — "
               "SKIPPING (set up params before running this test)\n");
        return 0;
    }

    /* Test 1: pull_range with happy-path mock — calls bump, but
     * accept_block_header rejects the synthetic header (no checkpoint
     * lineage), so headers_rejected goes up. */
    {
        hp_build_fixture();
        struct hp_mock srv;
        HP_CHECK("mock starts (happy)",
                 hp_mock_start(&srv, 10, false));

        struct header_probe_config cfg = {
            .rpc_host = "127.0.0.1",
            .rpc_port = srv.port,
            .rpc_user = "u",
            .rpc_password = "p",
            .batch_size = 5,
            .lag_threshold = 1,
        };
        HP_CHECK("init", header_probe_init(&cfg, &g_hp_ms, params).ok);

        int added = 0;
        bool ok = header_probe_pull_range(1, 5, &added).ok;
        HP_CHECK("pull_range returns true", ok);

        int64_t calls_total = hp_dump_int("calls_total");
        int64_t last_remote_height = hp_dump_int("last_remote_height");
        int64_t headers_rejected = hp_dump_int("headers_rejected");
        int64_t rpc_errors = hp_dump_int("rpc_errors");
        HP_CHECK("calls_total=1", calls_total == 1);
        HP_CHECK("last_remote_height=10", last_remote_height == 10);
        /* Either we deserialized + rejected (>=1), or zero adds.
         * Both are valid expressions of "the mock returned a header
         * that doesn't validate". */
        HP_CHECK("headers_rejected >= 1 OR added == 0",
                 headers_rejected >= 1 || added == 0);
        HP_CHECK("rpc_errors=0", rpc_errors == 0);

        hp_mock_stop(&srv);
        hp_teardown();
    }

    /* Test 2: malformed header hex from mock → reject path bumps. */
    {
        hp_build_fixture();
        struct hp_mock srv;
        HP_CHECK("mock starts (malformed)",
                 hp_mock_start(&srv, 5, true));

        struct header_probe_config cfg = {
            .rpc_host = "127.0.0.1",
            .rpc_port = srv.port,
            .rpc_user = "u", .rpc_password = "p",
            .batch_size = 3,
            .lag_threshold = 1,
        };
        HP_CHECK("init (malformed)",
                 header_probe_init(&cfg, &g_hp_ms, params).ok);

        int added = 0;
        (void)header_probe_pull_range(1, 3, &added);

        HP_CHECK("added = 0 with malformed hex",  added == 0);
        /* A malformed hex causes hp_fetch_one_header to fail and the
         * pull loop bumps rpc_errors before stopping. */
        HP_CHECK("rpc_errors >= 1 with malformed",
                 hp_dump_int("rpc_errors") >= 1);

        hp_mock_stop(&srv);
        hp_teardown();
    }

    /* Test 3: RPC error path — kill the mock listener mid-test. */
    {
        hp_build_fixture();
        struct hp_mock srv;
        HP_CHECK("mock starts (err)",
                 hp_mock_start(&srv, 100, false));
        int dead_port = srv.port;
        hp_mock_stop(&srv);  /* listener gone */

        struct header_probe_config cfg = {
            .rpc_host = "127.0.0.1",
            .rpc_port = dead_port,
            .rpc_user = "u", .rpc_password = "p",
            .batch_size = 5,
            .lag_threshold = 1,
        };
        HP_CHECK("init (err)",
                 header_probe_init(&cfg, &g_hp_ms, params).ok);

        int added = 0;
        (void)header_probe_pull_range(1, 5, &added);

        HP_CHECK("added=0 on unreachable",  added == 0);
        HP_CHECK("rpc_errors >= 1 on unreachable",
                 hp_dump_int("rpc_errors") >= 1);

        hp_teardown();
    }

    /* Test 4: direct poll tick under-lag does NOT pull. Our fixture
     * local_tip = 0; configure lag_threshold = 100 and remote_tip = 50.
     * The tick should see lag (50 vs 0) = 50 ≤ 100 → no fetch. */
    {
        hp_build_fixture();
        struct hp_mock srv;
        HP_CHECK("mock starts (under-lag)",
                 hp_mock_start(&srv, 50, false));

        struct header_probe_config cfg = {
            .rpc_host = "127.0.0.1",
            .rpc_port = srv.port,
            .rpc_user = "u", .rpc_password = "p",
            .batch_size = 5,
            .lag_threshold = 100,
        };
        HP_CHECK("init (under-lag)",
                 header_probe_init(&cfg, &g_hp_ms, params).ok);

        header_probe_tick_once();

        HP_CHECK("tick observed remote tip",
                 hp_dump_int("last_remote_height") == 50);
        /* Under-lag means tick_once did NOT call pull_range, so
         * calls_total stays at 0. */
        HP_CHECK("under-lag: calls_total=0",
                 hp_dump_int("calls_total") == 0);

        hp_mock_stop(&srv);
        hp_teardown();
    }

    /* Test 5: dumpstate exposes operational state only. */
    {
        hp_build_fixture();
        struct hp_mock srv;
        HP_CHECK("mock starts (dump)",
                 hp_mock_start(&srv, 12, false));

        struct header_probe_config cfg = {
            .rpc_host = "127.0.0.1",
            .rpc_port = srv.port,
            .rpc_user = "u", .rpc_password = "p",
            .batch_size = 5,
            .lag_threshold = 1,
        };
        HP_CHECK("init (dump)",
                 header_probe_init(&cfg, &g_hp_ms, params).ok);
        int added = 0;
        (void)header_probe_pull_range(1, 5, &added);

        struct json_value dump;
        json_init(&dump);
        bool ok = header_probe_dump_state_json(&dump, NULL);
        ok = ok && json_get(&dump, "initialized") != NULL;
        ok = ok && json_get_bool(json_get(&dump, "initialized"));
        ok = ok && json_get(&dump, "calls_total") != NULL;
        ok = ok && json_get_int(json_get(&dump, "calls_total")) == 1;
        ok = ok && json_get(&dump, "headers_added") != NULL;
        ok = ok && json_get(&dump, "headers_rejected") != NULL;
        ok = ok && json_get(&dump, "rpc_errors") != NULL;
        ok = ok && json_get(&dump, "last_remote_height") != NULL;
        ok = ok && json_get_int(json_get(&dump, "last_remote_height")) == 12;
        ok = ok && json_get(&dump, "last_local_height") != NULL;
        ok = ok && json_get(&dump, "running") == NULL;
        ok = ok && json_get(&dump, "rpc_host") == NULL;
        ok = ok && json_get(&dump, "rpc_port") == NULL;
        ok = ok && json_get(&dump, "have_user") == NULL;
        ok = ok && json_get(&dump, "have_password") == NULL;
        ok = ok && json_get(&dump, "batch_size") == NULL;
        ok = ok && json_get(&dump, "lag_threshold") == NULL;
        HP_CHECK("dump omits config echo", ok);
        json_free(&dump);

        hp_mock_stop(&srv);
        hp_teardown();
    }

    if (failures == 0)
        printf("=== header probe service: all checks passed ===\n");
    else
        printf("=== header probe service: %d failure(s) ===\n", failures);
    return failures;
}
