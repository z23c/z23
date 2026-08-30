/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the zclassicd oracle service. The mock RPC server is a
 * single-threaded loop that listens on a high port and replies to one
 * HTTP/1.1 JSON-RPC POST with a canned `result` hex string.
 *
 * Coverage:
 *   1. probe agrees when local block_index hash matches mock response.
 *   2. probe disagrees when mock returns a different hash.
 *   3. probe records rpc_errors when the mock listener is shut down.
 *   4. supervisor tick increments probes_total.
 */

#include "test/test_core.h"
#include "services/zclassicd_oracle_service.h"
#include "services/chain_evidence_authority_service.h"
#include "services/legacy_mirror_sync_service.h"
#include "services/sync_monitor.h"
#include "controllers/wallet_helpers.h"
#include "validation/process_block.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "validation/mirror_consensus.h"
#include "chain/chain.h"
#include "core/uint256.h"
#include "event/event.h"
#include "util/blocker.h"
#include "util/clientversion.h"
#include "util/supervisor.h"

#include <pthread.h>
#include <stdatomic.h>
#define _GNU_SOURCE 1
#define _DEFAULT_SOURCE 1

#include "platform/socket_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#define ZO_CHECK(name, expr) do {              \
    printf("oracle: %s... ", (name));          \
    if ((expr)) printf("OK\n");                \
    else { printf("FAIL\n"); failures++; }     \
} while (0)

/* ── Mock RPC server ──────────────────────────────────────────────
 *
 * Single-shot listener: accepts one connection, reads (and discards)
 * the HTTP request, writes a canned JSON-RPC response, closes. Spawns
 * a fresh thread per test so each test's port is fresh.
 *
 * `canned_hex` may be NULL (sends a JSON error body) or a 64-char
 * hex string for the .result field. */

struct mock_server {
    platform_socket_t listen_fd;
    int port;
    const char *canned_hex;       /* NULL → respond with JSON error */
    const char *chain_tip_hex;    /* optional distinct hash at chain_blocks */
    int chain_blocks;             /* >=0 → getblockchaininfo response */
    bool chain_omit_headers;      /* true → omit optional result.headers */
    bool chain_empty_result;      /* true → malformed empty chain-info result */
    bool chain_warmup;            /* true → getblockchaininfo RPC warmup */
    bool blockhash_warmup;        /* true → getblockhash RPC warmup */
    int blockhash_failures_remaining;
    _Atomic int requests_served;
    _Atomic bool stop;
    pthread_t thread;
};

static void *mock_server_loop(void *arg)  /* raw-pthread-ok: test-local */
{
    struct mock_server *m = arg;
    while (!atomic_load(&m->stop)) {
        struct sockaddr_in cli;
        size_t cl = sizeof(cli);
        platform_socket_t cfd = platform_socket_accept(m->listen_fd,
                                                       (struct sockaddr *)&cli,
                                                       &cl);
        if (cfd == PLATFORM_SOCKET_INVALID) break;

        /* Read until we see end-of-headers marker (\r\n\r\n), then
         * consume up to Content-Length more bytes. Time-bounded by
         * the recv timeout below. */
        /* buf MUST start terminated: every dispatch branch below calls
         * strstr(buf, ...), and this loop can exit with got == 0 on a recv
         * timeout or an early hangup. Leaving the array uninitialized in that
         * case made the mock classify random stack bytes as an RPC method —
         * a failure mode that needs a loaded machine to appear at all. */
        char buf[4096];
        buf[0] = '\0';
        size_t got = 0;
        /* 5s to match LRC_TIMEOUT_SECS in lib/rpc/src/legacy_rpc_client.c;
         * a tighter ceiling only makes the mock give up before the client
         * does when the box is contended. */
        (void)platform_socket_set_receive_timeout(cfd, 5000);
        for (;;) {
            int n = platform_socket_receive(cfd, buf + got,
                                            sizeof(buf) - 1 - got);
            if (n <= 0) break;
            got += (size_t)n;
            buf[got] = '\0';
            if (strstr(buf, "\r\n\r\n")) break;
            if (got >= sizeof(buf) - 1) break;
        }
        if (got == 0) {
            /* Nothing arrived — do not answer noise. */
            platform_socket_close(cfd);
            continue;
        }

        /* Build JSON-RPC body */
        char body[256];
        int bl;
        if ((m->chain_warmup && strstr(buf, "getblockchaininfo")) ||
            (m->blockhash_warmup && strstr(buf, "getblockhash"))) {
            bl = snprintf(body, sizeof(body),
                "{\"result\":null,\"error\":{\"code\":-28,"
                "\"message\":\"Activating best chain... height 0 (1%%)\"},"
                "\"id\":\"zcl-oracle\"}\n");
        } else if (m->chain_blocks >= 0 &&
                   strstr(buf, "getblockchaininfo")) {
            if (m->chain_empty_result) {
                bl = snprintf(body, sizeof(body),
                    "{\"result\":{},\"error\":null,\"id\":\"zcl-oracle\"}\n");
            } else if (m->chain_omit_headers) {
                bl = snprintf(body, sizeof(body),
                    "{\"result\":{\"blocks\":%d},"
                    "\"error\":null,\"id\":\"zcl-oracle\"}\n",
                    m->chain_blocks);
            } else {
                bl = snprintf(body, sizeof(body),
                    "{\"result\":{\"blocks\":%d,\"headers\":%d},"
                    "\"error\":null,\"id\":\"zcl-oracle\"}\n",
                    m->chain_blocks, m->chain_blocks);
            }
        } else if (m->blockhash_failures_remaining > 0 &&
                   strstr(buf, "getblockhash")) {
            m->blockhash_failures_remaining--;
            bl = snprintf(body, sizeof(body),
                "{\"result\":null,\"error\":{\"code\":-1,"
                "\"message\":\"transient hash failure\"},"
                "\"id\":\"zcl-oracle\"}\n");
        } else if (m->canned_hex) {
            const char *response_hex = m->canned_hex;
            char tip_param[32];
            snprintf(tip_param, sizeof(tip_param),
                     "\"params\":[%d]", m->chain_blocks);
            if (m->chain_tip_hex && strstr(buf, "getblockhash") &&
                strstr(buf, tip_param)) {
                response_hex = m->chain_tip_hex;
            }
            bl = snprintf(body, sizeof(body),
                "{\"result\":\"%s\",\"error\":null,\"id\":\"zcl-oracle\"}\n",
                response_hex);
        } else {
            bl = snprintf(body, sizeof(body),
                "{\"result\":null,\"error\":{\"code\":-1,"
                "\"message\":\"mock failure\"},\"id\":\"zcl-oracle\"}\n");
        }

        char resp[512];
        int rl = snprintf(resp, sizeof(resp),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n"
            "\r\n%s", bl, body);
        (void)platform_socket_send_all(cfd, resp, (size_t)rl);
        platform_socket_close(cfd);
        atomic_fetch_add(&m->requests_served, 1);
    }

    return NULL;
}

static bool mock_server_start(struct mock_server *m, const char *canned_hex)
{
    memset(m, 0, sizeof(*m));
    m->canned_hex = canned_hex;
    m->chain_blocks = -1;
    m->listen_fd = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, false);
    if (m->listen_fd == PLATFORM_SOCKET_INVALID) return false;

    (void)platform_socket_set_reuse_address(m->listen_fd, true);

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;  /* OS-chosen */
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
    if (platform_socket_listen(m->listen_fd, 4) != 0) {
        platform_socket_close(m->listen_fd);
        return false;
    }
    /* raw-pthread-ok: short-burst-joined-immediately */
    if (pthread_create(&m->thread, NULL, mock_server_loop, m) != 0) {
        platform_socket_close(m->listen_fd);
        return false;
    }
    return true;
}

static bool mock_server_start_chain(struct mock_server *m,
                                    const char *canned_hex,
                                    int blocks)
{
    bool ok = mock_server_start(m, canned_hex);
    if (ok)
        m->chain_blocks = blocks;
    return ok;
}

static bool mock_server_start_chain_with_tip(struct mock_server *m,
                                             const char *common_hex,
                                             const char *tip_hex,
                                             int blocks)
{
    bool ok = mock_server_start_chain(m, common_hex, blocks);
    if (ok)
        m->chain_tip_hex = tip_hex;
    return ok;
}

static bool mock_server_start_chain_with_hash_retry(struct mock_server *m,
                                                    const char *canned_hex,
                                                    int blocks)
{
    bool ok = mock_server_start_chain(m, canned_hex, blocks);
    if (ok)
        m->blockhash_failures_remaining = 1;
    return ok;
}

static bool mock_server_start_chain_blocks_only(struct mock_server *m,
                                                const char *canned_hex,
                                                int blocks)
{
    bool ok = mock_server_start_chain(m, canned_hex, blocks);
    if (ok)
        m->chain_omit_headers = true;
    return ok;
}

static bool mock_server_start_chain_empty_result(struct mock_server *m,
                                                 const char *canned_hex)
{
    bool ok = mock_server_start_chain(m, canned_hex, 0);
    if (ok)
        m->chain_empty_result = true;
    return ok;
}

static bool mock_server_start_chain_warmup(struct mock_server *m,
                                           const char *canned_hex)
{
    bool ok = mock_server_start(m, canned_hex);
    if (ok)
        m->chain_warmup = true;
    return ok;
}

static bool mock_server_start_blockhash_warmup(struct mock_server *m)
{
    bool ok = mock_server_start(m, NULL);
    if (ok)
        m->blockhash_warmup = true;
    return ok;
}

static void mock_server_stop(struct mock_server *m)
{
    atomic_store(&m->stop, true);
    /* Closing the listen socket interrupts the blocking accept() so the
     * thread exits (closesocket from another thread fails the in-flight
     * accept on Windows). */
    if (m->listen_fd != PLATFORM_SOCKET_INVALID) {
        platform_socket_close(m->listen_fd);
        m->listen_fd = PLATFORM_SOCKET_INVALID;
    }
    pthread_join(m->thread, NULL);
}

/* ── Fixture: a tiny main_state with one block at height 7 ─────── */

static struct main_state g_zo_ms;
static struct uint256    g_zo_hash7;

static void zo_build_fixture(const char *hex64_at_h7)
{
    main_state_init(&g_zo_ms);
    uint256_set_hex(&g_zo_hash7, hex64_at_h7);

    /* Insert blocks 0..7 with synthetic hashes; height 7 = our fixture. */
    struct uint256 fillers[8];
    memset(fillers, 0, sizeof(fillers));
    for (int h = 0; h < 7; h++) {
        fillers[h].data[0] = (uint8_t)(0xC0 + h);
        struct block_index *bi = chainstate_insert_block_index(
            (struct chainstate *)&g_zo_ms, &fillers[h]);
        if (bi) bi->nHeight = h;
    }
    struct block_index *bi7 = chainstate_insert_block_index(
        (struct chainstate *)&g_zo_ms, &g_zo_hash7);
    if (bi7) bi7->nHeight = 7;

    /* Build active_chain[0..7] */
    for (int h = 0; h <= 7; h++) {
        const struct uint256 *hp = (h < 7) ? &fillers[h] : &g_zo_hash7;
        struct block_index *bi = block_map_find(&g_zo_ms.map_block_index, hp);
        active_chain_move_window_tip(&g_zo_ms.chain_active, bi);
    }

    /* Wire main_state into wallet_rpc_context (read by oracle service). */
    extern struct wallet_rpc_context g_wallet_ctx;
    g_wallet_ctx.main_state = &g_zo_ms;
}

static void zo_teardown(void)
{
    extern struct wallet_rpc_context g_wallet_ctx;
    g_wallet_ctx.main_state = NULL;
    main_state_free(&g_zo_ms);
    zclassicd_oracle_reset_for_test();
}

/* ── Tests ─────────────────────────────────────────────────────── */

int test_zclassicd_oracle(void);

int test_zclassicd_oracle(void)
{
    printf("\n=== zclassicd oracle tests ===\n");
    int failures = 0;

    const char *AGREE_HEX =
        "1111111122222222333333334444444455555555666666667777777788888888";
    const char *DISAGREE_HEX =
        "ffffffffeeeeeeeeddddddddccccccccbbbbbbbbaaaaaaaa9999999988888888";

    /* Test 1: probe agrees when mock returns the matching hash. */
    {
        zo_build_fixture(AGREE_HEX);
        struct mock_server srv;
        ZO_CHECK("mock server starts (agree)",
                 mock_server_start(&srv, AGREE_HEX));

        struct zclassicd_oracle_config cfg = {
            .rpc_host = "127.0.0.1",
            .rpc_port = srv.port,
            .rpc_user = "u",
            .rpc_password = "p",
            .cadence_secs = 60,
            .heights_per_tick = 1,
        };
        ZO_CHECK("init", zclassicd_oracle_init(&cfg).ok);

        struct zclassicd_oracle_probe_result r;
        bool ok = zclassicd_oracle_probe(7, &r).ok;
        ZO_CHECK("probe returned true", ok);
        ZO_CHECK("no rpc error",    !r.error);
        ZO_CHECK("our_have_block",   r.our_have_block);
        ZO_CHECK("hashes match",     r.match);
        ZO_CHECK("their_hash set",
                 strcasecmp(r.their_hash, AGREE_HEX) == 0);

        struct zclassicd_oracle_stats st;
        zclassicd_oracle_stats_snapshot(&st);
        ZO_CHECK("attempts_total=1",  st.attempts_total == 1);
        ZO_CHECK("probes_total=1",    st.probes_total == 1);
        ZO_CHECK("probes_agree=1",    st.probes_agree == 1);
        ZO_CHECK("probes_disagree=0", st.probes_disagree == 0);
        ZO_CHECK("rpc_errors=0",      st.rpc_errors == 0);
        ZO_CHECK("transport reachable", st.rpc_transport_reachable);
        ZO_CHECK("oracle usable",       st.oracle_usable);
        ZO_CHECK("reachable alias true", st.reachable);
        ZO_CHECK("last error empty",    st.last_error[0] == '\0');
        ZO_CHECK("last attempt height", st.last_attempt_height == 7);
        ZO_CHECK("last attempt time",   st.last_attempt_unix_us > 0);

        mock_server_stop(&srv);
        zo_teardown();
    }

    /* Legacy advisory disagreement must block mirror adoption, not freeze
     * native publication evidence. */
    {
        zo_build_fixture(AGREE_HEX);
        struct mock_server srv;
        struct node_db ndb;
        ZO_CHECK("mock server starts (legacy contradiction)",
                 mock_server_start_chain(&srv, DISAGREE_HEX, 7));
        ZO_CHECK("legacy contradiction node_db opens",
                 node_db_open(&ndb, ":memory:"));
        process_block_set_node_db(&ndb);

        struct legacy_mirror_sync_config cfg = {
            .rpc_host = "127.0.0.1",
            .rpc_port = srv.port,
            .rpc_user = "u",
            .rpc_password = "p",
            .cadence_secs = 60,
            .max_blocks_tick = 8,
            .lag_sla = 1,
            .enabled = true,
        };
        ZO_CHECK("legacy mirror init for contradiction",
                 legacy_mirror_sync_init(&cfg, &g_zo_ms, NULL, NULL, NULL).ok);
        struct zcl_result catchup =
            legacy_mirror_sync_request_catchup_result("unit-contradiction");
        ZO_CHECK("legacy mirror catchup rejects contradiction",
                 !catchup.ok);
        ZO_CHECK("legacy mirror catchup names blocker",
                 strstr(catchup.message, "hash-disagreement") != NULL);

        struct chain_state_repository empty_csr = {0};
        struct chain_evidence_controller authority;
        struct chain_evidence_controller_view view;
        chain_evidence_controller_init(&authority, &ndb, &empty_csr);
        chain_evidence_controller_snapshot(&authority, &view);
        ZO_CHECK("legacy contradiction does not freeze evidence",
                 view.state != CEC_CONTRADICTION_FROZEN);
        ZO_CHECK("legacy contradiction leaves no freeze reason",
                 view.contradiction_reason[0] == '\0');

        struct legacy_mirror_sync_stats lms;
        legacy_mirror_sync_stats_snapshot(&lms);
        ZO_CHECK("legacy contradiction surfaces blocker",
                 strcmp(lms.last_blocker_id, "hash-disagreement") == 0);
        ZO_CHECK("legacy contradiction binds mismatch height",
                 lms.hash_disagreement_height == 7);
        ZO_CHECK("legacy contradiction does not claim rewind",
                 lms.authority_rewind_target == 0);

        mock_server_stop(&srv);
        catchup = legacy_mirror_sync_request_catchup_result(
            "unit-contradiction-then-rpc-down");
        ZO_CHECK("legacy contradiction followed by RPC loss still fails",
                 !catchup.ok);
        legacy_mirror_sync_stats_snapshot(&lms);
        ZO_CHECK("unknown comparison preserves prior mismatch as causal",
                 strcmp(lms.last_blocker_id, "hash-disagreement") == 0 &&
                 strcmp(lms.activation_blocker_reason,
                        "hash-disagreement") == 0 &&
                 lms.hash_disagreement_height == 7 &&
                 !lms.comparison_known);
        ZO_CHECK("RPC loss remains visible as secondary typed blocker",
                 blocker_exists("mirror.rpc-unreachable"));

        process_block_set_node_db(NULL);
        node_db_close(&ndb);
        legacy_mirror_sync_reset_for_test();
        blocker_clear("mirror.rpc-unreachable");
        zo_teardown();
    }

    /* A lagged node can be on the exact same chain.  The mirror must compare
     * both hashes at the local/common height, clear only the stale hash
     * blocker, and keep the independently sampled tip hashes unequal. */
    {
        zo_build_fixture(AGREE_HEX);
        struct mock_server srv;
        ZO_CHECK("mock server starts (lagged common-height agreement)",
                 mock_server_start_chain_with_tip(
                     &srv, AGREE_HEX, DISAGREE_HEX, 9));

        struct legacy_mirror_sync_stats seeded;
        memset(&seeded, 0, sizeof(seeded));
        seeded.enabled = true;
        seeded.running = true;
        seeded.hash_disagreement_height = 7;
        snprintf(seeded.last_blocker_id, sizeof(seeded.last_blocker_id),
                 "%s", "hash-disagreement");
        legacy_mirror_sync_test_set_stats(&seeded, &g_zo_ms);
        mirror_consensus_record_blocker("hash-disagreement");

        struct legacy_mirror_sync_config cfg = {
            .rpc_host = "127.0.0.1",
            .rpc_port = srv.port,
            .rpc_user = "u",
            .rpc_password = "p",
            .cadence_secs = 60,
            .max_blocks_tick = 8,
            .lag_sla = 1,
            .enabled = true,
        };
        ZO_CHECK("legacy mirror init for lagged agreement",
                 legacy_mirror_sync_init(&cfg, &g_zo_ms, NULL, NULL, NULL).ok);
        struct zcl_result catchup =
            legacy_mirror_sync_request_catchup_result("unit-lagged-agreement");
        ZO_CHECK("legacy mirror accepts lagged same-chain state", catchup.ok);

        struct legacy_mirror_sync_stats lms;
        legacy_mirror_sync_stats_snapshot(&lms);
        ZO_CHECK("legacy mirror records explicit common comparison",
                 lms.comparison_known && lms.comparison_hashes_agree &&
                 lms.comparison_height == 7 &&
                 strcasecmp(lms.comparison_zclassic23_hash, AGREE_HEX) == 0 &&
                 strcasecmp(lms.comparison_zclassicd_hash, AGREE_HEX) == 0);
        ZO_CHECK("legacy mirror does not compare different-height tips",
                 lms.local_height == 7 && lms.legacy_height == 9 &&
                 !lms.tip_hashes_agree &&
                 strcasecmp(lms.zclassic23_hash, AGREE_HEX) == 0 &&
                 strcasecmp(lms.zclassicd_hash, DISAGREE_HEX) == 0);
        ZO_CHECK("legacy mirror resolves exact stale hash blocker",
                 lms.last_blocker_id[0] == '\0' &&
                 lms.activation_blocker_reason[0] == '\0' &&
                 !blocker_exists("mirror.hash-disagreement"));
        ZO_CHECK("legacy mirror remains catching up",
                 lms.lag_known && lms.lag == 2 &&
                 strcmp(lms.state, "catching_up") == 0);

        struct json_value root;
        json_init(&root);
        json_set_object(&root);
        ZO_CHECK("lagged common comparison dump succeeds",
                 legacy_mirror_sync_dump_state_json(&root, NULL));
        ZO_CHECK("lagged dump exposes same-chain comparison",
                 json_get_bool(json_get(&root, "comparison_known")) &&
                 json_get_bool(json_get(&root, "comparison_hashes_agree")) &&
                 json_get_int(json_get(&root, "comparison_height")) == 7 &&
                 json_get_bool(json_get(
                     &root, "same_chain_at_comparison_height")));
        ZO_CHECK("lagged dump keeps tip agreement false",
                 !json_get_bool(json_get(&root, "tip_hashes_agree")));
        json_free(&root);

        mock_server_stop(&srv);
        legacy_mirror_sync_reset_for_test();
        blocker_clear("mirror.hash-comparison-unavailable");
        blocker_clear("mirror.rpc-unreachable");
        zo_teardown();
    }

    /* The independently sampled remote tip may fail once.  If the mandatory
     * same-height comparison retry succeeds, it is also the exact tip proof
     * and must refresh both tip caches for downstream health consumers. */
    {
        zo_build_fixture(AGREE_HEX);
        struct mock_server srv;
        ZO_CHECK("mock server starts (tip hash retry)",
                 mock_server_start_chain_with_hash_retry(&srv, AGREE_HEX, 7));
        struct legacy_mirror_sync_config cfg = {
            .rpc_host = "127.0.0.1",
            .rpc_port = srv.port,
            .rpc_user = "u",
            .rpc_password = "p",
            .cadence_secs = 60,
            .max_blocks_tick = 8,
            .lag_sla = 1,
            .enabled = true,
        };
        ZO_CHECK("legacy mirror init for tip hash retry",
                 legacy_mirror_sync_init(&cfg, &g_zo_ms, NULL, NULL, NULL).ok);
        struct zcl_result catchup =
            legacy_mirror_sync_request_catchup_result("unit-tip-hash-retry");
        ZO_CHECK("legacy mirror accepts successful comparison retry",
                 catchup.ok);
        struct legacy_mirror_sync_stats lms;
        legacy_mirror_sync_stats_snapshot(&lms);
        ZO_CHECK("comparison retry refreshes exact tip hashes",
                 lms.tip_hashes_agree && lms.comparison_known &&
                 lms.comparison_hashes_agree &&
                 lms.comparison_height == 7 &&
                 strcasecmp(lms.zclassic23_hash, AGREE_HEX) == 0 &&
                 strcasecmp(lms.zclassicd_hash, AGREE_HEX) == 0);
        mock_server_stop(&srv);
        legacy_mirror_sync_reset_for_test();
        zo_teardown();
    }

    /* Chain info alone is not a usable height/hash oracle. Two failed hash
     * samples latch an observation blocker; a later exact comparison must
     * clear only that blocker even while the local node remains lagged. */
    {
        zo_build_fixture(AGREE_HEX);
        struct mock_server srv;
        ZO_CHECK("mock server starts (hash observation recovery)",
                 mock_server_start_chain(&srv, AGREE_HEX, 9));
        srv.blockhash_failures_remaining = 2;
        struct legacy_mirror_sync_config cfg = {
            .rpc_host = "127.0.0.1",
            .rpc_port = srv.port,
            .rpc_user = "u",
            .rpc_password = "p",
            .cadence_secs = 60,
            .max_blocks_tick = 8,
            .lag_sla = 1,
            .enabled = true,
        };
        ZO_CHECK("legacy mirror init for hash observation recovery",
                 legacy_mirror_sync_init(&cfg, &g_zo_ms, NULL, NULL, NULL).ok);
        struct zcl_result first =
            legacy_mirror_sync_request_catchup_result("unit-hash-failure");
        ZO_CHECK("hash observation failure is named", !first.ok);
        struct legacy_mirror_sync_stats lms;
        legacy_mirror_sync_stats_snapshot(&lms);
        ZO_CHECK("chain info without hash leaves oracle unusable",
                 lms.reachable && lms.lag_known &&
                 !lms.comparison_known && !lms.legacy_oracle_usable &&
                 strcmp(lms.last_blocker_id, "rpc-unreachable") == 0 &&
                 strcmp(lms.activation_blocker_reason,
                        "rpc-unreachable") == 0 &&
                 blocker_exists("mirror.rpc-unreachable"));

        struct zcl_result second =
            legacy_mirror_sync_request_catchup_result("unit-hash-recovery");
        ZO_CHECK("later exact lagged comparison succeeds", second.ok);
        legacy_mirror_sync_stats_snapshot(&lms);
        ZO_CHECK("exact comparison restores usable hash oracle",
                 lms.comparison_known && lms.comparison_hashes_agree &&
                 lms.legacy_oracle_usable);
        ZO_CHECK("exact comparison clears observation blocker everywhere",
                 lms.last_blocker_id[0] == '\0' &&
                 lms.activation_blocker_reason[0] == '\0' &&
                 !blocker_exists("mirror.rpc-unreachable"));

        mock_server_stop(&srv);
        legacy_mirror_sync_reset_for_test();
        blocker_clear("mirror.rpc-unreachable");
        zo_teardown();
    }

    /* zclassicd variants may omit result.headers while still reporting
     * result.blocks. That must be treated as blocks==headers, not as an RPC
     * schema failure. */
    {
        zo_build_fixture(AGREE_HEX);
        struct mock_server srv;
        ZO_CHECK("mock server starts (legacy blocks-only chain info)",
                 mock_server_start_chain_blocks_only(&srv, AGREE_HEX, 7));

        struct legacy_mirror_sync_config cfg = {
            .rpc_host = "127.0.0.1",
            .rpc_port = srv.port,
            .rpc_user = "u",
            .rpc_password = "p",
            .cadence_secs = 60,
            .max_blocks_tick = 8,
            .lag_sla = 1,
            .enabled = true,
        };
        ZO_CHECK("legacy mirror init for blocks-only chain info",
                 legacy_mirror_sync_init(&cfg, &g_zo_ms, NULL, NULL, NULL).ok);
        struct zcl_result catchup =
            legacy_mirror_sync_request_catchup_result("unit-blocks-only");
        ZO_CHECK("legacy mirror accepts blocks-only chain info", catchup.ok);

        struct legacy_mirror_sync_stats lms;
        legacy_mirror_sync_stats_snapshot(&lms);
        ZO_CHECK("legacy mirror blocks-only sets headers from blocks",
                 lms.legacy_height == 7 && lms.legacy_headers == 7);
        ZO_CHECK("legacy mirror blocks-only stays reachable", lms.reachable);
        ZO_CHECK("legacy mirror blocks-only does not report headers error",
                 strstr(lms.last_error, "result.headers") == NULL);

        mock_server_stop(&srv);
        legacy_mirror_sync_reset_for_test();
        zo_teardown();
    }

    /* If the required result.blocks field is missing, optional headers parsing
     * must not overwrite the more precise required-field error. */
    {
        zo_build_fixture(AGREE_HEX);
        struct mock_server srv;
        ZO_CHECK("mock server starts (legacy empty chain info)",
                 mock_server_start_chain_empty_result(&srv, AGREE_HEX));

        struct legacy_mirror_sync_config cfg = {
            .rpc_host = "127.0.0.1",
            .rpc_port = srv.port,
            .rpc_user = "u",
            .rpc_password = "p",
            .cadence_secs = 60,
            .max_blocks_tick = 8,
            .lag_sla = 1,
            .enabled = true,
        };
        ZO_CHECK("legacy mirror init for empty chain info",
                 legacy_mirror_sync_init(&cfg, &g_zo_ms, NULL, NULL, NULL).ok);
        struct zcl_result catchup =
            legacy_mirror_sync_request_catchup_result("unit-empty-chain-info");
        ZO_CHECK("legacy mirror rejects empty chain info", !catchup.ok);
        ZO_CHECK("legacy mirror empty chain info names blocks",
                 strstr(catchup.message, "missing int result.blocks") != NULL);
        ZO_CHECK("legacy mirror empty chain info does not name headers",
                 strstr(catchup.message, "result.headers") == NULL);

        struct legacy_mirror_sync_stats lms;
        legacy_mirror_sync_stats_snapshot(&lms);
        ZO_CHECK("legacy mirror empty chain info last_error names blocks",
                 strstr(lms.last_error, "missing int result.blocks") != NULL);

        mock_server_stop(&srv);
        legacy_mirror_sync_reset_for_test();
        zo_teardown();
    }

    /* JSON-RPC warmup (-28) must survive the mirror's object-field parser.
     * Otherwise a reachable-but-activating zclassicd is misdiagnosed as a
     * schema mismatch like "missing int result.headers". */
    {
        zo_build_fixture(AGREE_HEX);
        struct mock_server srv;
        ZO_CHECK("mock server starts (legacy warmup)",
                 mock_server_start_chain_warmup(&srv, AGREE_HEX));

        struct legacy_mirror_sync_config cfg = {
            .rpc_host = "127.0.0.1",
            .rpc_port = srv.port,
            .rpc_user = "u",
            .rpc_password = "p",
            .cadence_secs = 60,
            .max_blocks_tick = 8,
            .lag_sla = 1,
            .enabled = true,
        };
        ZO_CHECK("legacy mirror init for warmup",
                 legacy_mirror_sync_init(&cfg, &g_zo_ms, NULL, NULL, NULL).ok);
        struct zcl_result catchup =
            legacy_mirror_sync_request_catchup_result("unit-warmup");
        ZO_CHECK("legacy mirror warmup returns failure", !catchup.ok);
        ZO_CHECK("legacy mirror warmup preserves rpc error",
                 strstr(catchup.message,
                        "rpc error -28: Activating best chain") != NULL);

        struct legacy_mirror_sync_stats lms;
        legacy_mirror_sync_stats_snapshot(&lms);
        ZO_CHECK("legacy mirror warmup names rpc blocker",
                 strcmp(lms.last_blocker_id, "rpc-unreachable") == 0);
        ZO_CHECK("legacy mirror warmup last_error is precise",
                 strstr(lms.last_error,
                        "rpc error -28: Activating best chain") != NULL);
        ZO_CHECK("legacy mirror warmup transport reachable",
                 lms.zclassicd_rpc_transport_reachable);
        ZO_CHECK("legacy mirror warmup oracle unusable",
                 !lms.legacy_oracle_usable);
        ZO_CHECK("legacy mirror warmup old reachable false", !lms.reachable);
        ZO_CHECK("legacy mirror warmup code",
                 lms.zclassicd_rpc_error_code == -28);
        ZO_CHECK("legacy mirror warmup message",
                 strstr(lms.zclassicd_rpc_error_message,
                        "Activating best chain") != NULL);
        struct json_value warmup_dump;
        json_init(&warmup_dump);
        json_set_object(&warmup_dump);
        ZO_CHECK("legacy mirror warmup dump succeeds",
                 legacy_mirror_sync_dump_state_json(&warmup_dump, NULL));
        ZO_CHECK("legacy mirror warmup dump transport",
                 json_get_bool(json_get(&warmup_dump,
                                        "zclassicd_rpc_transport_reachable")));
        ZO_CHECK("legacy mirror warmup dump unusable",
                 !json_get_bool(json_get(&warmup_dump,
                                         "legacy_oracle_usable")));
        ZO_CHECK("legacy mirror warmup dump code",
                 json_get_int(json_get(&warmup_dump,
                                       "zclassicd_rpc_error_code")) == -28);
        ZO_CHECK("legacy mirror warmup dump message",
                 strstr(json_get_str(json_get(
                            &warmup_dump, "zclassicd_rpc_error_message")),
                        "Activating best chain") != NULL);
        json_free(&warmup_dump);

        mock_server_stop(&srv);
        legacy_mirror_sync_reset_for_test();
        zo_teardown();
    }

    /* Test 2: probe disagrees when mock returns a different hash. */
    {
        zo_build_fixture(AGREE_HEX);
        struct mock_server srv;
        ZO_CHECK("mock server starts (disagree)",
                 mock_server_start(&srv, DISAGREE_HEX));

        struct zclassicd_oracle_config cfg = {
            .rpc_host = "127.0.0.1",
            .rpc_port = srv.port,
            .rpc_user = "u", .rpc_password = "p",
            .cadence_secs = 60, .heights_per_tick = 1,
        };
        ZO_CHECK("init (disagree)", zclassicd_oracle_init(&cfg).ok);

        struct zclassicd_oracle_probe_result r;
        (void)zclassicd_oracle_probe(7, &r);
        ZO_CHECK("disagree: no rpc error", !r.error);
        ZO_CHECK("disagree: !match",       !r.match);
        ZO_CHECK("disagree: have_block",    r.our_have_block);

        struct zclassicd_oracle_stats st;
        zclassicd_oracle_stats_snapshot(&st);
        ZO_CHECK("probes_disagree=1", st.probes_disagree == 1);
        ZO_CHECK("probes_agree=0",    st.probes_agree == 0);

        mock_server_stop(&srv);
        zo_teardown();
    }

    /* Test 3: RPC error path — kill the mock listener mid-test. */
    {
        zo_build_fixture(AGREE_HEX);
        struct mock_server srv;
        ZO_CHECK("mock server starts (err)",
                 mock_server_start(&srv, AGREE_HEX));
        int dead_port = srv.port;
        mock_server_stop(&srv);  /* listener gone */

        struct zclassicd_oracle_config cfg = {
            .rpc_host = "127.0.0.1",
            .rpc_port = dead_port,
            .rpc_user = "u", .rpc_password = "p",
            .cadence_secs = 60, .heights_per_tick = 1,
        };
        ZO_CHECK("init (err)", zclassicd_oracle_init(&cfg).ok);

        struct zclassicd_oracle_probe_result r;
        (void)zclassicd_oracle_probe(7, &r);
        ZO_CHECK("error flag set", r.error);

        struct zclassicd_oracle_stats st;
        zclassicd_oracle_stats_snapshot(&st);
        ZO_CHECK("err attempts_total=1", st.attempts_total == 1);
        ZO_CHECK("rpc_errors >= 1", st.rpc_errors >= 1);
        ZO_CHECK("err transport unreachable", !st.rpc_transport_reachable);
        ZO_CHECK("err oracle unusable", !st.oracle_usable);
        ZO_CHECK("err reachable alias false", !st.reachable);
        ZO_CHECK("err last attempt height", st.last_attempt_height == 7);
        ZO_CHECK("err last error height", st.last_error_height == 7);
        ZO_CHECK("err last error time", st.last_error_unix_us > 0);
        ZO_CHECK("err last error populated", st.last_error[0] != '\0');

        zo_teardown();
    }

    /* Test 4: JSON-RPC warmup error on getblockhash is a reachable transport
     * dependency but an unusable oracle. */
    {
        zo_build_fixture(AGREE_HEX);
        struct mock_server srv;
        ZO_CHECK("mock server starts (oracle warmup)",
                 mock_server_start_blockhash_warmup(&srv));

        struct zclassicd_oracle_config cfg = {
            .rpc_host = "127.0.0.1",
            .rpc_port = srv.port,
            .rpc_user = "u", .rpc_password = "p",
            .cadence_secs = 60, .heights_per_tick = 1,
        };
        ZO_CHECK("init (oracle warmup)", zclassicd_oracle_init(&cfg).ok);

        struct zclassicd_oracle_probe_result r;
        (void)zclassicd_oracle_probe(7, &r);
        ZO_CHECK("oracle warmup sets error", r.error);
        ZO_CHECK("oracle warmup preserves code",
                 strstr(r.error_msg, "rpc error -28") != NULL);

        struct zclassicd_oracle_stats st;
        zclassicd_oracle_stats_snapshot(&st);
        ZO_CHECK("oracle warmup attempts_total=1", st.attempts_total == 1);
        ZO_CHECK("oracle warmup no usable probe", st.probes_total == 0);
        ZO_CHECK("oracle warmup rpc_errors=1", st.rpc_errors == 1);
        ZO_CHECK("oracle warmup transport reachable",
                 st.rpc_transport_reachable);
        ZO_CHECK("oracle warmup unusable", !st.oracle_usable);
        ZO_CHECK("oracle warmup reachable alias false", !st.reachable);
        ZO_CHECK("oracle warmup last attempt height",
                 st.last_attempt_height == 7);
        ZO_CHECK("oracle warmup last error height", st.last_error_height == 7);
        ZO_CHECK("oracle warmup last error code", st.last_error_code == -28);
        ZO_CHECK("oracle warmup last error text",
                 strstr(st.last_error, "Activating best chain") != NULL);

        struct json_value root;
        json_init(&root);
        json_set_object(&root);
        ZO_CHECK("oracle warmup dump succeeds",
                 zclassicd_oracle_dump_state_json(&root, NULL));
        ZO_CHECK("oracle dump transport reachable",
                 json_get_bool(json_get(&root, "rpc_transport_reachable")));
        ZO_CHECK("oracle dump unusable",
                 !json_get_bool(json_get(&root, "oracle_usable")));
        ZO_CHECK("oracle dump last error code",
                 json_get_int(json_get(&root, "last_error_code")) == -28);
        ZO_CHECK("oracle dump last attempt nonzero",
                 json_get_int(json_get(&root, "last_attempt_unix_us")) > 0);
        json_free(&root);

        mock_server_stop(&srv);
        zo_teardown();
    }

    /* Test 5: supervisor tick increments probes_total. We fire the
     * supervisor at sub-second cadence by setting a small interval, and
     * lower the tip safety margin so our synthetic chain at h=7 still
     * has a valid probe range. */
    {
        setenv("ZCL_ORACLE_TIP_MARGIN", "0", 1);
        zo_build_fixture(AGREE_HEX);
        struct mock_server srv;
        ZO_CHECK("mock server starts (tick)",
                 mock_server_start(&srv, AGREE_HEX));

        struct zclassicd_oracle_config cfg = {
            .rpc_host = "127.0.0.1",
            .rpc_port = srv.port,
            .rpc_user = "u", .rpc_password = "p",
            .cadence_secs = 1,     /* fastest cadence */
            .heights_per_tick = 1,
        };
        ZO_CHECK("init (tick)", zclassicd_oracle_init(&cfg).ok);

        supervisor_reset_for_testing();
        supervisor_set_tick_ms_for_testing(50);
        ZO_CHECK("oracle_start", zclassicd_oracle_start().ok);
        struct supervisor_snapshot snaps[SUPERVISOR_CAP];
        int snap_n = supervisor_snapshot_all(snaps, SUPERVISOR_CAP);
        bool saw_contract = false;
        bool period_ok = false;
        bool deadline_ok = false;
        for (int i = 0; i < snap_n; i++) {
            if (strcmp(snaps[i].name, "oracle.zclassicd") == 0) {
                saw_contract = true;
                period_ok = snaps[i].period_secs == 1;
                deadline_ok = snaps[i].deadline_secs == 0;
            }
        }
        ZO_CHECK("supervisor contract registered", saw_contract);
        ZO_CHECK("supervisor period is cadence", period_ok);
        ZO_CHECK("supervisor deadline disabled", deadline_ok);

        /* Wait up to ~3s for the periodic tick. */
        bool saw_tick = false;
        for (int i = 0; i < 60; i++) {
            struct zclassicd_oracle_stats st;
            zclassicd_oracle_stats_snapshot(&st);
            if (st.probes_total >= 1) { saw_tick = true; break; }
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 50 * 1000 * 1000 };
            nanosleep(&ts, NULL);
        }
        ZO_CHECK("periodic tick fired", saw_tick);

        zclassicd_oracle_stop();
        supervisor_reset_for_testing();
        mock_server_stop(&srv);
        zo_teardown();
        unsetenv("ZCL_ORACLE_TIP_MARGIN");
    }

    /* Auto mode is advisory: an absent co-located zclassicd must remain
     * visible in oracle.rpc_errors but must not become a node/supervisor
     * liveness stall (or launch a debug-bundle storm). */
    {
        setenv("ZCL_ORACLE_TIP_MARGIN", "0", 1);
        zo_build_fixture(AGREE_HEX);
        struct zclassicd_oracle_config cfg = {
            .rpc_host = "127.0.0.1",
            .rpc_port = 1, /* closed by contract in this hermetic fixture */
            .rpc_user = "u", .rpc_password = "p",
            .cadence_secs = 1,
            .heights_per_tick = 1,
        };
        ZO_CHECK("init (absent optional oracle)",
                 zclassicd_oracle_init(&cfg).ok);

        supervisor_reset_for_testing();
        supervisor_set_tick_ms_for_testing(50);
        ZO_CHECK("oracle_start (absent optional oracle)",
                 zclassicd_oracle_start().ok);

        bool saw_error = false;
        for (int i = 0; i < 60; i++) {
            struct zclassicd_oracle_stats st;
            zclassicd_oracle_stats_snapshot(&st);
            if (st.rpc_errors >= 1) {
                saw_error = true;
                break;
            }
            struct timespec ts = {
                .tv_sec = 0, .tv_nsec = 50 * 1000 * 1000,
            };
            nanosleep(&ts, NULL);
        }
        ZO_CHECK("absent optional oracle records the dependency error",
                 saw_error);

        struct supervisor_snapshot snaps[SUPERVISOR_CAP];
        int snap_n = supervisor_snapshot_all(snaps, SUPERVISOR_CAP);
        const struct supervisor_snapshot *oracle = NULL;
        for (int i = 0; i < snap_n; i++) {
            if (strcmp(snaps[i].name, "oracle.zclassicd") == 0) {
                oracle = &snaps[i];
                break;
            }
        }
        ZO_CHECK("absent optional oracle contract remains registered",
                 oracle != NULL);
        ZO_CHECK("absent optional oracle is idle, never stalled",
                 oracle && oracle->stall_reason == SUPERVISOR_STALL_NONE &&
                 oracle->stall_fires == 0 && oracle->idle_ticks >= 1);

        zclassicd_oracle_stop();
        supervisor_reset_for_testing();
        zo_teardown();
        unsetenv("ZCL_ORACLE_TIP_MARGIN");
    }

    {
        /* F-1e: scope/auth machinery deleted. Tests now verify the
         * surviving observability primitives:
         *   - mirror_consensus_record_override (emits decision event)
         *   - mirror_consensus_record_blocker  (typed-blocker primitive)
         *   - mirror_consensus_stats_snapshot   (counters)
         * All overrides are classified "unsafe" now since there is no
         * authorized scope to validate them. */
        char events[4096];
        size_t events_len;
        event_log_init();
        mirror_consensus_reset_for_test();
        mirror_consensus_set_enabled(true);
        mirror_consensus_record_override(7, "bad-txns-BIP30");
        struct mirror_consensus_stats ms;
        mirror_consensus_stats_snapshot(&ms);
        ZO_CHECK("mirror override counted", ms.overrides_total == 1);
        ZO_CHECK("mirror override classified unsafe (no scope)",
                 ms.unsafe_overrides_total == 1);
        ZO_CHECK("mirror override marked unsafe", !ms.last_override_safe);
        ZO_CHECK("mirror override scope recorded",
                 strcmp(ms.last_override_scope,
                        "unsafe_no_authorized_scope") == 0);
        ZO_CHECK("mirror blockers initially zero", ms.blockers_total == 0);
        ZO_CHECK("mirror override height", ms.last_override_height == 7);
        ZO_CHECK("mirror override reason",
                 strcmp(ms.last_override_reason, "bad-txns-BIP30") == 0);
        events_len = event_dump_json(events, sizeof(events), 8);
        events[events_len < sizeof(events) ? events_len : sizeof(events) - 1] =
            '\0';
        ZO_CHECK("mirror override event visible",
                 strstr(events, "mirror.consensus_decision") != NULL);
        ZO_CHECK("mirror override event authority",
                 strstr(events,
                        "authority=local_consensus_validation") != NULL);
        ZO_CHECK("mirror override event advisory",
                 strstr(events,
                        "trust=bounded_advisory_fallback") != NULL);
        ZO_CHECK("mirror override event reason",
                 strstr(events, "reason=bad-txns-BIP30") != NULL);
        ZO_CHECK("mirror override event count",
                 strstr(events, "overrides=1") != NULL);
        mirror_consensus_record_blocker("activation-no-progress");
        mirror_consensus_stats_snapshot(&ms);
        ZO_CHECK("mirror blocker counted", ms.blockers_total == 1);
        ZO_CHECK("mirror blocker records precise code",
                 strcmp(ms.activation_blocker_reason,
                        "activation-no-progress") == 0);
        events_len = event_dump_json(events, sizeof(events), 8);
        events[events_len < sizeof(events) ? events_len : sizeof(events) - 1] =
            '\0';
        ZO_CHECK("mirror blocker event visible",
                 strstr(events, "op=blocker") != NULL);
        ZO_CHECK("mirror blocker event reason",
                 strstr(events, "reason=activation-no-progress") != NULL);
        ZO_CHECK("mirror blocker event count",
                 strstr(events, "blockers=1") != NULL);
        ZO_CHECK("mirror blocker event blocker code",
                 strstr(events, "blk=activation-no-progress") != NULL);
        ZO_CHECK("hash disagreement remains transient",
                 mirror_consensus_classify_blocker_reason(
                     "hash-disagreement") == BLOCKER_TRANSIENT);
        ZO_CHECK("body hash mismatch is permanent",
                 mirror_consensus_classify_blocker_reason(
                     "body-hash-mismatch") == BLOCKER_PERMANENT);
        ZO_CHECK("header hash mismatch is permanent",
                 mirror_consensus_classify_blocker_reason(
                     "header-hash-mismatch") == BLOCKER_PERMANENT);
        ZO_CHECK("merkle root mismatch is permanent",
                 mirror_consensus_classify_blocker_reason(
                     "merkle-root-mismatch") == BLOCKER_PERMANENT);
        ZO_CHECK("consensus reject is permanent",
                 mirror_consensus_classify_blocker_reason(
                     "consensus-reject") == BLOCKER_PERMANENT);
        ZO_CHECK("rpc unreachable is transient",
                 mirror_consensus_classify_blocker_reason(
                     "rpc-unreachable") == BLOCKER_TRANSIENT);
        blocker_clear("mirror.hash-disagreement");
        ZO_CHECK("non-hash blocker cannot use automatic resolver",
                 !mirror_consensus_resolve_hash_disagreement());
        mirror_consensus_stats_snapshot(&ms);
        ZO_CHECK("non-hash blocker remains latched",
                 strcmp(ms.activation_blocker_reason,
                        "activation-no-progress") == 0);
        mirror_consensus_record_blocker("hash-disagreement");
        ZO_CHECK("hash blocker enters typed registry",
                 blocker_exists("mirror.hash-disagreement"));
        ZO_CHECK("hash blocker exact resolver succeeds",
                 mirror_consensus_resolve_hash_disagreement());
        mirror_consensus_stats_snapshot(&ms);
        ZO_CHECK("hash resolver clears latch and typed record",
                 ms.activation_blocker_reason[0] == '\0' &&
                 !blocker_exists("mirror.hash-disagreement"));
        ZO_CHECK("resolved hash blocker cannot resolve twice",
                 !mirror_consensus_resolve_hash_disagreement());
        blocker_clear("mirror.activation-no-progress");
        mirror_consensus_reset_for_test();
    }

    {
        struct legacy_mirror_sync_stats stats;
        struct json_value root;
        const struct json_value *state;
        const struct json_value *authority;
        const struct json_value *build_commit;
        const struct json_value *mirror_enabled;
        const struct json_value *trust;
        const struct json_value *lag_known;
        const struct json_value *candidate_lag_known;
        const struct json_value *lag_observed;
        const struct json_value *overrides;
        const struct json_value *blockers_total;
        const struct json_value *override_height;
        const struct json_value *override_reason;
        const struct json_value *unsafe_overrides;
        const struct json_value *override_safe;
        const struct json_value *override_scope;
        const struct json_value *blocker;
        const struct json_value *last_blocker_code;
        const struct json_value *contract;
        const struct json_value *stalls_total;
        const struct json_value *local_recovery_active;
        const struct json_value *local_retries_exhausted;

        sync_monitor_init();
        zo_build_fixture(AGREE_HEX);
        legacy_mirror_sync_reset_for_test();
        mirror_consensus_set_enabled(true);
        mirror_consensus_record_override(123, "body-hash-mismatch");
        mirror_consensus_record_blocker("body-hash-mismatch");

        memset(&stats, 0, sizeof(stats));
        stats.enabled = true;
        stats.running = true;
        stats.reachable = true;
        stats.legacy_height = 8;
        stats.legacy_headers = 8;
        stats.local_height = 7;
        stats.best_header_height = 8;
        stats.target_height = 8;
        stats.stalls_total = 2;
        snprintf(stats.stuck_reason, sizeof(stats.stuck_reason),
                 "%s", "no-authorized-child");
        snprintf(stats.last_blocker_id, sizeof(stats.last_blocker_id),
                 "%s", "body-hash-mismatch");
        legacy_mirror_sync_test_set_stats(&stats, &g_zo_ms);

        json_init(&root);
        json_set_object(&root);
        ZO_CHECK("legacy mirror dump succeeds",
                 legacy_mirror_sync_dump_state_json(&root, NULL));
        state = json_get(&root, "state");
        authority = json_get(&root, "consensus_authority");
        build_commit = json_get(&root, "build_commit");
        mirror_enabled = json_get(&root, "mirror_authorization_enabled");
        trust = json_get(&root, "candidate_trust");
        lag_known = json_get(&root, "lag_known");
        candidate_lag_known = json_get(&root, "candidate_lag_known");
        lag_observed = json_get(&root, "lag_observed");
        overrides = json_get(&root, "overrides_total");
        unsafe_overrides = json_get(&root, "unsafe_overrides_total");
        blockers_total = json_get(&root, "blockers_total");
        override_height = json_get(&root, "last_override_height");
        override_safe = json_get(&root, "last_override_safe");
        override_scope = json_get(&root, "last_override_scope");
        override_reason = json_get(&root, "last_override_reason");
        blocker = json_get(&root, "activation_blocker");
        last_blocker_code = json_get(&root, "last_blocker_code");
        contract = json_get(&root, "mirror_contract");
        stalls_total = json_get(&root, "stalls_total");
        local_recovery_active = json_get(&root, "local_recovery_active");
        local_retries_exhausted = json_get(&root, "local_retries_exhausted");

        ZO_CHECK("legacy mirror dump state is blocked",
                 state && strcmp(json_get_str(state), "blocked") == 0);
        ZO_CHECK("legacy mirror dump authority stays local",
                 authority &&
                 strcmp(json_get_str(authority),
                        "local_consensus_validation") == 0);
        ZO_CHECK("legacy mirror dump build commit identifies runtime",
                 build_commit &&
                 strcmp(json_get_str(build_commit), zcl_build_commit()) == 0);
        ZO_CHECK("legacy mirror dump omits mirror authorization",
                 mirror_enabled == NULL);
        ZO_CHECK("legacy mirror dump trust is bounded advisory",
                 trust &&
                 strcmp(json_get_str(trust),
                        "bounded_advisory_fallback") == 0);
        ZO_CHECK("legacy mirror dump lag is known when reachable",
                 lag_known && json_get_bool(lag_known));
        ZO_CHECK("legacy mirror dump candidate lag is known when reachable",
                 candidate_lag_known && json_get_bool(candidate_lag_known));
        ZO_CHECK("legacy mirror dump observed lag is numeric when reachable",
                 lag_observed && !json_is_null(lag_observed) &&
                 json_get_int(lag_observed) == 1);
        ZO_CHECK("legacy mirror dump override count",
                 overrides && json_get_int(overrides) == 1);
        ZO_CHECK("legacy mirror dump unsafe override count",
                 unsafe_overrides && json_get_int(unsafe_overrides) == 1);
        ZO_CHECK("legacy mirror dump blocker count",
                 blockers_total && json_get_int(blockers_total) == 1);
        ZO_CHECK("legacy mirror dump override height",
                 override_height && json_get_int(override_height) == 123);
        ZO_CHECK("legacy mirror dump override safe flag",
                 override_safe && !json_get_bool(override_safe));
        ZO_CHECK("legacy mirror dump override scope",
                 override_scope &&
                 strcmp(json_get_str(override_scope),
                        "unsafe_no_authorized_scope") == 0);
        ZO_CHECK("legacy mirror dump override reason",
                 override_reason &&
                 strcmp(json_get_str(override_reason),
                        "body-hash-mismatch") == 0);
        ZO_CHECK("legacy mirror dump activation blocker",
                 blocker &&
                 strcmp(json_get_str(blocker),
                        "body-hash-mismatch") == 0);
        ZO_CHECK("legacy mirror dump last blocker code",
                 last_blocker_code &&
                 strcmp(json_get_str(last_blocker_code),
                        "body-hash-mismatch") == 0);
        ZO_CHECK("legacy mirror contract exists",
                 contract && contract->type == JSON_OBJ);
        ZO_CHECK("legacy mirror contract schema",
                 strcmp(json_get_str(json_get(contract, "schema")),
                        "zcl.mirror_status.v2") == 0);
        ZO_CHECK("legacy mirror contract authority",
                 json_get_bool(json_get(contract, "advisory_only")) &&
                 strcmp(json_get_str(json_get(contract, "consensus_authority")),
                        "local_consensus_validation") == 0);
        ZO_CHECK("legacy mirror contract blocked status",
                 strcmp(json_get_str(json_get(contract, "status")),
                        "blocked") == 0);
        ZO_CHECK("legacy mirror contract active blocker",
                 json_get_bool(json_get(contract, "blocker_active")) &&
                 strcmp(json_get_str(json_get(contract, "blocker_code")),
                        "body-hash-mismatch") == 0);
        ZO_CHECK("legacy mirror contract operator action",
                 json_get_bool(json_get(contract,
                                        "operator_action_required")));
        ZO_CHECK("legacy mirror contract lag",
                 json_get_int(json_get(contract, "lag_blocks")) == 1 &&
                 !json_get_bool(json_get(contract, "same_height")));
        ZO_CHECK("legacy mirror dump stall count",
                 stalls_total && json_get_int(stalls_total) == 2);
        ZO_CHECK("legacy mirror dump local recovery field",
                 local_recovery_active &&
                 !json_get_bool(local_recovery_active));
        ZO_CHECK("legacy mirror dump local retry field",
                 local_retries_exhausted &&
                 !json_get_bool(local_retries_exhausted));
        json_free(&root);
        legacy_mirror_sync_reset_for_test();
        zo_teardown();
    }

    {
        struct legacy_mirror_sync_stats stats;
        struct legacy_mirror_sync_stats snap;
        struct json_value root;
        const struct json_value *contract;

        zo_build_fixture(AGREE_HEX);
        legacy_mirror_sync_reset_for_test();
        mirror_consensus_reset_for_test();
        memset(&stats, 0, sizeof(stats));
        stats.enabled = true;
        stats.running = true;
        stats.reachable = true;
        stats.local_height = 7;
        stats.legacy_height = 7;
        stats.legacy_headers = 7;
        legacy_mirror_sync_test_set_stats(&stats, &g_zo_ms);
        mirror_consensus_record_blocker("activation-no-progress");

        legacy_mirror_sync_stats_snapshot(&snap);
        ZO_CHECK("legacy mirror at tip suppresses stale activation blocker",
                 snap.activation_blocker_reason[0] == '\0' &&
                 snap.last_blocker_id[0] == '\0');
        ZO_CHECK("legacy mirror at tip reports healthy after catchup",
                 strcmp(snap.state, "healthy") == 0);
        ZO_CHECK("legacy mirror at tip has known lag",
                 snap.lag_known && snap.lag_valid && snap.lag == 0);
        legacy_mirror_sync_reset_for_test();
        mirror_consensus_reset_for_test();
        zo_teardown();

        zo_build_fixture(AGREE_HEX);
        legacy_mirror_sync_reset_for_test();
        mirror_consensus_reset_for_test();
        memset(&stats, 0, sizeof(stats));
        stats.enabled = true;
        stats.running = true;
        stats.reachable = true;
        stats.local_height = 7;
        stats.legacy_height = 7;
        stats.legacy_headers = 7;
        stats.hash_disagreement_height = 7;
        snprintf(stats.zclassicd_hash, sizeof(stats.zclassicd_hash),
                 "%s", AGREE_HEX);
        snprintf(stats.last_blocker_id, sizeof(stats.last_blocker_id),
                 "%s", "db-writer-busy");
        legacy_mirror_sync_test_set_stats(&stats, &g_zo_ms);
        mirror_consensus_record_blocker("hash-disagreement");

        legacy_mirror_sync_stats_snapshot(&snap);
        ZO_CHECK("hash recovery preserves different local blocker",
                 snap.blocker_recovered_by_tip_agreement &&
                 strcmp(snap.last_blocker_id, "db-writer-busy") == 0 &&
                 snap.activation_blocker_reason[0] == '\0' &&
                 legacy_mirror_sync_blocker_is_active(&snap) &&
                 strcmp(snap.state, "blocked") == 0);
        json_init(&root);
        json_set_object(&root);
        ZO_CHECK("mixed blocker recovery dump succeeds",
                 legacy_mirror_sync_dump_state_json(&root, NULL));
        contract = json_get(&root, "mirror_contract");
        const struct json_value *health = json_get(&root, "_health");
        ZO_CHECK("mixed blocker remains active in mirror contract",
                 contract &&
                 json_get_bool(json_get(contract, "blocker_active")) &&
                 strcmp(json_get_str(json_get(contract, "blocker_code")),
                        "db-writer-busy") == 0 &&
                 json_get_bool(json_get(contract,
                                        "operator_action_required")));
        ZO_CHECK("mixed blocker remains unhealthy in diagnostics",
                 health && !json_get_bool(json_get(health, "ok")) &&
                 strcmp(json_get_str(json_get(health, "reason")),
                        "db-writer-busy") == 0);
        json_free(&root);
        legacy_mirror_sync_reset_for_test();
        mirror_consensus_reset_for_test();
        blocker_clear("mirror.db-writer-busy");
        blocker_clear("mirror.hash-disagreement");
        zo_teardown();

        zo_build_fixture(AGREE_HEX);
        legacy_mirror_sync_reset_for_test();
        mirror_consensus_reset_for_test();
        memset(&stats, 0, sizeof(stats));
        stats.enabled = true;
        stats.running = true;
        stats.reachable = true;
        stats.local_height = 7;
        stats.legacy_height = 9;
        stats.legacy_headers = 9;
        stats.hash_disagreement_height = 7;
        stats.comparison_height = 6;
        stats.comparison_known = true;
        stats.comparison_hashes_agree = true;
        snprintf(stats.comparison_zclassic23_hash,
                 sizeof(stats.comparison_zclassic23_hash), "%s", AGREE_HEX);
        snprintf(stats.comparison_zclassicd_hash,
                 sizeof(stats.comparison_zclassicd_hash), "%s", AGREE_HEX);
        snprintf(stats.last_blocker_id, sizeof(stats.last_blocker_id),
                 "%s", "hash-disagreement");
        legacy_mirror_sync_test_set_stats(&stats, &g_zo_ms);
        mirror_consensus_record_blocker("hash-disagreement");

        legacy_mirror_sync_stats_snapshot(&snap);
        ZO_CHECK("lower comparison cannot resolve higher mismatch",
                 strcmp(snap.last_blocker_id, "hash-disagreement") == 0 &&
                 strcmp(snap.activation_blocker_reason,
                        "hash-disagreement") == 0 &&
                 !snap.blocker_recovered_by_common_height_agreement &&
                 strcmp(snap.state, "blocked") == 0);
        legacy_mirror_sync_reset_for_test();
        blocker_clear("mirror.hash-disagreement");
        zo_teardown();

        zo_build_fixture(AGREE_HEX);
        legacy_mirror_sync_reset_for_test();
        mirror_consensus_reset_for_test();
        memset(&stats, 0, sizeof(stats));
        stats.enabled = true;
        stats.running = true;
        stats.reachable = true;
        stats.local_height = 7;
        stats.legacy_height = 7;
        stats.legacy_headers = 7;
        stats.hash_disagreement_height = 7;
        snprintf(stats.zclassicd_hash, sizeof(stats.zclassicd_hash),
                 "%s", AGREE_HEX);
        stats.last_progress_blocks = 1;
        snprintf(stats.last_blocker_id, sizeof(stats.last_blocker_id),
                 "%s", "hash-disagreement");
        legacy_mirror_sync_test_set_stats(&stats, &g_zo_ms);
        sync_monitor_test_set_local_recovery(true, true, 3170884, 3,
                                             "local_header_refill");
        mirror_consensus_record_blocker("hash-disagreement");

        legacy_mirror_sync_stats_snapshot(&snap);
        ZO_CHECK("legacy mirror matching tip preserves recovery context",
                 snap.local_recovery_active &&
                 snap.local_retries_exhausted &&
                 snap.local_missing_height == 3170884 &&
                 snap.local_retry_count == 3);
        ZO_CHECK("legacy mirror matching tip records hash agreement",
                 snap.tip_hashes_agree);
        ZO_CHECK("legacy mirror at matching tip suppresses stale hash blocker",
                 snap.activation_blocker_reason[0] == '\0' &&
                 snap.last_blocker_id[0] == '\0');
        ZO_CHECK("legacy mirror records hash blocker recovery",
                 snap.blocker_recovered_by_tip_agreement);
        ZO_CHECK("legacy mirror matching tip reports healthy",
                 strcmp(snap.state, "healthy") == 0);
        json_init(&root);
        json_set_object(&root);
        ZO_CHECK("legacy mirror recovery dump succeeds",
                 legacy_mirror_sync_dump_state_json(&root, NULL));
        ZO_CHECK("legacy mirror recovery dump reports healthy at tip",
                 strcmp(json_get_str(json_get(&root, "state")),
                        "healthy") == 0);
        ZO_CHECK("legacy mirror recovery dump active code empty",
                 strcmp(json_get_str(json_get(&root, "active_error_code")),
                        "") == 0);
        ZO_CHECK("legacy mirror recovery dump candidate blocker empty",
                 strcmp(json_get_str(json_get(&root, "candidate_blocker")),
                        "") == 0);
        ZO_CHECK("legacy mirror recovery dump activation blocker empty",
                 strcmp(json_get_str(json_get(&root, "activation_blocker")),
                        "") == 0);
        ZO_CHECK("legacy mirror recovery dump hash agreement true",
                 json_get_bool(json_get(&root, "tip_hashes_agree")));
        ZO_CHECK("legacy mirror recovery dump keeps local retry context",
                 json_get_bool(json_get(&root, "local_recovery_active")) &&
                 json_get_bool(json_get(&root, "local_retries_exhausted")) &&
                 json_get_int(json_get(&root, "local_missing_height")) ==
                     3170884 &&
                 json_get_int(json_get(&root, "local_retry_count")) == 3);
        ZO_CHECK("legacy mirror recovery dump flag true",
                 json_get_bool(json_get(&root,
                     "blocker_recovered_by_tip_agreement")));
        contract = json_get(&root, "mirror_contract");
        ZO_CHECK("legacy mirror recovery contract exists",
                 contract && contract->type == JSON_OBJ);
        ZO_CHECK("legacy mirror recovery contract healthy",
                 strcmp(json_get_str(json_get(contract, "status")),
                        "healthy") == 0);
        ZO_CHECK("legacy mirror recovery contract authority",
                 json_get_bool(json_get(contract, "advisory_only")) &&
                 strcmp(json_get_str(json_get(contract, "consensus_authority")),
                        "local_consensus_validation") == 0);
        ZO_CHECK("legacy mirror recovery contract no active blocker",
                 !json_get_bool(json_get(contract, "blocker_active")) &&
                 strcmp(json_get_str(json_get(contract, "blocker_code")),
                        "") == 0 &&
                 !json_get_bool(json_get(contract,
                                         "operator_action_required")));
        ZO_CHECK("legacy mirror recovery contract same hash",
                 json_get_bool(json_get(contract, "same_height")) &&
                 json_get_bool(json_get(contract, "tip_hashes_agree")));
        ZO_CHECK("legacy mirror recovery contract semantics",
                 json_get(contract, "semantics") != NULL);
        json_free(&root);
        sync_monitor_test_set_local_recovery(false, false, 0, 0, NULL);
        legacy_mirror_sync_reset_for_test();
        mirror_consensus_reset_for_test();
        zo_teardown();

        zo_build_fixture(AGREE_HEX);
        legacy_mirror_sync_reset_for_test();
        memset(&stats, 0, sizeof(stats));
        stats.enabled = true;
        stats.running = true;
        stats.reachable = true;
        stats.legacy_height = 4;
        stats.legacy_headers = 4;
        snprintf(stats.last_blocker_id, sizeof(stats.last_blocker_id),
                 "%s", "");
        legacy_mirror_sync_test_set_stats(&stats, &g_zo_ms);

        legacy_mirror_sync_stats_snapshot(&snap);
        ZO_CHECK("legacy mirror behind local observes",
                 strcmp(snap.state, "observing") == 0);
        ZO_CHECK("legacy mirror behind local has negative lag",
                 snap.lag_known && snap.lag_valid && snap.lag < 0);
        ZO_CHECK("legacy mirror behind local not blocked",
                 snap.activation_blocker_reason[0] == '\0' &&
                 snap.last_blocker_id[0] == '\0');
        legacy_mirror_sync_reset_for_test();
        zo_teardown();

        zo_build_fixture(AGREE_HEX);
        legacy_mirror_sync_reset_for_test();
        memset(&stats, 0, sizeof(stats));
        stats.enabled = true;
        stats.running = true;
        stats.reachable = false;
        stats.legacy_height = 0;
        stats.legacy_headers = 0;
        stats.local_height = 3157703;
        snprintf(stats.last_blocker_id, sizeof(stats.last_blocker_id),
                 "%s", "rpc-unreachable");
        snprintf(stats.last_error, sizeof(stats.last_error),
                 "%s", "connect failed");
        legacy_mirror_sync_test_set_stats(&stats, NULL);

        legacy_mirror_sync_stats_snapshot(&snap);
        ZO_CHECK("legacy mirror unreachable marks lag unknown",
                 !snap.lag_known && !snap.lag_valid);
        ZO_CHECK("legacy mirror unreachable clamps compatibility lag",
                 snap.lag == 0);
        ZO_CHECK("legacy mirror unreachable keeps rpc blocker",
                 strcmp(snap.last_blocker_id, "rpc-unreachable") == 0);
        ZO_CHECK("legacy mirror unreachable remains blocked",
                 strcmp(snap.state, "blocked") == 0);

        json_init(&root);
        json_set_object(&root);
        ZO_CHECK("legacy mirror unreachable dump succeeds",
                 legacy_mirror_sync_dump_state_json(&root, NULL));
        ZO_CHECK("legacy mirror unreachable dump lag_known=false",
                 !json_get_bool(json_get(&root, "lag_known")));
        ZO_CHECK("legacy mirror unreachable dump candidate_lag_known=false",
                 !json_get_bool(json_get(&root, "candidate_lag_known")));
        ZO_CHECK("legacy mirror unreachable dump observed lag null",
                 json_is_null(json_get(&root, "lag_observed")));
        ZO_CHECK("legacy mirror unreachable dump candidate observed lag null",
                 json_is_null(json_get(&root, "candidate_lag_observed")));
        ZO_CHECK("legacy mirror unreachable dump active code",
                 strcmp(json_get_str(json_get(&root, "active_error_code")),
                        "rpc-unreachable") == 0);
        ZO_CHECK("legacy mirror unreachable dump active detail",
                 strcmp(json_get_str(json_get(&root, "active_error_detail")),
                        "connect failed") == 0);
        ZO_CHECK("legacy mirror unreachable dump lag zero",
                 json_get_int(json_get(&root, "lag")) == 0 &&
                 json_get_int(json_get(&root, "candidate_lag")) == 0);
        json_free(&root);
        legacy_mirror_sync_reset_for_test();
        zo_teardown();
    }

    if (failures == 0)
        printf("=== zclassicd oracle: all checks passed ===\n");
    else
        printf("=== zclassicd oracle: %d failure(s) ===\n", failures);
    return failures;
}
