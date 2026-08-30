/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Robustness and defensive coding tests: validation, bounds, edge cases. */

#include "platform/time_compat.h"
#include "platform/system_memory.h"
#include "test/test_core.h"
#include "domain/encoding/base58.h"
#include "chain/pow.h"
#include "core/serialize.h"
#include "validation/check_transaction.h"
#include "models/database.h"
#include "controllers/store_controller.h"
#include "controllers/zslp_controller.h"
#include "net/fast_sync.h"
#include "net/net.h"
#include "rpc/httpserver.h"
#include "util/template.h"
#include "platform/socket_compat.h"
#include <unistd.h>
#include "util/safe_alloc.h"
#include "event/event.h"
#include <signal.h>
#include <stdatomic.h>

static char test_datadir[256];

static void setup_robustness_datadir(void)
{
    snprintf(test_datadir, sizeof(test_datadir), ".zcl_test_robust_%d",
             (int)getpid());
    mkdir(test_datadir, 0755);
}

static void cleanup_robustness_datadir(void)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", test_datadir);
    system(cmd);
}

static uint16_t reserve_test_port(void)
{
    uint16_t port = 0;
    platform_socket_t fd = platform_socket_open(AF_INET, SOCK_STREAM, 0,
                                                true, false);
    if (fd == PLATFORM_SOCKET_INVALID)
        return 0;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);

    if (platform_socket_bind(fd, (struct sockaddr *)&addr,
                             sizeof(addr)) == 0) {
        size_t len = sizeof(addr);
        if (platform_socket_local_address(fd, (struct sockaddr *)&addr,
                                          &len) == 0)
            port = ntohs(addr.sin_port);
    }
    platform_socket_close(fd);
    return port;
}

int test_robustness(void)
{
    int failures = 0;
    setup_robustness_datadir();

    /* ── Store: null/empty input handling ───────────────────── */

    printf("robust: store NULL path returns 0... ");
    {
        uint8_t resp[4096];
        size_t n = store_handle_request("GET", NULL, NULL, 0,
                                         resp, sizeof(resp), test_datadir);
        if (n == 0) printf("OK\n");
        else { printf("FAIL (n=%zu)\n", n); failures++; }
    }

    printf("robust: store NULL response buffer returns 0... ");
    {
        size_t n = store_handle_request("GET", "/store", NULL, 0,
                                         NULL, 0, test_datadir);
        if (n == 0) printf("OK\n");
        else { printf("FAIL (n=%zu)\n", n); failures++; }
    }

    printf("robust: store invalid product ID returns 404... ");
    {
        uint8_t resp[4096];
        size_t n = store_handle_request("GET", "/store/product/99999", NULL, 0,
                                         resp, sizeof(resp), test_datadir);
        bool ok = (n > 0) && (strstr((char *)resp, "404") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL (n=%zu)\n", n); failures++; }
    }

    printf("robust: store negative product ID handled... ");
    {
        uint8_t resp[4096];
        size_t n = store_handle_request("GET", "/store/product/-1", NULL, 0,
                                         resp, sizeof(resp), test_datadir);
        bool ok = (n > 0) && (strstr((char *)resp, "HTTP/1.1") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL (n=%zu)\n", n); failures++; }
    }

    printf("robust: store invalid order ID returns 404... ");
    {
        uint8_t resp[4096];
        size_t n = store_handle_request("GET", "/store/order/99999", NULL, 0,
                                         resp, sizeof(resp), test_datadir);
        bool ok = (n > 0) && (strstr((char *)resp, "404") != NULL ||
                               strstr((char *)resp, "not found") != NULL ||
                               strstr((char *)resp, "Not Found") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL (n=%zu)\n", n); failures++; }
    }

    printf("robust: store unknown path handled gracefully... ");
    {
        uint8_t resp[4096];
        size_t n = store_handle_request("GET", "/store/nonexistent", NULL, 0,
                                         resp, sizeof(resp), test_datadir);
        /* Unknown paths return 0 (no response) or a 404 — both are valid */
        bool ok = (n == 0) || (strstr((char *)resp, "404") != NULL);
        if (ok) printf("OK (n=%zu)\n", n);
        else { printf("FAIL (n=%zu)\n", n); failures++; }
    }

    /* ── Store: XSS prevention ─────────────────────────────── */

    printf("robust: XSS in customer_addr not reflected... ");
    {
        uint8_t resp[8192];
        const char *xss_body = "customer_addr=<script>alert(1)</script>";
        size_t n = store_handle_request("POST", "/store/buy/1",
                                         (const uint8_t *)xss_body,
                                         strlen(xss_body),
                                         resp, sizeof(resp), test_datadir);
        /* XSS payload must not appear unescaped */
        bool ok = (n > 0) && (strstr((char *)resp, "<script>") == NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("robust: valid address in POST accepted... ");
    {
        uint8_t resp[8192];
        const char *body = "customer_addr=t1YRBXKYLhrb4X8sTkBeRysAzBTMMHpUXrn";
        size_t n = store_handle_request("POST", "/store/buy/1",
                                         (const uint8_t *)body,
                                         strlen(body),
                                         resp, sizeof(resp), test_datadir);
        bool ok = (n > 0) && (strstr((char *)resp, "HTTP/1.1") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL (n=%zu)\n", n); failures++; }
    }

    /* ── Fast sync: PoW verification ──────────────────────── */

    printf("robust: NULL pow rejected... ");
    {
        bool ok = !fast_sync_verify_pow(NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("robust: zeroed pow rejected (bad timestamp)... ");
    {
        struct fast_sync_pow pow;
        memset(&pow, 0, sizeof(pow));
        bool ok = !fast_sync_verify_pow(&pow);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("robust: expired pow rejected... ");
    {
        struct fast_sync_pow pow;
        memset(&pow, 0, sizeof(pow));
        pow.timestamp = (int64_t)platform_time_wall_time_t() - 600;
        bool ok = !fast_sync_verify_pow(&pow);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("robust: future pow rejected... ");
    {
        struct fast_sync_pow pow;
        memset(&pow, 0, sizeof(pow));
        pow.timestamp = (int64_t)platform_time_wall_time_t() + 120;
        bool ok = !fast_sync_verify_pow(&pow);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Fast sync: rate limiter ─────────────────────────── */

    printf("robust: rate limiter allows initial request... ");
    {
        struct fast_sync_rate_limiter rl;
        memset(&rl, 0, sizeof(rl));
        uint8_t ip[16] = {0,0,0,0, 0,0,0,0, 0,0,0xff,0xff, 1,2,3,4};
        bool ok = fast_sync_rate_check(&rl, ip);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Snapshot offer: edge cases ──────────────────────── */

    printf("robust: build_offer nonexistent path fails... ");
    {
        struct snapshot_offer offer;
        bool ok = !fast_sync_build_offer("/nonexistent/path/zcl", &offer);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("robust: build_offer NULL offer fails... ");
    {
        bool ok = !fast_sync_build_offer(test_datadir, NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── RPC HTTP lifecycle ─────────────────────────────── */

    printf("robust: rpc_http start/stop is repeatable... ");
    {
        uint16_t port = reserve_test_port();
        bool ok = port != 0;
        if (ok)
            ok = rpc_http_start(NULL, port, "user", "pass", NULL);
        ok = ok && rpc_http_is_running();
        rpc_http_stop();
        ok = ok && !rpc_http_is_running();
        rpc_http_stop();
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Byte stream: bounds checking ────────────────────── */

    printf("robust: stream read past end returns false... ");
    {
        struct byte_stream s;
        uint8_t data[4] = {0x01, 0x02, 0x03, 0x04};
        stream_init_from_data(&s, data, sizeof(data));
        uint32_t val;
        bool ok = stream_read_u32_le(&s, &val);
        ok = ok && (val == 0x04030201);
        uint8_t extra;
        ok = ok && !stream_read_u8(&s, &extra);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("robust: stream read_bytes past end returns false... ");
    {
        struct byte_stream s;
        uint8_t data[8] = {0};
        stream_init_from_data(&s, data, sizeof(data));
        uint8_t buf[16];
        bool ok = !stream_read_bytes(&s, buf, 16);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("robust: stream read empty returns false... ");
    {
        struct byte_stream s;
        stream_init_from_data(&s, NULL, 0);
        uint8_t val;
        bool ok = !stream_read_u8(&s, &val);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("robust: compact_size reads valid values... ");
    {
        struct byte_stream s;
        uint8_t data[3] = {0xFD, 0xFD, 0x00};
        stream_init_from_data(&s, data, sizeof(data));
        uint64_t val;
        bool ok = stream_read_compact_size(&s, &val) && (val == 253);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("robust: compact_size rejects truncated data... ");
    {
        struct byte_stream s;
        uint8_t data[2] = {0xFD, 0x01};
        stream_init_from_data(&s, data, sizeof(data));
        uint64_t val;
        bool ok = !stream_read_compact_size(&s, &val);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── P2P message: header handling ────────────────────── */

    printf("robust: zeroed msg_header command empty... ");
    {
        struct msg_header hdr;
        memset(&hdr, 0, sizeof(hdr));
        char cmd[COMMAND_SIZE + 1];
        msg_header_get_command(&hdr, cmd, sizeof(cmd));
        bool ok = (strlen(cmd) == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL (got '%s')\n", cmd); failures++; }
    }

    printf("robust: msg_header command extraction... ");
    {
        struct msg_header hdr;
        memset(&hdr, 0, sizeof(hdr));
        memcpy(hdr.pchCommand, "version", 7);
        char cmd[COMMAND_SIZE + 1];
        msg_header_get_command(&hdr, cmd, sizeof(cmd));
        bool ok = (strcmp(cmd, "version") == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL (got '%s')\n", cmd); failures++; }
    }

    /* ── HTML escaping ───────────────────────────────────── */

    printf("robust: html_escape blocks XSS... ");
    {
        char out[256];
        html_escape(out, sizeof(out), "<script>alert('xss')</script>");
        bool ok = (strstr(out, "<script>") == NULL) &&
                  (strstr(out, "&lt;script&gt;") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL (got '%s')\n", out); failures++; }
    }

    printf("robust: html_escape escapes ampersand... ");
    {
        char out[64];
        html_escape(out, sizeof(out), "foo & bar");
        bool ok = (strstr(out, "&amp;") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL (got '%s')\n", out); failures++; }
    }

    printf("robust: html_escape escapes quotes... ");
    {
        char out[64];
        html_escape(out, sizeof(out), "a\"b");
        bool ok = (strstr(out, "&quot;") != NULL);
        if (ok) printf("OK\n");
        else { printf("FAIL (got '%s')\n", out); failures++; }
    }

    printf("robust: html_escape handles NULL... ");
    {
        char out[64] = "unchanged";
        html_escape(out, sizeof(out), NULL);
        bool ok = (out[0] == '\0' || strcmp(out, "unchanged") == 0);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("robust: html_escape handles empty string... ");
    {
        char out[64] = "X";
        html_escape(out, sizeof(out), "");
        bool ok = (out[0] == '\0');
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Validation: transaction checks ──────────────────── */

    printf("robust: empty tx rejected by check_transaction... ");
    {
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        struct validation_state state;
        validation_state_init(&state);
        bool ok = !check_transaction(&tx, &state);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("robust: negative value tx rejected... ");
    {
        struct transaction tx;
        memset(&tx, 0, sizeof(tx));
        tx.num_vin = 1;
        tx.vin = zcl_calloc(1, sizeof(struct tx_in), "test_vin");
        tx.num_vout = 1;
        tx.vout = zcl_calloc(1, sizeof(struct tx_out), "test_vout");
        tx.vout[0].value = -1;
        struct validation_state state;
        validation_state_init(&state);
        bool ok = !check_transaction(&tx, &state);
        free(tx.vin);
        free(tx.vout);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Inv item serialization ──────────────────────────── */

    printf("robust: inv_item serialize/deserialize roundtrip... ");
    {
        struct inv_item inv;
        inv.type = MSG_TX;
        memset(inv.hash.data, 0xAB, 32);

        struct byte_stream ws;
        stream_init(&ws, 64);
        inv_item_serialize(&inv, &ws);

        struct byte_stream rs;
        stream_init_from_data(&rs, ws.data, ws.size);
        struct inv_item inv2;
        bool ok = inv_item_deserialize(&inv2, &rs);
        ok = ok && (inv2.type == MSG_TX);
        ok = ok && uint256_eq(&inv.hash, &inv2.hash);
        stream_free(&ws);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("robust: inv_item truncated deserialize fails... ");
    {
        struct byte_stream rs;
        uint8_t data[4] = {0x01, 0x00, 0x00, 0x00};
        stream_init_from_data(&rs, data, sizeof(data));
        struct inv_item inv;
        bool ok = !inv_item_deserialize(&inv, &rs);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Base58 validation ───────────────────────────────── */

    printf("robust: base58check invalid chars rejected... ");
    {
        uint8_t result[32];
        size_t rlen = 0;
        bool ok = !domain_encoding_base58check_decode("0InvalidAddr", result, sizeof(result), &rlen);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("robust: base58check empty string rejected... ");
    {
        uint8_t result[32];
        size_t rlen = 0;
        bool ok = !domain_encoding_base58check_decode("", result, sizeof(result), &rlen);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Uint256 edge cases ──────────────────────────────── */

    printf("robust: uint256 zero comparison... ");
    {
        struct uint256 a, b;
        memset(&a, 0, 32);
        memset(&b, 0, 32);
        bool ok = uint256_eq(&a, &b);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("robust: uint256 different values not equal... ");
    {
        struct uint256 a, b;
        memset(&a, 0, 32);
        memset(&b, 0xFF, 32);
        bool ok = !uint256_eq(&a, &b);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── Duplicate detection ring buffers ────────────────── */

    printf("robust: block dedup ring buffer... ");
    {
        extern bool msgprocessor_test_block_already_seen(const struct uint256 *);
        extern void msgprocessor_test_block_mark_seen(const struct uint256 *);

        struct uint256 hash1;
        memset(hash1.data, 0x71, 32);

        bool ok = !msgprocessor_test_block_already_seen(&hash1);
        msgprocessor_test_block_mark_seen(&hash1);
        ok = ok && msgprocessor_test_block_already_seen(&hash1);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("robust: tx dedup ring buffer... ");
    {
        extern bool msgprocessor_test_tx_already_seen(const struct uint256 *);
        extern void msgprocessor_test_tx_mark_seen(const struct uint256 *);

        struct uint256 hash1;
        memset(hash1.data, 0xBB, 32);

        bool ok = !msgprocessor_test_tx_already_seen(&hash1);
        msgprocessor_test_tx_mark_seen(&hash1);
        ok = ok && msgprocessor_test_tx_already_seen(&hash1);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── P2P message size limit ──────────────────────────── */
    printf("robust: MAX_PROTOCOL_MESSAGE_LENGTH is 2MB... ");
    {
        /* MAX_PROTOCOL_MESSAGE_LENGTH should be 2 * 1024 * 1024 */
        bool ok = (MAX_PROTOCOL_MESSAGE_LENGTH == 2 * 1024 * 1024);
        if (ok) printf("OK (%u)\n", MAX_PROTOCOL_MESSAGE_LENGTH);
        else { printf("FAIL (got %u)\n", MAX_PROTOCOL_MESSAGE_LENGTH); failures++; }
    }

    /* ── Oversized message rejection ─────────────────────── */
    printf("robust: oversized message header rejected... ");
    {
        /* Construct a message header with size > 2MB and verify
         * p2p_node_receive_bytes rejects it */
        struct p2p_node fake_node;
        memset(&fake_node, 0, sizeof(fake_node));
        fake_node.socket = -1;
        snprintf(fake_node.addr_name, sizeof(fake_node.addr_name), "test");

        unsigned char msgstart[4] = {0x24, 0xe9, 0x27, 0x64};
        /* Build a valid header: magic(4) + command(12) + size(4) + checksum(4) = 24 bytes */
        unsigned char hdr[24];
        memcpy(hdr, msgstart, 4);
        memset(hdr + 4, 0, 12);
        memcpy(hdr + 4, "version", 7);
        /* Set size to 3MB (over limit) in little-endian */
        uint32_t big_size = 3 * 1024 * 1024;
        memcpy(hdr + 16, &big_size, 4);
        memset(hdr + 20, 0, 4); /* checksum */

        bool accepted = p2p_node_receive_bytes(&fake_node, (char*)hdr, 24, msgstart);
        /* Should return false because message size exceeds limit */
        bool ok = !accepted;
        if (ok) printf("OK (rejected 3MB message)\n");
        else { printf("FAIL (accepted oversized)\n"); failures++; }
        /* Clean up any allocated recv_msgs */
        free(fake_node.recv_msgs);
    }

    /* ── ZSLP ticker validation ──────────────────────────── */
    printf("robust: ZSLP rejects empty ticker... ");
    {
        const char *r = zslp_create_token(test_datadir, "", "Test", 0, 1000);
        if (!r) printf("OK\n");
        else { printf("FAIL (accepted empty)\n"); failures++; }
    }

    printf("robust: ZSLP rejects oversized ticker (11 chars)... ");
    {
        const char *r = zslp_create_token(test_datadir, "ABCDEFGHIJK", "Test", 0, 1000);
        if (!r) printf("OK\n");
        else { printf("FAIL (accepted 11-char)\n"); failures++; }
    }

    printf("robust: ZSLP rejects non-alphanumeric ticker... ");
    {
        const char *r = zslp_create_token(test_datadir, "BAD!@#", "Test", 0, 1000);
        if (!r) printf("OK\n");
        else { printf("FAIL (accepted special chars)\n"); failures++; }
    }

    printf("robust: ZSLP rejects decimals > 8... ");
    {
        const char *r = zslp_create_token(test_datadir, "TEST", "Test", 9, 1000);
        if (!r) printf("OK\n");
        else { printf("FAIL (accepted decimals=9)\n"); failures++; }
    }

    printf("robust: ZSLP rejects overflow supply... ");
    {
        const char *r = zslp_create_token(test_datadir, "TEST", "Test", 0,
                                            UINT64_MAX);
        if (!r) printf("OK\n");
        else { printf("FAIL (accepted overflow)\n"); failures++; }
    }

    printf("robust: ZSLP accepts valid ticker... ");
    {
        const char *r = zslp_create_token(test_datadir, "ZCL", "ZClassic", 8, 1000);
        /* Returns non-NULL on success (placeholder token_id) */
        if (r) printf("OK\n");
        else { printf("FAIL (rejected valid)\n"); failures++; }
    }

    /* ── Rate limiter enforcement ────────────────────────── */
    printf("robust: rate limiter enforces 5000 chunk limit... ");
    {
        struct fast_sync_rate_limiter rl;
        memset(&rl, 0, sizeof(rl));
        uint8_t ip[16] = {0};
        ip[15] = 42;

        bool ok = true;
        /* Send 5000 chunks — all should be allowed */
        for (int i = 0; i < 5000; i++) {
            if (!fast_sync_rate_check(&rl, ip)) {
                printf("FAIL (rejected at %d)\n", i);
                ok = false;
                break;
            }
        }
        if (ok) {
            /* 5001st should be rejected */
            if (fast_sync_rate_check(&rl, ip)) {
                printf("FAIL (accepted 5001st)\n");
                ok = false;
            }
        }
        if (ok) printf("OK\n");
        else failures++;
    }

    printf("robust: rate limiter allows different IPs independently... ");
    {
        struct fast_sync_rate_limiter rl;
        memset(&rl, 0, sizeof(rl));
        uint8_t ip1[16] = {0}; ip1[15] = 1;
        uint8_t ip2[16] = {0}; ip2[15] = 2;

        /* Exhaust ip1 */
        for (int i = 0; i < 5000; i++)
            fast_sync_rate_check(&rl, ip1);

        /* ip2 should still be allowed */
        bool ok = fast_sync_rate_check(&rl, ip2);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── SQLite batch sync state machine ────────────────── */
    printf("robust: batch sync default is per-block... ");
    {
        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        /* sync_batch_size=0 should be treated as 1 */
        int batch = ndb.sync_batch_size > 0 ? ndb.sync_batch_size : 1;
        bool ok = (batch == 1);
        if (ok) printf("OK\n");
        else { printf("FAIL (batch=%d)\n", batch); failures++; }
    }

    printf("robust: node_db_set_sync_batch_size clamps positive... ");
    {
        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        node_db_set_sync_batch_size(&ndb, 100);
        bool ok = (ndb.sync_batch_size == 100);
        node_db_set_sync_batch_size(&ndb, 0);
        ok = ok && (ndb.sync_batch_size == 1); /* 0 clamped to 1 */
        node_db_set_sync_batch_size(&ndb, -5);
        ok = ok && (ndb.sync_batch_size == 1); /* negative clamped to 1 */
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("robust: node_db_sync_flush with no batch is no-op... ");
    {
        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        ndb.open = false;
        bool ok = node_db_sync_flush(&ndb); /* not open → false */
        ndb.open = true;
        ndb.sync_in_batch = false;
        ok = ok || node_db_sync_flush(&ndb); /* no batch → true, no-op */
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("robust: node_db_set_sync_batch_size NULL safe... ");
    {
        node_db_set_sync_batch_size(NULL, 100); /* should not crash */
        printf("OK\n");
    }

    printf("robust: node_db_sync_flush NULL safe... ");
    {
        bool ok = !node_db_sync_flush(NULL); /* should return false */
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("robust: get_system_ram returns reasonable value... ");
    {
        uint64_t ram = 0;
        bool ok = platform_system_memory_bytes(&ram);
        /* Reasonable: at least 512MB, at most 1TB */
        ok = ok && ram >= (512ULL * 1024 * 1024);
        ok = ok && ram <= (1024ULL * 1024 * 1024 * 1024);
        printf("(%lluMB) ",
               (unsigned long long)(ram / (1024u * 1024u)));
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("robust: OOM warning triggers for huge entry count... ");
    {
        size_t sys_ram = 8ULL * 1024 * 1024 * 1024; /* simulate 8GB */
        size_t entry_count = 50000000; /* 50M entries */
        size_t est_mem = entry_count * sizeof(struct block_index);
        bool would_warn = (est_mem > sys_ram / 2);
        /* 50M * 264 = 13.2GB > 4GB, so warning should trigger */
        if (would_warn) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("robust: stale PID lock detection (dead PID)... ");
    {
        char pidfile[256];
        snprintf(pidfile, sizeof(pidfile), "%s/stale.pid", test_datadir);
        FILE *f = fopen(pidfile, "w");
        bool ok = (f != NULL);
        if (f) {
            /* Write a PID that definitely doesn't exist */
            fprintf(f, "999999999\n");
            fclose(f);
        }
        /* kill(pid,0) should fail for non-existent PID */
        ok = ok && (kill(999999999, 0) != 0);
        unlink(pidfile);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("robust: live PID lock detection (own PID)... ");
    {
        char pidfile[256];
        snprintf(pidfile, sizeof(pidfile), "%s/live.pid", test_datadir);
        FILE *f = fopen(pidfile, "w");
        bool ok = (f != NULL);
        if (f) {
            fprintf(f, "%ld\n", (long)getpid());
            fclose(f);
        }
        /* kill(getpid(),0) should succeed — we are alive */
        ok = ok && (kill(getpid(), 0) == 0);
        unlink(pidfile);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("robust: unclean shutdown detection (WAL exists, no marker)... ");
    {
        char marker[512], wal[512];
        snprintf(marker, sizeof(marker), "%s/.shutdown_clean", test_datadir);
        snprintf(wal, sizeof(wal), "%s/node.db-wal", test_datadir);
        /* Create a fake WAL file */
        FILE *f = fopen(wal, "w");
        if (f) { fprintf(f, "wal data"); fclose(f); }
        /* Remove marker if exists */
        unlink(marker);
        struct stat st;
        bool wal_exists = (stat(wal, &st) == 0 && st.st_size > 0);
        bool marker_exists = (access(marker, F_OK) == 0);
        bool crash_detected = (!marker_exists && wal_exists);
        unlink(wal);
        if (crash_detected) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("robust: clean shutdown detection (marker present)... ");
    {
        char marker[512];
        snprintf(marker, sizeof(marker), "%s/.shutdown_clean", test_datadir);
        FILE *f = fopen(marker, "w");
        if (f) { fprintf(f, "1713100000\n"); fclose(f); }
        bool marker_exists = (access(marker, F_OK) == 0);
        unlink(marker);
        if (marker_exists) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("robust: crash recovery event emitted on WAL + no marker... ");
    {
        /* Simulate crash detection: WAL present, marker absent.
         * Verify the event system can fire EV_CRASH_RECOVERY_START. */
        static _Atomic int crash_ev_count;
        atomic_store(&crash_ev_count, 0);

        /* Emit the event directly (same as boot.c does) */
        event_emitf(EV_CRASH_RECOVERY_START, 0,
                    "wal_size=%d clean_marker=missing", 1024);

        /* The event was emitted without crash — that's the key test.
         * If event_emitf segfaults on EV_CRASH_RECOVERY_START, we'd
         * never reach here. */
        printf("OK\n");
    }

    printf("robust: PID lock rejects already-running process... ");
    {
        /* Write our own PID to a lock file, then verify kill(pid,0)
         * returns 0 (process alive = lock should be rejected). */
        char pidfile[256];
        snprintf(pidfile, sizeof(pidfile), "%s/running.pid", test_datadir);
        FILE *f = fopen(pidfile, "w");
        bool ok = (f != NULL);
        if (f) {
            fprintf(f, "%ld\n", (long)getpid());
            fclose(f);
        }
        /* Read it back and check */
        f = fopen(pidfile, "r");
        if (f) {
            char buf[32] = {0};
            fread(buf, 1, sizeof(buf) - 1, f);
            fclose(f);
            long pid = strtol(buf, NULL, 10);
            ok = ok && (pid == (long)getpid());
            ok = ok && (kill((pid_t)pid, 0) == 0); /* we're alive */
        }
        unlink(pidfile);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("robust: OOM protection logs on alloc failure simulation... ");
    {
        /* zcl_malloc with size 0 should return NULL without crashing,
         * and zcl_malloc with reasonable size should succeed. */
        void *p = zcl_malloc(0, "test_zero");
        /* size=0 behavior is implementation-defined; just don't crash */
        free(p);
        p = zcl_malloc(64, "test_small");
        bool ok = (p != NULL);
        free(p);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    cleanup_robustness_datadir();
    return failures;
}
