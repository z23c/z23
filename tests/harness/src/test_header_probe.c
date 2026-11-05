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
    _Atomic platform_socket_t listen_fd; /* stop thread closes accept fd */
    int port;
    int remote_tip;             /* canned getblockcount value */
    bool malformed_header;      /* true → return non-deserializable hex */
    _Atomic int requests_served;
    _Atomic bool fail_batch;    /* true → answer batch requests with a non-array */
    _Atomic int first_height;   /* first getblockhash height asked for, -1 none */
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

static size_t hp_mock_body_len(const char *buf)
{
    const char *p = strstr(buf, "Content-Length:");
    return p ? (size_t)strtoul(p + strlen("Content-Length:"), NULL, 10) : 0;
}

static size_t hp_mock_read_request(platform_socket_t cfd, char *buf,
                                   size_t cap)
{
    /* buf MUST start terminated: every branch below calls strstr(buf, ...)
     * and the read loop can exit with got == 0 (recv timeout or hangup). */
    buf[0] = '\0';
    size_t got = 0;
    /* Matches LRC_TIMEOUT_SECS in engine/modules/rpc/src/legacy_rpc_client.c
     * (5s); a shorter ceiling makes the mock fail before the client. */
    (void)platform_socket_set_receive_timeout(cfd, 5000);
    for (;;) {
        int n = platform_socket_receive(cfd, buf + got, cap - 1 - got);
        if (n <= 0) break;
        got += (size_t)n;
        buf[got] = '\0';
        /* Stop reading once the whole Content-Length body has arrived, so a
         * large batch is drained before the reply and the close. */
        const char *sep = strstr(buf, "\r\n\r\n");
        if (sep && got >= (size_t)(sep + 4 - buf) + hp_mock_body_len(buf))
            break;
        if (got >= cap - 1) break;
    }
    return got;
}

static const char *hp_mock_find_method(const char *buf)
{
    const char *method = NULL;
    if (strstr(buf, "\"getblockcount\""))      method = "getblockcount";
    else if (strstr(buf, "\"getblockhash\""))  method = "getblockhash";
    else if (strstr(buf, "\"getblockheader\""))method = "getblockheader";
    return method;
}

static int hp_mock_count_batch(const char *json_body)
{
    int depth = 0;
    int batch_n = 0;
    for (const char *p = json_body; *p; p++) {
        if (*p == '[') depth++;
        else if (*p == ']') depth--;
        else if (*p == '{' && depth == 1) batch_n++;
    }
    if (batch_n < 1) batch_n = 1;
    return batch_n;
}

static int hp_mock_build_elem(struct hp_mock *m, const char *method,
                              char *elem, size_t cap)
{
    int el = 0;
    if (method && strcmp(method, "getblockcount") == 0) {
        el = snprintf(elem, cap,
            "{\"result\":%d,\"error\":null,\"id\":\"zcl-hp\"}",
            m->remote_tip);
    } else if (method && strcmp(method, "getblockhash") == 0) {
        int seq = atomic_fetch_add(&m->requests_served, 1) + 1;
        char hash_hex[65];
        for (int i = 0; i < 64; i++)
            hash_hex[i] = "0123456789abcdef"[seq & 0xf];
        hash_hex[64] = '\0';
        (void)seq;
        el = snprintf(elem, cap,
            "{\"result\":\"%s\",\"error\":null,\"id\":\"zcl-hp\"}",
            hash_hex);
    } else if (method && strcmp(method, "getblockheader") == 0) {
        const char *hex = m->malformed_header
                              ? HP_MALFORMED_HEX
                              : HP_VALID_HDR_HEX;
        el = snprintf(elem, cap,
            "{\"result\":\"%s\",\"error\":null,\"id\":\"zcl-hp\"}",
            hex);
    } else {
        el = snprintf(elem, cap,
            "{\"result\":null,\"error\":{\"code\":-1,"
            "\"message\":\"unknown method\"},\"id\":\"zcl-hp\"}");
    }
    return el;
}

static int hp_mock_build_body(char *body, size_t cap, bool is_batch,
                              int batch_n, const char *elem, int el)
{
    int bl = 0;
    if (!is_batch) {
        bl = snprintf(body, cap, "%s\n", elem);
    } else {
        int off = 0;
        body[off++] = '[';
        for (int i = 0; i < batch_n && off + el + 2 < (int)cap; i++) {
            if (i) body[off++] = ',';
            memcpy(body + off, elem, (size_t)el);
            off += el;
        }
        if (off + 2 < (int)cap) {
            body[off++] = ']';
            body[off++] = '\n';
        }
        bl = off;
    }
    return bl;
}

static void hp_mock_send_reply(platform_socket_t cfd, const char *body,
                               int bl)
{
    char hdr[256];
    int hl = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n", bl);
    (void)platform_socket_send_all(cfd, hdr, (size_t)hl);
    (void)platform_socket_send_all(cfd, body, (size_t)bl);
    platform_socket_close(cfd);
}

static void *hp_mock_loop(void *arg)  /* raw-pthread-ok: test-local */
{
    struct hp_mock *m = arg;
    while (!atomic_load(&m->stop)) {
        struct sockaddr_in cli;
        size_t cl = sizeof(cli);
        platform_socket_t listen_fd = atomic_load(&m->listen_fd);
        platform_socket_t cfd = platform_socket_accept(listen_fd,
                                                       (struct sockaddr *)&cli,
                                                       &cl);
        if (cfd == PLATFORM_SOCKET_INVALID) break;

        char buf[65536];
        size_t got = hp_mock_read_request(cfd, buf, sizeof(buf));
        if (got == 0) {
            /* Nothing arrived — answering would be answering noise. */
            platform_socket_close(cfd);
            continue;
        }

        const char *method = hp_mock_find_method(buf);

        /* Detect JSON-RPC array body (batched). Count items by
         * counting top-level "{" inside the JSON body. */
        const char *body_sep = strstr(buf, "\r\n\r\n");
        const char *json_body = body_sep ? body_sep + 4 : buf;
        bool is_batch = (json_body[0] == '[');
        if (method && strcmp(method, "getblockhash") == 0 &&
            atomic_load(&m->first_height) < 0) {
            const char *pp = strstr(json_body, "\"params\":[");
            if (pp) atomic_store(&m->first_height, atoi(pp + 10));
        }
        if (is_batch && atomic_load(&m->fail_batch))
            is_batch = false;   /* a single object where an array is due */
        int batch_n = 0;
        if (is_batch) batch_n = hp_mock_count_batch(json_body);

        /* Build one element body for the response. is_batch wraps it
         * in [] with batch_n copies. */
        char elem[8192];
        int el = hp_mock_build_elem(m, method, elem, sizeof(elem));

        /* Assemble final body — either single object or array. */
        char body[65536];
        int bl = hp_mock_build_body(body, sizeof(body), is_batch, batch_n,
                                    elem, el);

        hp_mock_send_reply(cfd, body, bl);
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
    atomic_store(&m->first_height, -1);
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
    platform_socket_t listen_fd =
        atomic_exchange(&m->listen_fd, PLATFORM_SOCKET_INVALID);
    if (listen_fd != PLATFORM_SOCKET_INVALID) {
        /* Shut down, then close: the close interrupts the blocking accept()
         * so the thread exits (on Windows, closesocket from another thread
         * fails the in-flight accept; the shutdown arm is platform-aware). */
        (void)platform_socket_shutdown_both(listen_fd);
        platform_socket_close(listen_fd);
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

static bool hp_dump_omits_config(const struct json_value *dump)
{
    return json_get(dump, "running") == NULL &&
           json_get(dump, "rpc_host") == NULL &&
           json_get(dump, "rpc_port") == NULL &&
           json_get(dump, "have_user") == NULL &&
           json_get(dump, "have_password") == NULL &&
           json_get(dump, "batch_size") == NULL &&
           json_get(dump, "lag_threshold") == NULL;
}

int test_header_probe(void);

/* From test_header_probe_state.c. */
struct hp_conf {
    char dir[PATH_MAX];
    char path[PATH_MAX + 32];
    bool set;
};
bool hp_conf_write(struct hp_conf *c, const char *text);
void hp_conf_drop(struct hp_conf *c);
bool hp_state_is_pristine(void);
int header_probe_state_tests(void);

/* ── Scenario table: pull and tick counts observed through the mock ──
 *
 * A malformed header makes a whole batch fail to decode, which adds exactly
 * the batch length n to rpc_errors and stops the pull, so rpc_errors reads
 * back n = min(requested, remote tip - start + 1, 128). The mock also records
 * the first height it was asked for. */

#define HP_ANY (-999)

struct hp_scn {
    int tip;                         /* remote tip */
    bool malformed, fail_batch, dead, tick, empty_chain, uninit_tick;
    int local;                       /* local best-header height; 0 = genesis */
    int batch, lag;                  /* config */
    int start, max;                  /* pull_range arguments */
    int conf_mode;                   /* 1 port from conf, 2 conf port ignored */
};

struct hp_want { int errors, rejected, calls, first, local, remote; };

struct hp_got {
    int added;
    int64_t errors, rejected, calls, local, remote;
    int first;
};

struct hp_row { const char *name; struct hp_scn s; struct hp_want w; };

static bool hp_scn_init(const struct chain_params *params,
                        const struct hp_scn *s, const struct hp_mock *srv,
                        struct hp_conf *conf)
{
    struct header_probe_config cfg = {
        .rpc_host = "127.0.0.1", .rpc_port = srv->port,
        .rpc_user = "u", .rpc_password = "p",
        .batch_size = s->batch, .lag_threshold = s->lag,
    };
    if (s->conf_mode) {
        char text[96];
        snprintf(text, sizeof(text), "rpcuser=cu\nrpcpassword=cp\nrpcport=%d\n",
                 s->conf_mode == 1 ? srv->port : 1);
        if (!hp_conf_write(conf, text)) return false;
        cfg.rpc_user = NULL;
        cfg.rpc_password = NULL;
        cfg.rpc_port = s->conf_mode == 1 ? 0 : srv->port;
    }
    return header_probe_init(&cfg, &g_hp_ms, params).ok;
}

static void hp_scn_collect(struct hp_got *g, const struct hp_mock *srv)
{
    g->errors = hp_dump_int("rpc_errors");
    g->rejected = hp_dump_int("headers_rejected");
    g->calls = hp_dump_int("calls_total");
    g->local = hp_dump_int("last_local_height");
    g->remote = hp_dump_int("last_remote_height");
    g->first = atomic_load(&srv->first_height);
}

static bool hp_scn_run(const struct chain_params *params,
                       const struct hp_scn *s, struct hp_got *g)
{
    memset(g, 0, sizeof(*g));
    if (s->empty_chain) {
        main_state_init(&g_hp_ms);
    } else {
        hp_build_fixture();
        if (s->local && g_hp_ms.pindex_best_header)
            g_hp_ms.pindex_best_header->nHeight = s->local;
    }
    struct hp_mock srv;
    struct hp_conf conf = {0};
    bool ok = hp_mock_start(&srv, s->tip, s->malformed);
    bool running = ok;
    if (ok) {
        atomic_store(&srv.fail_batch, s->fail_batch);
        if (s->dead) { hp_mock_stop(&srv); running = false; }
        ok = s->uninit_tick || hp_scn_init(params, s, &srv, &conf);
    }
    if (ok && s->tick) {
        header_probe_tick_once();
    } else if (ok) {
        struct zcl_result r = header_probe_pull_range(s->start, s->max, &g->added);
        ok = r.ok;
    }
    if (ok) hp_scn_collect(g, &srv);
    if (running) hp_mock_stop(&srv);
    hp_conf_drop(&conf);
    hp_teardown();
    return ok;
}

static bool hp_want_match(const struct hp_got *g, const struct hp_want *w)
{
    return (w->errors == HP_ANY || g->errors == w->errors) &&
           (w->rejected == HP_ANY || g->rejected == w->rejected) &&
           (w->calls == HP_ANY || g->calls == w->calls) &&
           (w->first == HP_ANY || g->first == w->first) &&
           (w->local == HP_ANY || g->local == w->local) &&
           (w->remote == HP_ANY || g->remote == w->remote);
}

#define HP_W(e, r, c, f, l, rm) { (e), (r), (c), (f), (l), (rm) }

static const struct hp_row g_pull_rows[] = {
    {"pull: max 0 means the default, capped at one 128 batch",
     {.tip = 1000, .malformed = true, .start = 1, .max = 0},
     HP_W(128, 0, 1, 1, HP_ANY, 1000)},
    {"pull: max 1 fetches one header",
     {.tip = 1000, .malformed = true, .start = 1, .max = 1},
     HP_W(1, 0, 1, 1, HP_ANY, HP_ANY)},
    {"pull: max 5 from height 10 fetches 5",
     {.tip = 1000, .malformed = true, .start = 10, .max = 5},
     HP_W(5, 0, 1, 10, HP_ANY, HP_ANY)},
    {"pull: the range ends at the remote tip",
     {.tip = 3, .malformed = true, .start = 1, .max = 10},
     HP_W(3, 0, 1, 1, HP_ANY, HP_ANY)},
    {"pull: start at the remote tip fetches exactly one",
     {.tip = 3, .malformed = true, .start = 3, .max = 10},
     HP_W(1, 0, 1, 3, HP_ANY, HP_ANY)},
    {"pull: start past the remote tip fetches nothing",
     {.tip = 3, .malformed = true, .start = 4, .max = 10},
     HP_W(0, 0, 1, -1, HP_ANY, 3)},
    {"pull: start 0 is a legal height",
     {.tip = 100, .malformed = true, .start = 0, .max = 3},
     HP_W(3, 0, 1, 0, HP_ANY, HP_ANY)},
    {"pull: max 100 under the batch cap",
     {.tip = 10000, .malformed = true, .start = 1, .max = 100},
     HP_W(100, 0, 1, 1, HP_ANY, HP_ANY)},
    {"pull: max 129 is cut to one batch of 128",
     {.tip = 10000, .malformed = true, .start = 1, .max = 129},
     HP_W(128, 0, 1, 1, HP_ANY, HP_ANY)},
    {"pull: max past 5000 is cut to one batch of 128",
     {.tip = 10000, .malformed = true, .start = 1, .max = 200000},
     HP_W(128, 0, 1, 1, HP_ANY, HP_ANY)},
    {"pull: a valid-looking header the chain refuses stops the pull at once",
     {.tip = 10, .start = 1, .max = 5},
     HP_W(0, 1, 1, 1, HP_ANY, 10)},
    {"pull: a failed batch falls back to one single fetch, refused once",
     {.tip = 10, .fail_batch = true, .start = 1, .max = 3},
     HP_W(1, 1, 1, 1, HP_ANY, HP_ANY)},
    {"pull: a failed batch and a failed single fetch cost two errors",
     {.tip = 10, .malformed = true, .fail_batch = true, .start = 1, .max = 3},
     HP_W(2, 0, 1, 1, HP_ANY, HP_ANY)},
    {"pull: an unreachable server costs exactly one error",
     {.tip = 100, .dead = true, .start = 1, .max = 5},
     HP_W(1, 0, 1, -1, 0, 0)},
    {"pull: credentials and port from the conf reach the server",
     {.tip = 50, .malformed = true, .start = 1, .max = 2, .conf_mode = 1},
     HP_W(2, 0, 1, 1, HP_ANY, HP_ANY)},
    {"pull: an explicit port beats the conf port",
     {.tip = 50, .malformed = true, .start = 1, .max = 2, .conf_mode = 2},
     HP_W(2, 0, 1, 1, HP_ANY, HP_ANY)},
};

static const struct hp_row g_tick_rows[] = {
    {"tick: remote tip at local + lag does not pull",
     {.tip = 10, .malformed = true, .tick = true, .local = 7, .batch = 100, .lag = 3},
     HP_W(0, 0, 0, -1, 7, 10)},
    {"tick: one past local + lag pulls from local + 1",
     {.tip = 11, .malformed = true, .tick = true, .local = 7, .batch = 100, .lag = 3},
     HP_W(4, 0, 1, 8, 7, 11)},
    {"tick: lag 0 defaults to 100 and 107 does not pull",
     {.tip = 107, .malformed = true, .tick = true, .local = 7},
     HP_W(0, 0, 0, -1, 7, 107)},
    {"tick: lag 0 defaults to 100 and 108 pulls 101 headers",
     {.tip = 108, .malformed = true, .tick = true, .local = 7},
     HP_W(101, 0, 1, 8, 7, 108)},
    {"tick: lag 1 and tip local + 1 does not pull",
     {.tip = 8, .malformed = true, .tick = true, .local = 7, .batch = 100, .lag = 1},
     HP_W(0, 0, 0, -1, 7, 8)},
    {"tick: lag 1 and tip local + 2 pulls two",
     {.tip = 9, .malformed = true, .tick = true, .local = 7, .batch = 100, .lag = 1},
     HP_W(2, 0, 1, 8, 7, 9)},
    {"tick: batch 5 caps the pull at five",
     {.tip = 300, .malformed = true, .tick = true, .local = 7, .batch = 5, .lag = 3},
     HP_W(5, 0, 1, 8, 7, 300)},
    {"tick: batch 1 is legal",
     {.tip = 300, .malformed = true, .tick = true, .local = 7, .batch = 1, .lag = 3},
     HP_W(1, 0, 1, 8, 7, 300)},
    {"tick: batch 0 defaults and is capped at one 128 batch",
     {.tip = 300, .malformed = true, .tick = true, .local = 7, .lag = 3},
     HP_W(128, 0, 1, 8, 7, 300)},
    {"tick: batch past 5000 is capped at one 128 batch",
     {.tip = 300, .malformed = true, .tick = true, .local = 7, .batch = 9999, .lag = 3},
     HP_W(128, 0, 1, 8, 7, 300)},
    {"tick: an empty chain counts as local height 0",
     {.tip = 4, .malformed = true, .tick = true, .empty_chain = true, .batch = 100, .lag = 3},
     HP_W(4, 0, 1, 1, 0, 4)},
    {"tick: an unreachable server costs exactly one error and no pull",
     {.tip = 100, .dead = true, .tick = true, .batch = 100, .lag = 1},
     HP_W(1, 0, 0, -1, 0, 0)},
    {"tick: an uninitialized probe does nothing",
     {.tip = 50, .uninit_tick = true, .tick = true},
     HP_W(0, 0, 0, -1, 0, 0)},
};

static int hp_run_rows(const struct chain_params *params,
                       const struct hp_row *rows, size_t n)
{
    int failures = 0;
    for (size_t i = 0; i < n; i++) {
        struct hp_got g;
        bool ran = hp_scn_run(params, &rows[i].s, &g);
        bool same = ran && hp_want_match(&g, &rows[i].w);
        if (!same)
            printf("header_probe: ran=%d errors=%lld rejected=%lld calls=%lld "
                   "first=%d local=%lld remote=%lld\n", ran,
                   (long long)g.errors, (long long)g.rejected,
                   (long long)g.calls, g.first, (long long)g.local,
                   (long long)g.remote);
        HP_CHECK(rows[i].name, same);
    }
    return failures;
}

static int hp_test_reset_clears_everything(const struct chain_params *params)
{
    int failures = 0;
    hp_build_fixture();
    struct hp_mock srv;
    bool up = hp_mock_start(&srv, 10, false);
    HP_CHECK("mock starts (reset)", up);
    if (up) {
        struct header_probe_config cfg = {
            .rpc_host = "127.0.0.1", .rpc_port = srv.port,
            .rpc_user = "u", .rpc_password = "p",
        };
        HP_CHECK("init (reset)", header_probe_init(&cfg, &g_hp_ms, params).ok);
        int added = 0;
        struct zcl_result r = header_probe_pull_range(1, 5, &added);
        HP_CHECK("pull (reset)", r.ok);
        header_probe_note_repair_served(HEADER_PROBE_SRC_ORACLE, 9);
        header_probe_note_repair_served(HEADER_PROBE_SRC_P2P, 9);
        header_probe_note_p2p_request(9, 0);
        header_probe_note_oracle_skipped();
        HP_CHECK("counters are dirty before the reset",
                 hp_dump_int("calls_total") == 1 &&
                 hp_dump_int("last_remote_height") == 10 &&
                 hp_dump_int("oracle_skipped") == 1 &&
                 !hp_state_is_pristine());
        hp_mock_stop(&srv);
    }
    header_probe_reset_for_test();
    HP_CHECK("reset leaves every counter at zero", hp_state_is_pristine());
    hp_teardown();
    return failures;
}

static int hp_test_reinit_clears_credentials(const struct chain_params *params)
{
    int failures = 0;
    hp_build_fixture();
    struct header_probe_config first = {
        .rpc_host = "127.0.0.1",
        .rpc_port = 18232,
        .rpc_user = "prior-user",
        .rpc_password = "prior-password",
    };
    HP_CHECK("initial init with explicit credentials",
             header_probe_init(&first, &g_hp_ms, params).ok);

    const char *old_home = getenv("HOME");
    char old_home_copy[1024] = {0};
    bool home_saved = !old_home || strlen(old_home) < sizeof old_home_copy;
    HP_CHECK("original HOME fits restoration buffer", home_saved);
    if (!home_saved) {
        hp_teardown();
        return failures;
    }
    if (old_home)
        snprintf(old_home_copy, sizeof(old_home_copy), "%s", old_home);
    char empty_home[PATH_MAX];
    bool home_created =
        test_mkdtemp(empty_home, sizeof empty_home, "header_probe_home") != NULL;
    bool home_ready = home_created && setenv("HOME", empty_home, 1) == 0;
    HP_CHECK("empty restart HOME fixture", home_ready);
    if (home_ready) {
        struct header_probe_config replacement = {
            .rpc_host = "127.0.0.1",
            .rpc_port = 18233,
        };
        struct zcl_result reinit =
            header_probe_init(&replacement, &g_hp_ms, params);
        HP_CHECK("restart without current credentials is refused", !reinit.ok);

        struct json_value dump;
        json_init(&dump);
        bool inactive = header_probe_dump_state_json(&dump, NULL) &&
            json_get(&dump, "initialized") != NULL &&
            !json_get_bool(json_get(&dump, "initialized"));
        HP_CHECK("failed restart leaves header probe inactive", inactive);
        json_free(&dump);
    }
    int restored = old_home ? setenv("HOME", old_home_copy, 1) : unsetenv("HOME");
    HP_CHECK("original HOME restored", restored == 0);
    if (home_created)
        HP_CHECK("empty restart HOME removed",
                 rmdir(empty_home) == 0);
    hp_teardown();
    return failures;
}

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
        ok = ok && hp_dump_omits_config(&dump);
        HP_CHECK("dump omits config echo", ok);
        json_free(&dump);

        hp_mock_stop(&srv);
        hp_teardown();
    }

    /* Test 6: an in-process restart must not inherit RPC credentials from the
     * prior run. With no credentials in the replacement config and no conf
     * file, re-init fails closed and leaves the probe inactive. */
    failures += hp_test_reinit_clears_credentials(params);

    /* Tests 7-10: exact pull and tick counts, reset, and the mock-free state
     * and init guards (test_header_probe_state.c). */
    failures += hp_run_rows(params, g_pull_rows,
                            sizeof(g_pull_rows) / sizeof(g_pull_rows[0]));
    failures += hp_run_rows(params, g_tick_rows,
                            sizeof(g_tick_rows) / sizeof(g_tick_rows[0]));
    failures += hp_test_reset_clears_everything(params);
    failures += header_probe_state_tests();

    if (failures == 0)
        printf("=== header probe service: all checks passed ===\n");
    else
        printf("=== header probe service: %d failure(s) ===\n", failures);
    return failures;
}
