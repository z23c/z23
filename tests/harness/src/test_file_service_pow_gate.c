/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * File-service PoW admission gate + resource caps.
 *
 * Proves the DDoS defense in front of the multi-GB block/index stream:
 *   1. an ungated ALL/RNG request is REFUSED (challenge issued), a request
 *      carrying a valid adaptive-difficulty puzzle is admitted (SERVE);
 *   2. a replayed solution is single-use rejected;
 *   3. the per-IP concurrency, per-IP hourly-byte, and per-connection
 *      byte/time caps all trip on abuse;
 *   4. difficulty rises under simulated load and falls when idle.
 *
 * None of this touches a consensus predicate — it only decides whether to
 * spend uplink on a public stream. */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "net/file_service.h"
#include "net/fast_sync.h"
#include "net/puzzle.h"
#include "net/file_service_generation.h"
#include "net/rom_seed.h"
#include "net/rom_fetch.h"
#include "crypto/sha3.h"
#include "util/thread_registry.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#ifndef _WIN32
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <signal.h>
#include <netinet/in.h>
#include <unistd.h>
extern void fs_server_test_spawn_failure(int index);
extern void fs_server_test_history_before_read(void (*hook)(void));
extern void fs_server_test_refresh_builder(bool (*builder)(struct file_manifest *, const char *));
#endif

/* Build a gated FS_REQUEST payload: [48-byte solution][body]. */
static uint32_t build_gated_request(uint8_t *out,
                                    const uint8_t solution[FS_POW_SOLUTION_SIZE],
                                    const char *body, uint32_t body_len)
{
    memcpy(out, solution, FS_POW_SOLUTION_SIZE);
    memcpy(out + FS_POW_SOLUTION_SIZE, body, body_len);
    return FS_POW_SOLUTION_SIZE + body_len;
}

/* Client-side: fetch a challenge from the gate, solve it bound to `token`. */
static bool solve_for_gate(const uint8_t token[32],
                           uint8_t solution[FS_POW_SOLUTION_SIZE])
{
    uint8_t seed[32];
    int bits = 0;
    int64_t st = 0;
    puzzle_gate_challenge(fs_pow_gate(), seed, &bits, &st);
    int64_t ts = (int64_t)platform_time_wall_time_t();
    uint64_t nonce = 0;
    if (!puzzle_solve(seed, token, ts, bits, &nonce))
        return false;
    memcpy(solution, token, 32);
    memcpy(solution + 32, &ts, 8);
    memcpy(solution + 40, &nonce, 8);
    return true;
}

static int test_ungated_all_refused_gated_served(void)
{
    int failures = 0;
    TEST("file_service: ungated ALL refused, gated ALL served") {
        fs_pow_reset_state();

        uint8_t token[32];
        memset(token, 0x9F, 32);  /* stands in for the handshake nonce */

        /* An ungated "ALL" (no puzzle) parses as a serve request but is not
         * admitted — the gate hands back a challenge instead of streaming. */
        bool is_all = false, is_rng = false;
        const uint8_t *puzzle = NULL;
        uint16_t s = 0, e = 0;
        ASSERT(fs_parse_serve_request((const uint8_t *)"ALL", 3,
                                      &is_all, &is_rng, &puzzle, &s, &e));
        ASSERT(is_all && puzzle == NULL);
        uint8_t seed[32];
        int bits = 0;
        int64_t st = 0;
        ASSERT(fs_admit_serve_pow(puzzle, token, seed, &bits, &st)
               == FS_ADMIT_CHALLENGE);

        /* Now solve the issued challenge and resubmit a gated ALL. */
        uint8_t solution[FS_POW_SOLUTION_SIZE];
        ASSERT(solve_for_gate(token, solution));
        uint8_t req[FS_POW_SOLUTION_SIZE + 8];
        uint32_t rlen = build_gated_request(req, solution, "ALL", 3);

        is_all = is_rng = false; puzzle = NULL;
        ASSERT(fs_parse_serve_request(req, rlen, &is_all, &is_rng,
                                      &puzzle, &s, &e));
        ASSERT(is_all && puzzle == req);
        ASSERT(fs_admit_serve_pow(puzzle, token, seed, &bits, &st)
               == FS_ADMIT_SERVE);
        PASS();
    } _test_next:;
    return failures;
}

static int test_gated_rng_parse_and_serve(void)
{
    int failures = 0;
    TEST("file_service: gated RNG parses range and admits") {
        fs_pow_reset_state();
        uint8_t token[32];
        memset(token, 0x41, 32);

        uint8_t solution[FS_POW_SOLUTION_SIZE];
        ASSERT(solve_for_gate(token, solution));

        /* body = "RNG" + start(2 LE) + end(2 LE) + pad */
        uint8_t body[8] = {'R','N','G', 0,0,0,0,0};
        body[3] = 5;  body[4] = 0;   /* start = 5   */
        body[5] = 40; body[6] = 0;   /* end   = 40  */
        uint8_t req[FS_POW_SOLUTION_SIZE + 8];
        uint32_t rlen = build_gated_request(req, solution, (const char *)body, 8);

        bool is_all = false, is_rng = false;
        const uint8_t *puzzle = NULL;
        uint16_t start = 0, end = 0;
        ASSERT(fs_parse_serve_request(req, rlen, &is_all, &is_rng,
                                      &puzzle, &start, &end));
        ASSERT(is_rng && !is_all);
        ASSERT(start == 5 && end == 40);
        uint8_t seed[32]; int bits = 0; int64_t st = 0;
        ASSERT(fs_admit_serve_pow(puzzle, token, seed, &bits, &st)
               == FS_ADMIT_SERVE);
        PASS();
    } _test_next:;
    return failures;
}

static int test_replayed_solution_rejected(void)
{
    int failures = 0;
    TEST("file_service: replayed solution is single-use rejected") {
        fs_pow_reset_state();
        uint8_t token[32];
        memset(token, 0x5B, 32);

        uint8_t solution[FS_POW_SOLUTION_SIZE];
        ASSERT(solve_for_gate(token, solution));
        uint8_t req[FS_POW_SOLUTION_SIZE + 3];
        uint32_t rlen = build_gated_request(req, solution, "ALL", 3);

        bool a = false, r = false; const uint8_t *pz = NULL; uint16_t s = 0, e = 0;
        ASSERT(fs_parse_serve_request(req, rlen, &a, &r, &pz, &s, &e));
        uint8_t seed[32]; int bits = 0; int64_t st = 0;
        /* First use admitted, exact replay refused (→ challenge). */
        ASSERT(fs_admit_serve_pow(pz, token, seed, &bits, &st)
               == FS_ADMIT_SERVE);
        ASSERT(fs_admit_serve_pow(pz, token, seed, &bits, &st)
               == FS_ADMIT_CHALLENGE);
        PASS();
    } _test_next:;
    return failures;
}

static int test_solution_bound_to_connection(void)
{
    int failures = 0;
    TEST("file_service: solution bound to the handshake token") {
        fs_pow_reset_state();
        uint8_t token_a[32], token_b[32];
        memset(token_a, 0x11, 32);
        memset(token_b, 0x22, 32);

        uint8_t solution[FS_POW_SOLUTION_SIZE];
        ASSERT(solve_for_gate(token_a, solution));
        uint8_t req[FS_POW_SOLUTION_SIZE + 3];
        build_gated_request(req, solution, "ALL", 3);

        uint8_t seed[32]; int bits = 0; int64_t st = 0;
        /* Presenting connection A's solution on connection B (peer_token B)
         * is refused — the token in the solution won't match. */
        ASSERT(fs_admit_serve_pow(req, token_b, seed, &bits, &st)
               == FS_ADMIT_CHALLENGE);
        PASS();
    } _test_next:;
    return failures;
}

static int test_per_ip_concurrency_cap(void)
{
    int failures = 0;
    TEST("file_service: per-IP concurrency cap trips") {
        fs_pow_reset_state();
        uint8_t ip[16];
        memset(ip, 0, 16);
        ip[15] = 7;

        /* Up to the cap acquires succeed. */
        for (int i = 0; i < FS_MAX_CONCURRENT_PER_IP; i++)
            ASSERT(fs_ip_serve_acquire(ip));
        /* One past the cap is refused. */
        ASSERT(!fs_ip_serve_acquire(ip));

        /* Releasing one frees a slot. */
        fs_ip_serve_release(ip);
        ASSERT(fs_ip_serve_acquire(ip));

        /* A different IP is independent. */
        uint8_t ip2[16];
        memset(ip2, 0, 16);
        ip2[15] = 8;
        ASSERT(fs_ip_serve_acquire(ip2));
        PASS();
    } _test_next:;
    return failures;
}

static int test_per_ip_hour_byte_cap(void)
{
    int failures = 0;
    TEST("file_service: per-IP hourly byte cap trips") {
        fs_pow_reset_state();
        uint8_t ip[16];
        memset(ip, 0, 16);
        ip[15] = 9;

        /* Charging just under the ceiling stays OK; crossing it trips. */
        uint64_t half = FS_IP_MAX_BYTES_PER_HOUR / 2;
        ASSERT(fs_ip_bytes_charge(ip, half));
        ASSERT(fs_ip_bytes_charge(ip, half));       /* now exactly at ceiling */
        ASSERT(!fs_ip_bytes_charge(ip, 1));          /* one byte over → refused */

        /* Independent IP has its own fresh budget. */
        uint8_t ip2[16];
        memset(ip2, 0, 16);
        ip2[15] = 10;
        ASSERT(fs_ip_bytes_charge(ip2, 1));
        PASS();
    } _test_next:;
    return failures;
}

static int test_per_connection_budget(void)
{
    int failures = 0;
    TEST("file_service: per-connection byte/time budget trips") {
        /* Fixed positive monotonic samples keep every boundary input valid
         * even on a host whose real monotonic epoch is still near zero. */
        int64_t now = INT64_C(10000000);

        /* Fresh connection, modest bytes → OK. */
        ASSERT(fs_conn_budget_ok(1024, now, now));

        /* Over the byte ceiling → refused. */
        ASSERT(!fs_conn_budget_ok(FS_CONN_MAX_BYTES + 1, now, now));

        /* Over the monotonic-time ceiling → refused. */
        int64_t start = now - ((int64_t)FS_CONN_MAX_SECONDS * 1000 + 5000);
        ASSERT(!fs_conn_budget_ok(1024, start, now));

        /* Exact time boundary is allowed; one millisecond past and a
         * backwards/invalid clock sample both fail closed. */
        int64_t boundary = now - (int64_t)FS_CONN_MAX_SECONDS * 1000;
        ASSERT(fs_conn_budget_ok(1024, boundary, now));
        ASSERT(!fs_conn_budget_ok(1024, boundary, now + 1));
        ASSERT(!fs_conn_budget_ok(1024, now + 1, now));

        /* At the boundary (exactly the ceiling) is still allowed. */
        ASSERT(fs_conn_budget_ok(FS_CONN_MAX_BYTES, now, now));
        PASS();
    } _test_next:;
    return failures;
}

#ifndef _WIN32
struct history_server_fixture {
    char dir[512];
    struct fs_history_generation first, second;
    int retained_fd;
    struct fs_session client;
    int client_fd;
    bool client_ready;
    bool dir_ready;
    uint64_t next_nonce;
    struct rom_artifact *selected, *other;
};

static bool history_fixture_rom_write(const char *dir, const char *name,
                                      uint8_t marker, struct rom_artifact *art)
{
    uint8_t snapshot[4096] = "SQLite format 3";
    snapshot[100] = marker;
    char path[640];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= sizeof(path))
        return false;
    FILE *stream = fopen(path, "wb");
    if (!stream)
        return false;
    bool written = fwrite(snapshot, 1, sizeof(snapshot), stream) == sizeof(snapshot);
    if (fclose(stream) != 0 || !written)
        return false;
    return rom_seed_register(dir, name, NULL, art) == ROM_REG_OK;
}

static bool history_fixture_roms(struct history_server_fixture *f)
{
    f->selected = calloc(1, sizeof(*f->selected));
    f->other = calloc(1, sizeof(*f->other));
    if (!f->selected || !f->other)
        return false;
    rom_seed_reset();
    rom_seed_set_enabled(true);
    return history_fixture_rom_write(f->dir, "consensus-state-bundle-1.sqlite", 0, f->selected) &&
           history_fixture_rom_write(f->dir, "consensus-state-bundle-2.sqlite", 1, f->other);
}

static bool history_fixture_make(struct history_server_fixture *f)
{
    memset(f, 0, sizeof(*f));
    f->client_fd = -1;
    fs_history_generation_init(&f->first);
    fs_history_generation_init(&f->second);
    if (!test_mkdtemp(f->dir, sizeof(f->dir), "zcl_fs_history"))
        return false;
    f->dir_ready = true;
    char blocks[600], file[640];
    if (snprintf(blocks, sizeof(blocks), "%s/blocks", f->dir) >= (int)sizeof(blocks) ||
        snprintf(file, sizeof(file), "%s/blk00000.dat", blocks) >= (int)sizeof(file) ||
        mkdir(blocks, 0700) != 0)
        return false;
    FILE *stream = fopen(file, "wb");
    if (!stream)
        return false;
    bool written = fwrite("abc", 1, 3, stream) == 3;
    if (fclose(stream) != 0 || chmod(file, 0600) != 0 || !written)
        return false;
    if (!history_fixture_roms(f))
        return false;
    struct file_manifest manifest = {0};
    manifest.num_chunks = 1;
    manifest.total_bytes = 3;
    manifest.chain_height = 1;
    manifest.chunks[0].size = 3;
    sha3_256((const uint8_t *)"abc", 3, manifest.chunks[0].sha3);
    sha3_256(manifest.chunks[0].sha3, 32, manifest.root_hash);
    struct platform_directory_transaction root1, root2;
    platform_directory_transaction_init(&root1);
    platform_directory_transaction_init(&root2);
    bool ok = platform_directory_transaction_open(&root1, f->dir) &&
              platform_directory_transaction_open(&root2, f->dir);
    uint8_t binding[32] = {1};
    ok = ok && fs_history_generation_take(&f->first, &root1, &manifest, f->selected->whole_sha3, 1, binding) &&
         fs_history_generation_take(&f->second, &root2, &manifest, f->selected->whole_sha3, 1, binding);
    platform_directory_transaction_close(&root1);
    platform_directory_transaction_close(&root2);
    f->retained_fd = (int)f->first.root.native;
    return ok;
}

static bool history_fixture_open(struct history_server_fixture *f)
{
    for (int i = 0; i < 2000 && !fs_server_is_running(); i++)
        platform_sleep_ms(1);
    if (!fs_server_is_running())
        return false;
    f->client_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = { .sin_family = AF_INET,
        .sin_port = htons(fs_server_get_port()), .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    if (f->client_fd < 0 || connect(f->client_fd, (struct sockaddr *)&address, sizeof(address)) != 0)
        return false;
    struct timeval timeout = { .tv_sec = 5 };
    (void)setsockopt(f->client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(f->client_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    fs_session_init(&f->client, f->client_fd);
    f->client_ready = true;
    return true;
}

static bool history_fixture_connect(struct history_server_fixture *f)
{
    uint8_t salt[32] = {0};
    return history_fixture_open(f) && fs_handshake(&f->client, salt, true);
}

static bool history_fixture_wrong_salt(void)
{
    struct history_server_fixture peer = { .client_fd = -1 };
    uint8_t wrong_salt[32] = {1};
    bool opened = history_fixture_open(&peer);
    bool refused = opened && !fs_handshake(&peer.client, wrong_salt, true);
    if (peer.client_ready)
        fs_session_cleanup(&peer.client);
    if (peer.client_fd >= 0)
        close(peer.client_fd);
    return refused;
}

static bool history_fixture_manifest(struct history_server_fixture *f)
{
    uint8_t type, digest[32];
    const uint8_t *body;
    uint32_t len;
    sha3_256((const uint8_t *)"abc", 3, digest);
    return fs_send_frame(&f->client, FS_MANIFEST, NULL, 0) &&
           fs_recv_frame(&f->client, &type, &body, &len) && type == FS_MANIFEST &&
           len == 45 && memcmp(body, digest, 32) == 0 && body[32] == 3 &&
           body[33] == 0 && body[34] == 0 && body[35] == 0 && body[36] == 0 &&
           fs_recv_frame(&f->client, &type, &body, &len) && type == FS_DONE && len == 0;
}

static bool history_fixture_rom_discovery(struct history_server_fixture *f)
{
    char body[4096];
    struct rom_fetch_manifest listed[2];
    uint8_t hashes[2][32];
    uint32_t count = 0;
    uint16_t port = fs_server_get_port();
    return rom_fetch_get_directory("127.0.0.1", port, body, sizeof(body)) &&
           rom_fetch_parse_directory(body, listed, 2) == 1 &&
           memcmp(listed[0].whole_sha3, f->selected->whole_sha3, 32) == 0 &&
           rom_fetch_get_manifest("127.0.0.1", port, f->selected->chunk_root,
                                  hashes, 2, &count) && count == 1 &&
           memcmp(hashes[0], f->selected->chunk_sha3[0], 32) == 0;
}

static bool history_fixture_rom_chunk_refusal(const struct history_server_fixture *f)
{
    struct history_server_fixture peer = { .client_fd = -1 };
    uint8_t request[FS_ROM_REQUEST_SIZE] = {'R', 'O', 'M'};
    memcpy(request + 3, f->other->chunk_root, 32);
    uint8_t refusal[5];
    bool ok = history_fixture_connect(&peer) &&
              fs_send_frame(&peer.client, FS_REQUEST, request, sizeof(request)) &&
              recv(peer.client_fd, refusal, sizeof(refusal), MSG_WAITALL) == (ssize_t)sizeof(refusal) &&
              refusal[0] == 0xff && refusal[1] == 0xff &&
              refusal[2] == 0xff && refusal[3] == 0xff &&
              refusal[4] == FS_ROM_REFUSE_UNKNOWN;
    if (peer.client_ready)
        fs_session_cleanup(&peer.client);
    if (peer.client_fd >= 0)
        close(peer.client_fd);
    return ok;
}

static bool history_fixture_selected_rom(const struct history_server_fixture *f)
{
    uint8_t *data = malloc(ROM_SEED_CHUNK_SIZE);
    if (!data)
        return false;
    uint32_t size = 0;
    bool ok = f->selected->height == 0 &&
        rom_fetch_chunk("127.0.0.1", fs_server_get_port(), f->selected->chunk_root,
                        0, data, ROM_SEED_CHUNK_SIZE, &size) && size == 4096 &&
        memcmp(data, "SQLite format 3", 16) == 0;
    free(data);
    return ok;
}

static bool history_fixture_request_range(struct history_server_fixture *f, bool all)
{
    uint8_t type;
    const uint8_t *body;
    uint32_t len;
    if (!fs_send_frame(&f->client, FS_CHALLENGE, NULL, 0) ||
        !fs_recv_frame(&f->client, &type, &body, &len) ||
        type != FS_CHALLENGE || len != FS_CHALLENGE_PAYLOAD_SIZE)
        return false;
    uint8_t seed[32];
    memcpy(seed, body, sizeof(seed));
    int bits = body[32];
    int64_t now = (int64_t)platform_time_wall_time_t();
    uint64_t nonce;
    if (!puzzle_solve_from(seed, f->client.our_nonce, now, bits,
                           f->next_nonce, &nonce) || nonce == UINT64_MAX)
        return false;
    f->next_nonce = nonce + 1;
    uint8_t request[FS_POW_SOLUTION_SIZE + 8] = {0};
    memcpy(request, f->client.our_nonce, 32);
    memcpy(request + 32, &now, 8);
    memcpy(request + 40, &nonce, 8);
    memcpy(request + FS_POW_SOLUTION_SIZE, all ? "ALL" : "RNG", 3);
    request[FS_POW_SOLUTION_SIZE + 5] = 1;
    uint32_t request_len = FS_POW_SOLUTION_SIZE + (all ? 3 : 8);
    return fs_send_frame(&f->client, FS_REQUEST, request, request_len);
}

static _Atomic bool g_history_range_read;
static void history_fixture_note_range_read(void)
{
    atomic_store(&g_history_range_read, true);
}

static bool history_fixture_range(struct history_server_fixture *f, bool all)
{
    uint8_t digest[32], *data = NULL;
    uint32_t len = 0;
    sha3_256((const uint8_t *)"abc", 3, digest);
    atomic_store(&g_history_range_read, false);
    fs_server_test_history_before_read(history_fixture_note_range_read);
    bool requested = history_fixture_request_range(f, all);
    bool received = requested && fs_recv_chunk_fast(&f->client, &data, &len, digest);
    printf("history range: all=%d requested=%d read=%d received=%d len=%u\n",
           all, requested, atomic_load(&g_history_range_read), received, len);
    fs_server_test_history_before_read(NULL);
    bool ok = received && len == 3 && memcmp(data, "abc", 3) == 0;
    free(data);
    return ok;
}

static _Atomic bool g_history_read_entered, g_history_read_release;
static void history_fixture_hold_read(void)
{
    atomic_store(&g_history_read_entered, true);
    while (!atomic_load(&g_history_read_release))
        platform_sleep_ms(1);
}
static void *history_fixture_stop(void *arg)
{
    (void)arg;
    fs_server_stop();
    return NULL;
}

static bool history_fixture_stop_during_read(struct history_server_fixture *f)
{
    atomic_store(&g_history_read_entered, false);
    atomic_store(&g_history_read_release, false);
    fs_server_test_history_before_read(history_fixture_hold_read);
    bool ok = history_fixture_request_range(f, false);
    for (int i = 0; i < 2000 && !atomic_load(&g_history_read_entered); i++)
        platform_sleep_ms(1);
    ok = ok && atomic_load(&g_history_read_entered);
    pthread_t stopper;
    bool started = ok && pthread_create(&stopper, NULL, history_fixture_stop, NULL) == 0;
    if (started) {
        for (int i = 0; i < 2000 && fs_server_is_running(); i++)
            platform_sleep_ms(1);
        ok = !fs_server_is_running() && fcntl(f->retained_fd, F_GETFD) >= 0 && ok;
    } else {
        ok = false;
    }
    atomic_store(&g_history_read_release, true);
    if (started)
        pthread_join(stopper, NULL);
    fs_server_test_history_before_read(NULL);
    uint8_t hash[32] = {1};
    return ok && fcntl(f->retained_fd, F_GETFD) < 0 &&
           !fs_server_history_matches(f->selected->whole_sha3, 1, hash);
}

static bool history_fixture_shutdown_child(struct history_server_fixture *f, bool after_start)
{
    bool started = !after_start || fs_server_start_with_history(&f->first, f->dir, 0, "127.0.0.1");
    thread_registry_request_shutdown();
    if (after_start) {
        fs_server_stop();
        return started && !f->first.ready && !fs_server_is_running() &&
               fcntl(f->retained_fd, F_GETFD) < 0;
    }
    return !fs_server_start_with_history(&f->first, f->dir, 0, "127.0.0.1") &&
           f->first.ready && (int)f->first.root.native == f->retained_fd &&
           fcntl(f->retained_fd, F_GETFD) >= 0;
}

static bool history_fixture_shutdown_case(struct history_server_fixture *f, bool after_start)
{
    pid_t child = fork();
    if (child < 0)
        return false;
    if (child == 0)
        _exit(history_fixture_shutdown_child(f, after_start) ? 0 : 1);
    int status = 0;
    for (int i = 0; i < 5000; i++) {
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child)
            return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        if (result < 0)
            return false;
        platform_sleep_ms(1); /* real-clock: child process shutdown uses kernel process scheduling */
    }
    (void)kill(child, SIGKILL);
    (void)waitpid(child, &status, 0);
    return false;
}

static bool history_fixture_adopt(struct history_server_fixture *f)
{
    fs_server_test_spawn_failure(0);
    bool ok = !fs_server_start_with_history(&f->first, f->dir, 0, "127.0.0.1") &&
              f->first.ready && (int)f->first.root.native == f->retained_fd;
    fs_server_test_spawn_failure(3);
    ok = ok && !fs_server_start_with_history(&f->first, f->dir, 0, "127.0.0.1") &&
         f->first.ready && (int)f->first.root.native == f->retained_fd;
    fs_server_test_spawn_failure(8);
    ok = ok && !fs_server_start_with_history(&f->first, f->dir, 0, "127.0.0.1") &&
         f->first.ready && (int)f->first.root.native == f->retained_fd;
    ok = ok && fs_server_start_with_history(&f->first, f->dir, 0, "127.0.0.1") &&
         !f->first.ready && f->first.root.native == UINTPTR_MAX;
    return ok && !fs_server_start_with_history(&f->second, f->dir, 0, "127.0.0.1") &&
           f->second.ready && !fs_server_refresh_manifest();
}

static bool history_fixture_matches(const struct history_server_fixture *f,
                                    const uint8_t hash[32], const uint8_t wrong[32])
{
    return fs_server_history_matches(f->selected->whole_sha3, 1, hash) &&
           !fs_server_history_matches(wrong, 1, hash) &&
           !fs_server_history_matches(NULL, 1, hash) &&
           !fs_server_history_matches(f->selected->whole_sha3, 1, NULL) &&
           !fs_server_history_matches(f->selected->whole_sha3, 2, hash) &&
           !fs_server_history_matches(f->selected->whole_sha3, 1, wrong);
}

static bool history_fixture_rom_protocol(struct history_server_fixture *f)
{
    return history_fixture_rom_discovery(f) && history_fixture_rom_chunk_refusal(f) &&
           history_fixture_selected_rom(f);
}

static bool history_fixture_protocol(struct history_server_fixture *f)
{
    uint8_t hash[32] = {1}, wrong[32] = {2};
    bool salt = history_fixture_wrong_salt();
    bool connected = salt && history_fixture_connect(f);
    bool matches = connected && history_fixture_matches(f, hash, wrong);
    bool rom = matches && history_fixture_rom_protocol(f);
    bool manifest = rom && history_fixture_manifest(f);
    bool range = manifest && history_fixture_range(f, false);
    bool all = range && history_fixture_range(f, true);
    printf("history protocol: salt=%d connected=%d matches=%d rom=%d manifest=%d range=%d all=%d\n",
           salt, connected, matches, rom, manifest, range, all);
    return salt && connected && matches && rom && manifest && range && all;
}

static int test_history_server_adoption_and_routing(void)
{
    struct history_server_fixture f;
    fs_server_stop();
    bool ok = history_fixture_make(&f);
    if (ok)
        ok = history_fixture_shutdown_case(&f, false) &&
             history_fixture_shutdown_case(&f, true);
    if (ok)
        ok = history_fixture_adopt(&f);
    if (ok)
        ok = history_fixture_protocol(&f);
    if (ok)
        ok = history_fixture_stop_during_read(&f);
    if (f.client_ready)
        fs_session_cleanup(&f.client);
    if (f.client_fd >= 0)
        close(f.client_fd);
    fs_server_stop();
    fs_history_generation_close(&f.first);
    fs_history_generation_close(&f.second);
    fs_server_test_spawn_failure(-1);
    fs_server_test_history_before_read(NULL);
    free(f.selected);
    free(f.other);
    rom_seed_reset();
    if (f.dir_ready)
        (void)test_rm_rf_recursive(f.dir);
    printf("file_service: retained history adoption and routing %s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static _Atomic bool g_refresh_entered, g_refresh_release, g_refresh_stopped;
static bool g_refresh_result;

static bool history_fixture_refresh_builder(struct file_manifest *out, const char *path)
{
    (void)path;
    atomic_store(&g_refresh_entered, true);
    while (!atomic_load(&g_refresh_release))
        platform_sleep_ms(1);
    memset(out, 0, sizeof(*out));
    out->num_chunks = 1;
    out->chunks[0].size = 99;
    return true;
}

static void *history_fixture_refresh_thread(void *arg)
{
    (void)arg;
    g_refresh_result = fs_server_refresh_manifest();
    return NULL;
}

static void *history_fixture_refresh_stop(void *arg)
{
    (void)arg;
    fs_server_stop();
    atomic_store(&g_refresh_stopped, true);
    return NULL;
}

static bool history_fixture_wait_flag(_Atomic bool *flag)
{
    for (int i = 0; i < 2000 && !atomic_load(flag); i++)
        platform_sleep_ms(1);
    return atomic_load(flag);
}

static void history_fixture_cleanup(struct history_server_fixture *f)
{
    if (f->client_ready)
        fs_session_cleanup(&f->client);
    if (f->client_fd >= 0)
        close(f->client_fd);
    fs_server_stop();
    fs_history_generation_close(&f->first);
    fs_history_generation_close(&f->second);
    free(f->selected);
    free(f->other);
    rom_seed_reset();
    if (f->dir_ready)
        (void)test_rm_rf_recursive(f->dir);
}

static int test_history_refresh_cannot_replace_generation(void)
{
    struct history_server_fixture f;
    fs_server_stop();
    bool ok = history_fixture_make(&f);
    atomic_store(&g_refresh_entered, false);
    atomic_store(&g_refresh_release, false);
    atomic_store(&g_refresh_stopped, false);
    g_refresh_result = true;
    fs_server_test_refresh_builder(history_fixture_refresh_builder);
    pthread_t refresh, stop;
    bool refresh_started = false, stop_started = false;
    if (ok)
        ok = fs_server_start(f.dir, 0, "127.0.0.1");
    if (ok) {
        refresh_started = pthread_create(&refresh, NULL, history_fixture_refresh_thread, NULL) == 0;
        ok = refresh_started && history_fixture_wait_flag(&g_refresh_entered);
    }
    if (ok) {
        stop_started = pthread_create(&stop, NULL, history_fixture_refresh_stop, NULL) == 0;
        ok = stop_started && history_fixture_wait_flag(&g_refresh_stopped);
    }
    if (ok)
        ok = fs_server_start_with_history(&f.first, f.dir, 0, "127.0.0.1");
    atomic_store(&g_refresh_release, true);
    if (refresh_started)
        pthread_join(refresh, NULL);
    if (stop_started)
        pthread_join(stop, NULL);
    fs_server_test_refresh_builder(NULL);
    if (ok)
        ok = !g_refresh_result && history_fixture_connect(&f) && history_fixture_manifest(&f);
    history_fixture_cleanup(&f);
    printf("file_service: stale refresh cannot replace history %s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}
#else
static int test_history_server_adoption_and_routing(void) { return 0; }
static int test_history_refresh_cannot_replace_generation(void) { return 0; }
#endif

int test_file_service_pow_gate(void)
{
    int failures = 0;
    failures += test_ungated_all_refused_gated_served();
    failures += test_gated_rng_parse_and_serve();
    failures += test_replayed_solution_rejected();
    failures += test_solution_bound_to_connection();
    failures += test_per_ip_concurrency_cap();
    failures += test_per_ip_hour_byte_cap();
    failures += test_per_connection_budget();
    failures += test_history_server_adoption_and_routing();
    failures += test_history_refresh_cannot_replace_generation();
    return failures;
}
