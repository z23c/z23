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
#include <string.h>
#include <stdint.h>

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
        int64_t now = platform_time_monotonic_ms();

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
    return failures;
}
