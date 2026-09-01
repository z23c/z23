/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Load-adaptive client-puzzle admission gate. See net/puzzle.h for the
 * contract, threat model, and the invariant that none of this is ever
 * persisted or a consensus predicate. */

#include "net/puzzle.h"
#include "platform/time_compat.h"
#include "crypto/sha3.h"
#include "core/random.h"
#include "util/log_macros.h"

#include <string.h>

/* ── Pure puzzle primitives ──────────────────────────────────────────── */

static bool puzzle_hash_has_bits(const uint8_t hash[32], int bits)
{
    if (bits <= 0) return true;
    if (bits > 256) bits = 256;
    int whole = bits / 8;
    for (int i = 0; i < whole; i++)
        if (hash[i] != 0) return false;   /* normal during solve — not error */
    int rem = bits % 8;
    if (rem > 0) {
        uint8_t mask = (uint8_t)(0xFF << (8 - rem));
        if (hash[whole] & mask) return false; /* normal during solve — not error */
    }
    return true;
}

static void puzzle_digest(const uint8_t challenge_seed[32],
                          const uint8_t peer_token[32],
                          int64_t ts, uint64_t nonce, uint8_t out[32])
{
    /* SHA3-256 for hash diversity from the SHA-256d consensus layer. */
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, challenge_seed, 32);
    sha3_256_write(&ctx, peer_token, 32);
    sha3_256_write(&ctx, (const unsigned char *)&ts, 8);
    sha3_256_write(&ctx, (const unsigned char *)&nonce, 8);
    sha3_256_finalize(&ctx, out);
}

bool puzzle_verify(const uint8_t challenge_seed[32],
                   const uint8_t peer_token[32],
                   int64_t ts, uint64_t nonce, int difficulty_bits)
{
    if (!challenge_seed || !peer_token)
        return false;   /* caller bug, but no policy log here (hot verify path) */
    uint8_t hash[32];
    puzzle_digest(challenge_seed, peer_token, ts, nonce, hash);
    return puzzle_hash_has_bits(hash, difficulty_bits);
}

bool puzzle_solve_from(const uint8_t challenge_seed[32],
                       const uint8_t peer_token[32],
                       int64_t ts, int difficulty_bits,
                       uint64_t start_nonce, uint64_t *nonce_out)
{
    GUARD(challenge_seed && peer_token && nonce_out, "puzzle",
          "solve: NULL arg (seed=%p token=%p out=%p)",
          (const void *)challenge_seed, (const void *)peer_token,
          (void *)nonce_out);
    uint64_t n = start_nonce;
    for (uint64_t tried = 0; tried < UINT64_MAX; tried++, n++) {
        if (puzzle_verify(challenge_seed, peer_token, ts, n, difficulty_bits)) {
            *nonce_out = n;
            return true;
        }
    }
    LOG_FAIL("puzzle", "solve: exhausted nonce space at D=%d", difficulty_bits);
}

bool puzzle_solve(const uint8_t challenge_seed[32],
                  const uint8_t peer_token[32],
                  int64_t ts, int difficulty_bits, uint64_t *nonce_out)
{
    return puzzle_solve_from(challenge_seed, peer_token, ts, difficulty_bits,
                             0, nonce_out);
}

bool puzzle_solve_random(const uint8_t challenge_seed[32],
                         const uint8_t peer_token[32],
                         int64_t ts, int difficulty_bits, uint64_t *nonce_out)
{
    uint64_t start = 0;
    GetRandBytes((unsigned char *)&start, sizeof(start));
    return puzzle_solve_from(challenge_seed, peer_token, ts, difficulty_bits,
                             start, nonce_out);
}

/* ── Policy resolution ───────────────────────────────────────────────── */

static int pick(int v, int def) { return v != 0 ? v : def; }

static void puzzle_policy_resolve(struct puzzle_policy *p)
{
    p->min_bits           = pick(p->min_bits, PUZZLE_MIN_BITS);
    p->max_bits           = pick(p->max_bits, PUZZLE_MAX_BITS);
    p->seed_rotate_secs   = pick(p->seed_rotate_secs, PUZZLE_SEED_ROTATE_SECS);
    p->ts_skew_secs       = pick(p->ts_skew_secs, PUZZLE_TS_SKEW_SECS);
    p->ewma_halflife_secs = pick(p->ewma_halflife_secs, PUZZLE_EWMA_HALFLIFE_SECS);
    p->soft_rate_per_sec  = pick(p->soft_rate_per_sec, PUZZLE_EWMA_SOFT_RATE);
    p->rate_step_per_sec  = pick(p->rate_step_per_sec, PUZZLE_EWMA_RATE_STEP);
    p->inflight_bits      = pick(p->inflight_bits, PUZZLE_INFLIGHT_BITS);
    if (p->min_bits < 0) p->min_bits = 0;
    if (p->max_bits < p->min_bits) p->max_bits = p->min_bits;
    if (p->rate_step_per_sec <= 0) p->rate_step_per_sec = 1;
    if (p->ewma_halflife_secs <= 0) p->ewma_halflife_secs = 1;
}

void puzzle_gate_init(struct puzzle_gate *g, const struct puzzle_policy *policy)
{
    if (!g) return;
    /* Preserve a real mutex across re-init; only the first init constructs it. */
    if (!g->initialized)
        pthread_mutex_init(&g->lock, NULL);
    pthread_mutex_lock(&g->lock);
    if (policy)
        g->policy = *policy;
    else
        memset(&g->policy, 0, sizeof(g->policy));
    puzzle_policy_resolve(&g->policy);
    memset(g->cur_seed, 0, sizeof(g->cur_seed));
    memset(g->prev_seed, 0, sizeof(g->prev_seed));
    g->cur_bits = g->policy.min_bits;
    g->prev_bits = g->policy.min_bits;
    g->cur_epoch_start = 0;
    g->have_prev = false;
    g->seeded = false;
    g->inflight = 0;
    g->rate_ewma_milli = 0;
    g->last_update_us = 0;
    memset(g->recent, 0, sizeof(g->recent));
    g->recent_head = 0;
    g->recent_count = 0;
    g->initialized = true;
    pthread_mutex_unlock(&g->lock);
}

static void puzzle_gate_ensure_init(struct puzzle_gate *g)
{
    if (!g->initialized)
        puzzle_gate_init(g, NULL);
}

/* ── EWMA of accepted-request rate (caller holds g->lock) ─────────────────
 *
 * A decayed-count EWMA: each accepted request contributes a unit impulse
 * (1 req/sec worth of mass, ×1000 fixed point), continuously decayed by the
 * elapsed monotonic time since the last tick with the policy half-life.
 * Unlike a tumbling window there is no reset edge — a flood that starts 1µs
 * after the last tick is visible immediately and decays smoothly.
 *
 * The decay applies whole half-life halvings first (bounded to keep this a
 * couple of shifts even after an idle gap), then a linear blend for the
 * sub-half-life remainder — no float, no libm pow() on the lock-held path. */
static void puzzle_ewma_tick_locked(struct puzzle_gate *g, int64_t now_us,
                                    bool accepted)
{
    int64_t halflife_us = (int64_t)g->policy.ewma_halflife_secs * 1000000;
    if (halflife_us <= 0) halflife_us = 1000000;

    if (g->last_update_us == 0) {
        /* First sample ever. */
        g->rate_ewma_milli = accepted ? 1000 : 0;
        g->last_update_us = now_us;
        return;
    }

    int64_t dt_us = now_us - g->last_update_us;
    if (dt_us < 0) dt_us = 0;                 /* clock stepped back — no negative decay */
    if (dt_us > 5000000) dt_us = 5000000;     /* cap: a long idle gap decays ≤5s worth  */
    g->last_update_us = now_us;

    if (dt_us > 0 && g->rate_ewma_milli > 0) {
        int k = 0;
        while (dt_us >= halflife_us && k < 20) {
            g->rate_ewma_milli /= 2;
            dt_us -= halflife_us;
            k++;
        }
        /* Sub-half-life remainder: linear blend toward zero. */
        if (dt_us > 0)
            g->rate_ewma_milli -= g->rate_ewma_milli * dt_us / (2 * halflife_us);
        if (g->rate_ewma_milli < 0) g->rate_ewma_milli = 0;
    }

    if (accepted)
        g->rate_ewma_milli += 1000;   /* this request's unit impulse */
}

/* Adaptive difficulty from live load (caller holds g->lock). */
static int puzzle_gate_adaptive_bits_locked(const struct puzzle_gate *g)
{
    const struct puzzle_policy *p = &g->policy;
    int rate_per_sec = (int)(g->rate_ewma_milli / 1000);
    int bits = p->min_bits;
    bits += (int)g->inflight * p->inflight_bits;
    if (rate_per_sec > p->soft_rate_per_sec)
        bits += (rate_per_sec - p->soft_rate_per_sec) / p->rate_step_per_sec;
    if (bits > p->max_bits) bits = p->max_bits;
    if (bits < p->min_bits) bits = p->min_bits;
    return bits;
}

/* Ensure a live seed exists / rotate if the epoch elapsed (holds g->lock). */
static void puzzle_gate_rotate_locked(struct puzzle_gate *g, int64_t now_wall)
{
    bool rotate = !g->seeded ||
                  (now_wall - g->cur_epoch_start) >= g->policy.seed_rotate_secs;
    if (!rotate)
        return;
    if (g->seeded) {
        memcpy(g->prev_seed, g->cur_seed, 32);
        g->prev_bits = g->cur_bits;
        g->have_prev = true;
    }
    GetRandBytes(g->cur_seed, 32);
    g->cur_epoch_start = now_wall;
    g->seeded = true;
}

void puzzle_gate_challenge_at(struct puzzle_gate *g, int64_t now_wall,
                              int64_t now_us, uint8_t out_seed[32],
                              int *out_bits, int64_t *out_server_time)
{
    if (!g) return;
    puzzle_gate_ensure_init(g);
    pthread_mutex_lock(&g->lock);
    puzzle_ewma_tick_locked(g, now_us, false);   /* age the load estimate */
    puzzle_gate_rotate_locked(g, now_wall);
    /* Recompute difficulty bound to the current seed from live load so a
     * flood immediately raises the price of a freshly issued challenge, while
     * an idle node hands out the cheap floor. */
    g->cur_bits = puzzle_gate_adaptive_bits_locked(g);
    if (out_seed) memcpy(out_seed, g->cur_seed, 32);
    if (out_bits) *out_bits = g->cur_bits;
    if (out_server_time) *out_server_time = now_wall;
    pthread_mutex_unlock(&g->lock);
}

void puzzle_gate_challenge(struct puzzle_gate *g, uint8_t out_seed[32],
                           int *out_bits, int64_t *out_server_time)
{
    puzzle_gate_challenge_at(g, (int64_t)platform_time_wall_time_t(),
                             platform_time_monotonic_us(),
                             out_seed, out_bits, out_server_time);
}

/* True if digest already in the single-use ring (caller holds g->lock). */
static bool puzzle_gate_seen_locked(const struct puzzle_gate *g,
                                    const uint8_t digest[32])
{
    for (uint32_t i = 0; i < g->recent_count; i++)
        if (memcmp(g->recent[i], digest, 32) == 0)
            return true;
    return false;
}

static void puzzle_gate_remember_locked(struct puzzle_gate *g,
                                        const uint8_t digest[32])
{
    memcpy(g->recent[g->recent_head], digest, 32);
    g->recent_head = (g->recent_head + 1) % PUZZLE_RECENT_CAP;
    if (g->recent_count < PUZZLE_RECENT_CAP)
        g->recent_count++;
}

bool puzzle_gate_verify_at(struct puzzle_gate *g, const uint8_t peer_token[32],
                           int64_t ts, uint64_t nonce,
                           int64_t now_wall, int64_t now_us)
{
    if (!g || !peer_token)
        return false;
    puzzle_gate_ensure_init(g);

    if (ts < now_wall - g->policy.ts_skew_secs ||
        ts > now_wall + g->policy.ts_skew_secs)
        return false;   /* stale/forward-dated — client should re-challenge */

    pthread_mutex_lock(&g->lock);
    puzzle_ewma_tick_locked(g, now_us, false);   /* age before deciding */

    if (!g->seeded) {
        pthread_mutex_unlock(&g->lock);
        return false;   /* no challenge issued yet */
    }

    /* Try the current seed, then the one-epoch grace seed. Only the seed the
     * client actually solved against yields the required leading zeros. */
    bool ok = false;
    uint8_t digest[32];
    if (puzzle_verify(g->cur_seed, peer_token, ts, nonce, g->cur_bits)) {
        puzzle_digest(g->cur_seed, peer_token, ts, nonce, digest);
        ok = true;
    } else if (g->have_prev &&
               puzzle_verify(g->prev_seed, peer_token, ts, nonce, g->prev_bits)) {
        puzzle_digest(g->prev_seed, peer_token, ts, nonce, digest);
        ok = true;
    }

    if (!ok) {
        pthread_mutex_unlock(&g->lock);
        return false;   /* wrong/insufficient solution — re-challenge */
    }

    /* Single-use: a previously accepted solution is refused. */
    if (puzzle_gate_seen_locked(g, digest)) {
        pthread_mutex_unlock(&g->lock);
        return false;
    }
    puzzle_gate_remember_locked(g, digest);
    puzzle_ewma_tick_locked(g, now_us, true);   /* count this admitted request */
    pthread_mutex_unlock(&g->lock);
    return true;
}

bool puzzle_gate_verify(struct puzzle_gate *g, const uint8_t peer_token[32],
                        int64_t ts, uint64_t nonce)
{
    return puzzle_gate_verify_at(g, peer_token, ts, nonce,
                                 (int64_t)platform_time_wall_time_t(),
                                 platform_time_monotonic_us());
}

bool puzzle_gate_admit_external(struct puzzle_gate *g,
                                const uint8_t solution_digest[32])
{
    if (!g || !solution_digest)
        return false;
    puzzle_gate_ensure_init(g);
    int64_t now_us = platform_time_monotonic_us();
    pthread_mutex_lock(&g->lock);
    puzzle_ewma_tick_locked(g, now_us, false);   /* age before deciding */
    if (puzzle_gate_seen_locked(g, solution_digest)) {
        pthread_mutex_unlock(&g->lock);
        return false;   /* replay of an already-admitted solution */
    }
    puzzle_gate_remember_locked(g, solution_digest);
    puzzle_ewma_tick_locked(g, now_us, true);    /* count this admitted request */
    pthread_mutex_unlock(&g->lock);
    return true;
}

void puzzle_gate_serve_begin(struct puzzle_gate *g)
{
    if (!g) return;
    puzzle_gate_ensure_init(g);
    pthread_mutex_lock(&g->lock);
    g->inflight++;
    pthread_mutex_unlock(&g->lock);
}

void puzzle_gate_serve_end(struct puzzle_gate *g)
{
    if (!g) return;
    puzzle_gate_ensure_init(g);
    pthread_mutex_lock(&g->lock);
    if (g->inflight > 0)
        g->inflight--;
    pthread_mutex_unlock(&g->lock);
}

int64_t puzzle_gate_rate_ewma_milli(struct puzzle_gate *g)
{
    if (!g) return 0;
    puzzle_gate_ensure_init(g);
    pthread_mutex_lock(&g->lock);
    int64_t v = g->rate_ewma_milli;
    pthread_mutex_unlock(&g->lock);
    return v;
}

int puzzle_gate_current_bits(struct puzzle_gate *g)
{
    if (!g) return 0;
    puzzle_gate_ensure_init(g);
    pthread_mutex_lock(&g->lock);
    int b = puzzle_gate_adaptive_bits_locked(g);
    pthread_mutex_unlock(&g->lock);
    return b;
}
