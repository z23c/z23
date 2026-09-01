/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * puzzle.{c,h} — a reusable, load-adaptive client-puzzle admission gate.
 *
 * This is an ANTI-ABUSE ADMISSION gate in front of expensive server-side
 * work (minting a z-address, streaming a multi-GB snapshot, rebuilding an
 * O(n) UTXO root). It is NEVER persisted, NEVER a consensus predicate, and
 * is entirely distinct from block/Equihash PoW — a fresh process starts
 * clean and consensus validity does not depend on any of this state.
 *
 * Puzzle:
 *
 *   SHA3-256(challenge_seed || peer_token || ts || nonce) has D leading
 *   zero bits.
 *
 * Verifying costs one keccak (negligible); an attacker pays O(2^D) hashes
 * per admitted request. Three properties generalize the hand-rolled gate
 * that previously lived in fast_sync.c (fast_sync_pow_gate):
 *
 *   1. SERVER-ISSUED, ROTATING challenge_seed — the requester cannot pick
 *      its own puzzle or precompute solutions offline against a predictable
 *      seed. A fresh random seed is minted every PUZZLE_SEED_ROTATE_SECS;
 *      the prior seed stays valid for one extra epoch so an in-flight honest
 *      solve is never invalidated by a rotation.
 *   2. SINGLE-USE accepted-solution ring — one solved puzzle admits exactly
 *      one request; an exact replay within the ring's retention is refused.
 *   3. LOAD-ADAPTIVE difficulty — required bits rise with the per-surface
 *      accepted-request rate (an EWMA, no reset edge — see puzzle.c §EWMA)
 *      and with concurrent large serves, and fall back to the idle floor
 *      when the surface is quiet.
 *
 * Each admission surface (store order mint, snapshot serve, file stream)
 * owns ONE struct puzzle_gate instance and its own peer_token derivation;
 * this file owns the seed/verify/EWMA/single-use machinery.
 */

#ifndef ZCL_NET_PUZZLE_H
#define ZCL_NET_PUZZLE_H

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

/* ── Pure puzzle primitives (no timestamp/rate/replay policy) ────────── */

/* True iff SHA3-256(challenge_seed || peer_token || ts || nonce) has
 * difficulty_bits leading zero bits. */
bool puzzle_verify(const uint8_t challenge_seed[32],
                   const uint8_t peer_token[32],
                   int64_t ts, uint64_t nonce, int difficulty_bits);

/* Nonce search for a solution (blocking). Returns true and sets
 * *nonce_out on success.
 *
 * WHERE THE SEARCH STARTS MATTERS. A search from zero is a pure function
 * of (seed, token, ts): two honest solvers that share all three — same
 * surface, same second — return the SAME nonce, so the second one's
 * genuinely-solved puzzle is refused by the single-use ring as a replay.
 * That is a live defect wherever the token is not per-requester (it is
 * why the snapshot-serve surface cannot enforce single-use on its current
 * wire format — see engine/services/src/snapshot_sync_service.c).
 *
 *   puzzle_solve()        — from zero. Deterministic; use when the caller
 *                           wants a reproducible answer (tests, fixtures).
 *   puzzle_solve_random() — from a random offset. THE DEFAULT for a real
 *                           client: collisions between independent honest
 *                           solvers become negligible.
 *   puzzle_solve_from()   — explicit start, for a caller that owns the
 *                           de-collision policy itself.
 *
 * All three cost the same expected number of hashes: the predicate is a
 * leading-zero-bits test on a hash, so no start point is luckier. */
bool puzzle_solve(const uint8_t challenge_seed[32],
                  const uint8_t peer_token[32],
                  int64_t ts, int difficulty_bits, uint64_t *nonce_out);
bool puzzle_solve_random(const uint8_t challenge_seed[32],
                         const uint8_t peer_token[32],
                         int64_t ts, int difficulty_bits, uint64_t *nonce_out);
bool puzzle_solve_from(const uint8_t challenge_seed[32],
                       const uint8_t peer_token[32],
                       int64_t ts, int difficulty_bits,
                       uint64_t start_nonce, uint64_t *nonce_out);

/* ── Difficulty band + load knobs (defaults) ─────────────────────────── */

#define PUZZLE_MIN_BITS          12   /* idle floor: ~4k hashes, sub-ms      */
#define PUZZLE_MAX_BITS          26   /* saturated: ~67M hashes per request  */
#define PUZZLE_SEED_ROTATE_SECS  45   /* challenge-seed epoch                */
#define PUZZLE_TS_SKEW_SECS     120   /* accepted client-timestamp skew      */
#define PUZZLE_RECENT_CAP      2048   /* single-use ring size                */

/* EWMA half-life for the per-surface accepted-request rate, in seconds.
 * Replaces the old 10s tumbling window whose count reset to 0 at each
 * boundary (a flood 1s after a reset read as "idle" for up to 9s). The
 * EWMA has no reset edge — see puzzle.c for the update rule. */
#define PUZZLE_EWMA_HALFLIFE_SECS 10
#define PUZZLE_EWMA_SOFT_RATE      8  /* accepted/sec before bits start rising */
#define PUZZLE_EWMA_RATE_STEP      4  /* +1 bit per this many accepted/sec over soft */
#define PUZZLE_INFLIGHT_BITS       2  /* +bits per concurrent large serve       */

/* Per-surface policy. Zero-init and puzzle_gate_init() fills every zero
 * field from the PUZZLE_* defaults, so a surface that wants the defaults
 * simply passes NULL. A surface with different honest-request economics
 * (a cheap store order vs. a multi-GB stream) passes its own band/rate. */
struct puzzle_policy {
    int min_bits, max_bits;      /* 0 → PUZZLE_MIN/MAX_BITS         */
    int seed_rotate_secs;        /* 0 → PUZZLE_SEED_ROTATE_SECS     */
    int ts_skew_secs;            /* 0 → PUZZLE_TS_SKEW_SECS         */
    int ewma_halflife_secs;      /* 0 → PUZZLE_EWMA_HALFLIFE_SECS   */
    int soft_rate_per_sec;       /* 0 → PUZZLE_EWMA_SOFT_RATE       */
    int rate_step_per_sec;       /* 0 → PUZZLE_EWMA_RATE_STEP       */
    int inflight_bits;           /* 0 → PUZZLE_INFLIGHT_BITS        */
};

/* In-memory admission gate for ONE named surface. Transient only. */
struct puzzle_gate {
    pthread_mutex_t lock;
    bool     initialized;
    struct puzzle_policy policy;      /* resolved (zero fields filled) */
    uint8_t  cur_seed[32];
    int      cur_bits;
    int64_t  cur_epoch_start;         /* wall seconds */
    uint8_t  prev_seed[32];
    int      prev_bits;
    bool     have_prev;
    bool     seeded;
    uint32_t inflight;                /* concurrent large serves in progress */
    /* EWMA of accepted-requests-per-second, fixed point ×1000 to avoid
     * float in a lock-held hot path. */
    int64_t  rate_ewma_milli;
    int64_t  last_update_us;          /* monotonic microseconds */
    /* Single-use accepted-solution digests (ring buffer). */
    uint8_t  recent[PUZZLE_RECENT_CAP][32];
    uint32_t recent_head;
    uint32_t recent_count;
};

/* Initialize (idempotent; resets all counters/seeds). policy NULL → all
 * defaults. Preserves the mutex across re-init. */
void puzzle_gate_init(struct puzzle_gate *g, const struct puzzle_policy *policy);

/* Issue the live challenge to a requester. Rotates the seed if the epoch
 * elapsed and recomputes the current adaptive difficulty from live load.
 * out_seed/out_bits/out_server_time may each be NULL. */
void puzzle_gate_challenge(struct puzzle_gate *g, uint8_t out_seed[32],
                           int *out_bits, int64_t *out_server_time);

/* Verify a solution against the live challenge (tries current then grace
 * seed). Enforces timestamp skew, difficulty, and single-use. On success
 * the digest is recorded (immediate replay fails) and the request counts
 * toward the load EWMA. Returns true iff admitted. */
bool puzzle_gate_verify(struct puzzle_gate *g, const uint8_t peer_token[32],
                        int64_t ts, uint64_t nonce);

/* Single-use admission for a surface that verifies its OWN proof but wants
 * the shared single-use ring + load EWMA — e.g. a legacy P2P wire format that
 * cannot yet carry a server-issued seed round-trip, but still needs a solved
 * proof to be good for exactly one expensive serve rather than replayable for
 * its whole validity window. `solution_digest` must be a 32-byte hash that
 * uniquely identifies the accepted (challenge, solution) so an exact replay is
 * caught. Returns true and records the digest + counts the request toward the
 * load EWMA on first sight; false if it is a replay of an already-admitted
 * solution. Does NOT itself verify difficulty — the caller owns that. */
bool puzzle_gate_admit_external(struct puzzle_gate *g,
                                const uint8_t solution_digest[32]);

/* Bracket a committed large serve so concurrency raises difficulty for the
 * duration. begin/end must be balanced. */
void puzzle_gate_serve_begin(struct puzzle_gate *g);
void puzzle_gate_serve_end(struct puzzle_gate *g);

/* Introspection (no state mutation) — backs the unit tests. */
int64_t puzzle_gate_rate_ewma_milli(struct puzzle_gate *g);
int     puzzle_gate_current_bits(struct puzzle_gate *g);

/* Deterministic-clock entry points (testing / reproducible simulation):
 * identical to the wall-clock functions above but the caller supplies both
 * the wall timestamp (seconds, drives seed epoch + skew) and the monotonic
 * clock (microseconds, drives the load EWMA). The public
 * puzzle_gate_challenge/verify call these with the live clocks. */
void puzzle_gate_challenge_at(struct puzzle_gate *g, int64_t now_wall,
                              int64_t now_us, uint8_t out_seed[32],
                              int *out_bits, int64_t *out_server_time);
bool puzzle_gate_verify_at(struct puzzle_gate *g, const uint8_t peer_token[32],
                           int64_t ts, uint64_t nonce,
                           int64_t now_wall, int64_t now_us);

#endif /* ZCL_NET_PUZZLE_H */
