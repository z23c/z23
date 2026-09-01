/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* The client-puzzle PoW guard the zchunkreq / zblkreq serve handlers ask
 * for admission from, plus the deterministic-clock test surface over it.
 *
 * Split out of msgprocessor_snapshot_serve.c — pure code motion, no
 * behavior change. It earns its own translation unit because it shares
 * nothing with the serve handlers except one call: the guard owns the
 * arming flag and the load window, the handlers own the cached offer,
 * manifests and the wire. See msgprocessor_snapshot_internal.h for the
 * one declaration that crosses the split. */

#include "platform/time_compat.h"
#include "base/serialize_le.h"
#include "msgprocessor_snapshot_internal.h"

#include "net/msgprocessor.h"
#include "net/puzzle.h"
#include "crypto/sha3.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>

/* ── Client-puzzle PoW guard for zchunkreq / zblkreq (PoW-DDoS posture) ──
 *
 * Cost of the two ops this guards (see the lane note for full numbers):
 *   - zchunkreq: one fast_sync_serve_chunk() DB read of up to
 *     SYNC_CHUNK_SIZE (500) UTXO rows (script up to 520 bytes each,
 *     ~571 B/row decoded) plus serialization — a single 4-byte request can
 *     pull ~285 KB out of storage.
 *   - zblkreq: up to BLOCKS_PER_PIECE (512) full block bodies read from
 *     disk and serialized, capped at MAX_PROTOCOL_MESSAGE_LENGTH (2 MiB)
 *     per response — a single 4-byte request can force up to 2 MiB of
 *     disk reads. This is the "large range" expensive op in this file.
 *   - zsnapreq (legacy full-snapshot serve) already goes through
 *     snapsync_validate_serve_request()'s existing PoW gate — untouched,
 *     reused as-is.
 *
 * Design: a STATELESS puzzle, per the lane note. No per-peer server state,
 * no stored rotating seed table (unlike struct puzzle_gate, which this
 * deliberately does NOT reuse because that primitive keeps a mutex-guarded
 * seed + single-use ring; this guard only needs the pure, already-tested
 * digest/verify primitives it exposes):
 *
 *   challenge   = SHA3-256(domain[16] || request_kind[1] ||
 *                          request_index[4 LE] || time_bucket[8 LE])
 *                 where domain is the fixed lane tag below — it exists to
 *                 namespace the digest, not to hide anything. It must NOT
 *                 be process-random material: a requester that cannot
 *                 derive the challenge can never produce a valid nonce, so
 *                 arming a secret-bound variant would permanently deny
 *                 every external client (the in-process tests could not
 *                 catch that, since solver and verifier share the secret
 *                 there).
 *   solve       = nonce such that SHA3-256(challenge || 0^32 || 0 || nonce)
 *                 has D leading zero bits (reuses the hardened
 *                 puzzle_verify/puzzle_solve digest from
 *                 fast_sync.c, passing a zero peer_token/ts since peer
 *                 request binding and freshness are already carried by
 *                 `challenge` itself).
 *
 * The derivation is public by construction. Request kind and index are the
 * first fields of zchunkreq/zblkreq, and the time bucket is explicit LE.
 * The server-observed peer address is deliberately excluded: a requester
 * behind NAT cannot know which address the server observes. Per-address
 * abuse containment remains the existing fast_sync_rate_check() gate.
 * Arming is still deferred —
 * requesters do not attach nonces yet, so an armed gate today would deny
 * honest legacy peers outright (see msgprocessor.h for the constants and
 * the adaptive-difficulty ramp).
 *
 * Difficulty is 0 (mechanism present, gate open) until armed via
 * msg_snapshot_pow_set_armed(true) — see lane note point 3. When
 * disarmed, zchunkreq/zblkreq behave exactly as before (existing
 * msg_snapshot_serving_allowed / range / fast_sync_rate_check gates only).
 * When armed, a peer that omits or fails the puzzle simply doesn't get
 * this particular response — same as today's rate-limited path: no ban,
 * no peer_scoring penalty, so old peers that never learned to attach a
 * solution degrade to (existing-rate-limit-only) throttled service rather
 * than being dropped or scored.
 *
 * SNAP_POW_* difficulty/window constants live in net/msgprocessor.h (not
 * here) so the test suite can assert scaling bounds without duplicating
 * magic numbers. */

static _Atomic bool g_snap_pow_armed = false;

static pthread_mutex_t g_snap_pow_load_mutex = PTHREAD_MUTEX_INITIALIZER;
static int64_t g_snap_pow_window_start = 0;
static uint32_t g_snap_pow_reqs_in_window = 0;

static void snap_pow_challenge(uint8_t request_kind, uint32_t request_index,
                               int64_t time_bucket, uint8_t out[32])
{
    static const uint8_t snap_pow_domain[16] = MSG_SNAP_POW_DOMAIN;
    uint8_t index_le[4];
    uint8_t bucket_le[8];
    uint64_t bucket_bits = (uint64_t)time_bucket;
    zcl_write_u32_le(index_le, request_index);
    zcl_write_u64_le(bucket_le, bucket_bits);
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, snap_pow_domain, sizeof(snap_pow_domain));
    sha3_256_write(&ctx, &request_kind, sizeof(request_kind));
    sha3_256_write(&ctx, index_le, sizeof(index_le));
    sha3_256_write(&ctx, bucket_le, sizeof(bucket_le));
    sha3_256_finalize(&ctx, out);
}

/* Recent-request-count load proxy → adaptive difficulty (caller-supplied
 * clock so tests are deterministic). Bumps the counter as a side effect,
 * matching the "note this request happened" contract every call site
 * needs (one call per admission decision). */
static int snap_pow_note_request_and_get_bits(int64_t now)
{
    pthread_mutex_lock(&g_snap_pow_load_mutex);
    if (now - g_snap_pow_window_start > SNAP_POW_WINDOW_SECS) {
        g_snap_pow_window_start = now;
        g_snap_pow_reqs_in_window = 0;
    }
    int bits = SNAP_POW_MIN_BITS;
    if (g_snap_pow_reqs_in_window > SNAP_POW_SOFT_RATE) {
        bits += (int)((g_snap_pow_reqs_in_window - SNAP_POW_SOFT_RATE) /
                      SNAP_POW_RATE_STEP);
    }
    if (bits > SNAP_POW_MAX_BITS) bits = SNAP_POW_MAX_BITS;
    if (g_snap_pow_reqs_in_window < UINT32_MAX)
        g_snap_pow_reqs_in_window++;
    pthread_mutex_unlock(&g_snap_pow_load_mutex);
    return bits;
}

static bool snap_pow_solve_at(uint8_t request_kind, uint32_t request_index,
                              int64_t at_time,
                              int difficulty_bits, uint64_t *nonce_out)
{
    int64_t bucket = at_time / SNAP_POW_BUCKET_SECS;
    uint8_t challenge[32];
    static const uint8_t zero32[32] = {0};
    snap_pow_challenge(request_kind, request_index, bucket, challenge);
    return puzzle_solve(challenge, zero32, 0, difficulty_bits,
                                  nonce_out);
}

/* Admit a zchunkreq/zblkreq at clock `now`. `nonce` is the peer-supplied
 * solution (NULL if the request carried none). Checks the current and
 * prior time bucket so a solve that started just before a rotation still
 * verifies (matches the +1 grace epoch struct puzzle_gate uses). */
static bool snap_pow_admit_at(uint8_t request_kind, uint32_t request_index,
                              int64_t now,
                              const uint64_t *nonce)
{
    int bits = snap_pow_note_request_and_get_bits(now);
    if (!atomic_load(&g_snap_pow_armed))
        return true;   /* difficulty-0 posture: mechanism wired, gate open */
    if (!nonce)
        return false;  /* no solution attached — no ban, just no serve */

    int64_t bucket = now / SNAP_POW_BUCKET_SECS;
    uint8_t challenge[32];
    static const uint8_t zero32[32] = {0};

    snap_pow_challenge(request_kind, request_index, bucket, challenge);
    if (puzzle_verify(challenge, zero32, 0, *nonce, bits))
        return true;
    snap_pow_challenge(request_kind, request_index, bucket - 1, challenge);
    return puzzle_verify(challenge, zero32, 0, *nonce, bits);
}

bool msg_snapshot_pow_admit(uint8_t request_kind, uint32_t request_index,
                            const uint64_t *nonce)
{
    return snap_pow_admit_at(request_kind, request_index,
                            (int64_t)platform_time_wall_time_t(), nonce);
}

void msg_snapshot_pow_set_armed(bool armed)
{
    atomic_store(&g_snap_pow_armed, armed);
}

bool msg_snapshot_pow_is_armed(void)
{
    return atomic_load(&g_snap_pow_armed);
}

bool msgprocessor_test_snap_pow_challenge(uint8_t request_kind,
                                          uint32_t request_index,
                                          int64_t at_time,
                                          uint8_t out[32])
{
    if (!out)
        return false;
    snap_pow_challenge(request_kind, request_index,
                       at_time / SNAP_POW_BUCKET_SECS, out);
    return true;
}

bool msgprocessor_test_snap_pow_solve(uint8_t request_kind,
                                      uint32_t request_index,
                                      int64_t at_time, int difficulty_bits,
                                      uint64_t *nonce_out)
{
    return snap_pow_solve_at(request_kind, request_index, at_time,
                             difficulty_bits, nonce_out);
}

bool msgprocessor_test_snap_pow_admit_at(uint8_t request_kind,
                                         uint32_t request_index,
                                         int64_t at_time,
                                         const uint64_t *nonce)
{
    return snap_pow_admit_at(request_kind, request_index, at_time, nonce);
}

int msgprocessor_test_snap_pow_bits_at(int64_t at_time)
{
    return snap_pow_note_request_and_get_bits(at_time);
}

void msgprocessor_test_snap_pow_reset(void)
{
    pthread_mutex_lock(&g_snap_pow_load_mutex);
    g_snap_pow_window_start = 0;
    g_snap_pow_reqs_in_window = 0;
    pthread_mutex_unlock(&g_snap_pow_load_mutex);
    atomic_store(&g_snap_pow_armed, false);
}
