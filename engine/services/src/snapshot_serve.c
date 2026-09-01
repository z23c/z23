/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Snapshot SERVE side — what this node does when a PEER asks IT for a
 * snapshot: admission (client puzzle + rate limit) and the per-tick chunk
 * cursor over the prebuilt in-RAM snapshot buffer.
 *
 * Split out of snapshot_sync_service.c, which owns the RECEIVE lifecycle
 * (the singleton, the service lock, the state machine) and had grown past
 * the app/ file-size ceiling (E1). The seam is the one that file's own
 * header comment already named: the serve path shares no state with the
 * receive state machine — the transitions there are owned by the
 * requesting peer — so it is a clean lift, not a new abstraction.
 *
 * Siblings: snapshot_offer.c (offer manifest + request build),
 * snapshot_fetch.c (chunk receive), snapshot_verify.c, snapshot_apply.c.
 * The public API is declared by net/snapshot_sync_contract.h. */

#include "net/snapshot_sync_contract.h"
#include "net/fast_sync.h"
#include "net/puzzle.h"
#include "net/net.h"
#include "crypto/sha3.h"
#include "util/log_macros.h"

#include <string.h>
#include <stdatomic.h>
#include <pthread.h>

/* Rate limiter — declared in fast_sync but we need the global instance */
extern struct fast_sync_rate_limiter g_rate_limiter;

/* ── Serve-side client-puzzle load census (OBSERVATION ONLY) ──────────
 *
 * The admission decision below is unchanged: fast_sync_verify_pow() at a
 * FIXED 20 bits, then the per-IP/global rate limiter. What is new is that
 * every accepted request is also offered to a struct puzzle_gate through
 * puzzle_gate_admit_external(), so the shared primitive's load EWMA is fed
 * by real snapshot-serve traffic instead of being idle on this surface.
 * The gate's verdict is discarded for admission — it is recorded as a
 * census (snapsync_get_serve_puzzle_census) and nothing else.
 *
 * WHY THE VERDICT CANNOT BE LOAD-BEARING YET — verified in the source, not
 * inherited:
 *
 *   The `zsnapreq` proof is the 48-byte tuple (peer_id, timestamp, nonce).
 *   The requester builds it in snapsync_build_request_pow()
 *   (engine/services/src/snapshot_offer.c): peer_id = SHA3-256(peer_ip) over
 *   the 16-byte address, then fast_sync_solve_pow() (core/modules/net/src/fast_sync.c)
 *   sets timestamp = platform_time_wall_time_t() — WHOLE SECONDS — and walks
 *   nonce upward from 0, returning the first hit. Every input is a pure
 *   function of (address, wall second). Two solves that share both therefore
 *   return the SAME nonce and serialize to BYTE-IDENTICAL proof bytes, and a
 *   single-use ring would refuse the second as a replay.
 *
 *   It is worse than "the same requester twice". The address hashed is
 *   `node->addr.svc.addr.ip` at the CALL SITE in core/modules/net/src/msgprocessor_snapshot.c,
 *   which on the requesting side is the address of the peer being ASKED —
 *   the server. So two DIFFERENT honest peers requesting a snapshot from the
 *   same server within one second also produce identical proofs, and the
 *   second would be refused. The serve side never compares pow.peer_id to
 *   the connection it arrived on (snapsync_validate_serve_request uses
 *   peer_ip only for the rate limiter), so the field binds nothing today.
 *
 *   tests/harness/src/test_snapshot_serve_loopback.c reproduces the collision:
 *   it runs the whole loopback twice in one process, from one fixed
 *   loopback address, and both runs build a real zsnapreq through
 *   snapsync_write_snapshot_request(). Whenever those two runs land in the
 *   same wall second the two proofs are identical byte-for-byte.
 *
 * WHAT WOULD MAKE IT ENFORCEABLE — a wire protocol revision, out of scope
 * for this change because it needs a compatibility window on a live network:
 *
 *   1. The snapshot OFFER carries the server's live challenge:
 *      challenge_seed[32] || difficulty_bits(u8) || server_time(i64), i.e.
 *      the output of puzzle_gate_challenge() on the serving node.
 *   2. The requester derives peer_token = SHA3-256("zsnapreq:" || its OWN
 *      advertised address || offer.block_hash) — bound to the requester and
 *      to the specific offer — and solves against the server's seed.
 *   3. The request carries seed-echo || peer_token || ts || nonce, and the
 *      serve side calls puzzle_gate_verify(), which gets the rotating seed,
 *      the adaptive difficulty and single-use for free.
 *   4. Compatibility: a peer that sent no seed echo is still validated by
 *      fast_sync_verify_pow() as today, for one release window, until the
 *      census below shows the legacy path is unused.
 *
 *   Step 2 is what removes the collision: distinct requesters get distinct
 *   tokens, and a rotating server seed means the nonce walk from zero lands
 *   somewhere different every epoch even for one requester.
 *
 * Deliberately NOT done here: randomizing the nonce start in
 * fast_sync_solve_pow() would de-collide our own solver, but it changes what
 * this node puts on the live wire and does nothing for peers running the
 * older binary, which is the population that matters. */
static struct puzzle_gate g_snapsync_serve_load_gate;
static pthread_once_t g_snapsync_serve_gate_once = PTHREAD_ONCE_INIT;

/* A bulk snapshot serve is a multi-hundred-MB uplink commitment, so the
 * honest request rate is very low and concurrency dominates. Floor and
 * ceiling are the primitive's defaults; only the rate thresholds tighten. */
static const struct puzzle_policy g_snapsync_serve_load_policy = {
    .soft_rate_per_sec = 2,
    .rate_step_per_sec = 1,
};

static void snapsync_serve_gate_init_once(void)
{
    puzzle_gate_init(&g_snapsync_serve_load_gate,
                     &g_snapsync_serve_load_policy);
}

static _Atomic uint64_t g_snapsync_serve_offered     = 0;
static _Atomic uint64_t g_snapsync_serve_first_sight = 0;
static _Atomic uint64_t g_snapsync_serve_duplicates  = 0;

void snapsync_get_serve_puzzle_census(struct snapsync_serve_puzzle_census *out)
{
    if (!out) return;
    pthread_once(&g_snapsync_serve_gate_once, snapsync_serve_gate_init_once);
    out->offered     = atomic_load(&g_snapsync_serve_offered);
    out->first_sight = atomic_load(&g_snapsync_serve_first_sight);
    out->duplicates  = atomic_load(&g_snapsync_serve_duplicates);
    out->bits_now    = puzzle_gate_current_bits(&g_snapsync_serve_load_gate);
    out->rate_ewma_milli =
        puzzle_gate_rate_ewma_milli(&g_snapsync_serve_load_gate);
}

void snapsync_reset_serve_puzzle_census(void)
{
    pthread_once(&g_snapsync_serve_gate_once, snapsync_serve_gate_init_once);
    puzzle_gate_init(&g_snapsync_serve_load_gate,
                     &g_snapsync_serve_load_policy);
    atomic_store(&g_snapsync_serve_offered, 0);
    atomic_store(&g_snapsync_serve_first_sight, 0);
    atomic_store(&g_snapsync_serve_duplicates, 0);
}

/* Feed one accepted request to the shared gate. Return value intentionally
 * unused by the caller — see the block comment above. */
static void snapsync_serve_note_puzzle(const struct fast_sync_pow *pow)
{
    uint8_t digest[32];

    pthread_once(&g_snapsync_serve_gate_once, snapsync_serve_gate_init_once);
    /* Hash the proof FIELDS, not the struct: sizeof(struct fast_sync_pow)
     * includes padding whose bytes are not part of the wire proof. */
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, pow->peer_id, 32);
    sha3_256_write(&ctx, (const unsigned char *)&pow->timestamp, 8);
    sha3_256_write(&ctx, (const unsigned char *)&pow->nonce, 8);
    sha3_256_finalize(&ctx, digest);

    atomic_fetch_add(&g_snapsync_serve_offered, 1);
    if (puzzle_gate_admit_external(&g_snapsync_serve_load_gate, digest)) {
        atomic_fetch_add(&g_snapsync_serve_first_sight, 1);
        return;
    }
    /* A byte-identical proof. Loud, because this is the exact event that
     * decides whether the protocol revision above can drop its
     * compatibility window — and it is NOT a refusal: the request is
     * served anyway. */
    uint64_t dups = atomic_fetch_add(&g_snapsync_serve_duplicates, 1) + 1;
    LOG_WARN("snapsync",
             "serve puzzle census: byte-identical zsnapreq proof "
             "(ts=%lld nonce=%llu) — served anyway, admission unchanged; "
             "duplicates=%llu of offered=%llu",
             (long long)pow->timestamp, (unsigned long long)pow->nonce,
             (unsigned long long)dups,
             (unsigned long long)atomic_load(&g_snapsync_serve_offered));
}

/* Action: validate a snapshot serve request (PoW + rate limit). */
enum snapsync_serve_result snapsync_validate_serve_request(
    const uint8_t *pow_data, size_t pow_len,
    const uint8_t peer_ip[16])
{
    if (!pow_data || pow_len < 48)
        return SNAPSYNC_SERVE_TRUNCATED;

    /* Parse PoW fields */
    struct fast_sync_pow pow;
    memset(&pow, 0, sizeof(pow));
    memcpy(pow.peer_id, pow_data, 32);
    memcpy(&pow.timestamp, pow_data + 32, 8);
    memcpy(&pow.nonce, pow_data + 40, 8);

    if (!fast_sync_verify_pow(&pow))
        return SNAPSYNC_SERVE_BAD_POW;

    if (!fast_sync_rate_check(&g_rate_limiter, peer_ip))
        return SNAPSYNC_SERVE_RATE_LIMITED;

    snapsync_serve_note_puzzle(&pow);
    return SNAPSYNC_SERVE_OK;
}

struct zcl_result snapsync_prepare_serve_step(struct snapsync_serve_step *step,
                                              struct p2p_node *node,
                                              const uint8_t *buf,
                                              int64_t buf_size)
{
    int64_t pos;
    int64_t scan;
    uint32_t entries;
    bool ok = true;

    if (!step || !node || !buf || buf_size <= 0)
        return ZCL_ERR(-1, "prepare_serve_step: invalid args step=%p node=%p "
                       "buf=%p size=%lld", (void*)step, (void*)node,
                       (void*)buf, (long long)buf_size);

    memset(step, 0, sizeof(*step));
    if (node->zsync_file_size == 0)
        node->zsync_file_size = buf_size;
    /* Allow up to 8MB of send buffer during snapshot serving.
     * The previous 2MB limit caused stalls: the receiver's SQLite writes
     * slow TCP drainage, the 2MB fills in ~50 chunks, and the sender's
     * message loop moves on to other peers before returning to pump more.
     * 8MB gives ~200 chunks of headroom. */
    if (node->send_size > 8 * 1024 * 1024)
        return ZCL_OK;  /* step->action == SNAPSYNC_SERVE_ACTION_NONE (backpressure) */

    pos = node->zsync_file_offset;
    if (pos >= buf_size) {
        step->action = SNAPSYNC_SERVE_ACTION_SEND_END;
        return ZCL_OK;
    }

    if (pos + 4 > buf_size)
        return ZCL_ERR(-2, "prepare_serve_step: pos %lld + 4 > buf_size %lld",
                       (long long)pos, (long long)buf_size);

    entries = buf[pos] | ((uint32_t)buf[pos + 1] << 8) |
              ((uint32_t)buf[pos + 2] << 16) |
              ((uint32_t)buf[pos + 3] << 24);
    if (entries == 0 || entries > 1000)
        return ZCL_ERR(-3, "prepare_serve_step: bad entry count %u at pos %lld",
                       entries, (long long)pos);

    scan = pos + 4;
    for (uint32_t i = 0; i < entries && ok; i++) {
        uint64_t slen;

        scan += 49;
        if (scan >= buf_size) {
            ok = false;
            break;
        }

        slen = buf[scan++];
        if (slen == 253) {
            if (scan + 2 > buf_size) {
                ok = false;
                break;
            }
            slen = buf[scan] | ((uint16_t)buf[scan + 1] << 8);
            scan += 2;
        } else if (slen == 254) {
            if (scan + 4 > buf_size) {
                ok = false;
                break;
            }
            slen = buf[scan] | ((uint32_t)buf[scan + 1] << 8) |
                   ((uint32_t)buf[scan + 2] << 16) |
                   ((uint32_t)buf[scan + 3] << 24);
            scan += 4;
        }
        scan += (int64_t)slen;
    }

    if (!ok || scan > buf_size)
        return ZCL_ERR(-4, "prepare_serve_step: scan overflow scan=%lld "
                       "buf_size=%lld entries=%u",
                       (long long)scan, (long long)buf_size, entries);

    step->action = SNAPSYNC_SERVE_ACTION_SEND_CHUNK;
    step->chunk_offset = pos;
    step->chunk_len = (size_t)(scan - pos);
    step->entries = entries;

    node->zsync_file_offset = scan;
    node->zsync_offset += entries;
    node->zsync_sent++;
    return ZCL_OK;
}
