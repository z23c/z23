/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* msg_headers.c — Header sync message processing.
 * Split from msgprocessor.c for maintainability. */

#include "net/msg_internal.h"
#include "net/msg_bounds_guard.h"
#include "net/p2p_message.h"
#include "net/peer_scoring.h"
#include "net/fast_sync.h"
#include "sync/sync_planner.h"
#include "storage/disk_block_io.h"
#include "storage/node_db_runtime.h"
#include "validation/check_block.h"
#include "validation/process_block.h"
#include "net/download.h"
#include "event/event.h"
#include "sync/sync_state.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"
#include "util/safe_alloc.h"
#include "util/timedata.h"
#include "coins/coins_view.h"
#include "chain/equihash.h"
#include "chain/pow.h"
#include "chain/checkpoints.h"
#include "crypto/sha256.h"
#include "util/clientversion.h"
#include "base/serialize_le.h"
#include "core/arith_uint256.h"
#include "net/netaddr.h"
#include "net/header_corroboration.h"
#include "net/checkpoint_header_fetch.h"
#include "net/header_serve_repair.h"
#include "platform/time_compat.h"
#include "services/header_range_scheduler.h"  // lib-layer-ok:net3-range-parallel-header-planner
#include <signal.h>
extern volatile sig_atomic_t g_shutdown_requested;
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

/* Header sync stall tracking state is in msg_send_messages (msgprocessor.c).
 * This file handles the receive-side header processing. */

#include <stdatomic.h>
#include <pthread.h>

/* ── Sync diagnostic counters ──────────────────────────────────── */

static _Atomic uint64_t g_headers_batches_received = 0;
static _Atomic uint64_t g_headers_total_accepted = 0;
static _Atomic uint64_t g_headers_total_rejected = 0;
static _Atomic uint64_t g_headers_newly_added = 0;
static _Atomic uint64_t g_headers_already_known = 0;

/* ── getheaders serve-path solution cache budget ────────────────────
 *
 * The in-memory block index deliberately drops nSolution to save RAM
 * (lib/storage/src/block_index_db.c: "Don't store solution in
 * block_index to save RAM"), so a header served off a disk-loaded index
 * has to re-read its Equihash solution from the flat block file or from
 * the node.db `blocks` row. headers_refresh_index_from_header() pins
 * that solution back onto the index entry so the next serve of the same
 * header is free — but block_index entries live for the whole process
 * lifetime, and `getheaders` needs nothing but a completed handshake.
 * One unauthenticated peer walking the entire header chain would
 * otherwise pin ~1.8 GB (585318 x 1344 + ~2.6M x 400 bytes), exactly
 * undoing the RAM decision above.
 *
 * So the CACHE is bounded, never the SERVE: past the budget the header
 * is still loaded from the store and still served in full, it is simply
 * not memoised. Bytes are counted only when this file allocates them and
 * are never returned (index entries outlive every serve), which biases
 * the count high — the safe direction for a cap. */
#define HEADERS_SOLUTION_CACHE_MAX_BYTES ((size_t)64 * 1024 * 1024)
static _Atomic size_t g_headers_solution_cache_bytes = 0;
static _Atomic bool g_headers_solution_cache_full_logged = false;

/* See net/msg_internal.h. */
size_t getheaders_solution_cache_bytes(void)
{
    return atomic_load(&g_headers_solution_cache_bytes);
}

/* ── getheaders serve-path accounting ───────────────────────────────
 *
 * Serving headers is the one thing an unauthenticated post-handshake peer
 * can make this node spend real CPU on, and until these counters existed
 * neither an operator nor a test could measure how much. See the
 * msg_headers_stats comments in net/msgprocessor.h for the pair's meaning;
 * g_headers_serve_pow_checks is the cost side — one full Equihash
 * verification each, 383-390 us at 200,9 — and its contract is at most one
 * per header put on the wire. */
static _Atomic uint64_t g_headers_served_total = 0;
static _Atomic uint64_t g_getheaders_served_requests = 0;
static _Atomic uint64_t g_headers_serve_pow_checks = 0;

/* See net/msg_internal.h. */
uint64_t getheaders_serve_pow_checks(void)
{
    return atomic_load(&g_headers_serve_pow_checks);
}

/* ── serve-path verification receipts ───────────────────────────────
 *
 * The dedup above is WITHIN one lookup: resolve which bytes are
 * authoritative, then verify those bytes once. It does nothing across
 * lookups. A peer that re-sends the same `getheaders` locator gets the same
 * page re-proved from scratch every time — 2000 headers x 383-390 us = 0.78 s
 * of a core per request, for a 61-byte request the peer can repeat forever.
 * That is the amplification this table closes: proof already DONE is not
 * re-done, and proof never done is never skipped.
 *
 * A receipt says exactly one thing: "this process, this build, these
 * consensus parameters, already ran the full serve-path verification over
 * the header whose hash is H, and it PASSED." It is not a status bit and
 * cannot degrade into one, for four structural reasons:
 *
 *   1. MINTED ONLY BY SUCCESS. The only write is at the bottom of
 *      headers_verify_bound_header, after check_equihash_solution,
 *      CheckProofOfWork and the timestamp check have all passed. There is no
 *      other writer, no loader, no persisted form, and nothing an operator
 *      or a peer can pre-seed. A slot can therefore only ever hold a hash
 *      this process itself proved.
 *   2. HASH-BOUND, AND THE BIND IS SELF-ENFORCED. nSolution is part of the
 *      serialized header, so a header hash uniquely determines every byte
 *      the verification read; two different byte strings cannot share a
 *      receipt. headers_verify_bound_header re-derives the hash from the
 *      bytes in front of it rather than trusting its caller's `hash`, so the
 *      key is a property of this function, not a contract with the caller.
 *   3. GENERATION-BOUND. Each slot stores the generation tag that was
 *      current when it was minted (build source id + genesis hash +
 *      powLimit). Lookup compares tags, so a verdict minted under a
 *      different build or different consensus parameters is a MISS, not a
 *      hit — nothing is honoured across a change that could alter what the
 *      verdict means. Stale slots need no sweeping: they simply stop
 *      matching.
 *   4. A MISS COSTS FULL VERIFICATION. Every path that is not an
 *      exact hash+generation match falls through to the unconditional
 *      three-check sequence. Eviction, a cold table, a generation change
 *      and a bucket collision all degrade to "verify it again" — never to
 *      "assume it passed".
 *
 * SUCCESSES ONLY; FAILURES ARE NEVER CACHED. Not caution — the verdict is
 * not symmetric. A PASS is monotone: Equihash over fixed bytes is
 * deterministic, CheckProofOfWork over fixed bytes and a fixed powLimit is
 * deterministic, and `nTime > now + 2h` can only stop being true as the
 * clock advances. So a PASS stays true for as long as the generation holds.
 * A FAIL is NOT monotone, and concretely so: a header refused right now for
 * time-too-new becomes servable a few minutes later. Caching that refusal
 * would make this node permanently refuse to serve headers it is willing to
 * serve — a peer feeding us a valid chain slightly ahead of our clock could
 * poison the serve path against that chain for the process lifetime. The
 * expensive verdict is the one worth keeping and the safe one to keep.
 *
 * BOUNDED BY CONSTRUCTION. A fixed static array, direct-mapped on the low
 * bits of the header hash. No allocation, so there is no allocation-failure
 * path at insert to get wrong, and no growth for a flood to drive: a peer
 * offering unlimited distinct headers churns slots at a constant 320 KB.
 * Colliding into an occupied slot overwrites it, which is the eviction
 * policy — the loser is re-verified next time it is served. An attacker can
 * grind hashes into one bucket to force that, but each such header costs
 * them a real Equihash mine and buys them only the behaviour this node had
 * before the table existed. 8192 slots is sized off the workload the
 * amplification actually uses: the serve loop caps one reply at `max_headers`
 * — 2000 for a fast-sync peer, 160 otherwise — so a peer replaying whole
 * maximum-size pages stays resident with room for four of them.
 *
 * The lock is what keeps a receipt honest under two serve threads. A slot is
 * 40 bytes and cannot be read or written atomically, and a torn read
 * pairing one header's hash prefix with another's suffix is exactly the
 * false HIT this whole design exists to make impossible. A 32-byte compare
 * under a mutex against 383-390 us of Equihash is not a cost worth
 * optimising. */
#define HEADERS_VERIFY_RECEIPT_SLOTS 8192u

struct headers_verify_receipt {
    struct uint256 hash;      /* the header this process proved */
    uint64_t generation;      /* tag it was proved under; 0 = empty slot */
};

static struct headers_verify_receipt
    g_headers_verify_receipts[HEADERS_VERIFY_RECEIPT_SLOTS];
static pthread_mutex_t g_headers_verify_receipt_lock =
    PTHREAD_MUTEX_INITIALIZER;
static _Atomic uint64_t g_headers_verify_receipt_hits = 0;
static _Atomic uint64_t g_headers_verify_receipt_mints = 0;
static _Atomic uint64_t g_headers_verify_receipt_evictions = 0;

/* See net/msg_internal.h. */
void getheaders_verify_receipt_stats(struct getheaders_receipt_stats *out)
{
    if (!out)
        return;
    out->slots = HEADERS_VERIFY_RECEIPT_SLOTS;
    out->bytes = sizeof(g_headers_verify_receipts);
    out->hits = atomic_load(&g_headers_verify_receipt_hits);
    out->mints = atomic_load(&g_headers_verify_receipt_mints);
    out->evictions = atomic_load(&g_headers_verify_receipt_evictions);

    size_t used = 0;
    pthread_mutex_lock(&g_headers_verify_receipt_lock);
    for (size_t i = 0; i < HEADERS_VERIFY_RECEIPT_SLOTS; i++) {
        if (g_headers_verify_receipts[i].generation != 0)
            used++;
    }
    pthread_mutex_unlock(&g_headers_verify_receipt_lock);
    out->occupied = used;
}

/* The generation tag: everything outside the header bytes that could change
 * what "this header verified" means. Recomputed on every lookup rather than
 * memoised against the params pointer — a params-pointer cache would go
 * stale if a struct were ever revised in place, and one SHA256 over ~100
 * bytes is ~0.3% of the Equihash verification it is guarding, so buying a
 * whole class of cache-invalidation bug for that is a bad trade.
 *
 * Inputs, and why each is here:
 *   - the build's source id: a different binary may verify differently, so
 *     its verdicts are not ours to honour;
 *   - hashGenesisBlock: identifies the network, and with it the height
 *     schedule the caller's Equihash size screen reads;
 *   - powLimit: the one consensus value the cached sequence actually reads
 *     (CheckProofOfWork). check_equihash_solution ignores its params
 *     argument entirely, so Equihash validity is a pure function of the
 *     header bytes the hash already binds.
 * Returns 0 when the tag cannot be established, which callers treat as
 * "no receipts" — verify, and mint nothing. */
static uint64_t headers_verify_generation(const struct chain_params *params)
{
    if (!params)
        return 0;
    const char *src = zcl_build_source_id_sha256();
    if (!src || !src[0])
        return 0;

    struct sha256_ctx ctx;
    sha256_init(&ctx);
    static const char domain[] = "zcl-getheaders-verify-receipt-v1";
    sha256_write(&ctx, (const unsigned char *)domain, sizeof(domain) - 1);
    sha256_write(&ctx, (const unsigned char *)src, strlen(src));
    sha256_write(&ctx, params->consensus.hashGenesisBlock.data, 32);
    sha256_write(&ctx, params->consensus.powLimit.data, 32);
    unsigned char out[SHA256_OUTPUT_SIZE];
    sha256_finalize(&ctx, out);

    uint64_t gen = zcl_read_u64_be(out);
    /* 0 is the empty-slot marker, so it must never be a live tag. */
    return gen ? gen : 1;
}

/* Direct-mapped on the LOW bytes of the hash. A valid header hash is under
 * target, so its high bytes are zeros and carry no information; the low
 * bytes are the only ones that spread. */
static size_t headers_verify_receipt_slot(const struct uint256 *hash)
{
    uint32_t v = zcl_read_u32_le(hash->data);
    return (size_t)(v & (HEADERS_VERIFY_RECEIPT_SLOTS - 1u));
}

/* True only for an exact hash AND generation match. Every other outcome is
 * false, and false means "verify it". */
static bool headers_verify_receipt_present(const struct uint256 *hash,
                                           uint64_t generation)
{
    if (!hash || generation == 0)
        return false;

    size_t slot = headers_verify_receipt_slot(hash);
    pthread_mutex_lock(&g_headers_verify_receipt_lock);
    const struct headers_verify_receipt *r = &g_headers_verify_receipts[slot];
    bool hit = r->generation == generation && uint256_eq(&r->hash, hash);
    pthread_mutex_unlock(&g_headers_verify_receipt_lock);

    if (hit)
        atomic_fetch_add(&g_headers_verify_receipt_hits, 1);
    return hit;
}

/* Mint. The ONLY writer, and its one caller is the success tail of
 * headers_verify_bound_header. */
static void headers_verify_receipt_record(const struct uint256 *hash,
                                          uint64_t generation)
{
    if (!hash || generation == 0)
        return;

    size_t slot = headers_verify_receipt_slot(hash);
    pthread_mutex_lock(&g_headers_verify_receipt_lock);
    struct headers_verify_receipt *r = &g_headers_verify_receipts[slot];
    bool displaced = r->generation != 0 && !uint256_eq(&r->hash, hash);
    r->hash = *hash;
    r->generation = generation;
    pthread_mutex_unlock(&g_headers_verify_receipt_lock);

    atomic_fetch_add(&g_headers_verify_receipt_mints, 1);
    if (displaced)
        atomic_fetch_add(&g_headers_verify_receipt_evictions, 1);
}

/* ── getheaders continuation-suppression counters ──────────────────
 *
 * push_getheaders_from() has two guards that used to `return;` silently:
 * a null-hash anchor and an active snapshot exchange. A silent header-sync
 * stop is forbidden by construction (a stall must always name a blocker or
 * a growing gap), so each guard now increments a counter and LOG_WARNs
 * once on the RISING EDGE of a suppression streak. The streak clears when
 * the guard stops firing, so a later stall re-announces itself instead of
 * the guard spamming the log on every ~10s poll. Surfaced through
 * msg_headers_get_stats() → health `headers` object. */
static _Atomic uint64_t g_getheaders_suppressed_no_hash = 0;
static _Atomic uint64_t g_getheaders_suppressed_snapshot = 0;
static _Atomic bool g_no_hash_streak = false;
static _Atomic bool g_snapshot_streak = false;

/* Rising edge of a suppression streak: true the first call after `streak`
 * was cleared, false while the streak persists. */
static bool getheaders_suppress_rising_edge(_Atomic bool *streak)
{
    return !atomic_exchange(streak, true);
}

/* Sibling silent-drop sites, same file, same defect class as the pair
 * above: each used to `return;` / `return true;` with zero counter and
 * zero log while a snapshot exchange owned the wire (or, for the
 * locator-alloc case, on allocation failure). Counted + rising-edge
 * logged for the same reason — a stall must always name a blocker,
 * never go quiet. Surfaced via msg_headers_get_stats(). */
static _Atomic uint64_t g_headers_recv_suppressed_snapshot = 0;
static _Atomic bool g_headers_recv_snapshot_streak = false;
static _Atomic uint64_t g_push_getheaders_suppressed_snapshot = 0;
static _Atomic bool g_push_getheaders_snapshot_streak = false;
static _Atomic uint64_t g_push_getheaders_span_suppressed_snapshot = 0;
static _Atomic bool g_push_getheaders_span_snapshot_streak = false;
static _Atomic uint64_t g_push_getheaders_span_alloc_fail = 0;
static _Atomic uint64_t g_getheaders_deferred_snapshot_serving = 0;
static _Atomic bool g_getheaders_deferred_streak = false;

/* Per-peer header advancement tracking (simplified: tracks last peer). */
static _Atomic int g_last_header_tip_height = 0;

static size_t collect_active_tip_successors(struct main_state *ms,
                                            struct uint256 *hashes,
                                            int32_t *heights,
                                            size_t max_collect,
                                            bool *has_data_successor)
{
    struct block_index *parent;
    size_t count = 0;

    if (has_data_successor)
        *has_data_successor = false;
    if (!ms || !hashes || !heights || max_collect == 0)
        return 0;

    parent = active_chain_tip(&ms->chain_active);
    while (parent && parent->phashBlock && count < max_collect) {
        /* O(log) per hop via the shared successor (best-header path
         * above the tip) — the old inline scan here visited the whole
         * block map per collected successor. */
        struct block_index *best_child =
            main_state_best_known_successor(ms, parent);

        if (!best_child || !best_child->phashBlock)
            break;

        if (!(best_child->nStatus & BLOCK_HAVE_DATA)) {
            hashes[count] = *best_child->phashBlock;
            heights[count] = best_child->nHeight;
            count++;
        } else if (has_data_successor) {
            *has_data_successor = true;
        }

        parent = best_child;
    }

    return count;
}

/* Reasons this file names itself, on top of the bind screen's own. Compared
 * with strcmp like every other reason here, never by pointer. */
#define HDR_REASON_NO_INDEX_SOLUTION  "no-index-solution"
#define HDR_REASON_NO_HEADER_BYTES    "no-header-bytes"
#define HDR_REASON_OVERSIZED_SOLUTION "oversized-index-solution"

/* Refusals attributed to "no store on this node holds these header bytes" —
 * a DATA-AVAILABILITY count, not a validity one. See msg_internal.h. */
static _Atomic uint64_t g_serve_refusals_no_bytes = 0;
/* De-storm the serve refusal: see the throttled emit in
 * getheaders_index_header_servable for the measured flood it bounds. Keyed by
 * REASON, not globally — a standing availability storm must never swallow the
 * first sighting of a different refusal (a forged solution, a wrong-hash
 * entry). A changed key always emits, and carries the previous key's
 * suppressed count with it. */
static struct log_throttle g_serve_refuse_throttle = LOG_THROTTLE_INIT;

static uint64_t headers_reason_key(const char *reason)
{
    uint64_t h = 1469598103934665603ULL;  /* FNV-1a 64 */
    for (const char *p = reason; p && *p; p++) {
        h ^= (uint64_t)(unsigned char)*p;
        h *= 1099511628211ULL;
    }
    /* LOG_THROTTLE_KEY_NONE is reserved; nudge the (unreachable) collision. */
    return h == LOG_THROTTLE_KEY_NONE ? 0u : h;
}

uint64_t getheaders_serve_refusals_no_header_bytes(void)
{
    return atomic_load(&g_serve_refusals_no_bytes);
}

/* Build the wire header for `iter` from the IN-MEMORY INDEX ALONE. Returns
 * NULL when the entry carries its own nSolution (the hot path), else a named
 * reason the caller's store ladder may still resolve.
 *
 * This used to read the whole block off disk here and copy only nSolution out
 * of it, then return true — so the caller re-read the identical block in
 * headers_try_disk_header a moment later (TWO full block reads per served
 * header on any flat-hydrated entry), and when nothing could be read it
 * returned true with nSolutionSize=0, which surfaced as the MISLEADING
 * "header-hash-mismatch". Both stores belong to the caller's ladder, which
 * already hash-binds before healing the index; this function only says
 * whether the index by itself is enough.
 *
 * Why the index alone is usually NOT enough: block_index.bin's on-disk row
 * (struct block_index_flat, app/services/src/block_index_loader.c) persists no
 * hashMerkleRoot, no nNonce and no nSolution, so an entry hydrated from it is
 * missing three of a header's seven fields. Below a snapshot-seed floor
 * neither store has the bytes either — measured on a seeded fleet node, the
 * node.db `blocks` table starts at h=3222916 against a 3226485-entry index —
 * so those headers are unservable as a matter of DATA AVAILABILITY, not
 * validity. That is a fleet-wide property of seeded datadirs; naming it
 * honestly is this function's whole job. */
static const char *headers_fill_header_from_index(struct msg_processor *mp,
                                                  struct block_index *iter,
                                                  struct block_header *hdr)
{
    if (!mp || !iter || !hdr)
        return "invalid-args";

    block_header_init(hdr);
    hdr->nVersion = iter->nVersion;
    if (iter->pprev && iter->pprev->phashBlock)
        hdr->hashPrevBlock = *iter->pprev->phashBlock;
    else
        memset(&hdr->hashPrevBlock, 0, sizeof(hdr->hashPrevBlock));
    hdr->hashMerkleRoot = iter->hashMerkleRoot;
    hdr->hashFinalSaplingRoot = iter->hashFinalSaplingRoot;
    hdr->nTime = iter->nTime;
    hdr->nBits = iter->nBits;
    hdr->nNonce = iter->nNonce;

    if (!iter->nSolution || iter->nSolutionSize == 0)
        return HDR_REASON_NO_INDEX_SOLUTION;
    if (iter->nSolutionSize > sizeof(hdr->nSolution)) {
        LOG_WARN("headers",
                 "getheaders: oversized in-memory solution h=%d size=%zu",
                 iter->nHeight, iter->nSolutionSize);
        return HDR_REASON_OVERSIZED_SOLUTION;
    }
    memcpy(hdr->nSolution, iter->nSolution, iter->nSolutionSize);
    hdr->nSolutionSize = iter->nSolutionSize;
    return NULL;
}

/* ── BIND, then VERIFY: the cheap screen ────────────────────────────
 *
 * Everything a candidate header can be rejected for WITHOUT spending an
 * Equihash verification: argument sanity, block version, the solution size
 * this height declares, and the hash bind itself. Cost is one header hash,
 * sub-microsecond. Writes the computed hash to `hash_out` on the paths that
 * reach it (a NULL return always does), so the verify phase below does not
 * recompute it.
 *
 * The bind is also what makes verifying ONCE sufficient. nSolution is part
 * of the serialized header, so `serialize(hdr) == *iter->phashBlock` says
 * these bytes ARE the bytes filed under this entry's hash — strictly
 * stronger than "this solution satisfies Equihash", which says nothing
 * about WHICH header the bytes belong to. Two different byte strings do not
 * share a hash, and every store this file falls back to (flat block file,
 * node.db `blocks` row) is itself required to hash-bind to the same
 * phashBlock. So once ANY source yields bound bytes, every other source
 * either yields the identical bytes or yields nothing, and a PoW verdict
 * over bound bytes is final — re-running it against another store cannot
 * change the answer. That is the whole license for the resolve-then-verify
 * loop in getheaders_index_header_servable.
 *
 * A non-NULL return here can still be retryable: the ordinary cause is a
 * hydrated index entry carrying no nSolution, which the flat-file / node.db
 * fallback repairs. */
static const char *headers_candidate_bind_reason(
    struct msg_processor *mp,
    const struct block_index *iter,
    const struct block_header *hdr,
    struct uint256 *hash_out)
{
    if (!mp || !iter || !hdr || !hash_out)
        return "invalid-args";

    if (hdr->nVersion < MIN_BLOCK_VERSION)
        return "version-too-low";

    if (hdr->nSolutionSize > 0 && iter->nHeight >= 0) {
        unsigned int eh_n = chain_params_equihash_n(mp->params,
                                                    iter->nHeight);
        unsigned int eh_k = chain_params_equihash_k(mp->params,
                                                    iter->nHeight);
        size_t expected = ((size_t)1 << eh_k) *
            (eh_n / (eh_k + 1) + 1) / 8;
        if (hdr->nSolutionSize != expected)
            return "bad-equihash-solution-size";
    }

    block_header_get_hash(hdr, hash_out);
    if (!iter->phashBlock || !uint256_eq(hash_out, iter->phashBlock))
        return "header-hash-mismatch";

    return NULL;
}

/* ── BIND, then VERIFY: the expensive half, run at most once ─────────
 *
 * `hdr` MUST already have passed headers_candidate_bind_reason (so `hash`
 * is its real hash and equals iter->phashBlock). At most one
 * check_equihash_solution call per invocation, counted so the cost is
 * measurable.
 *
 * FULL Equihash on every header this node serves, ONCE PER HEADER PER
 * PROCESS — no status-bit shortcut, and no persisted "already valid" flag.
 * The only thing that can stand in for re-running the check is a receipt
 * this same process minted by actually running it and watching it pass, over
 * byte-identical bytes, under the same build and the same consensus
 * parameters; see the receipt note above. A header this process has not
 * proved is always proved here, and a receipt cannot be created anywhere
 * except the success tail of this function.
 *
 * What must NEVER stand in for the check is a status bit. The hash bind
 * proves these bytes are the bytes filed under this entry's hash; it does
 * NOT prove anyone ever solved Equihash over them, because in this codebase
 * BLOCK_VALID_TREE does not witness an Equihash check. Four persisted-index
 * loaders set it at sampled or zero PoW strength:
 *
 *   app/services/src/block_index_blocks_hydrate.c  — full_check is
 *     (h % BLOCKS_HYDRATE_POW_STRIDE == 0) || h > rom_checkpoint,
 *     i.e. one row in 10,000 below the ROM checkpoint;
 *   app/services/src/block_index_loader.c          — calls
 *     block_row_verify(..., hdr = NULL), which per block_row_verify.h
 *     skips BOTH the hash bind and Equihash, leaving only
 *     CheckProofOfWork on the CLAIMED hash;
 *   config/src/boot_block_file_scan.c              — assigns
 *     BLOCK_VALID_TREE unconditionally;
 *   config/src/boot_header_seed_import.c           — CLAMPS a
 *     peer-supplied artifact down to BLOCK_VALID_TREE, and says in
 *     its own comment that bodies are fully re-validated later.
 *
 * The full-strength header pass does exist
 * (app/jobs/src/validate_headers_validator.c, block_row_verify with
 * check_equihash = true) but it records its verdict in a STAGE CURSOR,
 * not in nStatus, so nStatus cannot proxy for it.
 *
 * Concretely: a hostile block_index.bin / node.db bundle can carry
 * header rows below the ROM checkpoint at heights not divisible by
 * 10,000 whose nSolution is garbage but whose serialized bytes still
 * hash under target — one CheckProofOfWork-passing grind, not a mine.
 * Those rows hash-bind and carry BLOCK_VALID_TREE. Skipping Equihash
 * here would make this node re-broadcast them, which is header spam
 * peers ban for. This check is the last full-PoW gate applied to a
 * persisted row before it leaves the node, so it runs unconditionally.
 *
 * Cost, MEASURED on the dev host rather than estimated: 383-390 us per
 * header for 200,9 and 36.7-36.9 us for 192,7 (192,7 is ~10x CHEAPER,
 * the opposite of the earlier guess), so ~320 s of one thread to serve
 * one peer the whole 3.19M-header chain. What is NOT acceptable is paying
 * that bill more than once for the same header: the caller's
 * resolve-then-verify structure stops that within one lookup, and the
 * receipt stops it across lookups, so the bill is once per header per
 * process however often a peer asks. Recovering the FIRST payment — serving
 * a header this process has never proved without proving it — is a different
 * problem, and it still needs a gate that actually witnesses an Equihash
 * check (the validate_headers stage cursor), never a status bit. See
 * lib/test/src/test_getheaders_serve_fallback.c case 7,
 * lib/test/src/test_getheaders_serve_pow_dedup.c and
 * lib/test/src/test_getheaders_serve_receipt.c. */
static const char *headers_verify_bound_header(struct msg_processor *mp,
                                               const struct block_header *hdr,
                                               const struct uint256 *hash)
{
    if (!mp || !hdr || !hash)
        return "invalid-args";

    /* Re-derive the key from the bytes actually in front of us. The caller
     * has already hash-bound these, so this agrees every time in practice —
     * but a receipt keyed on a hash the CALLER supplied would only be as
     * hash-bound as the caller's discipline, and the whole strength of the
     * receipt rests on the key naming these exact bytes. One SHA256d over
     * ~1.5 KB makes that a property of this function. */
    struct uint256 own_hash;
    block_header_get_hash(hdr, &own_hash);
    if (!uint256_eq(&own_hash, hash))
        return "verify-hash-unbound";

    /* A receipt this process minted over THESE bytes under THIS generation
     * means the three checks below already ran and passed. Anything else —
     * cold slot, evicted slot, different bytes, different build, different
     * consensus parameters — falls through and pays in full. */
    uint64_t generation = headers_verify_generation(mp->params);
    if (headers_verify_receipt_present(&own_hash, generation))
        return NULL;

    atomic_fetch_add(&g_headers_serve_pow_checks, 1);
    if (!check_equihash_solution(hdr, mp->params))
        return "invalid-solution";

    if (!CheckProofOfWork(*hash, hdr->nBits, &mp->params->consensus))
        return "high-hash";

    if (block_header_get_time(hdr) > GetAdjustedTime() + 2 * 60 * 60)
        return "time-too-new";

    /* Full verification SUCCEEDED — the one and only point a receipt is
     * created. No failure path reaches here, so no refusal is ever cached;
     * see the "successes only" note at the table. */
    headers_verify_receipt_record(&own_hash, generation);
    return NULL;
}

/* Which BIND-phase refusals another store can still fix. Deliberately only
 * the two: a wrong solution size or a failed hash bind both mean "these are
 * not this entry's bytes", and a different store may hold the right ones.
 *
 * The VERIFY-phase refusals (invalid-solution, high-hash, time-too-new) are
 * absent on purpose, and dropping them is not a loosening: they are only
 * ever reached over already-BOUND bytes, bound bytes are unique, and so
 * every store that can hash-bind holds byte-identical bytes that fail the
 * same way. Retrying them re-pays a 383-390 us Equihash bill to reach the
 * identical verdict — which is exactly the amplification a peer used to be
 * able to drive three-deep for free. version-too-low is likewise absent
 * (unchanged): a store cannot change a header's version. */
static bool headers_bind_reason_can_retry_store(const char *reason)
{
    return reason &&
        (strcmp(reason, "bad-equihash-solution-size") == 0 ||
         strcmp(reason, "header-hash-mismatch") == 0 ||
         /* The hydrated-entry case: block_index.bin carries no nSolution (nor
          * merkle root, nor nonce), so the index alone cannot bind and BOTH
          * stores are worth asking. This is the ordinary path on every
          * bundle/snapshot-seeded node, not an exception. */
         strcmp(reason, HDR_REASON_NO_INDEX_SOLUTION) == 0 ||
         /* Same condition after attribution renames it: the serve path
          * relabels no-index-solution to no-header-bytes once it has
          * confirmed no store on this node holds them. That rename is the
          * point at which asking a PEER is the only remaining move, so it
          * must stay retryable -- dropping it here silently disarms the
          * bounded header-only repair on exactly the boxes that need it. */
         strcmp(reason, HDR_REASON_NO_HEADER_BYTES) == 0);
}

static bool headers_refresh_index_from_header(struct block_index *iter,
                                              const struct block_header *hdr)
{
    if (!iter || !hdr)
        return false;

    iter->nVersion = hdr->nVersion;
    iter->hashMerkleRoot = hdr->hashMerkleRoot;
    iter->hashFinalSaplingRoot = hdr->hashFinalSaplingRoot;
    iter->nTime = hdr->nTime;
    iter->nBits = hdr->nBits;
    iter->nNonce = hdr->nNonce;

    if (hdr->nSolutionSize > 0) {
        /* Already holding a same-sized buffer: refresh in place. No new
         * allocation, so the budget does not move — and no free(), so a
         * concurrent reader of this entry cannot see a dangling pointer. */
        if (iter->nSolution && iter->nSolutionSize == hdr->nSolutionSize) {
            memcpy(iter->nSolution, hdr->nSolution, hdr->nSolutionSize);
            return true;
        }

        /* Reserve first, roll back on refusal — two serve threads must not
         * both read "under budget" and both allocate. */
        size_t before = atomic_fetch_add(&g_headers_solution_cache_bytes,
                                         hdr->nSolutionSize);
        if (before + hdr->nSolutionSize > HEADERS_SOLUTION_CACHE_MAX_BYTES) {
            atomic_fetch_sub(&g_headers_solution_cache_bytes,
                             hdr->nSolutionSize);
            /* Not an error and not a serve refusal: the caller already
             * holds the full header and serves it. Log once so the
             * operator can tell "cold cache" from "capped cache". */
            if (!atomic_exchange(&g_headers_solution_cache_full_logged, true))
                LOG_WARN("headers",
                         "getheaders: serve-path solution cache reached its "
                         "%zu-byte budget at h=%d — headers are still served "
                         "in full, they are just re-read from the store "
                         "instead of being kept in RAM",
                         (size_t)HEADERS_SOLUTION_CACHE_MAX_BYTES,
                         iter->nHeight);
            return false;
        }

        uint8_t *sol = zcl_malloc(hdr->nSolutionSize,
                                  "headers_refresh_solution");
        if (!sol) {
            atomic_fetch_sub(&g_headers_solution_cache_bytes,
                             hdr->nSolutionSize);
            LOG_WARN("headers",
                     "getheaders: solution refresh alloc failed h=%d size=%zu",
                     iter->nHeight, hdr->nSolutionSize);
            return false;
        }
        memcpy(sol, hdr->nSolution, hdr->nSolutionSize);
        free(iter->nSolution);
        iter->nSolution = sol;
        iter->nSolutionSize = hdr->nSolutionSize;
        return true;
    }
    return false;
}

/* A header-only repair response is never trusted because it came from a peer.
 * Re-run the exact serve-path bind + full Equihash/PoW/time gate, then cache it
 * under the existing 64 MiB ceiling. The repair flight completes only after
 * the bytes are actually resident; allocation/budget refusal stays armed for
 * a later bounded retry. */
bool getheaders_cache_repair_candidate(struct msg_processor *mp,
                                       struct block_index *iter,
                                       const struct block_header *hdr)
{
    if (!header_serve_repair_wants(iter))
        return false;

    struct uint256 hash;
    const char *reason =
        headers_candidate_bind_reason(mp, iter, hdr, &hash);
    if (!reason)
        reason = headers_verify_bound_header(mp, hdr, &hash);
    if (reason) {
        LOG_WARN("headers",
                 "getheaders: header-only repair candidate refused h=%d "
                 "reason=%s",
                 iter ? iter->nHeight : -1, reason);
        return false;
    }
    if (!headers_refresh_index_from_header(iter, hdr))
        return false;

    header_serve_repair_note_cached(iter);
    return true;
}

static bool headers_try_disk_header(struct msg_processor *mp,
                                    struct block_index *iter,
                                    struct block_header *hdr_out)
{
    if (!mp || !iter || !hdr_out)
        return false;

    struct block blk;
    block_init(&blk);
    if (!read_block_from_disk_index(&blk, iter, mp->datadir)) {
        block_free(&blk);
        return false;
    }

    struct uint256 disk_hash;
    block_header_get_hash(&blk.header, &disk_hash);
    bool same_hash = iter->phashBlock &&
        uint256_eq(&disk_hash, iter->phashBlock);
    if (!same_hash) {
        char disk_hex[65], index_hex[65];
        uint256_get_hex(&disk_hash, disk_hex);
        if (iter->phashBlock)
            uint256_get_hex(iter->phashBlock, index_hex);
        else
            strcpy(index_hex, "(missing)");
        LOG_WARN("headers",
                 "getheaders: disk header hash mismatch h=%d index=%s disk=%s",
                 iter->nHeight, index_hex, disk_hex);
        block_free(&blk);
        return false;
    }

    *hdr_out = blk.header;
    headers_refresh_index_from_header(iter, hdr_out);
    block_free(&blk);
    return true;
}

static bool headers_try_node_db_header(struct block_index *iter,
                                       struct block_header *hdr_out)
{
    if (!iter || !hdr_out || !iter->phashBlock)
        return false;

    /* The runtime read port tries the existing durable full-header
     * authorities (node.db, the reducer repair table, then the event
     * projection). Each source hash-binds its bytes to phashBlock before a
     * true return. The port keeps lib/net below app/jobs and config while
     * allowing snapshot-seeded nodes whose old bodies are absent to serve
     * every locally retained solution. */
    /* raw-return-ok: the caller (getheaders_index_header_servable) logs the
     * named serve refusal; this guard only selects the fallback source. */
    if (!node_db_runtime_load_header_by_hash_height(
            iter->nHeight, iter->phashBlock->data, hdr_out))
        return false;

    /* Heal the in-memory entry so later serves of this header take the
     * hot in-memory path instead of re-reading node.db. */
    headers_refresh_index_from_header(iter, hdr_out);
    return true;
}

/* See net/msg_internal.h. */
bool getheaders_index_header_servable(struct msg_processor *mp,
                                      struct block_index *iter,
                                      struct block_header *hdr_out)
{
    struct block_header hdr;
    const char *fill_reason = headers_fill_header_from_index(mp, iter, &hdr);

    /* RESOLVE first, then VERIFY exactly once.
     *
     * Pre-fix this walked the same three sources — in-memory index, flat
     * block file, node.db `blocks` row — but handed each candidate to a
     * screen that ran FULL Equihash *before* the caller knew whether the
     * bytes were even the right bytes. So one lookup could spend three
     * Equihash verifications (~1.2 ms of a core at 200,9), and a peer that
     * drove the fallback path paid nothing to make this node pay 3x. Its
     * own honesty was the amplifier.
     *
     * Now the loop settles WHICH bytes are authoritative using only the
     * cheap bind screen, and the expensive check runs once, on the winner.
     * Which headers are servable does not change: bound bytes are unique
     * (see headers_candidate_bind_reason), so the verdict the old code
     * reached on its third attempt is the verdict this reaches on its
     * first. */
    struct uint256 hash;
    uint256_set_null(&hash);
    /* Only screen what the index actually produced. When the index could not
     * fill the header at all, its own reason stands — running the bind screen
     * over a header we KNOW is incomplete would relabel a data-availability
     * miss as "header-hash-mismatch", which is precisely the mislabel that
     * made two separate investigations read a seeded datadir as corrupt. */
    const char *reason = fill_reason ? fill_reason
        : headers_candidate_bind_reason(mp, iter, &hdr, &hash);

    if (reason && headers_bind_reason_can_retry_store(reason)) {
        struct block_header disk_hdr;
        if (headers_try_disk_header(mp, iter, &disk_hdr)) {
            const char *disk_reason =
                headers_candidate_bind_reason(mp, iter, &disk_hdr, &hash);
            if (!disk_reason) {
                hdr = disk_hdr;
                reason = NULL;
            } else {
                reason = disk_reason;
            }
        }
    }
    if (reason && headers_bind_reason_can_retry_store(reason)) {
        struct block_header ndb_hdr;
        if (headers_try_node_db_header(iter, &ndb_hdr)) {
            const char *ndb_reason =
                headers_candidate_bind_reason(mp, iter, &ndb_hdr, &hash);
            if (!ndb_reason) {
                hdr = ndb_hdr;
                reason = NULL;
            } else {
                reason = ndb_reason;
            }
        }
    }

    /* The one full-PoW pass, over the resolved bytes only. */
    if (!reason)
        reason = headers_verify_bound_header(mp, &hdr, &hash);

    if (reason) {
        /* Name the CONCLUSION, not the first miss: the index could not fill
         * the header AND neither store had the bytes. On a seeded datadir
         * every height below the seed floor is in this state permanently, so
         * this is a standing coverage fact, not a per-request anomaly. */
        if (strcmp(reason, HDR_REASON_NO_INDEX_SOLUTION) == 0) {
            reason = HDR_REASON_NO_HEADER_BYTES;
            atomic_fetch_add(&g_serve_refusals_no_bytes, 1);
        }
        char hex[65] = {0};
        if (iter && iter->phashBlock)
            uint256_get_hex(iter->phashBlock, hex);
        /* THROTTLED per reason. One getheaders whose locator lands in an
         * unservable span costs 64 of these (the successor-walk guard), and a
         * peer re-asks forever: node1 logged 100,230 identical refusals in
         * 400k lines, ~25% of its whole log. The keep-alive line still carries
         * a live sample (hash, height, reason) plus the suppressed count, so
         * the failure stays visible — it just stops being the log. */
        uint64_t reps = 0;
        if (log_throttle_should_emit(&g_serve_refuse_throttle,
                                     headers_reason_key(reason),
                                     platform_time_wall_unix(), 60, &reps))
            LOG_WARN("headers",
                     "getheaders: refusing to serve header %s h=%d reason=%s "
                     "(%llu suppressed refusals since last line)",
                     hex[0] ? hex : "(unknown)", iter ? iter->nHeight : -1,
                     reason, (unsigned long long)reps);
        if (iter && iter->phashBlock &&
            headers_bind_reason_can_retry_store(reason))
            header_serve_repair_arm(mp ? mp->main_state : NULL, iter);
        /* A serve refusal is NOT a validity verdict: every reason here can
         * arise from data UNAVAILABILITY (a hydrated index entry with no
         * nSolution and no reachable store yields "invalid-solution" for a
         * perfectly valid block), so marking BLOCK_FAILED_VALID from this
         * path poisons good index entries — and the persisted-FAILED
         * reconcile then keeps them failed across reboots. Validity
         * verdicts belong to the accept/validate paths; the serve path
         * only names why it cannot serve. */
        return false;
    }

    if (hdr_out)
        *hdr_out = hdr;
    if (header_serve_repair_wants(iter) && iter->nSolution &&
        iter->nSolutionSize == hdr.nSolutionSize)
        header_serve_repair_note_cached(iter);
    return true;
}

/* See net/msg_internal.h. */
struct block_index *getheaders_next_servable_successor(
    struct msg_processor *mp,
    struct block_index *parent,
    struct block_header *hdr_out)
{
    if (!mp || !parent)
        return NULL;

    /* Walk FORWARD, never re-query the same parent: each iteration moves
     * the cursor to the successor of the last unservable entry, so an
     * unservable span (e.g. hydrated entries below the body floor whose
     * node.db rows are also gone) is skipped up to the guard bound and
     * the walk always makes progress toward the tip. Pre-fix the loop
     * re-ran main_state_best_known_successor(parent) with an unchanged
     * `parent`, so the same unservable entry came back every iteration
     * and the serve ended with a 0-header reply. */
    struct block_index *cursor = parent;
    for (int guard = 0; guard < 64; guard++) {
        struct block_index *next =
            main_state_best_known_successor(mp->main_state, cursor);
        if (!next)
            return NULL;
        /* Keep the header the check just built. Discarding it (the old
         * `NULL` here) forced the serve loop to prove the very same entry a
         * second time, so every header on the wire cost two full Equihash
         * verifications instead of one. */
        struct block_header hdr;
        block_header_init(&hdr);
        if (getheaders_index_header_servable(mp, next, &hdr)) {
            if (hdr_out)
                *hdr_out = hdr;
            return next;
        }
        cursor = next;
    }
    LOG_WARN("headers",
             "getheaders: successor guard exhausted at parent h=%d",
             parent->nHeight);
    return NULL;
}

static struct block_index *headers_start_from_locator(
    struct main_state *ms,
    struct active_chain *chain,
    const struct block_locator *locator,
    const struct uint256 *hash_stop,
    const struct chain_params *params)
{
    struct block_index *pindex = NULL;

    if (!ms || !chain || !params)
        return NULL;

    if (locator && locator->num_hashes == 0 && hash_stop) {
        pindex = block_map_find(&ms->map_block_index, hash_stop);
    } else if (locator) {
        for (size_t i = 0; i < locator->num_hashes; i++) {
            struct block_index *found = block_map_find(
                &ms->map_block_index, &locator->vhave[i]);
            if (!found || !found->phashBlock)
                continue;

            struct block_index *active = active_chain_at(chain, found->nHeight);
            if ((active && active->phashBlock && uint256_eq(active->phashBlock, found->phashBlock)) ||
                uint256_eq(found->phashBlock, &params->consensus.hashGenesisBlock)) {
                pindex = found;
                break;
            }
        }
    }

    if (pindex)
        return main_state_best_known_successor(ms, pindex);

    pindex = block_map_find(&ms->map_block_index,
                            &params->consensus.hashGenesisBlock);
    if (pindex)
        return pindex;

    return active_chain_at(chain, 0);
}

void msg_headers_get_stats(struct msg_headers_stats *out)
{
    if (!out) return;
    out->batches_received = atomic_load(&g_headers_batches_received);
    out->total_accepted   = atomic_load(&g_headers_total_accepted);
    out->total_rejected   = atomic_load(&g_headers_total_rejected);
    out->newly_added      = atomic_load(&g_headers_newly_added);
    out->already_known    = atomic_load(&g_headers_already_known);
    out->getheaders_suppressed_no_hash =
        atomic_load(&g_getheaders_suppressed_no_hash);
    out->getheaders_suppressed_snapshot =
        atomic_load(&g_getheaders_suppressed_snapshot);
    out->headers_recv_suppressed_snapshot =
        atomic_load(&g_headers_recv_suppressed_snapshot);
    out->push_getheaders_suppressed_snapshot =
        atomic_load(&g_push_getheaders_suppressed_snapshot);
    out->push_getheaders_span_suppressed_snapshot =
        atomic_load(&g_push_getheaders_span_suppressed_snapshot);
    out->push_getheaders_span_alloc_fail =
        atomic_load(&g_push_getheaders_span_alloc_fail);
    out->getheaders_deferred_snapshot_serving =
        atomic_load(&g_getheaders_deferred_snapshot_serving);
    out->headers_served_total = atomic_load(&g_headers_served_total);
    out->getheaders_served_requests =
        atomic_load(&g_getheaders_served_requests);
}

bool process_getheaders(struct msg_processor *mp, struct p2p_node *node,
                        struct byte_stream *s)
{
    if (node->state == PEER_SNAPSHOT_SERVING || node->swarm_manifest_sent) {
        uint64_t n =
            atomic_fetch_add(&g_getheaders_deferred_snapshot_serving, 1) + 1;
        if (getheaders_suppress_rising_edge(&g_getheaders_deferred_streak))
            LOG_WARN("headers",
                     "process_getheaders: deferring getheaders from %s — "
                     "peer snapshot serving in progress "
                     "(deferred_snapshot_serving=%llu)",
                     node->addr_name, (unsigned long long)n);
        return true;
    }
    atomic_store(&g_getheaders_deferred_streak, false);

    struct block_locator locator;
    block_locator_init(&locator);
    if (!block_locator_deserialize(&locator, s)) {
        block_locator_free(&locator);
        LOG_FAIL("net", "failed to deserialize getheaders locator from %s",
                 node->addr_name);
    }

    struct uint256 hash_stop;
    if (!stream_read(s, hash_stop.data, 32)) {
        block_locator_free(&locator);
        LOG_FAIL("net", "failed to read getheaders hash_stop from %s",
                 node->addr_name);
    }

    struct active_chain *chain = &mp->main_state->chain_active;
    struct block_index *iter = NULL;

    iter = headers_start_from_locator(mp->main_state, chain, &locator,
                                      &hash_stop, mp->params);
    block_locator_free(&locator);

    /* Bound the reply by header count AND by bytes.
     *
     * Count: legacy ZClassic peers (MagicBean / pre-ZCL23) cap inbound headers
     * at MAX_HEADERS_RESULTS=160 and ban senders that exceed it (Misbehaving
     * +20 → disconnect). Serving a legacy peer a larger batch gets us banned
     * mid-handshake (zclassicd's debug.log: "ProcessMessages(headers, 1088003
     * bytes) FAILED" then "Misbehaving: 127.0.0.1:<port> (0 -> 20)"). ZCL23
     * peers carry NODE_ZCL23 and accept up to 2000.
     *
     * Bytes: ~2000 Equihash headers (~1.5 KB each with the 1344-byte solution)
     * serialize to ~2.9 MB, over the 2 MiB MAX_PROTOCOL_MESSAGE_LENGTH wire cap
     * — the receiver drops the whole oversized reply and never learns our tip.
     * getheaders_try_append_header() stops the batch at the byte budget, so we
     * emit exactly the count that fits under the cap. */
    const int max_headers = peer_supports_fast_sync(node->services) ? 2000 : 160;
    struct byte_stream body;
    stream_init(&body, 65536);
    int count = 0;

    /* Each header on the wire is verified EXACTLY ONCE.
     *
     * The successor walk hands back the header bytes it already proved, so
     * the loop appends what it was given instead of re-proving it. Pre-fix
     * the walk proved a candidate and then the loop head proved the same
     * entry again, doubling the Equihash bill for every header served — on
     * top of the up-to-3x inside the servability check itself.
     *
     * Only the locator-selected first entry can arrive unproven, so that
     * one case is handled once, ahead of the loop, rather than with a
     * re-check on every iteration. */
    struct block_header hdr;
    block_header_init(&hdr);
    struct block_index *it = iter;
    if (it && !getheaders_index_header_servable(mp, it, &hdr)) {
        struct block_index *parent = it->pprev;
        it = parent ? getheaders_next_servable_successor(mp, parent, &hdr)
                    : NULL;
    }

    while (it && count < max_headers) {
        if (!getheaders_try_append_header(&body, &hdr))
            break;  /* next header would overflow the wire cap */
        count++;
        if (!uint256_is_null(&hash_stop) && it->phashBlock &&
            uint256_eq(it->phashBlock, &hash_stop))
            break;
        it = getheaders_next_servable_successor(mp, it, &hdr);
    }

    struct byte_stream headers;
    stream_init(&headers, body.size + 16);
    stream_write_compact_size(&headers, (uint64_t)count);
    stream_write(&headers, body.data, body.size);
    stream_free(&body);

    p2p_node_begin_message(node, "headers", mp->params->pchMessageStart);
    p2p_node_write_message_data(node, headers.data, headers.size);
    p2p_node_end_message(node);
    stream_free(&headers);

    /* Serve-side accounting: one answered request, and the headers it
     * carried (a 0-header reply still counts as a request — that asymmetry
     * is the point, see net/msgprocessor.h). */
    atomic_fetch_add(&g_getheaders_served_requests, 1);
    atomic_fetch_add(&g_headers_served_total, (uint64_t)count);
    return true;
}

/* See net/msg_internal.h. */
bool getheaders_try_append_header(struct byte_stream *body,
                                  const struct block_header *hdr)
{
    size_t before = body->size;
    block_header_serialize(hdr, body);
    stream_write_compact_size(body, 0);  /* per-header tx count = 0 */
    /* Reserve headroom for the compact_size(count) prefix the caller writes
     * ahead of `body` (≤3 bytes for count ≤ 2000; 16 is generous). */
    if (body->error ||
        body->size + 16 > (size_t)MAX_PROTOCOL_MESSAGE_LENGTH) {
        body->size = before;
        return false;
    }
    return true;
}

bool process_headers(struct msg_processor *mp, struct p2p_node *node,
                     struct byte_stream *s)
{
    /* Defer header processing during any snapshot sync state — header parsing
     * and block index updates consume CPU and starve P2P reads.
     * During NEGOTIATING: headers trigger getblocks which compete. This is
     * the receive-side twin of the push_getheaders_from() snapshot guard
     * above: a real, intentional pause, but never a silent one — count it
     * and name it so an exchange that latches active announces itself
     * instead of the inbound headers stream just going quiet. */
    if (msg_processor_snapshot_active(mp)) {
        uint64_t n =
            atomic_fetch_add(&g_headers_recv_suppressed_snapshot, 1) + 1;
        if (getheaders_suppress_rising_edge(&g_headers_recv_snapshot_streak))
            LOG_WARN("headers",
                     "process_headers: inbound headers from %s DROPPED — "
                     "active snapshot sync (suppressed_recv_snapshot=%llu)",
                     node->addr_name, (unsigned long long)n);
        return true;
    }
    atomic_store(&g_headers_recv_snapshot_streak, false);

    uint64_t count;
    if (!stream_read_compact_size(s, &count))
        LOG_FAIL("net", "failed to read headers count from %s",
                 node->addr_name);

    if (msg_count_exceeds("net", "headers", count, 2000, node->addr_name)) {
        event_emitf(EV_PEER_MISBEHAVE, (uint32_t)node->id,
                    "headers count %llu exceeds 2000 from %s",
                    (unsigned long long)count, node->addr_name);
        peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_FLOOD,
                            "too many headers");
        (void)p2p_node_request_disconnect(
            node, P2P_DISCONNECT_RESOURCE_LIMIT,
            P2P_DISCONNECT_SOURCE_RESOURCE_GOVERNOR,
            node->endpoint_generation);
        return false;
    }

    struct uint256 last_hash;
    uint256_set_null(&last_hash);
    struct block_index *pindex_last = NULL;
    struct sync_header_processing_plan header_plan = {0};
    size_t accepted = 0;
    size_t newly_added = 0;  /* headers that were NOT already in block index */
    bool any_bad_prevblk = false;  /* any header rejected as unconnectable */
    struct uint256 seq_hashes[512];
    int32_t seq_heights[512];
    size_t seq_count = 0;
    int pre_tip_height = active_chain_height(&mp->main_state->chain_active);
    struct block_index *sequence_prev =
        active_chain_tip(&mp->main_state->chain_active);

    /* Address-group key of the peer offering these headers — the unit of
     * distinct-source counting for the eclipse-resistant switch corroboration
     * policy (net/header_corroboration.h). Onion and clearnet peers carry
     * distinct keys; a whole /16 (clearnet) or one onion group counts once. */
    unsigned char peer_group[NET_ADDR_GROUP_MAX];
    size_t peer_group_len = net_addr_get_group(&node->addr.svc.addr,
                                               peer_group, sizeof(peer_group));

    for (uint64_t i = 0; i < count; i++) {
        struct block_header hdr;
        block_header_init(&hdr);
        if (!block_header_deserialize(&hdr, s)) {
            event_emitf(EV_HEADERS_REJECTED, (uint32_t)node->id,
                        "malformed header[%llu] from %s",
                        (unsigned long long)i, node->addr_name);
            peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_FLOOD,
                                "malformed header");
            LOG_FAIL("net", "malformed header[%llu] from %s",
                     (unsigned long long)i, node->addr_name);
        }

        uint64_t dummy;
        if (!stream_read_compact_size(s, &dummy)) {
            peer_scoring_record(mp->net_mgr, node, PEER_OFFENCE_FLOOD,
                                "truncated header tx count");
            LOG_FAIL("net", "truncated header tx count at header[%llu] from %s",
                     (unsigned long long)i, node->addr_name);
        }

        /* Check if header already in index BEFORE accept_block_header */
        struct uint256 hdr_hash;
        block_header_get_hash(&hdr, &hdr_hash);
        bool was_known = (block_map_find(&mp->main_state->map_block_index,
                                          &hdr_hash) != NULL);

        /* Checkpoint-header-solution cure: offer every received header (with its
         * on-wire Equihash solution) to the checkpoint fetch. Cheap (one relaxed
         * atomic) when no fetch is armed; on a hash-pin match it captures the
         * bytes for the app-layer condition to frozen-verify + persist. The
         * header is captured even when `was_known` (the imported checkpoint
         * header IS already in the index — only its solution is missing). */
        checkpoint_header_fetch_offer(&hdr, &hdr_hash);

        struct validation_state state;
        validation_state_init(&state);
        struct block_index *pindex = NULL;
        if (accept_block_header(&hdr, &state, mp->main_state,
                                mp->params, &pindex)) {
            accepted++;
            if (!was_known)
                newly_added++;
            /* A serve miss may have requested this exact bounded header-only
             * span. Known headers take a cheap path in accept_block_header,
             * so independently full-verify before caching their solutions. */
            (void)getheaders_cache_repair_candidate(mp, pindex, &hdr);
            /* Record that THIS peer's address group served this header, so a
             * later best-header SWITCH to this branch can be corroborated
             * against a second distinct group before we adopt it. Records the
             * header hash regardless of whether it was new — a second peer
             * re-serving a known header is exactly the corroboration signal. */
            if (peer_group_len > 0)
                header_corroboration_note(&hdr_hash, peer_group, peer_group_len);
            if (pindex && sequence_prev && sequence_prev->phashBlock &&
                uint256_eq(&hdr.hashPrevBlock, sequence_prev->phashBlock)) {
                if (pindex->pprev != sequence_prev ||
                    pindex->nHeight != sequence_prev->nHeight + 1) {
                    pindex->pprev = sequence_prev;
                    pindex->nHeight = sequence_prev->nHeight + 1;
                    block_index_build_skip(pindex);
                    struct arith_uint256 proof = GetBlockProof(pindex);
                    arith_uint256_add(&pindex->nChainWork,
                                      &sequence_prev->nChainWork, &proof);
                }
                sequence_prev = pindex;
            }
            pindex_last = pindex;
            if (pindex && pindex->phashBlock)
                last_hash = *pindex->phashBlock;
            if (pindex && pindex->phashBlock &&
                pindex->nHeight > pre_tip_height &&
                pindex->nHeight <= pre_tip_height + 512 &&
                !(pindex->nStatus & BLOCK_HAVE_DATA) &&
                !(pindex->nStatus & BLOCK_FAILED_MASK) &&
                seq_count < 512) {
                seq_hashes[seq_count] = *pindex->phashBlock;
                seq_heights[seq_count] = pindex->nHeight;
                seq_count++;
            }
        } else {
            /* Track the unconnectable-rejection signal: a batch rejected
             * with bad-prevblk usually means the peer is AHEAD of us (we
             * missed the intermediate header), not that it is garbage —
             * the all-rejected recovery probe below keys on this. */
            if (strcmp(state.reject_reason, "bad-prevblk") == 0)
                any_bad_prevblk = true;
            if (i < 3) {
                char hex[65], prevhex[65];
                struct uint256 hh;
                block_header_get_hash(&hdr, &hh);
                uint256_get_hex(&hh, hex);
                uint256_get_hex(&hdr.hashPrevBlock, prevhex);
                printf("HEADER REJECT[%llu]: hash=%s prev=%s reason=%s\n",
                       (unsigned long long)i, hex, prevhex,
                       state.reject_reason[0] ? state.reject_reason
                                              : "unknown");
                event_emitf(EV_HEADERS_REJECTED, (uint32_t)node->id,
                            "header[%llu] %s reason=%s",
                            (unsigned long long)i, hex,
                            state.reject_reason[0] ? state.reject_reason
                                                   : "unknown");
            }
        }

        /* Detective A2 — score the peer for an objectively-forged header page.
         * accept_block_header admits header-first and defers the PoW/Equihash
         * verdict to the validate_headers stage, so it returns true even for a
         * bad-solution / high-hash header; check_block_header still computes the
         * DoS grade into `state`. A dos>0 here is an objective PoW/Equihash
         * failure (invalid-solution=100, high-hash=50) — penalize INVALID_HEADER
         * so a peer forging the header range (e.g. while a stale-header repair
         * is fetching the canonical bytes) is scored and eventually
         * disconnected, and the forged page never fools the repair. Gated on
         * dos>0 so orphans / failed-parent / obsolete-version (dos 0) — all
         * normal during sync — are never penalized. Trusted/localhost peers are
         * exempted inside peer_misbehaving. Mirrors msg_blocks.c grading. */
        int hdr_dos = 0;
        if (validation_state_get_dos(&state, &hdr_dos) && hdr_dos > 0) {
            peer_scoring_record(mp->net_mgr, node,
                                PEER_OFFENCE_INVALID_HEADER,
                                state.reject_reason[0] ? state.reject_reason
                                                       : "invalid header");
        }
    }

    /* Update diagnostic counters */
    atomic_fetch_add(&g_headers_batches_received, 1);
    atomic_fetch_add(&g_headers_total_accepted, accepted);
    atomic_fetch_add(&g_headers_total_rejected, count - accepted);
    atomic_fetch_add(&g_headers_newly_added, newly_added);
    atomic_fetch_add(&g_headers_already_known, accepted - newly_added);

    /* Per-peer usefulness credit (P1). MUST pass newly_added, NEVER
     * accepted: `accepted` also counts headers we already had in the
     * index (was_known above), so crediting it would let a withholding
     * peer replay known headers forever to refresh
     * last_useful_headers_time (defeating the stale-peer disconnect)
     * and inflate total_headers_delivered (deflecting worst-peer
     * eviction onto honest peers). Only new-to-index headers count. */
    syncsvc_note_headers_received(node, newly_added);

    /* Arm/disarm the recovery-probe pending flag: an all-rejected
     * bad-prevblk batch arms it (so the periodic per-peer tick re-probes
     * even after the announcement burst ends); any batch that accepts a
     * header disarms it — the conversation is connected again. */
    syncsvc_note_header_batch_outcome(node, accepted, any_bad_prevblk);

    {
        struct block_index *tip = active_chain_tip(&mp->main_state->chain_active);
        int our_height = tip ? tip->nHeight : 0;
        struct block_index *bi = block_map_find(
            &mp->main_state->map_block_index, &last_hash);
        size_t max_collect = 512;
        struct uint256 *hashes = zcl_malloc(max_collect * sizeof(struct uint256), "blk_req_hashes");
        int32_t *heights = zcl_malloc(max_collect * sizeof(int32_t), "blk_req_heights");

        if (!hashes || !heights) {
            LOG_WARN("sync", "malloc failed for block request arrays "
                     "(%zu entries)", max_collect);
            free(hashes); free(heights);
            hashes = NULL; heights = NULL;
        }

        syncsvc_plan_header_processing(&header_plan, accepted, count,
                                       pindex_last, sync_get_state(),
                                       bi, tip, our_height,
                                       hashes, heights, max_collect);
        if (seq_count > 0 && hashes && heights) {
            memcpy(hashes, seq_hashes, seq_count * sizeof(struct uint256));
            memcpy(heights, seq_heights, seq_count * sizeof(int32_t));
            header_plan.should_queue_needed_blocks = true;
            header_plan.queue_count = seq_count;
            header_plan.should_activate_chain = false;
            header_plan.download.needed_blocks.count = seq_count;
            header_plan.download.needed_blocks.chains_from_tip = true;
        }
        if (our_height > 1000000 && header_plan.should_scan_block_files) {
            printf("headers: skip inline block-file scan at live height h=%d\n",
                   our_height);
            header_plan.should_scan_block_files = false;
        }

        if (header_plan.batch.should_warn_all_rejected) {
            /* All headers rejected — this stalls sync. Log prominently. */
            event_emitf(EV_HEADERS_REJECTED, (uint32_t)node->id,
                        "all %llu headers rejected", (unsigned long long)count);
            printf("WARNING: Peer %s: all %llu headers rejected — sync stalled!\n",
                   node->addr_name, (unsigned long long)count);
        }

        /* All-rejected recovery probe (the missed-intermediate-header stall):
         * a direct tip announcement (BIP 130) whose prev we do not have is
         * all-rejected with bad-prevblk, and should_request_more_headers
         * requires accepted>0, so without this probe no getheaders follow-up
         * is ever scheduled and — once the frontier-parity gate disables the
         * stale-peer disconnect — the node forgets the announced height and
         * sits below the network tip forever. Re-probe with getheaders from
         * our best header; the exponential locator lets the peer serve the
         * missing intermediate headers. Keyed on the bad-prevblk signal and
         * rate-limited per peer so a garbage peer cannot make us ping-pong. */
        if (header_plan.batch.should_probe_after_reject && any_bad_prevblk) {
            int64_t now_s = (int64_t)platform_time_wall_time_t();
            int64_t last_probe = atomic_load_explicit(
                &node->last_reject_probe_time, memory_order_relaxed);
            if (syncsvc_should_probe_after_reject(now_s, last_probe)) {
                atomic_store_explicit(&node->last_reject_probe_time, now_s,
                                      memory_order_relaxed);
                int best_h = mp->main_state->pindex_best_header
                    ? mp->main_state->pindex_best_header->nHeight : -1;
                printf("Peer %s: all-rejected batch (bad-prevblk) — probing "
                       "with getheaders from our best header h=%d\n",
                       node->addr_name, best_h);
                push_getheaders_from(mp, node,
                                     mp->main_state->pindex_best_header);
            }
        }

        if (header_plan.batch.should_emit_received) {
            event_emitf(EV_HEADERS_RECEIVED, (uint32_t)node->id,
                        "accepted=%zu total=%llu tip=%d",
                        accepted, (unsigned long long)count,
                        pindex_last ? pindex_last->nHeight : -1);

            if (syncsvc_should_log_accepted_headers(node, pindex_last)) {
                int chain_h = active_chain_height(&mp->main_state->chain_active);
                printf("Peer %s: accepted %zu/%llu headers "
                       "(header tip=%d, chain tip=%d, peer=%d)\n",
                       node->addr_name, accepted, (unsigned long long)count,
                       pindex_last ? pindex_last->nHeight : -1,
                       chain_h, node->starting_height);
                /* Stall detection: if we accepted headers but the tip
                 * didn't advance past chain height, something is wrong
                 * with the block index heights. Log loudly. */
                if (pindex_last && accepted > 0 &&
                    pindex_last->nHeight < chain_h &&
                    node->starting_height > chain_h + 100) {
                    LOG_WARN("sync",
                        "STALL DETECTED: accepted %zu headers but "
                        "header tip=%d < chain tip=%d (peer at %d). "
                        "Block index heights may be corrupted.",
                        accepted, pindex_last->nHeight, chain_h,
                        node->starting_height);
                }
            }
        }

        /* The CSR owns both ranking and publication. Always submit the batch
         * candidate; a valid non-winning header is an idempotent no-op.
         *
         * Eclipse resistance (net/header_corroboration.h): before submitting a
         * candidate that would SWITCH us onto a different branch (a reorg of
         * the header tree deeper than MIN_SWITCH_DEPTH, above the compiled
         * checkpoint), require a second distinct address group to have served
         * that branch. An un-corroborated deep switch is HELD — we simply do
         * not submit it (the peer is NOT banned, the candidate stays in the
         * header tree, and plain extension of the current chain is unaffected).
         * The chain_reorg_uncorroborated condition surfaces the transient
         * blocker; the hold auto-clears when a second group corroborates or the
         * branch is abandoned. */
        if (pindex_last) {
            int ckpt_last =
                checkpoints_last_height(&mp->params->checkpointData);
            enum header_corroboration_gate g =
                header_corroboration_gate_switch(
                    mp->main_state->pindex_best_header, pindex_last,
                    ckpt_last, peer_group, peer_group_len, node->addr_name);
            if (g == HEADER_CORROBORATION_HOLD) {
                event_emitf(EV_HEADERS_REJECTED, (uint32_t)node->id,
                            "held un-corroborated header switch to h=%d from %s",
                            pindex_last->nHeight, node->addr_name);
            } else if (!msg_processor_commit_header_tip(mp, pindex_last)) {
                LOG_WARN("sync",
                         "best-header promotion rejected h=%d",
                         pindex_last->nHeight);
            }
        }

        /* An accepted header is chain-identity evidence regardless of whether
         * its sender advertises our optional fast-sync service bit. Standard
         * ZClassic peers speak headers too; excluding them made the off-host
         * agreement ledger see heights from the whole network but hashes from
         * only zclassic23 peers. The two-distinct-host judge remains the
         * authority that decides whether those per-peer votes corroborate. */
        if (pindex_last && pindex_last->phashBlock) {
            char peer_hash_hex[65];
            uint256_get_hex(pindex_last->phashBlock, peer_hash_hex);
            msg_processor_record_peer_header_vote(mp, (uint32_t)node->id,
                                                  pindex_last->nHeight,
                                                  peer_hash_hex);
        }

        /* Clear snapshot anchor once headers extend past the configured
         * immutable/finality window. The anchor blocks reducer activation.
         * Once the header chain has enough depth for the snapshot policy that
         * accepted it, clear it so blocks can be connected. Set chain tip to
         * the anchor so the reducer starts from the right UTXO state. */
        {
            struct block_index *anc = msg_processor_snapshot_anchor(mp);
            if (syncsvc_should_release_snapshot_anchor(anc, pindex_last)) {
                /* Verify the header chain reaches the anchor via pprev */
                struct block_index *walk = pindex_last;
                while (walk && walk->nHeight > anc->nHeight)
                    walk = walk->pprev;
                if (walk == anc) {
                    printf("Anchor cleared: headers extend %d blocks past "
                           "anchor h=%d — enabling block connection\n",
                           pindex_last->nHeight - anc->nHeight,
                           anc->nHeight);
                    /* Re-anchor active_chain at the snapshot anchor through
                     * the boot-owned chain-state boundary so
                     * block_map/coins_tip/header agree. In production this
                     * is typically a no-op move (active_chain is already at
                     * `anc`), but routing it through the single authority
                     * gives the transition a structured event and guards
                     * against drift since snapshot activation ran. */
                    bool anchor_recommitted = false;
                    if (anc->phashBlock) {
                        int from_height = mp->main_state ?
                            active_chain_height(&mp->main_state->chain_active) : -1;
                        anchor_recommitted =
                            msg_processor_recommit_snapshot_anchor(
                                mp, anc, from_height);
                        if (!anchor_recommitted) {
                            LOG_WARN("sync",
                                "anchor re-commit rejected h=%d",
                                anc->nHeight);
                        }
                    } else {
                        LOG_WARN("sync",
                            "refusing to clear snapshot anchor "
                            "without block hash h=%d", anc->nHeight);
                    }
                    if (anchor_recommitted) {
                        msg_processor_set_snapshot_anchor(mp, NULL);
                        msg_processor_clear_activation_anchor(
                            mp, "headers_past_anchor");
                    }
                }
            }
        }

        /* One-shot block file scan: if block files exist on disk (from
         * file_service) but weren't scanned at boot (empty index at boot),
         * scan them now that we have headers. This marks downloaded blocks
         * as BLOCK_HAVE_DATA so we don't re-download them from P2P. */
        if (header_plan.should_scan_block_files) {
            char bfp[576];
            snprintf(bfp, sizeof(bfp), "%s/blocks/blk00000.dat", mp->datadir);
            struct stat bfst;
            if (stat(bfp, &bfst) == 0 && bfst.st_size > 0) {
                printf("P2P trigger: scanning block files for HAVE_DATA...\n");
                int scan_m = msg_processor_scan_block_files(mp);

                struct sync_chain_activation activation = {0};
                syncsvc_build_block_file_scan_activation(&activation, scan_m);
                if (activation.should_activate && !g_shutdown_requested) {
                    printf("P2P block file scan: %d blocks marked\n", scan_m);
                    msg_processor_request_activation(
                        mp, MSG_ACTIVATE_BLOCK_FILE_SCAN);
                }

                /* Structural repair (block_map heights, active-tip
                 * restore) belongs in block_index_integrity, not this
                 * P2P handler. */
                msg_processor_repair_post_activation_anchor(mp);
            }
        }
        /* Header processing owns the HEADERS_DOWNLOAD -> BLOCKS_DOWNLOAD
         * phase edge even when there is no body to enqueue.  The empty-batch
         * case is the positive reply to an equal-height warm-start probe; the
         * all-data case activates from disk.  Keeping this inside the queue
         * branch stranded both cases in HEADERS_DOWNLOAD forever. */
        if (header_plan.should_set_sync_state)
            sync_set_state(header_plan.next_sync_state,
                           header_plan.should_queue_needed_blocks
                               ? "headers ahead, requesting blocks"
                               : "header probe complete");
        if (header_plan.should_queue_needed_blocks) {
            if (!header_plan.download.needed_blocks.chains_from_tip)
                printf("headers: skip block queue — chain doesn't reach "
                       "tip h=%d\n", our_height);

            {
                struct download_manager *dm = get_download_mgr();
                size_t queued = dl_queue_blocks(dm, hashes, heights,
                                                header_plan.queue_count);
                if (queued > 0)
                    event_emitf(EV_BLOCK_REQUESTED, (uint32_t)node->id,
                                "queued=%zu total_needed=%zu",
                                queued, header_plan.queue_count);
            }
        }

        if (hashes && heights && pindex_last &&
            pindex_last->nHeight > our_height &&
            header_plan.queue_count == 0) {
            bool has_data_successor = false;
            size_t fallback_count = collect_active_tip_successors(
                mp->main_state, hashes, heights, max_collect,
                &has_data_successor);
            if (fallback_count > 0) {
                struct download_manager *dm = get_download_mgr();
                size_t queued = dl_queue_blocks(dm, hashes, heights,
                                                fallback_count);
                if (queued > 0) {
                    sync_set_state(SYNC_BLOCKS_DOWNLOAD,
                                   "tip successor fallback");
                    event_emitf(EV_BLOCK_REQUESTED, (uint32_t)node->id,
                                "fallback_queued=%zu total_needed=%zu",
                                queued, fallback_count);
                    LOG_INFO("headers",
                        "fallback queued %zu active-tip "
                        "successor blocks after empty header plan "
                        "(tip=%d header=%d)",
                        queued, our_height, pindex_last->nHeight);
                }
            } else if (has_data_successor) {
                msg_processor_request_activation(
                    mp, MSG_ACTIVATE_HEADERS_ALL_DATA);
            }
        }

        /* Chain activation: if all blocks already have data (e.g. after
         * LDB import with symlinked blk files), needed_blocks.count is 0
         * but should_activate_chain is true.  This MUST run outside the
         * should_queue_needed_blocks guard — that gate requires count>0,
         * which is the opposite of the activation condition. */
        if (header_plan.should_activate_chain) {
            struct sync_chain_activation activation = {0};
            syncsvc_build_header_processing_activation(&activation,
                                                      &header_plan);
            if (activation.should_activate && !g_shutdown_requested) {
                msg_processor_request_activation(
                    mp, MSG_ACTIVATE_HEADERS_ALL_DATA);
            }
        }
        free(hashes);
        free(heights);
    }

    /* Request more headers if we accepted any.
     *
     * If ALL headers in the batch were already known (newly_added == 0),
     * skip ahead to pindex_best_header instead of crawling 160 at a time
     * through millions of known headers.  This happens after snapshot sync
     * when the block index has entries above the chain tip.
     *
     * If some headers were new, use pindex_last — the peer will continue
     * from right after it. */
    if (header_plan.batch.should_request_more_headers) {
        /* Track header advancement rate.  If a full batch of headers
         * didn't advance the tip by at least 100, something may be
         * wrong (e.g., heights still scrambled, bouncing locators). */
        if (pindex_last && accepted >= 100) {
            int prev_tip = atomic_load(&g_last_header_tip_height);
            int cur_tip = pindex_last->nHeight;
            if (prev_tip > 0 && cur_tip - prev_tip < 100 &&
                cur_tip > 0 && prev_tip > 0) {
                LOG_WARN("headers",
                    "SLOW ADVANCE: peer %s sent %zu headers "
                    "but tip only moved from %d to %d",
                    node->addr_name, accepted, prev_tip, cur_tip);
            }
            atomic_store(&g_last_header_tip_height, cur_tip);
        }

        /* Band fill: a below-tip batch that extends the trust-rooted
         * frontier toward an installed-above-frontier island is progress
         * — it must suppress BOTH the restart-from-tip and the
         * best-header skip below, or the band hole never closes. The
         * low-batch gate keeps the ancestry walk off the IBD hot path. */
        bool band_fill = (pindex_last &&
            pindex_last->nHeight <
                active_chain_height(&mp->main_state->chain_active))
            ? syncsvc_header_band_continue(&mp->main_state->chain_active,
                                           pindex_last)
            : false;

        if (syncsvc_should_restart_headers_from_tip(
                accepted, pindex_last, active_chain_height(
                    &mp->main_state->chain_active), node->starting_height,
                band_fill)) {
            LOG_WARN("headers",
                    "low batch from %s ended at h=%d below "
                    "chain tip h=%d; restarting getheaders from tip",
                    node->addr_name,
                    pindex_last ? pindex_last->nHeight : -1,
                    active_chain_height(&mp->main_state->chain_active));
            {
                struct block_index *restart_tip = active_chain_tip(
                    &mp->main_state->chain_active);
                if (restart_tip && restart_tip->phashBlock)
                    push_getheaders_from(mp, node, restart_tip);
                else
                    push_getheaders(mp, node);
            }
        } else if (!band_fill && newly_added == 0 && pindex_last &&
                   msg_processor_block_index_heights_repaired(mp) &&
                   mp->main_state->pindex_best_header &&
                   mp->main_state->pindex_best_header->phashBlock &&
                   mp->main_state->pindex_best_header->nHeight >
                       pindex_last->nHeight &&
                   node->starting_height >
                       mp->main_state->pindex_best_header->nHeight) {
            /* The whole batch was already known and our best header sits
             * far above it (boot restored a deep header chain, or a
             * periodic re-anchor pulled the conversation back to the
             * active tip). Continuing from pindex_last would crawl the
             * known span 160 headers per round trip — with millions of
             * known headers that is a multi-day stall that also burns a
             * core re-accepting known headers. Skip the conversation
             * straight to best_header; the exponential locator still
             * lets the peer pick an earlier fork point if our best
             * header is stale. Gated on repaired heights — with
             * scrambled heights this skip would loop forever.
             * Also gated on the peer's advertised starting_height being
             * ABOVE our best header: an honest peer whose tip is below
             * best_header answers a best_header-anchored getheaders with
             * the same all-known span every time (their fork point never
             * moves), so the skip would ping-pong the identical request
             * with that peer forever. Such peers take the pindex_last
             * continuation below, which terminates at their tip. */
            push_getheaders_from(mp, node, mp->main_state->pindex_best_header);
        } else {
            /* Advance from pindex_last — the actual last header the peer
             * sent.  Using pindex_best_header caused infinite loops after
             * snapshot/LDB import when heights were scrambled. */
            push_getheaders_from(mp, node, pindex_last);
        }
    }

    /* Band closure probe — deliberately OUTSIDE should_request_more_headers
     * (the final band batch can be shorter than 160). No-op without the
     * band blocker. */
    if (accepted > 0)
        syncsvc_header_band_after_batch(mp->main_state, pindex_last);

    return true;
}

void push_getheaders_from(struct msg_processor *mp,
                          struct p2p_node *node,
                          struct block_index *from)
{
    /* Robust continuation anchor. A caller may hand us a block_index whose
     * stable per-node hash slot was never populated (phashBlock == NULL).
     * Dropping the request here is a SILENT header-sync stop — forbidden by
     * construction. Re-anchor at the best-header tree tip, then the active-
     * chain tip (both always carry a hash), so the conversation continues
     * from the highest hashed frontier we hold. Give up only when nothing
     * anywhere has a hash, and then LOUDLY with a counter. */
    if (from && !from->phashBlock) {
        struct block_index *reanchor = NULL;
        if (mp && mp->main_state) {
            if (mp->main_state->pindex_best_header &&
                mp->main_state->pindex_best_header->phashBlock) {
                reanchor = mp->main_state->pindex_best_header;
            } else {
                struct block_index *tip =
                    active_chain_tip(&mp->main_state->chain_active);
                if (tip && tip->phashBlock)
                    reanchor = tip;
            }
        }
        uint64_t n = atomic_fetch_add(&g_getheaders_suppressed_no_hash, 1) + 1;
        if (getheaders_suppress_rising_edge(&g_no_hash_streak))
            LOG_WARN("headers",
                     "push_getheaders_from: anchor h=%d has no block hash — "
                     "re-anchoring at %s (suppressed_no_hash=%llu)",
                     from->nHeight,
                     reanchor ? "best-header/chain tip"
                              : "NONE (request skipped)",
                     (unsigned long long)n);
        from = reanchor;
        if (!from)
            return;  /* no hashed frontier anywhere — cannot build a locator */
    } else {
        atomic_store(&g_no_hash_streak, false);
    }

    /* Snapshot sync owns the wire while a peer snapshot exchange is live;
     * requesting headers then just competes with chunk transfer. This is a
     * real, intentional pause — but never a silent one: count it and name
     * it so a snapshot exchange that latches active (and thus wedges header
     * sync after one in-flight batch) announces itself instead of stalling
     * quietly. */
    if (msg_processor_snapshot_active(mp)) {
        uint64_t n = atomic_fetch_add(&g_getheaders_suppressed_snapshot, 1) + 1;
        if (getheaders_suppress_rising_edge(&g_snapshot_streak))
            LOG_WARN("headers",
                     "push_getheaders_from: header request SUPPRESSED by "
                     "active snapshot sync (anchor h=%d suppressed_snapshot="
                     "%llu) — header sync is paused until the snapshot "
                     "exchange completes or resets",
                     from ? from->nHeight : -1, (unsigned long long)n);
        return;
    }
    atomic_store(&g_snapshot_streak, false);

    /* Build locator for getheaders request.
     * After bulk height repair, heights are trustworthy — use a proper
     * Bitcoin-style exponential locator for better branch identification.
     * Before repair, fall back to the safe 2-hash locator. */
    struct block_locator loc;
    block_locator_init(&loc);
    if (from && from->phashBlock &&
        msg_processor_block_index_heights_repaired(mp)) {
        /* Exponential locator: tip, tip-1, tip-2, tip-4, tip-8, ... genesis.
         * Walk pprev chain with exponentially increasing steps. */
        int max_hashes = 32;
        struct uint256 *tmp = zcl_malloc((size_t)max_hashes * sizeof(struct uint256),
                                         "exp_locator");
        if (!tmp) return;
        int nh = 0;
        struct block_index *walk = from;
        int step = 1;
        while (walk && nh < max_hashes - 1) {
            if (walk->phashBlock)
                tmp[nh++] = *walk->phashBlock;
            /* Walk back 'step' blocks via pprev */
            struct block_index *prev_walk = walk;
            for (int s = 0; s < step && walk->pprev; s++)
                walk = walk->pprev;
            /* Stop when the walk made no progress (pprev exhausted — an
             * island root, not just the first hop): the old `walk == from`
             * test only caught the first iteration, so a detached-island
             * anchor degenerated the locator to [island hashes ×31,
             * genesis]. */
            if (walk == prev_walk) break;
            if (nh >= 10)
                step *= 2;  /* exponential after first 10 entries */
        }
        /* Always end with genesis */
        if (nh > 0 && nh < max_hashes)
            tmp[nh++] = mp->params->consensus.hashGenesisBlock;
        loc.vhave = tmp;
        loc.num_hashes = (size_t)nh;
    } else if (from && from->phashBlock) {
        struct zcl_result _r = syncsvc_build_getheaders_locator(&loc,
                                              &mp->main_state->chain_active,
                                              from,
                                              mp->main_state->pindex_best_header,
                                              &mp->params->consensus.hashGenesisBlock);
        if (!_r.ok) {
            fprintf(stderr, "[headers] %s:%d push_getheaders_from: build_locator failed: %s\n",
                    _r.source_file, _r.source_line, _r.message);
            return;
        }
    } else {
        struct zcl_result _r = syncsvc_build_getheaders_locator(&loc,
                                              &mp->main_state->chain_active,
                                              NULL,
                                              mp->main_state->pindex_best_header,
                                              &mp->params->consensus.hashGenesisBlock);
        if (!_r.ok) {
            fprintf(stderr, "[headers] %s:%d push_getheaders_from: build_locator failed: %s\n",
                    _r.source_file, _r.source_line, _r.message);
            return;
        }
    }

    struct byte_stream s;
    stream_init(&s, 512);
    if (!getheaders_serialize(&s, &loc, NULL)) {
        stream_free(&s);
        block_locator_free(&loc);
        return;
    }

    /* Debug: log locator hashes to diagnose sync stall */
    if (loc.num_hashes > 0 && loc.num_hashes <= 20) {
        for (size_t li = 0; li < loc.num_hashes && li < 3; li++) {
            char lhex[65];
            uint256_get_hex(&loc.vhave[li], lhex);
            LOG_INFO("headers", "getheaders locator[%zu]: %s", li, lhex);
        }
    }

    p2p_node_begin_message(node, "getheaders", mp->params->pchMessageStart);
    p2p_node_write_message_data(node, s.data, s.size);
    p2p_node_end_message(node);
    stream_free(&s);
    block_locator_free(&loc);
}

void push_getheaders(struct msg_processor *mp, struct p2p_node *node)
{
    if (msg_processor_snapshot_active(mp)) {
        uint64_t n =
            atomic_fetch_add(&g_push_getheaders_suppressed_snapshot, 1) + 1;
        if (getheaders_suppress_rising_edge(&g_push_getheaders_snapshot_streak))
            LOG_WARN("headers",
                     "push_getheaders: request to %s SUPPRESSED by active "
                     "snapshot sync (suppressed=%llu)",
                     node->addr_name, (unsigned long long)n);
        return;
    }
    atomic_store(&g_push_getheaders_snapshot_streak, false);

    /* Use the active-chain locator, including recent ancestors. A locator
     * containing only tip+genesis makes a one-block local fork invisible to
     * peers: they do not know our tip and fall back to genesis, sending old
     * headers instead of the sibling that reorgs us back to the best chain. */
    {
        struct block_locator loc;
        block_locator_init(&loc);
        if (syncsvc_build_getheaders_locator(
                &loc, &mp->main_state->chain_active, NULL,
                mp->main_state->pindex_best_header,
                &mp->params->consensus.hashGenesisBlock).ok) {
            struct byte_stream s;
            stream_init(&s, 512);
            if (getheaders_serialize(&s, &loc, NULL)) {
                p2p_node_begin_message(node, "getheaders",
                                       mp->params->pchMessageStart);
                p2p_node_write_message_data(node, s.data, s.size);
                p2p_node_end_message(node);
            }
            stream_free(&s);
            block_locator_free(&loc);
            return;
        }
        /* Fall through to snapsync anchor locator path. Builder
         * already logged via ZCL_ERR source/line; no need to dup. */
    }

    /* After snapshot sync, use the snapshot anchor as the locator start. */
    struct block_index *anchor = msg_processor_snapshot_anchor(mp);
    if (anchor && anchor->phashBlock)
        push_getheaders_from(mp, node, anchor);
    else
        push_getheaders_from(mp, node, NULL);
}

void push_getheaders_span(struct msg_processor *mp, struct p2p_node *node,
                          const struct uint256 *start_hash,
                          const struct uint256 *stop_hash)
{
    if (!mp || !node || !start_hash)
        return;
    if (msg_processor_snapshot_active(mp)) {
        uint64_t n = atomic_fetch_add(
            &g_push_getheaders_span_suppressed_snapshot, 1) + 1;
        if (getheaders_suppress_rising_edge(
                &g_push_getheaders_span_snapshot_streak))
            LOG_WARN("headers",
                     "push_getheaders_span: span request to %s SUPPRESSED "
                     "by active snapshot sync (suppressed=%llu)",
                     node->addr_name, (unsigned long long)n);
        return;
    }
    atomic_store(&g_push_getheaders_span_snapshot_streak, false);

    /* Minimal locator: [start_hash, genesis]. start_hash is a compiled
     * checkpoint (or our own frontier) so any honest full peer holds it
     * and forks there; genesis is the universal fallback. hash_stop
     * bounds the peer to this peer's span. */
    struct block_locator loc;
    block_locator_init(&loc);
    loc.vhave = zcl_malloc(2 * sizeof(struct uint256), "hrs_span_locator");
    if (!loc.vhave) {
        atomic_fetch_add(&g_push_getheaders_span_alloc_fail, 1);
        LOG_ERROR("headers",
                  "push_getheaders_span: locator alloc failed for %s — "
                  "span header request dropped",
                  node->addr_name);
        return;
    }
    loc.vhave[0] = *start_hash;
    loc.vhave[1] = mp->params->consensus.hashGenesisBlock;
    loc.num_hashes = 2;

    struct byte_stream s;
    stream_init(&s, 512);
    if (getheaders_serialize(&s, &loc, stop_hash)) {
        p2p_node_begin_message(node, "getheaders", mp->params->pchMessageStart);
        p2p_node_write_message_data(node, s.data, s.size);
        p2p_node_end_message(node);
    }
    stream_free(&s);
    block_locator_free(&loc);
}

/* Resolve a span-boundary height to a locally-known block hash: a compiled
 * checkpoint hash (held WITHOUT the intervening headers — the crux that
 * lets disjoint peers fork across a cold gap), else a block we already
 * hold at or below our frontier. Returns false when the height is neither
 * a checkpoint nor in our index (never fabricates a hash we lack). */
static bool hrs_resolve_anchor_hash(struct msg_processor *mp, int32_t height,
                                    int our_height, struct uint256 *out)
{
    if (!mp || !out)
        return false;
    if (checkpoints_hash_at_height(&mp->params->checkpointData, height, out))
        return true;
    if (height <= our_height) {
        struct block_index *bi =
            active_chain_at(&mp->main_state->chain_active, height);
        if (bi && bi->phashBlock) {
            *out = *bi->phashBlock;
            return true;
        }
    }
    return false;
}

bool msg_try_range_parallel_getheaders(struct msg_processor *mp,
                                       struct p2p_node *node,
                                       int our_height, int64_t now_seconds)
{
    if (!mp || !node || !mp->main_state || !mp->net_mgr || !mp->params)
        return false;
    /* The header-band backfill owns the getheaders anchor while a band
     * hole is open (exec_getheaders_action drives it). Range-parallel
     * feeds the band, never fights it: stand down entirely until the band
     * closes. */
    if (syncsvc_header_band_hole_open())
        return false;
    /* Only a fast-sync-capable outbound peer participates. Legacy peers
     * cap batches at 160 and never learn the NODE_ZCL23 span protocol —
     * they keep the existing single-peer path. */
    if (node->inbound || node->state < PEER_SYNCING_HEADERS ||
        !peer_supports_fast_sync(node->services))
        return false;

    struct main_state *ms = mp->main_state;
    int target = node->starting_height;
    if (ms->pindex_best_header &&
        ms->pindex_best_header->nHeight > target)
        target = ms->pindex_best_header->nHeight;
    int32_t gap = (int32_t)(target - our_height);

    /* Count connected fast-sync-capable outbound peers. */
    int fast_peers = 0;
    zcl_mutex_lock(&mp->net_mgr->cs_nodes);
    for (size_t pi = 0; pi < mp->net_mgr->num_nodes; pi++) {
        struct p2p_node *n = mp->net_mgr->nodes[pi];
        if (n && !n->inbound && !n->disconnect &&
            n->state >= PEER_ACTIVE &&
            peer_supports_fast_sync(n->services))
            fast_peers++;
    }
    zcl_mutex_unlock(&mp->net_mgr->cs_nodes);

    if (!hrs_should_parallelize(fast_peers, gap, 2000))
        return false;

    /* Anchors = compiled checkpoints strictly inside (our_height, target).
     * These are the only hashes we hold without having synced the
     * intervening headers, so they are the disjoint fork points that let N
     * peers cover N different checkpoint intervals at once. */
    const struct checkpoint_data *cpd = &mp->params->checkpointData;
    int32_t anchors[HRS_MAX_SPANS];
    size_t n_anchors = 0;
    for (int i = 0; cpd && cpd->entries && i < cpd->nEntries &&
                    n_anchors < HRS_MAX_SPANS; i++) {
        int h = cpd->entries[i].height;
        if (h > our_height && h < target)
            anchors[n_anchors++] = (int32_t)h;
    }

    struct header_range_scheduler *sched = header_range_scheduler_global();
    hrs_plan(sched, (int32_t)our_height, target, anchors, n_anchors);

    int64_t now_us = now_seconds * 1000000;

    /* Advance completions from our current header frontier so already-synced
     * spans free their peer slots before we (re)assign. */
    if (ms->pindex_best_header)
        hrs_note_frontier(sched, ms->pindex_best_header->nHeight);

    /* Sweep every expired span back into the free pool so a stalling peer
     * never stalls the whole sync, and demote EVERY reported stalling
     * owner — not just this peer. hrs_sweep_expired() is GLOBAL: it frees
     * every expired span in the table regardless of who is calling. A
     * "demote self, then discard the sweep's stalled-owner buffer"
     * pattern silently drops other peers' timeouts whenever some OTHER
     * peer's periodic tick happens to run the sweep first — by the time
     * the actually-stalled peer gets its own turn, hrs_peer_owns_expired_
     * span() is already false (its span was freed by someone else's
     * sweep) and it is never demoted. Reading the whole stalled-owner
     * buffer here means whichever peer's tick performs the sweep
     * correctly demotes every owner it evicted, including itself. */
    int32_t stalled_ids[HRS_MAX_SPANS];
    size_t n_stalled = hrs_sweep_expired(sched, now_us, stalled_ids, HRS_MAX_SPANS);
    if (n_stalled > 0) {
        zcl_mutex_lock(&mp->net_mgr->cs_nodes);
        for (size_t si = 0; si < n_stalled; si++) {
            int32_t sid = stalled_ids[si];
            bool dup = false;
            for (size_t sj = 0; sj < si; sj++) {
                if (stalled_ids[sj] == sid) { dup = true; break; }
            }
            if (dup)
                continue;
            for (size_t pi = 0; pi < mp->net_mgr->num_nodes; pi++) {
                struct p2p_node *sn = mp->net_mgr->nodes[pi];
                if (sn && sn->id == sid) {
                    peer_scoring_record(mp->net_mgr, sn, PEER_OFFENCE_TIMEOUT,
                                        "header span deadline missed");
                    break;
                }
            }
        }
        zcl_mutex_unlock(&mp->net_mgr->cs_nodes);
    }

    /* This peer's span: keep an existing live one, else claim a free span. */
    int32_t lo, hi;
    if (!hrs_peer_span(sched, node->id, now_us, &lo, &hi)) {
        int idx = hrs_assign(sched, node->id, now_us);
        if (idx < 0)
            return false;   /* no free span — fall back to single-peer path */
        if (!hrs_peer_span(sched, node->id, now_us, &lo, &hi))
            return false;
    }

    struct uint256 start_hash, stop_hash;
    if (!hrs_resolve_anchor_hash(mp, lo, our_height, &start_hash))
        return false;       /* cannot anchor — fall back */
    bool have_stop = hrs_resolve_anchor_hash(mp, hi, our_height, &stop_hash);

    push_getheaders_span(mp, node, &start_hash, have_stop ? &stop_hash : NULL);
    LOG_INFO("headers",
             "range-parallel: peer=%d span=[%d,%d] fast_peers=%d gap=%d",
             node->id, lo, hi, fast_peers, gap);
    return true;
}

void exec_getheaders_action(struct msg_processor *mp,
                            struct p2p_node *node,
                            const struct sync_getheaders_action *action)
{
    struct block_index *tip;

    if (!mp || !node || !action || !action->should_send)
        return;

    tip = active_chain_tip(&mp->main_state->chain_active);

    /* While a header band hole is recorded, every periodic kick drives
     * the band: anchor at the contiguous frontier so the peer forks
     * there and serves the band. Tip-side progress continues via batch
     * continuations and unsolicited header/inv pushes. O(1) when no
     * band fact exists. */
    {
        struct block_index *band_anchor =
            syncsvc_header_band_backfill_anchor(&mp->main_state->chain_active);
        if (band_anchor) {
            push_getheaders_from(mp, node, band_anchor);
            return;
        }
    }

    switch (action->anchor) {
    case SYNC_HEADER_REQUEST_TIP_PARENT:
        /* Prefer best_header whenever it leads the active tip — INCLUDING a
         * NULL tip (full-index boot before the active_chain window/authority
         * is seated). The old `tip &&` guard discarded best_header on a NULL
         * tip and fell to a genesis-only locator. */
        if (mp->main_state->pindex_best_header &&
            mp->main_state->pindex_best_header->phashBlock &&
            (!tip ||
             mp->main_state->pindex_best_header->nHeight > tip->nHeight)) {
            push_getheaders_from(mp, node, mp->main_state->pindex_best_header);
        } else if (tip && tip->pprev) {
            push_getheaders_from(mp, node, tip->pprev);
        } else {
            push_getheaders(mp, node);
        }
        break;
    case SYNC_HEADER_REQUEST_TIP:
    case SYNC_HEADER_REQUEST_EXPLICIT:
    default:
        /* When the validated header chain already extends above the
         * active tip, anchor the request at best_header — re-anchoring
         * at the tip makes the peer re-send known headers (160 per
         * round trip through the whole known span). The periodic IBD
         * re-kick fires every 10s, so a tip anchor here permanently
         * resets the conversation below the known frontier. The
         * locator includes lower heights, so a stale best_header still
         * converges on the true fork point. */
        if (msg_processor_block_index_heights_repaired(mp) &&
            mp->main_state->pindex_best_header &&
            mp->main_state->pindex_best_header->phashBlock &&
            (!tip ||
             mp->main_state->pindex_best_header->nHeight > tip->nHeight)) {
            push_getheaders_from(mp, node, mp->main_state->pindex_best_header);
        } else {
            push_getheaders(mp, node);
        }
        break;
    }
}
