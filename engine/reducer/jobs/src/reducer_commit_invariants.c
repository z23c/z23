/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * reducer_commit_invariants — implementation. See
 * jobs/reducer_commit_invariants.h for the contract, the three invariants, and
 * the threading / lock-order note.
 *
 * All state below is plain module-static: every entry point runs on the single
 * reducer drive thread while it holds progress_store_tx_lock, so there is no
 * concurrent writer and no need for atomics or a mutex (and taking one would
 * risk the LOCK-ORDER LAW). */

#include "jobs/reducer_commit_invariants.h"

#include "core/utiltime.h"          /* GetTimeMicros */
#include "storage/anchor_kv.h"      /* anchor_kv_max_height, ANCHOR_POOL_* */
#include "storage/coins_kv.h"       /* coins_kv_delta_* */
#include "storage/coins_ram.h"      /* coins_ram_active */
#include "util/blocker.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CI_SUBSYS "utxo_apply"

/* ── In-memory nullifier set (invariant c) ──────────────────────────────
 * Open-addressing set of (nf[32], pool), grown on demand, freed each batch.
 * Bounded by the nullifiers revealed in one batch (per_stage_batch blocks). */
struct ci_nf_slot {
    uint8_t nf[32];
    int32_t pool;
    uint8_t used;
};
struct ci_nf_set {
    struct ci_nf_slot *slots;
    size_t cap;      /* power of two, 0 when unallocated */
    size_t count;
};

static uint64_t ci_nf_hash(const uint8_t nf[32], int pool)
{
    uint64_t h = 1469598103934665603ULL;
    h ^= (uint64_t)(uint32_t)pool;
    h *= 1099511628211ULL;
    for (size_t i = 0; i < 32; i++) {
        h ^= nf[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static bool ci_nf_grow(struct ci_nf_set *s)
{
    size_t new_cap = s->cap ? s->cap * 2 : 256;
    struct ci_nf_slot *ns =
        zcl_calloc(new_cap, sizeof(*ns), "ci_nf_set");
    if (!ns)
        return false;
    /* Rehash existing entries into the larger table. */
    for (size_t i = 0; i < s->cap; i++) {
        if (!s->slots[i].used)
            continue;
        size_t mask = new_cap - 1;
        size_t pos = (size_t)ci_nf_hash(s->slots[i].nf, s->slots[i].pool) & mask;
        while (ns[pos].used)
            pos = (pos + 1) & mask;
        ns[pos] = s->slots[i];
    }
    free(s->slots);
    s->slots = ns;
    s->cap = new_cap;
    return true;
}

/* Returns 1 if (nf,pool) was already present (duplicate), 0 if freshly
 * inserted, -1 on OOM. */
static int ci_nf_add(struct ci_nf_set *s, const uint8_t nf[32], int pool)
{
    /* Keep load factor <= 1/2 for stable open-addressing probes. */
    if ((s->count + 1) * 2 > s->cap) {
        if (!ci_nf_grow(s))
            return -1;  // raw-return-ok:tri-state OOM sentinel; caller note_nullifier logs+refuses
    }
    size_t mask = s->cap - 1;
    size_t pos = (size_t)ci_nf_hash(nf, pool) & mask;
    for (size_t probes = 0; probes <= mask; probes++) {
        struct ci_nf_slot *slot = &s->slots[pos];
        if (!slot->used) {
            memcpy(slot->nf, nf, 32);
            slot->pool = pool;
            slot->used = 1;
            s->count++;
            return 0;
        }
        if (slot->pool == pool && memcmp(slot->nf, nf, 32) == 0)
            return 1;
        pos = (pos + 1) & mask;
    }
    return -1;  // raw-return-ok:tri-state full-table sentinel (unreachable at <=1/2 load); caller refuses
}

/* ── Batch window state ─────────────────────────────────────────────── */
enum { CI_POOLS = 2 };

static struct {
    bool     active;
    bool     reorg;          /* rebaseline: unwind mutated state this batch */
    bool     coins_touched;  /* any block authored coins */
    bool     count_gated;    /* (a) count-check skipped (overlay / no baseline) */
    int64_t  expected_net;   /* Σ(added − spent) */
    int64_t  top_height;     /* highest height touched (for blocker naming) */
    int64_t  anchor_last[CI_POOLS];  /* last appended height per pool (baseline) */

    struct ci_nf_set nf;

    /* First violation found (nullifier/anchor set at note time; coins at
     * verify). verify() raises the blocker from these. */
    bool     violation;
    int      violation_height;
    char     violation_kind[48];
    char     violation_detail[160];

    int64_t  last_count_us;
} g;

static void ci_wipe(void)
{
    coins_kv_delta_cancel();
    free(g.nf.slots);
    memset(&g, 0, sizeof(g));
    g.anchor_last[0] = -1;
    g.anchor_last[1] = -1;
}

static void ci_record_violation(int height, const char *kind,
                                 const char *detail)
{
    if (g.violation)
        return;  /* keep the FIRST violation (lowest-height cause) */
    g.violation = true;
    g.violation_height = height;
    snprintf(g.violation_kind, sizeof(g.violation_kind), "%s",
             kind ? kind : "unknown");
    snprintf(g.violation_detail, sizeof(g.violation_detail), "%s",
             detail ? detail : "");
}

void reducer_commit_invariants_reset(void)
{
    ci_wipe();
}

void reducer_commit_invariants_batch_begin(struct sqlite3 *db)
{
    ci_wipe();
    g.active = true;

    /* Invariant (a) — arm the exact physical-row meter off the overlay hot
     * path. A from-genesis/refold bulk fold uses the overlay's self-verify. */
    if (coins_ram_active()) {
        g.count_gated = true;
    } else {
        if (!db) {
            g.count_gated = true;
        } else {
            coins_kv_delta_begin();
        }
    }

    /* Invariant (b) baseline — per-pool max anchor height (indexed MAX, no
     * tree deserialization). A read failure leaves the baseline at -1, which
     * only ever makes the monotonic check MORE permissive (never a false
     * positive). */
    for (int pool = 0; pool < CI_POOLS; pool++) {
        int64_t mh = -1;
        if (db && anchor_kv_max_height(db, pool, &mh) && mh >= 0)
            g.anchor_last[pool] = mh;
        else
            g.anchor_last[pool] = -1;
    }
}

void reducer_commit_invariants_disable_coins_check(void)
{
    if (!g.active)
        return;
    g.count_gated = true;
    coins_kv_delta_cancel();
}

void reducer_commit_invariants_note_coins(int height, uint64_t added,
                                          uint64_t spent)
{
    if (!g.active || g.reorg)
        return;
    g.coins_touched = true;
    g.expected_net += (int64_t)added - (int64_t)spent;
    if ((int64_t)height > g.top_height)
        g.top_height = height;
}

void reducer_commit_invariants_note_anchor(int height, int pool)
{
    if (!g.active || g.reorg)
        return;
    if (pool < 0 || pool >= CI_POOLS)
        return;
    if ((int64_t)height > g.top_height)
        g.top_height = height;
    if (g.violation)
        return;
    /* Append-only / monotonic: each append must sit strictly above the pool's
     * pre-batch max and every earlier append in the batch. */
    if ((int64_t)height <= g.anchor_last[pool]) {
        char detail[160];
        snprintf(detail, sizeof(detail),
                 "anchor append pool=%d height=%d not above prior max=%lld "
                 "(append-only/monotonic violated within batch)",
                 pool, height, (long long)g.anchor_last[pool]);
        ci_record_violation(height, "anchor_nonmonotonic", detail);
        return;
    }
    g.anchor_last[pool] = height;
}

void reducer_commit_invariants_note_nullifier(int height, const uint8_t nf[32],
                                              int pool)
{
    if (!g.active || g.reorg || !nf)
        return;
    if ((int64_t)height > g.top_height)
        g.top_height = height;
    if (g.violation)
        return;
    int r = ci_nf_add(&g.nf, nf, pool);
    if (r == 1) {
        char hex[9] = {0};
        for (int i = 0; i < 4; i++)
            snprintf(hex + i * 2, 3, "%02x", nf[i]);
        char detail[160];
        snprintf(detail, sizeof(detail),
                 "duplicate nullifier insert pool=%d nf=%s.. at height=%d "
                 "(revealed twice within one batch — INSERT OR REPLACE would "
                 "silently swallow it)",
                 pool, hex, height);
        ci_record_violation(height, "nullifier_duplicate", detail);
    } else if (r < 0) {
        /* Accumulator OOM: cannot prove uniqueness — fail closed so the batch
         * is refused rather than committing unverified. */
        char detail[160];
        snprintf(detail, sizeof(detail),
                 "nullifier uniqueness set alloc failed at height=%d "
                 "(cannot prove batch nullifier uniqueness)", height);
        ci_record_violation(height, "nullifier_set_alloc", detail);
    }
}

void reducer_commit_invariants_note_reorg(void)
{
    if (!g.active)
        return;
    g.reorg = true;
}

int64_t reducer_commit_invariants_last_count_us(void)
{
    return g.last_count_us;
}

/* Raise the PERMANENT typed blocker naming the exact height + which invariant
 * failed. Corruption ⇒ owner-gated (no auto-retry can un-corrupt state). */
static void ci_raise_blocker(int height, const char *kind, const char *detail)
{
    struct blocker_record rec;
    char reason[BLOCKER_REASON_MAX];
    snprintf(reason, sizeof(reason),
             "reducer commit invariant failed height=%d kind=%.32s: %.80s; "
             "commit rolled back; owner must repair the store and clear blocker",
             height, kind ? kind : "unknown", detail ? detail : "");
    if (!blocker_init(&rec, UTXO_APPLY_COMMIT_INVARIANT_BLOCKER_ID, CI_SUBSYS,
                      BLOCKER_PERMANENT, reason))
        return;  /* blocker_init logged the overflow */
    blocker_set(&rec);
}

bool reducer_commit_invariants_verify(struct sqlite3 *db)
{
    (void)db;  /* compatibility: the exact delta meter no longer scans db */
    g.last_count_us = 0;

    if (!g.active)
        return true;  /* no window open — nothing to verify */

    /* Reorg-touched batch: the unwind's inverse-delta math rebases the
     * conservation baseline. Pass loudly and let the reorg/crash-replay test
     * groups own that path. */
    if (g.reorg) {
        LOG_INFO(CI_SUBSYS,
                 "[commit-invariants] batch contained a reorg unwind — "
                 "conservation baseline rebased, checks deferred to the "
                 "reorg/crash-replay groups (top_height=%lld)",
                 (long long)g.top_height);
        ci_wipe();
        return true;
    }

    /* (b)/(c) violations are recorded at note time. */
    if (g.violation) {
        /* Error-level log that CONTINUES (LOG_ERR embeds a return): emit, raise
         * the typed blocker, then explicitly refuse the commit. */
        ZCL_LOG_EMIT_AT(ZCL_LOG_ERROR,
                        "[%s] commit-invariants: REFUSE commit: %s at "
                        "height=%d: %s\n",
                        CI_SUBSYS, g.violation_kind, g.violation_height,
                        g.violation_detail);
        ci_raise_blocker(g.violation_height, g.violation_kind,
                         g.violation_detail);
        ci_wipe();
        return false;
    }

    /* (a) exact physical-row conservation — gated off the overlay hot path. */
    if (g.coins_touched && !g.count_gated) {
        int64_t t0 = GetTimeMicros();
        int64_t actual = 0;
        bool measured = coins_kv_delta_finish(&actual);
        g.last_count_us = GetTimeMicros() - t0;
        if (!measured || actual != g.expected_net) {
            char detail[160];
            snprintf(detail, sizeof(detail),
                     "coins_kv physical row delta actual=%lld expected=%lld "
                     "(meter=%s) — created−spent does not match the physical "
                     "coin set",
                     (long long)actual, (long long)g.expected_net,
                     measured ? "exact" : "unavailable");
            ZCL_LOG_EMIT_AT(ZCL_LOG_ERROR,
                    "[%s] commit-invariants: REFUSE commit: "
                    "coins_conservation at height=%lld: %s\n",
                    CI_SUBSYS, (long long)g.top_height, detail);
            ci_raise_blocker((int)g.top_height, "coins_conservation", detail);
            ci_wipe();
            return false;
        }
    }

    ci_wipe();
    return true;
}
