/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

// one-result-type-ok:bool-live-advance-effect
// chain_evidence_controller_record_finalized_tip() returns bool: it has a
// single, coherent effect — advance the persisted active-tip evidence to a
// tip the reducer ALREADY committed. It makes no service decision (the
// reducer is the tip authority; this is a durable follow), so there is no
// reason-bearing failure to switch on: any persist miss logs loudly via
// LOG_WARN and returns false. The health-collect drain treats false as
// "health degrades honestly, nothing more" — never a wedge, never a freeze.

/*
 * Live-path active-tip evidence advance — the FORWARD twin of the boot
 * reconcile reconstruct in chain_evidence_reconstruct.c.
 *
 * The served tip on a running node advances through the tip_finalize reducer
 * (active_chain_move_window_tip), NOT through chain_evidence_controller_
 * promote_tip. promote_tip is the boot / import publication boundary; it is
 * the only writer of the persisted cec.active_tip_* keys, and it ALSO drives
 * a csr_commit_tip. The live reducer already committed the tip, so re-driving
 * CSR here would double-commit. This function therefore writes ONLY the
 * durable evidence keys (the exact set promote_tip and reconstruct write),
 * leaving the concrete tip pointers to the reducer.
 *
 * Without this follow, cec.active_tip_hash / cec.active_tip_height /
 * cec.coins_best_block_height froze at the last boot reconcile while the
 * served tip advanced every block — so chain_evidence_controller_snapshot's
 * active_tip_hash_mismatch (live tip vs persisted) degraded health further
 * with each block until the next reboot: a green at-tip node reporting
 * healthy=false, /api/health 503.
 *
 * LOCK-ORDER LAW: the reducer drive holds the coins_kv authority mutex for
 * the whole ingest. No path may hold csr->lock while acquiring coins_kv;
 * csr_snapshot copies repository state and releases csr->lock before sampling
 * external stores. Taking csr->lock from inside the drive is still an unsafe
 * blocking edge for the hot reducer path, so the drive NEVER calls the
 * evidence machinery: tip_finalize only stamps the
 * pending slot below (chain_evidence_note_finalized_tip — one leaf mutex,
 * never nested), and chain_evidence_drain_pending_tip runs the actual
 * record from the health-collect path, which already owns the established
 * csr->coins_kv order. The drain happens BEFORE the health snapshot, so the
 * mismatch the follow exists to clear is never observed by the reader that
 * triggers it.
 *
 * Invariants (DEFENSIVE_CODING.md):
 *   - NEVER freeze, NEVER block the caller. A persist miss is transient
 *     (sqlite contention); it logs loudly and returns false. The caller is
 *     the health-collect path — its only reaction is honest health
 *     degradation, exactly the no-silent-halt-but-no-wedge contract.
 *   - The persisted record is honest LOCAL evidence (ancestry + chainwork
 *     proven by the reducer's own selection; bytes/nakamoto/utxo flags left
 *     false for background validation to upgrade). It is byte-identical to
 *     what cec_reconstruct_active_tip_evidence persists, so the boot
 *     reconcile's idempotence check accepts it unchanged on the next boot.
 *   - Guard A (coins-durability) still clamps the coins-height twin: the
 *     persisted cec.coins_best_block_height is never written above the
 *     genuine applied coins frontier.
 */

#include "services/chain_evidence_authority_service.h"
#include "services/chain_evidence_persistence_service.h"
#include "services/chain_state_service.h"

#include "models/database.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <stdatomic.h>
#include <string.h>

/* Pending-tip slot: the ONLY thing the reducer drive touches. A leaf mutex —
 * nothing else is ever acquired while it is held, on either side — so it can
 * participate in no lock cycle by construction. */
static pthread_mutex_t g_pending_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_pending_height = -1;
static struct uint256 g_pending_hash;

void chain_evidence_note_finalized_tip(const struct block_index *finalized_tip)
{
    if (!finalized_tip || !finalized_tip->phashBlock ||
        finalized_tip->nHeight < 0)
        return;
    pthread_mutex_lock(&g_pending_lock);
    /* Monotonic: a later publish supersedes an undrained earlier one (the
     * evidence keys only need the newest tip; intermediate heights carry no
     * extra information). */
    if (finalized_tip->nHeight >= g_pending_height) {
        g_pending_height = finalized_tip->nHeight;
        g_pending_hash = *finalized_tip->phashBlock;
    }
    pthread_mutex_unlock(&g_pending_lock);
}

void chain_evidence_pending_tip_test_reset(void)
{
    pthread_mutex_lock(&g_pending_lock);
    g_pending_height = -1;
    memset(&g_pending_hash, 0, sizeof(g_pending_hash));
    pthread_mutex_unlock(&g_pending_lock);
}

static bool cla_load_u256(struct node_db *ndb, const char *key,
                          struct uint256 *out);
static int cla_state_get_i32(struct node_db *ndb, const char *key, int def);

bool chain_evidence_drain_pending_tip(
    struct chain_evidence_controller *authority)
{
    pthread_mutex_lock(&g_pending_lock);
    int height = g_pending_height;
    struct uint256 hash = g_pending_hash;
    pthread_mutex_unlock(&g_pending_lock);
    if (height < 0) {
        if (!authority || !authority->ndb || !authority->csr)
            return true; /* nothing pending */

        struct chain_state_view view;
        memset(&view, 0, sizeof(view));
        csr_snapshot(authority->csr, &view);
        if (view.tip_height < 0)
            return true; /* no current tip to repair */

        struct uint256 persisted_hash;
        bool persisted_matches =
            cla_load_u256(authority->ndb, "cec.active_tip_hash",
                          &persisted_hash) &&
            memcmp(persisted_hash.data, view.tip_hash.data, 32) == 0 &&
            cla_state_get_i32(authority->ndb, "cec.active_tip_height", -1) ==
                view.tip_height &&
            cla_state_get_i32(authority->ndb,
                              "cec.repaired_active_tip_evidence", 0) == 1;
        if (persisted_matches)
            return true;

        struct block_index tip;
        memset(&tip, 0, sizeof(tip));
        tip.nHeight = view.tip_height;
        tip.hashBlock = view.tip_hash;
        tip.phashBlock = &tip.hashBlock;
        return chain_evidence_controller_record_finalized_tip(
            authority, &tip, "health.drain_current_tip");
    }

    /* Local index node: record_finalized_tip reads only nHeight and
     * *phashBlock. The slot lock is NOT held across the record call (it
     * takes csr->lock + node.db; the leaf mutex must stay a leaf). */
    struct block_index tip;
    memset(&tip, 0, sizeof(tip));
    tip.nHeight = height;
    tip.hashBlock = hash;
    tip.phashBlock = &tip.hashBlock;

    if (!chain_evidence_controller_record_finalized_tip(
            authority, &tip, "health.drain_pending"))
        return false; /* slot stays pending; next drain retries */

    pthread_mutex_lock(&g_pending_lock);
    /* Clear only if no newer publish superseded what we just recorded. */
    if (g_pending_height == height &&
        memcmp(g_pending_hash.data, hash.data, 32) == 0)
        g_pending_height = -1;
    pthread_mutex_unlock(&g_pending_lock);
    return true;
}

static bool cla_load_u256(struct node_db *ndb, const char *key,
                          struct uint256 *out)
{
    size_t len = 0;
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    return ndb && node_db_state_get(ndb, key, out->data, 32, &len) &&
           len == 32;
}

static int cla_state_get_i32(struct node_db *ndb, const char *key, int def)
{
    int64_t v = def;
    if (ndb)
        (void)node_db_state_get_int(ndb, key, &v);
    return (int)v;
}

/* The ONLY freeze reason that may self-clear: the boot-reconcile transient
 * where the csr-snapshot tip and the separately-read active-chain tip briefly
 * diverged (chain_evidence_reconstruct.c raises "active_tip_hash != csr_tip_hash
 * (h=...)"). NEVER matches ancestry/chainwork/snapshot/persist/utxo-ahead — those
 * are genuine contradictions that MUST keep paging. The reason embeds a height,
 * so match the stable prefix. */
#define CEC_BOOT_TIP_DIVERGENCE_PREFIX "active_tip_hash != csr_tip_hash"

/* True iff the boot-transient tip divergence is PROVABLY gone: the reducer has
 * finalized this exact tip AND the live csr-snapshot active tip hash equals it
 * (csr_snapshot's active_tip_hash IS the active-chain tip's hash). Fail-closed
 * (return false) on any uncertainty — a still-diverged or reorg-in-flight state
 * keeps the freeze and keeps paging. Runs on the health/drain path, which owns
 * no-nested-lock snapshot path; csr_snapshot acquires+releases csr->lock before
 * reading coins_kv and never runs from the reducer drive. */
static bool cec_boot_tip_divergence_resolved(
    struct chain_evidence_controller *authority,
    const struct block_index *finalized_tip)
{
    if (strncmp(authority->contradiction_reason,
                CEC_BOOT_TIP_DIVERGENCE_PREFIX,
                strlen(CEC_BOOT_TIP_DIVERGENCE_PREFIX)) != 0)
        return false; /* not the self-clearable reason — keep paging */
    if (!authority->csr)
        return false;
    struct chain_state_view view;
    csr_snapshot(authority->csr, &view); /* tip_height=-1 if csr uninitialized */
    if (view.tip_height < 0)
        return false;
    if (view.tip_height != finalized_tip->nHeight)
        return false;
    return memcmp(view.tip_hash.data,
                  finalized_tip->phashBlock->data, 32) == 0;
}

/* Lift the stale boot-transient freeze in memory + on disk (mirrors the
 * canonical boot lift). publish_state + forward evidence are written by the
 * persist block this function falls through to in record_finalized_tip. */
static void cec_lift_boot_tip_divergence_freeze(
    struct chain_evidence_controller *authority, int height)
{
    authority->state = CEC_EMPTY;
    memset(authority->contradiction_reason, 0,
           sizeof(authority->contradiction_reason));
    if (authority->ndb) {
        (void)chain_evidence_state_set_retry(
            authority->ndb, "cec.sync_state",
            "empty", strlen("empty") + 1,
            "cec_lift_boot_tip_divergence_freeze");
        (void)chain_evidence_state_set_retry(
            authority->ndb, "cec.contradiction_reason",
            "", 1, "cec_lift_boot_tip_divergence_freeze");
        /* freeze() left cec.publish_state at FROZEN_CONTRADICTION. Clear it to
         * the truthful post-lift value: this tip is the live active tip,
         * finalized by the reducer, so it IS locally publishable. Required
         * because the idempotence early-return below can skip the forward
         * persist that would otherwise rewrite publish_state — leaving it stale
         * FROZEN -> snapshot's publish_state_not_local -> a false "unhealthy"
         * on that one path. NOTE: snapshot keys
         * publish_state_not_local on (state != LOCAL_EVIDENCE), so 0/empty would
         * NOT clear it — LOCAL_EVIDENCE is the only value that does + is honest. */
        (void)chain_evidence_state_set_int_retry(
            authority->ndb, "cec.publish_state",
            CEC_PUBLISH_LOCAL_EVIDENCE,
            "cec_lift_boot_tip_divergence_freeze");
    }
    LOG_WARN("cec", "[cec] lifting stale boot-transient freeze: live tip "
             "h=%d hash-consistent (csr==finalized) — clearing '"
             CEC_BOOT_TIP_DIVERGENCE_PREFIX "' and resuming", height);
}

bool chain_evidence_controller_record_finalized_tip(
    struct chain_evidence_controller *authority,
    struct block_index *finalized_tip,
    const char *reason)
{
    if (!authority || !authority->ndb || !finalized_tip ||
        !finalized_tip->phashBlock || finalized_tip->nHeight < 0) {
        LOG_WARN("cec",
                 "[cec] record_finalized_tip: null/invalid arg "
                 "(authority=%d ndb=%d tip=%d) reason=%s",
                 authority != NULL, authority && authority->ndb,
                 finalized_tip != NULL, reason ? reason : "");
        return false;
    }

    /* A frozen controller is in a genuine contradiction state; the boot
     * reconcile owns lifting it. Do not paper over it from the hot path —
     * EXCEPT a demonstrably-reconciled boot-transient tip divergence:
     * if the reducer has finalized this exact tip and the live csr tip now
     * agrees, the contradiction is provably gone, so self-clear and fall
     * through to publish honest evidence. Every other freeze — and any
     * unreconciled divergence — still declines and keeps paging; the
     * condition's witness (state!=FROZEN) auto-clears only after a real lift. */
    if (authority->state == CEC_CONTRADICTION_FROZEN) {
        if (!cec_boot_tip_divergence_resolved(authority, finalized_tip))
            return false;  // raw-return-ok:fail-closed-predicate-still-frozen-keeps-paging
        cec_lift_boot_tip_divergence_freeze(authority, finalized_tip->nHeight);
    }

    /* Cheap idempotence: the served tip re-finalizes the SAME height on a
     * held frontier and post_finalize fires once per published block, so the
     * persisted hash usually already equals this tip. Skip the node.db write
     * (and the per-call WARN-free path) when nothing changed — this keeps a
     * steady at-tip node from rewriting the cec.* keys every tick. The
     * repaired marker must already be set, else a prior promote_tip write
     * (which leaves it 0) would be skipped and the reconcile idempotence
     * check below would never converge. */
    struct uint256 persisted_hash;
    if (cla_load_u256(authority->ndb, "cec.active_tip_hash", &persisted_hash) &&
        memcmp(persisted_hash.data, finalized_tip->phashBlock->data, 32) == 0 &&
        cla_state_get_i32(authority->ndb, "cec.active_tip_height", -1) ==
            finalized_tip->nHeight &&
        cla_state_get_i32(authority->ndb,
                          "cec.repaired_active_tip_evidence", 0) == 1) {
        /* Persisted evidence already names this exact tip — still keep the
         * in-memory coins cursor aligned (it is set per-process, not
         * persisted, so a fresh boot reconcile may have left it behind). */
        (void)csr_align_coins_best_block(authority->csr,
                                         finalized_tip->phashBlock);
        return true;
    }

    /* Honest forward evidence: the reducer SELECTED this tip (best work,
     * ancestry-linked) and APPLIED its UTXOs, so ancestry + chainwork are
     * proven. Leave bytes/nakamoto/utxo-sha3 flags false — background
     * validation upgrades them. Byte-identical to the reconcile reconstruct
     * record so boot idempotence accepts it. */
    struct chain_evidence_record forward = {
        .source_class = CEC_SOURCE_CLASS_LOCAL_IMPORT,
        .publish_state = CEC_PUBLISH_LOCAL_EVIDENCE,
        .header_ancestry_linked = true,
        .chainwork_recomputed = true,
    };

    /* Align the in-memory coins-view best-block cursor with the served tip
     * BEFORE deriving the coins-height twin. On the linear forward path the
     * served tip IS the applied coins frontier (the reducer finalizes height
     * H only after utxo_apply applied through it), so the cursor should
     * advance with the tip. Doing it first also makes Guard A's
     * frontier clamp a no-op (coins == tip) instead of pinning the persisted
     * cec.coins_best_block_height at the STALE boot cursor height — that
     * staleness is the csr_cursor_mismatch / coins_best_block_height freeze
     * this follow exists to prevent. The write is serialized under csr->lock
     * against a concurrent csr_snapshot reader. */
    (void)csr_align_coins_best_block(authority->csr, finalized_tip->phashBlock);

    int coins_height = chain_evidence_clamp_coins_height_to_frontier(
        authority, finalized_tip->nHeight);

    bool persisted =
        chain_evidence_controller_mark_block_evidence(
            authority, finalized_tip->phashBlock, &forward).ok &&
        chain_evidence_state_set_retry(
            authority->ndb, "cec.active_tip_hash",
            finalized_tip->phashBlock->data, 32,
            "chain_evidence_record_finalized_tip").ok &&
        chain_evidence_state_set_int_retry(
            authority->ndb, "cec.active_tip_height",
            finalized_tip->nHeight,
            "chain_evidence_record_finalized_tip").ok &&
        chain_evidence_state_set_int_retry(
            authority->ndb, "cec.coins_best_block_height",
            coins_height, "chain_evidence_record_finalized_tip").ok &&
        chain_evidence_state_set_int_retry(
            authority->ndb, "cec.utxo_max_height",
            finalized_tip->nHeight,
            "chain_evidence_record_finalized_tip").ok &&
        chain_evidence_state_set_int_retry(
            authority->ndb, "cec.publish_state",
            CEC_PUBLISH_LOCAL_EVIDENCE,
            "chain_evidence_record_finalized_tip").ok &&
        chain_evidence_state_set_int_retry(
            authority->ndb, "cec.active_tip_source_class",
            CEC_SOURCE_CLASS_LOCAL_IMPORT,
            "chain_evidence_record_finalized_tip").ok &&
        chain_evidence_state_set_int_retry(
            authority->ndb, "cec.repaired_active_tip_evidence", 1,
            "chain_evidence_record_finalized_tip").ok &&
        chain_evidence_store_persist(authority,
                                     "cec.block_index_evidence_state",
                                     &forward).ok &&
        chain_evidence_store_persist(authority, "cec.active_tip_evidence",
                                     &forward).ok;

    if (!persisted) {
        /* Transient (sqlite contention). Loud, but NOT a freeze and NOT a
         * blocker — the reducer already published the tip; only the durable
         * evidence follow lagged. Next finalize retries. Throttle so a
         * sustained miss does not storm the log every published block. */
        static _Atomic int64_t g_last_warn_unix;
        int64_t now = platform_time_wall_unix();
        int64_t prev = atomic_load(&g_last_warn_unix);
        if (now - prev >= 5 &&
            atomic_compare_exchange_strong(&g_last_warn_unix, &prev, now))
            LOG_WARN("cec",
                     "[cec] record_finalized_tip: persist miss h=%d reason=%s "
                     "— served tip advanced, durable evidence follow lagged; "
                     "health degrades honestly, retrying next finalize",
                     finalized_tip->nHeight, reason ? reason : "");
        return false;
    }

    return true;
}
