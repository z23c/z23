/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * checkpoint_header_solution_repair — see
 * conditions/checkpoint_header_solution_repair.h.
 *
 * The app-thread driver of the checkpoint-header-solution cure. The NET-thread
 * mechanism (send the bounded getheaders span, capture the one hash-pinned
 * header) lives in net/checkpoint_header_fetch.c; THIS file owns the trust
 * decision (frozen verify) and the durable persist + pass-record mint, plus the
 * detect/remedy/witness lifecycle and the typed no-peer blocker.
 *
 * CONSENSUS PARITY: nothing here relaxes a check. The persisted solution is
 * hash-pinned to the compiled checkpoint hash (the block hash commits to the
 * Equihash solution) and independently re-run through the frozen Equihash
 * checker before persist; ensure_pass_record then re-validates it a second time
 * before any -4 header-bootstrap anchor is minted.
 *
 * This is a data-SUPPLY rung, not a bad-writer band-aid: the missing datum (the
 * checkpoint header's Equihash solution) is STRUCTURALLY absent from a
 * headers-first artifact (block_index.bin / --importblockindex carry no
 * nSolution), so no writer can produce it locally — a peer is the only source. */

// repair-rung-ok:test_checkpoint_header_solution_repair — data-supply rung, not a
// bad-writer band-aid. The cited test pins the write-time invariant:
// verify_and_persist REFUSES (persists nothing) unless the fetched header
// hash-pins to the compiled checkpoint AND passes the frozen Equihash checker,
// so this rung can never emit an unverified solution.

#include "framework/condition.h"

#include "conditions/checkpoint_header_solution_repair.h"

#include "chain/chainparams.h"                         /* chain_params_get */
#include "chain/checkpoints.h"                          /* get_sha3_utxo_checkpoint */
#include "config/consensus_state_install_runtime.h"     /* header_ready + autodetect */
#include "controllers/agent_controller.h"               /* agent_runtime_context_datadir */
#include "core/uint256.h"
#include "event/event.h"
#include "jobs/stage_repair.h"                           /* header_solution_repair save/available */
#include "jobs/validate_headers_stage.h"                /* has/ensure pass record */
#include "net/checkpoint_header_fetch.h"
#include "net/connman.h"                                 /* connman_get_node_count */
#include "primitives/block.h"                            /* block_header_get_hash */
#include "services/block_row_verify.h"                   /* block_row_verify (frozen) */
#include "services/sync_monitor.h"                       /* main_state + connman */
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "validation/main_state.h"

#include <sqlite3.h>
#include <stdatomic.h>
#include <string.h>

#define CHSR_SUBSYS "condition"
#define CHSR_NAME   "checkpoint_header_solution_repair"
#define CHSR_NO_PEER_BLOCKER_ID "checkpoint_header_solution_no_peer"

#ifdef ZCL_TESTING
static _Atomic(struct main_state *) g_test_ms;
static const char *g_test_datadir;
static _Atomic int g_test_peer_count = -1;
static _Atomic(checkpoint_header_frozen_verify_fn) g_frozen_verify_override;
#endif

/* ── Frozen Equihash verifier (production = block_row_verify) ───────────────── */

static bool chsr_frozen_verify_default(const struct uint256 *expected_hash,
                                       const struct block_header *hdr)
{
    const struct chain_params *cp = chain_params_get();
    if (!cp) {
        LOG_WARN(CHSR_SUBSYS,
                 "[condition:%s] no chain params — cannot frozen-verify the "
                 "checkpoint header solution", CHSR_NAME);
        return false;
    }
    return block_row_verify(expected_hash->data, hdr->nBits, hdr, cp, true) ==
           BLOCK_ROW_VERIFY_OK;
}

static bool chsr_frozen_verify(const struct uint256 *expected_hash,
                               const struct block_header *hdr)
{
#ifdef ZCL_TESTING
    checkpoint_header_frozen_verify_fn ov = atomic_load(&g_frozen_verify_override);
    if (ov)
        return ov(expected_hash, hdr);
#endif
    return chsr_frozen_verify_default(expected_hash, hdr);
}

/* ── The testable trust core ───────────────────────────────────────────────── */

bool checkpoint_header_solution_verify_and_persist(
    struct main_state *ms, int32_t height,
    const struct uint256 *expected_hash, const struct block_header *hdr)
{
    if (!ms || height < 0 || !expected_hash || !hdr) {
        LOG_WARN(CHSR_SUBSYS,
                 "[condition:%s] verify_and_persist: missing args", CHSR_NAME);
        return false;
    }

    /* (1) HASH-PIN before ANY persist. The block hash serialization commits to
     * nSolution, so a header hashing to the compiled checkpoint hash IS the real
     * checkpoint header with its real solution — a peer cannot substitute a
     * different solution without changing the hash. */
    struct uint256 got;
    block_header_get_hash(hdr, &got);
    if (!uint256_eq(&got, expected_hash)) {
        LOG_WARN(CHSR_SUBSYS,
                 "[condition:%s] REFUSED h=%d: fetched header hash != compiled "
                 "checkpoint hash — nothing persisted (peer wasted one header)",
                 CHSR_NAME, height);
        return false;
    }

    /* (2) Frozen Equihash: the solution must pass the frozen PoW + Equihash
     * checker before it is persisted. Belt-and-suspenders over the hash-pin. */
    if (!chsr_frozen_verify(expected_hash, hdr)) {
        LOG_WARN(CHSR_SUBSYS,
                 "[condition:%s] REFUSED h=%d: fetched checkpoint header failed "
                 "the frozen PoW/Equihash check — nothing persisted",
                 CHSR_NAME, height);
        return false;
    }

    /* (3) Persist durably, hash-bound (the save recomputes hash(header)==hash). */
    sqlite3 *db = progress_store_db();
    if (!db) {
        LOG_WARN(CHSR_SUBSYS,
                 "[condition:%s] h=%d: progress store not open — cannot persist",
                 CHSR_NAME, height);
        return false;
    }
    if (!stage_repair_header_solution_save(db, height, expected_hash, hdr)) {
        LOG_WARN(CHSR_SUBSYS,
                 "[condition:%s] h=%d: header_solution_repair persist failed",
                 CHSR_NAME, height);
        return false;
    }

    LOG_INFO(CHSR_SUBSYS,
             "[condition:%s] checkpoint header solution PERSISTED h=%d "
             "(hash-pinned to the compiled checkpoint, frozen-Equihash "
             "verified) — bundle install can now bind", CHSR_NAME, height);

    /* (4) Mint the pass record now (idempotent; ensure_pass_record re-runs the
     * frozen validator over the just-persisted repair row). Fail-open: the
     * durable repair row alone lets a later ensure_pass_record succeed. */
    if (!validate_headers_stage_ensure_pass_record(ms, height))
        LOG_WARN(CHSR_SUBSYS,
                 "[condition:%s] h=%d: pass record not yet minted after persist "
                 "(header index may not resolve here); the durable repair row "
                 "lets a later boot's install mint it", CHSR_NAME, height);
    return true;
}

bool checkpoint_header_solution_available(int32_t height,
                                          const struct uint256 *expected_hash)
{
    if (height < 0 || !expected_hash)
        return false;
    if (validate_headers_stage_has_pass_record(height, expected_hash))
        return true;
    sqlite3 *db = progress_store_db();
    return db && stage_repair_header_solution_available(db, height, expected_hash);
}

/* ── Lifecycle glue ────────────────────────────────────────────────────────── */

static struct main_state *chsr_main_state(void)
{
#ifdef ZCL_TESTING
    struct main_state *t = atomic_load(&g_test_ms);
    if (t)
        return t;
#endif
    struct main_state *ms = sync_monitor_main_state();
    if (!ms)
        ms = condition_engine_main_state();
    return ms;
}

static const char *chsr_datadir(void)
{
#ifdef ZCL_TESTING
    if (g_test_datadir && g_test_datadir[0])
        return g_test_datadir;
#endif
    return agent_runtime_context_datadir();
}

static int chsr_peer_count(void)
{
#ifdef ZCL_TESTING
    int ov = atomic_load(&g_test_peer_count);
    if (ov >= 0)
        return ov;
#endif
    struct connman *cm = sync_monitor_connman();
    return cm ? (int)connman_get_node_count(cm) : 0;
}

static bool chsr_checkpoint_hash(const struct sha3_utxo_checkpoint *cp,
                                 struct uint256 *out)
{
    if (!cp)
        return false; // raw-return-ok:no-compiled-checkpoint-is-normal-not-an-error
    memcpy(out->data, cp->block_hash, 32);
    return true;
}

static bool detect_checkpoint_header_solution_repair(void)
{
    struct main_state *ms = chsr_main_state();
    const char *datadir = chsr_datadir();
    if (!ms || !datadir || !datadir[0])
        return false; // raw-return-ok:runtime-not-wired-detect-poll

    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    struct uint256 cp_hash;
    if (!chsr_checkpoint_hash(cp, &cp_hash))
        return false; // raw-return-ok:no-compiled-checkpoint

    /* Tip position does NOT gate the fetch. A fresh instant-on node is BELOW the
     * checkpoint; the live-cure node sits ABOVE it (e.g. H*=3,176,325 on borrowed
     * shielded state) yet STILL needs the checkpoint header's Equihash solution
     * so the staged consensus bundle can bind (validate_headers_stage_ensure_
     * pass_record(checkpoint) fails no-header-solution-backfill-required on a
     * headers-first substrate whatever the tip height). The staged-bundle
     * predicate below (boot_autodetect_consensus_bundle != NULL) is the real
     * scope: a healthy sovereign node has the marker → autodetect NULL → this
     * short-circuits and no fetch ever arms. */

    /* The header chain must own the checkpoint block so the fetched solution can
     * be validated + a pass record minted against a resolvable index entry. */
    if (!consensus_state_checkpoint_header_ready(ms))
        return false; // raw-return-ok:header-chain-not-yet-at-checkpoint

    /* Only fetch if there is actually a bundle waiting to install. */
    char *bundle = boot_autodetect_consensus_bundle(datadir);
    if (!bundle)
        return false; // raw-return-ok:no-staged-bundle-nothing-to-unblock
    free(bundle);

    /* Nothing to do once the solution is durably available. */
    if (checkpoint_header_solution_available(cp->height, &cp_hash))
        return false; // raw-return-ok:solution-already-durable
    return true;
}

static enum condition_remedy_result remedy_checkpoint_header_solution_repair(void)
{
    struct main_state *ms = chsr_main_state();
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    struct uint256 cp_hash;
    if (!ms || !chsr_checkpoint_hash(cp, &cp_hash))
        return COND_REMEDY_SKIP; // raw-return-ok:runtime-not-wired-this-tick

    /* (1) Did the net-thread fetch capture the checkpoint header? Verify +
     * persist it. */
    struct block_header hdr;
    int32_t captured_h = -1;
    if (checkpoint_header_fetch_take(&hdr, &captured_h)) {
        if (captured_h == cp->height &&
            checkpoint_header_solution_verify_and_persist(ms, cp->height,
                                                          &cp_hash, &hdr)) {
            checkpoint_header_fetch_disarm();
            blocker_clear(CHSR_NO_PEER_BLOCKER_ID);
            event_emitf(EV_RECOVERY_ACTION, 0,
                        "action=checkpoint_header_solution_persisted height=%d",
                        cp->height);
            return COND_REMEDY_OK;
        }
        LOG_WARN(CHSR_SUBSYS,
                 "[condition:%s] captured checkpoint header did not verify "
                 "(wrong hash / bad solution / height mismatch) — refused, will "
                 "re-fetch from another peer", CHSR_NAME);
        /* fall through: re-arm and try again */
    }

    /* (2) Not yet captured — (re-)arm the bounded getheaders span. The net
     * thread sends it to a capable peer; the capture arrives on a later tick. */
    checkpoint_header_fetch_arm(cp->height, &cp_hash);

    int peers = chsr_peer_count();
    if (peers <= 0) {
        struct blocker_record r;
        char reason[BLOCKER_REASON_MAX];
        snprintf(reason, sizeof(reason),
                 "checkpoint header solution h=%d needed to install the staged "
                 "bundle, but no connected peer can serve the getheaders span",
                 cp->height);
        if (blocker_init(&r, CHSR_NO_PEER_BLOCKER_ID, "checkpoint_fetch",
                         BLOCKER_TRANSIENT, reason))
            (void)blocker_set(&r);
        LOG_WARN(CHSR_SUBSYS,
                 "[condition:%s] armed checkpoint-header fetch h=%d but no peer "
                 "(peers=0) — named blocker %s, deferring (cooldown re-arms "
                 "forever, no operator page)",
                 CHSR_NAME, cp->height, CHSR_NO_PEER_BLOCKER_ID);
    } else {
        blocker_clear(CHSR_NO_PEER_BLOCKER_ID);
        LOG_INFO(CHSR_SUBSYS,
                 "[condition:%s] armed checkpoint-header fetch h=%d (peers=%d) — "
                 "awaiting the peer's one-header span reply",
                 CHSR_NAME, cp->height, peers);
    }
    return COND_REMEDY_SKIP;
}

/* Remedy-urgency: a checkpoint header was captured off the net thread and is
 * waiting to be verified + persisted. Consume it on the next engine tick
 * instead of waiting out backoff_secs (up to 30s) — the solution is the last
 * gate before the staged bundle can bind, so every second of that wait is dead
 * time on the cure path. Non-consuming peek; the remedy's take() does the
 * consume + frozen verify. */
static bool urgent_checkpoint_header_solution_repair(void)
{
    return checkpoint_header_fetch_has_capture();
}

static bool witness_checkpoint_header_solution_repair(int64_t target_at_detect)
{
    (void)target_at_detect;
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    struct uint256 cp_hash;
    if (!chsr_checkpoint_hash(cp, &cp_hash))
        return false; // raw-return-ok:no-compiled-checkpoint-witness-cannot-clear
    // honest-witness-ok: NOT poison-absence and NOT an FSM flag. This clears iff
    // a FRESH durable SELECT shows the checkpoint solution landed — a
    // validate_headers_log PASS row OR a hash-bound header_solution_repair row
    // (checkpoint_header_solution_available reads both). That is the exact
    // observable forward fact the remedy produces and the install then binds on.
    return checkpoint_header_solution_available(cp->height, &cp_hash);
}

static struct condition c_checkpoint_header_solution_repair = {
    .name = CHSR_NAME,
    .severity = COND_WARN,
    .poll_secs = 10,
    .backoff_secs = 30,
    .max_attempts = 5,
    /* Continue-with-cooldown: the solution can be un-available purely because
     * no peer is connected yet. cooldown_secs>0 + cooldown_max_rearms==0 re-arm
     * the remedy forever so a peer-absent window keeps retrying (never latches
     * to an operator page on a recoverable cause); the episode resets the
     * instant the solution lands (detect goes false). */
    .cooldown_secs = 300,
    .cooldown_max_rearms = 0,
    .detect = detect_checkpoint_header_solution_repair,
    .remedy = remedy_checkpoint_header_solution_repair,
    .witness = witness_checkpoint_header_solution_repair,
    /* A captured header makes the remedy immediately due — do not wait out the
     * 30s backoff to verify + persist the checkpoint solution. */
    .urgent = urgent_checkpoint_header_solution_repair,
    .witness_window_secs = 30,
};

void register_checkpoint_header_solution_repair(void)
{
    (void)condition_register(&c_checkpoint_header_solution_repair);
}

#ifdef ZCL_TESTING
void checkpoint_header_solution_set_frozen_verifier_for_test(
    checkpoint_header_frozen_verify_fn fn)
{
    atomic_store(&g_frozen_verify_override, fn);
}

void checkpoint_header_solution_repair_test_reset(void)
{
    atomic_store(&g_test_ms, NULL);
    g_test_datadir = NULL;
    atomic_store(&g_test_peer_count, -1);
    atomic_store(&g_frozen_verify_override, NULL);
    checkpoint_header_fetch_disarm();
    blocker_clear(CHSR_NO_PEER_BLOCKER_ID);
    condition_reset_state(&c_checkpoint_header_solution_repair);
}

void checkpoint_header_solution_repair_test_set_main_state(struct main_state *ms)
{
    atomic_store(&g_test_ms, ms);
}

void checkpoint_header_solution_repair_test_set_datadir(const char *datadir)
{
    g_test_datadir = datadir;
}

void checkpoint_header_solution_repair_test_set_peer_count(int n)
{
    atomic_store(&g_test_peer_count, n);
}

bool checkpoint_header_solution_repair_test_detect(void)
{
    return detect_checkpoint_header_solution_repair();
}

int checkpoint_header_solution_repair_test_remedy(void)
{
    return (int)remedy_checkpoint_header_solution_repair();
}
#endif
