// one-result-type-ok:telemetry-fill-provider — the single exported symbol
// here is wallet_dump_state_fill(), whose bool signature is fixed by the
// frozen telemetry contract (util/telemetry_render.h: a provider fills a typed
// snapshot) and is what tools/scripts/check_dumper_never_blocks.sh scans for by
// name. It owns no orchestration and has no fallible surface to propagate: a
// value it cannot read is recorded IN the snapshot as TELEMETRY_UNAVAILABLE
// with a static reason token, which is strictly more information than a
// zcl_result carries, and the only false return is a NULL argument.

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The `wallet` telemetry domain provider. See services/wallet_telemetry.h for
 * the contract; this file is the implementation of the one function in it.
 *
 * Reading order below matches the field table's group order: projection, then
 * security, then backup. Each group's filler writes every leaf of its group on
 * every path — including the "the subsystem is not here" path, which reports
 * UNAVAILABLE with a static token instead of returning early and leaving the
 * remaining leaves at their zero value. That early return is the exact defect
 * the presence enum exists to make visible, so it is written out longhand
 * rather than short-circuited.
 *
 * THE REASON TOKENS are static, greppable, and stable. An operator or an agent
 * keys on them; they are not prose and must never be formatted at runtime.
 *
 * WHAT IS DELIBERATELY ABSENT. The wallet view projection publishes its
 * address/tx/utxo/note counts only through SELECT COUNT(*) accessors
 * (engine/modules/storage/wallet_projection.h). A collector runs on the RPC/native thread
 * beside the reducer fold and may not pay an unbounded scan, so those counts
 * are NOT read here and the domain carries no note or UTXO count. That is a
 * recorded gap, not an oversight: the fix is an O(1) published counter on the
 * projection, not a scan in this file.
 */

#include "services/wallet_telemetry.h"

#include "platform/time_compat.h"
#include "sapling/sapling_prover.h"
#include "services/utxo_mirror_sync_service.h"
#include "services/wallet_backup_service.h"
#include "storage/wallet_projection.h"
#include "util/log_macros.h"
#include "util/telemetry_render.h"
#include "util/telemetry_snapshots.h"
#include "validation/process_block.h"
#include "wallet/wallet_lock.h"

#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

/* The mirror worker's lifecycle enum as a closed token set. Local rather than
 * borrowed because the service keeps its own name function file-static; the
 * enum itself is the public contract and is what this switches on. */
static const char *wt_mirror_state_token(int state)
{
    switch (state) {
    case UTXO_MIRROR_SYNC_IDLE:    return "idle";
    case UTXO_MIRROR_SYNC_RUNNING: return "running";
    case UTXO_MIRROR_SYNC_STOPPED: return "stopped";
    default:                       return "unrecognized";
    }
}

/* The Sapling checkpoint's boot-load outcome as a closed token set. Same
 * spellings the `sapling_checkpoint` dumper has always emitted, so an operator
 * who knows one surface reads the other without a translation table. */
static const char *wt_ckpt_load_token(int result)
{
    switch (result) {
    case SAPLING_CKPT_LOAD_NONE:      return "none";
    case SAPLING_CKPT_LOAD_ABSENT:    return "absent";
    case SAPLING_CKPT_LOAD_VERIFIED:  return "loaded_verified";
    case SAPLING_CKPT_LOAD_DISCARDED: return "discarded";
    default:                          return "unrecognized";
    }
}

/* ── projection ──────────────────────────────────────────────────────────
 * How current the wallet's own read models are. No amounts: the only numbers
 * here are a cursor distance and two counters. */
static void wt_fill_projection(struct wallet_snapshot *s)
{
    /* An atomic-acquire load inside the projection module; NULL before boot
     * opens it and in every one-shot CLI process. */
    TELEMETRY_SET_BOOL(s, view_projection_open,
                       wallet_projection_current() != NULL,
                       TELEMETRY_SRC_IN_PROCESS);

    struct utxo_mirror_sync_service *m = g_utxo_mirror_sync;
    TELEMETRY_SET_BOOL(s, utxo_mirror_wired, m != NULL,
                       TELEMETRY_SRC_IN_PROCESS);
    if (!m) {
        /* Every remaining leaf of this group is written, so none of them can
         * report the zero that a `return` here would leave behind. */
        TELEMETRY_UNAVAILABLE_LEAF(s, utxo_mirror_state,
                                   "utxo_mirror_not_wired");
        TELEMETRY_UNAVAILABLE_LEAF(s, utxo_mirror_lag_blocks,
                                   "utxo_mirror_not_wired");
        TELEMETRY_UNAVAILABLE_LEAF(s, utxo_mirror_rebuilds_run,
                                   "utxo_mirror_not_wired");
        TELEMETRY_UNAVAILABLE_LEAF(s, utxo_mirror_last_pass_unix,
                                   "utxo_mirror_not_wired");
        TELEMETRY_UNAVAILABLE_LEAF(s, utxo_mirror_last_error_unix,
                                   "utxo_mirror_not_wired");
        return;
    }

    TELEMETRY_SET_TEXT(s, utxo_mirror_state,
                       wt_mirror_state_token(atomic_load(&m->state)),
                       TELEMETRY_SRC_IN_PROCESS);

    /* The two cursors are published independently, so a torn pair can make the
     * difference momentarily negative. A negative lag is not a real state, so
     * it is reported as unavailable with a named reason rather than as a
     * nonsense number a reader would have to know to distrust. */
    int64_t frontier = atomic_load(&m->last_frontier);
    int64_t mirrored = atomic_load(&m->last_mirror_height);
    if (frontier < mirrored)
        TELEMETRY_UNAVAILABLE_LEAF(s, utxo_mirror_lag_blocks,
                                   "mirror_cursors_raced");
    else
        TELEMETRY_SET_I64(s, utxo_mirror_lag_blocks, frontier - mirrored,
                          TELEMETRY_SRC_CACHED_PUBLICATION);

    TELEMETRY_SET_I64(s, utxo_mirror_rebuilds_run,
                      atomic_load(&m->rebuilds_run),
                      TELEMETRY_SRC_CACHED_PUBLICATION);
    TELEMETRY_SET_I64(s, utxo_mirror_last_pass_unix,
                      atomic_load(&m->last_pass_unix),
                      TELEMETRY_SRC_CACHED_PUBLICATION);
    TELEMETRY_SET_I64(s, utxo_mirror_last_error_unix,
                      atomic_load(&m->last_error_unix),
                      TELEMETRY_SRC_CACHED_PUBLICATION);
}

/* ── security ────────────────────────────────────────────────────────────
 * Key-HANDLING posture. Whether the node can spend is published; what it
 * would spend is not, and no accessor reached from here can produce it. */
static void wt_fill_security(struct wallet_snapshot *s)
{
    /* Two short in-memory reads under the wallet-lock module's own mutex: no
     * I/O and no store lock is taken under it. Neither one can echo the
     * passphrase - the module's API exposes only the two booleans. */
    TELEMETRY_SET_BOOL(s, encrypted_at_rest, wallet_lock_encrypted_at_rest(),
                       TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_BOOL(s, keys_unlocked, wallet_lock_is_unlocked(),
                       TELEMETRY_SRC_IN_PROCESS);

    /* A BUILD fact, not a runtime one, and the only pair in this domain that
     * answers identically in the node and in a one-shot CLI process. It
     * reports what this binary can actually do: the default build links the
     * no-proving-backend translation unit and cannot create a Sapling proof
     * at all, so `can_spend_shielded` is false there however the rest of the
     * shielded stack is configured. */
    TELEMETRY_SET_BOOL(s, can_spend_shielded,
                       zclassic_sapling_prover_is_ready(),
                       TELEMETRY_SRC_CONFIG);
    TELEMETRY_SET_TEXT(s, shielded_prover_status,
                       zclassic_sapling_prover_status(),
                       TELEMETRY_SRC_CONFIG);

    struct sapling_ckpt_stats ck;
    memset(&ck, 0, sizeof ck);
    sapling_ckpt_get_stats(&ck);
    TELEMETRY_SET_TEXT(s, sapling_checkpoint_load_result,
                       wt_ckpt_load_token(ck.last_load_result),
                       TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, sapling_checkpoint_write_fails, ck.write_fails,
                      TELEMETRY_SRC_IN_PROCESS);
}

/* ── backup ──────────────────────────────────────────────────────────────
 * Whether a recoverable copy exists and how stale it is. The status snapshot
 * also carries the last backup's path, size and key count; none of those are
 * published here - a path names where the operator's keys are copied, and a
 * key count is a property of what the wallet holds. Existence and age answer
 * the operator's question without either. */
static void wt_fill_backup(struct wallet_snapshot *s, int64_t now_unix)
{
    /* A short mutex over scalar fields, held by the backup service across no
     * I/O; it is the same snapshot the existing wallet_backup dumper and every
     * RPC caller already take, and it is not a store lock. */
    struct wallet_backup_status st;
    memset(&st, 0, sizeof st);
    wallet_backup_status_snapshot(&st);

    TELEMETRY_SET_BOOL(s, backup_thread_running, st.running,
                       TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, backup_runs_total, st.total_runs,
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, backup_failures_total, st.total_failures,
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, backup_tables_verified,
                      (int64_t)st.last_tables_verified,
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(s, backup_wallet_table_count,
                      (int64_t)st.wallet_table_count,
                      TELEMETRY_SRC_IN_PROCESS);

    /* Three distinct answers, kept distinct. No backup has ever succeeded ->
     * an age is meaningless, which is NOT_APPLICABLE and not a failure. The
     * clock is unreadable, or the recorded run is in the future after a wall
     * jump -> UNAVAILABLE, because an age computed from a bad clock is worse
     * than no age. Otherwise the real difference. */
    if (st.last_run_unix <= 0)
        TELEMETRY_NOT_APPLICABLE_LEAF(s, backup_age_seconds,
                                      "no_successful_backup_yet");
    else if (now_unix < 0 || now_unix < st.last_run_unix)
        TELEMETRY_UNAVAILABLE_LEAF(s, backup_age_seconds,
                                   "wall_clock_unusable");
    else
        TELEMETRY_SET_I64(s, backup_age_seconds, now_unix - st.last_run_unix,
                          TELEMETRY_SRC_DERIVED);
}

bool wallet_dump_state_fill(struct wallet_snapshot *snap)
{
    if (!snap)
        LOG_FAIL("wallet_telemetry", "fill: snapshot is NULL");

    /* Zero first: every leaf starts at TELEMETRY_UNSET, so a field this file
     * forgets renders as a counted provider defect instead of a plausible 0. */
    memset(snap, 0, sizeof *snap);

    int64_t now = telemetry_now_unix();
    if (now < 0)
        TELEMETRY_UNAVAILABLE_LEAF(snap, collected_unix,
                                   "wall_clock_unusable");
    else
        TELEMETRY_SET_I64(snap, collected_unix, now, TELEMETRY_SRC_DERIVED);

    wt_fill_projection(snap);
    wt_fill_security(snap);
    wt_fill_backup(snap, now);
    return true;
}
