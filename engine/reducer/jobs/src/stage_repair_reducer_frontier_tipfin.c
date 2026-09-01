/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stage_repair_reducer_frontier_tipfin — FIX-1: hash-bound tip_finalize_log
 * hole backfill (row-only repair, runs before the L1 coin-tear refusal).
 *
 * The failure class this repairs: a rowless tip_finalize_log span [H*+1 .. served_floor)
 * pins H* while every upstream log (including utxo_apply_log — coins DID
 * apply those heights) is ok=1 through the span. Re-finalizing instead was
 * REJECTED: clamping tip_finalize back trips the live-UTXO-count check
 * (tip_finalize_stage.c:479-498), manufacturing utxo_count_diverged ok=0
 * evidence rows that pin H* permanently, and active_chain_move_window_tip
 * (:508) would regress the public tip below served finality. The honest
 * repair is the bookkeeping row itself: an ok=1 row above H (the served-floor
 * anchor) plus all-five-logs ok=1 AT H proves the pipeline advanced through
 * H; only the tip_finalize row is missing.
 *
 * Guard ladder (each refusal is one named LOG_WARN; see tipfin_refuse):
 *   G2 pin identification — the row at p = H*+1 must be ABSENT (tri-state,
 *      reducer_frontier.c LOG_ROW semantics). An ok=0 row is EVIDENCE.
 *   G3 unique binder — all five other logs ok=1 at p, validate vs script
 *      hashes at p agree (both 32B). A miss below the coins frontier is L2.
 *   G4 below served finality — p < served_floor, STRICT.
 *   G5 hash evidence for the row (row-H -> hash-H+1) — the validate/script
 *      dual binder at p+1, both ok=1, both 32B, equal; durable logs only.
 *   G6 write — log_insert(p, "finalize_backfill", ok=1, ...) with the ABSENT
 *      re-check inside the BEGIN IMMEDIATE tx (OR REPLACE never clobbers).
 *   G7 one-shot span marker keyed on the SPAN start; multi-tick resume rides
 *      the W witness record, not the marker.
 *   W  witness record repair_marker(tipfin_backfill.progress) =
 *      [last_backfilled_height i32 LE][total_count u32 LE], UPSERTed in the
 *      batch tx and DELETED in the tx that exhausts the span.
 *
 * INVARIANTS: inserts only (the sole deletion is the witness record above);
 * no cursor/coins/tip write; never writes at/above served_floor or where any
 * row exists. A 'finalize_backfill' row is inert: not is_anchor, and
 * finalized_row_active_match treats its lookahead hash like a finalized row. */

#include "stage_repair_reducer_frontier_internal.h"
#include "tip_finalize_log_store.h"

#include "jobs/stage_repair.h"
#include "jobs/mint_skip_crypto.h"

#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "storage/progress_store.h"
#include "storage/repair_marker.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Singleton resume witness: repair_marker at a fixed (kind, height=0, hash). */
#define TIPFIN_WITNESS_KIND REPAIR_MARKER_KIND_TIPFIN_PROGRESS
static const uint8_t TIPFIN_WITNESS_ZERO_HASH[32] = {0};
#define TIPFIN_BATCH_CAP 256

#define TIPFIN_REFUSED_NONE STAGE_REPAIR_TIPFIN_REFUSED_NONE
#define TIPFIN_REFUSED_G1_COIN_UNKNOWN \
    STAGE_REPAIR_TIPFIN_REFUSED_G1_COIN_UNKNOWN
#define TIPFIN_REFUSED_G2_EVIDENCE_ROW \
    STAGE_REPAIR_TIPFIN_REFUSED_G2_EVIDENCE_ROW
#define TIPFIN_REFUSED_G2_ROW_PRESENT \
    STAGE_REPAIR_TIPFIN_REFUSED_G2_ROW_PRESENT
#define TIPFIN_REFUSED_G3_MISSING_EVIDENCE \
    STAGE_REPAIR_TIPFIN_REFUSED_G3_MISSING_EVIDENCE
#define TIPFIN_REFUSED_G4_AT_SERVED_FLOOR \
    STAGE_REPAIR_TIPFIN_REFUSED_G4_AT_SERVED_FLOOR
#define TIPFIN_REFUSED_G5_BINDER_MISSING \
    STAGE_REPAIR_TIPFIN_REFUSED_G5_BINDER_MISSING
#define TIPFIN_REFUSED_G6_IN_TX_RECHECK \
    STAGE_REPAIR_TIPFIN_REFUSED_G6_IN_TX_RECHECK
#define TIPFIN_REFUSED_G7_MARKER_SEEN \
    STAGE_REPAIR_TIPFIN_REFUSED_G7_MARKER_SEEN
#define TIPFIN_REFUSED_HSTAR_RANGE STAGE_REPAIR_TIPFIN_REFUSED_HSTAR_RANGE

/* Tri-state row read, reducer_frontier.c:25-29 semantics. */
enum tipfin_row_state {
    TIPFIN_ROW_ABSENT = 0,
    TIPFIN_ROW_OK,
    TIPFIN_ROW_FAIL,
};

enum tipfin_p_verdict {
    TIPFIN_P_WRITE = 0,  /* G2-G5 all pass — write the row at p */
    TIPFIN_P_SPAN_END,   /* row exists at p, or p at/above served_floor */
    TIPFIN_P_BLOCKED,    /* evidence missing (G3/G5) — stop, keep witness */
};

struct tipfin_p_eval {
    enum tipfin_p_verdict verdict;
    enum stage_repair_tipfin_refused_reason reason;  /* code when not WRITE */
    const char *guard;        /* guard NAME for the refusal WARN */
    const char *binding_log;  /* log naming the refusal, or NULL */
    int binding_height;
    struct uint256 tip_hash;  /* the G5 binder hash; valid when WRITE */
};

static int tipfin_refused_log_code(const char *binding_log)
{
    if (!binding_log)
        return STAGE_REPAIR_TIPFIN_LOG_UNKNOWN;
    if (strcmp(binding_log, "validate_headers_log") == 0)
        return STAGE_REPAIR_TIPFIN_LOG_VALIDATE_HEADERS;
    if (strcmp(binding_log, "script_validate_log") == 0)
        return STAGE_REPAIR_TIPFIN_LOG_SCRIPT_VALIDATE;
    if (strcmp(binding_log, "validate_headers_log/script_validate_log split")
            == 0)
        return STAGE_REPAIR_TIPFIN_LOG_VALIDATE_SCRIPT_SPLIT;
    if (strcmp(binding_log, "body_persist_log") == 0)
        return STAGE_REPAIR_TIPFIN_LOG_BODY_PERSIST;
    if (strcmp(binding_log, "proof_validate_log") == 0)
        return STAGE_REPAIR_TIPFIN_LOG_PROOF_VALIDATE;
    if (strcmp(binding_log, "utxo_apply_log") == 0)
        return STAGE_REPAIR_TIPFIN_LOG_UTXO_APPLY;
    if (strcmp(binding_log, "tip_finalize_log") == 0)
        return STAGE_REPAIR_TIPFIN_LOG_TIP_FINALIZE;
    if (strcmp(binding_log, "header_admit_log") == 0)
        return STAGE_REPAIR_TIPFIN_LOG_HEADER_ADMIT;
    return STAGE_REPAIR_TIPFIN_LOG_UNKNOWN;
}

static bool tipfin_row_state_at(sqlite3 *db, int height,
                                enum tipfin_row_state *out)
{
    *out = TIPFIN_ROW_ABSENT;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT ok FROM tip_finalize_log WHERE height = ?",
            -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL("stage_repair",
                 "tipfin row state prepare failed h=%d: %s",
                 height, sqlite3_errmsg(db));
    sqlite3_bind_int(st, 1, height);
    bool rc_ok = true;
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        if (sqlite3_column_type(st, 0) != SQLITE_INTEGER ||
            (sqlite3_column_int(st, 0) != 0 &&
             sqlite3_column_int(st, 0) != 1)) {
            LOG_WARN("stage_repair",
                     "[stage_repair] malformed tipfin ok storage h=%d",
                     height);
            rc_ok = false;
        } else {
            *out = sqlite3_column_int(st, 0) == 1 ? TIPFIN_ROW_OK
                                                   : TIPFIN_ROW_FAIL;
        }
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("stage_repair",
                 "[stage_repair] tipfin row state step failed h=%d rc=%d: %s",
                 height, rc, sqlite3_errmsg(db));
        rc_ok = false;
    }
    sqlite3_finalize(st);
    return rc_ok;
}

/* `table` is always a fixed literal below (never caller input). */
static bool tipfin_log_ok_at(sqlite3 *db, const char *table, int height,
                             bool *found, bool *ok)
{
    *found = false;
    *ok = false;
    char sql[128];
    bool profile_bound = strcmp(table, "proof_validate_log") == 0 ||
                         strcmp(table, "utxo_apply_log") == 0;
    int n = snprintf(sql, sizeof(sql),
                     "SELECT ok%s FROM %s WHERE height = ?",
                     profile_bound ? ", status" : "", table);
    if (n < 0 || n >= (int)sizeof(sql))
        LOG_FAIL("stage_repair", "tipfin log_ok sql overflow table=%s", table);

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL("stage_repair", "tipfin log_ok prepare failed table=%s: %s",
                 table, sqlite3_errmsg(db));
    sqlite3_bind_int(st, 1, height);
    bool rc_ok = true;
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        *found = true;
        *ok = sqlite3_column_type(st, 0) == SQLITE_INTEGER &&
              sqlite3_column_int(st, 0) == 1;
        if (*ok && profile_bound) {
            int status_type = sqlite3_column_type(st, 1);
            const void *status = status_type == SQLITE_TEXT
                ? sqlite3_column_text(st, 1) : NULL;
            *ok = status &&
                mint_validation_evidence_parse(
                    status, (size_t)sqlite3_column_bytes(st, 1)) ==
                    MINT_VALIDATION_EVIDENCE_VERIFIED;
        }
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("stage_repair",
                 "[stage_repair] tipfin log_ok step failed table=%s h=%d "
                 "rc=%d: %s",
                 table, height, rc, sqlite3_errmsg(db));
        rc_ok = false;
    }
    sqlite3_finalize(st);
    return rc_ok;
}

/* *ok_hash is true only when the row exists with ok=1 AND a 32-byte hash. */
static bool tipfin_log_ok_hash_at(sqlite3 *db, const char *table,
                                  const char *hash_col, int height,
                                  uint8_t out_hash[32], bool *ok_hash)
{
    *ok_hash = false;
    char sql[160];
    bool profile_bound = strcmp(table, "script_validate_log") == 0 ||
                         strcmp(table, "proof_validate_log") == 0;
    int n = snprintf(sql, sizeof(sql),
                     "SELECT ok, %s%s FROM %s WHERE height = ?",
                     hash_col, profile_bound ? ", status" : "", table);
    if (n < 0 || n >= (int)sizeof(sql))
        LOG_FAIL("stage_repair", "tipfin hash sql overflow table=%s", table);

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL("stage_repair", "tipfin hash prepare failed table=%s: %s",
                 table, sqlite3_errmsg(db));
    sqlite3_bind_int(st, 1, height);
    bool rc_ok = true;
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        int hash_type = sqlite3_column_type(st, 1);
        const void *blob = hash_type == SQLITE_BLOB
            ? sqlite3_column_blob(st, 1) : NULL;
        int blen = blob ? sqlite3_column_bytes(st, 1) : 0;
        bool profile_ok = true;
        if (profile_bound) {
            int status_type = sqlite3_column_type(st, 2);
            const void *status = status_type == SQLITE_TEXT
                ? sqlite3_column_text(st, 2) : NULL;
            profile_ok = status &&
                mint_validation_evidence_parse(
                    status, (size_t)sqlite3_column_bytes(st, 2)) ==
                    MINT_VALIDATION_EVIDENCE_VERIFIED;
        }
        if (sqlite3_column_type(st, 0) == SQLITE_INTEGER &&
            sqlite3_column_int(st, 0) == 1 && profile_ok &&
            blob && blen == 32) {
            memcpy(out_hash, blob, 32);
            *ok_hash = true;
        }
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("stage_repair",
                 "[stage_repair] tipfin hash step failed table=%s h=%d "
                 "rc=%d: %s",
                 table, height, rc, sqlite3_errmsg(db));
        rc_ok = false;
    }
    sqlite3_finalize(st);
    return rc_ok;
}

/* Read a hash-only selected-chain row (header_admit has no ok column). */
static bool tipfin_plain_hash_at(sqlite3 *db, const char *table,
                                const char *hash_col, int height,
                                uint8_t out_hash[32], bool *found)
{
    *found = false;
    char sql[128];
    int n = snprintf(sql, sizeof(sql),
                     "SELECT %s FROM %s WHERE height = ?", hash_col, table);
    if (n < 0 || n >= (int)sizeof(sql))
        LOG_FAIL("stage_repair", "tipfin plain hash SQL overflow");
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL("stage_repair", "tipfin plain hash prepare failed: %s",
                 sqlite3_errmsg(db));
    sqlite3_bind_int(st, 1, height);
    bool rc_ok = true;
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        int type = sqlite3_column_type(st, 0);
        const void *blob = type == SQLITE_BLOB
            ? sqlite3_column_blob(st, 0) : NULL;
        if (blob && sqlite3_column_bytes(st, 0) == 32) {
            memcpy(out_hash, blob, 32);
            *found = true;
        }
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("stage_repair", "tipfin plain hash step failed h=%d: %s",
                 height, sqlite3_errmsg(db));
        rc_ok = false;
    }
    sqlite3_finalize(st);
    return rc_ok;
}

/* A UTXO verdict is branch-bound only through its transactionally co-written
 * delta row.  Require both the exact verified log and a BLOB32 branch hash. */
static bool tipfin_utxo_ok_hash_at(sqlite3 *db, int height,
                                   uint8_t out_hash[32], bool *ok_hash)
{
    *ok_hash = false;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT u.ok,u.status,d.branch_hash FROM utxo_apply_log u "
            "LEFT JOIN utxo_apply_delta d ON d.height=u.height "
            "WHERE u.height=?", -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL("stage_repair", "tipfin UTXO binder prepare failed: %s",
                 sqlite3_errmsg(db));
    sqlite3_bind_int(st, 1, height);
    bool rc_ok = true;
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        int ok_type = sqlite3_column_type(st, 0);
        int status_type = sqlite3_column_type(st, 1);
        int hash_type = sqlite3_column_type(st, 2);
        const void *status = status_type == SQLITE_TEXT
            ? sqlite3_column_text(st, 1) : NULL;
        const void *hash = hash_type == SQLITE_BLOB
            ? sqlite3_column_blob(st, 2) : NULL;
        bool verified = status && mint_validation_evidence_parse(
            status, (size_t)sqlite3_column_bytes(st, 1)) ==
            MINT_VALIDATION_EVIDENCE_VERIFIED;
        if (ok_type == SQLITE_INTEGER && sqlite3_column_int(st, 0) == 1 &&
            verified && hash && sqlite3_column_bytes(st, 2) == 32) {
            memcpy(out_hash, hash, 32);
            *ok_hash = true;
        }
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("stage_repair", "tipfin UTXO binder step failed h=%d: %s",
                 height, sqlite3_errmsg(db));
        rc_ok = false;
    }
    sqlite3_finalize(st);
    return rc_ok;
}

/* The validate/script dual binder at `height`: both rows ok=1 with 32-byte
 * hashes that AGREE. On a miss, *missing_log names the failing side. */
static bool tipfin_dual_binder_at(sqlite3 *db, int height, bool *bound,
                                  struct uint256 *hash_out,
                                  const char **missing_log)
{
    *bound = false;
    *missing_log = NULL;
    uint8_t vh[32], hh[32], sh[32];
    bool v_ok = false, h_ok = false, s_ok = false;
    if (!tipfin_log_ok_hash_at(db, "validate_headers_log", "hash", height,
                               vh, &v_ok))
        return false;
    if (!v_ok) {
        *missing_log = "validate_headers_log";
        return true;
    }
    if (!tipfin_plain_hash_at(db, "header_admit_log", "hash", height,
                              hh, &h_ok))
        return false;
    if (!h_ok || memcmp(vh, hh, 32) != 0) {
        *missing_log = "header_admit_log";
        return true;
    }
    if (!tipfin_log_ok_hash_at(db, "script_validate_log", "block_hash",
                               height, sh, &s_ok))
        return false;
    if (!s_ok) {
        *missing_log = "script_validate_log";
        return true;
    }
    if (memcmp(vh, sh, 32) != 0) {
        *missing_log = "validate_headers_log/script_validate_log split";
        return true;
    }
    if (hash_out)
        memcpy(hash_out->data, vh, 32);
    *bound = true;
    return true;
}

/* The G2-G5 ladder for one height. Returns false only on a DB read error. */
static bool tipfin_eval_p(sqlite3 *db, int p, int served_floor,
                          struct tipfin_p_eval *ev)
{
    memset(ev, 0, sizeof(*ev));
    ev->verdict = TIPFIN_P_BLOCKED;
    ev->binding_height = p;

    /* G2 — pin identification: the row at p must be ABSENT. */
    enum tipfin_row_state row;
    if (!tipfin_row_state_at(db, p, &row))
        return false;
    if (row != TIPFIN_ROW_ABSENT) {
        ev->verdict = TIPFIN_P_SPAN_END;
        if (row == TIPFIN_ROW_FAIL) {
            ev->reason = TIPFIN_REFUSED_G2_EVIDENCE_ROW;
            ev->guard = "G2_evidence_row";
        } else {
            ev->reason = TIPFIN_REFUSED_G2_ROW_PRESENT;
            ev->guard = "G2_row_present";
        }
        ev->binding_log = "tip_finalize_log";
        return true;
    }

    /* G3 — unique binder at p: five logs ok=1, validate/script hashes at p
     * agree. A miss below the coins frontier is the L2 refusal domain; the
     * refusal names the binding log + height (delta rows feed conservation
     * utxo_apply_sums_through and rewindability — never fabricated here). */
    bool bound = false;
    const char *missing = NULL;
    struct uint256 at_p;
    if (!tipfin_dual_binder_at(db, p, &bound, &at_p, &missing))
        return false;
    if (!bound) {
        ev->reason = TIPFIN_REFUSED_G3_MISSING_EVIDENCE;
        ev->guard = "G3_missing_evidence";
        ev->binding_log = missing;
        return true;
    }
    static const char *const k_simple_logs[] = { "body_persist_log" };
    for (size_t i = 0; i < sizeof(k_simple_logs) / sizeof(k_simple_logs[0]);
         i++) {
        bool found = false, okrow = false;
        if (!tipfin_log_ok_at(db, k_simple_logs[i], p, &found, &okrow))
            return false;
        if (!found || !okrow) {
            ev->reason = TIPFIN_REFUSED_G3_MISSING_EVIDENCE;
            ev->guard = "G3_missing_evidence";
            ev->binding_log = k_simple_logs[i];
            return true;
        }
    }
    uint8_t proof_hash[32];
    bool proof_ok = false;
    if (!tipfin_log_ok_hash_at(db, "proof_validate_log", "block_hash", p,
                               proof_hash, &proof_ok))
        return false;
    if (!proof_ok || memcmp(proof_hash, at_p.data, 32) != 0) {
        ev->reason = TIPFIN_REFUSED_G3_MISSING_EVIDENCE;
        ev->guard = "G3_missing_evidence";
        ev->binding_log = "proof_validate_log";
        return true;
    }
    uint8_t utxo_hash[32];
    bool utxo_ok = false;
    if (!tipfin_utxo_ok_hash_at(db, p, utxo_hash, &utxo_ok))
        LOG_FAIL("stage_repair", "tipfin UTXO binder read failed h=%d", p);
    if (!utxo_ok || memcmp(utxo_hash, at_p.data, 32) != 0) {
        ev->reason = TIPFIN_REFUSED_G3_MISSING_EVIDENCE;
        ev->guard = "G3_missing_evidence";
        ev->binding_log = "utxo_apply_log";
        return true;
    }

    /* G4 — STRICTLY below served finality: never write at/above the tip. */
    if (p >= served_floor) {
        ev->verdict = TIPFIN_P_SPAN_END;
        ev->reason = TIPFIN_REFUSED_G4_AT_SERVED_FLOOR;
        ev->guard = "G4_at_served_floor";
        ev->binding_log = "tip_finalize_log";
        return true;
    }

    /* G5 — hash evidence for the ROW (row-H -> hash-H+1 convention). The
     * boundary p+1 == coins_applied is resolved by ORDERING (FIX-2a refills
     * the script/proof rows first), never by weakening this dual binding. */
    bound = false;
    missing = NULL;
    if (!tipfin_dual_binder_at(db, p + 1, &bound, &ev->tip_hash, &missing))
        return false;
    if (!bound) {
        ev->reason = TIPFIN_REFUSED_G5_BINDER_MISSING;
        ev->guard = "G5_binder_missing";
        ev->binding_log = missing;
        ev->binding_height = p + 1;
        return true;
    }

    ev->verdict = TIPFIN_P_WRITE;
    return true;
}

/* Storm-safe refusal diagnostics: WARN on (guard, height) TRANSITION,
 * carrying the suppressed-repeat count; the first occurrence is never
 * suppressed. The L1 reconcile path is serialized (condition-engine tick
 * under progress_store_tx_lock), so plain statics are safe. */
static void tipfin_refuse(struct stage_reducer_frontier_reconcile_result *out,
                          enum stage_repair_tipfin_refused_reason reason,
                          const char *guard, const char *binding_log,
                          int height)
{
    static const char *s_last_guard = NULL;
    static int s_last_height = -1;
    static unsigned long long s_reps = 0;

    out->tipfin_backfill_refused_reason = (int)reason;
    out->tipfin_backfill_refused_height = height;
    out->tipfin_backfill_refused_log = tipfin_refused_log_code(binding_log);
    if (guard == s_last_guard && height == s_last_height) {
        s_reps++;
        return;
    }
    unsigned long long suppressed = s_reps;
    s_last_guard = guard;
    s_last_height = height;
    s_reps = 0;
    LOG_WARN("stage_repair",
             "[stage_repair] tipfin backfill refused guard=%s reason=%d "
             "binding_log=%s height=%d hstar=%d served_floor=%d "
             "coins_applied=%d (suppressed_repeats_of_prior=%llu)",
             guard, (int)reason, binding_log ? binding_log : "-", height,
             out->hstar, out->served_floor, out->coins_applied_height,
             suppressed);
}

/* W — witness record codec: [last_backfilled_height i32 LE][total u32 LE]. */
static void tipfin_witness_encode(uint8_t buf[8], int32_t last, uint32_t total)
{
    for (int i = 0; i < 4; i++)
        buf[i] = (uint8_t)((uint32_t)last >> (8 * i));
    for (int i = 0; i < 4; i++)
        buf[4 + i] = (uint8_t)(total >> (8 * i));
}

static bool tipfin_witness_read(sqlite3 *db, bool *found, int32_t *last,
                                uint32_t *total)
{
    *found = false;
    *last = -1;
    *total = 0;
    uint8_t buf[8] = {0};
    size_t n = 0;
    bool present = false;
    if (!repair_marker_have(db, TIPFIN_WITNESS_KIND, REPAIR_MARKER_TIPFIN_HEIGHT,
                            TIPFIN_WITNESS_ZERO_HASH, &present,
                            buf, sizeof(buf), &n))
        LOG_FAIL("stage_repair", "tipfin witness read failed");
    if (!present)
        return true;
    if (n != sizeof(buf)) {
        LOG_WARN("stage_repair",
                 "[stage_repair] tipfin witness malformed len=%zu "
                 "(expected 8); treating as absent",
                 n);
        return true;
    }
    uint32_t l = 0, t = 0;
    for (int i = 0; i < 4; i++)
        l |= (uint32_t)buf[i] << (8 * i);
    for (int i = 0; i < 4; i++)
        t |= (uint32_t)buf[4 + i] << (8 * i);
    *last = (int32_t)l;
    *total = t;
    *found = true;
    return true;
}

/* G6+G8 — the batch transaction: re-evaluate G2-G5 per height INSIDE the
 * BEGIN IMMEDIATE (the absent re-check), insert hash-bound ok=1 rows up to
 * the cap, then settle the marker + witness in the same tx. Zero-progress
 * returns true with *inserted == 0 (the caller refuses, named). */
static bool tipfin_batch_tx(sqlite3 *db, int span_first, int served_floor,
                            const struct uint256 *marker_hash,
                            uint32_t prior_total,
                            int *inserted, int *last_p, bool *exhausted)
{
    *inserted = 0;
    *last_p = -1;
    *exhausted = false;

    char *err = NULL;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("stage_repair",
                 "[stage_repair] tipfin backfill BEGIN failed: %s",
                 err ? err : "(no message)");
        if (err) sqlite3_free(err);
        return false;
    }

    struct arith_uint256 zero_work;
    arith_uint256_set_u64(&zero_work, 0);

    bool ok = true;
    int p = span_first;
    while (*inserted < TIPFIN_BATCH_CAP) {
        struct tipfin_p_eval ev;
        if (!tipfin_eval_p(db, p, served_floor, &ev)) {
            ok = false;
            break;
        }
        if (ev.verdict == TIPFIN_P_SPAN_END) {
            *exhausted = true;
            break;
        }
        if (ev.verdict == TIPFIN_P_BLOCKED)
            break;
        if (!log_insert(db, p, "finalize_backfill", true, &zero_work, -1, 0,
                        &ev.tip_hash)) {
            ok = false;
            break;
        }
        (*inserted)++;
        *last_p = p;
        p++;
    }

    if (ok && *inserted > 0) {
        if (marker_hash &&
            !stage_reducer_frontier_repair_marker_record_in_tx(
                db, REPAIR_MARKER_KIND_RF_TIPFIN_BACKFILL, span_first,
                marker_hash, "tipfin"))
            ok = false;
        if (ok && *exhausted) {
            /* The ONLY deletion in this repair: its own witness record,
             * in the tx of the batch that exhausts the span. */
            if (!repair_marker_forget_in_tx(db, TIPFIN_WITNESS_KIND,
                                            REPAIR_MARKER_TIPFIN_HEIGHT,
                                            TIPFIN_WITNESS_ZERO_HASH)) {
                LOG_WARN("stage_repair",
                         "[stage_repair] tipfin witness delete failed");
                ok = false;
            }
        } else if (ok) {
            uint8_t buf[8];
            tipfin_witness_encode(buf, (int32_t)*last_p,
                                  prior_total + (uint32_t)*inserted);
            if (!repair_marker_note_in_tx(db, TIPFIN_WITNESS_KIND,
                                          REPAIR_MARKER_TIPFIN_HEIGHT,
                                          TIPFIN_WITNESS_ZERO_HASH, buf,
                                          sizeof(buf))) {
                LOG_WARN("stage_repair",
                         "[stage_repair] tipfin witness write failed");
                ok = false;
            }
        }
    }

    if (!ok || *inserted == 0) {
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        *inserted = 0;
        *last_p = -1;
        *exhausted = false;
        return ok;
    }

    if (sqlite3_exec(db, "COMMIT", NULL, NULL, &err) != SQLITE_OK) {
        LOG_WARN("stage_repair",
                 "[stage_repair] tipfin backfill COMMIT failed: %s",
                 err ? err : "(no message)");
        if (err) sqlite3_free(err);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        *inserted = 0;
        *last_p = -1;
        *exhausted = false;
        return false;
    }
    return true;
}

bool stage_reducer_frontier_try_tipfin_backfill(
    sqlite3 *db,
    bool apply,
    struct stage_reducer_frontier_reconcile_result *out,
    bool *handled)
{
    if (!out || !handled)
        LOG_FAIL("stage_repair", "tipfin backfill: NULL out/handled");
    *handled = false;
    out->tipfin_backfill_height = -1;
    out->tipfin_backfill_count = 0;
    out->tipfin_backfill_marker_seen = false;
    out->tipfin_backfill_refused_reason = TIPFIN_REFUSED_NONE;
    out->tipfin_backfill_refused_height = -1;
    out->tipfin_backfill_refused_log = STAGE_REPAIR_TIPFIN_LOG_UNKNOWN;
    if (!db)
        LOG_FAIL("stage_repair", "tipfin backfill: NULL db");

    /* G1 — coin frontier unknown is returned upstream; refuse defensively
     * if reached anyway. */
    if (out->refused_coin_unknown) {
        tipfin_refuse(out, TIPFIN_REFUSED_G1_COIN_UNKNOWN, "G1_coin_unknown",
                      NULL, out->hstar + 1);
        return true;
    }

    /* Scope: the coin-tear pin, OR a tip_finalize-ONLY rowless hole at a REAL
     * anchored frontier (hstar > 0), served_floor > hstar, coins applied THROUGH
     * the span (the live H*-pin class). coins-cover keeps every fill coins-backed;
     * hstar>0 excludes the phantom-0 floor of a fresh datadir (the generic
     * cursor-clamp's domain). G2 guards a real ok=0 row at H*+1. */
    bool tipfin_only_hole = out->hstar > 0 && out->served_floor > out->hstar &&
        out->coins_applied_found &&
        out->coins_applied_height - 1 >= out->served_floor;
    if (!out->refused_coin_tear && !tipfin_only_hole)
        return true;

    if (out->hstar < 0 || out->hstar >= INT32_MAX - 2) {
        tipfin_refuse(out, TIPFIN_REFUSED_HSTAR_RANGE, "hstar_out_of_range",
                      NULL, out->hstar);
        return true;
    }

    progress_store_tx_lock();

    if (!ensure_log_schema(db) || !progress_meta_table_ensure(db) ||
        !repair_marker_table_ensure(db)) {
        progress_store_tx_unlock();
        LOG_FAIL("stage_repair", "tipfin backfill: schema ensure failed");
    }

    int span_first = out->hstar + 1;

    struct tipfin_p_eval ev;
    if (!tipfin_eval_p(db, span_first, out->served_floor, &ev)) {
        progress_store_tx_unlock();
        LOG_FAIL("stage_repair", "tipfin backfill: guard read failed h=%d",
                 span_first);
    }
    if (ev.verdict != TIPFIN_P_WRITE) {
        tipfin_refuse(out, ev.reason, ev.guard, ev.binding_log,
                      ev.binding_height);
        progress_store_tx_unlock();
        return true;  /* zero progress — fall through to the next repair */
    }

    /* W — resume channel. A multi-tick span resumes on the witness record;
     * the G7 marker only gates the SPAN start. */
    bool resuming = false;
    int32_t witness_last = -1;
    uint32_t prior_total = 0;
    if (!tipfin_witness_read(db, &resuming, &witness_last, &prior_total)) {
        progress_store_tx_unlock();
        return false;
    }
    if (resuming && witness_last + 1 != span_first) {
        LOG_WARN("stage_repair",
                 "[stage_repair] tipfin witness resume skew last=%d "
                 "span_first=%d (H* recompute moved the pin; treating "
                 "witness as stale and restarting marker gate)",
                 witness_last, span_first);
        resuming = false;
        witness_last = -1;
        prior_total = 0;
    }

    if (!resuming) {
        bool seen = false;
        if (!stage_reducer_frontier_repair_marker_seen(
                db, REPAIR_MARKER_KIND_RF_TIPFIN_BACKFILL, span_first,
                &ev.tip_hash, "tipfin", &seen)) {
            progress_store_tx_unlock();
            return false;
        }
        if (seen) {
            out->tipfin_backfill_marker_seen = true;
            tipfin_refuse(out, TIPFIN_REFUSED_G7_MARKER_SEEN,
                          "G7_marker_seen", "tip_finalize_log", span_first);
            progress_store_tx_unlock();
            return true;
        }
    }

    if (!apply) {
        progress_store_tx_unlock();
        out->repaired = true;
        out->tipfin_backfill_height = span_first;
        *handled = true;
        return true;
    }

    int inserted = 0;
    int last_p = -1;
    bool exhausted = false;
    if (!tipfin_batch_tx(db, span_first, out->served_floor,
                         resuming ? NULL : &ev.tip_hash, prior_total, &inserted,
                         &last_p, &exhausted)) {
        progress_store_tx_unlock();
        return false;
    }
    progress_store_tx_unlock();

    if (inserted == 0) {
        /* The pre-check passed but the in-tx re-check refused (G6). */
        tipfin_refuse(out, TIPFIN_REFUSED_G6_IN_TX_RECHECK,
                      "G6_in_tx_recheck", "tip_finalize_log", span_first);
        return true;
    }

    out->repaired = true;
    out->refused_coin_tear = false;  /* result-reporting only (:449-450) */
    out->tipfin_backfill_height = last_p;
    out->tipfin_backfill_count = inserted;
    *handled = true;
    LOG_WARN("stage_repair",
             "[stage_repair] tipfin backfill repaired rowless span "
             "first=%d last=%d count=%d total=%u exhausted=%d hstar=%d "
             "served_floor=%d coins_applied=%d",
             span_first, last_p, inserted,
             prior_total + (uint32_t)inserted, exhausted ? 1 : 0, out->hstar,
             out->served_floor, out->coins_applied_height);
    return true;
}
