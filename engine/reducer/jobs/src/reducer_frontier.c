/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * reducer_frontier — L0 authority. Compute H* and served_floor from
 * durable progress.kv state. See reducer_frontier.h for the contract.
 *
 * PURE SELECT-only: every statement here is a SELECT. There is no INSERT,
 * UPDATE, DELETE, REPLACE, BEGIN, or COMMIT in this translation unit. The
 * raw sqlite3_step sites read the progress.kv kernel store (the same hatch
 * the sibling *_log_store.c readers use) and carry the canonical
 * `// raw-sql-ok:progress-kv-kernel-store` marker. The caller holds
 * progress_store_tx_lock() so the snapshot is internally consistent. */

#include "jobs/reducer_frontier.h"
#include "reducer_frontier_trusted_base_internal.h"

#include "reducer_frontier_evidence.h"
#include "reducer_frontier_self_anchor.h"  /* self-derived anchor sourcing */
#include "reducer_frontier_itag.h"         /* watermark, probe, per-row verdict */
#include "reducer_frontier_stage_cursor_internal.h"  /* F1 derived-reader seam */
#include "jobs/mint_skip_crypto.h"
#include "jobs/refold_progress.h"
#include "chain/chainparams.h"
#include "chain/checkpoints.h"
#include "platform/time_compat.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/boot_scan.h"
#include "util/log_macros.h"
#include "support/log_throttle.h"

#include <sqlite3.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef ZCL_TESTING
/* Test-only override of the compiled SHA3-checkpoint anchor floor. The L0
 * frontier (H*) and the L1 reconcile it gates are clamped to never operate
 * below get_sha3_utxo_checkpoint()->height (mainnet 3,056,758) — a security
 * floor (never reorg/reconcile below a trusted checkpoint). A hermetic regtest
 * harness that drives the REAL reorg re-bind path (purge non-canonical
 * verdicts -> refill -> re-validate) cannot build a contiguous chain to that
 * height, so it lowers this floor and runs the IDENTICAL production logic at
 * testable heights. Sentinel -1 = use the compiled checkpoint (production
 * default; never changed off-test). Mirrored src-private by the test that
 * uses it (the witness/post_remedy_hook pattern). */
static _Atomic int32_t g_test_compiled_anchor_override = -1;

void reducer_frontier_test_set_compiled_anchor(int32_t height);
void reducer_frontier_test_set_compiled_anchor(int32_t height)
{
    atomic_store(&g_test_compiled_anchor_override, height);
}
#endif

/* The compiled anchor floor (the SHA3 UTXO checkpoint height): the minimum
 * height H* and the L1 reconcile may operate at. Single source so a test
 * override (if any) covers every read site identically.
 *
 * NETWORK-DERIVED: the SHA3 UTXO checkpoint is a MAINNET artifact (a specific
 * mainnet block at REDUCER_FRONTIER_TRUSTED_ANCHOR). On testnet/regtest there
 * is no such trusted finality checkpoint, so the floor is genesis (0) — H* may
 * legitimately sit anywhere from genesis up and a low cursor is NOT a defect.
 * Mainnet behavior is byte-identical to before (returns the compiled
 * checkpoint height). The runtime network is read from
 * chain_params_get()->strNetworkID ("main" / "test" / "regtest"). */
static int32_t reducer_frontier_compiled_anchor(void)
{
#ifdef ZCL_TESTING
    int32_t ov = atomic_load(&g_test_compiled_anchor_override);
    if (ov >= 0)
        return ov;
#endif
    /* Non-mainnet networks have no SHA3 UTXO checkpoint: the finality floor is
     * genesis. get_sha3_utxo_checkpoint() returns the compiled MAINNET
     * checkpoint unconditionally, so the network gate must live HERE (not in
     * core/modules/chain). chain_params_get() is always valid post-select (lazy-inits
     * to mainnet), so a NULL strNetworkID never reaches us. */
    const struct chain_params *p = chain_params_get();
    if (p && p->strNetworkID[0] != '\0' &&
        strcmp(p->strNetworkID, "main") != 0)
        return 0;

    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    int32_t compiled = cp ? cp->height : REDUCER_FRONTIER_TRUSTED_ANCHOR;

    /* Prefer a self-derived anchor THIS node folded and hard-verified itself
     * over the baked literal — see the "SELF-DERIVED SOURCING" note on
     * REDUCER_FRONTIER_TRUSTED_ANCHOR above and reducer_frontier_self_anchor.c.
     * Resolved once per process and cached there; every later call is a
     * lock-free atomic load, so this stays cheap exactly like the doc comment
     * on reducer_frontier_floor() promises. */
    int32_t self_derived = reducer_frontier_self_anchor_get(compiled);
    return self_derived >= 0 ? self_derived : compiled;
}

/* The FLOOR H* and the L1 reconcile operate at — see reducer_frontier.h. 0
 * during a from-GENESIS refold; the compiled anchor on a normal boot AND during
 * a from-ANCHOR refold — the from-anchor fold legitimately starts AT the
 * anchor and never re-walks below it, so the floor must stay at the anchor even
 * though refold_in_progress() is true. Floor only, no rule change. */
int32_t reducer_frontier_floor(void)
{
    if (refold_from_anchor_active())
        return reducer_frontier_compiled_anchor();
    return refold_in_progress() ? 0 : reducer_frontier_compiled_anchor();
}

/* The PROVABLE TIP cache (H*) served to external consumers. Init to a -1
 * SENTINEL meaning "not yet published" — NOT the baked finality anchor. The
 * old anchor-init was a PHANTOM on a fresh / empty datadir: tip_finalize never
 * advances there, so the cache stayed at REDUCER_FRONTIER_TRUSTED_ANCHOR and
 * getblockcount falsely reported the anchor height (e.g. 3056758) on a node
 * that has resolved nothing. The accessor maps the sentinel to 0 (honest
 * "nothing proven yet"). On a REAL datadir the first finalize advance /
 * reorg rewind immediately republishes the true H* through
 * reducer_frontier_provable_tip_set (both under progress_store_tx_lock); the
 * brief pre-first-advance boot window now reads 0 instead of the anchor, which
 * is the honest IBD value (we have not proven the anchor on THIS datadir yet).
 * Read lock-free by the external accessors. See reducer_frontier.h. */
#define REDUCER_FRONTIER_TIP_UNPUBLISHED ((int_least32_t)-1)
static _Atomic int_least32_t g_provable_tip = REDUCER_FRONTIER_TIP_UNPUBLISHED;

int32_t reducer_frontier_provable_tip_cached(void)
{
    int_least32_t v = atomic_load(&g_provable_tip);
    /* Never serve the -1 sentinel to a consumer: before the first publish the
     * honest provable height is 0 (nothing folded/finalized yet). */
    return v < 0 ? 0 : (int32_t)v;
}

bool reducer_frontier_provable_tip_is_published(void)
{
    /* True once the provable-tip cache holds a real H* (not the -1 "unpublished"
     * sentinel). Lets the tip_finalize step warm the cache EXACTLY once at boot
     * on a node that comes up already at tip (no finalize advance / reorg rewind
     * to publish through), so getblockcount serves the true height immediately
     * instead of 0 until the next network block. Read lock-free. */
    return atomic_load(&g_provable_tip) >= 0;
}

void reducer_frontier_provable_tip_set(int32_t hstar)
{
    /* Store the value as given: the caller passes a value already produced by
     * reducer_frontier_compute_hstar, whose HARD GUARD clamps it >= the
     * finality anchor on a normal boot (and legitimately below it only during
     * a from-genesis refold, where reporting the folded prefix is correct).
     * Re-clamping here would mask a refold's true (below-anchor) H*. */
    atomic_store(&g_provable_tip, (int_least32_t)hstar);
}

void reducer_frontier_provable_tip_reset(void)
{
    /* Reset to the "not yet published" sentinel (served as 0), mirroring the
     * stage's g_last_advance_height=-1 reset. The next finalize advance
     * republishes the true H*; until then 0 is the honest provable height. */
    atomic_store(&g_provable_tip, REDUCER_FRONTIER_TIP_UNPUBLISHED);
    /* A refold/reorg reset rewrites the fold prefix from the (new) floor, so
     * drop the integrity-tag watermark too: the next fold re-verifies every row
     * it folds rather than trusting a prefix from before the reset. */
    reducer_frontier_itag_watermark_reset();
}

/* Per-row reads return a tri-state so contiguity and discrimination can
 * tell "no row" apart from "ok=0 row". */
enum log_row_state {
    LOG_ROW_ABSENT = 0,   /* no row at this height */
    LOG_ROW_OK,           /* row present, ok=1 */
    LOG_ROW_FAIL,         /* row present, ok=0 (or integrity-tag MISMATCH) */
};

/* Per-row integrity tag (W4-4): each *_log row carries a truncated-SHA3 `itag`
 * (jobs/stage_row_itag.h). The fold below recomputes it — a row whose tag does
 * not verify is treated as NOT ok, so a flipped verdict byte LOWERS H*, never
 * raises it. Watermark/probe/warn: reducer_frontier_itag.[ch]. */

/* The success-checked logs whose contiguous ok=1 prefix bounds H* (C2).
 * Each entry pairs the log table with its stage cursor name (used only for
 * the C1 below-anchor diagnostic). validate_headers and script_validate
 * additionally feed the C3 hash-agreement check below.
 *
 * `served_tip` distinguishes the cursor convention. The upstream reducer
 * stages count the NEXT height to process — cursor U means "rows expected
 * up to U-1; U is the next height". tip_finalize uses the served-tip
 * convention: cursor C means "served tip at C; the C→C+1 transition is
 * pending", so its rows are expected up to C (the anchor row at C plus
 * finalized rows below). frontier_next_cursor() below normalizes
 * tip_finalize's cursor to the upstream "next height" frame (C+1) at every
 * scan/candidate read site, so the contiguity and anchor-candidate algorithms
 * stay identical regardless of the cursor convention. */
struct frontier_log {
    const char *log_table;
    const char *cursor_name;
    bool        served_tip;
};

static const struct frontier_log k_logs[] = {
    { "validate_headers_log", "validate_headers", false },
    { "script_validate_log",  "script_validate",  false },
    { "body_persist_log",     "body_persist",     false },
    { "proof_validate_log",   "proof_validate",   false },
    { "utxo_apply_log",       "utxo_apply",       false },
    { "tip_finalize_log",     "tip_finalize",     true  },
};
static const int k_logs_n = (int)(sizeof(k_logs) / sizeof(k_logs[0]));

static bool log_success_requires_full_validation(const char *table)
{
    return strcmp(table, "script_validate_log") == 0 ||
           strcmp(table, "proof_validate_log") == 0 ||
           strcmp(table, "utxo_apply_log") == 0;
}

/* Normalize a stage cursor to the "next height to process" frame the
 * contiguity / anchor-candidate scans expect. tip_finalize's served-tip
 * cursor C (served tip at C) is equivalent to next-height C+1 (its rows run
 * up to C, the anchor row included); every other stage already counts the
 * next height, so it passes through unchanged. */
static int64_t frontier_next_cursor(const struct frontier_log *fl,
                                    int64_t cursor)
{
    return (fl && fl->served_tip && cursor > 0) ? cursor + 1 : cursor;
}

/* Read the ok column of a *_log row at `height`. *out is set to one of the
 * tri-states. Returns false ONLY on a real SQLite prepare/step error
 * (caller propagates as a DB read failure). A missing row is success with
 * *out = LOG_ROW_ABSENT — that is the contiguity terminator, not an error. */
static bool log_ok_at(sqlite3 *db, const char *log_table, int32_t height,
                      enum log_row_state *out)
{
    *out = LOG_ROW_ABSENT;
    /* log_table is a fixed string from k_logs[] (never caller input), so the
     * concat below cannot inject. Bind the height parameter. */
    char sql[160];
    bool profile_bound = log_success_requires_full_validation(log_table);
    bool have_itag = reducer_frontier_itag_column_present(db, log_table);
    int n = snprintf(sql, sizeof(sql),
                     "SELECT ok%s%s FROM %s WHERE height = ?",
                     profile_bound ? ", status" : "",
                     have_itag ? ", itag" : "", log_table);
    if (n < 0 || n >= (int)sizeof(sql))
        LOG_FAIL("reducer", "log_ok_at sql overflow for table=%s", log_table);

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL("reducer", "prepare %s failed: %s",
                 log_table, sqlite3_errmsg(db));
    sqlite3_bind_int64(st, 1, (sqlite3_int64)height);

    bool rc_ok = true;
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        int ok_raw = sqlite3_column_type(st, 0) == SQLITE_INTEGER
                         ? sqlite3_column_int(st, 0) : 0;
        const void *status = NULL;
        size_t status_len = 0;
        if (profile_bound && sqlite3_column_type(st, 1) == SQLITE_TEXT) {
            status = sqlite3_column_text(st, 1);
            status_len = (size_t)sqlite3_column_bytes(st, 1);
        }
        bool row_ok = ok_raw == 1;
        if (row_ok && profile_bound)
            row_ok = status &&
                mint_validation_evidence_parse(status, status_len) ==
                    reducer_frontier_required_evidence();
        /* Integrity tag (only for a row that would otherwise count): a MISMATCH
         * forces FAIL (corruption LOWERS H*); ABSENT trusts ok but WARNs+counts.
         * UNTAGGED-ROW POLICY lives in reducer_frontier_itag.[ch]. */
        if (have_itag && row_ok) {
            int itag_col = profile_bound ? 2 : 1;
            const void *tag = sqlite3_column_type(st, itag_col) == SQLITE_BLOB
                                  ? sqlite3_column_blob(st, itag_col) : NULL;
            size_t tag_len = tag ? (size_t)sqlite3_column_bytes(st, itag_col) : 0;
            if (reducer_frontier_itag_row_fails(log_table, (int64_t)height,
                                                ok_raw, status, status_len,
                                                tag, tag_len))
                row_ok = false;
        }
        *out = row_ok ? LOG_ROW_OK : LOG_ROW_FAIL;
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("reducer", "step %s at h=%d failed: %s",
                 log_table, height, sqlite3_errmsg(db));
        rc_ok = false;
    }
    sqlite3_finalize(st);
    return rc_ok;
}

/* Walk one success-checked log upward from TRUSTED_ANCHOR+1, returning the
 * deepest height whose [anchor+1 .. h] run is all ok=1 (the contiguous
 * prefix). A missing row, an ok=0 row, OR an integrity-tag MISMATCH terminates
 * the run.
 *
 * `cursor` bounds the scan: rows are only expected up to `cursor-1` (the
 * cursor names the NEXT height to process). If cursor <= TRUSTED_ANCHOR the
 * log holds nothing above the anchor and is trivially consistent there, so
 * h_contiguous stays at the anchor (does not lower H*).
 *
 * `verify_above` is the per-boot integrity-tag watermark: rows at heights
 * <= verify_above were tag-verified on an earlier fold this boot and are
 * trusted (their ok/status is read directly); rows above it are tag-verified
 * now. Pass anchor / a floor to verify the whole scanned range.
 *
 * On a DB read error returns false; *h_contiguous is then meaningless. */
static bool log_contiguous_prefix(sqlite3 *db, const char *log_table,
                                  int32_t anchor, int64_t cursor,
                                  int32_t verify_above,
                                  int32_t *h_contiguous)
{
    int64_t scan_floor =
        reducer_frontier_itag_scan_floor(anchor, cursor, verify_above);
    *h_contiguous = (int32_t)scan_floor;
    if (cursor <= (int64_t)anchor)
        return true;  /* nothing above the anchor to disprove the prefix */
    /* ONE ranged scan instead of a prepare+bind+step PER HEIGHT (measured
     * 53x cheaper; the walk runs full length precisely on HEALTHY nodes,
     * under the global progress lock). `height` is the table's PRIMARY KEY,
     * so rows stream back in strictly increasing height order: the first
     * height JUMP is a hole (a missing row) and the first ok=0 row is a
     * recorded failure — both terminate the contiguous prefix. */
    char sql[192];
    bool profile_bound = log_success_requires_full_validation(log_table);
    bool have_itag = reducer_frontier_itag_column_present(db, log_table);
    int n = snprintf(sql, sizeof(sql),
                     "SELECT height, ok%s%s FROM %s "
                     "WHERE height > ? AND height < ? ORDER BY height",
                     profile_bound ? ", status" : "",
                     have_itag ? ", itag" : "", log_table);
    if (n < 0 || n >= (int)sizeof(sql))
        LOG_FAIL("reducer", "log_contiguous_prefix sql overflow for %s",
                 log_table);

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL("reducer", "prepare %s ranged scan failed: %s",
                 log_table, sqlite3_errmsg(db));
    sqlite3_bind_int64(st, 1, (sqlite3_int64)scan_floor);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)cursor);

    /* O(delta) witness: every row this walk streams from [anchor+1 .. cursor)
     * is one atomic add. On a healthy node the walk runs the FULL span above
     * the trusted anchor, so this counter == (cursor - anchor - 1) per log —
     * the delta above the sealed floor. If a regression drops the anchor back
     * to genesis/compiled-checkpoint on a warm boot, the count balloons to
     * O(chain) and test_boot_odelta_scan fails naming this step. Resolved once
     * per log invocation (8×/compute), NOT per row — the hot loop only bumps. */
    atomic_uint_least64_t *scan_ctr =
        boot_scan_counter("reducer_frontier.contiguity_rows");
    int itag_col = profile_bound ? 3 : 2;  /* only valid when have_itag */
    bool rc_ok = true;
    int64_t expect = scan_floor + 1;
    while (true) {
        int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
        if (rc == SQLITE_ROW) {
            boot_scan_bump(scan_ctr);
            int64_t h = sqlite3_column_int64(st, 0);
            int ok_raw = sqlite3_column_type(st, 1) == SQLITE_INTEGER
                             ? sqlite3_column_int(st, 1) : 0;
            const void *status = NULL;
            size_t status_len = 0;
            if (profile_bound && sqlite3_column_type(st, 2) == SQLITE_TEXT) {
                status = sqlite3_column_text(st, 2);
                status_len = (size_t)sqlite3_column_bytes(st, 2);
            }
            bool row_ok = ok_raw == 1;
            if (row_ok && profile_bound)
                row_ok = status &&
                    mint_validation_evidence_parse(status, status_len) ==
                        reducer_frontier_required_evidence();
            /* Integrity tag: verify rows above the per-boot watermark. A
             * MISMATCH terminates contiguity exactly like an ok=0 row (caps H*,
             * never raises it); an ABSENT (NULL) tag is trusted but WARNed +
             * counted (UNTAGGED-ROW POLICY, reducer_frontier_itag.[ch]). */
            if (row_ok && have_itag && h > (int64_t)verify_above) {
                const void *tag =
                    sqlite3_column_type(st, itag_col) == SQLITE_BLOB
                        ? sqlite3_column_blob(st, itag_col) : NULL;
                size_t tag_len =
                    tag ? (size_t)sqlite3_column_bytes(st, itag_col) : 0;
                if (reducer_frontier_itag_row_fails(log_table, h, ok_raw, status,
                                                    status_len, tag, tag_len))
                    row_ok = false;
            }
            if (h != expect || !row_ok)
                break;  /* hole, ok=0, or tag mismatch — contiguity ends */
            *h_contiguous = (int32_t)h;
            expect++;
        } else if (rc == SQLITE_DONE) {
            break;
        } else {
            LOG_WARN("reducer", "ranged scan %s failed: %s",
                     log_table, sqlite3_errmsg(db));
            rc_ok = false;
            break;
        }
    }
    sqlite3_finalize(st);
    return rc_ok;
}

/* Read the persisted cursor of a stage off stage_cursor. *out defaults to 0
 * (absent row == fresh init). Returns false only on a real SQLite error. Stays
 * a RAW read: it is the scan bound the log-frontier walk consumes (the F1
 * log-derived reader layers on top — reducer_frontier_stage_cursor.c). */
static bool cursor_at(sqlite3 *db, const char *name, int64_t *out)
{
    *out = 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT cursor FROM stage_cursor WHERE name = ?",
            -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL("reducer", "prepare stage_cursor failed: %s",
                 sqlite3_errmsg(db));
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    bool rc_ok = true;
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        *out = sqlite3_column_int64(st, 0);
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("reducer", "step stage_cursor %s failed: %s",
                 name, sqlite3_errmsg(db));
        rc_ok = false;
    }
    sqlite3_finalize(st);
    return rc_ok;
}

/* A tip_finalize status="anchor" row written by tip_finalize_stage_seed_anchor()
 * is the row marker for a logless trusted reducer base, but generic active-tip
 * reanchors use the same row shape. Row candidates stay strict: every reducer
 * stage cursor must have reached at least H+1 and, if it has advanced beyond
 * H+1, the first row above the anchor must be ok=1. Durable trusted-base meta
 * is stronger than a row marker: it is written raise-only by the verified seed
 * path and outlives the pipeline-owned row. For that declaration, an ABSENT
 * first row is allowed (blocks-less bundle, not yet re-derived), but an
 * explicit script/UTXO ok=0 still rejects the base as a torn seed. Header,
 * body, proof, and finalization failures at H+1 block advancement above H;
 * they do not disprove the UTXO seed itself. */
static bool trusted_base_fail_disproves_seed(const char *log_table)
{
    return strcmp(log_table, "script_validate_log") == 0 ||
           strcmp(log_table, "utxo_apply_log") == 0;
}

static bool reducer_anchor_candidate_ok(sqlite3 *db, int32_t height,
                                        bool allow_rowless_first)
{
    int64_t first = (int64_t)height + 1;
    if (first > INT32_MAX)
        return false;

    for (int i = 0; i < k_logs_n; i++) {
        int64_t raw_cursor = 0;
        if (!cursor_at(db, k_logs[i].cursor_name, &raw_cursor))
            return false;
        /* Normalize tip_finalize's served-tip cursor to the next-height frame:
         * a seed anchor at H stamps tip_finalize cursor == H, whose next-height
         * equivalent is H+1 == first, so this candidate gate matches the
         * upstream stages' next-height cursors. */
        int64_t cursor = frontier_next_cursor(&k_logs[i], raw_cursor);
        if (cursor < first)
            return false;
        if (cursor == first)
            continue;

        enum log_row_state row;
        if (!log_ok_at(db, k_logs[i].log_table, (int32_t)first, &row))
            return false;
        if (row == LOG_ROW_FAIL &&
            (!allow_rowless_first ||
             trusted_base_fail_disproves_seed(k_logs[i].log_table)))
            return false;
        if (row == LOG_ROW_ABSENT && !allow_rowless_first)
            return false;
    }
    return true;
}

static bool reducer_trusted_anchor(sqlite3 *db, int32_t compiled_anchor,
                                   int32_t *out)
{
    /* The compiled checkpoint is a candidate, not synthetic state. If this
     * datadir's proven coin frontier does not cover it, search from genesis
     * so a lower, genuinely covered imported base can still be selected. */
    int32_t covered_floor = compiled_anchor;
    if (covered_floor > 0 &&
        !reducer_frontier_coin_authority_covers(db, covered_floor))
        covered_floor = 0;
    *out = covered_floor;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT height FROM tip_finalize_log "
            "WHERE ok = 1 AND status = 'anchor' AND height >= ? "
            "ORDER BY height DESC",
            -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL("reducer", "prepare trusted anchor failed: %s",
                 sqlite3_errmsg(db));
    sqlite3_bind_int(st, 1, covered_floor);

    bool rc_ok = true;
    while (true) {
        int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
        if (rc == SQLITE_ROW) {
            int32_t h = (int32_t)sqlite3_column_int64(st, 0);
            if (reducer_frontier_coin_authority_covers(db, h) &&
                reducer_anchor_candidate_ok(db, h, false)) {
                *out = h;
                break;
            }
        } else if (rc == SQLITE_DONE) {
            break;
        } else {
            LOG_WARN("reducer", "step trusted anchor failed: %s",
                     sqlite3_errmsg(db));
            rc_ok = false;
            break;
        }
    }
    sqlite3_finalize(st);
    if (!rc_ok)
        return false;

    /* The durable trusted-base declaration outlives its (pipeline-consumed)
     * anchor row — see REDUCER_TRUSTED_BASE_HEIGHT_KEY. Same vetting as a
     * row candidate; only ever RAISES the anchor. */
    int32_t base_h = 0;
    bool base_found = false;
    if (!reducer_frontier_trusted_base_height_read(db, &base_h, &base_found))
        return false; /* raw-return-ok:trusted-base reader logged failure */
    if (base_found && base_h >= covered_floor && base_h > *out &&
        reducer_frontier_coin_authority_covers(db, base_h) &&
        reducer_anchor_candidate_ok(db, base_h, true))
        *out = base_h;
    return true;
}

/* served_floor = MAX(height FROM tip_finalize_log WHERE ok=1), or 0.
 * Scans the WHOLE log (including stale-debris rows below H*): served_floor
 * is reported independently of H* precisely so a torn view (a tip finalized
 * above the provable prefix) is visible to L1 as "hold, don't drop". */
static bool tip_finalize_served_floor(sqlite3 *db, int32_t *served_floor)
{
    *served_floor = 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT COALESCE(MAX(height), 0) FROM tip_finalize_log "
            "WHERE ok = 1",
            -1, &st, NULL) != SQLITE_OK)
        LOG_FAIL("reducer", "prepare served_floor failed: %s",
                 sqlite3_errmsg(db));
    bool rc_ok = true;
    int rc = sqlite3_step(st);  // raw-sql-ok:progress-kv-kernel-store
    if (rc == SQLITE_ROW) {
        *served_floor = (int32_t)sqlite3_column_int64(st, 0);
    } else if (rc != SQLITE_DONE) {
        LOG_WARN("reducer", "step served_floor failed: %s",
                 sqlite3_errmsg(db));
        rc_ok = false;
    }
    sqlite3_finalize(st);
    return rc_ok;
}

bool reducer_frontier_compute_hstar(sqlite3 *progress_db,
                                    int32_t *hstar,
                                    int32_t *served_floor)
{
    if (!progress_db)
        LOG_FAIL("reducer", "compute_hstar: NULL progress_db");
    if (!hstar || !served_floor)
        LOG_FAIL("reducer", "compute_hstar: NULL out param(s)");

    /* Witness every full O(delta) fold. The tip_finalize H* watermark advances
     * by one row per finalize WITHOUT calling this (see tf_advance_provable_tip),
     * so on a healthy fold this bumps ~once per boot (the warm) + once per real
     * doubt (reorg/gap) — never once per finalized block. test_boot_odelta_scan
     * asserts it stays O(1) across a run instead of tracking the delta. */
    boot_scan_bump(boot_scan_counter("reducer_frontier.hstar_full_recompute"));

    /* TRUSTED_ANCHOR floor via reducer_frontier_floor(): the SHA3 checkpoint
     * height on a NORMAL boot, 0 during a from-genesis refold so a refold's
     * below-anchor folded prefix is REPORTED as H* (not clamped up). During a
     * refold the cursors are reset to genesis, so reducer_trusted_anchor's
     * candidate gate rejects any stored anchor above them and the floor stays
     * 0; a normal boot returns the compiled anchor read. */
    int32_t compiled_anchor = reducer_frontier_floor();
    int32_t anchor = compiled_anchor;
    if (!reducer_trusted_anchor(progress_db, compiled_anchor, &anchor))
        LOG_FAIL("reducer", "trusted anchor read failed");

    *served_floor = 0;
    /* served_floor is independent of H* (C-served): report the deepest
     * finalized ok=1 even when it sits above the provable prefix. */
    if (!tip_finalize_served_floor(progress_db, served_floor))
        LOG_FAIL("reducer", "served_floor read failed");

    /* H* = MIN over every success-checked log of its contiguous ok=1 prefix
     * (C2). MIN-fold from a high sentinel: each log's h_contiguous is >=
     * anchor (its contiguity floor), so the weakest log bounds H*. A log with
     * no rows above the anchor returns exactly `anchor`, which correctly pins
     * H* to the anchor for that log. The hard guard at the end then clamps
     * the result up to the anchor (and covers the all-logs-empty case where
     * the sentinel survives). */
    int32_t hs = INT32_MAX;
    int32_t ua_contig = anchor;  /* utxo_apply's OWN contiguous frontier (C4) */
    /* Per-boot integrity-tag watermark: verify only the delta above it (rows
     * at/below were tag-verified earlier this boot). See reducer_frontier_itag.h. */
    int32_t verify_wm = reducer_frontier_itag_watermark(progress_db);
    for (int i = 0; i < k_logs_n; i++) {
        int64_t raw_cursor = 0;
        if (!cursor_at(progress_db, k_logs[i].cursor_name, &raw_cursor))
            LOG_FAIL("reducer", "cursor read failed: %s",
                     k_logs[i].cursor_name);
        /* Normalize tip_finalize's served-tip cursor (C == served tip) to the
         * next-height frame (C+1) the contiguity scan's exclusive upper bound
         * expects — its rows run up to C (the anchor row included). */
        int64_t scan_cursor = frontier_next_cursor(&k_logs[i], raw_cursor);

        /* C1 diagnostic: a cursor behind the anchor is a defect state the heal
         * will fix; flag it but do not abort H*. The normalized cursor is
         * compared so tip_finalize is not flagged for sitting one below the
         * upstream frame by convention. SUPPRESSED during a refold: a
         * below-anchor cursor is then EXPECTED (re-walking the prefix). */
        if (scan_cursor < (int64_t)anchor + 1 && !refold_in_progress())
            LOG_WARN("reducer", "cursor below hstar: %s cursor=%lld anchor=%d",
                     k_logs[i].cursor_name, (long long)raw_cursor, anchor);

        int32_t h_contig = anchor;
        if (!log_contiguous_prefix(progress_db, k_logs[i].log_table, anchor,
                                   scan_cursor, verify_wm, &h_contig))
            LOG_FAIL("reducer", "contiguity walk failed: %s",
                     k_logs[i].log_table);

        if (h_contig < hs)
            hs = h_contig;  /* H* = MIN over all logs */
        if (strcmp(k_logs[i].log_table, "utxo_apply_log") == 0)
            ua_contig = h_contig;  /* captured free for the C4 tear check */
    }
    if (hs == INT32_MAX)
        hs = anchor;  /* no logs scanned (k_logs_n>0, but defensive) */

    /* C3 — hash agreement: cap H* below the first validate_headers vs
     * script_validate split within [anchor+1 .. hs]. */
    if (!reducer_frontier_apply_hash_agreement(progress_db, anchor, &hs))
        LOG_FAIL("reducer", "hash-agreement walk failed");

    /* C4 diagnostic — coins frontier vs utxo_apply's OWN applied frontier.
     * coins_applied_height tracks the utxo_apply cursor by construction (the
     * stage co-commits both in one BEGIN IMMEDIATE), so a REAL tear is coins
     * applied ABOVE utxo_apply's contiguous ok=1 log prefix (ua_contig) — a
     * hole/ok=0 row below the cursor. It is NOT coins leading the global MIN
     * H*: H* is pinned by the SLOWEST log (tip_finalize), which legitimately
     * lags utxo_apply by the pipeline depth (every applied coin already passed
     * headers->script->proof->utxo_apply), and reading that lag as a tear is
     * the false positive that dead-ended at the never-built L2. Compare against
     * ua_contig, never hs. Do NOT lower H* here; absent key == unknown frontier
     * (not a defect for L0). De-stormed via the shared log_throttle: a
     * persistent tear fires once per pair change / 300 s keep-alive with the
     * suppressed count. Caller holds progress_store_tx_lock(); the throttle's
     * atomics keep the counters torn-read-safe regardless. */
    int32_t coins_applied = 0;
    bool coins_found = false;
    bool coins_read_ok =
        coins_kv_get_applied_height(progress_db, &coins_applied, &coins_found);
    if (!coins_read_ok) {
        /* A read ERROR (not an absent key) silently disarms the tear
         * diagnostic — surface it so the messenger going quiet is itself
         * visible. Throttled like the tear WARN below; caller holds the lock. */
        static struct log_throttle disarm_throttle = LOG_THROTTLE_INIT;
        int64_t now = platform_time_wall_unix();
        uint64_t reps = 0;
        if (log_throttle_should_emit(&disarm_throttle, 1, now, 300, &reps))
            LOG_WARN("reducer",
                     "coins_applied_height read failed — coin-tear diagnostic "
                     "disarmed this pass repeated=%llu",
                     (unsigned long long)reps);
    } else if (coins_found && coins_applied > ua_contig + 1) {
        static struct log_throttle tear_throttle = LOG_THROTTLE_INIT;
        uint64_t pair = ((uint64_t)(uint32_t)coins_applied << 32)
                        | (uint32_t)ua_contig;
        int64_t now = platform_time_wall_unix();
        uint64_t reps = 0;
        if (log_throttle_should_emit(&tear_throttle, pair, now, 300, &reps))
            LOG_WARN("reducer",
                     "coins_applied=%d > utxo_apply_frontier=%d "
                     "(coin tear vs own applied log) repeated=%llu",
                     coins_applied, ua_contig + 1, (unsigned long long)reps);
    }

    /* HARD GUARD — never rewind across finality. */
    if (hs < anchor)
        hs = anchor;

    /* Advance the watermark to the resolved H*: [anchor+1 .. hs] is now
     * tag-verified in every log (hs <= each log's verified prefix), so later
     * folds verify only the delta above it. See reducer_frontier_itag.h. */
    reducer_frontier_itag_watermark_publish(progress_db, hs);

    *hstar = hs;
    return true;
}

bool reducer_frontier_log_frontier(sqlite3 *progress_db,
                                   const char *log_table,
                                   const char *cursor_name,
                                   int32_t *out_h)
{
    if (!progress_db || !log_table || !cursor_name || !out_h)
        LOG_FAIL("reducer", "log_frontier: NULL arg");

    /* Recursive lock: safe whether or not the caller already holds it. */
    progress_store_tx_lock();

    /* Floor = 0 during a refold, else the compiled anchor (same scoping as
     * compute_hstar) so the per-stage frontier tracks the true folded height. */
    int32_t compiled_anchor = reducer_frontier_floor();
    int32_t anchor = compiled_anchor;
    int32_t h = anchor;
    int64_t cursor = 0;

    bool ok = reducer_trusted_anchor(progress_db, compiled_anchor, &anchor);
    if (ok)
        ok = cursor_at(progress_db, cursor_name, &cursor);
    if (ok && (strcmp(log_table, "tip_finalize_log") == 0 ||
               strcmp(cursor_name, "tip_finalize") == 0))
        cursor = cursor > 0 ? cursor + 1 : cursor;
    if (ok)
        /* verify_above = anchor: this per-stage helper is repair-path (not the
         * hot fold), so it tag-verifies its whole scanned range every call. */
        ok = log_contiguous_prefix(progress_db, log_table, anchor, cursor,
                                   anchor, &h);

    progress_store_tx_unlock();

    if (!ok)
        return false;  /* the failing inner read already logged the cause */
    *out_h = h;
    return true;
}

bool reducer_frontier_log_frontier_above(sqlite3 *progress_db,
                                         const char *log_table,
                                         const char *cursor_name,
                                         int32_t verified_floor,
                                         int32_t *out_h)
{
    if (!progress_db || !log_table || !cursor_name || !out_h)
        LOG_FAIL("reducer", "log_frontier_above: NULL arg");
    if (verified_floor < 0)
        LOG_FAIL("reducer", "log_frontier_above: negative floor %d",
                 verified_floor);

    /* Recursive lock: safe whether or not the caller already holds it. */
    progress_store_tx_lock();

    int64_t cursor = 0;
    int32_t h = verified_floor;
    bool ok = cursor_at(progress_db, cursor_name, &cursor);
    if (ok && (strcmp(log_table, "tip_finalize_log") == 0 ||
               strcmp(cursor_name, "tip_finalize") == 0))
        cursor = cursor > 0 ? cursor + 1 : cursor;
    if (ok)
        /* verify_above = verified_floor: verify the whole scanned range above
         * the caller's floor (repair-path, not the hot fold). */
        ok = log_contiguous_prefix(progress_db, log_table, verified_floor,
                                   cursor, verified_floor, &h);

    progress_store_tx_unlock();

    if (!ok)
        return false;  /* the failing inner read already logged the cause */
    *out_h = h;
    return true;
}

/* Resolve a stage cursor `name` to its success-checked *_log table (NULL for
 * header_admit / body_fetch), reporting the served-tip convention. Shared with
 * the F1 derived reader (reducer_frontier_stage_cursor.c). */
const char *reducer_frontier_cursor_log_table(const char *name,
                                              bool *served_tip)
{
    if (served_tip)
        *served_tip = false;
    if (!name)
        return NULL;
    for (int i = 0; i < k_logs_n; i++)
        if (strcmp(k_logs[i].cursor_name, name) == 0) {
            if (served_tip)
                *served_tip = k_logs[i].served_tip;
            return k_logs[i].log_table;
        }
    return NULL;
}
