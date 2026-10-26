/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "config/mint_anchor_progress.h"

#include "chain/checkpoints.h"
#include "jobs/refold_progress.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MINT_ANCHOR_MARKER_LEN 48
#define MINT_ANCHOR_LANE_FULL 1
#define MINT_ANCHOR_LANE_CHECKPOINT_FOLD 2

static bool producer_lane_read(sqlite3 *db, uint8_t *lane, bool *found)
{
    size_t n = 0;
    *lane = 0;
    *found = false;
    if (!progress_meta_get_blob_exact(db, MINT_ANCHOR_PRODUCER_LANE_KEY,
                                      lane, 1, &n, found))
        return false;
    if (*found && (n != 1 ||
                   (*lane != MINT_ANCHOR_LANE_FULL &&
                    *lane != MINT_ANCHOR_LANE_CHECKPOINT_FOLD))) {
        LOG_WARN("mint_anchor",
                 "[mint-anchor] producer lane marker is malformed "
                 "(value=%u bytes=%zu)", (unsigned)*lane, n);
        return false;
    }
    return true;
}

/* A pre-lane producer cannot prove whether its earlier rows came from the full
 * or crypto-skipping command.  Detect every durable legacy-resume shape before
 * writing a lane marker; unknown history may be conservatively downgraded to
 * checkpoint_fold, never promoted to full. */
static bool producer_legacy_state_present(sqlite3 *db, bool *present)
{
    uint8_t marker[MINT_ANCHOR_MARKER_LEN] = {0};
    size_t marker_n = 0;
    bool marker_found = false;
    if (!progress_meta_get_blob_exact(
            db, MINT_ANCHOR_IN_PROGRESS_KEY, marker, sizeof(marker),
            &marker_n, &marker_found))
        return false;

    uint8_t refold = 0;
    size_t refold_n = 0;
    bool refold_found = false;
    if (!progress_meta_get_blob_exact(db, REFOLD_IN_PROGRESS_KEY,
                                      &refold, sizeof(refold), &refold_n,
                                      &refold_found))
        return false;
    if (refold_found && (refold_n != 1 || refold != 1)) {
        LOG_WARN("mint_anchor", "[mint-anchor] legacy refold marker malformed");
        return false;
    }

    int32_t applied = 0;
    bool applied_found = false;
    if (!coins_kv_get_applied_height(db, &applied, &applied_found))
        return false;
    *present = marker_found || refold_found || applied_found;
    return true;
}

bool mint_anchor_producer_lane_bind(sqlite3 *db, bool checkpoint_fold)
{
    if (!db)
        LOG_FAIL("mint_anchor", "producer lane bind: NULL db");
    uint8_t want = checkpoint_fold ? MINT_ANCHOR_LANE_CHECKPOINT_FOLD
                                   : MINT_ANCHOR_LANE_FULL;
    uint8_t got = 0;
    bool found = false;
    if (!producer_lane_read(db, &got, &found))
        LOG_FAIL("mint_anchor", "producer lane read failed");
    if (found) {
        if (got == want)
            return true;
        LOG_WARN("mint_anchor",
                 "[mint-anchor] producer lane profile mismatch/malformed "
                 "(stored=%u requested=%u); use the original mode "
                 "or a fresh isolated producer datadir",
                 (unsigned)got, (unsigned)want);
        return false;
    }
    bool legacy = false;
    if (!producer_legacy_state_present(db, &legacy))
        LOG_FAIL("mint_anchor", "producer legacy-state inspection failed");
    if (legacy && !checkpoint_fold) {
        LOG_WARN("mint_anchor",
                 "[mint-anchor] pre-lane producer state has no proof of its "
                 "original crypto mode; refusing promotion to full. Resume "
                 "only as checkpoint_fold or use a fresh producer datadir");
        return false;
    }
    if (!progress_meta_set(db, MINT_ANCHOR_PRODUCER_LANE_KEY,
                           &want, sizeof(want)))
        LOG_FAIL("mint_anchor", "producer lane write failed");
    return true;
}

static bool table_has_non_full_success(sqlite3 *db, const char *table,
                                       bool allow_anchor, bool *found)
{
    *found = false;
    sqlite3_stmt *stmt = NULL;
    char sql[256];
    int n = snprintf(sql, sizeof(sql),
        "SELECT 1 FROM %s WHERE ok=1 AND "
        "(typeof(status)!='text' OR (CAST(status AS BLOB)!=CAST('verified' AS BLOB) "
        "AND (?=0 OR CAST(status AS BLOB)!=CAST('anchor' AS BLOB)))) "
        "LIMIT 1", table);
    if (n <= 0 || (size_t)n >= sizeof(sql))
        return false;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        const char *message = sqlite3_errmsg(db);
        if (message && strstr(message, "no such table") != NULL)
            return true;
        LOG_WARN("mint_anchor", "[mint-anchor] mode scan %s failed: %s",
                 table, message ? message : "unknown");
        return false;
    }
    sqlite3_bind_int(stmt, 1, allow_anchor ? 1 : 0);
    rc = sqlite3_step(stmt);  // raw-sql-ok:progress-kv-kernel-store
    *found = rc == SQLITE_ROW;
    bool ok = rc == SQLITE_ROW || rc == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return ok;
}

/* Normal-boot gate, marker phase: returns 1 when no offline mint in-progress
 * marker exists, 0 when one is present (reason describes the refusal), -1
 * when the marker cannot be read. */
static int normal_boot_progress_marker_state(sqlite3 *db, char *reason,
                                             size_t reason_size)
{
    uint8_t in_progress[MINT_ANCHOR_MARKER_LEN] = {0};
    size_t marker_size = 0;
    bool marker_found = false;
    if (!progress_meta_get_blob_exact(
            db, MINT_ANCHOR_IN_PROGRESS_KEY, in_progress,
            sizeof(in_progress), &marker_size, &marker_found))
        return -1;
    if (!marker_found)
        return 1;
    if (reason && reason_size)
        snprintf(reason, reason_size,
                 "datadir has an offline mint in-progress marker "
                 "(%zu bytes); resume only with the producer command or "
                 "install a verified artifact into a serving datadir",
                 marker_size);
    return 0;
}

/* Writes the normal-boot refusal reason for a lane-bound datadir. */
static void reason_producer_lane_bound(char *reason, size_t reason_size,
                                       uint8_t lane, size_t n)
{
    if (reason && reason_size)
        snprintf(reason, reason_size,
                 "datadir is permanently bound to offline producer lane "
                 "profile=%s; install its verified artifact into a separate "
                 "serving datadir",
                 n == 1 && lane == MINT_ANCHOR_LANE_FULL
                     ? "full" : "checkpoint_fold_or_invalid");
}

/* Normal-boot gate, evidence phase: returns 1 when every validation table is
 * compatible with normal serving, 0 when a table carries non-full successful
 * validation evidence (reason names it), -1 when a scan fails. */
static int normal_boot_validation_tables_state(sqlite3 *db, char *reason,
                                               size_t reason_size)
{
    static const char *const tables[] = {
        "script_validate_log", "proof_validate_log", "utxo_apply_log",
    };
    for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); i++) {
        bool incompatible = false;
        bool allow_anchor = strcmp(tables[i], "utxo_apply_log") == 0;
        if (!table_has_non_full_success(db, tables[i], allow_anchor,
                                        &incompatible))
            return -1;
        if (!incompatible)
            continue;
        if (reason && reason_size)
            snprintf(reason, reason_size,
                     "%s contains non-full successful validation evidence; "
                     "normal serving boot is contained", tables[i]);
        return 0;
    }
    return 1;
}

bool mint_anchor_normal_boot_allowed(sqlite3 *db, char *reason,
                                     size_t reason_size)
{
    if (reason && reason_size)
        reason[0] = '\0';
    if (!db)
        LOG_FAIL("mint_anchor", "normal boot gate: NULL db");
    int marker = normal_boot_progress_marker_state(db, reason, reason_size);
    if (marker < 0)
        LOG_FAIL("mint_anchor", "normal boot progress marker read failed");
    if (marker == 0)
        return false;
    uint8_t lane = 0;
    size_t n = 0;
    bool found = false;
    if (!progress_meta_get_blob_exact(db, MINT_ANCHOR_PRODUCER_LANE_KEY,
                                      &lane, sizeof(lane), &n, &found))
        LOG_FAIL("mint_anchor", "normal boot lane read failed");
    if (found) {
        reason_producer_lane_bound(reason, reason_size, lane, n);
        return false;
    }
    int tables = normal_boot_validation_tables_state(db, reason, reason_size);
    if (tables < 0)
        return false;
    if (tables == 0)
        return false;
    return true;
}

static void map_wle32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
    p[3] = (uint8_t)((v >> 24) & 0xff);
}

static uint32_t map_rle32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void map_wle64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

static uint64_t map_rle64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v |= ((uint64_t)p[i]) << (8 * i);
    return v;
}

static void marker_encode(uint8_t out[MINT_ANCHOR_MARKER_LEN],
                          const struct sha3_utxo_checkpoint *cp)
{
    memcpy(out, "ZAM1", 4);
    map_wle32(out + 4, (uint32_t)cp->height);
    map_wle64(out + 8, cp->utxo_count);
    memcpy(out + 16, cp->sha3_hash, 32);
}

static bool marker_matches(const uint8_t in[MINT_ANCHOR_MARKER_LEN],
                           const struct sha3_utxo_checkpoint *cp)
{
    if (memcmp(in, "ZAM1", 4) != 0)
        return false;
    if ((int32_t)map_rle32(in + 4) != cp->height)
        return false;
    if (map_rle64(in + 8) != cp->utxo_count)
        return false;
    return memcmp(in + 16, cp->sha3_hash, 32) == 0;
}

static bool read_matching_marker(sqlite3 *db,
                                 const struct sha3_utxo_checkpoint *cp,
                                 bool *found_out, bool *matches_out)
{
    if (found_out)
        *found_out = false;
    if (matches_out)
        *matches_out = false;
    if (!db || !cp)
        return false;

    uint8_t buf[MINT_ANCHOR_MARKER_LEN] = {0};
    size_t n = 0;
    bool found = false;
    if (!progress_meta_get_blob_exact(db, MINT_ANCHOR_IN_PROGRESS_KEY,
                                      buf, sizeof(buf), &n, &found))
        LOG_FAIL("mint_anchor", "progress marker read failed");

    if (found_out)
        *found_out = found;
    if (!found)
        return true;

    bool matches = n == sizeof(buf) && marker_matches(buf, cp);
    if (matches_out)
        *matches_out = matches;
    return true;
}

static bool applied_through(sqlite3 *db, int32_t *out, bool *found_out)
{
    if (out)
        *out = -1;
    if (found_out)
        *found_out = false;
    int32_t frontier = 0;
    bool found = false;
    if (!coins_kv_get_applied_height(db, &frontier, &found))
        LOG_FAIL("mint_anchor", "coins_applied_height read failed");
    if (found_out)
        *found_out = found;
    if (out)
        *out = found ? frontier - 1 : -1;
    return true;
}

bool mint_anchor_progress_mark(sqlite3 *db,
                               const struct sha3_utxo_checkpoint *cp)
{
    if (!db || !cp)
        LOG_FAIL("mint_anchor", "mark: invalid args db=%p cp=%p",
                 (void *)db, (const void *)cp);
    uint8_t marker[MINT_ANCHOR_MARKER_LEN] = {0};
    marker_encode(marker, cp);
    if (!progress_meta_set(db, MINT_ANCHOR_IN_PROGRESS_KEY,
                           marker, sizeof(marker)))
        LOG_FAIL("mint_anchor", "mark: progress_meta_set failed");
    return true;
}

bool mint_anchor_progress_clear(sqlite3 *db)
{
    if (!db)
        LOG_FAIL("mint_anchor", "clear: NULL db");
    if (!progress_meta_delete(db, MINT_ANCHOR_IN_PROGRESS_KEY))
        LOG_FAIL("mint_anchor", "clear: progress_meta_delete failed");
    return true;
}

static void resume_outputs_reset(int32_t *applied_through_out,
                                 bool *legacy_adopted_out)
{
    if (applied_through_out)
        *applied_through_out = -1;
    if (legacy_adopted_out)
        *legacy_adopted_out = false;
}

static void resume_report_applied(int32_t *applied_through_out,
                                  int32_t through)
{
    if (applied_through_out)
        *applied_through_out = through;
}

/* Loads every durable resume signal in inspection order. Returns 0 when the
 * producer lane is bound and both probes succeeded, 1 when no producer lane
 * is bound, -1 when a probe failed. */
static int resume_state_load(sqlite3 *db,
                             const struct sha3_utxo_checkpoint *cp,
                             bool *marker_found, bool *marker_matches,
                             int32_t *through, bool *have_frontier)
{
    uint8_t lane = 0;
    bool lane_found = false;
    if (!producer_lane_read(db, &lane, &lane_found))
        return -1;
    if (!lane_found)
        return 1;
    if (!read_matching_marker(db, cp, marker_found, marker_matches))
        return -1;  /* logged */
    if (!applied_through(db, through, have_frontier))
        return -1;  /* logged */
    return 0;
}

/* Outcome of comparing the durable in-progress marker against the anchor
 * checkpoint; the caller owns every log line. */
enum marker_phase {
    MARKER_PHASE_LEGACY,
    MARKER_PHASE_RESUME,
    MARKER_PHASE_RESET_MISMATCH,
    MARKER_PHASE_RESET_PAST_ANCHOR,
    MARKER_PHASE_RESET_NOTHING_APPLIED,
};

static enum marker_phase marker_phase_verdict(bool found, bool matches,
                                              bool have_frontier,
                                              int32_t through,
                                              int32_t anchor_height)
{
    if (!found)
        return MARKER_PHASE_LEGACY;
    if (!matches)
        return MARKER_PHASE_RESET_MISMATCH;
    if (have_frontier && through > anchor_height)
        return MARKER_PHASE_RESET_PAST_ANCHOR;
    /* A marker with NO applied progress is not a resumable fold. Nothing
     * was ever folded, so resuming preserves nothing — but it DOES skip
     * the genesis reset, and that reset is what truncates coins_kv. The
     * datadir is then left carrying the node.db mirror's coin set at the
     * SOURCE datadir's tip while coins_applied_height is 0, and
     * utxo_apply's stage init refuses that contradiction outright
     * ("future coin repair refused range=[1,<source tip>] cap=4096" ->
     * "staged.utxo_apply init failed" -> "FATAL: -mint-anchor: offline
     * reducer stage init failed"). The mint dies before the fold starts,
     * and every re-run resumes the same dead marker. Reset instead. */
    if (!have_frontier || through < 0)
        return MARKER_PHASE_RESET_NOTHING_APPLIED;
    return MARKER_PHASE_RESUME;
}

/* Legacy adoption: a producer that predates this marker may
 * have been killed after durable stage/coins commits. Only adopt when the
 * durable refold signal is active and the frontier is within the
 * genesis..anchor mint span. A contaminated or wrong fold cannot publish:
 * boot_mint_anchor_run still hard-asserts SHA3/count before writing. */
/* through < 0 (nothing applied) is refused for the same reason as the
 * matching-marker branch above: adopting it would skip the genesis reset
 * and strand a seeded coins_kv against coins_applied_height=0. */
static bool legacy_adoption_eligible(bool have_frontier, int32_t through,
                                     int32_t anchor_height)
{
    return refold_in_progress() && have_frontier && through >= 0 &&
           through <= anchor_height;
}

bool mint_anchor_progress_can_resume(sqlite3 *db,
                                     const struct sha3_utxo_checkpoint *cp,
                                     int32_t *applied_through_out,
                                     bool *legacy_adopted_out)
{
    resume_outputs_reset(applied_through_out, legacy_adopted_out);
    if (!db || !cp)
        LOG_FAIL("mint_anchor", "can_resume: invalid args db=%p cp=%p",
                 (void *)db, (const void *)cp);

    bool found = false;
    bool matches = false;
    int32_t through = -1;
    bool have_frontier = false;
    int loaded = resume_state_load(db, cp, &found, &matches, &through,
                                   &have_frontier);
    if (loaded < 0)
        return false;
    if (loaded > 0) {
        LOG_WARN("mint_anchor",
                 "[mint-anchor] resume refused without a durable producer "
                 "lane; bind the requested profile before resume inspection");
        return false;
    }

    enum marker_phase verdict = marker_phase_verdict(found, matches,
                                                     have_frontier, through,
                                                     cp->height);
    if (verdict == MARKER_PHASE_RESET_MISMATCH) {
        LOG_WARN("mint_anchor",
                 "[mint-anchor] existing progress marker targets a different "
                 "checkpoint — resetting the offline mint from genesis");
        return false;
    }
    if (verdict == MARKER_PHASE_RESET_PAST_ANCHOR) {
        LOG_WARN("mint_anchor",
                 "[mint-anchor] progress marker found but frontier "
                 "applied-through=%d is past anchor=%d — resetting",
                 through, cp->height);
        return false;
    }
    if (verdict == MARKER_PHASE_RESET_NOTHING_APPLIED) {
        LOG_WARN("mint_anchor",
                 "[mint-anchor] progress marker found but nothing has been "
                 "applied (applied-through=%d) — resetting from genesis "
                 "rather than resuming a fold that never started",
                 through);
        return false;
    }
    if (verdict == MARKER_PHASE_RESUME) {
        resume_report_applied(applied_through_out, through);
        return true;
    }

    /* MARKER_PHASE_LEGACY: no durable marker; legacy adoption decides. */
    if (!legacy_adoption_eligible(have_frontier, through, cp->height))
        return false;

    if (!mint_anchor_progress_mark(db, cp))
        return false;  /* logged */
    if (legacy_adopted_out)
        *legacy_adopted_out = true;
    resume_report_applied(applied_through_out, through);
    LOG_INFO("mint_anchor",
             "[mint-anchor] adopted legacy interrupted mint at "
             "applied-through=%d for checkpoint h=%d; future restarts resume "
             "without a genesis reset",
             through, cp->height);
    return true;
}
