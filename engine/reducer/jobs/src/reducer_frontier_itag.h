/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * reducer_frontier_itag — the fold-read side of the W4-4 per-row integrity tag.
 *
 * Split out of reducer_frontier.c (file-size ceiling) but conceptually part of
 * the L0 fold: the watermark that keeps a normal fold O(delta), the column
 * presence probe, and the typed mismatch error. The per-row verify itself stays
 * inline in the fold (log_ok_at / log_contiguous_prefix) and calls
 * stage_row_itag_verify(); see jobs/stage_row_itag.h for the tag contract.
 *
 * UNTAGGED-ROW POLICY (the "what about writers that do not stamp?" question)
 * ------------------------------------------------------------------------
 * A row in an itag-bearing *_log table can present one of three verdicts to the
 * fold; each is treated by DESIGN, not by accident:
 *
 *   MATCH     — tag present and recomputes: trust the row (normal case).
 *   MISMATCH  — tag PRESENT but does not recompute: the verdict bytes changed
 *               under a committed tag. This is the corruption case, so the row
 *               is forced NOT ok and H* is CAPPED below it (corruption LOWERS
 *               the frontier, never raises it). reducer_frontier_itag_mismatch_warn.
 *   ABSENT    — no tag (itag column present but the value is NULL). Every
 *               production writer stamps inline (the six *_log_store.c helpers +
 *               the tip_finalize seed anchor), and the one-time open-time
 *               backfill (stage_row_itag_backfill) stamps every legacy row, so a
 *               NULL itag AFTER migration is itself a defect. But a real datadir
 *               can be observed mid-transition (a freshly promoted consensus-state
 *               candidate snapshot writes 'anchor' rows into a schema whose itag
 *               column has not been backfilled yet), and wedging the node's H*
 *               there would be worse than the untagged row it guards. So an
 *               ABSENT row is trusted (its ok/status is read as before this
 *               feature), does NOT cap H*, but logs a rate-limited typed WARN and
 *               is COUNTED (reducer_frontier_itag_null_count, surfaced in
 *               dumpstate reducer_frontier) so a lingering untagged writer is
 *               visible instead of silent. */

#ifndef ZCL_JOBS_REDUCER_FRONTIER_ITAG_H
#define ZCL_JOBS_REDUCER_FRONTIER_ITAG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct sqlite3;

/* Per-boot integrity-tag watermark: the height at/below which every *_log row
 * has been tag-verified this boot. The first fold after boot/reset verifies its
 * whole scanned range; later folds trust the prefix at/below the last resolved
 * H* and verify only the delta above it (the fold is hot — this keeps a normal
 * at-tip fold O(delta), not O(chain)). A reboot re-verifies from scratch.
 *
 *   _watermark(db)          — this connection's watermark (-1 == none).
 *   _watermark_publish(db,h)— set it to the resolved H* (raise OR lower).
 *   _watermark_reset()    — drop to -1 (refold/reorg: re-verify what we refold).
 * State is connection-owned so one fixture/datadir cannot lend a trusted
 * prefix to another. A write hook invalidates mutations at/below the trusted
 * prefix while preserving append-only O(delta); the fold path is serialized
 * on progress_store's lock. */
int32_t reducer_frontier_itag_watermark(struct sqlite3 *db);
void reducer_frontier_itag_watermark_publish(struct sqlite3 *db,
                                             int32_t hstar);
void    reducer_frontier_itag_watermark_reset(void);

/* Bound the ranged scan to the unverified delta. The cursor is exclusive; a
 * watermark above it is clamped to cursor-1 rather than manufacturing H*. */
int64_t reducer_frontier_itag_scan_floor(int32_t anchor, int64_t cursor,
                                         int32_t verify_above);

/* Does `table` carry an `itag` column on `db`? Old fixtures / a pre-migration
 * datadir may not; when absent the fold skips tag verification (trusting ok,
 * exactly as before this feature). Cheap metadata read; NOT cached because the
 * same table name can back different schemas across the many test dbs in one
 * process. */
bool reducer_frontier_itag_column_present(struct sqlite3 *db,
                                          const char *table);

/* Typed, de-stormed error naming the (table, height) whose integrity tag failed
 * to verify: a WARN + a named recovery event, throttled (first sight / key
 * change / 300 s keep-alive) so a persistent corruption does not spam the log. */
void reducer_frontier_itag_mismatch_warn(const char *table, int64_t height);

/* Record an ABSENT (NULL-itag) row seen during the fold: bump the counter and
 * emit ONE throttled WARN per table per keep-alive window (a per-table, not
 * per-height, throttle — an untagged writer touches a whole run of heights, so a
 * per-height throttle would still storm; the counter carries the true row count).
 * Does NOT cap H* — see UNTAGGED-ROW POLICY above. */
void reducer_frontier_itag_null_warn(const char *table, int64_t height);

/* Total ABSENT (NULL-itag) rows the fold has trusted-but-flagged since the last
 * watermark reset (fresh boot / refold re-verifies from scratch). Lock-free;
 * surfaced by reducer_frontier_dump_state_json as "itag_null_rows_seen". */
uint64_t reducer_frontier_itag_null_count(void);

/* The one place the UNTAGGED-ROW POLICY (above) is applied. Verifies a row's
 * stored tag against its current fields and returns whether the fold must force
 * the row NOT ok: true ONLY for a PRESENT-but-mismatching tag (corruption, caps
 * H*). An ABSENT (NULL) tag is trusted (returns false) but WARNed + counted; a
 * MATCH returns false silently. Called by both fold sites (log_ok_at /
 * log_contiguous_prefix) so the verdict handling lives in exactly one place. */
bool reducer_frontier_itag_row_fails(const char *log_table, int64_t height,
                                     int ok_raw, const void *status,
                                     size_t status_len, const void *tag,
                                     size_t tag_len);

#endif /* ZCL_JOBS_REDUCER_FRONTIER_ITAG_H */
