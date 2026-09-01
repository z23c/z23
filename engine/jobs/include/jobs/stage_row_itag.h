/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stage_row_itag — per-row integrity tag for the reducer stage *_log rows.
 *
 * WHY
 * ----
 * H* (the node's headline sync frontier) is a pure fold over progress.kv stage
 * rows, trusting the `ok` column (and, for the three full-validation logs, the
 * `status` evidence) exactly as read from SQLite. A flipped bit in a stage row
 * (disk corruption, torn write) can silently RAISE H* past unfolded state:
 * SQLite's quick_check is structural only and cannot see that a row's verdict
 * bytes changed. This tag closes that hole.
 *
 * THE LAW
 * --------
 * The tag is a truncated SHA3-256 over the row's H*-load-bearing fields:
 *
 *     (log_table, height, ok [, status for the full-validation logs])
 *
 * — precisely the inputs the reducer_frontier fold turns into "is this row a
 * good ok=1 receipt". On write, each *_log_insert stamps the tag into a new
 * `itag` column. On the fold read, a row whose tag does not recompute is
 * treated as NOT ok: it caps H* at the last verified height and logs a typed
 * error naming the (table, height). Corruption therefore LOWERS the frontier,
 * never raises it.
 *
 * SCOPE
 * ------
 * `status` is folded into the tag only for the three logs whose fold verdict
 * parses `status` into VERIFIED (script_validate_log, proof_validate_log,
 * utxo_apply_log) — the exact set reducer_frontier treats as profile-bound.
 * For every other log the tag covers (table, height, ok). The helper decides
 * this internally from the table name, so a caller may always pass whatever
 * status it has; the tag stays canonical across write / backfill / verify.
 *
 * These are kernel-primitive helpers: they take a sqlite3 handle and touch no
 * stage module state. The backfill's raw sqlite3_step sites carry the canonical
 * `// raw-sql-ok:progress-kv-kernel-store` marker. */

#ifndef ZCL_JOBS_STAGE_ROW_ITAG_H
#define ZCL_JOBS_STAGE_ROW_ITAG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct sqlite3;

/* Truncated tag length. 128 bits: a random corruption has a 1-in-2^128 chance
 * of reproducing a matching tag — vastly beyond what accidental disk faults can
 * hit. The full SHA3-256 is computed; only the first STAGE_ROW_ITAG_LEN bytes
 * are stored/compared. */
#define STAGE_ROW_ITAG_LEN 16

/* Compute the integrity tag over the H*-load-bearing fields of a stage log row.
 * `status`/`status_len` may be NULL/0; the helper folds them in only for the
 * full-validation logs (see SCOPE above), so passing a status for a log that
 * does not cover it is harmless. `out` receives STAGE_ROW_ITAG_LEN bytes. */
void stage_row_itag_compute(const char *log_table, int64_t height, int ok,
                            const void *status, size_t status_len,
                            uint8_t out[STAGE_ROW_ITAG_LEN]);

/* Verdict of verifying a stored tag against the row's current fields. */
enum stage_row_itag_verdict {
    STAGE_ROW_ITAG_ABSENT = 0,   /* no tag stored (NULL / wrong length): the row
                                  * predates the migration or was written by a
                                  * path that does not tag — treat as untagged,
                                  * not as corruption. */
    STAGE_ROW_ITAG_MATCH,        /* tag present and recomputes exactly. */
    STAGE_ROW_ITAG_MISMATCH,     /* tag present but does NOT recompute: the row's
                                  * verdict bytes changed under it — corruption. */
};

/* Verify a stored tag (`tag`/`tag_len`, as read from the itag column) against
 * the row's current (table, height, ok, status). A NULL tag or a length other
 * than STAGE_ROW_ITAG_LEN is ABSENT (untagged), never MISMATCH. */
enum stage_row_itag_verdict stage_row_itag_verify(
    const char *log_table, int64_t height, int ok,
    const void *status, size_t status_len,
    const void *tag, size_t tag_len);

/* One-time, bounded migration: stamp an itag onto every row of `table` that
 * lacks one, then record a durable progress_meta flag so later boots skip the
 * O(rows) scan entirely (normal boot stays O(delta)). Idempotent: the flag
 * short-circuits, and the underlying UPDATE only touches itag-NULL rows.
 * Assumes the itag column already exists (the caller's ensure_schema ADDs it).
 * Recursive-lock safe; runs inside its own BEGIN IMMEDIATE when not already in
 * a transaction. Returns false only on a real SQLite error (logged). */
bool stage_row_itag_backfill(struct sqlite3 *db, const char *table);

#endif /* ZCL_JOBS_STAGE_ROW_ITAG_H */
