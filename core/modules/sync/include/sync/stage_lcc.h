/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * stage_lcc — Log-Cursor Contiguity (LCC) write-rule guard.
 *
 * See docs/work/fail-safe-architecture.md §0c "Design B — LOG-CURSOR
 * CONTIGUITY (LCC), the prevention side" and docs/TENACITY.md ("a new wedge
 * class earns a new write-time invariant, never a new repair rung").
 *
 * The invariant: for every success-checked stage log L with cursor C and
 * trusted base B, every height in [B, C) has a row in L at every commit
 * boundary. A stage cursor is persisted in the `stage_cursor` table; each
 * stage's per-height verdict rows live in a colocated `<stage>_log` table
 * keyed by an INTEGER PRIMARY KEY `height` (body_fetch_log, body_persist_log,
 * proof_validate_log, script_validate_log, utxo_apply_log, tip_finalize_log,
 * header_admit_log — and any future stage that follows the same convention).
 *
 * This guard is enforced at the SINGLE cursor-write chokepoint
 * (platform/modules/util/src/stage.c cursor_write_locked). A cursor advance over a rowless
 * hole — a borrowed-seed rowless span, a torn-snapshot coin hole, a boot
 * force-raise past a gap, or any cursor set above the durably-logged frontier —
 * is IMPOSSIBLE TO PERSIST: the write is refused inside its own transaction, so
 * the incoherent cursor is never committed. It is a WRITE rule (prevention),
 * not a repair rung; it forbids only INCOHERENT writes and never weakens an
 * existing consensus guard (a genuine consensus reject writes an ok=0 row — the
 * row still EXISTS, so contiguity holds and the named halt is preserved).
 */
#ifndef UTIL_STAGE_LCC_H
#define UTIL_STAGE_LCC_H

#include <sqlite3.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RAISE rule. Called from inside the cursor-write transaction, BEFORE the
 * cursor UPSERT persists `new_cursor` for stage `name`. Returns true when the
 * raise is coherent: every height in the newly-covered span [old_cursor,
 * new_cursor) that is at or above the trusted base has a row in the stage's
 * `<name>_log` table (visible in this same transaction). Returns false when the
 * raise would persist a rowless hole; *err (errcap bytes, NUL-terminated) then
 * names the stage and the first missing height.
 *
 * Always-allowed (returns true) cases: a non-raise (new_cursor <= old_cursor);
 * a `name` that has no `<name>_log` table (an arbitrary named cursor — not a
 * success-checked stage log); a covered span that lies entirely below the
 * trusted base. `db` MUST be the same handle/transaction as the pending cursor
 * write so just-inserted rows are visible. Never allocates. */
bool stage_lcc_check_raise(sqlite3 *db, const char *name,
                           uint64_t old_cursor, uint64_t new_cursor,
                           char *err, size_t errcap);

/* Trusted base. A base value B means state is complete and vetted up to and
 * INCLUDING height B: heights <= B are exempt from the contiguity requirement,
 * so the cursor may sit at B+1 without a per-height log row for every ancestor
 * (the design's `target <= trusted_base + 1` exemption). The base is a single
 * global value in progress_meta key "lcc:trusted_base"; absent / 0 means NO
 * exemption (0 is not "genesis vetted" — a genuine genesis fold writes the h=0
 * row anyway). The setter co-commits inside the caller's already-open
 * transaction — the base is a write-time fact, raised only alongside the
 * complete, crypto-vetted state commitment it authorizes, never a
 * caller-asserted trust flag. A SHA3 byte-digest of a borrowed snapshot is NOT
 * such a fact; do not raise the base for an assisted/borrowed seed. */
uint64_t stage_lcc_trusted_base(sqlite3 *db);
bool     stage_lcc_set_trusted_base_in_tx(sqlite3 *db, uint64_t base);

/* Enforcement switch (staged rollout). When enabled, the chokepoint REFUSES an
 * incoherent raise (the wedge is unwritable). When disabled — the default,
 * absent / 0 in progress_meta key "lcc:enforce" — the chokepoint still COMPUTES
 * the verdict and logs a loud "would-refuse" line for every detected hole
 * birth, but ALLOWS the write, so turning the guard on cannot itself brick a
 * boot that still depends on a not-yet-removed force-raise / borrowed-seed
 * install. The cure lane flips this on (in the same change that deletes the
 * remaining hole factories). The setter co-commits inside the caller's tx. */
bool stage_lcc_enforcement_enabled(sqlite3 *db);
bool stage_lcc_set_enforcement_in_tx(sqlite3 *db, bool on);

/* First-gap probe (the post-commit ratchet). On success sets *gap to the lowest
 * height in [base, cursor) that has NO row in `<name>_log` and returns true.
 * Returns false when the prefix is contiguous (no gap), the range is empty, or
 * the table is absent. Ordered index scan; used by the ratchet and to name the
 * offending height in a refusal. */
bool stage_lcc_first_gap(sqlite3 *db, const char *name,
                         uint64_t base, uint64_t cursor, uint64_t *gap);

/* DELETE-rule clamp. Lower the persisted cursor for `name` to
 * min(current, max_height) so a row deletion at max_height can never leave the
 * cursor above the surviving log frontier. A pure lower — it goes through the
 * chokepoint (which always permits lowering) and never raises. Returns true on
 * success, including the no-op when the cursor is already <= max_height. */
bool stage_cursor_clamp_to(sqlite3 *db, const char *name, uint64_t max_height);

#ifdef __cplusplus
}
#endif

#endif /* UTIL_STAGE_LCC_H */
