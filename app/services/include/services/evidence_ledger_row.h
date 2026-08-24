/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * evidence_ledger_row — the ONE reader for the flock-appended JSONL evidence
 * ledgers this repo's out-of-process recorders write under
 * ~/.local/state/zclassic23-*, so the node can describe evidence that exists
 * on disk without a second parser per ledger.
 *
 * WHY IT IS SHARED, not copied. Two in-node readers now exist over this same
 * file shape (services/stopwatch_skip_watch.h over the stopwatch history,
 * services/tip_agreement_watch.h over the off-host tip-hash agreement
 * ledger), and the subtle part is not the field extraction — it is the
 * BOUNDED TAIL READ:
 *
 *   - after a mid-file seek the first line is a FRAGMENT and must be dropped,
 *     never folded as a row (folding it invents a sample) — and dropping it
 *     must not cost the NEXT line, even when the fragment is long enough to
 *     fill the row buffer;
 *   - a row longer than the row buffer must have its tail CONSUMED, not
 *     folded as a second phantom row — while a row that FITS must not be
 *     mistaken for one that did not, which is a question about the missing
 *     newline and the data length, not about the buffer being exactly full;
 *   - a line with no newline at end of file is INCOMPLETE, not a sample. Every
 *     reader here takes the last row it was handed as authoritative for the
 *     per-sample fields, so handing over a torn append lets half a row become
 *     "the" current sample;
 *   - a row's CONTENT cannot decide where the row ends. A torn append can
 *     leave an embedded NUL in the middle of an otherwise newline-terminated
 *     line, so row boundaries are counted in bytes and never found with
 *     strlen(): the corrupt row is dropped, and the intact row after it is
 *     still parsed;
 *   - a missing or unreadable ledger is DATA (nothing scanned), never an
 *     error a caller branches on — a host that never installed a recorder
 *     looks exactly like that.
 *
 * Getting any of those wrong fabricates evidence, so there is one
 * implementation and both readers call it.
 *
 * THE ROW SHAPE this supports, deliberately narrow: single-line JSON objects
 * with no duplicate keys and scalar values; arrays may contain scalars or
 * bounded flat objects with scalar values because tip-agreement evidence
 * carries `{height,hash,peers}` entries. It is NOT a general JSON parser and
 * must not grow into one; any deeper shape belongs in json/json.h.
 *
 * Pure: no allocation, no clock, no globals, no threads. Reentrant-safe. */

#ifndef ZCL_SERVICES_EVIDENCE_LEDGER_ROW_H
#define ZCL_SERVICES_EVIDENCE_LEDGER_ROW_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The longest row this reader accepts, in DATA bytes with the newline
 * excluded. One ledger row is a flat JSON object well under 1 KiB; 4 KiB is
 * generous. A row longer than this is not an evidence row — see the overlong
 * note in evidence_ledger_scan_tail(). A row of exactly this length IS a row:
 * the boundary is decided by counting data bytes to the next newline, never by
 * a read buffer filling up or by where a NUL happens to sit. */
#define EVIDENCE_ROW_MAX 4096

/* Bounded, NUL-terminating copy of `len` bytes. A NULL/zero-cap dst is a
 * no-op; a NULL src writes the empty string. */
void evidence_copy_bounded(char *dst, size_t cap, const char *src, size_t len);

/* First occurrence of NUL-terminated `needle` inside [hay, hay+len), or NULL.
 * Substring search over a non-NUL-terminated span — that is why it is here
 * and not strstr(). */
const char *evidence_find_sub(const char *hay, size_t len, const char *needle);

/* Validate the complete narrow row grammar: one object, at most 64 unique
 * unescaped keys, and string/integer/bool/null values or arrays containing
 * those scalars and flat objects of at most 16 unique scalar fields. Trailing
 * bytes, deeper containers, duplicate keys and invalid escapes are rejected. */
bool evidence_row_flat_object_valid(const char *row, size_t len);

/* Copy a string-valued field into dst (always NUL-terminated when cap > 0).
 * Returns true when the FIELD EXISTS AS A JSON STRING, even when empty:
 * callers must be able to tell "the recorder wrote an empty value" from
 * "this row predates the field". */
bool evidence_row_str(const char *row, size_t len, const char *key,
                      char *dst, size_t cap);

/* Read an integer-valued field. Returns false when the field is absent or
 * not a number — JSON `null` included, because every recorder here writes
 * null for "I could not measure this", and null is not a zero. */
bool evidence_row_int(const char *row, size_t len, const char *key,
                      int64_t *out);

/* Read a JSON boolean field.  The token must be exactly `true` or `false`;
 * prefixes such as `truex` are rejected rather than accepted as evidence. */
bool evidence_row_bool(const char *row, size_t len, const char *key,
                       bool *out);

/* True only when the named field exists and its exact value is JSON null. */
bool evidence_row_is_null(const char *row, size_t len, const char *key);

/* Per-row callback. `row` is NOT NUL-terminated; use `len`. */
typedef void (*evidence_row_fn)(const char *row, size_t len, void *ctx);

/* Split an in-memory ledger (newline-separated rows) and hand each row to
 * `fn`. Pure: no IO, no clock. Returns false only on bad arguments.
 *
 * Unlike the tail read below there is no incomplete-line case here, and that
 * is not an oversight: the CALLER chose where this buffer ends, so a final
 * segment without a newline is a row the caller handed over deliberately, not
 * a write caught half-finished on disk. */
bool evidence_ledger_scan_text(const char *text, size_t len,
                              evidence_row_fn fn, void *ctx);

/* Read the trailing `tail_bytes` of `path` and hand each COMPLETE row to
 * `fn`, streaming so peak memory is one row rather than one tail. A COMPLETE
 * row is one that ended in a newline and is no longer than EVIDENCE_ROW_MAX
 * data bytes; nothing else ever reaches `fn`.
 *
 * A missing / empty / unreadable file is NOT a failure: `fn` is simply never
 * called and the call returns true. Returns false only on bad arguments.
 *
 * The two drop counters are separate BECAUSE THEY MEAN DIFFERENT THINGS. Both
 * may be NULL; both are INCREMENTED, never assigned:
 *   `out_overlong`   a row longer than EVIDENCE_ROW_MAX data bytes — corrupt
 *                    or foreign content. Callers count it as malformed.
 *   `out_incomplete` a write that did not all land: a line that ended without
 *                    a newline (the recorder's append was caught mid-write, or
 *                    the file is truncated), or one whose content carries an
 *                    embedded NUL. NOT malformed (the bytes may be a perfectly
 *                    good row that is not all there yet) and NOT a sample — it
 *                    is dropped, so a torn line can never become the last row
 *                    scanned, and dropping it never costs the row after it.
 * Either way the rest of that physical line is consumed, never folded as a
 * second row.
 *
 * The first line after a mid-file seek is a fragment and is dropped, without
 * counting toward either counter (its true length is unknown, so calling it
 * malformed would invent a defect) and without costing the line after it. */
bool evidence_ledger_scan_tail(const char *path, size_t tail_bytes,
                              evidence_row_fn fn, void *ctx,
                              unsigned *out_overlong,
                              unsigned *out_incomplete);

/* Resolve "<dir>/<file>" where dir is $<dir_env> when set and non-empty,
 * else "$HOME/<home_rel_dir>". Returns false (and empties `out`) when there
 * is no env override and no HOME, or when the result would not fit. Shared so
 * a node-side reader and the recorder script read the SAME env var and the
 * SAME default — a reader pointed at a different path than the writer reports
 * "no evidence" forever. */
bool evidence_ledger_resolve_path(const char *dir_env, const char *home_rel_dir,
                                 const char *file, char *out, size_t cap);

#endif /* ZCL_SERVICES_EVIDENCE_LEDGER_ROW_H */
