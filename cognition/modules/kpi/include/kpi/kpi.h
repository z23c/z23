/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * kpi — a durable, tamper-evident ledger of the numbers this build already
 * produces, so progress on the tree is measurable over time instead of
 * remembered.
 *
 * WHY THIS EXISTS
 * ---------------
 * Every number here already exists somewhere in the checkout: the generated
 * capability inventory, the registered test catalog, the Makefile's lint gate
 * list, the determinism ratchet baseline, the code index's territory rows.
 * What did not exist was a record of what those numbers WERE last time, so
 * "did that get better?" was answered from memory or not at all.
 *
 * This module invents no metric. It reads artifacts the build already writes,
 * folds them into one canonical frame, and appends that frame to a
 * engine/modules/chainlog log. Comparing two frames is then arithmetic, not archaeology.
 *
 * THE ONE RULE: 0 AND "I COULD NOT LOOK" ARE DIFFERENT FACTS
 * ----------------------------------------------------------
 * A metric whose source artifact is missing, unreadable, or whose parse
 * recognises nothing is KPI_STATE_UNAVAILABLE and carries no value. It is
 * never reported as 0. A ledger that conflated the two would record a repo
 * with no lint gates and a repo whose Makefile moved as the same event, and
 * every delta computed across that boundary would be a fiction.
 *
 * A run in which a metric is unavailable STILL writes a frame — the
 * unavailability is itself the fact being recorded — and the summary says how
 * many were unavailable so nobody reads a short ledger as a clean one.
 *
 * WHAT "PARSE RECOGNISED NOTHING" MEANS, PER SOURCE
 * -------------------------------------------------
 * The line between an honest 0 and an unreadable artifact is drawn per
 * source, deliberately, because it is not the same line everywhere:
 *
 *   capability inventory   readable AND at least one `"record":"…"` field
 *                          seen. Zero records of ANY kind means we did not
 *                          understand the file, not that the tree has no
 *                          capabilities. Zero records of the REQUESTED kind,
 *                          in a file that has other records, is an honest 0.
 *   test group catalog     readable AND at least one ZCL_TEST_GROUP row.
 *   Makefile LINT_GATES    the assignment found AND at least one gate token.
 *   determinism baseline   readable. Zero non-comment rows is an HONEST 0 and
 *                          is the goal state: the ratchet owes nothing. This
 *                          is the one source where 0 is a real answer, which
 *                          is exactly why it is spelled out here.
 *   territories/files      a code index handle AND territory_list() > 0.
 *
 * CANONICAL BYTES
 * ---------------
 * The frame payload is byte-identical for identical metric values regardless
 * of build flags, host, or clock. It carries no timestamp, no path and no pid:
 * two honest runs over the same tree must produce the same bytes, or the
 * ledger cannot be compared with a memcmp and its whole point is lost.
 * Ordering is the chainlog's `seq`, which is what a log is for.
 *
 *   0            source_root_sha3[32]  which tree this measured. All-zero
 *                                      means UNKNOWN — codeindex_source_root_sha3()
 *                                      never fabricates an all-zero
 *                                      generation, so the value is unambiguous.
 *   32           count u32 big-endian
 *   then, per metric, in the FIXED sorted-by-id order of kpi_metric_defs():
 *                id_len u8, id bytes, state u8 (0 present, 1 unavailable),
 *                value u64 big-endian (0 when unavailable)
 *
 * The state byte is what keeps UNAVAILABLE distinguishable from a real 0 on
 * disk. Dropping it would make the two encode identically and silently
 * destroy the distinction the whole module exists to preserve.
 *
 * IT GRANTS NOTHING. A frame is a measurement, never a permission, never a
 * pass, never an approval to land anything.
 */

#ifndef ZCL_KPI_H
#define ZCL_KPI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "chainlog/chainlog.h"

struct codeindex;

#define KPI_ID_MAX      32u
#define KPI_METRIC_MAX  16u
#define KPI_PAYLOAD_MAX 1024u

/* The chainlog record kind every kpi frame is written under. */
#define KPI_FRAME_KIND  1u

/* Which way is better. NEUTRAL means the number is context, not a score:
 * "more territories" is neither good nor bad and pretending otherwise would
 * manufacture a verdict out of a fact. */
enum kpi_direction {
    KPI_DIRECTION_NEUTRAL = 0,
    KPI_DIRECTION_LOWER_IS_BETTER,
    KPI_DIRECTION_HIGHER_IS_BETTER
};

/* On-disk values. Do not renumber: they are payload bytes. */
enum kpi_state {
    KPI_STATE_PRESENT = 0,
    KPI_STATE_UNAVAILABLE = 1
};

enum kpi_verdict {
    KPI_VERDICT_UNAVAILABLE = 0, /* this run could not measure it */
    KPI_VERDICT_NO_BASELINE,     /* nothing prior to compare against */
    KPI_VERDICT_UNCHANGED,
    KPI_VERDICT_IMPROVED,
    KPI_VERDICT_REGRESSED
};

const char *kpi_direction_label(enum kpi_direction d);
const char *kpi_state_label(enum kpi_state s);
const char *kpi_verdict_label(enum kpi_verdict v);

/* One metric's static identity: what it is called, which way is better, the
 * artifact it is read from, and the EXACT command a reader runs to see the
 * rows behind the number. A number nobody can drill into is a number nobody
 * can act on, so `drill` is part of the definition rather than prose in a doc
 * that would rot separately. */
struct kpi_metric_def {
    const char        *id;
    enum kpi_direction direction;
    const char        *source; /* repo-relative artifact, or "" for the index */
    const char        *drill;
};

/* Every metric, in the fixed sorted-by-id order the payload encodes. */
const struct kpi_metric_def *kpi_metric_defs(size_t *count);
const struct kpi_metric_def *kpi_metric_def_by_id(const char *id);

struct kpi_entry {
    char           id[KPI_ID_MAX];
    enum kpi_state state;
    uint64_t       value; /* meaningless, and always 0, when unavailable */
};

struct kpi_frame {
    uint8_t          source_root_sha3[32]; /* all-zero = unknown tree */
    uint32_t         count;
    struct kpi_entry metric[KPI_METRIC_MAX];
};

/* ── the parsers, exposed so they can be pointed at a fixture ─────────────
 * Each returns false when the artifact is missing, unreadable, or recognised
 * nothing — that is the UNAVAILABLE signal, and it is never folded into a 0.
 * `*out` is written only on true. */

/* Occurrences of `"record":"<record>"` in a JSONL artifact. `*out_total`, when
 * non-NULL, receives the count of `"record":"` fields of ANY kind, which is
 * what separates "no records of this kind" from "not a records file". */
bool kpi_count_jsonl_records(const char *path, const char *record,
                             uint64_t *out, uint64_t *out_total);

/* Registered group rows in a catalog .def — ZCL_TEST_GROUP and ZCL_SPEC_GROUP
 * both count, because both are rows `test_parallel --list` prints and
 * dispatches. The number is defined to be what the drill-down command beside
 * it shows; a metric whose drill-down disagrees is one nobody can check. */
bool kpi_count_test_groups(const char *path, uint64_t *out);

/* Gate tokens in the Makefile's LINT_GATES := backslash-continued list. */
bool kpi_count_lint_gates(const char *makefile_path, uint64_t *out);

/* Non-comment, non-blank rows of a lint baseline file. Zero is honest here. */
bool kpi_count_baseline_rows(const char *path, uint64_t *out);

/* ── collection ──────────────────────────────────────────────────────────
 * Fill every metric for the checkout at `root`. `ci` may be NULL, in which
 * case the index-derived metrics are UNAVAILABLE rather than guessed and the
 * frame's source root stays all-zero. Always fills the full metric set: an
 * unmeasurable metric is present in the frame WITH state UNAVAILABLE, because
 * omitting it would make it indistinguishable from a metric that did not
 * exist yet. */
void kpi_collect(const char *root, struct codeindex *ci,
                 struct kpi_frame *out);

/* ── canonical bytes ─────────────────────────────────────────────────── */

/* Encode into `buf`. Returns the byte count, or 0 if it does not fit or an id
 * is malformed. */
size_t kpi_encode(const struct kpi_frame *f, uint8_t *buf, size_t cap);

/* Decode. Refuses trailing bytes, a short buffer, an unknown state byte, a
 * zero-length id and a non-zero value on an unavailable metric, rather than
 * accepting a frame it half-understood. */
bool kpi_decode(const uint8_t *buf, size_t len, struct kpi_frame *out);

const struct kpi_entry *kpi_frame_find(const struct kpi_frame *f,
                                       const char *id);

/* The verdict for `cur` against `prev`. `prev` is NULL when no prior frame
 * carried this id, which is NO_BASELINE and never UNCHANGED — "the same as
 * nothing" is not a measurement. An unavailable current reading is
 * UNAVAILABLE whatever the baseline said; so is an unavailable baseline,
 * because a delta against a number nobody read is invented. */
enum kpi_verdict kpi_verdict_of(enum kpi_direction d,
                                const struct kpi_entry *prev,
                                const struct kpi_entry *cur);

/* ── the ledger ──────────────────────────────────────────────────────── */

struct kpi_ledger_result {
    enum zcl_chainlog_status status;
    bool                     wrote;
    uint64_t                 seq;           /* the frame just appended */
    bool                     have_previous;
    struct kpi_frame         previous;      /* the most recent PRIOR frame */
    uint64_t                 prior_records; /* frames in the log before this run */
    uint64_t                 torn_bytes;    /* uncommitted tail open() discarded */
};

/* The stream id this module's logs are bound to: SHA3-256("zcl.code_kpi.v1").
 * Appending a kpi frame to someone else's log is a STREAM_MISMATCH, not a
 * silent write into another history. */
void kpi_stream_id(uint8_t out[32]);

/* Read the most recent prior frame from `path`, then append `cur`. The read
 * happens FIRST and on purpose: `previous` must be the baseline this run is
 * measured against, never the row this run just wrote. */
bool kpi_ledger_record(const char *path, const struct kpi_frame *cur,
                       struct kpi_ledger_result *out);

#endif /* ZCL_KPI_H */
