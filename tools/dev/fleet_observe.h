/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: generate engine/composition/fleet_observations.def from the
 *          experiment ledger — the testable core, with no main() of its own
 *          so tests/harness/src/test_fleet_observe.c can call it directly.
 *          tools/dev/fleet_observe_main.c is the standalone CLI shim built
 *          into build/bin/z23-fleet-observe.
 *
 * CONTRACT. `docs/agent/EXECUTOR_HEURISTICS.md`'s doctrine table is asserted;
 * this table is MEASURED. Every row here is derived from ledger rows over a
 * trailing window, never hand-typed — tools/lint/check_fleet_observations.sh
 * is the price of writing it: --check regenerates from a fixture ledger and
 * diffs the committed .def, so a hand edit is caught rather than believed.
 *
 * SCHEMA. ~/.local/state/zclassic23/experiments/SCHEMA.md is the ledger's
 * closed vocabulary for `task_class`, `executor`, `harness`, `effort` and
 * `outcome`. A row using a term outside that vocabulary, or missing a
 * column, is a malformed ledger — refused by line number, never guessed at.
 *
 * THRESHOLDS (named here, never as bare numbers in the emitted .def):
 *   FO_ROUTABLE_MIN_N     an (executor, task_class) pair needs this many
 *                         measured outcomes before it can be called routable.
 *   FO_ROUTABLE_MIN_P_*   land-rate floor for routable_for, as a fraction
 *                         (num/den) so no float rounding enters a ground fact.
 *   FO_REFUSED_MIN_N      minimum n before a 0-for-n pair is refused_for.
 *   FO_PROBE_MAX_N        below this n (and not already refused), a pair is
 *                         probe_for: unobserved enough to still be explored.
 *   FO_FINISHER_MIN_P_*   FIX_LAND share of n needed to add a second row,
 *                         handles_with_finisher, alongside the primary one.
 * A pair that clears none of routable/refused/probe (n >= FO_ROUTABLE_MIN_N,
 * land rate below the routable floor, and not all-zero) is observed_for: the
 * fleet has enough rows to say something, but not enough to route on. */
#ifndef ZCL_TOOLS_DEV_FLEET_OBSERVE_H
#define ZCL_TOOLS_DEV_FLEET_OBSERVE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    FO_TOKEN_CAP = 40,
    FO_NOTE_CAP = 256,
    FO_LINE_CAP = 1024,
    FO_MAX_ROWS = 4096,      /* ledger rows read in one generation */
    FO_MAX_PAIRS = 512,      /* distinct (executor, task_class) pairs */
    FO_MAX_OBS_ROWS = 1024,  /* FLEET_OBSERVED rows emitted */

    /* thresholds, see file header */
    FO_ROUTABLE_MIN_N = 3,
    FO_ROUTABLE_MIN_P_NUM = 4,
    FO_ROUTABLE_MIN_P_DEN = 5,
    FO_REFUSED_MIN_N = 2,
    FO_PROBE_MAX_N = 3,
    FO_FINISHER_MIN_P_NUM = 1,
    FO_FINISHER_MIN_P_DEN = 2,

    FO_DEFAULT_WINDOW_DAYS = 7,
};

/* One parsed `result` ledger row. `predict` rows are read (to advance the
 * window anchor) but never counted toward n. */
struct fo_row {
    int64_t ts_unix;
    char kind[FO_TOKEN_CAP];
    char task_class[FO_TOKEN_CAP];
    char executor[FO_TOKEN_CAP];
    char outcome[FO_TOKEN_CAP];
};

/* Aggregation bucket for one (executor, task_class) pair. */
struct fo_pair {
    char executor[FO_TOKEN_CAP];
    char task_class[FO_TOKEN_CAP];
    int64_t n;
    int64_t land;
    int64_t fix_land;
};

/* One emitted FLEET_OBSERVED row. */
struct fo_observation {
    char subject[FO_TOKEN_CAP];
    char relation[FO_TOKEN_CAP];
    char object[FO_TOKEN_CAP];
    int64_t num;
    int64_t den;
};

/* ── ledger parsing ────────────────────────────────────────────────────── */

/* Parses one ISO-8601 UTC timestamp ("YYYY-MM-DDTHH:MM:SSZ") into Unix
 * seconds. Returns false on a malformed string. */
bool fo_parse_iso8601(const char *s, int64_t *out);

/* Parses one non-header TSV ledger line (22 tab-separated fields per
 * SCHEMA.md) into `out`. `line_no` is 1-based, used only to build `err`.
 * Returns false and fills `err` (bounded, always NUL-terminated) on: a wrong
 * field count, an unparsable timestamp, or a value outside the closed
 * enums this generator reads (kind, task_class, executor, outcome). */
bool fo_parse_line(const char *line, size_t line_no, struct fo_row *out,
                    char *err, size_t err_cap);

/* Closed-vocabulary membership, exposed for the malformed-row and
 * unknown-enum tests. */
bool fo_task_class_known(const char *v);
bool fo_executor_known(const char *v);
bool fo_kind_known(const char *v);
bool fo_outcome_known(const char *v);

/* True for the LAND-class outcomes: LAND, FIX_LAND, READY, landed. */
bool fo_outcome_is_land(const char *outcome);

/* ── aggregation and classification ───────────────────────────────────── */

/* Folds `rows[0..row_count)` into `pairs`, keeping only `kind == "result"`
 * rows whose ts falls in [anchor_unix - window_days*86400, anchor_unix].
 * Returns the number of pairs written (each pair appears once). */
size_t fo_aggregate(const struct fo_row *rows, size_t row_count,
                     int64_t anchor_unix, int window_days,
                     struct fo_pair *pairs, size_t pairs_cap);

/* The latest ts among `rows[0..row_count)`, or 0 if row_count == 0. This is
 * the window anchor: "trailing N days" is measured from the ledger's own
 * newest row, not wall-clock time, so a committed fixture regenerates
 * identically forever. */
int64_t fo_latest_ts(const struct fo_row *rows, size_t row_count);

/* Classifies one aggregated pair into 1 or 2 FLEET_OBSERVED rows (the
 * primary relation, plus handles_with_finisher when it clears the finisher
 * floor). Returns the count written (1 or 2). A pair with n == 0 is never
 * passed to this function by fo_aggregate. */
size_t fo_classify(const struct fo_pair *pair, struct fo_observation *out2);

/* ── rendering ─────────────────────────────────────────────────────────── */

/* Reads the ledger at `path` (header line + TSV rows) into `rows`, up to
 * `cap` rows. Returns false on the first malformed row or unknown enum
 * (fail-closed), filling `err` with the line number and reason; on success
 * `*count_out` holds the number of rows parsed. A missing file is also a
 * failure, reported in `err`. */
bool fo_read_ledger(const char *path, struct fo_row *rows, size_t cap,
                    size_t *count_out, char *err, size_t err_cap);

/* Renders the full engine/composition/fleet_observations.def text (header,
 * guard, rows, trailer) into `out` (bounded, NUL-terminated). `source_desc`
 * names the ledger the rows came from, for the generated-file header.
 * Returns the number of bytes that would have been written (snprintf
 * semantics), so a caller can detect truncation. */
size_t fo_render_def(const struct fo_observation *obs, size_t obs_count,
                      int window_days, int64_t generated_unix,
                      const char *source_desc, char *out, size_t out_cap);

#endif /* ZCL_TOOLS_DEV_FLEET_OBSERVE_H */
