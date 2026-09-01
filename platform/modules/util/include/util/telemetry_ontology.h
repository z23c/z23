/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Telemetry ontology — machine-readable MEANING for the network telemetry
 * fields that dumpstate already emits.
 *
 * The problem this closes. `dumpstate peer_lifecycle` returns
 * `"pre_handshake_disconnects":27` and nothing anywhere states what that
 * counts, what range is healthy, what a bad value implies, or what to look at
 * next. 27-of-332 on a healthy node and 8-of-8 on a node that cannot start
 * produce JSON that is IDENTICAL IN SHAPE; only the second one is the whole
 * story. An AI operator reading over a CLI cannot infer that.
 *
 * The mechanism. A declarative table (telemetry_ontology.def) carries one row
 * per emitted field: unit, a machine-evaluable health RULE, severity, what it
 * counts, what an unhealthy value implies, and the exact next command. The
 * table is static const data compiled into the binary, so it answers WITHOUT
 * a running node — which is exactly when an operator needs it most — and it
 * is fetched separately from values, so no routine dump grows by a byte.
 *
 * Layering: this is subsystem metadata about diagnostics output, not
 * consensus and not node state. It reads nothing and locks nothing.
 * Reentrant-safe and callable before boot.
 *
 * Related: engine/controllers/include/controllers/diagnostics_dumpers.def carries
 * the SUBSYSTEM-level descriptor (owner file, cost, freshness, key forms).
 * This file is strictly the FIELD level below it and duplicates none of that.
 *
 * Enforced by tools/lint/check_telemetry_ontology.sh: a field emitted inside a
 * covered dump function with no row here fails `make lint`.
 */
#ifndef ZCL_UTIL_TELEMETRY_ONTOLOGY_H
#define ZCL_UTIL_TELEMETRY_ONTOLOGY_H

#include <stdbool.h>
#include <stddef.h>

struct json_value;

/* What the number IS. Units are how a reader knows that 300000 is 0.3 s and
 * not 300000 blocks, and that a cumulative counter must be read as a ratio
 * against another cumulative counter rather than as a level. */
enum telemetry_unit {
    TFU_COUNT_TOTAL = 0, /* cumulative since boot; only ratios are meaningful */
    TFU_GAUGE,           /* instantaneous level; compare against a limit */
    TFU_BOOL,
    TFU_ENUM,            /* small closed string set */
    TFU_IDENTITY,        /* an id/address/hash: names a thing, never judged */
    TFU_SECONDS,
    TFU_MICROSECONDS,
    TFU_UNIX_TIME,
    TFU_BYTES,
    TFU_HEIGHT,          /* a block height */
    TFU_BLOCKS,          /* a difference in block heights */
    TFU_BPS_X1000,       /* blocks per second, fixed point x1000 */
};

/* How to judge the value. Every rule is evaluable by a machine against the
 * same dump the value came from — no prose parsing, no human inference. */
enum telemetry_rule {
    TFR_INFO = 0,     /* descriptive; carries no health verdict */
    TFR_EXPECT_ZERO,  /* any nonzero value is a finding */
    TFR_EXPECT_NONZERO,
    TFR_EXPECT_TRUE,
    TFR_EXPECT_FALSE,
    TFR_MIN_ABS,      /* healthy when value >= threshold */
    TFR_MAX_ABS,      /* healthy when value <= threshold */
    TFR_MIN_RATIO_OF, /* healthy when value*1000 >= threshold * dump[operand] */
    TFR_MAX_RATIO_OF, /* healthy when value*1000 <= threshold * dump[operand] */
};

enum telemetry_severity { TFS_INFO = 0, TFS_WARN, TFS_CRITICAL };

/* What evaluating one row against one dump body produced.
 *
 * These are DELIBERATELY not health levels. "we could not read it" (TV_ABSENT)
 * and "we read it and it is wrong" (TV_UNHEALTHY) are different facts, and the
 * mapping from a verdict to a health level depends on the row's severity and
 * rule — which is the caller's decision, not the evaluator's. Collapsing the
 * two here is exactly the defect that made an unreadable bool report as a
 * broken bool. */
enum telemetry_verdict {
    TV_HEALTHY = 0,
    TV_UNHEALTHY,
    TV_NOT_JUDGED,    /* the row is TFR_INFO: descriptive, carries no verdict */
    TV_ABSENT,        /* the value is missing, or not of the type the rule needs */
    TV_NOT_EVALUATED, /* an array-element row, or a ratio with no denominator */
};
/* The wire spelling. Stable: it is what dumpstate has always emitted. */
const char *telemetry_verdict_name(enum telemetry_verdict v);

/* One field's meaning. `path` is the dotted path inside that subsystem's
 * dumpstate body; a "[]" segment marks an array of objects (per-element rows
 * carry meaning but are not auto-evaluated, since the rollup above them is
 * what a verdict should key on). */
struct telemetry_field {
    const char *subsystem;
    const char *path;
    enum telemetry_unit unit;
    enum telemetry_rule rule;
    const char *operand;   /* sibling path for the ratio rules, else NULL */
    int threshold;         /* absolute for *_ABS, per-mille for *_RATIO_OF */
    enum telemetry_severity severity;
    const char *means;     /* what it counts — always present */
    const char *implies;   /* what an unhealthy value implies */
    const char *next;      /* the exact next command or field to read */
};

/* A path prefix that carries the same field set as another prefix, so the
 * table states it once. */
struct telemetry_alias {
    const char *subsystem;
    const char *prefix;
    const char *same_fields_as;
    const char *note;
};

/* The discovery index: an operator question mapped to the one command that
 * answers it. This is the half of the problem that costs time before any
 * field is even read — knowing WHICH of 23 state reports to open. */
struct telemetry_question {
    const char *id;
    const char *question;
    const char *keywords;    /* space-separated, lowercase */
    const char *command;     /* the one command that answers it */
    const char *subsystem;
    const char *fields;      /* comma-separated decisive field paths */
    const char *how_to_read; /* how to turn those fields into the answer */
};

size_t telemetry_field_count(void);
const struct telemetry_field *telemetry_field_at(size_t idx);
/* Exact (subsystem, path) match, or NULL. */
const struct telemetry_field *telemetry_field_lookup(const char *subsystem,
                                                     const char *path);
size_t telemetry_alias_count(void);
const struct telemetry_alias *telemetry_alias_at(size_t idx);
size_t telemetry_question_count(void);
const struct telemetry_question *telemetry_question_at(size_t idx);

bool telemetry_subsystem_covered(const char *subsystem);
size_t telemetry_subsystem_count(void);
const char *telemetry_subsystem_at(size_t idx);

const char *telemetry_unit_name(enum telemetry_unit u);
const char *telemetry_rule_name(enum telemetry_rule r);
const char *telemetry_severity_name(enum telemetry_severity s);
/* Render a row's rule into a machine-readable healthy-range expression, e.g.
 * "value <= 0.400 * summary.attempted" or "value != 0". Always NUL-terminates. */
void telemetry_field_healthy_range(const struct telemetry_field *f,
                                   char *out, size_t out_sz);

/* Ontology as JSON, node-free.
 *   key == NULL / ""          the whole table (subsystems + questions)
 *   key == "questions"        the discovery index only
 *   key == "<subsystem>"      one subsystem's field rows
 *   key == "<field>"          every row whose path ends in that field name
 * Returns false only on a NULL out. */
bool telemetry_ontology_json(struct json_value *out, const char *key);

/* Evaluate ONE row against a dumpstate body. This is THE rule evaluator —
 * telemetry_ontology_annotate() and the render layer both go through it, so a
 * field cannot be judged one way by `ops debug meaning` and another way by the
 * dump that carries it.
 *
 * `out_value` (required) receives a BORROWED pointer to the resolved value
 * inside `dump`, or NULL when the path did not resolve. It is valid only for
 * as long as `dump` is; copy the scalar out, never the pointer. Returns
 * TV_NOT_EVALUATED for a NULL row or a NULL dump. */
enum telemetry_verdict telemetry_field_evaluate(
    const struct telemetry_field *f, const struct json_value *dump,
    const struct json_value **out_value);

/* Evaluate the rules for `subsystem` against a dumpstate body and write
 * { subsystem, evaluated, healthy, findings:[{path,value,verdict,severity,
 * means,implies,next,healthy_range}], ... }. Array-element rows are reported
 * with verdict "not_evaluated" (their rollup is what carries the verdict).
 * Returns false on NULL args or an uncovered subsystem. */
bool telemetry_ontology_annotate(const char *subsystem,
                                 const struct json_value *dump,
                                 struct json_value *out);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe. */
bool telemetry_ontology_dump_state_json(struct json_value *out,
                                        const char *key);

#endif /* ZCL_UTIL_TELEMETRY_ONTOLOGY_H */
