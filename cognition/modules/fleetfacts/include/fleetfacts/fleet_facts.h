/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: The fleet's own doctrine as typed rows, asked by subject. */
#ifndef ZCL_FLEETFACTS_FLEET_FACTS_H
#define ZCL_FLEETFACTS_FLEET_FACTS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* WHAT THIS IS. engine/composition/fleet_facts.def holds what the fleet knows
 * about itself — which executor handles which unit kind, what the landing
 * rules are, which proof failure signature names which trap. This module is
 * the only reader of that table, and `dev.know` is the only caller. There is
 * no inference here: a row is answered or it is not, and "not" is answered as
 * one UNKNOWN row rather than as an empty result, so an ask is never met with
 * silence a caller can mistake for a denial.
 *
 * WHAT THIS IS NOT. It is not the ontology module. cognition/modules/ontology
 * is a fixed four-term Horn kernel whose vocabulary several tests pin; this
 * is a growing bounded table with no rules and no evaluator. It stores no
 * runtime observation either: every row here is DOCTRINE today, and the
 * OBSERVED confidence exists so that a later feed of gate and ledger
 * outcomes has a seam to arrive through without changing this shape. */

enum {
    ZCL_FLEET_FACTS_VERSION = 1,
    /* A subject, relation, object or context token. The longest terms are
     * tracked repository paths; the lint gate refuses a longer one. */
    ZCL_FLEET_FACTS_TOKEN_CAP = 64,
    /* A row's justification prose, also gate-bounded. */
    ZCL_FLEET_FACTS_WHY_CAP = 224,
    /* Rows one answer may carry. A query is subject-bound, so this is far
     * above the largest subject in the table. */
    ZCL_FLEET_FACTS_MAX_ROWS = 16,
};

enum zcl_fleet_fact_confidence {
    /* No row answered the ask. Synthesized, never stored. */
    ZCL_FLEET_CONFIDENCE_UNKNOWN = 0,
    /* Asserted by a fleet_facts.def row. */
    ZCL_FLEET_CONFIDENCE_DOCTRINE = 1,
    /* Derived from a gate receipt or a ledger. No such row exists yet. */
    ZCL_FLEET_CONFIDENCE_OBSERVED = 2,
};

/* Value semantics: a row is copied out, so it outlives nothing. */
struct zcl_fleet_fact_v1 {
    char subject[ZCL_FLEET_FACTS_TOKEN_CAP];
    char relation[ZCL_FLEET_FACTS_TOKEN_CAP];
    char object[ZCL_FLEET_FACTS_TOKEN_CAP];
    char context[ZCL_FLEET_FACTS_TOKEN_CAP];
    char why[ZCL_FLEET_FACTS_WHY_CAP];
    /* The row's canonical root, 64 lowercase hex: SHA3-256 over the domain
     * string and the four tokens. It identifies this exact row and changes
     * the moment any token does. The UNKNOWN row carries 64 zeros, because
     * there is no row to point at. */
    char provenance[65];
    enum zcl_fleet_fact_confidence confidence;
};

struct zcl_fleet_facts_answer_v1 {
    struct zcl_fleet_fact_v1 rows[ZCL_FLEET_FACTS_MAX_ROWS];
    size_t row_count;   /* rows carried here */
    size_t total;       /* rows that matched, before max_rows cut anything */
    bool truncated;     /* total > row_count; the caller was told, not fooled */
    bool unknown;       /* the single row is the synthesized no-answer */
};

/* The whole table, in declaration order. */
size_t zcl_fleet_facts_row_count(void);
bool zcl_fleet_facts_get(size_t index, struct zcl_fleet_fact_v1 *out);

/* The three closed vocabularies, for a caller that wants to say what is
 * askable before asking. A context may legitimately carry no rows. */
size_t zcl_fleet_facts_relation_count(void);
const char *zcl_fleet_facts_relation_at(size_t index);
size_t zcl_fleet_facts_context_count(void);
const char *zcl_fleet_facts_context_at(size_t index);
size_t zcl_fleet_facts_term_count(void);
const char *zcl_fleet_facts_term_at(size_t index);

const char *zcl_fleet_facts_confidence_name(enum zcl_fleet_fact_confidence c);

/* Ask what the fleet knows about `subject`. `relation` and `context` are
 * optional filters; NULL or "" means unfiltered. `max_rows` clamps to
 * ZCL_FLEET_FACTS_MAX_ROWS and a cut always sets `truncated` and reports the
 * full `total`. Returns false only on a malformed ask (no out, no subject);
 * a subject nobody has written a row about is an answer, not an error. */
bool zcl_fleet_facts_query(const char *subject, const char *relation,
                           const char *context, size_t max_rows,
                           struct zcl_fleet_facts_answer_v1 *out);

#endif /* ZCL_FLEETFACTS_FLEET_FACTS_H */
