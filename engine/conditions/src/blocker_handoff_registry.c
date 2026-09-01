// one-result-type-ok:lookup-predicate — this file owns no orchestration
// result. Its bool exports are pure table lookups over two compile-time .def
// tables; there is no fallible service lifecycle whose failure reason must
// travel via struct zcl_result.

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * blocker_handoff_registry — see conditions/blocker_handoff_registry.h.
 *
 * Two compile-time tables, expanded in place and joined by one glob rule:
 *
 *   blocker_remedy_bindings.def     id/pattern -> condition | ESCAPE(a) | OWNER
 *   blocker_operator_decisions.def  id/pattern -> the decision a person owns
 *
 * The first already existed and is enforced by tools/scripts/
 * check_blocker_remedy.sh; nothing here re-implements it. What was missing is
 * that the ratchet stopped at the build: a blocker rendered `escape_action: ""`
 * whether the condition engine was actively healing it or nothing in the tree
 * would ever touch it. This module carries the distinction to runtime.
 *
 * Rows stringize (the .def uses bare tokens for the id and the remedy), which
 * is the same projection tools/command/native_code_emitter_command.c already
 * takes over the remedy table — one .def, two readers, no second source of
 * truth. */

#include "conditions/blocker_handoff_registry.h"

#include "codeindex/codeindex_emitter.h"   /* codeindex_emit_glob_match */
#include "json/json.h"
#include "util/blocker.h"
#include "util/log_macros.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* ── Table 1: the remedy ratchet ─────────────────────────────────────── */

struct handoff_remedy_row {
    const char *pattern;
    const char *remedy;
};

#define ZCL_BLOCKER_REMEDY(id, remedy) { #id, #remedy },
static const struct handoff_remedy_row k_remedy_rows[] = {
#include "conditions/blocker_remedy_bindings.def"
};
#undef ZCL_BLOCKER_REMEDY

/* ── Table 2: the operator decisions ─────────────────────────────────── */

struct handoff_decision_row {
    const char *pattern;
    const char *decision;
};

#define ZCL_BLOCKER_DECISION(id, text) { #id, (text) },
static const struct handoff_decision_row k_decision_rows[] = {
#include "conditions/blocker_operator_decisions.def"
};
#undef ZCL_BLOCKER_DECISION

#define HANDOFF_REMEDY_ROWS   (sizeof(k_remedy_rows) / sizeof(k_remedy_rows[0]))
#define HANDOFF_DECISION_ROWS \
    (sizeof(k_decision_rows) / sizeof(k_decision_rows[0]))

size_t blocker_handoff_remedy_row_count(void)   { return HANDOFF_REMEDY_ROWS; }
size_t blocker_handoff_decision_row_count(void) { return HANDOFF_DECISION_ROWS; }

/* ── Matching ─────────────────────────────────────────────────────────
 * One rule, shared with the code emitter and the lint gate: '*' matches any
 * run of characters. An EXACT id always wins; among globs the LONGEST
 * pattern wins, so `coin_backfill.unprovable.*` outranks `coin_backfill.*`
 * and `*.below_snapshot_seed` outranks a hypothetical bare `*`. Ties keep
 * the first row, so table order stays a readable tiebreak. */
static int best_match(const char *id, const char *const *patterns,
                      size_t stride_rows, size_t n)
{
    /* `patterns` points at the first row's pattern field; rows are walked by
     * byte stride so both table types share this one scan. */
    int best = -1;
    size_t best_len = 0;
    for (size_t i = 0; i < n; i++) {
        const char *p = *(const char *const *)((const char *)patterns +
                                               i * stride_rows);
        if (!p || !p[0])
            continue;
        if (strcmp(p, id) == 0)
            return (int)i;                     /* exact — cannot be beaten */
        if (!strchr(p, '*'))
            continue;                          /* literal that did not match */
        if (!codeindex_emit_glob_match(p, id))
            continue;
        size_t len = strlen(p);
        if (best < 0 || len > best_len) {
            best = (int)i;
            best_len = len;
        }
    }
    return best;
}

static bool remedy_is_owner(const char *remedy)
{
    return remedy && strcmp(remedy, "OWNER") == 0;
}

bool blocker_handoff_lookup(const char *id, const char **remedy_out,
                            const char **decision_out, bool *needs_human_out)
{
    if (remedy_out)      *remedy_out = "";
    if (decision_out)    *decision_out = "";
    if (needs_human_out) *needs_human_out = false;
    if (!id || !id[0])
        return false;  // raw-return-ok:no id to resolve, not a failure

    int ri = best_match(id, &k_remedy_rows[0].pattern,
                        sizeof(k_remedy_rows[0]), HANDOFF_REMEDY_ROWS);
    if (ri < 0)
        return false;  // raw-return-ok:id is unbound -- an honest "no row owns this", which the caller renders as remedy_kind=unknown; logging would storm on every dump of a test/synthetic id

    const char *remedy = k_remedy_rows[ri].remedy;
    bool human = remedy_is_owner(remedy);
    if (remedy_out)      *remedy_out = remedy;
    if (needs_human_out) *needs_human_out = human;

    /* A decision only means anything for a hand-off: an id with a live
     * auto-remedy is not waiting on a person, so never dress one up as if
     * it were. */
    if (human && decision_out) {
        int di = best_match(id, &k_decision_rows[0].pattern,
                            sizeof(k_decision_rows[0]), HANDOFF_DECISION_ROWS);
        if (di >= 0)
            *decision_out = k_decision_rows[di].decision;
    }
    return true;
}

/* ── The resolver the primitive calls ────────────────────────────────── */

static bool resolve(const char *id, struct blocker_handoff *out)
{
    if (!out)
        return false;
    const char *remedy = "";
    const char *decision = "";
    bool human = false;
    if (!blocker_handoff_lookup(id, &remedy, &decision, &human))
        return false;  // raw-return-ok:pure table miss, not a failure -- the primitive renders it as remedy_kind=unknown; logging here would storm on every dump
    out->kind = human ? BLOCKER_HANDOFF_HUMAN : BLOCKER_HANDOFF_AUTOMATIC;
    out->remedy = remedy;
    out->decision = decision;
    return true;
}

void blocker_handoff_registry_install(void)
{
    blocker_set_handoff_resolver(resolve);
    LOG_INFO("blocker",
             "handoff resolver installed: %zu remedy row(s), %zu operator "
             "decision row(s)",
             HANDOFF_REMEDY_ROWS, HANDOFF_DECISION_ROWS);
}

/* ── Diagnostics ─────────────────────────────────────────────────────── */

bool blocker_handoff_dump_state_json(struct json_value *out, const char *key)
{
    if (!out)
        return false;
    json_set_object(out);

    size_t owner_rows = 0, declared = 0;
    for (size_t i = 0; i < HANDOFF_REMEDY_ROWS; i++) {
        if (!remedy_is_owner(k_remedy_rows[i].remedy))
            continue;
        owner_rows++;
        int di = best_match(k_remedy_rows[i].pattern, &k_decision_rows[0].pattern,
                            sizeof(k_decision_rows[0]), HANDOFF_DECISION_ROWS);
        if (di >= 0)
            declared++;
    }

    json_push_kv_int(out, "remedy_rows", (int64_t)HANDOFF_REMEDY_ROWS);
    json_push_kv_int(out, "decision_rows", (int64_t)HANDOFF_DECISION_ROWS);
    json_push_kv_int(out, "owner_bound_rows", (int64_t)owner_rows);
    json_push_kv_int(out, "owner_rows_with_decision", (int64_t)declared);

    /* `key` = a blocker id: resolve it exactly as the blocker dumper would,
     * so an operator can ask "what would this id say?" without waiting for
     * it to fire. */
    if (key && key[0]) {
        const char *remedy = "", *decision = "";
        bool human = false;
        bool found = blocker_handoff_lookup(key, &remedy, &decision, &human);
        json_push_kv_str(out, "query", key);
        json_push_kv_bool(out, "bound", found);
        json_push_kv_str(out, "remedy", remedy);
        json_push_kv_bool(out, "needs_human", human);
        json_push_kv_str(out, "operator_decision", decision);
    }

    /* The remaining debt, named: OWNER-bound patterns with no decision text.
     * Bounded render so a long list cannot balloon the dump. */
    struct json_value undeclared;
    json_init(&undeclared);
    json_set_array(&undeclared);
    int rendered = 0;
    for (size_t i = 0; i < HANDOFF_REMEDY_ROWS && rendered < 40; i++) {
        if (!remedy_is_owner(k_remedy_rows[i].remedy))
            continue;
        int di = best_match(k_remedy_rows[i].pattern, &k_decision_rows[0].pattern,
                            sizeof(k_decision_rows[0]), HANDOFF_DECISION_ROWS);
        if (di >= 0)
            continue;
        struct json_value s;
        json_init(&s);
        json_set_str(&s, k_remedy_rows[i].pattern);
        json_push_back(&undeclared, &s);
        json_free(&s);
        rendered++;
    }
    json_push_kv(out, "owner_rows_without_decision", &undeclared);
    json_free(&undeclared);

    char reason[192];
    snprintf(reason, sizeof(reason),
             "%zu OWNER-bound blocker pattern(s), %zu with an operator "
             "decision written down",
             owner_rows, declared);
    diag_push_health(out, true, reason);
    return true;
}
