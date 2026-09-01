/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_telemetry_sync_compat — the golden guard on `ops state`.
 *
 * WHAT THIS PROVES, and why it is a separate group from test_telemetry_sync.
 * The typed `sync` telemetry domain reads the SAME seven subsystems that
 * `ops state --subsystem=<name>` has always answered from: the reducer
 * frontier and the six ladder rungs. Nothing about the new leaves is supposed
 * to change those replies — but "supposed to" is exactly the claim that rots.
 * Something else already reads each of these bodies (docs/work/fast-path.md,
 * the deploy verify, the debug bundle, and every operator who has one in a
 * shell history), so a key that quietly vanishes or is renamed breaks a tool
 * nobody in this lane can see.
 *
 * The test therefore pins each subsystem's dumpstate body KEY-FOR-KEY against
 * a golden list recorded here. A key added is a FAILURE too, not just a key
 * removed: an added key is a migration in progress, and the point of this
 * group is that the migration has to be a decision somebody made, never a
 * side effect. Values are deliberately NOT pinned — they move every call — so
 * this is a shape guard, which is the part other tools bind to.
 *
 * ISOLATION IS LOAD-BEARING. Several of these dumpers resolve a datadir. A
 * test without SetDataDir would read the operator's RUNNING node and pass for
 * the wrong reason; that has happened in this repository. The datadir is
 * pinned to a hermetic per-pid temp directory before the first dump, and
 * nothing here writes to it.
 *
 * ON A FAILURE: the group prints the observed key list beside the golden one.
 * If the change was intended — a subsystem genuinely migrated onto the typed
 * renderer — update the golden row in the SAME change and say so, because the
 * whole value of this file is that the update is a visible act.
 */

#include "test/test_core.h"

#include "config/command_catalog.h"
#include "controllers/diagnostics_internal.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "util/util.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* One label-free assertion per line, matching test_telemetry_sync's style:
 * these checks are independent and more useful reported one by one. */
#define TSC_CHECK(name, cond) \
    do { \
        printf("%s... ", (name)); \
        if (cond) { printf("OK\n"); } \
        else { printf("FAIL (%s)\n", #cond); failures++; } \
    } while (0)

/* The golden shape of one subsystem's dumpstate body.
 *
 * `keys` is the COMPLETE top-level key list of the `state` object, in no
 * particular order (the check is set equality, because a dumper is free to
 * reorder its own pushes). A NULL terminates the list. */
struct tsc_golden {
    const char *subsystem;
    const char *const *keys;
};

/* ── the seven subsystems the sync telemetry provider reads ──────────────
 * These lists were CAPTURED from this very tree on the hermetic fixture
 * datadir below; they are a record, not a specification. Do not "tidy" one — a
 * difference between a list here and what the dumper emits is the finding.
 *
 * THE FIXTURE SHAPE IS THE PINNED SHAPE, and that is deliberate. Some of these
 * dumpers emit a different key set depending on what they can reach:
 * reducer_frontier's body below is its kernel-store-NOT-OPEN branch
 * (open/authority/floor/...), which is the only branch a test with no node can
 * reproduce, while a running node takes the other one. That makes this a guard
 * on the shape reachable from a fixture, not on every shape the dumper can
 * emit — which is exactly the guarantee a hermetic test can honestly give, and
 * it is still the guarantee that catches a rename, a dropped key, or a
 * migration onto the typed renderer. */

static const char *const k_reducer_frontier[] = {
    "open", "authority", "floor", "cached_provable_tip", "schema_ready",
    "schema_missing", NULL
};

static const char *const k_header_admit[] = {
    "initialised", "stage_name", "cursor", "admitted_total",
    "inbox_drained_total", "inbox_logged_total", "reorg_rewind_total",
    "reorg_audit_total", "reorg_audit_height_checks", "header_event_emit_total",
    "header_event_emit_fail_total", "produced_total", "last_admit_height",
    "last_step_unix", "last_blocked_unix", "authority", "_health", NULL
};

static const char *const k_validate_headers[] = {
    "initialised", "stage_name", "authority", "cursor", "pool_size",
    "batch_size", "passed_total", "failed_total", "last_step_unix",
    "last_blocked_unix", "failure_recheck_cursor", "last_recheck_frontier",
    "last_recheck_start", "last_recheck_selected", "mark_fail_warn_total",
    "failure_summary_status", "failure_log_count", "first_failed_height",
    "first_fail_reason", "last_failed_height", "last_fail_reason", "_health",
    NULL
};

static const char *const k_body_fetch[] = {
    "initialised", "stage_name", "cursor", "observed_total", "skipped_total",
    "last_advance_height", "last_step_unix", "last_blocked_unix",
    "last_idle_reason", "authority_best_header_absent_total",
    "authority_best_hash_mismatch_total",
    "authority_active_hash_mismatch_total",
    "authority_visible_parent_absent_total",
    "authority_visible_parent_mismatch_total", "authority_failed_total",
    "body_missing_total", "_health", NULL
};

static const char *const k_body_persist[] = {
    "initialised", "stage_name", "cursor", "verified_total",
    "upstream_failed_total", "read_failed_total", "header_mismatch_total",
    "merkle_mismatch_total", "header_event_emit_total",
    "header_event_emit_fail_total", "last_advance_height", "last_step_unix",
    "last_step_age_seconds", "last_blocked_unix", "log_rows",
    "log_rows_snapshot", "_health", NULL
};

static const char *const k_utxo_apply[] = {
    "initialised", "stage_name", "cursor", "verified_total",
    "spend_unknown_total", "utxo_collision_total", "value_overflow_total",
    "coinbase_protect_total", "bad_cb_amount_total",
    "shielded_double_spend_total", "shielded_anchor_reject_total",
    "upstream_failed_total", "internal_error_total", "reorg_unwound_total",
    "outputs_added_total", "outputs_spent_total", "last_advance_height",
    "last_step_unix", "last_step_age_seconds", "last_blocked_unix",
    "upstream_hole_total", "upstream_hole_height", "upstream_hole_first_unix",
    "upstream_hole_consec", "label_splice_total", "window_miss_total",
    "window_miss_height", "hash_bound_fallback_total",
    "hash_bound_fallback_height", "select_idle_total", "select_idle_height",
    "select_idle_reason", "log_rows", "log_rows_snapshot", NULL
};

static const char *const k_tip_finalize[] = {
    "initialised", "stage_name", "cursor", "durable_snapshot_available",
    "durable_snapshot_status", "finalized_total", "upstream_failed_total",
    "reorg_detected_total", "utxo_count_diverged_total",
    "precondition_failed_total", "successor_pending_total",
    "header_witness_total", "last_precondition_height",
    "precondition_repeat_count", "last_precondition_reason",
    "total_work_added_high", "total_work_added_low", "last_advance_height",
    "last_step_unix", "last_step_age_seconds", "last_blocked_unix",
    "last_blocked_reason", "blocked_uv_cursor_gap_total",
    "blocked_at_utxo_frontier_total", "blocked_utxo_apply_row_missing_total",
    "blocked_lookahead_tip_missing_total", "blocked_current_tip_missing_total",
    "blocked_successor_pending_total", "log_rows", "_health", NULL
};

static const struct tsc_golden k_golden[] = {
    { "reducer_frontier", k_reducer_frontier },
    { "header_admit", k_header_admit },
    { "validate_headers", k_validate_headers },
    { "body_fetch", k_body_fetch },
    { "body_persist", k_body_persist },
    { "utxo_apply", k_utxo_apply },
    { "tip_finalize", k_tip_finalize },
};

/* Dump one subsystem the way `ops state --subsystem=<name>` does: the same
 * `dumpstate` RPC entry point, so this test cannot pass against a code path
 * the command does not use. */
static bool tsc_dump(const char *subsystem, struct json_value *out)
{
    struct json_value params, item;
    json_init(&params);
    json_set_array(&params);
    json_init(&item);
    json_set_str(&item, subsystem);
    bool ok = json_push_back(&params, &item);
    json_free(&item);
    json_init(out);
    ok = ok && diag_rpc_dumpstate(&params, false, out);
    json_free(&params);
    return ok;
}

static bool tsc_list_has(const char *const *list, const char *name)
{
    for (size_t i = 0; list[i]; i++) {
        if (strcmp(list[i], name) == 0)
            return true;
    }
    return false;
}

static void tsc_print_observed(const struct json_value *state)
{
    printf("      observed:");
    for (size_t i = 0; i < state->num_children; i++)
        printf(" %s", state->keys[i] ? state->keys[i] : "(null)");
    printf("\n");
}

static void tsc_print_golden(const char *const *keys)
{
    printf("      golden:  ");
    for (size_t i = 0; keys[i]; i++)
        printf(" %s", keys[i]);
    printf("\n");
}

/* Set equality in both directions, reported separately: a key that VANISHED
 * and a key that APPEARED are different events with different causes, and
 * collapsing them into "differs" would hide which one happened. */
static int tsc_check_one(const struct tsc_golden *g)
{
    int failures = 0;
    char label[160];

    struct json_value result;
    bool dumped = tsc_dump(g->subsystem, &result);
    (void)snprintf(label, sizeof label,
                   "[compat] ops state --subsystem=%s still answers",
                   g->subsystem);
    TSC_CHECK(label, dumped);
    if (!dumped) {
        json_free(&result);
        return failures;
    }

    const struct json_value *state = json_get(&result, "state");
    (void)snprintf(label, sizeof label,
                   "[compat] %s returns a state object", g->subsystem);
    TSC_CHECK(label, state && state->type == JSON_OBJ);
    if (!state || state->type != JSON_OBJ) {
        json_free(&result);
        return failures;
    }

    size_t golden_count = 0;
    while (g->keys[golden_count])
        golden_count++;

    size_t missing = 0, added = 0;
    for (size_t i = 0; g->keys[i]; i++) {
        if (!json_get(state, g->keys[i])) {
            missing++;
            printf("      MISSING key '%s' from %s\n", g->keys[i],
                   g->subsystem);
        }
    }
    for (size_t i = 0; i < state->num_children; i++) {
        const char *k = state->keys ? state->keys[i] : NULL;
        if (!k || !tsc_list_has(g->keys, k)) {
            added++;
            printf("      ADDED key '%s' to %s\n", k ? k : "(null)",
                   g->subsystem);
        }
    }
    if (missing || added) {
        tsc_print_observed(state);
        tsc_print_golden(g->keys);
    }

    (void)snprintf(label, sizeof label,
                   "[compat] %s lost no dumpstate key", g->subsystem);
    TSC_CHECK(label, missing == 0);
    (void)snprintf(label, sizeof label,
                   "[compat] %s grew no unrecorded dumpstate key",
                   g->subsystem);
    TSC_CHECK(label, added == 0);
    (void)snprintf(label, sizeof label,
                   "[compat] %s key count is exactly the golden count",
                   g->subsystem);
    TSC_CHECK(label, state->num_children == golden_count);

    json_free(&result);
    return failures;
}

/* Anti-hollowness: a golden table that shrank to nothing would make every
 * check above vacuous, and the group would still print zero failures. */
static int check_the_guard_is_not_empty(void)
{
    int failures = 0;
    size_t rows = sizeof k_golden / sizeof k_golden[0];
    TSC_CHECK("[compat] the golden table still covers all seven sync "
              "subsystems", rows == 7);
    size_t total_keys = 0;
    for (size_t i = 0; i < rows; i++) {
        for (size_t j = 0; k_golden[i].keys[j]; j++)
            total_keys++;
    }
    TSC_CHECK("[compat] the golden table pins a non-trivial number of keys",
              total_keys >= 30);
    return failures;
}

/* ── the other half: the three new leaves must actually fit the wire ─────
 *
 * write_bounded_json() answers an over-budget reply with an EMPTY document and
 * a zero length — not a truncated one — and the native CLI writes the whole
 * envelope into ZCL_COMMAND_LIST_BUDGET+1 bytes. A telemetry document is the
 * single most likely reply in this registry to cross that line: the sync
 * domain renders 44 values plus a provenance entry each at FULL. So the size
 * is asserted rather than assumed, at EVERY view, against the same buffer the
 * CLI uses. A regression here shows up as "the command prints nothing", which
 * is the hardest kind of failure to attribute after the fact. */

static const struct zcl_command_spec *tsc_find(
    const struct zcl_command_registry *reg, const char *path)
{
    for (size_t i = 0; i < reg->count; i++) {
        if (strcmp(reg->commands[i].path, path) == 0)
            return &reg->commands[i];
    }
    return NULL;
}

/* Run one leaf exactly as the CLI does: same buffer size, same omnipotent
 * local-operator context, same view string. Returns the bytes written (0 is
 * the budget-overflow signal the caller is here to catch). */
static size_t tsc_exec(const struct zcl_command_registry *reg,
                       const char *path, const char *view,
                       const char *stage, char *out, size_t out_size)
{
    const struct zcl_command_spec *spec = tsc_find(reg, path);
    if (!spec)
        return 0;
    struct zcl_command_context ctx = {
        .registry = reg,
        .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
    };
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    if (stage)
        (void)json_push_kv_str(&input, "stage", stage);
    enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_INTERNAL;
    size_t n = zcl_command_registry_execute_json(reg, spec, &ctx, &input, false,
                                                 path, view, 0, 0, NULL,
                                                 out, out_size, &exit_code);
    json_free(&input);
    return n;
}

/* A reply is "ok" only if it parses AND the envelope says ok:true. Length
 * alone is not enough and asserting on it is the trap this test exists to
 * catch: when serialize_reply() cannot write the document it substitutes a
 * ~296-byte RESPONSE_BUDGET_EXCEEDED envelope, which is non-empty, parses
 * fine, and reports exit code 6. A `n > 0` assertion passes on it. On failure
 * this prints the whole reply, because the failure mode is "the command
 * silently returned nothing useful" and the envelope is the only evidence. */
static bool tsc_reply_ok(const char *out, size_t n)
{
    struct json_value doc;
    if (n == 0 || n > ZCL_COMMAND_LIST_BUDGET || !json_read(&doc, out, n)) {
        printf("    reply was unparseable (%zu bytes): %.*s\n", n,
               (int)(n > 700 ? 700 : n), n ? out : "");
        return false;
    }
    bool ok = json_get_bool(json_get(&doc, "ok"));
    if (!ok)
        printf("    reply not ok (%zu bytes): %.*s\n", n,
               (int)(n > 700 ? 700 : n), out);
    json_free(&doc);
    return ok;
}

static int check_the_leaves_fit_the_wire(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    static char out[ZCL_COMMAND_LIST_BUDGET + 1];
    char label[192];

    static const char *const k_views[] = { "summary", "normal", "full" };
    static const char *const k_paths[] = {
        "ops.telemetry.sync.summary",
        "ops.telemetry.sync.stages",
    };
    for (size_t p = 0; p < sizeof k_paths / sizeof k_paths[0]; p++) {
        for (size_t v = 0; v < 3; v++) {
            size_t n = tsc_exec(reg, k_paths[p], k_views[v], NULL, out,
                                sizeof out);
            (void)snprintf(label, sizeof label,
                           "[budget] %s --view=%s answers ok (%zu bytes of %u)",
                           k_paths[p], k_views[v], n,
                           (unsigned)ZCL_COMMAND_LIST_BUDGET);
            TSC_CHECK(label, tsc_reply_ok(out, n));
        }
    }

    /* Every rung, at full detail — the largest single-stage documents, because
     * each carries the provenance plane as well as the values. Every rung, not
     * a sample: the rungs differ in field count by nearly a factor of two, and
     * a budget guard that checks the small one is no guard at all. */
    static const char *const k_rungs[] = {
        "header_admit", "validate_headers", "body_fetch",
        "body_persist", "utxo_apply", "tip_finalize",
    };
    for (size_t i = 0; i < sizeof k_rungs / sizeof k_rungs[0]; i++) {
        size_t n = tsc_exec(reg, "ops.telemetry.sync.stage", "full",
                            k_rungs[i], out, sizeof out);
        (void)snprintf(label, sizeof label,
                       "[budget] ops.telemetry.sync.stage --stage=%s answers "
                       "ok (%zu bytes of %u)", k_rungs[i], n,
                       (unsigned)ZCL_COMMAND_LIST_BUDGET);
        TSC_CHECK(label, tsc_reply_ok(out, n));

        /* An ok envelope is not enough: assert the rung the caller ASKED for
         * is the rung that came back, and that a bounded rung states its
         * upstream. Without this, a handler that answered every name with the
         * same row would still be green above. */
        struct json_value rd;
        if (json_read(&rd, out, n)) {
            const struct json_value *d = json_get(&rd, "data");
            const struct json_value *rows = d ? json_get(d, "stages") : NULL;
            const char *got = rows ? json_get_str(
                json_get(json_at(rows, 0), "stage")) : NULL;
            (void)snprintf(label, sizeof label,
                           "[stage] --stage=%s returns that rung, not another",
                           k_rungs[i]);
            TSC_CHECK(label, got && strcmp(got, k_rungs[i]) == 0);

            const char *up = d ? json_get_str(json_get(d, "upstream_stage"))
                               : NULL;
            (void)snprintf(label, sizeof label,
                           "[stage] --stage=%s names %s as its upstream",
                           k_rungs[i], i ? k_rungs[i - 1] : "(none)");
            TSC_CHECK(label, up && strcmp(up, i ? k_rungs[i - 1] : "") == 0);

            /* The upstream drill-down must be reachable as DATA. It cannot be
             * a next[] step — the registry refuses a self-referential next[]
             * and answers the whole call with an empty document — so its
             * presence here is what keeps the link from silently vanishing. */
            const char *inv = d ? json_get_str(
                json_get(d, "upstream_invocation")) : NULL;
            (void)snprintf(label, sizeof label,
                           "[stage] --stage=%s carries a runnable upstream "
                           "invocation", k_rungs[i]);
            /* json_get_str() answers a missing key with "", never NULL. */
            TSC_CHECK(label, i == 0 ? (inv && inv[0] == 0)
                                    : (inv && strstr(inv, k_rungs[i - 1])));

            /* No next[] entry may point back at this same leaf. */
            const struct json_value *nx = json_get(&rd, "next");
            bool self = false;
            for (size_t j = 0; nx && j < nx->num_children; j++) {
                const char *c = json_get_str(json_get(json_at(nx, j),
                                                      "command"));
                if (c && strcmp(c, "ops.telemetry.sync.stage") == 0)
                    self = true;
            }
            (void)snprintf(label, sizeof label,
                           "[stage] --stage=%s emits no self-referential "
                           "next[]", k_rungs[i]);
            TSC_CHECK(label, !self);
            json_free(&rd);
        }
    }
    size_t n;

    /* An unknown rung is a TYPED refusal naming the valid set — never an empty
     * reply, and never a plausible empty stage row. */
    n = tsc_exec(reg, "ops.telemetry.sync.stage", "normal", "nonsense", out,
                 sizeof out);
    TSC_CHECK("[budget] an unknown stage still writes a reply", n > 0);
    struct json_value doc;
    bool parsed = n > 0 && json_read(&doc, out, n);
    TSC_CHECK("[stage] an unknown stage reply parses", parsed);
    if (parsed) {
        const struct json_value *err = json_get(&doc, "error");
        const char *code = err ? json_get_str(json_get(err, "code")) : NULL;
        TSC_CHECK("[stage] an unknown stage is UNKNOWN_STAGE, not an empty "
                  "result", code && strcmp(code, "UNKNOWN_STAGE") == 0);
        const char *evidence = err ? json_get_str(json_get(err, "evidence"))
                                   : NULL;
        TSC_CHECK("[stage] the refusal names the valid set",
                  evidence && strstr(evidence, "tip_finalize") != NULL &&
                      strstr(evidence, "header_admit") != NULL);
        TSC_CHECK("[stage] the refusal carries no data document",
                  json_get(&doc, "data") == NULL);
    }
    if (parsed)
        json_free(&doc);
    return failures;
}

/* The summary leaf's whole reason to exist: it must NAME a rung and point
 * next[] at that same rung. A `bottleneck` block whose next[] disagrees with
 * it would send an operator to the wrong subsystem, which is worse than
 * saying nothing — so the two are asserted to agree, at every view, including
 * the case where nothing is nameable (then next[] must go to `stages`). */
static int check_summary_names_a_bottleneck(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    static char out[ZCL_COMMAND_LIST_BUDGET + 1];

    size_t n = tsc_exec(reg, "ops.telemetry.sync.summary", "summary", NULL,
                        out, sizeof out);
    struct json_value doc;
    bool parsed = n > 0 && json_read(&doc, out, n);
    TSC_CHECK("[summary] the reply parses", parsed);
    if (!parsed)
        return failures;

    const struct json_value *data = json_get(&doc, "data");
    const struct json_value *b = data ? json_get(data, "bottleneck") : NULL;
    TSC_CHECK("[summary] the reply carries a bottleneck block at the "
              "shallowest view", b && b->type == JSON_OBJ);
    if (!b) {
        json_free(&doc);
        return failures;
    }
    const struct json_value *stage_v = json_get(b, "stage");
    const char *stage = json_get_str(stage_v);
    const char *basis = json_get_str(json_get(b, "basis"));
    const char *reason = json_get_str(json_get(b, "reason"));
    TSC_CHECK("[summary] the bottleneck states which basis chose it",
              basis && basis[0]);
    /* Either a rung is named, or the reason says why none could be — never
     * both empty, which is the shape that reads as "fine" and is not. */
    TSC_CHECK("[summary] a nameless bottleneck carries a reason token",
              (stage && stage[0]) || (reason && reason[0]));

    const struct json_value *next = json_get(&doc, "next");
    TSC_CHECK("[summary] the reply always carries a next step",
              next && next->type == JSON_ARR && next->num_children >= 1);
    if (next && next->type == JSON_ARR && next->num_children >= 1) {
        const struct json_value *first = &next->children[0];
        const char *cmd = json_get_str(json_get(first, "command"));
        const char *in = json_get_str(json_get(first, "input"));
        if (stage && stage[0]) {
            char want[192];
            (void)snprintf(want, sizeof want, "\"stage\":\"%s\"", stage);
            TSC_CHECK("[summary] next[] drills into the sync stage leaf",
                      cmd && strcmp(cmd, "ops.telemetry.sync.stage") == 0);
            TSC_CHECK("[summary] next[] names the SAME rung the bottleneck "
                      "block did, not a generic link",
                      in && strstr(in, want) != NULL);
        } else {
            TSC_CHECK("[summary] with no nameable rung, next[] lists the whole "
                      "ladder", cmd &&
                      strcmp(cmd, "ops.telemetry.sync.stages") == 0);
        }
    }
    json_free(&doc);
    return failures;
}

/* The stage set is derived from the field table, not listed anywhere. Prove
 * it resolved to the real ladder, so a derivation that silently found nothing
 * cannot pass as "no rungs to check". */
static int check_the_ladder_is_enumerated(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    static char out[ZCL_COMMAND_LIST_BUDGET + 1];

    size_t n = tsc_exec(reg, "ops.telemetry.sync.stages", "normal", NULL, out,
                        sizeof out);
    struct json_value doc;
    bool parsed = n > 0 && json_read(&doc, out, n);
    TSC_CHECK("[stages] the reply parses", parsed);
    if (!parsed)
        return failures;
    const struct json_value *data = json_get(&doc, "data");
    const struct json_value *rows = data ? json_get(data, "stages") : NULL;
    TSC_CHECK("[stages] the ladder renders one row per rung",
              rows && rows->type == JSON_ARR && rows->num_children == 6);
    TSC_CHECK("[stages] the rung set was not truncated",
              data && json_get(data, "stage_set_truncated") &&
                  !json_get_bool(json_get(data, "stage_set_truncated")));
    bool saw_persist = false;
    if (rows && rows->type == JSON_ARR) {
        for (size_t i = 0; i < rows->num_children; i++) {
            const char *nm = json_get_str(json_get(&rows->children[i],
                                                   "stage"));
            if (nm && strcmp(nm, "body_persist") == 0) {
                saw_persist = true;
                const struct json_value *f = json_get(&rows->children[i],
                                                      "fields");
                TSC_CHECK("[stages] a rung row carries its own fields, keyed "
                          "by the field table's own leaf keys",
                          f && f->type == JSON_OBJ &&
                              json_get(f, "body_persist_cursor") != NULL);
            }
        }
    }
    TSC_CHECK("[stages] the ladder includes body_persist", saw_persist);
    /* No leaf in this branch may be a dead end for a caller walking next[]. */
    const struct json_value *nx = json_get(&doc, "next");
    TSC_CHECK("[stages] the reply always carries a next step",
              nx && nx->type == JSON_ARR && nx->num_children > 0);
    json_free(&doc);
    return failures;
}

int test_telemetry_sync_compat(void)
{
    printf("\n=== telemetry sync ops-state compatibility ===\n");
    int failures = 0;

    /* Hermetic datadir for the whole group — see the ISOLATION note in the
     * file header. Pinned BEFORE the first dump, because that is the call
     * that would otherwise resolve the operator's live node. */
    char datadir[256];
    test_make_tmpdir(datadir, sizeof(datadir), "telemetry_sync_compat",
                     "datadir");
    SetDataDir(datadir);

    failures += check_the_guard_is_not_empty();
    for (size_t i = 0; i < sizeof k_golden / sizeof k_golden[0]; i++)
        failures += tsc_check_one(&k_golden[i]);
    failures += check_the_leaves_fit_the_wire();
    failures += check_summary_names_a_bottleneck();
    failures += check_the_ladder_is_enumerated();

    test_cleanup_tmpdir(datadir);
    printf("=== telemetry_sync_compat: %d failures ===\n", failures);
    return failures;
}
