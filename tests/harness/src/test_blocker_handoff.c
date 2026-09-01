/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the blocker hand-off surface — the half of "a stall is
 * always a named blocker" that was missing: every named blocker must carry
 * EITHER something the node attempts OR an explicit statement that a person
 * must decide, with the decision spelled out.
 *
 * Coverage:
 *   - the primitive defaults honestly with no resolver installed (UNKNOWN,
 *     empty strings) rather than implying "no remedy"
 *   - installing / removing the app-layer resolver
 *   - the three blockers standing on the canonical node 2026-07-27 resolve:
 *       address_index.below_snapshot_seed  -> human + decision text
 *       txindex.below_snapshot_seed        -> human + decision text
 *       catalog.op_return_index.lag_exceeded -> automatic (condition healer)
 *   - the two fresh-node self-heal escape hatches resolve human + decision
 *   - glob specificity: an exact row beats a pattern, longest pattern wins
 *   - a decision is only offered for a HUMAN hand-off, never dressed onto an
 *     auto-remedied blocker
 *   - the JSON dump renders remedy / remedy_kind / needs_human /
 *     operator_decision / standing per blocker plus the hand-off totals */

#include "test/test_core.h"
#include "conditions/blocker_handoff_registry.h"
#include "util/blocker.h"
#include "json/json.h"

#include <stdio.h>
#include <string.h>

#define BH_CHECK(name, expr) do { \
    printf("blocker_handoff: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Raise a DEPENDENCY blocker with no escape and no retry budget — the exact
 * shape of the three standing live blockers. */
static void raise_bare(const char *id, const char *owner)
{
    struct blocker_record r;
    if (blocker_init(&r, id, owner, BLOCKER_DEPENDENCY, "test reason")) {
        r.escape_deadline_secs = 0;
        r.retry_budget = 0;
        (void)blocker_set(&r);
    }
}

int test_blocker_handoff(void)
{
    int failures = 0;
    printf("\n=== blocker hand-off tests ===\n");

    blocker_reset_for_testing();
    blocker_set_handoff_resolver(NULL);

    /* ── No resolver: honest UNKNOWN, never a fabricated verdict ────── */
    {
        struct blocker_handoff h;
        bool found = blocker_resolve_handoff("address_index.below_snapshot_seed",
                                             &h);
        BH_CHECK("no resolver -> not found", !found);
        BH_CHECK("no resolver -> kind UNKNOWN",
                 h.kind == BLOCKER_HANDOFF_UNKNOWN);
        BH_CHECK("no resolver -> empty remedy", h.remedy && !h.remedy[0]);
        BH_CHECK("no resolver -> empty decision", h.decision && !h.decision[0]);
        BH_CHECK("kind names", strcmp(blocker_handoff_kind_name(
                                          BLOCKER_HANDOFF_UNKNOWN), "unknown") == 0 &&
                 strcmp(blocker_handoff_kind_name(
                            BLOCKER_HANDOFF_AUTOMATIC), "automatic") == 0 &&
                 strcmp(blocker_handoff_kind_name(
                            BLOCKER_HANDOFF_HUMAN), "human") == 0);
        BH_CHECK("null id -> false", !blocker_resolve_handoff(NULL, &h));
        BH_CHECK("null out -> false",
                 !blocker_resolve_handoff("anything", NULL));
    }

    /* ── Tables are non-empty and the resolver installs ─────────────── */
    BH_CHECK("remedy table populated",
             blocker_handoff_remedy_row_count() > 50);
    BH_CHECK("decision table populated",
             blocker_handoff_decision_row_count() >= 4);

    blocker_handoff_registry_install();

    /* ── The three blockers standing on the canonical node ──────────── */
    {
        struct blocker_handoff h;
        bool found = blocker_resolve_handoff("address_index.below_snapshot_seed",
                                             &h);
        BH_CHECK("address_index.below_snapshot_seed bound", found);
        BH_CHECK("address_index.below_snapshot_seed -> OWNER",
                 strcmp(h.remedy, "OWNER") == 0);
        BH_CHECK("address_index.below_snapshot_seed needs a human",
                 h.kind == BLOCKER_HANDOFF_HUMAN);
        /* The decision must actually STATE the tradeoff, not just say
         * "operator". Both options and the fact that consensus is unaffected
         * are the load-bearing content. */
        BH_CHECK("address_index decision names option A",
                 strstr(h.decision, "OPTION A") != NULL);
        BH_CHECK("address_index decision names option B",
                 strstr(h.decision, "OPTION B") != NULL);
        BH_CHECK("address_index decision states consensus impact",
                 strstr(h.decision, "Consensus is unaffected") != NULL);

        found = blocker_resolve_handoff("txindex.below_snapshot_seed", &h);
        BH_CHECK("txindex.below_snapshot_seed bound + human",
                 found && h.kind == BLOCKER_HANDOFF_HUMAN && h.decision[0]);

        found = blocker_resolve_handoff("op_return_index.below_snapshot_seed",
                                        &h);
        BH_CHECK("op_return_index.below_snapshot_seed bound + human",
                 found && h.kind == BLOCKER_HANDOFF_HUMAN && h.decision[0]);

        /* catalog lag HAS a real condition healer — it must NOT be dressed up
         * as a human hand-off, and must not carry decision text. */
        found = blocker_resolve_handoff("catalog.op_return_index.lag_exceeded",
                                        &h);
        BH_CHECK("catalog lag bound", found);
        BH_CHECK("catalog lag -> automatic",
                 h.kind == BLOCKER_HANDOFF_AUTOMATIC);
        BH_CHECK("catalog lag names its condition healer",
                 strcmp(h.remedy, "catalog_lag_exceeded") == 0);
        BH_CHECK("catalog lag carries no operator decision", !h.decision[0]);
    }

    /* ── The two fresh-node self-heal escape hatches ────────────────── */
    {
        struct blocker_handoff h;
        BH_CHECK("resnapshot_no_base human + decision",
                 blocker_resolve_handoff("sticky_escalator.resnapshot_no_base",
                                         &h) &&
                 h.kind == BLOCKER_HANDOFF_HUMAN && h.decision[0]);
        BH_CHECK("resnapshot_no_base names the artifact it wanted",
                 strstr(h.decision, "utxo-anchor.snapshot") != NULL);

        BH_CHECK("refold_no_anchor_artifact human + decision",
                 blocker_resolve_handoff(
                     "sticky_escalator.refold_no_anchor_artifact", &h) &&
                 h.kind == BLOCKER_HANDOFF_HUMAN && h.decision[0]);
        BH_CHECK("refold_no_anchor_artifact names the artifact it wanted",
                 strstr(h.decision, "utxo-anchor.snapshot") != NULL);
        BH_CHECK("refold_no_anchor_artifact names who produces it",
                 strstr(h.decision, "mint/export") != NULL);

        BH_CHECK("resnapshot_no_consumer human + decision",
                 blocker_resolve_handoff(
                     "sticky_escalator.resnapshot_no_consumer", &h) &&
                 h.kind == BLOCKER_HANDOFF_HUMAN && h.decision[0]);
    }

    /* ── Glob specificity ───────────────────────────────────────────── */
    {
        const char *remedy = NULL;
        bool human = false;
        /* Exact row beats the `coin_backfill.*` pattern; both are OWNER, so
         * assert the more specific pattern is what a longer id lands on. */
        BH_CHECK("coin_backfill.unprovable.<h> resolves",
                 blocker_handoff_lookup("coin_backfill.unprovable.4242",
                                        &remedy, NULL, &human) &&
                 strcmp(remedy, "OWNER") == 0 && human);
        /* An exact-literal row still wins over any pattern. */
        BH_CHECK("exact row wins: reducer_frontier.upstream_log_hole",
                 blocker_handoff_lookup("reducer_frontier.upstream_log_hole",
                                        &remedy, NULL, &human) &&
                 strcmp(remedy, "reducer_frontier_reconcile_light") == 0 &&
                 !human);
        /* Unbound id: honest false, no invented answer. */
        const char *decision = NULL;
        BH_CHECK("unbound id -> false + empty",
                 !blocker_handoff_lookup("no.such.blocker.id.exists",
                                         &remedy, &decision, &human) &&
                 !remedy[0] && !decision[0] && !human);
    }

    /* ── JSON dump renders the hand-off ─────────────────────────────── */
    {
        blocker_reset_for_testing();
        blocker_handoff_registry_install();
        raise_bare("address_index.below_snapshot_seed", "address_index");
        raise_bare("reducer_frontier.upstream_log_hole", "reducer_frontier");

        struct json_value out;
        json_init(&out);
        bool ok = blocker_dump_state_json(&out, NULL);
        BH_CHECK("dump ok", ok);
        BH_CHECK("human_handoff_count == 1",
                 json_get_int(json_get(&out, "human_handoff_count")) == 1);
        BH_CHECK("automatic_remedy_count == 1",
                 json_get_int(json_get(&out, "automatic_remedy_count")) == 1);
        BH_CHECK("undeclared_decision_count == 0",
                 json_get_int(json_get(&out, "undeclared_decision_count")) == 0);
        BH_CHECK("standing_handoff_count == 0 (fresh)",
                 json_get_int(json_get(&out, "standing_handoff_count")) == 0);

        const struct json_value *arr = json_get(&out, "blockers");
        int seen_human = 0, seen_auto = 0;
        for (size_t i = 0; i < json_size(arr); i++) {
            const struct json_value *e = json_at(arr, i);
            const char *id = json_get_str(json_get(e, "id"));
            const char *kind = json_get_str(json_get(e, "remedy_kind"));
            const char *remedy = json_get_str(json_get(e, "remedy"));
            const char *dec = json_get_str(json_get(e, "operator_decision"));
            bool needs = json_get_bool(json_get(e, "needs_human"));
            bool standing = json_get_bool(json_get(e, "standing"));
            if (id && strcmp(id, "address_index.below_snapshot_seed") == 0) {
                seen_human = 1;
                BH_CHECK("row: human kind", kind && strcmp(kind, "human") == 0);
                BH_CHECK("row: OWNER remedy",
                         remedy && strcmp(remedy, "OWNER") == 0);
                BH_CHECK("row: needs_human", needs);
                BH_CHECK("row: carries the decision text",
                         dec && strstr(dec, "OPTION A") != NULL &&
                         strstr(dec, "OPTION B") != NULL);
                BH_CHECK("row: fresh handoff is not standing", !standing);
            }
            if (id && strcmp(id, "reducer_frontier.upstream_log_hole") == 0) {
                seen_auto = 1;
                BH_CHECK("row: automatic kind",
                         kind && strcmp(kind, "automatic") == 0);
                BH_CHECK("row: names the healer",
                         remedy &&
                         strcmp(remedy, "reducer_frontier_reconcile_light") == 0);
                BH_CHECK("row: not a human hand-off", !needs);
                BH_CHECK("row: no decision on an auto-remedied blocker",
                         dec && !dec[0]);
            }
        }
        BH_CHECK("both rows rendered", seen_human && seen_auto);

        const char *health_reason =
            json_get_str(json_get(json_get(&out, "_health"), "reason"));
        BH_CHECK("summary leads with the disposition",
                 health_reason &&
                 strstr(health_reason, "awaiting an operator decision") != NULL);
        json_free(&out);
    }

    /* ── standing flips once the hand-off has been out for an hour ──── */
    {
        blocker_reset_for_testing();
        blocker_handoff_registry_install();
        blocker_set_clock_for_testing(1000000);
        raise_bare("txindex.below_snapshot_seed", "txindex");
        blocker_advance_clock_for_testing(
            (int64_t)(BLOCKER_STANDING_AGE_SECS + 1) * 1000000);

        struct json_value out;
        json_init(&out);
        (void)blocker_dump_state_json(&out, NULL);
        BH_CHECK("standing_handoff_count counted",
                 json_get_int(json_get(&out, "standing_handoff_count")) == 1);
        const struct json_value *e = json_at(json_get(&out, "blockers"), 0);
        BH_CHECK("aged handoff reports standing",
                 json_get_bool(json_get(e, "standing")));
        json_free(&out);
        blocker_set_clock_for_testing(0);
    }

    /* ── The registry's own dumper ──────────────────────────────────── */
    {
        struct json_value out;
        json_init(&out);
        bool ok = blocker_handoff_dump_state_json(
            &out, "address_index.below_snapshot_seed");
        BH_CHECK("registry dump ok", ok);
        BH_CHECK("registry dump resolves the queried id",
                 json_get_bool(json_get(&out, "bound")) &&
                 json_get_bool(json_get(&out, "needs_human")));
        BH_CHECK("registry dump reports owner-bound totals",
                 json_get_int(json_get(&out, "owner_bound_rows")) > 0 &&
                 json_get_int(json_get(&out, "owner_rows_with_decision")) > 0);
        BH_CHECK("registry dump names the remaining debt (array present)",
                 json_get(&out, "owner_rows_without_decision") != NULL);
        json_free(&out);
    }

    blocker_set_handoff_resolver(NULL);
    blocker_reset_for_testing();

    if (failures == 0) {
        printf("=== blocker hand-off tests: ALL PASS ===\n\n");
    } else {
        printf("=== blocker hand-off tests: %d FAILURE(S) ===\n\n", failures);
    }
    return failures;
}
