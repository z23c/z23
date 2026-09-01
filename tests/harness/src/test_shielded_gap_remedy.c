/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_shielded_gap_remedy — the CONTAINED verify-only remedy surface for the
 * shielded-history wedge (engine/controllers/src/shielded_gap_remedy_controller.c).
 *
 * Hermetic: drives the typed blocker registry + the agent runtime boot context
 * directly (no live datadir, no chain). Proves the merge-bar properties:
 *
 *   GAP PRESENT  — with a gap blocker set, classify() reports the gap, the
 *   dumpstate view emits the NAMED remedy (import command + copy-prove step),
 *   and on a live datadir/lane containment REFUSES live in-place apply while
 *   never auto-executing.
 *
 *   COPY DATADIR — on a throwaway -COPY- datadir the remedy is eligible for the
 *   OFFLINE operator-run import, yet auto_execute is still structurally false.
 *
 *   GAP ABSENT   — with no gap blocker, classify() is NONE and the view emits
 *   NO remedy (a healthy node surfaces no cure to run).
 */

#include "test/test_core.h"

#include "controllers/agent_controller.h"
#include "controllers/shielded_gap_remedy_controller.h"
#include "jobs/utxo_apply_anchors.h"
#include "jobs/utxo_apply_nullifiers.h"
#include "json/json.h"
#include "util/blocker.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SGR_CHECK(name, expr) do {                       \
    printf("  shielded_gap_remedy: %s... ", (name));     \
    if ((expr)) printf("OK\n");                          \
    else { printf("FAIL\n"); failures++; }               \
} while (0)

static void sgr_set_gap(const char *id)
{
    struct blocker_record r;
    blocker_init(&r, id, "utxo_apply", BLOCKER_PERMANENT, "test wedge");
    blocker_set(&r);
}

static bool sgr_str_eq(const struct json_value *obj, const char *key,
                       const char *want)
{
    const char *s = json_get_str(json_get(obj, key));
    return s && strcmp(s, want) == 0;
}

static bool sgr_bool(const struct json_value *obj, const char *key)
{
    return json_get_bool(json_get(obj, key));
}

int test_shielded_gap_remedy(void)
{
    int failures = 0;

    blocker_module_init();

    const char *home = getenv("HOME");
    char live_dir[600], copy_dir[600];
    snprintf(live_dir, sizeof(live_dir), "%s/.zclassic-c23",
             home && home[0] ? home : "/tmp");
    snprintf(copy_dir, sizeof(copy_dir),
             "%s/.zclassic-c23-COPY-1783000000-testgap",
             home && home[0] ? home : "/tmp");

    /* ── classify() reads the typed blocker registry ── */
    {
        blocker_reset_for_testing();
        SGR_CHECK("no blockers -> NONE",
                  shielded_gap_remedy_classify() == SHIELDED_GAP_NONE);

        sgr_set_gap(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID);
        SGR_CHECK("anchor blocker -> ANCHOR_ONLY",
                  shielded_gap_remedy_classify() == SHIELDED_GAP_ANCHOR_ONLY);

        sgr_set_gap(UTXO_APPLY_NF_GAP_BLOCKER_ID);
        SGR_CHECK("both blockers -> BOTH",
                  shielded_gap_remedy_classify() == SHIELDED_GAP_BOTH);

        blocker_clear(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID);
        SGR_CHECK("only nullifier blocker -> NULLIFIER_ONLY",
                  shielded_gap_remedy_classify() == SHIELDED_GAP_NULLIFIER_ONLY);
    }

    /* ── GAP PRESENT on a LIVE datadir/lane: named remedy + refuses live ── */
    {
        blocker_reset_for_testing();
        sgr_set_gap(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID);
        sgr_set_gap(UTXO_APPLY_NF_GAP_BLOCKER_ID);
        rpc_agent_set_boot_context("canonical", "release", live_dir,
                                   18232, 8033, 8443, 0);

        struct json_value out;
        json_init(&out);
        bool ok = shielded_gap_remedy_dump_state_json(&out, NULL);
        SGR_CHECK("dump returns true", ok);

        const struct json_value *gap = json_get(&out, "gap");
        SGR_CHECK("gap.state == both", sgr_str_eq(gap, "state", "both"));
        SGR_CHECK("gap.wedge_active true", sgr_bool(gap, "wedge_active"));
        SGR_CHECK("gap.anchor_gap_blocker_present true",
                  sgr_bool(gap, "anchor_gap_blocker_present"));
        SGR_CHECK("gap.nullifier_gap_blocker_present true",
                  sgr_bool(gap, "nullifier_gap_blocker_present"));

        /* The NAMED remedy is surfaced when the wedge is present. */
        const struct json_value *remedy = json_get(&out, "remedy");
        SGR_CHECK("remedy object present", remedy != NULL);
        SGR_CHECK("remedy.name is the import cure",
                  sgr_str_eq(remedy, "name",
                             "import_complete_shielded_history"));
        const char *imp = json_get_str(json_get(remedy, "import_command"));
        SGR_CHECK("remedy names -import-complete-shielded",
                  imp && strstr(imp, "-import-complete-shielded=") != NULL);
        const char *cp = json_get_str(json_get(remedy, "copy_prove_step"));
        SGR_CHECK("remedy names the copy-prove step",
                  cp && strstr(cp, "import-copy-prove.sh") != NULL);

        /* Containment: refuses live, never auto-executes. */
        const struct json_value *c = json_get(&out, "containment");
        SGR_CHECK("containment present", c != NULL);
        SGR_CHECK("containment.auto_execute false",
                  !sgr_bool(c, "auto_execute"));
        SGR_CHECK("containment.refuses_live true on canonical",
                  sgr_bool(c, "refuses_live"));
        SGR_CHECK("containment.datadir_is_live true",
                  sgr_bool(c, "datadir_is_live"));
        SGR_CHECK("containment.apply_in_place refused",
                  sgr_str_eq(c, "apply_in_place", "refused_live_lane"));
        SGR_CHECK("containment.owner_gated true",
                  sgr_bool(c, "owner_gated"));
        SGR_CHECK("containment.copy_prove_gated true",
                  sgr_bool(c, "copy_prove_gated"));
        SGR_CHECK("containment.operator_lane canonical",
                  sgr_str_eq(c, "operator_lane", "canonical"));

        json_free(&out);
    }

    /* ── COPY datadir: eligible offline, still never auto-executes ── */
    {
        blocker_reset_for_testing();
        sgr_set_gap(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID);
        sgr_set_gap(UTXO_APPLY_NF_GAP_BLOCKER_ID);
        /* No declared lane; a -COPY- datadir matches no live topology. */
        rpc_agent_set_boot_context("unknown", "release", copy_dir,
                                   0, 0, 0, 0);

        struct shielded_gap_containment c;
        shielded_gap_remedy_eval_containment(&c);
        SGR_CHECK("copy datadir_is_copy_marked", c.datadir_is_copy_marked);
        SGR_CHECK("copy datadir_is_live false", !c.datadir_is_live);
        SGR_CHECK("copy refuses_live false", !c.refuses_live);
        SGR_CHECK("copy apply_in_place eligible",
                  strcmp(c.apply_in_place, "eligible_offline_copy") == 0);
        SGR_CHECK("copy auto_execute STILL false", !c.auto_execute);

        struct json_value out;
        json_init(&out);
        shielded_gap_remedy_dump_state_json(&out, NULL);
        const struct json_value *jc = json_get(&out, "containment");
        SGR_CHECK("copy view apply_in_place eligible",
                  sgr_str_eq(jc, "apply_in_place", "eligible_offline_copy"));
        SGR_CHECK("copy view auto_execute false", !sgr_bool(jc, "auto_execute"));
        json_free(&out);
    }

    /* ── GAP ABSENT: no remedy emitted ── */
    {
        blocker_reset_for_testing();
        rpc_agent_set_boot_context("canonical", "release", live_dir,
                                   18232, 8033, 8443, 0);

        SGR_CHECK("classify NONE with no blockers",
                  shielded_gap_remedy_classify() == SHIELDED_GAP_NONE);

        struct json_value out;
        json_init(&out);
        shielded_gap_remedy_dump_state_json(&out, NULL);
        const struct json_value *gap = json_get(&out, "gap");
        SGR_CHECK("healthy gap.state none",
                  sgr_str_eq(gap, "state", "none"));
        SGR_CHECK("healthy gap.wedge_active false",
                  !sgr_bool(gap, "wedge_active"));
        SGR_CHECK("healthy emits NO remedy",
                  json_get(&out, "remedy") == NULL);
        /* Containment is still reported at rest, and still contained. */
        const struct json_value *c = json_get(&out, "containment");
        SGR_CHECK("healthy still reports containment", c != NULL);
        SGR_CHECK("healthy auto_execute false", !sgr_bool(c, "auto_execute"));
        json_free(&out);
    }

    blocker_reset_for_testing();
    return failures;
}
