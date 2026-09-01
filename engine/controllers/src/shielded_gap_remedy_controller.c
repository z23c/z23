/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * shielded_gap_remedy_controller — see the header for the contract.
 *
 * This is a CONTAINED, VERIFY-ONLY remedy surface.  It reads the typed blocker
 * registry + the runtime datadir/lane and emits a NAMED remedy (the exact
 * owner-run import command + the copy-prove step) with an explicit containment
 * verdict.  It NEVER executes the import, NEVER mutates state, NEVER auto-runs.
 * The only mutation the shielded-history cure performs lives in the owner-gated,
 * copy-prove-gated boot mode `-import-complete-shielded` (engine/entry/main.c) which
 * refuses live datadirs by construction; this surface merely points at it.
 */

#include "controllers/shielded_gap_remedy_controller.h"

#include "controllers/agent_controller.h"
#include "jobs/utxo_apply_anchors.h"
#include "jobs/utxo_apply_nullifiers.h"
#include "json/json.h"
#include "util/blocker.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SGR_STATE_SCHEMA "zcl.shielded_gap_remedy.v1"

/* The throwaway copy-prove datadir marker.  Mirrors
 * agent_copy_prove_controller.c cp_path_is_copy_marked() +
 * tools/scripts/import-copy-prove.sh's safety check: the ONLY datadir shape the
 * import may be applied against in place. */
#define SGR_COPY_MARKER "/.zclassic-c23-COPY-"

/* The named remedy, verbatim, so every status surface reports one canonical
 * cure.  These are advisory strings — never a command this process runs. */
#define SGR_REMEDY_NAME "import_complete_shielded_history"
#define SGR_REMEDY_SUMMARY \
    "Import the COMPLETE historical Sprout+Sapling anchor + nullifier set from " \
    "a co-located zclassicd chainstate, atomically flipping both activation " \
    "cursors to 0 — clearing the wedge without a from-genesis fold."
#define SGR_REMEDY_COPY_PROVE_STEP \
    "tools/scripts/import-copy-prove.sh --src=$HOME/.zclassic-c23 " \
    "--chainstate-src=$HOME/.zclassic/chainstate"
#define SGR_REMEDY_IMPORT_COMMAND \
    "zclassic23 -datadir=<TARGET-COPY> " \
    "-import-complete-shielded=<zclassicd-datadir>"
#define SGR_REMEDY_CUTOVER_NOTE \
    "Run the copy-prove step FIRST against a throwaway -COPY- datadir; gate on " \
    "H* CLIMB + tip-block-hash parity vs zclassicd; ONLY THEN cut over to " \
    "canonical. Never apply in place on a live node."
#define SGR_REMEDY_DOC "docs/work/shielded-history-importer.md"

enum shielded_gap_kind shielded_gap_remedy_classify(void)
{
    bool anchor = blocker_exists(UTXO_APPLY_ANCHOR_GAP_BLOCKER_ID);
    bool nullifier = blocker_exists(UTXO_APPLY_NF_GAP_BLOCKER_ID);
    if (anchor && nullifier)
        return SHIELDED_GAP_BOTH;
    if (anchor)
        return SHIELDED_GAP_ANCHOR_ONLY;
    if (nullifier)
        return SHIELDED_GAP_NULLIFIER_ONLY;
    return SHIELDED_GAP_NONE;
}

static const char *shielded_gap_kind_name(enum shielded_gap_kind k)
{
    switch (k) {
    case SHIELDED_GAP_ANCHOR_ONLY:    return "anchor_only";
    case SHIELDED_GAP_NULLIFIER_ONLY: return "nullifier_only";
    case SHIELDED_GAP_BOTH:           return "both";
    case SHIELDED_GAP_NONE:           break;
    }
    return "none";
}

/* Is `datadir` one of the two known live shielded-state datadirs?  Mirrors
 * engine/entry/main.c import_shielded_is_live_datadir() so this surface and the boot
 * mode agree on what "live" means. */
static bool sgr_datadir_is_live(const char *datadir)
{
    if (!datadir || !datadir[0])
        return false;
    const char *home = getenv("HOME");
    if (!home || !home[0])
        return false;
    char live[600], mint[600];
    snprintf(live, sizeof(live), "%s/.zclassic-c23", home);
    snprintf(mint, sizeof(mint), "%s/.zclassic-c23-mint", home);
    size_t tl = strlen(datadir);
    while (tl > 1 && datadir[tl - 1] == '/') tl--;
    return (strlen(live) == tl && strncmp(datadir, live, tl) == 0) ||
           (strlen(mint) == tl && strncmp(datadir, mint, tl) == 0);
}

void shielded_gap_remedy_eval_containment(struct shielded_gap_containment *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));

    /* Structural invariant: this surface NEVER executes the import. */
    out->auto_execute = false;

    const char *datadir = agent_runtime_context_datadir();
    const char *lane = agent_runtime_context_operator_lane();
    snprintf(out->datadir, sizeof(out->datadir), "%s", datadir ? datadir : "");
    snprintf(out->operator_lane, sizeof(out->operator_lane), "%s",
             lane && lane[0] ? lane : "unknown");

    out->datadir_is_live = sgr_datadir_is_live(datadir);
    out->datadir_is_copy_marked =
        datadir && strstr(datadir, SGR_COPY_MARKER) != NULL;

    /* Eligible to apply in place ONLY on a throwaway -COPY- datadir that is not
     * a known live path.  Everything else (canonical/soak/dev/unknown lanes,
     * any non-copy datadir) REFUSES — the operator must copy-prove first. */
    bool eligible = out->datadir_is_copy_marked && !out->datadir_is_live;
    out->refuses_live = !eligible;
    snprintf(out->apply_in_place, sizeof(out->apply_in_place), "%s",
             eligible ? "eligible_offline_copy" : "refused_live_lane");
}

static void sgr_push_remedy(struct json_value *out)
{
    struct json_value remedy = {0};
    json_init(&remedy);
    json_set_object(&remedy);
    json_push_kv_str(&remedy, "name", SGR_REMEDY_NAME);
    json_push_kv_str(&remedy, "summary", SGR_REMEDY_SUMMARY);
    json_push_kv_str(&remedy, "copy_prove_step", SGR_REMEDY_COPY_PROVE_STEP);
    json_push_kv_str(&remedy, "import_command", SGR_REMEDY_IMPORT_COMMAND);
    json_push_kv_str(&remedy, "cutover_note", SGR_REMEDY_CUTOVER_NOTE);
    json_push_kv_str(&remedy, "doc", SGR_REMEDY_DOC);
    json_push_kv(out, "remedy", &remedy);
    json_free(&remedy);
}

static void sgr_push_containment(struct json_value *out,
                                 const struct shielded_gap_containment *c)
{
    struct json_value obj = {0};
    json_init(&obj);
    json_set_object(&obj);
    /* Contained by construction: this surface never executes the cure. */
    json_push_kv_bool(&obj, "auto_execute", c->auto_execute);
    json_push_kv_bool(&obj, "contained", true);
    json_push_kv_bool(&obj, "owner_gated", true);
    json_push_kv_bool(&obj, "copy_prove_gated", true);
    json_push_kv_bool(&obj, "refuses_live", c->refuses_live);
    json_push_kv_bool(&obj, "datadir_is_live", c->datadir_is_live);
    json_push_kv_bool(&obj, "datadir_is_copy_marked", c->datadir_is_copy_marked);
    json_push_kv_str(&obj, "operator_lane", c->operator_lane);
    json_push_kv_str(&obj, "datadir", c->datadir);
    json_push_kv_str(&obj, "apply_in_place", c->apply_in_place);
    json_push_kv(out, "containment", &obj);
    json_free(&obj);
}

bool shielded_gap_remedy_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        LOG_FAIL("diag", "shielded_gap_remedy: output is NULL");

    json_set_object(out);
    json_push_kv_str(out, "schema", SGR_STATE_SCHEMA);

    enum shielded_gap_kind kind = shielded_gap_remedy_classify();
    bool wedged = kind != SHIELDED_GAP_NONE;

    struct json_value gap = {0};
    json_init(&gap);
    json_set_object(&gap);
    json_push_kv_bool(&gap, "anchor_gap_blocker_present",
                      kind == SHIELDED_GAP_ANCHOR_ONLY ||
                          kind == SHIELDED_GAP_BOTH);
    json_push_kv_bool(&gap, "nullifier_gap_blocker_present",
                      kind == SHIELDED_GAP_NULLIFIER_ONLY ||
                          kind == SHIELDED_GAP_BOTH);
    json_push_kv_str(&gap, "state", shielded_gap_kind_name(kind));
    json_push_kv_bool(&gap, "wedge_active", wedged);
    json_push_kv(out, "gap", &gap);
    json_free(&gap);

    /* The NAMED remedy is emitted ONLY when the wedge is actually present — a
     * healthy node surfaces no cure to run.  Containment is always reported so
     * a caller can see the surface is contained even at rest. */
    struct shielded_gap_containment c;
    shielded_gap_remedy_eval_containment(&c);
    if (wedged)
        sgr_push_remedy(out);
    sgr_push_containment(out, &c);

    return true;
}
