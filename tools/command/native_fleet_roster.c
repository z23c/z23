/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: ops.mesh.roster — the operator's own fleet, with every fact
 *          labelled by who established it. `z23 fleet roster` is its alias.
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────────
 *
 * WHY. A game that rewards an operator for the machines they run has to be
 * able to say which machines those are and what is actually known about
 * each. The mesh already knows: the pairing store says which machines this
 * operator paired, and the observation store keeps the latest independently
 * verified signed status receipt from each. This leaf is that answer in one
 * typed reply, and it is where the difference between "a peer observed it"
 * and "the machine said so" is made impossible to lose.
 *
 * READ-ONLY. It opens <datadir>/node.db through the shared read-only seam
 * and reads two projections. It never dials, never probes, never writes,
 * and never asks a running node anything — an operator can point it at a
 * copied datadir and the copy's hash still describes it afterwards.
 *
 * INPUT (zcl.fleet_roster_input.v1)
 *   datadir   optional string; defaults to the CLI's resolved datadir.
 *
 * OUTPUT (zcl.fleet_roster.v1) on ok=true
 *   leaf, generated_unix, rules_table
 *   rows[]    {pairing_id, zid, noise_fingerprint, state,
 *              verified[]      {fact, observed, held, observed_unix, why},
 *              self_reported[] {fact, observed, why},
 *              airships{<asset>: count}}
 *   row_count, total, truncated, airships{<asset>: fleet total}
 *
 * TWO CLASSES, NEVER ONE FIELD. `verified` carries only facts the rule
 * table marks PEER_VERIFIED, each with the time the observation was made;
 * `self_reported` carries the rest. No consumer can read one as the other,
 * because they are not in the same array and never share a key.
 *
 * UNOBSERVED IS NOT FALSE. A fact this node has no observer for comes back
 * observed:false with `why` saying what is missing, never held:true and
 * never a silent false. Both pay nothing; they say different things.
 *
 * AIRSHIPS. The counts come from engine/composition/fleet_airship_rules.def
 * through fleet_airship_award, over the facts OBSERVED TO HOLD. The facts
 * and the assets are read from that table too, so adding either is one .def
 * edit and no edit here.
 *
 * REFUSALS. ROSTER_UNPAIRED_OPERATOR when no machine is paired at all —
 * an empty fleet is a state to fix, not an empty list to render. And
 * ROSTER_IDENTITY_COLLISION when two rows carry one ZID fingerprint, which
 * would double-count one machine as two; the roster refuses rather than
 * reward it.
 */

#include "command/native_command.h"

#include "config/fleet_airship_rules.h"
#include "models/mesh_machine_observation.h"
#include "services/mesh_pairing_service.h"
#include "session/mesh_status_proto.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/time_compat.h"

#include <stdio.h>
#include <string.h>

#define ROSTER_LEAF "ops.mesh.roster"
#define ROSTER_RULES_TABLE "engine/composition/fleet_airship_rules.def"
/* The row cap is the game's airship cap: a roster that could name more
 * machines than a match can fly would promise a fleet the wire cannot
 * carry. Beyond it the reply says truncated with the full total. */
#define ROSTER_ROW_MAX 32u
/* Enough of a 64-hex domain-separated fingerprint to tell this operator's
 * own machines apart at a glance, and never enough to be mistaken for the
 * whole identity. The full fingerprint stays in `zid`. */
#define ROSTER_FINGERPRINT_SHORT 16u
#define ROSTER_HELD_MAX 32u

/* The latest durable evidence about one paired machine, reduced to what a
 * roster row needs. */
struct roster_evidence {
    bool present;
    enum mesh_status_receipt_status status;
    int64_t observed_unix;
};

static void roster_fail(struct zcl_command_reply *reply, const char *code,
                        const char *message, const char *next_action)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, "read", false, false,
                           message, ROSTER_RULES_TABLE);
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "%s", next_action);
}

/* What this node observed about one fact of one machine. Returns false when
 * nothing here observes that fact at all — which is not the same as
 * observing it to be false, and says so in `why`. */
static bool roster_observe(const char *fact,
                           const struct mesh_pairing_public_view *view,
                           const struct roster_evidence *evidence, bool *held,
                           int64_t *observed_unix, const char **why)
{
    *held = false;
    *observed_unix = 0;
    *why = "";
    if (strcmp(fact, "reachable") == 0) {
        if (!evidence->present) {
            *why = "no signed status receipt from this machine has ever "
                   "been verified here";
            return false;
        }
        /* Reaching a machine is what produced the receipt; an expired or
         * revoked pairing is a machine this operator no longer runs. */
        *held = evidence->status == MESH_STATUS_RECEIPT_OK &&
                strcmp(view->state, "active") == 0;
        *observed_unix = evidence->observed_unix;
        return true;
    }
    if (strcmp(fact, "reachable_two_paths") == 0) {
        *why = "the observation store records that a machine answered, "
               "never which path carried the answer";
        return false;
    }
    *why = "the pairing store carries no field a peer established for this "
           "fact";
    return false;
}

/* One roster row: identity, both fact classes, and what the rule table
 * awards this machine. Returns the count of facts observed to hold, which
 * the caller needs for nothing but reading the row back in a test. */
static void roster_push_row(struct json_value *rows,
                            const struct mesh_pairing_public_view *view,
                            const struct roster_evidence *evidence)
{
    struct json_value row, verified, self_reported, airships;
    const char *held[ROSTER_HELD_MAX];
    size_t held_count = 0;
    char shortfp[ROSTER_FINGERPRINT_SHORT + 1];

    (void)snprintf(shortfp, sizeof(shortfp), "%.*s",
                   (int)ROSTER_FINGERPRINT_SHORT, view->peer_noise_fingerprint);

    json_init(&row);
    json_set_object(&row);
    (void)json_push_kv_str(&row, "pairing_id", view->pairing_id);
    (void)json_push_kv_str(&row, "zid", view->peer_master_fingerprint);
    (void)json_push_kv_str(&row, "noise_fingerprint", shortfp);
    (void)json_push_kv_str(&row, "state", view->state);

    json_init(&verified);
    json_set_array(&verified);
    json_init(&self_reported);
    json_set_array(&self_reported);
    for (size_t i = 0; i < fleet_airship_fact_count(); i++) {
        const struct fleet_airship_fact_v1 *fact = fleet_airship_fact_at(i);
        struct json_value entry;
        bool observed, node_holds;
        int64_t observed_unix;
        const char *why;

        if (!fact)
            continue;
        observed = roster_observe(fact->name, view, evidence, &node_holds,
                                  &observed_unix, &why);
        json_init(&entry);
        json_set_object(&entry);
        (void)json_push_kv_str(&entry, "fact", fact->name);
        (void)json_push_kv_bool(&entry, "observed", observed);
        (void)json_push_kv_str(&entry, "why", why);
        if (fact->verification == FLEET_AIRSHIP_PEER_VERIFIED) {
            (void)json_push_kv_bool(&entry, "held", node_holds);
            (void)json_push_kv_int(&entry, "observed_unix", observed_unix);
            (void)json_push_back(&verified, &entry);
            if (observed && node_holds && held_count < ROSTER_HELD_MAX)
                held[held_count++] = fact->name;
        } else {
            (void)json_push_back(&self_reported, &entry);
        }
        json_free(&entry);
    }
    (void)json_push_kv(&row, "verified", &verified);
    (void)json_push_kv(&row, "self_reported", &self_reported);
    json_free(&verified);
    json_free(&self_reported);

    json_init(&airships);
    json_set_object(&airships);
    for (size_t i = 0; i < fleet_airship_asset_count(); i++) {
        const char *asset = fleet_airship_asset_at(i);

        if (asset)
            (void)json_push_kv_int(
                &airships, asset,
                (int64_t)fleet_airship_award(held, held_count, asset));
    }
    (void)json_push_kv(&row, "airships", &airships);
    json_free(&airships);

    (void)json_push_back(rows, &row);
    json_free(&row);
}

/* The fleet total for one asset: the same award, summed over the rows this
 * reply carries. A truncated reply totals what it returned, never what it
 * did not look at. */
static int64_t roster_fleet_award(const struct mesh_pairing_public_view *views,
                                  const struct roster_evidence *evidence,
                                  size_t count, const char *asset)
{
    int64_t total = 0;

    for (size_t r = 0; r < count; r++) {
        const char *held[ROSTER_HELD_MAX];
        size_t held_count = 0;

        for (size_t i = 0; i < fleet_airship_fact_count(); i++) {
            const struct fleet_airship_fact_v1 *fact = fleet_airship_fact_at(i);
            bool node_holds;
            int64_t at;
            const char *why;

            if (!fact || fact->verification != FLEET_AIRSHIP_PEER_VERIFIED)
                continue;
            if (roster_observe(fact->name, &views[r], &evidence[r], &node_holds,
                               &at, &why) &&
                node_holds && held_count < ROSTER_HELD_MAX)
                held[held_count++] = fact->name;
        }
        total += (int64_t)fleet_airship_award(held, held_count, asset);
    }
    return total;
}

/* Match each pairing view to its latest durable observation by pairing id.
 * A view with no observation keeps `present` false, which the fact reader
 * reports as unobserved rather than unreachable. */
static void roster_match_evidence(const struct mesh_pairing_public_view *views,
                                  size_t view_count,
                                  const struct db_mesh_machine_view *machines,
                                  size_t machine_count,
                                  struct roster_evidence *out)
{
    for (size_t i = 0; i < view_count; i++) {
        out[i].present = false;
        out[i].status = MESH_STATUS_RECEIPT_INTERNAL;
        out[i].observed_unix = 0;
        for (size_t j = 0; j < machine_count; j++) {
            if (strcmp(machines[j].pairing.pairing_id, views[i].pairing_id) != 0)
                continue;
            if (!machines[j].has_observation)
                break;
            out[i].present = true;
            out[i].status = machines[j].observation.status;
            out[i].observed_unix = machines[j].observation.observed_unix;
            break;
        }
    }
}

/* Two rows carrying one ZID fingerprint would count one machine twice.
 * Returns the colliding fingerprint, or NULL. */
static const char *roster_identity_collision(
    const struct mesh_pairing_public_view *views, size_t count)
{
    for (size_t i = 0; i + 1 < count; i++) {
        for (size_t j = i + 1; j < count; j++) {
            if (strcmp(views[i].peer_master_fingerprint,
                       views[j].peer_master_fingerprint) == 0)
                return views[i].peer_master_fingerprint;
        }
    }
    return NULL;
}

void zcl_native_handle_fleet_roster(const struct zcl_command_request *request,
                                    struct zcl_command_reply *reply)
{
    struct mesh_pairing_public_view views[ROSTER_ROW_MAX];
    struct roster_evidence evidence[ROSTER_ROW_MAX];
    struct db_mesh_machine_view *machines = NULL;
    struct db_mesh_pairing_counts counts;
    struct json_value rows, airships;
    const struct json_value *arg;
    const char *datadir = NULL;
    sqlite3 *db = NULL;
    struct node_db ndb;
    size_t view_count = 0;
    int machine_count = 0;
    int64_t now;

    if (!reply)
        return;

    arg = request && request->input ? json_get(request->input, "datadir") : NULL;
    if (arg && arg->type == JSON_STR)
        datadir = json_get_str(arg);
    if (!datadir || !datadir[0])
        datadir = zcl_native_command_datadir();

    /* READ leaf: node_db_open() here would create, migrate and clean the
     * staging tables of whatever datadir the caller named, including the
     * live one this leaf defaults to. */
    if (!zcl_native_node_db_require_readonly(datadir, reply,
                                             "the mesh pairing store", &db,
                                             &ndb))
        return;

    now = platform_time_wall_unix();
    memset(&counts, 0, sizeof(counts));
    if (!mesh_pairing_service_list(&ndb, now, views, ROSTER_ROW_MAX,
                                   &view_count, &counts)) {
        zcl_native_node_db_close_readonly(&db, &ndb);
        roster_fail(reply, "ROSTER_STORE_UNREADABLE",
                    "the mesh pairing store could not be read, so this "
                    "reply would be an empty fleet rather than a read one",
                    "z23 ops mesh pair list");
        return;
    }
    if (counts.total == 0) {
        zcl_native_node_db_close_readonly(&db, &ndb);
        roster_fail(reply, "ROSTER_UNPAIRED_OPERATOR",
                    "no machine is paired with this one, so there is no "
                    "fleet to roster",
                    "pair a machine with z23 ops mesh pair plan");
        return;
    }
    if (roster_identity_collision(views, view_count)) {
        zcl_native_node_db_close_readonly(&db, &ndb);
        roster_fail(reply, "ROSTER_IDENTITY_COLLISION",
                    "two pairing rows carry one chain identity, which would "
                    "count one machine as two",
                    "revoke the duplicate with z23 ops mesh pair revoke");
        return;
    }

    machines = zcl_calloc(ROSTER_ROW_MAX, sizeof(*machines), "roster_machines");
    if (machines) {
        machine_count = db_mesh_machine_observation_list(&ndb, machines,
                                                         ROSTER_ROW_MAX, now);
        if (machine_count < 0)
            machine_count = 0;
    }
    roster_match_evidence(views, view_count, machines, (size_t)machine_count,
                          evidence);
    free(machines);
    zcl_native_node_db_close_readonly(&db, &ndb);

    (void)json_push_kv_str(&reply->data, "leaf", ROSTER_LEAF);
    (void)json_push_kv_int(&reply->data, "generated_unix", now);
    (void)json_push_kv_str(&reply->data, "rules_table", ROSTER_RULES_TABLE);

    json_init(&rows);
    json_set_array(&rows);
    for (size_t i = 0; i < view_count; i++)
        roster_push_row(&rows, &views[i], &evidence[i]);
    (void)json_push_kv(&reply->data, "rows", &rows);
    json_free(&rows);

    (void)json_push_kv_int(&reply->data, "row_count", (int64_t)view_count);
    (void)json_push_kv_int(&reply->data, "total", counts.total);
    (void)json_push_kv_bool(&reply->data, "truncated",
                            (int64_t)view_count < counts.total);

    json_init(&airships);
    json_set_object(&airships);
    for (size_t i = 0; i < fleet_airship_asset_count(); i++) {
        const char *asset = fleet_airship_asset_at(i);

        if (asset)
            (void)json_push_kv_int(
                &airships, asset,
                roster_fleet_award(views, evidence, view_count, asset));
    }
    (void)json_push_kv(&reply->data, "airships", &airships);
    json_free(&airships);

    reply->status = ZCL_COMMAND_STATUS_PASSED;
}
