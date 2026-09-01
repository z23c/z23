/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * diagnostics_mvp.c — the "mvp" dumpstate subsystem (schema zcl.mvp_status.v1).
 *
 * Turns docs/MVP.md's eight operator acceptance criteria (v1 = MRS 8/8) from a
 * human reading docs against the node into a typed, evidence-derived query:
 * `z23 ops state --subsystem=mvp`.
 *
 * HONESTY CONTRACT — this is a REPORTER, never a gate. It derives
 * met=true|false|unknown STRICTLY from durable/runtime evidence the node
 * already produces (node_health tip-hold, the soak attestation service, the
 * standing utxo_parity oracle, the replay-canary watch). It can flip nothing
 * true on its own, performs no consensus/state writes, and a criterion whose
 * runtime evidence source is absent is reported "unknown" with a NAMED reason
 * — never silently "met". Criteria 1/2/4/5 are proven only by offline operator
 * make-targets (install / onion timing / shielded params / store buyer) with no
 * runtime signal, so at runtime they are honestly "unknown"; the value here is
 * the enumeration + the live signals that DO exist (sync_state/gap, soak
 * healthy/eligible, parity mismatches, canary latch) plus the met_count math.
 *
 * The classifier mvp_build_status_json() is a PURE function over struct
 * mvp_evidence — the single place met/unmet/unknown is decided — so the unit
 * test seeds known evidence and asserts the classification directly, while the
 * live dumper mvp_dump_state_json() only gathers evidence then calls it. */

#include "controllers/diagnostics_internal.h"

#include "config/runtime.h"
#include "services/node_health_service.h"
#include "services/soak_attestation_service.h"
#include "services/utxo_parity_service.h"
#include "services/canary_sentinel_watch.h"
#include "sync/sync_state.h"
#include "validation/main_state.h"
#include "models/database.h"
#include "json/json.h"
#include "util/log_macros.h"

#include <string.h>

/* Tri-state a criterion resolves to. JSON encodes MET→true, UNMET→false,
 * UNKNOWN→null (an absent/insufficient evidence source), with a parallel
 * "met_state" string for human/typed consumers. */
enum mvp_met { MVP_UNMET = 0, MVP_MET = 1, MVP_UNKNOWN = 2 };

static const char *mvp_met_state_name(enum mvp_met m)
{
    return m == MVP_MET ? "met" : m == MVP_UNMET ? "unmet" : "unknown";
}

/* Push one criterion object. `evidence` is a caller-built object (it MUST
 * already carry "evidence_source"); it is copied in and remains owned by the
 * caller. `since_epoch` <= 0 and `blocker` NULL/"" both encode as JSON null. */
static void mvp_push_criterion(struct json_value *arr, const char *id,
                               const char *title, enum mvp_met met,
                               int64_t since_epoch, const char *blocker,
                               const char *reason,
                               const struct json_value *evidence)
{
    struct json_value c = {0};
    json_set_object(&c);
    json_push_kv_str(&c, "id", id);
    json_push_kv_str(&c, "title", title);

    struct json_value m = {0};
    if (met == MVP_MET)       json_set_bool(&m, true);
    else if (met == MVP_UNMET) json_set_bool(&m, false);
    else                       json_set_null(&m);
    json_push_kv(&c, "met", &m);
    json_free(&m);

    json_push_kv_str(&c, "met_state", mvp_met_state_name(met));
    json_push_kv_str(&c, "reason", reason ? reason : "");

    struct json_value s = {0};
    if (since_epoch > 0) json_set_int(&s, since_epoch);
    else                 json_set_null(&s);
    json_push_kv(&c, "since", &s);
    json_free(&s);

    struct json_value b = {0};
    if (blocker && blocker[0]) json_set_str(&b, blocker);
    else                       json_set_null(&b);
    json_push_kv(&c, "blocker", &b);
    json_free(&b);

    if (evidence && evidence->type == JSON_OBJ)
        json_push_kv(&c, "evidence", evidence);

    json_push_back(arr, &c);
    json_free(&c);
}

/* Convenience: fresh evidence object seeded with its source label. */
static void mvp_evidence_begin(struct json_value *e, const char *source,
                               bool runtime_observable)
{
    json_set_object(e);
    json_push_kv_str(e, "evidence_source", source);
    json_push_kv_bool(e, "runtime_observable", runtime_observable);
}

bool mvp_build_status_json(const struct mvp_evidence *ev, struct json_value *out)
{
    if (!out)
        LOG_FAIL("mvp", "null out");
    static const struct mvp_evidence zero = {0};
    if (!ev) ev = &zero;

    json_set_object(out);
    json_push_kv_str(out, "schema", "zcl.mvp_status.v1");
    json_push_kv_str(out, "doc", "docs/MVP.md");
    json_push_kv_bool(out, "reporter_only", true);

    struct json_value arr = {0};
    json_set_array(&arr);
    int met_count = 0;

    /* ── C1: single-binary install on a clean OS ─────────────────────
     * Offline operator proof (make ci-install-linger); no runtime signal. */
    {
        struct json_value e = {0};
        mvp_evidence_begin(&e, "operator make-target (make ci-install-linger)",
                           false);
        enum mvp_met st = MVP_UNKNOWN;
        mvp_push_criterion(&arr, "C1",
            "Single-binary install on clean Ubuntu/Debian", st, 0, NULL,
            "clean-OS single-binary install is an offline operator proof; "
            "not runtime-observable",
            &e);
        json_free(&e);
        if (st == MVP_MET) met_count++;
    }

    /* ── C2: Tor onion bootstrap < 60s ───────────────────────────────
     * Offline operator proof (make mvp-onion-local); the <60s timing is not
     * durably recorded at runtime. */
    {
        struct json_value e = {0};
        mvp_evidence_begin(&e, "operator make-target (make mvp-onion-local)",
                           false);
        enum mvp_met st = MVP_UNKNOWN;
        mvp_push_criterion(&arr, "C2", "Tor onion bootstrap in <60s", st, 0,
            NULL,
            "onion <60s bootstrap timing is not durably recorded at runtime",
            &e);
        json_free(&e);
        if (st == MVP_MET) met_count++;
    }

    /* ── C3: cold-start sync to tip < 10min ──────────────────────────
     * Evidence = live tip-hold (node_health sync_state/gap) + a cold-start
     * sync-benchmark receipt. The receipt source is PENDING (no <10min
     * cold-start-to-tip receipt is produced yet), so the criterion is
     * unknown; the live tip-hold facts are surfaced as supporting evidence. */
    {
        struct json_value e = {0};
        mvp_evidence_begin(&e,
            "tip-hold (node_health sync_state/gap) + cold-start sync-benchmark "
            "receipt [pending]", true);
        json_push_kv_bool(&e, "sync_benchmark_receipt_present",
                          ev->c3_sync_benchmark_receipt_present);
        if (ev->c3_health_present) {
            json_push_kv_bool(&e, "health_present", true);
            json_push_kv_str(&e, "sync_state",
                             sync_state_name((enum sync_state)ev->c3_sync_state));
            json_push_kv_int(&e, "log_head_gap", ev->c3_log_head_gap);
            json_push_kv_bool(&e, "at_tip",
                              ev->c3_sync_state == SYNC_AT_TIP);
        } else {
            json_push_kv_bool(&e, "health_present", false);
        }
        json_push_kv_int(&e, "cold_sync_secs", ev->c3_cold_sync_secs);

        enum mvp_met st;
        const char *reason;
        const char *blocker = NULL;
        if (!ev->c3_sync_benchmark_receipt_present) {
            st = MVP_UNKNOWN;
            reason = "sync-benchmark receipt pending: no <10min "
                     "cold-start-to-tip receipt produced yet";
        } else if (ev->c3_cold_sync_secs >= 0 &&
                   ev->c3_cold_sync_secs <= 600) {
            st = MVP_MET;
            reason = "cold-start sync-to-tip receipt within the 10min budget";
        } else {
            st = MVP_UNMET;
            blocker = "sync.cold_start_over_budget";
            reason = "cold-start sync-to-tip receipt exceeded the 10min budget";
        }
        mvp_push_criterion(&arr, "C3", "Cold-start sync to tip in <10 min", st,
                           0, blocker, reason, &e);
        json_free(&e);
        if (st == MVP_MET) met_count++;
    }

    /* ── C4: receive shielded payment end-to-end ─────────────────────
     * Offline operator proof (make test-shielded-payment; needs
     * ~/.zcash-params); no runtime signal. */
    {
        struct json_value e = {0};
        mvp_evidence_begin(&e,
            "operator make-target (make test-shielded-payment)", false);
        enum mvp_met st = MVP_UNKNOWN;
        mvp_push_criterion(&arr, "C4", "Receive shielded payment end-to-end",
            st, 0, NULL,
            "full shielded send+receive is an offline operator proof "
            "(needs ~/.zcash-params); not runtime-observable",
            &e);
        json_free(&e);
        if (st == MVP_MET) met_count++;
    }

    /* ── C5: list + sell a file via the store ────────────────────────
     * Offline operator proof (make ci-mvp-gates store_e2e_shielded); no
     * full-live-buyer runtime signal. */
    {
        struct json_value e = {0};
        mvp_evidence_begin(&e,
            "operator make-target (make ci-mvp-gates store_e2e_shielded)",
            false);
        enum mvp_met st = MVP_UNKNOWN;
        mvp_push_criterion(&arr, "C5", "List + sell file via store", st, 0,
            NULL,
            "full live buyer/file-transfer proof is offline; "
            "not runtime-observable",
            &e);
        json_free(&e);
        if (st == MVP_MET) met_count++;
    }

    /* ── C6: 7-day soak with zero operator intervention ──────────────
     * Live evidence = the soak attestation service (per-tick healthy /
     * window-eligible) + the continuous clean-window hours + an optional
     * external SLO probe success rate. The soak service does not itself
     * compute the 168h continuous window at runtime, so window_hours is
     * unknown (-1) unless a caller supplies it → unknown with a named reason.
     * The make soak-evidence-report judge remains the authority. */
    {
        struct json_value e = {0};
        mvp_evidence_begin(&e,
            "soak attestation service + external SLO probe", true);
        json_push_kv_bool(&e, "soak_service_initialized", ev->c6_soak_present);
        json_push_kv_bool(&e, "last_healthy", ev->c6_soak_last_healthy);
        json_push_kv_bool(&e, "window_eligible", ev->c6_soak_window_eligible);
        json_push_kv_int(&e, "window_hours", ev->c6_soak_window_hours);
        json_push_kv_int(&e, "window_hours_required",
                         MVP_SOAK_WINDOW_HOURS_REQUIRED);
        json_push_kv_bool(&e, "slo_probe_present", ev->c6_slo_probe_present);
        json_push_kv_real(&e, "slo_success_rate", ev->c6_slo_success_rate);

        enum mvp_met st;
        int64_t since = 0;
        const char *blocker = NULL;
        const char *reason;
        if (!ev->c6_soak_present) {
            st = MVP_UNKNOWN;
            reason = "soak attestation service not initialized "
                     "(no soak_attestation.jsonl)";
        } else if (ev->c6_soak_window_hours < 0) {
            st = MVP_UNKNOWN;
            reason = "continuous clean-window hours not tracked at runtime; "
                     "run make soak-evidence-report for the MET/NOT_MET judge";
        } else if (!ev->c6_soak_last_healthy || !ev->c6_soak_window_eligible) {
            st = MVP_UNMET;
            blocker = "soak.window_broken";
            reason = "soak window not clean: an unhealthy or ineligible tick";
        } else if (ev->c6_soak_window_hours < MVP_SOAK_WINDOW_HOURS_REQUIRED) {
            st = MVP_UNMET;
            blocker = "soak.window_incomplete";
            reason = "clean soak window shorter than the required 168h";
        } else if (ev->c6_slo_probe_present &&
                   ev->c6_slo_success_rate < MVP_SLO_SUCCESS_MIN) {
            st = MVP_UNMET;
            blocker = "soak.slo_below_floor";
            reason = "external SLO probe success rate below the floor";
        } else {
            st = MVP_MET;
            reason = "168h+ clean, healthy, eligible soak window";
        }
        mvp_push_criterion(&arr, "C6",
            "7-day soak with zero operator intervention", st, since, blocker,
            reason, &e);
        json_free(&e);
        if (st == MVP_MET) met_count++;
    }

    /* ── C7: recover from kill -9 in <2 min ──────────────────────────
     * Evidence = a recovery-drill timing. Not recorded at runtime (make
     * test-crash-bootstrap is the operator proof) → unknown unless supplied. */
    {
        struct json_value e = {0};
        mvp_evidence_begin(&e,
            "recovery-drill timing (make test-crash-bootstrap)", false);
        json_push_kv_bool(&e, "recovery_drill_present",
                          ev->c7_recovery_drill_present);
        json_push_kv_int(&e, "recovery_secs", ev->c7_recovery_secs);
        json_push_kv_int(&e, "recovery_secs_max", MVP_RECOVERY_SECS_MAX);

        enum mvp_met st;
        const char *blocker = NULL;
        const char *reason;
        if (!ev->c7_recovery_drill_present) {
            st = MVP_UNKNOWN;
            reason = "recovery-drill timing not recorded at runtime; "
                     "make test-crash-bootstrap is the operator proof";
        } else if (ev->c7_recovery_secs >= 0 &&
                   ev->c7_recovery_secs <= MVP_RECOVERY_SECS_MAX) {
            st = MVP_MET;
            reason = "kill-9 recovery drill within the 2min budget";
        } else {
            st = MVP_UNMET;
            blocker = "recovery.too_slow";
            reason = "kill-9 recovery drill exceeded the 2min budget";
        }
        mvp_push_criterion(&arr, "C7", "Recover from kill -9 in <2 min", st, 0,
                           blocker, reason, &e);
        json_free(&e);
        if (st == MVP_MET) met_count++;
    }

    /* ── C8: consensus parity with zclassicd ─────────────────────────
     * Live evidence = the standing utxo_parity oracle (0 mismatches) + the
     * replay-canary watch (no FAIL latch). Absent oracle AND absent canary
     * verdict → unknown with a named reason. */
    {
        struct json_value e = {0};
        mvp_evidence_begin(&e,
            "utxo_parity oracle + replay-canary watch", true);
        json_push_kv_bool(&e, "parity_oracle_present", ev->c8_parity_present);
        json_push_kv_int(&e, "parity_mismatches", ev->c8_parity_mismatches);
        json_push_kv_bool(&e, "canary_present", ev->c8_canary_present);
        json_push_kv_bool(&e, "canary_fail_active", ev->c8_canary_fail_active);

        enum mvp_met st;
        const char *blocker = NULL;
        const char *reason;
        if (!ev->c8_parity_present && !ev->c8_canary_present) {
            st = MVP_UNKNOWN;
            reason = "no zclassicd parity oracle resolved and no replay-canary "
                     "verdict present";
        } else if (ev->c8_canary_fail_active) {
            st = MVP_UNMET;
            blocker = "consensus.replay_canary_failed";
            reason = "a replay-canary kind is latched FAIL";
        } else if (ev->c8_parity_present && ev->c8_parity_mismatches > 0) {
            st = MVP_UNMET;
            blocker = "consensus.utxo_drift";
            reason = "utxo_parity oracle detected mismatches";
        } else if (ev->c8_parity_present && ev->c8_parity_mismatches == 0) {
            st = MVP_MET;
            reason = "standing parity oracle at 0 mismatches, canary not failing";
        } else {
            /* canary present + not failing, but no standing parity oracle for
             * the "0 mismatches over the soak window" claim. */
            st = MVP_UNKNOWN;
            reason = "replay-canary not failing, but no standing parity oracle "
                     "for the 0-mismatch-over-soak claim";
        }
        mvp_push_criterion(&arr, "C8", "Consensus parity with zclassicd", st, 0,
                           blocker, reason, &e);
        json_free(&e);
        if (st == MVP_MET) met_count++;
    }

    json_push_kv(out, "criteria", &arr);
    json_free(&arr);

    json_push_kv_int(out, "met_count", met_count);
    json_push_kv_int(out, "total", MVP_CRITERIA_TOTAL);
    json_push_kv_bool(out, "ready_for_v1", met_count == MVP_CRITERIA_TOTAL);

    char health[96];
    snprintf(health, sizeof(health), "MVP reporter: MRS %d/%d",
             met_count, MVP_CRITERIA_TOTAL);
    diag_push_health(out, true, health);
    return true;
}

bool mvp_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        LOG_FAIL("mvp", "null out");

    struct mvp_evidence ev = {0};
    /* Sources with no runtime surface start explicitly absent/unknown. */
    ev.c3_sync_benchmark_receipt_present = false;
    ev.c3_cold_sync_secs = -1;
    ev.c6_soak_window_hours = -1;
    ev.c6_slo_probe_present = false;
    ev.c6_slo_success_rate = -1.0;
    ev.c7_recovery_drill_present = false;
    ev.c7_recovery_secs = -1;
    ev.c8_parity_mismatches = -1;

    /* C3 tip-hold: only when both the node_db and boot main_state are wired
     * (node_health_collect walks chain state — guarded to stay reentrant and
     * NULL-safe on an uninitialized node). */
    struct node_db *ndb = app_runtime_node_db();
    struct main_state *ms = diag_main_state();
    if (ndb && ms) {
        struct node_health_snapshot snap;
        memset(&snap, 0, sizeof(snap));
        node_health_collect(&snap, ndb, ms);
        ev.c3_health_present = true;
        ev.c3_sync_state = (int)snap.sync_state;
        ev.c3_log_head_gap = snap.log_head_gap;
    }

    /* C6 soak attestation service (read-back from its own dumper). */
    {
        struct json_value s = {0};
        if (soak_dump_state_json(&s, NULL)) {
            ev.c6_soak_present = json_get_bool(json_get(&s, "initialized"));
            ev.c6_soak_last_healthy =
                json_get_bool(json_get(&s, "last_healthy"));
            ev.c6_soak_window_eligible =
                json_get_bool(json_get(&s, "last_window_eligible"));
        }
        json_free(&s);
    }

    /* C8 standing utxo_parity oracle. */
    {
        struct json_value p = {0};
        if (utxo_parity_dump_state_json(&p, NULL)) {
            bool active = json_get_bool(json_get(&p, "active"));
            int64_t checks = json_get_int(json_get(&p, "checks_total"));
            ev.c8_parity_present = active && checks > 0;
            if (ev.c8_parity_present)
                ev.c8_parity_mismatches =
                    json_get_int(json_get(&p, "mismatches"));
        }
        json_free(&p);
    }

    /* C8 replay-canary watch. */
    ev.c8_canary_fail_active = canary_sentinel_watch_fail_active();
    {
        struct json_value cw = {0};
        if (canary_watch_dump_state_json(&cw, NULL)) {
            int64_t scans = json_get_int(json_get(&cw, "scans_total"));
            ev.c8_canary_present = scans > 0 || ev.c8_canary_fail_active;
        }
        json_free(&cw);
    }

    return mvp_build_status_json(&ev, out);
}
