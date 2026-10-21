/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * diagnostics_mvp.c — the "mvp" dumpstate subsystem (schema zcl.mvp_status.v1).
 *
 * Turns docs/quality/MVP.md's eight operator acceptance criteria (v1 = MRS 8/8) from a
 * human reading docs against the node into a typed, evidence-derived query:
 * `z23 ops state --subsystem=mvp`.
 *
 * HONESTY CONTRACT — this is a REPORTER, never a gate. It derives
 * met=true|false|unknown STRICTLY from durable/runtime evidence the node
 * already produces (node_health tip-hold, the soak attestation service, the
 * standing utxo_parity oracle, the replay-canary watch, and the C2 onion and
 * C7 crash-recovery receipt ledgers). It can flip nothing true on its own,
 * performs no consensus/state writes, and a criterion whose runtime evidence
 * source is absent is reported "unknown" with a NAMED reason — never silently
 * "met". Criteria 1/4/5 are proven only by offline operator make-targets
 * (install / shielded params / store buyer) with no runtime signal, so at
 * runtime they are honestly "unknown"; the value here is the enumeration + the
 * live signals that DO exist (sync_state/gap, soak healthy/eligible, parity
 * mismatches, canary latch, last receipt rows) plus the met_count math.
 *
 * The classifier mvp_build_status_json() is a PURE function over struct
 * mvp_evidence — the single place met/unmet/unknown is decided — so the unit
 * test seeds known evidence and asserts the classification directly, while the
 * live dumper mvp_dump_state_json() only gathers evidence then calls it. */

#include "controllers/diagnostics_internal.h"

#include "config/runtime.h"
#include "services/evidence_ledger_row.h"
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

/* A criterion's resolved state, blocker and reason. The reason pointer names
 * static text or a buffer inside the caller's struct mvp_evidence. */
struct mvp_verdict {
    enum mvp_met met;
    const char *blocker;
    const char *reason;
};

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

static bool mvp_c8_qualified(const struct mvp_evidence *ev)
{
    return ev->c8_canary_present && ev->c8_genesis_pass &&
        ev->c8_genesis_fresh && ev->c8_running_identity_match &&
        ev->c8_live_coarse_match && ev->c8_full_window_qualified;
}

static const char *mvp_c8_missing_reason(const struct mvp_evidence *ev)
{
    if (!ev->c8_canary_present || !ev->c8_genesis_pass)
        return "current from=genesis replay-canary PASS not supplied";
    if (!ev->c8_genesis_fresh)
        return "replay-canary PASS freshness within 7 days not qualified";
    if (!ev->c8_running_identity_match)
        return "replay-canary PASS not bound to running source and artifact";
    if (!ev->c8_live_coarse_match)
        return "current live coarse parity match not supplied";
    if (!ev->c8_full_window_qualified)
        return "identity-bound zero-mismatch 168h parity coverage not supplied";
    return "fresh exact genesis PASS, live coarse match and qualified 168h "
           "zero-mismatch parity coverage";
}

static const char *mvp_c8_oracle_gap(const struct mvp_evidence *ev)
{
    if (ev->c8_parity_present)
        return "standing parity oracle mismatch count unavailable; "
               "zero-mismatch coverage is unqualified";
    return "replay-canary not failing, but no standing parity oracle "
           "for the 0-mismatch-over-soak claim";
}

/* ── receipt ledgers: C2 onion bootstrap, C7 kill-9 recovery ─────────────
 * Each producer appends one flat JSON object per run to a JSONL ledger. The
 * LAST VALID row is the current evidence. Valid means: the expected schema, a
 * PASS|FAIL|SKIP verdict, and a complete line — the shared reader drops torn
 * tails. A missing or unreadable ledger is data, not an error, and leaves the
 * criterion UNKNOWN with its default reason. */

#define MVP_RECEIPT_TAIL_BYTES 65536
#define MVP_RECEIPT_FILE "receipts.jsonl"
#define MVP_ONION_SCHEMA "zcl.onion_bootstrap_receipt.v1"
#define MVP_CRASH_SCHEMA "zcl.crash_recovery_receipt.v1"
#define MVP_C2_OPERATOR_SOURCE "operator make-target (make mvp-onion-local)"
#define MVP_C7_OPERATOR_SOURCE "recovery-drill timing (make test-crash-bootstrap)"
#define MVP_C2_UNKNOWN_REASON \
    "onion <60s bootstrap timing is not durably recorded at runtime"
#define MVP_C7_UNKNOWN_REASON \
    "recovery-drill timing not recorded at runtime; " \
    "make test-crash-bootstrap is the operator proof"

struct mvp_receipt_ledger {
    const char *dir_env;
    const char *home_rel;
    const char *schema;
    const char *ms_key;
};

static const struct mvp_receipt_ledger g_onion_ledger = {
    "ZCL_ONION_RECEIPT_DIR", ".local/state/z23/onion-bootstrap",
    MVP_ONION_SCHEMA, "bootstrap_ms",
};

static const struct mvp_receipt_ledger g_crash_ledger = {
    "ZCL_CRASH_RECEIPT_DIR", ".local/state/z23/crash-recovery",
    MVP_CRASH_SCHEMA, "recover_ms",
};

/* The last valid row a scan has seen for one ledger. */
struct mvp_receipt_last {
    const struct mvp_receipt_ledger *lg;
    bool present;                           /* a valid row was found */
    int verdict;                            /* enum mvp_receipt_verdict */
    int64_t ms;                             /* bootstrap_ms or recover_ms; -1 when null */
    char path[MVP_RECEIPT_PATH_MAX];
    char utc[MVP_RECEIPT_UTC_MAX];
    char reason[MVP_RECEIPT_REASON_MAX];    /* the row's own reason text */
};

static int mvp_receipt_verdict_parse(const char *text)
{
    if (strcmp(text, "PASS") == 0) return MVP_RECEIPT_PASS;
    if (strcmp(text, "FAIL") == 0) return MVP_RECEIPT_FAIL;
    if (strcmp(text, "SKIP") == 0) return MVP_RECEIPT_SKIP;
    return MVP_RECEIPT_NONE;
}

static void mvp_receipt_scan_row(const char *row, size_t len, void *ctx)
{
    struct mvp_receipt_last *last = ctx;
    char text[MVP_RECEIPT_REASON_MAX];
    if (!evidence_row_flat_object_valid(row, len) ||
        !evidence_row_str(row, len, "schema", text, sizeof(text)) ||
        strcmp(text, last->lg->schema) != 0)
        return;
    if (!evidence_row_str(row, len, "verdict", text, sizeof(text)))
        return;
    int verdict = mvp_receipt_verdict_parse(text);
    if (verdict == MVP_RECEIPT_NONE)
        return;

    int64_t ms = -1;
    if (!evidence_row_int(row, len, last->lg->ms_key, &ms) || ms < 0)
        ms = -1;   /* JSON null or absent: not measured, never zero */
    last->present = true;
    last->verdict = verdict;
    last->ms = ms;
    /* evidence_row_str clears its destination first, so a later row without
     * these fields cannot inherit an earlier row's text. */
    (void)evidence_row_str(row, len, "utc", last->utc, sizeof(last->utc));
    (void)evidence_row_str(row, len, "reason", last->reason,
                           sizeof(last->reason));
}

static bool mvp_receipt_read(const struct mvp_receipt_ledger *lg,
                             struct mvp_receipt_last *last)
{
    memset(last, 0, sizeof(*last));
    last->lg = lg;
    last->ms = -1;
    if (!evidence_ledger_resolve_path(lg->dir_env, lg->home_rel,
                                      MVP_RECEIPT_FILE, last->path,
                                      sizeof(last->path)))
        return false;
    return evidence_ledger_scan_tail(last->path, MVP_RECEIPT_TAIL_BYTES,
                                     mvp_receipt_scan_row, last, NULL, NULL);
}

static void mvp_copy_text(char *dst, size_t cap, const char *src)
{
    evidence_copy_bounded(dst, cap, src, strlen(src));
}

static void mvp_c2_apply(struct mvp_evidence *ev,
                         const struct mvp_receipt_last *r)
{
    if (!r->present)
        return;
    ev->c2_verdict = r->verdict;
    ev->c2_bootstrap_ms = r->ms;
    mvp_copy_text(ev->c2_source, sizeof(ev->c2_source), r->path);
    mvp_copy_text(ev->c2_utc, sizeof(ev->c2_utc), r->utc);
    if (r->verdict == MVP_RECEIPT_SKIP) {
        snprintf(ev->c2_reason, sizeof(ev->c2_reason),
                 "onion bootstrap receipt verdict SKIP: %s",
                 r->reason[0] ? r->reason : "no reason recorded");
    } else if (r->verdict == MVP_RECEIPT_PASS && r->ms < 0) {
        mvp_copy_text(ev->c2_reason, sizeof(ev->c2_reason),
                      "onion bootstrap receipt has no bootstrap_ms (not measured)");
    }
}

static void mvp_c7_apply(struct mvp_evidence *ev,
                         const struct mvp_receipt_last *r)
{
    if (!r->present)
        return;
    ev->c7_verdict = r->verdict;
    mvp_copy_text(ev->c7_source, sizeof(ev->c7_source), r->path);
    mvp_copy_text(ev->c7_utc, sizeof(ev->c7_utc), r->utc);
    ev->c7_recovery_drill_present =
        r->ms >= 0 && r->verdict != MVP_RECEIPT_SKIP;
    if (r->ms >= 0) {
        /* Whole seconds, floored: floor(ms / 1000) < 120 exactly when ms < 120000. */
        ev->c7_recovery_secs = r->ms / 1000;
    }
    if (r->verdict == MVP_RECEIPT_SKIP) {
        snprintf(ev->c7_reason, sizeof(ev->c7_reason),
                 "kill-9 recovery drill verdict SKIP: %s",
                 r->reason[0] ? r->reason : "no reason recorded");
    } else if (r->verdict == MVP_RECEIPT_PASS && r->ms < 0) {
        mvp_copy_text(ev->c7_reason, sizeof(ev->c7_reason),
                      "kill-9 recovery receipt has no recover_ms (not measured)");
    }
}

/* Fill the C2 and C7 receipt fields of `ev` from the last valid row of each
 * ledger. Both ledgers absent leaves ev unchanged. */
static void mvp_receipt_evidence_read(struct mvp_evidence *ev)
{
    struct mvp_receipt_last onion;
    struct mvp_receipt_last crash;
    /* A missing or unreadable ledger is no evidence, not a failure. */
    (void)mvp_receipt_read(&g_onion_ledger, &onion);
    (void)mvp_receipt_read(&g_crash_ledger, &crash);
    mvp_c2_apply(ev, &onion);
    mvp_c7_apply(ev, &crash);
}

/* Legacy timing receipts establish an observed run, not qualification of the
 * current release. Neither producer binds source and artifact; the recovery
 * receipt also lacks the literal mid-block plus peer-tip acceptance scope. */
static struct mvp_verdict mvp_legacy_pass(bool onion)
{
    return (struct mvp_verdict){MVP_UNKNOWN, NULL, onion
        ? "observed onion bootstrap receipt PASS within the 60s budget; "
          "current source/artifact qualification unavailable"
        : "observed kill-9 recovery drill PASS within the 2min budget; "
          "current source/artifact and mid-block peer-tip qualification unavailable"};
}

/* Timing failures remain UNMET. Legacy PASS under budget remains UNKNOWN. */
static struct mvp_verdict mvp_c2_verdict(const struct mvp_evidence *ev)
{
    struct mvp_verdict v = {MVP_UNKNOWN, NULL,
        ev->c2_reason[0] ? ev->c2_reason : MVP_C2_UNKNOWN_REASON};
    if (ev->c2_verdict == MVP_RECEIPT_FAIL) {
        v.met = MVP_UNMET;
        v.blocker = ev->c2_bootstrap_ms >= MVP_ONION_BOOTSTRAP_MS_MAX
            ? "onion.too_slow" : "onion.failed";
        v.reason = "onion bootstrap receipt verdict FAIL";
    } else if (ev->c2_verdict == MVP_RECEIPT_PASS &&
               ev->c2_bootstrap_ms >= 0) {
        if (ev->c2_bootstrap_ms < MVP_ONION_BOOTSTRAP_MS_MAX) {
            v = mvp_legacy_pass(true);
        } else {
            v.met = MVP_UNMET;
            v.blocker = "onion.too_slow";
            v.reason = "onion bootstrap receipt exceeded the 60s budget";
        }
    }
    return v;
}

/* A drill flag alone cannot establish even an observed PASS verdict. */
static struct mvp_verdict mvp_c7_verdict(const struct mvp_evidence *ev)
{
    struct mvp_verdict v = {MVP_UNKNOWN, NULL,
        ev->c7_reason[0] ? ev->c7_reason : MVP_C7_UNKNOWN_REASON};
    if (ev->c7_verdict == MVP_RECEIPT_FAIL) {
        v.met = MVP_UNMET;
        v.blocker = "recovery.failed";
        v.reason = "kill-9 recovery drill verdict FAIL";
    } else if (ev->c7_verdict != MVP_RECEIPT_PASS ||
               !ev->c7_recovery_drill_present) {
        return v;
    } else if (ev->c7_recovery_secs >= 0 &&
               ev->c7_recovery_secs < MVP_RECOVERY_SECS_MAX) {
        v = mvp_legacy_pass(false);
    } else {
        v.met = MVP_UNMET;
        v.blocker = "recovery.too_slow";
        v.reason = "kill-9 recovery drill exceeded the 2min budget";
    }
    return v;
}

bool mvp_build_status_json(const struct mvp_evidence *ev, struct json_value *out)
{
    if (!out)
        LOG_FAIL("mvp", "null out");
    static const struct mvp_evidence zero = {0};
    if (!ev) ev = &zero;

    json_set_object(out);
    json_push_kv_str(out, "schema", "zcl.mvp_status.v1");
    json_push_kv_str(out, "qualification_policy", MVP_QUALIFICATION_POLICY);
    json_push_kv_str(out, "doc", "docs/quality/MVP.md");
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
     * Evidence = the last valid zcl.onion_bootstrap_receipt.v1 row. With no
     * ledger the criterion stays unknown and names the operator proof. */
    {
        struct json_value e = {0};
        bool seen = ev->c2_verdict != MVP_RECEIPT_NONE;
        mvp_evidence_begin(&e, seen ? ev->c2_source : MVP_C2_OPERATOR_SOURCE,
                           seen);
        json_push_kv_str(&e, "utc", ev->c2_utc);
        json_push_kv_int(&e, "bootstrap_ms", ev->c2_bootstrap_ms);
        json_push_kv_int(&e, "bootstrap_ms_max", MVP_ONION_BOOTSTRAP_MS_MAX);
        struct mvp_verdict v = mvp_c2_verdict(ev);
        mvp_push_criterion(&arr, "C2", "Tor onion bootstrap in <60s", v.met, 0,
                           v.blocker, v.reason, &e);
        json_free(&e);
        if (v.met == MVP_MET) met_count++;
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
     * Local ticks, elapsed hours and an optional SLO probe are partial
     * observations. They cannot establish the sovereign, exact-parity,
     * workload-bound 168h claim. A caller must also supply a retained MET
     * result from the full soak-evidence-report judge. Runtime does not
     * currently track that result, so C6 stays unknown with a named reason. */
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
        json_push_kv_bool(&e, "full_judge_met", ev->c6_full_judge_met);
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
            static const enum mvp_met verdict[2] = {MVP_UNKNOWN, MVP_MET};
            static const char *const explanation[2] = {
                "full C6 soak-evidence-report MET verdict not supplied; "
                "local healthy ticks cannot qualify the 168h window",
                "168h+ clean, healthy, eligible soak window with full judge MET",
            };
            st = verdict[ev->c6_full_judge_met];
            reason = explanation[ev->c6_full_judge_met];
        }
        mvp_push_criterion(&arr, "C6",
            "7-day soak with zero operator intervention", st, since, blocker,
            reason, &e);
        json_free(&e);
        if (st == MVP_MET) met_count++;
    }

    /* ── C7: recover from kill -9 in <2 min ──────────────────────────
     * Evidence = the last valid zcl.crash_recovery_receipt.v1 row. With no
     * ledger the criterion stays unknown and names the operator proof. */
    {
        struct json_value e = {0};
        bool seen = ev->c7_verdict != MVP_RECEIPT_NONE;
        mvp_evidence_begin(&e, seen ? ev->c7_source : MVP_C7_OPERATOR_SOURCE,
                           seen);
        json_push_kv_str(&e, "utc", ev->c7_utc);
        json_push_kv_bool(&e, "recovery_drill_present",
                          ev->c7_recovery_drill_present);
        json_push_kv_int(&e, "recovery_secs", ev->c7_recovery_secs);
        json_push_kv_int(&e, "recovery_secs_max", MVP_RECOVERY_SECS_MAX);
        struct mvp_verdict v = mvp_c7_verdict(ev);
        mvp_push_criterion(&arr, "C7", "Recover from kill -9 in <2 min", v.met,
                           0, v.blocker, v.reason, &e);
        json_free(&e);
        if (v.met == MVP_MET) met_count++;
    }

    /* C8 counter observations and a quiet canary latch are supporting facts.
     * Positive qualification additionally requires exact, fresh genesis proof
     * and retained coverage of the complete parity window. */
    {
        struct json_value e = {0};
        mvp_evidence_begin(&e,
            "utxo_parity oracle + replay-canary watch", true);
        json_push_kv_bool(&e, "parity_oracle_present", ev->c8_parity_present);
        json_push_kv_int(&e, "parity_mismatches", ev->c8_parity_mismatches);
        json_push_kv_bool(&e, "canary_present", ev->c8_canary_present);
        json_push_kv_bool(&e, "canary_fail_active", ev->c8_canary_fail_active);
        json_push_kv_bool(&e, "genesis_pass", ev->c8_genesis_pass);
        json_push_kv_bool(&e, "genesis_fresh", ev->c8_genesis_fresh);
        json_push_kv_bool(&e, "running_identity_match",
                          ev->c8_running_identity_match);
        json_push_kv_bool(&e, "live_coarse_match", ev->c8_live_coarse_match);
        json_push_kv_bool(&e, "full_window_qualified",
                          ev->c8_full_window_qualified);
        json_push_kv_int(&e, "window_hours_required",
                         MVP_SOAK_WINDOW_HOURS_REQUIRED);

        enum mvp_met st;
        const char *blocker = NULL;
        const char *reason;
        if (ev->c8_canary_fail_active) {
            st = MVP_UNMET;
            blocker = "consensus.replay_canary_failed";
            reason = "a replay-canary kind is latched FAIL";
        } else if (ev->c8_parity_present && ev->c8_parity_mismatches > 0) {
            st = MVP_UNMET;
            blocker = "consensus.utxo_drift";
            reason = "utxo_parity oracle detected mismatches";
        } else if (ev->c8_parity_present && ev->c8_parity_mismatches == 0) {
            static const enum mvp_met verdict[2] = {MVP_UNKNOWN, MVP_MET};
            st = verdict[mvp_c8_qualified(ev)];
            reason = mvp_c8_missing_reason(ev);
        } else if (!ev->c8_parity_present && !ev->c8_canary_present) {
            st = MVP_UNKNOWN;
            reason = "no zclassicd parity oracle resolved and no replay-canary "
                     "verdict present";
        } else {
            st = MVP_UNKNOWN;
            reason = mvp_c8_oracle_gap(ev);
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
    ev.c2_bootstrap_ms = -1;
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

    /* C2 onion and C7 crash-recovery receipt ledgers (last valid row each). */
    mvp_receipt_evidence_read(&ev);

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

    /* Watch slots retain history after sentinel deletion; scans and a quiet
     * latch therefore cannot establish current genesis PASS or freshness.
     * Parity counters carry no retained, identity-bound 168h coverage.
     * Positive qualification flags remain false until those producers exist. */

    return mvp_build_status_json(&ev, out);
}
