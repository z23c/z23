/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Shared MVP evidence classification and qualification snapshot validation. */
#ifndef ZCL_MVP_STATUS_H
#define ZCL_MVP_STATUS_H
#include <stdbool.h>
#include <limits.h>
struct json_value;
#define MVP_QUALIFICATION_POLICY "zcl.mvp_qualification.v1"
/* ── MVP v1 scoreboard (diagnostics_mvp.c) ──────────────────────────
 *
 * The "mvp" g_dumpers[] entry (schema zcl.mvp_status.v1): docs/quality/MVP.md's eight
 * operator acceptance criteria as a typed, evidence-derived query surfaced via
 * `ops state --subsystem=mvp`. REPORTER ONLY — it derives met=true|false|
 * unknown strictly from durable/runtime evidence the node already produces
 * (node_health tip-hold, the soak attestation service, the utxo_parity oracle,
 * the replay-canary watch), flips nothing true on its own, and reports any
 * criterion whose runtime evidence source is absent as "unknown" with a NAMED
 * reason (never silently "met"). */

#define MVP_CRITERIA_TOTAL 8
#define MVP_SOAK_WINDOW_HOURS_REQUIRED 168 /* the 7-day (168h) clean window */
#define MVP_RECOVERY_SECS_MAX 120          /* kill-9 budget (2 min): MET strictly below */
#define MVP_SLO_SUCCESS_MIN 0.999          /* SLO floor when a probe is present */
#define MVP_ONION_BOOTSTRAP_MS_MAX 60000   /* onion bootstrap budget (60 s) */
#define MVP_RECEIPT_PATH_MAX PATH_MAX       /* receipt ledger path buffer */
#define MVP_RECEIPT_UTC_MAX 40
#define MVP_RECEIPT_REASON_MAX 192

/* Verdict of the last valid receipt row (C2 and C7 ledgers). */
enum mvp_receipt_verdict {
    MVP_RECEIPT_NONE = 0,   /* no valid row: the criterion stays UNKNOWN */
    MVP_RECEIPT_PASS,
    MVP_RECEIPT_FAIL,
    MVP_RECEIPT_SKIP,
};

/* Raw evidence inputs, one bundle for all eight criteria. The live dumper
 * fills this from existing sources; the unit test seeds it directly.
 * mvp_build_status_json() is the SINGLE place met/unmet/unknown is decided. */
struct mvp_evidence {
    /* C2 — onion bootstrap: last valid zcl.onion_bootstrap_receipt.v1 row. */
    int       c2_verdict;                          /* observed enum mvp_receipt_verdict; legacy PASS is not release qualification */
    long long c2_bootstrap_ms;                     /* -1 when not measured */
    char      c2_source[MVP_RECEIPT_PATH_MAX];     /* ledger path of that row */
    char      c2_utc[MVP_RECEIPT_UTC_MAX];
    char      c2_reason[MVP_RECEIPT_REASON_MAX];   /* SKIP or unmeasured PASS */

    /* C7 — kill-9 recovery: last valid zcl.crash_recovery_receipt.v1 row. */
    int       c7_verdict;                          /* observed enum mvp_receipt_verdict; drill flag alone proves no verdict */
    char      c7_source[MVP_RECEIPT_PATH_MAX];
    char      c7_utc[MVP_RECEIPT_UTC_MAX];
    char      c7_reason[MVP_RECEIPT_REASON_MAX];   /* SKIP or unmeasured PASS */

    /* C3 — cold-start sync to tip: live tip-hold + sync-benchmark receipt. */
    bool      c3_health_present;                  /* node_health snapshot taken */
    int       c3_sync_state;                      /* enum sync_state */
    int       c3_log_head_gap;
    bool      c3_sync_benchmark_receipt_present;  /* pending source: false */
    long long c3_cold_sync_secs;                  /* -1 when unknown */

    /* C6 — 7-day soak. */
    bool      c6_soak_present;                    /* soak service initialized */
    bool      c6_soak_last_healthy;
    bool      c6_soak_window_eligible;
    long long c6_soak_window_hours;               /* -1 when not tracked */
    bool      c6_full_judge_met;                  /* retained full C6 judge MET, never inferred from ticks */
    bool      c6_slo_probe_present;               /* external SLO surface? */
    double    c6_slo_success_rate;                /* 0..1, <0 when unknown */

    /* C7 — kill-9 recovery. */
    bool      c7_recovery_drill_present;
    long long c7_recovery_secs;                   /* -1 when unknown */

    /* C8 — consensus parity. */
    bool      c8_parity_present;                  /* standing oracle, checks>0 */
    long long c8_parity_mismatches;               /* -1 when unknown */
    bool      c8_canary_present;
    bool      c8_canary_fail_active;
    /* Positive qualification requires current genesis PASS, <=7d age,
     * matching running source/artifact identities, a live coarse match,
     * and retained identity-bound zero-mismatch coverage for 168h.
     * Live producers for these positive claims are not wired here. */
    bool      c8_genesis_pass;
    bool      c8_genesis_fresh;
    bool      c8_running_identity_match;
    bool      c8_live_coarse_match;
    bool      c8_full_window_qualified;
};

/* Pure classifier: build schema zcl.mvp_status.v1 into `out` (set to a fresh
 * object) from `ev` (NULL treated as all-absent). Deterministic, no I/O — the
 * test seeds `ev` and asserts. Returns false only on a NULL `out`. */
bool mvp_build_status_json(const struct mvp_evidence *ev,
                           struct json_value *out);

/* The "mvp" g_dumpers[] entry. Gathers live evidence from the running node,
 * then calls mvp_build_status_json. Reentrant-safe; NULL-safe on an
 * uninitialized node. */
bool mvp_dump_state_json(struct json_value *out, const char *key);
struct mvp_qualification {
    bool available;
    int met_count;
    int state[MVP_CRITERIA_TOTAL]; /* -1 unknown, 0 unmet, 1 met */
};
/* Policy identifies semantics, not proof authenticity. Invalid input resets all
 * states to unknown and the count to zero. */
bool mvp_status_read_qualification(const struct json_value *status,
                                   struct mvp_qualification *out);
#endif
