/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Alert routing — threshold rules on EV_* events with log + webhook
 * dispatch.  Seeded with 4 rules: disk_low, peer_bans_high,
 * rpc_ratelimit_spike, chain_tip_rejected.
 *
 * Architecture:
 *   - Each rule watches a single event_type and counts occurrences
 *     within a rolling window (default 300s).
 *   - When the count crosses a threshold, the rule fires once and
 *     enters a cooldown period (default 600s) to suppress repeats.
 *   - Fired alerts dispatch to all configured sinks:
 *       * log:     fprintf(stderr, ...) — always on
 *       * webhook: HTTP POST via fork+curl to ZCL_ALERT_WEBHOOK_URL
 *
 * Env vars:
 *   ZCL_ALERT_WEBHOOK_URL — if set, POST JSON payloads to this URL
 *   ZCL_ALERTS_DISABLE    — set to "1" to disable all alerting
 */

#ifndef ZCL_ALERTS_H
#define ZCL_ALERTS_H

#include "event/event.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ALERT_MAX_RULES     16
#define ALERT_NAME_LEN      32
#define ALERT_WEBHOOK_LEN   512
#define ALERT_OPERATOR_NEEDED_DETAIL_LEN (EVENT_PAYLOAD_SIZE + 1)

struct alert_rule {
    char             name[ALERT_NAME_LEN];
    enum event_type  trigger;       /* which EV_* to watch */
    int              threshold;     /* fire when count >= this in window */
    int              window_sec;    /* rolling window in seconds */
    int              cooldown_sec;  /* min seconds between firings */
    bool             enabled;
};

/* Initialize the alert subsystem.  Installs event observers for all
 * enabled rules.  Reads ZCL_ALERT_WEBHOOK_URL.  Idempotent. */
void alerts_init(void);

/* Shut down: uninstall observers, clear state. */
void alerts_shutdown(void);

/* Add a custom rule at runtime.  Returns false if the table is full
 * or the rule name is a duplicate. */
bool alerts_add_rule(const struct alert_rule *rule);

/* Query: number of times a rule has fired since init. */
uint64_t alerts_fire_count(const char *rule_name);

/* Query: total rules registered. */
size_t alerts_rule_count(void);

/* Reset all counters and state (for tests). */
void alerts_reset(void);

/* True iff EV_OPERATOR_NEEDED has fired and not yet been cleared (by an
 * EV_CONDITION_CLEARED for the underlying condition, or an explicit clear).
 * This is the "a halt can never be silent" signal — the health surface reads
 * it to report DEGRADED / operator_needed. `detail_out` (optional) receives
 * the latched event payload; `since_unix_out` (optional) the first-fire time. */
bool alerts_operator_needed(char *detail_out, size_t detail_cap,
                            int64_t *since_unix_out);

/* Clear a stale chain-advance operator-needed latch once the caller has
 * independently proven the node is back at the served/log frontier. Returns
 * true only when it cleared an active chain-advance/local-recovery page. */
bool alerts_operator_needed_clear_if_chain_advance_recovered(
    bool frontier_recovered,
    char *detail_out,
    size_t detail_cap,
    int64_t *since_unix_out);

/* Clear the operator-needed latch. Called automatically on
 * EV_CONDITION_CLEARED; exposed for tests / manual operator ack. */
void alerts_operator_needed_clear(void);

/* Render a JSON summary of all rules + their fire counts.
 * Returns bytes written (excluding NUL). */
size_t alerts_report_json(char *buf, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_ALERTS_H */
