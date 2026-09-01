/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * One place decides whether a node status reason means an operator has to
 * intervene, and one place holds the operator-facing status/summary wording
 * for that reason.
 *
 * THE POLICY IS THE TABLE: controllers/operator_needed_policy.def. Read it to
 * see, or change, what any reason means. Do not re-derive `operator_needed`
 * inline at a call site — that is exactly the duplication this replaced, and
 * check-operator-needed-single fails `make lint` on a new inline ladder.
 *
 * USAGE at an operator surface:
 *   1. Write the if/else-if chain over YOUR OWN snapshot type and assign a
 *      `enum node_status_reason`. The chain order and the conditions belong
 *      to the surface, because surfaces read different snapshots and can
 *      observe different signals.
 *   2. Never select a reason whose signal you cannot observe, and never pass
 *      a literal to switch a rung off. A surface that cannot see, say,
 *      catch-up stall simply has no CATCHUP_STALLED branch.
 *   3. Read `status`, `summary`, and `operator_needed` back through the three
 *      accessors below. Surface-specific fields (a REST next_endpoint versus a
 *      native next command, a dynamic primary-blocker id) stay at the call
 *      site — those genuinely differ per surface. */

#ifndef ZCL_CONTROLLERS_OPERATOR_NEEDED_POLICY_H
#define ZCL_CONTROLLERS_OPERATOR_NEEDED_POLICY_H

#include <stdbool.h>
#include <stdint.h>

enum node_status_reason {
#define ZCL_STATUS_REASON(suffix, status_str, summary_str, need) \
    ZCL_STATUS_REASON_##suffix,
#include "controllers/operator_needed_policy.def"
#undef ZCL_STATUS_REASON
    ZCL_STATUS_REASON__COUNT
};

/* True when this reason means an operator has to intervene.
 *
 * `warning_count` is the surface's own named-warning count. It is a REQUIRED
 * input, not an optional one: the HEALTHCHECK_UNHEALTHY reason is actionable
 * only when at least one warning was named. Pass the real count. Passing a
 * constant here would put the decision back at the call site.
 *
 * An out-of-range reason returns true — an unknown state is an operator
 * problem, never a silent green. */
bool node_status_reason_operator_needed(enum node_status_reason reason,
                                        int64_t warning_count);

/* The coarse operator-facing status word ("healthy", "catching_up",
 * "degraded", "blocked"). Never NULL; an out-of-range reason yields
 * "degraded". */
const char *node_status_reason_status(enum node_status_reason reason);

/* The one-line operator-facing explanation. Never NULL; an out-of-range
 * reason yields a plainly-wrong-state sentence rather than an empty string. */
const char *node_status_reason_summary(enum node_status_reason reason);

/* The reason's enum suffix as text ("NO_PEERS", "CHAIN_GAP_DOWNLOADING", ...).
 * For tests and diagnostics; a surface's published `primary_blocker` string is
 * its own, because some rungs publish a dynamic blocking-reason there instead.
 * Never NULL. */
const char *node_status_reason_name(enum node_status_reason reason);

#endif /* ZCL_CONTROLLERS_OPERATOR_NEEDED_POLICY_H */
