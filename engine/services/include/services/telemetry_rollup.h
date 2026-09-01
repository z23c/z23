/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The whole-node telemetry rollup: the fold across every registered domain
 * that backs `ops.telemetry.summary`, `ops.telemetry.health` and
 * `ops.telemetry.alerts.active`.
 *
 * WHY THIS RUNS INSIDE THE NODE. Most telemetry collectors read subsystems
 * that only exist in a running node's process; a one-shot CLI invocation has
 * no app_init(), so calling them there does not merely return zeroes — the
 * sync collector reaches chain_params_get() and aborts on its assertion. Every
 * node-scoped domain controller therefore renders inside the node and is
 * reached over the SELECT-only `dumpstate` RPC, and the rollup, which collects
 * ALL of them, has the same constraint by definition. Its CLI handlers are one
 * round trip each.
 *
 * NO SECOND EVALUATOR AND NO DOMAIN LIST. Domains come from the provider
 * registry (services/telemetry_providers.h), which is pasted from
 * util/telemetry_domains.def, so a ninth domain joins the rollup without this
 * file being edited and cannot be omitted from it. Verdicts come from
 * telemetry_evaluate() — the same evaluator, over the same field tables, that
 * produces the `health` block inside each per-domain leaf. This file only
 * folds them with max() over the ordered health enum, so the rollup can never
 * disagree with the leaf it points at.
 */
#ifndef ZCL_SERVICES_TELEMETRY_ROLLUP_H
#define ZCL_SERVICES_TELEMETRY_ROLLUP_H

#include <stdbool.h>

/* See CLAUDE.md "Adding state introspection". Reentrant-safe.
 *
 * `key` selects the projection, and an unrecognized key is reported in the
 * body as `key_unrecognized` rather than guessed at:
 *   "summary" | NULL  the fold, the named bottleneck, and one compact row per
 *                     domain
 *   "health"          the fold and the per-domain rows, without the totals
 *   "alerts_active"   the failing rules themselves, bounded, with the number
 *                     dropped stated explicitly
 */
struct json_value;
bool telemetry_rollup_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_SERVICES_TELEMETRY_ROLLUP_H */
