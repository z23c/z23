/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The composition root for the confined-agent broker: where the REAL property
 * catalog and the REAL property grant service are joined to the broker's
 * provider seam (session/agent_broker.h).
 *
 * WHY IT LIVES HERE AND NOT IN cognition/modules/session. lib/ sits below app/services, so
 * the broker cannot name property_catalog_show() or the property grant service
 * at all. It declares a seam and refuses to serve when nothing fills it. This
 * file is the one place that knows both sides.
 *
 * ── THE ORDERING CONTRACT, WHICH IS A SECURITY PROPERTY ──────────────────
 * agent_broker_provider_compose() is called from engine/entry/main.c IMMEDIATELY BEFORE
 * agent_broker_mode_main(), which is to say BEFORE the confined child is
 * forked. A forked child inherits a copy-on-write image of everything the
 * parent holds at fork time, so anything secret that exists here would exist
 * in the child's address space.
 *
 * Compose therefore does exactly two things: it copies non-secret, immutable
 * configuration out of argv (a datadir path, a grant id or a grant spec path)
 * into static storage, and it installs static function pointers. It loads no
 * grant, mints nothing, draws no key, opens no datadir and reads no file. The
 * authority appears later, at `bind`, which the broker calls after the fork.
 *
 * ── PROVISIONING IS EXPLICIT ─────────────────────────────────────────────
 * Registering the provider grants NOTHING. Without `--grant-id=` or
 * `--grant-spec=` the provider refuses to bind and the broker serves nothing
 * but named refusals. There is no default grant, because a default grant is an
 * authority nobody issued.
 *
 * ── WHAT THIS SEAM CAN AND CANNOT DO ─────────────────────────────────────
 * It can answer INSPECT_PROPERTY out of the real property catalog, under a
 * live canonical grant decision. It CANNOT execute HOST, SELL, BUY, TRANSFER
 * or any other property effect, because nothing in this tree executes them:
 * property_grant_service_commit() authorizes, debits and seals a receipt, and
 * that is the whole of what it does. Those verbs are therefore refused by name
 * (MVAP_ERR_ACTION_EXECUTOR_UNAVAILABLE) and mint no receipt of any kind. A
 * successful-looking mutation that moved nothing is the worst answer available
 * here, strictly worse than an explicit refusal.
 */

#ifndef ZCL_SERVICES_AGENT_BROKER_PROVIDER_H
#define ZCL_SERVICES_AGENT_BROKER_PROVIDER_H

#include <stdbool.h>
#include <stddef.h>

/* Install the real provider. Inert and non-secret; see the ordering contract
 * above. Safe to call more than once (it overwrites the static configuration
 * and re-installs the same static provider object). */
void agent_broker_provider_compose(int argc, char **argv);

/* TEST SUPPORT: compose from explicit values instead of argv, so a test can
 * drive the production provider without building a command line. Same
 * inertness contract — nothing is loaded here. `grant_id` and `grant_spec` are
 * mutually exclusive; passing both is a refusal at bind time, not here.
 * Passing NULL/"" for both is the UNGRANTED configuration, which is exactly
 * what a caller proving fail-closed wants. */
void agent_broker_provider_compose_explicit(const char *datadir,
                                            const char *grant_id,
                                            const char *grant_spec);

/* The reason the last bind refused, or "" when the last bind succeeded or
 * none has run. Exposed so a test can assert the refusal is NAMED rather than
 * merely present. */
const char *agent_broker_provider_last_refusal(void);

#endif /* ZCL_SERVICES_AGENT_BROKER_PROVIDER_H */
