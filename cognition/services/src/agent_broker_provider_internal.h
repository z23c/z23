/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * PRIVATE to agent_broker_provider.c + agent_broker_catalog_seam.c. The two
 * files are one composition root split only so each stays readable: the first
 * owns configuration, binding and the live authority decision; the second owns
 * the property surface (the real catalog projection and the named refusals for
 * everything this seam cannot execute).
 *
 * The context below has STATIC LIFETIME in agent_broker_provider.c. That is a
 * requirement, not a convenience: agent_broker_provider_install() borrows the
 * provider pointer and every session's authority reference borrows the context
 * pointer, so a stack-local of either shape would dangle the moment the
 * composing frame returned.
 */

#ifndef ZCL_SERVICES_AGENT_BROKER_PROVIDER_INTERNAL_H
#define ZCL_SERVICES_AGENT_BROKER_PROVIDER_INTERNAL_H

#include "services/property_grant_service.h"
#include "session/agent_broker.h"

#include <stdbool.h>
#include <stddef.h>

#define BROKER_PROVIDER_PATH_MAX 480

/* Configuration copied out of argv at compose time. NON-SECRET BY
 * CONSTRUCTION: a datadir path, an operator-chosen grant id, and a path to a
 * grant specification. Nothing here is loaded, opened or minted until bind
 * runs, which is after the confined child has been forked. */
struct broker_provider_ctx {
    char datadir[BROKER_PROVIDER_PATH_MAX];
    char grant_id[METAVERSE_GRANT_ID_LEN + 1];
    char grant_spec[BROKER_PROVIDER_PATH_MAX];

    /* Filled at BIND, after the fork. */
    char bound_grant_id[METAVERSE_GRANT_ID_LEN + 1];
    char principal[METAVERSE_PRINCIPAL_MAX + 1];
    char source[32];                 /* "grant-id" | "grant-spec" | ""      */
    char refusal[192];
    struct agent_money_binding money[AGENT_MONEY_BINDINGS_MAX];
    size_t money_count;
    bool composed;
    bool bound;
};

/* The node-ops half (agent_broker_catalog_seam.c). */
struct agent_broker_node_ops broker_provider_ops(void *ctx);

/* Load a bounded grant specification from `path` and MINT it through
 * property_grant_service_mint(). Called only from bind, i.e. only after the
 * confined child exists. Writes the minted canonical id into `out_id` and the
 * refusal reason into `why` on failure. */
bool broker_provider_mint_from_spec(const char *path, char *out_id,
                                    size_t out_id_cap, char *why,
                                    size_t why_cap);

bool broker_provider_money_from_spec(
    const char *path, struct agent_money_binding *out, size_t max,
    size_t *count, char *why, size_t why_cap);

#endif /* ZCL_SERVICES_AGENT_BROKER_PROVIDER_INTERNAL_H */
