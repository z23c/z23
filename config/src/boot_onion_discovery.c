/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The config/-side implementation of lib/net's signed discovery port
 * (net/onion_discovery.h onion_signed_peer_source_fn). lib/net is
 * ranked below lib/vcs in config/lib_module_order.def and may not
 * include it, so the dependency is inverted here — the same shape
 * net_runtime_port.h and node_db_runtime.h use.
 *
 * THREE SOURCES, ALL ADDITIVE. Peer discovery is liveness-critical, so
 * every source ADDS candidates and none may remove, filter, or rank
 * down what another found:
 *
 *   1. signed endpoint records (zid/zendp.h "ZIDE",
 *      vcs/zendp_swarm.h) — signature over a validity window, a
 *      monotonic seq, AND a signing key resolved to an ACTIVE on-chain
 *      anchor. The strongest provenance that exists;
 *   2. signed onion-service descriptors (vcs/zdesc_swarm.h) —
 *      signature and window, verified against a caller-supplied key,
 *      NOT chain-bound;
 *   3. the unsigned wallet scrape, passed through to the onion service
 *      unchanged — the only source on a node that has never seen a
 *      signed document.
 *
 * CAPACITY IS RESERVED, NOT RACED. Sources 1 and 2 share this one
 * registered function and together may fill at most HALF of the
 * caller's capacity: a flood of signed records must not be able to
 * squeeze the unsigned scrape off the slate, because a record is a hint
 * about where to look and the scrape is sometimes the only source there
 * is. Within that half, endpoint records go first (chain-bound beats
 * key-bound) and descriptors fill what is left.
 *
 * A RECORD IS A HINT. Even a chain-anchored record does not prove who
 * answers at the address; that needs the Noise v2 transport, default
 * OFF today. Nothing here narrows peer selection, and nothing here may
 * grow into something that does. */

#include "config/boot_onion_discovery.h"

#include "config/boot_endpoint_records.h"

#include "platform/time_compat.h"
#include "vcs/zdesc_swarm.h"

#include <stdio.h>
#include <string.h>

#define BOOT_SIGNED_PEERS_MAX 32u

static int boot_signed_onion_peers(void *unused_ctx, struct onion_peer *out,
                                   size_t max)
{
    (void)unused_ctx;
    if (!out || max == 0)
        return 0;
    if (max > BOOT_SIGNED_PEERS_MAX)
        max = BOOT_SIGNED_PEERS_MAX;

    /* Half the slate, rounded down, is the ceiling for every signed
     * source combined. With max == 1 that is 0 and the unsigned scrape
     * keeps the only slot — deliberately: discovery must degrade toward
     * the source that always works. */
    size_t budget = max / 2u;
    if (budget == 0)
        return 0;

    /* Chain-anchored endpoint records first. */
    int n = boot_endpoint_record_peers(NULL, out, budget);
    if (n < 0)
        n = 0;
    if ((size_t)n >= budget)
        return n;

    /* Then signed descriptors, into whatever the records left. */
    size_t room = budget - (size_t)n;
    char hosts[BOOT_SIGNED_PEERS_MAX][ZDESC_ONION_LEN + 1];
    if (room > BOOT_SIGNED_PEERS_MAX)
        room = BOOT_SIGNED_PEERS_MAX;
    size_t d = zdesc_global_onions((uint64_t)platform_time_wall_unix(), hosts,
                                   room);
    for (size_t i = 0; i < d; i++) {
        memcpy(out[n].hostname, hosts[i], sizeof(hosts[i]));
        /* A descriptor carries no height; both consumers treat this as
         * display/storage only. */
        out[n].height = 0;
        n++;
    }
    return n;
}

void boot_onion_discovery_register(onion_blog_serve_fn blog_serve,
                                   onion_peer_discover_fn peer_discover,
                                   const char *datadir)
{
    /* Close the chain binding before anything can accept a record: with
     * no lookup registered, vcs/zendp_swarm refuses every record by
     * name (ZENDP_ERR_NO_ANCHOR_LOOKUP) rather than trusting one. */
    boot_endpoint_records_register();

    /* Then load what the operator has already accepted, re-verifying
     * each record against the chain as it goes. On the BOOT THREAD, once
     * — the discovery projection below runs on the shared supervisor
     * tick runner, where a blocking node.db read is exactly the hazard
     * that has had this node killed by its own watchdog. */
    (void)boot_endpoint_records_load(datadir);

    /* The load decides each record's chain verdict ONCE. This is what
     * keeps deciding it: a supervised worker on its OWN thread that
     * re-asks the chain whenever the fold reports an identity status
     * change, so a key revoked while the node stays up stops being
     * offered to peer discovery without waiting for the record's signed
     * expiry or a restart. Its own thread, not the tick runner, for the
     * same reason the load is boot-only. */
    boot_endpoint_records_start_revalidation();

    onion_service_set_app_handlers(blog_serve, peer_discover);
    /* Additive: signed sources are asked first, the unsigned scrape
     * still fills the remaining capacity. */
    onion_service_set_signed_peer_source(boot_signed_onion_peers, NULL);
}
