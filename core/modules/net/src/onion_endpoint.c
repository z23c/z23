/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The rich endpoint type that sits alongside struct onion_peer, and the
 * narrowing adapter between them. See net/onion_discovery.h for what a
 * record is (a hint about where to look) and what it is not (proof of
 * who is there).
 *
 * The hostname rule is NOT re-implemented here: onion_hostname_valid()
 * in net/onion_peer_merge.h is the one copy core/modules/net owns, and every
 * source goes through it regardless of provenance. */

#include "net/onion_discovery.h"

#include "net/onion_peer_merge.h"

#include "base/log_macros.h"

#include <stdio.h>
#include <string.h>

#define OEP_LOG "net.endpoint"

const char *onion_peer_provenance_string(enum onion_peer_provenance p)
{
    switch (p) {
    case ONION_PROV_UNSIGNED: return "unsigned";
    case ONION_PROV_SIGNED:   return "signed";
    case ONION_PROV_ANCHORED: return "anchored";
    }
    return "unknown";
}

static bool onion_endpoint_any_address(const struct onion_endpoint *ep)
{
    if (ep->hostname[0] != '\0')
        return true;
    for (size_t i = 0; i < sizeof(ep->ipv4); i++)
        if (ep->ipv4[i])
            return true;
    for (size_t i = 0; i < sizeof(ep->ipv6); i++)
        if (ep->ipv6[i])
            return true;
    return false;
}

bool onion_endpoint_live(const struct onion_endpoint *ep, uint64_t now_unix)
{
    if (!ep)
        LOG_FAIL(OEP_LOG, "live: NULL endpoint");
    if (!onion_endpoint_any_address(ep))
        LOG_FAIL(OEP_LOG,
                 "live: endpoint names no address at all — nothing to try");
    /* expiry 0 means "no signed window" (an unsigned source). A signed
     * record always carries one, and it is the ONLY freshness rule
     * there is: no heartbeat, no global refresh clock. */
    if (ep->expiry != 0 && now_unix >= ep->expiry)
        LOG_FAIL(OEP_LOG,
                 "live: record expired (now %llu >= expiry %llu)",
                 (unsigned long long)now_unix,
                 (unsigned long long)ep->expiry);
    return true;
}

bool onion_endpoint_to_peer(const struct onion_endpoint *ep,
                            struct onion_peer *out)
{
    if (!ep || !out)
        LOG_FAIL(OEP_LOG, "to_peer: NULL argument (ep=%p out=%p)",
                 (const void *)ep, (void *)out);
    if (!onion_hostname_valid(ep->hostname))
        LOG_FAIL(OEP_LOG,
                 "to_peer: endpoint carries no valid v3 onion hostname");
    memset(out, 0, sizeof(*out));
    snprintf(out->hostname, sizeof(out->hostname), "%s", ep->hostname);
    out->height = ep->height;
    return true;
}

int onion_endpoints_to_peers(const struct onion_endpoint *eps, int n,
                             struct onion_peer *out, size_t max,
                             uint64_t now_unix, int *rejected_out)
{
    if (rejected_out)
        *rejected_out = 0;
    if (!eps || !out || max == 0 || n <= 0)
        return 0;

    int kept = 0;
    int rejected = 0;
    for (int i = 0; i < n && (size_t)kept < max; i++) {
        const struct onion_endpoint *ep = &eps[i];
        /* A clearnet-only record is a legitimate record that this
         * narrow path simply cannot carry — not a rejection. */
        if (ep->hostname[0] == '\0')
            continue;
        if (!onion_endpoint_live(ep, now_unix) ||
            !onion_endpoint_to_peer(ep, &out[kept])) {
            rejected++;
            continue;
        }
        kept++;
    }
    if (rejected_out)
        *rejected_out = rejected;
    return kept;
}
