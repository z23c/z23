/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The v3 onion hostname rule and the two-source peer merge.
 * See net/onion_peer_merge.h. */

#include "net/onion_peer_merge.h"

#include <string.h>

bool onion_hostname_valid(const char *h)
{
    if (!h) return false;
    if (strlen(h) != 62 || strcmp(h + 56, ".onion") != 0) return false;
    for (size_t i = 0; i < 56; i++) {
        char c = h[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '2' && c <= '7')))
            return false;
    }
    return true;
}

/* Already in out[0..kept)? Sources are independent and a service may
 * advertise through both, so the merge must be idempotent. */
static bool onion_peer_seen(const struct onion_peer *out, int kept,
                            const char *hostname)
{
    for (int i = 0; i < kept; i++)
        if (strcmp(out[i].hostname, hostname) == 0)
            return true;
    return false;
}

/* Compact out[from..from+found) into out[kept..], dropping malformed
 * hostnames and duplicates. */
static int onion_peers_merge(struct onion_peer *out, int kept, int from,
                             int found, int *rejected)
{
    for (int i = from; i < from + found; i++) {
        if (!onion_hostname_valid(out[i].hostname)) {
            (*rejected)++;
            continue;
        }
        if (onion_peer_seen(out, kept, out[i].hostname))
            continue;
        if (kept != i)
            out[kept] = out[i];
        kept++;
    }
    return kept;
}

/* Clamp a source's claimed count to the space actually offered. */
static int onion_clamp(int found, size_t room)
{
    if (found < 0)
        return 0;
    return ((size_t)found > room) ? (int)room : found;
}

int onion_peers_collect(struct onion_peer *out, size_t max,
                        onion_signed_peer_source_fn signed_source,
                        void *signed_ctx, onion_peer_discover_fn discover,
                        const char *datadir, int *rejected_out)
{
    if (rejected_out)
        *rejected_out = 0;
    if (!out || max == 0)
        return 0;

    int kept = 0;
    int rejected = 0;
    const bool have_unsigned = (discover && datadir);

    /* CAPACITY IS RESERVED, AND THE BOUNDED SOURCE GOES FIRST.
     *
     * The signed slot used to be handed the full `max` and run first. The
     * chain projection wired behind it returns up to 64 rows and connman
     * asks for exactly 64, so on any node with >= 64 registered rows the
     * unsigned scrape was never invoked at all — not outranked, never
     * called. Consuming all the capacity is the same outage as removing a
     * source, and this call is the one place that can cause it.
     *
     * The fix is an order, not a second pass. The unsigned scrape runs
     * FIRST into at most half the slate; the signed source then takes
     * everything still free. That gives both properties at once and costs
     * nothing in the common case:
     *   - the scrape can never be squeezed out (it goes first), and it can
     *     never squeeze the signed source out either (it is capped at
     *     half);
     *   - an empty wallet — the usual state — scrapes nothing, so the
     *     signed source still gets the WHOLE slate. Re-asking a stable
     *     source for the leftovers would not work: it returns the same
     *     prefix, which the merge then drops as duplicates.
     * Same rule, same reason, as the signed-source budget in
     * engine/composition/src/boot_onion_discovery.c.
     *
     * With max == 1 there is nothing to split, and the slot goes to the
     * source that always works. */
    size_t unsigned_budget = max;
    if (signed_source && max >= 2)
        unsigned_budget = max / 2u;

    if (have_unsigned && unsigned_budget > 0) {
        int found = onion_clamp(discover(datadir, out, unsigned_budget),
                                unsigned_budget);
        kept = onion_peers_merge(out, kept, 0, found, &rejected);
    }

    if (signed_source && (size_t)kept < max) {
        size_t room = max - (size_t)kept;
        int found = onion_clamp(signed_source(signed_ctx, out + kept, room),
                                room);
        kept = onion_peers_merge(out, kept, kept, found, &rejected);
    }

    if (rejected_out)
        *rejected_out = rejected;
    return kept;
}
