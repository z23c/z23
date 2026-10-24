/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The gamelink latency probe: ping, pong, and the three numbers a fleet
 * operator needs before anyone tries to fly against anyone.
 *
 * The round trip is measured with ONE clock. A ping carries the sender's own
 * send time; the peer echoes those eight bytes back untouched; the sender
 * subtracts. Nothing here compares two machines' clocks, so nothing here can
 * be wrong because two machines disagree about the time — and because the
 * clock is injected, a test asserts an exact microsecond count instead of a
 * tolerance nobody can justify.
 *
 * Jitter is RFC 3550's exponentially weighted |delta| and lives in
 * gamelink_session.c beside the sample that feeds it. Loss is counted on the
 * receive side from sequence gaps, which is the only place it is visible:
 * a sender cannot see what did not arrive.
 *
 * The vitals half writes what it measured into the owner's private fleet
 * ledger, so a latency number becomes a row like every other fleet fact
 * rather than a line that scrolled past in a terminal.
 */

#include "gamelink_internal.h"

#include "fleetledger/fleet_ledger.h"

#include <stdio.h>
#include <string.h>

size_t gamelink_probe_serve(struct gamelink *echo)
{
    /* gamelink_poll already answers pings; this is a name for that intent,
     * so an echo endpoint's loop reads as what it is. */
    return gamelink_poll(echo, NULL, NULL);
}

size_t gamelink_probe_run(struct gamelink *link, struct gamelink *echo,
                          size_t rounds, int64_t interval_ns)
{
    (void)interval_ns; /* the caller owns pacing: this module never sleeps */
    if (!link)
        return 0;
    uint64_t before = link->stats.pongs_recv;
    for (size_t i = 0; i < rounds; i++) {
        if (gamelink_ping(link) != GAMELINK_OK)
            break;
        if (echo)
            (void)gamelink_probe_serve(echo);
        (void)gamelink_poll(link, NULL, NULL);
    }
    return (size_t)(link->stats.pongs_recv - before);
}

