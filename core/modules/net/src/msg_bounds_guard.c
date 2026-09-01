/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* msg_bounds_guard.c — see net/msg_bounds_guard.h for the rationale.
 * One shared bound check + rejection log for the P2P message-count guards. */

#include "net/msg_bounds_guard.h"
#include <stdio.h>

bool msg_count_exceeds(const char *domain, const char *what,
                       uint64_t count, uint64_t max_count,
                       const char *peer)
{
    if (count <= max_count)
        return false;

    /* Diagnostic only: the caller pairs this with its terminal reject
     * (peer disconnect / buffer free / return false), so this logs and
     * continues rather than returning here. */
    fprintf(stderr,  // obs-ok:msg_bound_reject_paired_at_callsite
            "[%s] %s(): %s count %llu exceeds cap %llu%s%s\n",
            domain, __func__, what,
            (unsigned long long)count, (unsigned long long)max_count,
            peer ? " from " : "", peer ? peer : "");
    return true;
}
