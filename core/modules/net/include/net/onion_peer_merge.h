/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The v3 onion hostname rule and the two-source peer merge — the one
 * home for both, so no caller re-derives either.
 *
 * Peer discovery has two independent sources and one validity rule:
 *   - the SIGNED source (zdesc descriptors, registered from config/):
 *     entries carry a signature over a validity window and a monotonic
 *     seq, and it takes every slot the other source leaves;
 *   - the unsigned wallet scrape (blog_discover_onion_peers): still
 *     wired, because it is the only source on a node that has never
 *     seen a descriptor. Discovery is liveness-critical and its
 *     fallbacks are deliberate, so it is asked first — but into at most
 *     half the slate, so neither source can crowd the other out.
 * Both are run through the same unchanged hostname rule, and a service
 * advertising through both is merged once. */

#ifndef ZCL_NET_ONION_PEER_MERGE_H
#define ZCL_NET_ONION_PEER_MERGE_H

#include "net/onion_discovery.h"
#include <stdbool.h>
#include <stddef.h>

/* Hostnames reaching this layer are attacker-controlled (on-chain
 * OP_RETURN payloads, peer-served directory JSON). Only the exact Tor v3
 * shape — 56 base32 [a-z2-7] chars + ".onion", 62 bytes total — may reach
 * HTML, JSON, the peer_directory table, or a fetch. THE single definition
 * in the tree, shared by the directory server, the connman seed walker,
 * the zdir codec and the on-chain projection, so no two of them can ever
 * drift apart on what a hostname is. */
bool onion_hostname_valid(const char *h);

/* Fill out[0..max) from both sources, dropping malformed hostnames and
 * duplicates. Either source may be NULL (discover also needs a non-NULL
 * datadir). *rejected_out, when non-NULL, receives the count of MALFORMED
 * hostnames dropped — a duplicate is agreement between sources, not an
 * attack, and is not counted. Returns how many entries were kept. With no
 * signed source registered this is exactly the old single-source
 * behaviour.
 *
 * CAPACITY IS RESERVED, not first-come. The unsigned scrape is asked
 * FIRST and for at most max/2 entries; the signed source then takes every
 * slot still free. So a source that can produce `max` records cannot
 * consume the whole slate and leave the other uninvoked — starving a
 * source is the same outage as removing it, and this call is the one
 * place that can cause it — while an empty scrape (the usual state) still
 * leaves the WHOLE slate to the signed source. With max == 1 the single
 * slot goes to the scrape, the source that always works. */
int onion_peers_collect(struct onion_peer *out, size_t max,
                        onion_signed_peer_source_fn signed_source,
                        void *signed_ctx, onion_peer_discover_fn discover,
                        const char *datadir, int *rejected_out);

#endif
