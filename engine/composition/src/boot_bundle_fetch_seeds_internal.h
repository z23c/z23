/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Internal seam between engine/composition/src/boot_bundle_fetch.c (the weld) and
 * engine/composition/src/boot_bundle_fetch_seeds.c (which peers the weld may contact).
 * The public entry point boot_bundle_fetch_seed_count() is declared in
 * config/boot_bundle_fetch.h; these two are module-internal. */

#ifndef ZCL_CONFIG_BOOT_BUNDLE_FETCH_SEEDS_INTERNAL_H
#define ZCL_CONFIG_BOOT_BUNDLE_FETCH_SEEDS_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct app_context;
struct rom_fetch_peer;

/* Append host[:port] to peers[] (default port FS_PORT), de-duped on
 * (addr, port). No-op when the array is full or the host does not fit. */
void bbf_add_peer(struct rom_fetch_peer *peers, size_t *np, size_t cap,
                  const char *host_port);

/* Append `host` at an EXPLICIT port, de-duped on (addr, port). The shared core
 * of bbf_add_peer, split out because a peer-discovered seed must NOT run the
 * host[:port] text split: the port comes from the peer's `zfileaddr` message
 * and may differ from FS_PORT. Running the split over a bare IPv6 literal
 * would incorrectly read its last group as a port number. */
void bbf_add_peer_at_port(struct rom_fetch_peer *peers, size_t *np, size_t cap,
                          const char *host, uint16_t port);

/* Assemble the file-service seed set the weld is permitted to contact:
 *   1. the operator's -fileservice= peer, when given (slot 0);
 *   2. then EITHER the hardcoded clearnet file-service seeds, OR — when
 *      ctx->connect_only is set — the operator's own `-connect=` hosts at
 *      FS_PORT;
 *   3. then the operator's `-addnode=` hosts;
 *   4. LAST: peers this node already completed a P2P handshake with that
 *      advertised `zfileaddr`, via the provider registered with
 *      boot_bundle_fetch_set_peer_source(). Lowest precedence on purpose — a
 *      source that needs no operator input must never displace one the
 *      operator named. Absent a registered provider this step is a no-op and
 *      the function behaves exactly as it did before the source existed.
 *
 * Why connect-only gets the -connect hosts rather than an EMPTY set: `-connect=`
 * means "reach ONLY these peers", not "reach nothing". Emptying the set turned
 * the instant-on weld structurally OFF for every connect-only boot — the
 * measured 2026-07-27 bare cold start passed `-connect=<peer>` and so never
 * contacted a single file-service seed, then reported the miss as
 * `fetch=no_seed`, indistinguishable from a genuine discovery miss. Reusing the
 * explicitly named peers honours the containment promise exactly: no compiled
 * seed, no gossiped address, nothing the operator did not name.
 *
 * The seeds are unauthenticated transport, which is fine here: every byte is
 * content-verified against the committed manifest and the install path binds the
 * result to the COMPILED checkpoint, so a hostile or forged seed can at worst
 * waste one bounded fetch or be refused at install — it can never seed accepted
 * state. Sets *out_explicit_first when the -fileservice peer took slot 0.
 * Returns the peer count. Pure: no IO, no network. */
size_t bbf_assemble_seeds(const struct app_context *ctx,
                          struct rom_fetch_peer *peers, size_t cap,
                          bool *out_explicit_first);

#endif /* ZCL_CONFIG_BOOT_BUNDLE_FETCH_SEEDS_INTERNAL_H */
