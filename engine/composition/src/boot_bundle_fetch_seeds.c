/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_bundle_fetch_seeds — the instant-on weld's file-service SEED SET.
 * Split out of engine/composition/src/boot_bundle_fetch.c: WHICH peers the weld is allowed
 * to contact is a policy decision with its own trust argument, separate from
 * the manifest/download machinery. See config/boot_bundle_fetch.h. */

#include "boot_bundle_fetch_seeds_internal.h"

#include "config/boot.h"                       /* struct app_context */
#include "config/boot_bundle_fetch.h"          /* peer-source seam types */
#include "config/bundle_fetch_seeds.h"         /* ZCL_BUNDLE_FETCH_CLEARNET_SEEDS */
#include "net/file_service.h"                  /* FS_PORT default */
#include "net/rom_fetch.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BBFS_SUBSYS "boot_bundle_fetch"

/* Mainnet nDefaultPort (core/chainparams/src/chainparams.c). The weld is
 * already mainnet-only. Operators write `-connect=peer:8033` because that is
 * the published P2P port; treating THAT one port as "the operator named a
 * host" is how a new node instant-on works. Any other named port stays
 * refused so 39xxx fixture sinks cannot be rewritten to FS_PORT. */
#define BBF_MAINNET_P2P_PORT 8033

/* Upper bound on endpoints one provider call may hand back in a single sweep.
 * The assembler's OWN bound, so a future provider cannot make it unbounded.
 * The seed array itself (ROM_FETCH_MAX_WORKERS) still binds how many land. */
#define BBF_PEER_SOURCE_MAX 16

/* The registered peer-endpoint provider. Process-global, like the rest of the
 * boot seams; NULL (the default) means the assembler behaves exactly as it did
 * before this source existed. */
static boot_bundle_peer_source_fn g_peer_source = NULL;
static void *g_peer_source_ctx = NULL;

void boot_bundle_fetch_set_peer_source(boot_bundle_peer_source_fn fn, void *ctx)
{
    g_peer_source = fn;
    g_peer_source_ctx = fn ? ctx : NULL;
}

/* Append host[:port] to peers[] (default port FS_PORT). No-op when full or the
 * host does not fit rom_fetch_peer.addr. */
void bbf_add_peer_at_port(struct rom_fetch_peer *peers, size_t *np, size_t cap,
                          const char *host, uint16_t port)
{
    if (!peers || !np || *np >= cap || !host || !host[0] || port == 0)
        return;
    if (strlen(host) >= sizeof(peers[0].addr))
        return;

    /* De-dup on (addr, port). */
    for (size_t i = 0; i < *np; i++)
        if (peers[i].port == port && strcmp(peers[i].addr, host) == 0)
            return;

    snprintf(peers[*np].addr, sizeof(peers[*np].addr), "%s", host);
    peers[*np].port = port;
    (*np)++;
}

void bbf_add_peer(struct rom_fetch_peer *peers, size_t *np, size_t cap,
                  const char *host_port)
{
    if (!peers || !np || *np >= cap || !host_port || !host_port[0])
        return;

    char host[128];
    snprintf(host, sizeof(host), "%s", host_port);
    uint16_t port = FS_PORT;

    /* A trailing ":<port>" overrides FS_PORT (operator/test convenience). Split
     * on the LAST ':' only when the suffix is a pure decimal port. */
    char *colon = strrchr(host, ':');
    if (colon && colon[1]) {
        char *end = NULL;
        long p = strtol(colon + 1, &end, 10);
        if (end && *end == '\0' && p >= 1 && p <= 65535) {
            port = (uint16_t)p;
            *colon = '\0';
        }
    }
    bbf_add_peer_at_port(peers, np, cap, host, port);
}

/* Does this value NAME a port? Same split rule as bbf_add_peer (LAST ':' + a
 * pure decimal 1..65535 suffix), so the two agree on what a port is. */
static bool bbf_names_a_port(const char *host_port)
{
    if (!host_port || !host_port[0])
        return false;
    const char *colon = strrchr(host_port, ':');
    if (!colon || !colon[1])
        return false;
    char *end = NULL;
    long p = strtol(colon + 1, &end, 10);
    return end && *end == '\0' && p >= 1 && p <= 65535;
}

/* True if `host` is already in the seed set under ANY port. An explicit
 * `-fileservice=HOST:PORT` names the exact file-service address the operator
 * wants; an auto-derived `-connect`/`-addnode` seed for the same host must not
 * shadow it with a different (often wrong) port. */
static bool bbf_host_already_seeded(const struct rom_fetch_peer *peers,
                                    size_t np, const char *host)
{
    for (size_t i = 0; i < np; i++)
        if (strcmp(peers[i].addr, host) == 0)
            return true;
    return false;
}

/* Derive a file-service seed from ONE `-connect=` value.
 *
 * `-connect` means the peer the operator named. This used to strip ANY port
 * and refill FS_PORT, so `-connect=127.0.0.1:39099` — a deliberately DEAD
 * fixture sink — was contacted as 127.0.0.1:18034, the operator's LIVE file
 * service. On 2026-07-28 that pulled ~1 GB of mainnet chain state into a
 * sealed regtest datadir. A dead sink whose deadness lives in a NON-DEFAULT
 * port is not a dead sink if that port is discarded.
 *
 * Rule:
 *   - no port: seed file-service at HOST:FS_PORT (the operator named a host)
 *   - port == mainnet P2P 8033: same — that is the published `-connect=peer:8033`
 *     new-node command, not a fixture sink
 *   - any other port: REFUSE. Pass `-fileservice=HOST[:PORT]` to name a
 *     file-service seed on a specific port.
 * Refusing a custom port is the safe direction for fixtures. Returns false
 * when refused. */
static bool bbf_add_connect_seed(struct rom_fetch_peer *peers, size_t *np,
                                 size_t cap, const char *host_port)
{
    if (!host_port || !host_port[0])
        return false;

    /* Extract the host once so we can check for an explicit -fileservice seed
     * on the same host before adding an auto-derived port. */
    char host[128];
    snprintf(host, sizeof(host), "%s", host_port);
    char *host_colon = strrchr(host, ':');
    if (host_colon) {
        char *end = NULL;
        long p = strtol(host_colon + 1, &end, 10);
        if (end && *end == '\0' && p >= 1 && p <= 65535)
            *host_colon = '\0';
    }
    if (!host[0] || strlen(host) >= sizeof(peers[0].addr))
        return false;

    if (bbf_host_already_seeded(peers, *np, host)) {
        LOG_INFO(BBFS_SUBSYS,
                 "-connect/-addnode=%s skipped as file-service seed: host %s "
                 "already named explicitly via -fileservice",
                 host_port, host);
        return false;
    }

    if (!bbf_names_a_port(host_port)) {
        bbf_add_peer(peers, np, cap, host_port);
        return true;
    }

    const char *port_colon = strrchr(host_port, ':');
    if (!port_colon || !port_colon[1])
        return false;
    char *end = NULL;
    long p = strtol(port_colon + 1, &end, 10);
    if (!end || *end != '\0' || p < 1 || p > 65535)
        return false;

    if (p == BBF_MAINNET_P2P_PORT) {
        LOG_INFO(BBFS_SUBSYS,
                 "-connect=%s names the default mainnet P2P port — seeding "
                 "file-service at %s:%u (pass -fileservice=HOST[:PORT] to "
                 "override)",
                 host_port, host, (unsigned)FS_PORT);
        bbf_add_peer(peers, np, cap, host);
        return true;
    }

    LOG_WARN(BBFS_SUBSYS,
             "-connect=%s names a non-default PORT, so it is NOT usable as a "
             "file-service seed: contacting that host on the file service's "
             "own port would be a different address than the one you named. "
             "Refusing to substitute a port. Pass -fileservice=HOST[:PORT] "
             "to name a file-service seed explicitly.",
             host_port);
    return false;
}

size_t bbf_assemble_seeds(const struct app_context *ctx,
                          struct rom_fetch_peer *peers, size_t cap,
                          bool *out_explicit_first)
{
    size_t np = 0;
    if (out_explicit_first)
        *out_explicit_first = false;

    if (ctx && ctx->file_service_peer && ctx->file_service_peer[0]) {
        bbf_add_peer(peers, &np, cap, ctx->file_service_peer);
        if (out_explicit_first && np == 1)
            *out_explicit_first = true; /* the explicit peer took slot 0 */
    }

    if (ctx && ctx->connect_only) {
        for (int i = 0; i < ctx->n_connect_peers; i++)
            (void)bbf_add_connect_seed(peers, &np, cap, ctx->connect_peers[i]);
    } else {
        for (int i = 0; ZCL_BUNDLE_FETCH_CLEARNET_SEEDS[i]; i++)
            bbf_add_peer(peers, &np, cap, ZCL_BUNDLE_FETCH_CLEARNET_SEEDS[i]);
    }

    /* Operator -addnode peers are also usable as file-service snapshot seeds:
     * the operator already named the peer for P2P, so treating it as a seed
     * does not expand the trust boundary. This lets z23 nodes help each other
     * bootstrap without forcing connect-only mode. */
    if (ctx) {
        for (int i = 0; i < ctx->n_addnode_peers; i++)
            (void)bbf_add_connect_seed(peers, &np, cap, ctx->addnode_peers[i]);
    }

    /* LAST, lowest precedence: peers that told US, over the existing zfileaddr
     * P2P advertisement, where their file service listens — cached in the
     * file_services table and handed here by the registered provider
     * (engine/composition/src/boot_bundle_fetch_peer_seeds.c). This is the only source
     * that needs no operator input at all, which is exactly why it must not
     * outrank a source the operator DID name: every earlier source keeps its
     * slot, and the discovery quorum still prefers the explicit -fileservice
     * candidate.
     *
     * The "did it advertise?" filter lives HERE rather than in the provider so
     * "advertised ⇒ offered, did not advertise ⇒ not offered" is one pure,
     * directly testable decision. A peer that advertised and then does not
     * serve costs one bounded discovery attempt (<= RF_CONNECT_TIMEOUT_MS +
     * the directory recv window, ~25 s worst case; see the stall bound note in
     * core/modules/net/src/rom_fetch.c) and is then DROPPED — bbf_discover_from_peers
     * `continue`s past it and, per struct bbf_discovery.live, it never enters
     * the per-chunk download rotation.
     *
     * The peer's OWN advertised port is used verbatim; FS_PORT is never
     * substituted. Seeders legitimately listen elsewhere (18034 and 18035 seen
     * on one live node's peer set), and dialing a port the peer did not name
     * is a guess, not a discovery.
     *
     * Offering an address grants it nothing: the bytes it serves ride the
     * identical transport-MAC + per-chunk SHA3 + whole-file SHA3 path an
     * operator-named seed rides, and the install still binds to the compiled
     * checkpoint. */
    if (g_peer_source) {
        struct boot_bundle_peer_seed found[BBF_PEER_SOURCE_MAX];
        memset(found, 0, sizeof(found));
        size_t n = g_peer_source(g_peer_source_ctx, found,
                                 sizeof(found) / sizeof(found[0]));
        if (n > sizeof(found) / sizeof(found[0]))
            n = sizeof(found) / sizeof(found[0]);
        for (size_t i = 0; i < n; i++) {
            if (found[i].port == 0)
                continue; /* peer never advertised a file service */
            bbf_add_peer_at_port(peers, &np, cap, found[i].host,
                                 found[i].port);
        }
    }
    return np;
}

size_t boot_bundle_fetch_seed_count(const struct app_context *ctx)
{
    struct rom_fetch_peer peers[ROM_FETCH_MAX_WORKERS];
    memset(peers, 0, sizeof(peers));
    return bbf_assemble_seeds(ctx, peers, sizeof(peers) / sizeof(peers[0]),
                              NULL);
}
