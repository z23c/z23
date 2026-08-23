/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_bundle_fetch_seeds — the instant-on weld's file-service SEED SET.
 * Split out of config/src/boot_bundle_fetch.c: WHICH peers the weld is allowed
 * to contact is a policy decision with its own trust argument, separate from
 * the manifest/download machinery. See config/boot_bundle_fetch.h. */

#include "boot_bundle_fetch_seeds_internal.h"

#include "config/boot.h"                       /* struct app_context */
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

/* Append host[:port] to peers[] (default port FS_PORT). No-op when full or the
 * host does not fit rom_fetch_peer.addr. */
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
    if (!host[0] || strlen(host) >= sizeof(peers[0].addr))
        return;

    /* De-dup on (addr, port). */
    for (size_t i = 0; i < *np; i++)
        if (peers[i].port == port && strcmp(peers[i].addr, host) == 0)
            return;

    snprintf(peers[*np].addr, sizeof(peers[*np].addr), "%s", host);
    peers[*np].port = port;
    (*np)++;
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
    if (!bbf_names_a_port(host_port)) {
        bbf_add_peer(peers, np, cap, host_port);
        return true;
    }

    char host[128];
    snprintf(host, sizeof(host), "%s", host_port);
    char *colon = strrchr(host, ':');
    if (!colon || !colon[1])
        return false;
    char *end = NULL;
    long p = strtol(colon + 1, &end, 10);
    if (!end || *end != '\0' || p < 1 || p > 65535)
        return false;

    if (p == BBF_MAINNET_P2P_PORT) {
        *colon = '\0';
        if (!host[0])
            return false;
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
    return np;
}

size_t boot_bundle_fetch_seed_count(const struct app_context *ctx)
{
    struct rom_fetch_peer peers[ROM_FETCH_MAX_WORKERS];
    memset(peers, 0, sizeof(peers));
    return bbf_assemble_seeds(ctx, peers, sizeof(peers) / sizeof(peers[0]),
                              NULL);
}
