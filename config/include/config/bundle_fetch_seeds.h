/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The hardcoded clearnet file-service seed set — ONE shared list so
 * config/src/boot_bundle_fetch.c (bbf_assemble_seeds, the instant-on bundle
 * discovery/fetch path) and config/src/boot_services.c (the legacy
 * -allow-clearnet-snapshot-fetch probe loop) can never drift apart. Both
 * ports default to FS_PORT (net/file_service.h).
 *
 * This project's OWN file-service seeds are deliberately NOT committed here:
 * they are passed at RUNTIME via -fileservice=HOST[:PORT] (handled by
 * bbf_add_peer in config/src/boot_bundle_fetch_seeds.c, which honours
 * ctx->file_service_peer as slot 0) or via -connect= hosts, so operator
 * endpoints stay local-only and are never named in the public source. The
 * single compiled seed below is a pre-existing third-party public seed not
 * operated by this project.
 *
 * Trust note: these seeds are unauthenticated (clearnet, no TLS, no
 * ZClassic state commitment) — an unreachable, hostile, or simply
 * operator-unknown seed can only waste a fetch attempt, never forge
 * accepted state. Every byte served through either caller is content-
 * verified against a committed manifest (per-chunk or whole-file SHA3)
 * before landing, and the sovereign install path independently re-checks
 * transparent/shielded state against the compiled checkpoint — a seed's
 * identity is not part of the trust boundary. See
 * docs/CONSENSUS_PARITY_DOCTRINE.md's "validate against the CHAIN, not the
 * reference text" doctrine for the same shape of reasoning applied to
 * content instead of network identity.
 *
 * Do not add a new seed IP without explicit owner review — this file is the
 * single place that decision is recorded. */

#ifndef ZCL_CONFIG_BUNDLE_FETCH_SEEDS_H
#define ZCL_CONFIG_BUNDLE_FETCH_SEEDS_H

/* NULL-terminated so callers loop `for (i = 0; arr[i]; i++)` with no
 * separate count constant to keep in sync. */
static const char *const ZCL_BUNDLE_FETCH_CLEARNET_SEEDS[] = {
    "140.174.189.3",
    NULL,
};

#endif /* ZCL_CONFIG_BUNDLE_FETCH_SEEDS_H */
