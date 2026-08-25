/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The hardcoded clearnet file-service seed set — ONE shared list so
 * config/src/boot_bundle_fetch.c (bbf_assemble_seeds, the instant-on bundle
 * discovery/fetch path) and config/src/boot_services.c (the legacy
 * -allow-clearnet-snapshot-fetch probe loop) can never drift apart. Both
 * ports default to FS_PORT (net/file_service.h).
 *
 * THE LIST IS DELIBERATELY EMPTY. File-service seeds are supplied at RUNTIME
 * via -fileservice=HOST[:PORT] (handled by bbf_add_peer in
 * config/src/boot_bundle_fetch_seeds.c, which honours ctx->file_service_peer
 * as slot 0) or via -connect= hosts, so no operator endpoint is named in the
 * public source. Both callers loop over this array, so an empty list is a
 * zero-iteration loop and simply contributes no compiled seed.
 *
 * Why empty rather than "one harmless seed": the entry that used to sit here
 * was annotated as a third-party public seed "not operated by this project".
 * That annotation was wrong — it was an address of one of this project's own
 * boxes, and the annotation is exactly why an earlier pass that removed the
 * other operator endpoints left this one behind. A provenance claim nobody
 * can check from inside the repository is not a safeguard; an empty list is.
 *
 * Trust note: any such seed is unauthenticated (clearnet, no TLS, no
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
 * Do not add a seed IP without explicit owner review, and never add one this
 * project operates — this file is the single place that decision is
 * recorded. */

#ifndef ZCL_CONFIG_BUNDLE_FETCH_SEEDS_H
#define ZCL_CONFIG_BUNDLE_FETCH_SEEDS_H

/* NULL-terminated so callers loop `for (i = 0; arr[i]; i++)` with no
 * separate count constant to keep in sync. Empty by policy — see above. */
static const char *const ZCL_BUNDLE_FETCH_CLEARNET_SEEDS[] = {
    NULL,
};

#endif /* ZCL_CONFIG_BUNDLE_FETCH_SEEDS_H */
