/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Blog controller — serves static HTML blog over Tor onion service.
 * Files served from {datadir}/blog/ directory.
 * Also handles ZSLP node registry for peer discovery. */

#ifndef ZCL_CONTROLLERS_BLOG_H
#define ZCL_CONTROLLERS_BLOG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "net/onion_discovery.h"

/* Serve an HTTP request for the blog.
 * path: URL path (e.g., "/", "/about", "/post/hello")
 * out: output buffer for HTTP response (headers + body)
 * out_len: size of output buffer
 * Returns bytes written, or 0 if path not found. */
size_t blog_serve(const char *datadir, const char *path,
                  char *out, size_t out_len);

/* ZSLP Node Registry — store/retrieve .onion addresses on-chain */

/* Build a ZSLP GENESIS tx for the ZCL23NODES token registry.
 * Returns the OP_RETURN script bytes. */
size_t blog_build_node_registry_genesis(uint8_t *out, size_t out_len);

/* Build a ZSLP SEND tx that announces an .onion address.
 * The onion hostname is stored in the token's metadata. */
size_t blog_build_node_announce(uint8_t *out, size_t out_len,
                                 const uint8_t token_id[32],
                                 const char *onion_hostname);

/* ── Onion peer discovery: TWO sources, merged, never narrowed ──────
 *
 * A directory record is a HINT ABOUT WHERE TO LOOK, never proof of who is
 * there (docs/work/NAT_AND_ONION_TRANSPORT.md). Both sources below only ADD
 * candidates; neither can exclude a peer, so the worst a poisoned record can
 * do is waste one connection attempt. */

/* SOURCE 1 — the on-chain node directory. Reads the onion_directory
 * projection, which contexts/naming/models/src/explorer_index_zdir.c folds from confirmed
 * ZDIR OP_RETURNs (zdir/zdir.h) during the ordinary block-index walk. Sees
 * every node's announcement regardless of what is in the local wallet.
 * Read-only, bounded, no network call, no clock read. Returns the count. */
int blog_discover_onion_peers_chain(const char *datadir,
                                    struct onion_peer *out, size_t max);

/* Both sources, chain first, merged and de-duplicated by onion_peers_collect
 * (net/onion_peer_merge.h) with every hostname held to onion_hostname_valid.
 * SOURCE 2 is the legacy wallet scrape — it reads db_wallet_tx_recent_raw(),
 * so it can only ever see transactions already in the LOCAL WALLET table.
 * It is deliberately still wired: it is the only source on a node whose
 * datadir predates the onion_directory table, and peer discovery is
 * liveness-critical. Returns the count of discovered addresses. */
int blog_discover_onion_peers(const char *datadir,
                               struct onion_peer *out, size_t max);

/* Per-source contribution of the LAST blog_discover_onion_peers() pass:
 * rows the chain projection produced, rows the wallet scrape produced, and
 * malformed hostnames the merge dropped. Diagnostic only — nothing branches
 * on it. It is the evidence that lets the wallet scrape be retired later
 * (a measured zero contribution) rather than deleted on a design argument.
 * Any out pointer may be NULL. */
void blog_onion_discovery_counts(int *out_chain, int *out_wallet,
                                 int *out_rejected);

/* Auto-announce .onion address on-chain via ZSLP SEND.
 * Returns true if a new announcement was created.
 * Returns false if already published or on error. */
bool blog_auto_announce_onion(const char *datadir, const char *onion_address);

#endif
