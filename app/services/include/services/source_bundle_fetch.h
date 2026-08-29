/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Identity-free P2P retrieval of a ZVCS source bundle BY ITS CONTENT ROOT.
 *
 * The gap this closes. Every zcode.workspace.source.bundle.* leaf took a local
 * filesystem path, so "any machine can rebuild this exact tree" meant a human
 * copied a .zvsb around. The one networked route that already existed —
 * zcode.workspace.source.package.checkout — is the wrong SHAPE for this: it
 * additionally demands an accepted_work_root, re-resolves PROVEN authority and
 * derives a signer from the candidate, and publishing into it needs a
 * self-generated author key, a finalized ZID master and -packagehost=1. So the
 * identity-free path could not move over the wire, and the path that moved over
 * the wire was not identity-free. This module is the missing edge.
 *
 * ── The trust model, stated as a rule ─────────────────────────────────
 *
 *   You may make bytes easier to FIND. You may not make them easier to ACCEPT.
 *
 * FINDING is everything this module adds: peers advertise a source bundle's
 * tree root in the ordinary ROM directory listing (rom_seed_report.c), and the
 * search below picks candidates by matching that advertisement. Every part of
 * that is an untrusted peer claim and is treated as a hint.
 *
 * ACCEPTING is unchanged and unweakened. The caller's own 32-byte
 * `source_root` is the sole authority. Bytes become a result only by surviving
 * vcs_source_bundle_verify() against it — which re-reads the bundle header,
 * re-parses the canonical ZVCS manifest, recomputes the tree hash, and rehashes
 * EVERY blob. There is no signer, no signature, no acceptance chain, no
 * approved-verifier list, no operator name and no hardcoded host anywhere in
 * this path. A peer is never asked who it is and could not benefit from
 * answering.
 *
 * ── What a hostile peer can and cannot cause ──────────────────────────
 *
 * CAN: waste bounded time and bounded bytes, and be dropped for it.
 * CANNOT: make this function return bytes that do not rederive to
 * `source_root`; make it write anything to a path of the peer's choosing (this
 * function never touches the caller's output path at all — it returns a buffer
 * and lets the caller commit it); or make a wrong candidate outlast a right one
 * (a candidate that fails the root check is abandoned, its peers are scored,
 * and the search continues).
 *
 * The specific attack this is built to refuse is SUBSTITUTION, not corruption:
 * a WELL-FORMED bundle of a tree that differs by one byte, which verifies
 * perfectly under its OWN root, offered in reply to a request for the honest
 * root. Byte-flip corruption is caught far upstream by framing and per-chunk
 * digests and proves nothing about this layer. Substitution reaches the content
 * check and is refused there, with zero bytes materialized.
 *
 * ── The time bound ───────────────────────────────────────────────────
 *
 * SOURCE_BUNDLE_FETCH_BUDGET_MS bounds the whole call. It is consulted before
 * every peer connection and before every candidate download, never inside a
 * socket operation, so the true ceiling is the budget PLUS one peer's in-flight
 * work. That in-flight work is itself bounded by the transport: a connect is
 * capped by RF_CONNECT_TIMEOUT_MS (10 s), a directory or manifest read by
 * RF_MANIFEST_IO_TIMEOUT_SEC (15 s), and a bundle download by
 * SOURCE_BUNDLE_FETCH_MAX_CHUNKS chunk reads each capped by RF_IO_TIMEOUT_MS
 * (120 s) of silence — all in lib/net/src/rom_fetch_transport.c. Bytes are
 * bounded independently and much more tightly: no candidate over
 * VCS_SOURCE_BUNDLE_MAX_WIRE_BYTES is ever attempted, and at most
 * SOURCE_BUNDLE_FETCH_MAX_CANDIDATES candidates are tried. */

#ifndef ZCL_SERVICES_SOURCE_BUNDLE_FETCH_H
#define ZCL_SERVICES_SOURCE_BUNDLE_FETCH_H

#include "net/rom_fetch.h"
#include "vcs/source_bundle.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Peers consulted in one call. Bounds connections, and with the byte cap below
 * bounds the total cost of a swarm that is entirely hostile. */
#define SOURCE_BUNDLE_FETCH_MAX_PEERS 16u

/* Distinct artifacts (by chunk_root) downloaded before the search gives up.
 * Peers offering the SAME artifact are grouped and tried together as failover
 * for one candidate, so this counts genuinely different byte sequences claiming
 * the same source root — i.e. how many substitution attempts are absorbed. */
#define SOURCE_BUNDLE_FETCH_MAX_CANDIDATES 8u

/* ceil(VCS_SOURCE_BUNDLE_MAX_WIRE_BYTES / ROM_SEED_CHUNK_SIZE): the largest
 * chunk count any acceptable candidate can have, so the per-chunk digest table
 * is a fixed stack array rather than a wire-sized allocation. */
#define SOURCE_BUNDLE_FETCH_MAX_CHUNKS \
    ((uint32_t)((VCS_SOURCE_BUNDLE_MAX_WIRE_BYTES + ROM_SEED_CHUNK_SIZE - 1) / \
                ROM_SEED_CHUNK_SIZE))

/* Whole-call wall budget — see the block comment above for exactly what it
 * does and does not bound. Ten minutes is deliberately generous: this fleet
 * includes 7200 rpm boxes and Tor-only nodes, and a budget tuned to an SSD on
 * a fast link would grade an honest slow seeder as an attacker. */
#define SOURCE_BUNDLE_FETCH_BUDGET_MS 600000

enum source_bundle_fetch_result {
    SOURCE_BUNDLE_FETCH_OK = 0,
    SOURCE_BUNDLE_FETCH_ERR_ARGS,       /* null/empty/over-cap arguments      */
    SOURCE_BUNDLE_FETCH_ERR_NO_PEER,    /* nobody advertised this root        */
    SOURCE_BUNDLE_FETCH_ERR_TRANSPORT,  /* offered, but no candidate arrived  */
    SOURCE_BUNDLE_FETCH_ERR_ROOT,       /* arrived, and refused by the root   */
    SOURCE_BUNDLE_FETCH_ERR_STAGING,    /* local staging path unusable        */
    SOURCE_BUNDLE_FETCH_ERR_ALLOC,
    SOURCE_BUNDLE_FETCH_ERR_BUDGET,     /* budget spent before a candidate    */
};

struct source_bundle_fetch_metrics {
    uint32_t peers_asked;       /* peers a directory request was sent to      */
    uint32_t peers_offering;    /* peers that advertised the requested root   */
    uint32_t candidates_tried;  /* distinct artifacts downloaded              */
    uint32_t candidates_refused;/* downloaded, then refused by the root check */
    uint64_t wire_bytes;        /* size of the ACCEPTED bundle, 0 on refusal  */
    /* Why the LAST refused candidate was refused, straight from the content
     * check. Carried out so the operator sees "tree-root-mismatch" (a
     * substitution) as a different fact from "bundle-limit" (a truncation) or
     * "compression-codec" (garbage) — three attacks that must never collapse
     * into one message. VCS_SOURCE_BUNDLE_OK when nothing was refused. */
    enum vcs_source_bundle_result last_refusal;
    struct vcs_source_bundle_metrics bundle; /* only meaningful on OK         */
};

/* Search `peers` for a ZVCS source bundle carrying `source_root`, download it,
 * prove it against `source_root`, and hand the verified wire back in memory.
 *
 * `staging_dir` must be an existing directory the CALLER owns; the download's
 * .part, .part.journal and staged-complete files live and die there and are
 * unlinked before return on every path. This function NEVER writes to a final
 * output path — the caller commits the returned buffer, so a failure here
 * cannot leave a partially materialized result anywhere.
 *
 * On SOURCE_BUNDLE_FETCH_OK, *wire_out is a heap buffer of *wire_len_out bytes
 * that has already passed vcs_source_bundle_verify() against `source_root`, and
 * the caller owns it (free()). On every other result *wire_out is NULL and
 * *wire_len_out is 0. `metrics` is optional and is zeroed on entry. */
enum source_bundle_fetch_result source_bundle_fetch(
    const struct rom_fetch_peer *peers, size_t npeers,
    const uint8_t source_root[32], const char *staging_dir,
    uint8_t **wire_out, size_t *wire_len_out,
    struct source_bundle_fetch_metrics *metrics);

/* Stable human label for a result code. Never NULL. */
const char *source_bundle_fetch_result_string(
    enum source_bundle_fetch_result result);

#endif /* ZCL_SERVICES_SOURCE_BUNDLE_FETCH_H */
