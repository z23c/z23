/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_bundle_fetch — THE WELD (instant-on install linchpin).
 *
 * On a fresh, stateless boot with NO local bundle and NO sovereign-install
 * marker, swarm-download the content-verified consensus-state checkpoint bundle
 * (chunk-SHA3-verified, net/rom_fetch.h) into <datadir>/bundles/ so the already
 * wired boot_autodetect_consensus_bundle (engine/composition/src/boot_auto_install_bundle.c)
 * installs it under its EXISTING fail-closed guards — the CHECKPOINT_ROM /
 * CHECKPOINT_CONTENT authority that binds the installed state to the compiled
 * get_sha3_utxo_checkpoint(). A fresh node then starts AT the checkpoint on full
 * validated UTXO/anchor/nullifier state and only folds the small remainder.
 *
 * This module downloads and verifies BYTES; it NEVER installs, activates, or
 * validates consensus state. The download is content-verified against a
 * committed manifest (per-chunk SHA3 when the seeder serves one, whole-file
 * SHA3 otherwise), and the install path is the SOLE sovereignty gate:
 *   - a byte-mismatch fails the content proof here → nothing lands → no install;
 *   - a landed-but-non-checkpoint artifact is REFUSED by the installer's
 *     CHECKPOINT_ROM authority (and marked <name>.failed → normal boot).
 * Neither guard is weakened by anything here.
 *
 * Default-on for a fresh datadir; opt out with -nofilesync or the environment
 * variable ZCL_NO_BUNDLE_FETCH=1. Best-effort + fail-open: an absent manifest
 * commitment, no reachable seeder, or a failed download leaves boot on its
 * unchanged path (P2P IBD / the operator bundle remain the fallback).
 */

#ifndef ZCL_CONFIG_BOOT_BUNDLE_FETCH_H
#define ZCL_CONFIG_BOOT_BUNDLE_FETCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct app_context;
struct rom_fetch_manifest;
struct rom_fetch_peer;

/* ── Peer-discovered seeds (no operator flag, no compiled host list) ──────
 *
 * PROBLEM this solves. Before this seam the seed set came from ONE of three
 * operator actions (-fileservice=, -connect=, -addnode=) plus a compiled
 * clearnet list that is DELIBERATELY EMPTY (config/bundle_fetch_seeds.h). A
 * stranger who runs the node with no flags assembles ZERO seeds, so the
 * instant-on fetch is never attempted and the node falls back to a
 * from-genesis IBD. Nothing was wrong with the fetch, and nothing was wrong
 * with the ADVERTISEMENT either — the seed set simply never CONSUMED what the
 * node already knew.
 *
 * WHAT ALREADY EXISTED (no new mechanism is introduced here). A node that runs
 * its file service tells every ZCL23 peer so, over the "zfileaddr" P2P
 * message, carrying its actual file-service PORT:
 *   send    core/modules/net/src/msg_version.c   (after the ZCL23 handshake)
 *   handle  core/modules/net/src/msgprocessor.c  handle_zfileaddr
 *   store   engine/composition/src/boot_msg_callbacks.c boot_save_file_service
 *           -> db_file_service_save, table file_services
 *           (ip[16], port, p2p_port, last_seen, is_zcl23)
 *   read    db_file_service_recent()  — whose own header comment already says
 *           "for download scheduling", a consumer that did not exist.
 * Live nodes really do advertise, and on DIFFERENT ports (18034 and 18035
 * observed on one node's peer set), which is exactly why this is a message
 * carrying a port and not a service bit.
 *
 * WHAT THIS ADDS. The missing consumer: those cached endpoints become an
 * ADDITIONAL, LOWEST-PRECEDENCE source for bbf_assemble_seeds. Operator-named
 * seeds keep their slots and their precedence, and the discovery quorum still
 * prefers the explicit -fileservice candidate.
 *
 * WHAT THIS DOES NOT ADD — the whole point. A peer-discovered seed is an
 * ADDRESS, not an authority. It is fed through the identical path an
 * -fileservice= seed is fed through: same transport MAC, same per-chunk SHA3,
 * same whole-file SHA3 against the committed manifest, same
 * CHECKPOINT_ROM/CHECKPOINT_CONTENT install gate binding the result to the
 * COMPILED checkpoint. A hostile peer that advertises and then serves garbage
 * costs one bounded fetch and is dropped. Nothing here relaxes any check. */

/* One cached peer file-service endpoint offered as a candidate seed. */
struct boot_bundle_peer_seed {
    char     host[64];   /* numeric address text; never a .onion (see below) */
    /* The port the peer ITSELF advertised in its zfileaddr message. Carried
     * per peer and never defaulted to FS_PORT: seeders legitimately run on
     * other ports, and dialing a port the peer did not name is a guess.
     * ZERO means "this peer never advertised a file service" and is the
     * not-a-seed case bbf_assemble_seeds filters out. */
    uint16_t port;
};

/* Provider seam: fill `out` (capacity `max`) with handshaked peers and return
 * how many were written. MUST be pure and IO-free — bbf_assemble_seeds (and
 * therefore boot_bundle_fetch_seed_count) is documented pure, so the disk read
 * happens once in boot_bundle_fetch_arm_peer_seeds(), not per call. */
typedef size_t (*boot_bundle_peer_source_fn)(void *ctx,
                                             struct boot_bundle_peer_seed *out,
                                             size_t max);

/* Register (fn == NULL clears) the provider bbf_assemble_seeds consults last.
 * Process-global, like the rest of the boot seams. */
void boot_bundle_fetch_set_peer_source(boot_bundle_peer_source_fn fn,
                                       void *ctx);

/* Production arming: read the file_services table ONCE via
 * db_file_service_recent() (most-recently-seen first), keep the usable rows in
 * a small static table, and register the pure provider over it. Safe and
 * silent when `ndb` is NULL/closed or the table is empty — that is a
 * first-ever boot, and the behaviour is exactly the pre-existing one. Never
 * fails boot. Call before boot_bundle_fetch_maybe(). */
struct node_db;
void boot_bundle_fetch_arm_peer_seeds(struct node_db *ndb);

/* Drop the armed table and unregister the provider (tests, shutdown). */
void boot_bundle_fetch_disarm_peer_seeds(void);

/* How many peer-discovered seeds are currently armed. Introspection + tests. */
size_t boot_bundle_fetch_armed_peer_seed_count(void);

typedef bool (*bbf_directory_fetch_fn)(const char *peer_addr, uint16_t port,
                                       char *buf, size_t cap);

/* Same shape as rom_fetch_get_manifest — the per-chunk ("RMF") manifest
 * pre-flight, seam-typed so the bounded fan-out that runs it can be driven
 * without a network. */
typedef bool (*bbf_manifest_fetch_fn)(const char *peer_addr, uint16_t port,
                                      const uint8_t chunk_root[32],
                                      uint8_t (*out_chunk_sha3)[32],
                                      uint32_t out_cap,
                                      uint32_t *out_num_chunks);

/* Gate: true iff the instant-on bundle fetch should run for `datadir` under
 * `ctx`. False when: datadir is empty; the caller opted out (-nofilesync via
 * ctx->no_file_sync, or ZCL_NO_BUNDLE_FETCH set in the environment); the
 * sovereign-install marker is already present (never re-fetch over sovereign
 * state); or a *.sqlite bundle is already staged under <datadir>/bundles/ (the
 * autodetect will install it — no download needed). `ctx` may be NULL. */
bool boot_bundle_fetch_should_run(const char *datadir,
                                  const struct app_context *ctx);

/* Parse a ROM /directory.json body ({"artifacts":[{digest,whole_sha3,size,
 * chunk_size,chunks},...]}) and pick the consensus-state bundle manifest: the
 * LARGEST manifest-sane artifact (the complete-state bundle is the big one).
 * directory.json entries carry no filename, so `out->filename` is assigned a
 * canonical, classifiable name (consensus-state-bundle-<checkpoint_height>
 * .sqlite) that both boot_autodetect_consensus_bundle and the installer's
 * classify step accept. Returns true iff a usable manifest was picked. Pure —
 * no IO, no network. */
bool boot_bundle_pick_manifest(const char *directory_json,
                               struct rom_fetch_manifest *out);

/* Parse a ROM /directory.json body and pick the header-chain seed manifest: the
 * ROM_ARTIFACT_HEADER_SEED-kinded entry (selected by kind ONLY, never by size —
 * a legacy directory that emits no kind cannot advertise a header seed).
 * directory.json entries carry no filename, so `out->filename` is assigned the
 * canonical "block_index.bin" that rom_seed_classify (serve + re-seed) and the
 * flat loader (boot_header_seed_import) accept. Returns true iff a usable
 * header-seed manifest was picked. Pure — no IO, no network. */
bool boot_bundle_pick_header_seed_manifest(const char *directory_json,
                                           struct rom_fetch_manifest *out);

/* Download the committed bundle `m` from the file-service `peers` (npeers>=1)
 * into <datadir>/bundles/, content-verified. Prefers the per-chunk-verified
 * swarm path (rom_fetch_download_verified_parallel) when a reachable seeder
 * serves the artifact's per-chunk manifest, falling back to the whole-file-only
 * multi-seeder path (rom_fetch_download_parallel) for a legacy seeder — both
 * verify the bytes against `m` before the atomic rename. Returns true iff a
 * verified bundle landed at <datadir>/bundles/<m->filename>. Installs nothing.
 * On any content/transport failure returns false, leaving no *.sqlite (a .part
 * may remain for a later resume). */
bool boot_bundle_fetch_download(const char *datadir,
                                const struct rom_fetch_peer *peers,
                                size_t npeers,
                                const struct rom_fetch_manifest *m);

/* The production entry point wired into boot_select_state_source (before the
 * autodetect+install). Runs boot_bundle_fetch_should_run; assembles the
 * file-service seed set from ctx (ctx->file_service_peer, which may carry a
 * host[:port], plus the hardcoded clearnet file-service seeds unless
 * ctx->connect_only); then obtains the manifest commitment. It prefers a LOCAL
 * <datadir>/bundles/directory.json (an operator hint, or one a prior discovery
 * persisted); when that is absent — the truly fresh node — it DISCOVERS the
 * manifest(s) from the seed set over the file-service "RLS" wire and RANKS them
 * newest-first (highest advertised height), preferring a >=2-seed / explicit
 * -fileservice candidate at a given height but never refusing a lone newest one
 * (STEP 0: the export is not cross-node byte-deterministic, so a per-height
 * triple quorum almost never forms; quorum is a bandwidth-DoS guard, not a trust
 * source — trust binds at install). It persists the winner as the local hint,
 * then downloads newest-first with bounded fallback to the next-highest on a
 * miss. The big bytes are always swarmed + content-verified against the
 * committed manifest, and the install path binds the result to the compiled
 * checkpoint. Best-effort: any miss returns false and boot proceeds unchanged
 * (P2P IBD). Returns true iff a verified bundle landed this boot. */
bool boot_bundle_fetch_maybe(const char *datadir, const struct app_context *ctx);

/* How many file-service seeds `ctx` assembles to (the exact set
 * boot_bundle_fetch_maybe would use). ZERO means the fetch is structurally OFF
 * — nothing was ever contacted — which the no_state_source blocker must report
 * as `seeds_empty`, NOT as `no_seed` (seeds contacted, none served a usable
 * manifest). Pure: no IO, no network, no side effects. `ctx` may be NULL. */
size_t boot_bundle_fetch_seed_count(const struct app_context *ctx);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe. SELECT-only
 * peek at the last discovery outcome bbf_discover_from_peers() persisted:
 * "reached" | "degraded_single_seed" | "no_quorum_fell_open_to_ibd", plus
 * how many seeds were assembled vs. actually responded with a directory
 * listing. `key` is unused (NULL-safe). */
struct json_value;
bool boot_bundle_fetch_discovery_dump_state_json(struct json_value *out,
                                                 const char *key);

#ifdef ZCL_TESTING
/* Arm ONE synthetic cached peer endpoint
 * (engine/composition/src/boot_bundle_fetch_peer_seeds.c) so a test can drive the
 * "advertised ⇒ offered / did not advertise ⇒ not offered" decision without a
 * network or a node_db. Deliberately does NOT pre-filter on port != 0 — that
 * filter is bbf_assemble_seeds's job and is what the test is checking. */
void boot_bundle_fetch_arm_peer_seed_for_test(const char *host, uint16_t port);
/* Test surface (implemented in engine/composition/src/boot_bundle_fetch.c). */
bool boot_bundle_manifest_facts_ok_for_test(const struct rom_fetch_manifest *m);
int  boot_bundle_quorum_pick_for_test(const int64_t *heights, const int *counts,
                                      const bool *has_explicit, size_t ncand);
size_t boot_bundle_probe_directories_for_test(
    const struct rom_fetch_peer *peers, size_t np, char *bodies,
    size_t stride, bool *responded, bbf_directory_fetch_fn fetch);
bool boot_bundle_probe_manifest_for_test(
    const struct rom_fetch_peer *peers, size_t np,
    const uint8_t chunk_root[32], uint32_t want_chunks,
    uint8_t (*out_chunk_sha3)[32], uint32_t out_cap,
    uint32_t *out_num_chunks, bbf_manifest_fetch_fn fetch);
#endif

#endif /* ZCL_CONFIG_BOOT_BUNDLE_FETCH_H */
