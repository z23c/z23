/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Boot snapshot-offer worker unit — the fast-sync snapshot offer builder
 * lifted out of boot_background_workers.c so that file stays under the E1
 * 800-line ceiling. The worker body (build_snapshot_offer_thread) exports the
 * UTXO snapshot, embeds the MMR + MMB roots, and publishes the snapshot /
 * chunk / block-piece manifests for fast-sync peers.
 *
 * It is a supervised background worker (Shape 5 — MONITOR): it shares the
 * worker_on_stall handler and boot_register_worker_supervisor helper exposed
 * by boot_background_workers.h, and reaches the single MMB leaf store declared
 * by boot_flyclient.h through boot_internal.h.
 *
 * The start/join pair is called from its existing sites in app_init_services /
 * app_shutdown_svc (boot_services.c), boot order preserved.
 *
 * The trust predicate and the separate payload-authority binding gate are the
 * fail-closed authority used by REST/RPC/P2P serving boundaries. Phase 0 keeps
 * the latter closed because the legacy codecs read node.db.utxos while H*
 * sovereignty is proven over coins_kv.
 */

#ifndef ZCL_BOOT_SNAPSHOT_OFFER_H
#define ZCL_BOOT_SNAPSHOT_OFFER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct boot_svc_ctx;

/* Pure trust policy behind snapshot re-serving. Assisted state is never
 * advertised: transparent state must be self-derived at H*, and every
 * shielded-history adoption cursor must be explicitly complete (zero). */
bool boot_snapshot_offer_trust_policy(
    bool hstar_known, bool transparent_self_derived,
    bool sprout_cursor_found, int64_t sprout_cursor,
    bool sapling_cursor_found, int64_t sapling_cursor,
    bool nullifier_cursor_found, int64_t nullifier_cursor);

/* Block-piece swarm is the cheap zclassic23 IBD assist: it advertises
 * bodies this node already has. UTXO snapshot export stays opt-in
 * (ZCL_PUBLISH_FASTSYNC_ON_BOOT) because it takes DB read locks.
 * IBD nodes (header tip far ahead of bodies) skip so boot is not spent
 * hashing a manifest they will replace. */
#define BOOT_BLOCK_SWARM_MAX_HEADER_LAG 1024
bool boot_publish_block_swarm(int32_t body_height, int32_t header_height,
                              int32_t blocks_per_piece);

/* Live composite serving check. It requires both sovereign state and an exact
 * authoritative payload binding. The latter is deliberately unavailable
 * until export streams from coins_kv and binds root/count/supply/active hash,
 * so release builds currently return false even for sovereign state. */
bool boot_snapshot_offer_state_is_sovereign(char *reason,
                                             size_t reason_size);

/* Serving eligibility additionally validates any durable local-export proof.
 * Such a proof cannot override the closed payload-authority binding gate. */
bool boot_snapshot_offer_artifact_is_eligible(const char *datadir,
                                               char *reason,
                                               size_t reason_size);

#ifdef ZCL_TESTING
/* Test-only live-boundary seam: -1 restores real state, 0/1 force the result.
 * Release builds contain no override symbol or environment switch. */
void boot_snapshot_offer_test_set_trust_override(int value);

/* Fixture-only payload-binding seam. The legacy trust override initializes
 * both fixture gates for compatibility; negative tests can then force this
 * second gate off to prove that state trust alone grants no serving authority.
 * Release builds have no such symbol. */
void boot_snapshot_offer_test_set_publication_override(int value);
#endif

/* Fast-sync snapshot offer + chunk/block manifest builder. */
bool boot_start_offer_service(struct boot_svc_ctx *svc);
void boot_join_offer_service(struct boot_svc_ctx *svc);

#endif
