/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONFIG_BOOT_FLYCLIENT_H
#define ZCL_CONFIG_BOOT_FLYCLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct active_chain;
struct boot_svc_ctx;
struct fc_challenge;
struct fc_response;
struct mmb_leaf;
struct mmb_leaf_store;

typedef bool (*boot_mmb_leaf_loader_fn)(int height,
                                        struct mmb_leaf *leaf_out);

/* The single MMB leaf-hash store for FlyClient proofs. The snapshot-offer
 * worker reads the same store to embed the MMB root in fast-sync offers. */
extern struct mmb_leaf_store g_mmb_leaf_store;

bool boot_build_flyclient_proof(struct fc_response *resp,
                                const struct fc_challenge *challenge,
                                const struct active_chain *chain_active,
                                void *ctx);

int boot_load_block_hashes_range(int32_t start_height,
                                 int32_t end_height,
                                 uint8_t (*hashes_out)[32],
                                 size_t max,
                                 void *ctx);

bool boot_compute_utxo_sha3(uint8_t out[32],
                            uint64_t *utxo_count,
                            void *ctx);

/* Returns the serialized UTXO count or -1 on invalid arguments or output
 * failure. sha3_out is required and is zeroed on failure; partial files must
 * not be used as snapshots. */
int64_t boot_serialize_utxo_snapshot(void *ctx,
                                     const char *path,
                                     uint32_t chunk_size,
                                     uint8_t sha3_out[32]);

bool boot_prepare_mmb_leaf_store(struct boot_svc_ctx *svc,
                                 const char *datadir,
                                 boot_mmb_leaf_loader_fn legacy_loader);

/* Reconcile the open leaf store with the active chain: append only the missing
 * tail when the stored prefix (last leaf and sampled older leaves) matches the
 * chain, otherwise fall back to mmb_leaf_store_rebuild. The target is clamped
 * to the leaves the chain can produce. Exposed for tests. */
struct mmb_leaf_store;
struct active_chain;
bool boot_reconcile_mmb_leaf_store(struct mmb_leaf_store *store,
                                   const struct active_chain *chain,
                                   uint64_t mmb_leaves);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_CONFIG_BOOT_FLYCLIENT_H */
