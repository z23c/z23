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

int64_t boot_serialize_utxo_snapshot(void *ctx,
                                     const char *path,
                                     uint32_t chunk_size,
                                     uint8_t sha3_out[32]);

bool boot_prepare_mmb_leaf_store(struct boot_svc_ctx *svc,
                                 const char *datadir,
                                 boot_mmb_leaf_loader_fn legacy_loader);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_CONFIG_BOOT_FLYCLIENT_H */
