/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Legacy zclassicd chain oracle helpers.
 *
 * These are synchronous, best-effort reads from a local legacy zclassicd RPC
 * endpoint. They are used only as bridge/oracle data while zclassic23 is still
 * building its native indexes, not as consensus acceptance rules.
 */

#ifndef ZCL_RPC_LEGACY_CHAIN_ORACLE_H
#define ZCL_RPC_LEGACY_CHAIN_ORACLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct mmb_leaf;

bool legacy_chain_rpc_get_block_hash_hex(int height, char out_hex[65]);
bool legacy_chain_rpc_get_mmb_leaf(int height, struct mmb_leaf *leaf);
bool legacy_chain_rpc_get_chainwork(const uint8_t block_hash[32],
                                    uint8_t chain_work[32]);

/* Best-effort read of the legacy zclassicd's current chain height
 * (getblockcount). Returns false on RPC error; *out_height is set on
 * success. Reuses the shared legacy_rpc transport. */
bool legacy_chain_rpc_get_block_count(int *out_height);

/* Fetch the raw serialized block at `height` from zclassicd
 * (getblockhash then getblock verbose=0). The hex string is written
 * NUL-terminated into out_hex (caller-sized; needs room for the full
 * block hex + NUL). Returns false on RPC error, oversize, or parse
 * failure. Reuses the shared legacy_rpc transport — no new client. */
bool legacy_chain_rpc_get_block_hex(int height, char *out_hex,
                                    size_t out_hex_sz);

#endif /* ZCL_RPC_LEGACY_CHAIN_ORACLE_H */
