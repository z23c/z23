/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_VALIDATION_SYNC_EVIDENCE_POLICY_H
#define ZCL_VALIDATION_SYNC_EVIDENCE_POLICY_H

#include <stdbool.h>
#include <stdint.h>

int zcl_finality_depth(void);
int zcl_immutable_height(int tip_height);
bool zcl_is_finality_safe_anchor(int anchor_height, int peer_tip_height);
bool zcl_is_snapshot_anchor_acceptable(int anchor_height, int peer_tip_height);
bool zcl_ibd_reorg_allowed(int reorg_depth);
bool zcl_reorg_allowed(int tip_height, int fork_height, bool in_ibd,
                       const char **reason_out);
bool zcl_chainwork_is_zero(const uint8_t chain_work[32]);
int zcl_chainwork_compare_le(const uint8_t a[32], const uint8_t b[32]);

/* Returns true when chain_work is strictly below floor_le. Both operands are
 * the canonical 32-byte little-endian chainwork layout (byte 0 = least
 * significant), matching mmb_leaf.chain_work / arith_uint256.pn-as-bytes and
 * struct uint256.data. The floor is the consensus nMinimumChainWork; an offered
 * fast-sync anchor below it is a forged minimum-difficulty chain and must be
 * rejected before its UTXO staging is accepted. A zero floor never rejects. */
bool zcl_chainwork_below_floor(const uint8_t chain_work[32],
                               const uint8_t floor_le[32]);

#endif /* ZCL_VALIDATION_SYNC_EVIDENCE_POLICY_H */
