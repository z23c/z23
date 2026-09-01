/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * simnet_byzantine — adversarial-peer fixtures over the real validator.
 *
 * Tier 1 drives malformed blocks through connect_block(..., just_check=false)
 * on a scratch coins view. Tier 2 mirrors the live header admission predicates
 * that reject before connect_block in the normal pipeline.
 */

#ifndef ZCL_SIM_SIMNET_BYZANTINE_H
#define ZCL_SIM_SIMNET_BYZANTINE_H

#include "chain/chain.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "sim/simnet.h"
#include "util/blocker.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum simnet_byzantine_tier {
    SIMNET_BYZ_TIER_CONNECT_BLOCK = 1,
    SIMNET_BYZ_TIER_HEADER_ADMISSION = 2,
};

enum simnet_byzantine_class {
    SIMNET_BYZ_BAD_MERKLE = 0,
    SIMNET_BYZ_BAD_CB_AMOUNT,
    SIMNET_BYZ_BIP30_DUP_TXID,
    SIMNET_BYZ_MISSING_SPEND,
    SIMNET_BYZ_IMMATURE_SPEND,
    SIMNET_BYZ_NEGATIVE_OUTPUT,
    SIMNET_BYZ_OVERFLOW_OUTPUT,
    SIMNET_BYZ_OVERSIZE_VTX,
    SIMNET_BYZ_INVALID_POW,
    SIMNET_BYZ_BAD_BITS,
    SIMNET_BYZ_BAD_TIMESTAMP,
    SIMNET_BYZ_CLASS_COUNT,
};

struct simnet_byzantine_block_case {
    enum simnet_byzantine_class kind;
    struct block block;
    int height;
    bool direct_vtx_free;
};

enum simnet_byzantine_header_gate {
    SIMNET_BYZ_HEADER_CHECK_BLOCK = 1,
    SIMNET_BYZ_HEADER_CONTEXTUAL,
};

struct simnet_byzantine_header_case {
    enum simnet_byzantine_class kind;
    enum simnet_byzantine_header_gate gate;
    struct block_header header;
    struct block_index prev;
    unsigned int expected_bits;
    int64_t prev_mtp;
};

struct simnet_byzantine_observation {
    enum simnet_byzantine_class kind;
    enum simnet_byzantine_tier tier;
    bool rejected;
    char reject_reason[64];
    enum blocker_class blocker_class;
    char blocker_id[64];
    int tip_before;
    int tip_after;
    bool honest_after_accepted;
    bool invariant_ok;
};

const char *simnet_byzantine_class_name(enum simnet_byzantine_class kind);
enum simnet_byzantine_tier
simnet_byzantine_class_tier(enum simnet_byzantine_class kind);
const char *simnet_byzantine_expected_reason(
    enum simnet_byzantine_class kind);
enum blocker_class simnet_byzantine_expected_blocker_class(
    enum simnet_byzantine_class kind);
enum blocker_class simnet_byzantine_blocker_class_for_reason(
    const char *reject_reason);

bool simnet_byzantine_build_bad_merkle(
    struct simnet *sim, struct simnet_byzantine_block_case *out);
bool simnet_byzantine_build_bad_cb_amount(
    struct simnet *sim, struct simnet_byzantine_block_case *out);
bool simnet_byzantine_build_bip30_duplicate_txid(
    struct simnet *sim, struct simnet_byzantine_block_case *out);
bool simnet_byzantine_build_missing_spend(
    struct simnet *sim, struct simnet_byzantine_block_case *out);
bool simnet_byzantine_build_immature_spend(
    struct simnet *sim, struct simnet_byzantine_block_case *out);
bool simnet_byzantine_build_negative_output(
    struct simnet *sim, struct simnet_byzantine_block_case *out);
bool simnet_byzantine_build_overflow_output(
    struct simnet *sim, struct simnet_byzantine_block_case *out);
bool simnet_byzantine_build_oversize_vtx(
    struct simnet *sim, struct simnet_byzantine_block_case *out);

bool simnet_byzantine_build_invalid_pow_header(
    const struct simnet *sim, struct simnet_byzantine_header_case *out);
bool simnet_byzantine_build_bad_bits_header(
    const struct simnet *sim, struct simnet_byzantine_header_case *out);
bool simnet_byzantine_build_bad_timestamp_header(
    const struct simnet *sim, struct simnet_byzantine_header_case *out);

void simnet_byzantine_block_case_free(
    struct simnet_byzantine_block_case *c);

bool simnet_byzantine_run_connect_case(
    enum simnet_byzantine_class kind,
    struct simnet_byzantine_observation *out);
bool simnet_byzantine_run_header_case(
    enum simnet_byzantine_class kind,
    struct simnet_byzantine_observation *out);

bool simnet_byzantine_observation_ok(
    const struct simnet_byzantine_observation *obs);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_SIM_SIMNET_BYZANTINE_H */
