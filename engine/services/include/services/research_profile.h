/* purpose: Bind one research profile to its baseline, schedule, and genesis. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_SERVICES_RESEARCH_PROFILE_H
#define ZCL_SERVICES_RESEARCH_PROFILE_H

#include "base/result.h"
#include <stddef.h>
#include <stdint.h>

/* Local port and datadir are configuration. They are copied onto the
 * identity and are not inputs to the commitment. The commitment binds the
 * baseline, the raw genesis hash, and every activation height. Callers
 * choose state_dir before opening a wallet or a chain store. This does not
 * install a consensus migration or a proof-of-work change. */
struct research_profile_spec {
    const uint8_t *baseline;
    int32_t start;
    int32_t window;
    const int32_t *activations;
    size_t activation_count;
    const uint8_t *genesis_wire;
    size_t genesis_wire_len;
    size_t header_len;
    uint16_t rpc_port;
    const char *datadir;
    const char *transport_domain;
};

struct research_profile_identity {
    uint8_t commitment[32];
    uint8_t genesis_raw[32];
    char genesis_display[65];
    uint8_t message_start[4];
    uint16_t rpc_port;
    char datadir[32];
    char state_dir[80];
};

struct research_profile_child {
    uint8_t prev[32];
    uint8_t commitment[32];
    uint8_t nonce[8];
    uint32_t compact_target;
};

struct zcl_result research_profile_bind(const struct research_profile_spec *spec,
                                        struct research_profile_identity *out);

/* Profile fixture: search for a SHA256d nonce in a synthetic 72-byte record.
 * Network blocks use the normal Equihash validation path. */
struct zcl_result research_profile_solve_child(const struct research_profile_identity *id,
                                               uint32_t compact_target,
                                               struct research_profile_child *out);

/* Check the fixture target, previous hash, and profile commitment. */
struct zcl_result research_profile_accept_child(const struct research_profile_identity *parent,
                                                const struct research_profile_child *child,
                                                int *pow_ok);
#endif
