/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_SIM_SOCIAL_APP_SIM_H
#define ZCL_SIM_SOCIAL_APP_SIM_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct zcl_social_sim_report {
    uint64_t seed;
    uint64_t transcript;
    uint32_t deliveries;
    uint32_t rejected_invalid;
    bool censorship_bypassed;
    bool partition_rejoin_converged;
    bool late_joiner_caught_up;
    bool invalid_signature_rejected;
    bool real_secp256k1_verified;
    bool tampered_payload_rejected;
    bool wrong_author_rejected;
    bool forged_event_id_distinct;
};

/* Fast deterministic application-network proof. No sockets, wall clock, or
 * filesystem. Verification uses the immutable process crypto registry. Same
 * seed must produce the same transcript. */
bool zcl_social_app_sim_run(uint64_t seed,
                            struct zcl_social_sim_report *out);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_SIM_SOCIAL_APP_SIM_H */
