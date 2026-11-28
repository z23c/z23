/* purpose: Evaluate prepared public Ironwood note commitment inputs. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_IRONWOOD_NOTE_COMMITMENT_H
#define ZCL_IRONWOOD_NOTE_COMMITMENT_H
#include "base/result.h"
#include <stdint.h>

/* Public research inputs only. This arithmetic is not qualified for wallet
 * secrets. Inputs must be canonical nonidentity Pallas points, canonical
 * Pallas base-field rho/psi and canonical Pallas scalar rcm. The caller is
 * responsible for deriving and validating these values from the note. */
struct ironwood_note_commitment_public {
    uint8_t gd[32], pkd[32], rho[32], psi[32], rcm[32];
    uint64_t value;
};
/* On any error out is unchanged. Does not establish note ownership. */
struct zcl_result ironwood_note_commitment_compute_public(
    const struct ironwood_note_commitment_public *input, uint8_t out[32]);
#endif
