/* purpose: Declare the resident public PostNu6_3 verifier parameters. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_IRONWOOD_RESIDENT_PARAMS_H
#define ZCL_IRONWOOD_RESIDENT_PARAMS_H
#include "services/ironwood_opening_equation.h"
extern const struct ironwood_opening_basis ironwood_resident_basis;
extern const uint8_t ironwood_resident_custom[48484];
extern const uint8_t ironwood_resident_permutation[997];
extern const uint8_t ironwood_resident_lookup[1159];
/* Public pinned MerkleCRH table, resident for the lifetime of the process. */
const uint8_t *ironwood_resident_merkle_parameters(size_t *size);
#endif
