/* purpose: Shared helpers for experimental profile tools. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef Z23_PROFILE_INSPECTOR_COMMON_H
#define Z23_PROFILE_INSPECTOR_COMMON_H
#include "services/experimental_profile.h"
#define PROFILE_MAX EXPERIMENTAL_PROFILE_MAX
#define GENESIS_SIZE EXPERIMENTAL_GENESIS_SIZE
void profile_print_hex(const uint8_t *bytes, size_t n);
#endif
