/* purpose: Share checked prevout validation for v6 transparent verification. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef Z23_TRANSACTION_V6_TRANSPARENT_INTERNAL_H
#define Z23_TRANSACTION_V6_TRANSPARENT_INTERNAL_H
#include "controllers/transaction_v6_transparent.h"
#include <stdbool.h>
bool v6_transparent_prevouts_valid(const struct transaction_v6_prevout *prevouts, size_t count);
#endif
