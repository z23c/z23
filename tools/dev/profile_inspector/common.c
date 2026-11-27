/* purpose: Render experimental profile values for offline tools. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "common.h"
#include "base/hex.h"
#include <stdio.h>
void profile_print_hex(const uint8_t *bytes, size_t n)
{
    char encoded[65];
    zcl_hex_encode(bytes, n, encoded);
    fputs(encoded, stdout);
}
