/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_PAIRING_H
#define ZAPP_PAIRING_H
#include <stdbool.h>
#include <stddef.h>
/* Six lowercase hex digits of SHA3-256 over the descriptor text, shown on the
 * laptop and on the phone so the owner can compare them before pairing. */
bool zapp_pair_code(const char *descriptor, char code[7]);
#endif
