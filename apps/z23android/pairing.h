/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_PAIRING_H
#define ZAPP_PAIRING_H
#include <stdbool.h>
#include <stddef.h>
/* Six lowercase hex digits of SHA3-256 over the descriptor text, shown on the
 * laptop and on the phone so the owner can compare them before pairing. */
bool zapp_pair_code(const char *descriptor, char code[7]);

/* True when the uid that launched the app may offer a pairing: the app itself, the adb shell (2000) or root (0).
 * Another app, or an unknown uid (negative), is refused. */
bool zapp_pair_caller_allowed(int caller_uid, int own_uid);
#endif
