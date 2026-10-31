/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_DEVICE_KEY_PROBE_H
#define ZAPP_DEVICE_KEY_PROBE_H
#include <android/native_activity.h>

enum zapp_devkey_probe_event { ZAPP_DEVKEY_PROBE_PAUSE, ZAPP_DEVKEY_PROBE_RESUME };
/* Phone measurement hook, built only with Z23_DEVKEY_PROBE (the preview package, never a node).
 * On resume it runs the single command in <internal data>/probe.cmd on its own thread and appends one
 * line to probe.out. Commands: prepare, wrap, unwrap, pay, twice, oldblob, roundtrip, store, discard,
 * secure on, secure off.
 *
 * Every wrap, unwrap, pay and each half of twice and roundtrip shows one system prompt that the owner
 * answers. Expected: `ok` after the PIN or fingerprint; `declined` after Back; `twice` shows two
 * prompts, and a second `ok` within about 100 ms of the first (no prompt shown) means the key
 * accepted an earlier authentication and is a failure; `oldblob` answers `old_format` with no prompt. */
void zapp_devkey_probe(ANativeActivity *activity, enum zapp_devkey_probe_event event);
#endif
