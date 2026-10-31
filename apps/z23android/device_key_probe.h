/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_DEVICE_KEY_PROBE_H
#define ZAPP_DEVICE_KEY_PROBE_H
#include <android/native_activity.h>

enum zapp_devkey_probe_event { ZAPP_DEVKEY_PROBE_PAUSE, ZAPP_DEVKEY_PROBE_RESUME };
/* Phone measurement hook, built only with Z23_DEVKEY_PROBE (the preview package, never a node).
 * On resume it runs the single command in <internal data>/probe.cmd (prepare, wrap, unwrap,
 * roundtrip, discard, secure on, secure off) and appends one line to probe.out. A command that
 * needs authentication starts the credential screen once and is retried on the next resume. */
void zapp_devkey_probe(ANativeActivity *activity, enum zapp_devkey_probe_event event);
#endif
