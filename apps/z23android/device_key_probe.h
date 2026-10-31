/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_DEVICE_KEY_PROBE_H
#define ZAPP_DEVICE_KEY_PROBE_H
#include <android/native_activity.h>

enum zapp_devkey_probe_event { ZAPP_DEVKEY_PROBE_PAUSE, ZAPP_DEVKEY_PROBE_RESUME };
/* Phone measurement hook, built only with Z23_DEVKEY_PROBE (the preview package, never a node).
 * On resume it runs the single command in <internal data>/probe.cmd on its own thread and appends one
 * line to probe.out. Commands: prepare, wrap, unwrap, pay, twice, noprompt, othercipher, oldblob,
 * roundtrip, store, discard, secure on, secure off. The worker copies the JVM, the data directory and
 * a global reference to the activity, so a prompt that outlives the activity reads no freed memory.
 *
 * Every wrap, unwrap, pay and each half of twice and roundtrip shows one system prompt that the owner
 * answers. Expected: `ok` after the PIN or fingerprint; `declined` after Back; `twice` shows two
 * prompts, one per call; `oldblob` answers `old_format` with no prompt.
 *
 * `noprompt` and `othercipher` are the enforcement checks, and each expects Keystore to refuse:
 * `noprompt` finishes an initialised cipher with no prompt, and `othercipher` authenticates one cipher
 * and finishes another. Both answer `ok accepted=0 auth_required=1 exception=...` when Keystore refused
 * with a user-not-authenticated error, and `error` when the key ran the operation (`accepted=1`) or the
 * refusal was some other fault (`auth_required=0`; the exception chain is printed). `othercipher` also
 * reports authenticated_cipher_ok=1 for the cipher the owner did authenticate. */
void zapp_devkey_probe(ANativeActivity *activity, enum zapp_devkey_probe_event event);
#endif
