/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Observe test-only startup authentication phase completion. */
#ifndef ZCL_BOOT_WALLET_AUTH_OBSERVE_H
#define ZCL_BOOT_WALLET_AUTH_OBSERVE_H
#ifdef ZCL_TESTING
static _Thread_local void (*boot_auth_test_observer)(char);
static inline bool boot_auth_test_bool(char phase, bool ok)
{
    if (boot_auth_test_observer)
        boot_auth_test_observer(ok ? phase : phase == 'R' ? 'x' : (char)(phase + ('a' - 'A')));
    return ok;
}
static inline struct zcl_result boot_auth_test_result(char phase, struct zcl_result result)
{
    (void)boot_auth_test_bool(phase, result.ok);
    return result;
}
#define BOOT_AUTH_BOOL(phase, value) boot_auth_test_bool((phase), (value))
#define BOOT_AUTH_RESULT(phase, value) boot_auth_test_result((phase), (value))
#else
#define BOOT_AUTH_BOOL(phase, value) (value)
#define BOOT_AUTH_RESULT(phase, value) (value)
#endif
#endif
