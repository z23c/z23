/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Native Windows acceptance: install refuses without touching caller state. */
#if defined(_WIN32)

#include "config/consensus_state_install_runtime.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    struct consensus_state_install_runtime_result result;
    struct consensus_state_install_runtime_result before;
    memset(&result, 0xa5, sizeof(result));
    before = result;
    struct zcl_result refused = consensus_state_install_from_bundle(
        NULL, NULL, "must-not-open.sqlite", "must-not-open-datadir", &result);
    if (refused.ok || memcmp(&result, &before, sizeof(result)) != 0)
        return 1;
    puts("consensus_state_install_runtime_refusal_acceptance: PASS");
    return 0;
}

#else
typedef int consensus_state_install_runtime_windows_refusal_not_built;
#endif
