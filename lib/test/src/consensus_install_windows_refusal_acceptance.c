/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: proves the Windows consensus-snapshot install refuses before it
 * touches the bundle -- the named refusal reason is reported, the bundle path
 * stays absent, and the artifact-evidence open fails leaving the caller a
 * NULL handle rather than a half-built one.
 *
 * Adopted from tools/tests/test_consensus_install_windows_refusal.c, which
 * the deleted tools/scripts/winacceptance.sh compiled and never ran. The
 * bundle path it took as argv[1] is now synthesized under the process temp
 * directory and deliberately never created, so the absent-path precondition
 * is established rather than assumed. */
#if defined(_WIN32)

#include "config/consensus_state_snapshot_install.h"
#include "platform/private_file.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <stdio.h>
#include <string.h>
#include <windows.h>

int main(void)
{
    char temp[MAX_PATH], bundle[MAX_PATH];
    DWORD n = GetTempPathA(sizeof(temp), temp);
    if (!n || n >= sizeof(temp))
        return 1;
    if (snprintf(bundle, sizeof(bundle), "%sz23-install-refuse-%lu.sqlite",
                 temp, (unsigned long)GetCurrentProcessId()) <= 0)
        return 1;
    if (!platform_private_path_absent(bundle))
        return 1;

    struct consensus_state_snapshot_install_request request = {
        .bundle_path = bundle,
    };
    struct consensus_state_install_result result;
    if (consensus_state_snapshot_install((struct sqlite3 *)(void *)&request,
                                         &request,
                                         &result) ||
        result.status != CONSENSUS_INSTALL_REFUSED ||
        !strstr(result.reason, "Windows consensus install refused") ||
        !platform_private_path_absent(bundle))
        return 1;

    struct consensus_state_artifact_evidence *evidence =
        (struct consensus_state_artifact_evidence *)(void *)&request;
    struct zcl_result opened = consensus_state_artifact_evidence_open(
        bundle, -1, &evidence);
    if (opened.ok || evidence != NULL || !platform_private_path_absent(bundle))
        return 1;
    puts("consensus_install_windows_refusal_acceptance: PASS");
    return 0;
}

#else
typedef int consensus_install_windows_refusal_not_built;
#endif
