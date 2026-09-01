/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: proves boot_export_consensus_bundle() honours its documented
 * TERMINAL contract (engine/composition/include/config/boot.h) and never returns, failing
 * closed on Windows.
 *
 * Adopted from tools/tests/test_boot_export_windows_refusal.c, which the
 * deleted tools/scripts/winacceptance.sh compiled and never ran. That program
 * called the verb from main() with the datadir in argv[1] and returned 3 if
 * control ever came back — a shape only a compiler can read, because a
 * process that observes the contract holding is a process that has already
 * exited. Here the observation is made from a parent: it re-executes ITSELF
 * with --child and that same datadir argument, and the child runs the
 * original body unchanged. The contract holds iff the child died with
 * EXIT_FAILURE rather than reaching the `return 3` the original wrote, and
 * iff the datadir it was handed was never created. */
#if defined(_WIN32)

#include "config/boot.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "--child") == 0) {
        boot_export_consensus_bundle(NULL, NULL, argv[2]);
        /* Reachable only if the TERMINAL contract was broken. */
        return 3;
    }

    /* The verb refuses before it reads a datadir, so this path is named and
     * never created; the refusal is proved against a path that stays absent. */
    char temp[MAX_PATH], datadir[MAX_PATH];
    DWORD n = GetTempPathA(sizeof(temp), temp);
    if (!n || n >= sizeof(temp) ||
        snprintf(datadir, sizeof(datadir), "%sz23-export-refuse-%lu", temp,
                 (unsigned long)GetCurrentProcessId()) <= 0 ||
        GetFileAttributesA(datadir) != INVALID_FILE_ATTRIBUTES)
        return 1;

    char image[MAX_PATH];
    if (!GetModuleFileNameA(NULL, image, sizeof(image)))
        return 1;
    char command[2 * MAX_PATH + 32];
    if (snprintf(command, sizeof(command), "\"%s\" --child \"%s\"", image,
                 datadir) <= 0)
        return 1;

    STARTUPINFOA startup;
    PROCESS_INFORMATION process;
    memset(&startup, 0, sizeof(startup));
    memset(&process, 0, sizeof(process));
    startup.cb = sizeof(startup);
    if (!CreateProcessA(image, command, NULL, NULL, FALSE, 0, NULL, NULL,
                        &startup, &process))
        return 1;
    DWORD waited = WaitForSingleObject(process.hProcess, 60000);
    DWORD code = 0;
    bool observed = waited == WAIT_OBJECT_0 &&
                    GetExitCodeProcess(process.hProcess, &code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    if (!observed || code == 3 || code != (DWORD)EXIT_FAILURE ||
        GetFileAttributesA(datadir) != INVALID_FILE_ATTRIBUTES)
        return 1;
    puts("boot_export_windows_refusal_acceptance: PASS");
    return 0;
}

#else
typedef int boot_export_windows_refusal_not_built;
#endif
