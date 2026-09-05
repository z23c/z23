/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Preserve final Git output and exit status in native fleet capture. */
#if defined(_WIN32)
#include "../../../tools/command/native_dev_fleet_internal.h"

#include <stdio.h>
#include <string.h>

static int fail(const char *message)
{
    fprintf(stderr, "dev_fleet_capture_windows_acceptance: FAIL: %s\n", message);
    return 1;
}

int main(void)
{
    char output[16384];
    bool truncated = false;
    const char *version[] = {"--version", NULL};
    /* Short children routinely exit during the capture wait. The old loop
     * reported exit zero with an empty buffer after peeking before that wait. */
    for (unsigned i = 0; i < 32; i++) {
        int rc = zcl_dev_fleet_git_capture(".", version, output,
                                         sizeof(output), &truncated);
        if (rc != 0 || truncated || strncmp(output, "git version ", 12) != 0 ||
            !strchr(output, '\n'))
            return fail("short-lived Git lost its final output");
    }

    /* A command-line config value exercises multiple pipe reads without
     * changing any user's configuration or repository state. */
    char setting[8210] = "z23.capture=";
    size_t prefix = strlen(setting);
    memset(setting + prefix, 'x', 8192);
    setting[prefix + 8192] = 0;
    const char *large[] = {"-c", setting, "config", "--get", "z23.capture", NULL};
    int rc = zcl_dev_fleet_git_capture(".", large, output,
                                     sizeof(output), &truncated);
    if (rc != 0 || truncated || strlen(output) != 8193 || output[8192] != '\n' ||
        memcmp(output, setting + prefix, 8192) != 0)
        return fail("multi-read Git output lost bytes");

    memset(output, '!', sizeof(output));
    rc = zcl_dev_fleet_git_capture(".", large, output, 17, &truncated);
    if (rc != 0 || !truncated || strlen(output) != 16 || output[17] != '!' ||
        memcmp(output, setting + prefix, 16) != 0)
        return fail("bounded capture did not drain and report truncation");

    const char *empty[] = {"-c", "z23.capture=", "config", "--get", "z23.capture", NULL};
    rc = zcl_dev_fleet_git_capture(".", empty, output, sizeof(output), &truncated);
    if (rc != 0 || truncated || strcmp(output, "\n") != 0)
        return fail("empty config value lost its newline");

    const char *invalid[] = {"z23-no-such-command-for-capture-acceptance", NULL};
    rc = zcl_dev_fleet_git_capture(".", invalid, output, sizeof(output), &truncated);
    if (rc != 1 || truncated || !strstr(output, invalid[0]))
        return fail("Git failure lost its exit status or diagnostic");

    puts("dev_fleet_capture_windows_acceptance: PASS");
    return 0;
}
#else
typedef int dev_fleet_capture_windows_acceptance_not_built;
#endif
