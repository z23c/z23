/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: normalise a machine into the platform triple used in release URLs
 * and in refusals, and answer whether a Z23 runtime is published for it.
 *
 * The failure this prevents: installing a binary that cannot run on the
 * machine that asked for it. A machine we publish no runtime for gets a
 * refusal that names both what it is and what we do publish, and downloads
 * nothing.
 *
 * PUBLISHED is not the same question as PACKAGED.
 * packaging/release/build_release.sh can package a windows-x86_64 runtime as
 * well as a linux-x86_64 one, and only linux-x86_64 is named below: the
 * Windows PE has never been executed, and there is no Windows second-stage
 * installer for the bootstrap to hand off to. Widening this list is checked
 * against what the cutter reports it produces by
 * tools/lint/check_published_platforms.sh, which is a floor and not a
 * licence — a platform can be packaged and still not be fit to publish.
 */

#include "install/front_door.h"

#include <stdio.h>
#include <string.h>

/* The published RUNTIME set, written ONCE as a space-separated literal so the
 * membership test and the text of the refusal cannot drift apart — a refusal
 * naming a platform we stopped publishing is worse than no refusal.
 *
 * This is not the same list as the set of platforms a bootstrap binary exists
 * for; packaging/install/install.sh carries that one, because it has to pick
 * a download before any C23 code is running. A bootstrap can honestly exist
 * for a machine we publish no runtime for, and then this refusal is the one
 * the user sees. */
#define FD_PUBLISHED "linux-x86_64"

/* Unknown spellings pass through verbatim rather than being guessed at:
 * "no Z23 runtime is published for sunos-sparc64" is a true sentence a user
 * can act on, where a wrong guess would send them to a 404. */
void fd_platform_triple(const char *sysname, const char *machine,
                        char out[FD_TRIPLE_MAX])
{
    if (!out)
        return;
    out[0] = '\0';
    const char *os = sysname && *sysname ? sysname : "unknown";
    const char *cpu = machine && *machine ? machine : "unknown";

    if (strcmp(os, "Linux") == 0)
        os = "linux";
    else if (strcmp(os, "Darwin") == 0)
        os = "darwin";

    if (strcmp(cpu, "x86_64") == 0 || strcmp(cpu, "amd64") == 0)
        cpu = "x86_64";
    else if (strcmp(cpu, "aarch64") == 0 || strcmp(cpu, "arm64") == 0)
        cpu = "aarch64";

    const int want = snprintf(out, FD_TRIPLE_MAX, "%s-%s", os, cpu);
    if (want < 0 || want >= FD_TRIPLE_MAX) {
        /* A machine whose uname strings do not fit is still refused by name;
         * "unknown" is the honest name for one we could not even print. */
        (void)snprintf(out, FD_TRIPLE_MAX, "unknown-unknown");
    }
}

bool fd_platform_published(const char *triple)
{
    if (!triple || !*triple)
        return false;
    const size_t want = strlen(triple);
    const char *p = FD_PUBLISHED;
    while (*p) {
        while (*p == ' ')
            p++;
        const char *end = p;
        while (*end && *end != ' ')
            end++;
        if ((size_t)(end - p) == want && memcmp(p, triple, want) == 0)
            return true;
        p = end;
    }
    return false;
}

const char *fd_platform_published_list(void)
{
    return FD_PUBLISHED;
}
