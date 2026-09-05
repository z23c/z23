/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: What a box can honestly say about itself at enrolment time, and
 *          the dedicated ssh public key the bridge restricts.
 *          See tools/dev/fleet_enrol.h for the contract.
 *
 * NOTHING HERE FAILS. A fact this host will not disclose is left empty or
 * zero. An enrolment that refused because /proc/meminfo was unreadable
 * would tell the owner nothing they wanted to know and would stop the box
 * joining at all; a missing fact renders as absent and the box still joins.
 *
 * Everything collected here is SELF-REPORTED. The box signs it, so it is
 * authenticated — this box said this — but no peer measured any of it, and
 * `fleet machines` renders it in the self_reported array for exactly that
 * reason. Do not add a field here and describe it as verified.
 *
 * The `_WIN32` branch exists because tools/dev sources are compiled for
 * ZCL_TARGET=windows-x86_64 like every other release translation unit, so
 * <sys/utsname.h> and <sys/statvfs.h> cannot be reached unconditionally.
 * The SUPPORTED Windows path for enrolment is still WSL2 (docs/agent/
 * FLEET_JOIN.md says so): the native branch answers the same questions so
 * the file compiles and reports honestly, not because a native Windows box
 * can serve the mesh terminal yet.
 */

#include "fleet_enrol.h"

#include "util/clientversion.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <unistd.h>
#endif

/* Close-on-exec on POSIX; the Windows CRT rejects the mode letter. */
#if defined(_WIN32)
#define FE_FOPEN_READ "rb"
#else
#define FE_FOPEN_READ "re"
#endif

/* Copy at most cap-1 bytes and NUL-terminate; drop anything that is not
 * printable ASCII, because every one of these strings is signed into a wire
 * field whose encoder refuses non-printables outright. */
static void fe_copy_clean(char *out, size_t cap, const char *in)
{
    size_t n = 0;
    if (!cap) return;
    for (size_t i = 0; in && in[i] && n + 1u < cap; ++i) {
        unsigned char c = (unsigned char)in[i];
        if (c >= 0x20u && c <= 0x7eu) out[n++] = (char)c;
    }
    out[n] = '\0';
}

/* The home directory this box's fleet ssh key would live under. Separate
 * from the state root: an ssh key belongs where sshd already looks. */
static bool fe_home(char *out, size_t cap)
{
#if defined(_WIN32)
    const char *home = getenv("USERPROFILE");
#else
    const char *home = getenv("HOME");
#endif
    if (!home || !home[0]) return false;
    int n = snprintf(out, cap, "%s", home);
    return n > 0 && (size_t)n < cap;
}

#if !defined(_WIN32)
/* PRETTY_NAME from /etc/os-release, which is the one line a human
 * recognises ("Ubuntu 24.04.1 LTS"). Absent on macOS and on a minimal
 * container, and that is fine — uname's release fills in. */
static bool fe_os_release_pretty(char *out, size_t cap)
{
    char line[256];
    FILE *f = fopen("/etc/os-release", FE_FOPEN_READ);
    bool found = false;
    if (!f) return false;
    while (!found && fgets(line, sizeof(line), f)) {
        char *value = NULL;
        if (strncmp(line, "PRETTY_NAME=", 12) != 0) continue;
        value = line + 12;
        if (*value == '"') ++value;
        for (char *p = value; *p; ++p) {
            if (*p == '"' || *p == '\n') { *p = '\0'; break; }
        }
        fe_copy_clean(out, cap, value);
        found = out[0] != '\0';
    }
    (void)fclose(f);
    return found;
}
#endif

void fleet_enrol_facts_collect(struct fleet_box_facts *out)
{
    memset(out, 0, sizeof(*out));
    /* Captured at compile time, so naming the compiler costs no process
     * spawn and no filesystem read. */
    fe_copy_clean(out->toolchain, sizeof(out->toolchain), __VERSION__);
    fe_copy_clean(out->git_head, sizeof(out->git_head), zcl_build_commit_full());
#if defined(_WIN32)
    {
        char name[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD name_len = (DWORD)sizeof(name);
        SYSTEM_INFO info;
        MEMORYSTATUSEX memory;
        ULARGE_INTEGER free_bytes;
        OSVERSIONINFOEXA version;
        char text[64];
        if (GetComputerNameA(name, &name_len))
            fe_copy_clean(out->hostname, sizeof(out->hostname), name);
        fe_copy_clean(out->os, sizeof(out->os), "Windows");
        memset(&version, 0, sizeof(version));
        version.dwOSVersionInfoSize = (DWORD)sizeof(version);
        if (GetVersionExA((OSVERSIONINFOA *)&version) &&
            snprintf(text, sizeof(text), "%lu.%lu build %lu",
                     (unsigned long)version.dwMajorVersion,
                     (unsigned long)version.dwMinorVersion,
                     (unsigned long)version.dwBuildNumber) > 0)
            fe_copy_clean(out->os_version, sizeof(out->os_version), text);
        GetSystemInfo(&info);
        out->cores = (uint32_t)info.dwNumberOfProcessors;
        fe_copy_clean(out->arch, sizeof(out->arch),
                      info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64
                          ? "x86_64"
                          : (info.wProcessorArchitecture ==
                                     PROCESSOR_ARCHITECTURE_ARM64
                                 ? "aarch64"
                                 : "unknown"));
        memset(&memory, 0, sizeof(memory));
        memory.dwLength = (DWORD)sizeof(memory);
        if (GlobalMemoryStatusEx(&memory))
            out->ram_mb = (uint64_t)(memory.ullTotalPhys / (1024u * 1024u));
        free_bytes.QuadPart = 0;
        if (GetDiskFreeSpaceExA(NULL, &free_bytes, NULL, NULL))
            out->disk_free_mb =
                (uint64_t)(free_bytes.QuadPart / (1024u * 1024u));
    }
#else
    {
        struct utsname sys;
        struct statvfs disk;
        long cores = sysconf(_SC_NPROCESSORS_ONLN);
        long pages = sysconf(_SC_PHYS_PAGES);
        long page_size = sysconf(_SC_PAGESIZE);
        if (uname(&sys) == 0) {
            /* nodename, not gethostname(2): it is the same string from a
             * call this tree already classifies, so collecting a fact costs
             * no new external symbol. The hostname is a FACT about the box,
             * never its fleet name — the owner chose that at invite time. */
            fe_copy_clean(out->hostname, sizeof(out->hostname), sys.nodename);
            fe_copy_clean(out->os, sizeof(out->os), sys.sysname);
            fe_copy_clean(out->arch, sizeof(out->arch), sys.machine);
            if (!fe_os_release_pretty(out->os_version, sizeof(out->os_version)))
                fe_copy_clean(out->os_version, sizeof(out->os_version),
                              sys.release);
        }
        if (cores > 0) out->cores = (uint32_t)cores;
        if (pages > 0 && page_size > 0)
            out->ram_mb =
                ((uint64_t)pages * (uint64_t)page_size) / (1024u * 1024u);
        /* The checkout the box was built in is the disk that matters to a
         * fleet driver deciding where a build can run. */
        if (statvfs(".", &disk) == 0 && disk.f_frsize > 0)
            out->disk_free_mb = ((uint64_t)disk.f_bavail *
                                 (uint64_t)disk.f_frsize) / (1024u * 1024u);
    }
#endif
}

void fleet_enrol_ssh_pubkey(char *out, size_t cap)
{
    char home[FLEET_ENROL_PATH_MAX];
    char path[FLEET_ENROL_PATH_MAX];
    char line[FLEET_ENROL_SSH_MAX + 2];
    FILE *f = NULL;
    if (!cap) return;
    out[0] = '\0';
    if (!fe_home(home, sizeof(home)) ||
        snprintf(path, sizeof(path), "%s/.ssh/z23_fleet.pub", home) <= 0)
        return;
    /* Deliberately NOT id_rsa/id_ed25519. The bridge line restricts exactly
     * the key it is given to one forwarded port; handing it a key the owner
     * also uses for shell access would silently narrow that key everywhere
     * sshd matched it first. A box with no dedicated key simply gets no
     * bridge, and `fleet join` says so. */
    f = fopen(path, FE_FOPEN_READ);
    if (!f) return;
    if (fgets(line, sizeof(line), f)) {
        for (char *p = line; *p; ++p) {
            if (*p == '\n' || *p == '\r') { *p = '\0'; break; }
        }
        if (strlen(line) <= (size_t)FLEET_ENROL_SSH_MAX)
            fe_copy_clean(out, cap, line);
    }
    (void)fclose(f);
}
