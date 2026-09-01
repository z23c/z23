/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Capture stable native hardware and operating-system facts. */

#include "zcode_science_platform.h"

#include "platform/logical_cpu.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/utsname.h>
#endif

#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#endif

static void capture_str(uint8_t *field, size_t len, const char *value)
{
    size_t n = strlen(value);
    if (n >= len) n = len - 1;
    memcpy(field, value, n);
}

#if !defined(_WIN32)
static bool cpuinfo_field(const char *line, const char *key, char *out,
                          size_t cap)
{
    size_t key_len = strlen(key);
    if (strncmp(line, key, key_len) != 0) return false;
    const char *colon = strchr(line, ':');
    if (!colon) return false;
    const char *value = colon + 1;
    while (*value == ' ' || *value == '\t') value++;
    size_t n = strcspn(value, "\r\n");
    if (n == 0 || cap == 0) return false;
    if (n >= cap) n = cap - 1;
    memcpy(out, value, n);
    out[n] = '\0';
    return true;
}
#endif

static uint64_t capture_invariant_tsc_hz(void)
{
#if defined(__x86_64__) || defined(__i386__)
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid_count(0x15, 0, &eax, &ebx, &ecx, &edx) &&
        eax != 0 && ebx != 0 && ecx != 0)
        return (uint64_t)ecx * ebx / eax;
    if (__get_cpuid_count(0x16, 0, &eax, &ebx, &ecx, &edx) && eax != 0)
        return (uint64_t)eax * UINT64_C(1000000);
#endif
    return 0;
}

static void capture_cpuinfo(struct vcs_zcode_hardware_profile_v1 *out)
{
#if defined(_WIN32)
#if defined(__x86_64__) || defined(__i386__)
    unsigned int eax, ebx, ecx, edx;
    char vendor[13] = {0};
    if (__get_cpuid(0, &eax, &ebx, &ecx, &edx)) {
        memcpy(vendor, &ebx, 4);
        memcpy(vendor + 4, &edx, 4);
        memcpy(vendor + 8, &ecx, 4);
        capture_str(out->cpu_vendor, sizeof(out->cpu_vendor), vendor);
    }
    unsigned int maximum = __get_cpuid_max(0x80000000u, NULL);
    if (maximum >= 0x80000004u) {
        char brand[49] = {0};
        for (unsigned int leaf = 0; leaf < 3; leaf++) {
            __cpuid(0x80000002u + leaf, eax, ebx, ecx, edx);
            memcpy(brand + leaf * 16, &eax, 4);
            memcpy(brand + leaf * 16 + 4, &ebx, 4);
            memcpy(brand + leaf * 16 + 8, &ecx, 4);
            memcpy(brand + leaf * 16 + 12, &edx, 4);
        }
        const char *start = brand;
        while (*start == ' ') start++;
        capture_str(out->cpu_brand, sizeof(out->cpu_brand), start);
    }
#endif
#else
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (!f) return;
    char line[256], value[128];
    bool have_vendor = false, have_brand = false;
    while (fgets(line, sizeof(line), f) && !(have_vendor && have_brand)) {
        if (!have_vendor &&
            cpuinfo_field(line, "vendor_id", value, sizeof(value))) {
            capture_str(out->cpu_vendor, sizeof(out->cpu_vendor), value);
            have_vendor = true;
        } else if (!have_brand &&
                   cpuinfo_field(line, "model name", value, sizeof(value))) {
            capture_str(out->cpu_brand, sizeof(out->cpu_brand), value);
            have_brand = true;
        }
    }
    fclose(f);
#endif
}

static void capture_timer_source(struct vcs_zcode_hardware_profile_v1 *out)
{
#if defined(_WIN32)
    LARGE_INTEGER frequency;
    if (QueryPerformanceFrequency(&frequency) && frequency.QuadPart > 0)
        capture_str(out->timer_source, sizeof(out->timer_source),
                    "QueryPerformanceCounter");
#else
    static const char path[] =
        "/sys/devices/system/clocksource/clocksource0/current_clocksource";
    FILE *f = fopen(path, "r");
    if (!f) return;
    char buf[64];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    buf[strcspn(buf, "\r\n")] = '\0';
    if (buf[0] != '\0')
        capture_str(out->timer_source, sizeof(out->timer_source), buf);
#endif
}

static void capture_os(struct vcs_zcode_hardware_profile_v1 *out)
{
#if defined(_WIN32)
    capture_str(out->os_sysname, sizeof(out->os_sysname), "Windows_NT");
#if defined(_M_X64) || defined(__x86_64__)
    capture_str(out->os_machine, sizeof(out->os_machine), "x86_64");
#elif defined(_M_IX86) || defined(__i386__)
    capture_str(out->os_machine, sizeof(out->os_machine), "x86");
#elif defined(_M_ARM64) || defined(__aarch64__)
    capture_str(out->os_machine, sizeof(out->os_machine), "aarch64");
#endif
    OSVERSIONINFOW version = {.dwOSVersionInfoSize = sizeof(version)};
    if (GetVersionExW(&version)) {
        char release[48];
        int n = snprintf(release, sizeof(release), "%lu.%lu.%lu",
                         (unsigned long)version.dwMajorVersion,
                         (unsigned long)version.dwMinorVersion,
                         (unsigned long)version.dwBuildNumber);
        if (n > 0 && (size_t)n < sizeof(release))
            capture_str(out->os_release, sizeof(out->os_release), release);
    }
#else
    struct utsname uts;
    if (uname(&uts) == 0) {
        capture_str(out->os_sysname, sizeof(out->os_sysname), uts.sysname);
        capture_str(out->os_machine, sizeof(out->os_machine), uts.machine);
        capture_str(out->os_release, sizeof(out->os_release), uts.release);
    }
#endif
}

int zcode_science_platform_logical_cores(void)
{
    uint32_t detected = platform_logical_cpu_count();
    return detected > INT_MAX ? INT_MAX : (int)detected;
}

void zcode_science_platform_capture(
    struct vcs_zcode_hardware_profile_v1 *out)
{
    capture_os(out);
    capture_cpuinfo(out);
    capture_timer_source(out);
    out->tsc_freq_hz = capture_invariant_tsc_hz();
}
