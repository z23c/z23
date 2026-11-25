/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: expose a boot-scoped invalidation identity. */
#include "platform/os_boot.h"
#include <stdio.h>
#include <string.h>
#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

static bool os_proc_uuid_digit(char *c, bool *nonzero)
{
    if (*c >= 'A' && *c <= 'F') *c = (char)(*c + ('a' - 'A'));
    if (!((*c >= '0' && *c <= '9') || (*c >= 'a' && *c <= 'f'))) return false;
    if (*c != '0') *nonzero = true;
    return true;
}

bool os_proc_boot_id_normalize(const char *text, size_t len, char out[37])
{
    char normalized[37];
    bool nonzero = false;
    if (!out) return false;
    if (!text || len != 36) goto invalid;
    for (size_t i = 0; i < 36; i++) {
        char c = text[i];
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (c != '-') goto invalid;
        } else {
            if (!os_proc_uuid_digit(&c, &nonzero)) goto invalid;
        }
        normalized[i] = c;
    }
    if (!nonzero) goto invalid;
    normalized[36] = '\0';
    memcpy(out, normalized, sizeof(normalized));
    return true;
invalid:
    out[0] = '\0';
    return false;
}

bool os_proc_boot_id(char out[37])
{
    if (!out) return false;
    out[0] = '\0';
#if defined(__linux__)
    char buf[39];
    FILE *f = fopen("/proc/sys/kernel/random/boot_id", "rb");
    if (!f) return false;
    size_t n = fread(buf, 1, sizeof(buf), f);
    bool ok = !ferror(f) && n == 37 && buf[36] == '\n' &&
              os_proc_boot_id_normalize(buf, 36, out);
    if (fclose(f) != 0) ok = false;
    if (!ok) out[0] = '\0';
    return ok;
#elif defined(__APPLE__)
    char buf[38];
    size_t n = sizeof(buf);
    return sysctlbyname("kern.bootsessionuuid", buf, &n, NULL, 0) == 0 &&
           n == 37 && buf[36] == '\0' && os_proc_boot_id_normalize(buf, 36, out);
#else
    return false;
#endif
}
