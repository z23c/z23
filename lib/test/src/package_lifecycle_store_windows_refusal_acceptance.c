/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Native Windows acceptance: unqualified package-store mutations fail closed. */
#if defined(_WIN32)

#include "package_lifecycle_internal.h"

#include <stdio.h>
#include <string.h>
#include <windows.h>

static bool missing(const char *path)
{
    return GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES &&
           GetLastError() == ERROR_FILE_NOT_FOUND;
}

int main(void)
{
    char path[256];
    (void)snprintf(path, sizeof(path),
                   "build/package-store-refusal-%lu", GetCurrentProcessId());
    if (!missing(path)) return 1;

    const uint8_t byte = 0x5a;
    uint8_t root[32] = {0};
    struct pkgl_ctx ctx = {0};
    struct zcl_result made = pkgl_mkdir_p(path);
    struct zcl_result wrote = pkgl_write_atomic(path, &byte, 1);
    struct zcl_result removed = pkgl_rm_rf(path);
    struct zcl_result materialized =
        pkgl_materialize_package(&ctx, root, path);
    if (made.ok || wrote.ok || removed.ok || materialized.ok || !missing(path))
        return 2;

    puts("package_lifecycle_store_refusal_acceptance: PASS");
    return 0;
}

#else
typedef int package_lifecycle_store_windows_refusal_not_built;
#endif
