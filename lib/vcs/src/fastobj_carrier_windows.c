/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: refuse unqualified fast-object carrier operations on Windows. */

#include "vcs/fastobj_carrier.h"

#if defined(_WIN32)
#include <stdio.h>

static bool fastobj_carrier_windows_refused(char *err, size_t err_cap)
{
    if (err && err_cap)
        (void)snprintf(err, err_cap,
                       "fastobj carrier disabled on native Windows until "
                       "sandboxed immutable cache admission is qualified");
    return false;
}

bool vcs_fastobj_carrier_export(const char *cache_dir,
                                struct vcs_package_store *store,
                                uint8_t root_out[32],
                                struct vcs_fastobj_carrier_stats *stats,
                                char *err, size_t err_cap)
{
    (void)cache_dir; (void)store; (void)root_out; (void)stats;
    return fastobj_carrier_windows_refused(err, err_cap);
}

bool vcs_fastobj_carrier_fetch(struct vcs_package_store *dst,
                               struct vcs_package_store *src,
                               const uint8_t root[32],
                               struct vcs_fastobj_carrier_stats *stats,
                               char *err, size_t err_cap)
{
    (void)dst; (void)src; (void)root; (void)stats;
    return fastobj_carrier_windows_refused(err, err_cap);
}

bool vcs_fastobj_carrier_verify(struct vcs_package_store *store,
                                const uint8_t root[32],
                                char *err, size_t err_cap)
{
    (void)store; (void)root;
    return fastobj_carrier_windows_refused(err, err_cap);
}

bool vcs_fastobj_carrier_admit(const char *cache_dir,
                               struct vcs_package_store *store,
                               const uint8_t root[32],
                               struct vcs_fastobj_carrier_stats *stats,
                               char *err, size_t err_cap)
{
    (void)cache_dir; (void)store; (void)root; (void)stats;
    return fastobj_carrier_windows_refused(err, err_cap);
}
#else
typedef int fastobj_carrier_windows_translation_unit_nonempty;
#endif
