/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Accessor for proof_dependencies.def, the single table of what a lane, the
 * land queue and a proof generation need from the primary checkout.
 */
#ifndef ZCL_PROOF_DEPENDENCIES_H
#define ZCL_PROOF_DEPENDENCIES_H

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

enum {
    ZCL_DEP_PROOF = 1,
    ZCL_DEP_LAND = 2,
    ZCL_DEP_LANE = 4,
};

enum zcl_dep_host { ZCL_DEP_HOST_ANY, ZCL_DEP_HOST_LINUX, ZCL_DEP_HOST_POSIX };
enum zcl_dep_acquire { ZCL_DEP_COPY, ZCL_DEP_SCAN };

struct zcl_dep_row {
    const char *path;
    unsigned consumers;
    enum zcl_dep_host host;
    bool optional;
    enum zcl_dep_acquire acquire;
};

static inline const struct zcl_dep_row *zcl_dep_rows(size_t *count)
{
    static const struct zcl_dep_row rows[] = {
#define ZCL_DEP(path, who, host, opt, acq) { path, who, host, opt != 0, acq },
#include "proof_dependencies.def"
#undef ZCL_DEP
    };
    *count = sizeof(rows) / sizeof(rows[0]);
    return rows;
}

/* True when a proof on this host copies a row with the given host class. */
static inline bool zcl_dep_host_applies(enum zcl_dep_host host)
{
    switch (host) {
    case ZCL_DEP_HOST_LINUX:
#if defined(__linux__)
        return true;
#else
        return false;
#endif
    case ZCL_DEP_HOST_POSIX:
#if !defined(_WIN32)
        return true;
#else
        return false;
#endif
    default:
        return true;
    }
}

static inline const struct zcl_dep_row *zcl_dep_find(const char *path)
{
    size_t n;
    const struct zcl_dep_row *rows = zcl_dep_rows(&n);
    for (size_t i = 0; i < n; i++)
        if (strcmp(rows[i].path, path) == 0)
            return &rows[i];
    return NULL;
}

#endif
