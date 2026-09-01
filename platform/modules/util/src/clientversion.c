/* Copyright (c) 2012-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "util/clientversion.h"
#include <stdio.h>

const char CLIENT_NAME[] = "ZClassic23";

/* Git commit ids intentionally stay outside the sovereign executable. If they
 * were baked as display text, the exact executable digest used by producer
 * receipts would still change with Git's SHA-1 history despite identical source
 * bytes. GitHub publication may attach that trace in an external sidecar. */
#ifndef ZCL_BUILD_SOURCE_ID
#define ZCL_BUILD_SOURCE_ID "unknown"
#endif
#ifndef ZCL_BUILD_CLEAN
#define ZCL_BUILD_CLEAN 0
#endif
#ifndef ZCL_BUILD_SOURCE_MUTATION
#define ZCL_BUILD_SOURCE_MUTATION "unknown"
#endif
#ifndef ZCL_BUILD_SOURCE_CAS_SHA3
#define ZCL_BUILD_SOURCE_CAS_SHA3 "unknown"
#endif

const char *zcl_build_commit(void)
{
    return "external";
}

const char *zcl_build_commit_full(void)
{
    return "external";
}

const char *zcl_build_source_id_sha256(void)
{
    return ZCL_BUILD_SOURCE_ID;
}

const char *zcl_build_source_mutation_sha256(void)
{
    return ZCL_BUILD_SOURCE_MUTATION;
}

const char *zcl_build_source_cas_sha3(void)
{
    return ZCL_BUILD_SOURCE_CAS_SHA3;
}

void FormatVersion(int nVersion, char *out, size_t out_size)
{
    int major = nVersion / 1000000;
    int minor = (nVersion / 10000) % 100;
    int rev = (nVersion / 100) % 100;
    int build = nVersion % 100;

    if (build < 25)
        snprintf(out, out_size, "%d.%d.%d-beta%d", major, minor, rev, build + 1);
    else if (build < 50)
        snprintf(out, out_size, "%d.%d.%d-rc%d", major, minor, rev, build - 24);
    else if (build == 50)
        snprintf(out, out_size, "%d.%d.%d", major, minor, rev);
    else
        snprintf(out, out_size, "%d.%d.%d-%d", major, minor, rev, build - 50);
}
