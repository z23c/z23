/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Compile-time unflagged targets for the release and development CLI lanes.
 */

#ifndef ZCL_CONFIG_CLI_LANE_DEFAULTS_H
#define ZCL_CONFIG_CLI_LANE_DEFAULTS_H

#include <stddef.h>
#include <stdio.h>

#ifdef ZCL_DEV_BUILD
#define ZCL_CLI_DEFAULT_DATADIR ".zclassic-c23-dev"
#define ZCL_CLI_DEFAULT_RPC_PORT 18252
#define ZCL_CLI_DEFAULT_UNIT "zcl23-dev"
#else
#define ZCL_CLI_DEFAULT_DATADIR ".zclassic-c23"
#define ZCL_CLI_DEFAULT_RPC_PORT 18232
#define ZCL_CLI_DEFAULT_UNIT "zclassic23"
#endif

static inline void zcl_cli_lane_default_datadir(char *out, size_t out_size,
                                                 const char *home)
{
    if (home)
        (void)snprintf(out, out_size, "%s/%s", home,
                       ZCL_CLI_DEFAULT_DATADIR);
    else
        (void)snprintf(out, out_size, "%s", ZCL_CLI_DEFAULT_DATADIR);
}

#endif
