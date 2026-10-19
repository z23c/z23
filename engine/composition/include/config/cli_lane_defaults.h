/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Compile-time unflagged targets for the release and development CLI lanes.
 */

#ifndef ZCL_CONFIG_CLI_LANE_DEFAULTS_H
#define ZCL_CONFIG_CLI_LANE_DEFAULTS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef ZCL_DEV_BUILD
#define ZCL_CLI_DEFAULT_DATADIR ".zclassic-c23-dev"
#define ZCL_CLI_DEFAULT_RPC_PORT 18252
#define ZCL_CLI_DEFAULT_UNIT "zcl23-dev"
#else
#define ZCL_CLI_DEFAULT_DATADIR ".zclassic-c23"
#define ZCL_CLI_DEFAULT_RPC_PORT 18232
#define ZCL_CLI_DEFAULT_UNIT "z23-node"
#endif

static inline bool zcl_cli_lane_default_datadir(char *out, size_t out_size,
                                                 const char *home)
{
    int n;
    if (home)
        n = snprintf(out, out_size, "%s/%s", home,
                     ZCL_CLI_DEFAULT_DATADIR);
    else
        n = snprintf(out, out_size, "%s", ZCL_CLI_DEFAULT_DATADIR);
    /* false when the path did not fit: out holds a truncated prefix that
     * can name another node's directory and must not be used. */
    return n >= 0 && (size_t)n < out_size;
}

/* Settle the operator-target datadir once the argv flags are parsed. An
 * env-named ZCL_DATADIR (env_datadir, the caller reads the variable) is an
 * operator-named target (sets *datadir_set,
 * like a -datadir= flag); with no flag or env target the HOME-derived
 * default must have fit (default_fit from zcl_cli_lane_default_datadir).
 * Every refusal prints error=DATADIR_TOO_LONG and returns false before any
 * cookie or config file is opened: a chopped prefix can name another
 * node's directory. */
static inline bool zcl_cli_lane_settle_datadir(char *datadir, size_t cap,
                                               bool *datadir_set,
                                               bool default_fit,
                                               const char *env_datadir)
{
    const char *env_dd = *datadir_set ? NULL : env_datadir;
    if (env_dd && env_dd[0]) {
        int n = snprintf(datadir, cap, "%s", env_dd);
        if (n < 0 || (size_t)n >= cap) {
            fprintf(stderr, "error=DATADIR_TOO_LONG detail=ZCL_DATADIR "
                    "exceeds the %zu-byte path buffer - refusing (no "
                    "silent truncation): a chopped cookie path can "
                    "authenticate against the wrong node\n", cap);
            return false;
        }
        *datadir_set = true;
    }
    if (!*datadir_set && !default_fit) {
        fprintf(stderr, "error=DATADIR_TOO_LONG detail=the default datadir "
                "derived from HOME exceeds the %zu-byte path buffer - "
                "refusing (no silent truncation): a chopped cookie path "
                "can authenticate against the wrong node try=use a "
                "shorter HOME or name -datadir=DIR\n", cap);
        return false;
    }
    return true;
}

/* Local lab feedback and guest boot do not need service defaults. */
static inline bool zcl_cli_skips_service_lookup(const char *method,
                                                const char *const *params,
                                                int nparams)
{
    if (method == NULL)
        return false;
    if (strcmp(method, "lab.run") == 0 ||
        strcmp(method, "lab.test") == 0 ||
        strcmp(method, "lab.show") == 0)
        return true;
    if (strcmp(method, "lab") == 0 && params != NULL && nparams > 0)
        return strcmp(params[0], "run") == 0 ||
               strcmp(params[0], "test") == 0 ||
               strcmp(params[0], "show") == 0;
    if (params == NULL || nparams < 3)
        return false;
    if (strcmp(method, "dev") != 0)
        return false;
    if (strcmp(params[0], "app") != 0)
        return false;
    if (strcmp(params[1], "machine") != 0)
        return false;
    return strcmp(params[2], "boot") == 0;
}

/* Local feedback skips the user unit. The test switch skips every lookup.
 * The bound argv belongs to the caller; this keeps no process state. */
static inline bool zcl_cli_service_lookup_blocked(const char *method,
                                                  const char *const *params,
                                                  int nparams)
{
    if (getenv("ZCL_CLI_TEST_NO_SERVICE_LOOKUP") != NULL)
        return true;
    return zcl_cli_skips_service_lookup(method, params, nparams);
}

#endif
