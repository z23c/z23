/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Private to engine/entry: the steps cli_main (main_cli_modes.c) delegates to
 * main_cli_dispatch.c — argv target-flag parsing and the field-selection
 * rendering of a raw RPC reply. Not a public interface. */
#ifndef ZCLASSIC23_ENGINE_ENTRY_MAIN_CLI_DISPATCH_H
#define ZCLASSIC23_ENGINE_ENTRY_MAIN_CLI_DISPATCH_H

#include "config/boot.h"
#include <stdbool.h>
#include <stddef.h>

enum { CLI_MAX_PARAMS = 128 };

/* Result of cli_parse_target_args: CLI_ARGS_OK, or a process exit code >= 0. */
enum { CLI_ARGS_OK = -1 };

/* What the operator named on argv: the target datadir/ports (the port
 * pointers name the file-scope targets cli_main's callees read), the network
 * and lane/profile choices, the method word and its parameters. */
struct cli_target_args {
    char *datadir;
    size_t datadir_cap;
    int *rpc_port;
    int *p2p_port;
    int *https_port;
    int *fs_port;
    bool datadir_set;
    bool rpcport_set;
    bool p2pport_set;
    bool httpsport_set;
    bool fsport_set;
    bool testnet_set;
    bool regtest_set;
    enum zcl_operator_lane operator_lane;
    enum zcl_runtime_profile runtime_profile;
    const char *method;
    const char **params;
    int nparams;
};

/* The raw RPC parameters left after a bare `field=` token is pulled out. */
struct cli_rpc_params {
    const char *storage[CLI_MAX_PARAMS];
    int count;
    const char *field_csv;
    bool saw_format_json;
};

int cli_parse_target_args(int argc, char **argv, struct cli_target_args *t);
void cli_apply_env_operator_lane(enum zcl_operator_lane *lane);
void cli_apply_env_rpcport(bool *rpcport_set, int *port);
const char *cli_canonical_method(const char *method);
void cli_split_rpc_params(const char *const *params, int nparams,
                          struct cli_rpc_params *out);
bool cli_brief_all_fields(const struct cli_rpc_params *params,
                          const char *method);
/* -1 when no field selection applies or nothing was printed and the caller
 * prints the full result;
 * otherwise the process exit code. The caller still owns resp. */
int cli_print_selected_fields(const char *resp, const char *method,
                              const char *field_csv, bool auto_all_fields);

#endif /* ZCLASSIC23_ENGINE_ENTRY_MAIN_CLI_DISPATCH_H */
