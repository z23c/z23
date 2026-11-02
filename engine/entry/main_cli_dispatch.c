/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Steps of cli_main split out of engine/entry/main_cli_modes.c to bring
 * cli_main under the cyclomatic cap: argv target-flag parsing, the env
 * overrides, method-alias normalisation and the field-selection rendering of
 * a raw RPC reply. Behaviour is identical to the inline code they replace. */
#if !defined(ZCL_TESTING) || !defined(ZCL_RPC_COMPOSER_TEST)
#include "main_cli_dispatch.h"
#include "command/native_command.h"
#include "config/args.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { CLI_FLAG_NOT_MINE = -2 };

struct cli_port_slot {
    const char *prefix;
    int *value;
    bool *is_set;
};

static int cli_take_datadir_flag(const char *arg, struct cli_target_args *t)
{
    if (strncmp(arg, "-datadir=", 9) != 0)
        return CLI_FLAG_NOT_MINE;
    /* cli_validate_client_argv already refused an over-long value;
     * re-check so the copy never depends on that ordering. */
    if (cli_flag_value_overflows_path_buffer(arg))
        return cli_refuse_overlong_datadir(arg);
    snprintf(t->datadir, t->datadir_cap, "%s", arg + 9);
    t->datadir_set = true;
    return CLI_ARGS_OK;
}

static bool cli_take_port_flag(const char *arg, struct cli_target_args *t)
{
    const struct cli_port_slot slots[] = {
        {"-rpcport=", t->rpc_port, &t->rpcport_set},
        {"-port=", t->p2p_port, &t->p2pport_set},
        {"-httpsport=", t->https_port, &t->httpsport_set},
        {"-fsport=", t->fs_port, &t->fsport_set},
    };
    for (size_t i = 0; i < sizeof(slots) / sizeof(slots[0]); i++) {
        size_t len = strlen(slots[i].prefix);
        if (strncmp(arg, slots[i].prefix, len) == 0) {
            *slots[i].value = atoi(arg + len);
            *slots[i].is_set = true;
            return true;
        }
    }
    return false;
}

/* -operator-lane=NAME and -profile=NAME; 1 on a name neither knows. */
static int cli_take_named_flag(const char *arg, struct cli_target_args *t)
{
    if (strncmp(arg, "-operator-lane=", 15) == 0) {
        if (app_operator_lane_parse(arg + 15, &t->operator_lane))
            return CLI_ARGS_OK;
        fprintf(stderr, "Unknown operator lane: %s\n", arg + 15);
        return 1;
    }
    if (strncmp(arg, "-profile=", 9) == 0) {
        if (app_runtime_profile_parse(arg + 9, &t->runtime_profile))
            return CLI_ARGS_OK;
        fprintf(stderr, "Unknown runtime profile: %s\n", arg + 9);
        return 1;
    }
    return CLI_FLAG_NOT_MINE;
}

static bool cli_take_network_flag(const char *arg, struct cli_target_args *t)
{
    if (strcmp(arg, "-testnet") == 0) {
        t->testnet_set = true;
        return true;
    }
    if (strcmp(arg, "-regtest") == 0) {
        t->regtest_set = true;
        return true;
    }
    return false;
}

static int cli_take_flag(const char *arg, struct cli_target_args *t)
{
    int rc = cli_take_datadir_flag(arg, t);
    if (rc != CLI_FLAG_NOT_MINE)
        return rc;
    if (cli_take_port_flag(arg, t))
        return CLI_ARGS_OK;
    rc = cli_take_named_flag(arg, t);
    if (rc != CLI_FLAG_NOT_MINE)
        return rc;
    return cli_take_network_flag(arg, t) ? CLI_ARGS_OK : CLI_FLAG_NOT_MINE;
}

static int cli_take_positional(const char *arg, struct cli_target_args *t)
{
    if (!t->method) {
        t->method = arg;
        return CLI_ARGS_OK;
    }
    if (t->nparams >= CLI_MAX_PARAMS) {
        fprintf(stderr, "Too many RPC parameters (max %d)\n", CLI_MAX_PARAMS);
        return 1;
    }
    t->params[t->nparams++] = arg;
    return CLI_ARGS_OK;
}

/* Operator target flags are accepted before or after the method so
 * `z23 agent -datadir=... -rpcport=...` cannot accidentally query
 * the default service while an agent is trying to inspect a lane. */
int cli_parse_target_args(int argc, char **argv, struct cli_target_args *t)
{
    for (int i = 1; i < argc; i++) {
        int rc = cli_take_flag(argv[i], t);
        if (rc == CLI_FLAG_NOT_MINE)
            rc = cli_take_positional(argv[i], t);
        if (rc != CLI_ARGS_OK)
            return rc;
    }
    return CLI_ARGS_OK;
}

void cli_apply_env_operator_lane(enum zcl_operator_lane *lane)
{
    const char *env_lane = getenv("ZCL_OPERATOR_LANE");
    if (env_lane && env_lane[0] && !app_operator_lane_parse(env_lane, lane)) {
        fprintf(stderr, "Ignoring unknown ZCL_OPERATOR_LANE=%s\n", env_lane);
    }
}

/* Flags win over env: a caller that already saw -rpcport= skips this. */
void cli_apply_env_rpcport(bool *rpcport_set, int *port)
{
    if (*rpcport_set)
        return;
    const char *env_rp = getenv("ZCL_RPCPORT");
    if (!env_rp || !env_rp[0])
        return;
    int parsed = atoi(env_rp);
    if (parsed > 0 && parsed < 65536) {
        *port = parsed;
        *rpcport_set = true;
    } else {
        fprintf(stderr, "Ignoring invalid ZCL_RPCPORT=%s\n", env_rp);
    }
}

const char *cli_canonical_method(const char *method)
{
    if (strcmp(method, "--agent") == 0 || strcmp(method, "-agent") == 0)
        return "agent";
    if (strcmp(method, "--status") == 0 || strcmp(method, "-status") == 0)
        return "status";
    if (strcmp(method, "--summary") == 0 || strcmp(method, "-summary") == 0)
        return "summary";
    return method;
}

/* CLI UX contract: `z23 dumpstate <subsystem> field=a,b` (and, in
 * principle, any other raw RPC method) — pull a bare `field=` token out
 * of the forwarded RPC params before the call, then select just those
 * names out of the response afterward. `dumpstate`'s result nests the
 * subsystem's own fields under "state" (see diag_rpc_dumpstate_builtin);
 * every other method is selected at the top level of "result". */
void cli_split_rpc_params(const char *const *params, int nparams,
                          struct cli_rpc_params *out)
{
    out->count = 0;
    out->field_csv = NULL;
    out->saw_format_json = false;
    for (int i = 0; i < nparams; i++) {
        const char *p = params[i];
        if (p && strncmp(p, "field=", 6) == 0 && p[6] && !out->field_csv) {
            out->field_csv = p + 6;
            continue;
        }
        if (p && strcmp(p, "--format=json") == 0)
            out->saw_format_json = true;
        if (out->count < CLI_MAX_PARAMS)
            out->storage[out->count++] = p;
    }
}

/* CLI UX contract: ZCL_BRIEF=1 makes `dumpstate` default to the flat
 * field-selected rendering (every top-level key of the subsystem's own
 * `.state`) without typing `field=`; --format=json still escapes it. The
 * `status` is always compact native output; this is the raw-RPC-path twin for
 * dumpstate, which has no separate brief body to fetch). */
bool cli_brief_all_fields(const struct cli_rpc_params *params,
                          const char *method)
{
    const char *env_brief = getenv("ZCL_BRIEF");
    bool zcl_brief_on = env_brief && env_brief[0] && strcmp(env_brief, "0") != 0;
    return !params->field_csv && zcl_brief_on && !params->saw_format_json &&
           strcmp(method, "dumpstate") == 0;
}

/* ZCL_BRIEF auto-select: no field= was given, so select every
 * top-level key of `result` — same selection function, no
 * second data path. */
static void cli_join_top_level_keys(const struct json_value *result,
                                    char *out, size_t cap)
{
    size_t alen = 0;
    for (size_t k = 0; k < result->num_children; k++) {
        int an = snprintf(out + alen, cap - alen, "%s%s", alen ? "," : "",
                          result->keys[k]);
        if (an > 0 && (size_t)an < cap - alen)
            alen += (size_t)an;
    }
}

static const struct json_value *cli_fields_source(const struct json_value *root,
                                                  const char *method)
{
    const struct json_value *result = json_get(root, "result");
    if (result && strcmp(method, "dumpstate") == 0) {
        const struct json_value *state = json_get(result, "state");
        if (state && state->type == JSON_OBJ)
            result = state;
    }
    return result;
}

/* Prints the selection and returns -1, or returns the exit code of an
 * explicit field= that selected nothing. *handled says whether output went
 * out. */
static int cli_render_root_fields(const struct json_value *root,
                                  const char *method, const char *field_csv,
                                  bool *handled)
{
    const struct json_value *result = cli_fields_source(root, method);
    char all_fields[2048] = "";
    const char *use_csv = field_csv;
    if (!use_csv && result && result->type == JSON_OBJ) {
        cli_join_top_level_keys(result, all_fields, sizeof(all_fields));
        use_csv = all_fields;
    }
    char sel[ZCL_COMMAND_LIST_BUDGET + 1];
    char selerr[320];
    if (result && use_csv && use_csv[0] &&
        zcl_native_render_field_selection(result, use_csv, sel, sizeof(sel),
                                          selerr, sizeof(selerr))) {
        fputs(sel, stdout);
        *handled = true;
    } else if (field_csv) {
        /* Only an explicit field= failure is a hard error; an
         * auto-select with nothing to select from just falls
         * through to the normal full-result print below. */
        fprintf(stderr, "error=UNKNOWN_FIELD detail=%s try=%s\n",
               result ? selerr : "this method returned no selectable "
                                  "result",
               method);
        return ZCL_COMMAND_EXIT_INVALID;
    }
    return -1;
}

int cli_print_selected_fields(const char *resp, const char *method,
                              const char *field_csv, bool auto_all_fields)
{
    if (!field_csv && !auto_all_fields)
        return -1;
    struct json_value root;
    bool handled = false;
    if (json_read(&root, resp, strlen(resp)) && root.type == JSON_OBJ) {
        int rc = cli_render_root_fields(&root, method, field_csv, &handled);
        if (rc >= 0) {
            json_free(&root);
            return rc;
        }
    }
    json_free(&root);
    if (handled)
        return 0;
    if (field_csv) {
        fprintf(stderr,
               "error=UNKNOWN_FIELD detail=response did not parse "
               "try=%s\n", method);
        return ZCL_COMMAND_EXIT_INVALID;
    }
    /* auto_all_fields found nothing to flatten (e.g. malformed
     * response) — fall through to the normal full print so ZCL_BRIEF
     * never hides a real error behind a silent no-op. */
    return -1;
}
#endif
