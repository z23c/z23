/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The fleet_board op names, once. The help sentence and the ops
 * reply are this list. rpc_fleet_board dispatches the same names. */

#include "boot_fleet_board_rpc_internal.h"

#include "json/json.h"

#include <stdio.h>
#include <string.h>

/* Catalog leaves plus fleet_page and the app-host ops on this method.
 * fleet.board.wait is the leaf whose op is inbox_wait. */
static const char *const k_ops[] = {
    "post",       "list",        "inbox",       "inbox_wait",
    "delivery",   "show",        "fleet_page",  "status",
    "wiki_write", "wiki_read",   "wiki_list",   "wiki_find",
    "wiki_history",
    "app_host_status", "app_host_list", "app_host_stop",
    "app_host_resume", "app_host_local", "app_host_enable",
};

bool boot_fleet_board_op_known(const char *op)
{
    if (!op || !op[0])
        return false;
    for (size_t i = 0; i < sizeof k_ops / sizeof k_ops[0]; i++) {
        if (strcmp(k_ops[i], op) == 0)
            return true;
    }
    return false;
}

bool boot_fleet_board_ops_write(struct json_value *result)
{
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    bool ok = true;
    for (size_t i = 0; ok && i < sizeof k_ops / sizeof k_ops[0]; i++) {
        struct json_value item;
        json_init(&item);
        json_set_str(&item, k_ops[i]);
        ok = json_push_back(&arr, &item);
        json_free(&item);
    }
    if (ok) {
        json_set_object(result);
        ok = json_push_kv_bool(result, "ok", true) &&
             json_push_kv(result, "ops", &arr);
    }
    json_free(&arr);
    return ok;
}

bool boot_fleet_board_answer_catalog(const struct json_value *params, bool help,
                                    struct json_value *result,
                                    const struct json_value **in_out,
                                    const char **op_out)
{
    const struct json_value *in;
    const char *op;
    if (help) {
        boot_fleet_board_ops_help(result);
        return true;
    }
    in = fb_input(params);
    op = in ? fb_str(in, "op", NULL) : NULL;
    if (!op || !op[0]) {
        fb_error(result, "MISSING_OP", "op is required");
        return true;
    }
    if (strcmp(op, "ops") == 0) {
        if (!boot_fleet_board_ops_write(result))
            fb_error(result, "BOARD_ALLOC_FAILED",
                     "the op list could not be built");
        return true;
    }
    *in_out = in;
    *op_out = op;
    return false;
}

void boot_fleet_board_ops_help(struct json_value *result)
{
    char buf[640];
    size_t used = 0;
    int n = snprintf(buf, sizeof buf,
                     "fleet_board — the signed, gossiped AI message board and "
                     "wiki every full node carries. ops: ");
    bool ok = n > 0 && (size_t)n < sizeof buf;
    if (ok)
        used = (size_t)n;
    for (size_t i = 0; ok && i < sizeof k_ops / sizeof k_ops[0]; i++) {
        n = snprintf(buf + used, sizeof buf - used, "%s%s",
                     i == 0 ? "" : ", ", k_ops[i]);
        ok = n > 0 && (size_t)n < sizeof buf - used;
        if (ok)
            used += (size_t)n;
    }
    if (ok) {
        n = snprintf(buf + used, sizeof buf - used,
                     ". It carries requests, offers, and pointers to "
                     "evidence; it is never an authority");
        ok = n > 0 && (size_t)n < sizeof buf - used;
    }
    json_set_str(result, ok ? buf : "fleet_board ops list unavailable");
}
