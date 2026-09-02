/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Native `z23 dev fleet` command envelope. */

#include "command/native_dev_fleet.h"
#include "command/native_devagent.h"

#include "controllers/shop_native_handler.h"
#include "json/json.h"

#include <stdio.h>

void zcl_native_handle_dev_fleet(const struct zcl_command_request *request,
                                 struct zcl_command_reply *reply)
{
    (void)request;
    char root[4096], why[512];
    if (!zcl_devagent_checkout_root(NULL, root, sizeof(root))) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED, "NOT_IN_A_CHECKOUT",
                               "resolve", false, false,
                               "no Z23 checkout root exists above the current directory",
                               "dev.fleet reads only local Git refs and lint receipts");
        (void)snprintf(reply->error.next_action,
                       sizeof(reply->error.next_action),
                       "cd into a Z23 checkout, then rerun: z23 dev fleet");
        reply->error.human_action_required = true;
        return;
    }
    if (!zcl_dev_fleet_collect(root, &reply->data, why, sizeof(why))) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED,
                               "FLEET_INVENTORY_FAILED", "inspect", false,
                               false, why,
                               "Git refs, worktree metadata, or lint receipts were invalid");
        (void)snprintf(reply->error.next_action,
                       sizeof(reply->error.next_action),
                       "repair the named Git or receipt problem, then rerun: z23 dev fleet");
        return;
    }
}
