/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: operator-directed P2P addnode RPC, including fail-closed onion
 * parsing and the observable handoff into the outbound dial scheduler. */

#include "controllers/network_controller.h"
#include "controllers/strong_params.h"
#include "json/json.h"
#include "net/connman.h"
#include "net/netbase.h"
#include "net/onion_stream.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

bool network_addnode_rpc(const struct json_value *params, bool help,
                         struct json_value *result)
{
    RPC_HELP(help, result,
        "addnode \"node\" \"add|remove|onetry\"\n"
        "Attempts to add or remove a node from the addnode list.");

    struct rpc_params p;
    rpc_params_init(&p, params);
    rpc_params_expect(&p, 2, 2);
    const char *node_str = rpc_require_str(&p, 0, "node");
    const char *cmd = rpc_require_str(&p, 1, "command");
    if (rpc_params_invalid(&p)) { rpc_params_error(&p, result); return false; }

    struct connman *cm = rpc_net_get_connman();
    if (!cm) {
        json_set_str(result, "P2P not initialized");
        return false;
    }

    if (strcmp(cmd, "remove") != 0 && strcmp(cmd, "onetry") != 0 &&
        strcmp(cmd, "add") != 0) {
        json_set_str(result, "addnode command must be add, remove, or onetry");
        return false;
    }

    struct net_service svc;
    if (net_name_is_onion(node_str)) {
        /* Operator-directed onion peer: parse locally, NEVER resolve via
         * DNS and never fall back to clearnet. */
        if (!lookup_onion(node_str, &svc, cm->manager.default_port)) {
            json_set_str(result,
                "addnode: invalid .onion address (onion peers are parsed "
                "locally and never resolved via DNS)");
            return false;
        }
    } else if (!lookup_numeric(node_str, &svc, cm->manager.default_port)) {
        json_set_str(result,
            "addnode requires a numeric IP address (DNS names are not resolved)");
        return false;
    }
    struct net_address addr;
    net_address_init(&addr);
    addr.svc = svc;

    if (strcmp(cmd, "remove") == 0) {
        if (!connman_remove_addnode(cm, &addr)) {
            json_set_str(result, "addnode entry not found");
            return false;
        }
        json_set_null(result);
        return true;
    }

    if (strcmp(cmd, "onetry") == 0 || strcmp(cmd, "add") == 0) {
        char host[NET_ADDR_STR_MAX + 1];
        net_addr_to_string(&addr.svc.addr, host, sizeof(host));
        connman_add_seed_node(cm, host, addr.svc.port);

        if (net_name_is_onion(node_str)) {
            printf("Connecting to onion addnode %s\n", node_str);
            onion_stream_note_last_dial(node_str, "queued");
            LOG_INFO("net", "onion addnode RPC queued target=%s cmd=%s",
                     node_str, cmd);
        }

        /* Direct connect — don't rely on addrman random selection. */
        connman_open_connection(cm, &addr);
        json_set_null(result);
        return true;
    }

    json_set_str(result, "addnode command must be add, remove, or onetry");
    return false;
}
