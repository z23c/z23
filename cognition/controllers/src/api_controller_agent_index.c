/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Agent-facing fragments of the self-describing REST API index. */

#include "api_controller_internal.h"

#include "controllers/agent_controller.h"

#include "json/json.h"

void api_rest_index_cli_json(struct json_value *cli)
{
    json_set_object(cli);
    agent_push_contract_api_cli_fields_json(cli);
}
