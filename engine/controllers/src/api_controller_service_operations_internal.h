/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCLASSIC23_API_CONTROLLER_SERVICE_OPERATIONS_INTERNAL_H
#define ZCLASSIC23_API_CONTROLLER_SERVICE_OPERATIONS_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>

struct json_value;

struct api_service_operation_contract {
    const char *service_name;
    const char *operation;
    const char *crud_capability;
    const char *status;
    const char *rest_method;
    const char *rest_route;
    const char *rpc_method;
    const char *input_contract;
    const char *output_schema;
    const char *authority;
    const char *effect;
    bool public_read;
    bool operator_private;
    bool destructive;
};

size_t api_service_operation_count(void);
const struct api_service_operation_contract *
api_service_operation_at(size_t index);
const char *api_service_operation_write_safety(
    const struct api_service_operation_contract *op);
const char *api_service_operation_agent_interface(
    const struct api_service_operation_contract *op);
void api_service_operation_json(
    struct json_value *obj,
    const struct api_service_operation_contract *op);

#endif /* ZCLASSIC23_API_CONTROLLER_SERVICE_OPERATIONS_INTERNAL_H */
