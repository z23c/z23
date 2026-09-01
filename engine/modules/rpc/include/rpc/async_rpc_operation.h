/* Copyright (c) 2016 The Zcash developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_ASYNC_RPC_OPERATION_H
#define ZCL_ASYNC_RPC_OPERATION_H

#include "json/json.h"
#include "util/sync.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>

#define ASYNC_OP_ID_SIZE 64

enum async_op_status {
    ASYNC_OP_READY = 0,
    ASYNC_OP_EXECUTING,
    ASYNC_OP_CANCELLED,
    ASYNC_OP_FAILED,
    ASYNC_OP_SUCCESS
};

struct async_rpc_operation;

typedef void (*async_op_main_fn)(struct async_rpc_operation *op);
typedef void (*async_op_cancel_fn)(struct async_rpc_operation *op);

struct async_rpc_operation {
    char id[ASYNC_OP_ID_SIZE];
    int64_t creation_time;
    _Atomic enum async_op_status state;
    zcl_mutex_t lock;
    struct json_value result;
    int error_code;
    char error_message[256];
    int64_t start_time_us;
    int64_t end_time_us;
    async_op_main_fn main_fn;
    async_op_cancel_fn cancel_fn;
    void *user_data;
};

void async_op_init(struct async_rpc_operation *op);
void async_op_free(struct async_rpc_operation *op);
void async_op_cancel(struct async_rpc_operation *op);

enum async_op_status async_op_get_state(const struct async_rpc_operation *op);
const char *async_op_state_str(enum async_op_status s);
bool async_op_is_cancelled(const struct async_rpc_operation *op);
bool async_op_is_ready(const struct async_rpc_operation *op);
bool async_op_is_failed(const struct async_rpc_operation *op);
bool async_op_is_success(const struct async_rpc_operation *op);

void async_op_set_state(struct async_rpc_operation *op, enum async_op_status s);
void async_op_set_error(struct async_rpc_operation *op, int code,
                        const char *message);
void async_op_set_result(struct async_rpc_operation *op,
                         const struct json_value *v);
void async_op_start_clock(struct async_rpc_operation *op);
void async_op_stop_clock(struct async_rpc_operation *op);

void async_op_get_status_json(const struct async_rpc_operation *op,
                              struct json_value *out);
void async_op_get_error_json(const struct async_rpc_operation *op,
                             struct json_value *out);
void async_op_get_result_json(const struct async_rpc_operation *op,
                              struct json_value *out);

void async_op_default_main(struct async_rpc_operation *op);

#endif
