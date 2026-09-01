/* Copyright (c) 2016 The Zcash developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "platform/time_compat.h"
#include "rpc/async_rpc_operation.h"
#include "core/random.h"
#include "core/utiltime.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

static void generate_uuid(char *out, size_t out_size)
{
    unsigned char bytes[16];
    GetRandBytes(bytes, 16);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    snprintf(out, out_size,
        "opid-%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15]);
}

void async_op_init(struct async_rpc_operation *op)
{
    memset(op, 0, sizeof(*op));
    generate_uuid(op->id, sizeof(op->id));
    op->creation_time = (int64_t)platform_time_wall_time_t();
    atomic_store(&op->state, ASYNC_OP_READY);
    zcl_mutex_init(&op->lock);
    json_init(&op->result);
    op->main_fn = async_op_default_main;
    op->cancel_fn = NULL;
    op->user_data = NULL;
}

void async_op_free(struct async_rpc_operation *op)
{
    json_free(&op->result);
    zcl_mutex_destroy(&op->lock);
}

void async_op_cancel(struct async_rpc_operation *op)
{
    if (async_op_is_ready(op)) {
        atomic_store(&op->state, ASYNC_OP_CANCELLED);
    }
    if (op->cancel_fn)
        op->cancel_fn(op);
}

enum async_op_status async_op_get_state(const struct async_rpc_operation *op)
{
    return atomic_load(&op->state);
}

const char *async_op_state_str(enum async_op_status s)
{
    switch (s) {
    case ASYNC_OP_READY: return "queued";
    case ASYNC_OP_EXECUTING: return "executing";
    case ASYNC_OP_CANCELLED: return "cancelled";
    case ASYNC_OP_FAILED: return "failed";
    case ASYNC_OP_SUCCESS: return "success";
    }
    return "unknown";
}

bool async_op_is_cancelled(const struct async_rpc_operation *op)
{
    return async_op_get_state(op) == ASYNC_OP_CANCELLED;
}

bool async_op_is_ready(const struct async_rpc_operation *op)
{
    return async_op_get_state(op) == ASYNC_OP_READY;
}

bool async_op_is_failed(const struct async_rpc_operation *op)
{
    return async_op_get_state(op) == ASYNC_OP_FAILED;
}

bool async_op_is_success(const struct async_rpc_operation *op)
{
    return async_op_get_state(op) == ASYNC_OP_SUCCESS;
}

void async_op_set_state(struct async_rpc_operation *op, enum async_op_status s)
{
    atomic_store(&op->state, s);
}

void async_op_set_error(struct async_rpc_operation *op, int code,
                        const char *message)
{
    zcl_mutex_lock(&op->lock);
    op->error_code = code;
    snprintf(op->error_message, sizeof(op->error_message), "%s", message);
    zcl_mutex_unlock(&op->lock);
}

void async_op_set_result(struct async_rpc_operation *op,
                         const struct json_value *v)
{
    zcl_mutex_lock(&op->lock);
    json_free(&op->result);
    json_copy(&op->result, v);
    zcl_mutex_unlock(&op->lock);
}

void async_op_start_clock(struct async_rpc_operation *op)
{
    zcl_mutex_lock(&op->lock);
    op->start_time_us = GetTimeMicros();
    zcl_mutex_unlock(&op->lock);
}

void async_op_stop_clock(struct async_rpc_operation *op)
{
    zcl_mutex_lock(&op->lock);
    op->end_time_us = GetTimeMicros();
    zcl_mutex_unlock(&op->lock);
}

void async_op_get_error_json(const struct async_rpc_operation *op,
                             struct json_value *out)
{
    json_init(out);
    if (!async_op_is_failed(op)) return;

    zcl_mutex_lock((zcl_mutex_t *)&op->lock);
    json_set_object(out);
    json_push_kv_int(out, "code", op->error_code);
    json_push_kv_str(out, "message", op->error_message);
    zcl_mutex_unlock((zcl_mutex_t *)&op->lock);
}

void async_op_get_result_json(const struct async_rpc_operation *op,
                              struct json_value *out)
{
    json_init(out);
    if (!async_op_is_success(op)) return;

    zcl_mutex_lock((zcl_mutex_t *)&op->lock);
    json_copy(out, &op->result);
    zcl_mutex_unlock((zcl_mutex_t *)&op->lock);
}

void async_op_get_status_json(const struct async_rpc_operation *op,
                              struct json_value *out)
{
    json_init(out);
    json_set_object(out);

    enum async_op_status status = async_op_get_state(op);
    json_push_kv_str(out, "id", op->id);
    json_push_kv_str(out, "status", async_op_state_str(status));
    json_push_kv_int(out, "creation_time", op->creation_time);

    if (status == ASYNC_OP_FAILED) {
        struct json_value err;
        async_op_get_error_json(op, &err);
        if (err.type == JSON_OBJ)
            json_push_kv(out, "error", &err);
        json_free(&err);
    }

    if (status == ASYNC_OP_SUCCESS) {
        struct json_value res;
        async_op_get_result_json(op, &res);
        if (res.type != JSON_NULL)
            json_push_kv(out, "result", &res);

        zcl_mutex_lock((zcl_mutex_t *)&op->lock);
        double elapsed = (double)(op->end_time_us - op->start_time_us) / 1e6;
        zcl_mutex_unlock((zcl_mutex_t *)&op->lock);
        json_push_kv_real(out, "execution_secs", elapsed);
        json_free(&res);
    }
}

void async_op_default_main(struct async_rpc_operation *op)
{
    if (async_op_is_cancelled(op)) return;
    async_op_set_state(op, ASYNC_OP_EXECUTING);
    async_op_start_clock(op);
    async_op_stop_clock(op);
    struct json_value v;
    json_init(&v);
    json_set_str(&v, "default result");
    async_op_set_result(op, &v);
    json_free(&v);
    async_op_set_state(op, ASYNC_OP_SUCCESS);
}
