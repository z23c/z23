/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: dev.loop.span, a read-only leaf. Parses text, folds it with
 * zcl_loop_span_token, and returns that integer. The hot-swap body is this
 * file so a module rebuild changes the token the leaf returns.
 */

#include "controllers/loop_span.h"

#include "command/native_command.h"
#include "json/json.h"

#include <string.h>

void zcl_native_handle_loop_span(const struct zcl_command_request *request,
                                 struct zcl_command_reply *reply)
{
    const struct json_value *text_value = NULL;
    const char *text = "";
    size_t len = 0;
    if (!reply)
        return;
    if (request && request->input)
        text_value = json_get(request->input, "text");
    if (text_value && text_value->type == JSON_STR && json_get_str(text_value)) {
        text = json_get_str(text_value);
        len = strlen(text);
    }
    if (!json_push_kv_int(&reply->data, "token",
                          (int64_t)zcl_loop_span_token(text, len)))
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "LOOP_SPAN_REPLY",
                               "render", false, false,
                               "could not render the span token", "token");
}

#if defined(ZCL_HOTSWAP_GEN) || defined(ZCL_HOTSWAP_MODULE_GEN)
#define ZCL_HOTSWAP_PROBE_LEAF "dev.loop.span"
#include "hotswap/hotswap_register.h"
ZCL_HOTSWAP_LEAVES_BEGIN(loop_span)
ZCL_HOTSWAP_LEAF("dev.loop.span", zcl_native_handle_loop_span)
ZCL_HOTSWAP_LEAVES_END(loop_span)
#endif
