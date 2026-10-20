/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: plugin host-call frame codec, method table and capability-gated
 * dispatcher. Pure computation over caller buffers: no node, file, socket or
 * clock access. */

#include "plugin/plugin_hostcall.h"

#include "base/serialize_le.h"
#include "plugin/plugin_store.h"

#include <string.h>

#define PH_MAX_KEY 255u /* key length is one byte */

static const struct plugin_hostcall_method_info k_methods[PLUGIN_HOSTCALL_METHOD_COUNT] = {
    { PLUGIN_HOSTCALL_M_CHAIN_TIP, "chain.tip", PLUGIN_HOSTCALL_CAP_CHAIN_READ, 0, 0, false },
    { PLUGIN_HOSTCALL_M_CHAIN_HEADER_BY_HEIGHT, "chain.header_by_height",
      PLUGIN_HOSTCALL_CAP_CHAIN_READ, 4, 4, false },
    { PLUGIN_HOSTCALL_M_STATE_GET, "state.get", PLUGIN_HOSTCALL_CAP_STATE,
      2, 1 + PH_MAX_KEY, false },
    { PLUGIN_HOSTCALL_M_STATE_PUT, "state.put", PLUGIN_HOSTCALL_CAP_STATE,
      3, PLUGIN_HOSTCALL_MAX_PAYLOAD, false },
    { PLUGIN_HOSTCALL_M_EVENT_APPEND, "event.append", PLUGIN_HOSTCALL_CAP_EVENTS,
      3, PLUGIN_HOSTCALL_MAX_PAYLOAD, false },
    /* Logging needs no grant: a confined plugin already writes its own stderr. */
    { PLUGIN_HOSTCALL_M_LOG_WRITE, "log.write", PLUGIN_HOSTCALL_CAP_NONE, 2, 1025, false },
    { PLUGIN_HOSTCALL_M_WALLET_REQUEST, "wallet.request", PLUGIN_HOSTCALL_CAP_WALLET,
      0, PLUGIN_HOSTCALL_MAX_PAYLOAD, true },
};

static const struct {
    const char *name;
    const char *action;
} k_status[] = {
    [PLUGIN_HOSTCALL_OK] = { "PLUGIN_HOSTCALL_OK", "none" },
    [PLUGIN_HOSTCALL_ERR_ARGUMENT] = { "PLUGIN_HOSTCALL_ARGUMENT", "pass non-null buffers with a size" },
    [PLUGIN_HOSTCALL_ERR_TRUNCATED] = { "PLUGIN_HOSTCALL_TRUNCATED", "read more bytes from the socket" },
    [PLUGIN_HOSTCALL_ERR_OVERSIZE] = { "PLUGIN_HOSTCALL_OVERSIZE", "send a frame within the maximum size" },
    [PLUGIN_HOSTCALL_ERR_UNDERSIZE] = { "PLUGIN_HOSTCALL_UNDERSIZE", "send a frame with the full header" },
    [PLUGIN_HOSTCALL_ERR_VERSION] = { "PLUGIN_HOSTCALL_VERSION", "speak host-call protocol version 1" },
    [PLUGIN_HOSTCALL_ERR_KIND] = { "PLUGIN_HOSTCALL_KIND", "send a request or reply frame" },
    [PLUGIN_HOSTCALL_ERR_METHOD] = { "PLUGIN_HOSTCALL_METHOD", "call a method in the method table" },
    [PLUGIN_HOSTCALL_ERR_PAYLOAD] = { "PLUGIN_HOSTCALL_PAYLOAD", "send a payload within the method's bounds" },
    [PLUGIN_HOSTCALL_DENIED] = { "PLUGIN_HOSTCALL_DENIED", "grant the capability in the plugin manifest and republish" },
    [PLUGIN_HOSTCALL_ERR_PLANNED] = { "PLUGIN_HOSTCALL_PLANNED", "the method is not built yet" },
    [PLUGIN_HOSTCALL_ERR_UNAVAILABLE] = { "PLUGIN_HOSTCALL_UNAVAILABLE", "the host has no handler for the method" },
    [PLUGIN_HOSTCALL_ERR_HANDLER] = { "PLUGIN_HOSTCALL_HANDLER", "retry the request or read the host log" },
    [PLUGIN_HOSTCALL_ERR_BUFFER] = { "PLUGIN_HOSTCALL_BUFFER", "pass a larger output buffer" },
};

const char *plugin_hostcall_status_code(enum plugin_hostcall_status status)
{
    if ((unsigned)status >= sizeof k_status / sizeof k_status[0])
        return "PLUGIN_HOSTCALL_UNKNOWN";
    return k_status[status].name;
}

const char *plugin_hostcall_status_next_action(enum plugin_hostcall_status status)
{
    if ((unsigned)status >= sizeof k_status / sizeof k_status[0])
        return "report the unknown status";
    return k_status[status].action;
}

uint32_t plugin_hostcall_cap_from_name(const char *name)
{
    if (name == nullptr)
        return 0;
    if (strcmp(name, "chain.read") == 0)
        return PLUGIN_HOSTCALL_CAP_CHAIN_READ;
    if (strcmp(name, "state") == 0)
        return PLUGIN_HOSTCALL_CAP_STATE;
    if (strcmp(name, "events.append") == 0)
        return PLUGIN_HOSTCALL_CAP_EVENTS;
    if (strcmp(name, "wallet.request") == 0)
        return PLUGIN_HOSTCALL_CAP_WALLET;
    return 0;
}

uint32_t plugin_hostcall_grants_from_manifest(unsigned manifest_capabilities)
{
    uint32_t granted = 0;
    for (unsigned i = 0; i < 8 * sizeof manifest_capabilities; i++) {
        const char *name = plugin_capability_name(i);
        if (name == nullptr)
            break;
        if (manifest_capabilities & (1u << i))
            granted |= plugin_hostcall_cap_from_name(name);
    }
    return granted;
}

const struct plugin_hostcall_method_info *plugin_hostcall_method_by_id(uint16_t id)
{
    if (id < 1 || id > PLUGIN_HOSTCALL_METHOD_COUNT)
        return nullptr;
    return &k_methods[id - 1];
}

const struct plugin_hostcall_method_info *plugin_hostcall_method_by_name(const char *name)
{
    if (name == nullptr)
        return nullptr;
    for (size_t i = 0; i < PLUGIN_HOSTCALL_METHOD_COUNT; i++)
        if (strcmp(k_methods[i].name, name) == 0)
            return &k_methods[i];
    return nullptr;
}

const struct plugin_hostcall_method_info *plugin_hostcall_method_at(size_t index)
{
    return index < PLUGIN_HOSTCALL_METHOD_COUNT ? &k_methods[index] : nullptr;
}
[[nodiscard]] enum plugin_hostcall_status plugin_hostcall_encode(

    const struct plugin_hostcall_frame *frame, uint8_t *out, size_t out_cap,
    size_t *written)
{
    if (written != nullptr)
        *written = 0;
    if (frame == nullptr || out == nullptr || written == nullptr)
        return PLUGIN_HOSTCALL_ERR_ARGUMENT;
    if (frame->kind != PLUGIN_HOSTCALL_KIND_REQUEST && frame->kind != PLUGIN_HOSTCALL_KIND_REPLY)
        return PLUGIN_HOSTCALL_ERR_KIND;
    if (frame->payload_len > PLUGIN_HOSTCALL_MAX_PAYLOAD)
        return PLUGIN_HOSTCALL_ERR_OVERSIZE;
    if (frame->payload == nullptr && frame->payload_len != 0)
        return PLUGIN_HOSTCALL_ERR_ARGUMENT;
    size_t total = PLUGIN_HOSTCALL_HEADER_BYTES + frame->payload_len;
    if (out_cap < total)
        return PLUGIN_HOSTCALL_ERR_BUFFER;
    zcl_write_u32_be(out, (uint32_t)(PLUGIN_HOSTCALL_BODY_FIXED + frame->payload_len));
    out[4] = PLUGIN_HOSTCALL_VERSION;
    out[5] = frame->kind;
    zcl_write_u32_be(out + 6, frame->id);
    uint8_t code_be[4];
    zcl_write_u32_be(code_be, frame->code);
    memcpy(out + 10, code_be + 2, 2);
    if (frame->payload_len > 0)
        memmove(out + PLUGIN_HOSTCALL_HEADER_BYTES, frame->payload, frame->payload_len);
    *written = total;
    return PLUGIN_HOSTCALL_OK;
}

[[nodiscard]] enum plugin_hostcall_status plugin_hostcall_decode(
    const uint8_t *buf, size_t len, struct plugin_hostcall_frame *frame,
    size_t *consumed)
{
    if (consumed != nullptr)
        *consumed = 0;
    if (buf == nullptr || frame == nullptr || consumed == nullptr)
        return PLUGIN_HOSTCALL_ERR_ARGUMENT;
    if (len < 4)
        return PLUGIN_HOSTCALL_ERR_TRUNCATED;
    uint32_t body = zcl_read_u32_be(buf);
    /* Judge the declared length before waiting for the bytes it promises, so
     * a hostile prefix is refused at once instead of stalling the reader. */
    if (body < PLUGIN_HOSTCALL_BODY_FIXED)
        return PLUGIN_HOSTCALL_ERR_UNDERSIZE;
    if (body - PLUGIN_HOSTCALL_BODY_FIXED > PLUGIN_HOSTCALL_MAX_PAYLOAD)
        return PLUGIN_HOSTCALL_ERR_OVERSIZE;
    if (len < PLUGIN_HOSTCALL_HEADER_BYTES)
        return PLUGIN_HOSTCALL_ERR_TRUNCATED;
    if (buf[4] != PLUGIN_HOSTCALL_VERSION)
        return PLUGIN_HOSTCALL_ERR_VERSION;
    if (buf[5] != PLUGIN_HOSTCALL_KIND_REQUEST && buf[5] != PLUGIN_HOSTCALL_KIND_REPLY)
        return PLUGIN_HOSTCALL_ERR_KIND;
    size_t total = 4 + (size_t)body;
    if (len < total)
        return PLUGIN_HOSTCALL_ERR_TRUNCATED;
    frame->kind = buf[5];
    frame->id = zcl_read_u32_be(buf + 6);
    frame->code = (uint16_t)(zcl_read_u32_be(buf + 8) & 0xFFFFu); /* id tail, then code */
    frame->payload_len = total - PLUGIN_HOSTCALL_HEADER_BYTES;
    frame->payload = buf + PLUGIN_HOSTCALL_HEADER_BYTES;
    *consumed = total;
    return PLUGIN_HOSTCALL_OK;
}

/* Reply with a status and an optional payload. */
static enum plugin_hostcall_status reply_with(
    uint32_t id, enum plugin_hostcall_status status, const uint8_t *payload,
    size_t payload_len, uint8_t *reply, size_t reply_cap, size_t *reply_len)
{
    struct plugin_hostcall_frame r = {
        .kind = PLUGIN_HOSTCALL_KIND_REPLY, .id = id, .code = (uint16_t)status,
        .payload = payload, .payload_len = payload_len,
    };
    enum plugin_hostcall_status e = plugin_hostcall_encode(&r, reply, reply_cap, reply_len);
    return e == PLUGIN_HOSTCALL_OK ? status : e;
}

/* The refusal for a known method, or OK to proceed to the handler. */
static enum plugin_hostcall_status gate(const struct plugin_hostcall_method_info *m,
                                        size_t payload_len, uint32_t granted)
{
    if (m->planned)
        return PLUGIN_HOSTCALL_ERR_PLANNED;
    if (m->capability != PLUGIN_HOSTCALL_CAP_NONE && (granted & m->capability) != m->capability)
        return PLUGIN_HOSTCALL_DENIED;
    if (payload_len < m->min_payload || payload_len > m->max_payload)
        return PLUGIN_HOSTCALL_ERR_PAYLOAD;
    return PLUGIN_HOSTCALL_OK;
}

[[nodiscard]] enum plugin_hostcall_status plugin_hostcall_dispatch(
    const struct plugin_hostcall_frame *request, uint32_t granted,
    const struct plugin_hostcall_handlers *handlers, uint8_t *reply,
    size_t reply_cap, size_t *reply_len)
{
    if (reply_len != nullptr)
        *reply_len = 0;
    if (request == nullptr || handlers == nullptr || reply == nullptr || reply_len == nullptr)
        return PLUGIN_HOSTCALL_ERR_ARGUMENT;
    if (request->kind != PLUGIN_HOSTCALL_KIND_REQUEST)
        return PLUGIN_HOSTCALL_ERR_KIND;
    const struct plugin_hostcall_method_info *m = plugin_hostcall_method_by_id(request->code);
    enum plugin_hostcall_status s = m == nullptr ? PLUGIN_HOSTCALL_ERR_METHOD
                                                 : gate(m, request->payload_len, granted);
    if (s == PLUGIN_HOSTCALL_OK && handlers->method[m->id - 1] == nullptr)
        s = PLUGIN_HOSTCALL_ERR_UNAVAILABLE;
    if (s != PLUGIN_HOSTCALL_OK)
        return reply_with(request->id, s, nullptr, 0, reply, reply_cap, reply_len);

    /* The handler writes straight into the reply payload area. */
    if (reply_cap < PLUGIN_HOSTCALL_HEADER_BYTES)
        return PLUGIN_HOSTCALL_ERR_BUFFER;
    size_t room = reply_cap - PLUGIN_HOSTCALL_HEADER_BYTES;
    if (room > PLUGIN_HOSTCALL_MAX_PAYLOAD)
        room = PLUGIN_HOSTCALL_MAX_PAYLOAD;
    uint8_t *body = reply + PLUGIN_HOSTCALL_HEADER_BYTES;
    size_t produced = 0;
    int rc = handlers->method[m->id - 1](handlers->context, request->payload,
                                         request->payload_len, body, room, &produced);
    if (rc != 0 || produced > room)
        return reply_with(request->id, PLUGIN_HOSTCALL_ERR_HANDLER, nullptr, 0,
                          reply, reply_cap, reply_len);
    /* body already sits in the payload area; encode moves it onto itself. */
    struct plugin_hostcall_frame r = {
        .kind = PLUGIN_HOSTCALL_KIND_REPLY, .id = request->id,
        .code = PLUGIN_HOSTCALL_OK, .payload = body, .payload_len = produced,
    };
    return plugin_hostcall_encode(&r, reply, reply_cap, reply_len);
}
