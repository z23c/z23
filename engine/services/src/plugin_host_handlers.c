/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: node-backed READ-ONLY plugin host-call handlers; see
 * services/plugin_host_handlers.h for the reply layouts and the contract. */

#include "services/plugin_host_handlers.h"

#include "base/log_macros.h"
#include "base/serialize_le.h"
#include "core/serialize.h"
#include "jobs/tip_finalize_stage.h"
#include "models/block.h"
#include "models/database.h"
#include "platform/clock.h"
#include "primitives/block.h"

#include <string.h>

/* The served authority pair when the node has no injected source. */
static bool served_authority(void *context, int64_t *height, uint8_t hash[32])
{
    (void)context;
    return tip_finalize_stage_authority_snapshot(height, hash);
}

static int read_authority(const struct plugin_host_node *n, int64_t *height,
                           uint8_t hash[32])
{
    plugin_host_authority_fn fn = n->authority != nullptr ? n->authority : served_authority;
    int64_t h = -1;
    if (!fn(n->authority_context, &h, hash))
        return -1; // raw-return-ok:no published authority; the handler refuses
    if (h < 0 || h > INT32_MAX)
        return -1; // raw-return-ok:out-of-range height; the handler refuses
    *height = h;
    return 0;
}

/* chain.tip: empty payload -> height u32, hash 32, time u32. */
static int host_chain_tip(void *context, const uint8_t *payload, size_t payload_len,
                          uint8_t *out, size_t out_cap, size_t *out_len)
{
    struct plugin_host_node *n = context;
    (void)payload;
    if (n == nullptr || out == nullptr || out_len == nullptr || payload_len != 0 ||
        out_cap < PLUGIN_HOST_TIP_REPLY_BYTES)
        return 1;
    int64_t height = -1;
    uint8_t hash[32];
    if (read_authority(n, &height, hash))
        return 2;
    struct block_header hdr;
    if (!db_block_load_header_by_hash_height(n->ndb, (int)height, hash, &hdr))
        return 3;
    zcl_write_u32_be(out, (uint32_t)height);
    memcpy(out + 4, hash, 32);
    zcl_write_u32_be(out + 36, hdr.nTime);
    *out_len = PLUGIN_HOST_TIP_REPLY_BYTES;
    return 0;
}

/* chain.header_by_height: height u32 -> header bytes, or an empty reply. */
static int host_header_by_height(void *context, const uint8_t *payload,
                                 size_t payload_len, uint8_t *out, size_t out_cap,
                                 size_t *out_len)
{
    struct plugin_host_node *n = context;
    if (n == nullptr || payload == nullptr || out == nullptr || out_len == nullptr ||
        payload_len != 4)
        return 1;
    *out_len = 0;
    uint32_t want = zcl_read_u32_be(payload);
    int64_t tip = -1;
    uint8_t tip_hash[32];
    if (read_authority(n, &tip, tip_hash))
        return 2;
    if (want > INT32_MAX || (int64_t)want > tip)
        return 0; /* not found: past the served tip */
    struct db_block row;
    if (!db_block_find_by_height(n->ndb, (int)want, &row))
        return 0;
    struct block_header hdr;
    if (!db_block_load_header_by_hash_height(n->ndb, (int)want, row.hash, &hdr))
        return 0;
    struct byte_stream s;
    stream_init(&s, 256);
    bool ok = block_header_serialize(&hdr, &s) && !s.error && s.size <= out_cap;
    if (ok) {
        memcpy(out, s.data, s.size);
        *out_len = s.size;
    }
    stream_free(&s);
    return ok ? 0 : 3;
}

/* Copy src into dst (cap bytes, NUL added) without control bytes. Returns the
 * kept length. */
static size_t strip_controls(char *dst, size_t cap, const uint8_t *src, size_t n)
{
    size_t w = 0;
    for (size_t i = 0; i < n && w + 1 < cap; i++)
        if (src[i] >= 0x20 && src[i] != 0x7f)
            dst[w++] = (char)src[i];
    dst[w] = '\0';
    return w;
}

static int64_t node_now_ms(const struct plugin_host_node *n)
{
    if (n->now_ms != nullptr)
        return n->now_ms(n->now_context);
    return clock_now_monotonic_ns() / 1000000;
}

static void emit_line(const struct plugin_host_node *n, unsigned level, const char *line)
{
    if (n->log_sink != nullptr) {
        n->log_sink(n->log_context, level, line);
        return;
    }
    switch (level) {
    case PLUGIN_HOST_LOG_ERROR:
        LOG_ERROR("plugin", "%s", line);
        break;
    case PLUGIN_HOST_LOG_WARN:
        LOG_WARN("plugin", "%s", line);
        break;
    default:
        LOG_INFO("plugin", "%s", line);
        break;
    }
}

/* log.write: level u8, text (1..PLUGIN_HOST_LOG_TEXT_MAX bytes) -> empty. */
static int host_log_write(void *context, const uint8_t *payload, size_t payload_len,
                          uint8_t *out, size_t out_cap, size_t *out_len)
{
    struct plugin_host_node *n = context;
    (void)out;
    (void)out_cap;
    if (n == nullptr || payload == nullptr || out_len == nullptr)
        return 1;
    *out_len = 0;
    if (payload_len < 2 || payload_len - 1 > PLUGIN_HOST_LOG_TEXT_MAX ||
        payload[0] > PLUGIN_HOST_LOG_ERROR)
        return 1;
    char text[PLUGIN_HOST_LOG_TEXT_MAX + 1];
    if (strip_controls(text, sizeof text, payload + 1, payload_len - 1) == 0)
        return 1;
    int64_t now = node_now_ms(n);
    if (now < n->window_start_ms || now - n->window_start_ms >= PLUGIN_HOST_LOG_WINDOW_MS) {
        n->window_start_ms = now;
        n->window_lines = 0;
    }
    if (n->window_lines >= PLUGIN_HOST_LOG_BURST) {
        n->log_dropped++;
        return 2;
    }
    n->window_lines++;
    char line[PLUGIN_HOST_LOG_LINE_MAX];
    int w = snprintf(line, sizeof line, "[plugin %s] %s", n->plugin, text);
    if (w < 0 || (size_t)w >= sizeof line)
        return 3;
    emit_line(n, payload[0], line);
    return 0;
}

struct zcl_result plugin_host_node_init(struct plugin_host_node *node, struct node_db *ndb,
                           const char *plugin_name)
{
    if (node == nullptr || ndb == nullptr || plugin_name == nullptr)
        return ZCL_ERR(-1, "plugin host node: bad argument or empty plugin name");
    memset(node, 0, sizeof *node);
    node->ndb = ndb;
    size_t len = strnlen(plugin_name, PLUGIN_HOST_NAME_MAX * 4);
    if (strip_controls(node->plugin, sizeof node->plugin, (const uint8_t *)plugin_name, len) == 0) {
        memset(node, 0, sizeof *node);
        return ZCL_ERR(-1, "plugin host node: bad argument or empty plugin name");
    }
    return ZCL_OK;
}

struct zcl_result plugin_host_node_handlers(struct plugin_hostcall_handlers *out,
                               struct plugin_host_node *node)
{
    if (out == nullptr || node == nullptr)
        return ZCL_ERR(-1, "plugin host node: bad argument or empty plugin name");
    memset(out, 0, sizeof *out);
    out->context = node;
    out->method[PLUGIN_HOSTCALL_M_CHAIN_TIP - 1] = host_chain_tip;
    out->method[PLUGIN_HOSTCALL_M_CHAIN_HEADER_BY_HEIGHT - 1] = host_header_by_height;
    out->method[PLUGIN_HOSTCALL_M_LOG_WRITE - 1] = host_log_write;
    return ZCL_OK;
}
