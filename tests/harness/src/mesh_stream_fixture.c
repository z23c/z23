/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Hand-composed ZSTRM frames for the mesh stream primitive's test groups
 * (see the header). Nothing here calls the production encoder: a test
 * that built its frames with the code under test could not tell a wire
 * change from a wire agreement.
 */

#include "test/mesh_stream_fixture.h"

#include "config/mesh_stream.h"

#include "base/serialize_le.h"

#include <stdbool.h>
#include <string.h>

static size_t stream_test_prefix(uint8_t *out, size_t out_cap, uint8_t kind,
                                 uint64_t stream_id)
{
    size_t n = MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u;
    if (out_cap < n)
        return 0;
    memcpy(out, MESH_STREAM_FRAME_PREFIX, MESH_STREAM_FRAME_PREFIX_LEN);
    out[MESH_STREAM_FRAME_PREFIX_LEN] = kind;
    zcl_write_u64_le(out + MESH_STREAM_FRAME_PREFIX_LEN + 1u, stream_id);
    return n;
}

size_t mesh_stream_test_open_frame(uint64_t stream_id, uint32_t window,
                                   const char *service_name,
                                   const uint8_t *payload, size_t payload_len,
                                   uint8_t *out, size_t out_cap)
{
    size_t name_len = service_name ? strlen(service_name) : 0;
    size_t n = stream_test_prefix(out, out_cap, MESH_STREAM_KIND_OPEN,
                                  stream_id);
    if (!n || name_len > 255 ||
        out_cap < n + 4u + 1u + name_len + 2u + payload_len)
        return 0;
    zcl_write_u32_le(out + n, window);
    n += 4u;
    out[n++] = (uint8_t)name_len;
    if (name_len)
        memcpy(out + n, service_name, name_len);
    n += name_len;
    zcl_write_u16_le(out + n, (uint16_t)payload_len);
    n += 2u;
    if (payload_len)
        memcpy(out + n, payload, payload_len);
    return n + payload_len;
}

size_t mesh_stream_test_data_frame(uint64_t stream_id, const uint8_t *payload,
                                   size_t payload_len, uint8_t *out,
                                   size_t out_cap)
{
    size_t n = stream_test_prefix(out, out_cap, MESH_STREAM_KIND_DATA,
                                  stream_id);
    if (!n || out_cap < n + 2u + payload_len)
        return 0;
    zcl_write_u16_le(out + n, (uint16_t)payload_len);
    n += 2u;
    if (payload_len)
        memcpy(out + n, payload, payload_len);
    return n + payload_len;
}

size_t mesh_stream_test_window_frame(uint64_t stream_id, uint32_t credit,
                                     uint8_t *out, size_t out_cap)
{
    size_t n = stream_test_prefix(out, out_cap, MESH_STREAM_KIND_WINDOW,
                                  stream_id);
    if (!n || out_cap < n + 4u)
        return 0;
    zcl_write_u32_le(out + n, credit);
    return n + 4u;
}

size_t mesh_stream_test_close_frame(uint64_t stream_id, uint8_t reason,
                                    const uint8_t *payload, size_t payload_len,
                                    uint8_t *out, size_t out_cap)
{
    size_t n = stream_test_prefix(out, out_cap, MESH_STREAM_KIND_CLOSE,
                                  stream_id);
    if (!n || out_cap < n + 3u + payload_len)
        return 0;
    out[n++] = reason;
    zcl_write_u16_le(out + n, (uint16_t)payload_len);
    n += 2u;
    if (payload_len)
        memcpy(out + n, payload, payload_len);
    return n + payload_len;
}

bool mesh_stream_test_read_header(const uint8_t *frame, size_t frame_len,
                                  uint8_t *kind_out, uint64_t *id_out)
{
    if (!frame || frame_len < MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u ||
        memcmp(frame, MESH_STREAM_FRAME_PREFIX,
               MESH_STREAM_FRAME_PREFIX_LEN) != 0)
        return false;
    if (kind_out)
        *kind_out = frame[MESH_STREAM_FRAME_PREFIX_LEN];
    if (id_out)
        *id_out = zcl_read_u64_le(frame + MESH_STREAM_FRAME_PREFIX_LEN + 1u);
    return true;
}
