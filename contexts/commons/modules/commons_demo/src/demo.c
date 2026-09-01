/* Copyright 2026 Rhett Creighton - MIT License
 * purpose: Compose base, codec, and JSON packages into a stable app result. */

#include "commons/demo.h"

#include "base/hex.h"
#include "codec/cursor.h"
#include "json/json.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

bool commons_demo_render(const char *input, char *out, size_t out_capacity)
{
    if (!input || !out || out_capacity == 0)
        return false;
    out[0] = '\0';

    struct json_value document;
    json_init(&document);
    size_t input_len = strlen(input);
    if (!json_read(&document, input, input_len) ||
        document.type != JSON_OBJ) {
        json_free(&document);
        return false;
    }
    const struct json_value *name_value = json_get(&document, "name");
    const struct json_value *count_value = json_get(&document, "count");
    if (!name_value || name_value->type != JSON_STR ||
        !count_value || count_value->type != JSON_INT ||
        count_value->val.i < 0 || count_value->val.i > UINT32_MAX) {
        json_free(&document);
        return false;
    }
    const char *name = json_get_str(name_value);
    size_t name_len = name ? strlen(name) : 0;
    if (name_len == 0 || name_len > 63u) {
        json_free(&document);
        return false;
    }
    char stable_name[64];
    memcpy(stable_name, name, name_len + 1u);
    uint32_t count = (uint32_t)count_value->val.i;
    json_free(&document);

    uint8_t wire[4u + 2u + 63u];
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, wire, sizeof(wire));
    size_t wire_len = 0;
    if (!zcl_codec_write_u32le(&writer, count) ||
        !zcl_codec_write_u16_string(&writer, stable_name, name_len) ||
        !zcl_codec_writer_finish(&writer, &wire_len))
        return false;

    char encoded[sizeof(wire) * 2u + 1u];
    zcl_hex_encode(wire, wire_len, encoded);
    int wrote = snprintf(out, out_capacity, "%s|%u|%s", stable_name,
                         count, encoded);
    if (wrote <= 0 || (size_t)wrote >= out_capacity) {
        out[0] = '\0';
        return false;
    }
    return true;
}
