/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "codec/cursor.h"

#include <stdint.h>
#include <string.h>

int main(void)
{
    uint8_t wire[64];
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, wire, sizeof(wire));
    if (!zcl_codec_write_u8(&writer, 0xa5) ||
        !zcl_codec_write_u16le(&writer, 0x1234) ||
        !zcl_codec_write_u32le(&writer, UINT32_C(0x89abcdef)) ||
        !zcl_codec_write_u64le(&writer, UINT64_C(0x0123456789abcdef)) ||
        !zcl_codec_write_i32le(&writer, -7) ||
        !zcl_codec_write_i64le(&writer, INT64_C(-9000000000)) ||
        !zcl_codec_write_u16_string(&writer, "c23", 3)) return 1;
    size_t length = 0;
    if (!zcl_codec_writer_finish(&writer, &length)) return 2;
    struct zcl_codec_reader reader;
    zcl_codec_reader_init(&reader, wire, length);
    uint8_t u8; uint16_t u16, text_len; uint32_t u32; uint64_t u64;
    int32_t i32; int64_t i64; char text[4];
    if (!zcl_codec_read_u8(&reader, &u8) || u8 != 0xa5 ||
        !zcl_codec_read_u16le(&reader, &u16) || u16 != 0x1234 ||
        !zcl_codec_read_u32le(&reader, &u32) || u32 != UINT32_C(0x89abcdef) ||
        !zcl_codec_read_u64le(&reader, &u64) || u64 != UINT64_C(0x0123456789abcdef) ||
        !zcl_codec_read_i32le(&reader, &i32) || i32 != -7 ||
        !zcl_codec_read_i64le(&reader, &i64) || i64 != INT64_C(-9000000000) ||
        !zcl_codec_read_u16_string(&reader, text, sizeof(text), &text_len) ||
        text_len != 3 || strcmp(text, "c23") != 0 ||
        !zcl_codec_reader_finish(&reader)) return 3;
    uint8_t short_prefix[1] = {0};
    zcl_codec_reader_init(&reader, short_prefix, sizeof(short_prefix));
    text_len = 77;
    if (zcl_codec_read_u16_bytes(&reader, NULL, 0, &text_len) ||
        reader.error != ZCL_CODEC_BOUNDS || reader.position != 0 ||
        text_len != 77) return 4;
    uint8_t empty_wire[2] = {0, 0};
    zcl_codec_reader_init(&reader, empty_wire, sizeof(empty_wire));
    if (!zcl_codec_read_u16_bytes(&reader, NULL, 0, &text_len) ||
        text_len != 0 || !zcl_codec_reader_finish(&reader)) return 5;
    return 0;
}
