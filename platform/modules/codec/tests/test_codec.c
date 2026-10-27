/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "codec/cursor.h"

#include <stdint.h>
#include <string.h>

/* Writes the roundtrip payload; true when any write fails. */
static bool write_roundtrip_payload_fails(struct zcl_codec_writer *writer)
{
    return !zcl_codec_write_u8(writer, 0xa5) ||
        !zcl_codec_write_u16le(writer, 0x1234) ||
        !zcl_codec_write_u32le(writer, UINT32_C(0x89abcdef)) ||
        !zcl_codec_write_u64le(writer, UINT64_C(0x0123456789abcdef)) ||
        !zcl_codec_write_i32le(writer, -7) ||
        !zcl_codec_write_i64le(writer, INT64_C(-9000000000)) ||
        !zcl_codec_write_u16_string(writer, "c23", 3);
}

/* Reads back the written scalar values in order; true when any read or compare fails. */
static bool read_roundtrip_scalars_fails(struct zcl_codec_reader *reader)
{
    uint8_t u8; uint16_t u16; uint32_t u32; uint64_t u64;
    int32_t i32; int64_t i64;
    return !zcl_codec_read_u8(reader, &u8) || u8 != 0xa5 ||
        !zcl_codec_read_u16le(reader, &u16) || u16 != 0x1234 ||
        !zcl_codec_read_u32le(reader, &u32) || u32 != UINT32_C(0x89abcdef) ||
        !zcl_codec_read_u64le(reader, &u64) || u64 != UINT64_C(0x0123456789abcdef) ||
        !zcl_codec_read_i32le(reader, &i32) || i32 != -7 ||
        !zcl_codec_read_i64le(reader, &i64) || i64 != INT64_C(-9000000000);
}

/* Reads back the u16 string and finishes the reader; true when any check fails. */
static bool read_roundtrip_string_fails(struct zcl_codec_reader *reader)
{
    uint16_t text_len;
    char text[4];
    return !zcl_codec_read_u16_string(reader, text, sizeof(text), &text_len) ||
        text_len != 3 || strcmp(text, "c23") != 0 ||
        !zcl_codec_reader_finish(reader);
}

/* True unless a one-byte prefix read fails with ZCL_CODEC_BOUNDS, position 0 and the length untouched. */
static bool short_prefix_bounds_fails(void)
{
    struct zcl_codec_reader reader;
    uint8_t short_prefix[1] = {0};
    uint16_t text_len = 77;
    zcl_codec_reader_init(&reader, short_prefix, sizeof(short_prefix));
    return zcl_codec_read_u16_bytes(&reader, NULL, 0, &text_len) ||
        reader.error != ZCL_CODEC_BOUNDS || reader.position != 0 ||
        text_len != 77;
}

/* Reads an empty u16 string from two zero bytes; true when any check fails. */
static bool empty_wire_string_fails(void)
{
    struct zcl_codec_reader reader;
    uint8_t empty_wire[2] = {0, 0};
    uint16_t text_len = 77;
    zcl_codec_reader_init(&reader, empty_wire, sizeof(empty_wire));
    return !zcl_codec_read_u16_bytes(&reader, NULL, 0, &text_len) ||
        text_len != 0 || !zcl_codec_reader_finish(&reader);
}

int main(void)
{
    uint8_t wire[64];
    struct zcl_codec_writer writer;
    zcl_codec_writer_init(&writer, wire, sizeof(wire));
    if (write_roundtrip_payload_fails(&writer)) return 1;
    size_t length = 0;
    if (!zcl_codec_writer_finish(&writer, &length)) return 2;
    struct zcl_codec_reader reader;
    zcl_codec_reader_init(&reader, wire, length);
    if (read_roundtrip_scalars_fails(&reader) ||
        read_roundtrip_string_fails(&reader)) return 3;
    if (short_prefix_bounds_fails()) return 4;
    if (empty_wire_string_fails()) return 5;
    return 0;
}
