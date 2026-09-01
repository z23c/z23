/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: implement sticky, atomic, bounded caller-owned codec cursors. */

#include "codec/cursor.h"

#include "base/checked.h"
#include "base/serialize_le.h"

#include <limits.h>
#include <string.h>

const char *zcl_codec_error_string(enum zcl_codec_error error)
{
    switch (error) {
    case ZCL_CODEC_OK: return "ok";
    case ZCL_CODEC_INVALID: return "invalid-argument";
    case ZCL_CODEC_BOUNDS: return "buffer-bounds";
    case ZCL_CODEC_LENGTH: return "length-bound";
    case ZCL_CODEC_TRAILING: return "trailing-bytes";
    }
    return "unknown-error";
}

void zcl_codec_reader_init(struct zcl_codec_reader *reader,
                           const void *buffer, size_t length)
{
    if (!reader) return;
    reader->buffer = buffer;
    reader->length = length;
    reader->position = 0;
    reader->error = (!buffer && length) ? ZCL_CODEC_INVALID : ZCL_CODEC_OK;
}

void zcl_codec_writer_init(struct zcl_codec_writer *writer, void *buffer,
                           size_t capacity)
{
    if (!writer) return;
    writer->buffer = buffer;
    writer->capacity = capacity;
    writer->position = 0;
    writer->error = (!buffer && capacity) ? ZCL_CODEC_INVALID : ZCL_CODEC_OK;
}

size_t zcl_codec_reader_remaining(const struct zcl_codec_reader *reader)
{
    if (!reader || reader->position > reader->length) return 0;
    return reader->length - reader->position;
}

size_t zcl_codec_writer_remaining(const struct zcl_codec_writer *writer)
{
    if (!writer || writer->position > writer->capacity) return 0;
    return writer->capacity - writer->position;
}

static bool reader_need(struct zcl_codec_reader *reader, size_t length)
{
    if (!reader || reader->error != ZCL_CODEC_OK) return false;
    if (length > zcl_codec_reader_remaining(reader)) {
        reader->error = ZCL_CODEC_BOUNDS;
        return false;
    }
    return true;
}

static bool writer_need(struct zcl_codec_writer *writer, size_t length)
{
    if (!writer || writer->error != ZCL_CODEC_OK) return false;
    if (length > zcl_codec_writer_remaining(writer)) {
        writer->error = ZCL_CODEC_BOUNDS;
        return false;
    }
    return true;
}

bool zcl_codec_reader_finish(struct zcl_codec_reader *reader)
{
    if (!reader || reader->error != ZCL_CODEC_OK) return false;
    if (reader->position != reader->length) {
        reader->error = ZCL_CODEC_TRAILING;
        return false;
    }
    return true;
}

bool zcl_codec_writer_finish(const struct zcl_codec_writer *writer,
                             size_t *written)
{
    if (!writer || writer->error != ZCL_CODEC_OK || !written) return false;
    *written = writer->position;
    return true;
}

bool zcl_codec_read_bytes(struct zcl_codec_reader *reader, void *out,
                          size_t length)
{
    if ((!out && length) || !reader) {
        if (reader && reader->error == ZCL_CODEC_OK)
            reader->error = ZCL_CODEC_INVALID;
        return false;
    }
    if (!reader_need(reader, length)) return false;
    if (length) memcpy(out, reader->buffer + reader->position, length);
    reader->position += length;
    return true;
}

bool zcl_codec_write_bytes(struct zcl_codec_writer *writer, const void *bytes,
                           size_t length)
{
    if ((!bytes && length) || !writer) {
        if (writer && writer->error == ZCL_CODEC_OK)
            writer->error = ZCL_CODEC_INVALID;
        return false;
    }
    if (!writer_need(writer, length)) return false;
    if (length) memcpy(writer->buffer + writer->position, bytes, length);
    writer->position += length;
    return true;
}

#define DEFINE_CODEC_READ(name, type, bytes, decode) \
bool name(struct zcl_codec_reader *reader, type *out) \
{ \
    if (!out || !reader_need(reader, bytes)) { \
        if (reader && !out && reader->error == ZCL_CODEC_OK) \
            reader->error = ZCL_CODEC_INVALID; \
        return false; \
    } \
    type value = (type)(decode(reader->buffer + reader->position)); \
    reader->position += bytes; \
    *out = value; \
    return true; \
}

DEFINE_CODEC_READ(zcl_codec_read_u16le, uint16_t, 2u, zcl_read_u16_le)
DEFINE_CODEC_READ(zcl_codec_read_u32le, uint32_t, 4u, zcl_read_u32_le)
DEFINE_CODEC_READ(zcl_codec_read_u64le, uint64_t, 8u, zcl_read_u64_le)

bool zcl_codec_read_i32le(struct zcl_codec_reader *reader, int32_t *out)
{
    uint32_t bits;
    if (!out || !reader_need(reader, 4u)) {
        if (reader && !out && reader->error == ZCL_CODEC_OK)
            reader->error = ZCL_CODEC_INVALID;
        return false;
    }
    bits = zcl_read_u32_le(reader->buffer + reader->position);
    reader->position += 4u;
    memcpy(out, &bits, sizeof(bits));
    return true;
}

bool zcl_codec_read_i64le(struct zcl_codec_reader *reader, int64_t *out)
{
    uint64_t bits;
    if (!out || !reader_need(reader, 8u)) {
        if (reader && !out && reader->error == ZCL_CODEC_OK)
            reader->error = ZCL_CODEC_INVALID;
        return false;
    }
    bits = zcl_read_u64_le(reader->buffer + reader->position);
    reader->position += 8u;
    memcpy(out, &bits, sizeof(bits));
    return true;
}

bool zcl_codec_read_u8(struct zcl_codec_reader *reader, uint8_t *out)
{
    return zcl_codec_read_bytes(reader, out, 1);
}

#define DEFINE_CODEC_WRITE(name, type, bytes, encode) \
bool name(struct zcl_codec_writer *writer, type value) \
{ \
    if (!writer_need(writer, bytes)) return false; \
    encode(writer->buffer + writer->position, value); \
    writer->position += bytes; \
    return true; \
}

DEFINE_CODEC_WRITE(zcl_codec_write_u16le, uint16_t, 2u, zcl_write_u16_le)
DEFINE_CODEC_WRITE(zcl_codec_write_u32le, uint32_t, 4u, zcl_write_u32_le)
DEFINE_CODEC_WRITE(zcl_codec_write_u64le, uint64_t, 8u, zcl_write_u64_le)

bool zcl_codec_write_i32le(struct zcl_codec_writer *writer, int32_t value)
{
    uint32_t bits;
    memcpy(&bits, &value, sizeof(bits));
    return zcl_codec_write_u32le(writer, bits);
}

bool zcl_codec_write_i64le(struct zcl_codec_writer *writer, int64_t value)
{
    uint64_t bits;
    memcpy(&bits, &value, sizeof(bits));
    return zcl_codec_write_u64le(writer, bits);
}

bool zcl_codec_write_u8(struct zcl_codec_writer *writer, uint8_t value)
{
    return zcl_codec_write_bytes(writer, &value, 1);
}

static bool reader_u16_payload(struct zcl_codec_reader *reader,
                               size_t capacity, uint16_t *length)
{
    if (!reader || reader->error != ZCL_CODEC_OK) return false;
    if (zcl_codec_reader_remaining(reader) < 2u) {
        reader->error = ZCL_CODEC_BOUNDS;
        return false;
    }
    uint16_t value = zcl_read_u16_le(reader->buffer + reader->position);
    size_t total;
    if (!zcl_size_add(2u, value, &total) ||
        total > zcl_codec_reader_remaining(reader)) {
        reader->error = ZCL_CODEC_BOUNDS;
        return false;
    }
    if ((size_t)value > capacity) {
        reader->error = ZCL_CODEC_LENGTH;
        return false;
    }
    *length = value;
    return true;
}

bool zcl_codec_read_u16_bytes(struct zcl_codec_reader *reader, void *out,
                              size_t out_capacity, uint16_t *out_len)
{
    if (!out_len || (!out && out_capacity)) {
        if (reader && reader->error == ZCL_CODEC_OK)
            reader->error = ZCL_CODEC_INVALID;
        return false;
    }
    uint16_t length = 0;
    if (!reader_u16_payload(reader, out_capacity, &length))
        return false;
    if (!out && length) {
        if (reader->error == ZCL_CODEC_OK)
            reader->error = ZCL_CODEC_INVALID;
        return false;
    }
    if (length) memcpy(out, reader->buffer + reader->position + 2u, length);
    reader->position += 2u + length;
    *out_len = length;
    return true;
}

bool zcl_codec_write_u16_bytes(struct zcl_codec_writer *writer,
                               const void *bytes, size_t length)
{
    if (!writer || (!bytes && length)) {
        if (writer && writer->error == ZCL_CODEC_OK)
            writer->error = ZCL_CODEC_INVALID;
        return false;
    }
    if (length > UINT16_MAX) {
        if (writer->error == ZCL_CODEC_OK) writer->error = ZCL_CODEC_LENGTH;
        return false;
    }
    size_t total;
    if (!zcl_size_add(2u, length, &total) || !writer_need(writer, total))
        return false;
    zcl_write_u16_le(writer->buffer + writer->position, (uint16_t)length);
    if (length)
        memcpy(writer->buffer + writer->position + 2u, bytes, length);
    writer->position += total;
    return true;
}

bool zcl_codec_read_u16_string(struct zcl_codec_reader *reader, char *out,
                               size_t out_capacity, uint16_t *out_len)
{
    if (!out || !out_len || out_capacity == 0) {
        if (reader && reader->error == ZCL_CODEC_OK)
            reader->error = ZCL_CODEC_INVALID;
        return false;
    }
    uint16_t length;
    if (!reader_u16_payload(reader, out_capacity - 1u, &length)) return false;
    if (memchr(reader->buffer + reader->position + 2u, '\0', length)) {
        reader->error = ZCL_CODEC_INVALID;
        return false;
    }
    memcpy(out, reader->buffer + reader->position + 2u, length);
    out[length] = '\0';
    reader->position += 2u + length;
    *out_len = length;
    return true;
}

bool zcl_codec_write_u16_string(struct zcl_codec_writer *writer,
                                const char *string, size_t length)
{
    if (!string && length) {
        if (writer && writer->error == ZCL_CODEC_OK)
            writer->error = ZCL_CODEC_INVALID;
        return false;
    }
    if (string && memchr(string, '\0', length) != NULL) {
        if (writer && writer->error == ZCL_CODEC_OK)
            writer->error = ZCL_CODEC_INVALID;
        return false;
    }
    return zcl_codec_write_u16_bytes(writer, string, length);
}
