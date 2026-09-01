/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: allocation-free bounded little-endian reader and writer cursors. */
#ifndef ZCL_CODEC_CURSOR_H
#define ZCL_CODEC_CURSOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum zcl_codec_error {
    ZCL_CODEC_OK = 0,
    ZCL_CODEC_INVALID,
    ZCL_CODEC_BOUNDS,
    ZCL_CODEC_LENGTH,
    ZCL_CODEC_TRAILING,
};

struct zcl_codec_reader {
    const uint8_t *buffer;
    size_t length;
    size_t position;
    enum zcl_codec_error error;
};

struct zcl_codec_writer {
    uint8_t *buffer;
    size_t capacity;
    size_t position;
    enum zcl_codec_error error;
};

const char *zcl_codec_error_string(enum zcl_codec_error error);
void zcl_codec_reader_init(struct zcl_codec_reader *reader,
                           const void *buffer, size_t length);
void zcl_codec_writer_init(struct zcl_codec_writer *writer, void *buffer,
                           size_t capacity);
size_t zcl_codec_reader_remaining(const struct zcl_codec_reader *reader);
size_t zcl_codec_writer_remaining(const struct zcl_codec_writer *writer);
bool zcl_codec_reader_finish(struct zcl_codec_reader *reader);
bool zcl_codec_writer_finish(const struct zcl_codec_writer *writer,
                             size_t *written);

bool zcl_codec_read_bytes(struct zcl_codec_reader *reader, void *out,
                          size_t length);
bool zcl_codec_write_bytes(struct zcl_codec_writer *writer, const void *bytes,
                           size_t length);

bool zcl_codec_read_u8(struct zcl_codec_reader *reader, uint8_t *out);
bool zcl_codec_read_u16le(struct zcl_codec_reader *reader, uint16_t *out);
bool zcl_codec_read_u32le(struct zcl_codec_reader *reader, uint32_t *out);
bool zcl_codec_read_u64le(struct zcl_codec_reader *reader, uint64_t *out);
bool zcl_codec_read_i32le(struct zcl_codec_reader *reader, int32_t *out);
bool zcl_codec_read_i64le(struct zcl_codec_reader *reader, int64_t *out);
bool zcl_codec_write_u8(struct zcl_codec_writer *writer, uint8_t value);
bool zcl_codec_write_u16le(struct zcl_codec_writer *writer, uint16_t value);
bool zcl_codec_write_u32le(struct zcl_codec_writer *writer, uint32_t value);
bool zcl_codec_write_u64le(struct zcl_codec_writer *writer, uint64_t value);
bool zcl_codec_write_i32le(struct zcl_codec_writer *writer, int32_t value);
bool zcl_codec_write_i64le(struct zcl_codec_writer *writer, int64_t value);

/* Atomic length-prefixed operations: the two-byte prefix and payload either
 * both commit or neither does. A failed read leaves out/out_len unchanged. */
bool zcl_codec_read_u16_bytes(struct zcl_codec_reader *reader, void *out,
                              size_t out_capacity, uint16_t *out_len);
bool zcl_codec_write_u16_bytes(struct zcl_codec_writer *writer,
                               const void *bytes, size_t length);
bool zcl_codec_read_u16_string(struct zcl_codec_reader *reader, char *out,
                               size_t out_capacity, uint16_t *out_len);
bool zcl_codec_write_u16_string(struct zcl_codec_writer *writer,
                                const char *string, size_t length);

#endif /* ZCL_CODEC_CURSOR_H */
