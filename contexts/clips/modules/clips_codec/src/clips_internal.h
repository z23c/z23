/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: helpers shared by the Clips codec sources. Not a public API. */

#ifndef ZCL_CLIPS_CODEC_INTERNAL_H
#define ZCL_CLIPS_CODEC_INTERNAL_H

#include "clips_codec/clips_codec.h"
#include "codec/cursor.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Length-prefixed fields: the read refuses a length above max before any
 * copy and reports truncation as CLIPS_ERR_BODY. */
enum clips_error clips_rd_lenbytes(struct zcl_codec_reader *r, uint8_t max,
                                   uint8_t *buf, uint8_t *len);
enum clips_error clips_rd_len16bytes(struct zcl_codec_reader *r, uint16_t max,
                                     uint8_t *buf, uint16_t *len);
enum clips_error clips_wr_lenbytes(struct zcl_codec_writer *w, uint8_t max,
                                   const uint8_t *buf, uint8_t len);
enum clips_error clips_wr_len16bytes(struct zcl_codec_writer *w, uint16_t max,
                                     const uint8_t *buf, uint16_t len);

enum clips_error clips_rd_textbytes(struct zcl_codec_reader *r, uint8_t max,
                                   uint8_t *buf, uint8_t *len);
enum clips_error clips_rd_text16bytes(struct zcl_codec_reader *r, uint16_t max,
                                     uint8_t *buf, uint16_t *len);
bool clips_text_wellformed(const uint8_t *s, size_t n);
bool clips_tag_valid(const uint8_t *t, size_t n);

enum clips_error clips_social_read(uint8_t kind, struct zcl_codec_reader *r,
                                   struct clips_body *out);
enum clips_error clips_social_write(const struct clips_body *in,
                                    struct zcl_codec_writer *w);

#endif /* ZCL_CLIPS_CODEC_INTERNAL_H */
