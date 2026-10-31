/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Clips ZCLM meta file codec, with layout and ceiling checks. */

#include "clips_internal.h"

#include <string.h>

static const uint8_t k_manifest_magic[4] = { 0x5a, 0x43, 0x4c, 0x4d };
static const uint8_t k_manifest_version = 1;

static bool clips_in_range(uint32_t v, uint32_t lo, uint32_t hi)
{
    return v >= lo && v <= hi;
}

static uint32_t clips_chunks_for(uint32_t total)
{
    return (total + CLIPS_CHUNK_SIZE - 1) / CLIPS_CHUNK_SIZE;
}

static enum clips_error clips_manifest_read_media(struct zcl_codec_reader *r,
                                                  struct clips_manifest *m)
{
    if (!zcl_codec_read_u8(r, &m->container) || !zcl_codec_read_u8(r, &m->video_codec) ||
        !zcl_codec_read_u8(r, &m->audio_codec) || !zcl_codec_read_u16le(r, &m->width) ||
        !zcl_codec_read_u16le(r, &m->height) || !zcl_codec_read_u32le(r, &m->duration_ms) ||
        !zcl_codec_read_u16le(r, &m->bitrate_kbps) || !zcl_codec_read_u8(r, &m->fps) ||
        !zcl_codec_read_u8(r, &m->rotation))
        return CLIPS_ERR_TRUNCATED;
    return CLIPS_OK;
}

static enum clips_error clips_manifest_read_layout(struct zcl_codec_reader *r,
                                                   struct clips_manifest *m)
{
    if (!zcl_codec_read_u8(r, &m->chunk_size_log2) || !zcl_codec_read_u32le(r, &m->total_size) ||
        !zcl_codec_read_u16le(r, &m->chunk_count) ||
        !zcl_codec_read_bytes(r, m->thumb_id, sizeof(m->thumb_id)) ||
        !zcl_codec_read_u16le(r, &m->thumb_width) || !zcl_codec_read_u16le(r, &m->thumb_height))
        return CLIPS_ERR_TRUNCATED;
    return CLIPS_OK;
}

static enum clips_error clips_manifest_read_header(struct zcl_codec_reader *r)
{
    uint8_t magic[4];
    uint8_t version = 0;

    if (!zcl_codec_read_bytes(r, magic, sizeof(magic)) || !zcl_codec_read_u8(r, &version))
        return CLIPS_ERR_TRUNCATED;
    if (memcmp(magic, k_manifest_magic, sizeof(magic)) != 0)
        return CLIPS_ERR_MAGIC;
    if (version != k_manifest_version)
        return CLIPS_ERR_VERSION;
    return CLIPS_OK;
}

static enum clips_error clips_manifest_check_media(const struct clips_manifest *m)
{
    if (m->container != 1 || m->video_codec != 1 || m->audio_codec > 1)
        return CLIPS_ERR_FIELD;
    if (!clips_in_range(m->width, 16, 1920) || !clips_in_range(m->height, 16, 1920))
        return CLIPS_ERR_FIELD;
    if (!clips_in_range(m->duration_ms, 1, 60000) ||
        !clips_in_range(m->bitrate_kbps, 1, 8000) || !clips_in_range(m->fps, 1, 60) ||
        m->rotation > 3)
        return CLIPS_ERR_FIELD;
    return CLIPS_OK;
}

static enum clips_error clips_manifest_check_layout(const struct clips_manifest *m)
{
    if (m->chunk_size_log2 != CLIPS_CHUNK_LOG2)
        return CLIPS_ERR_CHUNK_SIZE;
    if (!clips_in_range(m->total_size, 1, CLIPS_MANIFEST_TOTAL_MAX))
        return CLIPS_ERR_FIELD;
    if (m->chunk_count < 1 || m->chunk_count > CLIPS_CHUNK_MAX)
        return CLIPS_ERR_CHUNK_COUNT;
    if (m->chunk_count != clips_chunks_for(m->total_size))
        return CLIPS_ERR_CHUNK_COUNT;
    if (!clips_in_range(m->thumb_width, 16, 1080) || !clips_in_range(m->thumb_height, 16, 1920))
        return CLIPS_ERR_FIELD;
    return CLIPS_OK;
}

static enum clips_error clips_manifest_check(const struct clips_manifest *m)
{
    enum clips_error e = clips_manifest_check_media(m);

    if (e != CLIPS_OK)
        return e;
    return clips_manifest_check_layout(m);
}

enum clips_error clips_manifest_decode(const uint8_t *in, size_t len, struct clips_manifest *out)
{
    struct zcl_codec_reader r;
    enum clips_error e;
    size_t need = 0;

    if (!in || !out)
        return CLIPS_ERR_ARGUMENT;
    if (len < CLIPS_MANIFEST_HEADER_LEN)
        return CLIPS_ERR_TRUNCATED;
    zcl_codec_reader_init(&r, in, len);
    e = clips_manifest_read_header(&r);
    if (e != CLIPS_OK)
        return e;
    e = clips_manifest_read_media(&r, out);
    if (e != CLIPS_OK)
        return e;
    e = clips_manifest_read_layout(&r, out);
    if (e != CLIPS_OK)
        return e;
    e = clips_manifest_check(out);
    if (e != CLIPS_OK)
        return e;
    need = CLIPS_MANIFEST_HEADER_LEN + (size_t)out->chunk_count * CLIPS_HASH_LEN;
    if (len < need)
        return CLIPS_ERR_TRUNCATED;
    if (len > need)
        return CLIPS_ERR_TRAILING;
    for (uint16_t i = 0; i < out->chunk_count; i++) {
        if (!zcl_codec_read_bytes(&r, out->chunk_ids[i], CLIPS_HASH_LEN))
            return CLIPS_ERR_TRUNCATED;
    }
    return CLIPS_OK;
}

static bool clips_manifest_write_media(struct zcl_codec_writer *w, const struct clips_manifest *m)
{
    return zcl_codec_write_bytes(w, k_manifest_magic, sizeof(k_manifest_magic)) &&
           zcl_codec_write_u8(w, k_manifest_version) && zcl_codec_write_u8(w, m->container) &&
           zcl_codec_write_u8(w, m->video_codec) && zcl_codec_write_u8(w, m->audio_codec) &&
           zcl_codec_write_u16le(w, m->width) && zcl_codec_write_u16le(w, m->height) &&
           zcl_codec_write_u32le(w, m->duration_ms) && zcl_codec_write_u16le(w, m->bitrate_kbps) &&
           zcl_codec_write_u8(w, m->fps) && zcl_codec_write_u8(w, m->rotation);
}

static bool clips_manifest_write_layout(struct zcl_codec_writer *w, const struct clips_manifest *m)
{
    return zcl_codec_write_u8(w, m->chunk_size_log2) && zcl_codec_write_u32le(w, m->total_size) &&
           zcl_codec_write_u16le(w, m->chunk_count) &&
           zcl_codec_write_bytes(w, m->thumb_id, sizeof(m->thumb_id)) &&
           zcl_codec_write_u16le(w, m->thumb_width) && zcl_codec_write_u16le(w, m->thumb_height);
}

enum clips_error clips_manifest_encode(const struct clips_manifest *m, uint8_t *out,
                                       size_t cap, size_t *written)
{
    struct zcl_codec_writer w;
    struct clips_manifest check;
    size_t need = 0;
    enum clips_error e;

    if (!m || !out || !written)
        return CLIPS_ERR_ARGUMENT;
    e = clips_manifest_check(m);
    if (e != CLIPS_OK)
        return e;
    need = CLIPS_MANIFEST_HEADER_LEN + (size_t)m->chunk_count * CLIPS_HASH_LEN;
    if (cap < need)
        return CLIPS_ERR_ARGUMENT;
    zcl_codec_writer_init(&w, out, cap);
    if (!clips_manifest_write_media(&w, m) || !clips_manifest_write_layout(&w, m))
        return CLIPS_ERR_ARGUMENT;
    for (uint16_t i = 0; i < m->chunk_count; i++) {
        if (!zcl_codec_write_bytes(&w, m->chunk_ids[i], CLIPS_HASH_LEN))
            return CLIPS_ERR_ARGUMENT;
    }
    if (!zcl_codec_writer_finish(&w, written))
        return CLIPS_ERR_ARGUMENT;
    return clips_manifest_decode(out, *written, &check);
}
