/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Clips body codecs for post, profile, tombstone, list and rating kinds, with encode then verify. */

#include "clips_internal.h"

#include <string.h>

enum clips_error clips_rd_lenbytes(struct zcl_codec_reader *r, uint8_t max,
                                   uint8_t *buf, uint8_t *len)
{
    uint8_t n = 0;

    if (!zcl_codec_read_u8(r, &n))
        return CLIPS_ERR_BODY;
    if (n > max)
        return CLIPS_ERR_FIELD;
    if (!zcl_codec_read_bytes(r, buf, n))
        return CLIPS_ERR_BODY;
    *len = n;
    return CLIPS_OK;
}

enum clips_error clips_rd_len16bytes(struct zcl_codec_reader *r, uint16_t max,
                                     uint8_t *buf, uint16_t *len)
{
    uint16_t n = 0;

    if (!zcl_codec_read_u16le(r, &n))
        return CLIPS_ERR_BODY;
    if (n > max)
        return CLIPS_ERR_FIELD;
    if (!zcl_codec_read_bytes(r, buf, n))
        return CLIPS_ERR_BODY;
    *len = n;
    return CLIPS_OK;
}

enum clips_error clips_rd_textbytes(struct zcl_codec_reader *r, uint8_t max,
                                    uint8_t *buf, uint8_t *len)
{
    enum clips_error e = clips_rd_lenbytes(r, max, buf, len);

    if (e != CLIPS_OK)
        return e;
    return clips_text_wellformed(buf, *len) ? CLIPS_OK : CLIPS_ERR_TEXT;
}

enum clips_error clips_rd_text16bytes(struct zcl_codec_reader *r, uint16_t max,
                                      uint8_t *buf, uint16_t *len)
{
    enum clips_error e = clips_rd_len16bytes(r, max, buf, len);

    if (e != CLIPS_OK)
        return e;
    return clips_text_wellformed(buf, *len) ? CLIPS_OK : CLIPS_ERR_TEXT;
}

enum clips_error clips_wr_lenbytes(struct zcl_codec_writer *w, uint8_t max,
                                   const uint8_t *buf, uint8_t len)
{
    if (len > max)
        return CLIPS_ERR_FIELD;
    if (!zcl_codec_write_u8(w, len) || !zcl_codec_write_bytes(w, buf, len))
        return CLIPS_ERR_BODY;
    return CLIPS_OK;
}

enum clips_error clips_wr_len16bytes(struct zcl_codec_writer *w, uint16_t max,
                                     const uint8_t *buf, uint16_t len)
{
    if (len > max)
        return CLIPS_ERR_FIELD;
    if (!zcl_codec_write_u16le(w, len) || !zcl_codec_write_bytes(w, buf, len))
        return CLIPS_ERR_BODY;
    return CLIPS_OK;
}

static enum clips_error clips_read_post_head(struct zcl_codec_reader *r,
                                             struct clips_post *p)
{
    uint8_t flags = 0;

    if (!zcl_codec_read_u8(r, &flags) || !zcl_codec_read_u8(r, &p->level) ||
        !zcl_codec_read_u16le(r, &p->descriptors))
        return CLIPS_ERR_BODY;
    if (flags & 0xf8u)
        return CLIPS_ERR_RESERVED_FLAGS;
    if ((flags & 0x05u) == 0)
        return CLIPS_ERR_BODY;
    if (p->level < CLIPS_LEVEL_GENERAL || p->level > CLIPS_LEVEL_MAX)
        return CLIPS_ERR_LEVEL;
    if (p->descriptors & ~CLIPS_DESC_MASK)
        return CLIPS_ERR_DESCRIPTOR;
    p->has_manifest = (flags & 0x01u) != 0;
    p->has_reply_to = (flags & 0x02u) != 0;
    p->has_reshare_of = (flags & 0x04u) != 0;
    return CLIPS_OK;
}

static enum clips_error clips_read_tags(struct zcl_codec_reader *r, struct clips_post *p)
{
    enum clips_error e;

    if (!zcl_codec_read_u8(r, &p->tag_count))
        return CLIPS_ERR_BODY;
    if (p->tag_count > CLIPS_TAGS_MAX)
        return CLIPS_ERR_FIELD;
    for (uint8_t i = 0; i < p->tag_count; i++) {
        e = clips_rd_lenbytes(r, CLIPS_TAG_MAX, p->tags[i], &p->tag_len[i]);
        if (e != CLIPS_OK)
            return e;
        if (!clips_tag_valid(p->tags[i], p->tag_len[i]))
            return CLIPS_ERR_FIELD;
    }
    return CLIPS_OK;
}

static enum clips_error clips_read_post_ids(struct zcl_codec_reader *r, struct clips_post *p)
{
    if (p->has_manifest && !zcl_codec_read_bytes(r, p->manifest_id, sizeof(p->manifest_id)))
        return CLIPS_ERR_BODY;
    if (p->has_reply_to && !zcl_codec_read_bytes(r, p->reply_to, sizeof(p->reply_to)))
        return CLIPS_ERR_BODY;
    if (p->has_reshare_of && !zcl_codec_read_bytes(r, p->reshare_of, sizeof(p->reshare_of)))
        return CLIPS_ERR_BODY;
    return CLIPS_OK;
}

static enum clips_error clips_read_post(struct zcl_codec_reader *r, struct clips_post *p)
{
    enum clips_error e = clips_read_post_head(r, p);

    if (e != CLIPS_OK)
        return e;
    e = clips_read_post_ids(r, p);
    if (e != CLIPS_OK)
        return e;
    e = clips_rd_len16bytes(r, CLIPS_CAPTION_MAX, p->caption, &p->caption_len);
    if (e != CLIPS_OK)
        return e;
    if (!clips_text_wellformed(p->caption, p->caption_len))
        return CLIPS_ERR_TEXT;
    return clips_read_tags(r, p);
}

static enum clips_error clips_write_post_ids(struct zcl_codec_writer *w,
                                             const struct clips_post *p)
{
    if (p->has_manifest && !zcl_codec_write_bytes(w, p->manifest_id, sizeof(p->manifest_id)))
        return CLIPS_ERR_BODY;
    if (p->has_reply_to && !zcl_codec_write_bytes(w, p->reply_to, sizeof(p->reply_to)))
        return CLIPS_ERR_BODY;
    if (p->has_reshare_of && !zcl_codec_write_bytes(w, p->reshare_of, sizeof(p->reshare_of)))
        return CLIPS_ERR_BODY;
    return CLIPS_OK;
}

static enum clips_error clips_write_tags(struct zcl_codec_writer *w, const struct clips_post *p)
{
    enum clips_error e;

    if (p->tag_count > CLIPS_TAGS_MAX)
        return CLIPS_ERR_FIELD;
    if (!zcl_codec_write_u8(w, p->tag_count))
        return CLIPS_ERR_BODY;
    for (uint8_t i = 0; i < p->tag_count; i++) {
        e = clips_wr_lenbytes(w, CLIPS_TAG_MAX, p->tags[i], p->tag_len[i]);
        if (e != CLIPS_OK)
            return e;
    }
    return CLIPS_OK;
}

static enum clips_error clips_write_post(struct zcl_codec_writer *w, const struct clips_post *p)
{
    uint8_t flags = (p->has_manifest ? 0x01u : 0u) | (p->has_reply_to ? 0x02u : 0u) |
                    (p->has_reshare_of ? 0x04u : 0u);
    enum clips_error e;

    if (!zcl_codec_write_u8(w, flags) || !zcl_codec_write_u8(w, p->level) ||
        !zcl_codec_write_u16le(w, p->descriptors))
        return CLIPS_ERR_BODY;
    e = clips_write_post_ids(w, p);
    if (e != CLIPS_OK)
        return e;
    e = clips_wr_len16bytes(w, CLIPS_CAPTION_MAX, p->caption, p->caption_len);
    if (e != CLIPS_OK)
        return e;
    return clips_write_tags(w, p);
}

static enum clips_error clips_read_profile(struct zcl_codec_reader *r, struct clips_profile *p)
{
    uint8_t flag = 0;
    enum clips_error e;

    if (!zcl_codec_read_u8(r, &p->level))
        return CLIPS_ERR_BODY;
    if (!(p->level >= CLIPS_LEVEL_GENERAL && p->level <= CLIPS_LEVEL_MAX))
        return CLIPS_ERR_LEVEL;
    e = clips_rd_textbytes(r, CLIPS_PROFILE_NAME_MAX, p->name, &p->name_len);
    if (e != CLIPS_OK)
        return e;
    e = clips_rd_textbytes(r, CLIPS_PROFILE_BIO_MAX, p->bio, &p->bio_len);
    if (e != CLIPS_OK)
        return e;
    if (!zcl_codec_read_u8(r, &flag))
        return CLIPS_ERR_BODY;
    if (flag > 1)
        return CLIPS_ERR_FIELD;
    p->has_avatar = flag == 1;
    if (p->has_avatar && !zcl_codec_read_bytes(r, p->avatar_id, sizeof(p->avatar_id)))
        return CLIPS_ERR_BODY;
    return clips_rd_textbytes(r, CLIPS_PROFILE_TIP_MAX, p->tip, &p->tip_len);
}

static enum clips_error clips_write_profile(struct zcl_codec_writer *w,
                                            const struct clips_profile *p)
{
    enum clips_error e;

    if (!zcl_codec_write_u8(w, p->level))
        return CLIPS_ERR_BODY;
    e = clips_wr_lenbytes(w, CLIPS_PROFILE_NAME_MAX, p->name, p->name_len);

    if (e != CLIPS_OK)
        return e;
    e = clips_wr_lenbytes(w, CLIPS_PROFILE_BIO_MAX, p->bio, p->bio_len);
    if (e != CLIPS_OK)
        return e;
    if (!zcl_codec_write_u8(w, p->has_avatar ? 1 : 0))
        return CLIPS_ERR_BODY;
    if (p->has_avatar && !zcl_codec_write_bytes(w, p->avatar_id, sizeof(p->avatar_id)))
        return CLIPS_ERR_BODY;
    return clips_wr_lenbytes(w, CLIPS_PROFILE_TIP_MAX, p->tip, p->tip_len);
}

static enum clips_error clips_read_tombstone(struct zcl_codec_reader *r,
                                             struct clips_tombstone *t)
{
    if (!zcl_codec_read_bytes(r, t->target, sizeof(t->target)) ||
        !zcl_codec_read_u8(r, &t->reason))
        return CLIPS_ERR_BODY;
    return t->reason >= 1 && t->reason <= 4 ? CLIPS_OK : CLIPS_ERR_FIELD;
}

static enum clips_error clips_write_tombstone(struct zcl_codec_writer *w,
                                              const struct clips_tombstone *t)
{
    if (!zcl_codec_write_bytes(w, t->target, sizeof(t->target)) ||
        !zcl_codec_write_u8(w, t->reason))
        return CLIPS_ERR_BODY;
    return CLIPS_OK;
}

static enum clips_error clips_read_list(struct zcl_codec_reader *r, struct clips_list *l)
{
    enum clips_error e;

    if (!zcl_codec_read_bytes(r, l->list_object_id, sizeof(l->list_object_id)) ||
        !zcl_codec_read_u32le(r, &l->entry_count))
        return CLIPS_ERR_BODY;
    if (l->entry_count > CLIPS_LIST_ENTRIES_MAX)
        return CLIPS_ERR_FIELD;
    e = clips_rd_textbytes(r, CLIPS_LIST_TITLE_MAX, l->title, &l->title_len);
    if (e != CLIPS_OK)
        return e;
    if (!zcl_codec_read_u8(r, &l->list_kind))
        return CLIPS_ERR_BODY;
    return l->list_kind == 1 || l->list_kind == 2 ? CLIPS_OK : CLIPS_ERR_FIELD;
}

static enum clips_error clips_write_list(struct zcl_codec_writer *w, const struct clips_list *l)
{
    enum clips_error e;

    if (!zcl_codec_write_bytes(w, l->list_object_id, sizeof(l->list_object_id)) ||
        !zcl_codec_write_u32le(w, l->entry_count))
        return CLIPS_ERR_BODY;
    e = clips_wr_lenbytes(w, CLIPS_LIST_TITLE_MAX, l->title, l->title_len);
    if (e != CLIPS_OK)
        return e;
    return zcl_codec_write_u8(w, l->list_kind) ? CLIPS_OK : CLIPS_ERR_BODY;
}

static enum clips_error clips_read_rating(struct zcl_codec_reader *r,
                                          struct clips_rating_body *k)
{
    enum clips_error e;

    if (!zcl_codec_read_bytes(r, k->target, sizeof(k->target)) ||
        !zcl_codec_read_u8(r, &k->level) || !zcl_codec_read_u16le(r, &k->descriptors) ||
        !zcl_codec_read_u8(r, &k->method))
        return CLIPS_ERR_BODY;
    if (k->level > CLIPS_LEVEL_MAX)
        return CLIPS_ERR_LEVEL;
    if (k->descriptors & ~CLIPS_DESC_MASK)
        return CLIPS_ERR_DESCRIPTOR;
    if (k->method < 1 || k->method > 3)
        return CLIPS_ERR_FIELD;
    e = clips_rd_textbytes(r, CLIPS_RATING_NOTE_MAX, k->note, &k->note_len);
    return e;
}

static enum clips_error clips_write_rating(struct zcl_codec_writer *w,
                                           const struct clips_rating_body *k)
{
    if (!zcl_codec_write_bytes(w, k->target, sizeof(k->target)) ||
        !zcl_codec_write_u8(w, k->level) || !zcl_codec_write_u16le(w, k->descriptors) ||
        !zcl_codec_write_u8(w, k->method))
        return CLIPS_ERR_BODY;
    return clips_wr_lenbytes(w, CLIPS_RATING_NOTE_MAX, k->note, k->note_len);
}

static enum clips_error clips_body_read(uint8_t kind, struct zcl_codec_reader *r,
                                        struct clips_body *out)
{
    switch (kind) {
    case CLIPS_KIND_POST:
        return clips_read_post(r, &out->u.post);
    case CLIPS_KIND_PROFILE:
        return clips_read_profile(r, &out->u.profile);
    case CLIPS_KIND_TOMBSTONE:
        return clips_read_tombstone(r, &out->u.tombstone);
    case CLIPS_KIND_LIST:
        return clips_read_list(r, &out->u.list);
    case CLIPS_KIND_RATING:
        return clips_read_rating(r, &out->u.rating);
    default:
        return clips_social_read(kind, r, out);
    }
}

static enum clips_error clips_body_write(const struct clips_body *in,
                                         struct zcl_codec_writer *w)
{
    switch (in->kind) {
    case CLIPS_KIND_POST:
        return clips_write_post(w, &in->u.post);
    case CLIPS_KIND_PROFILE:
        return clips_write_profile(w, &in->u.profile);
    case CLIPS_KIND_TOMBSTONE:
        return clips_write_tombstone(w, &in->u.tombstone);
    case CLIPS_KIND_LIST:
        return clips_write_list(w, &in->u.list);
    case CLIPS_KIND_RATING:
        return clips_write_rating(w, &in->u.rating);
    default:
        return clips_social_write(in, w);
    }
}

enum clips_error clips_body_decode(uint8_t kind, const uint8_t *in, size_t len,
                                   struct clips_body *out)
{
    struct zcl_codec_reader r;
    enum clips_error e;

    if (!out || (!in && len != 0))
        return CLIPS_ERR_ARGUMENT;
    if (len > CLIPS_RECORD_BODY_MAX)
        return CLIPS_ERR_BODY_LEN;
    zcl_codec_reader_init(&r, in, len);
    out->kind = kind;
    e = clips_body_read(kind, &r, out);
    if (e != CLIPS_OK)
        return e;
    return zcl_codec_reader_finish(&r) ? CLIPS_OK : CLIPS_ERR_TRAILING;
}

/* Encode, then decode the result: a body that the decoder would refuse is
 * never returned. */
enum clips_error clips_body_encode(const struct clips_body *in, uint8_t *out,
                                   size_t cap, size_t *written)
{
    struct zcl_codec_writer w;
    struct clips_body check;
    enum clips_error e;

    if (!in || !out || !written)
        return CLIPS_ERR_ARGUMENT;
    zcl_codec_writer_init(&w, out, cap);
    e = clips_body_write(in, &w);
    if (e != CLIPS_OK)
        return e;
    if (!zcl_codec_writer_finish(&w, written))
        return CLIPS_ERR_ARGUMENT;
    return clips_body_decode(in->kind, out, *written, &check);
}
