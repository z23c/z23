/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Clips body codecs for reaction, comment, follow, block and report kinds. */

#include "clips_internal.h"

static enum clips_error clips_read_reaction(struct zcl_codec_reader *r,
                                            struct clips_reaction *x)
{
    if (!zcl_codec_read_bytes(r, x->target, sizeof(x->target)) ||
        !zcl_codec_read_u8(r, &x->reaction))
        return CLIPS_ERR_BODY;
    return x->reaction <= 5 ? CLIPS_OK : CLIPS_ERR_FIELD;
}

static enum clips_error clips_read_comment(struct zcl_codec_reader *r, struct clips_comment *c)
{
    enum clips_error e;

    if (!zcl_codec_read_bytes(r, c->target, sizeof(c->target)) ||
        !zcl_codec_read_bytes(r, c->parent, sizeof(c->parent)))
        return CLIPS_ERR_BODY;
    e = clips_rd_len16bytes(r, CLIPS_COMMENT_MAX, c->text, &c->text_len);
    if (e != CLIPS_OK)
        return e;
    if (c->text_len == 0)
        return CLIPS_ERR_FIELD;
    return clips_text_wellformed(c->text, c->text_len) ? CLIPS_OK : CLIPS_ERR_TEXT;
}

static enum clips_error clips_read_follow(struct zcl_codec_reader *r, struct clips_follow *f)
{
    if (!zcl_codec_read_bytes(r, f->target_author, sizeof(f->target_author)) ||
        !zcl_codec_read_u8(r, &f->flags))
        return CLIPS_ERR_BODY;
    return (f->flags & ~0x01u) == 0 ? CLIPS_OK : CLIPS_ERR_FIELD;
}

static enum clips_error clips_check_block(const struct clips_block *b)
{
    if (b->target_type != 1 && b->target_type != 2)
        return CLIPS_ERR_FIELD;
    if (b->flags & ~0x01u)
        return CLIPS_ERR_FIELD;
    if (b->target_type == 1) {
        for (size_t i = 32; i < sizeof(b->target); i++) {
            if (b->target[i] != 0)
                return CLIPS_ERR_FIELD;
        }
    }
    return CLIPS_OK;
}

static enum clips_error clips_read_block(struct zcl_codec_reader *r, struct clips_block *b)
{
    if (!zcl_codec_read_u8(r, &b->target_type) ||
        !zcl_codec_read_bytes(r, b->target, sizeof(b->target)) ||
        !zcl_codec_read_u8(r, &b->flags))
        return CLIPS_ERR_BODY;
    return clips_check_block(b);
}

static enum clips_error clips_read_report(struct zcl_codec_reader *r, struct clips_report *p)
{
    if (!zcl_codec_read_bytes(r, p->target, sizeof(p->target)) ||
        !zcl_codec_read_u8(r, &p->reason))
        return CLIPS_ERR_BODY;
    if (p->reason < 1 || p->reason > 7)
        return CLIPS_ERR_FIELD;
    return clips_rd_text16bytes(r, CLIPS_REPORT_NOTE_MAX, p->note, &p->note_len);
}

enum clips_error clips_social_read(uint8_t kind, struct zcl_codec_reader *r,
                                   struct clips_body *out)
{
    switch (kind) {
    case CLIPS_KIND_REACTION:
        return clips_read_reaction(r, &out->u.reaction);
    case CLIPS_KIND_COMMENT:
        return clips_read_comment(r, &out->u.comment);
    case CLIPS_KIND_FOLLOW:
        return clips_read_follow(r, &out->u.follow);
    case CLIPS_KIND_BLOCK:
        return clips_read_block(r, &out->u.block);
    case CLIPS_KIND_REPORT:
        return clips_read_report(r, &out->u.report);
    default:
        return CLIPS_ERR_KIND;
    }
}

static enum clips_error clips_write_reaction(struct zcl_codec_writer *w,
                                             const struct clips_reaction *x)
{
    if (!zcl_codec_write_bytes(w, x->target, sizeof(x->target)) ||
        !zcl_codec_write_u8(w, x->reaction))
        return CLIPS_ERR_BODY;
    return CLIPS_OK;
}

static enum clips_error clips_write_comment(struct zcl_codec_writer *w,
                                            const struct clips_comment *c)
{
    if (!zcl_codec_write_bytes(w, c->target, sizeof(c->target)) ||
        !zcl_codec_write_bytes(w, c->parent, sizeof(c->parent)))
        return CLIPS_ERR_BODY;
    return clips_wr_len16bytes(w, CLIPS_COMMENT_MAX, c->text, c->text_len);
}

static enum clips_error clips_write_follow(struct zcl_codec_writer *w,
                                           const struct clips_follow *f)
{
    if (!zcl_codec_write_bytes(w, f->target_author, sizeof(f->target_author)) ||
        !zcl_codec_write_u8(w, f->flags))
        return CLIPS_ERR_BODY;
    return CLIPS_OK;
}

static enum clips_error clips_write_block(struct zcl_codec_writer *w,
                                          const struct clips_block *b)
{
    if (!zcl_codec_write_u8(w, b->target_type) ||
        !zcl_codec_write_bytes(w, b->target, sizeof(b->target)) ||
        !zcl_codec_write_u8(w, b->flags))
        return CLIPS_ERR_BODY;
    return CLIPS_OK;
}

static enum clips_error clips_write_report(struct zcl_codec_writer *w,
                                           const struct clips_report *p)
{
    if (!zcl_codec_write_bytes(w, p->target, sizeof(p->target)) ||
        !zcl_codec_write_u8(w, p->reason))
        return CLIPS_ERR_BODY;
    return clips_wr_len16bytes(w, CLIPS_REPORT_NOTE_MAX, p->note, p->note_len);
}

enum clips_error clips_social_write(const struct clips_body *in, struct zcl_codec_writer *w)
{
    switch (in->kind) {
    case CLIPS_KIND_REACTION:
        return clips_write_reaction(w, &in->u.reaction);
    case CLIPS_KIND_COMMENT:
        return clips_write_comment(w, &in->u.comment);
    case CLIPS_KIND_FOLLOW:
        return clips_write_follow(w, &in->u.follow);
    case CLIPS_KIND_BLOCK:
        return clips_write_block(w, &in->u.block);
    case CLIPS_KIND_REPORT:
        return clips_write_report(w, &in->u.report);
    default:
        return CLIPS_ERR_KIND;
    }
}
