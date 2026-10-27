/* ztemplate — minimal {{variable}} template engine. */
#include "ztemplate/ztemplate.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdckdint.h>
#include <string.h>

typedef enum { SEG_LITERAL, SEG_VAR } seg_kind;

typedef struct {
    seg_kind kind;
    size_t   off;  /* offset into the template's own text copy */
    size_t   len;
} segment;

struct ztemplate {
    char    *text;    /* owned copy of the template */
    segment *segs;
    size_t   nsegs;
    size_t   cap_segs;
};

static bool seg_push(ztemplate *tp, seg_kind kind, size_t off, size_t len)
{
    if (len == 0) return true;
    /* coalesce adjacent literals (only when truly contiguous —
       skipped comments leave a gap) */
    if (kind == SEG_LITERAL && tp->nsegs > 0 &&
        tp->segs[tp->nsegs - 1].kind == SEG_LITERAL &&
        tp->segs[tp->nsegs - 1].off + tp->segs[tp->nsegs - 1].len == off) {
        tp->segs[tp->nsegs - 1].len += len;
        return true;
    }
    if (tp->nsegs == tp->cap_segs) {
        size_t ncap = 16, bytes;
        if (tp->cap_segs && ckd_mul(&ncap, tp->cap_segs, 2)) return false;
        if (ckd_mul(&bytes, ncap, sizeof *tp->segs)) return false;
        segment *ns = realloc(tp->segs, bytes);
        if (!ns) return false;
        tp->segs = ns;
        tp->cap_segs = ncap;
    }
    tp->segs[tp->nsegs++] = (segment){ kind, off, len };
    return true;
}

static bool is_name_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
}

static bool template_input_valid(const char *text, size_t len)
{
    return (text || len == 0) && len != SIZE_MAX;
}

/* allocate a template that owns a copy of text[0..text_len); NULL on failure */
static ztemplate *template_with_text(const char *text, size_t text_len)
{
    ztemplate *tp = calloc(1, sizeof *tp);
    if (!tp) return NULL;
    tp->text = malloc(text_len + 1);
    if (!tp->text) { free(tp); return NULL; }
    if (text_len) memcpy(tp->text, text, text_len);
    tp->text[text_len] = '\0';
    return tp;
}

/* find closing }} */
static size_t find_tag_close(const char *text, size_t text_len, size_t close)
{
    while (close + 1 < text_len &&
           !(text[close] == '}' && text[close + 1] == '}'))
        close++;
    return close;
}

/* trim whitespace */
static void trim_tag_bounds(const char *text, size_t *nb, size_t *ne)
{
    while (*nb < *ne && (text[*nb] == ' ' || text[*nb] == '\t'))
        (*nb)++;
    while (*ne > *nb && (text[*ne - 1] == ' ' || text[*ne - 1] == '\t'))
        (*ne)--;
}

/* first offset in [nb, ne) holding a non-name char, or ne if there is none */
static size_t find_bad_name_char(const char *text, size_t nb, size_t ne)
{
    for (size_t i = nb; i < ne; i++)
        if (!is_name_char(text[i])) return i;
    return ne;
}

/* outcome of handling one {{...}} tag */
typedef enum {
    TAG_CONSUMED,      /* tag consumed; *p and *lit_start moved past it */
    TAG_UNTERMINATED,  /* no closing }} found */
    TAG_EMPTY,         /* nothing left after trimming */
    TAG_BAD_NAME_CHAR, /* non-name character inside the tag */
    TAG_PUSH_FAIL      /* segment push failed */
} tag_outcome;

/* parse the {{...}} tag at *p; on TAG_CONSUMED *p and *lit_start move past it */
static tag_outcome parse_tag(ztemplate *tp, size_t text_len, size_t *p,
                             size_t *lit_start, size_t *err_pos)
{
    const char *t = tp->text;
    size_t start = *p;
    size_t close = find_tag_close(t, text_len, start + 2);
    if (close + 1 >= text_len) {
        if (err_pos) *err_pos = start;
        return TAG_UNTERMINATED; /* unterminated tag */
    }
    /* flush preceding literal */
    if (!seg_push(tp, SEG_LITERAL, *lit_start, start - *lit_start))
        return TAG_PUSH_FAIL;
    size_t nb = start + 2, ne = close;
    /* comment? */
    if (nb < ne && t[nb] == '!') {
        *p = close + 2;
        *lit_start = *p;
        return TAG_CONSUMED;
    }
    trim_tag_bounds(t, &nb, &ne);
    if (nb == ne) {
        if (err_pos) *err_pos = start;
        return TAG_EMPTY; /* empty tag */
    }
    size_t bad = find_bad_name_char(t, nb, ne);
    if (bad != ne) {
        if (err_pos) *err_pos = bad;
        return TAG_BAD_NAME_CHAR;
    }
    if (!seg_push(tp, SEG_VAR, nb, ne - nb))
        return TAG_PUSH_FAIL;
    *p = close + 2;
    *lit_start = *p;
    return TAG_CONSUMED;
}

ztemplate *ztemplate_parse(const char *text, size_t text_len,
                           size_t *err_pos)
{
    if (!template_input_valid(text, text_len)) return NULL;
    ztemplate *tp = template_with_text(text, text_len);
    if (!tp) return NULL;

    size_t p = 0, lit_start = 0;
    while (p < text_len) {
        if (tp->text[p] == '{' && p + 1 < text_len && tp->text[p + 1] == '{') {
            tag_outcome r = parse_tag(tp, text_len, &p, &lit_start, err_pos);
            if (r != TAG_CONSUMED) {
                ztemplate_free(tp);
                return NULL;
            }
        } else {
            p++;
        }
    }
    if (!seg_push(tp, SEG_LITERAL, lit_start, text_len - lit_start)) {
        ztemplate_free(tp);
        return NULL;
    }
    return tp;
}

void ztemplate_free(ztemplate *tp)
{
    if (!tp) return;
    free(tp->text);
    free(tp->segs);
    free(tp);
}

static void copy_fragment(char *out, size_t out_cap, size_t offset,
                          const char *src, size_t len)
{
    if (out && offset < out_cap) {
        size_t room = out_cap - offset;
        size_t take = len < room ? len : room;
        if (take > 0) memcpy(out + offset, src, take);
    }
}

static bool append_fragment(char *out, size_t out_cap, size_t *offset,
                            const char *src, size_t len, size_t *out_len)
{
    if (len > SIZE_MAX - *offset) {
        if (out && out_cap > 0)
            out[*offset < out_cap ? *offset : out_cap - 1] = '\0';
        *out_len = SIZE_MAX;
        return false;
    }
    copy_fragment(out, out_cap, *offset, src, len);
    *offset += len;
    return true;
}

ztemplate_status ztemplate_render(const ztemplate *tp,
                                  ztemplate_lookup lookup, void *ctx,
                                  char *out, size_t out_cap,
                                  size_t *out_len)
{
    if (!tp || !lookup || !out_len) return ZTEMPLATE_PARSE_ERROR;
    size_t o = 0;
    for (size_t i = 0; i < tp->nsegs; i++) {
        const segment *s = &tp->segs[i];
        const char *src;
        size_t slen;
        if (s->kind == SEG_LITERAL) {
            src = tp->text + s->off;
            slen = s->len;
        } else {
            const char *val = NULL;
            size_t vlen = 0;
            if (!lookup(tp->text + s->off, s->len, &val, &vlen, ctx))
                return ZTEMPLATE_UNKNOWN_VAR;
            if (!val && vlen > 0) return ZTEMPLATE_UNKNOWN_VAR;
            src = val;
            slen = vlen;
        }
        if (!append_fragment(out, out_cap, &o, src, slen, out_len))
            return ZTEMPLATE_OVERFLOW;
    }
    if (out && out_cap > 0)
        out[o < out_cap ? o : out_cap - 1] = '\0';
    *out_len = o;
    if (!out || o >= out_cap)
        return ZTEMPLATE_OVERFLOW;
    return ZTEMPLATE_OK;
}

bool ztemplate_foreach_var(const ztemplate *tp,
                           bool (*fn)(const char *name, size_t name_len,
                                      void *ctx),
                           void *ctx)
{
    if (!tp || !fn) return false;
    for (size_t i = 0; i < tp->nsegs; i++) {
        if (tp->segs[i].kind != SEG_VAR) continue;
        /* deduplicate against earlier var segments */
        bool seen = false;
        for (size_t j = 0; j < i; j++) {
            if (tp->segs[j].kind == SEG_VAR &&
                tp->segs[j].len == tp->segs[i].len &&
                memcmp(tp->text + tp->segs[j].off,
                       tp->text + tp->segs[i].off,
                       tp->segs[i].len) == 0) {
                seen = true;
                break;
            }
        }
        if (!seen && !fn(tp->text + tp->segs[i].off, tp->segs[i].len, ctx))
            return false;
    }
    return true;
}

static bool count_one(const char *name, size_t len, void *ctx)
{
    (void)name;
    (void)len;
    (*(size_t *)ctx)++;
    return true;
}

size_t ztemplate_var_count(const ztemplate *tp)
{
    size_t n = 0;
    if (!tp) return 0;
    ztemplate_foreach_var(tp, count_one, &n);
    return n;
}
