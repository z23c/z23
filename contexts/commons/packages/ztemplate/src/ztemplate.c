/* ztemplate — minimal {{variable}} template engine. */
#include "ztemplate/ztemplate.h"

#include <stdlib.h>
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
        size_t ncap = tp->cap_segs ? tp->cap_segs * 2 : 16;
        segment *ns = realloc(tp->segs, ncap * sizeof *ns);
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

ztemplate *ztemplate_parse(const char *text, size_t text_len,
                           size_t *err_pos)
{
    if (!text && text_len > 0) return NULL;
    ztemplate *tp = calloc(1, sizeof *tp);
    if (!tp) return NULL;
    tp->text = malloc(text_len + 1);
    if (!tp->text) { free(tp); return NULL; }
    if (text_len) memcpy(tp->text, text, text_len);
    tp->text[text_len] = '\0';

    size_t p = 0, lit_start = 0;
    while (p < text_len) {
        if (tp->text[p] == '{' && p + 1 < text_len && tp->text[p + 1] == '{') {
            /* find closing }} */
            size_t close = p + 2;
            while (close + 1 < text_len &&
                   !(tp->text[close] == '}' && tp->text[close + 1] == '}'))
                close++;
            if (close + 1 >= text_len) {
                if (err_pos) *err_pos = p;
                ztemplate_free(tp);
                return NULL; /* unterminated tag */
            }
            /* flush preceding literal */
            if (!seg_push(tp, SEG_LITERAL, lit_start, p - lit_start)) {
                ztemplate_free(tp);
                return NULL;
            }
            size_t nb = p + 2, ne = close;
            /* comment? */
            if (nb < ne && tp->text[nb] == '!') {
                p = close + 2;
                lit_start = p;
                continue;
            }
            /* trim whitespace */
            while (nb < ne && (tp->text[nb] == ' ' || tp->text[nb] == '\t'))
                nb++;
            while (ne > nb && (tp->text[ne - 1] == ' ' || tp->text[ne - 1] == '\t'))
                ne--;
            if (nb == ne) {
                if (err_pos) *err_pos = p;
                ztemplate_free(tp);
                return NULL; /* empty tag */
            }
            for (size_t i = nb; i < ne; i++) {
                if (!is_name_char(tp->text[i])) {
                    if (err_pos) *err_pos = i;
                    ztemplate_free(tp);
                    return NULL;
                }
            }
            if (!seg_push(tp, SEG_VAR, nb, ne - nb)) {
                ztemplate_free(tp);
                return NULL;
            }
            p = close + 2;
            lit_start = p;
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
        if (out && o < out_cap) {
            size_t room = out_cap - o;
            size_t take = slen < room ? slen : room;
            memcpy(out + o, src, take);
        }
        o += slen;
    }
    if (out && out_cap > 0)
        out[o < out_cap ? o : out_cap - 1] = '\0';
    *out_len = o;
    if (!out || o >= out_cap + 1 || o > out_cap)
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
