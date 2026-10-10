/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The FINDING-line parser. See engine/engine_findings.h for the format.
 * Pure: reads text[0..len), writes only its out arguments.
 */

#include "engine/engine_findings.h"

#include <string.h>

#define EFD_PREFIX "FINDING "
#define EFD_NONE "NO FINDINGS"

struct efd_cur {
    const char *p;
    size_t      n;
};

/* Take the field up to the next space (or the end) and step past that space.
 * `more` says a space followed. An empty field is false. */
static bool efd_field(struct efd_cur *c, const char **f, size_t *fl, bool *more)
{
    const char *sp = c->n ? memchr(c->p, ' ', c->n) : NULL;
    size_t l = sp ? (size_t)(sp - c->p) : c->n;
    size_t step = l + (sp ? 1u : 0u);
    *f = c->p;
    *fl = l;
    *more = sp != NULL;
    c->p += step;
    c->n -= step;
    return l > 0;
}

static bool efd_is(const char *f, size_t fl, const char *word)
{
    return fl == strlen(word) && memcmp(f, word, fl) == 0;
}

static bool efd_kind(const char *f, size_t fl, enum ers_kind *k)
{
    if (efd_is(f, fl, "CHANGE"))
        *k = ERS_KIND_CHANGE;
    else if (efd_is(f, fl, "CLAIM"))
        *k = ERS_KIND_CLAIM;
    else
        return false;
    return true;
}

static bool efd_severity(const char *f, size_t fl, enum efd_severity *s)
{
    if (efd_is(f, fl, "high"))
        *s = EFD_SEV_HIGH;
    else if (efd_is(f, fl, "medium"))
        *s = EFD_SEV_MEDIUM;
    else if (efd_is(f, fl, "low"))
        *s = EFD_SEV_LOW;
    else
        return false;
    return true;
}

/* `path:line`: the first colon splits; everything after it is digits. */
static bool efd_where(const char *f, size_t fl, struct efd_finding *out)
{
    const char *colon = memchr(f, ':', fl);
    if (!colon)
        return false;
    size_t plen = (size_t)(colon - f);
    size_t dlen = fl - plen - 1u;
    if (plen == 0 || plen >= ERS_FILE_MAX || dlen == 0)
        return false;
    int64_t v = 0;
    for (size_t i = 0; i < dlen; i++) {
        char d = colon[1 + i];
        if (d < '0' || d > '9')
            return false;
        v = v * 10 + (d - '0');
        if (v > EFD_LINE_MAX)
            return false;
    }
    if (v < 1)
        return false;
    memcpy(out->path, f, plen);
    out->path[plen] = '\0';
    out->line = v;
    return true;
}

/* The part of a FINDING line after the prefix. */
static bool efd_fields(struct efd_cur c, struct efd_finding *out)
{
    const char *f;
    size_t fl;
    bool more;
    if (!efd_field(&c, &f, &fl, &more) || !more || !efd_kind(f, fl, &out->kind))
        return false;
    if (!efd_field(&c, &f, &fl, &more) || !more ||
        !efd_severity(f, fl, &out->severity))
        return false;
    if (!efd_field(&c, &f, &fl, &more) || !efd_where(f, fl, out))
        return false;
    out->text = c.p;
    out->text_len = c.n;
    return true;
}

static void efd_line(const char *l, size_t n, struct efd_finding *out,
                     size_t cap, struct efd_result *res)
{
    if (n == strlen(EFD_NONE) && memcmp(l, EFD_NONE, n) == 0) {
        res->no_findings = true;
        return;
    }
    size_t pre = strlen(EFD_PREFIX);
    if (n < pre || memcmp(l, EFD_PREFIX, pre) != 0)
        return;
    struct efd_finding f;
    memset(&f, 0, sizeof(f));
    struct efd_cur c = {l + pre, n - pre};
    if (!efd_fields(c, &f)) {
        res->illformed++;
        return;
    }
    if (out && res->findings < cap)
        out[res->findings] = f;
    else
        res->truncated = true;
    res->findings++;
}

void efd_parse(const char *text, size_t len, struct efd_finding *out,
               size_t cap, struct efd_result *res)
{
    memset(res, 0, sizeof(*res));
    size_t pos = 0;
    while (text && pos < len) {
        const char *nl = memchr(text + pos, '\n', len - pos);
        size_t end = nl ? (size_t)(nl - text) : len;
        size_t n = end - pos;
        if (n > 0 && text[pos + n - 1u] == '\r')
            n--;
        efd_line(text + pos, n, out, cap, res);
        pos = end + 1u;
    }
}
