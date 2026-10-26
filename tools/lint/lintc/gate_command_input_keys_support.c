/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: growable text, interned words and ordered word sets for the
 * check-command-input-keys gate. Allocation failure ends the run with exit
 * status 2: a verdict is never reported off a partial scan.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "base/safe_alloc.h"
#include "lintc.h"
#include "gate_command_input_keys_priv.h"

void *cik_mem(void *old, size_t n, const char *label)
{
    void *p = zcl_realloc(old, n, label);
    if (!p) {
        fputs("check_command_input_keys: FATAL — out of memory; refusing"
              " to report a verdict.\n", stderr);
        exit(2);
    }
    return p;
}

char *cik_dup(const char *s, size_t n)
{
    char *p = cik_mem(NULL, n + 1, "cik_dup");
    memcpy(p, s, n);
    p[n] = '\0';
    return p;
}

void cik_buf_put(struct cik_buf *b, const char *s, size_t n)
{
    if (b->n + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 64;
        while (cap < b->n + n + 1)
            cap *= 2;
        b->p = cik_mem(b->p, cap, "cik_buf");
        b->cap = cap;
    }
    if (n)
        memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = '\0';
}

void cik_buf_putc(struct cik_buf *b, char c)
{
    cik_buf_put(b, &c, 1);
}

void cik_buf_puts(struct cik_buf *b, const char *s)
{
    cik_buf_put(b, s, strlen(s));
}

void cik_buf_clear(struct cik_buf *b)
{
    lintc_buf_clear(&b->p, &b->n);
}

void cik_buf_free(struct cik_buf *b)
{
    free(b->p);
    *b = (struct cik_buf){ 0 };
}

const char *cik_buf_str(const struct cik_buf *b)
{
    return b->p ? b->p : "";
}

char *cik_slurp(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    struct cik_buf b = { 0 };
    char chunk[8192];
    size_t got;
    bool bad;
    if (!f)
        return NULL;
    while ((got = fread(chunk, 1, sizeof chunk, f)) > 0)
        cik_buf_put(&b, chunk, got);
    bad = ferror(f) != 0;
    fclose(f);
    if (bad) {
        cik_buf_free(&b);
        return NULL;
    }
    if (b.n && b.p[b.n - 1] != '\n')
        cik_buf_putc(&b, '\n');
    *len = b.n;
    return b.p ? b.p : cik_dup("", 0);
}

static size_t cik_hash(const char *s, size_t n)
{
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++)
        h = (h ^ (unsigned char)s[i]) * 1099511628211ULL;
    return (size_t)h;
}

static void cik_dict_rehash(struct cik_dict *d)
{
    d->tcap = d->tcap ? d->tcap * 2 : 1024;
    free(d->tab);
    d->tab = cik_mem(NULL, d->tcap * sizeof *d->tab, "cik_dict_tab");
    memset(d->tab, 0, d->tcap * sizeof *d->tab);
    for (size_t i = 0; i < d->n; i++) {
        size_t h = cik_hash(d->word[i], strlen(d->word[i])) & (d->tcap - 1);
        while (d->tab[h])
            h = (h + 1) & (d->tcap - 1);
        d->tab[h] = (int)i + 1;
    }
}

int cik_intern(struct cik_dict *d, const char *s, size_t n)
{
    size_t h;
    if (d->n * 2 >= d->tcap)
        cik_dict_rehash(d);
    h = cik_hash(s, n) & (d->tcap - 1);
    for (; d->tab[h]; h = (h + 1) & (d->tcap - 1)) {
        const char *w = d->word[d->tab[h] - 1];
        if (strncmp(w, s, n) == 0 && w[n] == '\0')
            return d->tab[h] - 1;
    }
    if (d->n == d->cap) {
        d->cap = d->cap ? d->cap * 2 : 256;
        d->word = cik_mem(d->word, d->cap * sizeof *d->word, "cik_dict");
    }
    d->word[d->n] = cik_dup(s, n);
    d->tab[h] = (int)d->n + 1;
    return (int)d->n++;
}

void cik_dict_free(struct cik_dict *d)
{
    for (size_t i = 0; i < d->n; i++)
        free(d->word[i]);
    free(d->word);
    free(d->tab);
    *d = (struct cik_dict){ 0 };
}

static size_t cik_set_slot(const struct cik_set *s, int id)
{
    return ((size_t)id * 2654435761u) & (s->tcap - 1);
}

bool cik_set_has(const struct cik_set *s, int id)
{
    if (!s->tcap)
        return false;
    for (size_t h = cik_set_slot(s, id); s->tab[h]; h = (h + 1) & (s->tcap - 1))
        if (s->tab[h] - 1 == id)
            return true;
    return false;
}

static void cik_set_place(struct cik_set *s, int id)
{
    size_t h = cik_set_slot(s, id);
    while (s->tab[h])
        h = (h + 1) & (s->tcap - 1);
    s->tab[h] = id + 1;
}

static void cik_set_rehash(struct cik_set *s)
{
    s->tcap = s->tcap ? s->tcap * 2 : 8;
    free(s->tab);
    s->tab = cik_mem(NULL, s->tcap * sizeof *s->tab, "cik_set_tab");
    memset(s->tab, 0, s->tcap * sizeof *s->tab);
    for (size_t i = 0; i < s->n; i++)
        cik_set_place(s, s->v[i]);
}

bool cik_set_add(struct cik_set *s, int id)
{
    if (cik_set_has(s, id))
        return false;
    if (s->n * 2 >= s->tcap)
        cik_set_rehash(s);
    if (s->n == s->cap) {
        s->cap = s->cap ? s->cap * 2 : 8;
        s->v = cik_mem(s->v, s->cap * sizeof *s->v, "cik_set");
    }
    s->v[s->n++] = id;
    cik_set_place(s, id);
    return true;
}

void cik_set_clear(struct cik_set *s)
{
    s->n = 0;
    if (s->tcap)
        memset(s->tab, 0, s->tcap * sizeof *s->tab);
}

void cik_set_free(struct cik_set *s)
{
    free(s->v);
    free(s->tab);
    *s = (struct cik_set){ 0 };
}
