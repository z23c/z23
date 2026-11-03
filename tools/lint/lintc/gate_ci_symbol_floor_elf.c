/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the ELF half of the check-ci-symbol-floor gate. Reads the section
 * table of a 32- or 64-bit ELF (either byte order) and walks every
 * SHT_GNU_verneed and SHT_GNU_verdef table, folding each version name into
 * its family (GLIBC_, GLIBCXX_, CXXABI_). Bounded reads only: no heap, no
 * whole-file slurp, no <elf.h>. Every offset is checked against the byte
 * source before it is read, and any malformed table is "not parseable".
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "gate_ci_symbol_floor_priv.h"

enum {
    CSF_SHT_VERDEF = 0x6ffffffd,
    CSF_SHT_VERNEED = 0x6ffffffe,
    CSF_EHDR64 = 64,
    CSF_EHDR32 = 52,
    CSF_SHDR64 = 64,
    CSF_SHDR32 = 40,
    CSF_ENT_MAX = 20,    /* the larger of a verneed and a verdef entry */
    CSF_AUX_MAX = 16     /* the larger of a vernaux and a verdaux entry */
};

/* Field offsets of one version-table entry family. verneed and verdef share
 * the same 32-bit layout but place their fields differently. */
struct csf_vlay {
    unsigned entry_size, cnt_at, aux_at, next_at;
    unsigned aux_size, aux_name_at, aux_next_at;
};

static const struct csf_vlay k_need = { 16, 2, 8, 12, 16, 8, 12 };
static const struct csf_vlay k_def = { 20, 6, 12, 16, 8, 0, 4 };

struct csf_hdr {
    int is64, be;
    uint64_t shoff;
    unsigned shentsize, shnum;
};

struct csf_sec {
    uint32_t type, link;
    uint64_t off, size;
};

/* Everything one version-table walk needs, in one place. */
struct csf_walkc {
    const struct csf_src *s;
    const struct csf_sec *sec, *str;
    const struct csf_vlay *lay;
    int be;
};

int csf_read_at(const struct csf_src *s, uint64_t off, unsigned char *buf,
                size_t n)
{
    if (off > s->size || n > s->size - off)
        return -1;
    if (s->mem) {
        memcpy(buf, s->mem + off, n);
        return 0;
    }
    if (!s->f || fseeko(s->f, (off_t)off, SEEK_SET) != 0)
        return -1;
    return fread(buf, 1, n, s->f) == n ? 0 : -1;
}

/* Decode an n-byte unsigned field (n = 1, 2, 4 or 8) in the given order. */
static uint64_t csf_get(const unsigned char *p, unsigned n, int be)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < n; i++) {
        unsigned idx = be ? i : n - 1 - i;
        v = (v << 8) | p[idx];
    }
    return v;
}

static int csf_ident(const struct csf_src *s, struct csf_hdr *h)
{
    unsigned char id[16];
    if (csf_read_at(s, 0, id, sizeof id) != 0)
        return 1;
    if (id[0] != 0x7f || id[1] != 'E' || id[2] != 'L' || id[3] != 'F')
        return 1;
    if ((id[4] != 1 && id[4] != 2) || (id[5] != 1 && id[5] != 2))
        return 1;
    h->is64 = id[4] == 2;
    h->be = id[5] == 2;
    return 0;
}

/* The ELF header fields the walk needs: the section table location and
 * shape. Field offsets differ between the 32- and 64-bit headers. */
static int csf_ehdr(const struct csf_src *s, struct csf_hdr *h)
{
    unsigned char b[CSF_EHDR64];
    unsigned want = 0;
    if (csf_ident(s, h) != 0)
        return 1;
    size_t hl = h->is64 ? CSF_EHDR64 : CSF_EHDR32;
    if (csf_read_at(s, 0, b, hl) != 0)
        return 1;
    h->shoff = h->is64 ? csf_get(b + 0x28, 8, h->be)
                       : csf_get(b + 0x20, 4, h->be);
    h->shentsize = (unsigned)csf_get(b + (h->is64 ? 0x3A : 0x2E), 2, h->be);
    h->shnum = (unsigned)csf_get(b + (h->is64 ? 0x3C : 0x30), 2, h->be);
    want = h->is64 ? CSF_SHDR64 : CSF_SHDR32;
    if (h->shentsize != want || h->shnum == 0 || h->shnum > CSF_MAXSEC)
        return 1;
    return h->shoff > s->size ? 1 : 0;
}

static int csf_sec_at(const struct csf_src *s, const struct csf_hdr *h,
                      unsigned idx, struct csf_sec *sc)
{
    unsigned char b[CSF_SHDR64];
    if (idx >= h->shnum)
        return 1;
    uint64_t at = h->shoff + (uint64_t)idx * h->shentsize;
    if (csf_read_at(s, at, b, h->shentsize) != 0)
        return 1;
    sc->type = (uint32_t)csf_get(b + 4, 4, h->be);
    if (h->is64) {
        sc->off = csf_get(b + 24, 8, h->be);
        sc->size = csf_get(b + 32, 8, h->be);
        sc->link = (uint32_t)csf_get(b + 40, 4, h->be);
    } else {
        sc->off = csf_get(b + 16, 4, h->be);
        sc->size = csf_get(b + 20, 4, h->be);
        sc->link = (uint32_t)csf_get(b + 24, 4, h->be);
    }
    return 0;
}

/* Copy the NUL-terminated name at str.off + rel into out. A name that does
 * not end inside the string table or inside cap is not parseable. */
static int csf_cstr(const struct csf_src *s, const struct csf_sec *str,
                     uint64_t rel, char *out, size_t cap)
{
    for (size_t i = 0;; i++, rel++) {
        unsigned char c;
        if (i + 1 >= cap || rel >= str->size)
            return 1;
        if (csf_read_at(s, str->off + rel, &c, 1) != 0)
            return 1;
        out[i] = (char)c;
        if (c == 0)
            return 0;
    }
}

/* Dotted numeric compare, like sort -V on version tokens: 2.4 < 2.38 and
 * 2.2 < 2.2.5. Each part saturates rather than wrapping. */
static unsigned long long csf_part(const char **p)
{
    unsigned long long v = 0;
    while (**p >= '0' && **p <= '9') {
        if (v < 1000000000000ULL)
            v = v * 10 + (unsigned long long)(**p - '0');
        (*p)++;
    }
    if (**p == '.')
        (*p)++;
    return v;
}

int csf_vcmp(const char *a, const char *b)
{
    for (;;) {
        if (!*a && !*b)
            return 0;
        unsigned long long x = csf_part(&a);
        unsigned long long y = csf_part(&b);
        if (x != y)
            return x < y ? -1 : 1;
    }
}

/* Fold one version name into its family. The token after the family prefix
 * must be the digits-and-dots run grep -oE "PREFIX[0-9.]+" would match, so
 * GLIBC_PRIVATE names no version. 0 ok, 1 over-long token. */
static int csf_fold(struct csf_fam *fam, const char *pfx, const char *name)
{
    size_t pl = strlen(pfx);
    if (strncmp(name, pfx, pl) != 0)
        return 0;
    const char *t = name + pl;
    size_t n = strspn(t, "0123456789.");
    if (n == 0)
        return 0;
    if (n >= CSF_VER)
        return 1;
    char tok[CSF_VER];
    memcpy(tok, t, n);
    tok[n] = '\0';
    if (!fam->present || csf_vcmp(tok, fam->max) > 0)
        memcpy(fam->max, tok, n + 1);
    fam->present = 1;
    return 0;
}

static int csf_note(struct csf_floor *f, const char *name)
{
    return csf_fold(&f->glibc, "GLIBC_", name)
        || csf_fold(&f->glibcxx, "GLIBCXX_", name)
        || csf_fold(&f->cxxabi, "CXXABI_", name);
}

/* Fold every aux name of one version entry. cnt and the aux chain come from
 * the entry header; every aux is bounds-checked against the section. */
static int csf_auxes(const struct csf_walkc *c, uint64_t eo,
                     const unsigned char *e, struct csf_floor *out)
{
    const struct csf_vlay *L = c->lay;
    uint64_t cnt = csf_get(e + L->cnt_at, 2, c->be);
    uint64_t ao = eo + csf_get(e + L->aux_at, 4, c->be);
    for (uint64_t j = 0; j < cnt; j++) {
        unsigned char a[CSF_AUX_MAX];
        char nm[CSF_NAME];
        if (ao > c->sec->size || L->aux_size > c->sec->size - ao)
            return 1;
        if (csf_read_at(c->s, c->sec->off + ao, a, L->aux_size) != 0)
            return 1;
        uint64_t name = csf_get(a + L->aux_name_at, 4, c->be);
        if (csf_cstr(c->s, c->str, name, nm, sizeof nm) || csf_note(out, nm))
            return 1;
        uint64_t nx = csf_get(a + L->aux_next_at, 4, c->be);
        if (nx == 0)
            break;
        ao += nx;
    }
    return 0;
}

/* Walk one verneed or verdef table entry by entry (the vn_next/vd_next
 * chain), bounded by CSF_MAXVER entries. */
static int csf_walk(const struct csf_walkc *c, struct csf_floor *out)
{
    const struct csf_vlay *L = c->lay;
    uint64_t eo = 0;
    for (unsigned k = 0; k < CSF_MAXVER; k++) {
        unsigned char e[CSF_ENT_MAX];
        if (eo > c->sec->size || L->entry_size > c->sec->size - eo)
            return 1;
        if (csf_read_at(c->s, c->sec->off + eo, e, L->entry_size) != 0)
            return 1;
        if (csf_auxes(c, eo, e, out))
            return 1;
        uint64_t next = csf_get(e + L->next_at, 4, c->be);
        if (next == 0)
            return 0;
        eo += next;
    }
    return 1;
}

/* Walk one version section against the string table it links to. */
static int csf_table(const struct csf_src *s, const struct csf_hdr *h,
                     const struct csf_sec *sc, struct csf_floor *out)
{
    struct csf_sec str;
    struct csf_walkc c;
    if (sc->off > s->size || sc->size > s->size - sc->off)
        return 1;
    if (csf_sec_at(s, h, sc->link, &str) != 0)
        return 1;
    c.s = s;
    c.sec = sc;
    c.str = &str;
    c.lay = sc->type == CSF_SHT_VERNEED ? &k_need : &k_def;
    c.be = h->be;
    return csf_walk(&c, out);
}

int csf_scan(const struct csf_src *s, struct csf_floor *out)
{
    struct csf_hdr h;
    memset(out, 0, sizeof *out);
    if (csf_ehdr(s, &h) != 0)
        return 1;
    for (unsigned i = 0; i < h.shnum; i++) {
        struct csf_sec sc;
        if (csf_sec_at(s, &h, i, &sc) != 0)
            return 1;
        if (sc.type != CSF_SHT_VERNEED && sc.type != CSF_SHT_VERDEF)
            continue;
        if (csf_table(s, &h, &sc, out) != 0)
            return 1;
    }
    return 0;
}
