/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: fixtures for the lib module link-graph measurement
 * (gate_lib_module_order_graph.c). Writes tiny relocatable ELF64 objects
 * with a real symbol table (one defined function, any number of undefined
 * references) so the real nm joins them, then checks the object-tree rules
 * (newest epoch, stale-source filter) and the --edges / --modules / --fas
 * reports against the expected text. Used by
 * gate_lib_module_order_selftest.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_lib_module_order_graph.h"
#include "gate_lib_module_order_priv.h"

enum { LMSG_PATH = 1024, LMSG_IMG = 4096, LMSG_REPORT = 8192, LMSG_SYMS = 8,
       LMSG_SHNUM = 5 };

static void lmsg_put(unsigned char *b, size_t off, uint64_t v, unsigned n)
{
    for (unsigned i = 0; i < n; i++)
        b[off + i] = (unsigned char)(v >> (8 * i));
}

/* Appends s to the string table at *used; returns its offset. */
static uint32_t lmsg_str(unsigned char *tab, size_t *used, const char *s)
{
    uint32_t at = (uint32_t)*used;
    size_t n = strlen(s) + 1;
    memcpy(tab + *used, s, n);
    *used += n;
    return at;
}

static void lmsg_shdr(unsigned char *b, size_t at, const uint64_t f[8])
{
    lmsg_put(b, at, f[0], 4);
    lmsg_put(b, at + 4, f[1], 4);
    lmsg_put(b, at + 8, f[2], 8);
    lmsg_put(b, at + 24, f[3], 8);
    lmsg_put(b, at + 32, f[4], 8);
    lmsg_put(b, at + 40, f[5], 4);
    lmsg_put(b, at + 44, f[6], 4);
    lmsg_put(b, at + 56, f[7], 8);
}

static void lmsg_ehdr(unsigned char *b, size_t shoff)
{
    memcpy(b, "\177ELF\2\1\1", 7);
    lmsg_put(b, 16, 1, 2);       /* ET_REL */
    lmsg_put(b, 18, 62, 2);      /* EM_X86_64 */
    lmsg_put(b, 20, 1, 4);
    lmsg_put(b, 40, shoff, 8);
    lmsg_put(b, 52, 64, 2);
    lmsg_put(b, 58, 64, 2);
    lmsg_put(b, 60, LMSG_SHNUM, 2);
    lmsg_put(b, 62, LMSG_SHNUM - 1, 2);
}

/* Builds the object image: .text (empty), .symtab, .strtab, .shstrtab.
 * Symbol 1 is the defined function def, the rest are undefined globals.
 * Returns the image size. */
static size_t lmsg_image(unsigned char *b, const char *def,
                         const char *const *undef, int nundef)
{
    static const char shs[] = "\0.text\0.symtab\0.strtab\0.shstrtab";
    unsigned char strtab[512] = { 0 };
    size_t su = 1;
    int nsym = 2 + nundef;
    uint32_t name[LMSG_SYMS + 2] = { 0 };
    name[1] = lmsg_str(strtab, &su, def);
    for (int i = 0; i < nundef; i++)
        name[2 + i] = lmsg_str(strtab, &su, undef[i]);
    size_t sto = 64, sym = (sto + su + 7) & ~(size_t)7;
    size_t shso = sym + 24 * (size_t)nsym;
    size_t shdr = (shso + sizeof shs + 7) & ~(size_t)7;
    memset(b, 0, shdr + 64 * LMSG_SHNUM);
    memcpy(b + sto, strtab, su);
    memcpy(b + shso, shs, sizeof shs);
    for (int i = 1; i < nsym; i++) {
        size_t at = sym + 24 * (size_t)i;
        lmsg_put(b, at, name[i], 4);
        b[at + 4] = i == 1 ? 0x12 : 0x10; /* GLOBAL FUNC / GLOBAL NOTYPE */
        lmsg_put(b, at + 6, i == 1 ? 1 : 0, 2);
    }
    lmsg_ehdr(b, shdr);
    const uint64_t t[8] = { 1, 1, 6, 64, 0, 0, 0, 0 };
    const uint64_t s[8] = { 7, 2, 0, sym, 24 * (uint64_t)nsym, 3, 1, 24 };
    const uint64_t r[8] = { 15, 3, 0, sto, su, 0, 0, 0 };
    const uint64_t h[8] = { 23, 3, 0, shso, sizeof shs, 0, 0, 0 };
    lmsg_shdr(b, shdr + 64, t);
    lmsg_shdr(b, shdr + 128, s);
    lmsg_shdr(b, shdr + 192, r);
    lmsg_shdr(b, shdr + 256, h);
    return shdr + 64 * LMSG_SHNUM;
}

static int lmsg_write_obj(const char *path, const char *def,
                          const char *const *undef, int nundef)
{
    static unsigned char img[LMSG_IMG];
    size_t n = lmsg_image(img, def, undef, nundef);
    FILE *f = fopen(path, "wb");
    if (!f)
        return die("z23-lint: cannot write %s\n", path);
    int bad = fwrite(img, 1, n, f) != n;
    bad |= fclose(f) != 0;
    return bad ? die("z23-lint: cannot write %s\n", path) : 0;
}

/* Lays down lib/<mod>/src/<mod>.o under dir: it defines def_<mod> and
 * references def_<t> for each target t. */
static int lmsg_module(const char *dir, const char *mod,
                       const char *const *to, int nto)
{
    char path[LMSG_PATH], def[LMSG_PATH], sub[LMSG_PATH];
    char refs[LMSG_SYMS][128];
    const char *undef[LMSG_SYMS];
    if (nto > LMSG_SYMS)
        return 2;
    for (int i = 0; i < nto; i++) {
        if (ovf(snprintf(refs[i], sizeof refs[i], "def_%s", to[i]),
                sizeof refs[i]))
            return 2;
        undef[i] = refs[i];
    }
    if (ovf(snprintf(sub, sizeof sub, "%s/lib/%s/src", dir, mod), sizeof sub) ||
        ovf(snprintf(path, sizeof path, "%s/%s.o", sub, mod), sizeof path) ||
        ovf(snprintf(def, sizeof def, "def_%s", mod), sizeof def))
        return 2;
    int rc = csr_mkdirs(sub);
    return rc ? rc : lmsg_write_obj(path, def, undef, nto);
}

/* Index of name in the module table, adding it when new; -1 when full. */
static int lmsg_mod_index(char mods[][64], int *nm, const char *name)
{
    for (int i = 0; i < *nm; i++)
        if (strcmp(mods[i], name) == 0)
            return i;
    if (*nm >= LMSG_SYMS)
        return -1;
    snprintf(mods[*nm], 64, "%s", name);
    return (*nm)++;
}

/* Spec "a>b;a>c;d": one module per distinct name, with an edge per "x>y".
 * Returns 0, or non-zero after a message. */
int lmos_write_graph(const char *dir, const char *spec)
{
    char mods[LMSG_SYMS][64], to[LMSG_SYMS][LMSG_SYMS][64];
    int nto[LMSG_SYMS] = { 0 }, nm = 0;
    char buf[256];
    if (ovf(snprintf(buf, sizeof buf, "%s", spec), sizeof buf))
        return 2;
    for (char *tok = strtok(buf, ";"); tok; tok = strtok(NULL, ";")) {
        char *gt = strchr(tok, '>');
        if (gt)
            *gt++ = '\0';
        int m = lmsg_mod_index(mods, &nm, tok);
        if (gt && m >= 0 && nto[m] < LMSG_SYMS) {
            snprintf(to[m][nto[m]++], sizeof to[0][0], "%s", gt);
            (void)lmsg_mod_index(mods, &nm, gt); /* every target is a module */
        }
    }
    for (int m = 0; m < nm; m++) {
        const char *tp[LMSG_SYMS];
        for (int i = 0; i < nto[m]; i++)
            tp[i] = to[m][i];
        int rc = lmsg_module(dir, mods[m], tp, nto[m]);
        if (rc)
            return rc;
    }
    return 0;
}

/* ── report checks ────────────────────────────────────────────────────── */

static int lmsg_report(int mode, const char *root, const char *objroot,
                       char *buf, size_t cap)
{
    struct lmg_req rq = { mode, root, NULL, objroot };
    FILE *f = fmemopen(buf, cap, "w");
    if (!f)
        return -1;
    memset(buf, 0, cap);
    int rc = lmg_run(&rq, f, NULL);
    fclose(f);
    return rc;
}

static int lmsg_expect(const char *what, int mode, const char *root,
                       const char *objroot, int want_rc, const char *want,
                       const char *forbid)
{
    char buf[LMSG_REPORT];
    int rc = lmsg_report(mode, root, objroot, buf, sizeof buf);
    if (rc != want_rc || (want && !strstr(buf, want)) ||
        (forbid && strstr(buf, forbid))) {
        fprintf(stderr, "check_lib_module_order selftest: %s: rc=%d (want "
                "%d), report lacks \"%s\" or holds \"%s\"\n%s", what, rc,
                want_rc, want ? want : "", forbid ? forbid : "", buf);
        return 1;
    }
    printf("  selftest ok: %s\n", what);
    return 0;
}

/* Two epochs (the newer one wins) plus an object whose source is gone. */
static int lmsg_tree(const char *root)
{
    char old[LMSG_PATH], cur[LMSG_PATH], src[LMSG_PATH];
    if (ovf(snprintf(old, sizeof old, "%s/build/obj/epochs/old", root),
            sizeof old) ||
        ovf(snprintf(cur, sizeof cur, "%s/build/obj/epochs/new", root),
            sizeof cur) ||
        ovf(snprintf(src, sizeof src, "%s/lib/alpha/src", root), sizeof src))
        return 2;
    int rc = csr_mkdirs(old) || csr_mkdirs(cur) || csr_mkdirs(src);
    rc = rc ? rc : lmos_write_graph(old, "zeta>alpha");
    rc = rc ? rc : lmos_write_graph(cur, "alpha>beta;beta>alpha;gone>alpha");
    if (rc)
        return rc;
    struct timeval tv[2] = { { 1000, 0 }, { 1000, 0 } };
    if (utimes(old, tv) != 0)
        return die("z23-lint: cannot set mtime on %s\n", old);
    char path[LMSG_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/alpha.c", src), sizeof path))
        return 2;
    rc = csr_write(path, "int def_alpha;\n");
    if (rc || ovf(snprintf(src, sizeof src, "%s/lib/beta/src", root), sizeof src))
        return rc ? rc : 2;
    if (csr_mkdirs(src) || ovf(snprintf(path, sizeof path, "%s/beta.c", src),
                              sizeof path))
        return 2;
    return csr_write(path, "int def_beta;\n");
}

int lmos_graph_selftest(const char *root)
{
    int rc = lmsg_tree(root);
    if (rc)
        return rc;
    int bad = 0;
    bad |= lmsg_expect("edges: newest epoch, stale source dropped",
                       LMG_EDGES, root, "build/obj", 0,
                       "lib/alpha\tlib/beta\tdef_beta\tlib/alpha/src/alpha.c",
                       "lib/gone");
    bad |= lmsg_expect("edges: the older epoch is not measured", LMG_EDGES,
                       root, "build/obj", 0, NULL, "lib/zeta");
    bad |= lmsg_expect("modules: stale object leaves no module", LMG_MODULES,
                       root, "build/obj", 0, "lib/beta\n", "lib/gone");
    bad |= lmsg_expect("fas: a two-module cycle needs one back edge", LMG_FAS,
                       root, "build/obj", 0,
                       "MINIMUM FEEDBACK ARC SET over the whole lib/ subgraph "
                       "= 1", NULL);
    bad |= lmsg_expect("summary: unknown root measures nothing", LMG_SUMMARY,
                       root, "build/missing", LMG_NONE, NULL, NULL);
    return bad;
}
