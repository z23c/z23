/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the REAL module dependency graph, measured from the linker's
 * view (symbols), not from #include lines. For every object in the active
 * compile epoch, nm -A -g is split into DEFINED symbols (the object's
 * module owns them) and UNDEFINED ones (it references them); the join on
 * the symbol name, minus intra-module pairs, is exactly "module A's code
 * cannot link without module B". Modules are navigator groups: lib/<mod>
 * app/<shape> domain/<ctx> core config tools adapters ports root.
 * Ported from tools/dev/module-linkgraph.sh (deleted); the object-tree
 * selection is gate_lib_module_order_objs.c, the cycle report
 * gate_lib_module_order_fas.c.
 *
 * LTO trap: the production tree compiles with -flto=auto, so its objects
 * are slim and nm reads them only through the LTO linker plugin. A
 * binutils without it returns an almost empty table, which would make every
 * consumer report "no cross-module edges" and go green on a lie. So an
 * empty graph from a non-empty object tree is LMG_UNREADABLE, never clean.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "gate_lib_module_order_graph.h"
#include "gate_lib_module_order_priv.h"

enum { LMG_BATCH = 256, LMG_GROUP = 320 };

/* An interning string table: id -> text, with one int and one flag of
 * payload per id (the symbol table keeps its owning module and an
 * "ambiguous" mark there). */
struct lmg_pool {
    char *arena;
    size_t used, cap;
    size_t *off;
    int *aux;
    unsigned char *flag;
    size_t n, ncap;
    int *tab;
    size_t tcap;
};

struct lmg_edge { int from, to, sym, src; };

struct lmg_graph {
    struct lmg_pool mods, syms, srcs;
    struct lmg_edge *ref;
    size_t nref, cref;
};

struct lmg_scan { struct lmg_graph *g; size_t skip; };

static const char *lmg_str(const struct lmg_pool *p, int id)
{
    return p->arena + p->off[id];
}

static uint32_t lmg_hash(const char *s, size_t len)
{
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++)
        h = (h ^ (unsigned char)s[i]) * 16777619u;
    return h;
}

static int lmg_pool_rehash(struct lmg_pool *p)
{
    size_t nt = p->tcap ? p->tcap * 2 : 1024;
    int *t = calloc(nt, sizeof *t);
    if (!t)
        return -1;
    for (size_t i = 0; i < p->n; i++) {
        const char *s = lmg_str(p, (int)i);
        size_t j = lmg_hash(s, strlen(s)) & (nt - 1);
        while (t[j])
            j = (j + 1) & (nt - 1);
        t[j] = (int)i + 1;
    }
    free(p->tab);
    p->tab = t;
    p->tcap = nt;
    return 0;
}

static int lmg_pool_grow(struct lmg_pool *p, size_t len)
{
    if (p->used + len + 1 > p->cap) {
        size_t nc = p->cap ? p->cap * 2 : 65536;
        while (nc < p->used + len + 1)
            nc *= 2;
        char *a = realloc(p->arena, nc);
        if (!a)
            return -1;
        p->arena = a;
        p->cap = nc;
    }
    if (p->n == p->ncap) {
        size_t nc = p->ncap ? p->ncap * 2 : 1024;
        size_t *o = realloc(p->off, nc * sizeof *o);
        if (o)
            p->off = o;
        int *a = o ? realloc(p->aux, nc * sizeof *a) : NULL;
        if (a)
            p->aux = a;
        unsigned char *f = a ? realloc(p->flag, nc) : NULL;
        if (f)
            p->flag = f;
        if (!f)
            return -1;
        p->ncap = nc;
    }
    return 0;
}

/* The id of s[0..len), adding it (aux -1, flag 0) when new; -1 on OOM. */
static int lmg_intern(struct lmg_pool *p, const char *s, size_t len)
{
    if ((p->n + 1) * 2 > p->tcap && lmg_pool_rehash(p) != 0)
        return -1;
    size_t j = lmg_hash(s, len) & (p->tcap - 1);
    while (p->tab[j]) {
        int id = p->tab[j] - 1;
        const char *t = lmg_str(p, id);
        if (strlen(t) == len && memcmp(t, s, len) == 0)
            return id;
        j = (j + 1) & (p->tcap - 1);
    }
    if (lmg_pool_grow(p, len) != 0)
        return -1;
    memcpy(p->arena + p->used, s, len);
    p->arena[p->used + len] = '\0';
    p->off[p->n] = p->used;
    p->aux[p->n] = -1;
    p->flag[p->n] = 0;
    p->used += len + 1;
    p->tab[j] = (int)++p->n;
    return (int)p->n - 1;
}

static void lmg_pool_free(struct lmg_pool *p)
{
    free(p->arena);
    free(p->off);
    free(p->aux);
    free(p->flag);
    free(p->tab);
    memset(p, 0, sizeof *p);
}

/* ── module mapping ───────────────────────────────────────────────────── */

/* Navigator group of a repo-relative source path into out; the name's
 * length, or -1 when it does not fit. */
static int lmg_group(const char *p, char *out, size_t cap)
{
    static const struct { const char *pre; const char *name; } fixed[] = {
        { "core/", "core" }, { "config/", "config" }, { "tools/", "tools" },
        { "adapters/", "adapters" }, { "ports/", "ports" },
    };
    const char *kind = NULL, *rest = NULL;
    if (strncmp(p, "lib/", 4) == 0) {
        kind = "lib/";
        rest = p + 4;
    } else if (strncmp(p, "app/", 4) == 0) {
        kind = "app/";
        rest = p + 4;
    } else if (strncmp(p, "domain/", 7) == 0) {
        kind = "domain/";
        rest = p + 7;
    }
    for (size_t i = 0; !kind && i < sizeof fixed / sizeof fixed[0]; i++)
        if (strncmp(p, fixed[i].pre, strlen(fixed[i].pre)) == 0)
            return snprintf(out, cap, "%s", fixed[i].name);
    const char *slash = kind ? strchr(rest, '/') : NULL;
    if (!slash)
        return snprintf(out, cap, "root");
    int n = snprintf(out, cap, "%s%.*s", kind, (int)(slash - rest), rest);
    return n < 0 || (size_t)n >= cap ? -1 : n;
}

/* ── nm line parsing ──────────────────────────────────────────────────── */

/* Splits body on blank runs in place, after its leading blanks; tok keeps
 * the first three fields. Returns the field count, where trailing blanks
 * add one empty field (as awk's split does) and an empty body is 0. */
static int lmg_split(char *body, const char *tok[3])
{
    int nt = 0;
    char *p = body + strspn(body, " \t");
    while (*p) {
        char *q = p + strcspn(p, " \t");
        if (nt < 3)
            tok[nt] = p;
        nt++;
        char *next = *q ? q + strspn(q, " \t") : q;
        if (*q) {
            *q = '\0';
            if (!*next) { /* trailing blanks: one more, empty, field */
                if (nt < 3)
                    tok[nt] = next;
                nt++;
            }
        }
        p = next;
    }
    return nt;
}

/* Splits the part after the object path into (type, sym) the way nm prints
 * it: "addr type name" for a defined symbol, "type name" for an undefined
 * one (blank address column). 1 = parsed, 0 = skip the line. */
static int lmg_fields(char *body, const char **type, const char **sym)
{
    const char *tok[3] = { NULL, NULL, NULL };
    int nt = lmg_split(body, tok);
    if (nt >= 3) {
        *type = tok[1];
        *sym = tok[2];
    } else if (nt == 2) {
        *type = tok[0];
        *sym = tok[1];
    } else {
        return 0;
    }
    return **sym != '\0';
}

static int lmg_ref_push(struct lmg_graph *g, int mod, int sym, int src)
{
    if (g->nref == g->cref) {
        size_t nc = g->cref ? g->cref * 2 : 4096;
        struct lmg_edge *r = realloc(g->ref, nc * sizeof *r);
        if (!r)
            return -1;
        g->ref = r;
        g->cref = nc;
    }
    g->ref[g->nref++] = (struct lmg_edge){ mod, -1, sym, src };
    return 0;
}

/* First definer owns a symbol; a second module defining it makes it
 * ambiguous (reported as no edge at all). */
static void lmg_define(struct lmg_graph *g, int sym, int mod)
{
    int *owner = &g->syms.aux[sym];
    if (*owner < 0)
        *owner = mod;
    else if (*owner != mod)
        g->syms.flag[sym] = 1;
}

/* One nm -A line "<objpath>:<addr-or-blanks> <type> <symbol>". */
static int lmg_line(void *vctx, char *line)
{
    struct lmg_scan *sc = vctx;
    struct lmg_graph *g = sc->g;
    char *colon = strchr(line, ':');
    const char *type, *sym;
    if (!colon || !lmg_fields(colon + 1, &type, &sym))
        return 0;
    *colon = '\0';
    size_t ol = strlen(line);
    char src[4096], grp[LMG_GROUP];
    int n = snprintf(src, sizeof src, "%s", line + (ol < sc->skip ? ol : sc->skip));
    if (n < 0 || (size_t)n >= sizeof src)
        return -1;
    if (n >= 2 && strcmp(src + n - 2, ".o") == 0)
        src[n - 1] = 'c';
    int gl = lmg_group(src, grp, sizeof grp);
    int mod = gl < 0 ? -1 : lmg_intern(&g->mods, grp, (size_t)gl);
    int sid = mod < 0 ? -1 : lmg_intern(&g->syms, sym, strlen(sym));
    if (sid < 0)
        return -1;
    if (strcmp(type, "U") != 0 && strcmp(type, "w") != 0) {
        lmg_define(g, sid, mod);
        return 0;
    }
    int fid = lmg_intern(&g->srcs, src, (size_t)n);
    return fid < 0 ? -1 : lmg_ref_push(g, mod, sid, fid);
}

/* Runs nm over every object in batches; 0 ok, LMG_NONE when nm is absent,
 * LMG_ERROR otherwise (message on diag). */
static int lmg_scan(struct lmg_graph *g, const struct lmg_objs *o, FILE *diag)
{
    const char *nm = getenv("NM");
    if (!nm || !*nm)
        nm = "nm";
    struct lmg_scan sc = { g, strlen(o->dir) + 1 };
    char *argv[LMG_BATCH + 5];
    for (size_t i = 0; i < o->n; i += LMG_BATCH) {
        size_t k = 0;
        argv[k++] = (char *)nm;
        argv[k++] = (char *)"-A";
        argv[k++] = (char *)"-g";
        argv[k++] = (char *)"--";
        for (size_t j = i; j < o->n && j < i + LMG_BATCH; j++)
            argv[k++] = o->path[j];
        argv[k] = NULL;
        int rc = lmo_nm_stream(argv, lmg_line, &sc);
        if (rc == 127 && diag)
            fprintf(diag, "module-linkgraph: '%s' not found on PATH\n", nm);
        if (rc == 127)
            return LMG_NONE;
        if (rc != 0 && diag)
            fprintf(diag, "module-linkgraph: %s failed (status %d)\n", nm, rc);
        if (rc != 0)
            return LMG_ERROR;
    }
    return 0;
}

/* ── report ───────────────────────────────────────────────────────────── */

static int lmg_cmp_edge(const void *a, const void *b)
{
    const struct lmg_edge *x = a, *y = b;
    if (x->from != y->from)
        return x->from < y->from ? -1 : 1;
    if (x->to != y->to)
        return x->to < y->to ? -1 : 1;
    if (x->sym != y->sym)
        return x->sym < y->sym ? -1 : 1;
    if (x->src != y->src)
        return x->src < y->src ? -1 : 1;
    return 0;
}

/* Keeps only references whose symbol has exactly one owner in ANOTHER
 * module, fills .to, then sorts and drops repeats. Returns the new count. */
static size_t lmg_resolve(struct lmg_graph *g)
{
    size_t w = 0;
    for (size_t i = 0; i < g->nref; i++) {
        struct lmg_edge e = g->ref[i];
        int owner = g->syms.aux[e.sym];
        if (owner < 0 || g->syms.flag[e.sym] || owner == e.from)
            continue;
        e.to = owner;
        g->ref[w++] = e;
    }
    qsort(g->ref, w, sizeof *g->ref, lmg_cmp_edge);
    size_t u = 0;
    for (size_t i = 0; i < w; i++)
        if (u == 0 || lmg_cmp_edge(&g->ref[u - 1], &g->ref[i]) != 0)
            g->ref[u++] = g->ref[i];
    g->nref = u;
    return u;
}

static int lmg_cmp_line(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static char *lmg_fmt(const char *fmt, const char *a, const char *b,
                     const char *c, const char *d)
{
    int n = snprintf(NULL, 0, fmt, a, b, c, d);
    char *s = n < 0 ? NULL : malloc((size_t)n + 1);
    if (s)
        snprintf(s, (size_t)n + 1, fmt, a, b, c, d);
    return s;
}

static char **lmg_edge_lines(const struct lmg_graph *g, size_t *n)
{
    char **v = malloc((g->nref + 1) * sizeof *v);
    *n = 0;
    for (size_t i = 0; v && i < g->nref; i++) {
        const struct lmg_edge *e = &g->ref[i];
        v[*n] = lmg_fmt("%s\t%s\t%s\t%s", lmg_str(&g->mods, e->from),
                        lmg_str(&g->mods, e->to), lmg_str(&g->syms, e->sym),
                        lmg_str(&g->srcs, e->src));
        if (!v[*n]) {
            for (size_t k = 0; k < *n; k++)
                free(v[k]);
            free(v);
            return NULL;
        }
        (*n)++;
    }
    return v;
}

static int lmg_cmp_cstr(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* One summary line for the edges [lo, hi) sharing (from, to): the distinct
 * symbols, sorted. */
static char *lmg_group_line(const struct lmg_graph *g, size_t lo, size_t hi)
{
    const char **sy = malloc((hi - lo) * sizeof *sy);
    if (!sy)
        return NULL;
    size_t ns = 0, len = 0;
    for (size_t i = lo; i < hi; i++)
        if (i == lo || g->ref[i].sym != g->ref[i - 1].sym) {
            sy[ns] = lmg_str(&g->syms, g->ref[i].sym);
            len += strlen(sy[ns++]) + 1;
        }
    qsort(sy, ns, sizeof *sy, lmg_cmp_cstr);
    const char *from = lmg_str(&g->mods, g->ref[lo].from);
    const char *to = lmg_str(&g->mods, g->ref[lo].to);
    size_t cap = strlen(from) + strlen(to) + len + 64;
    char *line = malloc(cap);
    if (line) {
        int off = snprintf(line, cap, "%s -> %s\t%zu\t", from, to, ns);
        for (size_t i = 0; i < ns; i++)
            off += snprintf(line + off, cap - (size_t)off, "%s%s", i ? "," : "",
                            sy[i]);
    }
    free(sy);
    return line;
}

static char **lmg_summary_lines(const struct lmg_graph *g, size_t *n)
{
    char **v = malloc((g->nref + 1) * sizeof *v);
    size_t lo = 0;
    *n = 0;
    while (v && lo < g->nref) {
        size_t hi = lo + 1;
        while (hi < g->nref && g->ref[hi].from == g->ref[lo].from &&
               g->ref[hi].to == g->ref[lo].to)
            hi++;
        v[*n] = lmg_group_line(g, lo, hi);
        if (!v[*n]) {
            while (*n > 0)
                free(v[--*n]);
            free(v);
            return NULL;
        }
        (*n)++;
        lo = hi;
    }
    return v;
}

static void lmg_lines_free(char **v, size_t n)
{
    for (size_t i = 0; v && i < n; i++)
        free(v[i]);
    free(v);
}

static int lmg_emit_lines(char **v, size_t n, int fas, FILE *out)
{
    qsort(v, n, sizeof *v, lmg_cmp_line);
    int rc = 0;
    if (fas)
        rc = lmg_fas((const char *const *)v, n, out);
    else
        for (size_t i = 0; i < n; i++)
            fprintf(out, "%s\n", v[i]);
    return rc;
}

static void lmg_zero_msg(const struct lmg_objs *o, const char *nm, FILE *diag)
{
    if (!diag)
        return;
    fprintf(diag, "module-linkgraph: %zu object(s) under %s produced ZERO\n"
            "  cross-module edges. That is not a clean tree — it means the "
            "symbol\n  tables could not be read. Almost always: these are "
            "slim -flto=auto\n  objects and '%s' has no LTO plugin. Point "
            "the tool at a\n  non-LTO tree instead:\n    z23-lint "
            "module-linkgraph --obj-dir build/test-rel-obj/epochs/<epoch>\n"
            "  or install a binutils with the GCC LTO plugin.\n",
            o->n, o->dir_rel, nm);
}

static int lmg_modules(const struct lmg_graph *g, const struct lmg_objs *o,
                       FILE *out, FILE *diag)
{
    if (g->mods.n == 0) {
        if (diag)
            fprintf(diag, "module-linkgraph: no modules resolved from %s\n",
                    o->dir_rel);
        return LMG_UNREADABLE;
    }
    char **v = malloc(g->mods.n * sizeof *v);
    if (!v)
        return LMG_ERROR;
    for (size_t i = 0; i < g->mods.n; i++)
        v[i] = (char *)lmg_str(&g->mods, (int)i);
    qsort(v, g->mods.n, sizeof *v, lmg_cmp_line);
    for (size_t i = 0; i < g->mods.n; i++)
        fprintf(out, "%s\n", v[i]);
    free(v);
    return LMG_OK;
}

static int lmg_edges_report(struct lmg_graph *g, int mode,
                            const struct lmg_objs *o, FILE *out, FILE *diag)
{
    size_t nm = 0;
    lmg_resolve(g);
    char **v = mode == LMG_EDGES ? lmg_edge_lines(g, &nm)
                                 : lmg_summary_lines(g, &nm);
    if (!v)
        return LMG_ERROR;
    if (nm == 0) {
        const char *nmb = getenv("NM");
        lmg_zero_msg(o, nmb && *nmb ? nmb : "nm", diag);
        lmg_lines_free(v, nm);
        return LMG_UNREADABLE;
    }
    int rc = lmg_emit_lines(v, nm, mode == LMG_FAS, out);
    lmg_lines_free(v, nm);
    return rc == 0 ? LMG_OK : (rc == 1 ? LMG_NONE : LMG_ERROR);
}

int lmg_run(const struct lmg_req *req, FILE *out, FILE *diag)
{
    if (req->obj_dir && req->obj_root) {
        if (diag)
            fputs("module-linkgraph: --obj-dir and --obj-root are mutually "
                  "exclusive\n", diag);
        return LMG_USAGE;
    }
    struct lmg_objs o;
    int rc = lmg_collect(req, &o, diag);
    if (rc == 0) {
        static struct lmg_graph g;
        memset(&g, 0, sizeof g);
        rc = lmg_scan(&g, &o, diag);
        if (rc == 0 && req->mode == LMG_MODULES)
            rc = lmg_modules(&g, &o, out, diag);
        else if (rc == 0)
            rc = lmg_edges_report(&g, req->mode, &o, out, diag);
        lmg_pool_free(&g.mods);
        lmg_pool_free(&g.syms);
        lmg_pool_free(&g.srcs);
        free(g.ref);
    }
    lmg_objs_free(&o);
    return rc;
}
