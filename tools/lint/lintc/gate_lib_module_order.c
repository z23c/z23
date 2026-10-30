/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-lib-module-order — lib/ module link order (RATCHET).
 * Ported from tools/scripts/check_lib_module_order.sh (deleted). Proves the
 * declared link order in engine/composition/lib_module_order.def against the
 * MEASURED symbol graph (tools/dev/module-linkgraph.sh over compiled
 * objects). Three failures: (a) the .def module set disagreeing with the
 * lib/ tree on disk, (b) a graph module the .def does not rank, (c) a back
 * edge (rank(to) >= rank(from)) not grandfathered in
 * tools/scripts/lib_module_order_baseline.txt. With no compiled objects the
 * gate reports NOT MEASURED and exits 0, unless ZCL_LINT_REQUIRE_LINKGRAPH=1.
 * ZCL_LINKGRAPH_OBJ_DIR is the explicit test seam for the object tree.
 * Selftest: gate_lib_module_order_selftest.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_lib_module_order_priv.h"

static const char k_lmo_gate[] = "check_lib_module_order";
static const char k_lmo_def_rel[] = "engine/composition/lib_module_order.def";
static const char k_lmo_base_rel[] =
    "tools/scripts/lib_module_order_baseline.txt";
static const char k_lmo_tool_rel[] = "tools/dev/module-linkgraph.sh";
static const char k_lmo_obj_rel[] = "build/obj";

enum { LMO_MAX_MODS = 128, LMO_NAME = 64, LMO_PATH = 1024,
       LMO_MAX_BASE = 128, LMO_KEY = 256,
       LMO_MAX_UNDEC = 256, LMO_MAX_VIOL = 512, LMO_ROW = 256,
       LMO_MAX_DIRS = 128, LMO_LINE = 1024,
       LMO_GRAPH_CAP = 1048576 };

struct lmo_mods { char name[LMO_MAX_MODS][LMO_NAME]; int n; };
struct lmo_base {
    char key[LMO_MAX_BASE][LMO_KEY];
    int n;
    char tree[LMO_KEY];
    int tree_seen;
};
struct lmo_undec { char name[LMO_MAX_UNDEC][LMO_NAME]; int n; };
struct lmo_viol { char row[LMO_MAX_VIOL][LMO_ROW]; int n; };

struct lmo_paths {
    char def[LMO_PATH], base[LMO_PATH], tool[LMO_PATH];
};

struct lmo_grade {
    struct lmo_mods *mods;
    struct lmo_base *base;
    int hit[LMO_MAX_BASE];
    struct lmo_undec und;
    struct lmo_viol vio;
    int fail;
};

static int lmo_cmp_key(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

/* Sort rows in place and drop duplicates; returns the new count. */
static int lmo_sort_dedupe(char *rows, size_t width, int n)
{
    qsort(rows, (size_t)n, width, lmo_cmp_key);
    int w = 0;
    for (int i = 0; i < n; i++)
        if (w == 0 || strcmp(rows + (size_t)(w - 1) * width,
                             rows + (size_t)i * width) != 0)
            memcpy(rows + (size_t)w++ * width, rows + (size_t)i * width,
                   width);
    return w;
}

/* ── line reading ─────────────────────────────────────────────────────── */

/* Reads one line (newline stripped) into line. 1 = got a line, 0 = EOF,
 * -1 = read error or a line longer than cap-1 (message printed). *nl is set
 * when the line was newline-terminated. */
static int lmo_next_line(FILE *f, char *line, size_t cap, int *nl,
                         const char *what)
{
    if (!fgets(line, (int)cap, f)) {
        if (!ferror(f))
            return 0;
        fprintf(stderr, "%s: read error on %s\n", k_lmo_gate, what);
        return -1;
    }
    size_t n = strlen(line);
    *nl = n > 0 && line[n - 1] == '\n';
    if (*nl)
        line[n - 1] = '\0';
    else if (!feof(f)) {
        fprintf(stderr, "%s: %s has a line longer than %zu bytes\n",
                k_lmo_gate, what, cap - 1);
        return -1;
    }
    return 1;
}

/* ── .def parsing ─────────────────────────────────────────────────────── */

/* Matches one LIB_MODULE("name") declaration line; fills name. 1 = match,
 * 0 = not a declaration, -1 = a name too long for the fixed buffers. */
static int lmo_def_name(const char *line, char *name, size_t cap)
{
    size_t i = 0;
    while (isspace((unsigned char)line[i]))
        i++;
    const char *p = line + i;
    if (strncmp(p, "LIB_MODULE(\"", 12) != 0)
        return 0;
    p += 12;
    size_t j = 0;
    while (p[j] && (isalnum((unsigned char)p[j]) || p[j] == '_')) {
        if (j + 1 >= cap) {
            fprintf(stderr, "%s: module name exceeds %zu characters\n",
                    k_lmo_gate, cap - 1);
            return -1;
        }
        name[j] = p[j];
        j++;
    }
    name[j] = '\0';
    if (j == 0 || p[j] != '"' || p[j + 1] != ')')
        return 0;
    return 1;
}

/* Appends s as row *n of a width-wide table holding at most max rows. 0 ok,
 * 2 (message printed) when the table is full or s does not fit. */
static int lmo_put(char *rows, size_t width, int *n, int max,
                   const char *what, const char *s)
{
    if (*n >= max) {
        fprintf(stderr, "%s: %s exceed %d\n", k_lmo_gate, what, max);
        return 2;
    }
    if (ovf(snprintf(rows + (size_t)*n * width, width, "%s", s), width))
        return 2;
    (*n)++;
    return 0;
}

static int lmo_def_add(struct lmo_mods *m, const char *name)
{
    return lmo_put(m->name[0], LMO_NAME, &m->n, LMO_MAX_MODS,
                   "module declarations", name);
}

/* Loads the .def in line order (rank = position). 0 ok, 1 missing, 2 err. */
static int lmo_load_def(const char *path, struct lmo_mods *m, FILE *out)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(out, "%s: FAIL — missing %s\n", k_lmo_gate, k_lmo_def_rel);
        return 1;
    }
    char line[LMO_LINE], name[LMO_NAME];
    int nl, rc = 0, got;
    while (rc == 0 && (got = lmo_next_line(f, line, sizeof line, &nl,
                                           k_lmo_def_rel)) > 0) {
        int d = lmo_def_name(line, name, sizeof name);
        if (d < 0)
            rc = 2;
        else if (d > 0)
            rc = lmo_def_add(m, name);
    }
    fclose(f);
    return rc ? rc : (got < 0 ? 2 : 0);
}

/* Rank of "lib/<name>" (1-based); 0 when not declared. Later duplicates
 * win, matching the associative-array overwrite of the shell original. */
static int lmo_rank_of(const struct lmo_mods *m, const char *lib)
{
    if (strncmp(lib, "lib/", 4) != 0)
        return 0;
    int rank = 0;
    for (int i = 0; i < m->n; i++)
        if (strcmp(m->name[i], lib + 4) == 0)
            rank = i + 1;
    return rank;
}

/* ── baseline ─────────────────────────────────────────────────────────── */

/* Mirrors the shell's sed header match: a line that starts with '#', then
 * blanks, measured-from-tree:, blanks; the remainder (trailing blanks kept)
 * is the tree. Returns 1 and fills out on match. */
static int lmo_tree_decl(const char *raw, char *out, size_t cap)
{
    static const char tag[] = "measured-from-tree:";
    const char *p = raw;
    if (*p != '#')
        return 0;
    p++;
    while (isspace((unsigned char)*p))
        p++;
    if (strncmp(p, tag, sizeof tag - 1) != 0)
        return 0;
    p += sizeof tag - 1;
    while (isspace((unsigned char)*p))
        p++;
    if (ovf(snprintf(out, cap, "%s", p), cap))
        return -1;
    return 1;
}

static int lmo_base_stash(struct lmo_base *b, const char *line)
{
    return lmo_put(b->key[0], LMO_KEY, &b->n, LMO_MAX_BASE,
                   "baseline entries", line);
}

/* True for the lines the shell loop skips: empty, or ^[[:space:]]*#. */
static int lmo_base_skippable(const char *line)
{
    const char *p = line;
    if (*p == '\0')
        return 1;
    while (isspace((unsigned char)*p))
        p++;
    return *p == '#';
}

/* One baseline line, matched the way the shell does: the first
 * "#measured-from-tree:" header wins (even when empty); every line that is
 * not empty and not a comment is a key VERBATIM (indented and
 * whitespace-only lines included); a final line with no newline is never
 * read by `while read`, so it is not a key. 0 ok, 2 fatal. */
static int lmo_base_line(struct lmo_base *b, const char *line, int nl)
{
    if (!b->tree_seen) {
        int d = lmo_tree_decl(line, b->tree, sizeof b->tree);
        if (d < 0)
            return 2;
        b->tree_seen = d;
    }
    if (!nl || lmo_base_skippable(line))
        return 0;
    return lmo_base_stash(b, line);
}

/* Loads the baseline (creating it when missing) and the first
 * measured-from-tree header. 0 ok, 2 fatal. */
static int lmo_load_baseline(const char *path, struct lmo_base *b)
{
    if (access(path, F_OK) != 0) {
        FILE *f = fopen(path, "a");
        if (!f)
            return die("check_lib_module_order: cannot create %s\n", path);
        fclose(f);
    }
    FILE *f = fopen(path, "r");
    if (!f)
        return die("check_lib_module_order: cannot read %s\n", path);
    char line[LMO_KEY];
    int nl, rc = 0, got;
    while (rc == 0 && (got = lmo_next_line(f, line, sizeof line, &nl,
                                           k_lmo_base_rel)) > 0)
        rc = lmo_base_line(b, line, nl);
    fclose(f);
    return rc ? rc : (got < 0 ? 2 : 0);
}


/* Marks every baseline row equal to key as hit (duplicate rows collapse in
 * the shell's associative array). Returns 1 when the key is baselined. */
static int lmo_base_hit(struct lmo_grade *g, const char *key)
{
    int found = 0;
    for (int i = 0; i < g->base->n; i++)
        if (strcmp(g->base->key[i], key) == 0) {
            g->hit[i] = 1;
            found = 1;
        }
    return found;
}

/* ── def-vs-tree declaration check ────────────────────────────────────── */

/* Prints, one per line, entries of a that are not in b (both sorted). */
static void lmo_comm(const char a[][LMO_NAME], int na,
                     const char b[][LMO_NAME], int nb, FILE *out)
{
    int i = 0, j = 0;
    while (i < na) {
        int c = j < nb ? strcmp(a[i], b[j]) : -1;
        if (c == 0) {
            i++;
            j++;
        } else if (c < 0) {
            fprintf(out, "    %s\n", a[i]);
            i++;
        } else {
            j++;
        }
    }
}

static int lmo_set_equal(const char a[][LMO_NAME], int na,
                         const char b[][LMO_NAME], int nb)
{
    if (na != nb)
        return 0;
    for (int i = 0; i < na; i++)
        if (strcmp(a[i], b[i]) != 0)
            return 0;
    return 1;
}

/* 0 = the .def matches the disk set; 1 = mismatch reported; 2 = error. */
static int lmo_check_declared(const struct lmo_mods *m,
                              char disk[][LMO_NAME], int nd, FILE *out)
{
    static char ds[LMO_MAX_MODS][LMO_NAME], dk[LMO_MAX_DIRS][LMO_NAME];
    int i;
    for (i = 0; i < m->n && i < LMO_MAX_MODS; i++)
        memcpy(ds[i], m->name[i], LMO_NAME);
    int ns = lmo_sort_dedupe(ds[0], LMO_NAME, i);
    for (i = 0; i < nd && i < LMO_MAX_DIRS; i++)
        memcpy(dk[i], disk[i], LMO_NAME);
    int ndk = lmo_sort_dedupe(dk[0], LMO_NAME, nd);
    if (lmo_set_equal(ds, ns, dk, ndk))
        return 0;
    fprintf(out, "%s: FAIL — %s does not match the lib/ tree.\n", k_lmo_gate,
            k_lmo_def_rel);
    fprintf(out, "  declared but no such module directory:\n");
    lmo_comm(ds, ns, dk, ndk, out);
    fprintf(out, "  present in lib/ but never declared:\n");
    lmo_comm(dk, ndk, ds, ns, out);
    fprintf(out, "\n");
    fprintf(out, "  An undeclared module compiles nothing: the Makefile "
            "derives every\n");
    fprintf(out, "  lib/ source glob and -I flag from this file, so a module "
            "missing\n");
    fprintf(out, "  here is a module missing from the build. Add it at the "
            "lowest rank\n");
    fprintf(out, "  that keeps this gate green.\n");
    return 1;
}

/* Basenames of the physical module dirs into disk (unsorted); *n receives
 * the count. 0 ok, 2 on an over-long name or a formatting overflow. */
static int lmo_disk_names(char dirs[][RS_PATH], int nd,
                          char disk[][LMO_NAME], int *n)
{
    *n = 0;
    for (int i = 0; i < nd; i++) {
        const char *slash = strrchr(dirs[i], '/');
        const char *base = slash ? slash + 1 : dirs[i];
        if (strlen(base) >= LMO_NAME) {
            fprintf(stderr, "%s: module name exceeds %d\n", k_lmo_gate,
                    LMO_NAME);
            return 2;
        }
        if (ovf(snprintf(disk[*n], LMO_NAME, "%s", base), LMO_NAME))
            return 2;
        (*n)++;
    }
    return 0;
}

/* ── graph edge grading ───────────────────────────────────────────────── */

/* Extracts the idx-th tab-separated field; 0 ok, 1 absent, 2 too long. */
static int lmo_tab_field(const char *line, int idx, char *out, size_t cap)
{
    int cur = 0;
    const char *p = line;
    for (;;) {
        const char *tab = strchr(p, '\t');
        size_t len = tab ? (size_t)(tab - p) : strlen(p);
        if (cur == idx) {
            if (len >= cap)
                return 2;
            memcpy(out, p, len);
            out[len] = '\0';
            return 0;
        }
        if (!tab)
            return 1;
        p = tab + 1;
        cur++;
    }
}

/* Splits "A -> B" on the first and last separator (the shell's %% and ##
 * expansions); 0 ok, 1 no separator, 2 a side too long. */
static int lmo_split_edge(const char *edge, char *from, char *to)
{
    const char *first = strstr(edge, " -> ");
    const char *last = NULL;
    if (!first)
        return 1;
    for (const char *q = first; (q = strstr(q, " -> ")) != NULL; q += 4)
        last = q;
    size_t fl = (size_t)(first - edge);
    const char *tp = last + 4;
    size_t tl = strlen(tp);
    if (fl >= LMO_ROW || tl >= LMO_ROW)
        return 2;
    memcpy(from, edge, fl);
    from[fl] = '\0';
    memcpy(to, tp, tl);
    to[tl] = '\0';
    return 0;
}

static int lmo_undeclared(struct lmo_grade *g, const char *name)
{
    if (strlen(name) >= LMO_NAME || g->und.n >= LMO_MAX_UNDEC) {
        fprintf(stderr, "%s: undeclared module list exceeds %d\n", k_lmo_gate,
                LMO_MAX_UNDEC);
        return 2;
    }
    if (ovf(snprintf(g->und.name[g->und.n], LMO_NAME, "%s", name), LMO_NAME))
        return 2;
    g->und.n++;
    g->fail = 1;
    return 0;
}

static int lmo_viol_add(struct lmo_grade *g, const char *from, const char *to,
                        int rf, int rt, const char *count)
{
    if (g->vio.n >= LMO_MAX_VIOL) {
        fprintf(stderr, "%s: violation list exceeds %d\n", k_lmo_gate,
                LMO_MAX_VIOL);
        return 2;
    }
    if (ovf(snprintf(g->vio.row[g->vio.n], LMO_ROW,
                     "%s -> %s  (rank %d -> %d, %s symbol(s))", from, to, rf,
                     rt, count), LMO_ROW))
        return 2;
    g->vio.n++;
    g->fail = 1;
    return 0;
}

/* Splits a summary line into edge ends and count. 0 = parsed, 1 = not a
 * lib edge (skip), 2 = malformed lib edge (fail closed, message printed). */
static int lmo_parse_edge(const char *line, char *from, char *to,
                          char *count)
{
    static char edge[LMO_ROW];
    count[0] = '\0';
    int bad = lmo_tab_field(line, 0, edge, sizeof edge) == 2;
    if (!bad && strncmp(edge, "lib/", 4) != 0)
        return 1;
    if (!bad)
        bad = lmo_tab_field(line, 1, count, LMO_NAME) == 2 ||
              lmo_split_edge(edge, from, to) != 0;
    if (bad) {
        fprintf(stderr, "%s: malformed link-graph line: %.60s\n",
                k_lmo_gate, line);
        return 2;
    }
    return strncmp(to, "lib/", 4) != 0 ? 1 : 0;
}

/* Grades one summary line "from -> to<TAB>count<TAB>symbols". */
static int lmo_grade_edge(struct lmo_grade *g, const char *line)
{
    static char count[LMO_NAME], from[LMO_ROW], to[LMO_ROW];
    int pr = lmo_parse_edge(line, from, to, count);
    if (pr)
        return pr == 1 ? 0 : 2;
    if (strcmp(from, "lib/test") == 0 || strcmp(to, "lib/test") == 0)
        return 0;
    int rf = lmo_rank_of(g->mods, from);
    int rt = lmo_rank_of(g->mods, to);
    if (rf == 0)
        return lmo_undeclared(g, from);
    if (rt == 0)
        return lmo_undeclared(g, to);
    if (rt < rf)
        return 0;
    char key[LMO_KEY];
    if (ovf(snprintf(key, sizeof key, "%s -> %s", from, to), sizeof key))
        return 2;
    if (lmo_base_hit(g, key))
        return 0;
    return lmo_viol_add(g, from, to, rf, rt, count);
}

static int lmo_for_each_edge(const char *graph, size_t n, struct lmo_grade *g)
{
    size_t i = 0;
    while (i < n) {
        const char *nl = memchr(graph + i, '\n', n - i);
        size_t len = nl ? (size_t)(nl - (graph + i)) : n - i;
        static char line[LMO_LINE];
        /* Only the edge and count fields (both short) are graded; a long
         * symbol list past them is cut, an over-long edge field still
         * fails closed in lmo_parse_edge. */
        size_t keep = len < sizeof line ? len : sizeof line - 1;
        memcpy(line, graph + i, keep);
        line[keep] = '\0';
        int rc = lmo_grade_edge(g, line);
        if (rc)
            return rc;
        i = nl ? (size_t)(nl - graph) + 1 : n;
    }
    return 0;
}

/* ── reports ──────────────────────────────────────────────────────────── */

static void lmo_report_stale(const struct lmo_grade *g, FILE *out)
{
    static char rows[LMO_MAX_BASE][LMO_KEY];
    int n = 0;
    for (int i = 0; i < g->base->n; i++)
        if (!g->hit[i])
            memcpy(rows[n++], g->base->key[i], LMO_KEY);
    if (n == 0)
        return;
    n = lmo_sort_dedupe(rows[0], LMO_KEY, n);
    fprintf(out, "  ratchet can tighten — %d baseline entry/entries no "
            "longer violate:\n", n);
    for (int i = 0; i < n; i++)
        fprintf(out, "    %s\n", rows[i]);
    fprintf(out, "  Delete them from %s.\n", k_lmo_base_rel);
}

static int lmo_report_ok(const struct lmo_grade *g, FILE *out)
{
    fprintf(out, "%s: clean — %d ranked modules, %d baselined back edge(s), "
            "no NEW rank violations\n", k_lmo_gate, g->mods->n,
            g->base->n);
    lmo_report_stale(g, out);
    return 0;
}

static void lmo_report_undeclared(struct lmo_grade *g, FILE *out)
{
    if (g->und.n == 0)
        return;
    g->und.n = lmo_sort_dedupe(g->und.name[0], LMO_NAME, g->und.n);
    fprintf(out, "%s: lib module(s) in the link graph but NOT ranked in %s:\n",
            k_lmo_gate, k_lmo_def_rel);
    for (int i = 0; i < g->und.n; i++)
        fprintf(out, "    %s\n", g->und.name[i]);
    fprintf(out, "\n");
    fprintf(out, "  Add a LIB_MODULE(\"<name>\") line at the lowest rank that "
            "keeps this\n");
    fprintf(out, "  gate green. The Makefile's LIB_MODULES and codeindex's "
            "k_lib_modules[]\n");
    fprintf(out, "  are both derived from that file, so this is the ONE place "
            "to declare it.\n");
    fprintf(out, "\n");
}

static void lmo_report_viol(struct lmo_grade *g, FILE *out)
{
    if (g->vio.n == 0)
        return;
    qsort(g->vio.row, (size_t)g->vio.n, LMO_ROW, lmo_cmp_key);
    fprintf(out, "%s: %d NEW rank violation(s) not in %s\n", k_lmo_gate,
            g->vio.n, k_lmo_base_rel);
    fprintf(out, "\n");
    for (int i = 0; i < g->vio.n; i++)
        fprintf(out, "    %s\n", g->vio.row[i]);
    fprintf(out, "\n");
    fprintf(out, "Fix options (RATCHET gate — new debt is never accepted):\n");
    fprintf(out, "  1. Move the referenced symbol DOWN into a lower-ranked "
            "module.\n");
    fprintf(out, "  2. Invert the dependency: register a callback/port seam "
            "so the lower\n");
    fprintf(out, "     module never names the higher one (see\n");
    fprintf(out, "     node_db_set_quick_check_skip_probe in "
            "engine/models/include/models/database.h).\n");
    fprintf(out, "  3. Re-rank in %s — legitimate ONLY when the new position "
            "is\n", k_lmo_def_rel);
    fprintf(out, "     genuinely correct for the whole graph. Re-run\n");
    fprintf(out, "     'tools/dev/module-linkgraph.sh --summary' and confirm "
            "the total\n");
    fprintf(out, "     back-edge count did not grow before doing this.\n");
    fprintf(out, "\n");
    fprintf(out, "  Inspect the exact reference sites:\n");
    fprintf(out, "    tools/dev/module-linkgraph.sh --edges | grep -P "
            "'^lib/<from>\\tlib/<to>\\t'\n");
}

/* ── graph run and verdict ────────────────────────────────────────────── */

static int lmo_graph_argv(const struct lmo_paths *p, char *argv[5],
                          char *measured, size_t mcap)
{
    const char *od = getenv("ZCL_LINKGRAPH_OBJ_DIR");
    if (od && *od) {
        argv[0] = (char *)p->tool;
        argv[1] = (char *)"--summary";
        argv[2] = (char *)"--obj-dir";
        argv[3] = (char *)od;
        argv[4] = NULL;
        if (ovf(snprintf(measured, mcap, "%s (ZCL_LINKGRAPH_OBJ_DIR)", od),
                mcap))
            return 2;
        return 0;
    }
    argv[0] = (char *)p->tool;
    argv[1] = (char *)"--summary";
    argv[2] = (char *)"--obj-root";
    argv[3] = (char *)k_lmo_obj_rel;
    argv[4] = NULL;
    if (ovf(snprintf(measured, mcap, "%s", k_lmo_obj_rel), mcap))
        return 2;
    return 0;
}

/* Handles a non-zero graph exit. *rc becomes the gate verdict; 0 back means
 * "graph measured, continue grading". */
static int lmo_graph_dispatch(int grc, const char *measured,
                              char *const argv[], int *rc, FILE *out)
{
    size_t sinkn = 0;
    if (grc == 3) {
        fprintf(out, "%s: FAIL — the link graph could not be measured.\n",
                k_lmo_gate);
        fflush(out);
        /* Diagnostic re-run (stdout discarded, stderr visible); like the
         * shell's `|| true`, its own status cannot change the verdict. */
        (void)lmo_capture(argv, NULL, 0, &sinkn, 0);
        *rc = 1;
        return 0;
    }
    if (grc == 0)
        return 1;
    if (getenv("ZCL_LINT_REQUIRE_LINKGRAPH") &&
        strcmp(getenv("ZCL_LINT_REQUIRE_LINKGRAPH"), "1") == 0) {
        fprintf(out, "%s: FAIL — no compiled objects under %s; cannot "
                "measure the link graph.\n", k_lmo_gate, measured);
        fprintf(out, "  Run 'make build-only -j$(nproc)' first "
                "(ZCL_LINT_REQUIRE_LINKGRAPH=1 is set).\n");
        *rc = 1;
        return 0;
    }
    fprintf(out, "%s: NOT MEASURED — no compiled objects under %s.\n",
            k_lmo_gate, measured);
    fprintf(out, "  Ranks in %s were not checked. Run 'make build-only "
            "-j$(nproc)'\n", k_lmo_def_rel);
    fprintf(out, "  (the canonical arming path) or 'make lint-armed', then "
            "re-run.\n");
    *rc = 0;
    return 0;
}

static int lmo_measure_grade(const struct lmo_paths *p, struct lmo_grade *g,
                             FILE *out)
{
    static char graph[LMO_GRAPH_CAP];
    static char measured[LMO_PATH];
    char *argv[5];
    if (lmo_graph_argv(p, argv, measured, sizeof measured))
        return 2;
    size_t gn = 0;
    int grc = lmo_capture(argv, graph, sizeof graph, &gn, 1);
    if (grc < 0)
        return 2;
    int rc = 0;
    if (!lmo_graph_dispatch(grc, measured, argv, &rc, out))
        return rc;
    graph[gn] = '\0';
    int bad = lmo_for_each_edge(graph, gn, g);
    if (bad)
        return bad;
    if (!g->fail)
        return lmo_report_ok(g, out);
    fprintf(out, "\n");
    lmo_report_undeclared(g, out);
    lmo_report_viol(g, out);
    return 1;
}

/* ── entry ────────────────────────────────────────────────────────────── */

static int lmo_paths_init(struct lmo_paths *p, const char *root)
{
    if (ovf(snprintf(p->def, sizeof p->def, "%s/%s", root, k_lmo_def_rel),
            sizeof p->def))
        return 2;
    if (ovf(snprintf(p->base, sizeof p->base, "%s/%s", root, k_lmo_base_rel),
            sizeof p->base))
        return 2;
    if (ovf(snprintf(p->tool, sizeof p->tool, "%s/%s", root, k_lmo_tool_rel),
            sizeof p->tool))
        return 2;
    return 0;
}

/* Existence prechecks and the baseline/tree key check. 0 = continue. */
static int lmo_precheck(const struct lmo_paths *p, struct lmo_base *b,
                        FILE *out)
{
    if (access(p->def, F_OK) != 0) {
        fprintf(out, "%s: FAIL — missing %s\n", k_lmo_gate, k_lmo_def_rel);
        return 1;
    }
    if (access(p->tool, X_OK) != 0) {
        fprintf(out, "%s: FAIL — missing %s\n", k_lmo_gate, k_lmo_tool_rel);
        return 1;
    }
    int rc = lmo_load_baseline(p->base, b);
    if (rc)
        return rc;
    if (b->tree[0] != '\0' && strcmp(b->tree, k_lmo_obj_rel) != 0) {
        fprintf(out, "%s: FAIL — baseline/tree mismatch.\n", k_lmo_gate);
        fprintf(out, "  %s says it was measured from '%s'.\n", k_lmo_base_rel,
                b->tree);
        fprintf(out, "  This gate measures '%s'. Those are not comparable.\n",
                k_lmo_obj_rel);
        fprintf(out, "  Re-seed the baseline from %s (make build-only, then\n",
                k_lmo_obj_rel);
        fprintf(out, "  tools/dev/module-linkgraph.sh --summary --obj-root "
                "%s).\n", k_lmo_obj_rel);
        return 1;
    }
    return 0;
}

/* Declared-set check against the physical module dirs on disk. */
static int lmo_declared_vs_disk(const struct lmo_mods *m, FILE *out)
{
    static char dirs[LMO_MAX_DIRS][RS_PATH];
    static char disk[LMO_MAX_DIRS][LMO_NAME];
    int nd = 0;
    int rc = repo_shape_dirs("lib", "", dirs, LMO_MAX_DIRS, &nd);
    if (rc)
        return rc;
    int n = 0;
    rc = lmo_disk_names(dirs, nd, disk, &n);
    if (rc)
        return 2;
    n = lmo_sort_dedupe(disk[0], LMO_NAME, n);
    if (gate_require_scanned(n, 1, k_lmo_gate,
                             "no physical module directories found — is "
                             "this a checkout?"))
        return 2;
    return lmo_check_declared(m, disk, n, out);
}

int lmo_check_root(const char *root, FILE *out)
{
    struct lmo_paths p;
    int rc = lmo_paths_init(&p, root);
    if (rc)
        return rc;
    static struct lmo_base base;
    memset(&base, 0, sizeof base);
    rc = lmo_precheck(&p, &base, out);
    if (rc)
        return rc;
    static struct lmo_mods mods;
    memset(&mods, 0, sizeof mods);
    rc = lmo_load_def(p.def, &mods, out);
    if (rc)
        return rc;
    if (mods.n == 0) {
        fprintf(out, "%s: FAIL — no LIB_MODULE() entries parsed from %s\n",
                k_lmo_gate, k_lmo_def_rel);
        return 1;
    }
    if (setenv("ZCL_REPO_SHAPE_ROOT", root, 1) != 0)
        return 2;
    rc = rs_init();
    if (rc)
        return rc;
    rc = lmo_declared_vs_disk(&mods, out);
    if (rc)
        return rc;
    static struct lmo_grade g;
    memset(&g, 0, sizeof g);
    g.mods = &mods;
    g.base = &base;
    return lmo_measure_grade(&p, &g, out);
}

int check_lib_module_order_run(int argc, char **argv)
{
    const char *root = argc >= 1 ? argv[0] : ".";
    return lmo_check_root(root, stdout);
}
