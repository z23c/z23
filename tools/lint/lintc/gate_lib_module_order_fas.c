/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: cycle structure of the lib/ module subgraph (the --fas report of
 * `z23-lint module-linkgraph`). Two questions, both answered exactly:
 *
 *   1. Which modules are mutually reachable? (Tarjan strongly-connected
 *      components.) A component of size 1 can always be ranked; a larger one
 *      cannot be ordered without some edge running backward.
 *   2. How few edges MUST run backward? That is the minimum feedback arc
 *      set. It decomposes over components (an edge between two components
 *      can always be made forward by ordering the components topologically),
 *      so the graph-wide minimum is the sum of the per-component minima.
 *
 * Within a component the minimum is solved by dynamic programming over
 * subsets: dp[S] is the cheapest way to occupy the |S| lowest ranks with
 * exactly the modules in S, and appending module v costs one for every edge
 * from v to a module not yet placed (those necessarily point upward). That
 * is O(2^n * n), not O(n!). Scoped to lib/ minus lib/test, because that is
 * precisely what engine/composition/lib_module_order.def ranks. Ported from
 * the --fas half of tools/dev/module-linkgraph.sh (deleted).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdint.h>
#include <string.h>
#include "gate_lib_module_order_graph.h"

enum { LMF_N = 128, LMF_E = 4096, LMF_NAME = 64, LMF_EXACT_MAX = 20 };

struct lmf {
    int n, m, nc;
    char name[LMF_N][LMF_NAME];
    int eu[LMF_E], ev[LMF_E];
    int adj[LMF_N][LMF_N], adjn[LMF_N];
    int idx[LMF_N], low[LMF_N], comp[LMF_N];
};

static struct lmf g_lmf;
static int g_dp[1 << LMF_EXACT_MAX];
static int8_t g_par[1 << LMF_EXACT_MAX];

static int lmf_node(struct lmf *g, const char *s, size_t len)
{
    for (int i = 0; i < g->n; i++)
        if (strlen(g->name[i]) == len && memcmp(g->name[i], s, len) == 0)
            return i;
    if (g->n >= LMF_N || len >= LMF_NAME)
        return -1;
    memcpy(g->name[g->n], s, len);
    g->name[g->n][len] = '\0';
    return g->n++;
}

static int lmf_add_edge(struct lmf *g, int u, int v)
{
    if (g->m >= LMF_E || g->adjn[u] >= LMF_N)
        return -1;
    g->eu[g->m] = u;
    g->ev[g->m++] = v;
    g->adj[u][g->adjn[u]++] = v;
    return 0;
}

/* One summary line "from -> to<TAB>count<TAB>syms" -> graph edge when it is
 * a lib/ -> lib/ edge that does not touch lib/test. 0 ok or skipped, -1 when
 * the graph outgrows the fixed tables. */
static int lmf_line(struct lmf *g, const char *line)
{
    static const char arrow[] = " -> ";
    char edge[256];
    size_t el = strcspn(line, "\t");
    if (el >= sizeof edge)
        return -1;
    memcpy(edge, line, el);
    edge[el] = '\0';
    const char *lt = strstr(edge + (el >= 4 ? 4 : el), " -> lib/");
    if (strncmp(edge, "lib/", 4) != 0 || !lt || strstr(line, "lib/test"))
        return 0;
    const char *first = strstr(edge, arrow);
    const char *to = first + sizeof arrow - 1;
    const char *again = strstr(to, arrow);
    int u = lmf_node(g, edge, (size_t)(first - edge));
    int v = u < 0 ? -1 : lmf_node(g, to, again ? (size_t)(again - to) : strlen(to));
    return v < 0 ? -1 : lmf_add_edge(g, u, v);
}

/* ── Tarjan, iterative ────────────────────────────────────────────────── */

struct lmf_tj {
    int cnt, sp;
    int cs[LMF_N], ce[LMF_N], stk[LMF_N];
    unsigned char onstk[LMF_N];
};

static void lmf_tj_pop(struct lmf *g, struct lmf_tj *t, int *top, int w)
{
    (*top)--;
    if (*top > 0) {
        int p = t->cs[*top - 1];
        if (g->low[w] < g->low[p])
            g->low[p] = g->low[w];
    }
    if (g->low[w] != g->idx[w])
        return;
    int i;
    do {
        i = t->stk[--t->sp];
        t->onstk[i] = 0;
        g->comp[i] = g->nc;
    } while (i != w);
    g->nc++;
}

/* One step of the explicit-stack walk for the frame on top. */
static void lmf_tj_step(struct lmf *g, struct lmf_tj *t, int *top)
{
    int k = *top - 1, w = t->cs[k];
    if (t->ce[k] == 0) {
        g->idx[w] = g->low[w] = ++t->cnt;
        t->stk[t->sp++] = w;
        t->onstk[w] = 1;
    }
    if (t->ce[k] >= g->adjn[w]) {
        lmf_tj_pop(g, t, top, w);
        return;
    }
    int a = g->adj[w][t->ce[k]++];
    if (g->idx[a] == -1) {
        t->cs[*top] = a;
        t->ce[*top] = 0;
        (*top)++;
    } else if (t->onstk[a] && g->idx[a] < g->low[w]) {
        g->low[w] = g->idx[a];
    }
}

static void lmf_scc(struct lmf *g)
{
    static struct lmf_tj t;
    memset(&t, 0, sizeof t);
    g->nc = 0;
    for (int v = 0; v < g->n; v++)
        g->idx[v] = -1;
    for (int v = 0; v < g->n; v++) {
        if (g->idx[v] != -1)
            continue;
        int top = 1;
        t.cs[0] = v;
        t.ce[0] = 0;
        while (top > 0)
            lmf_tj_step(g, &t, &top);
    }
}

/* ── exact minimum feedback arc set of one component ──────────────────── */

struct lmf_comp {
    int sz, ne;
    int mem[LMF_N], loc[LMF_N];
    int su[LMF_E], sv[LMF_E];
    unsigned out[LMF_EXACT_MAX]; /* out[v]: bit j set = edge v -> j */
};

static void lmf_comp_load(const struct lmf *g, int c, struct lmf_comp *k)
{
    memset(k, 0, sizeof *k);
    for (int i = 0; i < g->n; i++)
        if (g->comp[i] == c) {
            k->mem[k->sz] = i;
            k->loc[i] = k->sz++;
        }
    for (int e = 0; e < g->m; e++)
        if (g->comp[g->eu[e]] == c && g->comp[g->ev[e]] == c) {
            k->su[k->ne] = k->loc[g->eu[e]];
            k->sv[k->ne++] = k->loc[g->ev[e]];
        }
}

static void lmf_dp(struct lmf_comp *k)
{
    unsigned full = 1u << k->sz;
    for (unsigned s = 0; s < full; s++)
        g_dp[s] = -1;
    g_dp[0] = 0;
    for (unsigned s = 0; s < full; s++) {
        if (g_dp[s] < 0)
            continue;
        for (int v = 0; v < k->sz; v++) {
            if ((s >> v) & 1u)
                continue;
            int add = __builtin_popcount(k->out[v] & ~s & ~(1u << v));
            unsigned t = s | (1u << v);
            if (g_dp[t] < 0 || g_dp[s] + add < g_dp[t]) {
                g_dp[t] = g_dp[s] + add;
                g_par[t] = (int8_t)v;
            }
        }
    }
}

/* Prints the ranking the DP chose and the edges it leaves backward. */
static void lmf_walk_back(const struct lmf *g, const struct lmf_comp *k,
                          int best, FILE *out)
{
    int order[LMF_EXACT_MAX], pos[LMF_EXACT_MAX];
    unsigned s = (1u << k->sz) - 1u;
    int j = k->sz;
    while (s > 0) {
        int v = g_par[s];
        order[--j] = v;
        s -= 1u << v;
    }
    for (int i = 0; i < k->sz; i++)
        pos[order[i]] = i;
    fprintf(out, "  a ranking that achieves it (lowest rank first):\n    ");
    for (int i = 0; i < k->sz; i++)
        fprintf(out, "%s ", g->name[k->mem[order[i]]]);
    fprintf(out, "\n  the %d edge(s) it leaves running backward:\n", best);
    for (int e = 0; e < k->ne; e++)
        if (pos[k->sv[e]] > pos[k->su[e]])
            fprintf(out, "    %s -> %s\n", g->name[k->mem[k->su[e]]],
                    g->name[k->mem[k->sv[e]]]);
}

/* Component c's minimum, or -1 for a trivial component (nothing printed) or
 * one too large to solve exactly. */
static int lmf_mfas(const struct lmf *g, int c, FILE *out)
{
    static struct lmf_comp k;
    lmf_comp_load(g, c, &k);
    if (k.sz < 2)
        return -1;
    fprintf(out, "\ncomponent (%d modules, %d internal edges):\n  ", k.sz, k.ne);
    for (int i = 0; i < k.sz; i++)
        fprintf(out, "%s ", g->name[k.mem[i]]);
    fprintf(out, "\n");
    if (k.sz > LMF_EXACT_MAX) {
        fprintf(out, "  component too large for exact solution (%d modules)\n",
                k.sz);
        return -1;
    }
    for (int e = 0; e < k.ne; e++)
        if (k.su[e] != k.sv[e])
            k.out[k.su[e]] |= 1u << k.sv[e];
    lmf_dp(&k);
    int best = g_dp[(1u << k.sz) - 1u];
    fprintf(out, "  exact minimum feedback arc set = %d\n", best);
    lmf_walk_back(g, &k, best, out);
    return best;
}

static void lmf_report(struct lmf *g, FILE *out)
{
    lmf_scc(g);
    int ntriv = 0;
    for (int c = 0; c < g->nc; c++) {
        int k = 0;
        for (int i = 0; i < g->n; i++)
            k += g->comp[i] == c;
        ntriv += k > 1;
    }
    fprintf(out, "lib/ subgraph: %d modules, %d edges, %d strongly-connected "
            "component(s), %d non-trivial\n", g->n, g->m, g->nc, ntriv);
    int total = 0;
    for (int c = 0; c < g->nc; c++) {
        int r = lmf_mfas(g, c, out);
        if (r > 0)
            total += r;
    }
    fprintf(out, "\nMINIMUM FEEDBACK ARC SET over the whole lib/ subgraph = "
            "%d\n", total);
    fprintf(out, "That is the floor on how many entries "
            "tools/scripts/lib_module_order_baseline.txt\n");
    fprintf(out, "can hold: no reordering of "
            "engine/composition/lib_module_order.def gets below it. Paying "
            "one\n");
    fprintf(out, "down means breaking a cycle, not re-ranking.\n");
}

int lmg_fas(const char *const *lines, size_t n, FILE *out)
{
    struct lmf *g = &g_lmf;
    memset(g, 0, sizeof *g);
    for (size_t i = 0; i < n; i++)
        if (lmf_line(g, lines[i]) != 0) {
            fputs("module-linkgraph: lib/ subgraph exceeds the fixed tables\n",
                  stderr);
            return 2;
        }
    if (g->n == 0) {
        fputs("no lib/ -> lib/ edges measured\n", out);
        return 1;
    }
    lmf_report(g, out);
    return 0;
}
