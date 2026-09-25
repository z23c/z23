/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Tell which reverse-caller hops of a selector plan are explained by
 * the include graph, so selections reached only through a bare-name match are
 * reported as over-approximation instead of proof premises. */

#include "dev_shadow_select.h"

#include "devloop.h"

#include "base/safe_alloc.h"
#include "codeindex/codeindex.h"

#include <stdlib.h>
#include <string.h>

#define SHADOW_HOP_INCLUDES 2048
#define SHADOW_HOP_ROUNDS 16

void zcl_shadow_component_of(const char *path, char *out, size_t cap)
{
    static const char *const cuts[] = {"/src/", "/include/", "/tests/"};
    size_t len = strlen(path);
    for (size_t i = 0; i < sizeof(cuts) / sizeof(cuts[0]); i++) {
        const char *hit = strstr(path, cuts[i]);
        if (hit && (size_t)(hit - path) < len) len = (size_t)(hit - path);
    }
    if (len == strlen(path)) {
        const char *slash = strrchr(path, '/');
        len = slash ? (size_t)(slash - path) : 0;
    }
    if (cap == 0) return;
    if (len >= cap) len = cap - 1;
    memcpy(out, path, len);
    out[len] = '\0';
}

struct shadow_components {
    char (*names)[ZCL_SHADOW_PATH_MAX];
    size_t len;
    size_t cap;
};

static bool shadow_components_has(const struct shadow_components *c,
                                  const char *name)
{
    for (size_t i = 0; i < c->len; i++)
        if (strcmp(c->names[i], name) == 0) return true;
    return false;
}

static void shadow_components_add(struct shadow_components *c,
                                  const char *name)
{
    if (!name[0] || shadow_components_has(c, name) || c->len >= c->cap) return;
    (void)snprintf(c->names[c->len++], ZCL_SHADOW_PATH_MAX, "%s", name);
}

/* The shared test scaffold is included by every test and names no callee;
 * a test file's component is the scaffold, never a callee's owner. */
static bool shadow_is_scaffold(const char *path)
{
    return strncmp(path, "tests/harness/", 14) == 0;
}

struct shadow_hop {
    const char *via;
    bool legit;
};

/* A caller TU is explained when its compiler depfile reads a header of a
 * component the walk already reached legitimately. Depfile edges are
 * transitive, so a real call through any header chain is seen. */
static int shadow_hop_explained(struct codeindex *ci, const char *via,
                                const struct shadow_components *reached,
                                char (*tmp)[256])
{
    int n = codeindex_includes_of_file(ci, via, tmp, SHADOW_HOP_INCLUDES);
    if (n < 0) return -1;
    if (n >= SHADOW_HOP_INCLUDES) return 1; /* unknown: never claim waste */
    for (int i = 0; i < n; i++) {
        if (shadow_is_scaffold(tmp[i])) continue;
        char comp[ZCL_SHADOW_PATH_MAX];
        zcl_shadow_component_of(tmp[i], comp, sizeof(comp));
        if (shadow_components_has(reached, comp)) return 1;
    }
    return 0;
}

static bool shadow_hop_seed(const char *via, const struct zcl_shadow_entry *e)
{
    size_t n = strlen(e->component);
    if (!codeindex_path_is_translation_unit(via)) return true;
    for (size_t i = 0; i < e->file_count; i++)
        if (strcmp(via, e->files[i]) == 0) return true;
    return !shadow_is_scaffold(via) && n > 0 &&
           strncmp(via, e->component, n) == 0 && via[n] == '/';
}

static bool shadow_hops_round(struct codeindex *ci, struct shadow_hop *hops,
                              size_t count, struct shadow_components *reached,
                              char (*tmp)[256], bool *changed)
{
    *changed = false;
    for (size_t i = 0; i < count; i++) {
        if (hops[i].legit) continue;
        int r = shadow_hop_explained(ci, hops[i].via, reached, tmp);
        if (r < 0) return false;
        if (r == 0) continue;
        hops[i].legit = true;
        *changed = true;
        if (!shadow_is_scaffold(hops[i].via)) {
            char comp[ZCL_SHADOW_PATH_MAX];
            zcl_shadow_component_of(hops[i].via, comp, sizeof(comp));
            shadow_components_add(reached, comp);
        }
    }
    return true;
}

static size_t shadow_hops_collect(const struct zcl_devloop_plan *plan,
                                  struct shadow_hop *hops)
{
    size_t count = 0;
    for (size_t i = 0; i < plan->selections_len; i++) {
        const struct zcl_devloop_selection *s = &plan->selections[i];
        if (s->dim != ZCL_DEVLOOP_DIM_SEMANTIC) continue;
        bool seen = false;
        for (size_t j = 0; j < count && !seen; j++)
            seen = strcmp(hops[j].via, s->via) == 0;
        if (!seen) hops[count++] = (struct shadow_hop){s->via, false};
    }
    return count;
}

static bool shadow_hops_resolve(struct codeindex *ci,
                                const struct zcl_shadow_entry *e,
                                struct shadow_hop *hops, size_t count)
{
    struct shadow_components reached = {0};
    reached.cap = ZCL_DEVLOOP_MAX_PLAN_SELECTIONS + 1;
    reached.names = zcl_calloc(reached.cap, sizeof(*reached.names),
                               "shadow_reached");
    char (*tmp)[256] = zcl_calloc(SHADOW_HOP_INCLUDES, sizeof(*tmp),
                                  "shadow_hop_inc");
    bool ok = reached.names && tmp;
    if (ok) shadow_components_add(&reached, e->component);
    for (size_t i = 0; ok && i < count; i++)
        hops[i].legit = shadow_hop_seed(hops[i].via, e);
    bool changed = true;
    for (unsigned r = 0; ok && changed && r < SHADOW_HOP_ROUNDS; r++)
        ok = shadow_hops_round(ci, hops, count, &reached, tmp, &changed);
    /* Out of rounds with progress still being made: the rest is unknown,
     * and unknown is never reported as waste. */
    for (size_t i = 0; ok && changed && i < count; i++) hops[i].legit = true;
    free(reached.names);
    free(tmp);
    return ok;
}

bool zcl_shadow_explained_selections(const char *root,
                                     const struct zcl_shadow_entry *e,
                                     const struct zcl_devloop_plan *plan,
                                     bool *explained, uint32_t *hops_out,
                                     uint32_t *collisions_out)
{
    if (!root || !e || !plan || !explained) return false;
    *hops_out = *collisions_out = 0;
    for (size_t i = 0; i < plan->selections_len; i++) explained[i] = true;
    struct shadow_hop *hops =
        zcl_calloc(ZCL_DEVLOOP_MAX_PLAN_SELECTIONS, sizeof(*hops), "shadow_hop");
    if (!hops) return false;
    size_t count = shadow_hops_collect(plan, hops);
    struct codeindex *ci = count ? codeindex_open_existing(root) : NULL;
    bool ok = count == 0 ||
              (ci && codeindex_include_edge_count(ci) > 0 &&
               shadow_hops_resolve(ci, e, hops, count));
    if (ci) codeindex_close(ci);
    if (!ok) {
        free(hops);
        return count > 0; /* no include graph: nothing is claimed as waste */
    }
    *hops_out = (uint32_t)count;
    for (size_t i = 0; i < plan->selections_len; i++) {
        const struct zcl_devloop_selection *s = &plan->selections[i];
        if (s->dim != ZCL_DEVLOOP_DIM_SEMANTIC) continue;
        for (size_t j = 0; j < count; j++)
            if (strcmp(hops[j].via, s->via) == 0) explained[i] = hops[j].legit;
    }
    for (size_t j = 0; j < count; j++) *collisions_out += hops[j].legit ? 0u : 1u;
    free(hops);
    return true;
}
