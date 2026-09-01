/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Apply declarative package recipes to ZVCS workspace manifests. */

#include "vcs/package_recipe.h"

#include "util/log_macros.h"
#include "vcs/vcs_manifest.h"

#include <stdio.h>
#include <string.h>

static bool recipe_vcs_has_file(const struct vcs_manifest *m,
                                const char *path)
{
    size_t lo = 0, hi = m->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2u;
        int cmp = strcmp(m->entries[mid].path, path);
        if (cmp == 0) return true;
        if (cmp < 0) lo = mid + 1u; else hi = mid;
    }
    return false;
}

static bool recipe_vcs_has_dir(const struct vcs_manifest *m, const char *dir)
{
    size_t dlen = strlen(dir);
    for (size_t i = 0; i < m->count; i++) {
        const char *path = m->entries[i].path;
        if (strncmp(path, dir, dlen) == 0 && path[dlen] == '/' &&
            path[dlen + 1u] != '\0')
            return true;
    }
    return false;
}

static bool recipe_list_in_vcs(
    const struct vcs_package_recipe_strings *list, const char *name,
    const struct vcs_manifest *manifest, char *detail, size_t detail_cap)
{
    for (size_t i = 0; i < list->count; i++) {
        if (recipe_vcs_has_file(manifest, list->items[i])) continue;
        if (detail && detail_cap > 0)
            (void)snprintf(detail, detail_cap, "%s: %s", name,
                           list->items[i]);
        return false;
    }
    return true;
}

bool vcs_package_recipe_files_in_vcs_manifest(
    const struct vcs_package_recipe *recipe,
    const struct vcs_manifest *manifest, char *detail_out,
    size_t detail_cap)
{
    if (!recipe || !manifest)
        LOG_RETURN(false, "vcs.recipe", "null recipe/vcs manifest");
    if (!recipe_list_in_vcs(&recipe->public_headers, "public_headers",
                            manifest, detail_out, detail_cap) ||
        !recipe_list_in_vcs(&recipe->sources, "sources", manifest,
                            detail_out, detail_cap) ||
        !recipe_list_in_vcs(&recipe->test_sources, "test_sources", manifest,
                            detail_out, detail_cap))
        return false;
    for (size_t i = 0; i < recipe->include_dirs.count; i++) {
        if (recipe_vcs_has_dir(manifest, recipe->include_dirs.items[i]))
            continue;
        if (detail_out && detail_cap > 0)
            (void)snprintf(detail_out, detail_cap, "include_dirs: %s",
                           recipe->include_dirs.items[i]);
        return false;
    }
    return true;
}
