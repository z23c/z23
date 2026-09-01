/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Compile the stateless reloadable-island ownership manifests. */

#include "hotswap/hotswap_module.h"

#include <stddef.h>
#include <string.h>

static const char *const g_swappable_owners[] = {
#define HOTSWAP_SWAPPABLE(source_tu_, leaves_) source_tu_,
#include "../../../engine/composition/hotswap_swappable.def"
#undef HOTSWAP_SWAPPABLE
};

static const struct {
    const char *owner;
    const char *members;
} g_islands[] = {
#define HOTSWAP_ISLAND(owner_, members_) { .owner = owner_, .members = members_ },
#include "../../../engine/composition/hotswap_islands.def"
#undef HOTSWAP_ISLAND
};

static bool token_list_contains(const char *list, const char *value)
{
    if (!list || !value || !value[0])
        return false;
    size_t value_len = strlen(value);
    for (const char *p = list; *p;) {
        while (*p == ' ' || *p == '\t') p++;
        const char *start = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if ((size_t)(p - start) == value_len &&
            memcmp(start, value, value_len) == 0)
            return true;
    }
    return false;
}

bool hotswap_source_is_swappable(const char *source_tu)
{
    if (!source_tu || !source_tu[0])
        return false;
    for (size_t i = 0;
         i < sizeof(g_swappable_owners) / sizeof(g_swappable_owners[0]); i++)
        if (strcmp(g_swappable_owners[i], source_tu) == 0)
            return true;
    return false;
}

const char *hotswap_island_owner_for_path(const char *path)
{
    if (!path || !path[0])
        return NULL;
    if (hotswap_source_is_swappable(path))
        return path;
    for (size_t i = 0; i < sizeof(g_islands) / sizeof(g_islands[0]); i++)
        if (token_list_contains(g_islands[i].members, path))
            return g_islands[i].owner;
    return NULL;
}

const char *hotswap_island_members_for_source(const char *source_tu)
{
    if (!source_tu || !source_tu[0])
        return NULL;
    for (size_t i = 0; i < sizeof(g_islands) / sizeof(g_islands[0]); i++)
        if (strcmp(g_islands[i].owner, source_tu) == 0)
            return g_islands[i].members;
    return "";
}
