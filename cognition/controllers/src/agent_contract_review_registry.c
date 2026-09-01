/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "controllers/agent_controller.h"

#include "json/json.h"

#include <string.h>

struct agent_contract_review_surface {
    const char *surface;
    int rank;
    const char *key;
    const char *value;
};

#define REVIEW_FIELD(surface, rank, key, value)                              \
    { surface, rank, key, value }

static const struct agent_contract_review_surface g_agent_review_surfaces[] = {
    REVIEW_FIELD(
        "agentops.architecture_review", 1, "architecture_center",
        "progress.kv fact log plus reducer stages; projections and API are derived views"),
    REVIEW_FIELD(
        "agentops.architecture_review", 2, "best_existing_primitive",
        "diagnostics_registry + dumpstate: one table maps subsystem names to C dumpers"),
    REVIEW_FIELD(
        "agentops.architecture_review", 3, "main_dry_problem",
        "native CLI, live RPC, REST, and helper scripts still expose overlapping shapes"),
    REVIEW_FIELD(
        "agentops.architecture_review", 4, "api_direction",
        "one C-owned JSON builder per contract; transports proxy it without reshaping"),
    REVIEW_FIELD(
        "agentops.architecture_review", 5, "preferred_payload",
        "versioned JSON with direct decision fields and explicit drill-down commands"),
};

#undef REVIEW_FIELD

static const size_t g_agent_review_surface_count =
    sizeof(g_agent_review_surfaces) / sizeof(g_agent_review_surfaces[0]);

size_t agent_contract_review_surface_total_count(void)
{
    return g_agent_review_surface_count;
}

size_t agent_contract_review_surface_count(const char *surface)
{
    if (!surface || !surface[0])
        return 0;

    size_t n = 0;
    for (size_t i = 0; i < g_agent_review_surface_count; i++) {
        const struct agent_contract_review_surface *e =
            &g_agent_review_surfaces[i];
        if (e->surface && strcmp(e->surface, surface) == 0)
            n++;
    }
    return n;
}

size_t agent_push_contract_review_surface_json(struct json_value *obj,
                                               const char *surface)
{
    if (!obj || !surface || !surface[0])
        return 0;

    int max_rank = 0;
    for (size_t i = 0; i < g_agent_review_surface_count; i++) {
        const struct agent_contract_review_surface *e =
            &g_agent_review_surfaces[i];
        if (e->surface && strcmp(e->surface, surface) == 0 &&
            e->rank > max_rank)
            max_rank = e->rank;
    }

    size_t pushed = 0;
    for (int rank = 1; rank <= max_rank; rank++) {
        for (size_t i = 0; i < g_agent_review_surface_count; i++) {
            const struct agent_contract_review_surface *e =
                &g_agent_review_surfaces[i];
            if (e->rank != rank || !e->surface ||
                strcmp(e->surface, surface) != 0)
                continue;
            json_push_kv_str(obj, e->key, e->value);
            pushed++;
        }
    }
    return pushed;
}
