/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* Shared freshness metadata for public REST responses. The served frontier is
 * the height this process is willing to expose; indexed_height is the source
 * projection's best known height when that projection is height-keyed. */

#include "api_controller_internal.h"

#include "json/json.h"

#include <stdint.h>

void api_freshness_prepare(struct api_freshness_meta *out,
                           const char *source_projection,
                           int64_t indexed_height)
{
    if (!out)
        return;

    out->served_height = api_served_tip_height();
    out->indexed_height = indexed_height >= 0 ? indexed_height
                                              : out->served_height;
    out->source_projection = source_projection && source_projection[0]
        ? source_projection : "unknown";
    out->fresh = false;
    out->freshness = "unavailable";
    out->blocker = "served_height_unavailable";

    if (out->served_height < 0)
        return;
    if (out->indexed_height < 0) {
        out->blocker = "indexed_height_unavailable";
        return;
    }
    if (out->indexed_height < out->served_height) {
        out->freshness = "stale";
        out->blocker = "index_behind_served_height";
        return;
    }

    out->fresh = true;
    out->freshness = "fresh";
    out->blocker = "none";
}

void api_freshness_push_json(struct json_value *obj,
                             const struct api_freshness_meta *freshness)
{
    if (!obj || !freshness)
        return;

    json_push_kv_int(obj, "served_height", freshness->served_height);
    json_push_kv_int(obj, "indexed_height", freshness->indexed_height);
    json_push_kv_bool(obj, "fresh", freshness->fresh);
    json_push_kv_str(obj, "freshness", freshness->freshness);
    json_push_kv_str(obj, "source_projection", freshness->source_projection);
    json_push_kv_str(obj, "blocker", freshness->blocker);
}

void api_json_add_freshness(struct json_value *obj,
                            const char *source_projection,
                            int64_t indexed_height)
{
    struct api_freshness_meta freshness;

    api_freshness_prepare(&freshness, source_projection, indexed_height);
    api_freshness_push_json(obj, &freshness);
}
