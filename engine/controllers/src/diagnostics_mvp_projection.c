/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Validate the shared typed MVP qualification projection. */
#include "controllers/mvp_status.h"
#include "json/json.h"
#include <stdio.h>
#include <string.h>

/* JSON preserves duplicate decoded keys. A required field is usable only
 * when exactly one occurrence exists, including escaped key spellings. */
static const struct json_value *mvp_projection_unique(
    const struct json_value *obj, const char *key)
{
    if (!obj || obj->type != JSON_OBJ) return NULL;
    const struct json_value *found = NULL;
    for (size_t i = 0; i < obj->num_children; i++) {
        if (strcmp(obj->keys[i], key) != 0) continue;
        if (found) return NULL;
        found = &obj->children[i];
    }
    return found;
}

static bool mvp_projection_string(const struct json_value *obj,
                                  const char *key, const char *expected)
{
    const struct json_value *v = mvp_projection_unique(obj, key);
    return v && v->type == JSON_STR && strcmp(json_get_str(v), expected) == 0;
}

static void mvp_projection_reset(struct mvp_qualification *q)
{
    q->available = false;
    q->met_count = 0;
    for (int i = 0; i < MVP_CRITERIA_TOTAL; i++) q->state[i] = -1;
}

static bool mvp_projection_state(const struct json_value *row, int index, int *out)
{
    const struct json_value *met = mvp_projection_unique(row, "met");
    char id[4];
    snprintf(id, sizeof(id), "C%d", index + 1);
    if (!mvp_projection_string(row, "id", id)) return false;
    if (met && met->type == JSON_BOOL) {
        *out = json_get_bool(met) ? 1 : 0;
        return mvp_projection_string(row, "met_state", *out ? "met" : "unmet");
    }
    *out = -1;
    return met && met->type == JSON_NULL &&
           mvp_projection_string(row, "met_state", "unknown");
}

static bool mvp_projection_read(const struct json_value *status,
                                struct mvp_qualification *q)
{
    const struct json_value *rows = mvp_projection_unique(status, "criteria");
    const struct json_value *count = mvp_projection_unique(status, "met_count");
    if (!status || status->type != JSON_OBJ ||
        !mvp_projection_string(status, "schema", "zcl.mvp_status.v1") ||
        !mvp_projection_string(status, "qualification_policy", MVP_QUALIFICATION_POLICY) ||
        !rows || rows->type != JSON_ARR || json_size(rows) != MVP_CRITERIA_TOTAL ||
        !count || count->type != JSON_INT) return false;
    for (int i = 0; i < MVP_CRITERIA_TOTAL; i++) {
        if (!mvp_projection_state(json_at(rows, (size_t)i), i, &q->state[i])) return false;
        if (q->state[i] == 1) q->met_count++;
    }
    return json_get_int(count) == q->met_count;
}

bool mvp_status_read_qualification(const struct json_value *status,
                                   struct mvp_qualification *out)
{
    if (!out) return false;
    mvp_projection_reset(out);
    if (!mvp_projection_read(status, out)) {
        mvp_projection_reset(out);
        return false;
    }
    out->available = true;
    return true;
}
