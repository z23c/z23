/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Read the separately named readiness facts (zcl.public_status.v3) out of the
 * node's cached `agent` document. Every field is optional: a v2 document omits
 * all of them and the caller then omits the flattened keys rather than
 * inventing a default.
 */

#include "status_brief_readiness_read.h"

#include "json/json.h"

#include <string.h>

static bool status_read_optional_bool(const struct json_value *obj,
                                      const char *key, bool *value_out)
{
    const struct json_value *v = obj ? json_get(obj, key) : NULL;
    if (!v || v->type != JSON_BOOL)
        return false;
    if (value_out)
        *value_out = v->val.b;
    return true;
}

void status_brief_readiness_facts_read(
    const struct json_value *agent, struct status_brief_readiness_facts *out)
{
    if (!out)
        return;
    *out = (struct status_brief_readiness_facts){0};
    out->tip_follow_known =
        status_read_optional_bool(agent, "tip_follow", &out->tip_follow);
    out->wallet_view_known = status_read_optional_bool(
        agent, "wallet_view_ready", &out->wallet_view_ready);
    out->wallet_spend_known = status_read_optional_bool(
        agent, "wallet_spend_allowed", &out->wallet_spend_allowed);
    out->full_replay_known = status_read_optional_bool(
        agent, "full_replay_verified", &out->full_replay_verified);
    const char *archive = json_get_str(json_get(agent, "archive_complete"));
    /* Only the three defined words. Anything else is runtime skew and is
     * dropped rather than passed through as a machine token. */
    if (archive && (strcmp(archive, "complete") == 0 ||
                    strcmp(archive, "incomplete") == 0 ||
                    strcmp(archive, "unknown") == 0))
        out->archive_complete = archive;
    out->known = out->tip_follow_known || out->wallet_view_known ||
        out->wallet_spend_known || out->full_replay_known ||
        out->archive_complete != NULL;
}
