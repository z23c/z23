/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * `sapling_checkpoint` dumpstate entry: flat-file Sapling note-commitment
 * tree cache. Shows the last periodic write (height/count/fails) and the
 * boot-time load outcome (absent/loaded_verified/discarded) so an operator
 * can confirm the fast-resume path fired instead of the ~16-min full
 * replay. Lives here (not diagnostics_registry.c) so that file stays a
 * routing table rather than a home for every dumper's full body — same
 * pattern as diagnostics_block_index.c: the registry owns routing and
 * controller state, heavier per-subsystem dump shapes live in their own
 * file.
 */

#include "controllers/diagnostics_internal.h"

#include "json/json.h"
#include "validation/process_block.h"

#include <string.h>

static const char *sapling_ckpt_load_result_str(int r)
{
    switch (r) {
    case SAPLING_CKPT_LOAD_NONE:      return "none";
    case SAPLING_CKPT_LOAD_ABSENT:    return "absent";
    case SAPLING_CKPT_LOAD_VERIFIED:  return "loaded_verified";
    case SAPLING_CKPT_LOAD_DISCARDED: return "discarded";
    }
    return "unknown";
}

bool sapling_checkpoint_dump_state_json(struct json_value *out,
                                        const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    struct sapling_ckpt_stats st;
    sapling_ckpt_get_stats(&st);

    json_push_kv_str(out, "path", st.path);
    json_push_kv_bool(out, "enabled", st.path[0] != '\0');
    json_push_kv_int(out, "writes", st.writes);
    json_push_kv_int(out, "write_fails", st.write_fails);
    json_push_kv_int(out, "last_write_height", st.last_write_height);
    json_push_kv_str(out, "last_load_result",
                     sapling_ckpt_load_result_str(st.last_load_result));
    json_push_kv_int(out, "last_load_height", st.last_load_height);
    json_push_kv_str(out, "last_load_detail", st.last_load_detail);

    /* Reserved `_health` key (see docs/work "Adding state introspection" +
     * engine/controllers/src/diagnostics_health_rollup.c): { ok, reason }.
     * Maps the already-computed write_fails counter and last_load_detail
     * string above — no new health logic. A nonzero write_fails means the
     * periodic checkpoint writer is failing; last_load_detail ==
     * "missing_or_corrupt" is the exact string sapling_ckpt_record_load()
     * records on the ABSENT boot-load path (engine/composition/src/boot.c) — surfacing
     * it here is a minimum, mechanical translation of an existing signal,
     * not a new judgment about whether a fresh datadir "should" have one. */
    {
        bool write_fail = st.write_fails > 0;
        bool load_missing_or_corrupt =
            strcmp(st.last_load_detail, "missing_or_corrupt") == 0;
        bool ok = !write_fail && !load_missing_or_corrupt;
        char reason_buf[192] = "";
        if (write_fail && load_missing_or_corrupt) {
            snprintf(reason_buf, sizeof(reason_buf),
                     "write_fails=%lld and last_load_detail=missing_or_corrupt",
                     (long long)st.write_fails);
        } else if (write_fail) {
            snprintf(reason_buf, sizeof(reason_buf),
                     "write_fails=%lld", (long long)st.write_fails);
        } else if (load_missing_or_corrupt) {
            snprintf(reason_buf, sizeof(reason_buf),
                     "last_load_detail=missing_or_corrupt");
        }
        diag_push_health(out, ok, reason_buf);
    }
    return true;
}
