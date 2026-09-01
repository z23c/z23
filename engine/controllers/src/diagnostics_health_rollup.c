/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unhealthy-only rollup over the dumpstate registry.
 *
 * Every dumper in `g_dumpers[]` (diagnostics_registry.c) already computes
 * SOME notion of "is this subsystem OK" — a blocker count, a decision
 * result, a lag SLA, a stage error counter — but in heterogeneous shapes.
 * There is no single call that answers "is anything wrong anywhere?"
 *
 * Convention (see CLAUDE.md "Adding state introspection"): a dumper OPTS IN
 * to the rollup by emitting a reserved `_health` object under that exact
 * key, alongside its normal fields:
 *
 *   "_health": { "ok": <bool>, "reason": "<short string, "" when ok>" }
 *
 * `ok` is derived from state the dumper already computes — this file does
 * not invent new health logic, it only aggregates what dumpers already
 * decided. `reason` is a short, human-readable explanation; empty when ok.
 *
 * This dumper (subsystem "unhealthy") walks every OTHER registered
 * subsystem via the existing diagnostics_dumper_count()/diagnostics_
 * dumper_at() accessors, invokes each entry's fn() into a scratch
 * json_value, and looks for `_health`. Dumpers that don't emit it yet are
 * silently skipped (tolerant/incremental adoption — 5 subsystems seed it
 * today: reducer_frontier, blocker, legacy_mirror, chain_advance_coordinator,
 * tip_finalize). Only the unhealthy ones (_health.ok == false) are
 * collected, so `z23 dumpstate unhealthy` stays small and cheap to
 * read even as adoption grows.
 *
 * Reentrant-safe: no shared state of its own, no allocation beyond the
 * caller's json_value tree (each per-entry scratch json_value is freed
 * before the next iteration). Skips itself ("unhealthy") by name to avoid
 * infinite recursion. */

#include "controllers/diagnostics_internal.h"

#include "json/json.h"
#include "util/log_macros.h"

#include <string.h>

/* This subsystem's own name in g_dumpers — skipped during the walk so a
 * self-referential dumpstate call can never recurse. */
#define ZCL_HEALTH_ROLLUP_SELF_NAME "unhealthy"

bool unhealthy_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out)
        LOG_FAIL("diag", "unhealthy rollup: output is NULL");

    json_set_object(out);

    struct json_value unhealthy_arr = {0};
    json_set_array(&unhealthy_arr);

    size_t checked = 0;
    size_t unhealthy_count = 0;
    size_t reporting_count = 0;

    size_t total = diagnostics_dumper_count();
    for (size_t i = 0; i < total; i++) {
        const struct diagnostics_dump_entry *e = diagnostics_dumper_at(i);
        if (!e || !e->name || !e->fn)
            continue;
        if (strcmp(e->name, ZCL_HEALTH_ROLLUP_SELF_NAME) == 0)
            continue;

        checked++;

        struct json_value scratch = {0};
        json_set_object(&scratch);
        bool dump_ok = e->fn(&scratch, NULL);
        if (!dump_ok) {
            /* Dumper itself failed (missing schema, uninitialised state,
             * etc). That is a diagnostic signal in its own right, but not
             * one this rollup invents an opinion about — it just isn't
             * reporting `_health` this cycle. */
            json_free(&scratch);
            continue;
        }

        const struct json_value *health = json_get(&scratch, "_health");
        if (!health || health->type != JSON_OBJ) {
            json_free(&scratch);
            continue;
        }
        reporting_count++;

        const struct json_value *ok_val = json_get(health, "ok");
        bool ok = ok_val && json_get_bool(ok_val);
        if (!ok) {
            const struct json_value *reason_val = json_get(health, "reason");
            const char *reason = reason_val ? json_get_str(reason_val) : "";

            struct json_value entry = {0};
            json_set_object(&entry);
            json_push_kv_str(&entry, "subsystem", e->name);
            json_push_kv_str(&entry, "reason", reason ? reason : "");
            json_push_back(&unhealthy_arr, &entry);
            json_free(&entry);
            unhealthy_count++;
        }
        json_free(&scratch);
    }

    json_push_kv_bool(out, "all_ok", unhealthy_count == 0);
    json_push_kv_int(out, "checked", (int64_t)checked);
    json_push_kv_int(out, "reporting", (int64_t)reporting_count);
    json_push_kv_int(out, "unhealthy_count", (int64_t)unhealthy_count);
    json_push_kv(out, "unhealthy", &unhealthy_arr);
    json_free(&unhealthy_arr);
    return true;
}
