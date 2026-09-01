/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Regression contract for the bounded C23 SLO evidence reader. */

#include "test/test_core.h"

#include "base/safe_alloc.h"
#include "config/command_catalog.h"
#include "controllers/diagnostics_internal.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "services/evidence_ledger_row.h"
#include "services/slo_ledger_summary.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SLO_CHECK(name_, expr_) do {                                      \
    printf("slo_ledger_summary: %s... ", (name_));                         \
    if (expr_)                                                             \
        printf("OK\n");                                                    \
    else {                                                                 \
        printf("FAIL\n");                                                  \
        failures++;                                                        \
    }                                                                      \
} while (0)

static bool slo_dumpstate_is_registered(void)
{
    struct json_value catalog;
    json_init(&catalog);
    bool ok = diag_rpc_statecatalog(NULL, false, &catalog);
    const struct json_value *subsystems = json_get(&catalog, "subsystems");
    bool found = false;
    for (size_t i = 0; ok && subsystems && i < json_size(subsystems); i++) {
        const struct json_value *entry = json_at(subsystems, i);
        const char *name = entry ?
            json_get_str(json_get(entry, "name")) : NULL;
        if (name && strcmp(name, "slo_evidence") == 0) {
            found = true;
            break;
        }
    }
    json_free(&catalog);
    return ok && found;
}

static const struct json_value *summary_for(const struct json_value *report,
                                            const char *instance)
{
    const struct json_value *rows = json_get(report, "summaries");
    if (!rows || rows->type != JSON_ARR)
        return NULL;
    for (size_t i = 0; i < json_size(rows); i++) {
        const struct json_value *row = json_at(rows, i);
        const char *name = row ?
            json_get_str(json_get(row, "instance")) : NULL;
        if (name && strcmp(name, instance) == 0)
            return row;
    }
    return NULL;
}

static bool write_sample(FILE *file, int64_t ts, bool reachable,
                         const char *gap)
{
    return fprintf(file,
        "{\"ts\":%lld,\"instance\":\"canonical\","
        "\"reachable\":%s,\"gap_vs_oracle\":%s}\n",
        (long long)ts, reachable ? "true" : "false", gap) > 0;
}

static bool with_fixture_path(char *dir, size_t dir_cap,
                              char *path, size_t path_cap)
{
    if (dir_cap < sizeof("/tmp/z23-slo-test.XXXXXX"))
        return false;
    strcpy(dir, "/tmp/z23-slo-test.XXXXXX");
    if (!mkdtemp(dir))
        return false;
    return snprintf(path, path_cap, "%s/uptime-ledger.jsonl", dir) <
           (int)path_cap;
}

static bool strict_primitives_reject_suffixes(void)
{
    const char bad_int[] = "{\"ts\":100x}";
    const char bad_bool[] = "{\"reachable\":truex}";
    int64_t ts = 0;
    bool reachable = false;
    const char bad_suffix[] = "{\"ts\":100}junk";
    return !evidence_row_int(bad_int, sizeof(bad_int) - 1, "ts", &ts) &&
           !evidence_row_bool(bad_bool, sizeof(bad_bool) - 1,
                              "reachable", &reachable) &&
           !evidence_row_flat_object_valid(bad_suffix,
                                           sizeof(bad_suffix) - 1);
}

static bool native_default_invocation_is_bounded(void)
{
    char dir[64], path[128];
    if (!with_fixture_path(dir, sizeof(dir), path, sizeof(path)))
        return false;
    if (setenv("ZCL_SLO_LEDGER_DIR", dir, 1) != 0) {
        rmdir(dir);
        return false;
    }

    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(reg, "ops.slo", NULL);
    struct zcl_command_context ctx = {
        .registry = reg,
        .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
    };
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    bool ok = json_push_kv_int(&input, "window_hours", 24);
    char why[128];
    ok = ok && spec && zcl_command_registry_input_validate(
        spec, &input, why, sizeof(why));

    char output[ZCL_COMMAND_LIST_BUDGET + 1];
    enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_INTERNAL;
    size_t n = ok ? zcl_command_registry_execute_json(
        reg, spec, &ctx, &input, true, "ops.slo", "normal", 0, 0, NULL,
        output, sizeof(output), &exit_code) : 0;
    json_free(&input);
    unsetenv("ZCL_SLO_LEDGER_DIR");
    rmdir(dir);

    struct json_value result;
    json_init(&result);
    ok = ok && n > 0 && n < sizeof(output) &&
         n <= (size_t)spec->budget_bytes &&
         exit_code == ZCL_COMMAND_EXIT_OK && json_read(&result, output, n) &&
         json_get_bool(json_get(&result, "ok"));
    const struct json_value *data = ok ? json_get(&result, "data") : NULL;
    const struct json_value *summaries = data ?
        json_get(data, "summaries") : NULL;
    ok = ok && data &&
         strcmp(json_get_str(json_get(data, "schema")),
                "zcl.slo_evidence.v1") == 0 &&
         summaries && json_size(summaries) == 2;
    json_free(&result);
    return ok;
}

static bool degraded_window_math_is_exact(void)
{
    char dir[64], path[128];
    if (!with_fixture_path(dir, sizeof(dir), path, sizeof(path)))
        return false;
    FILE *file = fopen(path, "wb");
    if (!file) {
        rmdir(dir);
        return false;
    }
    const int64_t base = 1700000000;
    bool wrote = true;
    for (int i = 0; i <= 24; i++) {
        bool reachable = i < 10 || i > 14;
        const char *gap = i == 20 ? "5" : (reachable ? "0" : "null");
        wrote = wrote && write_sample(file, base + (int64_t)i * 3600,
                                      reachable, gap);
    }
    bool closed = fclose(file) == 0;

    struct json_value report;
    json_init(&report);
    bool ok = wrote && closed && slo_ledger_summary_render_path(
        path, "canonical", 24, base + 24 * 3600 + 30, &report);
    const struct json_value *row = ok ? summary_for(&report, "canonical") : NULL;
    ok = row &&
         json_get_bool(json_get(row, "window_complete")) &&
         json_get_int(json_get(row, "probe_count")) == 25 &&
         json_get_int(json_get(row, "reachable_count")) == 20 &&
         json_get_int(json_get(row, "max_gap_vs_oracle")) == 5 &&
         json_get_int(json_get(row, "longest_unreachable_run_probes")) == 5 &&
         json_get_int(json_get(row, "longest_unreachable_run_sec")) == 14400 &&
         strcmp(json_get_str(json_get(row, "verdict")), "DEGRADED") == 0;
    json_free(&report);
    unlink(path);
    rmdir(dir);
    return ok;
}

static bool torn_final_row_cannot_refresh_age(void)
{
    char dir[64], path[128];
    if (!with_fixture_path(dir, sizeof(dir), path, sizeof(path)))
        return false;
    FILE *file = fopen(path, "wb");
    if (!file) {
        rmdir(dir);
        return false;
    }
    const int64_t base = 1700000000;
    bool wrote = write_sample(file, base, true, "0") &&
                 write_sample(file, base + 3600, true, "0") &&
                 fprintf(file,
                    "{\"ts\":%lld,\"instance\":\"canonical\","
                    "\"reachable\":true,\"gap_vs_oracle\":0",
                    (long long)(base + 3900)) > 0;
    bool closed = fclose(file) == 0;

    struct json_value report;
    json_init(&report);
    bool ok = wrote && closed && slo_ledger_summary_render_path(
        path, "canonical", 1, base + 3900, &report);
    const struct json_value *row = ok ? summary_for(&report, "canonical") : NULL;
    ok = row && json_get_int(json_get(&report, "incomplete_rows")) == 1 &&
         json_get_int(json_get(row, "probe_count")) == 2 &&
         json_get_int(json_get(row, "last_sample_ts")) == base + 3600 &&
         json_get_int(json_get(row, "last_sample_age_sec")) == 300 &&
         strcmp(json_get_str(json_get(row, "verdict")), "STALE") == 0;
    json_free(&report);
    unlink(path);
    rmdir(dir);
    return ok;
}

static bool malformed_complete_row_fails_closed(void)
{
    char dir[64], path[128];
    if (!with_fixture_path(dir, sizeof(dir), path, sizeof(path)))
        return false;
    FILE *file = fopen(path, "wb");
    if (!file) {
        rmdir(dir);
        return false;
    }
    const int64_t base = 1700000000;
    bool wrote = write_sample(file, base, true, "0") &&
                 write_sample(file, base + 3600, true, "0") &&
                 fprintf(file,
                    "{\"ts\":%lld,\"instance\":\"canonical\","
                    "\"reachable\":truex,\"gap_vs_oracle\":0}\n",
                    (long long)(base + 3601)) > 0 &&
                 fprintf(file,
                    "{\"ts\":%lld,\"instance\":\"canonical\","
                    "\"reachable\":true,\"gap_vs_oracle\":0}junk\n",
                    (long long)(base + 3602)) > 0 &&
                 fprintf(file,
                    "{\"ts\":%lld,\"instance\":\"canonical\","
                    "\"reachable\":true,\"gap_vs_oracle\":\"zero\"}\n",
                    (long long)(base + 3603)) > 0 &&
                 fprintf(file,
                    "{\"ts\":%lld,\"instance\":\"canon\\q\","
                    "\"reachable\":true,\"gap_vs_oracle\":0}\n",
                    (long long)(base + 3604)) > 0;
    bool closed = fclose(file) == 0;

    struct json_value report;
    json_init(&report);
    bool ok = wrote && closed && slo_ledger_summary_render_path(
        path, "canonical", 1, base + 3610, &report);
    const struct json_value *row = ok ? summary_for(&report, "canonical") : NULL;
    ok = row && json_get_int(json_get(&report, "malformed_rows")) == 4 &&
         strcmp(json_get_str(json_get(row, "verdict")),
                "INVALID_EVIDENCE") == 0 &&
         !json_get_bool(json_get(json_get(&report, "_health"), "ok"));
    json_free(&report);
    unlink(path);
    rmdir(dir);
    return ok;
}

static bool short_window_never_claims_ok(void)
{
    char dir[64], path[128];
    if (!with_fixture_path(dir, sizeof(dir), path, sizeof(path)))
        return false;
    FILE *file = fopen(path, "wb");
    if (!file) {
        rmdir(dir);
        return false;
    }
    const int64_t base = 1700000000;
    bool wrote = write_sample(file, base, true, "0");
    bool closed = fclose(file) == 0;
    struct json_value report;
    json_init(&report);
    bool ok = wrote && closed && slo_ledger_summary_render_path(
        path, "canonical", 24, base + 30, &report);
    const struct json_value *row = ok ? summary_for(&report, "canonical") : NULL;
    ok = row && !json_get_bool(json_get(row, "window_complete")) &&
         strcmp(json_get_str(json_get(row, "verdict")),
                "INCOMPLETE_WINDOW") == 0;
    json_free(&report);
    unlink(path);
    rmdir(dir);
    return ok;
}

static bool sample_arena_oom_is_reported(void)
{
    struct json_value report;
    json_init(&report);
    zcl_alloc_fault_fail_next("slo evidence samples");
    bool refused = !slo_ledger_summary_render_path(
        "/definitely/not/present", "canonical", 24, 1, &report);
    zcl_alloc_fault_clear();
    json_free(&report);
    return refused;
}

int test_slo_ledger_summary(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();

    bool was_alias = false;
    const struct zcl_command_spec *canonical =
        zcl_command_registry_find(reg, "ops.debug.dash.slo", NULL);
    const struct zcl_command_spec *alias =
        zcl_command_registry_find(reg, "ops.slo", &was_alias);

    SLO_CHECK("node-free typed leaf is registered",
              canonical && canonical->handler &&
              canonical->scope == ZCL_COMMAND_SCOPE_LOCAL);
    SLO_CHECK("short ops.slo alias resolves to the same leaf",
              alias == canonical && was_alias);
    SLO_CHECK("dumpstate exposes the same SLO evidence authority",
              slo_dumpstate_is_registered());
    SLO_CHECK("default native invocation is typed and fits its budget",
              native_default_invocation_is_bounded());
    SLO_CHECK("numeric and boolean prefixes are not evidence",
              strict_primitives_reject_suffixes());
    SLO_CHECK("24-hour window math and outage run are exact",
              degraded_window_math_is_exact());
    SLO_CHECK("torn final row cannot refresh sample age",
              torn_final_row_cannot_refresh_age());
    SLO_CHECK("malformed complete row fails closed",
              malformed_complete_row_fails_closed());
    SLO_CHECK("partial observation window cannot claim OK",
              short_window_never_claims_ok());
    SLO_CHECK("sample arena allocation failure is observable",
              sample_arena_oom_is_reported());

    return failures;
}
