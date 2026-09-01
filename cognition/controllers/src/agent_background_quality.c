/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native reader for background quality-lane verdicts. This keeps expensive
 * fuzz/coverage/full-suite proof work visible through the C agent API without
 * putting shell wrappers on the AI operator hot path. */

#include "controllers/agent_background_quality.h"

#include "json/json.h"
#include "util/clientversion.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define AGENT_QUALITY_PATH_MAX 4096
#define AGENT_QUALITY_JSON_MAX 32768

static bool agent_quality_format_path(char *out, size_t out_len,
                                      const char *a, const char *b,
                                      const char *c)
{
    int n;

    if (!out || out_len == 0)
        return false;
    n = snprintf(out, out_len, "%s%s%s", a ? a : "", b ? b : "",
                 c ? c : "");
    if (n < 0 || (size_t)n >= out_len) {
        out[0] = '\0';
        return false;
    }
    return true;
}

static bool agent_quality_state_dir(char *out, size_t out_len,
                                    const char **source_out)
{
    const char *quality_dir = getenv("ZCL_QUALITY_STATE_DIR");
    const char *xdg_state = getenv("XDG_STATE_HOME");
    const char *home = getenv("HOME");

    if (source_out)
        *source_out = "fallback";
    if (quality_dir && quality_dir[0]) {
        if (source_out)
            *source_out = "ZCL_QUALITY_STATE_DIR";
        return agent_quality_format_path(out, out_len, quality_dir, "", "");
    }
    if (xdg_state && xdg_state[0]) {
        if (source_out)
            *source_out = "XDG_STATE_HOME";
        return agent_quality_format_path(out, out_len, xdg_state,
                                         "/zclassic23-quality", "");
    }
    if (home && home[0]) {
        if (source_out)
            *source_out = "HOME";
        return agent_quality_format_path(out, out_len, home,
                                         "/.local/state/zclassic23-quality",
                                         "");
    }
    return agent_quality_format_path(out, out_len, "/tmp",
                                     "/.local/state/zclassic23-quality", "");
}

static bool agent_quality_stat_file(const char *path, int64_t *size_out,
                                    int64_t *mtime_out)
{
    struct stat st;

    if (!path || stat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return false;
    if (size_out)
        *size_out = (int64_t)st.st_size;
    if (mtime_out)
        *mtime_out = (int64_t)st.st_mtime;
    return true;
}

static bool agent_quality_read_json_file(const char *path,
                                         struct json_value *out)
{
    FILE *f;
    char buf[AGENT_QUALITY_JSON_MAX + 1];
    size_t n;
    int extra;
    bool parsed;

    if (!path || !out)
        return false;
    f = fopen(path, "rb");
    if (!f)
        return false;
    n = fread(buf, 1, AGENT_QUALITY_JSON_MAX, f);
    extra = fgetc(f);
    if (ferror(f) || extra != EOF) {
        fclose(f);
        return false;
    }
    fclose(f);
    if (n == 0)
        return false;
    buf[n] = '\0';
    parsed = json_read(out, buf, n);
    return parsed && out->type == JSON_OBJ;
}

static bool agent_quality_source_id_valid(const char *source_id)
{
    if (!source_id || strlen(source_id) != 64)
        return false;
    for (size_t i = 0; i < 64; i++) {
        if (!((source_id[i] >= '0' && source_id[i] <= '9') ||
              (source_id[i] >= 'a' && source_id[i] <= 'f')))
            return false;
    }
    return true;
}

static bool agent_quality_source_id_matches(const char *expected,
                                            const char *observed)
{
    return agent_quality_source_id_valid(expected) &&
           agent_quality_source_id_valid(observed) &&
           strcmp(expected, observed) == 0;
}

static void agent_push_quality_lane(struct json_value *arr, const char *lane,
                                    const char *service, const char *timer,
                                    const char *cadence,
                                    const char *status_dir,
                                    int *present_count, int *valid_count,
                                    int *failed_count, int *running_count,
                                    int *passed_count, int *skipped_count,
                                    int *current_count, int *stale_count,
                                    int *unknown_source_id_count)
{
    struct json_value obj, latest;
    char status_file[AGENT_QUALITY_PATH_MAX];
    int64_t file_size = 0;
    int64_t modified_at = 0;
    bool path_ok;
    bool present = false;
    bool valid = false;
    const char *latest_status = "unknown";
    const char *expected_source_id = zcl_build_source_id_sha256();
    const char *expected_commit = zcl_build_commit();
    const char *latest_source_id = "";
    const char *latest_commit = "";
    const char *source_id_freshness = "no_verdict";
    bool expected_source_id_valid =
        agent_quality_source_id_valid(expected_source_id);
    bool source_id_present = false;
    bool source_id_matches = false;
    bool commit_present = false;
    int n;

    n = snprintf(status_file, sizeof(status_file), "%s/%s.json",
                 status_dir ? status_dir : "", lane ? lane : "");
    path_ok = n >= 0 && (size_t)n < sizeof(status_file);
    if (!path_ok)
        status_file[0] = '\0';

    json_init(&obj);
    json_set_object(&obj);
    json_push_kv_str(&obj, "lane", lane);
    json_push_kv_str(&obj, "service", service);
    json_push_kv_str(&obj, "timer", timer);
    json_push_kv_str(&obj, "cadence", cadence);
    json_push_kv_str(&obj, "status_file", path_ok ? status_file : "");
    json_push_kv_bool(&obj, "status_file_path_valid", path_ok);

    if (path_ok)
        present = agent_quality_stat_file(status_file, &file_size,
                                          &modified_at);
    json_push_kv_bool(&obj, "status_file_present", present);
    if (present) {
        json_push_kv_int(&obj, "status_file_bytes", file_size);
        json_push_kv_int(&obj, "status_file_mtime", modified_at);
        if (present_count)
            (*present_count)++;
    }

    json_init(&latest);
    json_set_null(&latest);
    if (present) {
        valid = agent_quality_read_json_file(status_file, &latest);
        if (valid) {
            const struct json_value *status_v = json_get(&latest, "status");
            const struct json_value *source_id_v =
                json_get(&latest, "source_id_sha256");
            const struct json_value *commit_v = json_get(&latest, "commit");
            if (status_v)
                latest_status = json_get_str(status_v);
            if (source_id_v)
                latest_source_id = json_get_str(source_id_v);
            if (commit_v)
                latest_commit = json_get_str(commit_v);
            source_id_present =
                agent_quality_source_id_valid(latest_source_id);
            commit_present = latest_commit && latest_commit[0];
            source_id_matches = agent_quality_source_id_matches(
                expected_source_id, latest_source_id);
            if (source_id_matches) {
                source_id_freshness = "current";
                if (current_count)
                    (*current_count)++;
            } else if (expected_source_id_valid && source_id_present) {
                source_id_freshness = "stale";
                if (stale_count)
                    (*stale_count)++;
            } else {
                source_id_freshness = "unknown";
                if (unknown_source_id_count)
                    (*unknown_source_id_count)++;
            }
            if (valid_count)
                (*valid_count)++;
            if (strcmp(latest_status, "failed") == 0 && failed_count)
                (*failed_count)++;
            else if (strcmp(latest_status, "running") == 0 && running_count)
                (*running_count)++;
            else if (strcmp(latest_status, "passed") == 0 && passed_count)
                (*passed_count)++;
            else if (strcmp(latest_status, "skipped") == 0 && skipped_count)
                (*skipped_count)++;
        } else {
            json_set_null(&latest);
        }
    }
    json_push_kv_bool(&obj, "latest_json_valid", valid);
    json_push_kv_str(&obj, "latest_status", latest_status);
    json_push_kv_str(&obj, "freshness_authority", "source_id_sha256");
    json_push_kv_str(&obj, "expected_source_id_sha256",
                     expected_source_id);
    json_push_kv_str(&obj, "latest_source_id_sha256",
                     latest_source_id ? latest_source_id : "");
    json_push_kv_bool(&obj, "source_id_present", source_id_present);
    json_push_kv_bool(&obj, "expected_source_id_valid",
                      expected_source_id_valid);
    json_push_kv_bool(&obj, "source_id_matches_expected",
                      source_id_matches);
    json_push_kv_str(&obj, "source_id_freshness", source_id_freshness);
    /* Compatibility aliases: these values are source-ID-derived. Git commit
     * strings below are trace metadata and never participate in freshness. */
    json_push_kv_str(&obj, "expected_commit", expected_commit);
    json_push_kv_str(&obj, "latest_commit", latest_commit ? latest_commit : "");
    json_push_kv_bool(&obj, "commit_present", commit_present);
    json_push_kv_bool(&obj, "commit_matches_expected", source_id_matches);
    json_push_kv_str(&obj, "commit_freshness", source_id_freshness);
    json_push_kv(&obj, "latest", &latest);
    json_free(&latest);

    json_push_back(arr, &obj);
    json_free(&obj);
}

void agent_build_background_quality_status(struct json_value *out)
{
    struct json_value lanes;
    char state_dir[AGENT_QUALITY_PATH_MAX];
    char status_dir[AGENT_QUALITY_PATH_MAX];
    const char *state_source = "fallback";
    const char *summary = "no_background_quality_verdicts";
    const char *next_action = "run_make_install_quality_linger";
    bool state_ok;
    bool status_ok;
    int present_count = 0;
    int valid_count = 0;
    int failed_count = 0;
    int running_count = 0;
    int passed_count = 0;
    int skipped_count = 0;
    int current_count = 0;
    int stale_count = 0;
    int unknown_source_id_count = 0;

    state_ok = agent_quality_state_dir(state_dir, sizeof(state_dir),
                                       &state_source);
    status_ok = state_ok &&
        agent_quality_format_path(status_dir, sizeof(status_dir), state_dir,
                                  "/status", "");

    json_set_object(out);
    json_push_kv_str(out, "schema", "zcl.background_quality_runtime.v1");
    json_push_kv_str(out, "api_version", "v1");
    json_push_kv_str(out, "status", "ok");
    json_push_kv_bool(out, "native_status_reader", true);
    json_push_kv_bool(out, "requires_python", false);
    json_push_kv_str(out, "install_command", "make install-quality-linger");
    json_push_kv_str(out, "status_command", "make quality-linger-status");
    json_push_kv_str(out, "script",
                     "tools/scripts/background_quality_lane.sh");
    json_push_kv_str(out, "state_dir", state_ok ? state_dir : "");
    json_push_kv_str(out, "state_dir_source", state_source);
    json_push_kv_str(out, "status_dir", status_ok ? status_dir : "");
    json_push_kv_bool(out, "state_path_valid", state_ok && status_ok);
    json_push_kv_bool(out, "pre_push_blocks_on_long_lanes", false);

    json_init(&lanes);
    json_set_array(&lanes);
    if (status_ok) {
        agent_push_quality_lane(&lanes, "fuzz", "zclassic23-fuzz.service",
                                "zclassic23-fuzz.timer", "hourly",
                                status_dir, &present_count, &valid_count,
                                &failed_count, &running_count, &passed_count,
                                &skipped_count, &current_count, &stale_count,
                                &unknown_source_id_count);
        agent_push_quality_lane(&lanes, "coverage",
                                "zclassic23-coverage.service",
                                "zclassic23-coverage.timer", "weekly",
                                status_dir, &present_count, &valid_count,
                                &failed_count, &running_count, &passed_count,
                                &skipped_count, &current_count, &stale_count,
                                &unknown_source_id_count);
        agent_push_quality_lane(&lanes, "tests",
                                "zclassic23-test-suite.service",
                                "zclassic23-test-suite.timer", "hourly",
                                status_dir, &present_count, &valid_count,
                                &failed_count, &running_count, &passed_count,
                                &skipped_count, &current_count, &stale_count,
                                &unknown_source_id_count);
    }
    json_push_kv(out, "lanes", &lanes);
    json_free(&lanes);

    if (failed_count > 0) {
        summary = "background_quality_failures_present";
        next_action = "inspect_failed_lane_log";
    } else if (stale_count > 0) {
        summary = "background_quality_stale";
        next_action = "restart_or_wait_for_current_source_quality_lanes";
    } else if (unknown_source_id_count > 0) {
        summary = "background_quality_identity_unknown";
        next_action = "rerun_background_quality_lanes_for_current_source";
    } else if (running_count > 0) {
        summary = "background_quality_lane_running";
        next_action = "wait_or_inspect_running_lane_log";
    } else if (valid_count == 3 && current_count == 3) {
        summary = "background_quality_verdicts_present";
        next_action = "monitor_background_quality_lanes";
    } else if (present_count > 0) {
        summary = "background_quality_incomplete";
        next_action = "run_make_quality_linger_status";
    }
    json_push_kv_int(out, "lanes_configured", status_ok ? 3 : 0);
    json_push_kv_int(out, "status_files_present", present_count);
    json_push_kv_int(out, "status_files_valid", valid_count);
    json_push_kv_int(out, "passed_count", passed_count);
    json_push_kv_int(out, "skipped_count", skipped_count);
    json_push_kv_int(out, "running_count", running_count);
    json_push_kv_int(out, "failed_count", failed_count);
    json_push_kv_str(out, "freshness_authority", "source_id_sha256");
    json_push_kv_int(out, "current_source_id_count", current_count);
    json_push_kv_int(out, "stale_source_id_count", stale_count);
    json_push_kv_int(out, "unknown_source_id_count", unknown_source_id_count);
    /* Backward-compatible aliases, now computed only from SHA-256 source IDs. */
    json_push_kv_int(out, "current_commit_count", current_count);
    json_push_kv_int(out, "stale_commit_count", stale_count);
    json_push_kv_int(out, "unknown_commit_count", unknown_source_id_count);
    json_push_kv_str(out, "summary", summary);
    json_push_kv_str(out, "agent_next_action", next_action);
}
