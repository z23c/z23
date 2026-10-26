/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * getsyncdiag / anchorstatus / getsyncwatchdog cases: the JSON envelope is well formed on a dirty stack, and the mint-anchor backlog is reported as stale or active from the durable sample cadence.
 */

#include "test/syncdiag_rpc_fixture.h"

#define EXPECTED_MISSING_KEYS \
    "schema,api_version,build_commit,read_only," \
    "process_identity_available,process_identity_reason,datadir," \
    "captured_at_unix,progress_path,progress_present," \
    "progress_size_bytes,progress_mtime_unix,progress_age_seconds," \
    "snapshot_path,snapshot_present,snapshot_size_bytes," \
    "snapshot_mtime_unix,anchor_height,anchor_utxo_count," \
    "snapshot_header_readable,snapshot_payload_sha3_verified," \
    "snapshot_checkpoint_sha3_match,snapshot_version,snapshot_height," \
    "snapshot_utxo_count,snapshot_total_supply,snapshot_payload_sha3," \
    "snapshot_digest_source,progress_wal_path,progress_wal_present," \
    "progress_wal_size_bytes,progress_wal_mtime_unix," \
    "progress_wal_age_seconds,progress_activity_mtime_unix," \
    "progress_activity_age_seconds,progress_activity_source," \
    "progress_sample_interval_seconds,progress_stale_after_seconds," \
    "progress_recent,eta,producer_import_preflight," \
    "body_position_preflight,status,fold_recently_active,summary," \
    "agent_next_action"
#define EXPECTED_UNREADABLE_KEYS \
    "schema,api_version,build_commit,read_only," \
    "process_identity_available,process_identity_reason,datadir," \
    "captured_at_unix,progress_path,progress_present," \
    "progress_size_bytes,progress_mtime_unix,progress_age_seconds," \
    "snapshot_path,snapshot_present,snapshot_size_bytes," \
    "snapshot_mtime_unix,anchor_height,anchor_utxo_count," \
    "snapshot_header_readable,snapshot_payload_sha3_verified," \
    "snapshot_checkpoint_sha3_match,snapshot_version,snapshot_height," \
    "snapshot_utxo_count,snapshot_total_supply,snapshot_payload_sha3," \
    "snapshot_digest_source,progress_wal_path,progress_wal_present," \
    "progress_wal_size_bytes,progress_wal_mtime_unix," \
    "progress_wal_age_seconds,progress_activity_mtime_unix," \
    "progress_activity_age_seconds,progress_activity_source," \
    "progress_sample_interval_seconds,progress_stale_after_seconds," \
    "progress_recent,eta,producer_import_preflight," \
    "body_position_preflight,status,fold_recently_active,summary," \
    "agent_next_action,sqlite_error"
#include <sys/stat.h>
#include <unistd.h>

/* Comma-joined object keys in insertion order. */
static void anchor_case_keys(const struct json_value *obj, char *out,
                             size_t cap)
{
    out[0] = '\0';
    for (size_t i = 0; i < obj->num_children; i++) {
        size_t used = strlen(out);
        snprintf(out + used, cap - used, "%s%s", i ? "," : "",
                 obj->keys[i]);
    }
}

static bool anchor_case_has_duplicate_key(const struct json_value *obj)
{
    for (size_t i = 0; i < obj->num_children; i++)
        for (size_t j = i + 1; j < obj->num_children; j++)
            if (strcmp(obj->keys[i], obj->keys[j]) == 0)
                return true;
    return false;
}

static bool anchor_case_run(const char *dir, struct json_value *result)
{
    struct json_value params, arg;
    json_init(&params);
    json_set_array(&params);
    json_init(&arg);
    json_set_str(&arg, dir);
    json_push_back(&params, &arg);
    json_free(&arg);
    json_init(result);
    bool ok = rpc_agent_anchor_status(&params, false, result);
    json_free(&params);
    return ok && result->type == JSON_OBJ;
}

static bool anchor_case_str_is(const struct json_value *obj, const char *key,
                               const char *want)
{
    const char *got = json_get_str(json_get(obj, key));
    return got && strcmp(got, want) == 0;
}

/* The import-preflight argv names "<datadir>/node.db" as its last element. */
static bool anchor_case_preflight_names(const struct json_value *result,
                                        const char *dir)
{
    const struct json_value *prep =
        json_get(result, "producer_import_preflight");
    const struct json_value *argv = prep ? json_get(prep, "argv") : NULL;
    const struct json_value *node_db = argv ? json_at(argv, 3) : NULL;
    char want[512];
    snprintf(want, sizeof(want), "%s/node.db", dir);
    return node_db && strcmp(json_get_str(node_db), want) == 0;
}

static bool anchor_case_set_meta_sql(const char *dir, const char *sql)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/progress.kv", dir);
    sqlite3 *db = NULL;
    bool ok = sqlite3_open(path, &db) == SQLITE_OK &&
              syncdiag_exec_sql(db, sql);
    sqlite3_close(db);
    return ok;
}

static int anchor_case_missing_progress(void)
{
    printf("anchorstatus: missing progress store reports key order, "
           "datadir and summary... ");
    char dir[256], keys[4096];
    test_make_tmpdir(dir, sizeof(dir), "syncdiag_anchorstatus", "missing");
    struct json_value result;
    bool ok = anchor_case_run(dir, &result);
    anchor_case_keys(&result, keys, sizeof(keys));
    ok = ok && !anchor_case_has_duplicate_key(&result);
    ok = ok && strcmp(keys, EXPECTED_MISSING_KEYS) == 0;
    ok = ok && anchor_case_str_is(&result, "status", "missing");
    ok = ok && anchor_case_str_is(&result, "summary",
                                  "progress_store_missing");
    ok = ok && anchor_case_str_is(&result, "agent_next_action",
                                  "start_anchor_mint_on_full_history_datadir");
    ok = ok && anchor_case_str_is(&result, "datadir", dir);
    ok = ok && !json_get_bool(json_get(&result, "progress_present"));
    ok = ok && !json_get_bool(json_get(&result, "fold_recently_active"));
    ok = ok && anchor_case_preflight_names(&result, dir);
    if (!ok)
        printf("\n  keys=%s\n", keys);
    json_free(&result);
    test_cleanup_tmpdir(dir);
    printf("%s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static int anchor_case_path_too_long(void)
{
    printf("anchorstatus: over-long datadir reports path_too_long... ");
    char dir[1300];
    memset(dir, 'a', sizeof(dir) - 1);
    dir[0] = '/';
    dir[sizeof(dir) - 1] = '\0';
    struct json_value result;
    bool ok = anchor_case_run(dir, &result);
    ok = ok && anchor_case_str_is(&result, "status", "error");
    ok = ok && anchor_case_str_is(&result, "summary", "path_too_long");
    ok = ok && anchor_case_str_is(&result, "agent_next_action",
                                  "use_bounded_datadir_and_snapshot_paths");
    ok = ok && json_get(&result, "progress_path") == NULL;
    json_free(&result);
    printf("%s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static bool anchor_case_open_failed_ok(const struct json_value *result,
                                       const char *dir)
{
    char keys[4096];
    anchor_case_keys(result, keys, sizeof(keys));
    bool ok = !anchor_case_has_duplicate_key(result) &&
              strcmp(keys, EXPECTED_UNREADABLE_KEYS) == 0;
    if (!ok)
        printf("\n  keys=%s\n", keys);
    ok = ok && anchor_case_str_is(result, "status", "error");
    ok = ok && anchor_case_str_is(result, "summary",
                                  "progress_store_open_failed");
    ok = ok && anchor_case_str_is(
        result, "agent_next_action",
        "inspect_progress_store_permissions_or_locking");
    ok = ok && json_get_str(json_get(result, "sqlite_error")) != NULL;
    ok = ok && !json_get_bool(json_get(result, "fold_recently_active"));
    ok = ok && json_get_bool(json_get(result, "progress_present"));
    return ok && anchor_case_preflight_names(result, dir);
}

static int anchor_case_unreadable_store(void)
{
    printf("anchorstatus: unreadable progress store reports open failure... ");
    if (geteuid() == 0) {
        printf("SKIP (root ignores file modes)\n");
        return 0;
    }
    char dir[256], path[512];
    test_make_tmpdir(dir, sizeof(dir), "syncdiag_anchorstatus", "unreadable");
    snprintf(path, sizeof(path), "%s/progress.kv", dir);
    bool ok = syncdiag_seed_anchorstatus_progress(dir) &&
              chmod(path, 0) == 0;
    struct json_value result;
    ok = ok && anchor_case_run(dir, &result);
    if (ok) {
        ok = anchor_case_open_failed_ok(&result, dir);
        json_free(&result);
    }
    (void)chmod(path, 0600);
    test_cleanup_tmpdir(dir);
    printf("%s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static int anchor_case_applied_height(const char *tag, const char *sql,
                                      int64_t want_applied,
                                      int64_t want_durable)
{
    printf("anchorstatus: coins_applied_height %s... ", tag);
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "syncdiag_anchorstatus", tag);
    checkpoints_reset_sha3_override_for_test();
    bool ok = syncdiag_seed_anchorstatus_progress(dir) &&
              anchor_case_set_meta_sql(dir, sql);
    struct json_value result;
    ok = ok && anchor_case_run(dir, &result);
    if (ok) {
        ok = ok && anchor_case_str_is(&result, "status", "ok");
        ok = ok && json_get_int(json_get(&result, "coins_applied_height")) ==
            want_applied;
        ok = ok && json_get_int(json_get(
            &result, "durable_applied_through_height")) == want_durable;
        json_free(&result);
    }
    test_cleanup_tmpdir(dir);
    printf("%s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

enum {
    ANCHOR_OP_PRESENT = 0,
    ANCHOR_OP_STR,
    ANCHOR_OP_STR_RAW,
    ANCHOR_OP_BOOL,
    ANCHOR_OP_BOOL_RAW,
    ANCHOR_OP_INT_RAW,
    ANCHOR_OP_INT
};

enum {
    ANCHOR_CMP_EQ = 0,
    ANCHOR_CMP_GT,
    ANCHOR_CMP_GE,
    ANCHOR_CMP_LE
};

enum {
    ANCHOR_OBJ_PRESENT = 0,
    ANCHOR_OBJ_TYPED
};

struct anchor_expect {
    const char *key;
    int op;
    int cmp;
    bool flag;
    const char *str;
    int64_t num;
};

static const struct anchor_expect k_syncdiag_wd[] = {
    { .key = "last_recovery_reason", .op = ANCHOR_OP_PRESENT },
    { .key = "last_recovery_local_height", .op = ANCHOR_OP_PRESENT },
    { .key = "last_recovery_peer_height", .op = ANCHOR_OP_PRESENT },
    { .key = "last_recovery_peer_count", .op = ANCHOR_OP_PRESENT },
    { .key = "last_recovery_target_height", .op = ANCHOR_OP_PRESENT },
    { .key = "last_recovery_manifest_height", .op = ANCHOR_OP_PRESENT },
    { .key = "last_recovery_trigger", .op = ANCHOR_OP_PRESENT },
    { .key = "recoveries_total", .op = ANCHOR_OP_INT, .cmp = ANCHOR_CMP_EQ,
      .num = 1 },
    { .key = "last_recovery", .op = ANCHOR_OP_STR,
      .str = "SNAPSHOT_RESNAPSHOT" },
    { .key = "last_recovery_reason", .op = ANCHOR_OP_STR_RAW,
      .str = "condition:tip_wedged_resnapshot" },
    { .key = "last_recovery_local_height", .op = ANCHOR_OP_INT_RAW,
      .cmp = ANCHOR_CMP_EQ, .num = 100 },
    { .key = "last_recovery_peer_height", .op = ANCHOR_OP_INT_RAW,
      .cmp = ANCHOR_CMP_EQ, .num = 110 },
    { .key = "last_recovery_peer_count", .op = ANCHOR_OP_INT_RAW,
      .cmp = ANCHOR_CMP_EQ, .num = 4 },
    { .key = "last_recovery_target_height", .op = ANCHOR_OP_INT_RAW,
      .cmp = ANCHOR_CMP_EQ, .num = 101 },
    { .key = "last_recovery_manifest_height", .op = ANCHOR_OP_INT_RAW,
      .cmp = ANCHOR_CMP_EQ, .num = 111 },
    { .key = "last_recovery_trigger", .op = ANCHOR_OP_STR_RAW,
      .str = "block_failed_mask_exhausted" },
};

static const struct anchor_expect k_syncdiag_top[] = {
    { .key = "sync_state", .op = ANCHOR_OP_PRESENT },
    { .key = "chain_height", .op = ANCHOR_OP_PRESENT },
    { .key = "best_header_height", .op = ANCHOR_OP_PRESENT },
};

static const struct anchor_expect k_stale_top[] = {
    { .key = "schema", .op = ANCHOR_OP_STR,
      .str = "zcl.anchor_mint_status.v1" },
    { .key = "status", .op = ANCHOR_OP_STR, .str = "ok" },
    { .key = "captured_at_unix", .op = ANCHOR_OP_INT, .cmp = ANCHOR_CMP_GT,
      .num = 0 },
    { .key = "progress_age_seconds", .op = ANCHOR_OP_INT, .cmp = ANCHOR_CMP_GT,
      .num = 300 },
    { .key = "progress_recent", .op = ANCHOR_OP_BOOL, .flag = false },
    { .key = "progress_wal_present", .op = ANCHOR_OP_BOOL, .flag = false },
    { .key = "progress_activity_source", .op = ANCHOR_OP_STR_RAW,
      .str = "progress.kv" },
    { .key = "progress_sample_interval_seconds", .op = ANCHOR_OP_INT_RAW,
      .cmp = ANCHOR_CMP_EQ, .num = 60 },
    { .key = "progress_stale_after_seconds", .op = ANCHOR_OP_INT_RAW,
      .cmp = ANCHOR_CMP_EQ, .num = 300 },
    { .key = "fold_recently_active", .op = ANCHOR_OP_BOOL, .flag = false },
    { .key = "summary", .op = ANCHOR_OP_STR,
      .str = "mint_utxo_apply_far_behind_validated_backlog" },
    { .key = "agent_next_action", .op = ANCHOR_OP_STR,
      .str = "inspect_utxo_apply_idle_reason_before_waiting_more" },
    { .key = "mint_marker_present", .op = ANCHOR_OP_BOOL, .flag = true },
    { .key = "mint_marker_matches_checkpoint", .op = ANCHOR_OP_BOOL,
      .flag = true },
    { .key = "refold_in_progress_present", .op = ANCHOR_OP_BOOL,
      .flag = true },
    { .key = "coins_applied_height", .op = ANCHOR_OP_INT,
      .cmp = ANCHOR_CMP_EQ, .num = 164000 },
    { .key = "durable_applied_through_height", .op = ANCHOR_OP_INT,
      .cmp = ANCHOR_CMP_EQ, .num = 163999 },
    { .key = "validated_backlog_blocks", .op = ANCHOR_OP_INT,
      .cmp = ANCHOR_CMP_EQ, .num = 2627000 },
    { .key = "stale_header_rows_above_anchor", .op = ANCHOR_OP_INT,
      .cmp = ANCHOR_CMP_EQ, .num = 1 },
    { .key = "stale_rows_above_anchor", .op = ANCHOR_OP_BOOL, .flag = true },
    { .key = "utxo_apply_probe_next_action", .op = ANCHOR_OP_STR,
      .str = "inspect_anchor_mint_liveness_and_durable_activity" },
};

static const struct anchor_expect k_stale_probe[] = {
    { .key = "next_height", .op = ANCHOR_OP_INT, .cmp = ANCHOR_CMP_EQ,
      .num = 164000 },
    { .key = "previous_height", .op = ANCHOR_OP_INT, .cmp = ANCHOR_CMP_EQ,
      .num = 163999 },
    { .key = "previous_row_expected", .op = ANCHOR_OP_BOOL, .flag = true },
    { .key = "next_diagnosis", .op = ANCHOR_OP_STR,
      .str = "utxo_apply_idle_after_validated_row" },
    { .key = "history_diagnosis", .op = ANCHOR_OP_STR,
      .str = "utxo_apply_history_consistent" },
    { .key = "next_action", .op = ANCHOR_OP_STR,
      .str = "inspect_anchor_mint_liveness_and_durable_activity" },
};

static const struct anchor_expect k_stale_proof[] = {
    { .key = "row_present", .op = ANCHOR_OP_BOOL, .flag = true },
    { .key = "ok", .op = ANCHOR_OP_INT, .cmp = ANCHOR_CMP_EQ, .num = 1 },
};

static const struct anchor_expect k_stale_utxo_next[] = {
    { .key = "row_present", .op = ANCHOR_OP_BOOL, .flag = false },
};

static const struct anchor_expect k_stale_utxo[] = {
    { .key = "cursor", .op = ANCHOR_OP_INT, .cmp = ANCHOR_CMP_EQ,
      .num = 164000 },
    { .key = "log_max_height", .op = ANCHOR_OP_INT, .cmp = ANCHOR_CMP_EQ,
      .num = 163999 },
};

static const struct anchor_expect k_stale_eta[] = {
    { .key = "available", .op = ANCHOR_OP_BOOL, .flag = true },
    { .key = "older_height", .op = ANCHOR_OP_INT, .cmp = ANCHOR_CMP_EQ,
      .num = 0 },
    { .key = "newer_height", .op = ANCHOR_OP_INT, .cmp = ANCHOR_CMP_EQ,
      .num = 163999 },
    { .key = "eta_seconds", .op = ANCHOR_OP_INT, .cmp = ANCHOR_CMP_GT,
      .num = 0 },
};

static const struct anchor_expect k_snap_flags[] = {
    { .key = "read_only", .op = ANCHOR_OP_BOOL, .flag = true },
    { .key = "process_identity_available", .op = ANCHOR_OP_BOOL,
      .flag = false },
    { .key = "snapshot_payload_sha3_verified", .op = ANCHOR_OP_BOOL,
      .flag = true },
};

static const struct anchor_expect k_recent_status[] = {
    { .key = "status", .op = ANCHOR_OP_STR, .str = "ok" },
};

static const struct anchor_expect k_recent_tail[] = {
    { .key = "progress_recent", .op = ANCHOR_OP_BOOL, .flag = true },
    { .key = "fold_recently_active", .op = ANCHOR_OP_BOOL, .flag = true },
    { .key = "summary", .op = ANCHOR_OP_STR, .str = "mint_in_progress_recent" },
    { .key = "agent_next_action", .op = ANCHOR_OP_STR,
      .str = "observe_anchor_mint_progress" },
    { .key = "utxo_apply_probe_next_action", .op = ANCHOR_OP_STR,
      .str = "observe_anchor_mint_progress" },
};

static const struct anchor_expect k_recent_probe[] = {
    { .key = "next_diagnosis", .op = ANCHOR_OP_STR,
      .str = "utxo_apply_idle_after_validated_row" },
    { .key = "next_action", .op = ANCHOR_OP_STR,
      .str = "observe_anchor_mint_progress" },
};

static const struct anchor_expect k_wal_head[] = {
    { .key = "progress_age_seconds", .op = ANCHOR_OP_INT_RAW,
      .cmp = ANCHOR_CMP_GT, .num = 300 },
    { .key = "progress_wal_present", .op = ANCHOR_OP_BOOL_RAW, .flag = true },
    { .key = "progress_wal_size_bytes", .op = ANCHOR_OP_INT_RAW,
      .cmp = ANCHOR_CMP_GT, .num = 0 },
};

static const struct anchor_expect k_wal_tail[] = {
    { .key = "progress_activity_source", .op = ANCHOR_OP_STR_RAW,
      .str = "progress.kv-wal" },
    { .key = "progress_recent", .op = ANCHOR_OP_BOOL_RAW, .flag = true },
    { .key = "fold_recently_active", .op = ANCHOR_OP_BOOL_RAW, .flag = true },
    { .key = "summary", .op = ANCHOR_OP_STR_RAW,
      .str = "mint_in_progress_recent" },
    { .key = "utxo_apply_probe_next_action", .op = ANCHOR_OP_STR_RAW,
      .str = "observe_anchor_mint_progress" },
};

static const struct anchor_expect k_cadence_head[] = {
    { .key = "progress_age_seconds", .op = ANCHOR_OP_INT_RAW,
      .cmp = ANCHOR_CMP_GT, .num = 300 },
    { .key = "progress_wal_present", .op = ANCHOR_OP_BOOL_RAW,
      .flag = false },
    { .key = "progress_activity_source", .op = ANCHOR_OP_STR_RAW,
      .str = "durable_utxo_apply_sample" },
};

static const struct anchor_expect k_cadence_tail[] = {
    { .key = "progress_sample_interval_seconds", .op = ANCHOR_OP_INT_RAW,
      .cmp = ANCHOR_CMP_EQ, .num = 600 },
    { .key = "progress_stale_after_seconds", .op = ANCHOR_OP_INT_RAW,
      .cmp = ANCHOR_CMP_EQ, .num = 1200 },
    { .key = "progress_recent", .op = ANCHOR_OP_BOOL_RAW, .flag = true },
    { .key = "fold_recently_active", .op = ANCHOR_OP_BOOL_RAW, .flag = true },
    { .key = "summary", .op = ANCHOR_OP_STR_RAW,
      .str = "mint_in_progress_recent" },
    { .key = "utxo_apply_probe_next_action", .op = ANCHOR_OP_STR_RAW,
      .str = "observe_anchor_mint_progress" },
};

static const struct anchor_expect k_watchdog[] = {
    { .key = "enabled", .op = ANCHOR_OP_PRESENT },
    { .key = "recoveries_total", .op = ANCHOR_OP_INT, .cmp = ANCHOR_CMP_EQ,
      .num = 1 },
    { .key = "last_recovery", .op = ANCHOR_OP_STR,
      .str = "SNAPSHOT_RESNAPSHOT" },
    { .key = "last_recovery_time", .op = ANCHOR_OP_INT, .cmp = ANCHOR_CMP_GT,
      .num = 0 },
    { .key = "last_recovery_reason", .op = ANCHOR_OP_STR,
      .str = "condition:tip_wedged_resnapshot" },
    { .key = "last_recovery_local_height", .op = ANCHOR_OP_INT,
      .cmp = ANCHOR_CMP_EQ, .num = 120 },
    { .key = "last_recovery_peer_height", .op = ANCHOR_OP_INT,
      .cmp = ANCHOR_CMP_EQ, .num = 130 },
    { .key = "last_recovery_peer_count", .op = ANCHOR_OP_INT,
      .cmp = ANCHOR_CMP_EQ, .num = 2 },
    { .key = "last_recovery_target_height", .op = ANCHOR_OP_INT,
      .cmp = ANCHOR_CMP_EQ, .num = 121 },
    { .key = "last_recovery_manifest_height", .op = ANCHOR_OP_INT,
      .cmp = ANCHOR_CMP_EQ, .num = 131 },
    { .key = "last_recovery_trigger", .op = ANCHOR_OP_STR,
      .str = "local_import_exhausted" },
};

static bool anchor_int_cmp(int64_t got, int cmp, int64_t want)
{
    if (cmp == ANCHOR_CMP_EQ)
        return got == want;
    if (cmp == ANCHOR_CMP_GT)
        return got > want;
    if (cmp == ANCHOR_CMP_GE)
        return got >= want;
    if (cmp == ANCHOR_CMP_LE)
        return got <= want;
    return false;
}

static bool anchor_expect_holds(const struct json_value *obj,
                                const struct anchor_expect *row)
{
    const struct json_value *v = json_get(obj, row->key);
    if (row->op == ANCHOR_OP_PRESENT)
        return v != NULL;
    if (row->op == ANCHOR_OP_STR)
        return v != NULL && strcmp(json_get_str(v), row->str) == 0;
    if (row->op == ANCHOR_OP_STR_RAW)
        return strcmp(json_get_str(v), row->str) == 0;
    if (row->op == ANCHOR_OP_BOOL)
        return v != NULL && json_get_bool(v) == row->flag;
    if (row->op == ANCHOR_OP_BOOL_RAW)
        return json_get_bool(v) == row->flag;
    if (row->op == ANCHOR_OP_INT_RAW)
        return anchor_int_cmp(json_get_int(v), row->cmp, row->num);
    return v != NULL && anchor_int_cmp(json_get_int(v), row->cmp, row->num);
}

static int anchor_expects_match(const struct json_value *obj,
                                const struct anchor_expect *rows, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        bool held = anchor_expect_holds(obj, &rows[i]);
        if (!held)
            return 1;
    }
    return 0;
}

static int anchor_child_matches(const struct json_value *parent,
                                const char *key,
                                const struct anchor_expect *rows, size_t n,
                                int obj_kind)
{
    const struct json_value *child = json_get(parent, key);
    bool obj_ok;
    if (obj_kind == ANCHOR_OBJ_TYPED)
        obj_ok = child != NULL && child->type == JSON_OBJ;
    else
        obj_ok = child != NULL;
    if (!obj_ok)
        return 1;
    return anchor_expects_match(child, rows, n);
}

static int anchor_case_report(bool ok)
{
    if (ok) {
        printf("OK\n");
        return 0;
    }
    printf("FAIL\n");
    return 1;
}

static int anchor_syncdiag_ok(const struct json_value *result)
{
    if (result->type != JSON_OBJ)
        return 1;
    const struct json_value *wd = json_get(result, "watchdog");
    const struct json_value *hdr = json_get(result, "headers");
    bool wd_ok = wd && wd->type == JSON_OBJ && wd->num_children > 0;
    if (!wd_ok)
        return 1;
    bool hdr_ok = hdr && hdr->type == JSON_OBJ && hdr->num_children > 0;
    if (!hdr_ok)
        return 1;
    int bad = anchor_expects_match(wd, k_syncdiag_wd,
                                   sizeof k_syncdiag_wd /
                                   sizeof k_syncdiag_wd[0]);
    if (bad != 0)
        return bad;
    return anchor_expects_match(result, k_syncdiag_top,
                                sizeof k_syncdiag_top /
                                sizeof k_syncdiag_top[0]);
}

static int anchor_stale_result_ok(const struct json_value *result)
{
    if (result->type != JSON_OBJ)
        return 1;
    int bad = anchor_expects_match(result, k_stale_top,
                                   sizeof k_stale_top / sizeof k_stale_top[0]);
    if (bad != 0)
        return bad;
    bad = anchor_child_matches(result, "utxo_apply_probe", k_stale_probe,
                               sizeof k_stale_probe / sizeof k_stale_probe[0],
                               ANCHOR_OBJ_TYPED);
    if (bad != 0)
        return bad;
    const struct json_value *probe = json_get(result, "utxo_apply_probe");
    bad = anchor_child_matches(probe, "proof_validate_at_next", k_stale_proof,
                               sizeof k_stale_proof / sizeof k_stale_proof[0],
                               ANCHOR_OBJ_PRESENT);
    if (bad != 0)
        return bad;
    bad = anchor_child_matches(probe, "utxo_apply_at_next", k_stale_utxo_next,
                               sizeof k_stale_utxo_next /
                               sizeof k_stale_utxo_next[0],
                               ANCHOR_OBJ_PRESENT);
    if (bad != 0)
        return bad;
    const struct json_value *utxo = find_object_with_str(
        json_get(result, "stages"), "name", "utxo_apply");
    if (!utxo)
        return 1;
    bad = anchor_expects_match(utxo, k_stale_utxo,
                               sizeof k_stale_utxo / sizeof k_stale_utxo[0]);
    if (bad != 0)
        return bad;
    return anchor_child_matches(result, "eta", k_stale_eta,
                                sizeof k_stale_eta / sizeof k_stale_eta[0],
                                ANCHOR_OBJ_TYPED);
}

static int anchor_stale_preflight_ok(const struct json_value *snap)
{
    const struct json_value *prep =
        json_get(snap, "producer_import_preflight");
    /* --importblockindex is now scanned anywhere in argv (engine/entry/main.c),
     * so this field is correctly `false` — see
     * agent_cure_status_helpers.c and
     * test_importblockindex_cli_dispatch.c's nonfirst-position case for
     * the live proof. */
    bool prep_flag = prep &&
        json_get(prep, "importblockindex_must_be_argv1") != NULL &&
        !json_get_bool(json_get(prep, "importblockindex_must_be_argv1"));
    if (!prep_flag)
        return 1;
    bool templ = strstr(json_get_str(json_get(prep, "exact_template")),
                        "BIN --importblockindex") != NULL;
    if (!templ)
        return 1;
    const struct json_value *body =
        json_get(snap, "body_position_preflight");
    bool suspected = body && json_get_bool(json_get(body, "suspected"));
    if (!suspected)
        return 1;
    bool class_ok = strcmp(json_get_str(json_get(body, "classification")),
                           "header_only_import_body_position_unproven") == 0;
    if (!class_ok)
        return 1;
    return 0;
}

static int anchor_stale_snapshot_ok(const struct json_value *snap)
{
    int bad = anchor_expects_match(snap, k_snap_flags,
                                   sizeof k_snap_flags / sizeof k_snap_flags[0]);
    if (bad != 0)
        return bad;
    const char *payload_sha3 = json_get_str(
        json_get(snap, "snapshot_payload_sha3"));
    bool hex_ok = payload_sha3 && strlen(payload_sha3) == 64;
    if (!hex_ok)
        return 1;
    const struct json_value *snapshot_eta = json_get(snap, "eta");
    bool eta_ok = snapshot_eta &&
        json_get_bool(json_get(snapshot_eta, "available"));
    if (!eta_ok)
        return 1;
    return anchor_stale_preflight_ok(snap);
}

static int anchor_recent_ok(const struct json_value *result)
{
    if (result->type != JSON_OBJ)
        return 1;
    int bad = anchor_expects_match(result, k_recent_status,
                                   sizeof k_recent_status /
                                   sizeof k_recent_status[0]);
    if (bad != 0)
        return bad;
    const struct json_value *age = json_get(result, "progress_age_seconds");
    bool age_ok = age != NULL && json_get_int(age) >= 0 &&
                  json_get_int(age) <= 300;
    if (!age_ok)
        return 1;
    bad = anchor_expects_match(result, k_recent_tail,
                               sizeof k_recent_tail / sizeof k_recent_tail[0]);
    if (bad != 0)
        return bad;
    return anchor_child_matches(result, "utxo_apply_probe", k_recent_probe,
                                sizeof k_recent_probe /
                                sizeof k_recent_probe[0],
                                ANCHOR_OBJ_TYPED);
}

static int anchor_age_window_ok(const struct json_value *result,
                                const struct anchor_expect *head, size_t n_head,
                                const char *age_key, int64_t lo, int64_t hi,
                                const struct anchor_expect *tail, size_t n_tail)
{
    int bad = anchor_expects_match(result, head, n_head);
    if (bad != 0)
        return bad;
    int64_t age = json_get_int(json_get(result, age_key));
    bool age_ok = age >= lo && age <= hi;
    if (!age_ok)
        return 1;
    return anchor_expects_match(result, tail, n_tail);
}

static int anchor_watchdog_ok(const struct json_value *result)
{
    if (result->type != JSON_OBJ)
        return 1;
    return anchor_expects_match(result, k_watchdog,
                                sizeof k_watchdog / sizeof k_watchdog[0]);
}

static int anchor_case_syncdiag_json(void)
{
    printf("rpc_getsyncdiag: returns valid JSON without abort "
           "(RED)... ");
    dirty_stack_region();

    struct rpc_table tbl;
    rpc_table_init(&tbl);
    rpc_health_set_state(NULL, NULL, NULL, NULL);
    register_health_rpc_commands(&tbl);
    sync_monitor_init();
    sync_monitor_record_snapshot_resnapshot(
        100, 110, 4, 101, 111,
        "block_failed_mask_exhausted",
        "condition:tip_wedged_resnapshot");
    if (rpc_is_in_warmup(NULL, 0))
        set_rpc_warmup_finished();

    struct json_value params;
    json_init(&params);
    json_set_array(&params);

    struct json_value result;
    json_init(&result);

    bool executed = rpc_table_execute(&tbl, "getsyncdiag", &params, &result);
    bool ok = executed && anchor_syncdiag_ok(&result) == 0;

    json_free(&params);
    json_free(&result);
    return anchor_case_report(ok);
}

static int anchor_case_stale_backlog(void)
{
    printf("anchorstatus: names stale anchor mint UTXO backlog blocker "
           "(RED)... ");
    checkpoints_reset_sha3_override_for_test();
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "syncdiag_anchorstatus", "backlog");
    bool ok = syncdiag_seed_anchorstatus_progress(dir);
    ok = ok && syncdiag_set_progress_mtime_seconds_ago(dir, 3600);

    struct json_value params;
    json_init(&params);
    json_set_array(&params);
    struct json_value arg;
    json_init(&arg);
    json_set_str(&arg, dir);
    json_push_back(&params, &arg);
    json_free(&arg);

    struct json_value result;
    json_init(&result);
    ok = ok && rpc_agent_anchor_status(&params, false, &result);
    ok = ok && anchor_stale_result_ok(&result) == 0;

    /* Add a valid empty-body USS fixture so the existing typed offline
     * anchorstatus command proves it reports a digest only after the
     * read-only loader verifies the payload. */
    ok = ok && syncdiag_write_empty_anchor_snapshot(dir);
    ok = ok && syncdiag_seed_body_position_hazard(dir);
    struct json_value snapshot_result;
    json_init(&snapshot_result);
    ok = ok && rpc_agent_anchor_status(&params, false, &snapshot_result);
    ok = ok && anchor_stale_snapshot_ok(&snapshot_result) == 0;

    json_free(&snapshot_result);
    json_free(&params);
    json_free(&result);
    test_cleanup_tmpdir(dir);
    return anchor_case_report(ok);
}

static int anchor_case_recent_active(void)
{
    printf("anchorstatus: treats recent anchor mint backlog as active "
           "(RED)... ");
    checkpoints_reset_sha3_override_for_test();
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "syncdiag_anchorstatus", "active");
    bool ok = syncdiag_seed_anchorstatus_progress(dir);

    struct json_value params;
    json_init(&params);
    json_set_array(&params);
    struct json_value arg;
    json_init(&arg);
    json_set_str(&arg, dir);
    json_push_back(&params, &arg);
    json_free(&arg);

    struct json_value result;
    json_init(&result);
    ok = ok && rpc_agent_anchor_status(&params, false, &result);
    ok = ok && anchor_recent_ok(&result) == 0;

    json_free(&params);
    json_free(&result);
    test_cleanup_tmpdir(dir);
    return anchor_case_report(ok);
}

static int anchor_case_wal_activity(void)
{
    printf("anchorstatus: treats a fresh WAL as producer activity "
           "(RED)... ");
    checkpoints_reset_sha3_override_for_test();
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "syncdiag_anchorstatus", "wal_active");
    bool ok = syncdiag_seed_anchorstatus_progress(dir);
    sqlite3 *wal_db = NULL;
    ok = ok && syncdiag_open_fresh_progress_wal(dir, &wal_db);
    ok = ok && syncdiag_set_progress_mtime_seconds_ago(dir, 3600);

    struct json_value params;
    json_init(&params);
    json_set_array(&params);
    struct json_value arg;
    json_init(&arg);
    json_set_str(&arg, dir);
    json_push_back(&params, &arg);
    json_free(&arg);

    struct json_value result;
    json_init(&result);
    ok = ok && rpc_agent_anchor_status(&params, false, &result);
    ok = ok && anchor_age_window_ok(
        &result, k_wal_head, sizeof k_wal_head / sizeof k_wal_head[0],
        "progress_wal_age_seconds", 0, 30,
        k_wal_tail, sizeof k_wal_tail / sizeof k_wal_tail[0]) == 0;

    json_free(&params);
    json_free(&result);
    sqlite3_close(wal_db);
    test_cleanup_tmpdir(dir);
    return anchor_case_report(ok);
}

static int anchor_case_sample_cadence(void)
{
    printf("anchorstatus: honors durable sample cadence beyond 300 seconds "
           "(RED)... ");
    checkpoints_reset_sha3_override_for_test();
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "syncdiag_anchorstatus",
                     "cadence_active");
    bool ok = syncdiag_seed_anchorstatus_progress(dir);
    ok = ok && syncdiag_set_utxo_sample_ages(dir, 800, 200);
    ok = ok && syncdiag_set_progress_mtime_seconds_ago(dir, 3600);

    struct json_value params;
    json_init(&params);
    json_set_array(&params);
    struct json_value arg;
    json_init(&arg);
    json_set_str(&arg, dir);
    json_push_back(&params, &arg);
    json_free(&arg);

    struct json_value result;
    json_init(&result);
    ok = ok && rpc_agent_anchor_status(&params, false, &result);
    ok = ok && anchor_age_window_ok(
        &result, k_cadence_head,
        sizeof k_cadence_head / sizeof k_cadence_head[0],
        "progress_activity_age_seconds", 190, 240,
        k_cadence_tail,
        sizeof k_cadence_tail / sizeof k_cadence_tail[0]) == 0;

    json_free(&params);
    json_free(&result);
    test_cleanup_tmpdir(dir);
    return anchor_case_report(ok);
}

static int anchor_case_syncwatchdog(void)
{
    printf("getsyncwatchdog: exposes last recovery context "
           "(RED)... ");
    struct rpc_table tbl;
    rpc_table_init(&tbl);
    register_health_rpc_commands(&tbl);
    sync_monitor_init();
    sync_monitor_record_snapshot_resnapshot(
        120, 130, 2, 121, 131,
        "local_import_exhausted",
        "condition:tip_wedged_resnapshot");
    if (rpc_is_in_warmup(NULL, 0))
        set_rpc_warmup_finished();

    struct json_value params;
    json_init(&params);
    json_set_array(&params);

    struct json_value result;
    json_init(&result);

    bool ok = rpc_table_execute(&tbl, "getsyncwatchdog", &params, &result);
    ok = ok && anchor_watchdog_ok(&result) == 0;

    json_free(&params);
    json_free(&result);
    return anchor_case_report(ok);
}

static int anchor_case_http_envelope(void)
{
    printf("rpc_http response envelope: dirty stack still builds JSON "
           "(RED)... ");
    dirty_stack_region();

    struct json_value result;
    json_init(&result);
    json_set_object(&result);
    json_push_kv_str(&result, "watchdog", "ok");

    struct json_value id;
    json_init(&id);
    json_set_int(&id, 1);

    struct json_value response;
    bool ok = rpc_http_test_build_response_envelope(
        true, "getsyncdiag", &result, &id, &response);

    ok = ok && response.type == JSON_OBJ;
    ok = ok && json_get(&response, "result") != NULL;
    ok = ok && json_get(&response, "error") != NULL;
    ok = ok && json_get(&response, "id") != NULL;

    json_free(&result);
    json_free(&id);
    json_free(&response);
    return anchor_case_report(ok);
}

int syncdiag_cases_anchorstatus(void)
{
    int failures = 0;

    failures += anchor_case_syncdiag_json();

    failures += anchor_case_stale_backlog();

    failures += anchor_case_recent_active();

    failures += anchor_case_wal_activity();

    failures += anchor_case_sample_cadence();

    failures += anchor_case_syncwatchdog();

    failures += anchor_case_http_envelope();

    failures += anchor_case_missing_progress();
    failures += anchor_case_path_too_long();
    failures += anchor_case_unreadable_store();
    failures += anchor_case_applied_height(
        "zero", "UPDATE progress_meta SET value=zeroblob(8) "
                "WHERE key='coins_applied_height'", 0, -1);
    failures += anchor_case_applied_height(
        "absent", "DELETE FROM progress_meta "
                  "WHERE key='coins_applied_height'", -1, -1);

    return failures;
}
