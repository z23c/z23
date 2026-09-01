/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * agent_cure_status_helpers — render read-only sovereign-cure status facts. */

#ifndef ZCL_CONTROLLERS_AGENT_CURE_STATUS_HELPERS_H
#define ZCL_CONTROLLERS_AGENT_CURE_STATUS_HELPERS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct json_value;
struct sha3_utxo_checkpoint;
struct sqlite3;

struct agent_cure_eta_view {
    bool available;
    int64_t older_height;
    int64_t older_time;
    int64_t newer_height;
    int64_t newer_time;
    int64_t blocks_per_second_milli;
    int64_t eta_seconds;
    const char *reason;
};

struct agent_cure_snapshot_view {
    bool header_readable;
    bool payload_sha3_verified;
    bool checkpoint_sha3_match;
    uint32_t version;
    uint32_t height;
    uint64_t count;
    int64_t total_supply;
    char payload_sha3[65];
    char error[256];
};

/* Read-only helpers for the offline sovereign-cure status controller. */
bool agent_cure_stat_file(const char *path, int64_t *size_out,
                          int64_t *mtime_out);
bool agent_cure_path_join(char *out, size_t cap, const char *datadir,
                          const char *name);
int64_t agent_cure_progress_age_seconds(bool progress_present,
                                        int64_t captured_at_unix,
                                        int64_t progress_mtime);
bool agent_cure_push_activity_json(
    struct json_value *result, const char *progress_path,
    bool progress_present, int64_t progress_mtime, int64_t captured_at_unix,
    const struct agent_cure_eta_view *eta);
void agent_cure_snapshot_inspect(
    const char *path, const struct sha3_utxo_checkpoint *checkpoint,
    struct agent_cure_snapshot_view *out);
void agent_cure_push_snapshot_json(
    struct json_value *result, const struct agent_cure_snapshot_view *snapshot);
void agent_cure_eta_build(struct sqlite3 *db, int64_t target_height,
                          struct agent_cure_eta_view *out);
void agent_cure_push_eta_json(struct json_value *result,
                              const struct agent_cure_eta_view *eta);
void agent_cure_push_import_preflight_json(
    struct json_value *result, struct sqlite3 *db, const char *datadir,
    int64_t header_admit_cursor, int64_t body_fetch_cursor,
    int64_t body_persist_cursor);

#endif /* ZCL_CONTROLLERS_AGENT_CURE_STATUS_HELPERS_H */
