/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Read-only snapshot/durable-ETA helpers for agent_anchor_status_controller. */

#include "controllers/agent_cure_status_helpers.h"

#include "chain/checkpoints.h"
#include "chain/utxo_snapshot_loader.h"
#include "json/json.h"
#include "storage/cure_progress_read.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

enum {
    CURE_PROGRESS_RECENT_SECS = 300,
    CURE_PROGRESS_MAX_STALE_SECS = 86400,
};

struct agent_cure_activity_view {
    bool wal_present;
    bool recent;
    int64_t wal_size;
    int64_t wal_mtime;
    int64_t wal_age_seconds;
    int64_t activity_mtime;
    int64_t activity_age_seconds;
    int64_t sample_interval_seconds;
    int64_t stale_after_seconds;
    const char *activity_source;
    char wal_path[1200];
};

bool agent_cure_stat_file(const char *path, int64_t *size_out,
                          int64_t *mtime_out)
{
    if (size_out)
        *size_out = 0;
    if (mtime_out)
        *mtime_out = 0;
    if (!path || !path[0])
        return false;
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return false;
    if (size_out)
        *size_out = (int64_t)st.st_size;
    if (mtime_out)
        *mtime_out = (int64_t)st.st_mtime;
    return true;
}

bool agent_cure_path_join(char *out, size_t cap, const char *datadir,
                          const char *name)
{
    if (!out || cap == 0)
        return false;
    int n = snprintf(out, cap, "%s/%s",
                     datadir && datadir[0] ? datadir : ".", name);
    return n >= 0 && (size_t)n < cap;
}

int64_t agent_cure_progress_age_seconds(bool progress_present,
                                        int64_t captured_at_unix,
                                        int64_t progress_mtime)
{
    if (!progress_present || captured_at_unix <= 0 || progress_mtime <= 0)
        return -1; // raw-return-ok:anchorstatus-progress-age-missing-sentinel
    if (progress_mtime > captured_at_unix)
        return 0;
    return captured_at_unix - progress_mtime;
}

/* A4: the kernel store is consensus.db post-flip (or the legacy progress.kv on a
 * pre-flip datadir). Report the actual file the activity mtime came from rather
 * than a hardcoded name, so the diagnostic never claims progress.kv for a
 * consensus.db read. The returned pointer aliases `path`, which the caller keeps
 * live through the JSON emit. */
static const char *cure_kernel_store_basename(const char *path)
{
    if (!path || !path[0])
        return "kernel-store";
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static void agent_cure_activity_build(
    const char *progress_path, bool progress_present, int64_t progress_mtime,
    int64_t captured_at_unix, const struct agent_cure_eta_view *eta,
    struct agent_cure_activity_view *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    out->wal_age_seconds = -1;
    out->activity_mtime = progress_mtime;
    out->activity_age_seconds = -1;
    out->sample_interval_seconds = -1;
    out->stale_after_seconds = CURE_PROGRESS_RECENT_SECS;
    out->activity_source =
        progress_present ? cure_kernel_store_basename(progress_path)
                         : "unavailable";

    int n = snprintf(out->wal_path, sizeof(out->wal_path), "%s-wal",
                     progress_path ? progress_path : "");
    if (n >= 0 && (size_t)n < sizeof(out->wal_path)) {
        out->wal_present = agent_cure_stat_file(
            out->wal_path, &out->wal_size, &out->wal_mtime);
        out->wal_age_seconds = agent_cure_progress_age_seconds(
            out->wal_present, captured_at_unix, out->wal_mtime);
        if (out->wal_present && out->wal_mtime > out->activity_mtime) {
            out->activity_mtime = out->wal_mtime;
            out->activity_source = cure_kernel_store_basename(out->wal_path);
        }
    } else {
        out->wal_path[0] = '\0';
    }

    if (eta && eta->available && eta->newer_time > eta->older_time) {
        int64_t interval = eta->newer_time - eta->older_time;
        out->sample_interval_seconds = interval;
        int64_t cadence_budget = interval > CURE_PROGRESS_MAX_STALE_SECS / 2
            ? CURE_PROGRESS_MAX_STALE_SECS : interval * 2;
        if (cadence_budget > out->stale_after_seconds)
            out->stale_after_seconds = cadence_budget;
        if (eta->newer_time > out->activity_mtime &&
            eta->newer_time <= captured_at_unix) {
            out->activity_mtime = eta->newer_time;
            out->activity_source = "durable_utxo_apply_sample";
        }
    }

    out->activity_age_seconds = agent_cure_progress_age_seconds(
        progress_present, captured_at_unix, out->activity_mtime);
    out->recent = progress_present && out->activity_age_seconds >= 0 &&
        out->activity_age_seconds <= out->stale_after_seconds;
}

bool agent_cure_push_activity_json(
    struct json_value *result, const char *progress_path,
    bool progress_present, int64_t progress_mtime, int64_t captured_at_unix,
    const struct agent_cure_eta_view *eta)
{
    if (!result)
        return false;
    struct agent_cure_activity_view activity;
    agent_cure_activity_build(progress_path, progress_present, progress_mtime,
                              captured_at_unix, eta, &activity);
    const struct agent_cure_activity_view *a = &activity;
    json_push_kv_str(result, "progress_wal_path", a->wal_path);
    json_push_kv_bool(result, "progress_wal_present", a->wal_present);
    json_push_kv_int(result, "progress_wal_size_bytes", a->wal_size);
    json_push_kv_int(result, "progress_wal_mtime_unix", a->wal_mtime);
    json_push_kv_int(result, "progress_wal_age_seconds", a->wal_age_seconds);
    json_push_kv_int(result, "progress_activity_mtime_unix",
                     a->activity_mtime);
    json_push_kv_int(result, "progress_activity_age_seconds",
                     a->activity_age_seconds);
    json_push_kv_str(result, "progress_activity_source", a->activity_source);
    json_push_kv_int(result, "progress_sample_interval_seconds",
                     a->sample_interval_seconds);
    json_push_kv_int(result, "progress_stale_after_seconds",
                     a->stale_after_seconds);
    json_push_kv_bool(result, "progress_recent", a->recent);
    return a->recent;
}

static void cure_hex32(const uint8_t in[32], char out[65])
{
    if (!out)
        return;
    for (int i = 0; i < 32; i++)
        (void)snprintf(out + 2 * i, 3, "%02x", in ? in[i] : 0);
}

void agent_cure_snapshot_inspect(
    const char *path, const struct sha3_utxo_checkpoint *cp,
    struct agent_cure_snapshot_view *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    if (!path || !path[0]) {
        (void)snprintf(out->error, sizeof(out->error), "snapshot path missing");
        return;
    }

    struct uss_header hdr;
    memset(&hdr, 0, sizeof(hdr));
    struct uss_handle *peek = uss_open(path, false, NULL, &hdr,
                                       out->error, sizeof(out->error));
    if (!peek)
        return;
    out->header_readable = true;
    out->version = uss_version(peek);
    out->height = hdr.height;
    out->count = hdr.count;
    out->total_supply = hdr.total_supply;
    cure_hex32(hdr.sha3_hash, out->payload_sha3);
    out->checkpoint_sha3_match =
        cp && memcmp(hdr.sha3_hash, cp->sha3_hash, 32) == 0;
    uss_close(peek);

    out->error[0] = '\0';
    struct uss_handle *verified = uss_open(path, true, NULL, NULL,
                                           out->error, sizeof(out->error));
    if (verified) {
        out->payload_sha3_verified = true;
        uss_close(verified);
    }
}

void agent_cure_push_snapshot_json(
    struct json_value *result, const struct agent_cure_snapshot_view *s)
{
    if (!result || !s)
        return;
    json_push_kv_bool(result, "snapshot_header_readable", s->header_readable);
    json_push_kv_bool(result, "snapshot_payload_sha3_verified",
                      s->payload_sha3_verified);
    json_push_kv_bool(result, "snapshot_checkpoint_sha3_match",
                      s->checkpoint_sha3_match);
    json_push_kv_int(result, "snapshot_version", s->version);
    json_push_kv_int(result, "snapshot_height", s->height);
    json_push_kv_int(result, "snapshot_utxo_count", (int64_t)s->count);
    json_push_kv_int(result, "snapshot_total_supply", s->total_supply);
    json_push_kv_str(result, "snapshot_payload_sha3", s->payload_sha3);
    json_push_kv_str(result, "snapshot_digest_source",
                     s->payload_sha3_verified
                         ? "uss_verified_payload_sha3"
                         : s->header_readable
                             ? "uss_header_claim_unverified"
                             : "unavailable");
    if (s->error[0])
        json_push_kv_str(result, "snapshot_error", s->error);
}

void agent_cure_eta_build(sqlite3 *db, int64_t target_height,
                          struct agent_cure_eta_view *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    out->older_height = -1;
    out->older_time = -1;
    out->newer_height = -1;
    out->newer_time = -1;
    out->eta_seconds = -1;
    out->reason = "durable_samples_unavailable";
    if (!db || target_height < 0)
        return;

    struct cure_progress_sample older, newer;
    int samples = cure_progress_read_eta_samples(db, 60, &older, &newer);
    if (samples <= 0) {
        if (samples == 0)
            out->reason = "durable_sample_window_under_60_seconds";
        return;
    }
    out->older_height = older.height;
    out->older_time = older.time_unix;
    out->newer_height = newer.height;
    out->newer_time = newer.time_unix;

    int64_t blocks = out->newer_height - out->older_height;
    int64_t seconds = out->newer_time - out->older_time;
    int64_t remaining = target_height > out->newer_height
        ? target_height - out->newer_height : 0;
    if (blocks <= 0 || seconds < 60) {
        out->reason = "durable_samples_non_monotonic";
        return;
    }
    out->blocks_per_second_milli = (blocks * 1000) / seconds;
    out->eta_seconds = remaining == 0
        ? 0 : (remaining * seconds + blocks - 1) / blocks;
    out->available = true;
    out->reason = "durable_utxo_apply_samples";
}

void agent_cure_push_eta_json(struct json_value *result,
                              const struct agent_cure_eta_view *eta)
{
    struct json_value obj;
    json_init(&obj);
    json_set_object(&obj);
    json_push_kv_bool(&obj, "available", eta && eta->available);
    json_push_kv_str(&obj, "source",
                     "consensus.db:utxo_apply_log.applied_at");
    json_push_kv_str(&obj, "reason", eta && eta->reason
        ? eta->reason : "durable_samples_unavailable");
    json_push_kv_int(&obj, "older_height", eta ? eta->older_height : -1);
    json_push_kv_int(&obj, "older_time_unix", eta ? eta->older_time : -1);
    json_push_kv_int(&obj, "newer_height", eta ? eta->newer_height : -1);
    json_push_kv_int(&obj, "newer_time_unix", eta ? eta->newer_time : -1);
    json_push_kv_int(&obj, "blocks_per_second_milli",
                     eta ? eta->blocks_per_second_milli : 0);
    json_push_kv_int(&obj, "eta_seconds", eta ? eta->eta_seconds : -1);
    json_push_kv(result, "eta", &obj);
    json_free(&obj);
}

void agent_cure_push_import_preflight_json(
    struct json_value *result, sqlite3 *db, const char *datadir,
    int64_t header_cursor, int64_t body_fetch_cursor,
    int64_t body_persist_cursor)
{
    if (!result)
        return;
    bool row_present = false;
    char source[64] = {0};
    if (db && body_persist_cursor >= 0) {
        struct cure_body_persist_row row;
        int found = cure_progress_read_body_persist(
            db, body_persist_cursor, &row);
        row_present = found == 1;
        if (row_present)
            (void)snprintf(source, sizeof(source), "%s", row.source);
    }

    bool header_only_shape = header_cursor >= 1000 && body_persist_cursor <= 1;
    bool body_gap = body_fetch_cursor > body_persist_cursor && !row_present;
    bool suspected = header_only_shape && body_gap;
    char node_db[1200];
    int n = snprintf(node_db, sizeof(node_db), "%s/node.db",
                     datadir && datadir[0] ? datadir : "$MINTDIR");
    if (n < 0 || (size_t)n >= sizeof(node_db))
        (void)snprintf(node_db, sizeof(node_db), "$MINTDIR/node.db");

    struct json_value argv;
    json_init(&argv);
    json_set_array(&argv);
    const char *args[] = {
        "BIN", "--importblockindex", "$HOME/.zclassic", node_db,
    };
    for (size_t i = 0; i < sizeof(args) / sizeof(args[0]); i++) {
        struct json_value item;
        json_init(&item);
        json_set_str(&item, args[i]);
        json_push_back(&argv, &item);
        json_free(&item);
    }

    struct json_value prep;
    json_init(&prep);
    json_set_object(&prep);
    json_push_kv_str(&prep, "exact_template",
                     "BIN --importblockindex \"$HOME/.zclassic\" \"$MINTDIR/node.db\"");
    json_push_kv(&prep, "argv", &argv);
    /* --importblockindex is now scanned ANYWHERE in argv (engine/entry/main.c
     * main()), so it no longer needs to be the literal argv[1]. Kept
     * `false` (not removed) so an older/rolled-back binary's agent
     * guidance still reads unambiguously either way. */
    json_push_kv_bool(&prep, "importblockindex_must_be_argv1", false);
    json_push_kv_str(&prep, "wrong_order_effect",
                     "none — --importblockindex is dispatched from any argv "
                     "position; a missing or nonexistent source datadir "
                     "REFUSES loudly (exit 1) instead of falling through to "
                     "a normal boot");
    json_push_kv_str(&prep, "body_corpus_rule",
                     "block_index positions must be paired with the exact source blk*.dat corpus; matching filenames are not proof");
    json_push_kv(result, "producer_import_preflight", &prep);
    json_free(&prep);
    json_free(&argv);

    struct json_value body;
    json_init(&body);
    json_set_object(&body);
    json_push_kv_bool(&body, "suspected", suspected);
    json_push_kv_int(&body, "height", body_persist_cursor);
    json_push_kv_bool(&body, "durable_body_row_present", row_present);
    json_push_kv_str(&body, "durable_body_source", source);
    json_push_kv_str(&body, "classification",
                     suspected ? "header_only_import_body_position_unproven"
                               : "not_proven_by_offline_cursor_shape");
    json_push_kv_str(&body, "next_action",
                     suspected
                         ? "rebuild_and_copy_prove_the_isolated_producer_input; do_not_repair_a_serving_datadir"
                         : "continue_observing_durable_stage_progress");
    json_push_kv(result, "body_position_preflight", &body);
    json_free(&body);
}
