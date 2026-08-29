/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Discovery-outcome observability for config/src/boot_bundle_fetch.c's
 * bbf_discover_from_peers() — split into its own file to keep
 * boot_bundle_fetch.c near the E1 800-line file-size target
 * (tools/file_size_policy.c). See config/boot_bundle_fetch.h
 * for the public dump-function contract and CLAUDE.md "Adding state
 * introspection" for the convention this follows.
 *
 * bbf_discover_from_peers() previously only LOGGED its quorum outcome;
 * nothing durable recorded which of the three shapes ("reached" |
 * "degraded_single_seed" | "no_quorum_fell_open_to_ibd") a given boot landed
 * in. bbf_record_discovery_outcome() persists that + peer/response counts as
 * three small progress.kv keys (text + two int64 counts, same idiom as
 * controllers/sovereignty_controller.c's t_ready/t_sovereign stamps);
 * boot_bundle_fetch_discovery_dump_state_json() (registered as the
 * "bbf_discovery" diagnostics dumper, app/controllers/src/diagnostics_
 * registry.c) reads them back. Observability-only: nothing here reads this
 * back to gate any boot decision, and a persist failure never affects the
 * decision already made. */

#include "config/boot_bundle_fetch.h"

#include "json/json.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define BBF_SUBSYS "boot_bundle_fetch"

#define BBF_DISCOVERY_OUTCOME_KEY           "bbf.discovery_outcome"
#define BBF_DISCOVERY_SEED_COUNT_KEY        "bbf.discovery_seed_count"
#define BBF_DISCOVERY_RESPONDED_COUNT_KEY   "bbf.discovery_responded_count"

/* `outcome_name` is one of "reached" | "degraded_single_seed" |
 * "no_quorum_fell_open_to_ibd". `seed_count` is how many seeds this boot
 * assembled (bbf_assemble_seeds); `responded_count` is how many of those
 * actually returned a directory listing (rom_fetch_get_directory), whether
 * or not their manifest turned out usable. Called from bbf_discover_from_
 * peers() in boot_bundle_fetch.c (forward-declared there — same module,
 * split for line-count only). */
void bbf_record_discovery_outcome(const char *outcome_name,
                                  size_t seed_count, size_t responded_count)
{
    sqlite3 *pdb = progress_store_db();
    if (!pdb || !outcome_name)
        return;
    int64_t seeds = (int64_t)seed_count;
    int64_t responded = (int64_t)responded_count;

    progress_store_tx_lock();
    bool ok = progress_meta_set(pdb, BBF_DISCOVERY_OUTCOME_KEY, outcome_name,
                                strlen(outcome_name)) &&
        progress_meta_set(pdb, BBF_DISCOVERY_SEED_COUNT_KEY, &seeds,
                          sizeof(seeds)) &&
        progress_meta_set(pdb, BBF_DISCOVERY_RESPONDED_COUNT_KEY, &responded,
                          sizeof(responded));
    progress_store_tx_unlock();
    if (!ok)
        LOG_WARN(BBF_SUBSYS, "discovery: outcome persist failed "
                 "(observability-only, does not affect this boot's decision)");
}

/* `z23 dumpstate bbf_discovery`. SELECT-only peek at the outcome
 * bbf_record_discovery_outcome above last persisted; absent (never run this
 * boot, or a fresh datadir) reports outcome_recorded=false rather than a
 * fabricated zero/"none". `key` unused (NULL-safe). See CLAUDE.md "Adding
 * state introspection". Reentrant-safe. */
bool boot_bundle_fetch_discovery_dump_state_json(struct json_value *out,
                                                 const char *key)
{
    (void)key;
    if (!out)
        return false;
    json_set_object(out);

    sqlite3 *pdb = progress_store_db();
    bool progress_open = pdb != NULL;
    json_push_kv_bool(out, "progress_store_open", progress_open);

    char outcome[40] = {0};
    size_t outcome_len = 0;
    bool outcome_found = false;
    int64_t seed_count = 0, responded_count = 0;
    bool seed_found = false, responded_found = false;

    if (progress_open) {
        progress_store_tx_lock();
        (void)progress_meta_get(pdb, BBF_DISCOVERY_OUTCOME_KEY, outcome,
                                sizeof(outcome) - 1, &outcome_len,
                                &outcome_found);
        (void)progress_meta_get_blob_exact(pdb, BBF_DISCOVERY_SEED_COUNT_KEY,
                                           &seed_count, sizeof(seed_count),
                                           NULL, &seed_found);
        (void)progress_meta_get_blob_exact(pdb,
                                           BBF_DISCOVERY_RESPONDED_COUNT_KEY,
                                           &responded_count,
                                           sizeof(responded_count), NULL,
                                           &responded_found);
        progress_store_tx_unlock();
        if (outcome_found) {
            size_t copy = outcome_len < sizeof(outcome) - 1
                              ? outcome_len : sizeof(outcome) - 1;
            outcome[copy] = '\0';
        }
    }

    json_push_kv_bool(out, "outcome_recorded", outcome_found);
    json_push_kv_str(out, "outcome", outcome_found ? outcome : "none");
    json_push_kv_int(out, "seed_count", seed_found ? seed_count : -1);
    json_push_kv_int(out, "responded_count",
                     responded_found ? responded_count : -1);
    return true;
}
