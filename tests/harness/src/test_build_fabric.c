/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Prove the build-fabric v42 schema, leases, and relationships. */

#include "test/test_core.h"
#include "test/accepted_work_fixture.h"
#include "test/build_release_regression_fixture.h"

#include "models/build_fabric.h"
#include "models/build_proof_event.h"
#include "models/database.h"
#include "services/build_fabric_service.h"
#include "services/build_fabric_async.h"
#include "services/build_fabric_runtime.h"
#include "services/subordinate_work_admission.h"
#include "services/build_fabric_worker.h"
#include "services/build_fabric_worker_evidence.h"
#include "config/db_service.h"
#include "config/runtime.h"
#include "base/hex.h"
#include "crypto/ed25519.h"
#include "platform/time_compat.h"
#include "command/native_command.h"
#include "controllers/api_controller.h"
#include "json/json.h"
#include "vcs/build_action.h"
#include "vcs/build_artifact_manifest.h"
#include "vcs/build_execution_observation.h"
#include "vcs/build_release_qualification.h"
#include "vcs/build_release_regressions.h"
#include "vcs/package_store.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_dev.h"
#include "crypto/sha3.h"
#include "sha3/sha3.h"
#include "util/safe_alloc.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static const char id_a[] =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char id_b[] =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static const char id_c[] =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
static const char id_d[] =
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

static bool bf_open(struct node_db *ndb, char *dir, size_t dir_cap,
                    char *path, size_t path_cap, const char *tag)
{
    test_make_tmpdir(dir, dir_cap, "build_fabric", tag);
    (void)snprintf(path, path_cap, "%s/node.db", dir);
    memset(ndb, 0, sizeof(*ndb));
    return node_db_open(ndb, path);
}

static void bf_job(struct db_build_job *row)
{
    memset(row, 0, sizeof(*row));
    (void)snprintf(row->job_id, sizeof(row->job_id), "%s", id_a);
    (void)snprintf(row->source_sha256, sizeof(row->source_sha256), "%s", id_b);
    (void)snprintf(row->source_cas_sha3, sizeof(row->source_cas_sha3), "%s", id_c);
    (void)snprintf(row->toolchain_sha3, sizeof(row->toolchain_sha3), "%s", id_d);
    (void)snprintf(row->profile, sizeof(row->profile), "dev-x86-64-v3");
    (void)snprintf(row->state, sizeof(row->state), "PLANNED");
    row->created_at = 100;
    row->updated_at = 100;
}

static void bf_action(struct db_build_action *row)
{
    memset(row, 0, sizeof(*row));
    (void)snprintf(row->action_id, sizeof(row->action_id), "%s", id_b);
    (void)snprintf(row->job_id, sizeof(row->job_id), "%s", id_a);
    row->sequence = 0;
    (void)snprintf(row->kind, sizeof(row->kind),
                   "c23.compile.preprocessed.v1");
    (void)snprintf(row->state, sizeof(row->state), "SNAPSHOTTED");
    (void)snprintf(row->input_root_sha3, sizeof(row->input_root_sha3), "%s",
                   id_c);
    (void)snprintf(row->target, sizeof(row->target), "%s",
                   VCS_BUILD_TARGET_V1);
    uint8_t fixed_flags[32], fixed_environment[32];
    vcs_build_action_v1_fixed_flags_root(fixed_flags);
    vcs_build_action_v1_fixed_environment_root(fixed_environment);
    zcl_hex_encode(fixed_flags, 32, row->flags_sha3);
    zcl_hex_encode(fixed_environment, 32, row->environment_sha3);
    (void)snprintf(row->virtual_workdir, sizeof(row->virtual_workdir),
                   "/zbuild/src");
    (void)snprintf(row->declared_outputs, sizeof(row->declared_outputs),
                   "unit.o");
    (void)snprintf(row->resource_policy, sizeof(row->resource_policy), "%s",
                   VCS_BUILD_RESOURCE_POLICY_V1);
    row->created_at = 101;
    row->updated_at = 101;
}

static void bf_worker(struct db_build_worker *row)
{
    memset(row, 0, sizeof(*row));
    (void)snprintf(row->worker_id, sizeof(row->worker_id), "%s", id_c);
    (void)snprintf(row->signer_pubkey, sizeof(row->signer_pubkey), "%s", id_d);
    (void)snprintf(row->capabilities, sizeof(row->capabilities),
                   "linux,x86-64-v3,gcc,%s,%s", VCS_BUILD_ACTION_KIND_V1,
                   VCS_BUILD_ACTION_KIND_TEST_V1);
    row->approved = 1;
    row->approved_at = 102;
    row->last_seen_at = 102;
}

static void bf_worker_id_from_pubkey(const uint8_t pubkey[32], char out[65])
{
    static const char domain[] = "zcl.build_worker.v1";
    struct sha3_256_ctx sha;
    uint8_t digest[32];
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, pubkey, 32);
    sha3_256_finalize(&sha, digest);
    zcl_hex_encode(digest, 32, out);
}

static void bf_receipt(struct db_build_receipt *row)
{
    memset(row, 0, sizeof(*row));
    (void)snprintf(row->receipt_id, sizeof(row->receipt_id), "%s", id_d);
    (void)snprintf(row->action_id, sizeof(row->action_id), "%s", id_b);
    (void)snprintf(row->job_id, sizeof(row->job_id), "%s", id_a);
    (void)snprintf(row->worker_id, sizeof(row->worker_id), "%s", id_c);
    (void)snprintf(row->lease_id, sizeof(row->lease_id), "%s", id_d);
    (void)snprintf(row->action_sha3, sizeof(row->action_sha3), "%s", id_b);
    (void)snprintf(row->output_sha3, sizeof(row->output_sha3), "%s", id_c);
    memset(row->signature, 'e', BUILD_FABRIC_SIGNATURE_HEX);
    row->signature[BUILD_FABRIC_SIGNATURE_HEX] = '\0';
    (void)snprintf(row->confinement, sizeof(row->confinement),
                   "landlock=1,seccomp=1,network=0");
    (void)snprintf(row->trust_state, sizeof(row->trust_state),
                   "LOCAL_ACCEPTED");
    row->exit_status = 0;
    row->created_at = 103;
}

static bool bf_canonicalize(struct db_build_job *job,
                            struct db_build_action *action)
{
    char action_id[BUILD_FABRIC_ID_HEX + 1];
    char job_id[BUILD_FABRIC_ID_HEX + 1];
    if (!build_fabric_action_id(job, action, action_id).ok ||
        !build_fabric_job_id(job, action_id, job_id).ok)
        return false;
    (void)snprintf(action->action_id, sizeof(action->action_id), "%s",
                   action_id);
    (void)snprintf(job->job_id, sizeof(job->job_id), "%s", job_id);
    (void)snprintf(action->job_id, sizeof(action->job_id), "%s", job_id);
    return true;
}

static uint8_t *bf_read_fixture(const char *path, size_t *len_out)
{
    *len_out = 0;
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        st.st_size > 1024 * 1024)
        return NULL;
    uint8_t *bytes = zcl_malloc((size_t)st.st_size, "test.build_fixture");
    if (!bytes) return NULL;
    FILE *f = fopen(path, "rb");
    if (!f) { free(bytes); return NULL; }
    size_t got = fread(bytes, 1, (size_t)st.st_size, f);
    bool read_ok = got == (size_t)st.st_size && ferror(f) == 0;
    bool ok = fclose(f) == 0 && read_ok;
    if (!ok) { free(bytes); return NULL; }
    *len_out = got;
    return bytes;
}

static int test_bf_migration(void)
{
    int failures = 0;
    TEST("build_fabric: v45 migration creates worker trust and lane index") {
        struct node_db ndb;
        char dir[256], path[320];
        ASSERT(bf_open(&ndb, dir, sizeof(dir), path, sizeof(path), "migration"));
        ASSERT_EQ(node_db_schema_version(&ndb), NODE_DB_MAX_SCHEMA);
        sqlite3_stmt *st = NULL;
        ASSERT(sqlite3_prepare_v2(ndb.db,
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND "
            "name IN ('build_jobs','build_actions','build_workers',"
            "'build_receipts','build_proof_events')",
            -1, &st, NULL) == SQLITE_OK);
        ASSERT(sqlite3_step(st) == SQLITE_ROW); /* raw-sql-ok:test-readonly-count */
        ASSERT_EQ(sqlite3_column_int(st, 0), 5);
        sqlite3_finalize(st);
        ASSERT(sqlite3_prepare_v2(ndb.db,
            "SELECT count(*) FROM pragma_table_info('build_actions') WHERE "
            "name IN ('lease_id','lease_expires_at','lease_heartbeat_at',"
            "'attempt_count','claimed_at','started_at','finished_at')",
            -1, &st, NULL) == SQLITE_OK);
        ASSERT(sqlite3_step(st) == SQLITE_ROW); /* raw-sql-ok:test-readonly-count */
        ASSERT_EQ(sqlite3_column_int(st, 0), 7);
        sqlite3_finalize(st);
        ASSERT(sqlite3_prepare_v2(ndb.db,
            "SELECT count(*) FROM pragma_table_info('build_receipts') "
            "WHERE name IN ('lease_id','observation_sha3')", -1, &st,
            NULL) == SQLITE_OK);
        ASSERT(sqlite3_step(st) == SQLITE_ROW); /* raw-sql-ok:test-readonly-count */
        ASSERT_EQ(sqlite3_column_int(st, 0), 2);
        sqlite3_finalize(st);
        ASSERT(sqlite3_prepare_v2(ndb.db,
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND "
            "name='zcode_lane_receipts'", -1, &st, NULL) == SQLITE_OK);
        ASSERT(sqlite3_step(st) == SQLITE_ROW); /* raw-sql-ok:test-readonly-count */
        ASSERT_EQ(sqlite3_column_int(st, 0), 1);
        sqlite3_finalize(st);
        ASSERT(sqlite3_prepare_v2(ndb.db,
            "SELECT count(*) FROM sqlite_master WHERE type='index' AND "
            "name='idx_zcode_lane_source'", -1, &st, NULL) == SQLITE_OK);
        ASSERT(sqlite3_step(st) == SQLITE_ROW); /* raw-sql-ok:test-readonly-count */
        ASSERT_EQ(sqlite3_column_int(st, 0), 1);
        sqlite3_finalize(st);
        ASSERT(sqlite3_prepare_v2(ndb.db,
            "SELECT count(*) FROM pragma_table_info('build_receipts') "
            "WHERE name='trust_state'", -1, &st, NULL) == SQLITE_OK);
        ASSERT(sqlite3_step(st) == SQLITE_ROW); /* raw-sql-ok:test-readonly-count */
        ASSERT_EQ(sqlite3_column_int(st, 0), 1);
        sqlite3_finalize(st);
        node_db_close(&ndb);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bf_lifecycle(void)
{
    int failures = 0;
    TEST("build_fabric: AR lifecycle preserves indexed relationships") {
        struct node_db ndb;
        char dir[256], path[320];
        ASSERT(bf_open(&ndb, dir, sizeof(dir), path, sizeof(path), "lifecycle"));
        struct db_build_job job;
        struct db_build_action action;
        struct db_build_worker worker;
        struct db_build_receipt receipt;
        bf_job(&job);
        bf_action(&action);
        bf_worker(&worker);
        bf_receipt(&receipt);
        ASSERT(db_build_job_save(&ndb, &job));
        ASSERT(db_build_action_save(&ndb, &action));
        ASSERT(db_build_worker_save(&ndb, &worker));
        ASSERT(db_build_receipt_save(&ndb, &receipt));

        struct db_build_action actions[4];
        struct db_build_receipt receipts[4];
        struct db_build_worker workers[4];
        ASSERT_EQ(db_build_job_actions(&ndb, id_a, actions, 4), 1);
        ASSERT_STR_EQ(actions[0].action_id, id_b);
        ASSERT_EQ(db_build_job_receipts(&ndb, id_a, receipts, 4), 1);
        ASSERT_STR_EQ(receipts[0].worker_id, id_c);
        ASSERT_EQ(db_build_workers_list(&ndb, workers, 4), 1);
        ASSERT(workers[0].approved == 1 && workers[0].revoked == 0);

        /* Updating the parent is an UPSERT, not INSERT OR REPLACE: children
         * and receipts must survive the state transition. */
        (void)snprintf(job.state, sizeof(job.state), "QUEUED");
        job.updated_at = 104;
        ASSERT(db_build_job_save(&ndb, &job));
        ASSERT_EQ(db_build_job_actions(&ndb, id_a, actions, 4), 1);
        ASSERT_EQ(db_build_job_receipts(&ndb, id_a, receipts, 4), 1);

        (void)snprintf(action.state, sizeof(action.state), "ACCEPTED");
        (void)snprintf(action.outcome, sizeof(action.outcome), "ACCEPTED");
        (void)snprintf(action.output_root_sha3,
                       sizeof(action.output_root_sha3), "%s", id_d);
        (void)snprintf(action.worker_id, sizeof(action.worker_id), "%s", id_c);
        (void)snprintf(action.lease_id, sizeof(action.lease_id), "%s", id_b);
        action.lease_expires_at = 500;
        action.lease_heartbeat_at = 450;
        action.attempt_count = 2;
        action.claimed_at = 400;
        action.started_at = 410;
        action.finished_at = 490;
        action.updated_at = 105;
        ASSERT(db_build_action_save(&ndb, &action));
        ASSERT(db_build_action_find(&ndb, id_b, &action));
        ASSERT_STR_EQ(action.state, "ACCEPTED");
        ASSERT_STR_EQ(action.lease_id, id_b);
        ASSERT_EQ(action.attempt_count, 2);
        ASSERT_EQ(action.finished_at, 490);
        ASSERT_EQ(db_build_job_receipts(&ndb, id_a, receipts, 4), 1);
        node_db_close(&ndb);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bf_async_proof_events(void)
{
    int failures = 0;
    TEST("build_fabric: async proof events dedup and bind closed transitions") {
        struct node_db ndb;
        char dir[256], path[320];
        ASSERT(bf_open(&ndb, dir, sizeof(dir), path, sizeof(path), "async"));
        struct db_build_job job;
        struct db_build_action action;
        bf_job(&job); bf_action(&action);
        (void)snprintf(action.task_root_sha3,
                       sizeof(action.task_root_sha3), "%s", id_a);
        (void)snprintf(action.candidate_root_sha3,
                       sizeof(action.candidate_root_sha3), "%s", id_b);
        (void)snprintf(action.proof_policy_root_sha3,
                       sizeof(action.proof_policy_root_sha3), "%s", id_c);
        ASSERT(bf_canonicalize(&job, &action));
        ASSERT(build_fabric_plan(&ndb, &job, &action).ok);

        struct db_build_proof_event requested, duplicate, event;
        bool created = false;
        ASSERT(build_fabric_proof_request(
            &ndb, action.action_id, "/tmp/project", 0, 17, 1000,
            &requested, &created).ok);
        ASSERT(created);
        ASSERT_STR_EQ(requested.state, "REQUESTED");
        ASSERT_STR_EQ(requested.source_root_sha3, job.source_cas_sha3);
        ASSERT(requested.request_id ==
               build_fabric_proof_request_id(action.action_id));
        ASSERT(build_fabric_proof_request(
            &ndb, action.action_id, "/tmp/project", 99, 18, 2000,
            &duplicate, &created).ok);
        ASSERT(!created);
        ASSERT_STR_EQ(duplicate.event_root, requested.event_root);
        ASSERT(duplicate.request_id == requested.request_id);
        ASSERT(!build_fabric_proof_transition(
            &ndb, action.action_id, "RUNNING", 9, requested.request_id,
            id_d, NULL, 1100, 10, 1001, &event).ok);
        ASSERT(build_fabric_proof_transition(
            &ndb, action.action_id, "PEER_DISCOVERED", 9,
            requested.request_id, id_d, NULL, 1100, 10, 1001, &event).ok);
        ASSERT_STR_EQ(event.prior_event_root, requested.event_root);
        char checked[65];
        ASSERT(db_build_proof_event_root(&event, checked));
        ASSERT_STR_EQ(event.event_root, checked);
        struct db_build_proof_event forked = event;
        forked.peer_id++;
        ASSERT(db_build_proof_event_root(&forked, forked.event_root));
        ASSERT(!db_build_proof_event_save(&ndb, &forked));
        struct db_build_proof_event tampered = event;
        tampered.peer_id++;
        struct ar_errors event_errors;
        ASSERT(!db_build_proof_event_validate(&tampered, &event_errors));
        ASSERT(build_fabric_proof_transition(
            &ndb, action.action_id, "CONTEXT_READY", 9,
            requested.request_id, NULL, NULL, 0, 15, 1002, &event).ok);
        ASSERT_STR_EQ(event.source_root_sha3, job.source_cas_sha3);
        ASSERT(build_fabric_proof_transition(
            &ndb, action.action_id, "RUNNING", 9, requested.request_id,
            NULL, NULL, 0, 20, 1003, &event).ok);
        ASSERT(!build_fabric_proof_transition(
            &ndb, action.action_id, "REMOTE_GREEN", 9,
            requested.request_id, NULL, NULL, 0, 30, 1004, &event).ok);
        ASSERT(build_fabric_proof_transition(
            &ndb, action.action_id, "REMOTE_GREEN", 9,
            requested.request_id, NULL, id_a, 0, 30, 1004, &event).ok);
        ASSERT(build_fabric_proof_transition(
            &ndb, action.action_id, "RECEIPT_VERIFIED", 9,
            requested.request_id, NULL, NULL, 0, 40, 1005, &event).ok);
        ASSERT(build_fabric_proof_transition(
            &ndb, action.action_id, "REPRODUCED", 0,
            requested.request_id, NULL, NULL, 0, 50, 1006, &event).ok);
        ASSERT(build_fabric_proof_transition(
            &ndb, action.action_id, "READY_FOR_ACCEPTANCE", 0,
            requested.request_id, NULL, NULL, 0, 60, 1007, &event).ok);
        struct db_build_proof_event latest;
        ASSERT(db_build_proof_event_latest(&ndb, action.action_id, &latest));
        ASSERT_STR_EQ(latest.state, "READY_FOR_ACCEPTANCE");
        struct db_build_proof_event pending[4];
        ASSERT_EQ(db_build_proof_events_pending(&ndb, pending, 4), 0);
        struct build_fabric_proof_timings timings;
        ASSERT(build_fabric_proof_timings(
            &ndb, action.action_id, &timings).ok);
        ASSERT_EQ(timings.local_submit_us, 17);
        ASSERT_EQ(timings.peer_discovery_us, 10);
        ASSERT_EQ(timings.transfer_us, 15);
        ASSERT_EQ(timings.remote_queue_us, 20);
        ASSERT_EQ(timings.remote_execution_us, 30);
        ASSERT_EQ(timings.receipt_verification_us, 40);
        ASSERT_EQ(timings.total_background_proof_us, 60);

        struct db_service db_service;
        db_service_init(&db_service);
        ASSERT(db_service_attach(&db_service, &ndb));
        ASSERT(db_service_start_test_worker(&db_service));
        struct app_runtime_context runtime = {.db_service = &db_service};
        app_runtime_set_current(&runtime);
        struct json_value action_state;
        json_init(&action_state);
        ASSERT(build_fabric_dump_state_json(
            &action_state, action.action_id));
        ASSERT(json_get_bool(json_get(&action_state, "found")));
        ASSERT_STR_EQ(json_get_str(json_get(&action_state, "state")),
                      "READY_FOR_ACCEPTANCE");
        ASSERT_STR_EQ(json_get_str(json_get(&action_state, "candidate_root")),
                      action.candidate_root_sha3);
        ASSERT(json_get_bool(json_get(
            &action_state, "event_root_rederived")));
        json_free(&action_state);
        app_runtime_set_current(NULL);
        db_service_stop(&db_service);

        struct db_build_job newer_job;
        struct db_build_action newer_action;
        bf_job(&newer_job); bf_action(&newer_action);
        (void)snprintf(newer_job.source_cas_sha3,
                       sizeof(newer_job.source_cas_sha3), "%s", id_d);
        (void)snprintf(newer_action.input_root_sha3,
                       sizeof(newer_action.input_root_sha3), "%s", id_d);
        (void)snprintf(newer_action.task_root_sha3,
                       sizeof(newer_action.task_root_sha3), "%s", id_a);
        (void)snprintf(newer_action.candidate_root_sha3,
                       sizeof(newer_action.candidate_root_sha3), "%s", id_d);
        (void)snprintf(newer_action.proof_policy_root_sha3,
                       sizeof(newer_action.proof_policy_root_sha3), "%s",
                       id_c);
        ASSERT(bf_canonicalize(&newer_job, &newer_action));
        ASSERT(build_fabric_plan(&ndb, &newer_job, &newer_action).ok);
        ASSERT(build_fabric_proof_request(
            &ndb, newer_action.action_id, "/tmp/project", 0, 19, 1010,
            &requested, &created).ok);
        ASSERT(created);
        ASSERT(db_build_proof_event_latest(&ndb, action.action_id, &latest));
        ASSERT_STR_EQ(latest.state, "SUPERSEDED");
        ASSERT(db_build_proof_event_latest(
            &ndb, newer_action.action_id, &latest));
        ASSERT_STR_EQ(latest.state, "REQUESTED");
        node_db_close(&ndb);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bf_validation(void)
{
    int failures = 0;
    TEST("build_fabric: malformed ids and unnamed states fail validation") {
        struct ar_errors errors;
        struct db_build_job job;
        bf_job(&job);
        ASSERT(db_build_job_validate(&job, &errors));
        (void)snprintf(job.state, sizeof(job.state), "MAYBE");
        ASSERT(!db_build_job_validate(&job, &errors));
        bf_job(&job);
        (void)snprintf(job.source_cas_sha3, sizeof(job.source_cas_sha3), "abc");
        ASSERT(!db_build_job_validate(&job, &errors));
        struct db_build_worker worker;
        bf_worker(&worker);
        worker.revoked = 2;
        ASSERT(!db_build_worker_validate(&worker, &errors));
        PASS();
    } _test_next:;
    return failures;
}

static int test_bf_service(void)
{
    int failures = 0;
    TEST("build_fabric: service gates transitions and verifies signed receipts") {
        struct node_db ndb;
        char dir[256], path[320];
        ASSERT(bf_open(&ndb, dir, sizeof(dir), path, sizeof(path), "service"));
        struct db_build_job job;
        struct db_build_action action;
        bf_job(&job);
        bf_action(&action);
        ASSERT(bf_canonicalize(&job, &action));
        char action_id[65], job_id[65];
        ASSERT(build_fabric_action_id(&job, &action, action_id).ok);
        ASSERT(build_fabric_job_id(&job, action_id, job_id).ok);
        ASSERT(strlen(action_id) == 64 && strlen(job_id) == 64);
        ASSERT(strcmp(action_id, job_id) != 0);
        struct db_build_job planned_job = job;
        struct db_build_action planned_action = action;
        ASSERT(build_fabric_plan(&ndb, &job, &action).ok);
        ASSERT(build_fabric_plan(&ndb, &job, &action).ok); /* idempotent */
        ASSERT(build_fabric_submit(&ndb, job.job_id, 110).ok);
        ASSERT(build_fabric_submit(&ndb, job.job_id, 111).ok); /* idempotent */
        ASSERT(build_fabric_plan(&ndb, &planned_job, &planned_action).ok);
        ASSERT(db_build_action_find(&ndb, planned_action.action_id, &action));
        ASSERT_STR_EQ(action.state, "QUEUED");
        ASSERT(db_build_job_find(&ndb, planned_job.job_id, &job));
        ASSERT_STR_EQ(job.state, "QUEUED");

        uint8_t seed[32], pubkey[32], secret[32];
        memset(seed, 7, sizeof(seed));
        ed25519_keypair(pubkey, secret, seed);
        struct db_build_worker worker;
        bf_worker(&worker);
        zcl_hex_encode(pubkey, sizeof(pubkey), worker.signer_pubkey);
        ASSERT(build_fabric_worker_approve(&ndb, &worker, 112).ok);
        bool claimed = false;
        ASSERT(build_fabric_claim(&ndb, worker.worker_id, id_d, 113, 10,
                                  &action, &claimed).ok);
        ASSERT(claimed);
        ASSERT(build_fabric_start(&ndb, action.action_id, id_d, 114).ok);
        ASSERT(build_fabric_begin_verify(&ndb, action.action_id, id_d, 115).ok);
        struct db_build_receipt receipt;
        bf_receipt(&receipt);
        (void)snprintf(receipt.action_id, sizeof(receipt.action_id), "%s",
                       action.action_id);
        (void)snprintf(receipt.action_sha3, sizeof(receipt.action_sha3), "%s",
                       action.action_id);
        (void)snprintf(receipt.job_id, sizeof(receipt.job_id), "%s",
                       action.job_id);
        ASSERT(build_fabric_receipt_id(&receipt, receipt.receipt_id).ok);
        uint8_t receipt_id[32], signature[64];
        ASSERT(zcl_hex_decode_lower(receipt.receipt_id, receipt_id,
                                    sizeof(receipt_id)));
        ed25519_sign(signature, receipt_id, sizeof(receipt_id), secret, pubkey);
        zcl_hex_encode(signature, sizeof(signature), receipt.signature);
        ASSERT(build_fabric_receipt_accept(&ndb, &receipt, 116).ok);
        ASSERT(db_build_action_find(&ndb, planned_action.action_id, &action));
        ASSERT_STR_EQ(action.state, "ACCEPTED");
        ASSERT_STR_EQ(action.output_root_sha3, id_c);
        ASSERT_EQ(action.finished_at, 116);

        /* A fixed action's nonzero result is still authentic evidence. It is
         * stored atomically while the action and job finish FAILED. */
        struct db_build_job fail_job = planned_job;
        struct db_build_action fail_action = planned_action;
        (void)snprintf(fail_action.input_root_sha3,
                       sizeof(fail_action.input_root_sha3), "%s", id_a);
        fail_job.created_at = fail_job.updated_at = 117;
        fail_action.created_at = fail_action.updated_at = 117;
        ASSERT(bf_canonicalize(&fail_job, &fail_action));
        ASSERT(build_fabric_plan(&ndb, &fail_job, &fail_action).ok);
        ASSERT(build_fabric_submit(&ndb, fail_job.job_id, 117).ok);
        claimed = false;
        ASSERT(build_fabric_claim(&ndb, worker.worker_id, id_b, 118, 10,
                                  &fail_action, &claimed).ok);
        ASSERT(claimed);
        ASSERT(build_fabric_start(
            &ndb, fail_action.action_id, id_b, 119).ok);
        ASSERT(build_fabric_begin_verify(
            &ndb, fail_action.action_id, id_b, 120).ok);
        struct db_build_receipt failed_receipt;
        bf_receipt(&failed_receipt);
        (void)snprintf(failed_receipt.action_id,
                       sizeof(failed_receipt.action_id), "%s",
                       fail_action.action_id);
        (void)snprintf(failed_receipt.action_sha3,
                       sizeof(failed_receipt.action_sha3), "%s",
                       fail_action.action_id);
        (void)snprintf(failed_receipt.job_id,
                       sizeof(failed_receipt.job_id), "%s",
                       fail_action.job_id);
        (void)snprintf(failed_receipt.lease_id,
                       sizeof(failed_receipt.lease_id), "%s", id_b);
        failed_receipt.exit_status = 23;
        failed_receipt.created_at = 121;
        ASSERT(build_fabric_receipt_id(
            &failed_receipt, failed_receipt.receipt_id).ok);
        ASSERT(zcl_hex_decode_lower(failed_receipt.receipt_id, receipt_id,
                                    sizeof(receipt_id)));
        ed25519_sign(signature, receipt_id, sizeof(receipt_id), secret, pubkey);
        zcl_hex_encode(signature, sizeof(signature), failed_receipt.signature);
        ASSERT(build_fabric_receipt_accept(&ndb, &failed_receipt, 121).ok);
        ASSERT(db_build_action_find(
            &ndb, fail_action.action_id, &fail_action));
        ASSERT_STR_EQ(fail_action.state, "FAILED");
        ASSERT_STR_EQ(fail_action.last_error,
                      "fixed-action-reported-failure");
        ASSERT(db_build_receipt_find(
            &ndb, failed_receipt.receipt_id, &failed_receipt));

        /* Revocation is durable and makes a newly bound receipt fail before
         * signature acceptance; old evidence remains queryable. */
        ASSERT(build_fabric_worker_revoke(&ndb, id_c, 122).ok);
        ASSERT(build_fabric_worker_revoke(&ndb, id_c, 123).ok);
        receipt.created_at = 124;
        ASSERT(build_fabric_receipt_id(&receipt, receipt.receipt_id).ok);
        ASSERT(!build_fabric_receipt_accept(&ndb, &receipt, 124).ok);
        struct db_build_receipt rows[2];
        ASSERT_EQ(db_build_job_receipts(&ndb, planned_job.job_id, rows, 2), 1);
        ASSERT(!build_fabric_cancel(&ndb, planned_job.job_id, 125).ok);
        node_db_close(&ndb);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bf_reproduction_plan(void)
{
    int failures = 0;
    TEST("build_fabric: reproduction plan copies identity and owns no lifecycle") {
        struct node_db ndb;
        char dir[256], path[320];
        ASSERT(bf_open(&ndb, dir, sizeof(dir), path, sizeof(path),
                       "reproduction-plan"));
        struct db_build_job primary_job;
        struct db_build_action primary_action;
        bf_job(&primary_job);
        bf_action(&primary_action);
        ASSERT(bf_canonicalize(&primary_job, &primary_action));
        ASSERT(build_fabric_plan(&ndb, &primary_job, &primary_action).ok);

        char reproduction_action_id[BUILD_FABRIC_ID_HEX + 1];
        char reproduction_job_id[BUILD_FABRIC_ID_HEX + 1];
        ASSERT(build_fabric_plan_reproduction(
            &ndb, primary_action.action_id,
            VCS_BUILD_PACKAGE_PROFILE_STANDARD_B_V1, 110,
            reproduction_action_id, reproduction_job_id).ok);
        ASSERT(strcmp(reproduction_action_id,
                      primary_action.action_id) != 0);
        ASSERT(strcmp(reproduction_job_id, primary_job.job_id) != 0);

        struct db_build_job reproduction_job;
        struct db_build_action reproduction_action;
        ASSERT(db_build_job_find(
            &ndb, reproduction_job_id, &reproduction_job));
        ASSERT(db_build_action_find(
            &ndb, reproduction_action_id, &reproduction_action));
        ASSERT_STR_EQ(reproduction_job.profile,
                      VCS_BUILD_PACKAGE_PROFILE_STANDARD_B_V1);
        ASSERT_STR_EQ(reproduction_job.state, "PLANNED");
        ASSERT_STR_EQ(reproduction_action.state, "SNAPSHOTTED");
        ASSERT_EQ(reproduction_action.attempt_count, 0);
        ASSERT_EQ(reproduction_action.started_at, 0);
        ASSERT_STR_EQ(reproduction_action.worker_id, "");
        ASSERT_STR_EQ(reproduction_action.lease_id, "");
        ASSERT_STR_EQ(reproduction_job.source_sha256,
                      primary_job.source_sha256);
        ASSERT_STR_EQ(reproduction_job.source_cas_sha3,
                      primary_job.source_cas_sha3);
        ASSERT_STR_EQ(reproduction_job.toolchain_sha3,
                      primary_job.toolchain_sha3);
        ASSERT_STR_EQ(reproduction_action.input_root_sha3,
                      primary_action.input_root_sha3);
        ASSERT_STR_EQ(reproduction_action.target, primary_action.target);
        ASSERT_STR_EQ(reproduction_action.flags_sha3,
                      primary_action.flags_sha3);
        ASSERT_STR_EQ(reproduction_action.environment_sha3,
                      primary_action.environment_sha3);

        char repeated_action_id[BUILD_FABRIC_ID_HEX + 1];
        char repeated_job_id[BUILD_FABRIC_ID_HEX + 1];
        ASSERT(build_fabric_plan_reproduction(
            &ndb, primary_action.action_id,
            VCS_BUILD_PACKAGE_PROFILE_STANDARD_B_V1, 111,
            repeated_action_id, repeated_job_id).ok);
        ASSERT_STR_EQ(repeated_action_id, reproduction_action_id);
        ASSERT_STR_EQ(repeated_job_id, reproduction_job_id);
        ASSERT(!build_fabric_plan_reproduction(
            &ndb, primary_action.action_id, primary_job.profile, 112,
            repeated_action_id, repeated_job_id).ok);
        node_db_close(&ndb);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}


/* A requester node runs no build worker on purpose, so nothing else ever
 * enrolls its operator identity — and without an enrolled identity the
 * person on that node could never accept their own work. Enrollment is
 * first-use only: it must never resurrect an identity the operator already
 * ruled on. */
static int test_bf_local_enrollment(void)
{
    int failures = 0;
    TEST("build_fabric: local enrollment admits a first-use identity and never revives a revoked one") {
        struct node_db ndb;
        char dir[256], path[320];
        ASSERT(bf_open(&ndb, dir, sizeof(dir), path, sizeof(path), "enroll"));
        struct db_build_worker worker, stored;
        bf_worker(&worker);
        ASSERT(!db_build_worker_find(&ndb, worker.worker_id, &stored));

        /* First use: the identity is admitted on this node. */
        ASSERT(build_fabric_worker_enroll_local(&ndb, &worker, 130).ok);
        ASSERT(db_build_worker_find(&ndb, worker.worker_id, &stored));
        ASSERT_EQ(stored.approved, 1);
        ASSERT_EQ(stored.revoked, 0);

        /* Repeating it changes nothing: enrollment is not an approval loop. */
        ASSERT(build_fabric_worker_enroll_local(&ndb, &worker, 131).ok);
        ASSERT(db_build_worker_find(&ndb, worker.worker_id, &stored));
        ASSERT_EQ(stored.approved_at, worker.approved_at);

        /* The operator revokes it. Enrolling again still succeeds as a
         * call and MUST leave the refusal standing. */
        ASSERT(build_fabric_worker_revoke(&ndb, worker.worker_id, 132).ok);
        ASSERT(build_fabric_worker_enroll_local(&ndb, &worker, 133).ok);
        ASSERT(db_build_worker_find(&ndb, worker.worker_id, &stored));
        ASSERT_EQ(stored.revoked, 1);

        /* An expired row is the same story: still expired afterwards. One
         * identity per key, so this second one carries its own. */
        struct db_build_worker expiring;
        bf_worker(&expiring);
        (void)snprintf(expiring.worker_id, sizeof(expiring.worker_id), "%s",
                       id_b);
        (void)snprintf(expiring.signer_pubkey, sizeof(expiring.signer_pubkey),
                       "%s", id_a);
        expiring.expires_at = 140;
        ASSERT(build_fabric_worker_enroll_local(&ndb, &expiring, 134).ok);
        ASSERT(build_fabric_worker_enroll_local(&ndb, &expiring, 150).ok);
        ASSERT(db_build_worker_find(&ndb, expiring.worker_id, &stored));
        ASSERT_EQ(stored.expires_at, 140);

        /* Nothing without an open ledger or an identity. */
        ASSERT(!build_fabric_worker_enroll_local(NULL, &worker, 135).ok);
        ASSERT(!build_fabric_worker_enroll_local(&ndb, NULL, 135).ok);
        node_db_close(&ndb);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}
static int test_bf_leases(void)
{
    int failures = 0;
    TEST("build_fabric: leases claim once, recover restart, and refuse stale owners") {
        struct node_db ndb;
        char dir[256], path[320];
        ASSERT(bf_open(&ndb, dir, sizeof(dir), path, sizeof(path), "leases"));
        struct db_build_job job;
        struct db_build_action action;
        struct db_build_worker worker;
        bf_job(&job);
        bf_action(&action);
        bf_worker(&worker);
        ASSERT(bf_canonicalize(&job, &action));
        char job_id[BUILD_FABRIC_ID_HEX + 1];
        char action_id[BUILD_FABRIC_ID_HEX + 1];
        (void)snprintf(job_id, sizeof(job_id), "%s", job.job_id);
        (void)snprintf(action_id, sizeof(action_id), "%s", action.action_id);
        ASSERT(build_fabric_plan(&ndb, &job, &action).ok);
        ASSERT(build_fabric_submit(&ndb, job_id, 110).ok);
        ASSERT(build_fabric_worker_approve(&ndb, &worker, 111).ok);

        struct db_build_action claimed_action;
        bool claimed = false;
        ASSERT(build_fabric_claim(&ndb, worker.worker_id, id_d, 120, 10,
                                  &claimed_action, &claimed).ok);
        ASSERT(claimed);
        ASSERT_STR_EQ(claimed_action.action_id, action_id);
        ASSERT_STR_EQ(claimed_action.state, "CLAIMED");
        ASSERT_EQ(claimed_action.attempt_count, 1);
        ASSERT_EQ(claimed_action.lease_expires_at, 130);

        struct db_build_action no_action;
        claimed = true;
        ASSERT(build_fabric_claim(&ndb, worker.worker_id, id_b, 121, 10,
                                  &no_action, &claimed).ok);
        ASSERT(!claimed); /* the first compare-and-swap owns it */
        ASSERT(!build_fabric_start(&ndb, action_id, id_b, 121).ok);
        ASSERT(build_fabric_start(&ndb, action_id, id_d, 121).ok);
        ASSERT(build_fabric_heartbeat(&ndb, action_id, id_d, 125, 10).ok);
        ASSERT(build_fabric_begin_verify(&ndb, action_id, id_d, 126).ok);
        ASSERT(db_build_action_find(&ndb, action_id, &claimed_action));
        ASSERT_STR_EQ(claimed_action.state, "VERIFYING");
        ASSERT_EQ(claimed_action.lease_expires_at, 135);

        /* A new process sees the same expired lease and requeues it. */
        node_db_close(&ndb);
        memset(&ndb, 0, sizeof(ndb));
        ASSERT(node_db_open(&ndb, path));
        size_t requeued = 99;
        ASSERT(build_fabric_recover_expired(&ndb, 136, &requeued).ok);
        ASSERT_EQ(requeued, 1);
        ASSERT(db_build_action_find(&ndb, action_id, &claimed_action));
        ASSERT_STR_EQ(claimed_action.state, "QUEUED");
        ASSERT_STR_EQ(claimed_action.last_error, "lease-expired-requeued");
        ASSERT(claimed_action.lease_id[0] == '\0');
        ASSERT_EQ(claimed_action.attempt_count, 1);
        ASSERT(!build_fabric_begin_verify(&ndb, action_id, id_d, 137).ok);

        ASSERT(build_fabric_claim(&ndb, worker.worker_id, id_b, 137, 10,
                                  &claimed_action, &claimed).ok);
        ASSERT(claimed && claimed_action.attempt_count == 2);
        ASSERT(build_fabric_start(&ndb, action_id, id_b, 138).ok);
        ASSERT(build_fabric_cancel(&ndb, job_id, 139).ok);
        ASSERT(!build_fabric_heartbeat(&ndb, action_id, id_b, 140, 10).ok);
        ASSERT(db_build_action_find(&ndb, action_id, &claimed_action));
        ASSERT_STR_EQ(claimed_action.state, "CANCELLED");
        node_db_close(&ndb);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bf_execution_observation_codec(void)
{
    int failures = 0;
    TEST("build_fabric: physical observation codec fails closed on undeclared reads") {
        struct vcs_build_execution_observation_v1 observation = {
            .schema_version = VCS_BUILD_EXECUTION_OBSERVATION_VERSION,
            .flags = VCS_BUILD_OBS_REQUIRED_FLAGS,
            .exit_status = 0,
            .cpu_seconds_limit = 120,
            .memory_bytes_limit = UINT64_C(2048) * 1024u * 1024u,
            .process_limit = 16,
            .file_limit = 64,
            .file_bytes_limit = UINT64_C(256) * 1024u * 1024u,
            .output_bytes_limit = UINT64_C(256) * 1024u * 1024u,
            .wall_millis_limit = 120000,
        };
        memset(observation.action_root, 1, 32);
        memset(observation.action_input_root, 2, 32);
        memset(observation.observed_input_bytes_root, 8, 32);
        memset(observation.artifact_root, 3, 32);
        memset(observation.output_bytes_root, 4, 32);
        memset(observation.toolchain_root, 5, 32);
        memset(observation.flags_root, 6, 32);
        memset(observation.environment_root, 7, 32);
        vcs_build_execution_read_set_root(
            observation.action_input_root,
            observation.observed_input_bytes_root,
            observation.toolchain_root,
            observation.declared_reads_root);
        memcpy(observation.observed_reads_root,
               observation.declared_reads_root, 32);
        vcs_build_execution_declared_write_set_root(
            VCS_BUILD_OUTPUT_V1, observation.declared_writes_root);
        vcs_build_execution_observed_write_set_root(
            VCS_BUILD_OUTPUT_V1, observation.output_bytes_root,
            observation.observed_writes_root);
        uint8_t wire[VCS_BUILD_EXECUTION_OBSERVATION_WIRE_BYTES], root[32];
        struct vcs_build_execution_observation_v1 parsed;
        ASSERT(vcs_build_execution_observation_v1_serialize(
            &observation, wire));
        ASSERT(vcs_build_execution_observation_v1_root(&observation, root));
        ASSERT(vcs_build_execution_observation_v1_parse(
            wire, sizeof(wire), &parsed));
        ASSERT(parsed.schema_version == observation.schema_version &&
               parsed.flags == observation.flags &&
               memcmp(parsed.action_root, observation.action_root, 32) == 0 &&
               parsed.wall_millis_limit == observation.wall_millis_limit);
        observation.observed_reads_root[0] ^= 1u;
        ASSERT(!vcs_build_execution_observation_v1_valid(&observation));
        ASSERT(!vcs_build_execution_observation_v1_serialize(
            &observation, wire));
        PASS();
    } _test_next:;
    return failures;
}

static int test_bf_worker_identity_capability_honesty(void)
{
    int failures = 0;
    TEST("build_fabric: worker identity advertises the real host platform "
         "and declines compile capability it cannot execute") {
        /* On a host that CAN capture a toolchain capsule (this build/test
         * host always can — see test_bf_toolchain_capture_cache above),
         * build_fabric_worker_identity_load() must still succeed and the
         * advertised platform token must name the actual compiled-for
         * host, never a blind literal. */
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "build_fabric", "identity-honest");
        struct db_build_worker worker;
        uint8_t signer_secret[32], signer_pubkey[32];
        ASSERT(build_fabric_worker_identity_load(
            dir, &worker, signer_secret, signer_pubkey).ok);
#if defined(__linux__)
        static const char expected_platform[] = "linux,";
#elif defined(__APPLE__)
        static const char expected_platform[] = "macos,";
#else
        static const char expected_platform[] = "unknown,";
#endif
        ASSERT(strncmp(worker.capabilities, expected_platform,
                       sizeof(expected_platform) - 1) == 0);
        ASSERT(strstr(worker.capabilities, VCS_BUILD_ACTION_KIND_V1) != NULL);
        ASSERT(strstr(worker.capabilities,
                      VCS_BUILD_ACTION_KIND_TEST_V1) != NULL);
        ASSERT(strstr(worker.capabilities,
                      VCS_BUILD_ACTION_KIND_FUZZ_V1) != NULL);
        ASSERT(strstr(worker.capabilities,
                      VCS_BUILD_ACTION_KIND_PACKAGE_V1) != NULL);

        /* The same decision, driven directly (test seam) with the outcome
         * a host that CANNOT capture a toolchain capsule would see (e.g.
         * arm64 macOS, whose crt1.o/crti.o/crtn.o/libc.so.6 ELF/glibc
         * probes can never succeed): it must refuse by name, not write a
         * capability string that claims compile/test/fuzz/package it
         * cannot execute. */
        char declined[BUILD_FABRIC_CAPS_MAX + 1];
        declined[0] = '\1'; /* poison: must stay untouched on refusal */
        struct zcl_result refusal = build_fabric_worker_capabilities_for_test(
            false, declined, sizeof(declined));
        ASSERT(!refusal.ok);
        ASSERT(strstr(refusal.message, "declines") != NULL);
        ASSERT(declined[0] == '\1');

        /* And the honored path through the same seam matches the real
         * identity_load() output byte-for-byte. */
        char honored[BUILD_FABRIC_CAPS_MAX + 1];
        ASSERT(build_fabric_worker_capabilities_for_test(
            true, honored, sizeof(honored)).ok);
        ASSERT_STR_EQ(honored, worker.capabilities);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bf_confined_worker(void)
{
    int failures = 0;
    TEST("build_fabric: fixed worker confines, CAS-stores, signs, and accepts one TU") {
        struct node_db ndb;
        char dir[256], path[320];
        ASSERT(bf_open(&ndb, dir, sizeof(dir), path, sizeof(path), "worker"));
        ASSERT(vcs_object_store_init(dir));
        struct db_build_worker persistent_a, persistent_b;
        uint8_t persistent_sk_a[32], persistent_pk_a[32];
        uint8_t persistent_sk_b[32], persistent_pk_b[32];
        ASSERT(build_fabric_worker_identity_load(
            dir, &persistent_a, persistent_sk_a, persistent_pk_a).ok);
        ASSERT(build_fabric_worker_identity_load(
            dir, &persistent_b, persistent_sk_b, persistent_pk_b).ok);
        ASSERT_STR_EQ(persistent_a.worker_id, persistent_b.worker_id);
        ASSERT(memcmp(persistent_pk_a, persistent_pk_b, 32) == 0);
        char key_path[320];
        (void)snprintf(key_path, sizeof(key_path),
                       "%s/zcode/build-worker.ed25519", dir);
        ASSERT(chmod(key_path, 0644) == 0);
        ASSERT(!build_fabric_worker_identity_load(
            dir, &persistent_b, persistent_sk_b, persistent_pk_b).ok);
        ASSERT(chmod(key_path, 0600) == 0);
        static const uint8_t input[] =
            "int zbuild_fixture(void) { return 23; }\n";
        uint8_t input_root[32];
        sha3_256(input, sizeof(input) - 1u, input_root);
        ASSERT(vcs_object_put_addressed(dir, input_root, input,
                                        sizeof(input) - 1u));
        struct vcs_toolchain_capsule_v1 capsule;
        uint8_t capsule_root[32];
        ASSERT(vcs_toolchain_capsule_v1_capture(&capsule));
        ASSERT(vcs_toolchain_capsule_v1_root(&capsule, capsule_root));

        struct db_build_job job;
        struct db_build_action action;
        bf_job(&job);
        bf_action(&action);
        zcl_hex_encode(capsule_root, sizeof(capsule_root), job.toolchain_sha3);
        zcl_hex_encode(input_root, sizeof(input_root), action.input_root_sha3);
        uint8_t fixed_flags[32], fixed_environment[32];
        vcs_build_action_v1_fixed_flags_root(fixed_flags);
        vcs_build_action_v1_fixed_environment_root(fixed_environment);
        zcl_hex_encode(fixed_flags, 32, action.flags_sha3);
        zcl_hex_encode(fixed_environment, 32, action.environment_sha3);
        ASSERT(bf_canonicalize(&job, &action));
        char action_id[65];
        (void)snprintf(action_id, sizeof(action_id), "%s", action.action_id);
        ASSERT(build_fabric_plan(&ndb, &job, &action).ok);
        int64_t now = (int64_t)platform_time_wall_unix();
        ASSERT(build_fabric_submit(&ndb, job.job_id, now).ok);

        uint8_t seed[32], pubkey[32], secret[32];
        memset(seed, 29, sizeof(seed));
        ed25519_keypair(pubkey, secret, seed);
        struct db_build_worker worker;
        bf_worker(&worker);
        zcl_hex_encode(pubkey, sizeof(pubkey), worker.signer_pubkey);
        ASSERT(build_fabric_worker_approve(&ndb, &worker, now).ok);
        bool claimed = false;
        ASSERT(build_fabric_claim(&ndb, worker.worker_id, id_d, now, 300,
                                  &action, &claimed).ok);
        ASSERT(claimed);
        struct db_build_receipt receipt;
        struct zcl_result executed = build_fabric_worker_execute(
            &ndb, dir, dir, action_id, id_d, secret, pubkey, &receipt, NULL);
        if (!executed.ok)
            printf("worker detail: %s\n", executed.message);
        ASSERT(executed.ok);
        ASSERT(db_build_action_find(&ndb, action_id, &action));
        ASSERT_STR_EQ(action.state, "VERIFYING");
        ASSERT_STR_EQ(receipt.trust_state, "REMOTE_OBSERVED");
        ASSERT(strlen(receipt.observation_sha3) == 64);
        ASSERT(!build_fabric_receipt_admit(
            &ndb, "/definitely/not/the/workspace", receipt.receipt_id,
            now + 1).ok);
        ASSERT(db_build_action_find(&ndb, action_id, &action));
        ASSERT_STR_EQ(action.state, "VERIFYING");

        uint8_t good_observation_root[32], *poison_wire = NULL;
        size_t poison_wire_len = 0;
        ASSERT(zcl_hex_decode_lower(receipt.observation_sha3,
                                    good_observation_root, 32));
        ASSERT_EQ(vcs_object_load_raw(
            dir, good_observation_root, &poison_wire, &poison_wire_len), 0);
        struct vcs_build_execution_observation_v1 poisoned_observation;
        ASSERT(vcs_build_execution_observation_v1_parse(
            poison_wire, poison_wire_len, &poisoned_observation));
        free(poison_wire);
        poisoned_observation.action_root[0] ^= 1u;
        uint8_t poisoned_root[32];
        ASSERT(build_fabric_worker_store_observation(
            dir, &poisoned_observation, poisoned_root).ok);
        struct db_build_receipt poisoned_receipt = receipt;
        zcl_hex_encode(poisoned_root, 32,
                       poisoned_receipt.observation_sha3);
        poisoned_receipt.created_at = now + 1;
        ASSERT(build_fabric_receipt_id(
            &poisoned_receipt, poisoned_receipt.receipt_id).ok);
        uint8_t poisoned_id[32], poisoned_signature[64];
        ASSERT(zcl_hex_decode_lower(
            poisoned_receipt.receipt_id, poisoned_id, 32));
        ed25519_sign(poisoned_signature, poisoned_id, 32, secret, pubkey);
        zcl_hex_encode(poisoned_signature, 64,
                       poisoned_receipt.signature);
        ASSERT(build_fabric_receipt_quarantine(
            &ndb, &poisoned_receipt, now + 1).ok);
        ASSERT(!build_fabric_receipt_admit(
            &ndb, dir, poisoned_receipt.receipt_id, now + 1).ok);
        ASSERT(db_build_action_find(&ndb, action_id, &action));
        ASSERT_STR_EQ(action.state, "VERIFYING");
        ASSERT(build_fabric_receipt_admit(
            &ndb, dir, receipt.receipt_id, now + 1).ok);
        ASSERT(db_build_action_find(&ndb, action_id, &action));
        ASSERT_STR_EQ(action.state, "ACCEPTED");
        ASSERT_STR_EQ(action.output_root_sha3, receipt.output_sha3);
        uint8_t manifest_root[32];
        ASSERT(zcl_hex_decode_lower(receipt.output_sha3, manifest_root, 32));
        uint8_t *wire = NULL;
        size_t wire_len = 0;
        ASSERT_EQ(vcs_object_load_raw(dir, manifest_root, &wire, &wire_len), 0);
        struct vcs_build_artifact_manifest_v1 manifest;
        ASSERT(vcs_build_artifact_manifest_v1_parse(wire, wire_len, &manifest));
        free(wire);
        ASSERT_EQ(manifest.chunk_count, 1);
        uint8_t *object = NULL;
        size_t object_len = 0;
        ASSERT_EQ(vcs_object_load_raw(dir, manifest.chunk_sha3[0], &object,
                                      &object_len), 0);
        ASSERT(vcs_build_artifact_manifest_v1_verify_chunk(
            &manifest, 0, object, object_len));
#if defined(__APPLE__)
        ASSERT(object_len >= 16 && object[0] == 0xcf && object[1] == 0xfa &&
               object[2] == 0xed && object[3] == 0xfe &&
               object[4] == 0x0c && object[7] == 0x01 &&
               object[12] == 0x01 && object[13] == 0x00);
#else
        ASSERT(object_len >= 20 && object[0] == 0x7f && object[1] == 'E' &&
               object[16] == 1 && object[18] == 62);
#endif
        free(object);

        /* A clean shadow is a second signed receipt for this SAME action,
         * never a profile-mutated action. Exact observations match; an
         * observed write-set divergence remains named RED. */
        struct db_build_receipt primary;
        ASSERT(db_build_receipt_find(&ndb, receipt.receipt_id, &primary));
        uint8_t shadow_seed[32], shadow_pubkey[32], shadow_secret[32];
        memset(shadow_seed, 41, sizeof(shadow_seed));
        ed25519_keypair(shadow_pubkey, shadow_secret, shadow_seed);
        struct db_build_worker shadow_worker;
        bf_worker(&shadow_worker);
        (void)snprintf(shadow_worker.worker_id,
                       sizeof(shadow_worker.worker_id), "%s", id_a);
        zcl_hex_encode(shadow_pubkey, 32, shadow_worker.signer_pubkey);
        ASSERT(build_fabric_worker_approve(
            &ndb, &shadow_worker, now + 2).ok);
        struct db_build_receipt shadow = primary;
        (void)snprintf(shadow.worker_id, sizeof(shadow.worker_id), "%s",
                       shadow_worker.worker_id);
        (void)snprintf(shadow.lease_id, sizeof(shadow.lease_id), "%s", id_b);
        (void)snprintf(shadow.trust_state, sizeof(shadow.trust_state),
                       "REMOTE_OBSERVED");
        shadow.created_at = now + 2;
        ASSERT(build_fabric_receipt_id(&shadow, shadow.receipt_id).ok);
        uint8_t shadow_id[32], shadow_signature[64];
        ASSERT(zcl_hex_decode_lower(shadow.receipt_id, shadow_id, 32));
        ed25519_sign(shadow_signature, shadow_id, 32,
                     shadow_secret, shadow_pubkey);
        zcl_hex_encode(shadow_signature, 64, shadow.signature);
        ASSERT(db_build_receipt_save(&ndb, &shadow));
        struct build_fabric_shadow_match match;
        ASSERT(build_fabric_clean_shadow_compare(
            &ndb, dir, primary.receipt_id, shadow.receipt_id, &match).ok);
        ASSERT(match.same_action && match.distinct_signers &&
               match.artifact_match && match.observed_reads_match &&
               match.observed_writes_match);

        struct db_build_worker alias_worker;
        bf_worker(&alias_worker);
        (void)snprintf(alias_worker.worker_id,
                       sizeof(alias_worker.worker_id), "%s", id_d);
        zcl_hex_encode(pubkey, 32, alias_worker.signer_pubkey);
        ASSERT(!build_fabric_worker_approve(
            &ndb, &alias_worker, now + 2).ok);

        /* Release qualification is a third exact execution plus an explicit
         * signed human decision. It emits an inert CAS artifact and cannot
         * publish or deploy. */
        uint8_t reproduction_seed[32], reproduction_pubkey[32];
        uint8_t reproduction_secret[32];
        memset(reproduction_seed, 42, sizeof(reproduction_seed));
        ed25519_keypair(reproduction_pubkey, reproduction_secret,
                        reproduction_seed);
        struct db_build_worker reproduction_worker;
        bf_worker(&reproduction_worker);
        (void)snprintf(reproduction_worker.worker_id,
                       sizeof(reproduction_worker.worker_id), "%s", id_b);
        zcl_hex_encode(reproduction_pubkey, 32,
                       reproduction_worker.signer_pubkey);
        ASSERT(build_fabric_worker_approve(
            &ndb, &reproduction_worker, now + 3).ok);
        struct db_build_receipt reproduction = primary;
        (void)snprintf(reproduction.worker_id,
                       sizeof(reproduction.worker_id), "%s",
                       reproduction_worker.worker_id);
        (void)snprintf(reproduction.lease_id,
                       sizeof(reproduction.lease_id), "%s", id_c);
        (void)snprintf(reproduction.trust_state,
                       sizeof(reproduction.trust_state), "REMOTE_OBSERVED");
        reproduction.created_at = now + 3;
        ASSERT(build_fabric_receipt_id(
            &reproduction, reproduction.receipt_id).ok);
        uint8_t reproduction_id[32], reproduction_signature[64];
        ASSERT(zcl_hex_decode_lower(
            reproduction.receipt_id, reproduction_id, 32));
        ed25519_sign(reproduction_signature, reproduction_id, 32,
                     reproduction_secret, reproduction_pubkey);
        zcl_hex_encode(reproduction_signature, 64,
                       reproduction.signature);
        ASSERT(db_build_receipt_save(&ndb, &reproduction));

        static const uint8_t machine_evidence[3][32] = {
            "machine-a-physical-run-1",
            "machine-b-clean-shadow-2",
            "machine-c-reproduction-3",
        };
        uint8_t machine_roots[3][32];
        for (size_t i = 0; i < 3; i++) {
            sha3_256(machine_evidence[i], sizeof(machine_evidence[i]),
                     machine_roots[i]);
            ASSERT(vcs_object_put_addressed(
                dir, machine_roots[i], machine_evidence[i],
                sizeof(machine_evidence[i])));
        }
        uint8_t regression_action_root[32], regression_proof_root[32];
        char regression_receipt_id[65];
        ASSERT(test_build_release_regression_fixture(
            &ndb, dir, &job, input_root, now + 4,
            regression_action_root, regression_proof_root,
            regression_receipt_id));
        uint8_t confirmer_seed[32], confirmer_pubkey[32];
        uint8_t confirmer_secret[32];
        memset(confirmer_seed, 43, sizeof(confirmer_seed));
        ed25519_keypair(confirmer_pubkey, confirmer_secret, confirmer_seed);
        struct db_build_worker confirmer;
        bf_worker(&confirmer);
        bf_worker_id_from_pubkey(confirmer_pubkey, confirmer.worker_id);
        zcl_hex_encode(confirmer_pubkey, 32, confirmer.signer_pubkey);
        (void)snprintf(confirmer.capabilities,
                       sizeof(confirmer.capabilities),
                       "release-confirmation.v2");
        ASSERT(build_fabric_worker_approve(&ndb, &confirmer, now + 4).ok);
        struct vcs_build_release_confirmation_v2 confirmation;
        vcs_build_release_confirmation_v2_init(&confirmation);
        confirmation.decision = VCS_BUILD_RELEASE_DECISION_CONFIRM;
        ASSERT(zcl_hex_decode_lower(action_id, confirmation.action_root, 32));
        ASSERT(zcl_hex_decode_lower(primary.output_sha3,
                                    confirmation.artifact_root, 32));
        ASSERT(zcl_hex_decode_lower(primary.receipt_id,
                                    confirmation.candidate_receipt_root, 32));
        ASSERT(zcl_hex_decode_lower(shadow.receipt_id,
                                    confirmation.shadow_receipt_root, 32));
        ASSERT(zcl_hex_decode_lower(
            reproduction.receipt_id,
            confirmation.reproduction_receipt_root, 32));
        memcpy(confirmation.candidate_machine_evidence_root,
               machine_roots[0], 32);
        memcpy(confirmation.shadow_machine_evidence_root,
               machine_roots[1], 32);
        memcpy(confirmation.reproduction_machine_evidence_root,
               machine_roots[2], 32);
        memcpy(confirmation.regression_action_root,
               regression_action_root, 32);
        memcpy(confirmation.regression_proof_set_root,
               regression_proof_root, 32);
        confirmation.confirmed_unix = now + 4;
        ASSERT_EQ(vcs_build_release_confirmation_v2_seal(
            &confirmation, confirmer_secret, confirmer_pubkey),
            VCS_BUILD_RELEASE_EVIDENCE_OK);
        uint8_t confirmation_wire[
            VCS_BUILD_RELEASE_CONFIRMATION_WIRE_BYTES];
        uint8_t confirmation_root[32];
        ASSERT_EQ(vcs_build_release_confirmation_v2_serialize(
            &confirmation, confirmation_wire),
            VCS_BUILD_RELEASE_EVIDENCE_OK);
        ASSERT_EQ(vcs_build_release_confirmation_v2_root(
            &confirmation, confirmation_root),
            VCS_BUILD_RELEASE_EVIDENCE_OK);
        ASSERT(vcs_object_put_addressed(
            dir, confirmation_root, confirmation_wire,
            sizeof(confirmation_wire)));
        char confirmation_hex[65];
        zcl_hex_encode(confirmation_root, 32, confirmation_hex);
        struct build_fabric_release_qualification_report qualified;
        ASSERT(build_fabric_release_qualify(
            &ndb, dir, confirmation_hex, now + 5, &qualified).ok);
        ASSERT(qualified.candidate_admitted &&
               qualified.clean_shadow_match &&
               qualified.independent_reproduction_match &&
               qualified.distinct_executor_signers &&
               qualified.physical_evidence_present &&
               qualified.regression_proof_satisfied &&
               qualified.human_confirmed && qualified.confirmer_approved &&
               !qualified.publication_performed);
        ASSERT(strlen(qualified.qualification_root_sha3) == 64);
        struct db_build_receipt regression_receipt_after;
        ASSERT(db_build_receipt_find(
            &ndb, regression_receipt_id, &regression_receipt_after));
        ASSERT_STR_EQ(regression_receipt_after.trust_state,
                      "REMOTE_OBSERVED");
        uint8_t qualification_root[32], *qualification_wire = NULL;
        size_t qualification_len = 0;
        ASSERT(zcl_hex_decode_lower(qualified.qualification_root_sha3,
                                    qualification_root, 32));
        ASSERT_EQ(vcs_object_load_raw(
            dir, qualification_root, &qualification_wire,
            &qualification_len), 0);
        struct vcs_build_release_qualification_v2 parsed_qualification;
        ASSERT_EQ(vcs_build_release_qualification_v2_parse(
            qualification_wire, qualification_len, &parsed_qualification),
            VCS_BUILD_RELEASE_EVIDENCE_OK);
        ASSERT(memcmp(parsed_qualification.artifact_root,
                      confirmation.artifact_root, 32) == 0);
        ASSERT(memcmp(parsed_qualification.regression_action_root,
                      regression_action_root, 32) == 0);
        ASSERT(memcmp(parsed_qualification.regression_proof_set_root,
                      regression_proof_root, 32) == 0);
        qualification_wire[20] ^= 1u;
        bool repaired_poison = false;
        ASSERT(vcs_object_put_addressed_repair(
            dir, qualification_root, qualification_wire,
            qualification_len, &repaired_poison));
        ASSERT(repaired_poison);
        free(qualification_wire);
        ASSERT(!build_fabric_release_qualify(
            &ndb, dir, confirmation_hex, now + 5, &qualified).ok);
        ASSERT_STR_EQ(qualified.first_bad_invariant,
                      "qualified-release-cas-poisoned");

        struct vcs_build_release_confirmation_v2 missing_regression =
            confirmation;
        missing_regression.regression_proof_set_root[0] ^= 1u;
        ASSERT_EQ(vcs_build_release_confirmation_v2_seal(
            &missing_regression, confirmer_secret, confirmer_pubkey),
            VCS_BUILD_RELEASE_EVIDENCE_OK);
        ASSERT_EQ(vcs_build_release_confirmation_v2_serialize(
            &missing_regression, confirmation_wire),
            VCS_BUILD_RELEASE_EVIDENCE_OK);
        ASSERT_EQ(vcs_build_release_confirmation_v2_root(
            &missing_regression, confirmation_root),
            VCS_BUILD_RELEASE_EVIDENCE_OK);
        ASSERT(vcs_object_put_addressed(
            dir, confirmation_root, confirmation_wire,
            sizeof(confirmation_wire)));
        zcl_hex_encode(confirmation_root, 32, confirmation_hex);
        ASSERT(!build_fabric_release_qualify(
            &ndb, dir, confirmation_hex, now + 5, &qualified).ok);
        ASSERT_STR_EQ(qualified.first_bad_invariant,
                      "historical-regression-proof-invalid");

        const uint8_t *regression_manifest = NULL;
        size_t regression_manifest_len = 0;
        uint8_t regression_manifest_root[32];
        vcs_build_release_regression_manifest_v1_bytes(
            &regression_manifest, &regression_manifest_len);
        vcs_build_release_regression_manifest_v1_root(
            regression_manifest_root);
        ASSERT(regression_manifest && regression_manifest_len < 1024);
        uint8_t corrupted_manifest[1024];
        memcpy(corrupted_manifest, regression_manifest,
               regression_manifest_len);
        corrupted_manifest[0] ^= 1u;
        bool repaired_manifest = false;
        ASSERT(vcs_object_put_addressed_repair(
            dir, regression_manifest_root, corrupted_manifest,
            regression_manifest_len, &repaired_manifest));
        ASSERT(repaired_manifest);
        ASSERT(!vcs_build_release_regression_manifest_v1_verify_cas(
            dir, regression_manifest_root));
        ASSERT(!build_fabric_release_qualify(
            &ndb, dir, confirmation_hex, now + 5, &qualified).ok);
        ASSERT_STR_EQ(qualified.first_bad_invariant,
                      "regression-intent-manifest-invalid");
        repaired_manifest = false;
        ASSERT(vcs_object_put_addressed_repair(
            dir, regression_manifest_root, regression_manifest,
            regression_manifest_len, &repaired_manifest));
        ASSERT(repaired_manifest);
        ASSERT(vcs_build_release_regression_manifest_v1_verify_cas(
            dir, regression_manifest_root));

        struct vcs_build_release_confirmation_v2 missing_physical =
            confirmation;
        missing_physical.reproduction_machine_evidence_root[0] ^= 1u;
        ASSERT_EQ(vcs_build_release_confirmation_v2_seal(
            &missing_physical, confirmer_secret, confirmer_pubkey),
            VCS_BUILD_RELEASE_EVIDENCE_OK);
        ASSERT_EQ(vcs_build_release_confirmation_v2_serialize(
            &missing_physical, confirmation_wire),
            VCS_BUILD_RELEASE_EVIDENCE_OK);
        ASSERT_EQ(vcs_build_release_confirmation_v2_root(
            &missing_physical, confirmation_root),
            VCS_BUILD_RELEASE_EVIDENCE_OK);
        ASSERT(vcs_object_put_addressed(
            dir, confirmation_root, confirmation_wire,
            sizeof(confirmation_wire)));
        zcl_hex_encode(confirmation_root, 32, confirmation_hex);
        ASSERT(!build_fabric_release_qualify(
            &ndb, dir, confirmation_hex, now + 5, &qualified).ok);
        ASSERT_STR_EQ(qualified.first_bad_invariant,
                      "physical-machine-evidence-invalid");

        struct vcs_build_release_confirmation_v2 cancelled = confirmation;
        cancelled.decision = VCS_BUILD_RELEASE_DECISION_CANCEL;
        ASSERT_EQ(vcs_build_release_confirmation_v2_seal(
            &cancelled, confirmer_secret, confirmer_pubkey),
            VCS_BUILD_RELEASE_EVIDENCE_OK);
        ASSERT_EQ(vcs_build_release_confirmation_v2_serialize(
            &cancelled, confirmation_wire),
            VCS_BUILD_RELEASE_EVIDENCE_OK);
        ASSERT_EQ(vcs_build_release_confirmation_v2_root(
            &cancelled, confirmation_root),
            VCS_BUILD_RELEASE_EVIDENCE_OK);
        ASSERT(vcs_object_put_addressed(
            dir, confirmation_root, confirmation_wire,
            sizeof(confirmation_wire)));
        zcl_hex_encode(confirmation_root, 32, confirmation_hex);
        ASSERT(!build_fabric_release_qualify(
            &ndb, dir, confirmation_hex, now + 5, &qualified).ok);
        ASSERT_STR_EQ(qualified.first_bad_invariant,
                      "human-cancelled-release");

        uint8_t observation_root[32], *observation_wire = NULL;
        size_t observation_len = 0;
        ASSERT(zcl_hex_decode_lower(primary.observation_sha3,
                                    observation_root, 32));
        ASSERT_EQ(vcs_object_load_raw(
            dir, observation_root, &observation_wire, &observation_len), 0);
        struct vcs_build_execution_observation_v1 divergent;
        ASSERT(vcs_build_execution_observation_v1_parse(
            observation_wire, observation_len, &divergent));
        free(observation_wire);
        divergent.observed_writes_root[0] ^= 1u;
        uint8_t divergent_root[32];
        ASSERT(build_fabric_worker_store_observation(
            dir, &divergent, divergent_root).ok);
        struct db_build_receipt red_shadow = shadow;
        zcl_hex_encode(divergent_root, 32, red_shadow.observation_sha3);
        red_shadow.created_at = now + 3;
        ASSERT(build_fabric_receipt_id(
            &red_shadow, red_shadow.receipt_id).ok);
        ASSERT(zcl_hex_decode_lower(red_shadow.receipt_id, shadow_id, 32));
        ed25519_sign(shadow_signature, shadow_id, 32,
                     shadow_secret, shadow_pubkey);
        zcl_hex_encode(shadow_signature, 64, red_shadow.signature);
        ASSERT(db_build_receipt_save(&ndb, &red_shadow));
        ASSERT(!build_fabric_clean_shadow_compare(
            &ndb, dir, primary.receipt_id, red_shadow.receipt_id,
            &match).ok);
        ASSERT_STR_EQ(match.first_bad_invariant,
                      "physical-observation-root-mismatch");
        node_db_close(&ndb);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bf_toolchain_capture_cache(void)
{
    int failures = 0;
    TEST("build_fabric: unchanged GCC capsule is captured once per process") {
        struct vcs_toolchain_capsule_v1 first, second, changed_environment;
        uint8_t first_root[32], second_root[32], changed_root[32];
        uint64_t fresh = 0, hits = 0;
        const char *old_lc_all = getenv("LC_ALL");
        char *saved_lc_all = old_lc_all ? strdup(old_lc_all) : NULL;
        ASSERT(!old_lc_all || saved_lc_all != NULL);
        vcs_toolchain_capsule_v1_cache_reset_for_test();
        ASSERT(vcs_toolchain_capsule_v1_capture(&first));
        ASSERT(vcs_toolchain_capsule_v1_capture(&second));
        ASSERT(vcs_toolchain_capsule_v1_root(&first, first_root));
        ASSERT(vcs_toolchain_capsule_v1_root(&second, second_root));
        ASSERT(memcmp(first_root, second_root, sizeof(first_root)) == 0);
        vcs_toolchain_capsule_v1_cache_stats_for_test(&fresh, &hits);
        ASSERT_EQ(fresh, 1u);
        ASSERT_EQ(hits, 1u);
        bool changed_ok = setenv(
            "LC_ALL", old_lc_all && strcmp(old_lc_all, "C") == 0
                ? "POSIX" : "C", 1) == 0;
        changed_ok = changed_ok &&
            vcs_toolchain_capsule_v1_capture(&changed_environment) &&
            vcs_toolchain_capsule_v1_root(&changed_environment,
                                           changed_root) &&
            memcmp(first_root, changed_root, sizeof(first_root)) == 0;
        vcs_toolchain_capsule_v1_cache_stats_for_test(&fresh, &hits);
        bool restored = false;
        if (saved_lc_all) {
            restored = setenv("LC_ALL", saved_lc_all, 1) == 0;
            free(saved_lc_all);
        } else {
            restored = unsetenv("LC_ALL") == 0;
        }
        vcs_toolchain_capsule_v1_cache_reset_for_test();
        ASSERT(changed_ok && restored);
        ASSERT_EQ(fresh, 2u);
        ASSERT_EQ(hits, 1u);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bf_assembler_identity_is_version(void)
{
    int failures = 0;
    TEST("build_fabric: assembler identity is GNU as --version, not file bytes") {
        struct vcs_toolchain_capsule_v1 capsule;
        uint8_t file_sha3[32];
        FILE *f;
        vcs_toolchain_capsule_v1_cache_reset_for_test();
        ASSERT(vcs_toolchain_capsule_v1_capture(&capsule));
        f = fopen("/usr/bin/as", "rb");
        ASSERT(f != NULL);
        {
            struct sha3_256_ctx sha;
            uint8_t buf[65536];
            size_t got;
            sha3_256_init(&sha);
            while ((got = fread(buf, 1, sizeof(buf), f)) > 0)
                sha3_256_write(&sha, buf, got);
            ASSERT(ferror(f) == 0);
            sha3_256_finalize(&sha, file_sha3);
        }
        ASSERT(fclose(f) == 0);
        ASSERT(memcmp(capsule.assembler_sha3, file_sha3, 32) != 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bf_confined_test_worker(void)
{
    int failures = 0;
    TEST("build_fabric: fixed test action executes one exact binary and signs evidence") {
        struct node_db ndb;
        char dir[256], path[320];
        ASSERT(bf_open(&ndb, dir, sizeof(dir), path, sizeof(path),
                       "test-worker"));
        ASSERT(vcs_object_store_init(dir));
        size_t input_len = 0;
        uint8_t *input = bf_read_fixture("/usr/bin/true", &input_len);
        ASSERT(input && input_len > 20);
        uint8_t input_root[32];
        sha3_256(input, input_len, input_root);
        ASSERT(vcs_object_put_addressed(dir, input_root, input, input_len));
        free(input);

        struct vcs_toolchain_capsule_v1 capsule;
        uint8_t capsule_root[32];
        ASSERT(vcs_toolchain_capsule_v1_capture(&capsule));
        ASSERT(vcs_toolchain_capsule_v1_root(&capsule, capsule_root));
        struct db_build_job job;
        struct db_build_action action;
        bf_job(&job);
        bf_action(&action);
        (void)snprintf(action.kind, sizeof(action.kind), "%s",
                       VCS_BUILD_ACTION_KIND_TEST_V1);
        zcl_hex_encode(capsule_root, 32, job.toolchain_sha3);
        zcl_hex_encode(input_root, 32, action.input_root_sha3);
        uint8_t fixed_flags[32], fixed_environment[32];
        ASSERT(vcs_build_action_v1_fixed_flags_root_for_kind(
            action.kind, fixed_flags));
        ASSERT(vcs_build_action_v1_fixed_environment_root_for_kind(
            action.kind, fixed_environment));
        zcl_hex_encode(fixed_flags, 32, action.flags_sha3);
        zcl_hex_encode(fixed_environment, 32, action.environment_sha3);
        (void)snprintf(action.virtual_workdir,
                       sizeof(action.virtual_workdir), "%s",
                       VCS_BUILD_PACKAGE_VIRTUAL_ROOT_V1);
        (void)snprintf(action.declared_outputs,
                       sizeof(action.declared_outputs), "%s",
                       VCS_BUILD_TEST_OUTPUT_V1);
        (void)snprintf(action.resource_policy,
                       sizeof(action.resource_policy), "%s",
                       VCS_BUILD_TEST_RESOURCE_POLICY_V1);
        ASSERT(bf_canonicalize(&job, &action));
        char action_id[65];
        (void)snprintf(action_id, sizeof(action_id), "%s", action.action_id);
        ASSERT(build_fabric_plan(&ndb, &job, &action).ok);
        int64_t now = (int64_t)platform_time_wall_unix();
        ASSERT(build_fabric_submit(&ndb, job.job_id, now).ok);

        uint8_t seed[32], pubkey[32], secret[32];
        memset(seed, 31, sizeof(seed));
        ed25519_keypair(pubkey, secret, seed);
        struct db_build_worker worker;
        bf_worker(&worker);
        zcl_hex_encode(pubkey, 32, worker.signer_pubkey);
        ASSERT(build_fabric_worker_approve(&ndb, &worker, now).ok);
        bool claimed = false;
        ASSERT(build_fabric_claim(&ndb, worker.worker_id, id_d, now, 300,
                                  &action, &claimed).ok);
        ASSERT(claimed);
        struct db_build_receipt receipt;
        struct zcl_result executed = build_fabric_worker_execute(
            &ndb, dir, dir, action_id, id_d, secret, pubkey, &receipt, NULL);
        if (!executed.ok) printf("test worker detail: %s\n", executed.message);
        ASSERT(executed.ok);
        ASSERT_EQ(receipt.exit_status, 0);
        ASSERT(receipt.work_receipt_sha3[0] == '\0');
        ASSERT(db_build_action_find(&ndb, action_id, &action));
        ASSERT_STR_EQ(action.state, "VERIFYING");
        ASSERT(build_fabric_receipt_admit(
            &ndb, dir, receipt.receipt_id, now + 1).ok);
        ASSERT(db_build_action_find(&ndb, action_id, &action));
        ASSERT_STR_EQ(action.state, "ACCEPTED");

        uint8_t manifest_root[32];
        ASSERT(zcl_hex_decode_lower(receipt.output_sha3, manifest_root, 32));
        uint8_t *wire = NULL;
        size_t wire_len = 0;
        ASSERT_EQ(vcs_object_load_raw(dir, manifest_root, &wire, &wire_len), 0);
        struct vcs_build_artifact_manifest_v1 manifest;
        ASSERT(vcs_build_artifact_manifest_v1_parse(wire, wire_len, &manifest));
        free(wire);
        ASSERT_EQ(manifest.chunk_count, 1);
        uint8_t *evidence = NULL;
        size_t evidence_len = 0;
        ASSERT_EQ(vcs_object_load_raw(dir, manifest.chunk_sha3[0], &evidence,
                                      &evidence_len), 0);
        ASSERT_EQ(evidence_len, 84);
        ASSERT(memcmp(evidence, "ZCTEST\r\n", 8) == 0 &&
               evidence[8] == 1 && evidence[10] == 1);
        free(evidence);
        node_db_close(&ndb);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bf_native(void)
{
    int failures = 0;
    TEST("build_fabric: native plan and read-only status share the service") {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "build_fabric", "native");
        struct json_value input;
        json_init(&input); json_set_object(&input);
        (void)json_push_kv_str(&input, "source_sha256", id_a);
        (void)json_push_kv_str(&input, "source_cas_sha3", id_b);
        (void)json_push_kv_str(&input, "toolchain_sha3", id_c);
        (void)json_push_kv_str(&input, "input_root_sha3", id_d);
        uint8_t native_flags[32], native_environment[32];
        char native_flags_hex[65], native_environment_hex[65];
        vcs_build_action_v1_fixed_flags_root(native_flags);
        vcs_build_action_v1_fixed_environment_root(native_environment);
        zcl_hex_encode(native_flags, 32, native_flags_hex);
        zcl_hex_encode(native_environment, 32, native_environment_hex);
        (void)json_push_kv_str(&input, "flags_sha3", native_flags_hex);
        (void)json_push_kv_str(&input, "environment_sha3",
                               native_environment_hex);
        (void)json_push_kv_str(&input, "profile", "dev");
        (void)json_push_kv_str(&input, "datadir", dir);
        struct zcl_command_request request = { .input = &input };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.build_plan.v1");
        zcl_native_handle_metaverse_build_plan(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        const struct json_value *job = json_get(&reply.data, "job");
        const char *returned_id = json_get_str(json_get(job, "job_id"));
        ASSERT(returned_id && strlen(returned_id) == 64);
        char job_id[65];
        (void)snprintf(job_id, sizeof(job_id), "%s", returned_id);
        zcl_command_reply_free(&reply);
        json_free(&input);

        json_init(&input); json_set_object(&input);
        (void)json_push_kv_str(&input, "job_id", job_id);
        (void)json_push_kv_str(&input, "datadir", dir);
        request.input = &input;
        zcl_command_reply_init(&reply, "zcl.build_status.v1");
        zcl_native_handle_metaverse_build_status(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "state")), "PLANNED");
        ASSERT_EQ(json_get_int(json_get(&reply.data, "action_count")), 1);
        const struct json_value *actions = json_get(&reply.data, "actions");
        ASSERT(actions && actions->type == JSON_ARR &&
               actions->num_children == 1);
        ASSERT_STR_EQ(json_get_str(json_get(json_at(actions, 0), "kind")),
                     "c23.compile.preprocessed.v1");
        zcl_command_reply_free(&reply);
        json_free(&input);

        char db_path[320];
        (void)snprintf(db_path, sizeof(db_path), "%s/node.db", dir);
        struct node_db api_db;
        memset(&api_db, 0, sizeof(api_db));
        ASSERT(node_db_open(&api_db, db_path));
        api_set_state(NULL, NULL, NULL, &api_db, dir);
        ASSERT(api_route_is_operator_private("/api/v1/builds"));
        ASSERT(api_route_is_operator_private("/api/v1/builds/abc/actions"));
        ASSERT(api_route_is_operator_private("/api/v1/build_workers"));
        ASSERT(api_route_is_operator_private("/api/v1/build_receipts/abc"));
        uint8_t response[16384];
        size_t response_len = api_handle_request(
            "GET", "/api/v1/builds", NULL, 0, response, sizeof(response));
        ASSERT(response_len > 0 && response_len < sizeof(response));
        response[response_len] = '\0';
        ASSERT(strstr((char *)response, "HTTP/1.1 200 OK") != NULL);
        ASSERT(strstr((char *)response, "zcl.builds.index.v1") != NULL);
        char member_path[128];
        (void)snprintf(member_path, sizeof(member_path),
                       "/api/v1/builds/%s/actions", job_id);
        response_len = api_handle_request("GET", member_path, NULL, 0,
                                          response, sizeof(response));
        ASSERT(response_len > 0 && response_len < sizeof(response));
        response[response_len] = '\0';
        ASSERT(strstr((char *)response, "zcl.build_actions.index.v1") != NULL);
        api_set_state(NULL, NULL, NULL, NULL, NULL);
        node_db_close(&api_db);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bf_runtime_dump(void)
{
    int failures = 0;
    TEST("build_fabric: runtime diagnostics publish ceilings and supervision") {
        struct json_value state;
        json_init(&state);
        ASSERT(build_fabric_dump_state_json(&state, NULL));
        ASSERT_STR_EQ(json_get_str(json_get(&state, "schema")),
                      "zcl.build_fabric_state.v1");
        ASSERT_EQ(json_get_int(json_get(&state, "max_actions_per_job")), 256);
        ASSERT_EQ(json_get_int(json_get(&state, "worker_cpu_limit")), 1);
        ASSERT(!json_get_bool(json_get(&state, "worker_network_allowed")));
        const struct json_value *health = json_get(&state, "_health");
        ASSERT(health && health->type == JSON_OBJ);
        json_free(&state);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bf_content_contracts(void)
{
    int failures = 0;
    TEST("build_fabric: capsules, actions, and artifact chunks are content-bound") {
        struct vcs_toolchain_capsule_v1 capsule = {0};
        memset(capsule.compiler_driver_sha3, 1, 32);
        memset(capsule.compiler_backend_sha3, 2, 32);
        memset(capsule.assembler_sha3, 3, 32);
        memset(capsule.sysroot_sha3, 4, 32);
        memset(capsule.target_probes_sha3, 5, 32);
        memset(capsule.abi_files_sha3, 6, 32);
        (void)snprintf(capsule.target, sizeof(capsule.target), "%s",
                       VCS_BUILD_TARGET_V1);
        uint8_t capsule_a[32], capsule_b[32];
        ASSERT(vcs_toolchain_capsule_v1_root(&capsule, capsule_a));
        capsule.compiler_backend_sha3[0] ^= 1;
        ASSERT(vcs_toolchain_capsule_v1_root(&capsule, capsule_b));
        ASSERT(memcmp(capsule_a, capsule_b, 32) != 0);

        struct vcs_build_action_v1 action = {0};
        memset(action.source_sha256, 1, 32);
        memset(action.source_cas_sha3, 2, 32);
        memset(action.input_root_sha3, 3, 32);
        memcpy(action.toolchain_capsule_sha3, capsule_b, 32);
        memset(action.flags_sha3, 4, 32);
        memset(action.environment_sha3, 5, 32);
        (void)snprintf(action.target, sizeof(action.target), "%s",
                       VCS_BUILD_TARGET_V1);
        (void)snprintf(action.profile, sizeof(action.profile), "dev");
        (void)snprintf(action.virtual_workdir,
                       sizeof(action.virtual_workdir), "%s",
                       VCS_BUILD_VIRTUAL_ROOT_V1);
        (void)snprintf(action.declared_outputs,
                       sizeof(action.declared_outputs), "%s",
                       VCS_BUILD_OUTPUT_V1);
        (void)snprintf(action.resource_policy,
                       sizeof(action.resource_policy), "%s",
                       VCS_BUILD_RESOURCE_POLICY_V1);
        uint8_t action_a[32], action_b[32];
        ASSERT(vcs_build_action_v1_root(&action, action_a));
        action.environment_sha3[0] ^= 1;
        ASSERT(vcs_build_action_v1_root(&action, action_b));
        ASSERT(memcmp(action_a, action_b, 32) != 0);
        ASSERT_EQ(vcs_build_action_v1_work_kind(VCS_BUILD_ACTION_KIND_V1),
                  VCS_ZCODE_WORK_BUILD);
        ASSERT_EQ(vcs_build_action_v1_work_kind(
                      VCS_BUILD_ACTION_KIND_PACKAGE_V1),
                  VCS_ZCODE_WORK_BUILD);
        ASSERT_EQ(vcs_build_action_v1_work_kind(
                      VCS_BUILD_ACTION_KIND_TEST_V1),
                  VCS_ZCODE_WORK_TEST);
        ASSERT_EQ(vcs_build_action_v1_work_kind(
                      VCS_BUILD_ACTION_KIND_FUZZ_V1),
                  VCS_ZCODE_WORK_FUZZ);
        ASSERT_EQ(vcs_build_action_v1_work_kind(
                      VCS_BUILD_ACTION_KIND_REVIEW_V1),
                  VCS_ZCODE_WORK_REVIEW);
        ASSERT_EQ(vcs_build_action_v1_work_kind(
                      VCS_BUILD_ACTION_KIND_RESIDENT_PROOF_CHILD_V1),
                  0);
        ASSERT_EQ(vcs_build_action_v1_work_kind("c23.shell.v1"), 0);
        uint8_t test_flags[32], test_env[32], test_action[32];
        ASSERT(vcs_build_action_v1_fixed_flags_root_for_kind(
            VCS_BUILD_ACTION_KIND_TEST_V1, test_flags));
        ASSERT(vcs_build_action_v1_fixed_environment_root_for_kind(
            VCS_BUILD_ACTION_KIND_TEST_V1, test_env));
        memcpy(action.flags_sha3, test_flags, 32);
        memcpy(action.environment_sha3, test_env, 32);
        (void)snprintf(action.virtual_workdir,
                       sizeof(action.virtual_workdir), "%s",
                       VCS_BUILD_PACKAGE_VIRTUAL_ROOT_V1);
        (void)snprintf(action.declared_outputs,
                       sizeof(action.declared_outputs), "%s",
                       VCS_BUILD_TEST_OUTPUT_V1);
        (void)snprintf(action.resource_policy,
                       sizeof(action.resource_policy), "%s",
                       VCS_BUILD_TEST_RESOURCE_POLICY_V1);
        ASSERT(vcs_build_action_v1_root_for_kind(
            VCS_BUILD_ACTION_KIND_TEST_V1, &action, test_action));
        ASSERT(memcmp(action_b, test_action, 32) != 0);
        ASSERT(!vcs_build_action_v1_root_for_kind(
            "c23.shell.v1", &action, test_action));

        uint8_t proof_action_a[32], proof_action_b[32];
        ASSERT(!vcs_build_action_v1_fixed_flags_root_for_kind(
            VCS_BUILD_ACTION_KIND_RESIDENT_PROOF_CHILD_V1, proof_action_a));
        ASSERT(!vcs_build_action_v1_fixed_environment_root_for_kind(
            VCS_BUILD_ACTION_KIND_RESIDENT_PROOF_CHILD_V1,
            proof_action_a));
        (void)snprintf(action.profile, sizeof(action.profile),
                       "resident-proof-child-v1");
        (void)snprintf(action.virtual_workdir,
                       sizeof(action.virtual_workdir), "%s",
                       VCS_BUILD_RESIDENT_PROOF_VIRTUAL_ROOT_V1);
        (void)snprintf(action.declared_outputs,
                       sizeof(action.declared_outputs), "%s",
                       VCS_BUILD_RESIDENT_PROOF_OUTPUT_V1);
        (void)snprintf(action.resource_policy,
                       sizeof(action.resource_policy), "%s",
                       VCS_BUILD_RESIDENT_PROOF_RESOURCE_POLICY_V1);
        action.sequence = 3;
        ASSERT(vcs_build_action_v1_root_for_kind(
            VCS_BUILD_ACTION_KIND_RESIDENT_PROOF_CHILD_V1,
            &action, proof_action_a));
        ASSERT(vcs_build_action_v1_root_for_kind(
            VCS_BUILD_ACTION_KIND_RESIDENT_PROOF_CHILD_V1,
            &action, proof_action_b));
        ASSERT(memcmp(proof_action_a, proof_action_b, 32) == 0);
        action.input_root_sha3[0] ^= 1;
        ASSERT(vcs_build_action_v1_root_for_kind(
            VCS_BUILD_ACTION_KIND_RESIDENT_PROOF_CHILD_V1,
            &action, proof_action_b));
        ASSERT(memcmp(proof_action_a, proof_action_b, 32) != 0);
        action.input_root_sha3[0] ^= 1;
        action.sequence = 2;
        ASSERT(vcs_build_action_v1_root_for_kind(
            VCS_BUILD_ACTION_KIND_RESIDENT_PROOF_CHILD_V1,
            &action, proof_action_b));
        ASSERT(memcmp(proof_action_a, proof_action_b, 32) != 0);

        const uint8_t chunks[2][3] = {{'a','b','c'}, {'d','e','f'}};
        struct vcs_build_artifact_manifest_v1 manifest = {0}, parsed = {0};
        memcpy(manifest.action_sha3, action_b, 32);
        manifest.total_bytes = 6;
        manifest.chunk_bytes = 3;
        manifest.chunk_count = 2;
        sha3_256(chunks[0], sizeof(chunks[0]), manifest.chunk_sha3[0]);
        sha3_256(chunks[1], sizeof(chunks[1]), manifest.chunk_sha3[1]);
        uint8_t root[32], wire[VCS_BUILD_ARTIFACT_WIRE_MAX];
        size_t wire_len = 0;
        ASSERT(vcs_build_artifact_manifest_v1_root(&manifest, root));
        ASSERT(vcs_build_artifact_manifest_v1_serialize(
            &manifest, wire, sizeof(wire), &wire_len));
        ASSERT(vcs_build_artifact_manifest_v1_parse(wire, wire_len, &parsed));
        ASSERT(vcs_build_artifact_manifest_v1_verify_chunk(
            &parsed, 1, chunks[1], sizeof(chunks[1])));
        uint8_t corrupt[3] = {'d','e','x'};
        ASSERT(!vcs_build_artifact_manifest_v1_verify_chunk(
            &parsed, 1, corrupt, sizeof(corrupt)));
        manifest.total_bytes = VCS_BUILD_ARTIFACT_MAX_BYTES + 1;
        ASSERT(!vcs_build_artifact_manifest_v1_valid(&manifest));
        ASSERT_EQ(VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES,
                  UINT64_C(64) * 1024u * 1024u);
        ASSERT(VCS_BUILD_ARTIFACT_MAX_BYTES >
               VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bf_proof_materialization(void)
{
    int failures = 0;
    TEST("build_fabric: proof materialization stores evidence without trust promotion") {
        struct node_db ndb;
        char dir[256], path[320];
        ASSERT(bf_open(&ndb, dir, sizeof(dir), path, sizeof(path),
                       "proof_materialize"));
        ASSERT(vcs_object_store_init(dir));
        int64_t now = 2000;
        static const uint8_t source[] = "proof-materialization-source";
        uint8_t source_root[32];
        sha3_256(source, sizeof(source) - 1u, source_root);
        struct test_accepted_work_fixture fixture;
        ASSERT(test_accepted_work_fixture_create(
            dir, source_root, now, 0x35, &fixture));

        struct db_build_job job;
        struct db_build_action action;
        bf_job(&job);
        bf_action(&action);
        zcl_hex_encode(source_root, 32, job.source_cas_sha3);
        zcl_hex_encode(fixture.accepted.task.toolchain_capsule_root, 32,
                       job.toolchain_sha3);
        zcl_hex_encode(source_root, 32, action.input_root_sha3);
        zcl_hex_encode(fixture.accepted.task_root, 32,
                       action.task_root_sha3);
        zcl_hex_encode(fixture.accepted.candidate_root, 32,
                       action.candidate_root_sha3);
        zcl_hex_encode(fixture.accepted.proof_policy_root, 32,
                       action.proof_policy_root_sha3);
        ASSERT(bf_canonicalize(&job, &action));
        ASSERT(build_fabric_plan(&ndb, &job, &action).ok);

        uint8_t task_wire[VCS_ZCODE_TASK_WIRE_BYTES];
        uint8_t candidate_wire[VCS_ZCODE_CANDIDATE_WIRE_BYTES];
        uint8_t policy_wire[VCS_ZCODE_PROOF_POLICY_WIRE_BYTES];
        ASSERT_EQ(vcs_zcode_task_serialize(
            &fixture.accepted.task, task_wire), VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_candidate_serialize(
            &fixture.accepted.candidate, candidate_wire),
            VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_proof_policy_serialize(
            &fixture.accepted.policy, policy_wire), VCS_ZCODE_DEV_OK);
        uint8_t misaddressed_authority[3][32];
        memset(misaddressed_authority[0], 0xf1, 32);
        memset(misaddressed_authority[1], 0xf2, 32);
        memset(misaddressed_authority[2], 0xf3, 32);
        ASSERT(vcs_object_put_addressed(
            dir, misaddressed_authority[0], task_wire, sizeof(task_wire)));
        ASSERT(vcs_object_put_addressed(
            dir, misaddressed_authority[1], candidate_wire,
            sizeof(candidate_wire)));
        ASSERT(vcs_object_put_addressed(
            dir, misaddressed_authority[2], policy_wire,
            sizeof(policy_wire)));
        for (size_t i = 0; i < 3; i++) {
            struct db_build_job bad_job = job;
            struct db_build_action bad_action = action;
            bad_action.sequence = (int64_t)i + 1;
            if (i == 0)
                zcl_hex_encode(misaddressed_authority[i], 32,
                               bad_action.task_root_sha3);
            else if (i == 1)
                zcl_hex_encode(misaddressed_authority[i], 32,
                               bad_action.candidate_root_sha3);
            else
                zcl_hex_encode(misaddressed_authority[i], 32,
                               bad_action.proof_policy_root_sha3);
            ASSERT(bf_canonicalize(&bad_job, &bad_action));
            ASSERT(build_fabric_plan(&ndb, &bad_job, &bad_action).ok);
            struct build_fabric_proof_evaluation rejected = {0};
            ASSERT(!build_fabric_proof_evaluate_readonly(
                &ndb, dir, bad_action.action_id, now, &rejected).ok);
        }

        struct db_build_worker worker;
        bf_worker(&worker);
        bf_worker_id_from_pubkey(fixture.signer_pubkey, worker.worker_id);
        zcl_hex_encode(fixture.signer_pubkey, 32, worker.signer_pubkey);
        worker.approved_at = now - 30;
        worker.last_seen_at = now - 30;
        ASSERT(db_build_worker_save(&ndb, &worker));

        struct vcs_zcode_work_receipt_v1 work = {
            .schema_version = VCS_ZCODE_DEV_VERSION,
            .work_kind = VCS_ZCODE_WORK_BUILD,
            .status = VCS_ZCODE_WORK_PASS,
            .exit_status = 0,
            .started_unix = now - 20,
            .finished_unix = now - 10,
        };
        memcpy(work.task_root, fixture.accepted.task_root, 32);
        memcpy(work.candidate_root, fixture.accepted.candidate_root, 32);
        ASSERT(zcl_hex_decode_lower(action.action_id, work.action_root, 32));
        memcpy(work.input_root, source_root, 32);
        memcpy(work.proof_policy_root,
               fixture.accepted.proof_policy_root, 32);
        memcpy(work.toolchain_capsule_root,
               fixture.accepted.task.toolchain_capsule_root, 32);
        memset(work.output_root, 0xd1, 32);
        memset(work.lease_id, 0xd2, 32);
        memset(work.confinement_root, 0xd4, 32);
        struct vcs_build_execution_observation_v1 observation = {
            .schema_version = VCS_BUILD_EXECUTION_OBSERVATION_VERSION,
            .flags = VCS_BUILD_OBS_REQUIRED_FLAGS,
            .exit_status = 0,
            .cpu_seconds_limit = 120,
            .memory_bytes_limit = UINT64_C(2048) * 1024u * 1024u,
            .process_limit = 16,
            .file_limit = 64,
            .file_bytes_limit = UINT64_C(256) * 1024u * 1024u,
            .output_bytes_limit = UINT64_C(256) * 1024u * 1024u,
            .wall_millis_limit = 120000,
        };
        memcpy(observation.action_root, work.action_root, 32);
        memcpy(observation.action_input_root, work.input_root, 32);
        memset(observation.observed_input_bytes_root, 0xc1, 32);
        memcpy(observation.artifact_root, work.output_root, 32);
        memset(observation.output_bytes_root, 0xc2, 32);
        memcpy(observation.toolchain_root,
               work.toolchain_capsule_root, 32);
        ASSERT(zcl_hex_decode_lower(
            action.flags_sha3, observation.flags_root, 32));
        ASSERT(zcl_hex_decode_lower(
            action.environment_sha3, observation.environment_root, 32));
        vcs_build_execution_read_set_root(
            observation.action_input_root,
            observation.observed_input_bytes_root,
            observation.toolchain_root,
            observation.declared_reads_root);
        memcpy(observation.observed_reads_root,
               observation.declared_reads_root, 32);
        vcs_build_execution_declared_write_set_root(
            action.declared_outputs, observation.declared_writes_root);
        vcs_build_execution_observed_write_set_root(
            action.declared_outputs, observation.output_bytes_root,
            observation.observed_writes_root);
        ASSERT(vcs_build_execution_observation_v1_root(
            &observation, work.evidence_root));
        uint8_t work_wire[VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES];
        uint8_t work_root[32];
        ASSERT_EQ(vcs_zcode_work_receipt_seal(
            &work, fixture.signer_secret, fixture.signer_pubkey),
            VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_work_receipt_validate_for_candidate(
            &fixture.accepted.task, &fixture.accepted.candidate,
            &work, now), VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_work_receipt_serialize(&work, work_wire),
                  VCS_ZCODE_DEV_OK);
        ASSERT_EQ(vcs_zcode_work_receipt_id(&work, work_root),
                  VCS_ZCODE_DEV_OK);
        ASSERT(vcs_object_put_addressed(
            dir, work_root, work_wire, sizeof(work_wire)));

        struct db_build_receipt row = {0};
        zcl_hex_encode(work_root, 32, row.receipt_id);
        (void)snprintf(row.action_id, sizeof(row.action_id), "%s",
                       action.action_id);
        (void)snprintf(row.job_id, sizeof(row.job_id), "%s", job.job_id);
        (void)snprintf(row.worker_id, sizeof(row.worker_id), "%s",
                       worker.worker_id);
        zcl_hex_encode(work.lease_id, 32, row.lease_id);
        (void)snprintf(row.action_sha3, sizeof(row.action_sha3), "%s",
                       action.action_id);
        zcl_hex_encode(work.output_root, 32, row.output_sha3);
        (void)snprintf(row.work_receipt_sha3,
                       sizeof(row.work_receipt_sha3), "%s", row.receipt_id);
        zcl_hex_encode(work.signature, 64, row.signature);
        zcl_hex_encode(work.evidence_root, 32, row.observation_sha3);
        (void)snprintf(row.confinement, sizeof(row.confinement),
                       "test=canonical-proof-materialization");
        (void)snprintf(row.trust_state, sizeof(row.trust_state),
                       "REMOTE_OBSERVED");
        row.created_at = work.finished_unix;
        ASSERT(db_build_receipt_save(&ndb, &row));

        int db_changes = sqlite3_total_changes(ndb.db);
        struct build_fabric_proof_evaluation readonly = {0};
        ASSERT(build_fabric_proof_evaluate_readonly(
            &ndb, dir, action.action_id, now, &readonly).ok);
        ASSERT_EQ(sqlite3_total_changes(ndb.db), db_changes);
        ASSERT_EQ(readonly.valid_receipts, 0);
        ASSERT(readonly.proof_set_root_sha3[0] == '\0');

        uint8_t observation_wire[
            VCS_BUILD_EXECUTION_OBSERVATION_WIRE_BYTES];
        ASSERT(vcs_build_execution_observation_v1_serialize(
            &observation, observation_wire));
        observation_wire[16] ^= 1u;
        ASSERT(vcs_object_put_addressed(
            dir, work.evidence_root, observation_wire,
            sizeof(observation_wire)));
        memset(&readonly, 0, sizeof(readonly));
        ASSERT(build_fabric_proof_evaluate_readonly(
            &ndb, dir, action.action_id, now, &readonly).ok);
        ASSERT_EQ(sqlite3_total_changes(ndb.db), db_changes);
        ASSERT_EQ(readonly.valid_receipts, 0);
        ASSERT(readonly.proof_set_root_sha3[0] == '\0');

        ASSERT(vcs_build_execution_observation_v1_serialize(
            &observation, observation_wire));
        bool repaired = false;
        ASSERT(vcs_object_put_addressed_repair(
            dir, work.evidence_root, observation_wire,
            sizeof(observation_wire), &repaired));
        ASSERT(repaired);
        uint8_t misaddressed_receipt_root[32];
        memset(misaddressed_receipt_root, 0xf4, 32);
        ASSERT(vcs_object_put_addressed(
            dir, misaddressed_receipt_root, work_wire,
            sizeof(work_wire)));
        zcl_hex_encode(misaddressed_receipt_root, 32,
                       row.work_receipt_sha3);
        ASSERT(db_build_receipt_save(&ndb, &row));
        db_changes = sqlite3_total_changes(ndb.db);
        memset(&readonly, 0, sizeof(readonly));
        ASSERT(build_fabric_proof_evaluate_readonly(
            &ndb, dir, action.action_id, now, &readonly).ok);
        ASSERT_EQ(sqlite3_total_changes(ndb.db), db_changes);
        ASSERT_EQ(readonly.valid_receipts, 0);
        ASSERT(readonly.proof_set_root_sha3[0] == '\0');
        struct build_fabric_proof_evaluation refused_materialization = {0};
        ASSERT(build_fabric_proof_materialize(
            &ndb, dir, action.action_id, now,
            &refused_materialization).ok);
        ASSERT_EQ(sqlite3_total_changes(ndb.db), db_changes);
        ASSERT_EQ(refused_materialization.valid_receipts, 0);
        ASSERT(refused_materialization.proof_set_root_sha3[0] == '\0');
        (void)snprintf(row.work_receipt_sha3,
                       sizeof(row.work_receipt_sha3), "%s",
                       row.receipt_id);
        ASSERT(db_build_receipt_save(&ndb, &row));
        db_changes = sqlite3_total_changes(ndb.db);
        memset(&readonly, 0, sizeof(readonly));
        ASSERT(build_fabric_proof_evaluate_readonly(
            &ndb, dir, action.action_id, now, &readonly).ok);
        ASSERT_EQ(sqlite3_total_changes(ndb.db), db_changes);
        ASSERT_EQ(readonly.valid_receipts, 1);
        ASSERT_EQ(readonly.compile_receipts, 1);
        ASSERT(strlen(readonly.proof_set_root_sha3) == 64);
        uint8_t proof_root[32];
        ASSERT(zcl_hex_decode_lower(
            readonly.proof_set_root_sha3, proof_root, 32));
        ASSERT(!vcs_object_has(dir, proof_root));
        struct db_build_receipt observed;
        ASSERT(db_build_receipt_find(&ndb, row.receipt_id, &observed));
        ASSERT_STR_EQ(observed.trust_state, "REMOTE_OBSERVED");

        struct db_build_worker alias_worker = worker;
        uint8_t alias_pubkey[32];
        memset(alias_pubkey, 0xa7, sizeof(alias_pubkey));
        bf_worker_id_from_pubkey(alias_pubkey, alias_worker.worker_id);
        zcl_hex_encode(alias_pubkey, sizeof(alias_pubkey),
                       alias_worker.signer_pubkey);
        ASSERT(db_build_worker_save(&ndb, &alias_worker));
        (void)snprintf(row.worker_id, sizeof(row.worker_id), "%s",
                       alias_worker.worker_id);
        ASSERT(db_build_receipt_save(&ndb, &row));
        struct build_fabric_proof_evaluation corrupted_projection = {0};
        ASSERT(build_fabric_proof_evaluate_readonly(
            &ndb, dir, action.action_id, now, &corrupted_projection).ok);
        ASSERT_EQ(corrupted_projection.valid_receipts, 0);
        (void)snprintf(row.worker_id, sizeof(row.worker_id), "%s",
                       worker.worker_id);
        ASSERT(db_build_receipt_save(&ndb, &row));
        db_changes = sqlite3_total_changes(ndb.db);

        struct build_fabric_proof_evaluation materialized = {0};
        ASSERT(build_fabric_proof_materialize(
            &ndb, dir, action.action_id, now, &materialized).ok);
        ASSERT_EQ(sqlite3_total_changes(ndb.db), db_changes);
        ASSERT_STR_EQ(materialized.proof_set_root_sha3,
                      readonly.proof_set_root_sha3);
        ASSERT(vcs_object_has(dir, proof_root));
        uint8_t *stored = NULL;
        size_t stored_len = 0;
        ASSERT_EQ(vcs_object_load_raw(
            dir, proof_root, &stored, &stored_len), 0);
        uint8_t stored_roots[VCS_ZCODE_PROOF_SET_MAX_RECEIPTS][32];
        size_t stored_count = 0;
        ASSERT_EQ(vcs_zcode_proof_set_parse(
            stored, stored_len, stored_roots,
            VCS_ZCODE_PROOF_SET_MAX_RECEIPTS, &stored_count),
            VCS_ZCODE_DEV_OK);
        ASSERT_EQ(stored_count, 1);
        ASSERT(memcmp(stored_roots[0], work_root, 32) == 0);
        ASSERT(db_build_receipt_find(&ndb, row.receipt_id, &observed));
        ASSERT_STR_EQ(observed.trust_state, "REMOTE_OBSERVED");

        struct build_fabric_proof_evaluation repeated = {0};
        ASSERT(build_fabric_proof_materialize(
            &ndb, dir, action.action_id, now, &repeated).ok);
        ASSERT_EQ(sqlite3_total_changes(ndb.db), db_changes);
        ASSERT_STR_EQ(repeated.proof_set_root_sha3,
                      materialized.proof_set_root_sha3);
        uint8_t *stored_again = NULL;
        size_t stored_again_len = 0;
        ASSERT_EQ(vcs_object_load_raw(
            dir, proof_root, &stored_again, &stored_again_len), 0);
        ASSERT_EQ(stored_again_len, stored_len);
        ASSERT(memcmp(stored_again, stored, stored_len) == 0);
        free(stored_again);
        free(stored);
        ASSERT(db_build_receipt_find(&ndb, row.receipt_id, &observed));
        ASSERT_STR_EQ(observed.trust_state, "REMOTE_OBSERVED");

        struct build_fabric_proof_evaluation authoritative = {0};
        ASSERT(build_fabric_proof_evaluate(
            &ndb, dir, action.action_id, now, &authoritative).ok);
        ASSERT(sqlite3_total_changes(ndb.db) > db_changes);
        ASSERT_STR_EQ(authoritative.proof_set_root_sha3,
                      materialized.proof_set_root_sha3);
        ASSERT(db_build_receipt_find(&ndb, row.receipt_id, &observed));
        ASSERT_STR_EQ(observed.trust_state, "QUORUM_MATCHED");

        struct db_build_receipt filler = row;
        filler.work_receipt_sha3[0] = '\0';
        filler.created_at = now + 1;
        for (size_t i = 0; i < VCS_ZCODE_PROOF_SET_MAX_RECEIPTS; i++) {
            uint8_t filler_root[32];
            sha3_256((const uint8_t *)&i, sizeof(i), filler_root);
            zcl_hex_encode(filler_root, sizeof(filler_root), filler.receipt_id);
            if (strcmp(filler.receipt_id, row.receipt_id) == 0)
                continue;
            ASSERT(db_build_receipt_save(&ndb, &filler));
            if (i + 2u == VCS_ZCODE_PROOF_SET_MAX_RECEIPTS) {
                struct build_fabric_proof_evaluation bounded = {0};
                ASSERT(build_fabric_proof_evaluate_readonly(
                    &ndb, dir, action.action_id, now, &bounded).ok);
                ASSERT_EQ(bounded.valid_receipts, 1);
            }
        }
        struct build_fabric_proof_evaluation truncated = {0};
        ASSERT(!build_fabric_proof_evaluate_readonly(
            &ndb, dir, action.action_id, now, &truncated).ok);
        node_db_close(&ndb);
        test_rm_rf(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int test_bf_subordinate_work_admission(void)
{
    int failures = 0;
    TEST("build worker defers before lease claim on every blockchain pressure fact") {
        struct subordinate_work_facts facts = {
            .running = true,
            .sync_at_tip = true,
            .disk_clear = true,
            .memory_clear = true,
            .db_long_operation_clear = true,
            .persistence_ready = true,
            .db_open = true,
            .db_transaction_clear = true,
            .db_turbo_clear = true,
            .db_pending_blocks_clear = true,
        };
        ASSERT(subordinate_work_admission_decide(&facts) ==
               SUBORDINATE_WORK_ADMIT);
#define BF_REFUSES(member_, reason_) do {                                  \
        facts.member_ = false;                                             \
        ASSERT(subordinate_work_admission_decide(&facts) == (reason_));     \
        ASSERT(strcmp(subordinate_work_refusal_token(reason_), "admit") != \
               0);                                                         \
        facts.member_ = true;                                              \
    } while (0)
        BF_REFUSES(running, SUBORDINATE_WORK_STOPPING);
        BF_REFUSES(sync_at_tip, SUBORDINATE_WORK_SYNC_NOT_AT_TIP);
        BF_REFUSES(disk_clear, SUBORDINATE_WORK_DISK_PRESSURE);
        BF_REFUSES(memory_clear, SUBORDINATE_WORK_MEMORY_PRESSURE);
        BF_REFUSES(db_long_operation_clear,
                   SUBORDINATE_WORK_DB_LONG_OPERATION);
        BF_REFUSES(persistence_ready,
                   SUBORDINATE_WORK_PERSISTENCE_UNAVAILABLE);
        BF_REFUSES(db_open, SUBORDINATE_WORK_DB_CLOSED);
        BF_REFUSES(db_transaction_clear, SUBORDINATE_WORK_DB_TRANSACTION);
        BF_REFUSES(db_turbo_clear, SUBORDINATE_WORK_DB_TURBO);
        BF_REFUSES(db_pending_blocks_clear,
                   SUBORDINATE_WORK_DB_PENDING_BLOCKS);
#undef BF_REFUSES
        ASSERT(subordinate_work_admission_decide(NULL) ==
               SUBORDINATE_WORK_NOT_OBSERVED);
        PASS();
    } _test_next:;
    return failures;
}

int test_build_fabric(void)
{
    int failures = 0;
    failures += test_bf_migration();
    failures += test_bf_lifecycle();
    failures += test_bf_async_proof_events();
    failures += test_bf_validation();
    failures += test_bf_service();
    failures += test_bf_reproduction_plan();
    failures += test_bf_leases();
    failures += test_bf_local_enrollment();
    failures += test_bf_toolchain_capture_cache();
    failures += test_bf_assembler_identity_is_version();
    failures += test_bf_execution_observation_codec();
    failures += test_bf_worker_identity_capability_honesty();
    failures += test_bf_confined_worker();
    failures += test_bf_confined_test_worker();
    failures += test_bf_native();
    failures += test_bf_runtime_dump();
    failures += test_bf_content_contracts();
    failures += test_bf_proof_materialization();
    failures += test_bf_subordinate_work_admission();
    printf("=== build_fabric: %d failures ===\n", failures);
    return failures;
}
