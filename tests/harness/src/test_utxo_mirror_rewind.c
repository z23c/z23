/* purpose: exercise automatic verified UTXO mirror rewind recovery. */
/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#ifndef ZCL_TEST_UTXO_MIRROR_REWIND_INCLUDED
#define ZCL_TEST_UTXO_MIRROR_REWIND_INCLUDED
typedef int zcl_test_utxo_mirror_rewind_translation_unit;
#ifdef ZCL_TESTING
/* Reuse the existing fixture and assertions without changing their source. */
#define test_utxo_mirror_sync test_utxo_mirror_sync_rewind_fixture_copy
#include "test_utxo_mirror_sync.c"
#undef test_utxo_mirror_sync
#include "platform/time_compat.h"
#endif
#endif

#if defined(ZCL_TEST_UTXO_MIRROR_REWIND_INCLUDED) && defined(ZCL_TESTING)
static void umr_loop(struct utxo_mirror_sync_service *svc)
{
    (void)utxo_mirror_rebuild_job_service(svc);
    (void)utxo_mirror_sync_run_once(svc);
}

static bool umr_job_is(struct utxo_mirror_sync_service *svc, uint64_t id, int state)
{
    struct utxo_mirror_rebuild_job job;
    utxo_mirror_rebuild_job_snapshot(svc, &job);
    return job.id == id && job.state == state;
}

static bool umr_height(struct node_db *ndb, int64_t height)
{
    int64_t cursor = -1;
    return node_db_state_get_int(ndb, UTXO_MIRROR_SYNC_CURSOR_KEY, &cursor) &&
           cursor == height;
}

static bool umr_healthy(struct ums_fx *fx, int64_t height)
{
    return atomic_load(&fx->svc.mirror_health) == UTXO_MIRROR_HEALTHY &&
           ums_cause_dump_is(&fx->svc, "unknown") &&
           umr_height(&fx->ndb, height) && ums_roots_equal(&fx->ndb, fx->pdb);
}

static bool umr_lower(struct ums_fx *fx)
{
    uint8_t txid[32];
    ums_txid(txid, 0x52);
    return coins_kv_spend(fx->pdb, txid, 0) && ums_set_frontier(fx->pdb, 101);
}

static bool umr_start(struct ums_fx *fx, const char *name)
{
    ums_fx_open(fx, name);
    atomic_store(&fx->svc.thread_started, true);
    return fx->ok && utxo_mirror_sync_run_once(&fx->svc) == 2;
}

static void umr_expire_window(struct utxo_mirror_sync_service *svc)
{
    atomic_store(&svc->auto_rewind_last_ms,
                 platform_time_monotonic_ms() - INT64_C(60000));
}

static int umr_test_height(void)
{
    int failures = 0;
    struct ums_fx fx;
    UMS_CHECK("T1 fixture and rewind", umr_start(&fx, "rewind_t1") && umr_lower(&fx));
    char before[4096], after[4096];
    UMS_CHECK("T1 original projection", ums_digest(fx.ndb.db, before, sizeof(before)));
    umr_loop(&fx.svc);
    UMS_CHECK("T1 first iteration quarantines and queues",
              ums_quarantined_with_cause(&fx.svc, "authority_rewind") &&
              umr_job_is(&fx.svc, 1, UTXO_MIRROR_JOB_PENDING) &&
              ums_digest(fx.ndb.db, after, sizeof(after)) && !strcmp(before, after));
    umr_loop(&fx.svc);
    UMS_CHECK("T1 second iteration verified height recovery",
              umr_job_is(&fx.svc, 1, UTXO_MIRROR_JOB_DONE) && umr_healthy(&fx, 101));
    ums_fx_close(&fx);
    return failures;
}

static int umr_test_branch(void)
{
    int failures = 0;
    struct ums_fx fx;
    ums_fx_open(&fx, "rewind_t2");
    atomic_store(&fx.svc.thread_started, true);
    UMS_CHECK("T2 fixture with branch identity",
              fx.ok && ums_write_branch_delta_row(fx.pdb, 101, 0x51) &&
              utxo_mirror_sync_run_once(&fx.svc) == 2);
    uint8_t old[32];
    ums_txid(old, 0x52);
    UMS_CHECK("T2 replace branch at same height",
              coins_kv_spend(fx.pdb, old, 0) &&
              ums_add_coin(fx.pdb, 0x53, 3000, 101) &&
              ums_write_branch_delta_row(fx.pdb, 101, 0x53));
    umr_loop(&fx.svc);
    UMS_CHECK("T2 first iteration quarantines and queues",
              ums_quarantined_with_cause(&fx.svc, "authority_rewind") &&
              umr_job_is(&fx.svc, 1, UTXO_MIRROR_JOB_PENDING) &&
              db_utxo_exists(&fx.ndb, old, 0) && umr_height(&fx.ndb, 102));
    umr_loop(&fx.svc);
    UMS_CHECK("T2 second iteration verified branch recovery",
              umr_job_is(&fx.svc, 1, UTXO_MIRROR_JOB_DONE) &&
              umr_healthy(&fx, 102) && ums_branch_hash_is(&fx.ndb, 0x53));
    ums_fx_close(&fx);
    return failures;
}

static int umr_test_window(void)
{
    int failures = 0;
    struct ums_fx fx;
    UMS_CHECK("T3 fixture and first rewind",
              umr_start(&fx, "rewind_t3") && umr_lower(&fx));
    umr_loop(&fx.svc);
    umr_loop(&fx.svc);
    UMS_CHECK("T3 first repair complete", umr_healthy(&fx, 101));
    uint8_t txid[32];
    ums_txid(txid, 0x51);
    UMS_CHECK("T3 second authority rewind",
              coins_kv_spend(fx.pdb, txid, 0) &&
              ums_add_coin(fx.pdb, 0x54, 4000, 99) && ums_set_frontier(fx.pdb, 100));
    char before[4096], after[4096];
    UMS_CHECK("T3 capture old projection", ums_digest(fx.ndb.db, before, sizeof(before)));
    umr_loop(&fx.svc);
    umr_loop(&fx.svc);
    UMS_CHECK("T3 inside window no second job or mutation",
              ums_quarantined_with_cause(&fx.svc, "authority_rewind") &&
              umr_job_is(&fx.svc, 1, UTXO_MIRROR_JOB_DONE) &&
              ums_digest(fx.ndb.db, after, sizeof(after)) && !strcmp(before, after));
    umr_expire_window(&fx.svc);
    umr_loop(&fx.svc);
    UMS_CHECK("T3 expired window queues second job",
              umr_job_is(&fx.svc, 2, UTXO_MIRROR_JOB_PENDING));
    umr_loop(&fx.svc);
    UMS_CHECK("T3 expired window verified recovery", umr_healthy(&fx, 100));
    ums_fx_close(&fx);
    return failures;
}

static int umr_test_refusal(void)
{
    int failures = 0;
    struct ums_fx fx;
    UMS_CHECK("T4 fixture and rewind", umr_start(&fx, "rewind_t4") && umr_lower(&fx));
    umr_loop(&fx.svc);
    char before[4096], after[4096];
    UMS_CHECK("T4 capture old projection",
              ums_digest(fx.ndb.db, before, sizeof(before)) &&
              progress_meta_delete(fx.pdb, COINS_KV_MIGRATION_COMPLETE_KEY));
    umr_loop(&fx.svc);
    struct utxo_mirror_rebuild_job job;
    utxo_mirror_rebuild_job_snapshot(&fx.svc, &job);
    UMS_CHECK("T4 authority refusal preserves quarantine and bytes",
              job.state == UTXO_MIRROR_JOB_DONE && job.result == UTXO_MIRROR_REBUILD_REFUSED &&
              ums_quarantined_with_cause(&fx.svc, "authority_rewind") &&
              ums_digest(fx.ndb.db, after, sizeof(after)) && !strcmp(before, after));
    UMS_CHECK("T4 restore proven authority", coins_kv_mark_migration_complete(fx.pdb));
    umr_expire_window(&fx.svc);
    umr_loop(&fx.svc);
    umr_loop(&fx.svc);
    UMS_CHECK("T4 later valid authority recovers", umr_healthy(&fx, 101));
    ums_fx_close(&fx);
    return failures;
}

static int umr_test_restart(void)
{
    int failures = 0;
    struct ums_fx fx;
    UMS_CHECK("T5 fixture and rewind", umr_start(&fx, "rewind_t5") && umr_lower(&fx));
    umr_loop(&fx.svc);
    UMS_CHECK("T5 old service quarantined",
              ums_quarantined_with_cause(&fx.svc, "authority_rewind"));
    struct utxo_mirror_sync_service restarted;
    atomic_store(&fx.svc.thread_started, false);
    utxo_mirror_sync_init(&restarted, &fx.ndb);
    atomic_store(&restarted.thread_started, true);
    umr_loop(&restarted);
    UMS_CHECK("T5 restarted service redetects and queues",
              ums_quarantined_with_cause(&restarted, "authority_rewind") &&
              umr_job_is(&restarted, 1, UTXO_MIRROR_JOB_PENDING));
    umr_loop(&restarted);
    UMS_CHECK("T5 restarted service verified recovery",
              atomic_load(&restarted.mirror_health) == UTXO_MIRROR_HEALTHY &&
              ums_cause_dump_is(&restarted, "unknown") &&
              umr_height(&fx.ndb, 101) && ums_roots_equal(&fx.ndb, fx.pdb));
    ums_fx_close(&fx);
    return failures;
}

static int umr_test_missing_delta(void)
{
    int failures = 0;
    struct ums_fx fx;
    UMS_CHECK("T6 fixture and missing forward delta",
              umr_start(&fx, "rewind_t6") && ums_set_frontier(fx.pdb, 103));
    char before[4096], after[4096];
    UMS_CHECK("T6 capture original projection", ums_digest(fx.ndb.db, before, sizeof(before)));
    umr_loop(&fx.svc);
    umr_loop(&fx.svc);
    UMS_CHECK("T6 missing delta stays quarantined without job",
              ums_quarantined_with_cause(&fx.svc, "missing_delta") &&
              umr_job_is(&fx.svc, 0, UTXO_MIRROR_JOB_IDLE) &&
              ums_digest(fx.ndb.db, after, sizeof(after)) && !strcmp(before, after));
    ums_fx_close(&fx);
    return failures;
}

int test_utxo_mirror_rewind(void);
int test_utxo_mirror_rewind(void)
{
    int failures = 0;
    failures += umr_test_height();
    failures += umr_test_branch();
    failures += umr_test_window();
    failures += umr_test_refusal();
    failures += umr_test_restart();
    failures += umr_test_missing_delta();
    return failures;
}
#endif
