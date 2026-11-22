/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: test deterministic crash and successor boundaries for serving acceptance. */
#include "test/test_core.h"
#include "models/package_resident.h"
#include "crypto/sha256.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define PR_CHECK(name, expr) do { \
    bool passed = (expr); \
    printf("package_resident_record: %s... %s\n", name, passed ? "OK" : "FAIL"); \
    if (!passed) ++failures; \
} while (0)

static struct package_resident_identity pr_test_identity(char byte, int64_t config)
{
    struct package_resident_identity id = {0};
    memset(id.package_root, byte, 64);
    memset(id.receipt_id, byte, 64);
    memset(id.artifact_sha3, byte, 64);
    (void)snprintf(id.program, sizeof(id.program), "bin/ztasks");
    id.configuration_generation = config;
    return id;
}

static void pr_crash_before_commit(void *context, int operation,
    const char *database, const char *table, sqlite3_int64 row)
{
    (void)context; (void)operation; (void)database; (void)table; (void)row;
    _exit(71); /* OS closes the connection without SQLite cleanup/commit. */
}

static bool pr_crash(const char *directory, const struct package_resident_identity *target,
                      bool before_commit)
{
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        struct package_resident_store store = {0};
        struct package_resident_record record;
        if (!package_resident_store_open(&store, directory).ok ||
            !package_resident_record_read(&store, &record).ok ||
            !package_resident_record_begin(&store, record.generation, &record).ok) _exit(70);
        if (before_commit)
            (void)sqlite3_update_hook(store.db, pr_crash_before_commit, NULL);
        if (!package_resident_record_commit(&store, record.revision,
                record.generation, target, &record).ok) _exit(70);
        _exit(72); /* Committed selection survives even without close(). */
    }
    int status = 0;
    return waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
        WEXITSTATUS(status) == (before_commit ? 71 : 72);
}
#endif

#if !defined(_WIN32)
struct pr_test_state {
    char directory[256];
    struct package_resident_store store;
    struct package_resident_record row;
    struct package_resident_identity a, b, c;
    int64_t generation_a, ticket_b, ticket_c;
};

static const char pr_nonce_a[] =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char pr_nonce_b[] =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
static const char pr_nonce_c[] =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

static bool pr_test_setup(struct pr_test_state *t)
{
    memset(t, 0, sizeof(*t));
    (void)snprintf(t->directory, sizeof(t->directory), "/tmp/z23-resident-record-XXXXXX");
    if (!mkdtemp(t->directory)) return false;
    char child[512];
    (void)snprintf(child, sizeof(child), "%s/zcode", t->directory);
    if (mkdir(child, 0700) != 0) return false;
    t->a = pr_test_identity('a', 1);
    t->b = pr_test_identity('b', 2);
    t->c = pr_test_identity('c', 3);
    return true;
}

static int pr_test_cleanup(struct pr_test_state *t)
{
    int failures = 0;
    char child[512];
    PR_CHECK("final store close", package_resident_store_close(&t->store).ok);
    (void)snprintf(child, sizeof(child), "%s/zcode/resident.db", t->directory);
    PR_CHECK("isolated database removed", unlink(child) == 0);
    (void)snprintf(child, sizeof(child), "%s/zcode/resident.db-journal", t->directory);
    PR_CHECK("closed isolated journal removed", unlink(child) == 0 || errno == ENOENT);
    (void)snprintf(child, sizeof(child), "%s/zcode", t->directory);
    PR_CHECK("isolated directories removed", rmdir(child) == 0 && rmdir(t->directory) == 0);
    return failures;
}

static int pr_test_legacy_0(struct pr_test_state *t)
{
    int failures = 0;
    PR_CHECK("isolated owner opens", package_resident_store_open(&t->store, t->directory).ok);
    PR_CHECK("first acceptance reserves and commits", package_resident_record_begin(&t->store, t->row.generation, &t->row).ok &&
        package_resident_record_commit(&t->store, t->row.revision, 0, &t->a, &t->row).ok);
    t->generation_a = t->row.generation;
    PR_CHECK("A is exact", package_resident_identity_equal(&t->row.current, &t->a));
    PR_CHECK("B reserves outside slow work", package_resident_record_begin(&t->store, t->row.generation, &t->row).ok);
    t->ticket_b = t->row.revision;
    PR_CHECK("C supersedes B", package_resident_record_begin(&t->store, t->row.generation, &t->row).ok);
    t->ticket_c = t->row.revision;
    PR_CHECK("obsolete B cannot win", !package_resident_record_commit(&t->store, t->ticket_b,
        t->generation_a, &t->b, &t->row).ok);
    PR_CHECK("C activates from exact A precondition", package_resident_record_commit(&t->store,
        t->ticket_c, t->generation_a, &t->c, &t->row).ok);
    PR_CHECK("consumed ticket cannot overwrite current", !package_resident_record_commit(&t->store,
        t->ticket_c, t->ticket_c, &t->b, &t->row).ok);
    PR_CHECK("exact A remains prior", package_resident_record_read(&t->store, &t->row).ok &&
        package_resident_identity_equal(&t->row.previous, &t->a));
    return failures;
}

static int pr_test_legacy_1(struct pr_test_state *t)
{
    int failures = 0;
    int64_t before_stale_revision = t->row.revision;
    PR_CHECK("stale reservation refuses without fencing current work",
        !package_resident_record_begin(&t->store, t->generation_a, &t->row).ok &&
        package_resident_record_read(&t->store, &t->row).ok && t->row.revision == before_stale_revision);
    PR_CHECK("reasserting C advances authority without erasing prior A",
        package_resident_record_begin(&t->store, t->row.generation, &t->row).ok &&
        package_resident_record_commit(&t->store, t->row.revision, t->row.generation, &t->c, &t->row).ok &&
        package_resident_identity_equal(&t->row.previous, &t->a));
    return failures;
}

static int pr_test_legacy_2(struct pr_test_state *t)
{
    int failures = 0;
    PR_CHECK("rollback reserves", package_resident_record_begin(&t->store, t->row.generation, &t->row).ok);
    PR_CHECK("rollback supports aliased exact prior argument", package_resident_record_commit(&t->store,
        t->row.revision, t->row.generation, &t->row.previous, &t->row).ok &&
        package_resident_identity_equal(&t->row.current, &t->a));
    return failures;
}

static int pr_test_legacy_3(struct pr_test_state *t)
{
    int failures = 0;
    PR_CHECK("close before process crashes", package_resident_store_close(&t->store).ok);
    PR_CHECK("crash before activation commit injected", pr_crash(t->directory, &t->b, true));
    PR_CHECK("restart chooses committed A", package_resident_store_open(&t->store, t->directory).ok &&
        package_resident_record_read(&t->store, &t->row).ok && package_resident_identity_equal(&t->row.current, &t->a));
    return failures;
}

static int pr_test_legacy_4(struct pr_test_state *t)
{
    int failures = 0;
    PR_CHECK("close before second crash", package_resident_store_close(&t->store).ok);
    PR_CHECK("crash after activation commit injected", pr_crash(t->directory, &t->b, false));
    PR_CHECK("restart chooses committed B with exact prior A", package_resident_store_open(&t->store, t->directory).ok &&
        package_resident_record_read(&t->store, &t->row).ok && package_resident_identity_equal(&t->row.current, &t->b) &&
        package_resident_identity_equal(&t->row.previous, &t->a));
    return failures;
}

static int pr_test_legacy_5(struct pr_test_state *t)
{
    int failures = 0;
    PR_CHECK("close before rollback crash", package_resident_store_close(&t->store).ok);
    PR_CHECK("crash during rollback injected", pr_crash(t->directory, &t->a, true));
    PR_CHECK("interrupted rollback retains committed B", package_resident_store_open(&t->store, t->directory).ok &&
        package_resident_record_read(&t->store, &t->row).ok && package_resident_identity_equal(&t->row.current, &t->b));
    return failures;
}

static bool pr_test_accept(struct pr_test_state *t,
    const struct package_resident_identity *id, const char *nonce, uint64_t token)
{
    if (!package_resident_record_read(&t->store, &t->row).ok) return false;
    if (!package_resident_record_begin(&t->store, t->row.generation, &t->row).ok) return false;
    return package_resident_record_accept(&t->store, t->row.revision,
        t->row.generation, id, nonce, token, &t->row).ok;
}

static bool pr_test_activate(struct pr_test_state *t, const char *nonce, uint64_t token)
{
    return package_resident_record_activate(&t->store, t->row.pending_ticket,
        t->row.generation, nonce, token, &t->row).ok;
}

static int pr_test_named_first(struct pr_test_state *t)
{
    int failures = 0;
    PR_CHECK("named app owner opens", package_resident_store_open_app(&t->store,
        t->directory, "local/tasks").ok);
    PR_CHECK("first accept stores supplied binding", pr_test_accept(t, &t->a, pr_nonce_a, 11));
    PR_CHECK("accept leaves serving absent", t->row.generation == 0 && !t->row.current.artifact_sha3[0]);
    PR_CHECK("pending exact tuple and supplied binding retained",
        package_resident_identity_equal(&t->row.pending, &t->a) &&
        strcmp(t->row.pending_nonce, pr_nonce_a) == 0 && t->row.pending_start_token == 11);
    t->ticket_b = t->row.pending_ticket;
    PR_CHECK("activate exact pending increments serving once", pr_test_activate(t, pr_nonce_b, 12));
    PR_CHECK("A serving and pending cleared", t->row.generation == 1 &&
        package_resident_identity_equal(&t->row.current, &t->a) && !t->row.pending_ticket);
    PR_CHECK("fresh activation proof is persisted", strcmp(t->row.current_nonce, pr_nonce_b) == 0 &&
        t->row.current_start_token == 12);
    return failures;
}

static int pr_test_named_consumed(struct pr_test_state *t)
{
    int failures = 0;
    int64_t ticket = t->row.consumed_ticket;
    int64_t generation = t->row.generation;
    PR_CHECK("consumed activation cannot admit new pending at current generation",
        !package_resident_record_accept(&t->store, ticket, generation,
            &t->b, pr_nonce_c, 71, &t->row).ok);
    PR_CHECK("consumed activation cannot activate at current generation",
        !package_resident_record_activate(&t->store, ticket, generation,
            pr_nonce_c, 72, &t->row).ok);
    PR_CHECK("consumed rollback cannot replay with new generation",
        !package_resident_record_rollback(&t->store, ticket, generation,
            pr_nonce_c, 73, &t->row).ok);
    PR_CHECK("consumption fence preserves current and empty pending",
        package_resident_record_read(&t->store, &t->row).ok &&
            t->row.generation == generation && t->row.pending_ticket == 0);
    return failures;
}

static int pr_test_named_fence(struct pr_test_state *t)
{
    int failures = 0;
    PR_CHECK("activation ticket cannot activate twice",
        !package_resident_record_activate(&t->store, t->ticket_b, 0, pr_nonce_c, 13, &t->row).ok);
    PR_CHECK("B accepts without switching A", pr_test_accept(t, &t->b, pr_nonce_b, 21));
    PR_CHECK("A remains exact while B pending", package_resident_identity_equal(&t->row.current, &t->a));
    t->ticket_b = t->row.pending_ticket;
    t->generation_a = t->row.generation;
    PR_CHECK("C reservation supersedes pending B",
        package_resident_record_begin(&t->store, t->generation_a, &t->row).ok);
    t->ticket_c = t->row.revision;
    PR_CHECK("reservation invalidates obsolete pending", t->row.pending_ticket == 0);
    PR_CHECK("reservation reports exact pending displaced atomically",
        package_resident_identity_equal(&t->row.displaced_pending, &t->b));
    PR_CHECK("late B accept cannot win", !package_resident_record_accept(&t->store,
        t->ticket_b, t->generation_a, &t->b, pr_nonce_b, 22, &t->row).ok);
    PR_CHECK("late B activate cannot win", !package_resident_record_activate(&t->store,
        t->ticket_b, t->generation_a, pr_nonce_b, 23, &t->row).ok);
    PR_CHECK("C completes only current reserved ticket", package_resident_record_accept(&t->store,
        t->ticket_c, t->generation_a, &t->c, pr_nonce_c, 31, &t->row).ok);
    PR_CHECK("pending C preserves serving A", package_resident_identity_equal(&t->row.current, &t->a));
    return failures;
}

static int pr_test_named_reopen(struct pr_test_state *t)
{
    int failures = 0;
    PR_CHECK("close durable pending", package_resident_store_close(&t->store).ok);
    PR_CHECK("reopen named pending", package_resident_store_open_app(&t->store,
        t->directory, "local/tasks").ok);
    PR_CHECK("read recovered pending", package_resident_record_read(&t->store, &t->row).ok);
    PR_CHECK("restart restores accepted pending C exactly", package_resident_identity_equal(&t->row.pending, &t->c) &&
        t->row.pending_ticket == t->ticket_c && t->row.pending_start_token == 31);
    PR_CHECK("restart retains committed A", package_resident_identity_equal(&t->row.current, &t->a) &&
        t->row.generation == t->generation_a);
    PR_CHECK("C activates with fresh proof", pr_test_activate(t, pr_nonce_a, 32));
    PR_CHECK("generation advances once despite abandoned tickets", t->row.generation == t->generation_a + 1);
    PR_CHECK("C current exact prior A", package_resident_identity_equal(&t->row.current, &t->c) &&
        package_resident_identity_equal(&t->row.previous, &t->a));
    return failures;
}

static int pr_test_named_rollback(struct pr_test_state *t)
{
    int failures = 0;
    PR_CHECK("B can be pending while C serves", pr_test_accept(t, &t->b, pr_nonce_b, 41));
    int64_t old_pending = t->row.pending_ticket;
    int64_t old_generation = t->row.generation;
    PR_CHECK("rollback reserves and invalidates pending", package_resident_record_begin(&t->store,
        old_generation, &t->row).ok);
    PR_CHECK("rollback restores exact previous tuple after proof", package_resident_record_rollback(&t->store,
        t->row.revision, old_generation, pr_nonce_a, 42, &t->row).ok);
    PR_CHECK("rollback restores A configuration and preserves C", package_resident_identity_equal(&t->row.current, &t->a) &&
        package_resident_identity_equal(&t->row.previous, &t->c));
    PR_CHECK("rollback increments generation exactly once", t->row.generation == old_generation + 1);
    PR_CHECK("pending B cannot resurrect after rollback", !package_resident_record_activate(&t->store,
        old_pending, old_generation, pr_nonce_b, 43, &t->row).ok);
    PR_CHECK("read serving after stale refusal", package_resident_record_read(&t->store, &t->row).ok);
    PR_CHECK("stale refusal leaves exact A serving", package_resident_identity_equal(&t->row.current, &t->a));
    return failures;
}

static int pr_test_named_isolation(struct pr_test_state *t)
{
    int failures = 0;
    struct package_resident_store other = {0};
    struct package_resident_record row = {0};
    PR_CHECK("separate app opens same database", package_resident_store_open_app(&other,
        t->directory, "other/tasks").ok);
    PR_CHECK("separate app has no inferred serving authority", package_resident_record_read(&other, &row).ok &&
        row.generation == 0 && !row.current.package_root[0] && !row.pending_ticket);
    PR_CHECK("other app reserves independently", package_resident_record_begin(&other, 0, &row).ok);
    PR_CHECK("other app accepts independently", package_resident_record_accept(&other,
        row.revision, 0, &t->b, pr_nonce_b, 51, &row).ok);
    PR_CHECK("other app activates independently", package_resident_record_activate(&other,
        row.pending_ticket, 0, pr_nonce_c, 52, &row).ok);
    PR_CHECK("original app unchanged", package_resident_record_read(&t->store, &t->row).ok &&
        package_resident_identity_equal(&t->row.current, &t->a));
    PR_CHECK("separate app closes", package_resident_store_close(&other).ok);
    return failures;
}

static int pr_test_named_invalid(struct pr_test_state *t)
{
    int failures = 0;
    PR_CHECK("reserve malformed probe fixture", package_resident_record_begin(&t->store,
        t->row.generation, &t->row).ok);
    int64_t ticket = t->row.revision;
    int64_t generation = t->row.generation;
    PR_CHECK("malformed nonce cannot become pending", !package_resident_record_accept(&t->store,
        ticket, generation, &t->b, "bad", 61, &t->row).ok);
    PR_CHECK("zero process token cannot become pending", !package_resident_record_accept(&t->store,
        ticket, generation, &t->b, pr_nonce_b, 0, &t->row).ok);
    PR_CHECK("unrepresentable process token cannot truncate", !package_resident_record_accept(&t->store,
        ticket, generation, &t->b, pr_nonce_b, UINT64_MAX, &t->row).ok);
    PR_CHECK("bad probe leaves current unchanged", package_resident_record_read(&t->store, &t->row).ok &&
        package_resident_identity_equal(&t->row.current, &t->a) && !t->row.pending_ticket);
    PR_CHECK("close before final restart", package_resident_store_close(&t->store).ok);
    PR_CHECK("restart after rollback opens", package_resident_store_open_app(&t->store,
        t->directory, "local/tasks").ok);
    PR_CHECK("restart restores A and supplied rollback binding", package_resident_record_read(&t->store, &t->row).ok &&
        package_resident_identity_equal(&t->row.current, &t->a) && t->row.current_start_token == 42);
    return failures;
}

/* This fixture recreates the production v1 schema and its exact old row.
 * It is isolated test setup, not a product write or alternate authority. */
static bool pr_test_legacy_schema(struct pr_test_state *t)
{
    char path[512];
    (void)snprintf(path, sizeof(path), "%s/zcode/resident.db", t->directory);
    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK) {
        if (db) (void)sqlite3_close(db);
        return false;
    }
    const char *sql =
        "CREATE TABLE resident_serving(id INTEGER PRIMARY KEY CHECK(id=1),"
        "revision INTEGER NOT NULL,generation INTEGER NOT NULL,root TEXT NOT NULL,"
        "receipt TEXT NOT NULL,digest TEXT NOT NULL,program TEXT NOT NULL,config INTEGER NOT NULL,"
        "prior_root TEXT NOT NULL,prior_receipt TEXT NOT NULL,prior_digest TEXT NOT NULL,"
        "prior_program TEXT NOT NULL,prior_config INTEGER NOT NULL);";
    bool ok = sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
    char insert[2048];
    (void)snprintf(insert, sizeof(insert),
        "INSERT INTO resident_serving VALUES(1,7,5,'%s','%s','%s','bin/ztasks',2,"
        "'%s','%s','%s','bin/ztasks',1)", t->b.package_root, t->b.receipt_id,
        t->b.artifact_sha3, t->a.package_root, t->a.receipt_id, t->a.artifact_sha3);
    if (ok) ok = sqlite3_exec(db, insert, NULL, NULL, NULL) == SQLITE_OK;
    bool closed = sqlite3_close(db) == SQLITE_OK;
    return ok && closed;
}

static int pr_test_migration(struct pr_test_state *t)
{
    int failures = 0;
    PR_CHECK("legacy schema fixture created", pr_test_legacy_schema(t));
    PR_CHECK("old singleton migrates transactionally", package_resident_store_open(&t->store, t->directory).ok);
    PR_CHECK("legacy record reads after migration", package_resident_record_read(&t->store, &t->row).ok);
    PR_CHECK("migration preserves exact revision and generation", t->row.revision == 7 && t->row.generation == 5);
    PR_CHECK("migration preserves exact current and prior tuple", package_resident_identity_equal(&t->row.current, &t->b) &&
        package_resident_identity_equal(&t->row.previous, &t->a));
    PR_CHECK("migration invents no historical launch proof", !t->row.current_nonce[0] &&
        t->row.current_start_token == 0 && !t->row.pending_ticket);
    PR_CHECK("close migrated legacy", package_resident_store_close(&t->store).ok);
    PR_CHECK("named app opens after legacy migration", package_resident_store_open_app(&t->store,
        t->directory, "local/tasks").ok);
    PR_CHECK("named app never adopts singleton", package_resident_record_read(&t->store, &t->row).ok &&
        t->row.generation == 0 && !t->row.current.artifact_sha3[0]);
    return failures;
}

static int pr_test_legacy_all(struct pr_test_state *t)
{
    int failures = pr_test_legacy_0(t);
    failures += pr_test_legacy_1(t);
    failures += pr_test_legacy_2(t);
    failures += pr_test_legacy_3(t);
    failures += pr_test_legacy_4(t);
    failures += pr_test_legacy_5(t);
    return failures;
}

static bool pr_named_crash_child(const char *directory, bool rollback, bool before_commit)
{
    struct package_resident_store store = {0};
    struct package_resident_record row = {0};
    if (!package_resident_store_open_app(&store, directory, "local/tasks").ok) return false;
    if (!package_resident_record_read(&store, &row).ok) return false;
    if (rollback && !package_resident_record_begin(&store, row.generation, &row).ok) return false;
    if (before_commit) (void)sqlite3_update_hook(store.db, pr_crash_before_commit, NULL);
    struct zcl_result result;
    if (rollback)
        result = package_resident_record_rollback(&store, row.revision,
            row.generation, pr_nonce_a, 82, &row);
    else
        result = package_resident_record_activate(&store, row.pending_ticket,
            row.generation, pr_nonce_b, 81, &row);
    if (!result.ok) return false;
    _exit(72);
}

static bool pr_named_crash(const char *directory, bool rollback, bool before_commit)
{
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        (void)pr_named_crash_child(directory, rollback, before_commit);
        _exit(70);
    }
    int status = 0;
    pid_t waited;
    do { waited = waitpid(pid, &status, 0); } while (waited < 0 && errno == EINTR);
    return waited == pid && WIFEXITED(status) &&
        WEXITSTATUS(status) == (before_commit ? 71 : 72);
}

static bool pr_named_recover(struct pr_test_state *t)
{
    if (!package_resident_store_open_app(&t->store, t->directory, "local/tasks").ok) return false;
    return package_resident_record_read(&t->store, &t->row).ok;
}

static int pr_test_named_activation_crash(struct pr_test_state *t)
{
    int failures = 0;
    PR_CHECK("crash fixture accepts B while exact A serves", pr_test_accept(t, &t->b, pr_nonce_b, 80));
    int64_t generation = t->row.generation;
    int64_t ticket = t->row.pending_ticket;
    PR_CHECK("close before named activation crash", package_resident_store_close(&t->store).ok);
    PR_CHECK("named activation crashes before commit", pr_named_crash(t->directory, false, true));
    PR_CHECK("recover interrupted named activation", pr_named_recover(t));
    PR_CHECK("interrupted activation retains A generation and configuration",
        package_resident_identity_equal(&t->row.current, &t->a) && t->row.generation == generation);
    PR_CHECK("interrupted activation preserves exact accepted pending B",
        package_resident_identity_equal(&t->row.pending, &t->b) && t->row.pending_ticket == ticket);
    PR_CHECK("close before committed activation crash", package_resident_store_close(&t->store).ok);
    PR_CHECK("named activation crashes after commit", pr_named_crash(t->directory, false, false));
    PR_CHECK("recover committed named activation", pr_named_recover(t));
    PR_CHECK("committed activation restores exact B and prior A",
        package_resident_identity_equal(&t->row.current, &t->b) &&
        package_resident_identity_equal(&t->row.previous, &t->a));
    PR_CHECK("committed activation consumes pending exactly once", t->row.generation == generation + 1 &&
        !t->row.pending_ticket && t->row.consumed_ticket == ticket);
    PR_CHECK("committed activation recovers supplied proof token", t->row.current_start_token == 81);
    return failures;
}

static int pr_test_named_rollback_crash(struct pr_test_state *t)
{
    int failures = 0;
    int64_t generation = t->row.generation;
    PR_CHECK("close before named rollback crash", package_resident_store_close(&t->store).ok);
    PR_CHECK("named rollback crashes before commit", pr_named_crash(t->directory, true, true));
    PR_CHECK("recover interrupted named rollback", pr_named_recover(t));
    PR_CHECK("interrupted rollback retains exact B configuration and generation",
        package_resident_identity_equal(&t->row.current, &t->b) && t->row.generation == generation);
    PR_CHECK("interrupted rollback retains exact prior A", package_resident_identity_equal(&t->row.previous, &t->a));
    PR_CHECK("close before committed rollback crash", package_resident_store_close(&t->store).ok);
    PR_CHECK("named rollback crashes after commit", pr_named_crash(t->directory, true, false));
    PR_CHECK("recover committed named rollback", pr_named_recover(t));
    PR_CHECK("committed rollback restores exact A configuration and prior B",
        package_resident_identity_equal(&t->row.current, &t->a) &&
        package_resident_identity_equal(&t->row.previous, &t->b));
    PR_CHECK("committed rollback advances serving generation once", t->row.generation == generation + 1);
    PR_CHECK("committed rollback recovers supplied proof token", t->row.current_start_token == 82);
    return failures;
}

#if defined(__linux__) || defined(__APPLE__)
static int pr_test_readonly_absent(struct pr_test_state *t)
{
    int failures = 0;
    char path[512];
    (void)snprintf(path, sizeof(path), "%s/zcode/resident.db", t->directory);
    struct package_resident_store reader = {0};
    char missing[512]; (void)snprintf(missing, sizeof(missing), "%s/missing", t->directory);
    PR_CHECK("readonly refuses absent profile",
        !package_resident_store_open_app_readonly(&reader, missing, "local/tasks").ok);
    PR_CHECK("readonly creates no profile", access(missing, F_OK) != 0 && errno == ENOENT);
    PR_CHECK("readonly refuses absent database",
        !package_resident_store_open_app_readonly(&reader, t->directory, "local/tasks").ok);
    PR_CHECK("readonly absence creates no database", access(path, F_OK) != 0 && errno == ENOENT);
    PR_CHECK("readonly absent cleanup", package_resident_store_close(&reader).ok);
    sqlite3 *empty = NULL;
    PR_CHECK("empty database fixture", sqlite3_open(path, &empty) == SQLITE_OK);
    PR_CHECK("empty database initialized", sqlite3_exec(empty, "CREATE TABLE other(v)", NULL, NULL, NULL) == SQLITE_OK);
    PR_CHECK("empty database fixture closes", sqlite3_close(empty) == SQLITE_OK);
    PR_CHECK("readonly opens existing empty database",
        package_resident_store_open_app_readonly(&reader, t->directory, "local/tasks").ok);
    struct package_resident_record row = {0};
    PR_CHECK("readonly refuses missing schema", !package_resident_record_read(&reader, &row).ok);
    PR_CHECK("readonly closes empty database", package_resident_store_close(&reader).ok);
    PR_CHECK("empty database fixture removed", unlink(path) == 0);
    return failures;
}

static bool pr_hash(const char *path, unsigned char digest[32])
{
    FILE *f = fopen(path, "rb"); if (!f) return false;
    struct sha256_ctx hash; sha256_init(&hash);
    unsigned char buffer[4096]; size_t n;
    while ((n = fread(buffer, 1, sizeof(buffer), f)) != 0) sha256_write(&hash, buffer, n);
    bool ok = !ferror(f); if (fclose(f) != 0) ok = false;
    if (ok) sha256_finalize(&hash, digest);
    return ok;
}

static int pr_test_readonly_refusals(void)
{
    int failures = 0; struct pr_test_state t;
    if (!pr_test_setup(&t)) return 1;
    char path[512], wal[520], package[512];
    (void)snprintf(path, sizeof(path), "%s/zcode/resident.db", t.directory);
    (void)snprintf(wal, sizeof(wal), "%s-wal", path);
    (void)snprintf(package, sizeof(package), "%s/zcode", t.directory);
    sqlite3 *db = NULL; struct package_resident_store reader = {0};
    PR_CHECK("refusal fixture database", sqlite3_open(path, &db) == SQLITE_OK &&
        sqlite3_exec(db, "CREATE TABLE sample(v)", NULL, NULL, NULL) == SQLITE_OK && sqlite3_close(db) == SQLITE_OK);
    FILE *f = fopen(wal, "wb");
    bool made = f && fwrite("stale", 1, 5, f) == 5; if (f && fclose(f) != 0) made = false;
    unsigned char before[32], after[32];
    PR_CHECK("stale WAL fixture", made && pr_hash(wal, before));
    PR_CHECK("readonly refuses stale WAL", !package_resident_store_open_app_readonly(&reader, t.directory, "local/tasks").ok);
    PR_CHECK("stale WAL bytes retained", pr_hash(wal, after) && !memcmp(before, after, 32) && unlink(wal) == 0);
    PR_CHECK("unsafe database mode fixture", chmod(path, 0666) == 0);
    PR_CHECK("readonly refuses unsafe database mode", !package_resident_store_open_app_readonly(&reader, t.directory, "local/tasks").ok);
    PR_CHECK("unsafe fixture reset", chmod(path, 0600) == 0 && unlink(path) == 0);
    PR_CHECK("nonregular FIFO fixture", mkfifo(path, 0600) == 0);
    PR_CHECK("readonly refuses FIFO", !package_resident_store_open_app_readonly(&reader, t.directory, "local/tasks").ok);
    PR_CHECK("FIFO fixture reset", unlink(path) == 0);
    PR_CHECK("symlink fixture", symlink("/dev/null", path) == 0);
    PR_CHECK("readonly refuses symlink", !package_resident_store_open_app_readonly(&reader, t.directory, "local/tasks").ok);
    PR_CHECK("refusal fixture cleanup", unlink(path) == 0 && rmdir(package) == 0 && rmdir(t.directory) == 0);
    return failures;
}

static bool pr_make_hot_journal(const char *path)
{
    pid_t child = fork();
    if (child < 0) return false;
    if (child == 0) {
        sqlite3 *db = NULL;
        if (sqlite3_open(path, &db) != SQLITE_OK || sqlite3_exec(db,
            "PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA; PRAGMA cache_size=3; "
            "CREATE TABLE scratch_guard(v BLOB); INSERT INTO scratch_guard VALUES(zeroblob(16384)); "
            "BEGIN IMMEDIATE; UPDATE scratch_guard SET v=randomblob(16384)", NULL, NULL, NULL) != SQLITE_OK ||
            sqlite3_db_cacheflush(db) != SQLITE_OK) _exit(1);
        _exit(0);
    }
    int status = 0;
    return waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int pr_test_readonly_hot(void)
{
    int failures = 0; struct pr_test_state t;
    if (!pr_test_setup(&t)) return 1;
    char path[512], journal[520], package[512];
    (void)snprintf(path, sizeof(path), "%s/zcode/resident.db", t.directory);
    (void)snprintf(journal, sizeof(journal), "%s-journal", path);
    (void)snprintf(package, sizeof(package), "%s/zcode", t.directory);
    PR_CHECK("hot journal fixture", pr_make_hot_journal(path));
    static const unsigned char magic[8] = {0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7};
    unsigned char actual[8]; FILE *hot = fopen(journal, "rb");
    bool hot_header = hot && fread(actual, 1, sizeof(actual), hot) == sizeof(actual) && !memcmp(actual, magic, sizeof(magic));
    if (hot && fclose(hot) != 0) hot_header = false;
    PR_CHECK("fixture journal is hot", hot_header);
    unsigned char db_before[32], journal_before[32], db_after[32], journal_after[32];
    PR_CHECK("hot journal hashes", pr_hash(path, db_before) && pr_hash(journal, journal_before));
    struct package_resident_store reader = {0}; struct package_resident_record row = {0};
    bool opened = package_resident_store_open_app_readonly(&reader, t.directory, "local/tasks").ok;
    PR_CHECK("readonly refuses hot recovery", !opened || !package_resident_record_read(&reader, &row).ok);
    PR_CHECK("hot readonly closes", package_resident_store_close(&reader).ok);
    PR_CHECK("hot database and journal bytes unchanged", pr_hash(path, db_after) && pr_hash(journal, journal_after) &&
        !memcmp(db_before, db_after, 32) && !memcmp(journal_before, journal_after, 32));
    PR_CHECK("hot fixture cleanup", unlink(journal) == 0 && unlink(path) == 0 && rmdir(package) == 0 && rmdir(t.directory) == 0);
    return failures;
}

static int pr_test_readonly_wal(void)
{
    int failures = 0; struct pr_test_state t;
    if (!pr_test_setup(&t)) return 1;
    char path[512], wal[520], shm[520];
    (void)snprintf(path, sizeof(path), "%s/zcode/resident.db", t.directory);
    (void)snprintf(wal, sizeof(wal), "%s-wal", path);
    (void)snprintf(shm, sizeof(shm), "%s-shm", path);
    sqlite3 *writer = NULL; struct package_resident_store reader = {0};
    PR_CHECK("WAL fixture open", sqlite3_open(path, &writer) == SQLITE_OK);
    PR_CHECK("WAL fixture writes", sqlite3_exec(writer, "PRAGMA journal_mode=WAL; CREATE TABLE sample(v); INSERT INTO sample VALUES(1)", NULL, NULL, NULL) == SQLITE_OK);
    unsigned char before_wal[32], before_shm[32], after_wal[32], after_shm[32];
    PR_CHECK("WAL fixture sidecars present", pr_hash(wal, before_wal) && pr_hash(shm, before_shm));
    PR_CHECK("readonly refuses live WAL", !package_resident_store_open_app_readonly(&reader, t.directory, "local/tasks").ok);
    PR_CHECK("WAL sidecars untouched", pr_hash(wal, after_wal) && pr_hash(shm, after_shm) &&
        !memcmp(before_wal, after_wal, 32) && !memcmp(before_shm, after_shm, 32));
    PR_CHECK("WAL writer closes", sqlite3_close(writer) == SQLITE_OK);
    PR_CHECK("WAL sidecars absent after close", access(wal, F_OK) != 0 && errno == ENOENT && access(shm, F_OK) != 0 && errno == ENOENT);
    PR_CHECK("readonly refuses WAL header", !package_resident_store_open_app_readonly(&reader, t.directory, "local/tasks").ok);
    PR_CHECK("readonly creates no WAL sidecars", access(wal, F_OK) != 0 && errno == ENOENT && access(shm, F_OK) != 0 && errno == ENOENT);
    PR_CHECK("WAL reader closes", package_resident_store_close(&reader).ok);
    char package[512]; (void)snprintf(package, sizeof(package), "%s/zcode", t.directory);
    PR_CHECK("WAL fixture cleanup", unlink(path) == 0 && rmdir(package) == 0 && rmdir(t.directory) == 0);
    return failures;
}

static bool pr_reserved_lock(const char *directory, bool expected)
{
    char path[512];
    if (snprintf(path, sizeof(path), "%s/zcode/resident.db", directory) >= (int)sizeof(path)) return false;
    pid_t parent = getpid(), child = fork();
    if (child < 0) return false;
    if (!child) {
        int fd = open(path, O_RDONLY | O_NOFOLLOW);
        if (fd < 0) _exit(2);
        struct flock lock = { .l_type = F_WRLCK, .l_whence = SEEK_SET,
            .l_start = 1073741825, .l_len = 1 };
        int rc = fcntl(fd, F_GETLK, &lock);
        bool matched = rc == 0 && (expected ? lock.l_type == F_WRLCK && lock.l_pid == parent : lock.l_type == F_UNLCK);
        (void)close(fd); _exit(matched ? 0 : 1);
    }
    int status = 0;
    return waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int pr_test_readonly_existing(struct pr_test_state *t)
{
    int failures = 0;
    struct package_resident_store reader = {0};
    struct package_resident_record row = {0};
    PR_CHECK("readonly writer active", sqlite3_exec(t->store.db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK);
    PR_CHECK("writer makes uncommitted change", sqlite3_exec(t->store.db, "UPDATE resident_serving SET revision=revision+1", NULL, NULL, NULL) == SQLITE_OK);
    PR_CHECK("other writer blocked before lookup", pr_reserved_lock(t->directory, true));
    PR_CHECK("readonly opens existing", package_resident_store_open_app_readonly(&reader, t->directory, "local/tasks").ok);
    PR_CHECK("readonly sees committed identity during writer",
        package_resident_record_read(&reader, &row).ok && row.generation == t->row.generation && row.revision == t->row.revision &&
        package_resident_identity_equal(&row.current, &t->row.current));
    PR_CHECK("readonly rejects write", sqlite3_exec(reader.db, "DELETE FROM resident_serving", NULL, NULL, NULL) == SQLITE_READONLY);
    PR_CHECK("readonly closes while writer active", package_resident_store_close(&reader).ok);
    PR_CHECK("other writer remains blocked after reader close", pr_reserved_lock(t->directory, true));
    PR_CHECK("readonly writer rollback", sqlite3_exec(t->store.db, "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK);
    PR_CHECK("reserved lock released after rollback", pr_reserved_lock(t->directory, false));
    PR_CHECK("readonly reopens after writer", package_resident_store_open_app_readonly(&reader, t->directory, "local/tasks").ok);
    PR_CHECK("readonly model mutation refuses",
        !package_resident_record_begin(&reader, row.generation, &row).ok && sqlite3_get_autocommit(reader.db));
    PR_CHECK("readonly closes", package_resident_store_close(&reader).ok);
    return failures;
}

#endif

static int pr_test_named_all(struct pr_test_state *t)
{
    int failures = pr_test_named_first(t);
    failures += pr_test_named_consumed(t);
    failures += pr_test_named_fence(t);
    failures += pr_test_named_reopen(t);
    failures += pr_test_named_rollback(t);
    failures += pr_test_named_consumed(t);
    failures += pr_test_named_isolation(t);
    failures += pr_test_named_invalid(t);
    failures += pr_test_named_activation_crash(t);
    failures += pr_test_named_rollback_crash(t);
    return failures;
}

/* A group/world-writable ancestor is refused with its path, mode and fix. */
static int pr_test_ancestor_message(void)
{
    int failures = 0;
    struct pr_test_state t;
    if (!pr_test_setup(&t)) return 1;
    struct package_resident_store store = {0};
    bool opened_loose = chmod(t.directory, 0777) == 0;
    struct zcl_result r = package_resident_store_open(&store, t.directory);
    PR_CHECK("writable ancestor refuses the open", opened_loose && !r.ok);
    PR_CHECK("refusal names the failing path", strstr(r.message, "z23-resident-record-") != NULL);
    PR_CHECK("refusal names the mode", strstr(r.message, "0777") != NULL);
    PR_CHECK("refusal gives the chmod fix", strstr(r.message, "chmod go-w") != NULL);
    char child[512];
    (void)snprintf(child, sizeof(child), "%s/zcode", t.directory);
    PR_CHECK("ancestor test directories removed", rmdir(child) == 0 && rmdir(t.directory) == 0);
    return failures;
}
#endif

int test_package_resident_record(void)
{
#if defined(_WIN32)
    printf("package_resident_record: Windows execution capability unavailable\n");
    return 0;
#else
    struct pr_test_state test;
    if (!pr_test_setup(&test)) return 1;
    int failures = pr_test_legacy_all(&test);
    failures += pr_test_cleanup(&test);
    if (!pr_test_setup(&test)) return failures + 1;
#if defined(__linux__) || defined(__APPLE__)
    failures += pr_test_readonly_absent(&test);
#endif
    failures += pr_test_named_all(&test);
#if defined(__linux__) || defined(__APPLE__)
    failures += pr_test_readonly_existing(&test);
    failures += pr_test_readonly_wal();
    failures += pr_test_readonly_hot();
    failures += pr_test_readonly_refusals();
#endif
    failures += pr_test_cleanup(&test);
    if (!pr_test_setup(&test)) return failures + 1;
    failures += pr_test_migration(&test);
    failures += pr_test_cleanup(&test);
    failures += pr_test_ancestor_message();
    return failures;
#endif
}
