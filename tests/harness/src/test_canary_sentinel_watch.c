/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_canary_sentinel_watch — hermetic tests for the in-node replay-canary
 * sentinel watcher + its replay_canary_failed Condition.
 *
 * Every block uses a private tmp dir exported via ZCL_CANARY_VERDICT_DIR
 * (the same env the canary harness reads), so the operator's real verdict
 * dir, the live node, and $HOME are never touched. Asserts the six
 * contracts from the build spec:
 *   (a) FAIL sentinel  → condition raised (and pages),
 *   (b) PASS overwrite → condition cleared,
 *   (c) corrupt JSON   → no raise, no crash, logged once per mtime,
 *   (d) absent dir     → quiet no-op,
 *   (e) idempotency    → two ticks on the same FAIL = ONE raise/remedy,
 *   (f) mixed kinds    → anchor=FAIL + genesis=PASS pages naming only the
 *                        failing kind; all-green clears.
 *   (g) cross-source   → a FAIL written from DIFFERENT source bytes than the
 *                        running is ignored (shared dir + fresh deploy); a
 *                        same-source FAIL still pages.
 *   (h) Git trace only → differing build_commit metadata cannot demote a
 *                        same-source FAIL.
 *   (i) pre-start run  → a FAIL from a run started before this process is
 *                        ignored; a fresh same-build FAIL still pages.
 *   (j) fail-closed clear → stale/cross-source/malformed/unknown verdicts
 *                        cannot clear a current exact-source FAIL latch.
 * Plus the documented absence policy: a FAIL stays latched when its
 * sentinel disappears (a re-running canary must not un-page the node). */

#include "test/test_core.h"
#include "crypto/sha256.h"

#include "framework/condition.h"
#include "json/json.h"
#include "platform/os_proc.h"
#include "services/canary_sentinel_watch.h"
#include "conditions/replay_canary_failed.h"
#include "util/clientversion.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CSW_CHECK(name, expr) do { \
    printf("canary_sentinel_watch: %s... ", (name)); \
    if (expr) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static bool write_file(const char *dir, const char *name, const char *body)
{
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s", dir, name) >=
        (int)sizeof(path))
        return false;
    FILE *f = fopen(path, "w");
    if (!f)
        return false;
    bool ok = fputs(body, f) >= 0;
    fclose(f);
    return ok;
}

/* Mirror the harness's sentinel shape (extra fields prove tolerance). Source
 * ID is the sole cross-build authority; build_commit is display-only. */
static bool test_running_artifact_sha256(char out[65])
{
    FILE *image = os_proc_open_self_exe();
    if (!image)
        return false;
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    uint8_t buf[32768];
    bool ok = true;
    for (;;) {
        size_t n = fread(buf, 1, sizeof(buf), image);
        if (n > 0) {
            sha256_write(&ctx, buf, n);
            continue;
        }
        if (feof(image))
            break;
        ok = false;
        break;
    }
    if (fclose(image) != 0)
        ok = false;
    if (!ok)
        return false;
    uint8_t digest[32];
    static const char hex[] = "0123456789abcdef";
    sha256_finalize(&ctx, digest);
    for (size_t i = 0; i < sizeof(digest); i++) {
        out[i * 2] = hex[digest[i] >> 4];
        out[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    out[64] = '\0';
    return true;
}

static bool write_sentinel_full_identity(
    const char *dir, const char *kind, const char *verdict,
    const char *reason, long long ts, const char *source_id,
    const char *artifact_sha256, const char *build_commit)
{
    char name[128];
    char body[768];
    snprintf(name, sizeof(name), "replay_canary_%s.json", kind);
    snprintf(body, sizeof(body),
             "{\"verdict\":\"%s\",\"from\":\"%s\",\"ts\":%lld,"
             "\"started_ts\":%lld,\"source_id_sha256\":\"%s\","
             "\"artifact_sha256\":\"%s\","
             "\"build_commit\":\"%s\","
             "\"tip\":3145000,\"verified_height\":3145000,"
             "\"bg_state\":\"complete\",\"consensus_rejects\":0,"
             "\"reason\":\"%s\",\"elapsed_sec\":1234}\n",
             verdict, kind, ts, ts - 1200, source_id ? source_id : "",
             artifact_sha256 ? artifact_sha256 : "",
             build_commit ? build_commit : "", reason);
    return write_file(dir, name, body);
}

static bool write_sentinel_identity(const char *dir, const char *kind,
                                    const char *verdict, const char *reason,
                                    long long ts, const char *source_id,
                                    const char *build_commit)
{
    char artifact_sha256[65];
    return test_running_artifact_sha256(artifact_sha256) &&
           write_sentinel_full_identity(
               dir, kind, verdict, reason, ts, source_id, artifact_sha256,
               build_commit);
}

/* The common case: a sentinel written from the RUNNING source tree, so a FAIL
 * latches (same-source verdicts are genuine evidence about this binary). */
static bool write_sentinel(const char *dir, const char *kind,
                           const char *verdict, const char *reason,
                           long long ts)
{
    return write_sentinel_identity(dir, kind, verdict, reason, ts,
                                   zcl_build_source_id_sha256(),
                                   zcl_build_commit());
}

static bool different_source_id(char out[65])
{
    const char *running = zcl_build_source_id_sha256();
    if (!running || strlen(running) != 64)
        return false;
    snprintf(out, 65, "%s", running);
    out[0] = out[0] == '0' ? '1' : '0';
    return true;
}

static void rm_in_dir(const char *dir, const char *name)
{
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s", dir, name) <
        (int)sizeof(path))
        unlink(path);
}

static void watch_test_setup(const char *dir)
{
    condition_engine_reset_for_testing();
    canary_sentinel_watch_test_reset();
    canary_sentinel_watch_test_set_process_start(1717000000LL);
    replay_canary_failed_test_reset();
    register_replay_canary_failed();
    setenv("ZCL_CANARY_VERDICT_DIR", dir, 1);
}

static void watch_test_teardown(const char *dir)
{
    rm_in_dir(dir, "replay_canary_anchor.json");
    rm_in_dir(dir, "replay_canary_genesis.json");
    rm_in_dir(dir, "replay_canary_anchor.json.tmp.999");
    unsetenv("ZCL_CANARY_VERDICT_DIR");
    canary_sentinel_watch_test_reset();
    replay_canary_failed_test_reset();
    condition_engine_reset_for_testing();
}

static bool cond_snapshot(struct condition_runtime_snapshot *out)
{
    return condition_engine_get_registered_snapshot("replay_canary_failed",
                                                    out);
}

static int64_t dump_int(const char *field)
{
    struct json_value v;
    json_init(&v);
    int64_t val = -1;
    if (canary_watch_dump_state_json(&v, NULL))
        val = json_get_int(json_get(&v, field));
    json_free(&v);
    return val;
}

static bool dump_bool(const char *field)
{
    struct json_value v;
    json_init(&v);
    bool val = false;
    if (canary_watch_dump_state_json(&v, NULL))
        val = json_get_bool(json_get(&v, field));
    json_free(&v);
    return val;
}

static bool current_kind(const char *kind, const bool expected[3])
{
    static const char *const fields[] = {"present", "parsed", "current_pass"};
    struct json_value dump;
    json_init(&dump);
    bool ok = false;
    if (!canary_watch_dump_state_json(&dump, NULL))
        goto done;
    const struct json_value *kinds = json_get(&dump, "kinds");
    for (size_t i = 0; i < json_size(kinds); i++) {
        const struct json_value *slot = json_at(kinds, i);
        const char *name = json_get_str(json_get(slot, "kind"));
        if (!name || strcmp(name, kind) != 0)
            continue;
        ok = true;
        for (size_t j = 0; j < 3; j++) {
            const struct json_value *field = json_get(slot, fields[j]);
            if (!field || field->type != JSON_BOOL) {
                ok = false;
                break;
            }
            ok = ok && json_get_bool(field) == expected[j];
        }
        break;
    }
done:
    json_free(&dump);
    return ok;
}

static int current_identity_cases(const char *dir)
{
    int failures = 0;
    char artifact[65], other_source[65], other_artifact[65];
    if (!test_running_artifact_sha256(artifact) ||
        !different_source_id(other_source))
        return 1;
    snprintf(other_artifact, sizeof(other_artifact), "%s", artifact);
    other_artifact[0] = artifact[0] == '0' ? '1' : '0';
    const char *source = zcl_build_source_id_sha256();
    const struct { long long ts; const char *source, *artifact; bool pass; } rows[] = {
        {1717001199, source, artifact, false}, {1717001200, source, artifact, true},
        {1200, source, artifact, false},
        {1717002400, other_source, artifact, false},
        {1717002400, source, other_artifact, false},
        {1717002400, "", artifact, false}, {1717002400, "invalid", artifact, false},
        {1717002400, source, "", false}, {1717002400, source, "invalid", false},
    };
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        watch_test_setup(dir);
        bool ok = write_sentinel(dir, "genesis", "FAIL", "retained", 1717002400);
        canary_sentinel_watch_tick_once();
        ok = ok && write_sentinel_full_identity(dir, "genesis", "PASS", "",
            rows[i].ts, rows[i].source, rows[i].artifact, zcl_build_commit());
        canary_sentinel_watch_tick_once();
        const bool expected[] = {true, true, rows[i].pass};
        ok = ok && current_kind("genesis", expected);
        ok = ok && canary_sentinel_watch_fail_active() == !rows[i].pass;
        CSW_CHECK("current PASS requires existing exact clear authority", ok);
        watch_test_teardown(dir);
    }
    return failures;
}

static int current_replacement_cases(const char *dir)
{
    int failures = 0;
    const bool pass[] = {true, true, true}, gone[] = {false, false, false};
    const bool corrupt[] = {true, false, false};
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/replay_canary_genesis.json", dir);
    if (n < 0 || (size_t)n >= sizeof(path))
        return 1;
    watch_test_setup(dir);
    bool ok = write_sentinel(dir, "genesis", "PASS", "", 1717002400);
    canary_sentinel_watch_tick_once();
    CSW_CHECK("current exact genesis PASS has typed observation flags",
              ok && current_kind("genesis", pass));
    ok = unlink(path) == 0;
    canary_sentinel_watch_tick_once();
    CSW_CHECK("removed PASS loses current eligibility", ok && current_kind("genesis", gone));
    ok = write_sentinel(dir, "genesis", "PASS", "", 1717002400);
    canary_sentinel_watch_tick_once();
    ok = ok && write_file(dir, "replay_canary_anchor.json.tmp.999", "{torn");
    char replacement[PATH_MAX];
    n = snprintf(replacement, sizeof(replacement), "%s/replay_canary_anchor.json.tmp.999", dir);
    if (n < 0 || (size_t)n >= sizeof(replacement))
        ok = false;
    else
        ok = ok && rename(replacement, path) == 0;
    canary_sentinel_watch_tick_once();
    CSW_CHECK("atomic corrupt replacement cannot inherit PASS", ok && current_kind("genesis", corrupt));
    watch_test_teardown(dir);
    return failures;
}

static int current_absence_cases(const char *dir)
{
    int failures = 0;
    const bool gone[] = {false, false, false}, unknown[] = {true, true, false};
    watch_test_setup(dir);
    bool ok = write_sentinel(dir, "genesis", "UNKNOWN", "", 1717002400);
    canary_sentinel_watch_tick_once();
    CSW_CHECK("parsed UNKNOWN has no current PASS", ok && current_kind("genesis", unknown));
    ok = write_sentinel(dir, "genesis", "PASS", "", 1717002400);
    canary_sentinel_watch_tick_once();
    const bool pass[] = {true, true, true};
    CSW_CHECK("exact replacement restores current PASS", ok && current_kind("genesis", pass));
    ok = write_sentinel(dir, "genesis", "FAIL", "retained", 1717002400);
    canary_sentinel_watch_tick_once();
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/replay_canary_genesis.json", dir);
    ok = ok && n > 0 && (size_t)n < sizeof(path);
    if (ok)
        ok = unlink(path) == 0;
    canary_sentinel_watch_tick_once();
    CSW_CHECK("removed FAIL retains latch independently of observation",
              ok && current_kind("genesis", gone) && canary_sentinel_watch_fail_active());
    ok = write_sentinel(dir, "genesis", "PASS", "", 1717002400);
    canary_sentinel_watch_tick_once();
    ok = ok && setenv("ZCL_CANARY_VERDICT_DIR", path, 1) == 0;
    canary_sentinel_watch_tick_once();
    CSW_CHECK("unreadable directory resets current evidence", ok && current_kind("genesis", gone));
    watch_test_teardown(dir);
    return failures;
}

static int current_kind_cases(const char *dir)
{
    int failures = 0;
    const bool pass[] = {true, true, true}, gone[] = {false, false, false};
    watch_test_setup(dir);
    canary_sentinel_watch_tick_once();
    CSW_CHECK("empty scan has no genesis observation", !current_kind("genesis", gone));
    bool ok = write_sentinel(dir, "anchor", "PASS", "", 1717002400);
    canary_sentinel_watch_tick_once();
    CSW_CHECK("anchor PASS does not create genesis evidence", ok && !current_kind("genesis", pass));
    char artifact[65], body[512];
    ok = test_running_artifact_sha256(artifact);
    int n = snprintf(body, sizeof(body),
        "{\"verdict\":\"PASS\",\"from\":\"anchor\",\"ts\":1717002400,"
        "\"started_ts\":1717001200,\"source_id_sha256\":\"%s\","
        "\"artifact_sha256\":\"%s\"}", zcl_build_source_id_sha256(), artifact);
    ok = ok && n > 0 && (size_t)n < sizeof(body);
    ok = ok && write_file(dir, "replay_canary_genesis.json", body);
    canary_sentinel_watch_tick_once();
    CSW_CHECK("filename genesis owns PASS despite display-only anchor", ok && current_kind("genesis", pass));
    char path[PATH_MAX];
    n = snprintf(path, sizeof(path), "%s/replay_canary_genesis.json", dir);
    ok = ok && n > 0 && (size_t)n < sizeof(path);
    if (ok)
        ok = unlink(path) == 0;
    canary_sentinel_watch_tick_once();
    CSW_CHECK("anchor cannot retain removed genesis eligibility",
              ok && current_kind("genesis", gone) && current_kind("anchor", pass));
    watch_test_teardown(dir);
    return failures;
}

#if defined(__linux__)
struct current_deep_dir {
    int fds[32];
    char names[32][201];
    size_t depth;
    char path[4096];
};

static bool current_deep_create(struct current_deep_dir *tree, const char *dir)
{
    tree->depth = 0;
    tree->fds[0] = -1;
    int n = snprintf(tree->path, sizeof(tree->path), "%s", dir);
    if (n < 0 || (size_t)n >= sizeof(tree->path))
        return false;
    tree->fds[0] = open(dir, O_RDONLY | O_DIRECTORY);
    if (tree->fds[0] < 0)
        return false;
    size_t used = strlen(tree->path);
    while (used < 4070) {
        if (tree->depth >= 31)
            return false;
        size_t len = 4070 - used - 1;
        if (len > 200)
            len = 200;
        char *name = tree->names[tree->depth];
        memset(name, 'a', len);
        name[len] = '\0';
        if (mkdirat(tree->fds[tree->depth], name, 0700) != 0)
            return false;
        int fd = openat(tree->fds[tree->depth], name, O_RDONLY | O_DIRECTORY);
        if (fd < 0) {
            (void)unlinkat(tree->fds[tree->depth], name, AT_REMOVEDIR);
            return false;
        }
        tree->fds[++tree->depth] = fd;
        tree->path[used++] = '/';
        memcpy(tree->path + used, name, len + 1);
        used += len;
    }
    return true;
}

static bool current_deep_remove(struct current_deep_dir *tree)
{
    bool ok = true;
    while (tree->depth > 0) {
        ok = (close(tree->fds[tree->depth]) == 0) && ok;
        tree->depth--;
        ok = (unlinkat(tree->fds[tree->depth], tree->names[tree->depth], AT_REMOVEDIR) == 0) && ok;
    }
    if (tree->fds[0] >= 0)
        ok = (close(tree->fds[0]) == 0) && ok;
    return ok;
}

static int current_path_boundary_case(const char *dir)
{
    int failures = 0;
    struct current_deep_dir tree;
    bool ok = current_deep_create(&tree, dir);
    int fd = -1;
    if (ok)
        fd = openat(tree.fds[tree.depth], "replay_canary_genesis.json", O_WRONLY | O_CREAT | O_EXCL, 0600);
    ok = ok && fd >= 0;
    if (fd >= 0) {
        ok = (write(fd, "{}", 2) == 2) && ok;
        ok = (close(fd) == 0) && ok;
    }
    if (ok) {
        watch_test_setup(tree.path);
        canary_sentinel_watch_tick_once();
        const bool seen[] = {true, false, false};
        CSW_CHECK("observed filename survives full-path read refusal",
                  dump_int("files_seen_last") == 1 && current_kind("genesis", seen));
        watch_test_teardown(tree.path);
    }
    int removed = fd >= 0 ? unlinkat(tree.fds[tree.depth], "replay_canary_genesis.json", 0) : 0;
    CSW_CHECK("deep-directory fixture created and removed", ok && removed == 0);
    CSW_CHECK("deep-directory handles and parents restored", current_deep_remove(&tree));
    return failures;
}
#endif

static int current_observation_cases(const char *dir)
{
    const char *previous = getenv("ZCL_CANARY_VERDICT_DIR");
    bool had_previous = previous != NULL;
    char saved[PATH_MAX];
    int n = snprintf(saved, sizeof(saved), "%s", previous ? previous : "");
    if (n < 0 || (size_t)n >= sizeof(saved))
        return 1;
    int failures = current_replacement_cases(dir);
    failures += current_absence_cases(dir);
    failures += current_identity_cases(dir);
    failures += current_kind_cases(dir);
#if defined(__linux__)
    failures += current_path_boundary_case(dir);
#endif
    int rc = had_previous ? setenv("ZCL_CANARY_VERDICT_DIR", saved, 1)
                      : unsetenv("ZCL_CANARY_VERDICT_DIR");
    return failures + (rc != 0);
}

/* (a) FAIL sentinel → condition raised, remedy logged, page emitted. */
static int watch_fail_raises_pages_case(const char *dir)
{
    int failures = 0;
    watch_test_setup(dir);
    bool ok = write_sentinel(dir, "anchor", "FAIL", "sha3_mismatch",
                             1718000000LL);
    canary_sentinel_watch_tick_once();
    ok = ok && canary_sentinel_watch_fail_active();

    char detail[256];
    int fails = canary_sentinel_watch_fail_detail(detail, sizeof(detail));
    ok = ok && fails == 1;
    ok = ok && strstr(detail, "kind=anchor") != NULL;
    ok = ok && strstr(detail, "reason=sha3_mismatch") != NULL;
    ok = ok && strstr(detail, "ts=1718000000") != NULL;

    condition_engine_tick();
    struct condition_runtime_snapshot snap;
    ok = ok && cond_snapshot(&snap);
    ok = ok && snap.currently_active;
    ok = ok && snap.attempts == 1;
    ok = ok && snap.operator_needed_emitted;
    ok = ok && replay_canary_failed_test_remedy_calls() == 1;
    ok = ok && dump_bool("condition_active");
    CSW_CHECK("FAIL sentinel raises replay_canary_failed and pages", ok);
    watch_test_teardown(dir);
    return failures;
}

/* (e) idempotency: re-scanning the SAME FAIL must not re-raise — one
 * detect edge, one remedy, no event spam. */
static int watch_same_fail_idempotent_case(const char *dir)
{
    int failures = 0;
    watch_test_setup(dir);
    bool ok = write_sentinel(dir, "anchor", "FAIL", "crossnode_height",
                             1718000001LL);
    canary_sentinel_watch_tick_once();
    condition_engine_tick();
    canary_sentinel_watch_tick_once();   /* tick 2: same FAIL file */
    condition_engine_tick();
    struct condition_runtime_snapshot snap;
    ok = ok && cond_snapshot(&snap);
    ok = ok && snap.currently_active;
    ok = ok && snap.attempts == 1;       /* still ONE remedy attempt */
    ok = ok && snap.cleared_count == 0;
    ok = ok && replay_canary_failed_test_remedy_calls() == 1;
    CSW_CHECK("two ticks on the same FAIL = one raise", ok);
    watch_test_teardown(dir);
    return failures;
}

/* (b) PASS overwrite (the harness's atomic replace) → cleared. */
static int watch_pass_overwrite_clears_case(const char *dir)
{
    int failures = 0;
    watch_test_setup(dir);
    bool ok = write_sentinel(dir, "anchor", "FAIL", "budget_exceeded",
                             1718000002LL);
    canary_sentinel_watch_tick_once();
    condition_engine_tick();
    struct condition_runtime_snapshot snap;
    ok = ok && cond_snapshot(&snap) && snap.currently_active;

    ok = ok && write_sentinel(dir, "anchor", "PASS", "", 1718000060LL);
    canary_sentinel_watch_tick_once();
    ok = ok && !canary_sentinel_watch_fail_active();
    condition_engine_tick();
    ok = ok && cond_snapshot(&snap);
    ok = ok && !snap.currently_active;
    ok = ok && snap.cleared_count == 1;
    ok = ok && condition_engine_get_active_count() == 0;
    CSW_CHECK("PASS overwrite clears the condition", ok);
    watch_test_teardown(dir);
    return failures;
}

/* (f) mixed verdicts across kinds: anchor=FAIL + genesis=PASS must keep
 * the condition raised with detail naming ONLY the failing kind; a later
 * anchor PASS (all kinds green) clears it. */
static int watch_mixed_kinds_page_case(const char *dir)
{
    int failures = 0;
    watch_test_setup(dir);
    bool ok = write_sentinel(dir, "anchor", "FAIL", "sha3_mismatch",
                             1718000100LL);
    ok = ok && write_sentinel(dir, "genesis", "PASS", "", 1718000101LL);
    canary_sentinel_watch_tick_once();
    ok = ok && canary_sentinel_watch_fail_active();

    char detail[256];
    int fails = canary_sentinel_watch_fail_detail(detail, sizeof(detail));
    ok = ok && fails == 1;
    ok = ok && strstr(detail, "kind=anchor") != NULL;
    ok = ok && strstr(detail, "kind=genesis") == NULL;

    condition_engine_tick();
    struct condition_runtime_snapshot snap;
    ok = ok && cond_snapshot(&snap) && snap.currently_active;

    ok = ok && write_sentinel(dir, "anchor", "PASS", "", 1718000160LL);
    canary_sentinel_watch_tick_once();
    ok = ok && !canary_sentinel_watch_fail_active();
    condition_engine_tick();
    ok = ok && cond_snapshot(&snap) && !snap.currently_active;
    CSW_CHECK("mixed FAIL+PASS kinds page on the failing kind only", ok);
    watch_test_teardown(dir);
    return failures;
}

/* (c) corrupt JSON → no raise, no crash; logged once per mtime; an
 * in-flight .tmp. file is never read as a verdict. */
static int watch_corrupt_json_case(const char *dir)
{
    int failures = 0;
    watch_test_setup(dir);
    bool ok = write_file(dir, "replay_canary_anchor.json",
                         "{\"verdict\":\"FA");  /* torn write */
    ok = ok && write_file(dir, "replay_canary_anchor.json.tmp.999",
                          "{\"verdict\":\"FAIL\",\"from\":\"anchor\","
                          "\"ts\":1,\"reason\":\"x\"}\n");
    canary_sentinel_watch_tick_once();
    ok = ok && !canary_sentinel_watch_fail_active();
    ok = ok && dump_int("parse_failures_logged") == 1;
    canary_sentinel_watch_tick_once();   /* same mtime: no second log */
    ok = ok && dump_int("parse_failures_logged") == 1;
    condition_engine_tick();
    ok = ok && condition_engine_get_active_count() == 0;
    ok = ok && replay_canary_failed_test_remedy_calls() == 0;
    CSW_CHECK("corrupt JSON never raises and logs once per mtime", ok);
    watch_test_teardown(dir);
    return failures;
}

/* Documented absence policy: a latched FAIL survives its sentinel
 * disappearing (canary re-run deletes it first) — only PASS clears. */
static int watch_absence_keeps_latch_case(const char *dir)
{
    int failures = 0;
    watch_test_setup(dir);
    bool ok = write_sentinel(dir, "genesis", "FAIL", "rpc_never_ready",
                             1718000003LL);
    canary_sentinel_watch_tick_once();
    ok = ok && canary_sentinel_watch_fail_active();
    rm_in_dir(dir, "replay_canary_genesis.json");
    canary_sentinel_watch_tick_once();   /* file gone: still latched */
    ok = ok && canary_sentinel_watch_fail_active();
    ok = ok && write_sentinel(dir, "genesis", "PASS", "",
                              1718000400LL);
    canary_sentinel_watch_tick_once();
    ok = ok && !canary_sentinel_watch_fail_active();
    CSW_CHECK("FAIL stays latched across sentinel absence until PASS",
              ok);
    watch_test_teardown(dir);
    return failures;
}

/* (g) Cross-source staleness: a FAIL written from DIFFERENT source bytes
 * than the one running is not evidence about THIS build (shared dir + a
 * freshly-deployed binary) — it must NOT latch the pager. A SAME-source
 * FAIL alongside it still pages, proving we did not disable FAIL paging
 * wholesale; the stale one is excluded from the page detail. */
static int watch_cross_source_fail_case(const char *dir)
{
    int failures = 0;
    watch_test_setup(dir);
    /* Stale cross-source FAIL alone → recorded but never raises. */
    char other_source_id[65];
    bool ok = different_source_id(other_source_id);
    ok = ok && write_sentinel_identity(
        dir, "anchor", "FAIL", "rpc_unreachable", 1718000500LL,
        other_source_id, "deadbee_oldbuild");
    canary_sentinel_watch_tick_once();
    ok = ok && !canary_sentinel_watch_fail_active();
    ok = ok && dump_bool("fail_latched") == false;
    condition_engine_tick();
    ok = ok && condition_engine_get_active_count() == 0;
    ok = ok && replay_canary_failed_test_remedy_calls() == 0;

    /* A same-source FAIL on another kind DOES page. */
    ok = ok && write_sentinel(dir, "genesis", "FAIL", "sha3_mismatch",
                              1718000501LL);
    canary_sentinel_watch_tick_once();
    ok = ok && canary_sentinel_watch_fail_active();
    char detail[256];
    int fails = canary_sentinel_watch_fail_detail(detail, sizeof(detail));
    ok = ok && fails == 1;                            /* only the genuine one */
    ok = ok && strstr(detail, "kind=genesis") != NULL;
    ok = ok && strstr(detail, "kind=anchor") == NULL; /* stale one excluded */
    CSW_CHECK("cross-source FAIL ignored; same-source FAIL still pages",
              ok);
    watch_test_teardown(dir);
    return failures;
}

/* (h) Git trace metadata is never staleness authority. A deliberately
 * different build_commit with the same source ID must still page. */
static int watch_commit_mismatch_pages_case(const char *dir)
{
    int failures = 0;
    watch_test_setup(dir);
    bool ok = write_sentinel_identity(
        dir, "anchor", "FAIL", "sha3_mismatch", 1718000600LL,
        zcl_build_source_id_sha256(), "different-github-trace");
    canary_sentinel_watch_tick_once();
    ok = ok && canary_sentinel_watch_fail_active();
    CSW_CHECK("build_commit mismatch cannot demote same-source FAIL", ok);
    watch_test_teardown(dir);
    return failures;
}

static bool watch_untyped_verdict_keeps_latch(const char *dir,
                                              char running_artifact[65])
{
    bool ok = write_sentinel(dir, "anchor", "FAIL", "live_failure",
                             1718001000LL);
    canary_sentinel_watch_tick_once();
    ok = ok && canary_sentinel_watch_fail_active();

    /* Syntactically valid JSON can still omit every typed sentinel field.
     * It is an untrusted unknown verdict: never crash and never clear the
     * exact current FAIL already latched above. */
    ok = ok && write_file(dir, "replay_canary_anchor.json", "{}\n");
    canary_sentinel_watch_tick_once();
    ok = ok && canary_sentinel_watch_fail_active();

    ok = ok && test_running_artifact_sha256(running_artifact);
    char body[768];
    snprintf(body, sizeof(body),
             "{\"from\":\"anchor\",\"ts\":1718001025,"
             "\"started_ts\":1718001000,"
             "\"source_id_sha256\":\"%s\","
             "\"artifact_sha256\":\"%s\","
             "\"reason\":\"missing_verdict\"}\n",
             zcl_build_source_id_sha256(), running_artifact);
    ok = ok && write_file(dir, "replay_canary_anchor.json", body);
    canary_sentinel_watch_tick_once();
    ok = ok && canary_sentinel_watch_fail_active();
    return ok;
}

static bool watch_foreign_clear_keeps_latch(const char *dir, bool ok,
                                            const char *running_artifact)
{
    char other_source_id[65];
    char other_artifact[65];
    ok = ok && different_source_id(other_source_id);
    snprintf(other_artifact, sizeof(other_artifact), "%s",
             running_artifact);
    other_artifact[0] = other_artifact[0] == '0' ? '1' : '0';
    ok = ok && write_sentinel_full_identity(
        dir, "anchor", "PASS", "cross_artifact_pass", 1718001050LL,
        zcl_build_source_id_sha256(), other_artifact, "trace-artifact");
    canary_sentinel_watch_tick_once();
    ok = ok && canary_sentinel_watch_fail_active();
    ok = ok && write_sentinel_identity(
        dir, "anchor", "FAIL", "cross_fail", 1718001100LL,
        other_source_id, "trace-a");
    canary_sentinel_watch_tick_once();
    ok = ok && canary_sentinel_watch_fail_active();
    ok = ok && write_sentinel_identity(
        dir, "anchor", "PASS", "cross_pass", 1718001200LL,
        other_source_id, "trace-b");
    canary_sentinel_watch_tick_once();
    ok = ok && canary_sentinel_watch_fail_active();
    return ok;
}

static bool watch_prestart_clear_keeps_latch(const char *dir, bool ok)
{
    canary_sentinel_watch_test_set_process_start(1719000000LL);
    ok = ok && write_sentinel(dir, "anchor", "FAIL", "prestart_fail",
                              1718002000LL);
    canary_sentinel_watch_tick_once();
    ok = ok && canary_sentinel_watch_fail_active();
    ok = ok && write_sentinel(dir, "anchor", "PASS", "prestart_pass",
                              1718002100LL);
    canary_sentinel_watch_tick_once();
    ok = ok && canary_sentinel_watch_fail_active();
    return ok;
}

static bool watch_partial_sentinel_keeps_latch(const char *dir, bool ok,
                                              const char *running_artifact)
{
    char body[768];
    snprintf(body, sizeof(body),
             "{\"verdict\":\"PASS\",\"from\":\"anchor\","
             "\"ts\":1720001000,\"started_ts\":1720000000,"
             "\"reason\":\"missing_source\"}\n");
    ok = ok && write_file(dir, "replay_canary_anchor.json", body);
    canary_sentinel_watch_tick_once();
    ok = ok && canary_sentinel_watch_fail_active();

    snprintf(body, sizeof(body),
             "{\"verdict\":\"PASS\",\"from\":\"anchor\","
             "\"ts\":1720002000,\"source_id_sha256\":\"%s\","
             "\"artifact_sha256\":\"%s\","
             "\"reason\":\"missing_started_ts\"}\n",
             zcl_build_source_id_sha256(), running_artifact);
    ok = ok && write_file(dir, "replay_canary_anchor.json", body);
    canary_sentinel_watch_tick_once();
    ok = ok && canary_sentinel_watch_fail_active();

    ok = ok && write_sentinel(dir, "anchor", "UNKNOWN", "bad_enum",
                              1720003000LL);
    canary_sentinel_watch_tick_once();
    ok = ok && canary_sentinel_watch_fail_active();
    ok = ok && dump_bool("fail_latched");

    char detail[256];
    int fails = canary_sentinel_watch_fail_detail(detail, sizeof(detail));
    ok = ok && fails == 1 && strstr(detail, "live_failure") != NULL;

    ok = ok && write_sentinel(dir, "anchor", "PASS", "",
                              1721002000LL);
    canary_sentinel_watch_tick_once();
    ok = ok && !canary_sentinel_watch_fail_active();
    return ok;
}

/* (j) A genuine current FAIL may be cleared only by an exact-source PASS
 * from a run started during this process. Every stale or malformed clear
 * attempt preserves both the latch and the original failure detail. */
static int watch_exact_source_clear_case(const char *dir)
{
    int failures = 0;
    watch_test_setup(dir);
    char running_artifact[65];
    bool ok = watch_untyped_verdict_keeps_latch(dir, running_artifact);
    ok = watch_foreign_clear_keeps_latch(dir, ok, running_artifact);
    ok = watch_prestart_clear_keeps_latch(dir, ok);
    ok = watch_partial_sentinel_keeps_latch(dir, ok, running_artifact);
    CSW_CHECK("only current exact-source PASS clears a latched FAIL", ok);
    watch_test_teardown(dir);
    return failures;
}

/* (i) Run-start staleness: the shared verdict dir can contain a FAIL from
 * this same source build, but from a canary run started before this node
 * process. It is not evidence about the running process, so it must not
 * page. A fresh same-source FAIL still pages. */
static int watch_prestart_fail_ignored_case(const char *dir)
{
    int failures = 0;
    watch_test_setup(dir);
    canary_sentinel_watch_test_set_process_start(1718000000LL);
    bool ok = write_sentinel(dir, "anchor", "FAIL", "old_process_fail",
                             1718000500LL);
    canary_sentinel_watch_tick_once();
    ok = ok && !canary_sentinel_watch_fail_active();
    ok = ok && dump_bool("fail_latched") == false;
    condition_engine_tick();
    ok = ok && condition_engine_get_active_count() == 0;
    ok = ok && replay_canary_failed_test_remedy_calls() == 0;

    ok = ok && write_sentinel(dir, "genesis", "FAIL", "fresh_fail",
                              1718002000LL);
    canary_sentinel_watch_tick_once();
    ok = ok && canary_sentinel_watch_fail_active();
    char detail[256];
    int fails = canary_sentinel_watch_fail_detail(detail, sizeof(detail));
    ok = ok && fails == 1;
    ok = ok && strstr(detail, "kind=genesis") != NULL;
    ok = ok && strstr(detail, "kind=anchor") == NULL;
    CSW_CHECK("pre-start FAIL ignored; fresh same-source FAIL still pages",
              ok);
    watch_test_teardown(dir);
    return failures;
}

/* (d) absent dir → quiet no-op, nothing raised, no crash. */
static int watch_absent_dir_case(const char *dir)
{
    int failures = 0;
    char absent[PATH_MAX];
    snprintf(absent, sizeof(absent), "%s/never_created", dir);
    watch_test_setup(absent);
    canary_sentinel_watch_tick_once();
    canary_sentinel_watch_tick_once();
    condition_engine_tick();
    bool ok = !canary_sentinel_watch_fail_active();
    ok = ok && condition_engine_get_active_count() == 0;
    ok = ok && replay_canary_failed_test_remedy_calls() == 0;
    ok = ok && dump_int("files_seen_last") == 0;
    CSW_CHECK("absent dir is a quiet no-op", ok);
    watch_test_teardown(absent);
    return failures;
}

int test_canary_sentinel_watch(void)
{
    printf("\n=== canary_sentinel_watch tests ===\n");
    int failures = 0;

    char tmpl[] = "/tmp/zcl_canary_watch_XXXXXX";
    char *dir = mkdtemp(tmpl);
    if (!dir) {
        printf("canary_sentinel_watch: mkdtemp FAILED — cannot run\n");
        return 1;
    }

    failures += watch_absent_dir_case(dir);
    failures += watch_fail_raises_pages_case(dir);
    failures += watch_same_fail_idempotent_case(dir);
    failures += watch_pass_overwrite_clears_case(dir);
    failures += watch_mixed_kinds_page_case(dir);
    failures += watch_corrupt_json_case(dir);
    failures += watch_absence_keeps_latch_case(dir);
    failures += watch_cross_source_fail_case(dir);
    failures += watch_commit_mismatch_pages_case(dir);
    failures += watch_exact_source_clear_case(dir);
    failures += watch_prestart_fail_ignored_case(dir);
    failures += current_observation_cases(dir);
    rmdir(dir);
    return failures;
}
