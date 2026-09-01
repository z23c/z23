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

    /* (d) absent dir → quiet no-op, nothing raised, no crash. */
    {
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
    }

    /* (a) FAIL sentinel → condition raised, remedy logged, page emitted. */
    {
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
    }

    /* (e) idempotency: re-scanning the SAME FAIL must not re-raise — one
     * detect edge, one remedy, no event spam. */
    {
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
    }

    /* (b) PASS overwrite (the harness's atomic replace) → cleared. */
    {
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
    }

    /* (f) mixed verdicts across kinds: anchor=FAIL + genesis=PASS must keep
     * the condition raised with detail naming ONLY the failing kind; a later
     * anchor PASS (all kinds green) clears it. */
    {
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
    }

    /* (c) corrupt JSON → no raise, no crash; logged once per mtime; an
     * in-flight .tmp. file is never read as a verdict. */
    {
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
    }

    /* Documented absence policy: a latched FAIL survives its sentinel
     * disappearing (canary re-run deletes it first) — only PASS clears. */
    {
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
    }

    /* (g) Cross-source staleness: a FAIL written from DIFFERENT source bytes
     * than the one running is not evidence about THIS build (shared dir + a
     * freshly-deployed binary) — it must NOT latch the pager. A SAME-source
     * FAIL alongside it still pages, proving we did not disable FAIL paging
     * wholesale; the stale one is excluded from the page detail. */
    {
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
    }

    /* (h) Git trace metadata is never staleness authority. A deliberately
     * different build_commit with the same source ID must still page. */
    {
        watch_test_setup(dir);
        bool ok = write_sentinel_identity(
            dir, "anchor", "FAIL", "sha3_mismatch", 1718000600LL,
            zcl_build_source_id_sha256(), "different-github-trace");
        canary_sentinel_watch_tick_once();
        ok = ok && canary_sentinel_watch_fail_active();
        CSW_CHECK("build_commit mismatch cannot demote same-source FAIL", ok);
        watch_test_teardown(dir);
    }

    /* (j) A genuine current FAIL may be cleared only by an exact-source PASS
     * from a run started during this process. Every stale or malformed clear
     * attempt preserves both the latch and the original failure detail. */
    {
        watch_test_setup(dir);
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

        char running_artifact[65];
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

        canary_sentinel_watch_test_set_process_start(1719000000LL);
        ok = ok && write_sentinel(dir, "anchor", "FAIL", "prestart_fail",
                                  1718002000LL);
        canary_sentinel_watch_tick_once();
        ok = ok && canary_sentinel_watch_fail_active();
        ok = ok && write_sentinel(dir, "anchor", "PASS", "prestart_pass",
                                  1718002100LL);
        canary_sentinel_watch_tick_once();
        ok = ok && canary_sentinel_watch_fail_active();

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
        CSW_CHECK("only current exact-source PASS clears a latched FAIL", ok);
        watch_test_teardown(dir);
    }

    /* (i) Run-start staleness: the shared verdict dir can contain a FAIL from
     * this same source build, but from a canary run started before this node
     * process. It is not evidence about the running process, so it must not
     * page. A fresh same-source FAIL still pages. */
    {
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
    }

    rmdir(dir);
    return failures;
}
