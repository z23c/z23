/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"
#include "test/test_group_selector.h"
#include "platform/os_proc.h"
#include "test_group_catalog.h"
#include "util/clientversion.h"
#include "json/json.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#if defined(_WIN32)
/* The UCRT _pclose() returns the child's raw exit code, not a wait(2)
 * status word; map the two macros onto that honestly. popen() routes
 * through cmd.exe, which cannot run the POSIX test-group-list.sh driver,
 * so commands are re-dispatched through the MSYS2 sh on the lane's PATH.
 * The command strings in this file carry no double quotes. */
#define WIFEXITED(s) ((s) >= 0)
#define WEXITSTATUS(s) (s)
static const char *tgs_wrap_command(const char *command, char *buf,
                                    size_t cap)
{
    int n = snprintf(buf, cap, "sh -c \"%s\"", command);
    if (n < 0 || (size_t)n >= cap)
        return NULL;
    return buf;
}
#endif

static int capture_command(const char *command, char *out, size_t cap)
{
    if (!command || !out || cap == 0)
        return -1;
    out[0] = '\0';
#if defined(_WIN32)
    char wrapped[4096];
    command = tgs_wrap_command(command, wrapped, sizeof(wrapped));
    if (!command)
        return -1;
#endif
    FILE *pipe = popen(command, "r");
    if (!pipe)
        return -1;
    size_t used = 0;
    unsigned char chunk[4096];
    for (;;) {
        size_t got = fread(chunk, 1, sizeof(chunk), pipe);
        size_t room = cap - used - 1;
        size_t keep = got < room ? got : room;
        if (keep > 0) {
            memcpy(out + used, chunk, keep);
            used += keep;
        }
        if (got == 0)
            break;
    }
    out[used] = '\0';
    int status = pclose(pipe);
    if (status < 0 || !WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status);
}

/* These nested runs select at most two groups. Refuse a larger or partial
 * artifact instead of accidentally validating a prefix of another run. */
static bool selector_timing_read(struct json_value *out)
{
    char bytes[8192];
    FILE *fp = fopen(".cache/test-timing/last-run.json", "rb");
    if (!fp) {
        fprintf(stderr, "selector: timing artifact open failed\n");
        return false;
    }
    size_t n = fread(bytes, 1, sizeof(bytes), fp);
    bool complete = !ferror(fp) && feof(fp) && n < sizeof(bytes);
    if (fclose(fp) != 0)
        complete = false;
    if (!complete || !json_read(out, bytes, n) || out->type != JSON_OBJ) {
        fprintf(stderr, "selector: timing artifact incomplete or invalid\n");
        json_free(out);
        return false;
    }
    return true;
}

static bool selector_timing_zero(const struct json_value *row, const char *key)
{
    const struct json_value *v = json_get(row, key);
    return v && v->type == JSON_INT && json_get_int(v) == 0;
}

static bool selector_timing_hex_key(const struct json_value *value)
{
    const char *s = json_get_str(value);
    if (!s || strlen(s) != 64)
        return false;
    for (size_t i = 0; i < 64; i++)
        if (!((s[i] >= '0' && s[i] <= '9') ||
              (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    return true;
}

static void reverse_range(char *b, size_t lo, size_t hi)
{
    while (lo < hi) {
        char t = b[lo];
        b[lo] = b[hi];
        b[hi] = t;
        lo++;
        hi--;
    }
}

/* Left-rotate b[0..n) by k using three reversals. */
static void reverse_rotate(char *b, size_t n, size_t k)
{
    if (n == 0 || k % n == 0)
        return;
    k %= n;
    reverse_range(b, 0, k - 1);
    reverse_range(b, k, n - 1);
    reverse_range(b, 0, n - 1);
}

/* Capture a bounded HEAD and a bounded TAIL of a command whose total output
 * is unbounded, discarding the middle. Both buffers are NUL-terminated and
 * neither grows with the output. Return value matches capture_command. */
static int capture_command_ends(const char *command, char *head,
                                size_t head_cap, char *tail, size_t tail_cap)
{
    if (!command || !head || head_cap == 0 || !tail || tail_cap < 2)
        return -1;
    head[0] = '\0';
    tail[0] = '\0';
#if defined(_WIN32)
    char wrapped[4096];
    command = tgs_wrap_command(command, wrapped, sizeof(wrapped));
    if (!command)
        return -1;
#endif
    FILE *pipe = popen(command, "r");
    if (!pipe)
        return -1;
    const size_t ring_cap = tail_cap - 1;
    size_t head_used = 0;
    size_t ring_len = 0;  /* bytes held in the ring */
    size_t ring_head = 0; /* index of the oldest byte once wrapped */
    unsigned char chunk[4096];
    for (;;) {
        size_t got = fread(chunk, 1, sizeof(chunk), pipe);
        if (got == 0)
            break;
        size_t room = head_cap - head_used - 1;
        size_t keep = got < room ? got : room;
        if (keep > 0) {
            memcpy(head + head_used, chunk, keep);
            head_used += keep;
        }
        /* Ring-append the same bytes; only the last ring_cap survive. */
        for (size_t i = 0; i < got; i++) {
            if (ring_len < ring_cap) {
                tail[ring_len++] = (char)chunk[i];
            } else {
                tail[ring_head] = (char)chunk[i];
                ring_head = (ring_head + 1) % ring_cap;
            }
        }
    }
    head[head_used] = '\0';
    /* Rotate the ring into reading order in place (three reversals), so the
     * capture needs no allocation at all. ring_head is non-zero only after
     * the ring wrapped, and then ring_len == ring_cap. */
    if (ring_head != 0)
        reverse_rotate(tail, ring_len, ring_head);
    tail[ring_len] = '\0';
    int status = pclose(pipe);
    if (status < 0 || !WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status);
}

static int test_selector_predicate(void)
{
    int failures = 0;
    TEST("test group selector: exact mode cannot widen to a sibling") {
        ASSERT(test_group_selector_matches("test_api", "api", false));
        ASSERT(test_group_selector_matches("test_native_api_contract", "api",
                                           false));
        ASSERT(!test_group_selector_matches("test_api", "api", true));
        ASSERT(test_group_selector_matches("test_api", "test_api", true));
        ASSERT(!test_group_selector_matches("test_native_api_contract",
                                            "test_api", true));
        ASSERT(!test_group_selector_matches("test_api", "", true));
        ASSERT(!test_group_selector_matches(NULL, "test_api", true));
        ASSERT(test_group_selector_matches_exact_set(
            "test_api", "test_hex_codec,test_api"));
        ASSERT(!test_group_selector_matches_exact_set(
            "test_native_api_contract", "test_hex_codec,test_api"));
        PASS();
    } _test_next:;
    return failures;
}


/* ── Assertion-message contract ───────────────────────────────────
 *
 * The FAIL line is the whole diagnosis for most failures, so its shape is
 * a contract rather than cosmetics: it has to name the source position and,
 * for a value comparison, both actual values. A reader who has to reopen the
 * file and add printf calls is paying for a message that was already free.
 *
 * The macros bind their operands to temporaries before comparing, which is
 * also what makes the message trustworthy: each operand is evaluated exactly
 * ONCE, so the value printed is the value the predicate tested. Call sites
 * routinely pass function calls with side effects.
 *
 * Each deliberately failing assertion runs in its own frame (its own
 * `failures` counter and `_test_next` label) with stdout captured, so the
 * FAIL text is inspected here and never reaches the transcript. */

static int g_assert_probe_calls;

static int assert_probe(int value)
{
    g_assert_probe_calls++;
    return value;
}

static const char *assert_probe_str(const char *value)
{
    g_assert_probe_calls++;
    return value;
}

static int probe_failing_assert(void)
{
    int failures = 0;
    ASSERT(assert_probe(0) != 0);
_test_next:;
    return failures;
}

static int probe_failing_assert_eq(void)
{
    int failures = 0;
    ASSERT_EQ(assert_probe(7), assert_probe(9));
_test_next:;
    return failures;
}

static int probe_failing_assert_str_eq(void)
{
    int failures = 0;
    ASSERT_STR_EQ(assert_probe_str("alpha"), assert_probe_str("beta"));
_test_next:;
    return failures;
}

/* A pointer against NULL, and an unsigned lvalue against the integer
 * constant 0, are the two operand shapes that a naive per-operand `auto`
 * binding breaks: the first becomes a pointer/int comparison error, the
 * second loses its constant expression and trips -Wsign-compare under
 * -Werror. Both are ordinary in this suite, so both are compiled here. */
static int probe_failing_assert_eq_pointer(void)
{
    int failures = 0;
    const char *present = "x";
    ASSERT_EQ(present, NULL);
_test_next:;
    return failures;
}

static int probe_failing_assert_eq_unsigned(void)
{
    int failures = 0;
    size_t counted = 3;
    ASSERT_EQ(counted, 0);
_test_next:;
    return failures;
}

static int probe_failing_assert_eq_char(void)
{
    int failures = 0;
    char got = 'a';
    ASSERT_EQ(got, 'b');
_test_next:;
    return failures;
}

static int probe_failing_assert_eq_bool(void)
{
    int failures = 0;
    bool ready = false;
    ASSERT_EQ(ready, true);
_test_next:;
    return failures;
}

/* Run `probe` with stdout redirected into an unnamed temp file and return
 * the harness failure count it reported, leaving what it printed in `out`. */
static int run_capturing_stdout(int (*probe)(void), char *out, size_t cap)
{
    if (!out || cap == 0)
        return -1;
    out[0] = '\0';
    FILE *sink = tmpfile();
    if (!sink)
        return -1;
    fflush(stdout);
    int saved = dup(STDOUT_FILENO);
    if (saved < 0) {
        fclose(sink);
        return -1;
    }
    if (dup2(fileno(sink), STDOUT_FILENO) < 0) {
        close(saved);
        fclose(sink);
        return -1;
    }
    int reported = probe();
    fflush(stdout);
    if (dup2(saved, STDOUT_FILENO) < 0)
        reported = -1;
    close(saved);
    rewind(sink);
    size_t used = fread(out, 1, cap - 1, sink);
    out[used] = '\0';
    fclose(sink);
    return reported;
}

static int test_assert_macros_report_where_and_what(void)
{
    int failures = 0;
    char msg[512];

    TEST("assert macros: operands are evaluated exactly once") {
        g_assert_probe_calls = 0;
        ASSERT_EQ(assert_probe(5), assert_probe(5));   /* passing path */
        ASSERT_EQ(g_assert_probe_calls, 2);

        g_assert_probe_calls = 0;
        ASSERT_STR_EQ(assert_probe_str("same"), assert_probe_str("same"));
        ASSERT_EQ(g_assert_probe_calls, 2);

        g_assert_probe_calls = 0;                      /* failing path */
        ASSERT_EQ(run_capturing_stdout(probe_failing_assert_eq,
                                       msg, sizeof(msg)), 1);
        ASSERT_EQ(g_assert_probe_calls, 2);

        g_assert_probe_calls = 0;
        ASSERT_EQ(run_capturing_stdout(probe_failing_assert_str_eq,
                                       msg, sizeof(msg)), 1);
        ASSERT_EQ(g_assert_probe_calls, 2);
        PASS();
    } _test_next:;
    return failures;
}

static int test_assert_messages_name_file_line_and_values(void)
{
    int failures = 0;
    char msg[512];

    TEST("assert macros: FAIL names file:line and both values") {
        ASSERT_EQ(run_capturing_stdout(probe_failing_assert,
                                       msg, sizeof(msg)), 1);
        ASSERT(strstr(msg, "test_test_group_selector.c:") != NULL);
        ASSERT(strstr(msg, "assert_probe(0) != 0") != NULL);

        ASSERT_EQ(run_capturing_stdout(probe_failing_assert_eq,
                                       msg, sizeof(msg)), 1);
        ASSERT(strstr(msg, "test_test_group_selector.c:") != NULL);
        ASSERT(strstr(msg, "7 != 9") != NULL);

        ASSERT_EQ(run_capturing_stdout(probe_failing_assert_str_eq,
                                       msg, sizeof(msg)), 1);
        ASSERT(strstr(msg, "test_test_group_selector.c:") != NULL);
        ASSERT(strstr(msg, "\"alpha\" != \"beta\"") != NULL);

        /* Pointers cannot be enumerated in a _Generic, so they take the
         * fallback arm; both sides must still print as addresses. */
        ASSERT_EQ(run_capturing_stdout(probe_failing_assert_eq_pointer,
                                       msg, sizeof(msg)), 1);
        ASSERT(strstr(msg, "test_test_group_selector.c:") != NULL);
        ASSERT(strstr(msg, "(nil)") != NULL);
        ASSERT(strstr(msg, "0x") != NULL);

        ASSERT_EQ(run_capturing_stdout(probe_failing_assert_eq_unsigned,
                                       msg, sizeof(msg)), 1);
        ASSERT(strstr(msg, "3 != 0") != NULL);

        ASSERT_EQ(run_capturing_stdout(probe_failing_assert_eq_bool,
                                       msg, sizeof(msg)), 1);
        ASSERT(strstr(msg, "false != true") != NULL);

        /* The printer type comes from the ORIGINAL operand, so a char
         * still renders as a char even though `1 ? c : 'b'` promotes
         * the compared value to int. */
        ASSERT_EQ(run_capturing_stdout(probe_failing_assert_eq_char,
                                       msg, sizeof(msg)), 1);
        ASSERT(strstr(msg, "'a' (97) != 98") != NULL);
        PASS();
    } _test_next:;
    return failures;
}
static int test_tmpdir_recursive_cleanup(void)
{
    int failures = 0;
    TEST("test tmpdir: repeated PID/tag removes nested stale state") {
        char root[PATH_MAX], nested[PATH_MAX], stale[PATH_MAX];
        test_make_tmpdir(root, sizeof(root), "tmpdir_cleanup", "nested");
        int n = snprintf(nested, sizeof(nested), "%s/one", root);
        ASSERT(n > 0 && (size_t)n < sizeof(nested));
        ASSERT(mkdir(nested, 0755) == 0);
        n = snprintf(stale, sizeof(stale), "%s/stale", nested);
        ASSERT(n > 0 && (size_t)n < sizeof(stale));
        FILE *fixture = fopen(stale, "wb");
        ASSERT(fixture != NULL);
        ASSERT(fputs("stale", fixture) >= 0);
        ASSERT(fclose(fixture) == 0);

        test_make_tmpdir(root, sizeof(root), "tmpdir_cleanup", "nested");
        ASSERT(access(root, F_OK) == 0);
        ASSERT(access(nested, F_OK) != 0);
        ASSERT(test_rm_rf_recursive(root) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_registry_exact_resolution(void)
{
    int failures = 0;
    TEST("test group selector: legacy plan id resolves to one canonical id") {
        char out[4096];
        char bounded[64];
        int rc = capture_command("yes x 2>/dev/null | head -c 65536", bounded,
                                 sizeof(bounded));
        ASSERT(rc == 0);
        ASSERT(strlen(bounded) == sizeof(bounded) - 1);

        rc = capture_command(
            "tools/dev/test-group-list.sh --resolve-exact api 2>&1", out,
            sizeof(out));
        ASSERT(rc == 0);
        ASSERT(strcmp(out, "test_api\n") == 0);

        rc = capture_command(
            "tools/dev/test-group-list.sh --resolve-exact test_api 2>&1", out,
            sizeof(out));
        ASSERT(rc == 0);
        ASSERT(strcmp(out, "test_api\n") == 0);

        rc = capture_command(
            "tools/dev/test-group-list.sh --resolve-exact api_missing 2>&1",
            out, sizeof(out));
        ASSERT(rc == 1);
        ASSERT(out[0] == '\0');

        rc = capture_command(
            "tools/dev/test-group-list.sh --check-impact-rules 2>&1", out,
            sizeof(out));
        ASSERT(rc == 0);
        ASSERT(out[0] == '\0');

        char fixture_path[256];
        int fixture_n = snprintf(
            fixture_path, sizeof(fixture_path),
            "test-tmp/impact-rules-negative-%ld.def", (long)getpid());
        ASSERT(fixture_n > 0 && (size_t)fixture_n < sizeof(fixture_path));
        FILE *fixture = fopen(fixture_path, "w");
        ASSERT(fixture != NULL);
        ASSERT(fprintf(fixture,
            "AGENT_IMPACT_RULE(\"tests/harness/src/test_hex_codec.c\", \"\")\n"
            "AGENT_IMPACT_RULE(\"tests/harness/src/test_api.c\", \"api_missing\")\n"
            "AGENT_IMPACT_RULE(\"tests/harness/src/test_hex_codec.c\", \"api\")\n") > 0);
        ASSERT(fclose(fixture) == 0);
        char fixture_command[512];
        int command_n = snprintf(
            fixture_command, sizeof(fixture_command),
            "tools/dev/test-group-list.sh --check-impact-rules %s 2>&1",
            fixture_path);
        ASSERT(command_n > 0 && (size_t)command_n < sizeof(fixture_command));
        rc = capture_command(fixture_command, out, sizeof(out));
        ASSERT(remove(fixture_path) == 0);
        ASSERT(rc == 1);
        ASSERT(strstr(out, "empty impact proof plan") != NULL);
        ASSERT(strstr(out, "non-exact impact proof id: api_missing") != NULL);
        ASSERT(strstr(out, "omits its registered group test_hex_codec") !=
               NULL);

        rc = capture_command(
            "tools/dev/test-group-list.sh --resolve-proof make_lint_gates "
            "api 2>&1", out, sizeof(out));
        ASSERT(rc == 0);
        ASSERT(strstr(out, "test_make_lint_gates\n") != NULL);
        ASSERT(strstr(out, "test_make_lint_gates_shard_01\n") != NULL);
        ASSERT(strstr(out, "test_make_lint_gates_heavy_02\n") != NULL);
        ASSERT(strstr(out, "test_api\n") != NULL);
        ASSERT(strstr(out, "test_native_api_contract\n") != NULL);

        rc = capture_command(
            "tools/dev/test-group-list.sh --resolve-proof test_api 2>&1",
            out, sizeof(out));
        ASSERT(rc == 0);
        ASSERT(strcmp(out, "test_api\n") == 0);

        /* A legacy prefixless ID may itself begin with "test_". It is exact
         * only when that literal full ID exists in the registry. */
        rc = capture_command(
            "tools/dev/test-group-list.sh --resolve-proof "
            "test_group_selector 2>&1", out, sizeof(out));
        ASSERT(rc == 0);
        ASSERT(strcmp(out, "test_test_group_selector\n") == 0);

        /* Coverage migration is lossless: a legacy family selector becomes
         * exact full IDs, but only after its exact primary is admitted. */
        rc = capture_command(
            "tools/dev/test-group-list.sh --resolve-proof stage_repair 2>&1",
            out, sizeof(out));
        ASSERT(rc == 0);
        ASSERT(strstr(out, "test_stage_repair\n") != NULL);
        ASSERT(strstr(out, "test_stage_repair_coin_backfill\n") != NULL);
        ASSERT(strstr(out, "test_stage_repair_script_refill\n") != NULL);
        ASSERT(strstr(out, "test_stage_repair_tipfin_backfill\n") != NULL);

        rc = capture_command(
            "tools/dev/test-group-list.sh --resolve-proof oracle_policy "
            "2>&1", out, sizeof(out));
        ASSERT(rc == 0);
        ASSERT(strstr(out, "test_oracle_policy\n") != NULL);
        ASSERT(strstr(out, "test_groth16_r1cs_oracle\n") != NULL);
        ASSERT(strstr(out, "test_zclassicd_oracle\n") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_native_catalog_resolution(void)
{
    int failures = 0;
    TEST("test group selector: C catalog owns exact proof expansion") {
        ASSERT(zcl_test_group_catalog_count() > 800);
        ASSERT(zcl_test_group_catalog_contains("test_api"));
        ASSERT(zcl_test_group_integration_policy_valid());
        ASSERT(!zcl_test_group_catalog_contains("api"));
        ASSERT(zcl_test_group_source_is_semantic_leaf(
            "tests/harness/src/test_stage_repair_coin_backfill.c"));
        ASSERT(zcl_test_group_source_is_semantic_leaf(
            "tests/harness/src/test_dev_platform.c"));
        ASSERT(zcl_test_group_source_is_semantic_leaf(
            "tests/harness/src/test_file_controller.c"));
        ASSERT(zcl_test_group_source_is_semantic_leaf(
            "tests/harness/src/test_cold_join_sovereign.c"));
        ASSERT(zcl_test_group_source_is_semantic_leaf(
            "tests/harness/src/test_test_group_selector.c"));
        ASSERT(!zcl_test_group_source_is_semantic_leaf(
            "tests/harness/src/test_api.c"));

        char full[ZCL_TEST_GROUP_FULL_MAX];
        ASSERT(zcl_test_group_resolve_exact("api", full));
        ASSERT(strcmp(full, "test_api") == 0);
        ASSERT(zcl_test_group_resolve_exact("test_api", full));
        ASSERT(strcmp(full, "test_api") == 0);
        ASSERT(!zcl_test_group_resolve_exact("api_missing", full));
        ASSERT(zcl_test_group_plan_selects("test_api", "test_api"));
        ASSERT(!zcl_test_group_plan_selects("test_api",
                                            "test_native_api_contract"));
        ASSERT(zcl_test_group_plan_selects("api",
                                           "test_native_api_contract"));
        ASSERT(zcl_test_group_plan_selects("test_group_selector",
                                           "test_test_group_selector"));

        const char *ids[] = { "api", "stage_repair", "oracle_policy" };
        char expanded[16][ZCL_TEST_GROUP_FULL_MAX];
        bool truncated = true;
        size_t total = zcl_test_group_expand_plan(
            ids, sizeof(ids) / sizeof(ids[0]), expanded,
            sizeof(expanded) / sizeof(expanded[0]), &truncated);
        ASSERT(total == 10);
        ASSERT(!truncated);
        bool saw_api = false, saw_native_api = false, saw_stage_coin = false;
        bool saw_groth = false, saw_zclassicd = false, saw_quorum = false;
        for (size_t i = 0; i < total; i++) {
            saw_api |= strcmp(expanded[i], "test_api") == 0;
            saw_native_api |= strcmp(expanded[i],
                                     "test_native_api_contract") == 0;
            saw_stage_coin |= strcmp(expanded[i],
                                      "test_stage_repair_coin_backfill") == 0;
            saw_groth |= strcmp(expanded[i],
                                "test_groth16_r1cs_oracle") == 0;
            saw_zclassicd |= strcmp(expanded[i],
                                    "test_zclassicd_oracle") == 0;
            saw_quorum |= strcmp(expanded[i], "test_quorum_oracle") == 0;
        }
        ASSERT(saw_api && saw_native_api && saw_stage_coin);
        ASSERT(saw_groth && saw_zclassicd && saw_quorum);

        const char *exact_ids[] = { "test_api" };
        truncated = true;
        ASSERT(zcl_test_group_expand_plan(
                   exact_ids, 1, expanded,
                   sizeof(expanded) / sizeof(expanded[0]), &truncated) == 1);
        ASSERT(!truncated);
        ASSERT(strcmp(expanded[0], "test_api") == 0);

        char one[1][ZCL_TEST_GROUP_FULL_MAX];
        truncated = false;
        ASSERT(zcl_test_group_expand_plan(ids, 3, one, 1, &truncated) == 10);
        ASSERT(truncated);
        const char *invalid[] = { "api_missing" };
        ASSERT(zcl_test_group_expand_plan(invalid, 1, one, 1, &truncated) ==
               SIZE_MAX);

        const char *lint_ids[] = { "make_lint_gates" };
        char immediate[32][ZCL_TEST_GROUP_FULL_MAX];
        truncated = true;
        size_t immediate_total = zcl_test_group_expand_plan_immediate(
            lint_ids, 1, immediate,
            sizeof(immediate) / sizeof(immediate[0]), &truncated);
        ASSERT(immediate_total == 0);
        ASSERT(!truncated);
        ASSERT(zcl_test_group_is_integration_only(
            "test_make_lint_gates_heavy_01"));
        ASSERT(zcl_test_group_is_integration_only(
            "test_make_lint_gates_heavy_02"));
        ASSERT(zcl_test_group_is_integration_only(
            "test_make_lint_gates_shard_01"));
        ASSERT(zcl_test_group_is_integration_only(
            "test_shielded_payment_gate"));
        ASSERT(zcl_test_group_is_integration_only(
            "test_event_log_kill9"));
        ASSERT(zcl_test_group_is_integration_only(
            "test_event_log_benchmark"));
        ASSERT(zcl_test_group_is_integration_only(
            "test_kill9_recovery"));
        ASSERT(zcl_test_group_is_integration_only(
            "test_chain_advance_atomicity"));
        ASSERT(zcl_test_group_is_integration_only(
            "test_reducer_block_ingest_gate"));
        ASSERT(zcl_test_group_is_integration_only("test_store_e2e_gate"));
        ASSERT(zcl_test_group_is_integration_only(
            "test_store_e2e_shielded"));
        ASSERT(zcl_test_group_is_integration_only(
            "test_self_folded_anchor_heavy"));
        ASSERT(!zcl_test_group_is_integration_only("test_event_log"));
        ASSERT(zcl_test_group_proof_contracts_valid());
        ASSERT(zcl_test_group_proof_contract(
                   "test_shielded_payment_gate") == ZCL_TEST_PROOF_STRESS);
        ASSERT(zcl_test_group_proof_contract(
                   "test_shielded_receive_persist") == ZCL_TEST_PROOF_STRESS);
        ASSERT(zcl_test_group_proof_contract(
                   "test_shielded_receive_slice") == ZCL_TEST_PROOF_STRESS);
        ASSERT(zcl_test_group_proof_contract(
                   "test_shielded_spend_slice") == ZCL_TEST_PROOF_STRESS);
        ASSERT(zcl_test_group_proof_contract(
                   "test_kill9_recovery") == ZCL_TEST_PROOF_STRESS);
        ASSERT(zcl_test_group_proof_contract(
                   "test_chain_advance_atomicity") == ZCL_TEST_PROOF_STRESS);
        ASSERT(zcl_test_group_proof_contract(
                   "test_reducer_block_ingest_gate") == ZCL_TEST_PROOF_STRESS);
        ASSERT(zcl_test_group_proof_contract(
                   "test_reducer_forward_progress_gate") ==
               ZCL_TEST_PROOF_STRESS);
        ASSERT(zcl_test_group_proof_contract(
                   "test_parity_slice") == ZCL_TEST_PROOF_STRESS);
        ASSERT(zcl_test_group_proof_contract(
                   "test_store_e2e_gate") == ZCL_TEST_PROOF_STRESS);
        ASSERT(zcl_test_group_proof_contract(
                   "test_store_e2e_shielded") == ZCL_TEST_PROOF_STRESS);
        ASSERT(zcl_test_group_proof_contract(
                   "test_event_log_kill9") == ZCL_TEST_PROOF_EVENT_LOG_KILL9);
        ASSERT(zcl_test_group_proof_contract(
                   "test_event_log_benchmark") ==
               ZCL_TEST_PROOF_EVENT_LOG_BENCH);
        ASSERT(zcl_test_group_proof_contract(
                   "test_golden_dev_cycle") ==
               ZCL_TEST_PROOF_GOLDEN_TIMING);
        ASSERT(zcl_test_group_proof_contract("test_event_log") ==
               ZCL_TEST_PROOF_NONE);
        ASSERT(zcl_test_group_catalog_contains(
            "test_zcode_score_receipt_packages"));
        ASSERT(zcl_test_group_catalog_contains(
            "test_zcode_score_receipt_rejections"));
        ASSERT(zcl_test_group_catalog_contains(
            "test_zcode_score_receipt_creation"));
        ASSERT(zcl_test_group_catalog_contains(
            "test_zcode_score_receipt_patronage"));
        ASSERT(zcl_test_group_catalog_contains(
            "test_zcode_score_receipt_reproduction"));
        ASSERT(zcl_test_group_catalog_contains(
            "test_zcode_score_receipt_shadow"));
        for (size_t i = 0; i < immediate_total; i++) {
            ASSERT(strcmp(immediate[i],
                          "test_make_lint_gates_heavy_01") != 0);
            ASSERT(strcmp(immediate[i],
                          "test_make_lint_gates_heavy_02") != 0);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_process_sensitive_groups_are_catalog_exclusive(void)
{
    int failures = 0;
    TEST("process-sensitive groups are isolated without serializing catalog structure") {
        ASSERT(zcl_test_group_catalog_contains(
            "test_command_registry_latency"));
        ASSERT(zcl_test_group_requires_exclusive_run(
            "test_command_registry_latency"));
        /* Constant-time comparisons are paired CPU measurements. Saturated
         * process concurrency created a 1.250 false delta in physical CI;
         * measure cryptographic weight sensitivity before the worker pool. */
        ASSERT(zcl_test_group_requires_exclusive_run(
            "test_sapling_crypto"));
        /* ZVCS hard-gates warm status and manifest latency. Running it in
         * the worker pool made unrelated CPU and filesystem producers turn
         * the 20 ms contract into a scheduler-contention measurement. */
        ASSERT(zcl_test_group_requires_exclusive_run(
            "test_vcs_core"));
        /* Exact push proof enables this group's wall-clock assertions, so it
         * must finish before the worker pool can add scheduler contention. */
        ASSERT(zcl_test_group_requires_exclusive_run(
            "test_golden_dev_cycle"));
        /* SIGKILL recovery carries bounded wall-clock budgets and kill
         * windows; execute it before unrelated workers can distort either. */
        ASSERT(zcl_test_group_requires_exclusive_run(
            "test_kill9_recovery"));
        /* Sandbox lint shards retain a bounded parallel lane of their own;
         * they are not smuggled into this serial predicate. */
        ASSERT(!zcl_test_group_requires_exclusive_run(
            "test_make_lint_gates_shard_01"));
        ASSERT(lint_gates_group_requires_quiet_pool(
            "test_make_lint_gates_shard_01"));
        ASSERT(lint_gates_group_requires_quiet_pool(
            "test_make_lint_gates_shard_08"));
        ASSERT(!lint_gates_group_requires_quiet_pool(
            "test_make_lint_gates_realroot"));
        /* This compares forced-pool and serial routing back-to-back. The
         * worker pool must not introduce a different producer population
         * between those two measurements. */
        ASSERT(zcl_test_group_requires_exclusive_run(
            "test_validate_parallel_determinism"));
        /* The clean-vs-injected growth detector is a host-latency contract;
         * parallel CPU/disk contention can invert its positive control. */
        ASSERT(zcl_test_group_requires_exclusive_run(
            "test_simnet_perf"));
        /* The replay-canary identity fixture waits on a child/FIFO handshake.
         * A saturated 32-worker parent can starve that child past the bounded
         * five-second rendezvous and grade scheduler pressure as identity
         * failure. */
        ASSERT(zcl_test_group_requires_exclusive_run(
            "test_replay_canary_verdict"));
        /* This group launches the current runner recursively to prove exact
         * selection.  Competing with the 32-worker parent pool can kill the
         * nested positive control under transient memory pressure, grading
         * host saturation instead of selector semantics. */
        ASSERT(zcl_test_group_requires_exclusive_run(
            "test_test_group_selector"));
        ASSERT(!zcl_test_group_requires_exclusive_run(
            "test_command_registry_catalog"));
        ASSERT(!zcl_test_group_plan_selects(
            "command_registry_catalog", "test_command_registry_latency"));
        ASSERT(zcl_test_group_plan_selects(
            "command_registry_latency", "test_command_registry_latency"));
        PASS();
    } _test_next:;
    return failures;
}

/* Hosted-CI diagnosis: an rc assert failing deep into this test used to
 * leave no evidence (the captured command output never made the group log).
 * Print the command tag, both rc values, and a bounded output prefix. */
static void dump_bad_rc(const char *tag, int rc, int expected,
                        const char *out)
{
    if (rc == expected) return;
    fprintf(stderr, "%s: rc=%d (expected %d), captured output prefix:\n",
            tag, rc, expected);
    fprintf(stderr, "%.4000s\n", out ? out : "(null)");
}

static int test_runner_exact_selection(void)
{
    int failures = 0;
    TEST("test group selector: runner exact mode executes exactly one id") {
        /* The make -n dry run below prints the full out-of-date recipe
         * chain, and that chain's SIZE is a property of the CHECKOUT's build
         * state, not of the seam under test: invoked from a parent make that
         * just built this profile's epoch chain (isolated t-fast) it is a
         * few KB, but invoked cold — the parallel suite, which builds a
         * different profile, or a fresh clone — every object, session, link
         * and stamp recipe in the chain prints. Measured 12.2 MB on a cold
         * clone of this commit, and it grows with the tree.
         *
         * This probe needs exactly two facts, and they sit at the two ends:
         * the parse-time admission line is the FIRST line, and the selector
         * actually handed to the runner is in the LAST. So capture a bounded
         * head and a bounded tail and throw the middle away — a whole-output
         * buffer is a race against the source tree that the tree wins. An
         * earlier revision sized that buffer at 8 MiB against a claimed
         * ~2 MB worst case; the cold measurement above is 1.5x past it, and
         * the truncation would have silently dropped the tail assertion. */
        static char head[64 * 1024];
        static char tail[64 * 1024];
        /* The nested-runner captures below still need the WHOLE output —
         * --source-id/--source-record are compared exactly. Their size is
         * bounded by one test group's own logging, not by the source tree,
         * so a fixed buffer is honest here in a way it was not above. */
        static char out[1024 * 1024];
        char exe[PATH_MAX];
        ASSERT(os_proc_exe_path(exe, sizeof(exe)));
        ASSERT(exe[0] != '\0');
        char command[PATH_MAX + 320];
        int n = snprintf(command, sizeof(command),
                         "\"%s\" --jobs=1 --exact=test_hex_codec "
                         "--no-cache 2>&1", exe);
        ASSERT(n > 0 && (size_t)n < sizeof(command));
        int rc = capture_command(command, out, sizeof(out));
        if (rc != 0)
            fprintf(stderr, "nested exact positive control:\n%s\n", out);
        ASSERT(rc == 0);
        ASSERT(strstr(out, "groups_ran=1") != NULL);
        ASSERT(strstr(out, "groups_failed=0") != NULL);
        ASSERT(strstr(out, "\"schema\":\"zcl.test_phase_receipt.v1\"") !=
               NULL);
        ASSERT(strstr(out, "\"startup_ms\":") != NULL);
        ASSERT(strstr(out, "\"test_body_ms\":") != NULL);

        struct json_value timing = {0};
        ASSERT(selector_timing_read(&timing));
        ASSERT(selector_timing_zero(&timing, "self_skips"));
        ASSERT(selector_timing_zero(&timing, "env_unobserved"));
        ASSERT(selector_timing_zero(&timing, "load_flaky"));
        ASSERT(selector_timing_hex_key(json_get(&timing, "toolkey_full")));
        const struct json_value *module = json_get(&timing,
                                                   "hotswap_module_active");
        ASSERT(module && module->type == JSON_BOOL && !json_get_bool(module));
        ASSERT(json_get(&timing, "hotswap_module_sha256") &&
               json_is_null(json_get(&timing, "hotswap_module_sha256")));
        ASSERT(json_get(&timing, "hotswap_module_source") &&
               json_is_null(json_get(&timing, "hotswap_module_source")));
        const struct json_value *timing_rows = json_get(&timing, "groups");
        ASSERT(timing_rows && timing_rows->type == JSON_ARR &&
               json_size(timing_rows) == 1);
        const struct json_value *timing_row = json_at(timing_rows, 0);
        ASSERT(strcmp(json_get_str(json_get(timing_row, "name")),
                      "test_hex_codec") == 0);
        ASSERT(json_get_bool(json_get(timing_row, "measured")));
        const struct json_value *key_valid = json_get(timing_row, "key_valid");
        ASSERT(key_valid && key_valid->type == JSON_BOOL &&
               !json_get_bool(key_valid));
        ASSERT(json_get(timing_row, "input_key") &&
               json_is_null(json_get(timing_row, "input_key")));
        ASSERT(selector_timing_zero(timing_row, "proof_contract"));
        ASSERT(selector_timing_zero(timing_row, "skip_markers"));
        ASSERT(selector_timing_zero(timing_row, "env_unobserved"));
        ASSERT(selector_timing_zero(timing_row, "load_flaky"));
        json_free(&timing);

        n = snprintf(command, sizeof(command), "\"%s\" --source-id 2>&1",
                     exe);
        ASSERT(n > 0 && (size_t)n < sizeof(command));
        rc = capture_command(command, out, sizeof(out));
        dump_bad_rc("nested --source-id", rc, 0, out);
        ASSERT(rc == 0);
        char expected_source[80];
        ASSERT(snprintf(expected_source, sizeof(expected_source), "%s\n",
                        zcl_build_source_id_sha256()) == 65);
        ASSERT(strcmp(out, expected_source) == 0);

        n = snprintf(command, sizeof(command),
                     "\"%s\" --source-record 2>&1", exe);
        ASSERT(n > 0 && (size_t)n < sizeof(command));
        rc = capture_command(command, out, sizeof(out));
        dump_bad_rc("nested --source-record", rc, 0, out);
        ASSERT(rc == 0);
        char expected_record[160];
        ASSERT(snprintf(expected_record, sizeof(expected_record),
                        "%s 1 %s\n", zcl_build_source_id_sha256(),
                        zcl_build_source_mutation_sha256()) == 132);
        ASSERT(strcmp(out, expected_record) == 0);

        n = snprintf(command, sizeof(command),
                     "\"%s\" --source-id --list 2>&1", exe);
        ASSERT(n > 0 && (size_t)n < sizeof(command));
        rc = capture_command(command, out, sizeof(out));
        ASSERT(rc == 2);
        ASSERT(strstr(out, "Usage:") != NULL);

        n = snprintf(command, sizeof(command),
                     "\"%s\" --jobs=1 "
                     "--exact=test_hex_codec,test_byte_order_codec "
                     "--no-cache 2>&1", exe);
        ASSERT(n > 0 && (size_t)n < sizeof(command));
        rc = capture_command(command, out, sizeof(out));
        dump_bad_rc("nested exact two-id", rc, 0, out);
        ASSERT(rc == 0);
        ASSERT(strstr(out, "groups_ran=2") != NULL);
        ASSERT(strstr(out, "groups_failed=0") != NULL);

        /* Exercise the runner's proof-contract/cache boundary with the
         * smallest real STRESS-contract group.  The contract dispatch is the
         * behavior under test here; recursively running the roughly
         * 100-second reducer forward-progress acceptance twice only tested
         * that unrelated product behavior twice and dominated every exact
         * selector proof. */
        ASSERT(zcl_test_group_proof_contract("test_store_e2e_gate") ==
               ZCL_TEST_PROOF_STRESS);
        n = snprintf(command, sizeof(command),
                     "\"%s\" --jobs=1 "
                     "--exact=test_store_e2e_gate "
                     "--activate-proof-contracts --cache 2>&1", exe);
        ASSERT(n > 0 && (size_t)n < sizeof(command));
        char first_proof_key[65] = {0};
        for (int proof_run = 0; proof_run < 2; proof_run++) {
            rc = capture_command(command, out, sizeof(out));
            dump_bad_rc("nested proof-contract activation", rc, 0, out);
            ASSERT(rc == 0);
            ASSERT(strstr(out,
                          "proof contract "
                          "group=test_store_e2e_gate "
                          "env=ZCL_STRESS_TESTS") != NULL);
            ASSERT(strstr(out, "active-proof-contract") != NULL);
            ASSERT(strstr(out, "cache PLAN — 0 cacheable, 0 cache HIT") !=
                   NULL);
            ASSERT(strstr(out, "groups_ran=1 groups_cached=0") != NULL);
            ASSERT(strstr(out, "groups_failed=0 self_skips=0") != NULL);
            ASSERT(selector_timing_read(&timing));
            timing_rows = json_get(&timing, "groups");
            ASSERT(timing_rows && json_size(timing_rows) == 1);
            timing_row = json_at(timing_rows, 0);
            ASSERT(json_get_bool(json_get(timing_row, "measured")));
            ASSERT(!json_get_bool(json_get(timing_row, "cached")));
            ASSERT(json_get_int(json_get(timing_row, "proof_contract")) ==
                   ZCL_TEST_PROOF_STRESS);
            ASSERT(json_get_bool(json_get(timing_row, "key_valid")));
            ASSERT(selector_timing_hex_key(json_get(timing_row, "input_key")));
            const char *key = json_get_str(json_get(timing_row, "input_key"));
            if (proof_run == 0)
                memcpy(first_proof_key, key, sizeof(first_proof_key));
            else
                ASSERT(strcmp(first_proof_key, key) == 0);
            ASSERT(selector_timing_zero(timing_row, "skip_markers"));
            ASSERT(selector_timing_zero(timing_row, "env_unobserved"));
            json_free(&timing);
        }

        n = snprintf(command, sizeof(command),
                     "env -u ZCL_STRESS_TESTS \"%s\" --jobs=1 "
                     "--exact=test_store_e2e_gate --no-cache 2>&1", exe);
        ASSERT(n > 0 && (size_t)n < sizeof(command));
        rc = capture_command(command, out, sizeof(out));
        ASSERT(rc == 0);
        ASSERT(strstr(out, "self_skips=1") != NULL);
        ASSERT(selector_timing_read(&timing));
        ASSERT(json_get_int(json_get(&timing, "self_skips")) == 1);
        timing_row = json_at(json_get(&timing, "groups"), 0);
        ASSERT(json_get_int(json_get(timing_row, "skip_markers")) > 0);
        ASSERT(json_get_bool(json_get(timing_row, "measured")));
        ASSERT(selector_timing_zero(timing_row, "rc"));
        ASSERT(selector_timing_zero(timing_row, "proof_contract"));
        json_free(&timing);

        n = snprintf(command, sizeof(command),
                     "\"%s\" --activate-proof-contracts --no-cache 2>&1",
                     exe);
        ASSERT(n > 0 && (size_t)n < sizeof(command));
        rc = capture_command(command, out, sizeof(out));
        ASSERT(rc == 2);
        ASSERT(strstr(out,
                      "--activate-proof-contracts requires an exact selector")
               != NULL);

        /* "test_api" is a valid exact id. Bare "api" is deliberately not:
         * accepting it here would restore the substring false-green. */
        n = snprintf(command, sizeof(command),
                     "\"%s\" --jobs=1 --exact=api --no-cache 2>&1", exe);
        ASSERT(n > 0 && (size_t)n < sizeof(command));
        rc = capture_command(command, out, sizeof(out));
        ASSERT(rc == 2);
        ASSERT(strstr(out, "--exact contains no registered group: api") !=
               NULL);

        n = snprintf(command, sizeof(command),
                     "\"%s\" --jobs=1 "
                     "--exact=test_hex_codec,api --no-cache 2>&1", exe);
        ASSERT(n > 0 && (size_t)n < sizeof(command));
        rc = capture_command(command, out, sizeof(out));
        ASSERT(rc == 2);
        ASSERT(strstr(out, "--exact contains no registered group: api") !=
               NULL);

        /* Exercise the Make admission seam without running its recipe (and
         * therefore without recursively acquiring the checkout lock). */
        n = snprintf(command, sizeof(command),
                     "make -n t-fast-exact ONLY=api "
                     "TEST_PARALLEL_ARGS= "
                     "TEST_PARALLEL_FAST_CANDIDATE=/bin/true "
                     "TEST_PARALLEL_FAST_ACTIVE=/bin/true "
                     "BUILD_SOURCE_RECORD='%s 1 %s' 2>&1",
                     zcl_build_source_id_sha256(),
                     zcl_build_source_mutation_sha256());
        ASSERT(n > 0 && (size_t)n < sizeof(command));
        rc = capture_command_ends(command, head, sizeof(head), tail,
                                  sizeof(tail));
        dump_bad_rc("make -n t-fast-exact ONLY=api (head)", rc, 0, head);
        dump_bad_rc("make -n t-fast-exact ONLY=api (tail)", rc, 0, tail);
        ASSERT(rc == 0);
        ASSERT(strstr(head, "resolves to exact set test_api") != NULL);
        ASSERT(strstr(tail, "--exact=test_api") != NULL);

        n = snprintf(command, sizeof(command),
                     "make -n t-fast-exact ONLY=api_missing "
                     "TEST_PARALLEL_ARGS= "
                     "TEST_PARALLEL_FAST_CANDIDATE=/bin/true "
                     "TEST_PARALLEL_FAST_ACTIVE=/bin/true "
                     "BUILD_SOURCE_RECORD='%s 1 %s' 2>&1",
                     zcl_build_source_id_sha256(),
                     zcl_build_source_mutation_sha256());
        ASSERT(n > 0 && (size_t)n < sizeof(command));
        /* The refusal is a parse-time $(error): make stops before printing
         * any recipe, so this leg is small and the head alone carries it. */
        rc = capture_command_ends(command, head, sizeof(head), tail,
                                  sizeof(tail));
        ASSERT(rc == 2);
        ASSERT(strstr(head, "ONLY='api_missing' is not a valid exact registered group set") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

int test_test_group_selector(void)
{
    int failures = 0;
    failures += test_tmpdir_recursive_cleanup();
    failures += test_selector_predicate();
    failures += test_registry_exact_resolution();
    failures += test_native_catalog_resolution();
    failures += test_process_sensitive_groups_are_catalog_exclusive();
    failures += test_runner_exact_selection();
    failures += test_assert_macros_report_where_and_what();
    failures += test_assert_messages_name_file_line_and_values();
    return failures;
}
