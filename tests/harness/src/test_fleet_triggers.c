/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for fleet.triggers (tools/command/native_fleet_triggers_*.c).
 *
 * z23 owns its own reactions to local events instead of a human watching a
 * board or a landing queue by hand. Every case below runs against an
 * isolated XDG_STATE_HOME/HOME and a fixed injected clock, so it proves the
 * evaluator's own behavior — cursor advance, dry-run, truncation, absent
 * fields, the JSON shape, the stamped clock — rather than the state of this
 * machine's real board or landing queue.
 *
 * The handlers are called DIRECTLY, with the input additionally validated
 * through the real registry first (as dev.land's own acceptance test does),
 * so a key the .def never declared is caught here rather than passing
 * in-process and failing from a shell.
 */

#include "test/test_core.h"

#include "command/native_fleet_triggers.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/clock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define FTX_PATH "fleet.triggers.check"

/* ── isolated state root ─────────────────────────────────────────────── */

static char g_ftx_state[PATH_MAX];
static char g_ftx_home[PATH_MAX];
static char g_ftx_saved_xdg[PATH_MAX];
static char g_ftx_saved_home[PATH_MAX];
static bool g_ftx_saved;

static void ftx_isolate(const char *tag)
{
    char base[PATH_MAX - 64];
    test_make_tmpdir(base, sizeof(base), "fleet_triggers", tag);
    if (!g_ftx_saved) {
        g_ftx_saved = true;
        const char *xdg = getenv("XDG_STATE_HOME");
        const char *home = getenv("HOME");
        (void)snprintf(g_ftx_saved_xdg, sizeof(g_ftx_saved_xdg), "%s",
                      xdg ? xdg : "");
        (void)snprintf(g_ftx_saved_home, sizeof(g_ftx_saved_home), "%s",
                      home ? home : "");
    }
    (void)snprintf(g_ftx_state, sizeof(g_ftx_state), "%s/state", base);
    (void)snprintf(g_ftx_home, sizeof(g_ftx_home), "%s/home", base);
    setenv("XDG_STATE_HOME", g_ftx_state, 1);
    setenv("HOME", g_ftx_home, 1);
}

static void ftx_restore(void)
{
    if (!g_ftx_saved)
        return;
    if (g_ftx_saved_xdg[0])
        setenv("XDG_STATE_HOME", g_ftx_saved_xdg, 1);
    else
        unsetenv("XDG_STATE_HOME");
    if (g_ftx_saved_home[0])
        setenv("HOME", g_ftx_saved_home, 1);
    else
        unsetenv("HOME");
}

static void ftx_mkdir_p(const char *path)
{
    char copy[PATH_MAX];
    size_t length = strlen(path);
    if (!length || length >= sizeof copy)
        return;
    memcpy(copy, path, length + 1u);
    for (char *p = copy + (copy[0] == '/' ? 1 : 0); ; p++) {
        if (*p != '/' && *p != '\0')
            continue;
        char saved = *p;
        *p = '\0';
        if (copy[0])
            (void)mkdir(copy, 0700);
        *p = saved;
        if (!saved)
            break;
    }
}

/* Write `content` to the path a source resolves to, creating parent
 * directories first. */
static void ftx_write_file(const char *path, const char *content)
{
    char dir[PATH_MAX];
    (void)snprintf(dir, sizeof dir, "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash)
        *slash = 0;
    ftx_mkdir_p(dir);
    FILE *f = fopen(path, "wb");
    if (!f)
        return;
    (void)fputs(content, f);
    fclose(f);
}

/* ── fixed clock: every "ts" this run stamps must be exactly this ──────── */

#define FTX_FAKE_WALL_MS  1757000000000LL /* 2025-09-04T15:33:20Z */
#define FTX_FAKE_TS_ISO  "2025-09-04T15:33:20Z"

static int64_t ftx_fake_now_mono(void *self)
{
    (void)self;
    return 1;
}

static int64_t ftx_fake_now_wall(void *self)
{
    (void)self;
    return FTX_FAKE_WALL_MS;
}

static void ftx_install_clock(void)
{
    static const clock_iface_t iface = {
        .now_monotonic_ns = ftx_fake_now_mono,
        .now_wall_ms = ftx_fake_now_wall,
        .self = NULL,
    };
    clock_set_default(&iface);
}

/* ── one in-process `fleet.triggers.check` call ─────────────────────────── */

struct ftx_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void ftx_begin(struct ftx_call *c, bool dry_run, int64_t since_s)
{
    json_init(&c->input);
    json_set_object(&c->input);
    if (dry_run)
        (void)json_push_kv_bool(&c->input, "dry-run", true);
    if (since_s > 0)
        (void)json_push_kv_int(&c->input, "since", since_s);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec = zcl_command_registry_find(zcl_command_catalog(),
                                                FTX_PATH, NULL);
    zcl_command_reply_init(&c->reply, "zcl.fleet_triggers_check.v1");
}

static bool ftx_run(struct ftx_call *c)
{
    char why[256];
    if (c->request.spec &&
        !zcl_command_registry_input_validate(c->request.spec, &c->input, why,
                                             sizeof(why))) {
        printf("[input rejected: %s] ", why);
        return false;
    }
    zcl_native_handle_fleet_triggers_check(&c->request, &c->reply);
    return true;
}

static void ftx_end(struct ftx_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static int64_t ftx_int(const struct ftx_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v ? json_get_int(v) : -1;
}

/* ── fired.jsonl line counting, without trusting any parser but our own
 * newline count ─────────────────────────────────────────────────────── */

static size_t ftx_count_lines(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return 0;
    size_t n = 0;
    int ch;
    while ((ch = fgetc(f)) != EOF)
        if (ch == '\n')
            n++;
    fclose(f);
    return n;
}

static bool ftx_file_contains(const char *path, const char *needle)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    char buf[8192];
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = 0;
    return strstr(buf, needle) != NULL;
}

/* Capture stdout around one ftx_run call, into a caller buffer. */
static bool ftx_run_captured(struct ftx_call *c, char *out, size_t cap)
{
    fflush(stdout);
    FILE *capture = tmpfile();
    if (!capture)
        return false;
    int saved_out = dup(STDOUT_FILENO);
    if (saved_out < 0 || dup2(fileno(capture), STDOUT_FILENO) < 0) {
        if (saved_out >= 0)
            close(saved_out);
        fclose(capture);
        return false;
    }
    bool ran = ftx_run(c);
    fflush(stdout);
    (void)dup2(saved_out, STDOUT_FILENO);
    close(saved_out);
    rewind(capture);
    size_t n = fread(out, 1, cap - 1, capture);
    out[n] = 0;
    fclose(capture);
    return ran;
}

/* Each of the following is one property from the group's ACCEPTANCE BAR
 * above, pulled out of the single group entry function purely to keep each
 * one's own decision-point count under the per-function cyclomatic-
 * complexity cap — the assertions, fixtures, and isolation are unchanged
 * from a single flat function; only where the goto ASSERT() lands (the
 * end of THIS case, not the end of the whole group) is different. */

static int ftx_case_landed_ledger_once(void)
{
    int failures = 0;
    char landing_path[PATH_MAX], fired_path[PATH_MAX];

    ftx_isolate("landed_ledger_once");
    ftx_install_clock();
    ASSERT(zcl_trigger_landing_path(landing_path, sizeof landing_path));
    ASSERT(zcl_trigger_fired_ledger_path(fired_path, sizeof fired_path));
    ftx_write_file(landing_path,
                  "{\"seq\":1,\"ts\":\"2026-09-06T10:00:00Z\","
                  "\"state\":\"landed\",\"note\":\"demo\"}\n");

    printf("fleet_triggers: landed row ledgers exactly once across two "
          "runs... ");
    struct ftx_call c1;
    ftx_begin(&c1, false, 0);
    ASSERT(ftx_run(&c1));
    ASSERT_EQ(ftx_int(&c1, "checked"), 1);
    ASSERT_EQ(ftx_int(&c1, "fired"), 1);
    ftx_end(&c1);
    ASSERT_EQ((int64_t)ftx_count_lines(fired_path), 1);
    ASSERT(ftx_file_contains(fired_path, "landing_landed_to_ledger"));

    struct ftx_call c2;
    ftx_begin(&c2, false, 0);
    ASSERT(ftx_run(&c2));
    ASSERT_EQ(ftx_int(&c2, "checked"), 0);
    ASSERT_EQ(ftx_int(&c2, "fired"), 0);
    ftx_end(&c2);
    ASSERT_EQ((int64_t)ftx_count_lines(fired_path), 1);
    clock_reset_default();
    PASS();
_test_next:;
    return failures;
}

static int ftx_case_failed_prints(void)
{
    int failures = 0;
    char landing_path[PATH_MAX], fired_path[PATH_MAX];

    ftx_isolate("failed_prints");
    ASSERT(zcl_trigger_landing_path(landing_path, sizeof landing_path));
    ASSERT(zcl_trigger_fired_ledger_path(fired_path, sizeof fired_path));
    ftx_write_file(landing_path,
                  "{\"seq\":1,\"ts\":\"2026-09-06T10:00:00Z\","
                  "\"state\":\"failed\",\"note\":\"demo\"}\n");

    printf("fleet_triggers: failed row prints, does not ledger... ");
    struct ftx_call c;
    ftx_begin(&c, false, 0);
    char out[4096];
    ASSERT(ftx_run_captured(&c, out, sizeof out));
    ASSERT(strstr(out, "TRIGGER landing_failed_print landing_outcomes "
                      "state=failed") != NULL);
    ASSERT_EQ(ftx_int(&c, "fired"), 1);
    ftx_end(&c);
    /* print never writes the ledger file at all. */
    FILE *never = fopen(fired_path, "rb");
    ASSERT(never == NULL);
    PASS();
_test_next:;
    return failures;
}

static int ftx_case_dry_run_no_advance(void)
{
    int failures = 0;
    char landing_path[PATH_MAX];

    ftx_isolate("dry_run_no_advance");
    ASSERT(zcl_trigger_landing_path(landing_path, sizeof landing_path));
    ftx_write_file(landing_path,
                  "{\"seq\":1,\"ts\":\"2026-09-06T10:00:00Z\","
                  "\"state\":\"landed\",\"note\":\"demo\"}\n");

    printf("fleet_triggers: --dry-run fires but never advances the "
          "cursor... ");
    struct ftx_call c1;
    ftx_begin(&c1, true, 0);
    ASSERT(ftx_run(&c1));
    ASSERT_EQ(ftx_int(&c1, "checked"), 1);
    ASSERT_EQ(ftx_int(&c1, "fired"), 1);
    ftx_end(&c1);

    struct ftx_call c2;
    ftx_begin(&c2, true, 0);
    ASSERT(ftx_run(&c2));
    ASSERT_EQ(ftx_int(&c2, "checked"), 1);
    ASSERT_EQ(ftx_int(&c2, "fired"), 1);
    ftx_end(&c2);
    PASS();
_test_next:;
    return failures;
}

static int ftx_case_truncated_restarts(void)
{
    int failures = 0;
    char landing_path[PATH_MAX];

    ftx_isolate("truncated_restarts");
    ASSERT(zcl_trigger_landing_path(landing_path, sizeof landing_path));
    ftx_write_file(landing_path,
                  "{\"seq\":1,\"ts\":\"2026-09-06T10:00:00Z\","
                  "\"state\":\"landed\",\"note\":\"one\"}\n");

    printf("fleet_triggers: a shrunk source restarts from byte zero... ");
    struct ftx_call c1;
    ftx_begin(&c1, false, 0);
    ASSERT(ftx_run(&c1));
    ASSERT_EQ(ftx_int(&c1, "checked"), 1);
    ftx_end(&c1);

    /* Shrink the file (a rotated/replaced outcomes.jsonl), then write a
     * single fresh row shorter than what the cursor last saw. */
    ftx_write_file(landing_path,
                  "{\"seq\":1,\"ts\":\"2026-09-06T10:01:00Z\","
                  "\"state\":\"landed\"}\n");
    struct ftx_call c2;
    ftx_begin(&c2, false, 0);
    ASSERT(ftx_run(&c2));
    ASSERT_EQ(ftx_int(&c2, "checked"), 1);
    ASSERT_EQ(ftx_int(&c2, "fired"), 1);
    ftx_end(&c2);
    PASS();
_test_next:;
    return failures;
}

static int ftx_case_unknown_field_never_fires(void)
{
    int failures = 0;
    char landing_path[PATH_MAX];

    ftx_isolate("unknown_field_never_fires");
    ASSERT(zcl_trigger_landing_path(landing_path, sizeof landing_path));
    /* No "state" key at all: every trigger reading "state" must see it as
     * absent, not as an empty or mismatched string, and never fire — "ne"
     * included, though the registry only declares "eq" here. */
    ftx_write_file(landing_path,
                  "{\"seq\":1,\"ts\":\"2026-09-06T10:00:00Z\","
                  "\"note\":\"no state field\"}\n");

    printf("fleet_triggers: a row missing the matched field never "
          "fires... ");
    struct ftx_call c;
    ftx_begin(&c, false, 0);
    ASSERT(ftx_run(&c));
    ASSERT_EQ(ftx_int(&c, "checked"), 1);
    ASSERT_EQ(ftx_int(&c, "fired"), 0);
    ftx_end(&c);
    PASS();
_test_next:;
    return failures;
}

static int ftx_case_board_and_experiment_sources(void)
{
    int failures = 0;
    char board_path[PATH_MAX], exp_path[PATH_MAX];

    ftx_isolate("board_and_experiment_sources");
    ASSERT(zcl_trigger_board_path(board_path, sizeof board_path));
    ASSERT(zcl_trigger_experiment_path(exp_path, sizeof exp_path));
    ftx_write_file(board_path,
                  "{\"ts\":\"2026-09-06T10:00:00Z\",\"id\":\"a1\","
                  "\"host\":\"h\",\"agent\":\"x\",\"kind\":\"need\","
                  "\"ref\":\"\",\"text\":\"help\"}\n");
    ftx_write_file(
        exp_path,
        "ts\tkind\tbox\ttask_id\ttask_class\tstory\texecutor\tharness\t"
        "model\teffort\ttokens_in\ttokens_out\ttokens_cache\t"
        "tokens_reasoning\ttool_uses\tturns\twall_s\toutcome\t"
        "lines_added\tlines_removed\tdefects\tnote\n"
        "2026-09-06T10:00:00Z\tresult\tnode1\tt1\tread\ts\te\th\tm\tlow\t"
        "1\t1\t0\t0\t0\t1\t1\ttimeout\t0\t0\t0\tn\n");

    printf("fleet_triggers: board need and experiment timeout both "
          "fire... ");
    struct ftx_call c;
    ftx_begin(&c, false, 0);
    ASSERT(ftx_run(&c));
    ASSERT_EQ(ftx_int(&c, "checked"), 2);
    ASSERT_EQ(ftx_int(&c, "fired"), 2);
    ftx_end(&c);
    PASS();
_test_next:;
    return failures;
}

static int ftx_case_json_well_formed(void)
{
    int failures = 0;
    char landing_path[PATH_MAX];

    ftx_isolate("json_well_formed");
    ASSERT(zcl_trigger_landing_path(landing_path, sizeof landing_path));
    ftx_write_file(landing_path,
                  "{\"seq\":1,\"ts\":\"2026-09-06T10:00:00Z\","
                  "\"state\":\"landed\"}\n");

    printf("fleet_triggers: the check reply serializes and re-parses "
          "cleanly... ");
    struct ftx_call c;
    ftx_begin(&c, false, 0);
    ASSERT(ftx_run(&c));
    char buf[65536];
    size_t n = json_write(&c.reply.data, buf, sizeof buf);
    ASSERT(n > 0 && n < sizeof buf);
    struct json_value reread;
    ASSERT(json_read(&reread, buf, n));
    ASSERT(reread.type == JSON_OBJ);
    ASSERT(json_get(&reread, "checked") != NULL);
    ASSERT(json_get(&reread, "fired_ids") != NULL);
    json_free(&reread);
    ftx_end(&c);
    PASS();
_test_next:;
    return failures;
}

static int ftx_case_clock_stamps_ts(void)
{
    int failures = 0;
    char landing_path[PATH_MAX], fired_path[PATH_MAX];

    ftx_isolate("clock_stamps_ts");
    ftx_install_clock();
    ASSERT(zcl_trigger_landing_path(landing_path, sizeof landing_path));
    ASSERT(zcl_trigger_fired_ledger_path(fired_path, sizeof fired_path));
    ftx_write_file(landing_path,
                  "{\"seq\":1,\"ts\":\"2026-09-06T10:00:00Z\","
                  "\"state\":\"landed\"}\n");

    printf("fleet_triggers: the injected clock stamps the ledger row's "
          "ts... ");
    struct ftx_call c;
    ftx_begin(&c, false, 0);
    ASSERT(ftx_run(&c));
    ftx_end(&c);
    ASSERT(ftx_file_contains(fired_path, "\"ts\":\"" FTX_FAKE_TS_ISO "\""));
    clock_reset_default();
    PASS();
_test_next:;
    return failures;
}

/* Exercises `fleet.triggers.list`, so the registry accessor and its
 * rendering are proven too, not only `check`. */
static int ftx_case_list_enumerates(void)
{
    int failures = 0;

    printf("fleet_triggers: list enumerates the closed registry... ");
    struct zcl_command_request req;
    struct zcl_command_reply reply;
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    memset(&req, 0, sizeof req);
    req.input = &input;
    zcl_command_reply_init(&reply, "zcl.fleet_triggers_list.v1");
    zcl_native_handle_fleet_triggers_list(&req, &reply);
    ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED);
    ASSERT_EQ((int64_t)json_get_int(json_get(&reply.data, "count")),
             (int64_t)zcl_trigger_count());
    ASSERT(zcl_trigger_count() >= 6);
    zcl_command_reply_free(&reply);
    json_free(&input);
    PASS();
_test_next:;
    return failures;
}

int test_fleet_triggers(void);
int test_fleet_triggers(void)
{
    int failures = 0;
    failures += ftx_case_landed_ledger_once();
    failures += ftx_case_failed_prints();
    failures += ftx_case_dry_run_no_advance();
    failures += ftx_case_truncated_restarts();
    failures += ftx_case_unknown_field_never_fires();
    failures += ftx_case_board_and_experiment_sources();
    failures += ftx_case_json_well_formed();
    failures += ftx_case_clock_stamps_ts();
    failures += ftx_case_list_enumerates();

    ftx_restore();
    if (failures == 0)
        printf("test_fleet_triggers: all passed\n");
    else
        printf("test_fleet_triggers: %d FAILED\n", failures);
    return failures;
}
