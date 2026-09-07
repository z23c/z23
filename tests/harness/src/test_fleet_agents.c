/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for dev.fleet.agents (tools/command/native_dev_agents_*.c).
 *
 * Everything here is proved against fixtures built in this file — a
 * throwaway workspace root holding two small Git repositories and a
 * hand-written delegation ledger — never against the machine the test runs
 * on, so it grades BEHAVIOUR rather than whatever this box happens to be
 * doing today.
 *
 * NO VERDICT HERE IS DECIDED BY A CLOCK. `now` is injected through the
 * platform clock seam (clock_set_default), so the same ledger grades to the
 * same numbers on every machine forever. The one thing deliberately NOT
 * asserted is the AGE of a fixture file: those files are created while the
 * test runs, so their modification times come from the real clock and no
 * pass/fail may ride on them.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_dev_agents.h"
#include "config/command_catalog.h"
#include "controllers/rpc_client.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/clock.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAX_PATH "dev.fleet.agents"

/* 2026-09-06T12:00:00Z. Every timestamp in the fixture ledger is written
 * relative to this instant, and the leaf is told this is now. */
#define FAX_NOW 1788696000LL

/* ── the injected clock ─────────────────────────────────────────────────── */

static int64_t fax_mono(void *self) { (void)self; return 1000; }
static int64_t fax_wall(void *self) { (void)self; return FAX_NOW * 1000LL; }
static const clock_iface_t fax_clock = {
    .now_monotonic_ns = fax_mono, .now_wall_ms = fax_wall, .self = NULL,
};

/* ── fixture helpers ────────────────────────────────────────────────────── */

static bool fax_git(const char *dir, const char *const args[])
{
    const char *argv[24];
    char out[8192];
    size_t n = 0;
    argv[n++] = "git";
    argv[n++] = "-C";
    argv[n++] = dir;
    for (size_t i = 0; args[i]; i++) {
        if (n + 1 >= sizeof(argv) / sizeof(argv[0])) return false;
        argv[n++] = args[i];
    }
    argv[n] = NULL;
    return zcl_spawn_capture(argv, out, sizeof(out), 60000) == 0;
}

static bool fax_write(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    size_t len = strlen(text);
    bool wrote;
    if (!f) return false;
    wrote = fwrite(text, 1, len, f) == len;
    return fclose(f) == 0 && wrote;
}

static bool fax_mkdir(const char *path)
{
    const char *argv[] = {"mkdir", "-p", path, NULL};
    char out[512];
    return zcl_spawn_capture(argv, out, sizeof(out), 30000) == 0;
}

/* One small repository with one commit. `dirty` leaves an uncommitted edit. */
static bool fax_repo(const char *root, const char *name, bool dirty)
{
    char dir[1024], file[1200];
    static const char *const init[] = {"-c", "init.defaultBranch=main", "init",
                                       "-q", ".", NULL};
    static const char *const add[] = {"add", "-A", NULL};
    static const char *const commit[] = {
        "-c", "user.name=Z23 Test", "-c",
        "user.email=z23-test@example.invalid", "-c", "commit.gpgsign=false",
        "commit", "-q", "-m", "base", NULL};
    (void)snprintf(dir, sizeof(dir), "%s/lanes/%s", root, name);
    if (!fax_mkdir(dir)) return false;
    (void)snprintf(file, sizeof(file), "%s/source.c", dir);
    if (!fax_write(file, "int main(void){return 0;}\n")) return false;
    if (!fax_git(dir, init) || !fax_git(dir, add) || !fax_git(dir, commit))
        return false;
    if (dirty && !fax_write(file, "int main(void){return 1;}\n")) return false;
    return true;
}

/* ── the fixture ledger ─────────────────────────────────────────────────── */

/* One row. The 22 columns are the ledger's own order; only the ones a grade
 * reads carry meaning here and the rest are filled with plausible constants,
 * so a column that silently moved would change a number this file asserts. */
#define FAX_ROW(ts, kind, task, class_, story, exec, tin, tout, wall, outcome) \
    ts "\t" kind "\tnode1\t" task "\t" class_ "\t" story "\t" exec            \
       "\tagent-tool\tmodel\tmedium\t" tin "\t" tout                          \
       "\t0\t0\t0\t0\t" wall "\t" outcome "\t0\t0\t0\tnote\n"

static const char *const FAX_LEDGER =
    "ts\tkind\tbox\ttask_id\ttask_class\tstory\texecutor\tharness\tmodel"
    "\teffort\ttokens_in\ttokens_out\ttokens_cache\ttokens_reasoning"
    "\ttool_uses\tturns\twall_s\toutcome\tlines_added\tlines_removed"
    "\tdefects\tnote\n"
    /* grok: four results, all successful, three of them predicted. */
    FAX_ROW("2026-09-06T10:00:00Z", "result", "g1", "read", "alpha", "grok",
            "1000", "200", "100", "LAND")
    FAX_ROW("2026-09-06T10:01:00Z", "result", "g2", "read", "alpha", "grok",
            "2000", "400", "200", "LAND")
    FAX_ROW("2026-09-06T10:02:00Z", "result", "g3", "read", "alpha", "grok",
            "3000", "600", "300", "LAND")
    FAX_ROW("2026-09-06T10:03:00Z", "result", "g4", "read", "alpha", "grok",
            "4000", "800", "400", "READY")
    FAX_ROW("2026-09-06T09:00:00Z", "predict", "g1", "read", "alpha", "grok",
            "0", "0", "100", "LAND")
    FAX_ROW("2026-09-06T09:01:00Z", "predict", "g2", "read", "alpha", "grok",
            "0", "0", "200", "LAND")
    FAX_ROW("2026-09-06T09:02:00Z", "predict", "g3", "read", "alpha", "grok",
            "0", "0", "200", "LAND")
    /* A prediction whose delegation never reported back. It must count as a
     * prediction and must not invent a result. */
    FAX_ROW("2026-09-06T09:03:00Z", "predict", "zz", "read", "alpha", "grok",
            "0", "0", "999", "LAND")
    /* claude-sonnet: four successes and one HOLD, running late. */
    FAX_ROW("2026-09-06T10:10:00Z", "result", "s1", "unit_docs", "beta",
            "claude-sonnet", "100", "0", "100", "LAND")
    FAX_ROW("2026-09-06T10:11:00Z", "result", "s2", "unit_docs", "beta",
            "claude-sonnet", "100", "0", "200", "LAND")
    FAX_ROW("2026-09-06T10:12:00Z", "result", "s3", "unit_docs", "beta",
            "claude-sonnet", "100", "0", "300", "READY")
    FAX_ROW("2026-09-06T10:13:00Z", "result", "s4", "unit_docs", "beta",
            "claude-sonnet", "100", "0", "400", "landed")
    FAX_ROW("2026-09-06T10:14:00Z", "result", "s5", "unit_docs", "beta",
            "claude-sonnet", "100", "0", "500", "HOLD")
    FAX_ROW("2026-09-06T09:10:00Z", "predict", "s1", "unit_docs", "beta",
            "claude-sonnet", "0", "0", "50", "LAND")
    FAX_ROW("2026-09-06T09:11:00Z", "predict", "s2", "unit_docs", "beta",
            "claude-sonnet", "0", "0", "100", "LAND")
    FAX_ROW("2026-09-06T09:12:00Z", "predict", "s3", "unit_docs", "beta",
            "claude-sonnet", "0", "0", "100", "LAND")
    /* codex: two failures and one land. */
    FAX_ROW("2026-09-06T10:20:00Z", "result", "c1", "diagnose", "gamma",
            "codex", "0", "0", "60", "failed")
    FAX_ROW("2026-09-06T10:21:00Z", "result", "c2", "diagnose", "gamma",
            "codex", "0", "0", "90", "failed")
    FAX_ROW("2026-09-06T10:22:00Z", "result", "c3", "diagnose", "gamma",
            "codex", "0", "0", "120", "LAND")
    /* glm: too few results to earn a letter. */
    FAX_ROW("2026-09-06T10:30:00Z", "result", "m1", "read", "delta", "glm",
            "0", "0", "10", "LAND")
    FAX_ROW("2026-09-06T10:31:00Z", "result", "m2", "read", "delta", "glm",
            "0", "0", "20", "LAND")
    /* Five days old: inside the ledger, outside a 24-hour window. */
    FAX_ROW("2026-09-01T00:00:00Z", "result", "o1", "read", "epsilon", "muse",
            "0", "0", "77", "LAND")
    /* Malformed: five columns where the ledger has twenty-two. */
    "2026-09-06T10:40:00Z\tresult\tnode1\tbad\tclaude-opus\n";

/* Line numbers above, counted from 1 including the header. */
#define FAX_LEDGER_LINES 24
#define FAX_BAD_LINE 24

/* ── one in-process invocation ──────────────────────────────────────────── */

struct fax_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void fax_begin(struct fax_call *c)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), FAX_PATH, NULL);
    zcl_command_reply_init(&c->reply, ZCL_AGENTS_SCHEMA);
}

/* Validate through the REAL registry first: a key the .def never declared, or
 * one the transport's type chain refuses, must fail HERE rather than pass
 * in-process and be unreachable from a shell. */
static bool fax_run(struct fax_call *c)
{
    char why[192];
    if (c->request.spec &&
        !zcl_command_registry_input_validate(c->request.spec, &c->input, why,
                                             sizeof(why))) {
        printf("[input rejected: %s] ", why);
        return false;
    }
    zcl_native_handle_dev_agents(&c->request, &c->reply);
    return true;
}

static void fax_end(struct fax_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static const struct json_value *fax_sec(const struct fax_call *c,
                                        const char *name)
{
    const struct json_value *v = json_get(&c->reply.data, name);
    return v && v->type == JSON_OBJ ? v : NULL;
}

static int64_t fax_int(const struct json_value *o, const char *key)
{
    const struct json_value *v = o ? json_get(o, key) : NULL;
    return v && v->type == JSON_INT ? json_get_int(v) : -424242;
}

static const char *fax_str(const struct json_value *o, const char *key)
{
    const struct json_value *v = o ? json_get(o, key) : NULL;
    return v && v->type == JSON_STR && json_get_str(v) ? json_get_str(v) : "";
}

/* The grade row for one executor, by name, out of the grades section. */
static const struct json_value *fax_row(const struct fax_call *c,
                                        const char *key)
{
    const struct json_value *rows = json_get(fax_sec(c, "grades"), "rows");
    if (!rows || rows->type != JSON_ARR) return NULL;
    for (size_t i = 0; i < rows->num_children; i++) {
        const struct json_value *row = json_at(rows, i);
        if (strcmp(fax_str(row, "key"), key) == 0) return row;
    }
    return NULL;
}

/* ── a fake fleet board, for --publish and --fleet ──────────────────────
 *
 * `--publish`/`--fleet` talk to the local node over the `fleet_board` RPC
 * method exactly like `fleet board post/list` do, so they are proved the
 * same way test_telemetry_agents.c proves an RPC-reading collector: behind
 * node_rpc_client_set_test_hook, against canned bodies. No socket, no
 * node.db, no dependence on a node happening to run. */

#define FAX_SELF_HEX \
    "1111111111111111111111111111111111111111111111111111111111111111"
#define FAX_HOST_A \
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define FAX_HOST_B \
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

struct fax_board_post { char host[65]; char text[2200]; int64_t created_at; };
static struct fax_board_post fax_board[16];
static size_t fax_board_n = 0;

static void fax_board_reset(void) { fax_board_n = 0; }

static void fax_board_append(const char *host, const char *text,
                             int64_t created_at)
{
    if (fax_board_n >= 16) return;
    (void)snprintf(fax_board[fax_board_n].host, 65, "%s", host);
    (void)snprintf(fax_board[fax_board_n].text,
                  sizeof(fax_board[fax_board_n].text), "%s", text);
    fax_board[fax_board_n].created_at = created_at;
    fax_board_n++;
}

static void fax_board_list(const struct json_value *in,
                           struct json_value *posts)
{
    const char *host = json_get_str(json_get(in, "host"));
    for (size_t i = fax_board_n; i-- > 0;) {
        if (host && host[0] && strcmp(fax_board[i].host, host) != 0) continue;
        struct json_value p;
        json_init(&p); json_set_object(&p);
        (void)json_push_kv_str(&p, "host", fax_board[i].host);
        (void)json_push_kv_str(&p, "text", fax_board[i].text);
        (void)json_push_kv_int(&p, "created_at", fax_board[i].created_at);
        (void)json_push_back(posts, &p);
        json_free(&p);
    }
}

static void fax_board_op_status(struct json_value *result)
{
    (void)json_push_kv_bool(result, "ok", true);
    (void)json_push_kv_str(result, "host", FAX_SELF_HEX);
}

static void fax_board_op_post(const struct json_value *in,
                              struct json_value *result)
{
    fax_board_append(FAX_SELF_HEX, json_get_str(json_get(in, "text")),
                     FAX_NOW);
    (void)json_push_kv_bool(result, "ok", true);
    (void)json_push_kv_str(result, "id", "testpostid");
}

static void fax_board_op_list(const struct json_value *in,
                              struct json_value *result)
{
    struct json_value posts;
    json_init(&posts); json_set_array(&posts);
    fax_board_list(in, &posts);
    (void)json_push_kv_bool(result, "ok", true);
    (void)json_push_kv(result, "posts", &posts);
    json_free(&posts);
}

static void fax_board_dispatch(const struct json_value *in,
                               struct json_value *result)
{
    const char *op = json_get_str(json_get(in, "op"));
    json_set_object(result);
    if (op && strcmp(op, "status") == 0) fax_board_op_status(result);
    else if (op && strcmp(op, "post") == 0) fax_board_op_post(in, result);
    else if (op && strcmp(op, "list") == 0) fax_board_op_list(in, result);
    else (void)json_push_kv_bool(result, "ok", false);
}

static char *fax_board_hook(const char *method, const char *params_json)
{
    struct json_value arr, result;
    char buf[16384];
    if (!method || strcmp(method, "fleet_board") != 0 || !params_json)
        return strdup("{\"ok\":false}");
    json_init(&arr); json_init(&result);
    (void)json_read(&arr, params_json, strlen(params_json));
    fax_board_dispatch(json_at(&arr, 0), &result);
    size_t n = json_write(&result, buf, sizeof(buf));
    json_free(&arr); json_free(&result);
    char *out = malloc(n + 1);
    if (out) { memcpy(out, buf, n); out[n] = 0; }
    return out;
}

/* One `agents` row from another host's own body, by field. */
static const struct json_value *fax_host_row(const struct json_value *out,
                                             const char *name)
{
    const struct json_value *hosts = json_get(out, "hosts");
    for (size_t i = 0; hosts && i < hosts->num_children; i++) {
        const struct json_value *h = json_at(hosts, i);
        if (strcmp(fax_str(h, "name"), name) == 0) return h;
    }
    return NULL;
}

static int test_fleet_agents_publish(const char *root, const char *ledger);
int test_fleet_agents(void);
int test_fleet_agents(void)
{
    int failures = 0;
    char root[512], ledger[1024], ready[1024], marker[1200];

    test_make_tmpdir(root, sizeof(root), "fleet_agents", "fixture");
    (void)snprintf(ledger, sizeof(ledger), "%s/rows.tsv", root);
    (void)snprintf(ready, sizeof(ready), "%s/scratch/cleanlane", root);
    (void)snprintf(marker, sizeof(marker), "%s/READY", ready);
    clock_set_default(&fax_clock);

    TEST("agents: the leaf is registered, aliased, and bound") {
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(zcl_command_catalog(), FAX_PATH, NULL);
        bool was_alias = false;
        ASSERT(spec != NULL);
        ASSERT(spec->handler != NULL);
        ASSERT(spec->input_keys && strstr(spec->input_keys, "since"));
        ASSERT(spec->input_keys && strstr(spec->input_keys, "ledger"));
        /* `z23-dev fleet agents` is the command a person types; it reaches
         * this leaf only through the alias. */
        ASSERT(zcl_command_registry_find(zcl_command_catalog(), "fleet.agents",
                                         &was_alias) == spec);
        ASSERT(was_alias);
        PASS();
    }

    TEST("agents: a missing ledger is one plain sentence and a failure") {
        struct fax_call c;
        fax_begin(&c);
        (void)json_push_kv_str(&c.input, "ledger", "/nonexistent/rows.tsv");
        (void)json_push_kv_str(&c.input, "root", root);
        (void)json_push_kv_bool(&c.input, "include_units", false);
        ASSERT(fax_run(&c));
        ASSERT(c.reply.status != ZCL_COMMAND_STATUS_PASSED);
        ASSERT_EQ((int)c.reply.exit_code, (int)ZCL_COMMAND_EXIT_FAILED);
        ASSERT_STR_EQ(c.reply.error.code, "NO_LEDGER");
        ASSERT(strstr(c.reply.error.message, "/nonexistent/rows.tsv") != NULL);
        /* One sentence, not a stack of them. */
        ASSERT(strchr(c.reply.error.message, '\n') == NULL);
        fax_end(&c);
        PASS();
    }

    ASSERT(fax_write(ledger, FAX_LEDGER));

    TEST("agents: the ledger is read whole, and the malformed row is named") {
        struct fax_call c;
        const struct json_value *g, *bad;
        fax_begin(&c);
        (void)json_push_kv_str(&c.input, "ledger", ledger);
        (void)json_push_kv_str(&c.input, "root", root);
        (void)json_push_kv_int(&c.input, "since", 24);
        (void)json_push_kv_bool(&c.input, "include_units", false);
        ASSERT(fax_run(&c));
        ASSERT_EQ((int)c.reply.status, (int)ZCL_COMMAND_STATUS_PASSED);
        g = fax_sec(&c, "grades");
        ASSERT(g != NULL);
        ASSERT_EQ(fax_int(g, "ledger_lines"), (int64_t)FAX_LEDGER_LINES);
        ASSERT_EQ(fax_int(g, "result_rows_total"), (int64_t)15);
        /* The five-day-old row is in the ledger and out of the window. */
        ASSERT_EQ(fax_int(g, "result_rows_in_window"), (int64_t)14);
        ASSERT_EQ(fax_int(g, "predict_rows"), (int64_t)7);
        ASSERT_EQ(fax_int(g, "skipped_rows"), (int64_t)1);
        bad = json_get(g, "skipped_lines");
        ASSERT(bad != NULL && bad->type == JSON_ARR);
        ASSERT_EQ((int)bad->num_children, 1);
        ASSERT_EQ(json_get_int(json_at(bad, 0)), (int64_t)FAX_BAD_LINE);
        /* Four executors reported; the out-of-window one is not among them. */
        ASSERT_EQ(fax_int(g, "total"), (int64_t)4);
        ASSERT(fax_row(&c, "muse") == NULL);
        fax_end(&c);
        PASS();
    }

    TEST("agents: every grade, rate, median and ratio is the expected number") {
        struct fax_call c;
        const struct json_value *row, *totals;
        fax_begin(&c);
        (void)json_push_kv_str(&c.input, "ledger", ledger);
        (void)json_push_kv_str(&c.input, "root", root);
        (void)json_push_kv_int(&c.input, "since", 24);
        (void)json_push_kv_bool(&c.input, "include_units", false);
        ASSERT(fax_run(&c));

        /* grok: 4 for 4, and it hit its estimates. */
        row = fax_row(&c, "grok");
        ASSERT(row != NULL);
        ASSERT_EQ(fax_int(row, "tasks"), (int64_t)4);
        ASSERT_EQ(fax_int(row, "success"), (int64_t)4);
        ASSERT_EQ(fax_int(row, "failure"), (int64_t)0);
        ASSERT_EQ(fax_int(row, "other"), (int64_t)0);
        ASSERT_EQ(fax_int(row, "success_rate_bp"), (int64_t)10000);
        ASSERT_EQ(fax_int(row, "median_wall_s"), (int64_t)200);
        ASSERT_EQ(fax_int(row, "median_ratio_bp"), (int64_t)10000);
        ASSERT_EQ(fax_int(row, "tokens_per_success"), (int64_t)3000);
        ASSERT_EQ(fax_int(row, "last_activity_age_s"),
                  (int64_t)7020); /* 2026-09-06T10:03:00Z to 12:00:00Z */
        ASSERT_STR_EQ(fax_str(row, "grade"), "A");

        /* claude-sonnet: one HOLD costs the A, and it ran twice its estimate. */
        row = fax_row(&c, "claude-sonnet");
        ASSERT(row != NULL);
        ASSERT_EQ(fax_int(row, "tasks"), (int64_t)5);
        ASSERT_EQ(fax_int(row, "success"), (int64_t)4);
        ASSERT_EQ(fax_int(row, "failure"), (int64_t)1);
        ASSERT_EQ(fax_int(row, "success_rate_bp"), (int64_t)8000);
        ASSERT_EQ(fax_int(row, "median_wall_s"), (int64_t)300);
        ASSERT_EQ(fax_int(row, "median_ratio_bp"), (int64_t)20000);
        ASSERT_EQ(fax_int(row, "tokens_per_success"), (int64_t)125);
        ASSERT_STR_EQ(fax_str(row, "grade"), "B");

        /* codex: one land in three, and nothing predicted it. */
        row = fax_row(&c, "codex");
        ASSERT(row != NULL);
        ASSERT_EQ(fax_int(row, "tasks"), (int64_t)3);
        ASSERT_EQ(fax_int(row, "success"), (int64_t)1);
        ASSERT_EQ(fax_int(row, "failure"), (int64_t)2);
        ASSERT_EQ(fax_int(row, "success_rate_bp"), (int64_t)3333);
        ASSERT_EQ(fax_int(row, "median_wall_s"), (int64_t)90);
        ASSERT_EQ(fax_int(row, "median_ratio_bp"), (int64_t)-1);
        ASSERT_STR_EQ(fax_str(row, "grade"), "F");

        /* glm: two rows is not a track record. */
        row = fax_row(&c, "glm");
        ASSERT(row != NULL);
        ASSERT_EQ(fax_int(row, "tasks"), (int64_t)2);
        ASSERT_STR_EQ(fax_str(row, "grade"), "n/a (n<3)");

        totals = json_get(fax_sec(&c, "grades"), "totals");
        ASSERT(totals != NULL);
        ASSERT_EQ(fax_int(totals, "tasks"), (int64_t)14);
        ASSERT_EQ(fax_int(totals, "success"), (int64_t)11);
        ASSERT_EQ(fax_int(totals, "failure"), (int64_t)3);
        ASSERT_EQ(fax_int(totals, "success_rate_bp"), (int64_t)7857);
        ASSERT_EQ(fax_int(totals, "median_wall_s"), (int64_t)120);
        fax_end(&c);
        PASS();
    }

    TEST("agents: the whole ledger, and grouping by lane and by class") {
        struct fax_call c;
        fax_begin(&c);
        (void)json_push_kv_str(&c.input, "ledger", ledger);
        (void)json_push_kv_str(&c.input, "root", root);
        (void)json_push_kv_int(&c.input, "since", 0);
        (void)json_push_kv_bool(&c.input, "include_units", false);
        ASSERT(fax_run(&c));
        /* since=0 is the whole ledger, so the five-day-old row is graded. */
        ASSERT_EQ(fax_int(fax_sec(&c, "grades"), "result_rows_in_window"),
                  (int64_t)15);
        ASSERT(fax_row(&c, "muse") != NULL);
        fax_end(&c);

        fax_begin(&c);
        (void)json_push_kv_str(&c.input, "ledger", ledger);
        (void)json_push_kv_str(&c.input, "root", root);
        (void)json_push_kv_int(&c.input, "since", 24);
        (void)json_push_kv_str(&c.input, "by", "lane");
        (void)json_push_kv_bool(&c.input, "include_units", false);
        ASSERT(fax_run(&c));
        ASSERT_STR_EQ(fax_str(fax_sec(&c, "grades"), "group_by"), "lane");
        ASSERT(fax_row(&c, "beta") != NULL);
        ASSERT_EQ(fax_int(fax_row(&c, "beta"), "tasks"), (int64_t)5);
        ASSERT(fax_row(&c, "grok") == NULL);
        fax_end(&c);

        fax_begin(&c);
        (void)json_push_kv_str(&c.input, "ledger", ledger);
        (void)json_push_kv_str(&c.input, "root", root);
        (void)json_push_kv_int(&c.input, "since", 24);
        (void)json_push_kv_str(&c.input, "by", "class");
        (void)json_push_kv_bool(&c.input, "include_units", false);
        ASSERT(fax_run(&c));
        /* read covers grok's four and glm's two. */
        ASSERT_EQ(fax_int(fax_row(&c, "read"), "tasks"), (int64_t)6);
        ASSERT_EQ(fax_int(fax_row(&c, "diagnose"), "tasks"), (int64_t)3);
        fax_end(&c);
        PASS();
    }

    TEST("agents: an out-of-range window and an unknown grouping are refused") {
        struct fax_call c;
        fax_begin(&c);
        (void)json_push_kv_str(&c.input, "ledger", ledger);
        (void)json_push_kv_int(&c.input, "since", 100000);
        ASSERT(fax_run(&c));
        ASSERT_STR_EQ(c.reply.error.code, "SINCE_OUT_OF_RANGE");
        fax_end(&c);

        fax_begin(&c);
        (void)json_push_kv_str(&c.input, "ledger", ledger);
        (void)json_push_kv_str(&c.input, "by", "planet");
        ASSERT(fax_run(&c));
        ASSERT_STR_EQ(c.reply.error.code, "UNKNOWN_GROUPING");
        fax_end(&c);
        PASS();
    }

    ASSERT(fax_repo(root, "dirtylane", true));
    ASSERT(fax_repo(root, "cleanlane", false));
    ASSERT(fax_mkdir(ready));
    ASSERT(fax_write(marker, "abc1234def\n"));

    TEST("agents: the scan reports each workspace, its dirt and its marker") {
        struct fax_call c;
        const struct json_value *r, *rows, *dirty = NULL, *clean = NULL;
        fax_begin(&c);
        (void)json_push_kv_str(&c.input, "ledger", ledger);
        (void)json_push_kv_str(&c.input, "root", root);
        (void)json_push_kv_bool(&c.input, "include_units", false);
        ASSERT(fax_run(&c));
        r = fax_sec(&c, "running");
        ASSERT(r != NULL);
        ASSERT_STR_EQ(fax_str(r, "state"), "observed");
        ASSERT_STR_EQ(fax_str(r, "root"), root);
        ASSERT_EQ(fax_int(r, "scanned"), (int64_t)2);
        ASSERT_EQ(fax_int(r, "count"), (int64_t)2);
        ASSERT(!json_get_bool(json_get(r, "truncated")));
        /* include_units=false leaves the systemd read out entirely rather
         * than reporting an empty one. */
        ASSERT(json_get(r, "units") == NULL);
        rows = json_get(r, "rows");
        ASSERT(rows != NULL && rows->type == JSON_ARR);
        ASSERT_EQ((int)rows->num_children, 2);
        for (size_t i = 0; i < rows->num_children; i++) {
            const struct json_value *row = json_at(rows, i);
            if (strcmp(fax_str(row, "name"), "dirtylane") == 0) dirty = row;
            if (strcmp(fax_str(row, "name"), "cleanlane") == 0) clean = row;
        }
        ASSERT(dirty != NULL && clean != NULL);
        ASSERT_STR_EQ(fax_str(dirty, "kind"), "lane");
        ASSERT_EQ(fax_int(dirty, "dirty"), (int64_t)1);
        ASSERT_EQ(fax_int(clean, "dirty"), (int64_t)0);
        /* A short HEAD is nine characters of hex for both. */
        ASSERT_EQ((int)strlen(fax_str(dirty, "head")), 9);
        ASSERT_EQ((int)strlen(fax_str(clean, "head")), 9);
        /* Only one of the two wrote a READY marker, and it is reported
         * verbatim with no newline. */
        ASSERT_STR_EQ(fax_str(clean, "ready"), "abc1234def");
        ASSERT_STR_EQ(fax_str(dirty, "ready"), "");
        ASSERT_EQ(fax_int(dirty, "process_count"), (int64_t)0);
        fax_end(&c);
        PASS();
    }

    TEST("agents: the machine object and the plain text carry one measurement") {
        struct fax_call c;
        struct json_value reread;
        char *doc = NULL;
        size_t n;
        const char *text;
        fax_begin(&c);
        (void)json_push_kv_str(&c.input, "ledger", ledger);
        (void)json_push_kv_str(&c.input, "root", root);
        (void)json_push_kv_int(&c.input, "since", 24);
        (void)json_push_kv_bool(&c.input, "include_units", false);
        ASSERT(fax_run(&c));

        /* The data object is what --json prints: it must round-trip through
         * this tree's own JSON writer and reader. */
        doc = malloc(65536);
        ASSERT(doc != NULL);
        n = json_write(&c.reply.data, doc, 65536);
        ASSERT(n > 0 && n < 65536);
        json_init(&reread);
        ASSERT(json_read(&reread, doc, n));
        ASSERT(reread.type == JSON_OBJ);
        ASSERT_STR_EQ(json_get_str(json_get(&reread, "schema")),
                      ZCL_AGENTS_SCHEMA);
        ASSERT_EQ(json_get_int(json_get(&reread, "now_unix")),
                  (int64_t)FAX_NOW);
        json_free(&reread);
        free(doc);

        /* The plain text is rendered from that same object, so every number
         * a reader sees is one of the numbers above. */
        text = json_get_str(json_get(&c.reply.data, "text"));
        ASSERT(text != NULL);
        ASSERT(strstr(text, "RUNNING NOW") != NULL);
        ASSERT(strstr(text, "dirtylane") != NULL);
        ASSERT(strstr(text, "abc1234def") != NULL);
        ASSERT(strstr(text, "GRADES") != NULL);
        ASSERT(strstr(text, "grok") != NULL);
        ASSERT(strstr(text, "n/a (n<3)") != NULL);
        /* 20000 basis points reads as 2.00 to a person. */
        ASSERT(strstr(text, "2.00") != NULL);
        ASSERT(strstr(text, "OTHER HOSTS") != NULL);
        ASSERT(strstr(text, ZCL_AGENTS_OTHER_HOSTS_NOTE) != NULL);
        fax_end(&c);
        PASS();
    }

_test_next:;
    clock_reset_default();
    failures += test_fleet_agents_publish(root, ledger);
    if (failures == 0) printf("test_fleet_agents: all passed\n");
    else printf("test_fleet_agents: %d FAILED\n", failures);
    return failures;
}

/* `--publish` and `--fleet`, against the same ledger/workspace fixture,
 * split into its own function so the acceptance bar's pinned complexity
 * does not grow with every new flag this leaf gains. */
static int test_fleet_agents_publish(const char *root, const char *ledger)
{
    int failures = 0;
    TEST("agents publish: the body is compact, deterministic, and dedupes "
        "within one minute") {
        struct json_value running, grades;
        char text_a[ZCL_AGENTS_PUBLISH_TEXT_MAX + 1];
        char text_b[ZCL_AGENTS_PUBLISH_TEXT_MAX + 1];
        struct zcl_agents_options options;
        memset(&options, 0, sizeof(options));
        options.root = root; options.ledger = ledger;
        options.since_hours = 24; options.now_unix = FAX_NOW;
        json_init(&running); json_init(&grades);
        zcl_agents_running_json(&options, &running);
        ASSERT(zcl_agents_grades_json(&options, &grades, NULL, 0));

        size_t na = zcl_agents_publish_text(&running, &grades, "boxname",
                                            FAX_NOW, text_a, sizeof(text_a));
        size_t nb = zcl_agents_publish_text(&running, &grades, "boxname",
                                            FAX_NOW, text_b, sizeof(text_b));
        ASSERT(na > 0 && na < ZCL_AGENTS_PUBLISH_TEXT_MAX);
        ASSERT_STR_EQ(text_a, text_b);
        (void)nb;
        ASSERT(strstr(text_a, "v1|host=boxname|now=") == text_a);
        ASSERT(strstr(text_a, "R|dirtylane|lane|") != NULL);
        ASSERT(strstr(text_a, "G|grok|") != NULL);

        /* The same body inside one minute is a duplicate; a minute later, or
         * a changed body, is not. */
        ASSERT(zcl_agents_publish_is_duplicate(text_a, FAX_NOW, text_a,
                                               FAX_NOW + 30));
        ASSERT(!zcl_agents_publish_is_duplicate(text_a, FAX_NOW, text_a,
                                                FAX_NOW + 61));
        ASSERT(!zcl_agents_publish_is_duplicate(text_a, FAX_NOW, "different",
                                                FAX_NOW));
        ASSERT(!zcl_agents_publish_is_duplicate(NULL, FAX_NOW, text_a,
                                                FAX_NOW));
        json_free(&running); json_free(&grades);
        PASS();
    }

    TEST("agents publish: two runs inside one minute post exactly once") {
        struct json_value running, grades;
        struct zcl_agents_options options;
        struct zcl_command_reply reply;
        fax_board_reset();
        node_rpc_client_set_test_hook(fax_board_hook);
        memset(&options, 0, sizeof(options));
        options.root = root; options.ledger = ledger;
        options.since_hours = 24; options.now_unix = FAX_NOW;
        json_init(&running); json_init(&grades);
        zcl_agents_running_json(&options, &running);
        ASSERT(zcl_agents_grades_json(&options, &grades, NULL, 0));

        zcl_command_reply_init(&reply, ZCL_AGENTS_SCHEMA);
        zcl_agents_do_publish(&options, &running, &grades, &reply);
        ASSERT(json_get_bool(json_get(&reply.data, "posted")));
        ASSERT_EQ(fax_board_n, (size_t)1);
        zcl_command_reply_free(&reply);

        zcl_command_reply_init(&reply, ZCL_AGENTS_SCHEMA);
        zcl_agents_do_publish(&options, &running, &grades, &reply);
        ASSERT(!json_get_bool(json_get(&reply.data, "posted")));
        ASSERT_EQ(fax_board_n, (size_t)1);
        zcl_command_reply_free(&reply);

        node_rpc_client_set_test_hook(NULL);
        json_free(&running); json_free(&grades);
        PASS();
    }

    TEST("agents fleet: merges this box with two board hosts, one stale") {
        struct json_value running, grades, out;
        struct zcl_agents_options options;
        fax_board_reset();
        fax_board_append(FAX_HOST_A,
                         "v1|host=nodeA|now=1000\n"
                         "R|lane1|lane|abcd123|0|1\n"
                         "G|codex|5|4|1|8000|B\n",
                         FAX_NOW - 120);
        fax_board_append(FAX_HOST_B,
                         "v1|host=nodeB|now=500\n"
                         "R|lane2|unit|ef0111|2|0\n",
                         FAX_NOW - 1200);
        node_rpc_client_set_test_hook(fax_board_hook);
        memset(&options, 0, sizeof(options));
        options.root = root; options.ledger = ledger;
        options.since_hours = 24; options.now_unix = FAX_NOW;
        json_init(&running); json_init(&grades); json_init(&out);
        zcl_agents_running_json(&options, &running);
        ASSERT(zcl_agents_grades_json(&options, &grades, NULL, 0));

        zcl_agents_do_fleet_merge(&running, &grades, FAX_NOW, &out);
        ASSERT_EQ(json_get_int(json_get(&out, "hosts_reporting")),
                  (int64_t)3);
        ASSERT(json_get_int(json_get(&out, "hosts_known")) >= 3);
        ASSERT(strstr(json_get_str(json_get(&out, "note")),
                      "hosts reporting: 3 of") != NULL);

        const struct json_value *a = fax_host_row(&out, "nodeA");
        ASSERT(a != NULL);
        ASSERT(!json_get_bool(json_get(a, "stale")));
        ASSERT_EQ(json_get_int(json_get(a, "running_rows")), (int64_t)1);
        ASSERT_EQ(json_get_int(json_get(a, "grade_rows")), (int64_t)1);

        const struct json_value *b = fax_host_row(&out, "nodeB");
        ASSERT(b != NULL);
        ASSERT(json_get_bool(json_get(b, "stale")));
        ASSERT_EQ(json_get_int(json_get(b, "running_rows")), (int64_t)1);

        node_rpc_client_set_test_hook(NULL);
        json_free(&running); json_free(&grades); json_free(&out);
        PASS();
    }

_test_next:;
    return failures;
}
