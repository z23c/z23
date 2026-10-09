/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Acceptance tests for dev.land.window (tools/command/native_dev_land_window.c)
 * against an isolated state root. Inbox rows are written straight into the
 * fixture mail dir; announce posts through the real dev.agent.mail post. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/private_directory.h"
#include "platform/state_root.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DLW_PATH "dev.land.window"
#define DLW_T1000 1791540000LL /* 2026-10-09T10:00:00Z */
#define DLW_T2355 1791590100LL /* 2026-10-09T23:55:00Z */
#define DLW_REF "\"ref\":\"astra-board-runs\""
#define DLW_C "aaaaaaaaaa"
#define DLW_B "bbbbbbbbbb"

struct dlw_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void dlw_begin(struct dlw_call *c)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), DLW_PATH, NULL);
    zcl_command_reply_init(&c->reply, "zcl.land_window.v1");
}

static void dlw_end(struct dlw_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static void dlw_open(struct dlw_call *c, const char *host, long long now)
{
    dlw_begin(c);
    (void)json_push_kv_str(&c->input, "action", "open");
    (void)json_push_kv_str(&c->input, "host", host);
    (void)json_push_kv_int(&c->input, "now", now);
    zcl_native_handle_dev_land_window(&c->request, &c->reply);
}

static void dlw_announce_pair(struct dlw_call *c, const char *cand,
                               const char *base, const char *expected)
{
    dlw_begin(c);
    (void)json_push_kv_str(&c->input, "action", "announce");
    (void)json_push_kv_str(&c->input, "host", "hosta");
    (void)json_push_kv_int(&c->input, "seq", 7);
    (void)json_push_kv_str(&c->input, "candidate", cand);
    (void)json_push_kv_str(&c->input, "base", base);
    (void)json_push_kv_str(&c->input, "expected_done", expected);
    zcl_native_handle_dev_land_window(&c->request, &c->reply);
}

static void dlw_announce(struct dlw_call *c, const char *cand,
                         const char *expected)
{
    dlw_announce_pair(c, cand, "0123456789abcdef0123456789abcdef01234567",
                      expected);
}


static bool dlw_ok(const struct dlw_call *c)
{
    return c->reply.status == ZCL_COMMAND_STATUS_PASSED;
}

static int64_t dlw_int(const struct dlw_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_INT ? json_get_int(v) : -1;
}

static size_t dlw_windows(const struct dlw_call *c)
{
    const struct json_value *v = json_get(&c->reply.data, "open_windows");
    return v && v->type == JSON_ARR ? json_size(v) : 99;
}

static bool dlw_bool(const struct dlw_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

static char g_dlw_mail[4096];

/* Replace the fixture inbox with the given raw lines. */
static void dlw_rows(const char *const *lines, size_t n)
{
    char path[4200];
    FILE *f;
    (void)snprintf(path, sizeof(path), "%s/inbox.peer.jsonl", g_dlw_mail);
    f = fopen(path, "w");
    if (!f)
        abort();
    for (size_t i = 0; i < n; i++)
        (void)fprintf(f, "%s\n", lines[i]);
    (void)fclose(f);
}

#define WROW(seq, ts, from, hh, host, done)                                   \
    "{\"seq\":" #seq ",\"ts\":\"" ts "\",\"from\":\"" from                    \
    "\",\"to\":\"*\",\"kind\":\"note\",\"body\":\"LAND-WINDOW " host          \
    ", candidate " DLW_C " on base " DLW_B ", proving now, expected done "    \
    done ".\"," DLW_REF "}"
#define CROW(seq, ts, from, text)                                             \
    "{\"seq\":" #seq ",\"ts\":\"" ts "\",\"from\":\"" from                    \
    "\",\"to\":\"*\",\"kind\":\"note\",\"body\":\"" text "\"," DLW_REF "}"

static char g_dlw_saved[4096];
static bool g_dlw_had;

static void dlw_isolate(void)
{
    char base[512], state[1024];
    const char *old = getenv("XDG_STATE_HOME");
    g_dlw_had = old != NULL;
    if (old)
        (void)snprintf(g_dlw_saved, sizeof(g_dlw_saved), "%s", old);
    test_make_tmpdir(base, sizeof(base), "dev_land_window", "rig");
    (void)snprintf(state, sizeof(state), "%s/state", base);
    if (!platform_private_directory_ensure(state) ||
        setenv("XDG_STATE_HOME", state, 1) != 0)
        abort();
    if (!platform_state_root(state, sizeof(state)))
        abort();
    (void)snprintf(g_dlw_mail, sizeof(g_dlw_mail), "%s/mail", state);
    if (!platform_private_directory_ensure(g_dlw_mail))
        abort();
}

static void dlw_restore(void)
{
    if (g_dlw_had)
        (void)setenv("XDG_STATE_HOME", g_dlw_saved, 1);
    else
        (void)unsetenv("XDG_STATE_HOME");
}

static size_t dlw_outbox_lines(void)
{
    char path[4200], buf[8192];
    size_t n = 0;
    FILE *f;
    (void)snprintf(path, sizeof(path), "%s/outbox.jsonl", g_dlw_mail);
    f = fopen(path, "r");
    if (!f)
        return 0;
    while (fgets(buf, sizeof(buf), f))
        n++;
    (void)fclose(f);
    return n;
}

int test_dev_land_window(void);
int test_dev_land_window(void)
{
    int failures = 0;
    struct dlw_call c;
    dlw_isolate();

    TEST("land.window: another host's open window is reported") {
        const char *rows[] = {
            WROW(1, "2026-10-09T09:50:00Z", "agent-b", 0, "hostb", "10:30Z"),
            CROW(5, "2026-10-09T09:55:00Z", "agent-c",
                 "LANDED " DLW_C " on main"),
        };
        dlw_rows(rows, 2);
        dlw_open(&c, "hosta", DLW_T1000);
        ASSERT(dlw_ok(&c));
        ASSERT_EQ((int)dlw_windows(&c), 1);
        ASSERT_EQ(dlw_int(&c, "max_seconds_left"), (int64_t)1800);
        ASSERT_EQ(json_get_int(json_get(json_at(json_get(&c.reply.data,
                      "open_windows"), 0), "seconds_left")), (int64_t)1800);
        ASSERT_STR_EQ(json_get_str(json_get(json_at(json_get(&c.reply.data,
                      "open_windows"), 0), "host")), "hostb");
        dlw_end(&c);
        PASS();
    }

    TEST("land.window: a later LANDED from the same sender closes it") {
        const char *rows[] = {
            WROW(1, "2026-10-09T09:50:00Z", "agent-b", 0, "hostb", "10:30Z"),
            CROW(2, "2026-10-09T09:58:00Z", "agent-b",
                 "LANDED " DLW_C " on main"),
        };
        dlw_rows(rows, 2);
        dlw_open(&c, "hosta", DLW_T1000);
        ASSERT(dlw_ok(&c));
        ASSERT_EQ((int)dlw_windows(&c), 0);
        ASSERT_EQ(dlw_int(&c, "max_seconds_left"), (int64_t)0);
        dlw_end(&c);
        PASS();
    }

    TEST("land.window: a later RELEASED from the same sender closes it") {
        const char *rows[] = {
            WROW(1, "2026-10-09T09:50:00Z", "agent-b", 0, "hostb", "10:30Z"),
            CROW(2, "2026-10-09T09:58:00Z", "agent-b",
                 "RELEASED " DLW_C " without landing"),
        };
        dlw_rows(rows, 2);
        dlw_open(&c, "hosta", DLW_T1000);
        ASSERT(dlw_ok(&c));
        ASSERT_EQ((int)dlw_windows(&c), 0);
        dlw_end(&c);
        PASS();
    }

    TEST("land.window: an expired window is not open") {
        const char *rows[] = {
            WROW(1, "2026-10-09T09:30:00Z", "agent-b", 0, "hostb", "09:55Z"),
        };
        dlw_rows(rows, 1);
        dlw_open(&c, "hosta", DLW_T1000);
        ASSERT(dlw_ok(&c));
        ASSERT_EQ((int)dlw_windows(&c), 0);
        dlw_end(&c);
        PASS();
    }

    TEST("land.window: the asking host's own window is ignored") {
        const char *rows[] = {
            WROW(1, "2026-10-09T09:50:00Z", "agent-a", 0, "hosta", "10:30Z"),
        };
        dlw_rows(rows, 1);
        dlw_open(&c, "hosta", DLW_T1000);
        ASSERT(dlw_ok(&c));
        ASSERT_EQ((int)dlw_windows(&c), 0);
        dlw_end(&c);
        PASS();
    }

    TEST("land.window: expected-done earlier than the row rolls to next day") {
        const char *rows[] = {
            WROW(1, "2026-10-09T23:50:00Z", "agent-b", 0, "hostb", "00:20Z"),
        };
        dlw_rows(rows, 1);
        dlw_open(&c, "hosta", DLW_T2355);
        ASSERT(dlw_ok(&c));
        ASSERT_EQ((int)dlw_windows(&c), 1);
        ASSERT_EQ(dlw_int(&c, "max_seconds_left"), (int64_t)1500);
        dlw_end(&c);
        PASS();
    }

    TEST("land.window: malformed rows are skipped and counted") {
        const char *rows[] = {
            "this is not json",
            CROW(1, "2026-10-09T09:50:00Z", "agent-b",
                 "LAND-WINDOW hostb, candidate zz on base " DLW_B
                 ", proving now, expected done 10:30Z."),
            WROW(3, "2026-10-09T09:50:00Z", "agent-b", 0, "hostb", "10:30Z"),
        };
        dlw_rows(rows, 3);
        dlw_open(&c, "hosta", DLW_T1000);
        ASSERT(dlw_ok(&c));
        ASSERT_EQ((int)dlw_windows(&c), 1);
        ASSERT(dlw_int(&c, "skipped") >= 2);
        dlw_end(&c);
        PASS();
    }

    TEST("land.window: announce posts once, then reports already_announced") {
        const char *cand = "fedcba9876543210fedcba9876543210fedcba98";
        dlw_announce(&c, cand, "10:30Z");
        ASSERT(dlw_ok(&c));
        ASSERT(!dlw_bool(&c, "already_announced"));
        dlw_end(&c);
        ASSERT_EQ((int)dlw_outbox_lines(), 1);
        dlw_announce(&c, cand, "10:30Z");
        ASSERT(dlw_ok(&c));
        ASSERT(dlw_bool(&c, "already_announced"));
        dlw_end(&c);
        ASSERT_EQ((int)dlw_outbox_lines(), 1);
        PASS();
    }

    TEST("land.window: announce refuses a malformed expected_done") {
        dlw_announce(&c, "fedcba9876", "25:00Z");
        ASSERT(!dlw_ok(&c));
        ASSERT_STR_EQ(c.reply.error.code, "INVALID_INPUT");
        dlw_end(&c);
        dlw_announce(&c, "xyz", "10:30Z");
        ASSERT(!dlw_ok(&c));
        dlw_end(&c);
        ASSERT_EQ((int)dlw_outbox_lines(), 1);
        PASS();
    }

    TEST("land.window: same seq, new candidate/base pair announces again") {
        const char *cand2 = "543e52aa0a1111111111";
        const char *base2 = "d3297d65b2222222222222";
        dlw_announce_pair(&c, cand2, "25b88f1a51aaaaaaaaaa", "11:00Z");
        ASSERT(dlw_ok(&c));
        ASSERT(!dlw_bool(&c, "already_announced"));
        dlw_end(&c);
        ASSERT_EQ((int)dlw_outbox_lines(), 2);
        /* same candidate, base moved: a new proof attempt, a new row */
        dlw_announce_pair(&c, cand2, base2, "11:30Z");
        ASSERT(dlw_ok(&c));
        ASSERT(!dlw_bool(&c, "already_announced"));
        dlw_end(&c);
        ASSERT_EQ((int)dlw_outbox_lines(), 3);
        /* repeating either current pair stays idempotent */
        dlw_announce_pair(&c, cand2, base2, "11:30Z");
        ASSERT(dlw_ok(&c));
        ASSERT(dlw_bool(&c, "already_announced"));
        dlw_end(&c);
        ASSERT_EQ((int)dlw_outbox_lines(), 3);
        PASS();
    }

    TEST("land.window: open with base keeps only windows on that base") {
        const char *rows[] = {
            WROW(1, "2026-10-09T09:50:00Z", "agent-b", 0, "hostb", "10:30Z"),
            CROW(2, "2026-10-09T09:51:00Z", "agent-d",
                 "LAND-WINDOW hostd, candidate cccccccccc on base dddddddddd"
                 ", proving now, expected done 10:20Z."),
        };
        dlw_rows(rows, 2);
        dlw_begin(&c);
        (void)json_push_kv_str(&c.input, "action", "open");
        (void)json_push_kv_str(&c.input, "host", "hosta");
        (void)json_push_kv_int(&c.input, "now", DLW_T1000);
        (void)json_push_kv_str(&c.input, "base", "dddddddddd");
        zcl_native_handle_dev_land_window(&c.request, &c.reply);
        ASSERT(dlw_ok(&c));
        ASSERT_EQ((int)dlw_windows(&c), 1);
        ASSERT_EQ(dlw_int(&c, "max_seconds_left"), (int64_t)1200);
        dlw_end(&c);
        dlw_open(&c, "hosta", DLW_T1000);
        ASSERT_EQ((int)dlw_windows(&c), 2);
        dlw_end(&c);
        PASS();
    }

_test_next:;
    dlw_restore();
    if (failures == 0)
        printf("test_dev_land_window: all passed\n");
    else
        printf("test_dev_land_window: %d FAILED\n", failures);
    return failures;
}
