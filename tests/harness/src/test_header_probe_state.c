/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Header probe state, accounting and init guards that need no RPC mock:
 * repair-source counters, the state dump, reset, init credential rules and the
 * argument guards of header_probe_pull_range. Entry point:
 * header_probe_state_tests(), called from test_header_probe(). The conf
 * helpers are shared with the mock-driven cases in test_header_probe.c. */

#include "test/test_core.h"
#include "services/header_probe.h"
#include "chain/chainparams.h"
#include "json/json.h"
#include "validation/main_state.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define HPS_CHECK(name, expr) do {                       \
    printf("header_probe_state: %s... ", (name));        \
    if ((expr)) printf("OK\n");                          \
    else { printf("FAIL\n"); failures++; }               \
} while (0)

struct hp_conf {
    char dir[PATH_MAX];
    char path[PATH_MAX + 32];
    bool set;
};

bool hp_conf_write(struct hp_conf *c, const char *text);
void hp_conf_drop(struct hp_conf *c);
bool hp_state_is_pristine(void);

static const struct json_value *dump_find(struct json_value *dump,
                                          const char *key)
{
    if (!header_probe_dump_state_json(dump, NULL)) return NULL;
    return json_get(dump, key);
}

static int64_t dump_int(const char *key)
{
    struct json_value dump;
    json_init(&dump);
    const struct json_value *v = dump_find(&dump, key);
    int64_t out = (v && v->type == JSON_INT) ? json_get_int(v) : INT64_MIN;
    json_free(&dump);
    return out;
}

static bool dump_str_is(const char *key, const char *want)
{
    struct json_value dump;
    json_init(&dump);
    const struct json_value *v = dump_find(&dump, key);
    bool same = v && v->type == JSON_STR && v->val.s &&
                strcmp(v->val.s, want) == 0;
    json_free(&dump);
    return same;
}

static bool dump_initialized_is(bool want)
{
    struct json_value dump;
    json_init(&dump);
    const struct json_value *v = dump_find(&dump, "initialized");
    bool same = v && v->type == JSON_BOOL && json_get_bool(v) == want;
    json_free(&dump);
    return same;
}

bool hp_conf_write(struct hp_conf *c, const char *text)
{
    if (!test_mkdtemp(c->dir, sizeof(c->dir), "header_probe_conf")) return false;
    snprintf(c->path, sizeof(c->path), "%s/zclassic.conf", c->dir);
    FILE *f = fopen(c->path, "w");
    if (!f) return false;
    bool ok = fputs(text, f) >= 0;
    ok = (fclose(f) == 0) && ok;
    ok = ok && chmod(c->path, 0600) == 0;
    ok = ok && setenv("ZCL_LEGACY_ORACLE_CONF", c->path, 1) == 0;
    c->set = ok;
    return ok;
}

void hp_conf_drop(struct hp_conf *c)
{
    (void)unsetenv("ZCL_LEGACY_ORACLE_CONF");
    if (c->path[0]) (void)unlink(c->path);
    if (c->dir[0]) (void)rmdir(c->dir);
    c->set = false;
}

/* True when every counter is zero, the repair height is -1 and the probe is
 * neither initialized nor configured: the state header_probe_reset_for_test
 * promises. */
bool hp_state_is_pristine(void)
{
    static const char *const zero_keys[] = {
        "calls_total", "headers_added", "headers_rejected", "rpc_errors",
        "last_remote_height", "last_local_height", "oracle_repairs",
        "p2p_requests", "p2p_repairs", "p2p_no_peer_events", "oracle_skipped",
    };
    for (size_t i = 0; i < sizeof(zero_keys) / sizeof(zero_keys[0]); i++)
        if (dump_int(zero_keys[i]) != 0) return false;
    struct header_probe_repair_stats st;
    memset(&st, 0x5a, sizeof(st));
    header_probe_test_get_repair_stats(&st);
    return dump_int("last_repair_height") == -1 &&
           dump_str_is("last_repair_source", "none") &&
           dump_initialized_is(false) && !header_probe_oracle_configured() &&
           st.oracle_repairs == 0 && st.p2p_requests == 0 &&
           st.p2p_repairs == 0 && st.p2p_no_peer_events == 0 &&
           st.oracle_skipped == 0 && st.last_repair_height == -1 &&
           st.last_repair_source == HEADER_PROBE_SRC_NONE;
}

static int hp_state_repair_oracle(void)
{
    int failures = 0;
    header_probe_reset_for_test();
    HPS_CHECK("reset state is pristine", hp_state_is_pristine());

    header_probe_note_repair_served(HEADER_PROBE_SRC_ORACLE, 42);
    struct header_probe_repair_stats st;
    header_probe_test_get_repair_stats(&st);
    HPS_CHECK("oracle repair counted once with its height and source",
              st.oracle_repairs == 1 && st.p2p_repairs == 0 &&
              st.last_repair_source == HEADER_PROBE_SRC_ORACLE &&
              st.last_repair_height == 42);
    HPS_CHECK("dump names the oracle source",
              dump_str_is("last_repair_source", "oracle") &&
              dump_int("last_repair_height") == 42 &&
              dump_int("oracle_repairs") == 1);
    return failures;
}

/* Continues from the state hp_state_repair_oracle left behind. */
static int hp_state_repair_p2p_and_none(void)
{
    int failures = 0;
    struct header_probe_repair_stats st;
    header_probe_note_repair_served(HEADER_PROBE_SRC_P2P, 77);
    header_probe_test_get_repair_stats(&st);
    HPS_CHECK("p2p repair counted beside the oracle one",
              st.oracle_repairs == 1 && st.p2p_repairs == 1 &&
              st.last_repair_source == HEADER_PROBE_SRC_P2P &&
              st.last_repair_height == 77);
    HPS_CHECK("dump names the p2p source",
              dump_str_is("last_repair_source", "p2p") &&
              dump_int("p2p_repairs") == 1);

    header_probe_note_repair_served(HEADER_PROBE_SRC_NONE, 5);
    header_probe_test_get_repair_stats(&st);
    HPS_CHECK("a NONE repair records nothing",
              st.oracle_repairs == 1 && st.p2p_repairs == 1 &&
              st.last_repair_source == HEADER_PROBE_SRC_P2P &&
              st.last_repair_height == 77);
    return failures;
}

static int hp_state_repair_requests(void)
{
    int failures = 0;
    struct header_probe_repair_stats st;
    header_probe_note_p2p_request(90, 0);
    header_probe_test_get_repair_stats(&st);
    HPS_CHECK("a p2p request with no peer counts as a missing-input event",
              st.p2p_requests == 1 && st.p2p_no_peer_events == 1 &&
              st.last_repair_height == 90);
    header_probe_note_p2p_request(91, 1);
    header_probe_test_get_repair_stats(&st);
    HPS_CHECK("a p2p request with one peer is not a missing-input event",
              st.p2p_requests == 2 && st.p2p_no_peer_events == 1 &&
              st.last_repair_height == 91);
    header_probe_note_p2p_request(92, -1);
    header_probe_test_get_repair_stats(&st);
    HPS_CHECK("a negative peer count is a missing-input event too",
              st.p2p_requests == 3 && st.p2p_no_peer_events == 2 &&
              st.last_repair_height == 92);
    return failures;
}

static int hp_state_repair_skips_and_dump(void)
{
    int failures = 0;
    struct header_probe_repair_stats st;
    header_probe_note_oracle_skipped();
    header_probe_note_oracle_skipped();
    header_probe_test_get_repair_stats(&st);
    HPS_CHECK("oracle skips are counted", st.oracle_skipped == 2);
    HPS_CHECK("dump carries every repair counter",
              dump_int("p2p_requests") == 3 &&
              dump_int("p2p_no_peer_events") == 2 &&
              dump_int("oracle_skipped") == 2 &&
              dump_int("last_repair_height") == 92);
    return failures;
}

static int hp_state_repair_names_and_reset(void)
{
    int failures = 0;
    HPS_CHECK("repair source names",
              strcmp(header_probe_repair_source_name(HEADER_PROBE_SRC_ORACLE),
                     "oracle") == 0 &&
              strcmp(header_probe_repair_source_name(HEADER_PROBE_SRC_P2P),
                     "p2p") == 0 &&
              strcmp(header_probe_repair_source_name(HEADER_PROBE_SRC_NONE),
                     "none") == 0 &&
              strcmp(header_probe_repair_source_name(
                         (enum header_probe_repair_source)99), "none") == 0);

    header_probe_reset_for_test();
    HPS_CHECK("reset clears every repair counter and the height",
              hp_state_is_pristine());
    return failures;
}

static int hp_state_repair_accounting(void)
{
    int failures = 0;
    failures += hp_state_repair_oracle();
    failures += hp_state_repair_p2p_and_none();
    failures += hp_state_repair_requests();
    failures += hp_state_repair_skips_and_dump();
    failures += hp_state_repair_names_and_reset();
    return failures;
}

static int hp_state_pull_guards(const struct chain_params *params)
{
    int failures = 0;
    static struct main_state dummy;
    header_probe_reset_for_test();
    int added = 99;
    struct zcl_result r = header_probe_pull_range(-1, 5, &added);
    HPS_CHECK("negative start is refused with code -1",
              !r.ok && r.code == -1 && added == 0);
    added = 99;
    r = header_probe_pull_range(0, 5, &added);
    HPS_CHECK("uninitialized pull is refused with code -2",
              !r.ok && r.code == -2 && added == 0 &&
              dump_int("calls_total") == 0);

    struct header_probe_config cfg = {
        .rpc_host = "127.0.0.1", .rpc_port = 1,
        .rpc_user = "u", .rpc_password = "p",
    };
    HPS_CHECK("init with explicit credentials",
              header_probe_init(&cfg, NULL, NULL).ok);
    HPS_CHECK("oracle is configured after init",
              header_probe_oracle_configured() && dump_initialized_is(true));
    r = header_probe_pull_range(0, 5, &added);
    HPS_CHECK("pull without a main state or params is refused with code -2",
              !r.ok && r.code == -2 && dump_int("calls_total") == 0);
    HPS_CHECK("init with a main state but no params",
              header_probe_init(&cfg, &dummy, NULL).ok);
    r = header_probe_pull_range(0, 5, &added);
    HPS_CHECK("pull without params is refused with code -2",
              !r.ok && r.code == -2 && dump_int("calls_total") == 0);
    HPS_CHECK("init with params but no main state",
              header_probe_init(&cfg, NULL, params).ok);
    r = header_probe_pull_range(0, 5, &added);
    HPS_CHECK("pull without a main state is refused with code -2",
              !r.ok && r.code == -2 && dump_int("calls_total") == 0);
    r = header_probe_pull_range(-1, 5, &added);
    HPS_CHECK("negative start is refused with code -1 once initialized",
              !r.ok && r.code == -1 && dump_int("calls_total") == 0);
    header_probe_reset_for_test();
    HPS_CHECK("reset un-configures the oracle", !header_probe_oracle_configured());
    return failures;
}

static int hp_state_credential_rules(const struct chain_params *params)
{
    int failures = 0;
    static struct main_state dummy;
    struct hp_conf conf = {0};
    header_probe_reset_for_test();
    HPS_CHECK("conf fixture written",
              hp_conf_write(&conf, "rpcuser=cu\nrpcpassword=cp\nrpcport=23456\n"));
    if (!conf.set) { hp_conf_drop(&conf); return failures; }

    struct header_probe_config user_only = { .rpc_user = "u" };
    struct header_probe_config pass_only = { .rpc_password = "p" };
    HPS_CHECK("no config at all takes both credentials from the conf",
              header_probe_init(NULL, &dummy, params).ok &&
              header_probe_oracle_configured());
    HPS_CHECK("user only: the conf supplies the password",
              header_probe_init(&user_only, &dummy, params).ok);
    HPS_CHECK("password only: the conf supplies the user",
              header_probe_init(&pass_only, &dummy, params).ok);
    hp_conf_drop(&conf);

    /* The conf now names a missing file: a half-supplied pair is refused. */
    (void)setenv("ZCL_LEGACY_ORACLE_CONF", "/nonexistent/header_probe.conf", 1);
    struct zcl_result r = header_probe_init(&user_only, &dummy, params);
    HPS_CHECK("user only without a conf is refused with code -1",
              !r.ok && r.code == -1 && !header_probe_oracle_configured() &&
              dump_initialized_is(false));
    r = header_probe_init(&pass_only, &dummy, params);
    HPS_CHECK("password only without a conf is refused with code -1",
              !r.ok && r.code == -1 && !header_probe_oracle_configured());
    r = header_probe_init(NULL, &dummy, params);
    HPS_CHECK("no credentials without a conf is refused with code -1",
              !r.ok && r.code == -1);
    struct header_probe_config both = { .rpc_user = "u", .rpc_password = "p" };
    HPS_CHECK("a full pair needs no conf",
              header_probe_init(&both, &dummy, params).ok &&
              header_probe_oracle_configured());
    (void)unsetenv("ZCL_LEGACY_ORACLE_CONF");
    header_probe_reset_for_test();
    return failures;
}

int header_probe_state_tests(void);

int header_probe_state_tests(void)
{
    int failures = 0;
    const struct chain_params *params = chain_params_get();
    failures += hp_state_repair_accounting();
    failures += hp_state_pull_guards(params);
    failures += hp_state_credential_rules(params);
    return failures;
}
