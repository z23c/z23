/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: pure machine projection contracts; no fleet services or state. */
#include "command/native_fleet_steer_machines.h"

#include <stdio.h>
#include <string.h>

#define FM_CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "machine projection:%d: %s\n", __LINE__, #x); return 1; \
} } while (0)
#define FM_BOX_A "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define FM_BOX_B "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define FM_POST_A "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
#define FM_HISTORY_ROWS_FIRST \
    "{\"seq\":1,\"timestamp\":900,\"metric\":\"box.cores\",\"cadence_s\":86400,\"present\":true,\"value\":32}," \
    "{\"seq\":2,\"timestamp\":900,\"metric\":\"box.ram_total_mib\",\"cadence_s\":86400,\"present\":true,\"value\":65536}," \
    "{\"seq\":3,\"timestamp\":950,\"metric\":\"box.load1\",\"cadence_s\":300,\"present\":true,\"value\":125},"
#define FM_HISTORY_ROWS FM_HISTORY_ROWS_FIRST \
    "{\"seq\":4,\"timestamp\":990,\"metric\":\"box.ram_used_mib\",\"cadence_s\":300,\"present\":true,\"value\":16384}"

static struct json_value fm_parse(const char *text)
{
    struct json_value out = {0};
    if (!json_read(&out, text, strlen(text)))
        fprintf(stderr, "machine fixture: invalid JSON\n");
    return out;
}

static int fm_is(const struct json_value *row, const char *key, const char *text)
{
    const struct json_value *value = json_get(row, key);
    return value && value->type == JSON_STR &&
           strcmp(json_get_str(value), text) == 0;
}

static int fm_number(const struct json_value *row, const char *key, int64_t number)
{
    const struct json_value *value = json_get(row, key);
    return value && value->type == JSON_INT && json_get_int(value) == number;
}

static struct json_value fm_roster(bool second, bool duplicate_name)
{
    char text[2048];
    if (second)
        (void)snprintf(text, sizeof(text),
            "{\"total\":2,\"offset\":0,\"returned\":2,\"next_offset\":-1,"
            "\"truncated\":false,\"unverifiable\":0,\"machines\":["
            "{\"rows\":2,\"verified\":{\"name\":\"r1\",\"box_pubkey\":\"%s\"}},"
            "{\"rows\":1,\"verified\":{\"name\":\"%s\",\"box_pubkey\":\"%s\"}}]}",
            FM_BOX_A, duplicate_name ? "r1" : "r2", FM_BOX_B);
    else
        (void)snprintf(text, sizeof(text),
            "{\"total\":1,\"offset\":0,\"returned\":1,\"next_offset\":-1,"
            "\"truncated\":false,\"unverifiable\":0,\"machines\":["
            "{\"rows\":2,\"verified\":{\"name\":\"r1\",\"box_pubkey\":\"%s\"}}]}",
            FM_BOX_A);
    return fm_parse(text);
}

static struct json_value fm_history_last(const char *box, int64_t head, bool more,
                                         const char *verification, int64_t last_timestamp)
{
    char text[4096];
    (void)snprintf(text, sizeof(text),
        "{\"box\":\"%s\",\"found\":true,\"more\":%s,\"snapshot_head\":%lld,"
        "\"verification\":\"%s\",\"delegation\":\"not_evaluated\",\"rows\":[" FM_HISTORY_ROWS_FIRST
        "{\"seq\":4,\"timestamp\":%lld,\"metric\":\"box.ram_used_mib\",\"cadence_s\":300,\"present\":true,\"value\":16384}]}",
        box, more ? "true" : "false", (long long)head, verification,
        (long long)last_timestamp);
    return fm_parse(text);
}

static struct json_value fm_history(const char *box, int64_t head, bool more,
                                    const char *verification)
{
    return fm_history_last(box, head, more, verification, 990);
}

static struct json_value fm_history_array(const char *box, int64_t head,
                                          bool more, const char *verification)
{
    struct json_value history = fm_history(box, head, more, verification);
    struct json_value array = {0};
    json_set_array(&array);
    if (!json_push_back(&array, &history))
        fprintf(stderr, "machine fixture: history array allocation failed\n");
    json_free(&history);
    return array;
}

static struct json_value fm_workers(bool unbound)
{
    return fm_parse(unbound
        ? "[{\"name\":\"agent-a\",\"board_post\":\"" FM_POST_A "\",\"board_signer\":\"" FM_BOX_A "\","
          "\"current_ref\":\"task-a\",\"stage\":\"running\",\"state\":\"working\",\"last_seen_ts\":\"2026-11-19T20:00:00Z\","
          "\"workspace_head\":\"0123456789012345678901234567890123456789\",\"workspace_selector\":\"receiver\"},"
          "{\"name\":\"agent-b\",\"host\":\"r2\",\"current_ref\":\"task-b\",\"state\":\"working\"}]"
        : "[{\"name\":\"agent-a\",\"board_post\":\"" FM_POST_A "\",\"board_signer\":\"" FM_BOX_A "\","
          "\"current_ref\":\"task-a\",\"stage\":\"running\",\"state\":\"working\",\"last_seen_ts\":\"2026-11-19T20:00:00Z\","
          "\"workspace_head\":\"0123456789012345678901234567890123456789\",\"workspace_selector\":\"receiver\"}]");
}

static int fm_complete_case(void)
{
    struct json_value roster = fm_roster(false, false);
    struct json_value histories = fm_history_array(FM_BOX_A, 4, false,
                                                    "signature_chain_only");
    struct json_value workers = fm_workers(false);
    char before[8192], after[8192];
    (void)json_write(&histories, before, sizeof(before));
    struct zcl_fmc_machines view;
    zcl_fmc_machines_init(&view);
    FM_CHECK(zcl_fmc_machines_project(&view, &roster, &histories, &workers,
                                      true, 1000, 900));
    FM_CHECK(view.complete);
    FM_CHECK(view.total == 1 && json_size(&view.rows) == 1);
    const struct json_value *machine = json_at(&view.rows, 0);
    FM_CHECK(fm_is(machine, "name", "r1"));
    FM_CHECK(fm_is(machine, "heartbeat_state", "LIVE"));
    FM_CHECK(fm_number(machine, "heartbeat_age_s", 10));
    FM_CHECK(fm_number(machine, "cpus", 32));
    FM_CHECK(fm_number(machine, "load1_centi", 125));
    FM_CHECK(fm_number(machine, "ram_used_mib", 16384));
    FM_CHECK(fm_number(machine, "ram_total_mib", 65536));
    FM_CHECK(fm_number(machine, "ram_avail_mib", 49152));
    FM_CHECK(fm_is(machine, "vitals_evidence", "signature_chain_only"));
    FM_CHECK(fm_is(machine, "vitals_delegation", "not_evaluated"));
    FM_CHECK(fm_is(machine, "agents_state", "BOUND"));
    const struct json_value *agents = json_get(machine, "agents");
    FM_CHECK(agents && json_size(agents) == 1);
    FM_CHECK(fm_is(json_at(agents, 0), "source", "signed_board_mail"));
    FM_CHECK(fm_is(json_at(agents, 0), "task_evidence", "worker_self_report"));
    FM_CHECK(fm_is(json_at(agents, 0), "current_ref", "task-a"));
    FM_CHECK(json_get(json_at(agents, 0), "host") == NULL);
    const struct json_value *cores = json_get(json_get(machine, "metrics"), "box.cores");
    FM_CHECK(fm_is(cores, "state", "FRESH"));
    FM_CHECK(fm_number(cores, "age_s", 100));
    struct json_value out = {0};
    json_set_object(&out);
    FM_CHECK(zcl_fmc_machines_emit(&view, &out));
    FM_CHECK(json_get_bool(json_get(&out, "machines_complete")));
    FM_CHECK(json_get_bool(json_get(&out, "machine_agents_complete")));
    FM_CHECK(fm_number(&out, "machine_agents_unbound_total", 0));
    (void)json_write(&histories, after, sizeof(after));
    FM_CHECK(strcmp(before, after) == 0);
    FM_CHECK(!zcl_fmc_machines_project(&view, &roster, &histories, &workers,
                                       true, 1000, -1));
    json_free(&out);
    json_free(&workers);
    json_free(&histories);
    json_free(&roster);
    zcl_fmc_machines_free(&view);
    return 0;
}

static int fm_multiple_machines_case(void)
{
    struct json_value roster = fm_roster(true, false);
    struct json_value histories = fm_history_array(FM_BOX_A, 4, false,
                                                    "signature_chain_only");
    struct json_value history_b = fm_history_last(FM_BOX_B, 4, false,
                                                   "signature_chain_only", 99);
    FM_CHECK(json_push_back(&histories, &history_b));
    json_free(&history_b);
    struct json_value workers = fm_workers(true);
    struct zcl_fmc_machines view;
    zcl_fmc_machines_init(&view);
    FM_CHECK(zcl_fmc_machines_project(&view, &roster, &histories, &workers,
                                      true, 1000, 900));
    FM_CHECK(!view.complete && view.unbound_workers == 1);
    const struct json_value *a = json_at(&view.rows, 0);
    const struct json_value *b = json_at(&view.rows, 1);
    FM_CHECK(fm_is(a, "agents_state", "PARTIAL"));
    FM_CHECK(fm_is(b, "agents_state", "UNKNOWN"));
    FM_CHECK(fm_is(b, "heartbeat_state", "STALE"));
    FM_CHECK(fm_number(b, "heartbeat_age_s", 901));
    FM_CHECK(json_is_null(json_get(b, "cpus")));
    FM_CHECK(fm_is(json_get(json_get(b, "metrics"), "box.cores"), "state",
                   "UNKNOWN"));
    struct json_value out = {0};
    json_set_object(&out);
    FM_CHECK(zcl_fmc_machines_emit(&view, &out));
    FM_CHECK(fm_number(&out, "machine_agents_unbound_total", 1));
    FM_CHECK(!json_get_bool(json_get(&out, "machine_agents_complete")));
    json_free(&out);
    json_free(&workers);
    json_free(&histories);
    json_free(&roster);
    zcl_fmc_machines_free(&view);
    return 0;
}

static int fm_stale_future_case(void)
{
    struct json_value roster = fm_roster(false, false);
    struct json_value histories = fm_history_array(FM_BOX_A, 4, false,
                                                    "signature_chain_only");
    struct json_value workers = fm_workers(false);
    struct zcl_fmc_machines view;
    zcl_fmc_machines_init(&view);
    FM_CHECK(zcl_fmc_machines_project(&view, &roster, &histories, &workers,
                                      true, 1901, 900));
    const struct json_value *machine = json_at(&view.rows, 0);
    FM_CHECK(fm_is(machine, "heartbeat_state", "STALE"));
    FM_CHECK(fm_number(machine, "cpus", 32));
    FM_CHECK(json_is_null(json_get(machine, "load1_centi")));
    FM_CHECK(json_is_null(json_get(machine, "ram_used_mib")));
    FM_CHECK(json_is_null(json_get(machine, "ram_avail_mib")));
    FM_CHECK(fm_is(json_get(json_get(machine, "metrics"), "box.load1"), "state", "STALE"));
    zcl_fmc_machines_free(&view);

    zcl_fmc_machines_init(&view);
    FM_CHECK(zcl_fmc_machines_project(&view, &roster, &histories, &workers,
                                      true, 800, 900));
    machine = json_at(&view.rows, 0);
    FM_CHECK(fm_is(machine, "heartbeat_state", "UNKNOWN"));
    FM_CHECK(json_is_null(json_get(machine, "heartbeat_age_s")));
    FM_CHECK(json_is_null(json_get(machine, "cpus")));
    zcl_fmc_machines_free(&view);
    json_free(&workers);
    json_free(&histories);
    json_free(&roster);
    return 0;
}

static int fm_incomplete_history_case(int64_t head, bool more,
                                      const char *verification, bool duplicate)
{
    struct json_value roster = fm_roster(false, false);
    struct json_value histories = fm_history_array(FM_BOX_A, head, more, verification);
    if (duplicate) {
        struct json_value other = fm_history(FM_BOX_A, 4, false, verification);
        FM_CHECK(json_push_back(&histories, &other));
        json_free(&other);
    }
    struct json_value workers = fm_workers(false);
    struct zcl_fmc_machines view;
    zcl_fmc_machines_init(&view);
    FM_CHECK(zcl_fmc_machines_project(&view, &roster, &histories, &workers,
                                      true, 1000, 900));
    const struct json_value *machine = json_at(&view.rows, 0);
    FM_CHECK(!json_get_bool(json_get(machine, "history_complete")));
    FM_CHECK(json_get_bool(json_get(machine, "history_discrepancy")) == duplicate);
    FM_CHECK(fm_is(machine, "heartbeat_state", "UNKNOWN"));
    FM_CHECK(json_is_null(json_get(machine, "cpus")));
    FM_CHECK(json_is_null(json_get(machine, "ram_used_mib")));
    FM_CHECK(fm_is(machine, "vitals_evidence",
                   strcmp(verification, "signature_chain_only") == 0
                       ? "signature_chain_only" : "UNKNOWN"));
    zcl_fmc_machines_free(&view);
    json_free(&workers);
    json_free(&histories);
    json_free(&roster);
    return 0;
}

static int fm_discrepancy_cases(void)
{
    FM_CHECK(fm_incomplete_history_case(5, false, "signature_chain_only", false) == 0);
    FM_CHECK(fm_incomplete_history_case(4, true, "signature_chain_only", false) == 0);
    FM_CHECK(fm_incomplete_history_case(4, false, "unverified", false) == 0);
    FM_CHECK(fm_incomplete_history_case(4, false, "signature_chain_only", true) == 0);

    struct json_value roster = fm_roster(true, true);
    struct json_value histories = {0}, workers = {0};
    json_set_array(&histories);
    json_set_array(&workers);
    struct zcl_fmc_machines view;
    zcl_fmc_machines_init(&view);
    FM_CHECK(zcl_fmc_machines_project(&view, &roster, &histories, &workers,
                                      true, 1000, 900));
    FM_CHECK(json_get_bool(json_get(json_at(&view.rows, 0), "name_discrepancy")));
    FM_CHECK(json_get_bool(json_get(json_at(&view.rows, 1), "name_discrepancy")));
    FM_CHECK(fm_is(json_at(&view.rows, 0), "vitals_evidence", "UNKNOWN"));
    zcl_fmc_machines_free(&view);
    json_free(&workers);
    json_free(&histories);
    json_free(&roster);
    return 0;
}

static int fm_agent_binding_cases(void)
{
    struct json_value roster = fm_roster(false, false);
    struct json_value histories = fm_history_array(FM_BOX_A, 4, false,
                                                    "signature_chain_only");
    struct json_value workers = fm_workers(false);
    struct zcl_fmc_machines view;
    zcl_fmc_machines_init(&view);
    FM_CHECK(zcl_fmc_machines_project(&view, &roster, &histories, &workers,
                                      false, 1000, 900));
    FM_CHECK(fm_is(json_at(&view.rows, 0), "agents_state", "PARTIAL"));
    zcl_fmc_machines_free(&view);

    struct json_value unknown = fm_parse("[{\"name\":\"other\",\"board_post\":\"" FM_POST_A "\","
        "\"board_signer\":\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"}]");
    zcl_fmc_machines_init(&view);
    FM_CHECK(zcl_fmc_machines_project(&view, &roster, &histories, &unknown,
                                      true, 1000, 900));
    FM_CHECK(view.unbound_workers == 1);
    FM_CHECK(fm_is(json_at(&view.rows, 0), "agents_state", "UNKNOWN"));
    zcl_fmc_machines_free(&view);

    struct json_value malformed = fm_parse("[{\"name\":\"local\",\"board_post\":\"bad\","
        "\"board_signer\":\"" FM_BOX_A "\"}]");
    zcl_fmc_machines_init(&view);
    FM_CHECK(zcl_fmc_machines_project(&view, &roster, &histories, &malformed,
                                      true, 1000, 900));
    FM_CHECK(view.unbound_workers == 1);
    zcl_fmc_machines_free(&view);
    json_free(&malformed);
    json_free(&unknown);
    json_free(&workers);
    json_free(&histories);
    json_free(&roster);
    return 0;
}

static int fm_duplicate_box_binding_case(void)
{
    struct json_value roster = fm_roster(true, false);
    const struct json_value *second = json_at(json_get(&roster, "machines"), 1);
    json_set_str((struct json_value *)json_get(json_get(second, "verified"),
                                              "box_pubkey"), FM_BOX_A);
    struct json_value histories = fm_history_array(FM_BOX_A, 4, false,
                                                    "signature_chain_only");
    struct json_value workers = fm_workers(false);
    struct zcl_fmc_machines view;
    zcl_fmc_machines_init(&view);
    FM_CHECK(zcl_fmc_machines_project(&view, &roster, &histories, &workers,
                                      true, 1000, 900));
    FM_CHECK(!view.complete && view.unbound_workers == 1);
    for (size_t i = 0; i < 2; i++) {
        const struct json_value *machine = json_at(&view.rows, i);
        FM_CHECK(json_get_bool(json_get(machine, "duplicate_box")));
        FM_CHECK(fm_is(machine, "agents_state", "UNKNOWN"));
        FM_CHECK(json_size(json_get(machine, "agents")) == 0);
    }
    struct json_value out = {0};
    json_set_object(&out);
    FM_CHECK(zcl_fmc_machines_emit(&view, &out));
    FM_CHECK(!json_get_bool(json_get(&out, "machine_agents_complete")));
    json_free(&out);
    json_free(&workers);
    json_init(&workers);
    json_set_array(&workers);
    FM_CHECK(zcl_fmc_machines_project(&view, &roster, &histories, &workers,
                                      true, 1000, 900));
    FM_CHECK(view.unbound_workers == 0);
    FM_CHECK(fm_is(json_at(&view.rows, 0), "agents_state", "UNKNOWN"));
    json_init(&out);
    json_set_object(&out);
    FM_CHECK(zcl_fmc_machines_emit(&view, &out));
    FM_CHECK(!json_get_bool(json_get(&out, "machine_agents_complete")));
    json_free(&out);
    zcl_fmc_machines_free(&view);
    json_free(&workers);
    json_free(&histories);
    json_free(&roster);
    return 0;
}

static int fm_bounded_roster_case(void)
{
    struct json_value roster = {0}, rows = {0}, histories = {0}, workers = {0};
    json_set_object(&roster);
    json_set_array(&rows);
    json_set_array(&histories);
    json_set_array(&workers);
    for (size_t i = 0; i < ZCL_FMC_MACHINE_CAP + 1u; i++) {
        char box[65], name[24];
        (void)snprintf(box, sizeof(box), "%064llx", (unsigned long long)i + 1u);
        (void)snprintf(name, sizeof(name), "box-%zu", i);
        struct json_value verified = {0}, source = {0};
        json_set_object(&verified);
        json_set_object(&source);
        FM_CHECK(json_push_kv_str(&verified, "name", name));
        FM_CHECK(json_push_kv_str(&verified, "box_pubkey", box));
        FM_CHECK(json_push_kv(&source, "verified", &verified));
        FM_CHECK(json_push_kv_int(&source, "rows", 1));
        FM_CHECK(json_push_back(&rows, &source));
        json_free(&source);
        json_free(&verified);
    }
    FM_CHECK(json_push_kv_int(&roster, "total", ZCL_FMC_MACHINE_CAP + 1u));
    FM_CHECK(json_push_kv_int(&roster, "offset", 0));
    FM_CHECK(json_push_kv_int(&roster, "returned", ZCL_FMC_MACHINE_CAP + 1u));
    FM_CHECK(json_push_kv_int(&roster, "next_offset", -1));
    FM_CHECK(json_push_kv_bool(&roster, "truncated", false));
    FM_CHECK(json_push_kv_int(&roster, "unverifiable", 0));
    FM_CHECK(json_push_kv(&roster, "machines", &rows));
    struct zcl_fmc_machines view;
    zcl_fmc_machines_init(&view);
    FM_CHECK(zcl_fmc_machines_project(&view, &roster, &histories, &workers,
                                      true, 1000, 900));
    FM_CHECK(view.truncated && !view.complete);
    FM_CHECK(view.total == ZCL_FMC_MACHINE_CAP + 1u);
    FM_CHECK(json_size(&view.rows) == ZCL_FMC_MACHINE_CAP);
    struct json_value out = {0};
    json_set_object(&out);
    FM_CHECK(zcl_fmc_machines_emit(&view, &out));
    FM_CHECK(fm_number(&out, "machines_total", ZCL_FMC_MACHINE_CAP + 1u));
    FM_CHECK(json_get_bool(json_get(&out, "machines_truncated")));
    FM_CHECK(!json_get_bool(json_get(&out, "machine_agents_complete")));
    json_free(&out);
    zcl_fmc_machines_free(&view);
    json_free(&workers);
    json_free(&histories);
    json_free(&rows);
    json_free(&roster);
    return 0;
}

static int fm_bad_roster_case(void)
{
    struct json_value roster = fm_parse("{\"machines\":{}}");
    struct json_value histories = {0}, workers = {0};
    json_set_array(&histories);
    json_set_array(&workers);
    struct zcl_fmc_machines view;
    zcl_fmc_machines_init(&view);
    FM_CHECK(zcl_fmc_machines_project(&view, &roster, &histories, &workers,
                                      true, 1000, 900));
    FM_CHECK(!view.roster_ok && !view.complete && view.total == 0);
    FM_CHECK(json_size(&view.rows) == 0);
    zcl_fmc_machines_free(&view);
    json_free(&workers);
    json_free(&histories);
    json_free(&roster);
    return 0;
}

static int fm_mutated_history_case(int kind)
{
    struct json_value roster = fm_roster(false, false);
    struct json_value histories = fm_history_array(FM_BOX_A, 4, false,
                                                    "signature_chain_only");
    struct json_value workers = fm_workers(false);
    const struct json_value *history = json_at(&histories, 0);
    const struct json_value *rows = json_get(history, "rows");
    if (kind == 0)
        json_set_bool((struct json_value *)json_get(history, "found"), false);
    else if (kind == 1)
        json_set_str((struct json_value *)json_get(history, "delegation"),
                     "verified");
    else if (kind == 2)
        json_set_int((struct json_value *)json_get(json_at(rows, 3), "value"),
                     -1);
    else if (kind == 3)
        json_set_int((struct json_value *)json_get(json_at(rows, 3), "value"),
                     131072);
    else
        json_set_int((struct json_value *)json_get(json_at(rows, 1), "seq"), 1);
    struct zcl_fmc_machines view;
    zcl_fmc_machines_init(&view);
    FM_CHECK(zcl_fmc_machines_project(&view, &roster, &histories, &workers,
                                      true, 1000, 900));
    const struct json_value *machine = json_at(&view.rows, 0);
    if (kind == 0 || kind == 4) {
        FM_CHECK(!json_get_bool(json_get(machine, "history_complete")));
        FM_CHECK(fm_is(machine, "heartbeat_state", "UNKNOWN"));
        FM_CHECK(json_is_null(json_get(machine, "cpus")));
    } else if (kind == 1) {
        FM_CHECK(fm_is(machine, "vitals_delegation", "UNKNOWN"));
    } else {
        FM_CHECK(!view.complete);
        FM_CHECK(json_is_null(json_get(machine, "ram_avail_mib")));
        if (kind == 2)
            FM_CHECK(json_is_null(json_get(machine, "ram_used_mib")));
    }
    zcl_fmc_machines_free(&view);
    json_free(&workers);
    json_free(&histories);
    json_free(&roster);
    return 0;
}

static int fm_roster_review_case(bool missing_name)
{
    struct json_value roster = fm_roster(false, false);
    struct json_value histories = fm_history_array(FM_BOX_A, 4, false,
                                                    "signature_chain_only");
    struct json_value workers = fm_workers(false);
    if (missing_name) {
        const struct json_value *source = json_at(json_get(&roster, "machines"), 0);
        json_set_str((struct json_value *)json_get(json_get(source, "verified"),
                                                  "name"), "");
    } else {
        json_set_int((struct json_value *)json_get(&roster, "total"), 2);
        json_set_int((struct json_value *)json_get(&roster, "next_offset"), 1);
        json_set_bool((struct json_value *)json_get(&roster, "truncated"), true);
    }
    struct zcl_fmc_machines view;
    zcl_fmc_machines_init(&view);
    FM_CHECK(zcl_fmc_machines_project(&view, &roster, &histories, &workers,
                                      true, 1000, 900));
    FM_CHECK(!view.complete);
    if (!missing_name)
        FM_CHECK(!view.roster_ok);
    if (missing_name) {
        FM_CHECK(json_is_null(json_get(json_at(&view.rows, 0), "name")));
    } else {
        FM_CHECK(view.total == 2 && view.truncated);
        FM_CHECK(json_size(&view.rows) == 1);
        struct json_value out = {0};
        json_set_object(&out);
        FM_CHECK(zcl_fmc_machines_emit(&view, &out));
        FM_CHECK(fm_number(&out, "machines_total", 2));
        FM_CHECK(json_get_bool(json_get(&out, "machines_truncated")));
        json_free(&out);
    }
    zcl_fmc_machines_free(&view);
    json_free(&workers);
    json_free(&histories);
    json_free(&roster);
    return 0;
}

int test_fleet_steer_machines(void)
{
    int failures = 0;
    failures += fm_complete_case();
    failures += fm_multiple_machines_case();
    failures += fm_stale_future_case();
    failures += fm_discrepancy_cases();
    failures += fm_agent_binding_cases();
    failures += fm_duplicate_box_binding_case();
    failures += fm_bounded_roster_case();
    failures += fm_bad_roster_case();
    for (int kind = 0; kind < 5; kind++)
        failures += fm_mutated_history_case(kind);
    failures += fm_roster_review_case(false);
    failures += fm_roster_review_case(true);
    if (failures == 0)
        printf("fleet_steer_machines: all projection cases passed\n");
    return failures;
}
