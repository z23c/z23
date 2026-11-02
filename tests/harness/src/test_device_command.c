/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: isolated real public-binary owner-device CLI acceptance. */
#include "test/test_core.h"
#include "devloop.h"
#include "command/native_command.h"
#include "config/command_catalog.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "services/device_identity.h"
#include "services/device_host_key.h"
#include "base/hex.h"
#include "platform/clock.h"
#include "platform/positioned_file.h"
#include "support/cleanse.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <poll.h>

#if !defined(_WIN32)
struct command_fixture {
    char home[1024], local[1200], peer[1200];
    char peer_key[65], fingerprint[65], root[65];
    int64_t expires;
};
static bool command_input(struct json_value *input, const char *directory)
{
    json_set_object(input);
    return json_push_kv_str(input, "directory", directory);
}
static bool command_process(const char *const argv[], const char *const env[],
                            struct zcl_devloop_process_result *captured)
{
    const char *prior = getenv("ZCL_DEVLOOP_TEST_PROCESS");
    char *saved = prior ? strdup(prior) : NULL;
    if (prior && !saved) return false;
    if (setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1) != 0) { free(saved); return false; }
    bool ran = zcl_devloop_process_run_env(".", argv, env, 10000, captured);
    bool restored = (saved ? setenv("ZCL_DEVLOOP_TEST_PROCESS", saved, 1)
                          : unsetenv("ZCL_DEVLOOP_TEST_PROCESS")) == 0;
    free(saved);
    return ran && restored;
}
static bool command_result(const char *action, const struct zcl_devloop_process_result *captured,
                           struct json_value *reply, bool success)
{
    if (captured->timed_out || captured->cancelled || captured->output_truncated ||
        captured->term_signal || captured->exit_code < 0) return false;
    const char *json = strchr(captured->output, '{');
    if (!json || !json_read(reply, json, strlen(json))) {
        fprintf(stderr, "device CLI %s: invalid observation: %s\n", action, captured->output);
        return false;
    }
    const struct json_value *observed = json_get(reply, "ok");
    if (!observed || observed->type != JSON_BOOL) return false;
    if (json_get(json_get(reply, "data"), "private_key")) return false;
    bool ok = json_get_bool(json_get(reply, "ok"));
    if (ok != success || (captured->exit_code == 0) != success)
        fprintf(stderr, "device CLI %s: exit=%d output=%s\n", action, captured->exit_code, captured->output);
    return ok == success && (captured->exit_code == 0) == success;
}
static bool command_capture(const struct command_fixture *fixture, const char *action,
    const struct json_value *input, struct json_value *reply, bool success)
{
    char wire[8192], argument[8216], home[1100];
    if (json_write(input, wire, sizeof(wire)) <= 0) return false;
    int n = snprintf(argument, sizeof(argument), "--input=%s", wire);
    if (n < 0 || (size_t)n >= sizeof(argument)) return false;
    n = snprintf(home, sizeof(home), "HOME=%s", fixture->home);
    if (n < 0 || (size_t)n >= sizeof(home)) return false;
    const char *argv[] = {"build/bin/z23", "ops", "mesh", "device", action,
        argument, "--format=json", NULL};
    const char *env[] = {home, "PATH=/usr/bin:/bin", "ZCL_CLI_TEST_NO_SERVICE_LOOKUP=1", NULL};
    struct zcl_devloop_process_result captured = {0};
    return command_process(argv, env, &captured) && command_result(action, &captured, reply, success);
}
static bool command_call(const struct command_fixture *fixture, const char *action,
    const struct json_value *input, bool success)
{
    struct json_value reply = {0};
    bool ok = command_capture(fixture, action, input, &reply, success);
    json_free(&reply);
    return ok;
}
static bool reply_string(const struct json_value *reply, const char *key, char out[65])
{
    const struct json_value *data = json_get(reply, "data");
    const struct json_value *value = json_get(data, key);
    if (!value || value->type != JSON_STR || strlen(json_get_str(value)) != 64) return false;
    memcpy(out, json_get_str(value), 65);
    return true;
}
static size_t reply_field_count(const struct json_value *reply, const char *key)
{
    const struct json_value *data = json_get(reply, "data");
    if (!data || data->type != JSON_OBJ) return 0;
    size_t count = 0;
    for (size_t i = 0; i < data->num_children; ++i)
        if (!strcmp(data->keys[i], key)) ++count;
    return count;
}
static bool reply_is(const struct json_value *reply, const char *key, const char *text)
{
    const struct json_value *value = json_get(json_get(reply, "data"), key);
    return value && value->type == JSON_STR && !strcmp(json_get_str(value), text);
}
static bool reply_bool(const struct json_value *reply, const char *key, bool expected)
{
    const struct json_value *value = json_get(json_get(reply, "data"), key);
    return value && value->type == JSON_BOOL && json_get_bool(value) == expected;
}
static bool reply_mutated(const struct json_value *reply, bool expected)
{
    const struct json_value *value = json_get(json_get(reply, "error"), "mutated");
    return value && value->type == JSON_BOOL && json_get_bool(value) == expected;
}
static bool failure_fact_is(const struct json_value *reply, const char *key, const char *text)
{
    const struct json_value *facts = json_get(json_get(reply, "error"), "facts");
    if (!facts || facts->type != JSON_OBJ) return false;
    const struct json_value *value = json_get(facts, key);
    return value && value->type == JSON_STR && !strcmp(json_get_str(value), text);
}
static bool initialize_profile(struct command_fixture *fixture, const char *directory,
    char key[65], char fingerprint[65])
{
    struct json_value input = {0}, reply = {0};
    bool ok = command_input(&input, directory) &&
        command_capture(fixture, "init", &input, &reply, true) &&
        reply_string(&reply, "public_key", key) && reply_string(&reply, "fingerprint", fingerprint) &&
        reply_is(&reply, "identity_publication", "durable") &&
        reply_field_count(&reply, "identity_publication") == 1 &&
        reply_field_count(&reply, "publication") == 0 && reply_bool(&reply, "observation_only", false);
    json_free(&reply);
    json_free(&input);
    return ok;
}
static bool grant_input(struct json_value *input, const struct command_fixture *fixture)
{
    return command_input(input, fixture->local) &&
        json_push_kv_str(input, "peer_key", fixture->peer_key) &&
        json_push_kv_str(input, "capability", "status-read") &&
        json_push_kv_int(input, "expires_at", fixture->expires);
}
static bool grant_inspect(const struct command_fixture *fixture, struct db_device_pairing *row,
    uint8_t root[32])
{
    struct device_identity identity = {0};
    struct device_identity_publication_report report;
    struct device_pairing_store store;
    uint8_t peer[32];
    bool ok = device_identity_open(&identity, fixture->local, false, &report).ok &&
        zcl_hex_decode(fixture->peer_key, peer, 32) &&
        device_identity_pair_store(&identity, peer, &store).ok &&
        db_device_pairing_inspect(&store, peer, row, root);
    device_identity_close(&identity);
    return ok;
}
static bool revoke_input(struct json_value *input, const struct command_fixture *fixture,
    const char *root, const char *fingerprint)
{
    if (!command_input(input, fixture->local) ||
        !json_push_kv_str(input, "peer_key", fixture->peer_key)) return false;
    if (root && !json_push_kv_str(input, "expected_root", root)) return false;
    return !fingerprint || json_push_kv_str(input, "fingerprint", fingerprint);
}
static bool fixture_fresh(void)
{
    struct stat binary;
    if (stat("build/bin/z23", &binary) != 0) return false;
    const char *files[] = {"tools/command/native_device_command.c", "engine/composition/commands/ops.def",
        "tools/command/native_device_host_command.c", "engine/services/src/device_host_key.c",
        "engine/services/src/device_identity.c", "engine/models/src/device_pairing.c"};
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); ++i) {
        struct stat source;
        if (stat(files[i], &source) != 0 || source.st_mtime > binary.st_mtime) return false;
    }
    return true;
}
static int command_identity_flows(struct command_fixture *fixture)
{
    int failures = 0;
    struct json_value input = {0}, reply = {0};
    TEST_CASE("device CLI: real init and identity flows expose public facts, refuse retries and malformed input") {
        char local_key[65], local_fingerprint[65];
        ASSERT(initialize_profile(fixture, fixture->local, local_key, local_fingerprint));
        ASSERT(initialize_profile(fixture, fixture->peer, fixture->peer_key, fixture->fingerprint));
        ASSERT(command_input(&input, fixture->local));
        ASSERT(command_capture(fixture, "identity", &input, &reply, true));
        ASSERT(reply_bool(&reply, "observation_only", true));
        ASSERT(reply_is(&reply, "identity_publication", "not_published"));
        json_free(&reply);
        ASSERT(command_call(fixture, "init", &input, false));
        json_free(&input);
        ASSERT(command_input(&input, fixture->local));
        ASSERT(json_push_kv_int(&input, "peer_key", 7));
        ASSERT(command_call(fixture, "plan", &input, false));
        json_free(&input);
        ASSERT(command_input(&input, fixture->local));
        ASSERT(json_push_kv_str(&input, "unexpected", "refuse"));
        ASSERT(command_call(fixture, "identity", &input, false));
    } TEST_END
    json_free(&reply);
    json_free(&input);
    return failures;
}
static int command_grant_flows(struct command_fixture *fixture)
{
    int failures = 0;
    struct json_value input = {0}, reply = {0};
    TEST_CASE("device CLI: plan proposes; explicit independently confirmed commit inserts only") {
        ASSERT(grant_input(&input, fixture));
        ASSERT(command_capture(fixture, "plan", &input, &reply, true));
        ASSERT(!json_get_bool(json_get(json_get(&reply, "data"), "committed")));
        struct db_device_pairing row;
        uint8_t root[32];
        ASSERT(!grant_inspect(fixture, &row, root));
        ASSERT(json_push_kv_str(&input, "expected_root", "absent"));
        ASSERT(json_push_kv_str(&input, "fingerprint", "0000000000000000000000000000000000000000000000000000000000000000"));
        ASSERT(command_call(fixture, "commit", &input, false));
        ASSERT(!grant_inspect(fixture, &row, root));
        json_free(&input);
        ASSERT(grant_input(&input, fixture));
        ASSERT(json_push_kv_str(&input, "expected_root", "absent"));
        ASSERT(json_push_kv_str(&input, "fingerprint", fixture->fingerprint));
        json_free(&reply);
        ASSERT(command_capture(fixture, "commit", &input, &reply, true));
        ASSERT_EQ(reply_field_count(&reply, "publication"), (size_t)1);
        ASSERT(reply_is(&reply, "publication", "durable"));
        ASSERT(grant_inspect(fixture, &row, root));
        ASSERT_EQ(row.capabilities, DEVICE_PAIRING_CAP_STATUS_READ);
        ASSERT_EQ(row.expires_at, (uint64_t)fixture->expires);
        ASSERT(command_call(fixture, "commit", &input, false));
        uint8_t unchanged[32];
        ASSERT(grant_inspect(fixture, &row, unchanged));
        ASSERT(!memcmp(root, unchanged, 32));
    } TEST_END
    json_free(&reply);
    json_free(&input);
    return failures;
}
static int command_revoke_flows(struct command_fixture *fixture)
{
    int failures = 0;
    struct json_value input = {0}, reply = {0};
    TEST_CASE("device CLI: revoke inspection, paired approvals, stale-root refusal and sticky revocation") {
        ASSERT(revoke_input(&input, fixture, NULL, NULL));
        ASSERT(command_capture(fixture, "revoke", &input, &reply, true));
        ASSERT(reply_string(&reply, "expected_root", fixture->root));
        json_free(&input);
        ASSERT(revoke_input(&input, fixture, NULL, fixture->fingerprint));
        ASSERT(command_call(fixture, "revoke", &input, false));
        json_free(&input);
        char stale[65];
        memcpy(stale, fixture->root, sizeof(stale));
        stale[0] = stale[0] == '0' ? '1' : '0';
        ASSERT(revoke_input(&input, fixture, stale, fixture->fingerprint));
        ASSERT(command_call(fixture, "revoke", &input, false));
        struct db_device_pairing row;
        uint8_t root[32], expected[32];
        ASSERT(grant_inspect(fixture, &row, root));
        ASSERT_EQ(row.revoked_at, 0);
        ASSERT(zcl_hex_decode(fixture->root, expected, 32));
        ASSERT(!memcmp(root, expected, 32));
        json_free(&input);
        ASSERT(revoke_input(&input, fixture, fixture->root, fixture->fingerprint));
        json_free(&reply);
        ASSERT(command_capture(fixture, "revoke", &input, &reply, true));
        ASSERT_EQ(reply_field_count(&reply, "publication"), (size_t)1);
        ASSERT(reply_is(&reply, "publication", "durable"));
        ASSERT_EQ(reply_field_count(&reply, "expected_root"), (size_t)0);
        char prior[65];
        ASSERT(reply_string(&reply, "inspected_prior_root", prior));
        ASSERT(!strcmp(prior, fixture->root));
        ASSERT(grant_inspect(fixture, &row, root));
        ASSERT(row.revoked_at > 0);
        ASSERT_EQ(row.generation, 1);
        uint64_t revoked = row.revoked_at;
        zcl_hex_encode(root, 32, fixture->root);
        json_free(&input);
        ASSERT(revoke_input(&input, fixture, fixture->root, fixture->fingerprint));
        ASSERT(command_call(fixture, "revoke", &input, true));
        ASSERT(grant_inspect(fixture, &row, root));
        ASSERT_EQ(row.revoked_at, revoked);
        ASSERT_EQ(row.generation, 1);
    } TEST_END
    json_free(&reply);
    json_free(&input);
    return failures;
}
struct host_command_fixture {
    struct command_fixture profile;
    char local_blob[DEVICE_HOST_KEY_BLOB_SIZE * 2 + 1], peer_blob[DEVICE_HOST_KEY_BLOB_SIZE * 2 + 1];
    char proposal[65], prior[65];
    char other_directory[1200];
    int64_t paired;
};
static void host_blob(char text[DEVICE_HOST_KEY_BLOB_SIZE * 2 + 1], uint8_t seed)
{
    uint8_t blob[DEVICE_HOST_KEY_BLOB_SIZE] = {0, 0, 0, 19};
    memcpy(blob + 4, "ssh-mldsa44-ed25519", 19);
    blob[25] = 5; blob[26] = 64;
    for (size_t i = 27; i < sizeof(blob); ++i) blob[i] = (uint8_t)(i + seed);
    zcl_hex_encode(blob, sizeof(blob), text);
}
static bool host_int(struct json_value *input, const char *key, int64_t value, const char *omit)
{
    return (omit && !strcmp(omit, key)) || json_push_kv_int(input, key, value);
}
static bool host_str(struct json_value *input, const char *key, const char *value, const char *omit)
{
    return !value || (omit && !strcmp(omit, key)) || json_push_kv_str(input, key, value);
}
static bool host_input(struct json_value *input, const struct host_command_fixture *host,
    const char *prior, const char *approval, const char *omit)
{
    if (!command_input(input, host->profile.local)) return false;
    if (!host_str(input, "peer_key", host->profile.peer_key, omit) ||
        !host_str(input, "capability", "host-forward", omit) ||
        !host_str(input, "local_pq_blob", host->local_blob, omit) ||
        !host_str(input, "peer_pq_blob", host->peer_blob, omit) ||
        !host_str(input, "expected_root", prior, omit) ||
        !host_str(input, "confirmed_proposal_root", approval, omit)) return false;
    if (host->paired && !host_int(input, "paired_at", host->paired, omit)) return false;
    return host_int(input, "backend", 1, omit) && host_int(input, "inbound_port", 2222, omit) &&
        host_int(input, "outbound_port", 0, omit) && host_int(input, "expires_at", host->profile.expires, omit);
}
static bool host_fixture_init(const struct command_fixture *base, struct host_command_fixture *host)
{
    memset(host, 0, sizeof(*host)); host->profile = *base;
    int n = snprintf(host->profile.local, sizeof(host->profile.local), "%s/host-local", base->home);
    if (n <= 0 || (size_t)n >= sizeof(host->profile.local)) return false;
    char key[65], fingerprint[65];
    host_blob(host->local_blob, 1); host_blob(host->peer_blob, 2);
    if (!initialize_profile(&host->profile, host->profile.local, key, fingerprint)) return false;
    n = snprintf(host->other_directory, sizeof(host->other_directory), "%s/host-other", base->home);
    return n > 0 && (size_t)n < sizeof(host->other_directory) &&
        initialize_profile(&host->profile, host->other_directory, key, fingerprint);
}
static bool host_plan(struct host_command_fixture *host, const char *prior)
{
    struct json_value input = {0}, reply = {0};
    bool ok = host_input(&input, host, prior, NULL, NULL) &&
        command_capture(&host->profile, "plan", &input, &reply, true);
    const struct json_value *paired = json_get(json_get(&reply, "data"), "paired_at");
    if (ok) ok = paired && paired->type == JSON_INT && json_get_int(paired) > 0 &&
        reply_string(&reply, "proposal_root", host->proposal) && reply_bool(&reply, "committed", false) &&
        reply_is(&reply, "possession", "not_established_by_this_command") &&
        reply_is(&reply, "backend_qualification", "not_established_by_this_command") &&
        reply_is(&reply, "local_pq_blob", host->local_blob) && reply_is(&reply, "peer_pq_blob", host->peer_blob);
    if (ok) host->paired = json_get_int(paired);
    json_free(&input); json_free(&reply); return ok;
}
static bool host_later_wall(int64_t paired)
{
    int64_t deadline = clock_now_monotonic_ns() + INT64_C(5000000000);
    while (clock_now_monotonic_ns() < deadline) {
        if (clock_now_wall_ms() / 1000 > paired) return true;
        (void)poll(NULL, 0, 20);
    }
    return false;
}
/* Only mutate fields of this owned JSON object, never append duplicate keys. */
static struct json_value *host_member(struct json_value *input, const char *key)
{
    for (size_t i = 0; i < input->num_children; ++i)
        if (!strcmp(input->keys[i], key)) return &input->children[i];
    return NULL;
}
static void host_tamper(struct json_value *input, unsigned field, const struct host_command_fixture *host)
{
    switch (field) {
    case 0: json_set_int(host_member(input, "backend"), 2); break;
    case 1: json_set_int(host_member(input, "inbound_port"), 2223); break;
    case 2: json_set_int(host_member(input, "outbound_port"), 2222); break;
    case 3: json_set_int(host_member(input, "paired_at"), host->paired - 1); break;
    case 4: json_set_int(host_member(input, "expires_at"), host->profile.expires + 1); break;
    case 5: json_set_str(host_member(input, "local_pq_blob"), "00"); break;
    case 6: json_set_str(host_member(input, "peer_pq_blob"), "not-hex"); break;
    case 7: json_set_str(host_member(input, "capability"), "status-read"); break;
    case 8: json_set_str(host_member(input, "confirmed_proposal_root"), host->profile.peer_key); break;
    case 9: json_set_int(host_member(input, "expires_at"), host->paired); break;
    case 10: json_set_int(host_member(input, "paired_at"), host->profile.expires + 1); break;
    default: json_set_int(host_member(input, "expires_at"), host->paired + 2592001); break;
    }
}
static int host_refusals(struct host_command_fixture *host)
{
    int failures = 0;
    struct json_value input = {0}, reply = {0};
    TEST_CASE("device HOST CLI: missing approvals, malformed representations and one-field tamper do not publish") {
        static const char *const fields[] = {"capability", "peer_key", "backend", "local_pq_blob", "peer_pq_blob", "inbound_port",
            "outbound_port", "paired_at", "expires_at", "expected_root", "confirmed_proposal_root"};
        struct db_device_pairing row;
        uint8_t root[32];
        for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
            ASSERT(host_input(&input, host, "absent", host->proposal, fields[i]));
            ASSERT(command_capture(&host->profile, "commit", &input, &reply, false));
            ASSERT(reply_mutated(&reply, false));
            ASSERT(!grant_inspect(&host->profile, &row, root));
            json_free(&input); json_free(&reply);
        }
        for (unsigned field = 0; field < 12; ++field) {
            ASSERT(host_input(&input, host, "absent", host->proposal, NULL));
            host_tamper(&input, field, host);
            ASSERT(command_capture(&host->profile, "commit", &input, &reply, false));
            ASSERT(reply_mutated(&reply, false));
            ASSERT(!grant_inspect(&host->profile, &row, root));
            json_free(&input); json_free(&reply);
        }
        for (unsigned key = 0; key < 2; ++key) {
            ASSERT(host_input(&input, host, "absent", host->proposal, NULL));
            char changed[DEVICE_HOST_KEY_BLOB_SIZE * 2 + 1];
            memcpy(changed, key ? host->peer_blob : host->local_blob, sizeof(changed));
            changed[sizeof(changed) - 2] = changed[sizeof(changed) - 2] == '0' ? '1' : '0';
            struct json_value *value = host_member(&input, key ? "peer_pq_blob" : "local_pq_blob");
            json_set_str(value, changed); ASSERT(value->type == JSON_STR);
            ASSERT(command_capture(&host->profile, "commit", &input, &reply, false));
            ASSERT(reply_mutated(&reply, false));
            ASSERT(!grant_inspect(&host->profile, &row, root));
            json_free(&input); json_free(&reply);
        }
        ASSERT(host_input(&input, host, "absent", host->proposal, NULL));
        json_set_str(host_member(&input, "directory"), host->other_directory);
        ASSERT(command_capture(&host->profile, "commit", &input, &reply, false));
        ASSERT(reply_mutated(&reply, false));
        ASSERT(!grant_inspect(&host->profile, &row, root));
    } TEST_END
    json_free(&input); json_free(&reply); return failures;
}
static int host_commit_stable(struct host_command_fixture *host)
{
    int failures = 0;
    struct json_value input = {0}, reply = {0};
    TEST_CASE("device HOST CLI: later real-binary commit preserves exact approved paired_at") {
        ASSERT(host_later_wall(host->paired));
        ASSERT(host_input(&input, host, "absent", host->proposal, NULL));
        ASSERT(command_capture(&host->profile, "commit", &input, &reply, true));
        ASSERT(reply_is(&reply, "publication", "durable"));
        ASSERT_EQ(reply_field_count(&reply, "publication"), 1);
        struct db_device_pairing row; uint8_t root[32];
        ASSERT(grant_inspect(&host->profile, &row, root));
        ASSERT_EQ(row.paired_at, (uint64_t)host->paired);
        ASSERT_EQ(row.expires_at, (uint64_t)host->profile.expires);
        ASSERT_EQ(row.capabilities, DEVICE_PAIRING_CAP_HOST_FORWARD);
        ASSERT_EQ(row.host_scope.inbound_port, 2222); ASSERT_EQ(row.host_scope.outbound_port, 0);
        uint8_t independently[32]; ASSERT(device_pairing_host_proposal_root(&row, independently));
        char proposal[65]; zcl_hex_encode(independently, 32, proposal);
        ASSERT(!strcmp(proposal, host->proposal));
        zcl_hex_encode(root, 32, host->prior);
    } TEST_END
    json_free(&input); json_free(&reply); return failures;
}
static int host_upgrade_revoke(struct host_command_fixture *host)
{
    int failures = 0;
    struct json_value input = {0}, reply = {0};
    TEST_CASE("device HOST CLI: full replacement approval plus exact old root and sticky revocation") {
        host->profile.expires++;
        ASSERT(host_plan(host, host->prior));
        ASSERT(host_input(&input, host, host->prior, host->proposal, NULL));
        ASSERT(command_capture(&host->profile, "commit", &input, &reply, true));
        ASSERT(reply_is(&reply, "publication", "durable"));
        struct db_device_pairing row; uint8_t root[32], unchanged[32];
        ASSERT(grant_inspect(&host->profile, &row, root));
        ASSERT_EQ(row.paired_at, (uint64_t)host->paired);
        char current[65]; zcl_hex_encode(root, 32, current);
        ASSERT(strcmp(current, host->prior));
        ASSERT(command_call(&host->profile, "commit", &input, false));
        ASSERT(grant_inspect(&host->profile, &row, unchanged)); ASSERT(!memcmp(root, unchanged, 32));
        json_free(&input); json_free(&reply);
        ASSERT(revoke_input(&input, &host->profile, current, host->profile.fingerprint));
        ASSERT(command_capture(&host->profile, "revoke", &input, &reply, true));
        ASSERT(reply_is(&reply, "publication", "durable"));
        ASSERT(grant_inspect(&host->profile, &row, root)); ASSERT(row.revoked_at > 0);
        zcl_hex_encode(root, 32, current);
        json_free(&input); json_free(&reply);
        ASSERT(host_input(&input, host, current, host->proposal, NULL));
        ASSERT(command_call(&host->profile, "commit", &input, false));
        json_free(&input);
        ASSERT(host_input(&input, host, current, NULL, NULL));
        ASSERT(command_call(&host->profile, "plan", &input, false));
        ASSERT(grant_inspect(&host->profile, &row, unchanged)); ASSERT(!memcmp(root, unchanged, 32));
    } TEST_END
    json_free(&input); json_free(&reply); return failures;
}
static int host_input_types(void)
{
    int failures = 0;
    struct json_value input = {0};
    TEST_CASE("device HOST schema: scoped integer descriptors preserve unrelated backend strings") {
        const struct zcl_command_spec *spec = zcl_command_registry_find(
            zcl_command_catalog(), "ops.mesh.device.plan", NULL);
        ASSERT(spec != NULL);
        struct zcl_command_input_descriptor descriptor;
        static const char *const fields[] = {"backend", "inbound_port", "outbound_port", "paired_at"};
        for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
            ASSERT(zcl_command_registry_input_descriptor(spec, fields[i], &descriptor));
            ASSERT_EQ(descriptor.type, JSON_INT);
        }
        /* Preserve the registered spec's valid schema and contract metadata. */
        struct zcl_command_spec unrelated = *spec;
        unrelated.path = "fixture.unrelated";
        unrelated.input_keys = "backend";
        json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "backend", "unchanged-string-backend"));
        char why[192];
        ASSERT(zcl_command_registry_input_validate(&unrelated, &input, why, sizeof(why)));
        json_set_int(&input.children[0], 1);
        ASSERT(!zcl_command_registry_input_validate(&unrelated, &input, why, sizeof(why)));
    } TEST_END
    json_free(&input);
    return failures;
}
static int command_host_flows(const struct command_fixture *base)
{
    int failures = 0;
    struct host_command_fixture host;
    failures += host_input_types();
    TEST_CASE("device HOST CLI: read-only complete proposal using trusted local identity") {
        ASSERT(host_fixture_init(base, &host));
        ASSERT(host_plan(&host, "absent"));
        struct db_device_pairing row; uint8_t root[32];
        ASSERT(!grant_inspect(&host.profile, &row, root));
        failures += host_refusals(&host);
        failures += host_commit_stable(&host);
        failures += host_upgrade_revoke(&host);
    } TEST_END
    return failures;
}

struct serialization_clock {
    const clock_iface_t *previous;
    struct zcl_command_reply *reply;
    bool constrained;
};
static int64_t serialization_mono(void *context)
{
    struct serialization_clock *clock = context;
    return clock->previous->now_monotonic_ns(clock->previous->self);
}
static int64_t serialization_wall(void *context)
{
    struct serialization_clock *clock = context;
    struct json_value *data = &clock->reply->data;
    if (!clock->constrained && json_get(data, "inspected_prior_root") &&
        data->num_children > 0 && data->num_children <= data->children_cap) {
        /* White-box geometry: shrink capacity within existing allocation,
         * preserving every initialized child. The next append must grow. */
        data->children_cap = data->num_children;
        clock->constrained = true;
        zcl_alloc_fault_fail_next("json_children");
    }
    return clock->previous->now_wall_ms(clock->previous->self);
}
static int host_legacy_upgrade(const struct command_fixture *base)
{
    int failures = 0;
    struct host_command_fixture host = {0};
    struct json_value input = {0};
    TEST_CASE("device HOST CLI: legacy status grant can still upgrade to backend1") {
        host.profile = *base;
        ASSERT(snprintf(host.profile.local, sizeof(host.profile.local), "%s/legacy-host-local", base->home) > 0);
        char local[65], fingerprint[65];
        ASSERT(initialize_profile(&host.profile, host.profile.local, local, fingerprint));
        host_blob(host.local_blob, 1); host_blob(host.peer_blob, 2);
        ASSERT(grant_input(&input, &host.profile));
        ASSERT(json_push_kv_str(&input, "expected_root", "absent"));
        ASSERT(json_push_kv_str(&input, "fingerprint", host.profile.fingerprint));
        ASSERT(command_call(&host.profile, "commit", &input, true));
        struct db_device_pairing row; uint8_t root[32];
        ASSERT(grant_inspect(&host.profile, &row, root)); zcl_hex_encode(root, 32, host.prior);
        ASSERT(host_plan(&host, host.prior));
        json_free(&input);
        ASSERT(host_input(&input, &host, host.prior, host.proposal, NULL));
        ASSERT(command_call(&host.profile, "commit", &input, true));
        ASSERT(grant_inspect(&host.profile, &row, root)); ASSERT_EQ(row.host_scope.binding.backend_profile, 1);
    } TEST_END
    json_free(&input); return failures;
}
struct psk_command_fixture {
    struct host_command_fixture host;
    char id[65], source[1200];
    int64_t epoch;
};
static bool psk_command_input(struct json_value *input, const struct psk_command_fixture *psk,
    const char *prior, const char *approval, bool commit)
{
    const struct host_command_fixture *host = &psk->host;
    if (!command_input(input, host->profile.local)) return false;
    if (!host_str(input, "peer_key", host->profile.peer_key, NULL) ||
        !host_str(input, "capability", "host-forward", NULL) ||
        !host_str(input, "expected_root", prior, NULL) ||
        !host_str(input, "confirmed_proposal_root", approval, NULL) ||
        !host_str(input, "credential_id", psk->id, NULL)) return false;
    if (commit && !host_str(input, "secret_file", psk->source, NULL)) return false;
    if (host->paired && !host_int(input, "paired_at", host->paired, NULL)) return false;
    return host_int(input, "backend", 2, NULL) && host_int(input, "key_epoch", psk->epoch, NULL) &&
        host_int(input, "inbound_port", 2222, NULL) && host_int(input, "outbound_port", 2223, NULL) &&
        host_int(input, "expires_at", host->profile.expires, NULL);
}
static bool psk_source_write(const char *path, size_t size, mode_t mode, uint8_t pattern)
{
    unsigned char bytes[33]; memset(bytes, pattern, sizeof(bytes)); /* PUBLIC fixture, no live secret. */
    FILE *file = fopen(path, "wb");
    if (!file) return false;
    bool wrote = fwrite(bytes, 1, size, file) == size;
    bool closed = fclose(file) == 0;
    return wrote && closed && chmod(path, mode) == 0;
}
static bool psk_command_plan(struct psk_command_fixture *psk, const char *prior)
{
    struct json_value input = {0}, reply = {0};
    bool ok = psk_command_input(&input, psk, prior, NULL, false) &&
        command_capture(&psk->host.profile, "plan", &input, &reply, true);
    const struct json_value *paired = json_get(json_get(&reply, "data"), "paired_at");
    if (ok) ok = paired && paired->type == JSON_INT && reply_string(&reply, "proposal_root", psk->host.proposal) &&
        reply_is(&reply, "credential_id", psk->id) && reply_bool(&reply, "committed", false);
    if (ok) psk->host.paired = json_get_int(paired);
    json_free(&input); json_free(&reply); return ok;
}
static bool psk_reply_public(const struct json_value *reply, const char *source)
{
    char wire[8192];
    if (json_write(reply, wire, sizeof(wire)) <= 0) return false;
    return !strstr(wire, source) && !strstr(wire, "5a5a5a5a5a5a5a5a") && !strstr(wire, "6b6b6b6b6b6b6b6b") &&
        !json_get(json_get(reply, "data"), "secret_file") &&
        !json_get(json_get(reply, "data"), "secret");
}
static int psk_source_refusals(struct psk_command_fixture *psk)
{
    int failures = 0;
    struct json_value input = {0}, reply = {0};
    const size_t sizes[] = {31, 33, 32};
    for (size_t i = 0; i < 3; ++i) {
        TEST_CASE("backend2 CLI: invalid private source refuses before transaction") {
            ASSERT(psk_source_write(psk->source, sizes[i], i == 2 ? 0644 : 0600, 0x5a));
            ASSERT(psk_command_input(&input, psk, "absent", psk->host.proposal, true));
            ASSERT(command_capture(&psk->host.profile, "commit", &input, &reply, false));
            ASSERT(reply_mutated(&reply, false));
            ASSERT(failure_fact_is(&reply, "secret_publication", "not_published"));
            ASSERT(failure_fact_is(&reply, "grant_publication", "not_published"));
            ASSERT(psk_reply_public(&reply, psk->source));
        } TEST_END
        json_free(&input); json_free(&reply);
    }
    return failures;
}
static int psk_source_shapes(struct psk_command_fixture *psk)
{
    int failures = 0;
    struct json_value input = {0}, reply = {0};
    TEST_CASE("backend2 CLI: symlink and nonregular source refused") {
        ASSERT(unlink(psk->source) == 0);
        ASSERT(symlink("missing-private-source", psk->source) == 0);
        ASSERT(psk_command_input(&input, psk, "absent", psk->host.proposal, true));
        ASSERT(command_capture(&psk->host.profile, "commit", &input, &reply, false));
        ASSERT(reply_mutated(&reply, false));
        json_free(&reply);
        ASSERT(unlink(psk->source) == 0);
        ASSERT(mkdir(psk->source, 0700) == 0);
        ASSERT(command_capture(&psk->host.profile, "commit", &input, &reply, false));
        ASSERT(reply_mutated(&reply, false));
    } TEST_END
    json_free(&input); json_free(&reply);
    (void)rmdir(psk->source);
    return failures;
}
static int psk_plan_source_refusal(struct psk_command_fixture *psk)
{
    int failures = 0;
    struct json_value input = {0};
    TEST_CASE("backend2 CLI: plan never opens a private source and mixed bindings refuse") {
        ASSERT(psk_command_input(&input, psk, "absent", NULL, false));
        ASSERT(json_push_kv_str(&input, "secret_file", psk->source));
        ASSERT(command_call(&psk->host.profile, "plan", &input, false));
    } TEST_END
    json_free(&input);
    return failures;
}
static int psk_mixed_refusals(struct psk_command_fixture *psk)
{
    int failures = 0;
    struct json_value input = {0};
    const char *forbidden[] = {"local_pq_blob", "secret", "psk", "key"};
    for (size_t i = 0; i < 4; ++i) {
        TEST_CASE("backend2 CLI: mixed or raw-secret fields refuse") {
            ASSERT(psk_command_input(&input, psk, "absent", psk->host.proposal, true));
            ASSERT(json_push_kv_str(&input, forbidden[i], "public-invalid-fixture"));
            ASSERT(command_call(&psk->host.profile, "commit", &input, false));
        } TEST_END
        json_free(&input);
    }
    return failures;
}
static int psk_approval_refusals(struct psk_command_fixture *psk)
{
    int failures = 0;
    struct json_value input = {0};
    TEST_CASE("backend2 CLI: incomplete independent approval and changed epoch refuse") {
        ASSERT(psk_command_input(&input, psk, "absent", NULL, true));
        ASSERT(command_call(&psk->host.profile, "commit", &input, false));
        json_free(&input);
        ASSERT(psk_command_input(&input, psk, "absent", psk->host.proposal, true));
        json_set_int(host_member(&input, "key_epoch"), psk->epoch + 1);
        ASSERT(command_call(&psk->host.profile, "commit", &input, false));
    } TEST_END
    json_free(&input);
    return failures;
}
static bool psk_snapshot_matches(const struct psk_command_fixture *psk, uint8_t pattern)
{
    struct device_identity identity = {0};
    struct device_identity_publication_report report;
    struct device_pairing_store store;
    struct device_pairing_guard guard = {0};
    struct device_pairing_psk_snapshot snapshot = {0};
    uint8_t peer[32], root[32], id[32], expected[32]; memset(expected, pattern, 32);
    bool ok = device_identity_open(&identity, psk->host.profile.local, false, &report).ok &&
        zcl_hex_decode(psk->host.profile.peer_key, peer, 32) &&
        zcl_hex_decode(psk->host.prior, root, 32) && zcl_hex_decode(psk->id, id, 32) &&
        device_identity_pair_store(&identity, peer, &store).ok &&
        device_pairing_psk_snapshot_acquire(&store, peer, root, (uint64_t)(clock_now_wall_ms() / 1000),
            DEVICE_PAIRING_HOST_OUTBOUND, 2223, &guard, &snapshot);
    if (ok) ok = !memcmp(snapshot.secret, expected, 32) && !memcmp(snapshot.root, root, 32) &&
        !memcmp(snapshot.row.host_scope.binding.psk.credential_id, id, 32) &&
        snapshot.row.host_scope.binding.psk.key_epoch == (uint64_t)psk->epoch;
    device_pairing_guard_release(&guard);
    device_pairing_psk_snapshot_destroy(&snapshot);
    device_identity_close(&identity);
    return ok;
}
static int psk_commit_flow(struct psk_command_fixture *psk)
{
    int failures = 0;
    struct json_value input = {0}, reply = {0};
    struct db_device_pairing row; uint8_t root[32];
    TEST_CASE("backend2 CLI: independently approved import emits two durable facts") {
        ASSERT(psk_source_write(psk->source, 32, 0600, 0x5a));
        ASSERT(psk_command_input(&input, psk, "absent", psk->host.proposal, true));
        ASSERT(command_capture(&psk->host.profile, "commit", &input, &reply, true));
        ASSERT(reply_is(&reply, "secret_publication", "durable"));
        ASSERT(reply_is(&reply, "grant_publication", "durable"));
        ASSERT(reply_field_count(&reply, "secret_publication") == 1);
        ASSERT(reply_field_count(&reply, "grant_publication") == 1);
        ASSERT(reply_field_count(&reply, "publication") == 0);
        ASSERT(reply_bool(&reply, "mutation_attempted", true)); ASSERT(reply_bool(&reply, "intent_retired", true));
        ASSERT(psk_reply_public(&reply, psk->source));
        /* The same public fingerprint psk.new prints for this source. */
        uint8_t source_key[32]; char expect[17];
        memset(source_key, 0x5a, sizeof(source_key)); zcl_native_device_psk_fingerprint(source_key, expect);
        ASSERT(reply_is(&reply, "psk_fingerprint", expect));
        ASSERT(grant_inspect(&psk->host.profile, &row, root));
        ASSERT_EQ(row.host_scope.binding.backend_profile, 2);
        ASSERT_EQ(row.host_scope.binding.psk.key_epoch, (uint64_t)psk->epoch);
        ASSERT_EQ(row.paired_at, (uint64_t)psk->host.paired);
        zcl_hex_encode(root, 32, psk->host.prior);
        ASSERT(psk_snapshot_matches(psk, 0x5a));
    } TEST_END
    json_free(&input); json_free(&reply);
    return failures;
}
static int psk_rotate_flow(struct psk_command_fixture *psk)
{
    int failures = 0;
    struct json_value input = {0}, reply = {0};
    struct db_device_pairing row; uint8_t root[32];
    TEST_CASE("backend2 CLI: exact-root rotation retains paired_at and rejects stale approval") {
        psk->id[0] = 'b'; psk->epoch = 2;
        ASSERT(psk_source_write(psk->source, 32, 0600, 0x6b));
        ASSERT(psk_command_plan(psk, psk->host.prior));
        ASSERT(psk_command_input(&input, psk, psk->host.prior, psk->host.proposal, true));
        ASSERT(command_capture(&psk->host.profile, "commit", &input, &reply, true));
        ASSERT(reply_is(&reply, "secret_publication", "durable"));
        ASSERT(reply_is(&reply, "grant_publication", "durable"));
        ASSERT(grant_inspect(&psk->host.profile, &row, root));
        ASSERT_EQ(row.paired_at, (uint64_t)psk->host.paired); ASSERT_EQ(row.host_scope.binding.psk.key_epoch, 2);
        zcl_hex_encode(root, 32, psk->host.prior);
        ASSERT(psk_snapshot_matches(psk, 0x6b));
        ASSERT(command_call(&psk->host.profile, "commit", &input, false));
    } TEST_END
    json_free(&input); json_free(&reply);
    return failures;
}
static int psk_revoke_flow(struct psk_command_fixture *psk)
{
    int failures = 0;
    struct json_value input = {0}, reply = {0};
    TEST_CASE("backend2 CLI: revoked row cannot rotate or be implicitly resurrected") {
        ASSERT(revoke_input(&input, &psk->host.profile, NULL, NULL));
        ASSERT(command_capture(&psk->host.profile, "revoke", &input, &reply, true));
        char inspected[65]; ASSERT(reply_string(&reply, "expected_root", inspected));
        ASSERT(!strcmp(inspected, psk->host.prior));
        json_free(&input); json_free(&reply);
        ASSERT(revoke_input(&input, &psk->host.profile, inspected, psk->host.profile.fingerprint));
        ASSERT(command_call(&psk->host.profile, "revoke", &input, true));
        json_free(&input);
        ASSERT(psk_command_input(&input, psk, psk->host.prior, psk->host.proposal, true));
        ASSERT(command_call(&psk->host.profile, "commit", &input, false));
    } TEST_END
    json_free(&input); json_free(&reply);
    return failures;
}
static void psk_allocation_after_effect(const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    zcl_native_handle_ops_mesh_device(request, reply);
    if (reply->status == ZCL_COMMAND_STATUS_PASSED)
        zcl_alloc_fault_fail_next("json_children");
}
static int psk_execute_allocation_failure(const struct command_fixture *base, unsigned mode)
{
    int failures = 0;
    struct psk_command_fixture psk = {0};
    struct json_value input = {0}, reply = {0};
    TEST_CASE("backend2 CLI: actual persisted import survives execute-envelope allocation failure honestly") {
        psk.host.profile = *base;
        ASSERT(snprintf(psk.host.profile.local, sizeof(psk.host.profile.local), "%s/psk-envelope-local-%u", base->home, mode) > 0);
        char local[65], fingerprint[65];
        ASSERT(initialize_profile(&psk.host.profile, psk.host.profile.local, local, fingerprint));
        ASSERT(snprintf(psk.source, sizeof(psk.source), "%s/envelope-private32", base->home) > 0);
        memset(psk.id, 'f', 64); psk.id[64] = 0; psk.epoch = 1;
        ASSERT(psk_command_plan(&psk, "absent"));
        ASSERT(psk_source_write(psk.source, 32, 0600, 0x5a));
        ASSERT(psk_command_input(&input, &psk, "absent", psk.host.proposal, true));
        const struct zcl_command_registry *registry = zcl_command_catalog();
        const struct zcl_command_spec *registered = zcl_command_registry_find(registry, "ops.mesh.device.commit", NULL);
        ASSERT(registered != NULL);
        struct zcl_command_spec spec = *registered; spec.handler = psk_allocation_after_effect;
        struct zcl_command_context context = {.registry = registry,
            .granted_capabilities = UINT64_MAX, .authority_ceiling = ZCL_COMMAND_AUTH_OWNER};
        char wire[8192]; enum zcl_command_exit exit_code;
        size_t length = zcl_command_registry_execute_json(registry, &spec, &context, &input,
            false, spec.path, "normal", mode == 2 ? 16 : 0, 0, NULL, wire,
            mode == 1 ? 16 : sizeof(wire), &exit_code);
        bool consumed = zcl_alloc_fault_armed_label() == NULL;
        zcl_alloc_fault_clear();
        ASSERT(consumed); ASSERT(exit_code != ZCL_COMMAND_EXIT_OK);
        if (mode) ASSERT_EQ(length, 0);
        else {
            ASSERT(length > 0); ASSERT(json_read(&reply, wire, length));
            ASSERT(!json_get_bool(json_get(&reply, "ok"))); ASSERT(reply_mutated(&reply, true));
            const struct json_value *error = json_get(&reply, "error");
            ASSERT(!json_get_bool(json_get(error, "retryable")));
            const char *next_action = json_get_str(json_get(error, "next_action"));
            ASSERT(next_action != NULL); ASSERT(!strstr(next_action, "retry"));
        }
        struct db_device_pairing row; uint8_t root[32];
        ASSERT(grant_inspect(&psk.host.profile, &row, root)); zcl_hex_encode(root, 32, psk.host.prior);
        ASSERT(psk_snapshot_matches(&psk, 0x5a));
    } TEST_END
    zcl_alloc_fault_clear(); json_free(&input); json_free(&reply); return failures;
}
static _Thread_local unsigned failure_envelope_mode;
static void failure_envelope_handler(const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    (void)request;
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
        "PUBLIC_FIXTURE_REFUSAL", "fixture", false, failure_envelope_mode != 0,
        "public fixture failure", "public fixture");
    (void)json_push_kv_str(&reply->data, "private_partial", "PRIVATE-PARTIAL-PATH-SENTINEL");
    if (!failure_envelope_mode) return;
    if (failure_envelope_mode == 2) {
        (void)json_push_kv_str(&reply->data, "failure_facts", "invalid-nonobject"); return;
    }
    struct json_value facts = {0}; json_set_object(&facts);
    (void)json_push_kv_str(&facts, "secret_publication", "durable");
    (void)json_push_kv_str(&facts, "grant_publication", "durability_unknown");
    (void)json_push_kv_bool(&facts, "mutation_attempted", true);
    (void)json_push_kv_bool(&facts, "intent_retired", false);
    if (failure_envelope_mode == 3) {
        char large[4097]; memset(large, 'x', sizeof(large) - 1); large[sizeof(large) - 1] = 0;
        (void)json_push_kv_str(&facts, "public_overflow_fixture", large);
    }
    (void)json_push_kv(&reply->data, "failure_facts", &facts); json_free(&facts);
}
static int psk_failure_envelope(void)
{
    int failures = 0;
    const struct zcl_command_registry *registry = zcl_command_catalog();
    const struct zcl_command_spec *registered = zcl_command_registry_find(registry, "ops.mesh.device.identity", NULL);
    if (!registered) return 1;
    struct zcl_command_spec spec = *registered; spec.handler = failure_envelope_handler;
    struct zcl_command_context context = {.registry = registry,
        .granted_capabilities = UINT64_MAX, .authority_ceiling = ZCL_COMMAND_AUTH_OWNER};
    struct json_value input = {0}, reply = {0};
    for (unsigned mode = 0; mode < 4; ++mode) {
        TEST_CASE("failure envelope: explicit typed facts only; mutation survives serialization refusal") {
            ASSERT(command_input(&input, "PUBLIC-NONEXISTENT-FIXTURE"));
            failure_envelope_mode = mode;
            char wire[8192]; enum zcl_command_exit exit_code;
            size_t length = zcl_command_registry_execute_json(registry, &spec, &context, &input,
                false, spec.path, "normal", 0, 0, NULL, wire, mode == 3 ? 1024 : sizeof(wire), &exit_code);
            ASSERT(length > 0); ASSERT(json_read(&reply, wire, length));
            ASSERT(exit_code != ZCL_COMMAND_EXIT_OK); ASSERT(!json_get_bool(json_get(&reply, "ok")));
            ASSERT(reply_mutated(&reply, mode != 0));
            ASSERT(!strstr(wire, "PRIVATE-PARTIAL-PATH-SENTINEL")); ASSERT(!json_get(&reply, "data"));
            if (mode == 1) {
                ASSERT(failure_fact_is(&reply, "secret_publication", "durable"));
                ASSERT(failure_fact_is(&reply, "grant_publication", "durability_unknown"));
                const struct json_value *error = json_get(&reply, "error"); size_t count = 0;
                for (size_t i = 0; i < error->num_children; ++i)
                    if (!strcmp(error->keys[i], "facts")) ++count;
                ASSERT_EQ(count, 1);
            } else ASSERT(!json_get(json_get(&reply, "error"), "facts"));
            if (mode >= 2) {
                const struct json_value *error = json_get(&reply, "error");
                ASSERT(!json_get_bool(json_get(error, "retryable")));
                const char *next_action = json_get_str(json_get(error, "next_action"));
                ASSERT(next_action != NULL); ASSERT(!strstr(next_action, "retry"));
            }
        } TEST_END
        json_free(&input); json_free(&reply);
    }
    failure_envelope_mode = 0; return failures;
}
struct psk_import_clock {
    const clock_iface_t *previous;
    uint64_t expiry;
    unsigned samples;
};
static int64_t psk_import_mono(void *context)
{
    struct psk_import_clock *clock = context;
    return clock->previous->now_monotonic_ns(clock->previous->self);
}
static int64_t psk_import_wall(void *context)
{
    struct psk_import_clock *clock = context;
    /* Proposal parsing and pre-source approval see the active old grant.
     * The required post-source admission sample crosses its expiry. */
    ++clock->samples;
    uint64_t seconds = clock->samples <= 2 ? clock->expiry - 1 : clock->expiry + 1;
    return (int64_t)(seconds * 1000);
}
static int psk_import_expiry(const struct command_fixture *base)
{
    int failures = 0;
    struct psk_command_fixture psk = {0};
    struct json_value input = {0};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.device.grant.v1");
    const clock_iface_t *previous = clock_default();
    struct psk_import_clock clock = {.previous = previous};
    clock_iface_t fake = {.self = &clock, .now_monotonic_ns = psk_import_mono, .now_wall_ms = psk_import_wall};
    TEST_CASE("backend2 CLI: source acquisition cannot extend an expired prior grant") {
        psk.host.profile = *base;
        ASSERT(snprintf(psk.host.profile.local, sizeof(psk.host.profile.local), "%s/psk-clock-local", base->home) > 0);
        char local[65], fingerprint[65];
        ASSERT(initialize_profile(&psk.host.profile, psk.host.profile.local, local, fingerprint));
        ASSERT(snprintf(psk.source, sizeof(psk.source), "%s/clock-private32", base->home) > 0);
        memset(psk.id, 'd', 64); psk.id[64] = 0; psk.epoch = 1;
        ASSERT(psk_command_plan(&psk, "absent"));
        ASSERT(psk_source_write(psk.source, 32, 0600, 0x5a));
        ASSERT(psk_command_input(&input, &psk, "absent", psk.host.proposal, true));
        ASSERT(command_call(&psk.host.profile, "commit", &input, true));
        struct db_device_pairing row; uint8_t before[32], after[32];
        ASSERT(grant_inspect(&psk.host.profile, &row, before));
        zcl_hex_encode(before, 32, psk.host.prior); clock.expiry = row.expires_at;
        psk.id[0] = 'e'; psk.epoch = 2; psk.host.profile.expires += 600;
        ASSERT(psk_command_plan(&psk, psk.host.prior));
        json_free(&input);
        ASSERT(psk_command_input(&input, &psk, psk.host.prior, psk.host.proposal, true));
        const struct zcl_command_spec *spec = zcl_command_registry_find(zcl_command_catalog(), "ops.mesh.device.commit", NULL);
        ASSERT(spec != NULL);
        struct zcl_command_request request = {.spec = spec, .input = &input};
        clock_set_default(&fake);
        zcl_native_handle_ops_mesh_device(&request, &reply);
        clock_set_default(previous);
        ASSERT(clock.samples >= 3); ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT(grant_inspect(&psk.host.profile, &row, after)); ASSERT(!memcmp(before, after, 32));
        ASSERT_EQ(row.host_scope.binding.psk.key_epoch, 1);
    } TEST_END
    clock_set_default(previous);
    zcl_command_reply_free(&reply); json_free(&input); return failures;
}
static int psk_interrupted_reply(const struct command_fixture *base)
{
    int failures = 0;
    const unsigned stages[] = {5, 7};
    for (size_t i = 0; i < 2; ++i) {
        struct psk_command_fixture psk = {0};
        struct json_value input = {0};
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.device.grant.v1");
        TEST_CASE("backend2 CLI: interrupted publication retains distinct honest durability facts") {
            psk.host.profile = *base;
            ASSERT(snprintf(psk.host.profile.local, sizeof(psk.host.profile.local), "%s/psk-interrupted-%u", base->home, stages[i]) > 0);
            char local[65], fingerprint[65];
            ASSERT(initialize_profile(&psk.host.profile, psk.host.profile.local, local, fingerprint));
            ASSERT(snprintf(psk.source, sizeof(psk.source), "%s/interrupt-private32", base->home) > 0);
            memset(psk.id, 'c', 64); psk.id[64] = 0; psk.epoch = 1;
            ASSERT(psk_command_plan(&psk, "absent"));
            ASSERT(psk_source_write(psk.source, 32, 0600, 0x5a));
            ASSERT(psk_command_input(&input, &psk, "absent", psk.host.proposal, true));
            const struct zcl_command_spec *spec = zcl_command_registry_find(
                zcl_command_catalog(), "ops.mesh.device.commit", NULL);
            ASSERT(spec != NULL);
            struct zcl_command_request request = {.spec = spec, .input = &input};
            device_pairing_test_interrupt(stages[i]);
            zcl_native_handle_ops_mesh_device(&request, &reply);
            device_pairing_test_interrupt(0);
            ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_FAILED); ASSERT(reply.error.mutated);
            const struct json_value *secret = json_get(&reply.data, "secret_publication");
            const struct json_value *grant = json_get(&reply.data, "grant_publication");
            ASSERT(secret != NULL); ASSERT(grant != NULL);
            ASSERT(!strcmp(json_get_str(secret), i == 0 ? "durability_unknown" : "durable"));
            ASSERT(!strcmp(json_get_str(grant), i == 0 ? "not_published" : "durability_unknown"));
            ASSERT(json_get_bool(json_get(&reply.data, "intent_retired")) == (i == 1));
            ASSERT(!json_get(&reply.data, "secret_file"));
        } TEST_END
        device_pairing_test_interrupt(0);
        zcl_command_reply_free(&reply); json_free(&input);
    }
    return failures;
}
static int command_psk_flows(const struct command_fixture *base)
{
    int failures = 0;
    struct psk_command_fixture psk = {0};
    TEST_CASE("backend2 CLI: read-only proposal does not create authority") {
        psk.host.profile = *base;
        ASSERT(snprintf(psk.host.profile.local, sizeof(psk.host.profile.local), "%s/psk-local", base->home) > 0);
        char local[65], fingerprint[65];
        ASSERT(initialize_profile(&psk.host.profile, psk.host.profile.local, local, fingerprint));
        ASSERT(snprintf(psk.source, sizeof(psk.source), "%s/import-private32", base->home) > 0);
        memset(psk.id, 'a', 64); psk.id[64] = 0; psk.epoch = 1;
        ASSERT(psk_command_plan(&psk, "absent"));
        struct db_device_pairing row; uint8_t root[32];
        ASSERT(!grant_inspect(&psk.host.profile, &row, root));
        failures += psk_approval_refusals(&psk);
        failures += psk_plan_source_refusal(&psk);
        failures += psk_mixed_refusals(&psk);
        failures += psk_source_refusals(&psk);
        failures += psk_source_shapes(&psk);
        failures += psk_commit_flow(&psk);
        failures += psk_rotate_flow(&psk);
        failures += psk_revoke_flow(&psk);
    } TEST_END
    return failures;
}
static bool prepare_command_input(struct json_value *input, const struct psk_command_fixture *psk)
{
    return command_input(input, psk->host.profile.local) &&
        json_push_kv_str(input, "peer_key", psk->host.profile.peer_key) &&
        json_push_kv_str(input, "capability", "host-forward") && json_push_kv_int(input, "backend", 2) &&
        json_push_kv_str(input, "destination", psk->source) && json_push_kv_bool(input, "confirm", true);
}
static bool prepared_read(const char *path, uint8_t bytes[32])
{
    struct platform_positioned_file file; platform_positioned_file_init(&file);
    struct platform_positioned_file_snapshot before, after;
    bool ok = platform_positioned_file_open(&file, path) && platform_positioned_file_is_private(&file) &&
        platform_positioned_file_is_current_user_only(&file) && platform_positioned_file_snapshot(&file, &before) &&
        before.size == 32 && platform_positioned_file_read(&file, bytes, 32, 0) == 32 &&
        platform_positioned_file_snapshot(&file, &after) && platform_positioned_file_snapshot_equal(&before, &after);
    platform_positioned_file_close(&file); return ok;
}
static bool prepared_reply_safe(const struct psk_command_fixture *psk, const struct json_value *reply)
{
    uint8_t bytes[32] = {0}; char secret_text[65] = {0}, wire[8192] = {0};
    bool ok = prepared_read(psk->source, bytes);
    if (ok) {
        zcl_hex_encode(bytes, 32, secret_text);
        ok = json_write(reply, wire, sizeof(wire)) > 0;
    }
    if (ok) ok = !strstr(wire, secret_text) && strcmp(psk->id, secret_text);
    memory_cleanse(bytes, sizeof(bytes)); memory_cleanse(secret_text, sizeof(secret_text));
    memory_cleanse(wire, sizeof(wire)); return ok;
}
static bool prepared_import_matches(const struct psk_command_fixture *psk)
{
    uint8_t bytes[32] = {0}, peer[32], root[32];
    struct device_identity identity = {0}; struct device_identity_publication_report report;
    struct device_pairing_store store; struct device_pairing_guard guard = {0};
    struct device_pairing_psk_snapshot snapshot = {0};
    bool ok = prepared_read(psk->source, bytes) &&
        device_identity_open(&identity, psk->host.profile.local, false, &report).ok &&
        zcl_hex_decode(psk->host.profile.peer_key, peer, 32) && zcl_hex_decode(psk->host.prior, root, 32) &&
        device_identity_pair_store(&identity, peer, &store).ok &&
        device_pairing_psk_snapshot_acquire(&store, peer, root, (uint64_t)(clock_now_wall_ms() / 1000),
            DEVICE_PAIRING_HOST_OUTBOUND, 2223, &guard, &snapshot);
    if (ok) ok = !memcmp(bytes, snapshot.secret, 32);
    device_pairing_guard_release(&guard); device_pairing_psk_snapshot_destroy(&snapshot);
    device_identity_close(&identity); memory_cleanse(bytes, sizeof(bytes)); return ok;
}
static bool prepare_fixture(const struct command_fixture *base, struct psk_command_fixture *psk, unsigned index)
{
    memset(psk, 0, sizeof(*psk)); psk->host.profile = *base; psk->epoch = 1;
    int n = snprintf(psk->host.profile.local, sizeof(psk->host.profile.local), "%s/prepare-profile-%u", base->home, index);
    if (n <= 0 || (size_t)n >= sizeof(psk->host.profile.local)) return false;
    char local[65], fingerprint[65];
    if (!initialize_profile(&psk->host.profile, psk->host.profile.local, local, fingerprint)) return false;
    n = snprintf(psk->source, sizeof(psk->source), "%s/prepare-source-%u", base->home, index);
    return n > 0 && (size_t)n < sizeof(psk->source);
}
static int prepare_binary_success(const struct command_fixture *base)
{
    int failures = 0; struct psk_command_fixture psk = {0};
    struct json_value input = {0}, reply = {0};
    TEST_CASE("prepare-secret CLI: private inert exact32 source imports only after independent approval") {
        ASSERT(prepare_fixture(base, &psk, 0)); ASSERT(prepare_command_input(&input, &psk));
        ASSERT(command_capture(&psk.host.profile, "prepare-secret", &input, &reply, true));
        ASSERT(reply_is(&reply, "source_publication", "durable")); ASSERT(reply_bool(&reply, "mutation_attempted", true));
        ASSERT(reply_string(&reply, "credential_id", psk.id));
        ASSERT(prepared_reply_safe(&psk, &reply));
        ASSERT(strcmp(psk.id, "0000000000000000000000000000000000000000000000000000000000000000"));
        char wire[8192]; ASSERT(json_write(&reply, wire, sizeof(wire)) > 0);
        ASSERT(!strstr(wire, psk.source)); ASSERT(!json_get(json_get(&reply, "data"), "secret"));
        struct db_device_pairing row; uint8_t root[32];
        ASSERT(!grant_inspect(&psk.host.profile, &row, root));
        struct stat before, after; ASSERT(stat(psk.source, &before) == 0);
        ASSERT_EQ(before.st_size, 32); ASSERT_EQ(before.st_mode & 0777, 0600); ASSERT_EQ(before.st_uid, geteuid());
        ASSERT(command_call(&psk.host.profile, "prepare-secret", &input, false));
        ASSERT(stat(psk.source, &after) == 0); ASSERT_EQ(before.st_ino, after.st_ino); ASSERT_EQ(before.st_size, after.st_size);
        ASSERT(psk_command_plan(&psk, "absent")); json_free(&input); json_free(&reply);
        ASSERT(psk_command_input(&input, &psk, "absent", psk.host.proposal, true));
        ASSERT(command_call(&psk.host.profile, "commit", &input, true));
        ASSERT(grant_inspect(&psk.host.profile, &row, root)); zcl_hex_encode(root, 32, psk.host.prior);
        ASSERT(prepared_import_matches(&psk));
    } TEST_END
    json_free(&input); json_free(&reply); return failures;
}
static int prepare_input_refusals(const struct command_fixture *base)
{
    int failures = 0; struct psk_command_fixture psk = {0}; struct json_value input = {0};
    const char *fields[] = {"secret", "seed", "credential_id", "key_epoch"};
    if (!prepare_fixture(base, &psk, 1)) return 1;
    for (size_t i = 0; i < 4; ++i) {
        TEST_CASE("prepare-secret CLI: raw bytes/seeds/caller identifiers are not accepted") {
            ASSERT(prepare_command_input(&input, &psk));
            ASSERT(json_push_kv_str(&input, fields[i], "PUBLIC-INVALID-FIXTURE"));
            ASSERT(command_call(&psk.host.profile, "prepare-secret", &input, false));
            struct stat st; ASSERT(lstat(psk.source, &st) != 0); ASSERT_EQ(errno, ENOENT);
        } TEST_END
        json_free(&input);
    }
    return failures;
}
static int prepare_confirmation_refusals(const struct command_fixture *base)
{
    int failures = 0; struct psk_command_fixture psk = {0}; struct json_value input = {0}, reply = {0};
    if (!prepare_fixture(base, &psk, 2)) return 1;
    for (unsigned i = 0; i < 5; ++i) {
        TEST_CASE("prepare-secret CLI: explicit owner confirmation and fixed backend2 HOST purpose required") {
            ASSERT(prepare_command_input(&input, &psk));
            if (i == 0) json_set_bool(host_member(&input, "confirm"), false);
            if (i == 1) json_set_int(host_member(&input, "backend"), 1);
            if (i == 2) json_set_str(host_member(&input, "capability"), "guest-stream");
            if (i == 3) json_set_str(host_member(&input, "peer_key"),
                "0000000000000000000000000000000000000000000000000000000000000000");
            if (i == 4) {
                struct device_identity identity = {0}; struct device_identity_publication_report report;
                bool opened = device_identity_open(&identity, psk.host.profile.local, false, &report).ok;
                char local[65]; if (opened) zcl_hex_encode(identity.public_key, 32, local);
                device_identity_close(&identity); ASSERT(opened);
                json_set_str(host_member(&input, "peer_key"), local);
            }
            ASSERT(command_capture(&psk.host.profile, "prepare-secret", &input, &reply, false));
            ASSERT(reply_mutated(&reply, false)); ASSERT(failure_fact_is(&reply, "source_publication", "not_published"));
            struct stat st; ASSERT(lstat(psk.source, &st) != 0); ASSERT_EQ(errno, ENOENT);
        } TEST_END
        json_free(&input); json_free(&reply);
    }
    return failures;
}
static int prepare_path_refusals(const struct command_fixture *base)
{
    int failures = 0; struct psk_command_fixture psk = {0}; struct json_value input = {0}, reply = {0};
    if (!prepare_fixture(base, &psk, 3)) return 1;
    for (unsigned i = 0; i < 3; ++i) {
        TEST_CASE("prepare-secret CLI: existing regular/link/directory destination never overwritten") {
            if (i == 0) ASSERT(psk_source_write(psk.source, 32, 0600, 0x5a));
            if (i == 1) ASSERT(symlink("PUBLIC-MISSING-FIXTURE", psk.source) == 0);
            if (i == 2) ASSERT(mkdir(psk.source, 0700) == 0);
            struct stat before, after; ASSERT(lstat(psk.source, &before) == 0);
            ASSERT(prepare_command_input(&input, &psk));
            ASSERT(command_capture(&psk.host.profile, "prepare-secret", &input, &reply, false));
            ASSERT(reply_mutated(&reply, false)); ASSERT(failure_fact_is(&reply, "source_publication", "not_published"));
            ASSERT(lstat(psk.source, &after) == 0); ASSERT_EQ(before.st_ino, after.st_ino); ASSERT_EQ(before.st_mode, after.st_mode);
        } TEST_END
        json_free(&input); json_free(&reply);
        if (i == 2) (void)rmdir(psk.source); else (void)unlink(psk.source);
    }
    return failures;
}
static int prepare_parent_refusal(const struct command_fixture *base)
{
    int failures = 0; struct psk_command_fixture psk = {0};
    struct json_value input = {0}, reply = {0};
    TEST_CASE("prepare-secret CLI: permissive source parent refused before creation") {
        ASSERT(prepare_fixture(base, &psk, 4));
        char parent[1200]; ASSERT(snprintf(parent, sizeof(parent), "%s/prepare-permissive", base->home) > 0);
        ASSERT(mkdir(parent, 0755) == 0); ASSERT(chmod(parent, 0755) == 0);
        ASSERT(snprintf(psk.source, sizeof(psk.source), "%s/source", parent) > 0);
        ASSERT(prepare_command_input(&input, &psk));
        ASSERT(command_capture(&psk.host.profile, "prepare-secret", &input, &reply, false));
        ASSERT(reply_mutated(&reply, false)); ASSERT(failure_fact_is(&reply, "source_publication", "not_published"));
        struct stat st; ASSERT(lstat(psk.source, &st) != 0); ASSERT_EQ(errno, ENOENT);
    } TEST_END
    json_free(&input); json_free(&reply); return failures;
}
static int prepare_fault_cases(const struct command_fixture *base)
{
    int failures = 0;
    for (unsigned stage = 1; stage <= 8; ++stage) {
        struct psk_command_fixture psk = {0}; struct json_value input = {0};
        struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.device.secret-source.v1");
        TEST_CASE("prepare-secret handler: entropy/publication/reply faults preserve truthful effect and unique artifacts") {
            ASSERT(prepare_fixture(base, &psk, 10 + stage)); ASSERT(prepare_command_input(&input, &psk));
            const struct zcl_command_spec *spec = zcl_command_registry_find(zcl_command_catalog(), "ops.mesh.device.prepare-secret", NULL);
            ASSERT(spec != NULL); struct zcl_command_request request = {.spec = spec, .input = &input};
            zcl_native_device_prepare_test_interrupt(stage); zcl_native_handle_ops_mesh_device(&request, &reply);
            zcl_native_device_prepare_test_interrupt(0);
            bool consumed = zcl_alloc_fault_armed_label() == NULL; zcl_alloc_fault_clear();
            ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_FAILED); ASSERT_EQ(reply.error.mutated, stage >= 4);
            const struct json_value *facts = json_get(&reply.data, "failure_facts"); ASSERT(facts != NULL);
            const char *state = json_get_str(json_get(facts, "source_publication")); ASSERT(state != NULL);
            ASSERT(!strcmp(state, stage < 4 ? "not_published" : stage == 8 ? "durable" : "durability_unknown"));
            struct stat st; int observed = lstat(psk.source, &st);
            if (stage <= 4) { ASSERT(observed != 0); ASSERT_EQ(errno, ENOENT); }
            else { ASSERT_EQ(observed, 0); ASSERT_EQ(st.st_size, stage == 5 ? 0 : 32); }
            if (stage == 8) ASSERT(consumed);
            if (stage >= 4) ASSERT(json_get(facts, "credential_id") != NULL);
        } TEST_END
        zcl_native_device_prepare_test_interrupt(0); zcl_alloc_fault_clear();
        zcl_command_reply_free(&reply); json_free(&input);
    }
    return failures;
}
static int prepare_restrictive_umask(const struct command_fixture *base)
{
    int failures = 0; struct psk_command_fixture psk = {0}; struct json_value input = {0};
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.device.secret-source.v1");
    mode_t prior = umask(0077); umask(prior);
    TEST_CASE("prepare-secret handler: restrictive umask cannot claim unusable source durable") {
        ASSERT(prepare_fixture(base, &psk, 30)); ASSERT(prepare_command_input(&input, &psk));
        const struct zcl_command_spec *spec = zcl_command_registry_find(zcl_command_catalog(), "ops.mesh.device.prepare-secret", NULL);
        ASSERT(spec != NULL); struct zcl_command_request request = {.spec = spec, .input = &input};
        umask(0777); zcl_native_handle_ops_mesh_device(&request, &reply); umask(prior);
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_FAILED); ASSERT(reply.error.mutated);
        const struct json_value *facts = json_get(&reply.data, "failure_facts"); ASSERT(facts != NULL);
        const char *state = json_get_str(json_get(facts, "source_publication")); ASSERT(state != NULL);
        ASSERT(!strcmp(state, "durability_unknown"));
        struct stat st; ASSERT(stat(psk.source, &st) == 0); ASSERT_EQ(st.st_mode & 0777, 0);
    } TEST_END
    umask(prior); zcl_command_reply_free(&reply); json_free(&input); return failures;
}
static int command_prepare_flows(const struct command_fixture *base)
{
    return prepare_binary_success(base) + prepare_input_refusals(base) + prepare_confirmation_refusals(base) +
        prepare_path_refusals(base) + prepare_parent_refusal(base) + prepare_fault_cases(base) + prepare_restrictive_umask(base);
}
static int command_serialization_fault(struct command_fixture *fixture)
{
    int failures = 0;
    struct command_fixture fault = *fixture;
    struct json_value input = {0};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.device.grant.v1");
    const clock_iface_t *previous = clock_default();
    struct serialization_clock clock = {.previous = previous, .reply = &reply};
    clock_iface_t fake = {.now_monotonic_ns = serialization_mono,
        .now_wall_ms = serialization_wall, .self = &clock};
    TEST_CASE("device CLI handler: constrained post-save JSON growth failure reports the persisted revocation") {
        char peer_directory[1200];
        ASSERT(snprintf(peer_directory, sizeof(peer_directory), "%s/fault-peer", fixture->home) > 0);
        ASSERT(initialize_profile(&fault, peer_directory, fault.peer_key, fault.fingerprint));
        ASSERT(grant_input(&input, &fault));
        ASSERT(json_push_kv_str(&input, "fingerprint", fault.fingerprint));
        ASSERT(json_push_kv_str(&input, "expected_root", "absent"));
        ASSERT(command_call(&fault, "commit", &input, true));
        struct db_device_pairing row;
        uint8_t root[32];
        ASSERT(grant_inspect(&fault, &row, root));
        ASSERT_EQ(row.revoked_at, 0);
        ASSERT_EQ(row.capabilities, DEVICE_PAIRING_CAP_STATUS_READ);
        char expected[65];
        zcl_hex_encode(root, 32, expected);
        json_free(&input);
        ASSERT(revoke_input(&input, &fault, expected, fault.fingerprint));
        zcl_command_reply_free(&reply);
        zcl_command_reply_init(&reply, "zcl.device.grant.v1");
        const struct zcl_command_spec *spec = zcl_command_registry_find(
            zcl_command_catalog(), "ops.mesh.device.revoke", NULL);
        ASSERT(spec != NULL);
        struct zcl_command_request request = {.spec = spec, .input = &input};
        clock_set_default(&fake);
        zcl_native_handle_ops_mesh_device(&request, &reply);
        bool consumed = zcl_alloc_fault_armed_label() == NULL;
        clock_set_default(previous);
        zcl_alloc_fault_clear();
        ASSERT(clock.constrained);
        ASSERT(consumed);
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_FAILED);
        ASSERT(reply.error.mutated);
        ASSERT(json_get(&reply.data, "publication") == NULL);
        ASSERT(grant_inspect(&fault, &row, root));
        ASSERT(row.revoked_at > 0);
        ASSERT_EQ(row.generation, 1);
    } TEST_END
    clock_set_default(previous);
    zcl_alloc_fault_clear();
    zcl_command_reply_free(&reply);
    json_free(&input);
    return failures;
}
#endif
int test_device_command(void);
int test_device_command(void)
{
#if defined(_WIN32)
    fprintf(stderr, "device_command: real-binary Windows capture unqualified; refused\n");
    return 1;
#else
    int failures = 0;
    struct command_fixture fixture = {0};
    TEST_CASE("device CLI: public binary exists and timestamp staleness checks permit isolated fixtures") {
        ASSERT(fixture_fresh());
        ASSERT(test_mkdtemp(fixture.home, sizeof(fixture.home), "device-cli"));
        ASSERT(snprintf(fixture.local, sizeof(fixture.local), "%s/local", fixture.home) > 0);
        ASSERT(snprintf(fixture.peer, sizeof(fixture.peer), "%s/peer", fixture.home) > 0);
        fixture.expires = clock_now_wall_ms() / 1000 + 600;
        failures += command_identity_flows(&fixture);
        failures += command_grant_flows(&fixture);
        failures += command_revoke_flows(&fixture);
        failures += command_serialization_fault(&fixture);
        failures += command_host_flows(&fixture);
        failures += host_legacy_upgrade(&fixture);
        failures += command_psk_flows(&fixture);
        failures += psk_interrupted_reply(&fixture);
        failures += psk_import_expiry(&fixture);
        failures += psk_failure_envelope();
        failures += psk_execute_allocation_failure(&fixture, 0);
        failures += psk_execute_allocation_failure(&fixture, 1);
        failures += psk_execute_allocation_failure(&fixture, 2);
        failures += command_prepare_flows(&fixture);
    } TEST_END
    if (fixture.home[0]) test_rm_rf(fixture.home);
    return failures;
#endif
}
