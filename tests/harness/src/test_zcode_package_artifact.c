/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "test/test_core.h"
#include "command/native_command.h"
#include "command/native_package_artifact.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "dev/devloop.h"
#include "platform/private_file.h"
#include "platform/directory_compat.h"
#include "json/json.h"
#include "vcs/package_prepare.h"
#include "vcs/package_accept.h"
#include "config/command_catalog.h"
#include "config/boot_zcode_dht.h"
#include "controllers/rpc_client.h"
#include "rpc/server.h"
#include <secp256k1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <unistd.h>
#include <sys/stat.h>

static const char artifact_public_key[] = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
struct artifact_fixture { char home[1024], source[1200], output[1200], store[1200], apps[1200]; char chain[VCS_PACKAGE_RELEASE_CHAIN_ID_MAX + 1]; };
static bool artifact_path(char *out, size_t capacity, const char *root, const char *leaf)
{
    int length = snprintf(out, capacity, "%s/%s", root, leaf);
    return length > 0 && (size_t)length < capacity;
}
static bool artifact_write(const char *path, const char *text)
{
    struct platform_private_file file; platform_private_file_init(&file);
    bool ok = platform_private_file_create_locked(path, &file) &&
        platform_private_file_write_at(&file, text, strlen(text), 0) && platform_private_file_flush(&file);
    platform_private_file_close(&file); return ok;
}
static bool artifact_fixture_file(const struct artifact_fixture *fixture, const char *leaf, const char *text)
{
    char path[1600]; return artifact_path(path, sizeof(path), fixture->source, leaf) && artifact_write(path, text);
}
static bool artifact_fixture_directories(const struct artifact_fixture *fixture)
{
    const char *roots[] = {fixture->source, fixture->apps, fixture->store}; char path[1600];
    for (size_t i = 0; i < 3; ++i) if (platform_directory_create(roots[i], 0700) != 0) return false;
    static const char *const dirs[] = {"src", "include", "docs"};
    for (size_t i = 0; i < 3; ++i)
        if (!artifact_path(path, sizeof(path), fixture->source, dirs[i]) || platform_directory_create(path, 0700) != 0) return false;
    return true;
}
static bool artifact_fixture_open(struct artifact_fixture *fixture)
{
    memset(fixture, 0, sizeof(*fixture));
    if (!vcs_package_accept_chain_id(fixture->chain, sizeof(fixture->chain))) return false;
    if (!test_mkdtemp(fixture->home, sizeof(fixture->home), "package-artifact")) return false;
    if (!artifact_path(fixture->source, sizeof(fixture->source), fixture->home, "source") ||
        !artifact_path(fixture->output, sizeof(fixture->output), fixture->home, "artifacts") ||
        !artifact_path(fixture->store, sizeof(fixture->store), fixture->home, "store") ||
        !artifact_path(fixture->apps, sizeof(fixture->apps), fixture->home, "apps")) return false;
    if (!artifact_fixture_directories(fixture)) return false;
    return artifact_fixture_file(fixture, "LICENSE", "MIT\n") &&
        artifact_fixture_file(fixture, "src/x.c", "int artifact_fixture_value(void) { return 1; }\n") &&
        artifact_fixture_file(fixture, "include/x.h", "int artifact_fixture_value(void);\n") &&
        artifact_fixture_file(fixture, "zcode-package.json",
            "{\"schema\":1,\"name\":\"zclassic23/artifact-fixture\",\"semver\":\"0.1.0\",\"language\":\"c23\",\"license\":\"MIT\",\"source_dir\":\"src\",\"include_dir\":\"include\",\"dependencies\":[]}\n");
}
static bool artifact_fixture_large(const struct artifact_fixture *fixture)
{
    for (unsigned i = 0; i < 107; ++i) {
        char leaf[160]; int length = snprintf(leaf, sizeof(leaf), "docs/public-immutable-package-wire-fixture-document-number-%03u.txt", i);
        if (length <= 0 || (size_t)length >= sizeof(leaf) || !artifact_fixture_file(fixture, leaf, "PUBLIC fixed fixture documentation\n")) return false;
    }
    return true;
}
static bool artifact_prepare_input(struct json_value *input, const struct artifact_fixture *fixture, bool exporting)
{
    json_set_object(input);
    bool ok = json_push_kv_str(input, "dir", fixture->source) &&
        json_push_kv_str(input, "publisher_pubkey", artifact_public_key) && json_push_kv_int(input, "publisher_sequence", 1) &&
        json_push_kv_str(input, "chain_id", fixture->chain);
    if (exporting) ok = ok && json_push_kv_str(input, "artifact_dir", fixture->output) && json_push_kv_bool(input, "confirm", true);
    return ok;
}
static bool artifact_process(const char *const argv[], const char *const env[], struct zcl_devloop_process_result *capture)
{
    const char *prior = getenv("ZCL_DEVLOOP_TEST_PROCESS"); char *saved = prior ? strdup(prior) : NULL;
    if (prior && !saved) return false;
    if (setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1) != 0) { free(saved); return false; }
    bool ran = zcl_devloop_process_run_env(".", argv, env, 30000, capture);
    bool restored = (saved ? setenv("ZCL_DEVLOOP_TEST_PROCESS", saved, 1) : unsetenv("ZCL_DEVLOOP_TEST_PROCESS")) == 0;
    free(saved); return ran && restored;
}
static bool artifact_native_arguments(const struct artifact_fixture *fixture, const char *const parts[],
    const struct json_value *input, const char *argv[12], char argument[8220], char home[1200])
{
    char wire[8192]; size_t size = json_write(input, wire, sizeof(wire));
    if (!size || size >= sizeof(wire)) return false;
    int length = snprintf(argument, 8220, "--input=%s", wire);
    if (length <= 0 || length >= 8220) return false;
    length = snprintf(home, 1200, "HOME=%s", fixture->home);
    if (length <= 0 || length >= 1200) return false;
    argv[0] = "build/bin/z23"; argv[1] = "zcode"; argv[2] = "package"; size_t count = 3;
    for (size_t i = 0; parts[i]; ++i) { if (count >= 10) return false; argv[count++] = parts[i]; }
    argv[count++] = argument; argv[count] = NULL; return true;
}
static bool artifact_native_result(const struct zcl_devloop_process_result *capture, struct json_value *reply, bool success)
{
    if (capture->timed_out || capture->cancelled || capture->term_signal || capture->output_truncated || capture->exit_code < 0) return false;
    const char *text = strchr(capture->output, '{');
    if (!text || !json_read(reply, text, strlen(text))) { fprintf(stderr, "artifact CLI malformed: %s\n", capture->output); return false; }
    const struct json_value *ok = json_get(reply, "ok");
    if (!ok || ok->type != JSON_BOOL) return false;
    bool observed = json_get_bool(ok);
    if (observed != success || (capture->exit_code == 0) != success) fprintf(stderr, "artifact CLI unexpected: %s\n", capture->output);
    return observed == success && (capture->exit_code == 0) == success;
}
static bool artifact_native(const struct artifact_fixture *fixture, const char *const parts[],
    const struct json_value *input, struct json_value *reply, bool success)
{
    char argument[8220], home[1200]; const char *argv[12]; struct zcl_devloop_process_result capture;
    if (!artifact_native_arguments(fixture, parts, input, argv, argument, home)) return false;
    const char *env[] = {home, "PATH=/usr/bin:/bin", NULL};
    return artifact_process(argv, env, &capture) && artifact_native_result(&capture, reply, success);
}
static bool artifact_file_input(struct json_value *input, const struct artifact_fixture *fixture,
    const struct json_value *exported, const char *name, const char *filename)
{
    char path[1600], file_key[64], digest_key[64];
    if (!artifact_path(path, sizeof(path), fixture->output, filename)) return false;
    int a = snprintf(file_key, sizeof(file_key), "%s_file", name), b = snprintf(digest_key, sizeof(digest_key), "%s_sha3", name);
    if (a <= 0 || b <= 0 || (size_t)a >= sizeof(file_key) || (size_t)b >= sizeof(digest_key)) return false;
    const char *digest = json_get_str(json_get(exported, digest_key));
    return digest && json_push_kv_str(input, file_key, path) && json_push_kv_str(input, digest_key, digest);
}
static bool artifact_verify_exports(const struct artifact_fixture *fixture, const struct json_value *data)
{
    static const char *const names[] = {"manifest", "recipe", "dependency_lock", "api_capsule", "release_body"};
    static const char *const files[] = {"manifest.wire", "recipe.wire", "dependency-lock.wire", "api-capsule.wire", "release-body.wire"};
    for (size_t i = 0; i < 5; ++i) {
        struct json_value input = {0}; json_set_object(&input); uint8_t *bytes = NULL; size_t size = 0; char size_key[64];
        int count = snprintf(size_key, sizeof(size_key), "%s_bytes", names[i]);
        bool ok = count > 0 && (size_t)count < sizeof(size_key) && artifact_file_input(&input, fixture, data, names[i], files[i]);
        if (ok) ok = zcl_native_package_artifact_read(&input, "unused_hex", input.keys[0], input.keys[1], 1048576, &bytes, &size);
        if (ok) ok = (int64_t)size == json_get_int(json_get(data, size_key));
        free(bytes); json_free(&input); if (!ok) return false;
    }
    return true;
}
static bool artifact_reference_file(const char *directory, const char *name, const uint8_t *expected, size_t length)
{
    char path[1600]; if (!artifact_path(path, sizeof(path), directory, name)) return false;
    struct platform_private_file file; platform_private_file_init(&file); uint64_t size = 0;
    uint8_t *copy = zcl_malloc(length, "artifact.fixture.reference");
    bool ok = copy && platform_private_file_open_observation(path, &file) && platform_private_file_size(&file, &size) && size == length;
    if (ok) ok = platform_private_file_read_at(&file, copy, length, 0) && memcmp(copy, expected, length) == 0;
    platform_private_file_close(&file); free(copy); return ok;
}
static bool artifact_hex_is(const struct json_value *data, const char *key, const uint8_t expected[32])
{
    uint8_t actual[32]; const char *text = json_get_str(json_get(data, key));
    return text && zcl_hex_decode_lower(text, actual, 32) && memcmp(actual, expected, 32) == 0;
}
static bool artifact_roots_match(const struct json_value *data, const struct vcs_package_prepared *expected)
{
    return artifact_hex_is(data, "package_root", expected->package_root) &&
        artifact_hex_is(data, "recipe_root", expected->recipe_root) &&
        artifact_hex_is(data, "dependency_lock_root", expected->lock_root) &&
        artifact_hex_is(data, "api_capsule_root", expected->capsule_root) &&
        artifact_hex_is(data, "release_signing_digest", expected->signing_digest);
}
static bool artifact_compare_derivation(const struct artifact_fixture *fixture, const struct json_value *data)
{
    struct vcs_package_prepare_options options = {.dir = fixture->source, .publisher_sequence = 1, .chain_id = fixture->chain};
    if (!zcl_hex_decode_lower(artifact_public_key, options.publisher_pubkey, 33)) return false;
    struct vcs_package_prepared expected; char detail[256];
    if (vcs_package_prepare(&options, &expected, detail, sizeof(detail)) != VCS_PACKAGE_PREPARE_OK) return false;
    bool ok = !data || artifact_roots_match(data, &expected);
    if (ok) ok = artifact_reference_file(fixture->output, "manifest.wire", expected.manifest_wire, expected.manifest_wire_len) &&
        artifact_reference_file(fixture->output, "recipe.wire", expected.recipe_wire, expected.recipe_wire_len) &&
        artifact_reference_file(fixture->output, "dependency-lock.wire", expected.lock_wire, expected.lock_wire_len) &&
        artifact_reference_file(fixture->output, "api-capsule.wire", expected.capsule_wire, expected.capsule_wire_len) &&
        artifact_reference_file(fixture->output, "release-body.wire", expected.release_body, expected.release_body_len);
    vcs_package_prepared_free(&expected); return ok;
}
static bool artifact_sign(const uint8_t digest[32], uint8_t signature[64])
{
    uint8_t secret[32] = {0}; secret[31] = 1; /* PUBLIC fixed fixture key, never operator identity. */
    secp256k1_context *context = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!context) return false;
    secp256k1_ecdsa_signature raw, normalized;
    bool ok = secp256k1_ecdsa_sign(context, &raw, digest, secret, NULL, NULL) == 1;
    if (ok) { (void)secp256k1_ecdsa_signature_normalize(context, &normalized, &raw);
        ok = secp256k1_ecdsa_signature_serialize_compact(context, signature, &normalized) == 1; }
    secp256k1_context_destroy(context); return ok;
}
static bool artifact_seal_input(struct json_value *input, const struct artifact_fixture *fixture, const struct json_value *data)
{
    uint8_t digest[32], signature[64]; char signature_hex[129];
    const char *hash = json_get_str(json_get(data, "release_signing_digest"));
    if (!hash || !zcl_hex_decode_lower(hash, digest, 32) || !artifact_sign(digest, signature)) return false;
    zcl_hex_encode(signature, 64, signature_hex); json_set_object(input);
    return artifact_file_input(input, fixture, data, "release_body", "release-body.wire") && json_push_kv_str(input, "signature_hex", signature_hex);
}
static bool artifact_publish_input(struct json_value *input, const struct artifact_fixture *fixture,
    const struct json_value *exported, const struct json_value *sealed, bool explicit_store)
{
    json_set_object(input); const char *release = json_get_str(json_get(sealed, "release_hex"));
    return release && json_push_kv_str(input, "release_hex", release) && json_push_kv_str(input, "dir", fixture->source) &&
        (!explicit_store || json_push_kv_str(input, "datadir", fixture->store)) && artifact_file_input(input, fixture, exported, "manifest", "manifest.wire") &&
        artifact_file_input(input, fixture, exported, "recipe", "recipe.wire");
}
static bool artifact_local_plan(const struct artifact_fixture *fixture, const struct json_value *exported,
    const struct json_value *sealed)
{
    struct json_value input = {0}, reply = {0}; static const char *const action[] = {"add", "plan", NULL};
    const char *root = json_get_str(json_get(exported, "package_root"));
    bool ok = artifact_publish_input(&input, fixture, exported, sealed, true) && root;
    if (ok) { json_set_str((struct json_value *)json_get(&input, "datadir"), fixture->apps);
        ok = json_push_kv_str(&input, "name_or_root", root) && json_push_kv_bool(&input, "local_only", true); }
    if (ok) ok = artifact_native(fixture, action, &input, &reply, true);
    const struct json_value *data = json_get(&reply, "data");
    const char *target = json_get_str(json_get(data, "target_root"));
    const struct json_value *publication = json_get(data, "publication");
    if (ok) ok = json_get_bool(json_get(data, "ready")) && target && strcmp(target, root) == 0 &&
        publication && publication->type == JSON_BOOL && !json_get_bool(publication);
    json_free(&input); json_free(&reply); return ok;
}
static const struct artifact_fixture *artifact_rpc_fixture;
static bool artifact_rpc_observed;
static char *artifact_rpc_stub(const char *method, const char *wire)
{
    struct json_value params = {0};
    bool ok = artifact_rpc_fixture && strcmp(method, "zcode_package_publish_commit") == 0 && json_read(&params, wire, strlen(wire));
    const struct json_value *input = json_at(&params, 0);
    if (ok) ok = json_size(&params) == 1 && zcl_native_package_artifact_paths_absolute(input);
    static const char *const names[] = {"manifest_file", "recipe_file"}, *const files[] = {"manifest.wire", "recipe.wire"};
    for (size_t i = 0; i < 2 && ok; ++i) {
        char expected[1600]; const char *path = json_get_str(json_get(input, names[i]));
        ok = artifact_path(expected, sizeof(expected), artifact_rpc_fixture->output, files[i]) && path && strcmp(path, expected) == 0;
    }
    const char *source = json_get_str(json_get(input, "dir"));
    if (ok) ok = source && strcmp(source, artifact_rpc_fixture->source) == 0;
    artifact_rpc_observed = ok; json_free(&params);
    return ok ? strdup("{\"ok\":true,\"mutated\":true,\"data\":{\"result\":\"resident-fixture-only\"}}") : NULL;
}
static bool artifact_relative(char *out, size_t capacity, const char *absolute)
{
    char cwd[4096]; if (!getcwd(cwd, sizeof(cwd)) || absolute[0] != '/') return false;
    size_t used = 0;
    for (size_t i = 0; cwd[i]; ++i) {
        if (cwd[i] != '/' || !cwd[i + 1]) continue;
        if (used + 3 >= capacity) return false;
        memcpy(out + used, "../", 3); used += 3;
    }
    int length = snprintf(out + used, capacity - used, "%s", absolute + 1);
    return length > 0 && (size_t)length < capacity - used;
}
static bool artifact_resident_forward(const struct artifact_fixture *fixture, struct json_value *input)
{
    char cookie[1600]; if (!artifact_path(cookie, sizeof(cookie), fixture->store, ".cookie") || !artifact_write(cookie, "PUBLIC fixture cookie\n")) return false;
    static const char *const names[] = {"manifest_file", "recipe_file"};
    for (size_t i = 0; i < 2; ++i) {
        const char *path = json_get_str(json_get(input, names[i])); char relative[1800];
        if (!path || !artifact_relative(relative, sizeof(relative), path)) return false;
        json_set_str((struct json_value *)json_get(input, names[i]), relative);
    }
    const char *before = zcl_native_command_datadir(); char *saved = strdup(before ? before : "");
    if (!saved) return false;
    int port = zcl_native_command_rpc_port(); artifact_rpc_fixture = fixture; artifact_rpc_observed = false;
    zcl_native_bridge_bind_rpc(fixture->store, 0); node_rpc_client_set_test_hook(artifact_rpc_stub);
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "fixture"); struct zcl_command_request request = {.input = input};
    zcl_native_handle_zcode_package_publish_commit(&request, &reply);
    node_rpc_client_set_test_hook(NULL); zcl_native_bridge_bind_rpc(saved, port); free(saved); artifact_rpc_fixture = NULL;
    const char *result = json_get_str(json_get(&reply.data, "result"));
    bool ok = artifact_rpc_observed && reply.status == ZCL_COMMAND_STATUS_PASSED && result && strcmp(result, "resident-fixture-only") == 0;
    zcl_command_reply_free(&reply); return ok;
}
static bool artifact_resident_relative_refusal(const struct json_value *input)
{
    struct rpc_table table; rpc_table_init(&table); boot_zcode_package_register_rpc(&table);
    const struct rpc_command *command = rpc_table_find(&table, "zcode_package_publish_commit");
    struct json_value params = {0}, reply = {0}; json_set_array(&params);
    bool ok = command && json_push_back(&params, input) && command->actor(&params, false, &reply);
    const char *code = json_get_str(json_get(&reply, "code"));
    if (ok) ok = !json_get_bool(json_get(&reply, "ok")) && code && strcmp(code, "INVALID_INPUT") == 0;
    /* rpc_table owns a fixed array of borrowed static commands, no heap. */
    json_free(&params); json_free(&reply); return ok;
}
static bool artifact_resident_roundtrip(const struct artifact_fixture *fixture, const struct json_value *data,
    const struct json_value *sealed)
{
    struct json_value input = {0};
    bool ok = artifact_publish_input(&input, fixture, data, sealed, false) && artifact_resident_forward(fixture, &input);
    if (ok) ok = artifact_resident_relative_refusal(&input);
    json_free(&input); return ok;
}
static int artifact_binary_roundtrip(void)
{
    int failures = 0; struct artifact_fixture fixture = {0}; struct json_value input = {0}, prepared = {0}, sealed = {0}, reply = {0};
    static const char *const prepare[] = {"dev", "prepare", NULL}, *const exporting[] = {"dev", "prepare", "export", NULL};
    static const char *const seal[] = {"dev", "seal", NULL}, *const plan[] = {"publish", "plan", NULL}, *const commit[] = {"publish", "commit", NULL};
    TEST_CASE("package artifacts: actual111-file source exports bounded raw wires then verified file-body seal and file publish plan") {
        ASSERT(artifact_fixture_open(&fixture)); ASSERT(artifact_fixture_large(&fixture));
        ASSERT(artifact_prepare_input(&input, &fixture, false)); ASSERT(artifact_native(&fixture, prepare, &input, &reply, false));
        const char *code = json_get_str(json_get(json_get(&reply, "error"), "code")); ASSERT(code != NULL); ASSERT_EQ(strcmp(code, "RESPONSE_BUDGET_EXCEEDED"), 0);
        json_free(&input); ASSERT(artifact_prepare_input(&input, &fixture, true)); ASSERT(artifact_native(&fixture, exporting, &input, &prepared, true));
        const struct json_value *data = json_get(&prepared, "data"); ASSERT(data != NULL);
        ASSERT(json_get_int(json_get(data, "manifest_bytes")) > 8192); ASSERT(artifact_verify_exports(&fixture, data));
        ASSERT(artifact_compare_derivation(&fixture, data));
        ASSERT(artifact_seal_input(&input, &fixture, data)); ASSERT(artifact_native(&fixture, seal, &input, &sealed, true));
        ASSERT(artifact_resident_roundtrip(&fixture, data, json_get(&sealed, "data")));
        ASSERT(artifact_publish_input(&input, &fixture, data, json_get(&sealed, "data"), true));
        json_free(&reply); json_init(&reply); ASSERT(artifact_native(&fixture, plan, &input, &reply, true));
        ASSERT(json_get_bool(json_get(json_get(&reply, "data"), "valid")));
        json_free(&reply); json_init(&reply); ASSERT(artifact_native(&fixture, commit, &input, &reply, true));
        ASSERT(json_get_bool(json_get(json_get(&reply, "data"), "local_commit_complete")));
        json_free(&reply); json_init(&reply); ASSERT(artifact_native(&fixture, commit, &input, &reply, true));
        const char *result = json_get_str(json_get(json_get(&reply, "data"), "result")); ASSERT(result != NULL); ASSERT_EQ(strcmp(result, "duplicate"), 0);
        ASSERT(artifact_local_plan(&fixture, data, json_get(&sealed, "data")));
    } TEST_END
    json_free(&input); json_free(&prepared); json_free(&sealed); json_free(&reply);
    if (fixture.home[0]) test_rm_rf(fixture.home);
    return failures;
}
static bool artifact_export_execute(const struct json_value *input, unsigned stage, bool allocation,
    struct json_value *reply, bool *consumed)
{
    const struct zcl_command_registry *registry = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(registry, "zcode.package.dev.prepare.export", NULL);
    if (!spec || zcl_alloc_fault_armed_label()) return false;
    struct zcl_command_context context = {.registry = registry, .granted_capabilities = UINT64_MAX,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER};
    unsigned prior = zcl_native_package_export_test_failure_stage(stage);
    if (allocation) zcl_alloc_fault_fail_next("zcode.package.dev.hex");
    char wire[8192]; enum zcl_command_exit exit_code;
    size_t size = zcl_command_registry_execute_json(registry, spec, &context, input, false,
        spec->path, "normal", 0, 0, NULL, wire, sizeof(wire), &exit_code);
    *consumed = !allocation || zcl_alloc_fault_armed_label() == NULL;
    if (allocation) zcl_alloc_fault_clear();
    (void)zcl_native_package_export_test_failure_stage(prior);
    return size > 0 && exit_code != ZCL_COMMAND_EXIT_OK && json_read(reply, wire, size);
}
static bool artifact_bool(const struct json_value *object, const char *key, bool expected)
{
    const struct json_value *value = json_get(object, key);
    return value && value->type == JSON_BOOL && json_get_bool(value) == expected;
}
static int artifact_export_interruption(unsigned stage, bool allocation)
{
    int failures = 0; struct artifact_fixture fixture = {0}; struct json_value input = {0}, reply = {0}; bool consumed = false;
    TEST_CASE("package artifact execute: partial and post-marker barrier failure or post-save allocation retain honest effect/publication") {
        ASSERT(artifact_fixture_open(&fixture)); ASSERT(artifact_prepare_input(&input, &fixture, true));
        ASSERT(artifact_export_execute(&input, stage, allocation, &reply, &consumed)); ASSERT(consumed);
        const struct json_value *error = json_get(&reply, "error"), *facts = json_get(error, "facts");
        ASSERT(json_get_bool(json_get(error, "mutated"))); ASSERT(facts != NULL);
        ASSERT_EQ(facts->type, JSON_OBJ); ASSERT_EQ(json_size(facts), 4);
        const char *publication = json_get_str(json_get(facts, "artifact_publication")); ASSERT(publication != NULL);
        ASSERT_EQ(strcmp(publication, allocation ? "durable" : "durability_unknown"), 0);
        ASSERT(artifact_bool(facts, "mutation_attempted", true)); ASSERT(artifact_bool(facts, "automatic_retry", false));
        ASSERT(artifact_bool(facts, "pending_marker_removed", stage != 1));
        char marker[1600]; ASSERT(artifact_path(marker, sizeof(marker), fixture.output, "EXPORT-PENDING"));
        ASSERT_EQ(platform_private_path_absent(marker), stage != 1);
        char file[1600]; ASSERT(artifact_path(file, sizeof(file), fixture.output, "manifest.wire"));
        ASSERT_EQ(platform_private_path_absent(file), stage == 1);
        if (allocation) ASSERT(artifact_compare_derivation(&fixture, NULL));
    } TEST_END
    json_free(&input); json_free(&reply); if (fixture.home[0]) test_rm_rf(fixture.home);
    return failures;
}
static int artifact_export_preflight(unsigned kind)
{
    int failures = 0; struct artifact_fixture fixture = {0}; struct json_value input = {0};
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "fixture");
    TEST_CASE("package artifact export: existing destination, source-contained destination and root source refuse without mutation") {
        ASSERT(artifact_fixture_open(&fixture)); ASSERT(artifact_prepare_input(&input, &fixture, true));
        char path[1600], sentinel[1600];
        if (kind == 0) {
            ASSERT_EQ(platform_directory_create(fixture.output, 0700), 0);
            ASSERT(artifact_path(sentinel, sizeof(sentinel), fixture.output, "PUBLIC-sentinel")); ASSERT(artifact_write(sentinel, "unchanged\n"));
        } else if (kind == 1) {
            ASSERT(artifact_path(path, sizeof(path), fixture.source, "nested-output"));
            json_set_str((struct json_value *)json_get(&input, "artifact_dir"), path);
        } else json_set_str((struct json_value *)json_get(&input, "dir"), "/");
        struct zcl_command_request request = {.input = &input}; zcl_native_handle_zcode_package_dev_prepare_export(&request, &reply);
        ASSERT_EQ(reply.status, ZCL_COMMAND_STATUS_FAILED); ASSERT(!reply.error.mutated);
        ASSERT_EQ(strcmp(reply.error.code, "BAD_EXPORT_INPUT"), 0);
        if (kind == 0) ASSERT(artifact_reference_file(fixture.output, "PUBLIC-sentinel", (const uint8_t *)"unchanged\n", 10));
        else ASSERT(platform_private_path_absent(kind == 1 ? path : fixture.output));
    } TEST_END
    json_free(&input); zcl_command_reply_free(&reply); if (fixture.home[0]) test_rm_rf(fixture.home);
    return failures;
}
static bool artifact_reader_fault(struct json_value *input, const char *path, unsigned kind)
{
    if (kind == 0) return json_push_kv_str(input, "wire_hex", "01020304");
    if (kind == 1) json_set_str((struct json_value *)json_get(input, "wire_sha3"),
        "0000000000000000000000000000000000000000000000000000000000000000");
    if (kind == 2) json_set_null((struct json_value *)json_get(input, "wire_file"));
    if (kind == 3) json_set_int((struct json_value *)json_get(input, "wire_sha3"), 1);
    if (kind == 4) {
        struct platform_private_file file; platform_private_file_init(&file);
        bool ok = platform_private_file_open_locked(path, &file) && platform_private_file_write_at(&file, "tamper", 6, 0);
        platform_private_file_close(&file); return ok;
    }
    if (kind == 5) {
        char link[1600]; if (snprintf(link, sizeof(link), "%s.link", path) <= 0 || symlink(path, link) != 0) return false;
        json_set_str((struct json_value *)json_get(input, "wire_file"), link);
    }
    if (kind == 8) {
        char fifo[1600]; if (snprintf(fifo, sizeof(fifo), "%s.fifo", path) <= 0 || mkfifo(fifo, 0600) != 0) return false;
        json_set_str((struct json_value *)json_get(input, "wire_file"), fifo);
    }
    return true;
}
static int artifact_reader_refusal(unsigned kind)
{
    int failures = 0; struct artifact_fixture fixture = {0}; struct json_value input = {0}; uint8_t *bytes = NULL; size_t size = 77;
    TEST_CASE("package artifact reader: mixed, wrong digest, null/non-string, tampered bytes or symlink refuse with no output") {
        ASSERT(artifact_fixture_open(&fixture)); char path[1600]; ASSERT(artifact_path(path, sizeof(path), fixture.home, "public-wire"));
        ASSERT(artifact_write(path, "PUBLIC fixture bytes\n")); uint8_t digest[32]; char hex[65];
        zcl_native_package_artifact_digest(digest, (const uint8_t *)"PUBLIC fixture bytes\n", 21); zcl_hex_encode(digest, 32, hex);
        json_set_object(&input); ASSERT(json_push_kv_str(&input, "wire_file", path));
        if (kind != 6) ASSERT(json_push_kv_str(&input, "wire_sha3", hex));
        ASSERT(artifact_reader_fault(&input, path, kind));
        ASSERT(!zcl_native_package_artifact_read(&input, "wire_hex", "wire_file", "wire_sha3", kind == 7 ? 16 : 4096, &bytes, &size));
        ASSERT(bytes == NULL); ASSERT_EQ(size, 0);
    } TEST_END
    free(bytes); json_free(&input); if (fixture.home[0]) test_rm_rf(fixture.home);
    return failures;
}
/* kind 0: a mode-000 child directory; kind 1: a package manifest whose root
 * is a JSON array. Both must refuse the package with a named detail. */
static int artifact_walk_refusal(unsigned kind)
{
    int failures = 0; struct artifact_fixture fixture = {0}; char dir[1600] = "";
    TEST_CASE("package prepare: an unopenable child directory or array-root manifest refuses the package") {
        ASSERT(artifact_fixture_open(&fixture));
        struct vcs_package_prepare_options options = {.dir = fixture.source, .publisher_sequence = 1, .chain_id = fixture.chain};
        ASSERT(zcl_hex_decode_lower(artifact_public_key, options.publisher_pubkey, 33));
        char detail[256] = "", sdetail[256] = ""; struct vcs_package_prepared prepared, scanned; bool has_config = false;
        enum vcs_package_prepare_error err, serr = VCS_PACKAGE_PREPARE_OK;
        if (kind == 0 && geteuid() == 0) { printf("package_artifact: SKIP (root ignores mode 000)\n"); }
        else if (kind == 0) {
            ASSERT(artifact_path(dir, sizeof(dir), fixture.source, "docs")); ASSERT(chmod(dir, 0) == 0);
            err = vcs_package_prepare(&options, &prepared, detail, sizeof(detail));
            serr = vcs_package_scan_layout(fixture.source, &scanned, &has_config, sdetail, sizeof(sdetail));
            vcs_package_prepared_free(&scanned);
            ASSERT(err != VCS_PACKAGE_PREPARE_OK); ASSERT(strstr(detail, "docs") != NULL);
            ASSERT(serr != VCS_PACKAGE_PREPARE_OK); ASSERT(strstr(sdetail, "docs") != NULL);
        } else {
            { char mp[1600]; ASSERT(artifact_path(mp, sizeof(mp), fixture.source, "zcode-package.json")); ASSERT(unlink(mp) == 0); }
            ASSERT(artifact_fixture_file(&fixture, "zcode-package.json", "[\"a\",\"b\"]\n"));
            err = vcs_package_prepare(&options, &prepared, detail, sizeof(detail));
            ASSERT_EQ(err, VCS_PACKAGE_PREPARE_ERR_META);
            ASSERT(strstr(detail, "zcode-package.json is not a JSON object") != NULL);
        }
    } TEST_END
    if (dir[0]) (void)chmod(dir, 0700);
    if (fixture.home[0]) test_rm_rf(fixture.home);
    return failures;
}
int test_zcode_package_artifact(void);
int test_zcode_package_artifact(void)
{
    int failures = artifact_binary_roundtrip() + artifact_export_interruption(1, false) +
        artifact_export_interruption(2, false) + artifact_export_interruption(0, true);
    for (unsigned i = 0; i < 3; ++i) failures += artifact_export_preflight(i);
    for (unsigned i = 0; i < 9; ++i) failures += artifact_reader_refusal(i);
    for (unsigned i = 0; i < 2; ++i) failures += artifact_walk_refusal(i);
    return failures;
}
#else
int test_zcode_package_artifact(void);
int test_zcode_package_artifact(void)
{
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "fixture");
    struct json_value input = {0}; struct zcl_command_request request = {.input = &input};
    zcl_native_handle_zcode_package_dev_prepare_export(&request, &reply);
    bool refused = reply.status == ZCL_COMMAND_STATUS_FAILED && !reply.error.mutated;
    zcl_command_reply_free(&reply); return refused ? 0 : 1;
}
#endif
