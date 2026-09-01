/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Command-registry authority-ceiling + capability enforcement tests. Proves
 * the new execute_json branch fails closed with AUTHORITY_DENIED when a leaf's
 * authority exceeds the session ceiling (before the capability check), that a
 * capability subset failure still yields CAPABILITY_DENIED, that a GUEST
 * session is denied a capped leaf, that an OWNER-ceiling session reaches an
 * OWNER leaf's handler, that discover.describe reports account.role's OWNER
 * authority, and that the principals/auth dumpstate surfaces return bounded
 * JSON. */

#include "test/test_core.h"

#include "config/command_catalog.h"
#include "kernel/command_registry.h"
#include "models/principal.h"
#include "models/auth_challenge.h"
#include "json/json.h"

#include <stdio.h>
#include <string.h>

static const struct zcl_command_spec *find_spec(
    const struct zcl_command_registry *reg, const char *path)
{
    for (size_t i = 0; i < reg->count; i++)
        if (strcmp(reg->commands[i].path, path) == 0)
            return &reg->commands[i];
    return NULL;
}

static enum zcl_command_exit exec_with(const struct zcl_command_registry *reg,
                                       const char *path,
                                       enum zcl_command_authority ceiling,
                                       uint64_t granted,
                                       char *out, size_t out_size)
{
    const struct zcl_command_spec *spec = find_spec(reg, path);
    if (!spec)
        return ZCL_COMMAND_EXIT_INTERNAL;
    struct zcl_command_context ctx = {
        .registry = reg,
        .granted_capabilities = granted,
        .authority_ceiling = ceiling,
    };
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
    (void)zcl_command_registry_execute_json(reg, spec, &ctx, &input, false,
                                            path, "normal", 0, 0, NULL,
                                            out, out_size, &code);
    json_free(&input);
    return code;
}

static int test_authority_denied(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    char out[ZCL_COMMAND_RESULT_BUDGET + 1];
    TEST("authority > ceiling fails closed with AUTHORITY_DENIED") {
        enum zcl_command_exit code = exec_with(reg, "app.account.role",
                                               ZCL_COMMAND_AUTH_OPERATOR,
                                               ~(uint64_t)0, out, sizeof(out));
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_DENIED);
        ASSERT(strstr(out, "AUTHORITY_DENIED") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_capability_denied(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    char out[ZCL_COMMAND_RESULT_BUDGET + 1];
    TEST("capability subset failure yields CAPABILITY_DENIED") {
        enum zcl_command_exit code = exec_with(reg, "app.list",
                                               ZCL_COMMAND_AUTH_OWNER,
                                               0, out, sizeof(out));
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_DENIED);
        ASSERT(strstr(out, "CAPABILITY_DENIED") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_guest_denied_capped_leaf(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    char out[ZCL_COMMAND_RESULT_BUDGET + 1];
    TEST("a GUEST (CAP_NONE) session is denied a capped leaf") {
        enum zcl_command_exit code = exec_with(reg, "app.list",
                                               ZCL_COMMAND_AUTH_PUBLIC,
                                               0, out, sizeof(out));
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_DENIED);
        PASS();
    } _test_next:;
    return failures;
}

static int test_owner_reaches_handler(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    char out[ZCL_COMMAND_RESULT_BUDGET + 1];
    TEST("an OWNER-ceiling session reaches the account.role handler") {
        enum zcl_command_exit code = exec_with(reg, "app.account.role",
                                               ZCL_COMMAND_AUTH_OWNER,
                                               ~(uint64_t)0, out, sizeof(out));
        ASSERT(strstr(out, "AUTHORITY_DENIED") == NULL);
        ASSERT(strstr(out, "BAD_ROLE") != NULL);
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_INVALID);
        PASS();
    } _test_next:;
    return failures;
}

static int test_full_authority_public_leaf_runs(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    char out[ZCL_COMMAND_RESULT_BUDGET + 1];
    TEST("a full-authority public leaf runs (argv omnipotence parity)") {
        enum zcl_command_exit code = exec_with(reg, "app.account.whoami",
                                               ZCL_COMMAND_AUTH_OWNER,
                                               ~(uint64_t)0, out, sizeof(out));
        ASSERT(strstr(out, "AUTHORITY_DENIED") == NULL);
        ASSERT(strstr(out, "CAPABILITY_DENIED") == NULL);
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_INVALID);
        PASS();
    } _test_next:;
    return failures;
}

static int test_describe_shows_owner(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    TEST("discover.describe reports account.role's OWNER authority") {
        char desc[ZCL_COMMAND_SPEC_BUDGET + 1];
        size_t n = zcl_command_registry_describe_json(reg, "app.account.role",
                                                      desc, sizeof(desc));
        ASSERT(n > 0);
        ASSERT(strstr(desc, "owner") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_dumpstate_bounded(void)
{
    int failures = 0;
    TEST("dumpstate principals/auth return bounded JSON") {
        struct json_value obj;
        json_init(&obj);
        json_set_object(&obj);
        ASSERT(principal_dump_state_json(&obj, NULL));
        size_t sz = json_write(&obj, NULL, 0);
        ASSERT(sz > 0 && sz <= ZCL_COMMAND_RESULT_BUDGET);
        json_free(&obj);

        struct json_value obj2;
        json_init(&obj2);
        json_set_object(&obj2);
        ASSERT(auth_challenge_dump_state_json(&obj2, NULL));
        size_t sz2 = json_write(&obj2, NULL, 0);
        ASSERT(sz2 > 0 && sz2 <= ZCL_COMMAND_RESULT_BUDGET);
        json_free(&obj2);
        PASS();
    } _test_next:;
    return failures;
}

int test_command_authority(void)
{
    int failures = 0;
    failures += test_authority_denied();
    failures += test_capability_denied();
    failures += test_guest_denied_capped_leaf();
    failures += test_owner_reaches_handler();
    failures += test_full_authority_public_leaf_runs();
    failures += test_describe_shows_owner();
    failures += test_dumpstate_bounded();
    printf("=== command_authority: %d failures ===\n", failures);
    return failures;
}
