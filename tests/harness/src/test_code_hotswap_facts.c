/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Isolated native hotswap facts: indexed advice is never semantic proof. */
#include "test/test_core.h"
#include "command/native_command.h"
#include "config/command_catalog.h"
#include "kernel/command_registry.h"
#include "codeindex/codeindex.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include <errno.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

static bool hft_write(const char *root, const char *rel, const char *body)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof path, "%s/%s", root, rel);
    if (n <= 0 || (size_t)n >= sizeof path) return false;
    for (char *p = path + 1; *p; ++p) {
        if (*p != '/') continue;
        *p = '\0'; bool ok = platform_directory_ensure(path, 0700); *p = '/';
        if (!ok) return false;
    }
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    size_t len = strlen(body);
    bool ok = fwrite(body, 1, len, f) == len;
    return fclose(f) == 0 && ok;
}

static bool hft_fixture(const char *root)
{
    return hft_write(root, "engine/controllers/src/advice.c", "int hft_unique(void) { return 1; }\nint hft_ambiguous(void) { return 2; }\n") &&
        hft_write(root, "cognition/controllers/src/advice.c", "int hft_ambiguous(void) { return 3; }\n") &&
        hft_write(root, "contexts/messaging/controllers/src/advice.c", "int hft_context(void) { return 4; }\n") &&
        hft_write(root, "engine/reducer/src/advice.c", "int hft_reducer(void) { return 5; }\n") &&
        hft_write(root, "engine/controllers_extra/src/advice.c", "int hft_nearmiss(void) { return 6; }\n") &&
        hft_write(root, "contexts/messaging/services/src/advice.c", "int hft_service(void) { return 7; }\n") &&
        hft_write(root, "engine/controllers/include/prototype.h", "int hft_prototype(void);\n");
}

static bool hft_append(struct json_value *array, const char *text)
{
    struct json_value value; json_init(&value); json_set_str(&value, text);
    bool ok = json_push_back(array, &value);
    json_free(&value); return ok;
}

static bool hft_extra_inputs(struct json_value *names, struct json_value *files, unsigned mode)
{
    bool ok = true;
    if (mode == 1) ok = hft_append(names, "bad-name");
    if (mode == 2) for (int i = 5; i < 129; ++i) ok = hft_append(names, "hft_unique") && ok;
    if (mode == 8) for (int i = 5; i < 128; ++i) {
        char name[32]; snprintf(name, sizeof(name), "hft_missing_%d", i);
        ok = hft_append(names, name) && ok;
    }
    if (mode == 4) for (int i = 7; i < 65; ++i) ok = hft_append(files, "engine/controllers/src/advice.c") && ok;
    if (mode == 5) ok = hft_append(files, "../outside.c");
    if (mode == 6) ok = hft_append(files, "engine/controllers/src/bad\tname.c");
    return ok;
}

static bool hft_input(struct json_value *input, unsigned mode)
{
    static const char *const symbols[] = {"hft_unique", "hft_ambiguous", "hft_prototype", "hft_missing", "hft_replacement"};
    static const char *const paths[] = {"engine/controllers/src/advice.c", "cognition/controllers/src/advice.c", "contexts/messaging/controllers/src/advice.c", "engine/reducer/src/advice.c", "engine/controllers/src/absent.c", "engine/controllers_extra/src/advice.c", "contexts/messaging/services/src/advice.c"};
    struct json_value names, files; json_init(&names); json_init(&files);
    json_set_array(&names); json_set_array(&files);
    bool ok = true;
    for (size_t i = 0; i < sizeof symbols / sizeof symbols[0]; ++i) ok = hft_append(&names, symbols[i]) && ok;
    for (size_t i = 0; i < sizeof paths / sizeof paths[0]; ++i) ok = hft_append(&files, paths[i]) && ok;
    ok = hft_extra_inputs(&names, &files, mode) && ok;
    json_set_object(input);
    ok = json_push_kv(input, "symbols", &names) && json_push_kv(input, "paths", &files) && ok;
    json_free(&names); json_free(&files); return ok;
}

static bool hft_call(const char *root, const struct json_value *input, struct json_value *wire, size_t budget)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(reg, "code.hotswap-facts", NULL);
    if (!spec) { fprintf(stderr, "hotswap facts command not registered\n"); return false; }
    struct zcl_command_context ctx = {.registry = reg, .source_root = root,
        .operator_lane = "dev", .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER, .dev_build = true};
    char *out = calloc(1, 65537); if (!out) return false;
    enum zcl_command_exit exit_code;
    size_t n = zcl_command_registry_execute_json(reg, spec, &ctx, input, false, spec->path,
                                                  "normal", budget, 0, NULL, out, 65537, &exit_code);
    bool ok = n > 0 && n < 65537 && json_read(wire, out, n);
    free(out); return ok;
}

static bool hft_row(const struct json_value *array, const char *key, const char *id,
                    const char *field, const char *expected)
{
    if (!array || array->type != JSON_ARR) return false;
    for (size_t i = 0; i < json_size(array); ++i) {
        const struct json_value *row = json_at(array, i);
        if (!strcmp(json_get_str(json_get(row, key)), id))
            return !strcmp(json_get_str(json_get(row, field)), expected);
    }
    return false;
}

static bool hft_symbol_results(const struct json_value *data)
{
    const struct json_value *a = json_get(data, "symbols");
    return hft_row(a, "name", "hft_unique", "status", "indexed_candidate") &&
        hft_row(a, "name", "hft_unique", "path", "engine/controllers/src/advice.c") &&
        hft_row(a, "name", "hft_ambiguous", "reason", "ambiguous") &&
        hft_row(a, "name", "hft_prototype", "status", "unknown") &&
        hft_row(a, "name", "hft_missing", "status", "unknown");
}

static bool hft_path_results(const struct json_value *data)
{
    const struct json_value *a = json_get(data, "paths");
    return hft_row(a, "path", "engine/controllers/src/advice.c", "classification", "allowed") &&
        hft_row(a, "path", "cognition/controllers/src/advice.c", "classification", "allowed") &&
        hft_row(a, "path", "contexts/messaging/controllers/src/advice.c", "classification", "allowed") &&
        hft_row(a, "path", "engine/controllers_extra/src/advice.c", "classification", "other") &&
        hft_row(a, "path", "contexts/messaging/services/src/advice.c", "classification", "other") &&
        hft_row(a, "path", "engine/reducer/src/advice.c", "classification", "forbidden") &&
        hft_row(a, "path", "engine/controllers/src/absent.c", "classification", "unknown");
}

static bool hft_success(const struct json_value *wire)
{
    const struct json_value *data = json_get(wire, "data");
    const struct json_value *census = json_get(data, "census");
    return json_get_bool(json_get(wire, "ok")) &&
        !strcmp(json_get_str(json_get(data, "schema")), "zcl.code_hotswap_facts.v1") &&
        !strcmp(json_get_str(json_get(data, "ownership_basis")), "indexed_definitions") &&
        !strcmp(json_get_str(json_get(data, "semantic_completeness")), "unproven") &&
        census && census->type == JSON_INT && json_get_int(census) == 3 &&
        strstr(json_get_str(json_get(data, "text")), "owner\thft_unique\tengine/controllers/src/advice.c") &&
        hft_symbol_results(data) && hft_path_results(data);
}

static bool hft_refreshed(const struct json_value *wire)
{
    const struct json_value *symbols = json_get(json_get(wire, "data"), "symbols");
    return json_get_bool(json_get(wire, "ok")) &&
        hft_row(symbols, "name", "hft_unique", "status", "unknown") &&
        hft_row(symbols, "name", "hft_replacement", "status", "indexed_candidate") &&
        hft_row(symbols, "name", "hft_replacement", "path", "engine/controllers/src/advice.c");
}

static bool hft_path_absent(const char *path)
{
    struct stat st;
    return stat(path, &st) != 0 && errno == ENOENT;
}

static bool hft_invalid_fresh(void)
{
    char root[PATH_MAX] = {0}, index[PATH_MAX];
    test_make_tmpdir(root, sizeof root, "code_hotswap_facts", "invalid_fresh");
    int n = snprintf(index, sizeof index, "%s/.codeindex", root);
    if (!root[0] || n <= 0 || (size_t)n >= sizeof index) return false;
    bool absent = hft_path_absent(index);
    struct json_value input = {0}, wire = {0};
    json_set_object(&input);
    bool called = hft_call(root, &input, &wire, 0);
    bool refused = called && !json_get_bool(json_get(&wire, "ok"));
    const char *code = json_get_str(json_get(json_get(&wire, "error"), "code"));
    bool code_ok = strcmp(code, "HOTSWAP_FACTS_INVALID_INPUT") == 0;
    bool still_absent = hft_path_absent(index);
    if (!absent || !called || !refused || !code_ok || !still_absent)
        fprintf(stderr, "hotswap invalid fresh: absent=%d called=%d refused=%d code=%s code_ok=%d still_absent=%d\n",
                absent, called, refused, code, code_ok, still_absent);
    json_free(&wire); json_free(&input);
    bool removed = test_rm_rf_recursive(root) == 0;
    return absent && refused && code_ok && still_absent && removed;
}

static bool hft_run(const char *root, unsigned mode, bool success)
{
    struct json_value input, wire; json_init(&input); json_init(&wire);
    bool made = hft_input(&input, mode);
    bool called = made && hft_call(root, &input, &wire, mode == 7 ? 1024 : 0);
    bool ok = called && (mode == 3 ? hft_refreshed(&wire) :
                         success ? hft_success(&wire) : !json_get_bool(json_get(&wire, "ok")));
    if (ok && mode == 7) {
        const struct json_value *data = json_get(&wire, "data");
        ok = !json_get(data, "symbols") && !json_get(data, "paths") && !json_get(data, "text");
    }
    if (ok && mode == 8)
        ok = json_size(json_get(json_get(&wire, "data"), "symbols")) == 128;
    if (!ok) fprintf(stderr, "hotswap facts mode=%u input=%d dispatch=%d\n", mode, made, called);
    json_free(&wire); json_free(&input); return ok;
}

int test_code_hotswap_facts(void)
{
    int failures = 0;
    char root[PATH_MAX] = {0};
    test_make_tmpdir(root, sizeof root, "code_hotswap_facts", "fixture");
    bool ready = root[0] && hft_fixture(root);
    struct codeindex *index = ready ? codeindex_open(root) : NULL;
    ready = ready && index != NULL; codeindex_close(index);
    TEST("code.hotswap-facts: native bounded advisory from isolated index") {
        ASSERT(hft_invalid_fresh());
        ASSERT(ready);
        ASSERT(hft_run(root, 0, true));
        ASSERT(hft_run(root, 1, false));
        ASSERT(hft_run(root, 2, false));
        ASSERT(hft_run(root, 4, false));
        ASSERT(hft_run(root, 5, false));
        ASSERT(hft_run(root, 6, false));
        ASSERT(hft_run(root, 7, false));
        ASSERT(hft_run(root, 8, true));
        ASSERT(hft_write(root, "engine/controllers/src/advice.c", "int hft_replacement(void) { return 8; }\n"));
        ASSERT(hft_run(root, 3, true));
        PASS();
    } _test_next:;
    if (root[0] && test_rm_rf_recursive(root) != 0) failures++;
    return failures;
}
