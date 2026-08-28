/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: human-first inspection and exact initialization of one C23 project. */

#include "command/native_command.h"

#include "base/checked.h"
#include "base/hex.h"
#include "json/json.h"
#if defined(_WIN32)
#include "platform/directory_transaction.h"
#endif
#include "sha3/sha3.h"
#include "vcs/package_prepare.h"
#include "vcs/zcode_dev_product.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <process.h>
#endif
#include <sys/stat.h>
#include <unistd.h>

static const uint8_t zproject_inspection_pubkey[33] = {
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb,
    0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28,
    0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98,
};

struct zproject_init_plan {
    char name[VCS_PACKAGE_RELEASE_NAME_MAX + 1u];
    char semver[VCS_PACKAGE_RELEASE_SEMVER_MAX + 1u];
    char license[VCS_PACKAGE_RELEASE_LICENSE_MAX + 1u];
    char configuration[1024];
    uint8_t source_root[32];
    uint8_t plan_id[32];
};

static bool zproject_render_layout(
    struct json_value *out, const struct vcs_package_prepared *prepared);

static const char *zproject_str(const struct json_value *input,
                                const char *key)
{
    const struct json_value *value = input ? json_get(input, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static void zproject_fail(struct zcl_command_reply *reply, const char *code,
                          const char *detail)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, "inspect", false,
                           false, detail, "zcode.project.inspect");
}

static void zproject_fail_at(struct zcl_command_reply *reply, const char *code,
                             const char *stage, const char *detail,
                             const char *next)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, code, stage, false, false,
                           detail, next);
}

static bool zproject_bool(const struct json_value *input, const char *key)
{
    const struct json_value *value = input ? json_get(input, key) : NULL;
    return value && value->type == JSON_BOOL && json_get_bool(value);
}

static bool zproject_has_manifest_path(
    const struct vcs_package_manifest *manifest, const char *path)
{
    for (size_t i = 0; i < manifest->count; i++)
        if (strcmp(manifest->files[i].path, path) == 0)
            return true;
    return false;
}

static bool zproject_infer_name(const char *workspace, char *out, size_t cap)
{
    size_t len = strlen(workspace);
    while (len > 0 && workspace[len - 1u] == '/')
        len--;
    size_t start = len;
    while (start > 0 && workspace[start - 1u] != '/')
        start--;
    char half[VCS_PACKAGE_RELEASE_NAME_HALF_MAX + 1u];
    size_t used = 0;
    bool hyphen = false;
    for (size_t i = start; i < len && used < sizeof(half) - 1u; i++) {
        unsigned char c = (unsigned char)workspace[i];
        if (isalnum(c)) {
            half[used++] = (char)tolower(c);
            hyphen = false;
        } else if (used > 0 && !hyphen) {
            half[used++] = '-';
            hyphen = true;
        }
    }
    while (used > 0 && half[used - 1u] == '-')
        used--;
    if (used == 0)
        return false;
    half[used] = '\0';
    int n = snprintf(out, cap, "local/%s", half);
    return n > 0 && (size_t)n < cap;
}

static bool zproject_infer_license(const char *workspace, char *out,
                                   size_t cap)
{
#if defined(_WIN32)
    struct platform_directory_transaction root;
    struct platform_directory_child file;
    struct platform_directory_child_info info;
    platform_directory_transaction_init(&root);
    platform_directory_child_init(&file);
    if (!platform_directory_transaction_open(&root, workspace) ||
        !platform_directory_child_open(&root, "LICENSE", &file) ||
        !platform_directory_child_info(&file, &info) || info.size > 8192u) {
        platform_directory_child_close(&file);
        platform_directory_transaction_close(&root);
        return false;
    }
    char text[8193];
    size_t used = (size_t)info.size;
    struct platform_directory_child_info after;
    bool ok = platform_directory_child_read_exact(&file, text, used, 0) &&
        platform_directory_child_info(&file, &after) &&
        after.volume == info.volume && after.file_low == info.file_low &&
        after.file_high == info.file_high && after.size == info.size &&
        after.modified_seconds == info.modified_seconds &&
        after.modified_nanoseconds == info.modified_nanoseconds &&
        after.changed_seconds == info.changed_seconds &&
        after.changed_nanoseconds == info.changed_nanoseconds;
    platform_directory_child_close(&file);
    platform_directory_transaction_close(&root);
    if (!ok)
        return false;
#else
    int root = open(workspace, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root < 0)
        return false;
    int fd = openat(root, "LICENSE", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    close(root);
    if (fd < 0)
        return false;
    char text[8193];
    size_t used = 0;
    bool ok = true;
    while (used < sizeof(text) - 1u) {
        ssize_t got = read(fd, text + used, sizeof(text) - 1u - used);
        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0) {
            ok = false;
            break;
        }
        if (got == 0)
            break;
        used += (size_t)got;
    }
    char extra;
    if (ok && used == sizeof(text) - 1u && read(fd, &extra, 1) != 0)
        ok = false;
    close(fd);
    if (!ok)
        return false;
#endif
    text[used] = '\0';
    const char *license = NULL;
    if (strstr(text, "Apache License") || strstr(text, "Apache-2.0"))
        license = "Apache-2.0";
    else if (strcmp(text, "MIT\n") == 0 || strcmp(text, "MIT") == 0 ||
             strstr(text, "MIT License") ||
             strstr(text, "Permission is hereby granted"))
        license = "MIT";
    else if (strstr(text, "BSD 2-Clause"))
        license = "BSD-2-Clause";
    else if (strstr(text, "BSD 3-Clause"))
        license = "BSD-3-Clause";
    else if (strstr(text, "ISC License"))
        license = "ISC";
    else if (strstr(text, "Zlib License"))
        license = "Zlib";
    else if (strstr(text, "Zero-Clause BSD") || strstr(text, "0BSD"))
        license = "0BSD";
    if (!license || strlen(license) >= cap)
        return false;
    (void)snprintf(out, cap, "%s", license);
    return true;
}

static bool zproject_config_valid(const struct zproject_init_plan *plan)
{
    struct vcs_package_release release;
    memset(&release, 0, sizeof(release));
    release.schema_version = VCS_PACKAGE_RELEASE_VERSION;
    (void)snprintf(release.name, sizeof(release.name), "%s", plan->name);
    (void)snprintf(release.semver, sizeof(release.semver), "%s", plan->semver);
    (void)snprintf(release.license, sizeof(release.license), "%s",
                   plan->license);
    (void)snprintf(release.chain_id, sizeof(release.chain_id),
                   "zclassic-main");
    release.package_root[0] = 1;
    release.recipe_root[0] = 1;
    memcpy(release.publisher_pubkey, zproject_inspection_pubkey,
           sizeof(zproject_inspection_pubkey));
    release.publisher_sequence = 1;
    return vcs_package_release_validate(&release) == VCS_PACKAGE_RELEASE_OK;
}

static bool zproject_plan_derive(const struct json_value *input,
                                 struct zproject_init_plan *plan,
                                 struct vcs_package_prepared *scan,
                                 char *detail, size_t detail_cap)
{
    memset(plan, 0, sizeof(*plan));
    const char *workspace = zproject_str(input, "workspace");
    bool has_config = false;
    enum vcs_package_prepare_error err = vcs_package_scan_layout(
        workspace, scan, &has_config, detail, detail_cap);
    if (err != VCS_PACKAGE_PREPARE_OK) {
        char prior[256];
        (void)snprintf(prior, sizeof(prior), "%s", detail ? detail : "");
        if (detail && detail_cap)
            (void)snprintf(detail, detail_cap, "%s: %s",
                           vcs_package_prepare_error_string(err), prior);
        return false;
    }
    if (has_config) {
        if (detail && detail_cap)
            (void)snprintf(detail, detail_cap,
                           "zcode-package.json already exists; overwrite refused");
        return false;
    }
    if (!zproject_has_manifest_path(&scan->manifest, "LICENSE")) {
        if (detail && detail_cap)
            (void)snprintf(detail, detail_cap,
                           "LICENSE is required before project initialization");
        return false;
    }
    const char *name = zproject_str(input, "name");
    const char *semver = zproject_str(input, "semver");
    const char *license = zproject_str(input, "license");
    if (name) {
        if (strlen(name) >= sizeof(plan->name))
            return false;
        (void)snprintf(plan->name, sizeof(plan->name), "%s", name);
    } else if (!zproject_infer_name(workspace, plan->name,
                                    sizeof(plan->name))) {
        if (detail && detail_cap)
            (void)snprintf(detail, detail_cap,
                           "package name could not be inferred; supply name");
        return false;
    }
    (void)snprintf(plan->semver, sizeof(plan->semver), "%s",
                   semver ? semver : "0.1.0-dev.1");
    if (license) {
        if (strlen(license) >= sizeof(plan->license))
            return false;
        (void)snprintf(plan->license, sizeof(plan->license), "%s", license);
    } else if (!zproject_infer_license(workspace, plan->license,
                                       sizeof(plan->license))) {
        if (detail && detail_cap)
            (void)snprintf(detail, detail_cap,
                           "permissive SPDX license could not be inferred; "
                           "new original work defaults to Apache-2.0 — "
                           "supply license or use Apache-2.0 LICENSE text");
        return false;
    }
    if (!zproject_config_valid(plan)) {
        if (detail && detail_cap)
            (void)snprintf(detail, detail_cap,
                           "name, semver or license violates the existing package schema");
        return false;
    }
    int n = snprintf(plan->configuration, sizeof(plan->configuration),
        "{\n"
        "  \"schema\": 1,\n"
        "  \"name\": \"%s\",\n"
        "  \"semver\": \"%s\",\n"
        "  \"language\": \"c23\",\n"
        "  \"license\": \"%s\",\n"
        "  \"include_dir\": \"include\",\n"
        "  \"source_dir\": \"src\",\n"
        "  \"dependencies\": []\n"
        "}\n", plan->name, plan->semver, plan->license);
    if (n <= 0 || (size_t)n >= sizeof(plan->configuration) ||
        !vcs_package_manifest_root(&scan->manifest, plan->source_root)) {
        if (detail && detail_cap)
            (void)snprintf(detail, detail_cap,
                           "bounded initialization plan could not be derived");
        return false;
    }
    static const uint8_t domain[] = "zcl.zcode_project_init_plan.local.v1";
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, domain, sizeof(domain));
    sha3_256_write(&ctx, plan->source_root, sizeof(plan->source_root));
    sha3_256_write(&ctx, (const uint8_t *)plan->configuration,
                   strlen(plan->configuration));
    sha3_256_finalize(&ctx, plan->plan_id);
    return true;
}

static bool zproject_render_plan(struct json_value *out,
                                 const struct zproject_init_plan *plan,
                                 const struct vcs_package_prepared *scan)
{
    struct json_value layout;
    if (!zproject_render_layout(&layout, scan))
        return false;
    char plan_hex[65], source_hex[65];
    zcl_hex_encode(plan->plan_id, 32, plan_hex);
    zcl_hex_encode(plan->source_root, 32, source_hex);
    bool ok = json_push_kv_str(out, "name", plan->name) &&
              json_push_kv_str(out, "semver", plan->semver) &&
              json_push_kv_str(out, "license", plan->license) &&
              json_push_kv(out, "layout", &layout) &&
              json_push_kv_str(out, "configuration_text",
                               plan->configuration) &&
              json_push_kv_str(out, "plan_id", plan_hex) &&
              json_push_kv_bool(out, "correctable", true) &&
              json_push_kv_bool(out, "read_only", true);
    struct json_value expert;
    json_init(&expert); json_set_object(&expert);
    if (ok)
        ok = json_push_kv_str(&expert, "preinit_source_root", source_hex) &&
             json_push_kv(out, "expert", &expert);
    json_free(&expert);
    json_free(&layout);
    return ok;
}

static bool zproject_push_strings(
    struct json_value *out, const char *key,
    const struct vcs_package_recipe_strings *strings)
{
    struct json_value values;
    json_init(&values);
    json_set_array(&values);
    bool ok = true;
    for (size_t i = 0; ok && i < strings->count; i++) {
        struct json_value value;
        json_init(&value);
        json_set_str(&value, strings->items[i]);
        ok = json_push_back(&values, &value);
        json_free(&value);
    }
    if (ok) ok = json_push_kv(out, key, &values);
    json_free(&values);
    return ok;
}

static bool zproject_push_libraries(struct json_value *out,
                                    const struct vcs_package_recipe *recipe)
{
    struct json_value values;
    json_init(&values);
    json_set_array(&values);
    bool ok = true;
    for (size_t i = 0; ok && i < recipe->library_count; i++) {
        const char *name = vcs_package_recipe_library_name(
            recipe->libraries[i]);
        struct json_value value;
        json_init(&value);
        if (!name) {
            ok = false;
        } else {
            json_set_str(&value, name);
            ok = json_push_back(&values, &value);
        }
        json_free(&value);
    }
    if (ok) ok = json_push_kv(out, "allowed_libraries", &values);
    json_free(&values);
    return ok;
}

static bool zproject_push_root(struct json_value *out, const char *key,
                               const uint8_t root[32])
{
    char hex[65];
    zcl_hex_encode(root, 32, hex);
    return json_push_kv_str(out, key, hex);
}

static bool zproject_render_layout(struct json_value *out,
                                   const struct vcs_package_prepared *prepared)
{
    json_init(out);
    json_set_object(out);
    return zproject_push_strings(out, "public_headers",
                                 &prepared->recipe.public_headers) &&
           zproject_push_strings(out, "sources",
                                 &prepared->recipe.sources) &&
           zproject_push_strings(out, "tests",
                                 &prepared->recipe.test_sources) &&
           zproject_push_strings(out, "include_directories",
                                 &prepared->recipe.include_dirs) &&
           zproject_push_libraries(out, &prepared->recipe);
}

static bool zproject_render_expert(struct json_value *out,
                                   const struct vcs_package_prepared *prepared)
{
    json_init(out);
    json_set_object(out);
    return zproject_push_root(out, "package_root", prepared->package_root) &&
           zproject_push_root(out, "recipe_root", prepared->recipe_root) &&
           zproject_push_root(out, "dependency_lock_root",
                              prepared->lock_root) &&
           zproject_push_root(out, "api_capsule_root",
                              prepared->capsule_root);
}

static bool zproject_render_profile(struct json_value *out)
{
    struct vcs_zcode_dev_profile profile;
    uint8_t root[32];
    if (!vcs_zcode_dev_profile_expand("standard", &profile) ||
        vcs_zcode_proof_policy_root(&profile.policy, root) !=
            VCS_ZCODE_DEV_OK)
        return false;
    struct json_value exact;
    json_init(&exact);
    json_set_object(&exact);
    bool ok = zproject_push_root(&exact, "root", root) &&
        json_push_kv_int(&exact, "required_proofs",
                         profile.policy.required_proofs) &&
        json_push_kv_int(&exact, "minimum_compile_receipts",
                         profile.policy.minimum_compile_receipts) &&
        json_push_kv_int(&exact, "minimum_test_receipts",
                         profile.policy.minimum_test_receipts) &&
        json_push_kv_int(&exact, "minimum_fuzz_receipts",
                         profile.policy.minimum_fuzz_receipts) &&
        json_push_kv_int(&exact, "minimum_reviews",
                         profile.policy.minimum_reviews) &&
        json_push_kv_int(&exact, "minimum_matching_receipts",
                         profile.policy.minimum_matching_receipts) &&
        json_push_kv_int(&exact, "maximum_proof_age_seconds",
                         profile.policy.maximum_proof_age_seconds);
    json_init(out);
    json_set_object(out);
    if (ok) {
        ok = json_push_kv_str(out, "name", profile.name) &&
             json_push_kv_bool(out, "package_build", true) &&
             json_push_kv_bool(out, "declared_tests", true) &&
             json_push_kv_bool(out, "warning_fatal",
                               profile.warning_fatal) &&
             json_push_kv_bool(out, "sanitizers", profile.sanitizers) &&
             json_push_kv_bool(out, "deterministic_fuzz",
                               profile.deterministic_fuzz) &&
             json_push_kv_bool(out, "local_reproduction",
                               profile.local_reproduction) &&
             json_push_kv_bool(out, "separate_review",
                               profile.separate_review) &&
             json_push_kv_bool(out, "approved_reproduction",
                               profile.approved_reproduction) &&
             json_push_kv(out, "exact_policy", &exact);
    }
    json_free(&exact);
    return ok;
}

static bool zproject_total_bytes(const struct vcs_package_manifest *manifest,
                                 uint64_t *out)
{
    uint64_t total = 0;
    for (size_t i = 0; i < manifest->count; i++) {
        if (!zcl_u64_add(total, manifest->files[i].size, &total)) {
            *out = 0;
            return false;
        }
    }
    *out = total;
    return true;
}

void zcl_native_handle_zcode_project_inspect(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply) return;
    const char *workspace = zproject_str(request->input, "workspace");
    if (!workspace || !workspace[0]) {
        zproject_fail(reply, "BAD_WORKSPACE",
                      "workspace must name one existing C23 package directory");
        return;
    }
    struct vcs_package_prepare_options options = {
        .dir = workspace,
        .publisher_sequence = 1,
        .reward_address = "",
        .chain_id = "zclassic-main",
    };
    memcpy(options.publisher_pubkey, zproject_inspection_pubkey,
           sizeof(zproject_inspection_pubkey));
    struct vcs_package_prepared prepared;
    char detail[256] = {0};
    enum vcs_package_prepare_error err = vcs_package_prepare(
        &options, &prepared, detail, sizeof(detail));
    if (err != VCS_PACKAGE_PREPARE_OK) {
        struct zproject_init_plan plan;
        struct vcs_package_prepared scan;
        char plan_detail[256] = {0};
        if (zproject_plan_derive(request->input, &plan, &scan, plan_detail,
                                 sizeof(plan_detail))) {
            uint64_t total_bytes = 0;
            bool ok = zproject_total_bytes(&scan.manifest, &total_bytes) &&
                      zproject_render_plan(&reply->data, &plan, &scan) &&
                      json_push_kv_int(&reply->data, "file_count",
                                       (int64_t)scan.manifest.count) &&
                      json_push_kv_int(&reply->data, "total_project_bytes",
                                       (int64_t)total_bytes) &&
                      json_push_kv_bool(&reply->data,
                                        "existing_package_config", false) &&
                      json_push_kv_str(&reply->data, "suggested_profile",
                                       "standard") &&
                      json_push_kv_str(&reply->data, "next_safe_command",
                                       "zcode project init plan");
            vcs_package_prepared_free(&scan);
            if (!ok)
                zproject_fail(reply, "PROJECT_INSPECT_OUTPUT",
                              "the bounded initialization proposal could not be rendered");
            return;
        }
        vcs_package_prepared_free(&scan);
        char message[384];
        (void)snprintf(message, sizeof(message), "%s: %s%s%s",
                       vcs_package_prepare_error_string(err), detail,
                       plan_detail[0] ? "; initialization: " : "",
                       plan_detail);
        zproject_fail(reply, "PROJECT_INSPECT_FAILED", message);
        return;
    }

    uint64_t total_bytes = 0;
    struct json_value layout, expert, profile, limits, scopes;
    json_init(&layout);
    json_init(&expert);
    json_init(&profile);
    bool ok = zproject_total_bytes(&prepared.manifest, &total_bytes) &&
              zproject_render_layout(&layout, &prepared) &&
              zproject_render_expert(&expert, &prepared) &&
              zproject_render_profile(&profile);
    json_init(&limits); json_set_object(&limits);
    json_init(&scopes); json_set_array(&scopes);
    if (ok) {
        const struct vcs_package_recipe_strings *lists[] = {
            &prepared.recipe.include_dirs,
        };
        for (size_t i = 0; ok && i < lists[0]->count; i++) {
            struct json_value value;
            json_init(&value); json_set_str(&value, lists[0]->items[i]);
            ok = json_push_back(&scopes, &value);
            json_free(&value);
        }
        struct json_value src, tests;
        json_init(&src); json_set_str(&src, "src");
        json_init(&tests); json_set_str(&tests, "tests");
        if (ok) ok = json_push_back(&scopes, &src);
        if (ok && prepared.recipe.test_sources.count != 0)
            ok = json_push_back(&scopes, &tests);
        json_free(&src); json_free(&tests);
    }
    if (ok) {
        ok = json_push_kv_int(&limits, "maximum_test_seconds",
                              prepared.recipe.maximum_test_seconds) &&
             json_push_kv_int(&limits, "maximum_memory_bytes",
                              (int64_t)prepared.recipe.maximum_memory_bytes) &&
             json_push_kv_str(&reply->data, "name", prepared.release.name) &&
             json_push_kv_str(&reply->data, "semver",
                              prepared.release.semver) &&
             json_push_kv_str(&reply->data, "license",
                              prepared.release.license) &&
             json_push_kv_int(&reply->data, "file_count",
                              (int64_t)prepared.manifest.count) &&
             json_push_kv_int(&reply->data, "total_project_bytes",
                              (int64_t)total_bytes) &&
             json_push_kv(&reply->data, "layout", &layout) &&
             json_push_kv(&reply->data, "likely_write_scopes", &scopes) &&
             json_push_kv(&reply->data, "resource_ceilings", &limits) &&
             json_push_kv_str(&reply->data, "suggested_profile", "standard") &&
             json_push_kv(&reply->data, "proof_profile", &profile) &&
             json_push_kv_bool(&reply->data, "existing_package_config", true) &&
             json_push_kv_bool(&reply->data, "read_only", true) &&
             json_push_kv_str(&reply->data, "next_safe_command",
                              "zcode work start") &&
             json_push_kv(&reply->data, "expert", &expert);
    }
    json_free(&scopes); json_free(&limits); json_free(&profile);
    json_free(&expert);
    json_free(&layout);
    vcs_package_prepared_free(&prepared);
    if (!ok)
        zproject_fail(reply, "PROJECT_INSPECT_OUTPUT",
                      "the bounded project summary could not be rendered");
}

void zcl_native_handle_zcode_project_init_plan(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *workspace = zproject_str(request->input, "workspace");
    if (!workspace || !workspace[0]) {
        zproject_fail_at(reply, "BAD_WORKSPACE", "init_plan",
                         "workspace must name one existing C23 package directory",
                         "zcode project inspect");
        return;
    }
    struct zproject_init_plan plan;
    struct vcs_package_prepared scan;
    char detail[256] = {0};
    if (!zproject_plan_derive(request->input, &plan, &scan, detail,
                              sizeof(detail))) {
        vcs_package_prepared_free(&scan);
        zproject_fail_at(reply, "PROJECT_INIT_PLAN_FAILED", "init_plan",
                         detail[0] ? detail : "initialization plan rejected",
                         "zcode project inspect");
        return;
    }
    bool ok = zproject_render_plan(&reply->data, &plan, &scan) &&
              json_push_kv_str(&reply->data, "state", "PLANNED") &&
              json_push_kv_bool(&reply->data, "writes_workspace", false) &&
              json_push_kv_str(&reply->data, "next_safe_command",
                               "zcode project init commit");
    vcs_package_prepared_free(&scan);
    if (!ok)
        zproject_fail_at(reply, "PROJECT_INIT_PLAN_OUTPUT", "init_plan",
                         "the bounded initialization plan could not be rendered",
                         "zcode project inspect");
}

#if !defined(_WIN32)
static bool zproject_write_all(int fd, const char *text)
{
    size_t off = 0, len = strlen(text);
    while (off < len) {
        ssize_t wrote = write(fd, text + off, len - off);
        if (wrote < 0 && errno == EINTR)
            continue;
        if (wrote <= 0)
            return false;
        off += (size_t)wrote;
    }
    return true;
}
#endif

void zcl_native_handle_zcode_project_init_commit(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *workspace = zproject_str(request->input, "workspace");
    const char *plan_hex = zproject_str(request->input, "plan_id");
    uint8_t requested_plan[32];
    if (!workspace || !workspace[0] || !plan_hex ||
        !zcl_hex_decode_lower(plan_hex, requested_plan,
                              sizeof(requested_plan)) ||
        !zproject_bool(request->input, "confirm")) {
        zproject_fail_at(reply, "BAD_INIT_COMMIT_INPUT", "init_commit",
                         "workspace, the lowercase plan_id from init plan, and confirm:true are required",
                         "zcode project init plan");
        return;
    }
    struct zproject_init_plan plan;
    struct vcs_package_prepared scan;
    char detail[256] = {0};
    if (!zproject_plan_derive(request->input, &plan, &scan, detail,
                              sizeof(detail))) {
        vcs_package_prepared_free(&scan);
        zproject_fail_at(reply, "PROJECT_INIT_RECHECK_FAILED", "init_commit",
                         detail[0] ? detail : "initialization recheck rejected",
                         "zcode project init plan");
        return;
    }
    vcs_package_prepared_free(&scan);
    if (memcmp(requested_plan, plan.plan_id, sizeof(requested_plan)) != 0) {
        zproject_fail_at(reply, "STALE_INIT_PLAN", "init_commit",
                         "workspace bytes or corrected configuration changed after planning",
                         "zcode project init plan");
        return;
    }
#if defined(_WIN32)
    struct platform_directory_transaction root;
    struct platform_directory_child staged;
    platform_directory_transaction_init(&root);
    platform_directory_child_init(&staged);
    if (!platform_directory_transaction_open(&root, workspace)) {
        zproject_fail_at(reply, "PROJECT_INIT_OPEN", "init_commit",
                         "workspace could not be reopened as a private real directory",
                         "zcode project init plan");
        return;
    }
    char staged_leaf[80];
    int staged_n = snprintf(staged_leaf, sizeof(staged_leaf),
                            ".zcode-package.%ld.tmp", (long)_getpid());
    bool staged_created = false;
    size_t configuration_len = strlen(plan.configuration);
    bool written = staged_n > 0 && (size_t)staged_n < sizeof(staged_leaf) &&
        platform_directory_child_create(&root, staged_leaf, &staged) &&
        (staged_created = true) &&
        platform_directory_child_write_exact(&staged, plan.configuration,
                                             configuration_len, 0) &&
        platform_directory_child_flush(&staged) &&
        platform_directory_child_replace(&root, &staged,
                                         VCS_PACKAGE_DEPS_META_PATH, true) &&
        platform_directory_transaction_flush(&root);
    platform_directory_child_close(&staged);
    if (!written && staged_created)
        (void)platform_directory_child_unlink(&root, staged_leaf, true);
    platform_directory_transaction_close(&root);
    if (!written) {
        zproject_fail_at(reply, "PROJECT_INIT_OVERWRITE_REFUSED", "init_commit",
                         "metadata exists or its atomic durable creation failed",
                         "zcode project status");
        return;
    }
#else
    int root = open(workspace, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root < 0) {
        zproject_fail_at(reply, "PROJECT_INIT_OPEN", "init_commit",
                         "workspace could not be reopened without following a symlink",
                         "zcode project init plan");
        return;
    }
    int fd = openat(root, VCS_PACKAGE_DEPS_META_PATH,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    0644);
    if (fd < 0) {
        close(root);
        zproject_fail_at(reply, "PROJECT_INIT_OVERWRITE_REFUSED", "init_commit",
                         "zcode-package.json already exists or cannot be created exclusively",
                         "zcode project status");
        return;
    }
    bool written = zproject_write_all(fd, plan.configuration) && fsync(fd) == 0;
    int close_rc = close(fd);
    if (close_rc != 0)
        written = false;
    if (written && fsync(root) != 0)
        written = false;
    if (!written)
        (void)unlinkat(root, VCS_PACKAGE_DEPS_META_PATH, 0);
    close(root);
    if (!written) {
        zproject_fail_at(reply, "PROJECT_INIT_WRITE_FAILED", "init_commit",
                         "exclusive metadata write did not reach durable completion",
                         "zcode project init plan");
        return;
    }
#endif
    struct vcs_package_prepare_options options = {
        .dir = workspace,
        .publisher_sequence = 1,
        .reward_address = "",
        .chain_id = "zclassic-main",
    };
    memcpy(options.publisher_pubkey, zproject_inspection_pubkey,
           sizeof(zproject_inspection_pubkey));
    struct vcs_package_prepared prepared;
    detail[0] = '\0';
    enum vcs_package_prepare_error err = vcs_package_prepare(
        &options, &prepared, detail, sizeof(detail));
    if (err != VCS_PACKAGE_PREPARE_OK) {
#if defined(_WIN32)
        struct platform_directory_transaction cleanup_root;
        platform_directory_transaction_init(&cleanup_root);
        if (platform_directory_transaction_open(&cleanup_root, workspace)) {
            (void)platform_directory_child_unlink(
                &cleanup_root, VCS_PACKAGE_DEPS_META_PATH, true);
            platform_directory_transaction_close(&cleanup_root);
        }
#else
        int cleanup_root = open(workspace, O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                           O_NOFOLLOW);
        if (cleanup_root >= 0) {
            (void)unlinkat(cleanup_root, VCS_PACKAGE_DEPS_META_PATH, 0);
            close(cleanup_root);
        }
#endif
        vcs_package_prepared_free(&prepared);
        zproject_fail_at(reply, "PROJECT_INIT_VALIDATION_FAILED", "init_commit",
                         detail[0] ? detail : "created metadata did not prepare",
                         "zcode project init plan");
        return;
    }
    char package_hex[65];
    zcl_hex_encode(prepared.package_root, 32, package_hex);
    struct json_value expert;
    json_init(&expert); json_set_object(&expert);
    bool ok = json_push_kv_str(&expert, "package_root", package_hex) &&
              json_push_kv_str(&reply->data, "state", "READY") &&
              json_push_kv_bool(&reply->data, "created", true) &&
              json_push_kv_str(&reply->data, "path",
                               VCS_PACKAGE_DEPS_META_PATH) &&
              json_push_kv_str(&reply->data, "name", prepared.release.name) &&
              json_push_kv_str(&reply->data, "semver",
                               prepared.release.semver) &&
              json_push_kv_str(&reply->data, "license",
                               prepared.release.license) &&
              json_push_kv_str(&reply->data, "next_safe_command",
                               "zcode project status") &&
              json_push_kv(&reply->data, "expert", &expert);
    json_free(&expert);
    vcs_package_prepared_free(&prepared);
    if (!ok)
        zproject_fail_at(reply, "PROJECT_INIT_OUTPUT", "init_commit",
                         "initialized project summary could not be rendered",
                         "zcode project status");
}

void zcl_native_handle_zcode_project_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *workspace = zproject_str(request->input, "workspace");
    if (!workspace || !workspace[0]) {
        zproject_fail_at(reply, "BAD_WORKSPACE", "status",
                         "workspace must name one existing C23 package directory",
                         "zcode project inspect");
        return;
    }
    struct vcs_package_prepare_options options = {
        .dir = workspace,
        .publisher_sequence = 1,
        .reward_address = "",
        .chain_id = "zclassic-main",
    };
    memcpy(options.publisher_pubkey, zproject_inspection_pubkey,
           sizeof(zproject_inspection_pubkey));
    struct vcs_package_prepared prepared;
    char detail[256] = {0};
    enum vcs_package_prepare_error err = vcs_package_prepare(
        &options, &prepared, detail, sizeof(detail));
    if (err == VCS_PACKAGE_PREPARE_OK) {
        struct json_value expert;
        bool ok = zproject_render_expert(&expert, &prepared) &&
                  json_push_kv_str(&reply->data, "state", "READY") &&
                  json_push_kv_str(&reply->data, "name",
                                   prepared.release.name) &&
                  json_push_kv_str(&reply->data, "semver",
                                   prepared.release.semver) &&
                  json_push_kv_str(&reply->data, "license",
                                   prepared.release.license) &&
                  json_push_kv_bool(&reply->data, "read_only", true) &&
                  json_push_kv_str(&reply->data, "next_safe_command",
                                   "zcode work start") &&
                  json_push_kv(&reply->data, "expert", &expert);
        json_free(&expert);
        vcs_package_prepared_free(&prepared);
        if (!ok)
            zproject_fail_at(reply, "PROJECT_STATUS_OUTPUT", "status",
                             "project status could not be rendered",
                             "zcode project inspect");
        return;
    }
    struct zproject_init_plan plan;
    struct vcs_package_prepared scan;
    char plan_detail[256] = {0};
    if (zproject_plan_derive(request->input, &plan, &scan, plan_detail,
                             sizeof(plan_detail))) {
        vcs_package_prepared_free(&scan);
        (void)json_push_kv_str(&reply->data, "state",
                               "INITIALIZATION_REQUIRED");
        (void)json_push_kv_bool(&reply->data, "read_only", true);
        (void)json_push_kv_str(&reply->data, "next_safe_command",
                               "zcode project init plan");
        return;
    }
    vcs_package_prepared_free(&scan);
    char message[512];
    (void)snprintf(message, sizeof(message), "%s: %s%s%s",
                   vcs_package_prepare_error_string(err), detail,
                   plan_detail[0] ? "; initialization: " : "", plan_detail);
    zproject_fail_at(reply, "PROJECT_STATUS_BLOCKED", "status", message,
                     "zcode project inspect");
}
