/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * Pure test-fast result key canonicalization, never an eligibility decision. */
#include "verify/fixed_result_key_v2.h"

#include "base/hex.h"
#include "platform/fd_path.h"
#include "sha3/sha3.h"
#include "verify/fixed_result_contract.h"

#include <stdio.h>
#include <string.h>

#define SOURCE ZCL_FR_SOURCE

static void sha3_bytes(const uint8_t *p, size_t n, uint8_t out[32])
{
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    sha3_256_write(&h, p, n);
    sha3_256_finalize(&h, out);
}

static bool zero_hash(const uint8_t h[32])
{
    static const uint8_t zero[32] = {0};
    return memcmp(h, zero, 32) == 0;
}

static bool target_ok(const char *target)
{
    return target && zcl_fr_target_check(target, strlen(target)) == NULL;
}

static bool append_arg(char out[16384], size_t *used,
                       const uint8_t *arg, size_t len)
{
    if (!arg || len == 0 || memchr(arg, '\0', len)) return false;
    char prefix[32];
    int n = snprintf(prefix, sizeof(prefix), "%zu:", len);
    if (n <= 0 || n >= (int)sizeof(prefix) ||
        *used + (size_t)n + len >= 16384) return false;
    memcpy(out + *used, prefix, (size_t)n);
    *used += (size_t)n;
    memcpy(out + *used, arg, len);
    *used += len;
    out[*used] = '\0';
    return true;
}

static bool append_literal(char out[16384], size_t *used, const char *s)
{
    return append_arg(out, used, (const uint8_t *)s, strlen(s));
}

static bool actual_arg_matches(const uint8_t *p, size_t n, const char *cwd,
                               const char *actual)
{
    if (!actual) return false;
    static const char marker[] = "@CWD@";
    const uint8_t *tag = NULL;
    for (size_t i = 0; i + sizeof(marker) - 1 <= n; i++)
        if (memcmp(p + i, marker, sizeof(marker) - 1) == 0) {
            if (tag) return false;
            tag = p + i;
        }
    if (!tag) return strlen(actual) == n && memcmp(actual, p, n) == 0;
    size_t before = (size_t)(tag - p);
    size_t after = n - before - (sizeof(marker) - 1);
    size_t cwd_len = strlen(cwd);
    return strlen(actual) == before + cwd_len + after &&
           memcmp(actual, p, before) == 0 &&
           memcmp(actual + before, cwd, cwd_len) == 0 &&
           memcmp(actual + before + cwd_len,
                  tag + sizeof(marker) - 1, after) == 0;
}

static bool work_paths_ok(const char *dep, const char *obj)
{
    static const char work[] = "/work/result.";
    if (strncmp(dep, work, sizeof(work) - 1) != 0 ||
        strncmp(obj, work, sizeof(work) - 1) != 0) return false;
    const char *d = dep + sizeof(work) - 1;
    const char *o = obj + sizeof(work) - 1;
    if (strlen(d) != 6 + sizeof("/deps.d") - 1 ||
        strlen(o) != 6 + sizeof("/result.o") - 1) return false;
    for (size_t i = 0; i < 6; i++) {
        bool alnum = (d[i] >= '0' && d[i] <= '9') ||
                     (d[i] >= 'A' && d[i] <= 'Z') ||
                     (d[i] >= 'a' && d[i] <= 'z');
        if (!alnum || d[i] != o[i]) return false;
    }
    return strcmp(d + 6, "/deps.d") == 0 &&
           strcmp(o + 6, "/result.o") == 0;
}

static bool fd_paths_ok(const char *dep, const char *obj, int dirfd)
{
    if (dirfd < 3) return false;
    char expected_dep[4096], expected_obj[4096];
    return platform_dirfd_child_path(expected_dep, sizeof(expected_dep),
                                     dirfd, "result.d") &&
           platform_dirfd_child_path(expected_obj, sizeof(expected_obj),
                                     dirfd, "result.o") &&
           strcmp(dep, expected_dep) == 0 && strcmp(obj, expected_obj) == 0;
}

static bool actual_tail_ok(const char *const *argv, size_t argc,
                           const char *target, int output_dirfd)
{
    static const char *const exact[] = {
        "-MMD", "-MP", "-MF", NULL, "-MT", NULL,
        "-c", "-o", NULL, SOURCE
    };
    if (!argv || argc != ZCL_FR_PROFILE_ARGC + sizeof(exact) / sizeof(exact[0])) return false;
    for (size_t i = 0; i < sizeof(exact) / sizeof(exact[0]); i++) {
        const char *actual = argv[ZCL_FR_PROFILE_ARGC + i];
        if (!actual) return false;
        if (exact[i] && strcmp(actual, exact[i]) != 0) return false;
    }
    if (strcmp(argv[ZCL_FR_PROFILE_ARGC + 5], target) != 0) return false;
    const char *dep = argv[ZCL_FR_PROFILE_ARGC + 3], *obj = argv[ZCL_FR_PROFILE_ARGC + 8];
    return output_dirfd == -1 ? work_paths_ok(dep, obj) :
           fd_paths_ok(dep, obj, output_dirfd);
}

static bool profile_args_append(const uint8_t *profile, size_t len,
                                const char *cwd, const char *const *actual,
                                char out[16384], size_t *used)
{
    size_t start = 0, count = 0;
    for (size_t i = 0; i < len; i++) {
        if (profile[i] != '\n') continue;
        if (count >= ZCL_FR_PROFILE_ARGC || i == start ||
            !actual_arg_matches(profile + start, i - start, cwd,
                                actual[count]) ||
            !append_arg(out, used, profile + start, i - start))
            return false;
        count++;
        start = i + 1;
    }
    return count == ZCL_FR_PROFILE_ARGC && start == len;
}

static bool tail_args_append(char out[16384], size_t *used)
{
    static const char *const tail[] = {
        "-MMD", "-MP", "-MF", "<DEP>", "-MT", "<EPOCH_TARGET>",
        "-c", "-o", "<OBJECT>", SOURCE
    };
    for (size_t i = 0; i < sizeof(tail) / sizeof(tail[0]); i++)
        if (!append_literal(out, used, tail[i])) return false;
    return true;
}

static bool build_argv(const uint8_t *profile, size_t len,
                       const char *cwd, const char *const *actual,
                       size_t actual_count, const char *target,
                       int output_dirfd, char out[16384])
{
    static const char domain[] = "z23verify.fixed_result.argv.v2\n";
    if (!profile || len == 0 || len > 65536 || profile[len - 1] != '\n' ||
        memchr(profile, '\0', len) || !cwd || cwd[0] != '/' ||
        strlen(cwd) > 2048 ||
        !actual_tail_ok(actual, actual_count, target, output_dirfd))
        return false;
    size_t used = sizeof(domain) - 1;
    memcpy(out, domain, used);
    out[used] = '\0';
    return profile_args_append(profile, len, cwd, actual, out, &used) &&
           tail_args_append(out, &used);
}

static bool fixed_roots_ok(const struct zcl_fixed_result_v2_roots *r)
{
    return zcl_fr_roots_check(r) == NULL;
}

static bool actual_env_ok(const char *const *envp, size_t count)
{
    return zcl_fr_env_check(envp, count) == NULL;
}

/* SHA3-256 of F(closure domain), the twelve labeled roots in pins order,
 * then recorded_cwd, source and argv_norm, each F(label) F(value). */
static void closure_hash(const struct zcl_fixed_result_v2_roots *r,
                         const char *argv, uint8_t out[32])
{
    struct sha3_256_ctx h;
    struct zcl_fr_writer w;
    sha3_256_init(&h);
    zcl_fr_writer_hash(&w, &h);
    zcl_fr_put(&w, ZCL_FR_DOMAIN_CLOSURE, sizeof(ZCL_FR_DOMAIN_CLOSURE) - 1);
    for (size_t i = 0; i < ZCL_FR_ROOT_COUNT; i++)
        zcl_fr_put_hash(&w, zcl_fr_root_label(i), zcl_fr_root_at(r, i));
    zcl_fr_put_text(&w, "recorded_cwd", ZCL_FR_CWD);
    zcl_fr_put_text(&w, "source", SOURCE);
    zcl_fr_put_text(&w, "argv_norm", argv);
    sha3_256_finalize(&h, out);
}
static bool profile_and_argv_ok(
    const struct zcl_fixed_result_v2_roots *roots,
    const uint8_t *profile_bytes, size_t profile_len,
    const char *actual_physical_cwd, const char *const *actual_argv,
    size_t actual_argc, const char *actual_epoch_target,
    int actual_output_dirfd, char argv_norm[16384])
{
    uint8_t profile_hash[32];
    char profile_hex[65];
    sha3_bytes(profile_bytes, profile_len, profile_hash);
    zcl_hex_encode(profile_hash, 32, profile_hex);
    return strcmp(profile_hex, ZCL_FR_PROFILE_SHA3) == 0 &&
           memcmp(profile_hash, roots->profile_args, 32) == 0 &&
           build_argv(profile_bytes, profile_len, actual_physical_cwd,
                      actual_argv, actual_argc, actual_epoch_target,
                      actual_output_dirfd, argv_norm);
}

static bool fill_expected(const struct zcl_fixed_result_v2_roots *roots,
                          const uint8_t fresh_pp_sha3[32],
                          struct zcl_fixed_result_v2_expected *out)
{
    char tool_hex[65];
    zcl_hex_encode(roots->tool_image, 32, tool_hex);
    int n = snprintf(out->toolchain_id, sizeof(out->toolchain_id),
                     "z23.gcc14.fast_result.v2:%s", tool_hex);
    if (n <= 0 || n >= (int)sizeof(out->toolchain_id)) return false;
    out->expected.toolchain_id = (struct zcl_verify_attest_text){
        out->toolchain_id, (size_t)n
    };
    out->expected.argv_norm = (struct zcl_verify_attest_text){
        out->argv_norm, strlen(out->argv_norm)
    };
    out->expected.recorded_cwd = (struct zcl_verify_attest_text){
        ZCL_FR_CWD, sizeof(ZCL_FR_CWD) - 1
    };
    memcpy(out->expected.pp_sha3, fresh_pp_sha3, 32);
    closure_hash(roots, out->argv_norm, out->expected.closure_sha3);
    return true;
}

static bool constructor_arguments_ok(
    const struct zcl_fixed_result_v2_roots *roots,
    const uint8_t current_source_content[32],
    const uint8_t fresh_pp_sha3[32], const char *actual_epoch_target,
    const uint8_t *profile_bytes, size_t profile_len,
    const char *const *actual_envp, size_t actual_envc,
    const struct zcl_fixed_result_v2_expected *out)
{
    return roots && current_source_content && fresh_pp_sha3 && out &&
           profile_bytes && profile_len > 0 && profile_len <= 65536 &&
           target_ok(actual_epoch_target) &&
           actual_env_ok(actual_envp, actual_envc);
}

static bool constructor_roots_ok(
    const struct zcl_fixed_result_v2_roots *roots,
    const uint8_t current_source_content[32],
    const uint8_t fresh_pp_sha3[32])
{
    return fixed_roots_ok(roots) && !zero_hash(fresh_pp_sha3) &&
           memcmp(current_source_content, roots->source_content, 32) == 0;
}

bool zcl_fixed_result_expected_v2(
    const struct zcl_fixed_result_v2_roots *roots,
    const uint8_t current_source_content[32],
    const uint8_t fresh_pp_sha3[32],
    const char *actual_epoch_target,
    const uint8_t *profile_bytes, size_t profile_len,
    const char *actual_physical_cwd,
    const char *const *actual_argv, size_t actual_argc,
    const char *const *actual_envp, size_t actual_envc,
    int actual_output_dirfd,
    struct zcl_fixed_result_v2_expected *out, const char **why)
{
    if (why) *why = "fixed_result_v2_arguments_invalid";
    if (!constructor_arguments_ok(roots, current_source_content, fresh_pp_sha3,
                                  actual_epoch_target, profile_bytes,
                                  profile_len, actual_envp, actual_envc, out))
        return false;
    if (!constructor_roots_ok(roots, current_source_content, fresh_pp_sha3)) {
        if (why) *why = "fixed_result_v2_root_mismatch";
        return false;
    }
    if (!profile_and_argv_ok(roots, profile_bytes, profile_len,
                             actual_physical_cwd, actual_argv, actual_argc,
                             actual_epoch_target, actual_output_dirfd,
                             out->argv_norm)) {
        if (why) *why = "fixed_result_v2_profile_mismatch";
        return false;
    }
    if (!fill_expected(roots, fresh_pp_sha3, out)) return false;
    if (why) *why = NULL;
    return true;
}
