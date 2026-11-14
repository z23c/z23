/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * Local key-format falsification. No authority or reusable artifact. */
#include "verify/fixed_result_key_v2.h"
#include "verify/fixed_result_contract.h"

#include "base/hex.h"
#include "platform/fd_path.h"
#include "sha3/sha3.h"

#include <stdio.h>
#include <string.h>

struct fixture {
    uint8_t profile[65536], pp[32];
    size_t profile_len;
    struct zcl_fixed_result_v2_roots roots;
    char target_a[160], target_b[160], profile_copy[65536], cwd_arg[4096];
    const char *argv[(ZCL_FR_PROFILE_ARGC + 10u)];
    const char *envp[4];
    struct zcl_fixed_result_v2_expected baseline, observed;
    const char *why;
};

static void hash(const uint8_t *p, size_t n, uint8_t out[32])
{
    struct sha3_256_ctx h;
    sha3_256_init(&h);
    sha3_256_write(&h, p, n);
    sha3_256_finalize(&h, out);
}

static bool same_expected(const struct zcl_fixed_result_v2_expected *a,
                          const struct zcl_fixed_result_v2_expected *b)
{
    return strcmp(a->toolchain_id, b->toolchain_id) == 0 &&
           strcmp(a->argv_norm, b->argv_norm) == 0 &&
           memcmp(a->expected.pp_sha3, b->expected.pp_sha3, 32) == 0 &&
           memcmp(a->expected.closure_sha3, b->expected.closure_sha3, 32) == 0;
}

static bool make_actual(struct fixture *f)
{
    memcpy(f->profile_copy, f->profile, f->profile_len);
    size_t count = 0;
    char *line = f->profile_copy;
    for (size_t i = 0; i < f->profile_len; i++) {
        if (f->profile_copy[i] != '\n') continue;
        if (count >= ZCL_FR_PROFILE_ARGC) return false;
        f->profile_copy[i] = '\0';
        char *tag = strstr(line, "@CWD@");
        if (tag) {
            int used = snprintf(f->cwd_arg, sizeof(f->cwd_arg), "%.*s%s%s",
                                (int)(tag - line), line, "/tmp/z23-proof-A",
                                tag + sizeof("@CWD@") - 1);
            if (used < 0 || used >= (int)sizeof(f->cwd_arg)) return false;
            f->argv[count] = f->cwd_arg;
        } else f->argv[count] = line;
        count++;
        line = f->profile_copy + i + 1;
    }
    if (count != ZCL_FR_PROFILE_ARGC) return false;
    static const char *const tail[10] = {
        "-MMD", "-MP", "-MF", "/work/result.ABC123/deps.d", "-MT", NULL,
        "-c", "-o", "/work/result.ABC123/result.o",
        "platform/modules/base/src/result.c"
    };
    for (size_t i = 0; i < 10; i++) f->argv[ZCL_FR_PROFILE_ARGC + i] = tail[i];
    return true;
}

static bool setup(struct fixture *f)
{
    static const char path[] = "tools/verify/fixed_result_fast.args";
    FILE *file = fopen(path, "rb");
    if (!file) return false;
    f->profile_len = fread(f->profile, 1, sizeof(f->profile), file);
    if (ferror(file) || fclose(file) != 0 || f->profile_len != 5939)
        return false;
    uint8_t *fields = (uint8_t *)&f->roots;
    for (size_t i = 0; i < sizeof(f->roots); i++)
        fields[i] = (uint8_t)(1 + i / 32);
    hash(f->profile, f->profile_len, f->roots.profile_args);
    zcl_fr_env_fixed_root(f->roots.environment);
    f->envp[0] = "LC_ALL=C";
    f->envp[1] = "TZ=UTC";
    f->envp[2] = "TMPDIR=/tmp";
    f->envp[3] = "PATH=/usr/bin:/bin";
    memset(f->pp, 0x5a, sizeof(f->pp));
    static const char *const prefix = "build/test-obj/epochs/";
    static const char *const suffix = "/platform/modules/base/src/result.o";
    char a[65], b[65];
    memset(a, 'a', 64); a[64] = '\0';
    memset(b, 'b', 64); b[64] = '\0';
    if (snprintf(f->target_a, sizeof(f->target_a), "%s%s%s", prefix, a,
                 suffix) >= (int)sizeof(f->target_a) ||
        snprintf(f->target_b, sizeof(f->target_b), "%s%s%s", prefix, b,
                 suffix) >= (int)sizeof(f->target_b)) return false;
    if (!make_actual(f)) return false;
    f->argv[ZCL_FR_PROFILE_ARGC + 5] = f->target_a;
    return true;
}

static bool construct(struct fixture *f, const uint8_t source[32],
                      const uint8_t pp[32], const char *target,
                      const char *const *envp, int dirfd)
{
    return zcl_fixed_result_expected_v2(
        &f->roots, source, pp, target, f->profile, f->profile_len,
        "/tmp/z23-proof-A", f->argv, (ZCL_FR_PROFILE_ARGC + 10u), envp, 4, dirfd,
        &f->observed, &f->why);
}

static bool initial_and_epoch(struct fixture *f)
{
    if (!construct(f, f->roots.source_content, f->pp, f->target_a,
                   f->envp, -1)) return false;
    f->baseline = f->observed;
    /* The text pointers in the embedded expected value point into baseline. */
    f->argv[ZCL_FR_PROFILE_ARGC + 5] = f->target_b;
    bool valid = construct(f, f->roots.source_content, f->pp, f->target_b,
                           f->envp, -1) &&
                 same_expected(&f->baseline, &f->observed);
    f->argv[ZCL_FR_PROFILE_ARGC + 5] = f->target_a;
    return valid;
}

static bool fd_path_checks(struct fixture *f)
{
    char dep[4096], obj[4096], short_obj[4096];
    if (!platform_dirfd_child_path(dep, sizeof(dep), 17, "result.d") ||
        !platform_dirfd_child_path(obj, sizeof(obj), 17, "result.o"))
        return false;
    f->argv[ZCL_FR_PROFILE_ARGC + 3] = dep;
    f->argv[ZCL_FR_PROFILE_ARGC + 8] = obj;
    if (!construct(f, f->roots.source_content, f->pp, f->target_a,
                   f->envp, 17) ||
        !same_expected(&f->baseline, &f->observed)) return false;
    memcpy(short_obj, obj, strlen(obj) + 1);
    short_obj[strlen(short_obj) - strlen("result.o")] = '\0';
    f->argv[ZCL_FR_PROFILE_ARGC + 8] = short_obj;
    bool refused = !construct(f, f->roots.source_content, f->pp,
                              f->target_a, f->envp, 17);
    f->argv[ZCL_FR_PROFILE_ARGC + 3] = "/work/result.ABC123/deps.d";
    f->argv[ZCL_FR_PROFILE_ARGC + 8] = "/work/result.ABC123/result.o";
    return refused;
}

static bool output_path_rejections(struct fixture *f)
{
    if (construct(f, f->roots.source_content, f->pp, "result.o",
                  f->envp, -1)) return false;
    f->argv[ZCL_FR_PROFILE_ARGC + 3] = "";
    if (construct(f, f->roots.source_content, f->pp, f->target_a,
                  f->envp, -1)) return false;
    f->argv[ZCL_FR_PROFILE_ARGC + 3] = "/dev/null";
    if (construct(f, f->roots.source_content, f->pp, f->target_a,
                  f->envp, -1)) return false;
    f->argv[ZCL_FR_PROFILE_ARGC + 3] = "/work/result.ABC123/deps.d";
    f->argv[ZCL_FR_PROFILE_ARGC + 8] = "";
    if (construct(f, f->roots.source_content, f->pp, f->target_a,
                  f->envp, -1)) return false;
    f->argv[ZCL_FR_PROFILE_ARGC + 8] = "/work/result.XYZ999/result.o";
    if (construct(f, f->roots.source_content, f->pp, f->target_a,
                  f->envp, -1)) return false;
    f->argv[ZCL_FR_PROFILE_ARGC + 8] = "/work/result.ABC123/result.o";
    return true;
}

static bool invocation_rejections(struct fixture *f)
{
    const char *saved = f->argv[1];
    f->argv[1] = "-std=c2x";
    if (construct(f, f->roots.source_content, f->pp, f->target_a,
                  f->envp, -1)) return false;
    f->argv[1] = saved;
    static const char *const bad_envp[4] = {
        "LC_ALL=C", "TZ=UTC", "TMPDIR=/tmp", "PATH=/usr/local/bin:/usr/bin"
    };
    return !construct(f, f->roots.source_content, f->pp, f->target_a,
                      bad_envp, -1);
}

static bool root_mutations(struct fixture *f)
{
    f->roots.check_image[0] ^= 1;
    if (!construct(f, f->roots.source_content, f->pp, f->target_a,
                   f->envp, -1) ||
        same_expected(&f->baseline, &f->observed)) return false;
    f->roots.check_image[0] ^= 1;
    f->roots.tool_image[0] ^= 1;
    uint8_t changed_pp[32];
    memcpy(changed_pp, f->pp, 32);
    changed_pp[0] ^= 1;
    if (!construct(f, f->roots.source_content, changed_pp, f->target_a,
                   f->envp, -1) ||
        same_expected(&f->baseline, &f->observed)) return false;
    f->roots.environment[0] ^= 1;
    if (construct(f, f->roots.source_content, f->pp, f->target_a,
                  f->envp, -1) || !f->why ||
        strcmp(f->why, "fixed_result_v2_root_mismatch") != 0) return false;
    f->roots.environment[0] ^= 1;
    if (!construct(f, f->roots.source_content, f->pp, f->target_a,
                   f->envp, -1) ||
        same_expected(&f->baseline, &f->observed)) return false;
    f->roots.tool_image[0] ^= 1;
    return true;
}

static bool source_profile_mutations(struct fixture *f)
{
    uint8_t changed_source[32];
    memcpy(changed_source, f->roots.source_content, 32);
    changed_source[0] ^= 1;
    if (construct(f, changed_source, f->pp, f->target_a, f->envp, -1) ||
        !f->why || strcmp(f->why, "fixed_result_v2_root_mismatch") != 0)
        return false;
    f->profile[0] ^= 1;
    return !construct(f, f->roots.source_content, f->pp, f->target_a,
                      f->envp, -1);
}

int main(void)
{
    struct fixture f = {0};
    if (!setup(&f)) return fprintf(stderr, "fixture_setup_failed\n"), 2;
    if (!initial_and_epoch(&f)) return fprintf(stderr, "epoch_failed\n"), 2;
    if (!fd_path_checks(&f)) return fprintf(stderr, "fd_paths_failed\n"), 2;
    if (!output_path_rejections(&f))
        return fprintf(stderr, "output_paths_failed\n"), 2;
    if (!invocation_rejections(&f))
        return fprintf(stderr, "invocation_failed\n"), 2;
    if (!root_mutations(&f)) return fprintf(stderr, "roots_failed\n"), 2;
    if (!source_profile_mutations(&f))
        return fprintf(stderr, "source_profile_failed\n"), 2;
    char closure[65];
    zcl_hex_encode(f.baseline.expected.closure_sha3, 32, closure);
    printf("fixed_result_v2_format_green=1 closure_sha3=%s "
           "target_normalized=1 fd_path_normalized=1 "
           "changed_check_cold=1 changed_tool_cold=1 "
           "changed_pp_cold=1 changed_env_cold=1 "
           "changed_source_cold=1 changed_profile_cold=1 "
           "changed_actual_argv_cold=1 changed_actual_env_cold=1 "
           "malformed_output_cold=1 wrong_dep_path_cold=1 "
           "mixed_workdir_cold=1 short_fd_object_cold=1 "
           "compiler_launches=0 proof_launches_avoided=0 attest_eligible=0\n",
           closure);
    return 0;
}
