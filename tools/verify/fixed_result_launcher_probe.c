/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: Ineligible launcher preflight and pins v2 falsification on an
 *          unprivileged host. It builds the launcher, encodes a pins v2 file
 *          with it, and proves that file, a forged byte, a trailing byte, a
 *          v1 text pins file and the strict profile digest each parse or
 *          refuse by name. Run from the repository root through
 *          fixed_result_launcher_probe.sh; --selftest checks the helpers. */
#define _POSIX_C_SOURCE 200809L
#include "verify/probe_util.h"
#include "sha3/sha3.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define NROOTS 12u
#define STRICT_SHA3 \
    "5fb3b13597488c20a9f5aeca2b654fad92b39714d93069c12c082206977aadaf"

static const char *const CC_FLAGS[] = {
    "/usr/bin/cc", "-std=c23", "-Wall", "-Wextra", "-Werror", "-pedantic",
    "-Itools", "-Iplatform/modules/sha3/include",
    "-Iplatform/modules/base/include", "-Iplatform/modules/platform/include",
    nullptr};
static const char *const COMMON[] = {
    "tools/verify/fixed_result_contract.c", "tools/verify/fixed_result_source.c",
    "platform/modules/base/src/safe_alloc.c", "platform/modules/sha3/src/sha3.c",
    "platform/modules/platform/src/os_proc.c", nullptr};

static const char *g_script = "fixed_result_launcher_probe.sh";

struct probe {
    char repo[PU_PATH_MAX];
    char work[PU_PATH_MAX];
    char roots[NROOTS][65];
    const char *rootv[NROOTS + 3u];
};

static _Noreturn void fail(const char *why)
{
    fprintf(stderr, "fixed_result_launcher_probe_refuse=%s\n", why);
    exit(2);
}

static void compile(const struct probe *p, const char *extra, const char *src,
                    const char *exe)
{
    struct pu_argv a = {.n = 0};
    pu_argv_addv(&a, CC_FLAGS);
    if (extra) pu_argv_add(&a, extra);
    pu_argv_add(&a, src);
    pu_argv_addv(&a, COMMON);
    pu_argv_add(&a, "-o");
    pu_argv_add(&a, pu_at(p->work, exe));
    int rc = pu_run(&a, nullptr, nullptr);
    if (rc != 0) exit(rc > 0 ? rc : 1);
}

/* Run the launcher with one command word and optional extra arguments. */
static int launch(const struct probe *p, const char *const *args,
                  const char *out, const char *err)
{
    struct pu_argv a = {.n = 0};
    pu_argv_add(&a, pu_at(p->work, "launcher"));
    pu_argv_addv(&a, args);
    return pu_run(&a, out ? pu_at(p->work, out) : nullptr,
                  err ? pu_at(p->work, err) : nullptr);
}

static void expect_refusal(const struct probe *p, const char *const *args,
                           const char *token, const char *accepted,
                           const char *wrong)
{
    char line[160];
    if (launch(p, args, "out", "err") == 0) fail(accepted);
    snprintf(line, sizeof line, "fixed_result_launcher_refuse=%s", token);
    if (!pu_has_line(pu_at(p->work, "err"), line)) fail(wrong);
}

static void hex_of(const uint8_t d[32], char out[65])
{
    for (size_t i = 0; i < 32u; ++i) snprintf(out + 2u * i, 3u, "%02x", d[i]);
}

static void fast_args_digest(char out[65])
{
    static uint8_t buf[65536];
    uint8_t digest[32];
    struct sha3_256_ctx h;
    size_t n = 0;
    if (!pu_read("tools/verify/fixed_result_fast.args", (char *)buf,
                 sizeof buf, &n, false)) exit(1);
    sha3_256_init(&h);
    sha3_256_write(&h, buf, n);
    sha3_256_finalize(&h, digest);
    hex_of(digest, out);
}

static void fill_roots(struct probe *p)
{
    for (unsigned i = 0; i < NROOTS; ++i) {
        int n = snprintf(p->roots[i], sizeof p->roots[i], "%02x", i + 1u);
        for (unsigned j = 0; j < 31u; ++j) {
            size_t room = sizeof p->roots[i] - (size_t)n;
            if (snprintf(p->roots[i] + n, room, "ab") >= (int)room) exit(1);
            n += 2;
        }
    }
    fast_args_digest(p->roots[1]);
    memset(p->roots[11], 'c', 64);
    p->roots[11][64] = '\0';
    p->rootv[0] = "pins-encode";
    for (unsigned i = 0; i < NROOTS; ++i) p->rootv[i + 1u] = p->roots[i];
    p->rootv[NROOTS + 1u] = nullptr;
}

static bool is_hex64(const char *s)
{
    if (strlen(s) != 64u) return false;
    for (; *s; ++s)
        if (!((*s >= '0' && *s <= '9') || (*s >= 'a' && *s <= 'f')))
            return false;
    return true;
}

static void encode_with_env_root(struct probe *p)
{
    char hex[PU_PATH_MAX];
    struct pu_argv env = {.n = 0};
    pu_argv_add(&env, pu_at(p->work, "env"));
    expect_refusal(p, p->rootv, "contract_env_mismatch", "env_root_unchecked",
                   "env_wrong_refusal");
    compile(p, nullptr, "tools/verify/fixed_result_launcher_env.c", "env");
    if (pu_run(&env, pu_at(p->work, "root"), nullptr) != 0 ||
        !pu_read(pu_at(p->work, "root"), hex, sizeof hex, nullptr, true))
        exit(1);
    if (!is_hex64(hex)) fail("env_root_shape");
    memcpy(p->roots[7], hex, sizeof p->roots[7]);
    if (launch(p, p->rootv, "pins", "err") != 0) fail("pins_encode_refused");
}

static void check_parser(struct probe *p)
{
    struct pu_argv a = {.n = 0};
    pu_argv_add(&a, pu_at(p->work, "check"));
    pu_argv_add(&a, pu_at(p->work, "pins"));
    compile(p, "-I.", "tools/verify/fixed_result_launcher_check.c", "check");
    if (pu_run(&a, nullptr, nullptr) != 0) fail("parser_false_green");
    snprintf(p->roots[1], sizeof p->roots[1], "%s", STRICT_SHA3);
    expect_refusal(p, p->rootv, "contract_profile_mismatch",
                   "strict_profile_accepted", "strict_wrong_refusal");
}

static void check_refusals(const struct probe *p)
{
    const char *const preflight[] = {"preflight", nullptr};
    const char *const other[] = {"other", nullptr};
    struct pu_argv inst = {.n = 0};
    expect_refusal(p, preflight, "root_required", "same_uid_accepted",
                   "same_uid_wrong_refusal");
    expect_refusal(p, other, "request_shape_unsupported",
                   "unknown_command_accepted", "unknown_wrong_refusal");
    pu_argv_add(&inst, "platform/deploy/fixed-result-launcher-install.sh");
    pu_argv_add(&inst, "install");
    if (pu_run(&inst, pu_at(p->work, "out"), pu_at(p->work, "err")) == 0)
        fail("same_uid_install_accepted");
    if (!pu_has_line(pu_at(p->work, "err"),
                     "fixed_result_install_refuse=root_required"))
        fail("same_uid_install_wrong_refusal");
}

static void stage_source(const struct probe *p)
{
    static const char *const rel[] = {
        "platform/modules/base/include/base/format_attribute.h",
        "platform/modules/base/include/base/result.h",
        "platform/modules/base/src/result.c"};
    char dir[PU_PATH_MAX];
    for (size_t i = 0; i < 3u; ++i) {
        const char *dst = pu_at(pu_at(p->work, "src"), rel[i]);
        snprintf(dir, sizeof dir, "%s", dst);
        *strrchr(dir, '/') = '\0';
        if (!pu_mkdirs(dir) || !pu_copy(rel[i], dst) || chmod(dst, 0600) != 0)
            exit(1);
    }
}

static void check_source_content(const struct probe *p)
{
    char content[PU_PATH_MAX], again[PU_PATH_MAX];
    const char *const sc[] = {"source-content", p->repo, nullptr};
    char src[PU_PATH_MAX];
    snprintf(src, sizeof src, "%s", pu_at(p->work, "src"));
    const char *const sc2[] = {"source-content", src, nullptr};
    const char *const rh = "src/platform/modules/base/include/base/result.h";
    if (launch(p, sc, "out", nullptr) != 0) fail("source_content_refused");
    if (!pu_read(pu_at(p->work, "out"), content, sizeof content, nullptr, true) ||
        !is_hex64(content)) fail("source_content_shape");
    stage_source(p);
    if (launch(p, sc2, "out", nullptr) != 0 ||
        !pu_read(pu_at(p->work, "out"), again, sizeof again, nullptr, true) ||
        strcmp(content, again) != 0) fail("source_content_mode_dependent");
    if (rename(pu_at(p->work, rh), pu_at(p->work, "result.h")) != 0 ||
        symlink(pu_at(p->work, "result.h"), pu_at(p->work, rh)) != 0) exit(1);
    expect_refusal(p, sc2, "source_content_unreadable",
                   "source_content_followed_link",
                   "source_content_link_wrong_refusal");
}

static int run_probe(struct probe *p)
{
    char cwd[PU_PATH_MAX];
    if (!pu_repo_root(p->repo, sizeof p->repo)) exit(1);
    if (!getcwd(cwd, sizeof cwd) || strcmp(cwd, p->repo) != 0)
        fail("checkout_cwd");
    const char *home = getenv("HOME");
    char templ[PU_PATH_MAX];
    if (!home || !*home) {
        fprintf(stderr, "usage: %s (run from the repository root with HOME set)\n", g_script);
        return 2;
    }
    snprintf(templ, sizeof templ, "%s/.z23-launcher-probe.XXXXXX", home);
    if (!pu_scratch_make(templ, p->work, sizeof p->work)) exit(1);
    compile(p, nullptr, "tools/verify/fixed_result_launcher.c", "launcher");
    fill_roots(p);
    encode_with_env_root(p);
    check_parser(p);
    check_refusals(p);
    check_source_content(p);
    fputs("pins_v2_parser=GREEN forged_label=RED trailing_bytes=RED "
          "truncated=RED v1_pins=RED strict_profile=RED env_root=RED "
          "same_uid=REFUSE compiler_invocations=3 executed_launcher=8 "
          "installer_refusals=1 source_content=GREEN source_content_link=RED "
          "proof_launches_avoided=0 attest_eligible=0\n", stdout);
    return 0;
}

int main(int argc, char **argv)
{
    static struct probe p;
    if (argc >= 2) g_script = argv[1];
    if (argc == 3 && strcmp(argv[2], "--selftest") == 0) return pu_selftest();
    return run_probe(&p);
}
