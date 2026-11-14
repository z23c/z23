/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: Local test-fast result.c worker acceptance. Pins the ordered
 *          test-fast GCC 14 argv in fixed_result_fast.args against the Make
 *          recipe, qualifies result.c through the fixed worker on the full
 *          tree and on a sparse tree, and falsifies epoch, descriptor, header
 *          shadow, changed source and same-UID cases. No same-UID result is
 *          eligible. Run from the repository root through
 *          fixed_result_fast_probe.sh; --selftest checks the helpers. */
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#include "verify/fixed_result_profile.h"
#include "verify/fixed_result_contract.h"
#include "platform/fd_path.h"

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define FRF_SOURCE "platform/modules/base/src/result.c"
#define FRF_HEADER "platform/modules/base/include/base/result.h"
#define FRF_MANIFEST "tools/verify/fixed_result_fast.args"
#define FRF_MANIFEST_SHA3 ZCL_FR_PROFILE_SHA3
#define FRF_OBJECT_SHA256 \
    "e6cc944b229437d98654b1222d208ca932fb8b17c565ac512c6f7becc6d4892e"
#define FRF_GCC "/usr/bin/x86_64-linux-gnu-gcc-14"
#define FRF_PINNED ZCL_FR_PROFILE_ARGC
#define FRF_EXPANDED (ZCL_FR_PROFILE_ARGC - 1u)
#define FRF_SEED "-frandom-seed=" FRF_SOURCE
#define FRF_RECIPE \
    "__z23_fast_profile: ; @printf \"__PROFILE_BEGIN__\\n\"; " \
    "printf \"%s\\n\" $(CC) $(TEST_FAST_OBJECT_CFLAGS) $(ZCL_TU_RANDOM_SEED); " \
    "printf \"__TARGET__\\n%s\\n\" " \
    "\"$(TEST_FAST_OBJ_DIR)/platform/modules/base/src/result.o\""
#define FRF_REFUSE_DIGEST "fixed_result_worker_refuse=pinned_input_digest_mismatch"
#define FRF_REFUSE_PEER "fixed_result_worker_refuse=launcher_peer_mismatch"
#define FRF_ALTERED "<zcl_result: altered format>"
#define FRF_MISSING "<zcl_result: missing format>"

struct frf_probe {
    char repo[PU_PATH_MAX];
    char work[PU_PATH_MAX];
    char sparse[PU_PATH_MAX];
    char src[PU_PATH_MAX];
    char target[PU_PATH_MAX];
    char manifest_sha3[65];
    struct frp_lines pinned, repo_args, sparse_args;
    struct frp_timing full, sparse_time;
};

static _Noreturn void frf_fail(const char *why)
{
    fprintf(stderr, "fixed_result_fast_refuse=%s\n", why);
    exit(2);
}

static void frf_run_or_exit(const char *dir, const struct pu_argv *a,
                            const char *out, const char *err,
                            struct frp_timing *t)
{
    int rc = frp_run(dir, a, out, err, t);
    if (rc != 0) exit(rc > 0 ? rc : 1);
}

static const char *frf_w(const struct frf_probe *p, const char *name)
{
    return pu_at(p->work, name);
}

static void frf_preflight(struct frf_probe *p)
{
    char templ[PU_PATH_MAX];
    const char *why = frp_checkout(p->repo, sizeof p->repo);
    const char *scratch = getenv("TMPDIR");
    char gcc[PATH_MAX];
    if (why) frf_fail(why);
    if (!realpath("/usr/bin/cc", gcc) || strcmp(gcc, FRF_GCC) != 0)
        frf_fail("gcc14_driver_mismatch");
    frp_sha3_file(FRF_MANIFEST, p->manifest_sha3);
    if (strcmp(p->manifest_sha3, FRF_MANIFEST_SHA3) != 0)
        frf_fail("manifest_bytes_mismatch");
    if (!scratch || scratch[0] != '/') frf_fail("absolute_scratch_root_required");
    if (snprintf(templ, sizeof templ, "%s/z23-fast-result.XXXXXX", scratch) >=
            (int)sizeof templ ||
        !pu_scratch_make(templ, p->work, sizeof p->work)) exit(1);
    snprintf(p->sparse, sizeof p->sparse, "%s", frf_w(p, "sparse"));
    snprintf(p->src, sizeof p->src, "%s", pu_at(p->sparse, "src"));
}

/* The recipe lines between the profile markers, as the script's awk read them. */
static bool frf_profile_lines(const struct frp_lines *all, struct frp_lines *out)
{
    bool inside = false;
    for (size_t i = 0; i < all->n; ++i) {
        if (strcmp(all->v[i], "__TARGET__") == 0) break;
        if (strcmp(all->v[i], "__PROFILE_BEGIN__") == 0) inside = true;
        else if (inside && !frp_lines_add(out, all->v[i])) return false;
    }
    return true;
}

/* The line after the first __TARGET__ marker, or "". */
static const char *frf_target_line(const struct frp_lines *all)
{
    for (size_t i = 0; i < all->n; ++i)
        if (strcmp(all->v[i], "__TARGET__") == 0)
            return i + 1u < all->n ? all->v[i + 1u] : "";
    return "";
}

static void frf_check_profile(struct frf_probe *p, const struct frp_lines *actual)
{
    char zcc[PU_PATH_MAX + 16u];
    snprintf(zcc, sizeof zcc, "%s/build/bin/zcc", p->repo);
    if (actual->n != FRF_PINNED + 1u || p->pinned.n != FRF_PINNED ||
        strcmp(actual->v[0], zcc) != 0 || strcmp(actual->v[1], "cc") != 0)
        frf_fail("make_profile_shape");
    for (size_t i = 0; i < FRF_EXPANDED; ++i)
        if (strcmp(actual->v[i + 1u], p->repo_args.v[i]) != 0)
            frf_fail("make_profile_mismatch");
    if (strcmp(actual->v[FRF_PINNED], "-frandom-seed=") != 0 ||
        strcmp(p->pinned.v[FRF_EXPANDED], FRF_SEED) != 0)
        frf_fail("seed_mismatch");
}

static void frf_load_profile(struct frf_probe *p)
{
    struct pu_argv make = {.n = 0};
    struct frp_lines all = {.v = nullptr, .n = 0}, actual = {.v = nullptr, .n = 0};
    const char *out = frf_w(p, "make.out");
    pu_argv_addv(&make, (const char *const[]){"make", "-s",
                 "--eval=" FRF_RECIPE, "__z23_fast_profile", nullptr});
    frf_run_or_exit(nullptr, &make, out, nullptr, nullptr);
    if (!frp_lines_load(out, &all) || !frf_profile_lines(&all, &actual) ||
        !frp_lines_load(FRF_MANIFEST, &p->pinned) ||
        !frp_expand(&p->pinned, p->pinned.n, p->repo, &p->repo_args))
        exit(1);
    frf_check_profile(p, &actual);
    snprintf(p->target, sizeof p->target, "%s", frf_target_line(&all));
    if (!frp_glob(p->target, "build/test-obj/epochs/*/platform/modules/base/src/result.o"))
        frf_fail("target_malformed");
    frp_lines_free(&actual);
    frp_lines_free(&all);
}

/* strict adds the warning gate; the driver links use only -std=c23. */
static void frf_cc(bool strict, const char *const *rest)
{
    struct pu_argv a = {.n = 0};
    pu_argv_addv(&a, (const char *const[]){"/usr/bin/cc", "-std=c23", nullptr});
    if (strict)
        pu_argv_addv(&a, (const char *const[]){"-Wall", "-Wextra", "-Werror",
                     "-pedantic", nullptr});
    pu_argv_addv(&a, rest);
    frf_run_or_exit(nullptr, &a, nullptr, nullptr, nullptr);
}

static void frf_build_tools(const struct frf_probe *p)
{
    frf_cc(true, (const char *const[]){
        "-Itools", "-Iplatform/modules/sha3/include",
        "-Iplatform/modules/base/include", "-Iplatform/modules/platform/include",
        "-Iplatform/modules/codec/include",
        "tools/verify/fixed_result_worker.c",
        "tools/verify/fixed_result_contract.c", "platform/modules/sha3/src/sha3.c",
        "platform/modules/codec/src/cursor.c",
        "platform/modules/platform/src/os_proc.c", "-o", frf_w(p, "worker"),
        nullptr});
    frf_cc(true, (const char *const[]){"tools/verify/fixed_result_peer_probe.c", "-o",
                                 frf_w(p, "peer"), nullptr});
}

static void frf_mkdirs(const char *path)
{
    if (!pu_mkdirs(path)) exit(1);
}

static void frf_copy(const char *src, const char *dst)
{
    if (!pu_copy(src, dst) || chmod(dst, 0600) != 0) exit(1);
}

static void frf_stage_sparse(const struct frf_probe *p)
{
    static const char *const base = "platform/modules/base";
    char root[PU_PATH_MAX];
    snprintf(root, sizeof root, "%s", pu_at(p->src, base));
    frf_mkdirs(frf_w(p, "full"));
    for (size_t i = 0; i < p->pinned.n; ++i)
        if (strncmp(p->pinned.v[i], "-I", 2) == 0)
            frf_mkdirs(pu_at(p->src, p->pinned.v[i] + 2));
    frf_mkdirs(pu_at(root, "src"));
    frf_mkdirs(pu_at(root, "include/base"));
    frf_copy(FRF_SOURCE, pu_at(root, "src/result.c"));
    for (const char *const *h = (const char *const[]){"result.h",
             "format_attribute.h", nullptr}; *h; ++h) {
        char name[PU_PATH_MAX];
        snprintf(name, sizeof name, "include/base/%s", *h);
        frf_copy(pu_at("platform/modules/base", name), pu_at(root, name));
    }
}

static int frf_qualify(const struct frf_probe *p, const char *tree,
                       const char *outdir, const char *out, const char *err,
                       struct frp_timing *t)
{
    struct pu_argv a = {.n = 0};
    pu_argv_addv(&a, (const char *const[]){frf_w(p, "worker"), "qualify", tree,
                 p->target, outdir, nullptr});
    return frp_run(nullptr, &a, out, err, t);
}

static void frf_qualify_or_exit(const struct frf_probe *p, const char *tree,
                                const char *outdir, const char *out,
                                struct frp_timing *t)
{
    int rc = frf_qualify(p, tree, outdir, out, nullptr, t);
    if (rc != 0) exit(rc > 0 ? rc : 1);
}

static void frf_qualify_both(struct frf_probe *p)
{
    frf_qualify_or_exit(p, p->repo, frf_w(p, "full"), frf_w(p, "full.out"),
                        &p->full);
    frf_qualify_or_exit(p, p->src, p->sparse, frf_w(p, "sparse.out"),
                        &p->sparse_time);
    for (const char *const *n = (const char *const[]){"result.o", "deps.d",
             "stderr.bin", "result.i", nullptr}; *n; ++n) {
        char why[64];
        if (pu_same_file(pu_at(frf_w(p, "full"), *n), pu_at(p->sparse, *n)))
            continue;
        snprintf(why, sizeof why, "%s-byte-mismatch", *n);
        frf_fail(why);
    }
}

static void frf_object_baseline(const struct frf_probe *p)
{
    struct pu_argv a = {.n = 0};
    char line[160];
    const char *out = frf_w(p, "object.sha256");
    pu_argv_add(&a, "sha256sum");
    pu_argv_add(&a, pu_at(frf_w(p, "full"), "result.o"));
    frf_run_or_exit(nullptr, &a, out, nullptr, nullptr);
    if (!pu_read(out, line, sizeof line, nullptr, true) ||
        strncmp(line, FRF_OBJECT_SHA256 " ", 65) != 0)
        frf_fail("object_baseline_mismatch");
}

/* One GCC launch under the fixed environment in dir. */
static void frf_gcc(const struct frp_lines *args, const char *dir,
                    const char *const *rest, const char *err)
{
    struct pu_argv a = {.n = 0};
    frp_env_argv(&a, args);
    pu_argv_addv(&a, rest);
    frf_run_or_exit(dir, &a, nullptr, err, nullptr);
}

static void frf_target_with(char *out, size_t cap, char epoch)
{
    char hash[65];
    memset(hash, epoch, 64);
    hash[64] = '\0';
    snprintf(out, cap, "build/test-obj/epochs/%s/platform/modules/base/src/result.o",
             hash);
}

/* Only depfile target bytes may change when the output target changes. */
static void frf_epoch(const struct frf_probe *p)
{
    char target_b[PU_PATH_MAX];
    const char *const *tail;
    frf_target_with(target_b, sizeof target_b, 'b');
    tail = (const char *const[]){"-MMD", "-MP", "-MF", frf_w(p, "epoch-b.d"),
                                 "-MT", target_b, "-c", "-o",
                                 frf_w(p, "epoch-b.o"), FRF_SOURCE, nullptr};
    frf_gcc(&p->repo_args, p->repo, tail, frf_w(p, "epoch-b.err"));
    if (!pu_same_file(pu_at(frf_w(p, "full"), "result.o"), frf_w(p, "epoch-b.o")))
        frf_fail("epoch_object_mismatch");
    if (!pu_same_file(pu_at(frf_w(p, "full"), "stderr.bin"), frf_w(p, "epoch-b.err")))
        frf_fail("epoch_stderr_mismatch");
    if (pu_same_file(pu_at(frf_w(p, "full"), "deps.d"), frf_w(p, "epoch-b.d")))
        frf_fail("epoch_dep_target_not_changed");
}

/* Linux ZCC's private stage reaches GCC as /proc/self/fd/N/leaf; it must be
 * byte-equivalent to the worker's ordinary private-directory spelling. */
static void frf_fd_stage(const struct frf_probe *p)
{
    char dep[64], obj[64];
    char stage[PU_PATH_MAX];
    int fd;
    snprintf(stage, sizeof stage, "%s", frf_w(p, "fd-stage"));
    if (mkdir(stage, 0777) != 0) exit(1);
    fd = open(stage, O_RDONLY | O_DIRECTORY);
    if (fd < 0) exit(1);
    if (!platform_fd_path(dep, sizeof dep, fd, "result.d") ||
        !platform_fd_path(obj, sizeof obj, fd, "result.o")) exit(1);
    frf_gcc(&p->repo_args, p->repo, (const char *const[]){"-MMD", "-MP", "-MF",
            dep, "-MT", p->target, "-c", "-o", obj, FRF_SOURCE, nullptr},
            frf_w(p, "fd-stage.err"));
    close(fd);
    if (!pu_same_file(pu_at(frf_w(p, "full"), "result.o"), pu_at(stage, "result.o")))
        frf_fail("fd_object_mismatch");
    if (!pu_same_file(pu_at(frf_w(p, "full"), "deps.d"), pu_at(stage, "result.d")))
        frf_fail("fd_dep_mismatch");
    if (!pu_same_file(pu_at(frf_w(p, "full"), "stderr.bin"), frf_w(p, "fd-stage.err")))
        frf_fail("fd_stderr_mismatch");
}

static void frf_sparse_preprocess(const struct frf_probe *p, const char *stem)
{
    char name[96];
    snprintf(name, sizeof name, "%s.d", stem);
    const char *dep = frf_w(p, name);
    snprintf(name, sizeof name, "%s.i", stem);
    const char *pp = frf_w(p, name);
    snprintf(name, sizeof name, "%s.err", stem);
    frf_gcc(&p->sparse_args, p->src, (const char *const[]){"-fno-working-directory",
            "-MMD", "-MP", "-MF", dep, "-MT", p->target, "-E", "-o", pp,
            FRF_SOURCE, nullptr}, frf_w(p, name));
}

static bool frf_sparse_detects(const struct frf_probe *p, const char *stem)
{
    char shadow[96];
    snprintf(shadow, sizeof shadow, "%s.i", stem);
    bool pp_same = pu_same_file(pu_at(p->sparse, "result.i"), frf_w(p, shadow));
    snprintf(shadow, sizeof shadow, "%s.d", stem);
    bool dep_same = pu_same_file(pu_at(p->sparse, "deps.d"), frf_w(p, shadow));
    return !pp_same && !dep_same;
}

static void frf_write_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (!f || fputs(text, f) == EOF || fclose(f) != 0) exit(1);
}

/* A formerly absent earlier search-path header redirects this exact include;
 * fresh preprocessing and the depfile must expose it, as must a system
 * header shadow. */
static void frf_shadows(struct frf_probe *p)
{
    char dir[PU_PATH_MAX], header[PU_PATH_MAX], sys[PU_PATH_MAX];
    snprintf(dir, sizeof dir, "%s", pu_at(p->src, "engine/models/include"));
    snprintf(header, sizeof header, "%s", pu_at(dir, "base/result.h"));
    snprintf(sys, sizeof sys, "%s", pu_at(dir, "stdio.h"));
    frf_mkdirs(pu_at(dir, "base"));
    frf_copy(FRF_HEADER, header);
    if (!frp_expand(&p->pinned, p->pinned.n, p->src, &p->sparse_args)) exit(1);
    frf_sparse_preprocess(p, "shadow");
    if (!frf_sparse_detects(p, "shadow")) frf_fail("header_shadow_not_detected");
    if (remove(header) != 0) exit(1);
    frf_write_file(sys, "#include_next <stdio.h>\n");
    frf_sparse_preprocess(p, "system-shadow");
    if (!frf_sparse_detects(p, "system-shadow"))
        frf_fail("system_header_shadow_not_detected");
    if (remove(sys) != 0) exit(1);
}

/* Replace the first occurrence of from on every line of path, as sed s/// does. */
static void frf_edit_source(const char *path, const char *from, const char *to)
{
    char tmp[PU_PATH_MAX];
    FILE *in = fopen(path, "rb"), *out;
    char *line = nullptr;
    size_t cap = 0, flen = strlen(from);
    ssize_t n;
    snprintf(tmp, sizeof tmp, "%s.new", path);
    out = in ? fopen(tmp, "wb") : nullptr;
    if (!out || chmod(tmp, 0600) != 0) exit(1);
    while ((n = getline(&line, &cap, in)) >= 0) {
        char *hit = strstr(line, from);
        if (hit) fprintf(out, "%.*s%s%s", (int)(hit - line), line, to, hit + flen);
        else fwrite(line, 1, (size_t)n, out);
    }
    free(line);
    fclose(in);
    if (ferror(out) || fclose(out) != 0 || rename(tmp, path) != 0) exit(1);
}

static void frf_changed_source(const struct frf_probe *p)
{
    frf_edit_source(pu_at(p->src, FRF_SOURCE), FRF_MISSING, FRF_ALTERED);
    if (frf_qualify(p, p->src, frf_w(p, "red-body"), frf_w(p, "red.out"),
                    frf_w(p, "red.err"), nullptr) == 0)
        frf_fail("changed_source_accepted");
    if (!pu_has_line(frf_w(p, "red.err"), FRF_REFUSE_DIGEST))
        frf_fail("changed_source_wrong_refusal");
}

static void frf_same_uid(const struct frf_probe *p)
{
    struct pu_argv a = {.n = 0};
    pu_argv_add(&a, frf_w(p, "peer"));
    pu_argv_add(&a, frf_w(p, "worker"));
    if (frp_run(nullptr, &a, nullptr, frf_w(p, "serve.err"), nullptr) != 0)
        frf_fail("same_uid_accepted");
    if (!pu_has_line(frf_w(p, "serve.err"), FRF_REFUSE_PEER))
        frf_fail("same_uid_wrong_refusal");
}

/* The pre-edit object and a fresh compile must differ observably once this
 * pinned source changes; neither object is proof reuse. */
static void frf_stale_fresh(struct frf_probe *p)
{
    static const char driver[] =
        "#include \"base/result.h\"\n#include <stdio.h>\n"
        "int main(void)\n{\n"
        "    struct zcl_result r = zcl_result_make(-1, __FILE__, __LINE__, NULL);\n"
        "    puts(r.message);\n    return 0;\n}\n";
    frf_gcc(&p->sparse_args, p->src, (const char *const[]){"-MMD", "-MP", "-MF",
            frf_w(p, "changed.d"), "-MT", p->target, "-c", "-o",
            frf_w(p, "changed.o"), FRF_SOURCE, nullptr}, nullptr);
    frf_write_file(frf_w(p, "driver.c"), driver);
    frf_cc(false, (const char *const[]){"-Iplatform/modules/base/include",
           frf_w(p, "driver.c"), pu_at(frf_w(p, "full"), "result.o"), "-o",
           frf_w(p, "stale-driver"), nullptr});
    frf_cc(false, (const char *const[]){"-Iplatform/modules/base/include",
           frf_w(p, "driver.c"), frf_w(p, "changed.o"), "-o",
           frf_w(p, "fresh-driver"), nullptr});
    for (const char *const *d = (const char *const[]){"stale", "fresh", nullptr};
         *d; ++d) {
        struct pu_argv a = {.n = 0};
        char exe[32], out[32];
        snprintf(exe, sizeof exe, "%s-driver", *d);
        snprintf(out, sizeof out, "%s.out", *d);
        pu_argv_add(&a, frf_w(p, exe));
        frf_run_or_exit(nullptr, &a, frf_w(p, out), nullptr, nullptr);
    }
    if (!pu_has_line(frf_w(p, "stale.out"), FRF_MISSING))
        frf_fail("stale_behavior_mismatch");
    if (!pu_has_line(frf_w(p, "fresh.out"), FRF_ALTERED))
        frf_fail("fresh_behavior_mismatch");
}

static void frf_print_listing(const struct frf_probe *p, const char *tool,
                              const char *flag)
{
    struct pu_argv a = {.n = 0};
    pu_argv_add(&a, tool);
    if (flag) pu_argv_add(&a, flag);
    for (const char *const *n = (const char *const[]){"result.o", "deps.d",
             "stderr.bin", "result.i", nullptr}; *n; ++n)
        pu_argv_add(&a, pu_at(frf_w(p, "full"), *n));
    frf_run_or_exit(nullptr, &a, nullptr, nullptr, nullptr);
}

static void frf_report(const struct frf_probe *p)
{
    printf("profile_green=1 source=%s manifest_sha3=%s\n", FRF_SOURCE,
           p->manifest_sha3);
    frf_print_listing(p, "sha256sum", nullptr);
    frf_print_listing(p, "wc", "-c");
    printf("full_wall=%.2f full_user=%.2f full_system=%.2f\n", p->full.wall,
           p->full.user, p->full.sys);
    printf("sparse_wall=%.2f sparse_user=%.2f sparse_system=%.2f\n",
           p->sparse_time.wall, p->sparse_time.user, p->sparse_time.sys);
    puts("object_equal=1 dep_equal=1 stderr_equal=1 pp_equal=1 "
         "epoch_object_equal=1 epoch_dep_target_differs=1 fd_output_parity=1 "
         "header_shadow_red=1 system_header_shadow_red=1 "
         "profile_compiler_launches=5 preprocess_launches=4 "
         "worker_build_invocations=1 peer_fixture_build_invocations=1 "
         "driver_compile_link_invocations=2 executed_drivers=2 "
         "red_pin_compiler_launches=0 proof_launches_avoided=0 "
         "attest_eligible=0");
}

static int frf_selftest(void)
{
    return frp_selftest() == 0 && pu_selftest() == 0 ? 0 : 1;
}

int main(int argc, char **argv)
{
    static struct frf_probe p;
    if (argc == 3 && strcmp(argv[2], "--selftest") == 0) return frf_selftest();
    frf_preflight(&p);
    frf_load_profile(&p);
    frf_build_tools(&p);
    frf_stage_sparse(&p);
    frf_qualify_both(&p);
    frf_object_baseline(&p);
    frf_epoch(&p);
    frf_fd_stage(&p);
    frf_shadows(&p);
    frf_changed_source(&p);
    frf_same_uid(&p);
    frf_stale_fresh(&p);
    frf_report(&p);
    return 0;
}
