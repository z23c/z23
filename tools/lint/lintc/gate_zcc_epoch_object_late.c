/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: part2 of the check-zcc-epoch-object gate port
 * (gate_zcc_epoch_object.c): distinct canonical paths, the long and
 * control-character diagnostic paths, the standalone compile, the
 * separate-inode zcc copy unwrap, the same-size different-wrapper
 * refusal, opt-in whole-invocation timing, native/legacy object parity,
 * and the -MMD depfile parity sweep.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>
#include "lintc_text.h"
#include "lintc.h"
#include "gate_zcc_epoch_object_priv.h"

static void p2_must(struct zeo *z, int ret, int rc)
{
    if (ret != 0 || rc != 0)
        zeo_bail(rc ? rc : 1);
    (void)z;
}

static void p2_distinct(struct zeo *z)
{
    static const char *const leaf[2] = { "first", "second" };
    for (int i = 0; i < 2; i++) {
        char obj[ZEO_PATH];
        if (ovf(snprintf(obj, sizeof obj, "%s/%s/same.o", z->object_root,
                         leaf[i]), sizeof obj))
            zeo_bail(2);
        char *cc[5];
        cc[0] = (char *)"cc";
        cc[1] = (char *)"-std=c23";
        cc[2] = (char *)"-O2";
        cc[3] = (char *)"-Wall";
        cc[4] = NULL;
        int rc = 0;
        p2_must(z, zeo_compile_x(z, NULL, "dep", obj, cc, NULL, NULL, NULL,
                                 &rc), rc);
        zeo_expect_log_output(z, obj);
    }
}

static void p2_long(struct zeo *z)
{
    char out[ZEO_PATH], exp[ZEO_PATH];
    char part[161], esc[321];
    memset(part, '\\', 160);
    part[160] = '\0';
    memset(esc, '\\', 320);
    esc[320] = '\0';
    size_t lo = strlen(z->object_root), eo = lo;
    if (lo + 1 >= sizeof out)
        zeo_bail(2);
    memcpy(out, z->object_root, lo + 1);
    memcpy(exp, z->object_root, lo + 1);
    for (int i = 0; i < 4; i++) {
        if (lo + 162 >= sizeof out || eo + 322 >= sizeof exp)
            zeo_bail(2);
        out[lo] = '/';
        memcpy(out + lo + 1, part, 161);
        lo += 161;
        out[lo] = '\0';
        exp[eo] = '/';
        memcpy(exp + eo + 1, esc, 321);
        eo += 321;
        exp[eo] = '\0';
    }
    if (lo + 8 >= sizeof out || eo + 8 >= sizeof exp)
        zeo_bail(2);
    strcpy(out + lo, "/long.o");
    strcpy(exp + eo, "/long.o");
    if (strlen(out) >= 1024)
        zeo_fail("long diagnostic fixture real path exceeds Darwin bound");
    if (strlen(exp) <= 1024)
        zeo_fail("long diagnostic fixture did not exceed old log bound");
    printf("check_zcc_epoch_object: long diagnostic real=%zu rendered=%zu "
           "bytes\n", strlen(out), strlen(exp));
    long before = zeo_count_line_eq(z->compiler_launches, "compile");
    char *cc[6];
    cc[0] = z->counting;
    cc[1] = (char *)"-std=c23";
    cc[2] = (char *)"-O2";
    cc[3] = (char *)"-Wall";
    cc[4] = (char *)"-DZCL_LONG_DIAGNOSTIC=1";
    cc[5] = NULL;
    int rc = 0;
    p2_must(z, zeo_compile_x(z, NULL, "dep", out, cc, NULL, NULL, NULL, &rc),
            rc);
    if (zeo_count_line_eq(z->compiler_launches, "compile") != before + 1)
        zeo_fail("long diagnostic fixture did not execute an object "
                 "compiler");
    zeo_expect_log_output(z, exp);
}

static void p2_control(struct zeo *z)
{
    char out[ZEO_PATH], exp[ZEO_PATH];
    if (ovf(snprintf(out, sizeof out, "%s/diagnostic\\tab\tline\nreturn\r.o",
                     z->object_root), sizeof out) ||
        ovf(snprintf(exp, sizeof exp,
                     "%s/diagnostic\\\\tab\\x09line\\x0areturn\\x0d.o",
                     z->object_root), sizeof exp))
        zeo_bail(2);
    long before = zeo_count_lines(z->zcc_log);
    char *cc[5];
    cc[0] = (char *)"cc";
    cc[1] = (char *)"-std=c23";
    cc[2] = (char *)"-O2";
    cc[3] = (char *)"-Wall";
    cc[4] = NULL;
    int rc = 0;
    p2_must(z, zeo_compile_x(z, NULL, "dep", out, cc, NULL, NULL, NULL, &rc),
            rc);
    zeo_expect_log_output(z, exp);
    if (zeo_count_lines(z->zcc_log) <= before)
        zeo_fail("control-path log missing");
    if (zeo_grep_re("^return", z->zcc_log))
        zeo_fail("control path injected a log row");
}

static void p2_standalone(struct zeo *z)
{
    char obj[ZEO_PATH];
    if (zeo_join(obj, sizeof obj, z->work, "standalone.o"))
        zeo_bail(2);
    char *argv[9];
    argv[0] = z->zcc;
    argv[1] = (char *)"cc";
    argv[2] = (char *)"-std=c23";
    argv[3] = (char *)"-O2";
    argv[4] = (char *)"-c";
    argv[5] = z->source;
    argv[6] = (char *)"-o";
    argv[7] = obj;
    argv[8] = NULL;
    if (zeo_run(z->zcc, argv, NULL, NULL) != 0)
        zeo_bail(1);
    zeo_expect_log_output(z, obj);
}

static void p2_copy_cold(struct zeo *z, const char *obj, const char *errf)
{
    long launches_before = zeo_count_lines(z->compiler_launches);
    char *cc[10];
    zeo_args_wrap(cc, z->zcc_copy, z->counting, "-DMAKE_COPY_EPOCH=1",
                  z->seed);
    int rc = 0;
    p2_must(z, zeo_compile_x(z, NULL, "dep", obj, cc, NULL, errf, NULL, &rc),
            rc);
    if (zeo_count_lines(z->compiler_launches) <= launches_before)
        zeo_fail("copied-wrapper cold compile launched no compiler child");
}

static const char k_no_print_prog[] = "zcc: cannot execute -print-prog-name=";

static void p2_copy_clone(struct zeo *z)
{
    struct stat a, b;
    if (zeo_copy_file(z->zcc, z->zcc_copy) != 0 ||
        chmod(z->zcc_copy, 0755) != 0 || stat(z->zcc, &a) != 0 ||
        stat(z->zcc_copy, &b) != 0)
        zeo_bail(1);
    if (a.st_dev == b.st_dev && a.st_ino == b.st_ino)
        zeo_fail("copied zcc shares the original inode");
    if (!zeo_files_equal(z->zcc, z->zcc_copy))
        zeo_fail("copied zcc bytes differ");
}

static void p2_copy_outcome(struct zeo *z, long want, const char *kind,
                            const char *msg)
{
    char tail[ZEO_PATH];
    if (zeo_outcome_count(z->zcc_log) != want ||
        zeo_tail1(z->zcc_log, tail, sizeof tail) != 0 ||
        !zeo_first_tok_is(tail, kind))
        zeo_fail(msg);
}

static void p2_copy_warm(struct zeo *z, const char *obj, const char *errf,
                         long log_before)
{
    long cold_pre = zeo_count_line_eq(z->compiler_launches, "preprocess");
    long cold_cmp = zeo_count_line_eq(z->compiler_launches, "compile");
    char dep[ZEO_PATH];
    if (zeo_dep_of(dep, sizeof dep, obj) || unlink(obj) != 0 ||
        unlink(dep) != 0)
        zeo_bail(1);
    char *cc[10];
    zeo_args_wrap(cc, z->zcc_copy, z->counting, "-DMAKE_COPY_EPOCH=1",
                  z->seed);
    int rc = 0;
    p2_must(z, zeo_compile_x(z, NULL, "dep", obj, cc, NULL, errf, NULL,
                             &rc), rc);
    p2_copy_outcome(z, log_before + 2, "HIT",
                    "copied-wrapper warm compile used more than one zcc "
                    "coordinator");
    if (zeo_count_line_eq(z->compiler_launches, "preprocess") != cold_pre + 1 ||
        zeo_count_line_eq(z->compiler_launches, "compile") != cold_cmp)
        zeo_fail("copied-wrapper warm hit failed fresh preprocess or "
                 "compiled an object");
    if (lct_file_has(errf, k_no_print_prog))
        zeo_fail("copied-wrapper warm compile queried zcc as the compiler "
                 "driver");
}

static void p2_copy(struct zeo *z)
{
    char obj[ZEO_PATH], cold_err[ZEO_PATH], warm_err[ZEO_PATH];
    if (zeo_join(z->zcc_copy, sizeof z->zcc_copy, z->work, "zcc-copy") ||
        ovf(snprintf(obj, sizeof obj, "%s/make-copy.o", z->object_root),
            sizeof obj) ||
        zeo_join(cold_err, sizeof cold_err, z->work, "make-copy-cold.err") ||
        zeo_join(warm_err, sizeof warm_err, z->work, "make-copy-warm.err"))
        zeo_bail(2);
    p2_copy_clone(z);
    strcpy(z->make_copy, obj);
    long log_before = zeo_outcome_count(z->zcc_log);
    p2_copy_cold(z, obj, cold_err);
    p2_copy_outcome(z, log_before + 1, "MISS",
                    "copied-wrapper cold compile used more than one zcc "
                    "coordinator");
    if (lct_file_has(cold_err, k_no_print_prog))
        zeo_fail("copied-wrapper cold compile queried zcc as the compiler "
                 "driver");
    p2_copy_warm(z, obj, warm_err, log_before);
}

static const char k_different_c[] =
    "#define _POSIX_C_SOURCE 200809L\n"
    "#include <stdio.h>\n"
    "#include <stdlib.h>\n"
    "#include <unistd.h>\n"
    "int main(int argc, char **argv)\n"
    "{\n"
    "    const char *log = getenv(\"COMPILER_LAUNCHES\");\n"
    "    if (argc < 2 || !log) return 2;\n"
    "    FILE *f = fopen(log, \"a\");\n"
    "    if (!f) return 2;\n"
    "    int wrote = fputs(\"different-wrapper\\n\", f);\n"
    "    int closed = fclose(f);\n"
    "    if (wrote < 0 || closed != 0) return 2;\n"
    "    execvp(argv[1], argv + 1);\n"
    "    perror(\"different-wrapper: compiler\");\n"
    "    return 2;\n"
    "}\n";

static void p2_diff_build(struct zeo *z, const char *src, const char *bin)
{
    if (zeo_write_file(src, k_different_c) != 0)
        zeo_bail(1);
    char *ccargs[10];
    ccargs[0] = z->posix_cc;
    ccargs[1] = (char *)"-std=c23";
    ccargs[2] = (char *)"-O1";
    ccargs[3] = (char *)"-Wall";
    ccargs[4] = (char *)"-Wextra";
    ccargs[5] = (char *)"-Werror";
    ccargs[6] = (char *)src;
    ccargs[7] = (char *)"-o";
    ccargs[8] = (char *)bin;
    ccargs[9] = NULL;
    if (zeo_run(z->posix_cc, ccargs, NULL, NULL) != 0)
        zeo_bail(1);
}

static void p2_diff_pad(struct zeo *z, const char *bin)
{
    long zs = zeo_size(z->zcc), ds = zeo_size(bin);
    if (zs <= 0 || ds < 0 || ds >= zs)
        zeo_fail("different-wrapper fixture cannot be padded to zcc size");
    int fd = open(bin, O_WRONLY);
    if (fd < 0)
        zeo_bail(1);
    if (lseek(fd, zs - 1, SEEK_SET) < 0 || write(fd, "\0", 1) != 1) {
        close(fd);
        zeo_bail(1);
    }
    close(fd);
    if (zeo_size(bin) != zs)
        zeo_fail("different-wrapper size differs from zcc");
    if (zeo_files_equal(z->zcc, bin))
        zeo_fail("different-wrapper bytes equal zcc");
}

static void p2_different(struct zeo *z)
{
    char src[ZEO_PATH], bin[ZEO_PATH], obj[ZEO_PATH], errf[ZEO_PATH];
    char ver[ZEO_PATH];
    if (zeo_join(src, sizeof src, z->work, "different-wrapper.c") ||
        zeo_join(bin, sizeof bin, z->work, "different-wrapper") ||
        ovf(snprintf(obj, sizeof obj, "%s/make-different.o", z->object_root),
            sizeof obj) ||
        zeo_join(errf, sizeof errf, z->work, "make-different.err") ||
        zeo_join(ver, sizeof ver, z->work, "different-wrapper-version"))
        zeo_bail(2);
    p2_diff_build(z, src, bin);
    p2_diff_pad(z, bin);
    char *vargs[4] = { bin, z->posix_cc, (char *)"--version", NULL };
    if (zeo_run(bin, vargs, ver, NULL) != 0)
        zeo_bail(1);
    long before = zeo_count_line_eq(z->compiler_launches, "different-wrapper");
    char *cc[10];
    zeo_args_wrap(cc, bin, z->counting, "-DMAKE_COPY_EPOCH=1", z->seed);
    int rc = 0;
    p2_must(z, zeo_compile_x(z, NULL, "dep", obj, cc, NULL, errf, NULL, &rc),
            rc);
    if (zeo_count_line_eq(z->compiler_launches, "different-wrapper") <=
        before)
        zeo_fail("same-size different executable was incorrectly unwrapped");
    if (!zeo_files_equal(z->make_copy, obj))
        zeo_fail("same-size different executable changed forwarded compile "
                 "output");
}

static void p2_timing_kind(struct zeo *z, const char *kind,
                           const char *wrapper, const char *ref)
{
    char obj[ZEO_PATH], dep[ZEO_PATH], warmup[ZEO_PATH], sample[ZEO_PATH];
    if (ovf(snprintf(obj, sizeof obj, "%s/timing-%s.o", z->object_root, kind),
            sizeof obj) ||
        zeo_dep_of(dep, sizeof dep, obj) ||
        ovf(snprintf(warmup, sizeof warmup, "%s/timing-warmup.err", z->work),
            sizeof warmup) ||
        ovf(snprintf(sample, sizeof sample, "%s/timing-sample.err", z->work),
            sizeof sample))
        zeo_bail(2);
    char *cc[10];
    zeo_args_wrap(cc, wrapper, z->counting, "-DMAKE_COPY_EPOCH=1", z->seed);
    int rc = 0;
    p2_must(z, zeo_compile_x(z, NULL, "dep", obj, cc, NULL, warmup, NULL,
                             &rc), rc);
    long hits = zeo_count_first_field(z->zcc_log, "HIT");
    long pre = zeo_count_line_eq(z->compiler_launches, "preprocess");
    long cmp = zeo_count_line_eq(z->compiler_launches, "compile");
    struct timespec t0, t1;
    struct rusage r0, r1;
    clock_gettime(CLOCK_MONOTONIC, &t0); // platform-ok: z23-lint links no platform library; elapsed time for the timing probe only
    getrusage(RUSAGE_CHILDREN, &r0);
    for (int s = 0; s < 5; s++) {
        if (unlink(obj) != 0 || unlink(dep) != 0)
            zeo_bail(1);
        rc = 0;
        p2_must(z, zeo_compile_x(z, NULL, "dep", obj, cc, NULL, sample, NULL,
                                 &rc), rc);
        if (!zeo_files_equal(ref, obj))
            zeo_fail("timed invocation changed object bytes");
    }
    getrusage(RUSAGE_CHILDREN, &r1);
    clock_gettime(CLOCK_MONOTONIC, &t1); // platform-ok: z23-lint links no platform library; elapsed time for the timing probe only
    double real = (double)(t1.tv_sec - t0.tv_sec) +
                  (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
    double user = (double)(r1.ru_utime.tv_sec - r0.ru_utime.tv_sec) +
                  (double)(r1.ru_utime.tv_usec - r0.ru_utime.tv_usec) / 1e6;
    double sysv = (double)(r1.ru_stime.tv_sec - r0.ru_stime.tv_sec) +
                  (double)(r1.ru_stime.tv_usec - r0.ru_stime.tv_usec) / 1e6;
    printf("epoch-wrapper-timing %s n=5 real_s=%.3f user_s=%.3f sys_s=%.3f\n",
           kind, real, user, sysv);
    if (zeo_count_first_field(z->zcc_log, "HIT") != hits + 5)
        zeo_fail("timing batch did not produce five warm hits");
    if (zeo_count_line_eq(z->compiler_launches, "preprocess") != pre + 5)
        zeo_fail("timing batch did not freshly preprocess every invocation");
    if (zeo_count_line_eq(z->compiler_launches, "compile") != cmp)
        zeo_fail("timing batch launched an object compiler");
}

static void p2_timing(struct zeo *z)
{
    const char *opt = getenv("ZCC_EPOCH_TIMING");
    if (!opt || strcmp(opt, "1") != 0)
        return;
    char ref[ZEO_PATH];
    if (zeo_join(ref, sizeof ref, z->work, "timing-reference.o") != 0 ||
        zeo_copy_file(z->make_copy, ref) != 0)
        zeo_bail(1);
    p2_timing_kind(z, "same-inode", z->zcc, ref);
    p2_timing_kind(z, "identical-copy", z->zcc_copy, ref);
    puts("epoch-wrapper-timing scope=whole-invocation-plus-output-check; "
         "includes preprocessing, not isolated hashing");
}

static void p2_legacy_parity(struct zeo *z)
{
    char obj[ZEO_PATH];
    if (ovf(snprintf(obj, sizeof obj, "%s/legacy.o", z->object_root),
            sizeof obj))
        zeo_bail(2);
    char *cc[8];
    cc[0] = (char *)"cc";
    cc[1] = (char *)"-std=c23";
    cc[2] = (char *)"-O2";
    cc[3] = (char *)"-Wall";
    cc[4] = (char *)"-Wextra";
    cc[5] = (char *)"-Werror";
    cc[6] = z->seed;
    cc[7] = NULL;
    int rc = 0;
    p2_must(z, zeo_legacy_x(z, "dep", obj, cc, NULL, NULL, NULL, &rc), rc);
    if (!zeo_files_equal(z->object, obj))
        zeo_fail("native and legacy object bytes diverged");
}

static void p2_mmd_retained(const char *ndep, const char *const dirs[3],
                            const char *label)
{
    static const char *const names[3] = { "/local_header.h",
                                           "/generated_header.h",
                                           "/vendor_header.h" };
    char needle[ZEO_PATH];
    for (int i = 0; i < 3; i++) {
        if (ovf(snprintf(needle, sizeof needle, "%s%s", dirs[i], names[i]),
                sizeof needle))
            zeo_bail(2);
        if (!lct_file_has(ndep, needle))
            zeo_failf("%s MMD depfile omitted project input %s", label,
                      needle);
    }
}

static void p2_mmd_compare(struct zeo *z, char *cc[10], const char *label,
                           const char *const dirs[3], const char *sysn,
                           const char *const f[5])
{
    /* f: out, dep, nobj, ndep */
    int rc = 0;
    if (zeo_copy_file(f[0], f[2]) != 0 || zeo_copy_file(f[1], f[3]) != 0 ||
        unlink(f[0]) != 0 || unlink(f[1]) != 0)
        zeo_bail(1);
    p2_must(z, zeo_legacy_x(z, "dep", f[0], cc, NULL, NULL, NULL, &rc), rc);
    if (!zeo_files_equal(f[2], f[0]))
        zeo_failf("%s native/legacy MMD object bytes diverged", label);
    if (!zeo_files_equal(f[3], f[1]))
        zeo_failf("%s native/legacy MMD depfile bytes diverged", label);
    p2_mmd_retained(f[3], dirs, label);
    if (lct_file_has(f[3], sysn) || lct_file_has(f[3], "stdio.h"))
        zeo_failf("%s MMD depfile retained a system header", label);
}

static void p2_mmd_one(struct zeo *z, const char *compiler,
                       const char *label, const char *local,
                       const char *gen, const char *vend,
                       const char *sysdir)
{
    char out[ZEO_PATH], dep[ZEO_PATH], nobj[ZEO_PATH], ndep[ZEO_PATH];
    char il[ZEO_PATH], ig[ZEO_PATH], iv[ZEO_PATH], sysn[ZEO_PATH];
    if (ovf(snprintf(out, sizeof out, "%s/mmd-%s.o", z->object_root, label),
            sizeof out) ||
        ovf(snprintf(nobj, sizeof nobj, "%s/mmd-%s.native.o", z->work, label),
            sizeof nobj) ||
        ovf(snprintf(ndep, sizeof ndep, "%s/mmd-%s.native.d", z->work, label),
            sizeof ndep) ||
        ovf(snprintf(il, sizeof il, "-I%s", local), sizeof il) ||
        ovf(snprintf(ig, sizeof ig, "-I%s", gen), sizeof ig) ||
        ovf(snprintf(iv, sizeof iv, "-I%s", vend), sizeof iv) ||
        ovf(snprintf(sysn, sizeof sysn, "%s/system_header.h", sysdir),
            sizeof sysn) ||
        zeo_dep_of(dep, sizeof dep, out))
        zeo_bail(2);
    char *cc[10];
    cc[0] = (char *)compiler;
    cc[1] = (char *)"-std=c23";
    cc[2] = (char *)"-O2";
    cc[3] = (char *)"-Wall";
    cc[4] = (char *)"-Wextra";
    cc[5] = (char *)"-Werror";
    cc[6] = il;
    cc[7] = ig;
    cc[8] = iv;
    cc[9] = NULL;
    int rc = 0;
    p2_must(z, zeo_compile_x(z, NULL, "dep", out, cc, NULL, NULL, NULL, &rc),
            rc);
    const char *const dirs[3] = { local, gen, vend };
    const char *const files[5] = { out, dep, nobj, ndep, NULL };
    p2_mmd_compare(z, cc, label, dirs, sysn, files);
}

static void p2_mmd_hdr(const char *dir, const char *name, const char *text)
{
    char hdr[ZEO_PATH];
    if (zeo_join(hdr, sizeof hdr, dir, name) ||
        zeo_write_file(hdr, text) != 0)
        zeo_bail(1);
}

static void p2_mmd(struct zeo *z)
{
    char local[ZEO_PATH], gen[ZEO_PATH], vend[ZEO_PATH], sysd[ZEO_PATH];
    char src[ZEO_PATH], orig[ZEO_PATH], clang[ZEO_PATH];
    if (ovf(snprintf(local, sizeof local, "%s/mmd/local", z->work),
            sizeof local) ||
        ovf(snprintf(gen, sizeof gen, "%s/mmd/generated", z->work),
            sizeof gen) ||
        ovf(snprintf(vend, sizeof vend, "%s/mmd/vendor", z->work),
            sizeof vend) ||
        ovf(snprintf(sysd, sizeof sysd, "%s/mmd/system", z->work),
            sizeof sysd) ||
        ovf(snprintf(src, sizeof src, "%s/mmd/main.c", z->work), sizeof src))
        zeo_bail(2);
    if (csr_mkdirs(local) || csr_mkdirs(gen) || csr_mkdirs(vend) ||
        csr_mkdirs(sysd))
        zeo_bail(1);
    p2_mmd_hdr(local, "local_header.h", "#define MMD_LOCAL_VALUE 1\n");
    p2_mmd_hdr(gen, "generated_header.h", "#define MMD_GENERATED_VALUE 2\n");
    p2_mmd_hdr(vend, "vendor_header.h", "#define MMD_VENDOR_VALUE 4\n");
    p2_mmd_hdr(sysd, "system_header.h", "#define MMD_SYSTEM_VALUE 8\n");
    if (zeo_write_file(src,
                       "#include <stdio.h>\n"
                       "#include \"local_header.h\"\n"
                       "#include <generated_header.h>\n"
                       "#include <vendor_header.h>\n"
                       "#include <system_header.h>\n"
                       "int mmd_value(void) {\n"
                       " return MMD_LOCAL_VALUE + MMD_GENERATED_VALUE +\n"
                       "        MMD_VENDOR_VALUE + MMD_SYSTEM_VALUE;\n"
                       "}\n") != 0)
        zeo_bail(1);
    strcpy(orig, z->source);
    strcpy(z->source, src);
    if (setenv("C_INCLUDE_PATH", sysd, 1) != 0)
        zeo_bail(1);
    p2_mmd_one(z, "cc", "gcc", local, gen, vend, sysd);
    if (zeo_which("clang", clang, sizeof clang) == 0)
        p2_mmd_one(z, "clang", "clang", local, gen, vend, sysd);
    unsetenv("C_INCLUDE_PATH");
    strcpy(z->source, orig);
}

int zeo_part2(struct zeo *z)
{
    p2_distinct(z);
    p2_long(z);
    p2_control(z);
    p2_standalone(z);
    p2_copy(z);
    p2_different(z);
    p2_timing(z);
    p2_legacy_parity(z);
    p2_mmd(z);
    return 0;
}
