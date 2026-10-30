/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-zcc-epoch-object — focused parity and fail-closed
 * gate for native compile-epoch publication. Ported from
 * tools/lint/check_zcc_epoch_object.sh (deleted). This file holds the
 * entry point, fixture setup, and part1: the silent-compiler refusal, the
 * serialized admission-lock compile, marker-authority refusals, the
 * in-process cache hit, verified-mode MISS, and the Make-style wrapper
 * unwrap. Parts 2 and 3 live in gate_zcc_epoch_object_late.c and
 * gate_zcc_epoch_object_refuse.c. Selftest:
 * gate_zcc_epoch_object_selftest.c.
 */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc_text.h"
#include "lintc.h"
#include "gate_zcc_epoch_object_priv.h"

static const char k_main_c[] =
    "#if __has_include(\"epoch-choice.h\")\n"
    "#include \"epoch-choice.h\"\n"
    "#else\n"
    "#define EPOCH_LABEL \"native-epoch\"\n"
    "#endif\n"
    "#include <stdio.h>\n"
    "int main(void) { puts(EPOCH_LABEL); return 0; }\n";

static const char k_counting_sh[] =
    "#!/usr/bin/env bash\n"
    "set -euo pipefail\n"
    "kind=other\n"
    "is_compile=0\n"
    "for argument in \"$@\"; do\n"
    "    if [ \"$argument\" = -c ]; then\n"
    "        is_compile=1\n"
    "        kind=compile\n"
    "    elif [ \"$argument\" = -E ]; then\n"
    "        kind=preprocess\n"
    "    fi\n"
    "done\n"
    "printf '%s\\n' \"$kind\" >> \"$COMPILER_LAUNCHES\"\n"
    "cc \"$@\"\n"
    "if [ \"$is_compile\" = 1 ] && [ -n \"${COMPILER_COMPLETED:-}\" ]; then\n"
    "    : > \"$COMPILER_COMPLETED\"\n"
    "fi\n";

static const char k_lock_holder_c[] =
    "#define _DARWIN_C_SOURCE\n"
    "#define _POSIX_C_SOURCE 200809L\n"
    "#include <errno.h>\n"
    "#include <fcntl.h>\n"
    "#include <stdio.h>\n"
    "#include <sys/file.h>\n"
    "#include <time.h>\n"
    "#include <unistd.h>\n"
    "int main(int argc, char **argv)\n"
    "{\n"
    "    if (argc != 4)\n"
    "        return 2;\n"
    "    int fd = open(argv[1], O_RDWR | O_CREAT, 0600);\n"
    "    if (fd < 0 || flock(fd, LOCK_EX) != 0)\n"
    "        return 2;\n"
    "    int ready = open(argv[2], O_WRONLY | O_CREAT | O_EXCL, 0600);\n"
    "    if (ready < 0 || close(ready) != 0)\n"
    "        return 2;\n"
    "    const struct timespec pause = { .tv_sec = 0, .tv_nsec = 1000000 };\n"
    "    while (access(argv[3], F_OK) != 0) {\n"
    "        if (errno != ENOENT || nanosleep(&pause, NULL) != 0)\n"
    "            return 2;\n"
    "    }\n"
    "    return close(fd) == 0 ? 0 : 2;\n"
    "}\n";

static void p1_args_cc(char *args[8], const char *compiler,
                       const char *seed)
{
    args[0] = (char *)compiler;
    args[1] = (char *)"-std=c23";
    args[2] = (char *)"-O2";
    args[3] = (char *)"-Wall";
    args[4] = (char *)"-Wextra";
    args[5] = (char *)"-Werror";
    args[6] = (char *)seed;
    args[7] = NULL;
}

void zeo_args_wrap(char *args[10], const char *wrapper,
                   const char *counting, const char *dflag,
                   const char *seed)
{
    args[0] = (char *)wrapper;
    args[1] = (char *)counting;
    args[2] = (char *)"-std=c23";
    args[3] = (char *)"-O2";
    args[4] = (char *)"-Wall";
    args[5] = (char *)"-Wextra";
    args[6] = (char *)"-Werror";
    args[7] = (char *)dflag;
    args[8] = (char *)seed;
    args[9] = NULL;
}

static void p1_silent(struct zeo *z)
{
    char silent[ZEO_PATH], obj[ZEO_PATH], log[ZEO_PATH], dep[ZEO_PATH];
    char needle[ZEO_PATH];
    if (zeo_join(silent, sizeof silent, z->work, "silent-compiler.sh") ||
        ovf(snprintf(obj, sizeof obj, "%s/silent-compiler.o", z->object_root),
            sizeof obj) ||
        zeo_join(log, sizeof log, z->work, "silent-compiler.log") ||
        zeo_dep_of(dep, sizeof dep, obj))
        zeo_bail(2);
    if (zeo_write_file(silent, "#!/usr/bin/env bash\nexit 2\n") != 0 ||
        chmod(silent, 0755) != 0)
        zeo_bail(1);
    char *args[] = { silent, NULL };
    int rc = 0;
    if (zeo_legacy_x(z, "dep", obj, args, log, log, NULL, &rc) != 0)
        zeo_bail(1);
    if (rc == 0)
        zeo_fail("legacy epoch object accepted a silent compiler failure");
    if (ovf(snprintf(needle, sizeof needle, "compiler exited rc=2 source=%s",
                     z->source), sizeof needle))
        zeo_bail(2);
    if (!lct_file_has(log, needle)) {
        zeo_head_to_stderr(log, 80);
        zeo_fail("silent compiler failure lacked source and exit-status "
                 "context");
    }
    if (zeo_exists(obj) || zeo_exists(dep))
        zeo_fail("silent compiler failure published stable artifacts");
}

static void p1_verify_published(struct zeo *z, const char *dep,
                                const char *prog, char *out, size_t cap)
{
    char quar[ZEO_PATH], quar_d[ZEO_PATH], needle[ZEO_PATH];
    if (ovf(snprintf(quar, sizeof quar, "%s/.admission.lock", z->object_root),
            sizeof quar) ||
        ovf(snprintf(quar_d, sizeof quar_d, "%s.d", quar), sizeof quar_d) ||
        ovf(snprintf(needle, sizeof needle, "%s:", z->object), sizeof needle))
        zeo_bail(2);
    if (zeo_exists(quar) || zeo_exists(quar_d))
        zeo_fail("epoch publisher created a quarantine-splittable admission "
                 "lock");
    if (!zeo_nonempty(z->object) || !zeo_nonempty(dep))
        zeo_fail("native dep compile did not publish both artifacts");
    if (!zeo_files_equal(z->expected, z->unverified))
        zeo_fail("successful publication did not leave exact unverified "
                 "authority");
    if (!lct_file_has(dep, needle))
        zeo_fail("native depfile does not name the final object");
    char *largs[5];
    largs[0] = (char *)"cc";
    largs[1] = (char *)"-o";
    largs[2] = (char *)prog;
    largs[3] = z->object;
    largs[4] = NULL;
    if (zeo_run("cc", largs, NULL, NULL) != 0)
        zeo_bail(1);
    char *pargs[2];
    pargs[0] = (char *)prog;
    pargs[1] = NULL;
    if (zeo_capture(prog, pargs, out, cap) != 0 ||
        strcmp(out, "native-epoch") != 0)
        zeo_fail("native object did not execute the source behavior");
}

static void p1_adm_build(struct zeo *z, const char *src, const char *holder)
{
    if (zeo_write_file(src, k_lock_holder_c) != 0)
        zeo_bail(1);
    char *ccargs[10];
    ccargs[0] = z->posix_cc;
    ccargs[1] = (char *)"-std=c23";
    ccargs[2] = (char *)"-Wall";
    ccargs[3] = (char *)"-Wextra";
    ccargs[4] = (char *)"-Werror";
    ccargs[5] = (char *)"-pedantic";
    ccargs[6] = (char *)"-o";
    ccargs[7] = (char *)holder;
    ccargs[8] = (char *)src;
    ccargs[9] = NULL;
    if (zeo_run(z->posix_cc, ccargs, NULL, NULL) != 0)
        zeo_bail(1);
}

static void p1_adm_blocked(struct zeo *z, const char *dep, const char *log)
{
    if (setenv("COMPILER_COMPLETED", z->lock_compile_done, 1) != 0)
        zeo_bail(1);
    char *cargs[8];
    p1_args_cc(cargs, z->counting, z->seed);
    int rc = 0;
    if (zeo_compile_x(z, NULL, "dep", z->object, cargs, log, log,
                      &z->locked_compile, &rc) != 0)
        zeo_bail(1);
    zeo_wait_marker(z->lock_compile_done, z->locked_compile,
                    "locked epoch compile");
    zeo_wait_lock_waiter(z->admission_lock, z->locked_compile);
    if (!zeo_alive(z->locked_compile))
        zeo_fail("epoch object did not wait for the held admission lock");
    if (zeo_exists(z->object) || zeo_exists(dep) || zeo_exists(z->unverified))
        zeo_fail("stable epoch state appeared while admission lock was held");
}

static void p1_adm_release(struct zeo *z, const char *release,
                           const char *log)
{
    if (zeo_write_file(release, "") != 0)
        zeo_bail(1);
    if (zeo_wait(z->lock_holder) != 0)
        zeo_fail("admission lock holder failed");
    z->lock_holder = 0;
    if (zeo_wait(z->locked_compile) != 0) {
        zeo_head_to_stderr(log, 80);
        zeo_fail("serialized epoch compile failed after lock release");
    }
    z->locked_compile = 0;
    unsetenv("COMPILER_COMPLETED");
}

static void p1_admission(struct zeo *z)
{
    char src[ZEO_PATH], holder[ZEO_PATH], ready[ZEO_PATH], release[ZEO_PATH];
    char log[ZEO_PATH], dep[ZEO_PATH], prog[ZEO_PATH], out[256];
    if (zeo_join(src, sizeof src, z->work, "lock-holder.c") ||
        zeo_join(holder, sizeof holder, z->work, "lock-holder") ||
        zeo_join(ready, sizeof ready, z->work, "admission-lock-ready") ||
        zeo_join(release, sizeof release, z->work, "admission-lock-release") ||
        zeo_join(log, sizeof log, z->work, "locked-compile.log") ||
        zeo_join(prog, sizeof prog, z->work, "program") ||
        zeo_dep_of(dep, sizeof dep, z->object))
        zeo_bail(2);
    p1_adm_build(z, src, holder);
    char *hargs[5] = { holder, z->admission_lock, ready, release, NULL };
    z->lock_holder = zeo_spawn(holder, hargs, NULL, NULL);
    if (z->lock_holder < 0)
        zeo_bail(1);
    zeo_wait_marker(ready, z->lock_holder, "admission lock holder");
    p1_adm_blocked(z, dep, log);
    p1_adm_release(z, release, log);
    p1_verify_published(z, dep, prog, out, sizeof out);
}

static void p1_refuse(struct zeo *z, int native, const char *tag,
                      const char *m1, const char *m2)
{
    const char *b = native ? "native" : "legacy";
    char obj[ZEO_PATH], dep[ZEO_PATH];
    if (ovf(snprintf(obj, sizeof obj, "%s/%s-%s.o", z->object_root, tag, b),
            sizeof obj) ||
        zeo_dep_of(dep, sizeof dep, obj))
        zeo_bail(2);
    char *cc[8];
    p1_args_cc(cc, "cc", z->seed);
    int rc = 0;
    if (zeo_backend_x(z, native, "dep", obj, cc, "/dev/null", "/dev/null",
                      NULL, &rc) != 0)
        zeo_bail(1);
    if (rc == 0)
        zeo_failf(m1, b);
    if (zeo_exists(obj) || zeo_exists(dep))
        zeo_failf(m2, b);
}

static void p1_stamp(struct zeo *z)
{
    char obj[ZEO_PATH], b[ZEO_STAMP];
    if (zeo_file_stamp(z->unverified, z->marker_stamp, ZEO_STAMP) != 0)
        zeo_fail("could not capture unverified marker identity");
    if (ovf(snprintf(obj, sizeof obj, "%s/legacy-marker-reuse.o",
                     z->object_root), sizeof obj))
        zeo_bail(2);
    char *cc[8];
    p1_args_cc(cc, "cc", z->seed);
    int rc = 0;
    if (zeo_legacy_x(z, "dep", obj, cc, NULL, NULL, NULL, &rc) != 0 || rc != 0)
        zeo_bail(rc ? rc : 1);
    if (zeo_file_stamp(z->unverified, b, sizeof b) != 0 ||
        strcmp(z->marker_stamp, b) != 0)
        zeo_fail("legacy same-authority publication rewrote the durable "
                 "marker");
}

static void p1_markers(struct zeo *z)
{
    char redir[ZEO_PATH];
    if (zeo_write_file(z->unverified, "malformed\n") != 0)
        zeo_bail(1);
    p1_refuse(z, 1, "malformed-marker",
              "%s epoch object overwrote a malformed unverified marker",
              "%s malformed marker allowed stable artifact publication");
    p1_refuse(z, 0, "malformed-marker",
              "%s epoch object overwrote a malformed unverified marker",
              "%s malformed marker allowed stable artifact publication");
    if (zeo_copy_file(z->expected, z->unverified) != 0 ||
        unlink(z->unverified) != 0)
        zeo_bail(1);
    if (zeo_join(redir, sizeof redir, z->work, "unverified-redirect") != 0 ||
        mkdir(redir, 0755) != 0)
        zeo_bail(1);
    if (zeo_dir_link(z->unverified, redir) != 0)
        zeo_fail("could not create a real unverified-marker link fixture");
    p1_refuse(z, 1, "symlink-marker",
              "%s epoch object followed an unverified marker symlink",
              "%s symlink marker allowed stable artifact publication");
    p1_refuse(z, 0, "symlink-marker",
              "%s epoch object followed an unverified marker symlink",
              "%s symlink marker allowed stable artifact publication");
    zeo_dir_unlink(z->unverified);
    if (zeo_copy_file(z->expected, z->unverified) != 0)
        zeo_bail(1);
    p1_stamp(z);
}

static int p1_stamp_eq(struct zeo *z)
{
    char b[ZEO_STAMP];
    return zeo_file_stamp(z->unverified, b, sizeof b) == 0 &&
           strcmp(z->marker_stamp, b) == 0;
}

static void p1_cache_hit(struct zeo *z)
{
    char dep[ZEO_PATH], tail[ZEO_PATH];
    long cold_pre = zeo_count_line_eq(z->compiler_launches, "preprocess");
    long cold_cmp = zeo_count_line_eq(z->compiler_launches, "compile");
    if (zeo_dep_of(dep, sizeof dep, z->object) != 0 ||
        unlink(z->object) != 0 || unlink(dep) != 0)
        zeo_bail(1);
    if (setenv("COMPILER_COMPLETED", z->lock_compile_done, 1) != 0)
        zeo_bail(1);
    char *cc[8];
    p1_args_cc(cc, z->counting, z->seed);
    int rc = 0;
    if (zeo_compile_x(z, NULL, "dep", z->object, cc, NULL, NULL, NULL,
                      &rc) != 0 || rc != 0)
        zeo_bail(rc ? rc : 1);
    unsetenv("COMPILER_COMPLETED");
    if (zeo_tail1(z->zcc_log, tail, sizeof tail) != 0 ||
        !zeo_first_tok_is(tail, "HIT"))
        zeo_fail("identical epoch compile did not use the in-process cache");
    if (zeo_count_line_eq(z->compiler_launches, "preprocess") != cold_pre + 1)
        zeo_fail("source cache hit did not recheck the include search");
    if (zeo_count_line_eq(z->compiler_launches, "compile") != cold_cmp)
        zeo_fail("unchanged source cache hit launched an object compiler");
    if (!zeo_nonempty(z->object) || !zeo_nonempty(dep))
        zeo_fail("cache hit did not restore both epoch artifacts");
    if (!p1_stamp_eq(z))
        zeo_fail("same-authority publication rewrote the durable unverified "
                 "marker");
}

static void p1_verified(struct zeo *z)
{
    char dep[ZEO_PATH], tail[ZEO_PATH];
    long before = zeo_count_lines(z->compiler_launches);
    if (zeo_dep_of(dep, sizeof dep, z->object) != 0 ||
        unlink(z->object) != 0 || unlink(dep) != 0)
        zeo_bail(1);
    if (setenv("ZCC_VERIFIED", "1", 1) != 0)
        zeo_bail(1);
    char *cc[8];
    p1_args_cc(cc, z->counting, z->seed);
    int rc = 0;
    if (zeo_compile_x(z, NULL, "dep", z->object, cc, NULL, NULL, NULL,
                      &rc) != 0 || rc != 0)
        zeo_bail(rc ? rc : 1);
    unsetenv("ZCC_VERIFIED");
    if (zeo_tail1(z->zcc_log, tail, sizeof tail) != 0 ||
        !zeo_first_tok_is(tail, "MISS"))
        zeo_fail("verified epoch compile served a same-account cache entry");
    zeo_expect_log_output(z, z->object);
    if (zeo_count_lines(z->compiler_launches) != before + 1)
        zeo_fail("verified epoch compile skipped the real compiler");
    if (!zeo_nonempty(z->object) || !zeo_nonempty(dep))
        zeo_fail("verified epoch compile did not publish complete fresh "
                 "artifacts");
}

static void p1_ms_compile(struct zeo *z, const char *obj, char *cc[10])
{
    int rc = 0;
    if (zeo_compile_x(z, NULL, "dep", obj, cc, NULL, NULL, NULL, &rc) != 0 ||
        rc != 0)
        zeo_bail(rc ? rc : 1);
}

static void p1_ms_outcome(struct zeo *z, const char *obj, long want,
                          const char *kind, const char *msg)
{
    char tail[ZEO_PATH];
    if (zeo_outcome_count(z->zcc_log) != want ||
        zeo_tail1(z->zcc_log, tail, sizeof tail) != 0 ||
        !zeo_first_tok_is(tail, kind))
        zeo_fail(msg);
    zeo_expect_log_output(z, obj);
}

static void p1_make_style(struct zeo *z)
{
    char obj[ZEO_PATH], dep[ZEO_PATH];
    if (ovf(snprintf(obj, sizeof obj, "%s/make-style.o", z->object_root),
            sizeof obj) ||
        zeo_dep_of(dep, sizeof dep, obj))
        zeo_bail(2);
    long log_before = zeo_outcome_count(z->zcc_log);
    long launches_before = zeo_count_lines(z->compiler_launches);
    char *cc[10];
    zeo_args_wrap(cc, z->zcc, z->counting, "-DMAKE_STYLE_EPOCH=1", z->seed);
    p1_ms_compile(z, obj, cc);
    p1_ms_outcome(z, obj, log_before + 1, "MISS",
                  "Make-style cold compile used more than one zcc "
                  "coordinator");
    if (zeo_count_lines(z->compiler_launches) <= launches_before)
        zeo_fail("Make-style cold compile launched no compiler child");
    long cold_pre = zeo_count_line_eq(z->compiler_launches, "preprocess");
    long cold_cmp = zeo_count_line_eq(z->compiler_launches, "compile");
    if (unlink(obj) != 0 || unlink(dep) != 0)
        zeo_bail(1);
    p1_ms_compile(z, obj, cc);
    p1_ms_outcome(z, obj, log_before + 2, "HIT",
                  "Make-style warm compile used more than one zcc "
                  "coordinator");
    if (zeo_count_line_eq(z->compiler_launches, "preprocess") != cold_pre + 1)
        zeo_fail("Make-style warm hit did not recheck includes");
    if (zeo_count_line_eq(z->compiler_launches, "compile") != cold_cmp)
        zeo_fail("Make-style warm hit launched an object compiler");
}

int zeo_part1(struct zeo *z)
{
    p1_silent(z);
    p1_admission(z);
    p1_markers(z);
    p1_cache_hit(z);
    p1_verified(z);
    p1_make_style(z);
    return 0;
}

static int run_setup_zcc(struct zeo *z)
{
    const char *test_bin = getenv("ZCC_EPOCH_TEST_BIN");
    if (test_bin && test_bin[0]) {
        if (ovf(snprintf(z->zcc, sizeof z->zcc, "%s", test_bin), sizeof z->zcc))
            return 2;
        return 0;
    }
    char script[ZEO_PATH], *argv[2];
    if (ovf(snprintf(script, sizeof script, "%s/tools/dev/zcc_bootstrap.sh",
                     z->root), sizeof script))
        return 2;
    argv[0] = script;
    argv[1] = NULL;
    int code = zeo_capture(script, argv, z->zcc, sizeof z->zcc);
    if (code != 0)
        zeo_bail(code);
    if (!z->zcc[0])
        zeo_bail(1);
    return 0;
}

static int run_paths_work(struct zeo *z)
{
    if (zeo_join(z->source, sizeof z->source, z->work, "main.c") ||
        zeo_join(z->object_base, sizeof z->object_base, z->work, "objects") ||
        ovf(snprintf(z->object_root, sizeof z->object_root, "%s/epochs/%s",
                     z->object_base, z->epoch), sizeof z->object_root) ||
        ovf(snprintf(z->admission_lock, sizeof z->admission_lock,
                     "%s/.epoch-admission/%s.lock", z->object_base,
                     z->epoch), sizeof z->admission_lock) ||
        ovf(snprintf(z->session, sizeof z->session, "%s/.build-session",
                     z->object_root), sizeof z->session) ||
        ovf(snprintf(z->unverified, sizeof z->unverified, "%s/.unverified",
                     z->object_root), sizeof z->unverified) ||
        ovf(snprintf(z->object, sizeof z->object, "%s/main.o",
                     z->object_root), sizeof z->object))
        return 2;
    return 0;
}

static int run_paths_aux(struct zeo *z)
{
    if (zeo_join(z->expected, sizeof z->expected, z->work,
                 "unverified.expected") ||
        zeo_join(z->zcc_log, sizeof z->zcc_log, z->work, "zcc.log") ||
        zeo_join(z->counting, sizeof z->counting, z->work,
                 "counting-compiler.sh") ||
        zeo_join(z->compiler_launches, sizeof z->compiler_launches, z->work,
                 "compiler-launches") ||
        zeo_join(z->lock_compile_done, sizeof z->lock_compile_done, z->work,
                 "admission-compiler-complete") ||
        zeo_join(z->refusal_marker, sizeof z->refusal_marker, z->work,
                 "compiler-ran") ||
        ovf(snprintf(z->seed, sizeof z->seed, "-frandom-seed=%s", z->source),
            sizeof z->seed))
        return 2;
    if (ovf(snprintf(z->posix_cc, sizeof z->posix_cc, "cc"),
            sizeof z->posix_cc))
        return 2;
    return 0;
}

static int run_exports(struct zeo *z)
{
    char cache[ZEO_PATH], lock_root[ZEO_PATH];
    if (zeo_join(cache, sizeof cache, z->work, "cache") ||
        ovf(snprintf(lock_root, sizeof lock_root, "%s/.epoch-admission",
                     z->object_base), sizeof lock_root))
        return 2;
    if (csr_mkdirs(z->object_root) != 0 || csr_mkdirs(lock_root) != 0)
        return 1;
    if (setenv("ZCC_DIR", cache, 1) != 0 ||
        setenv("ZCC_LOG", z->zcc_log, 1) != 0 ||
        setenv("COMPILER_LAUNCHES", z->compiler_launches, 1) != 0 ||
        setenv("REFUSAL_MARKER", z->refusal_marker, 1) != 0)
        return 1;
    return 0;
}

static int run_fixtures(struct zeo *z)
{
    if (zeo_write_file(z->source, k_main_c) != 0 ||
        zeo_write_file(z->counting, k_counting_sh) != 0 ||
        chmod(z->counting, 0755) != 0)
        return 1;
    zeo_write_session(z);
    char text[512];
    zeo_write_marker(z, z->expected, text, sizeof text,
                     "schema=zcl.build_epoch_unverified.v1\n"
                     "source_id=%s\nmutation=%s\ncompiler_id=%s\n"
                     "epoch=%s\n",
                     "unverified text exceeds its buffer",
                     "could not write the expected unverified marker");
    return 0;
}

static void run_hashes(struct zeo *z)
{
    if (zeo_sha256_hex("source", z->source_id) ||
        zeo_sha256_hex("mutation", z->mutation) ||
        zeo_sha256_hex("epoch", z->epoch) ||
        zeo_sha256_hex("compiler", z->compiler_id))
        zeo_fail("SHA-256 tool is unavailable");
}

static void run_scratch(struct zeo *z)
{
    char tpl[ZEO_PATH];
    const char *td = env_or("TMPDIR", "test-tmp");
    if (csr_mkdirs(td) != 0)
        zeo_bail(2);
    if (ovf(snprintf(tpl, sizeof tpl, "%s/zcl-zcc-epoch.XXXXXX", td),
            sizeof tpl))
        zeo_bail(2);
    if (!mkdtemp(tpl))
        zeo_fail("mkdtemp failed for the epoch-object scratch directory");
    char resolved[PATH_MAX];
    if (!realpath(tpl, resolved))
        zeo_bail(1);
    if (ovf(snprintf(z->work, sizeof z->work, "%s", resolved),
            sizeof z->work))
        zeo_bail(2);
}

int check_zcc_epoch_object_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    static struct zeo z;
    char ccpath[ZEO_PATH];
    memset(&z, 0, sizeof z);
    zeo_set_ctx(&z);
    unsetenv("ZCC_VERIFIED");
    if (!getcwd(z.root, sizeof z.root))
        zeo_bail(1);
    int rc = run_setup_zcc(&z);
    if (rc != 0)
        zeo_bail(rc);
    run_scratch(&z);
    if (access(z.zcc, X_OK) != 0)
        zeo_fail("zcc bootstrap is unavailable");
    if (zeo_which("cc", ccpath, sizeof ccpath) != 0)
        zeo_fail("C23 compiler is unavailable");
    run_hashes(&z);
    rc = run_paths_work(&z);
    if (rc == 0)
        rc = run_paths_aux(&z);
    if (rc == 0)
        rc = run_exports(&z);
    if (rc == 0)
        rc = run_fixtures(&z);
    if (rc != 0)
        zeo_bail(rc);
    zeo_part1(&z);
    zeo_part2(&z);
    zeo_part3(&z);
    zeo_cleanup(&z);
    printf("check_zcc_epoch_object: PASS cache=content_hit "
           "fresh_preprocess=observed object_compile_avoided=observed "
           "shadow_behavior=executed mmd_dep_parity=exact "
           "system_authority=closed path_swap=closed "
           "admission_lock=serialized unverified=durable "
           "coverage_record=last\n");
    return 0;
}
