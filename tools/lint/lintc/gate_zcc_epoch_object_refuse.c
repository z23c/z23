/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: part3 of the check-zcc-epoch-object gate port
 * (gate_zcc_epoch_object.c): the authority-refusal battery (wrong source
 * id, output outside the epoch, session mutation, NUL, malformed, extra
 * and newline-less sessions, symlinked object paths), the adversarial
 * parent-swap compiler, the ABA session boundary, coverage-note
 * admission, the shadow-header behavior change, the ephemeral-descriptor
 * leak check, and the PASS line.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_zcc_epoch_object_priv.h"

static const char k_refusal_sh[] =
    "#!/usr/bin/env bash\n"
    "set -euo pipefail\n"
    ": > \"$REFUSAL_MARKER\"\n"
    "exit 0\n";

static const char k_aba_sh[] =
    "#!/usr/bin/env bash\n"
    "set -euo pipefail\n"
    "cc \"$@\"\n"
    "printf '%s\\n' 'changed-during-compile' >> \"$SESSION_PATH\"\n";

static const char k_swap_sh[] =
    "#!/usr/bin/env bash\n"
    "set -euo pipefail\n"
    "mv -- \"$SWAP_PARENT\" \"$SWAP_SAVED\"\n"
    "if uname -s | grep -Eq '^(MSYS|MINGW|CYGWIN)'; then\n"
    "    cmd.exe /d /c mklink /J \"$(cygpath -w \"$SWAP_PARENT\")\" "
    "\"$(cygpath -w \"$SWAP_ESCAPE\")\" >/dev/null\n"
    "else\n"
    "    ln -s -- \"$SWAP_ESCAPE\" \"$SWAP_PARENT\"\n"
    "fi\n"
    "cc \"$@\"\n"
    ": > \"$SWAP_DONE\"\n";

static void p3_must(int ret, int rc)
{
    if (ret != 0 || rc != 0)
        zeo_bail(rc ? rc : 1);
}

static void p3_wrong_source(struct zeo *z)
{
    char bad[ZEO_PATH], wrong[ZEO_HASH];
    if (ovf(snprintf(bad, sizeof bad, "%s/bad.o", z->object_root),
            sizeof bad) ||
        zeo_join(z->refusal, sizeof z->refusal, z->work,
                 "refusal-compiler.sh"))
        zeo_bail(2);
    if (zeo_sha256_hex("wrong-source", wrong) != 0)
        zeo_fail("SHA-256 tool is unavailable");
    if (zeo_write_file(z->refusal, k_refusal_sh) != 0 ||
        chmod(z->refusal, 0755) != 0 ||
        zeo_write_file(z->refusal_marker, "") != 0)
        zeo_bail(1);
    unlink(z->refusal_marker);
    char *argv[14];
    argv[0] = z->zcc;
    argv[1] = (char *)"--epoch-object";
    argv[2] = (char *)"dep";
    argv[3] = bad;
    argv[4] = z->source;
    argv[5] = wrong;
    argv[6] = (char *)"1";
    argv[7] = z->mutation;
    argv[8] = z->epoch;
    argv[9] = z->compiler_id;
    argv[10] = z->session;
    argv[11] = (char *)"--";
    argv[12] = z->refusal;
    argv[13] = NULL;
    if (zeo_run(z->zcc, argv, "/dev/null", "/dev/null") == 0)
        zeo_fail("mismatched session authority was accepted");
    if (zeo_exists(bad))
        zeo_fail("authority refusal published an object");
}

static void p3_outside(struct zeo *z, int native, const char *b)
{
    char o1[ZEO_PATH], o2[ZEO_PATH];
    if (ovf(snprintf(o1, sizeof o1, "%s/outside-%s.o", z->work, b),
            sizeof o1) ||
        ovf(snprintf(o2, sizeof o2, "%s/../escaped-%s.o", z->object_root, b),
            sizeof o2))
        zeo_bail(2);
    char *args[2];
    args[0] = z->refusal;
    args[1] = NULL;
    int rc = 0;
    unlink(z->refusal_marker);
    if (zeo_backend_x(z, native, "dep", o1, args, "/dev/null", "/dev/null",
                      NULL, &rc) != 0)
        zeo_bail(1);
    if (rc == 0)
        zeo_failf("%s accepted output outside the epoch", b);
    rc = 0;
    unlink(z->refusal_marker);
    if (zeo_backend_x(z, native, "dep", o2, args, "/dev/null", "/dev/null",
                      NULL, &rc) != 0)
        zeo_bail(1);
    if (rc == 0)
        zeo_failf("%s accepted parent traversal in the epoch namespace", b);
    if (zeo_exists(z->refusal_marker))
        zeo_failf("%s containment refusal launched the compiler", b);
}

static void p3_case(struct zeo *z, const char *tag, int check_marker,
                    const char *m1, const char *m2)
{
    for (int native = 1; native >= 0; native--) {
        const char *b = native ? "native" : "legacy";
        char obj[ZEO_PATH];
        if (ovf(snprintf(obj, sizeof obj, "%s/%s-%s.o", z->object_root, tag,
                         b), sizeof obj))
            zeo_bail(2);
        unlink(z->refusal_marker);
        char *args[2];
        args[0] = z->refusal;
        args[1] = NULL;
        int rc = 0;
        if (zeo_backend_x(z, native, "dep", obj, args, "/dev/null",
                          "/dev/null", NULL, &rc) != 0)
            zeo_bail(1);
        if (rc == 0)
            zeo_failf(m1, b);
        if (check_marker && zeo_exists(z->refusal_marker))
            zeo_failf(m2, b);
    }
}

static void p3_no_newline(struct zeo *z)
{
    char text[1024];
    size_t len = 0;
    if (zeo_read_file(z->session, text, sizeof text, &len) != 0 || len == 0 ||
        text[len - 1] != '\n')
        zeo_bail(1);
    text[len - 1] = '\0';
    if (zeo_write_file(z->session, text) != 0)
        zeo_bail(1);
    p3_case(z, "bad-newline", 0, "%s accepted a session without its final "
            "newline", "");
}

static void p3_symlink_dir(struct zeo *z)
{
    char real[ZEO_PATH], link[ZEO_PATH];
    if (ovf(snprintf(real, sizeof real, "%s/real-directory", z->object_root),
            sizeof real) ||
        ovf(snprintf(link, sizeof link, "%s/symlink-directory",
                     z->object_root), sizeof link))
        zeo_bail(2);
    if (mkdir(real, 0755) != 0)
        zeo_bail(1);
    if (zeo_dir_link(link, real) != 0)
        zeo_fail("could not create a real object-path link fixture");
    for (int native = 1; native >= 0; native--) {
        const char *b = native ? "native" : "legacy";
        char obj[ZEO_PATH];
        if (ovf(snprintf(obj, sizeof obj, "%s/symlink-directory/%s.o",
                         z->object_root, b), sizeof obj))
            zeo_bail(2);
        char *args[2];
        args[0] = z->refusal;
        args[1] = NULL;
        int rc = 0;
        if (zeo_backend_x(z, native, "dep", obj, args, "/dev/null",
                          "/dev/null", NULL, &rc) != 0)
            zeo_bail(1);
        if (rc == 0)
            zeo_failf("%s accepted a symlink in the object path", b);
    }
}

static void p3_sessions(struct zeo *z)
{
    char id[ZEO_HASH], row[128];
    if (zeo_sha256_hex("conflicting-source", id) != 0)
        zeo_fail("SHA-256 tool is unavailable");
    if (ovf(snprintf(row, sizeof row, "source_id=%s\n", id), sizeof row))
        zeo_bail(2);
    if (zeo_append_file(z->session, row) != 0)
        zeo_bail(1);
    p3_case(z, "bad", 1,
            "%s accepted conflicting duplicate session authority",
            "%s duplicate-key refusal launched the compiler");
    zeo_write_session(z);
    if (zeo_append_raw(z->session, "\0", 1) != 0)
        zeo_bail(1);
    p3_case(z, "bad-nul", 1, "%s accepted a NUL-bearing session",
            "%s NUL refusal launched the compiler");
    char text[1024];
    zeo_write_marker(z, z->session, text, sizeof text,
                     "schema=zcl.build_epoch_session.v1\n"
                     "source_id=%s\ncomplete=1\nmutation=%s\n"
                     "compiler_id=%s\nepoch=%s\nprofile=fixture-v1\n",
                     "session text exceeds the session buffer",
                     "could not write the build session");
    p3_case(z, "bad-malformed", 1,
            "%s accepted a session without its flags binding",
            "%s malformed-session refusal launched the compiler");
    zeo_write_session(z);
    if (zeo_append_file(z->session, "unknown=authority-expansion\n") != 0)
        zeo_bail(1);
    p3_case(z, "bad-extra", 0, "%s accepted an unknown session row", "");
    zeo_write_session(z);
    p3_no_newline(z);
    zeo_write_session(z);
    p3_symlink_dir(z);
}

/* v: parent, saved, escape, done */
static int p3_swap_env(const char *const v[4], int on)
{
    static const char *const k[4] = { "SWAP_PARENT", "SWAP_SAVED",
                                      "SWAP_ESCAPE", "SWAP_DONE" };
    if (!on) {
        unsetenv("ZCC_DISABLE");
        for (int i = 0; i < 4; i++)
            unsetenv(k[i]);
        return 0;
    }
    if (setenv("ZCC_DISABLE", "1", 1) != 0)
        return 1;
    for (int i = 0; i < 4; i++)
        if (setenv(k[i], v[i], 1) != 0)
            return 1;
    return 0;
}

/* v: parent, saved, escape, done, obj, dep */
static void p3_swap_check(int rc, const char *const v[6])
{
    struct stat st;
    if (rc == 0)
        zeo_fail("native publication accepted a swapped output parent");
    if (lstat(v[0], &st) != 0 || !S_ISLNK(st.st_mode))
        zeo_fail("adversarial compiler did not swap the parent");
    if (!zeo_exists(v[3]))
        zeo_fail("adversarial compiler did not finish its write");
    if (zeo_dir_has_file(v[2]))
        zeo_fail("native compiler write escaped through a swapped parent "
                 "symlink");
    if (zeo_dir_has_file(v[1]))
        zeo_fail("native refusal retained artifacts in the renamed output "
                 "parent");
    if (zeo_exists(v[4]) || zeo_exists(v[5]))
        zeo_fail("native parent-swap refusal published final artifacts");
}

static void p3_swap_prep(const char *script, const char *parent,
                         const char *escape)
{
    if (csr_mkdirs(parent) != 0 || csr_mkdirs(escape) != 0 ||
        zeo_write_file(script, k_swap_sh) != 0 || chmod(script, 0755) != 0)
        zeo_bail(1);
}

static void p3_swap(struct zeo *z)
{
    char container[ZEO_PATH], parent[ZEO_PATH], saved[ZEO_PATH];
    char escape[ZEO_PATH], done[ZEO_PATH], obj[ZEO_PATH], dep[ZEO_PATH];
    char script[ZEO_PATH];
    if (ovf(snprintf(container, sizeof container, "%s/swap-container",
                     z->object_root), sizeof container) ||
        ovf(snprintf(parent, sizeof parent, "%s/parent", container),
            sizeof parent) ||
        ovf(snprintf(saved, sizeof saved, "%s/held-parent", container),
            sizeof saved) ||
        zeo_join(escape, sizeof escape, z->work, "swap-escape") ||
        zeo_join(done, sizeof done, z->work, "swap-compiler-complete") ||
        ovf(snprintf(obj, sizeof obj, "%s/swap.o", parent), sizeof obj) ||
        zeo_dep_of(dep, sizeof dep, obj) ||
        zeo_join(script, sizeof script, z->work, "swap-compiler.sh"))
        zeo_bail(2);
    p3_swap_prep(script, parent, escape);
    const char *const env[4] = { parent, saved, escape, done };
    if (p3_swap_env(env, 1) != 0)
        zeo_bail(1);
    char *cc[8] = { script, (char *)"-std=c23", (char *)"-O2",
                    (char *)"-Wall", (char *)"-Wextra", (char *)"-Werror",
                    z->seed, NULL };
    int rc = 0;
    if (zeo_compile_x(z, NULL, "dep", obj, cc, "/dev/null", "/dev/null",
                      NULL, &rc) != 0)
        zeo_bail(1);
    p3_swap_env(env, 0);
    const char *const chk[6] = { parent, saved, escape, done, obj, dep };
    p3_swap_check(rc, chk);
    zeo_dir_unlink(parent);
    if (rename(saved, parent) != 0)
        zeo_bail(1);
}

static void p3_aba(struct zeo *z)
{
    char script[ZEO_PATH];
    if (zeo_join(script, sizeof script, z->work, "aba-compiler.sh"))
        zeo_bail(2);
    if (zeo_write_file(script, k_aba_sh) != 0 || chmod(script, 0755) != 0)
        zeo_bail(1);
    for (int native = 1; native >= 0; native--) {
        const char *b = native ? "native" : "legacy";
        char obj[ZEO_PATH];
        if (ovf(snprintf(obj, sizeof obj, "%s/aba-%s.o", z->object_root, b),
                sizeof obj))
            zeo_bail(2);
        zeo_write_session(z);
        if (setenv("SESSION_PATH", z->session, 1) != 0)
            zeo_bail(1);
        char *cc[8];
        cc[0] = script;
        cc[1] = (char *)"-std=c23";
        cc[2] = (char *)"-O2";
        cc[3] = (char *)"-Wall";
        cc[4] = (char *)"-Wextra";
        cc[5] = (char *)"-Werror";
        cc[6] = z->seed;
        cc[7] = NULL;
        int rc = 0;
        if (zeo_backend_x(z, native, "dep", obj, cc, "/dev/null",
                          "/dev/null", NULL, &rc) != 0)
            zeo_bail(1);
        if (rc == 0)
            zeo_failf("%s published after its session changed", b);
        if (zeo_exists(obj))
            zeo_failf("%s ABA refusal published an object", b);
    }
    unsetenv("SESSION_PATH");
    if (zeo_dir_has_entry_prefix(z->object_root, ".zcc-epoch."))
        zeo_fail("failed native compile leaked a staging directory");
    zeo_write_session(z);
}

static void p3_cov_partial(struct zeo *z, int native, const char *b)
{
    char obj[ZEO_PATH], dep[ZEO_PATH], note[ZEO_PATH];
    if (ovf(snprintf(obj, sizeof obj, "%s/partial-%s.o", z->object_root, b),
            sizeof obj) ||
        zeo_dep_of(dep, sizeof dep, obj) ||
        zeo_gcno_of(note, sizeof note, obj))
        zeo_bail(2);
    if (mkdir(note, 0755) != 0)
        zeo_bail(1);
    char *cc[5];
    cc[0] = (char *)"cc";
    cc[1] = (char *)"--coverage";
    cc[2] = (char *)"-std=c23";
    cc[3] = (char *)"-O0";
    cc[4] = NULL;
    int rc = 0;
    if (zeo_backend_x(z, native, "coverage", obj, cc, "/dev/null",
                      "/dev/null", NULL, &rc) != 0)
        zeo_bail(1);
    if (rc == 0)
        zeo_failf("%s coverage accepted a blocked admission record", b);
    if (zeo_exists(obj) || zeo_exists(dep))
        zeo_failf("%s failed coverage admission partially published "
                  "artifacts", b);
    if (rmdir(note) != 0)
        zeo_bail(1);
}

static void p3_cov_reuse(struct zeo *z, const char *cov, char *false_args[2])
{
    for (int native = 1; native >= 0; native--) {
        const char *b = native ? "native" : "legacy";
        int rc = 0;
        if (zeo_backend_x(z, native, "coverage", cov, false_args,
                          "/dev/null", "/dev/null", NULL, &rc) != 0)
            zeo_bail(1);
        if (rc == 0)
            zeo_failf("%s coverage reused an artifact without "
                      "invocation-bound authority", b);
    }
}

static void p3_coverage(struct zeo *z)
{
    char cov[ZEO_PATH], dep[ZEO_PATH], note[ZEO_PATH], text[512];
    p3_cov_partial(z, 1, "native");
    p3_cov_partial(z, 0, "legacy");
    if (ovf(snprintf(cov, sizeof cov, "%s/coverage.o", z->object_root),
            sizeof cov) ||
        zeo_dep_of(dep, sizeof dep, cov) ||
        zeo_gcno_of(note, sizeof note, cov))
        zeo_bail(2);
    char *cc[5];
    cc[0] = (char *)"cc";
    cc[1] = (char *)"--coverage";
    cc[2] = (char *)"-std=c23";
    cc[3] = (char *)"-O0";
    cc[4] = NULL;
    int rc = 0;
    p3_must(zeo_compile_x(z, NULL, "coverage", cov, cc, NULL, NULL, NULL,
                          &rc), rc);
    if (zeo_read_first(note, text, sizeof text) != 0)
        zeo_bail(1);
    if (!zeo_nonempty(cov) || !zeo_nonempty(dep) || !zeo_nonempty(text))
        zeo_fail("coverage publication is incomplete");
    char *false_args[2] = { (char *)"/bin/false", NULL };
    p3_cov_reuse(z, cov, false_args);
    if (unlink(note) != 0)
        zeo_bail(1);
    rc = 0;
    if (zeo_compile_x(z, NULL, "coverage", cov, false_args, "/dev/null",
                      "/dev/null", NULL, &rc) != 0)
        zeo_bail(1);
    if (rc == 0)
        zeo_fail("coverage object with a missing note was accepted");
    rc = 0;
    p3_must(zeo_compile_x(z, NULL, "coverage", cov, cc, NULL, NULL, NULL,
                          &rc), rc);
    if (zeo_read_first(note, text, sizeof text) != 0 || !zeo_nonempty(text))
        zeo_fail("coverage compile did not repair its note");
}

static void p3_shadow(struct zeo *z)
{
    char hdr[ZEO_PATH], obj[ZEO_PATH], prog[ZEO_PATH], tail[ZEO_PATH];
    char out[256];
    if (zeo_join(hdr, sizeof hdr, z->work, "epoch-choice.h") ||
        ovf(snprintf(obj, sizeof obj, "%s/shadow.o", z->object_root),
            sizeof obj) ||
        zeo_join(prog, sizeof prog, z->work, "shadow-program"))
        zeo_bail(2);
    if (zeo_write_file(hdr, "#define EPOCH_LABEL \"native-epoch-shadow\"\n") !=
        0)
        zeo_bail(1);
    long before = zeo_count_line_eq(z->compiler_launches, "compile");
    char *cc[8];
    cc[0] = z->counting;
    cc[1] = (char *)"-std=c23";
    cc[2] = (char *)"-O2";
    cc[3] = (char *)"-Wall";
    cc[4] = (char *)"-Wextra";
    cc[5] = (char *)"-Werror";
    cc[6] = z->seed;
    cc[7] = NULL;
    int rc = 0;
    p3_must(zeo_compile_x(z, NULL, "dep", obj, cc, NULL, NULL, NULL, &rc),
            rc);
    if (zeo_tail1(z->zcc_log, tail, sizeof tail) != 0 ||
        !zeo_first_tok_is(tail, "MISS"))
        zeo_fail("new local header was served from the old source cache key");
    if (zeo_count_line_eq(z->compiler_launches, "compile") != before + 1)
        zeo_fail("new local header did not launch a fresh object compile");
    char *largs[5];
    largs[0] = (char *)"cc";
    largs[1] = (char *)"-o";
    largs[2] = prog;
    largs[3] = obj;
    largs[4] = NULL;
    if (zeo_run("cc", largs, NULL, NULL) != 0)
        zeo_bail(1);
    char *pargs[2];
    pargs[0] = prog;
    pargs[1] = NULL;
    if (zeo_capture(prog, pargs, out, sizeof out) != 0 ||
        strcmp(out, "native-epoch-shadow") != 0)
        zeo_fail("new local header did not change executed behavior");
}

int zeo_part3(struct zeo *z)
{
    p3_wrong_source(z);
    p3_outside(z, 1, "native");
    p3_outside(z, 0, "legacy");
    p3_sessions(z);
    p3_swap(z);
    p3_aba(z);
    p3_coverage(z);
    p3_shadow(z);
    if (zeo_grep_re("/pro" "c/self/fd/[0-9]+/|/dev/fd/[0-9]+", z->zcc_log))
        zeo_fail("native diagnostic exposed an ephemeral descriptor output");
    return 0;
}
