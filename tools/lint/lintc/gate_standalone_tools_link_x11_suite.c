/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the hermetic X11 standalone-tools selftest, ported from the former
 * shell self-test script (deleted). Runs the real
 * z23-lint check-standalone-tools-link gate against a private fixture with
 * a fake compiler that can be told to fail in every way the shell original
 * could inject. Same checks, same report lines, same exit codes; every
 * subprocess is fork plus execvp with an argv array. Must run from the
 * repository root, like the script.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"
#include "lintc_text.h"
#include "gate_standalone_tools_link_priv.h"
#include "gate_standalone_tools_link_x11_suite.h"

static const char *const k_mode_name[] = { "normal", "build-only", "list-targets" };
static const char *const k_mode_arg[] = { NULL, "--build-only", "--list-targets" };
static const char *const k_ci[] = {
    "fuzz_zcode_commons", "fuzz_zcode_dht", "fuzz_zcode_science",
    "fuzz_mesh_status_proto", "fuzz_semantic_manifest",
};
static const char *const k_ign[] = { "baseline-run", "partial-object", "partial-baseline" };
static const char *const k_spell[] = { "i", "--ignore-errors" };
static const char *const k_flag[] = { "n", "t", "q" };
static const char *const k_fatal[] = {
    "compile", "wrong-target", "generic-link", "mixed-link", "object",
    "empty-object",
};
static const char *const k_defect[] = { "syntax", "warning", "pedantic" };
static const char *const k_defect_line[] = {
    "this is not C;\n",
    "static int unused(void){return 0;}\n",
    "int extension(void){return ({1;});}\n",
};
static const char *const k_host[] = { "Darwin", "MSYS_NT-10.0" };

struct stl_x11_run {
    const char *mode, *makeflags, *gnumakeflags, *fault, *host, *tmpdir;
    const char *probe_done, *runtime_ok;
    int no_makeflags, fake_path, unset_display;
};

static void x11_eset(const char *k, const char *v)
{
    if (v)
        setenv(k, v, 1);
}

static void x11_child_mf(struct stl_x11_ctx *c, const struct stl_x11_run *r)
{
    char mf[STL_X11_PATH + 64];
    if (r->no_makeflags) {
        unsetenv("MAKEFLAGS");
    } else if (r->makeflags) {
        setenv("MAKEFLAGS", r->makeflags, 1);
    } else if (!ovf(snprintf(mf, sizeof mf, "CC=%s", c->ccbin), sizeof mf)) {
        setenv("MAKEFLAGS", mf, 1);
    }
}

/* Forked child: cd fixture, redirect to out/err, build the gate's env, exec. */
static void x11_child(struct stl_x11_ctx *c, const struct stl_x11_run *r)
{
    char pe[STL_X11_PATH + 64], fl[STL_X11_PATH];
    int fo = open(c->out, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    int fe = open(c->err, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fo < 0 || fe < 0 || dup2(fo, 1) < 0 || dup2(fe, 2) < 0 ||
        chdir(c->fixture) != 0)
        _exit(127);
    x11_child_mf(c, r);
    x11_eset("GNUMAKEFLAGS", r->gnumakeflags);
    setenv("PR72_FAULT", r->fault ? r->fault : "absent", 1);
    x11_eset("PR72_HOST", r->host);
    x11_eset("TMPDIR", r->tmpdir);
    x11_eset("X11_PROBE_DONE", r->probe_done);
    x11_eset("X11_RUNTIME_OK", r->runtime_ok);
    if (r->unset_display)
        unsetenv("DISPLAY");
    if (r->fake_path && !ovf(snprintf(pe, sizeof pe, "%s/bin:%s", c->tmp,
                                      getenv("PATH") ? getenv("PATH") : ""),
                             sizeof pe))
        setenv("PATH", pe, 1);
    if (ovf(snprintf(fl, sizeof fl, "%s/lib", c->tmp), sizeof fl))
        _exit(127);
    setenv("REAL_CC", c->realcc, 1);
    setenv("PR72_FIXTURE_LIB", fl, 1);
    setenv("PR72_CC_LOG", c->cclog, 1);
    setenv("ZCL_LINT_REPO_ROOT", c->fixture, 1);
    char *av[4];
    av[0] = c->lint;
    av[1] = (char *)"check-standalone-tools-link";
    av[2] = (char *)r->mode;
    av[3] = NULL;
    execvp(c->lint, av);
    _exit(127);
}

static int x11_spawn(struct stl_x11_ctx *c, const struct stl_x11_run *r)
{
    pid_t pid = fork();
    if (pid == 0) {
        x11_child(c, r);
        _exit(127);
    }
    if (pid < 0)
        return -1;
    int st = 0;
    if (waitpid(pid, &st, 0) < 0)
        return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128;
}

static int x11_check(struct stl_x11_ctx *c, const char *label, int expected,
                     const struct stl_x11_run *r)
{
    int rc = x11_spawn(c, r);
    if (rc != expected) {
        stl_copy_to(stderr, c->out);
        stl_copy_to(stderr, c->err);
        fprintf(stderr, "FAIL %s: expected %d, got %d\n", label, expected, rc);
        return 1;
    }
    c->cases++;
    printf("PASS %s\n", label);
    return 0;
}

static int x11_refute(int r, const char *desc)
{
    if (r != 1) {
        fprintf(stderr, "FAIL: negative match assertion returned %d: %s\n",
                r, desc);
        return 1;
    }
    return 0;
}

/* grep -q, unanchored: 0 match, 1 no match, 2 unreadable (fail closed). */
static int x11_fh(const char *path, const char *needle)
{
    if (!lct_readable(path))
        return 2;
    return lct_file_has(path, needle) ? 0 : 1;
}

/* grep -q on a ^...$ anchored single line: 0 match, 1 no match, 2 error. */
static int x11_fl(const char *path, const char *line)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 2;
    char buf[4096];
    int r = 1;
    while (fgets(buf, sizeof buf, f)) {
        size_t n = strlen(buf);
        if (n && buf[n - 1] == '\n')
            buf[n - 1] = '\0';
        if (strcmp(buf, line) == 0) {
            r = 0;
            break;
        }
    }
    if (ferror(f))
        r = 2;
    fclose(f);
    return r;
}

static int x11_append(const char *path, const char *text)
{
    FILE *f = fopen(path, "a");
    if (!f)
        return 1;
    int bad = fputs(text, f) == EOF;
    if (fclose(f) != 0)
        bad = 1;
    return bad;
}

static int x11_phase_modes(struct stl_x11_ctx *c)
{
    char lb[256], bin[STL_X11_PATH];
    struct stat sb;
    if (ovf(snprintf(bin, sizeof bin, "%s/build/bin/native_ui_driver",
                     c->fixture), sizeof bin))
        return 2;
    for (int i = 0; i < 3; i++) {
        int lt = i == 2;
        struct stl_x11_run absent = { .mode = k_mode_arg[i], .fault = "absent" };
        struct stl_x11_run present = { .mode = k_mode_arg[i], .fault = "present",
                                       .unset_display = 1 };
        if (ovf(snprintf(lb, sizeof lb, "absent/%s", k_mode_name[i]), sizeof lb))
            return 2;
        int rc = x11_check(c, lb, 0, &absent);
        if (rc)
            return rc;
        if (x11_fh(c->err, "no-x11-runtime-exempt native_ui_driver") != 0)
            return 1;
        if (lt && x11_refute(x11_fl(c->out, "build/bin/native_ui_driver"),
                             "grep -q ^build/bin/native_ui_driver$ out"))
            return 1;
        unlink(bin);
        if (ovf(snprintf(lb, sizeof lb, "present/%s, DISPLAY unset",
                         k_mode_name[i]), sizeof lb))
            return 2;
        rc = x11_check(c, lb, 0, &present);
        if (rc)
            return rc;
        if (x11_refute(x11_fh(c->err, "no-x11-runtime-exempt"),
                       "grep -q no-x11-runtime-exempt err"))
            return 1;
        if (lt) {
            if (x11_fl(c->out, "build/bin/native_ui_driver") != 0)
                return 1;
        } else if (stat(bin, &sb) != 0 || sb.st_size <= 0) {
            return 1;
        }
    }
    return 0;
}

static int x11_phase_ci_a(struct stl_x11_ctx *c)
{
    char lb[256], ln[128], un[STL_X11_PATH];
    if (x11_append(c->mk, "$(BIN_DIR)/fuzz_unknown_fixture:\n"
                    "\t@mkdir -p build/bin; touch $@\n"))
        return 1;
    if (ovf(snprintf(un, sizeof un, "%s/bin/uname", c->tmp), sizeof un))
        return 2;
    if (csr_write(un, "#!/usr/bin/env bash\nprintf \"%s\\n\" \"$PR72_HOST\"\n") != 0 ||
        chmod(un, 0755) != 0)
        return 1;
    struct stl_x11_run linux = { .mode = "--list-targets", .fault = "absent",
                                 .host = "Linux", .fake_path = 1 };
    int rc = x11_check(c, "CI fuzzers excluded on Linux", 0, &linux);
    if (rc)
        return rc;
    for (int i = 0; i < 5; i++) {
        if (ovf(snprintf(ln, sizeof ln, "build/bin/%s", k_ci[i]), sizeof ln) ||
            ovf(snprintf(lb, sizeof lb, "grep -q ^build/bin/%s$ out", k_ci[i]),
                sizeof lb))
            return 2;
        if (x11_refute(x11_fl(c->out, ln), lb))
            return 1;
    }
    if (x11_fl(c->out, "build/bin/fuzz_unknown_fixture") != 0)
        return 1;
    if (x11_fl(c->out, "build/bin/fixture_1") != 0)
        return 1;
    struct stl_x11_run darwin = { .mode = "--list-targets", .fault = "absent",
                                  .host = "Darwin", .fake_path = 1 };
    return x11_check(c, "unknown fuzzer refused on Darwin", 2, &darwin);
}

static int x11_phase_ci_b(struct stl_x11_ctx *c)
{
    char un[STL_X11_PATH];
    struct stl_x11_run linux = { .mode = "--list-targets", .fault = "absent",
                                 .host = "Linux", .fake_path = 1 };
    struct stl_x11_run darwin = { .mode = "--list-targets", .fault = "absent",
                                  .host = "Darwin", .fake_path = 1 };
    int rc;
    if (stl_x11_make_from(c, STL_X11_MK_DROP_DHT))
        return 1;
    rc = x11_check(c, "removed CI fuzzer is built on Linux", 0, &linux);
    if (rc)
        return rc;
    if (x11_fl(c->out, "build/bin/fuzz_zcode_dht") != 0)
        return 1;
    rc = x11_check(c, "removed CI fuzzer refused on Darwin", 2, &darwin);
    if (rc)
        return rc;
    if (stl_x11_make_from(c, STL_X11_MK_COPY))
        return 1;
    if (x11_append(c->mk, "FUZZ_TARGETS += $(BIN_DIR)/other\n"))
        return 1;
    rc = x11_check(c, "ambiguous CI fuzzer assignment refuses", 2, &linux);
    if (rc)
        return rc;
    if (stl_x11_make_from(c, STL_X11_MK_INVALID_DHT))
        return 1;
    rc = x11_check(c, "invalid CI fuzzer token refuses", 2, &linux);
    if (rc)
        return rc;
    if (stl_x11_make_from(c, STL_X11_MK_FUZZCI))
        return 1;
    rc = x11_check(c, "missing fuzz-ci prerequisite refuses", 2, &linux);
    if (rc)
        return rc;
    if (stl_x11_make_from(c, STL_X11_MK_COPY))
        return 1;
    if (ovf(snprintf(un, sizeof un, "%s/bin/uname", c->tmp), sizeof un))
        return 2;
    unlink(un);
    return 0;
}

static int x11_phase_ignore(struct stl_x11_ctx *c)
{
    char lb[256], mf[STL_X11_PATH + 64];
    int rc;
    for (int i = 0; i < 3; i++) {
        for (int f = 0; f < 3; f++) {
            for (int s = 0; s < 2; s++) {
                if (ovf(snprintf(mf, sizeof mf, "%s CC=%s", k_spell[s],
                                 c->ccbin), sizeof mf))
                    return 2;
                struct stl_x11_run a = { .mode = k_mode_arg[i], .makeflags = mf,
                                         .fault = k_ign[f] };
                if (ovf(snprintf(lb, sizeof lb, "%s/%s/MAKEFLAGS=%s",
                                 k_mode_name[i], k_ign[f], k_spell[s]),
                        sizeof lb))
                    return 2;
                rc = x11_check(c, lb, 2, &a);
                if (rc)
                    return rc;
                struct stl_x11_run g = { .mode = k_mode_arg[i],
                                         .gnumakeflags = k_spell[s],
                                         .fault = k_ign[f] };
                if (ovf(snprintf(lb, sizeof lb, "%s/%s/GNUMAKEFLAGS=%s",
                                 k_mode_name[i], k_ign[f], k_spell[s]),
                        sizeof lb))
                    return 2;
                rc = x11_check(c, lb, 2, &g);
                if (rc)
                    return rc;
            }
        }
        for (int j = 0; j < 3; j++) {
            if (ovf(snprintf(mf, sizeof mf, "%s CC=%s", k_flag[j], c->ccbin),
                    sizeof mf))
                return 2;
            struct stl_x11_run a = { .mode = k_mode_arg[i], .makeflags = mf,
                                     .fault = "absent" };
            if (ovf(snprintf(lb, sizeof lb, "%s/non-execution MAKEFLAGS=%s",
                             k_mode_name[i], k_flag[j]), sizeof lb))
                return 2;
            rc = x11_check(c, lb, 2, &a);
            if (rc)
                return rc;
        }
    }
    return 0;
}

static int x11_phase_env(struct stl_x11_ctx *c)
{
    char mf[STL_X11_PATH + 96], mf2[STL_X11_PATH];
    if (ovf(snprintf(mf, sizeof mf,
                     "i CC=%s ZCL_PLATFORM_CPPFLAGS=-DPR72_PLATFORM=2",
                     c->ccbin), sizeof mf))
        return 2;
    struct stl_x11_run a = { .mode = "--list-targets", .makeflags = mf,
                             .fault = "absent" };
    int rc = x11_check(c, "successful compiler override survives MAKEFLAGS "
                       "ignore-errors", 0, &a);
    if (rc)
        return rc;
    struct stl_x11_run b = { .mode = "--list-targets",
                             .gnumakeflags = "--ignore-errors" };
    rc = x11_check(c, "successful compiler override survives GNUMAKEFLAGS "
                   "ignore-errors", 0, &b);
    if (rc)
        return rc;
    struct stl_x11_run d = { .mode = "--list-targets", .no_makeflags = 1 };
    rc = x11_check(c, "default compiler", 0, &d);
    if (rc)
        return rc;
    struct stl_x11_run p = { .mode = "--list-targets", .fault = "present",
                             .probe_done = "1", .runtime_ok = "0" };
    rc = x11_check(c, "inherited probe variables cannot exempt present runtime",
                   0, &p);
    if (rc)
        return rc;
    if (x11_fl(c->out, "build/bin/native_ui_driver") != 0)
        return 1;
    struct stl_x11_run h = { .mode = "--list-targets", .fault = "generic-link",
                             .probe_done = "1", .runtime_ok = "0" };
    rc = x11_check(c, "inherited probe variables cannot hide failure", 2, &h);
    if (rc)
        return rc;
    for (int i = 0; i < 6; i++) {
        char lb[96];
        if (ovf(snprintf(lb, sizeof lb, "%s is fatal", k_fatal[i]), sizeof lb))
            return 2;
        struct stl_x11_run r = { .mode = "--list-targets", .fault = k_fatal[i] };
        rc = x11_check(c, lb, 2, &r);
        if (rc)
            return rc;
    }
    if (ovf(snprintf(mf2, sizeof mf2, "CC=%s/no-such-compiler", c->tmp),
            sizeof mf2))
        return 2;
    struct stl_x11_run m = { .mode = "--list-targets", .makeflags = mf2 };
    return x11_check(c, "missing compiler is fatal", 2, &m);
}

static int x11_phase_source(struct stl_x11_ctx *c)
{
    char text[STL_X11_TEXT], lb[96], hdr[STL_X11_PATH], bak[STL_X11_PATH];
    for (int i = 0; i < 3; i++) {
        if (ovf(snprintf(text, sizeof text, "%s%s", k_stl_x11_good,
                         k_defect_line[i]), sizeof text))
            return 2;
        if (csr_write(c->driver, text) != 0)
            return 1;
        if (ovf(snprintf(lb, sizeof lb, "%s remains fatal when X11 absent",
                         k_defect[i]), sizeof lb))
            return 2;
        struct stl_x11_run r = { .mode = "--list-targets", .fault = "absent" };
        int rc = x11_check(c, lb, 2, &r);
        if (rc)
            return rc;
    }
    if (csr_write(c->driver, k_stl_x11_good) != 0)
        return 1;
    if (ovf(snprintf(hdr, sizeof hdr, "%s/vendor/x11/include/X11/Xlib.h",
                     c->fixture), sizeof hdr) ||
        ovf(snprintf(bak, sizeof bak, "%s/Xlib.h", c->tmp), sizeof bak))
        return 2;
    if (rename(hdr, bak) != 0)
        return 1;
    if (csr_write(c->driver,
                  "#include \"../vendor/x11/include/X11/Xlib.h\"\n") != 0)
        return 1;
    struct stl_x11_run r2 = { .mode = "--list-targets", .fault = "absent" };
    int rc = x11_check(c, "missing vendor header is fatal", 2, &r2);
    if (rc)
        return rc;
    if (rename(bak, hdr) != 0)
        return 1;
    return csr_write(c->driver, k_stl_x11_good) != 0 ? 1 : 0;
}

static int x11_phase_platform(struct stl_x11_ctx *c)
{
    char mf[STL_X11_PATH + 96], nd[STL_X11_PATH], td[STL_X11_PATH];
    if (ovf(snprintf(mf, sizeof mf,
                     "CC=%s ZCL_PLATFORM_CPPFLAGS=-DPR72_PLATFORM=2",
                     c->ccbin), sizeof mf))
        return 2;
    struct stl_x11_run r = { .mode = "--list-targets", .makeflags = mf,
                             .fault = "absent" };
    int rc = x11_check(c, "platform flags selected by Make", 0, &r);
    if (rc)
        return rc;
    if (x11_fh(c->cclog, "-std=c23 -O2 -Wall -Wextra -Werror -pedantic") != 0)
        return 1;
    if (x11_fh(c->cclog, "-DPR72_PLATFORM=2") != 0)
        return 1;
    if (x11_fh(c->cclog, "-c tools/native_ui_driver.c") != 0)
        return 1;
    if (ovf(snprintf(nd, sizeof nd, "%s/not-directory", c->tmp), sizeof nd) ||
        ovf(snprintf(td, sizeof td, "%s/no-such-dir", c->tmp), sizeof td))
        return 2;
    if (csr_write(nd, "not a directory\n") != 0)
        return 1;
    struct stl_x11_run t1 = { .mode = "--list-targets", .tmpdir = td };
    rc = x11_check(c, "temp creation failure is fatal", 2, &t1);
    if (rc)
        return rc;
    struct stl_x11_run t2 = { .mode = "--list-targets", .tmpdir = nd };
    return x11_check(c, "temp write failure is fatal", 2, &t2);
}

static int x11_phase_hosts(struct stl_x11_ctx *c)
{
    char un[STL_X11_PATH], lb[128], text[128];
    if (x11_append(c->mk, "$(BIN_DIR)/unknown_fixture:\n\t@exit 1\n"))
        return 1;
    if (ovf(snprintf(un, sizeof un, "%s/bin/uname", c->tmp), sizeof un))
        return 2;
    for (int i = 0; i < 2; i++) {
        if (ovf(snprintf(text, sizeof text,
                         "#!/usr/bin/env bash\nprintf \"%%s\\n\" \"%s\"\n",
                         k_host[i]), sizeof text))
            return 2;
        if (csr_write(un, text) != 0 || chmod(un, 0755) != 0)
            return 1;
        if (ovf(snprintf(lb, sizeof lb, "%s routing (no Linux exemption)",
                         k_host[i]), sizeof lb))
            return 2;
        struct stl_x11_run r = { .mode = "--list-targets", .fault = "compile",
                                 .fake_path = 1 };
        int rc = x11_check(c, lb, 0, &r);
        if (rc)
            return rc;
        if (x11_refute(x11_fh(c->err, "no-x11-runtime-exempt"),
                       "grep -q no-x11-runtime-exempt err"))
            return 1;
        if (x11_fl(c->out, "build/bin/unknown_fixture") != 0)
            return 1;
    }
    unlink(un);
    struct stl_x11_run u = { .mode = "--list-targets", .fault = "absent" };
    int rc = x11_check(c, "unknown tool remains covered", 0, &u);
    if (rc)
        return rc;
    if (x11_fl(c->out, "build/bin/unknown_fixture") != 0)
        return 1;
    struct stl_x11_run bo = { .mode = "--build-only", .fault = "absent" };
    return x11_check(c, "unknown tool build fails", 1, &bo);
}

static int x11_phase_tail(struct stl_x11_ctx *c)
{
    char wa[STL_X11_PATH];
    if (stl_x11_make_from(c, STL_X11_MK_COPY))
        return 1;
    if (ovf(snprintf(wa, sizeof wa,
                     "%s/platform/modules/platform/tests/windows_acceptance.mk",
                     c->fixture), sizeof wa))
        return 2;
    if (csr_write(wa, "ZCL_WINDOWS_ACCEPTANCE_TESTS := unrelated\n") != 0)
        return 1;
    struct stl_x11_run a = { .mode = "--list-targets", .fault = "absent" };
    int rc = x11_check(c, "replacement coverage loss is fatal", 2, &a);
    if (rc)
        return rc;
    if (csr_write(c->mk, "CC = cc\n") != 0)
        return 1;
    rc = x11_check(c, "tool floor is fatal", 2, &a);
    if (rc)
        return rc;
    struct stl_x11_run b = { .mode = "--bogus", .fault = "absent" };
    return x11_check(c, "unknown argument is fatal", 2, &b);
}

static int x11_phases(struct stl_x11_ctx *c)
{
    int rc = x11_phase_modes(c);
    if (rc == 0)
        rc = x11_phase_ci_a(c);
    if (rc == 0)
        rc = x11_phase_ci_b(c);
    if (rc == 0)
        rc = x11_phase_ignore(c);
    if (rc == 0)
        rc = x11_phase_env(c);
    if (rc == 0)
        rc = x11_phase_source(c);
    if (rc == 0)
        rc = x11_phase_platform(c);
    if (rc == 0)
        rc = x11_phase_hosts(c);
    if (rc == 0)
        rc = x11_phase_tail(c);
    return rc;
}

int stl_x11_selftest_run(void)
{
    struct stl_x11_ctx c;
    int rc = stl_x11_fixture(&c);
    if (rc == 0 && setenv(k_stl_x11_nested, c.fixture, 1) != 0)
        rc = 2;
    if (rc == 0)
        rc = x11_phases(&c);
    if (rc == 0)
        printf("standalone X11 selftest: %d cases passed\n", c.cases);
    if (c.tmp[0])
        rap_rm_rf(c.tmp);
    return rc;
}
