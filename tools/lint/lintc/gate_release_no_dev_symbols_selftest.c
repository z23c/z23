/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-release-no-dev-symbols
 * (gate_release_no_dev_symbols.c). Builds a fixture repo tree under a
 * mkdtemp directory in $TMPDIR (default /tmp) with a
 * clean Makefile, main.c and dev-activation guard files, then proves each
 * case: the clean tree passes with no binary; a devloop dispatch in main.c,
 * a missing DEV_ONLY_SRCS executor, a missing filter-out line, a missing
 * dev-activation guard, a missing engine file, and an unreadable (non-ELF)
 * fresh binary each fail. The passing artifact read with a real release
 * binary is not fabricated here; only its error path is exercised.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include "lintc.h"

/* Implemented in gate_release_no_dev_symbols.c (no private header in this
 * port; the harness wires only these two files). */
int rnd_check_root(const char *root, const char *bin, FILE *out, FILE *err);

enum { RNFS_PATH = 1024, RNFS_TEXT = 4096 };

static const char k_rnfs_mk_clean[] =
    "DEV_ONLY_SRCS = tools/dev/devloop_cli.c tools/dev/devloop_cycle.c \\\n"
    "    tools/dev/devloop_watch.c tools/dev/devloop_process.c \\\n"
    "    tools/dev/dev_extra.c\n"
    "DEVLOOP_SRCS = $(filter-out $(DEV_ONLY_SRCS),$(ALL_SRCS))\n"
    "ALL_SRCS := main.c\n";

static const char k_rnfs_mk_no_cli[] =
    "DEV_ONLY_SRCS = \\\n"
    "    tools/dev/devloop_cycle.c \\\n"
    "    tools/dev/devloop_watch.c \\\n"
    "    tools/dev/devloop_process.c \\\n"
    "    tools/dev/dev_extra.c\n"
    "DEVLOOP_SRCS = $(filter-out $(DEV_ONLY_SRCS),$(ALL_SRCS))\n";

static const char k_rnfs_mk_no_filter[] =
    "DEV_ONLY_SRCS = \\\n"
    "    tools/dev/devloop_cli.c \\\n"
    "    tools/dev/devloop_cycle.c \\\n"
    "    tools/dev/devloop_watch.c \\\n"
    "    tools/dev/devloop_process.c \\\n"
    "    tools/dev/dev_extra.c\n"
    "DEVLOOP_SRCS = $(ALL_SRCS)\n";

static const char k_rnfs_guard_or[] =
    "#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)\n"
    "int dev_fixture(void) { return 0; }\n"
"#endif\n";

static const char k_rnfs_guard_strict[] =
    "#ifdef ZCL_DEV_BUILD\n"
    "int dev_ops_fixture(void) { return 0; }\n"
"#endif\n";

static const char k_rnfs_unguarded[] =
    "int dev_fixture(void) { return 0; }\n";

struct rnfs_case {
    const char *name;
    const char *mk;        /* NULL = clean Makefile */
    const char *main_extra;/* line inserted into main.c */
    const char *act_file;  /* dev-activation file to override */
    const char *act_text;  /* its content */
    const char *drop;      /* repo-relative file to remove */
    const char *bin;       /* NULL = no binary */
    int want;
    const char *elf_src;   /* non-NULL: build bin from this C source with cc */
    const char *want_text; /* NULL = rc only; else a substring the report holds */
};

static const char k_rnfs_elf_exports[] =
    "void zcl_devloop_run_cycle(void) {}\n"
    "int main(void) { return 0; }\n";

static const char k_rnfs_elf_clean[] =
    "int main(void) { return 0; }\n";

/* The nm read the gate reports, chosen per host as the gate does: Mach-O has
 * no dynamic symbol table, so Darwin reads nm -gU; ELF reads nm -D. */
#if defined(__APPLE__)
#define RNFS_NM_READ "nm -gU"
#else
#define RNFS_NM_READ "nm -D --defined-only"
#endif

static const struct rnfs_case k_rnfs_cases[] = {
    { "clean fixture with no binary passes", NULL, NULL, NULL, NULL, NULL,
      NULL, 0, NULL, NULL },
    { "devloop dispatch in main.c fails", NULL,
      "    zcl_devloop_cli_main(0, 0);\n", NULL, NULL, NULL, NULL, 1, NULL, NULL },
    { "DEV_ONLY_SRCS missing an executor fails", k_rnfs_mk_no_cli, NULL,
      NULL, NULL, NULL, NULL, 1, NULL, NULL },
    { "missing filter-out line fails", k_rnfs_mk_no_filter, NULL, NULL, NULL,
      NULL, NULL, 1, NULL, NULL },
    { "dev_activation.c missing the or-guard fails", NULL, NULL,
      "tools/dev/dev_activation.c", k_rnfs_unguarded, NULL, NULL, 1, NULL, NULL },
    { "dev_activation_ops.c missing the strict guard fails", NULL, NULL,
      "tools/dev/dev_activation_ops.c", k_rnfs_guard_or, NULL, NULL, 1, NULL, NULL },
    { "missing dev_activation engine file fails closed", NULL, NULL, NULL,
      NULL, "tools/dev/dev_activation_verify.c", NULL, 1, NULL, NULL },
    { "unreadable fresh artifact binary fails", NULL, NULL, NULL, NULL, NULL,
      "build/bin/z23", 1, NULL, NULL },
    { "fresh ELF exporting zcl_devloop_run_cycle fails the nm read", NULL,
      NULL, NULL, NULL, NULL, "build/bin/rnd-exports", 1, k_rnfs_elf_exports,
      "FAIL: release binary build/bin/rnd-exports exports dev-only symbol "
      "'zcl_devloop_run_cycle'" },
    { "fresh clean ELF passes the nm read", NULL, NULL, NULL, NULL, NULL,
      "build/bin/rnd-clean", 0, k_rnfs_elf_clean,
      RNFS_NM_READ " build/bin/rnd-clean: all 11 dev-executor symbols "
      "ABSENT" },
};

static int rnfs_write(const char *root, const char *rel, const char *text)
{
    char path[RNFS_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, rel), sizeof path))
        return 2;
    return csr_write(path, text);
}

/* Stamps a file with a fixed far-future mtime (2100-01-01 UTC), so the
 * freshness test (strictly newer than the sources) holds without reading
 * the wall clock. */
static int rnfs_touch_future(const char *path)
{
    struct timespec ts[2];
    ts[0].tv_sec = 4102444800L;
    ts[0].tv_nsec = 0;
    ts[1] = ts[0];
    if (utimensat(AT_FDCWD, path, ts, 0) != 0)
        return die("z23-lint: utimensat failed on %s\n", path);
    return 0;
}

/* main.c and the Makefile for one case. */
static int rnfs_write_base(const char *root, const struct rnfs_case *c)
{
    char mainc[RNFS_TEXT];
    if (ovf(snprintf(mainc, sizeof mainc,
                     "int main(void)\n{\n%s    return 0;\n}\n",
                     c->main_extra ? c->main_extra : ""), sizeof mainc))
        return 2;
    int rc = rnfs_write(root, "engine/entry/main.c", mainc);
    if (rc == 0)
        rc = rnfs_write(root, "Makefile", c->mk ? c->mk : k_rnfs_mk_clean);
    return rc;
}

/* The dev-activation guard files, each overridden when the case names it. */
static int rnfs_write_guards(const char *root, const struct rnfs_case *c)
{
    static const char *const k_or[] = {
        "tools/dev/dev_activation.c", "tools/dev/dev_activation_internal.h",
        "tools/dev/dev_activation_stage.c", "tools/dev/dev_activation_verify.c"
    };
    int rc = 0;
    for (int i = 0; rc == 0 && i < 4; i++) {
        const char *text = k_rnfs_guard_or;
        if (c->act_file && strcmp(c->act_file, k_or[i]) == 0)
            text = c->act_text;
        rc = rnfs_write(root, k_or[i], text);
    }
    if (rc == 0) {
        const char *ops = k_rnfs_guard_strict;
        if (c->act_file && strcmp(c->act_file,
                                  "tools/dev/dev_activation_ops.c") == 0)
            ops = c->act_text;
        rc = rnfs_write(root, "tools/dev/dev_activation_ops.c", ops);
    }
    return rc;
}

/* Compiles root/fx.c into root/<bin> with cc (fork + execvp, argv array, no
 * shell) and stamps the result fresh. A missing cc is reported, never
 * skipped: the case fails with rc=2. */
static int rnfs_build_elf(const char *root, const struct rnfs_case *c)
{
    char src[RNFS_PATH], out[RNFS_PATH];
    int rc = rnfs_write(root, c->bin, "placeholder\n");
    if (rc == 0)
        rc = rnfs_write(root, "fx.c", c->elf_src);
    if (rc)
        return rc;
    if (ovf(snprintf(src, sizeof src, "%s/fx.c", root), sizeof src) ||
        ovf(snprintf(out, sizeof out, "%s/%s", root, c->bin), sizeof out))
        return 2;
    pid_t pid = fork();
    if (pid < 0)
        return die("z23-lint: fork failed for the selftest cc\n", "");
    if (pid == 0) {
        char *argv[] = { (char *)"cc", (char *)"-std=c23", (char *)"-O0",
                         (char *)"-rdynamic", (char *)"-o", out, src, NULL };
        execvp("cc", argv);
        _exit(127);
    }
    int st = 0;
    pid_t r;
    do {
        r = waitpid(pid, &st, 0);
    } while (r < 0 && errno == EINTR);
    if (r != pid)
        return die("z23-lint: waitpid failed for the selftest cc\n", "");
    if (WIFEXITED(st) && WEXITSTATUS(st) == 127) {
        fputs("selftest: cc not found\n", stderr);
        return 2;
    }
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        fputs("selftest: cc failed to build the ELF fixture\n", stderr);
        return 2;
    }
    return rnfs_touch_future(out);
}

/* Removes the case's dropped file and writes its fresh non-ELF artifact. */
static int rnfs_drop_and_bin(const char *root, const struct rnfs_case *c)
{
    char path[RNFS_PATH];
    if (c->drop) {
        if (ovf(snprintf(path, sizeof path, "%s/%s", root, c->drop),
                sizeof path))
            return 2;
        if (unlink(path) != 0)
            return die("z23-lint: cannot remove fixture %s\n", path);
    }
    if (!c->bin)
        return 0;
    int rc = c->elf_src ? rnfs_build_elf(root, c)
                        : rnfs_write(root, c->bin, "not an elf binary\n");
    if (rc)
        return rc;
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, c->bin), sizeof path))
        return 2;
    if (chmod(path, 0755) != 0)
        return die("z23-lint: chmod failed on %s\n", path);
    return rnfs_touch_future(path);
}

static int rnfs_write_fixture(const char *root, const struct rnfs_case *c)
{
    int rc = rnfs_write_base(root, c);
    if (rc == 0)
        rc = rnfs_write_guards(root, c);
    if (rc == 0)
        rc = rnfs_drop_and_bin(root, c);
    return rc;
}

/* Fixture scratch root: mkdtemp under TMPDIR (default /tmp). */
static int rnfs_fixture_root(char *out, size_t cap)
{
    if (ovf(snprintf(out, cap, "%s/z23-lint-release-no-dev.XXXXXX",
                     env_or("TMPDIR", "/tmp")), cap))
        return 2;
    if (!mkdtemp(out))
        return die("z23-lint: mkdtemp failed for selftest scratch\n", "");
    return 0;
}

/* True when the captured report (sink, rewound) holds want as a substring. */
static int rnfs_text_has(FILE *sink, const char *want)
{
    char buf[RNFS_TEXT];
    if (fseek(sink, 0, SEEK_SET) != 0)
        return 0;
    size_t n = fread(buf, 1, sizeof buf - 1, sink);
    buf[n] = '\0';
    return strstr(buf, want) != NULL;
}

static int rnfs_run_case(const char *root, const struct rnfs_case *c)
{
    int rc = rnfs_write_fixture(root, c);
    if (rc)
        return rc;
    FILE *sink = tmpfile();
    if (!sink)
        return die("z23-lint: tmpfile failed\n", "");
    int got = rnd_check_root(root, c->bin ? c->bin : "build/bin/z23", sink,
                             sink);
    int text_ok = !c->want_text || rnfs_text_has(sink, c->want_text);
    fclose(sink);
    if (got != c->want || !text_ok) {
        fprintf(stderr, "check-release-no-dev-symbols selftest: %s: "
                "want rc=%d got rc=%d (report text %s)\n", c->name, c->want,
                got, text_ok ? "present" : "MISSING");
        return 1;
    }
    printf("  selftest ok: %s (rc=%d)\n", c->name, got);
    return 0;
}

/* Runs every case in a fresh fixture root. 0 = all pass, 1 = a case failed,
 * 2 = an infrastructure error (missing cc, fixture I/O): the worst wins. */
static int rnfs_run_suite(void)
{
    char root[RNFS_PATH];
    int rc = rnfs_fixture_root(root, sizeof root);
    if (rc)
        return rc;
    int worst = 0;
    for (size_t i = 0; i < sizeof k_rnfs_cases / sizeof k_rnfs_cases[0]; i++) {
        int got = rnfs_run_case(root, &k_rnfs_cases[i]);
        if (got > worst)
            worst = got;
    }
    rap_rm_rf(root);
    return worst;
}

int check_release_no_dev_symbols_selftest(void)
{
    int bad = rnfs_run_suite();
    if (bad == 2)
        return 2;
    if (bad)
        fputs("FAIL: check-release-no-dev-symbols selftest\n", stderr);
    return st_ok(bad, "check-release-no-dev-symbols selftest: OK\n");
}
