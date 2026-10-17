/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: self-test of check-accel-oracle-pinned. Builds a synthetic
 * repository (two ISA-dispatched implementations reached from core/, their
 * oracles, a registry and a test group catalog) in a scratch directory,
 * proves it passes, then proves each failure class is rejected: an
 * unregistered ISA file, a malformed row, stale rows, a missing marker, an
 * unregistered test group, an oracle naming no export (including one naming
 * only a static function), a row for a file the core no longer reaches or that
 * lost its ISA dispatch, a missing oracle file, diagnostics out of
 * implementation order, and each collapsed scan floor or a missing registry
 * (exit 2). The unregistered hw_profile.c carrying an ISA dispatch must not
 * fail the passing case. The scratch directory is removed on
 * exit and after SIGINT, SIGTERM or SIGHUP.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "gate_accel_oracle_pinned_priv.h"
#include "lintc.h"
#include "lintc_sig.h"

enum { AOPS_PATH = 4096, AOPS_OUT = 16384 };

struct aops_file { const char *path; const char *text; };

#define AOPS_SHA "core/modules/crypto/src/sha.c"
#define AOPS_FAST "core/modules/crypto/src/fast_avx.c"
#define AOPS_LATE "core/modules/crypto/src/late_priv.h"
#define AOPS_HW "platform/modules/util/src/hw_profile.c"
#define AOPS_REG "tools/lint/accel_oracle_registry.txt"
#define AOPS_CAT "tools/dev/test_group_catalog.def"

static const char k_aops_sha_late[] =
    "#include \"crypto/fast.h\"\n#include \"sha_priv.h\"\n#include \"late_priv.h\"\n"
    "int sha_digest(int x) {\n    return fast_hash(x);\n}\n";
static const char k_aops_reg_sha[] =
    "# registry\n" AOPS_SHA " tests/sha_oracle.c sha_group\n";
static const char k_aops_reg_full[] =
    "# registry\n" AOPS_SHA " tests/sha_oracle.c sha_group\n"
    AOPS_FAST " tests/fast_oracle.c fast_group  # trailing comment\n";

static const char k_aops_reg_unreached[] =
    "# registry\n" AOPS_SHA " tests/sha_oracle.c sha_group\n"
    AOPS_FAST " tests/fast_oracle.c fast_group\n"
    "tests/fast_oracle.c tests/fast_oracle.c fast_group\n";
static const char k_aops_reg_noorc[] =
    "# registry\n" AOPS_SHA " tests/sha_oracle.c sha_group\n"
    AOPS_FAST " tests/absent_oracle.c fast_group\n";
static const char k_aops_reg_unsorted[] =
    "# registry\n"
    "core/modules/crypto/src/z_gone.c tests/gone.c g\n"
    AOPS_SHA " tests/sha_oracle.c sha_group\n"
    "core/modules/crypto/src/a_gone.c tests/gone.c g\n"
    AOPS_FAST " tests/fast_oracle.c fast_group\n";

static const struct aops_file k_aops_base[] = {
    /* No src directory: header-only modules remain valid. */
    { "engine/modules/header_only/include/header_only/empty.h", "int empty;\n" },
    { "engine/modules/glob_probe/include/glob_probe/empty.h", "int empty;\n" },
    { "core/consensus/src/a.c", "#include \"crypto/sha.h\"\n#include \"util/hw_profile.h\"\n"
                                "int a(void) { return 0; }\n" },
    { "platform/modules/util/include/util/hw_profile.h", "int hw_probe(void);\n" },
    { AOPS_HW, "int hw_probe(void) {\n    return __builtin_cpu_supports(\"avx2\");\n}\n" },
    { "core/modules/crypto/include/crypto/sha.h", "int sha_digest(int x);\n" },
    { "core/modules/crypto/include/crypto/fast.h", "int fast_hash(int x);\n" },
    { AOPS_SHA, "#include \"crypto/fast.h\"\n#include \"sha_priv.h\"\n"
                "int sha_digest(int x) {\n    return fast_hash(x);\n}\n"
                "static int sha_helper(void) {\n    return 0;\n}\n" },
    { "core/modules/crypto/src/sha_priv.h", "#include <immintrin.h>\n" },
    { AOPS_FAST, "int fast_hash(int x) {\n"
                 "    return __builtin_cpu_supports(\"avx2\") ? x : -x;\n}\n" },
    { "tests/sha_oracle.c", "/* ACCEL-ORACLE: " AOPS_SHA " */\n"
                            "int t(void) { return sha_digest(1); }\n" },
    { "tests/fast_oracle.c", "/* ACCEL-ORACLE: " AOPS_FAST " */\n"
                             "int t(void) { return fast_hash(1); }\n" },
    { AOPS_REG, k_aops_reg_full },
    { AOPS_CAT, "ZCL_TEST_GROUP(sha_group)\nZCL_TEST_GROUP(fast_group)\n" },
};

struct aops_case {
    const char *name;
    const char *path;
    const char *text;
    const struct aop_cfg *cfg;
    int want_rc;
    const char *needle;
    const char *after;
};

static const struct aop_cfg k_aops_cfg = { AOPS_REG, AOPS_CAT, 2, 2, 2, 2, 1 };
static const struct aop_cfg k_aops_cfg_hollow = { AOPS_REG, AOPS_CAT, 100, 2, 2, 2, 1 };
static const struct aop_cfg k_aops_cfg_work = { AOPS_REG, AOPS_CAT, 2, 100, 2, 2, 1 };
static const struct aop_cfg k_aops_cfg_closure = { AOPS_REG, AOPS_CAT, 2, 2, 100, 2, 1 };
static const struct aop_cfg k_aops_cfg_isa = { AOPS_REG, AOPS_CAT, 2, 2, 2, 100, 1 };
static const struct aop_cfg k_aops_cfg_isa1 = { AOPS_REG, AOPS_CAT, 2, 2, 2, 1, 1 };
static const struct aop_cfg k_aops_cfg_rows = { AOPS_REG, AOPS_CAT, 2, 2, 2, 2, 100 };
static const struct aop_cfg k_aops_cfg_nolist = { "tools/lint/absent.txt", AOPS_CAT, 2, 2, 2, 2, 1 };

static const struct aops_case k_aops_cases[] = {
    { "the synthetic tree passes", NULL, NULL, &k_aops_cfg, 0,
      "OK: 2 ISA-dispatched file(s) reachable from sealed core/ (closure 3 files)", NULL },
    { "an unregistered ISA file", AOPS_REG, k_aops_reg_sha, &k_aops_cfg, 1,
      AOPS_FAST " is ISA-dispatched and reachable", NULL },
    { "a malformed row", AOPS_REG, "# registry\n" AOPS_SHA " tests/sha_oracle.c sha_group\nbad.c oracle.c\n",
      &k_aops_cfg, 1, "malformed row", NULL },
    { "a stale row", AOPS_REG,
      "# registry\n" AOPS_SHA " tests/sha_oracle.c sha_group\n"
      AOPS_FAST " tests/fast_oracle.c fast_group\n"
      "core/modules/crypto/src/gone.c tests/gone.c g\n",
      &k_aops_cfg, 1, "gone.c', which does not exist", NULL },
    { "a missing marker", "tests/fast_oracle.c", "int t(void) { return fast_hash(1); }\n",
      &k_aops_cfg, 1, "does not carry the marker line", NULL },
    { "an unregistered group", AOPS_CAT, "ZCL_TEST_GROUP(sha_group)\n",
      &k_aops_cfg, 1, "test group 'fast_group'", NULL },
    { "an oracle naming no export", "tests/sha_oracle.c",
      "/* ACCEL-ORACLE: " AOPS_SHA " */\nint t(void) { return sha_digestx(1); }\n",
      &k_aops_cfg, 1, "references no function exported", NULL },
    { "a collapsed header floor", NULL, NULL, &k_aops_cfg_hollow, 2, "FATAL", NULL },
    { "a collapsed implementation floor", NULL, NULL, &k_aops_cfg_work, 2,
      "resolved to almost no lib implementation files", NULL },
    { "a collapsed closure floor", NULL, NULL, &k_aops_cfg_closure, 2,
      "include closure collapsed", NULL },
    { "a collapsed ISA floor", NULL, NULL, &k_aops_cfg_isa, 2,
      "no ISA-dispatched file found", NULL },
    { "a collapsed registry floor", NULL, NULL, &k_aops_cfg_rows, 2,
      "registry lost rows", NULL },
    { "a missing registry", NULL, NULL, &k_aops_cfg_nolist, 2, "FATAL — missing", NULL },
    { "an oracle naming only a static function", "tests/sha_oracle.c",
      "/* ACCEL-ORACLE: " AOPS_SHA " */\nint t(void) { return sha_helper(); }\n",
      &k_aops_cfg, 1, "references no function exported", NULL },
    { "a row for a file the core no longer reaches", AOPS_REG, k_aops_reg_unreached,
      &k_aops_cfg, 1, "which sealed core/ no longer reaches", NULL },
    { "a row for a file that lost its ISA dispatch", AOPS_FAST,
      "int fast_hash(int x) {\n    return x;\n}\n",
      &k_aops_cfg_isa1, 1, "which no longer carries an ISA dispatch", NULL },
    { "a missing oracle file", AOPS_REG, k_aops_reg_noorc, &k_aops_cfg, 1,
      "'tests/absent_oracle.c', which does not exist", NULL },
    { "stale rows reported in implementation order", AOPS_REG, k_aops_reg_unsorted,
      &k_aops_cfg, 1, "src/a_gone.c', which does not exist",
      "src/z_gone.c', which does not exist" },
};

static int aops_fail(const char *what, const char *detail)
{
    fprintf(stderr, "check_accel_oracle_pinned: selftest FAIL: %s%s%s\n", what,
            detail[0] ? ": " : "", detail);
    return 1;
}

static int aops_put_base(const char *path)
{
    for (size_t i = 0; i < sizeof k_aops_base / sizeof k_aops_base[0]; i++)
        if (strcmp(k_aops_base[i].path, path) == 0)
            return csr_write(path, k_aops_base[i].text);
    return 2;
}

static int aops_populate(void)
{
    for (size_t i = 0; i < sizeof k_aops_base / sizeof k_aops_base[0]; i++)
        if (csr_write(k_aops_base[i].path, k_aops_base[i].text) != 0)
            return 2;
    return 0;
}

static int aops_git_track(void)
{
    char out[1024];
    int code = 0;
    int rc = capture_cmd("env -u GIT_DIR -u GIT_INDEX_FILE -u GIT_WORK_TREE "
                         "GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null "
                         "sh -c 'git init -q . && git add -A' 2>&1", out, sizeof out, &code);
    return rc == 0 && code == 0 ? 0 : 2;
}

/* Runs the gate with stdout and stderr captured into out. */
static int aops_run(const struct aop_cfg *cfg, char *out, size_t cap)
{
    int so = dup(1), se = dup(2);
    int fd = open("capture.txt", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    int rc = -1;
    size_t n = 0;
    FILE *f;
    out[0] = '\0';
    if (so < 0 || se < 0 || fd < 0)
        return -1;
    fflush(stdout);
    fflush(stderr);
    if (dup2(fd, 1) >= 0 && dup2(fd, 2) >= 0)
        rc = aop_run_cfg(cfg);
    fflush(stdout);
    fflush(stderr);
    dup2(so, 1);
    dup2(se, 2);
    close(so);
    close(se);
    close(fd);
    f = fopen("capture.txt", "r");
    if (f) {
        n = fread(out, 1, cap - 1, f);
        fclose(f);
    }
    out[n] = '\0';
    return rc;
}

static int aops_case(const struct aops_case *k)
{
    char out[AOPS_OUT];
    int rc;
    if (k->path && csr_write(k->path, k->text) != 0)
        return aops_fail(k->name, "cannot write the mutation");
    rc = aops_run(k->cfg, out, sizeof out);
    if (k->path && aops_put_base(k->path) != 0)
        return aops_fail(k->name, "cannot restore the fixture");
    if (rc != k->want_rc) {
        fprintf(stderr, "%s", out);
        return aops_fail(k->name, "unexpected exit code");
    }
    const char *hit = strstr(out, k->needle);
    if (!hit) {
        fprintf(stderr, "%s", out);
        return aops_fail(k->name, "expected message missing");
    }
    if (k->after && !strstr(hit + 1, k->after)) {
        fprintf(stderr, "%s", out);
        return aops_fail(k->name, "messages out of order");
    }
    return 0;
}

/* Runs the gate on the current fixture and checks exit code and needle. */
static int aops_expect(const char *name, int want_rc, const char *needle)
{
    char out[AOPS_OUT];
    int rc = aops_run(&k_aops_cfg, out, sizeof out);
    if (rc != want_rc) {
        fprintf(stderr, "%s", out);
        return aops_fail(name, "unexpected exit code");
    }
    if (!strstr(out, needle)) {
        fprintf(stderr, "%s", out);
        return aops_fail(name, "expected message missing");
    }
    return 0;
}

/* Swaps the file at path for an empty directory (opens, then read fails). */
static int aops_swap_dir(const char *path)
{
    return unlink(path) != 0 ? -1 : mkdir(path, 0755);
}

static int aops_restore_dir(const char *path)
{
    return rmdir(path) != 0 ? -1 : aops_put_base(path);
}

/* A private header that the sha.c scan list picks up (core/ seed reads only
 * see tracked files), built untracked: a directory is FATAL by name, and an
 * unreadable regular file reaches the same FATAL read-failure line. */
static int aops_header_cases(void)
{
    int bad = 0;
    if (csr_write(AOPS_SHA, k_aops_sha_late) != 0 || mkdir(AOPS_LATE, 0755) != 0)
        return aops_fail("header that is a directory", "cannot build the fixture");
    bad |= aops_expect("a scanned header that is a directory", 2,
                       AOPS_LATE " exists but is not a regular file");
    if (rmdir(AOPS_LATE) != 0)
        return aops_fail("header that is a directory", "cannot restore the fixture");
    if (geteuid() != 0) {
        if (csr_write(AOPS_LATE, "int late;\n") != 0 || chmod(AOPS_LATE, 0) != 0)
            return aops_fail("unreadable header", "cannot build the fixture");
        bad |= aops_expect("an unreadable scanned header (chmod 000)", 2,
                           "FATAL — grep failed (exit 2) for: " AOPS_LATE);
        if (unlink(AOPS_LATE) != 0)
            return aops_fail("unreadable header", "cannot remove the fixture");
    } else {
        fprintf(stderr, "check_accel_oracle_pinned: SKIP unreadable header "
                "case: running as root, chmod 000 does not deny the read\n");
    }
    if (aops_put_base(AOPS_SHA) != 0)
        return aops_fail("scanned header cases", "cannot restore the fixture");
    return bad;
}

/* Keep unrelated healthy implementations above every floor: denying an
 * additional empty src directory must not be mistaken for genuine NOMATCH. */
static int aops_glob_case(void)
{
    const char *dir = "engine/modules/glob_probe/src";
    int bad = 0;
    if (mkdir(dir, 0755) != 0)
        return aops_fail("glob traversal", "cannot create src directory");
    if (geteuid() == 0) {
        fprintf(stderr, "check_accel_oracle_pinned: glob EACCES case "
                "cannot run as root\n");
        bad = aops_fail("glob traversal", "EACCES witness unqualified");
    } else {
        if (chmod(dir, 0) != 0)
            return aops_fail("glob traversal", "cannot deny directory access");
        errno = 0;
        DIR *probe = opendir(dir);
        int denied = !probe && errno == EACCES;
        if (probe)
            closedir(probe);
        if (!denied) {
            bad = aops_fail("glob traversal", "EACCES prerequisite not observed");
        } else {
            char out[AOPS_OUT];
            int rc = aops_run(&k_aops_cfg, out, sizeof out);
            if (rc != 2 || !strstr(out, "glob failed for") || strstr(out, "OK:"))
                bad = aops_fail("glob traversal", "expected fatal without OK");
        }
        /* Restore before any return, including prerequisite/assertion failure. */
        if (chmod(dir, 0755) != 0)
            return aops_fail("glob traversal", "cannot restore directory mode");
    }
    if (!lsc_pending())
        bad |= aops_expect("restored empty src and absent header-only src", 0,
                       "OK: 2 ISA-dispatched file(s)");
    if (rmdir(dir) != 0)
        bad |= aops_fail("glob traversal", "cannot remove empty src directory");
    return bad;
}

/* Unreadable-file cases that a text mutation cannot express. Every case
 * runs so that one red case does not hide the others. */
static int aops_fs_cases(void)
{
    static const char orc[] = "tests/sha_oracle.c";
    int bad = 0;
    if (geteuid() == 0) {
        fprintf(stderr, "check_accel_oracle_pinned: SKIP permission-denied "
                "case: running as root, chmod 000 does not deny the read\n");
    } else {
        if (chmod(orc, 0) != 0)
            return aops_fail("unreadable oracle", "cannot chmod the fixture");
        bad |= aops_expect("an unreadable oracle (chmod 000)", 2,
                           "tests/sha_oracle.c: Permission denied");
        if (chmod(orc, 0644) != 0)
            return aops_fail("unreadable oracle", "cannot restore the mode");
    }
    if (aops_swap_dir(orc) != 0)
        return aops_fail("oracle that fails to read", "cannot swap in a directory");
    bad |= aops_expect("an oracle that opens but fails to read", 2,
                       "tests/sha_oracle.c: Is a directory");
    if (aops_restore_dir(orc) != 0)
        return aops_fail("oracle that fails to read", "cannot restore the fixture");
    return bad | aops_header_cases();
}

/* w40: the include/export readers and the impl glob must refuse an
 * unreadable or non-regular operand instead of treating it as an empty
 * result set (a dropped seed file can hide a whole accelerator). */
static int aops_reader_cases(void)
{
    static const char k_dir_impl[] = "core/modules/crypto/src/fast_dir.c";
    int bad = 0;
    if (aops_put_base(AOPS_SHA) != 0)
        return aops_fail("unreadable seed source", "cannot build the fixture");
    if (geteuid() != 0) {
        if (chmod(AOPS_SHA, 0) != 0)
            return aops_fail("unreadable seed source", "cannot chmod the fixture");
        bad |= aops_expect("an unreadable seed source (chmod 000)", 2,
                           "cannot read " AOPS_SHA);
        if (chmod(AOPS_SHA, 0644) != 0)
            return aops_fail("unreadable seed source", "cannot restore the fixture");
    } else {
        fprintf(stderr, "check_accel_oracle_pinned: seed EACCES case "
                "cannot run as root\n");
        bad = aops_fail("unreadable seed source", "EACCES witness unqualified");
    }
    if (mkdir(k_dir_impl, 0755) != 0)
        return aops_fail("directory impl", "cannot build the fixture");
    bad |= aops_expect("an implementation source that is a directory", 2,
                       "exists but is not a regular file");
    if (rmdir(k_dir_impl) != 0)
        return aops_fail("directory impl", "cannot remove the fixture");
    return bad;
}

static int aops_cases(void)
{
    for (size_t i = 0; i < sizeof k_aops_cases / sizeof k_aops_cases[0]; i++) {
        int rc = aops_case(&k_aops_cases[i]);
        if (rc || lsc_pending())
            return rc;
    }
    int rc = aops_fs_cases();
    if (rc || lsc_pending())
        return rc;
    rc = aops_glob_case();
    if (rc || lsc_pending())
        return rc;
    return aops_reader_cases();
}

static int aops_in_fixture(const char *dir)
{
    char old[AOPS_PATH];
    int rc;
    if (!getcwd(old, sizeof old) || chdir(dir) != 0)
        return aops_fail("cannot enter the scratch directory", dir);
    rc = aops_populate() || aops_git_track()
        ? aops_fail("cannot build the synthetic tree", dir) : aops_cases();
    if (chdir(old) != 0)
        rc = rc ? rc : aops_fail("cannot return to the working directory", old);
    return rc;
}

static int aops_scratch(char *dir, size_t cap)
{
    const char *tmp = env_or("TMPDIR", "test-tmp");
    if (csr_mkdirs(tmp) != 0
        || snprintf(dir, cap, "%s/accel-oracle-pinned.XXXXXX", tmp) >= (int)cap)
        return -1;
    return mkdtemp(dir) ? 0 : -1;
}

int check_accel_oracle_pinned_selftest(void)
{
    char dir[AOPS_PATH];
    int rc, sig;
    if (lsc_install() != 0 || aops_scratch(dir, sizeof dir) != 0)
        return aops_fail("cannot create the scratch directory", "");
    lsc_unblock();
    rc = aops_in_fixture(dir);
    lsc_block();
    rap_rm_rf(dir);
    sig = lsc_pending();
    if (sig)
        lsc_finish(sig);
    if (rc == 0)
        puts("check_accel_oracle_pinned: selftest OK (pass, unregistered ISA file, "
             "malformed row, stale row, missing marker, unregistered group, "
             "unwired oracle, static-only oracle, unreached row, row without ISA dispatch, "
             "missing oracle file, hw_profile.c skip, ordered diagnostics, collapsed floors, "
             "missing registry, unreadable oracle, read-failing oracle, non-regular ISA include, unreadable ISA include)");
    return rc;
}
