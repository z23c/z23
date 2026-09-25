/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: base-relative premise selection (tools/lint/lintc/premise.h)
 *          reruns exactly what a change could affect and nothing it could
 *          not: a header two includes down reruns only its dependent unit,
 *          an added shadowing header, a gate-code, pin or Makefile-value
 *          edit reruns every unit, and a base that is not an ancestor of
 *          the anchoring tip or whose tree object was tampered with in the
 *          persistent store disables selection outright.
 *
 * Every fixture is a real Git repository under test-tmp/, committed with a
 * scrubbed Git environment. The candidate is the working tree; the base is
 * a commit verified through a fresh private store. NOT proven here: the
 * real gates' unit lists (`z23-lint select --dry` enumerates those from the
 * live Makefile; docs/experiments/2026-09-25-lint-premise-selection.md
 * records a run over real main commits). */
#include "test/test_core.h"

#include "lint/lintc/premise.h"
#include "util/spawn.h"

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if !defined(_WIN32)

struct lsel_fx {
    char dir[PATH_MAX];
    char repo[PATH_MAX];
    char scratch[PATH_MAX];
    char base[PREMISE_OID_MAX];
};

static int lsel_git(const struct lsel_fx *fx, const char *const *args,
                    char *out, size_t cap)
{
    char home[PATH_MAX + 8];
    char ceiling[PATH_MAX + 32];
    char sink[256];
    /* The ceiling keeps git from ever discovering the enclosing checkout,
     * even if a fixture step leaves the repo directory without .git. */
    const char *argv[32] = {
        "/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LC_ALL=C", home, ceiling,
        "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
        "git", "-C", fx->repo, "-c", "user.name=fixture",
        "-c", "user.email=fixture@invalid", "-c", "commit.gpgsign=false",
        "-c", "init.defaultBranch=main",
    };
    size_t n = 0;
    while (argv[n])
        n++;
    (void)snprintf(home, sizeof(home), "HOME=%s", fx->dir);
    (void)snprintf(ceiling, sizeof(ceiling), "GIT_CEILING_DIRECTORIES=%s",
                   fx->dir);
    for (size_t i = 0; args[i] && n + 1 < 32; i++)
        argv[n++] = args[i];
    argv[n] = NULL;
    int rc = zcl_spawn_capture(argv, out ? out : sink, out ? cap : sizeof(sink),
                               60000);
    for (size_t i = out ? strlen(out) : 0; i > 0 && out[i - 1] == '\n'; i--)
        out[i - 1] = '\0';
    return rc;
}

static bool lsel_write(const struct lsel_fx *fx, const char *rel,
                       const char *text)
{
    char path[PATH_MAX * 2];
    (void)snprintf(path, sizeof(path), "%s/%s", fx->repo, rel);
    char *slash = strrchr(path, '/');
    if (slash && slash > path + strlen(fx->repo)) {
        *slash = '\0';
        (void)mkdir(path, 0755);
        *slash = '/';
    }
    FILE *f = fopen(path, "w");
    if (!f)
        return false;
    bool ok = fputs(text, f) >= 0;
    return fclose(f) == 0 && ok;
}

static const char k_makefile[] =
    "FLOOR := 0x0A00\n"
    "CPPFLAGS_X = -DFLOOR=$(FLOOR) \\\n"
    "    -DEXTRA\n"
    "OTHER := unrelated\n";

static bool lsel_commit_all(struct lsel_fx *fx, const char *msg)
{
    const char *add[] = { "add", "-A", NULL };
    const char *commit[] = { "commit", "-q", "-m", msg, NULL };
    const char *head[] = { "rev-parse", "HEAD", NULL };
    return lsel_git(fx, add, NULL, 0) == 0
           && lsel_git(fx, commit, NULL, 0) == 0
           && lsel_git(fx, head, fx->base, sizeof(fx->base)) == 0
           && strlen(fx->base) == 40;
}

/* Base commit: a.c -> inc/x.h -> inc/y.h, and an independent b.c. */
static bool lsel_fixture(struct lsel_fx *fx)
{
    memset(fx, 0, sizeof(*fx));
    if (!test_mkdtemp(fx->dir, sizeof(fx->dir), "lintsel"))
        return false;
    (void)snprintf(fx->repo, sizeof(fx->repo), "%s/repo", fx->dir);
    (void)snprintf(fx->scratch, sizeof(fx->scratch), "%s/scratch", fx->dir);
    if (mkdir(fx->repo, 0755) != 0 || mkdir(fx->scratch, 0700) != 0)
        return false;
    const char *init[] = { "init", "-q", NULL };
    return lsel_git(fx, init, NULL, 0) == 0
           && lsel_write(fx, "Makefile", k_makefile)
           && lsel_write(fx, "gate.sh", "#!/bin/sh\necho gate\n")
           && lsel_write(fx, "baseline.txt", "# rows\nb.c 1\n")
           && lsel_write(fx, "inc/x.h", "#include \"y.h\"\nint x;\n")
           && lsel_write(fx, "inc/y.h", "int y;\n")
           && lsel_write(fx, "a.c", "#include \"x.h\"\nint a;\n")
           && lsel_write(fx, "b.c", "#include <stdio.h>\nint b;\n")
           && lsel_commit_all(fx, "base");
}

static const char *const k_gate_files[] = { "gate.sh" };
static const char *const k_make_vars[] = { "CPPFLAGS_X" };
static const char *const k_baselines[] = { "baseline.txt" };

static const struct premise_gate k_gate = {
    .name = "fixture-gate",
    .gate_files = k_gate_files, .n_gate_files = 1,
    .make_vars = k_make_vars, .n_make_vars = 1,
    .baselines = k_baselines, .n_baselines = 1,
    .pin = "toolchain.pin",
};

/* Evaluate a.c and b.c of the working tree against fx->base (or base). */
static int lsel_eval(const struct lsel_fx *fx, const char *base, bool confined,
                     struct premise_unit u[2], char *disabled, size_t cap)
{
    struct premise_base_opts opts = {
        .objects = fx->repo, .remote = fx->repo, .ref = "refs/heads/main",
        .base = base ? base : fx->base, .scratch = fx->scratch,
    };
    struct premise_session s;
    memset(u, 0, 2 * sizeof(*u));
    u[0].unit = "a.c";
    u[1].unit = "b.c";
    int rc = premise_session_open(&s, fx->repo, &opts, confined, stderr);
    if (rc == 0)
        rc = premise_gate_eval(&s, &k_gate, u, 2, stderr);
    (void)snprintf(disabled, cap, "%s", s.disabled);
    premise_session_close(&s);
    return rc;
}

static bool lsel_prefix(const char *s, const char *prefix)
{
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

static int test_lsel_unchanged_inherits(void)
{
    int failures = 0;
    TEST_CASE("lint_selection: an unchanged candidate inherits every unit") {
        struct lsel_fx fx;
        struct premise_unit u[2];
        char why[PREMISE_REASON_MAX];
        ASSERT(lsel_fixture(&fx));
        ASSERT_EQ(lsel_eval(&fx, NULL, true, u, why, sizeof(why)), 0);
        ASSERT_STR_EQ(why, "");
        ASSERT(u[0].would_inherit && u[1].would_inherit);
        ASSERT_STR_EQ(u[0].reason, "premise-equal");
        ASSERT(u[0].base_root_known);
        ASSERT(memcmp(u[0].action_root, u[0].base_root, PREMISE_HASH_BYTES) == 0);
        ASSERT(memcmp(u[0].action_root, u[1].action_root, PREMISE_HASH_BYTES) != 0);
        test_rm_rf_recursive(fx.dir);
    } TEST_END
    return failures;
}

static int test_lsel_deep_header(void)
{
    int failures = 0;
    TEST_CASE("lint_selection: a header two includes down reruns only its "
              "dependent unit") {
        struct lsel_fx fx;
        struct premise_unit u[2];
        char why[PREMISE_REASON_MAX];
        ASSERT(lsel_fixture(&fx));
        ASSERT(lsel_write(&fx, "inc/y.h", "int y;\nint y2;\n"));
        ASSERT_EQ(lsel_eval(&fx, NULL, true, u, why, sizeof(why)), 0);
        ASSERT(!u[0].would_inherit);
        ASSERT_STR_EQ(u[0].reason, "closure-changed:inc/y.h");
        ASSERT(memcmp(u[0].action_root, u[0].base_root, PREMISE_HASH_BYTES) != 0);
        ASSERT(u[1].would_inherit);
        ASSERT_STR_EQ(u[1].reason, "premise-equal");
        test_rm_rf_recursive(fx.dir);
    } TEST_END
    return failures;
}

static int test_lsel_shadow_header(void)
{
    int failures = 0;
    TEST_CASE("lint_selection: a new shadowing header flips every unit fresh") {
        struct lsel_fx fx;
        struct premise_unit u[2];
        char why[PREMISE_REASON_MAX];
        ASSERT(lsel_fixture(&fx));
        /* "x.h" next to a.c now wins its quoted include over inc/x.h. */
        ASSERT(lsel_write(&fx, "x.h", "int shadow;\n"));
        ASSERT_EQ(lsel_eval(&fx, NULL, true, u, why, sizeof(why)), 0);
        ASSERT(!u[0].would_inherit && !u[1].would_inherit);
        ASSERT_STR_EQ(u[0].reason, "path-set-changed");
        ASSERT_STR_EQ(u[1].reason, "path-set-changed");
        test_rm_rf_recursive(fx.dir);
    } TEST_END
    return failures;
}

static int lsel_all_fresh(const struct lsel_fx *fx, const char *reason)
{
    struct premise_unit u[2];
    char why[PREMISE_REASON_MAX];
    if (lsel_eval(fx, NULL, true, u, why, sizeof(why)) != 0)
        return 1;
    if (u[0].would_inherit || u[1].would_inherit
        || strcmp(u[0].reason, reason) != 0 || strcmp(u[1].reason, reason) != 0) {
        printf("expected every unit fresh as %s, got %s / %s\n", reason,
               u[0].reason, u[1].reason);
        return 1;
    }
    return 0;
}

static int test_lsel_gate_inputs(void)
{
    int failures = 0;
    TEST_CASE("lint_selection: gate code, the pin, and an extracted Makefile "
              "value each flip every unit; an unrelated Makefile line does "
              "not") {
        struct lsel_fx fx;
        struct premise_unit u[2];
        char why[PREMISE_REASON_MAX];
        ASSERT(lsel_fixture(&fx));
        ASSERT(lsel_write(&fx, "Makefile", "FLOOR := 0x0A00\n"
                                            "CPPFLAGS_X = -DFLOOR=$(FLOOR) \\\n"
                                            "    -DEXTRA\n"
                                            "OTHER := changed\n"));
        ASSERT_EQ(lsel_eval(&fx, NULL, true, u, why, sizeof(why)), 0);
        ASSERT(u[0].would_inherit && u[1].would_inherit);
        ASSERT(lsel_write(&fx, "Makefile", "FLOOR := 0x0A01\n"
                                            "CPPFLAGS_X = -DFLOOR=$(FLOOR) \\\n"
                                            "    -DEXTRA\n"
                                            "OTHER := unrelated\n"));
        ASSERT_EQ(lsel_all_fresh(&fx, "make-value:FLOOR"), 0);
        ASSERT(lsel_write(&fx, "Makefile", k_makefile));
        ASSERT(lsel_write(&fx, "gate.sh", "#!/bin/sh\necho stricter gate\n"));
        ASSERT_EQ(lsel_all_fresh(&fx, "gate-code:gate.sh"), 0);
        ASSERT(lsel_write(&fx, "gate.sh", "#!/bin/sh\necho gate\n"));
        ASSERT(lsel_write(&fx, "toolchain.pin", "cc sha3 0000\n"));
        /* Adding the pin also adds a path; the gate root is checked first. */
        ASSERT_EQ(lsel_all_fresh(&fx, "pin"), 0);
        test_rm_rf_recursive(fx.dir);
    } TEST_END
    return failures;
}

static int test_lsel_baseline_rows(void)
{
    int failures = 0;
    TEST_CASE("lint_selection: a unit's own baseline rows are its premise, "
              "other rows are not") {
        struct lsel_fx fx;
        struct premise_unit u[2];
        char why[PREMISE_REASON_MAX];
        ASSERT(lsel_fixture(&fx));
        ASSERT(lsel_write(&fx, "baseline.txt", "# rows, reworded\nb.c 2\n"));
        ASSERT_EQ(lsel_eval(&fx, NULL, true, u, why, sizeof(why)), 0);
        ASSERT(u[0].would_inherit);
        ASSERT(!u[1].would_inherit);
        ASSERT_STR_EQ(u[1].reason, "baseline-rows-changed");
        test_rm_rf_recursive(fx.dir);
    } TEST_END
    return failures;
}

static int test_lsel_computed_include(void)
{
    int failures = 0;
    TEST_CASE("lint_selection: a macro-computed include never inherits") {
        struct lsel_fx fx;
        struct premise_unit u[2];
        char why[PREMISE_REASON_MAX];
        ASSERT(lsel_fixture(&fx));
        ASSERT(lsel_write(&fx, "inc/y.h", "#define H \"z.h\"\n#include H\n"));
        ASSERT(lsel_commit_all(&fx, "computed include at base"));
        ASSERT_EQ(lsel_eval(&fx, NULL, true, u, why, sizeof(why)), 0);
        ASSERT(!u[0].would_inherit);
        ASSERT_STR_EQ(u[0].reason, "computed-include");
        ASSERT(u[1].would_inherit);
        test_rm_rf_recursive(fx.dir);
    } TEST_END
    return failures;
}

/* Overwrite the base root tree's loose object with another object's bytes:
 * the persistent store now answers the base tree id with a different tree. */
static bool lsel_tamper_tree(struct lsel_fx *fx)
{
    char spec[PREMISE_OID_MAX + 16], tree[PREMISE_OID_MAX], blob[PREMISE_OID_MAX];
    (void)snprintf(spec, sizeof(spec), "%s^{tree}", fx->base);
    const char *t[] = { "rev-parse", spec, NULL };
    const char *b[] = { "rev-parse", "HEAD:a.c", NULL };
    if (lsel_git(fx, t, tree, sizeof(tree)) != 0
        || lsel_git(fx, b, blob, sizeof(blob)) != 0)
        return false;
    char victim[PATH_MAX * 2], donor[PATH_MAX * 2];
    (void)snprintf(victim, sizeof(victim), "%s/.git/objects/%.2s/%s",
                   fx->repo, tree, tree + 2);
    (void)snprintf(donor, sizeof(donor), "%s/.git/objects/%.2s/%s",
                   fx->repo, blob, blob + 2);
    unsigned char bytes[65536];
    FILE *in = fopen(donor, "rb");
    size_t n = in ? fread(bytes, 1, sizeof(bytes), in) : 0;
    if (!in || fclose(in) != 0 || n == 0 || n == sizeof(bytes)
        || chmod(victim, 0644) != 0)
        return false;
    FILE *out = fopen(victim, "wb");
    bool ok = out && fwrite(bytes, 1, n, out) == n;
    if (out && fclose(out) != 0)
        ok = false;
    return ok;
}

static int test_lsel_tampered_tree(void)
{
    int failures = 0;
    TEST_CASE("lint_selection: a tampered base tree object disables "
              "selection") {
        struct lsel_fx fx;
        struct premise_unit u[2];
        char why[PREMISE_REASON_MAX];
        ASSERT(lsel_fixture(&fx));
        ASSERT(lsel_tamper_tree(&fx));
        ASSERT_EQ(lsel_eval(&fx, NULL, true, u, why, sizeof(why)), 0);
        ASSERT(lsel_prefix(why, "base-unverified:fresh-store fetch"));
        ASSERT(!u[0].would_inherit && !u[1].would_inherit);
        ASSERT(!u[0].base_root_known);
        ASSERT(lsel_prefix(u[0].reason, "base-unverified:"));
        test_rm_rf_recursive(fx.dir);
    } TEST_END
    return failures;
}

static int test_lsel_non_ancestor(void)
{
    int failures = 0;
    TEST_CASE("lint_selection: a base that is not an ancestor of the tip "
              "disables selection") {
        struct lsel_fx fx;
        struct premise_unit u[2];
        char why[PREMISE_REASON_MAX], side[PREMISE_OID_MAX];
        ASSERT(lsel_fixture(&fx));
        const char *branch[] = { "checkout", "-q", "-b", "side", NULL };
        const char *back[] = { "checkout", "-q", "main", NULL };
        ASSERT_EQ(lsel_git(&fx, branch, NULL, 0), 0);
        ASSERT(lsel_write(&fx, "b.c", "int side;\n"));
        char main_base[PREMISE_OID_MAX];
        memcpy(main_base, fx.base, sizeof(main_base));
        ASSERT(lsel_commit_all(&fx, "side"));
        memcpy(side, fx.base, sizeof(side));
        ASSERT_EQ(lsel_git(&fx, back, NULL, 0), 0);
        ASSERT_EQ(lsel_eval(&fx, side, true, u, why, sizeof(why)), 0);
        ASSERT(lsel_prefix(why, "base-unverified:"));
        ASSERT(strstr(why, "not an ancestor") != NULL);
        ASSERT(!u[0].would_inherit && !u[1].would_inherit);
        ASSERT_EQ(lsel_eval(&fx, main_base, true, u, why, sizeof(why)), 0);
        ASSERT(u[0].would_inherit && u[1].would_inherit);
        test_rm_rf_recursive(fx.dir);
    } TEST_END
    return failures;
}

int test_lint_selection(void)
{
    int failures = 0;
    failures += test_lsel_unchanged_inherits();
    failures += test_lsel_deep_header();
    failures += test_lsel_shadow_header();
    failures += test_lsel_gate_inputs();
    failures += test_lsel_baseline_rows();
    failures += test_lsel_computed_include();
    failures += test_lsel_tampered_tree();
    failures += test_lsel_non_ancestor();
    return failures;
}

#else

int test_lint_selection(void)
{
    printf("lint_selection: SKIP — premise selection verifies bases with a "
           "POSIX Git subprocess; not built on Windows\n");
    return 0;
}

#endif
