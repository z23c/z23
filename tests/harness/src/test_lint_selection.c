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
#include <arpa/inet.h>
#include <dirent.h>
#include <netinet/in.h>
#include <sys/socket.h>
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

/* ── unit-exec: the Landlocked unit runner ─────────────────────────────── */

struct lsel_ux {
    char dir[PATH_MAX];
    char root[PATH_MAX];
    char scratch[PATH_MAX];
    char premise[PATH_MAX];
};

static bool lsel_ux_file(const char *dir, const char *rel, const char *text)
{
    char path[PATH_MAX * 2];
    (void)snprintf(path, sizeof(path), "%s/%s", dir, rel);
    FILE *f = fopen(path, "w");
    if (!f)
        return false;
    bool ok = fputs(text, f) >= 0;
    return fclose(f) == 0 && ok;
}

/* root/{a.c, secret.txt, sub/inner.txt}; the premise declares a.c only. */
static bool lsel_ux_fixture(struct lsel_ux *ux)
{
    memset(ux, 0, sizeof(*ux));
    if (!test_mkdtemp(ux->dir, sizeof(ux->dir), "lintunit"))
        return false;
    (void)snprintf(ux->root, sizeof(ux->root), "%s/root", ux->dir);
    (void)snprintf(ux->scratch, sizeof(ux->scratch), "%s/scratch", ux->dir);
    (void)snprintf(ux->premise, sizeof(ux->premise), "%s/premise.txt", ux->dir);
    char sub[PATH_MAX + 8];
    (void)snprintf(sub, sizeof(sub), "%s/sub", ux->root);
    return mkdir(ux->root, 0755) == 0 && mkdir(ux->scratch, 0700) == 0
           && mkdir(sub, 0755) == 0
           && lsel_ux_file(ux->root, "a.c", "int a;\n")
           && lsel_ux_file(ux->root, "secret.txt", "undeclared\n")
           && lsel_ux_file(ux->root, "sub/inner.txt", "listed?\n")
           && lsel_ux_file(ux->dir, "premise.txt", "a.c\n");
}

/* Run `z23-lint unit-exec` in-process over the fixture; returns its code. */
static int lsel_ux_run(const struct lsel_ux *ux, bool no_landlock,
                       const char *const *cmd)
{
    char root[PATH_MAX + 16], premise[PATH_MAX + 16], scratch[PATH_MAX + 16];
    (void)snprintf(root, sizeof(root), "--root=%s", ux->root);
    (void)snprintf(premise, sizeof(premise), "--premise=%s", ux->premise);
    (void)snprintf(scratch, sizeof(scratch), "--scratch=%s", ux->scratch);
    char *argv[16] = { root, premise, scratch };
    int n = 3;
    if (no_landlock)
        argv[n++] = (char *)"--no-landlock";
    argv[n++] = (char *)"--";
    for (size_t i = 0; cmd[i] && n < 15; i++)
        argv[n++] = (char *)cmd[i];
    argv[n] = NULL;
    fflush(NULL);
    return lint_unit_exec_main(n, argv);
}

static int test_lsel_ux_declared_and_undeclared(void)
{
    int failures = 0;
    TEST_CASE("lint_selection: unit-exec reads its premise, an undeclared "
              "read is PREMISE_INCOMPLETE") {
        struct lsel_ux ux;
        ASSERT(lsel_ux_fixture(&ux));
        const char *ok[] = { "cat", "a.c", NULL };
        const char *bad[] = { "cat", "secret.txt", NULL };
        ASSERT_EQ(lsel_ux_run(&ux, false, ok), 0);
        ASSERT_EQ(lsel_ux_run(&ux, false, bad), 3);
        test_rm_rf_recursive(ux.dir);
    } TEST_END
    return failures;
}

static int test_lsel_ux_read_dir(void)
{
    int failures = 0;
    TEST_CASE("lint_selection: unit-exec refuses an undeclared directory "
              "listing") {
        struct lsel_ux ux;
        ASSERT(lsel_ux_fixture(&ux));
        const char *ls_sub[] = { "ls", "sub", NULL };
        const char *ls_root[] = { "ls", ".", NULL };
        ASSERT_EQ(lsel_ux_run(&ux, false, ls_sub), 3);
        ASSERT_EQ(lsel_ux_run(&ux, false, ls_root), 3);
        /* A directory can never be declared: its rule would grant the
         * whole subtree. The runner refuses before running anything. */
        ASSERT(lsel_ux_file(ux.dir, "premise.txt", "a.c\nsub\n"));
        const char *ok[] = { "cat", "a.c", NULL };
        ASSERT_EQ(lsel_ux_run(&ux, false, ok), 2);
        test_rm_rf_recursive(ux.dir);
    } TEST_END
    return failures;
}

/* A regular file directly in the real $HOME, which no unit may read. */
static bool lsel_home_file(char *out, size_t cap)
{
    const char *home = getenv("HOME");
    DIR *d = home ? opendir(home) : NULL;
    struct dirent *de;
    bool found = false;
    while (d && !found && (de = readdir(d)) != NULL) {
        struct stat st;
        (void)snprintf(out, cap, "%s/%s", home, de->d_name);
        found = lstat(out, &st) == 0 && S_ISREG(st.st_mode)
                && access(out, R_OK) == 0;
    }
    if (d)
        closedir(d);
    return found;
}

static int test_lsel_ux_home(void)
{
    int failures = 0;
    TEST_CASE("lint_selection: unit-exec refuses a $HOME read") {
        struct lsel_ux ux;
        char victim[PATH_MAX * 2];
        ASSERT(lsel_ux_fixture(&ux));
        ASSERT(lsel_home_file(victim, sizeof(victim)));
        const char *cmd[] = { "cat", victim, NULL };
        ASSERT_EQ(lsel_ux_run(&ux, false, cmd), 3);
        /* The unit's own HOME is its private scratch, and that works. */
        const char *own[] = { "sh", "-c", "echo x > \"$HOME/own\" && cat \"$HOME/own\"",
                              NULL };
        ASSERT_EQ(lsel_ux_run(&ux, false, own), 0);
        test_rm_rf_recursive(ux.dir);
    } TEST_END
    return failures;
}

static int lsel_listener(int *port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    socklen_t len = sizeof(a);
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0
        || listen(fd, 4) != 0 || getsockname(fd, (struct sockaddr *)&a, &len) != 0) {
        if (fd >= 0)
            close(fd);
        return -1;
    }
    *port = ntohs(a.sin_port);
    return fd;
}

static int test_lsel_ux_tcp(void)
{
    int failures = 0;
    TEST_CASE("lint_selection: unit-exec refuses a TCP connect") {
        struct lsel_ux ux;
        int port = 0;
        int fd = lsel_listener(&port);
        ASSERT(fd >= 0);
        ASSERT(lsel_ux_fixture(&ux));
        char script[128];
        (void)snprintf(script, sizeof(script),
                       "exec 3<>/dev/tcp/127.0.0.1/%d && echo connected", port);
        /* Control: the same connect succeeds outside the domain. */
        const char *plain[] = { "/usr/bin/env", "bash", "-c", script, NULL };
        char out[64] = "";
        ASSERT_EQ(zcl_spawn_capture(plain, out, sizeof(out), 10000), 0);
        ASSERT(strstr(out, "connected") != NULL);
        const char *cmd[] = { "bash", "-c", script, NULL };
        ASSERT_EQ(lsel_ux_run(&ux, false, cmd), 5);
        close(fd);
        test_rm_rf_recursive(ux.dir);
    } TEST_END
    return failures;
}

static int test_lsel_ux_forced_off(void)
{
    int failures = 0;
    TEST_CASE("lint_selection: Landlock forced off runs nothing and inherits "
              "nothing") {
        struct lsel_ux ux;
        struct lsel_fx fx;
        struct premise_unit u[2];
        char why[PREMISE_REASON_MAX], marker[PATH_MAX + 16];
        ASSERT(lsel_ux_fixture(&ux));
        (void)snprintf(marker, sizeof(marker), "%s/ran", ux.scratch);
        const char *touch[] = { "touch", marker, NULL };
        ASSERT_EQ(lsel_ux_run(&ux, true, touch), 4);
        ASSERT(access(marker, F_OK) != 0);
        ASSERT_EQ(lsel_ux_run(&ux, false, touch), 0);
        ASSERT(access(marker, F_OK) == 0);
        /* The same unchanged candidate that inherits when confined. */
        ASSERT(lsel_fixture(&fx));
        ASSERT_EQ(lsel_eval(&fx, NULL, false, u, why, sizeof(why)), 0);
        ASSERT_STR_EQ(why, "landlock-unavailable");
        ASSERT(!u[0].would_inherit && !u[1].would_inherit);
        ASSERT_STR_EQ(u[0].reason, "landlock-unavailable");
        ASSERT(memcmp(u[0].action_root, u[0].base_root, PREMISE_HASH_BYTES) == 0);
        test_rm_rf_recursive(fx.dir);
        test_rm_rf_recursive(ux.dir);
    } TEST_END
    return failures;
}

/* The premise the selection core computes is enough for a real compiler,
 * and dropping one closure file from it fails the unit closed. */
static int test_lsel_ux_compiler_premise(void)
{
    int failures = 0;
    TEST_CASE("lint_selection: a computed premise compiles under unit-exec; "
              "a premise missing a header is PREMISE_INCOMPLETE") {
        struct lsel_fx fx;
        struct lsel_ux ux;
        struct premise_session s;
        ASSERT(lsel_fixture(&fx));
        ASSERT(lsel_ux_fixture(&ux));
        (void)snprintf(ux.root, sizeof(ux.root), "%s", fx.repo);
        FILE *out = fopen(ux.premise, "w");
        ASSERT(out != NULL);
        ASSERT_EQ(premise_session_open(&s, fx.repo, NULL, true, stderr), 0);
        int rc = premise_unit_grants(&s, &k_gate, "a.c", out, stderr);
        premise_session_close(&s);
        ASSERT(fclose(out) == 0);
        ASSERT_EQ(rc, 0);
        const char *cc[] = { "cc", "-fsyntax-only", "-Iinc", "a.c", NULL };
        ASSERT_EQ(lsel_ux_run(&ux, false, cc), 0);
        ASSERT(lsel_ux_file(ux.dir, "premise.txt", "a.c\ninc/x.h\n"));
        ASSERT_EQ(lsel_ux_run(&ux, false, cc), 3);
        test_rm_rf_recursive(ux.dir);
        test_rm_rf_recursive(fx.dir);
    } TEST_END
    return failures;
}

/* A per-file gate run by a tool built from tree sources: tool.c's header
 * chain, a source named only by a Makefile value, a "cfg/" prefix and the
 * gate's own rule are gate code; each unit is its own bytes. */
static const char *const k_tool_files[] = { "lint/tool.c", "cfg/" };
static const char *const k_tool_vars[] = { "check-x:", "TOOL_SRCS" };
static const struct premise_gate k_tool_gate = {
    .name = "fixture-file-gate",
    .gate_files = k_tool_files, .n_gate_files = 2,
    .make_vars = k_tool_vars, .n_make_vars = 2,
    .pin = "toolchain.pin", .unit_self = true,
};

static const char k_tool_makefile[] =
    "TOOL_SRCS = lint/extra.c\n"
    "check-x: tool\n"
    "\t@./tool --scan\n"
    "check-y:\n"
    "\t@true\n";

static bool lsel_tool_fixture(struct lsel_fx *fx)
{
    return lsel_fixture(fx) && lsel_write(fx, "Makefile", k_tool_makefile)
           && lsel_write(fx, "lint/tool.c", "#include \"tool.h\"\n")
           && lsel_write(fx, "lint/tool.h", "#include \"dep.h\"\n")
           && lsel_write(fx, "lint/dep.h", "int dep;\n")
           && lsel_write(fx, "lint/extra.c", "int extra;\n")
           && lsel_write(fx, "cfg/policy.txt", "strict\n")
           && lsel_commit_all(fx, "tool gate");
}

/* Write rel, evaluate the tool gate, and require a.c and b.c to carry the
 * given reasons ("premise-equal" means the unit inherits). */
static int lsel_tool_eval(struct lsel_fx *fx, const char *rel, const char *text,
                          const char *want_a, const char *want_b)
{
    struct premise_base_opts opts = {
        .objects = fx->repo, .remote = fx->repo, .ref = "refs/heads/main",
        .base = fx->base, .scratch = fx->scratch,
    };
    struct premise_unit u[2] = { { .unit = "a.c" }, { .unit = "b.c" } };
    struct premise_session s;
    int rc = lsel_write(fx, rel, text) ? 0 : 2;
    if (rc == 0)
        rc = premise_session_open(&s, fx->repo, &opts, true, stderr);
    if (rc == 0) {
        rc = premise_gate_eval(&s, &k_tool_gate, u, 2, stderr);
        premise_session_close(&s);
    }
    bool inherit_a = strcmp(want_a, "premise-equal") == 0;
    bool inherit_b = strcmp(want_b, "premise-equal") == 0;
    if (rc == 0 && (strcmp(u[0].reason, want_a) || strcmp(u[1].reason, want_b)
                    || u[0].would_inherit != inherit_a
                    || u[1].would_inherit != inherit_b))
        rc = 1;
    if (rc)
        printf("after %s: want %s / %s, got %s / %s\n", rel, want_a, want_b,
               u[0].reason, u[1].reason);
    return rc;
}

static int lsel_tool_all(struct lsel_fx *fx, const char *rel, const char *text,
                         const char *want)
{
    return lsel_tool_eval(fx, rel, text, want, want);
}

static const char k_tool_makefile_lax[] =
    "TOOL_SRCS = lint/extra.c\ncheck-x: tool\n\t@./tool --scan --lax\n"
    "check-y:\n\t@true\n";
static const char k_tool_makefile_other[] =
    "TOOL_SRCS = lint/extra.c\ncheck-x: tool\n\t@./tool --scan\n"
    "check-y:\n\t@false\n";

static int test_lsel_per_file_gate(void)
{
    int failures = 0;
    TEST_CASE("lint_selection: a per-file unit is its own bytes; the tool's "
              "header chain, Makefile-named sources, prefix files and rule "
              "are gate code") {
        struct lsel_fx fx;
        const char *eq = "premise-equal";
        ASSERT(lsel_tool_fixture(&fx));
        /* A header two includes below a.c is no premise of a per-file unit;
         * a.c's own bytes are. */
        ASSERT_EQ(lsel_tool_all(&fx, "inc/y.h", "int y;\nint y2;\n", eq), 0);
        ASSERT_EQ(lsel_tool_eval(&fx, "a.c", "#include \"x.h\"\nint a2;\n",
                                 "closure-changed:a.c", eq), 0);
        ASSERT_EQ(lsel_tool_all(&fx, "a.c", "#include \"x.h\"\nint a;\n", eq), 0);
        ASSERT_EQ(lsel_tool_all(&fx, "lint/dep.h", "int dep2;\n",
                                "gate-code:lint/dep.h"), 0);
        ASSERT_EQ(lsel_tool_all(&fx, "lint/dep.h", "int dep;\n", eq), 0);
        ASSERT_EQ(lsel_tool_all(&fx, "lint/extra.c", "int extra2;\n",
                                "gate-code:lint/extra.c"), 0);
        ASSERT_EQ(lsel_tool_all(&fx, "lint/extra.c", "int extra;\n", eq), 0);
        ASSERT_EQ(lsel_tool_all(&fx, "cfg/policy.txt", "lax\n",
                                "gate-code:cfg/policy.txt"), 0);
        ASSERT_EQ(lsel_tool_all(&fx, "cfg/policy.txt", "strict\n", eq), 0);
        ASSERT_EQ(lsel_tool_all(&fx, "Makefile", k_tool_makefile_lax,
                                "make-value:check-x:"), 0);
        ASSERT_EQ(lsel_tool_all(&fx, "Makefile", k_tool_makefile_other, eq), 0);
        test_rm_rf_recursive(fx.dir);
    } TEST_END
    return failures;
}

static int test_lsel_gate_code_computed(void)
{
    int failures = 0;
    TEST_CASE("lint_selection: a computed include in gate code keeps every "
              "unit fresh") {
        struct lsel_fx fx;
        const char *computed = "#define T \"dep.h\"\n#include T\n";
        ASSERT(lsel_tool_fixture(&fx));
        ASSERT(lsel_write(&fx, "lint/tool.h", computed));
        ASSERT(lsel_commit_all(&fx, "computed include in gate code"));
        ASSERT_EQ(lsel_tool_all(&fx, "lint/tool.h", computed,
                                "gate-computed-include"), 0);
        test_rm_rf_recursive(fx.dir);
    } TEST_END
    return failures;
}

/* ── catalog-row units ─────────────────────────────────────────────────── */

/* Rows one and two build from their own sources; row three links an
 * archive only the Makefile defines, so no tree path bounds its premise. */
static const char k_cat_makefile[] =
    "LIBX := out/libx.a\n"
    "$(LIBX): vendor/x.c\n"
    "\tcc -c vendor/x.c -o $@\n"
    "include cat.mk\n";

static const char k_cat[] =
    "# the catalog\n"
    "SHARED_LIB := -lshared\n"
    "ZCL_WINDOWS_ACCEPTANCE_TESTS := \\\n"
    "\tone \\\n"
    "\ttwo \\\n"
    "\tthree\n"
    "ZCL_WINDOWS_ACCEPTANCE_one_SOURCES := \\\n"
    "\tsrc/one.c \\\n"
    "\tsrc/common.c\n"
    "ZCL_WINDOWS_ACCEPTANCE_one_LIBS := $(SHARED_LIB)\n"
    "ZCL_WINDOWS_ACCEPTANCE_two_SOURCES := src/two.c\n"
    "ZCL_WINDOWS_ACCEPTANCE_two_FLAGS := -DTWO\n"
    "ZCL_WINDOWS_ACCEPTANCE_three_SOURCES := src/three.c\n"
    "ZCL_WINDOWS_ACCEPTANCE_three_LIBDEPS := $(LIBX)\n";

static const char *const k_cat_files[] = { "gate.sh", "Makefile" };
static const struct premise_gate k_cat_gate = {
    .name = "fixture-catalog-gate",
    .gate_files = k_cat_files, .n_gate_files = 2,
    .pin = "toolchain.pin", .catalog = "cat.mk",
};

static bool lsel_cat_fixture(struct lsel_fx *fx)
{
    return lsel_fixture(fx) && lsel_write(fx, "Makefile", k_cat_makefile)
           && lsel_write(fx, "cat.mk", k_cat)
           && lsel_write(fx, "inc/one.h", "int one;\n")
           && lsel_write(fx, "inc/two.h", "int two;\n")
           && lsel_write(fx, "src/one.c", "#include \"one.h\"\n")
           && lsel_write(fx, "src/common.c", "int common;\n")
           && lsel_write(fx, "src/two.c", "#include \"two.h\"\n")
           && lsel_write(fx, "src/three.c", "int three;\n")
           && lsel_write(fx, "vendor/x.c", "#define H <stdio.h>\n#include H\n")
           && lsel_commit_all(fx, "catalog");
}

/* Replace rel with text (NULL: leave the tree), evaluate the named units of
 * gate g, and require each to carry its reason. */
static int lsel_units_eval(struct lsel_fx *fx, const struct premise_gate *g,
                           const char *rel, const char *text,
                           const char *const *ids, const char *const *want,
                           size_t n)
{
    struct premise_base_opts opts = {
        .objects = fx->repo, .remote = fx->repo, .ref = "refs/heads/main",
        .base = fx->base, .scratch = fx->scratch,
    };
    struct premise_unit u[12];
    struct premise_session s;
    memset(u, 0, sizeof(u));
    if (n > sizeof(u) / sizeof(u[0]))
        return 2;
    for (size_t i = 0; i < n; i++)
        u[i].unit = ids[i];
    int rc = !rel || lsel_write(fx, rel, text) ? 0 : 2;
    if (rc == 0)
        rc = premise_session_open(&s, fx->repo, &opts, true, stderr);
    if (rc == 0) {
        rc = premise_gate_eval(&s, g, u, n, stderr);
        premise_session_close(&s);
    }
    for (size_t i = 0; rc == 0 && i < n; i++)
        if (strcmp(u[i].reason, want[i]) != 0
            || u[i].would_inherit != (strcmp(want[i], "premise-equal") == 0)) {
            printf("after %s: unit %s want %s, got %s\n", rel ? rel : "-",
                   ids[i], want[i], u[i].reason);
            rc = 1;
        }
    return rc;
}

static int lsel_cat_eval(struct lsel_fx *fx, const char *rel, const char *text,
                         const char *const *ids, const char *const *want,
                         size_t n)
{
    return lsel_units_eval(fx, &k_cat_gate, rel, text, ids, want, n);
}

static int lsel_cat_two(struct lsel_fx *fx, const char *rel, const char *text,
                        const char *want_one, const char *want_two)
{
    const char *ids[] = { "one", "two" };
    const char *want[] = { want_one, want_two };
    return lsel_cat_eval(fx, rel, text, ids, want, 2);
}

static int test_lsel_catalog_rows(void)
{
    int failures = 0;
    TEST_CASE("lint_selection: a catalog row reruns on its own sources, "
              "closure and text; residue and gate code rerun every row") {
        struct lsel_fx fx;
        const char *eq = "premise-equal";
        const char *residue = "catalog-residue:cat.mk";
        char cat[sizeof(k_cat) + 128];
        ASSERT(lsel_cat_fixture(&fx));
        const char *ids3[] = { "one", "two", "three" };
        const char *want3[] = { eq, eq, "computed-include" };
        ASSERT_EQ(lsel_cat_eval(&fx, NULL, NULL, ids3, want3, 3), 0);
        ASSERT_EQ(lsel_cat_two(&fx, "inc/two.h", "int two2;\n", eq,
                               "closure-changed:inc/two.h"), 0);
        ASSERT_EQ(lsel_cat_two(&fx, "inc/two.h", "int two;\n", eq, eq), 0);
        ASSERT_EQ(lsel_cat_two(&fx, "src/common.c", "int common2;\n",
                               "closure-changed:src/common.c", eq), 0);
        ASSERT_EQ(lsel_cat_two(&fx, "src/common.c", "int common;\n", eq, eq), 0);
        (void)snprintf(cat, sizeof(cat), "%s", k_cat);
        memcpy(strstr(cat, "-DTWO"), "-DTWX", 5);
        ASSERT_EQ(lsel_cat_two(&fx, "cat.mk", cat, eq, "catalog-row-changed"), 0);
        /* A row naming a file the tree does not hold has no finite premise. */
        (void)snprintf(cat, sizeof(cat), "%s", k_cat);
        memcpy(strstr(cat, "src/two.c"), "src/tw0.c", 9);
        ASSERT_EQ(lsel_cat_two(&fx, "cat.mk", cat, eq, "computed-include"), 0);
        (void)snprintf(cat, sizeof(cat), "%s", k_cat);
        memcpy(strstr(cat, "-lshared"), "-lshaRED", 8);
        ASSERT_EQ(lsel_cat_two(&fx, "cat.mk", cat, residue, residue), 0);
        (void)snprintf(cat, sizeof(cat), "# the catalog, reworded\n%s",
                       k_cat + strlen("# the catalog\n"));
        ASSERT_EQ(lsel_cat_two(&fx, "cat.mk", cat, eq, eq), 0);
        /* A new row reusing a tracked source: the others still inherit. */
        const char *tail = strstr(k_cat, "\tthree\n");
        (void)snprintf(cat, sizeof(cat), "%.*s\tthree \\\n\tfour\n%s"
                       "ZCL_WINDOWS_ACCEPTANCE_four_SOURCES := src/two.c\n",
                       (int)(tail - k_cat), k_cat, tail + strlen("\tthree\n"));
        const char *ids4[] = { "one", "two", "four" };
        const char *want4[] = { eq, eq, "unit-new" };
        ASSERT_EQ(lsel_cat_eval(&fx, "cat.mk", cat, ids4, want4, 3), 0);
        ASSERT_EQ(lsel_cat_two(&fx, "cat.mk", k_cat, eq, eq), 0);
        char mk[sizeof(k_cat_makefile) + 32];
        (void)snprintf(mk, sizeof(mk), "%sexport CPATH := inc\n",
                       k_cat_makefile);
        ASSERT_EQ(lsel_cat_two(&fx, "Makefile", mk, "gate-code:Makefile",
                               "gate-code:Makefile"), 0);
        test_rm_rf_recursive(fx.dir);
    } TEST_END
    return failures;
}

/* A row list that is not literal is refused, never read as no rows. */
static int test_lsel_catalog_refusal(void)
{
    int failures = 0;
    TEST_CASE("lint_selection: a computed catalog row list is refused") {
        struct lsel_fx fx;
        struct premise_catalog c;
        struct premise_session s;
        ASSERT(lsel_cat_fixture(&fx));
        ASSERT(lsel_write(&fx, "cat.mk",
                          "ZCL_WINDOWS_ACCEPTANCE_TESTS := $(shell ls src)\n"));
        ASSERT_EQ(premise_session_open(&s, fx.repo, NULL, false, stderr), 0);
        ASSERT_EQ(premise_catalog_open(&s.cand, "cat.mk", &c, stderr), 2);
        premise_catalog_close(&c);
        premise_session_close(&s);
        test_rm_rf_recursive(fx.dir);
    } TEST_END
    return failures;
}

/* ── doc-claims units ──────────────────────────────────────────────────── */

/* one.md binds a symbol to one header and to a glob; two.md binds a path
 * and an oracle gate; plain.md binds nothing. The last six are each
 * unbounded by one rule: pathspec magic, a prefix reaching a pruned
 * directory, a pruned path, a path the file system and the path set
 * disagree about, a path through a symlink, and a document that is itself
 * a symlink (its evaluated bytes are the target's, which the path set does
 * not bind). */
static const char *const k_doc_ids[] = {
    "docs/one.md", "docs/two.md", "docs/plain.md", "docs/magic.md",
    "docs/reach.md", "docs/pruned.md", "docs/empty.md", "docs/link.md",
    "docs/selflink.md",
};
enum { LSEL_DOCS = sizeof(k_doc_ids) / sizeof(k_doc_ids[0]), LSEL_BOUND = 3 };

static const char k_doc_two[] =
    "a.c exists.\n<!-- claim: file-present a.c -->\n"
    "The oracle holds.\n<!-- claim: gate-passes check-x -->\n";

static const char *const k_doc_files[] = { "gate.sh" };
static const struct premise_gate k_doc_gate = {
    .name = "fixture-doc-claims-gate",
    .gate_files = k_doc_files, .n_gate_files = 1,
    .pin = "toolchain.pin", .doc_claims = true,
};

static bool lsel_doc_fixture(struct lsel_fx *fx)
{
    char empty[PATH_MAX * 2], link[PATH_MAX * 2];
    bool ok = lsel_fixture(fx)
        && lsel_write(fx, "docs/one.md",
                      "x is declared.\n<!-- claim: symbol-present x inc/x.h -->\n"
                      "```\n<!-- claim: symbol-absent zz src/*.c # fenced -->\n```\n")
        && lsel_write(fx, "docs/two.md", k_doc_two)
        && lsel_write(fx, "docs/plain.md", "No claims here.\n")
        && lsel_write(fx, "docs/magic.md",
                      "<!-- claim: symbol-present a :(glob)*.c -->\n")
        && lsel_write(fx, "docs/reach.md",
                      "<!-- claim: symbol-absent a vendor/r*.c -->\n")
        && lsel_write(fx, "docs/pruned.md",
                      "<!-- claim: file-absent build/out -->\n")
        && lsel_write(fx, "docs/empty.md", "<!-- claim: file-absent empty -->\n")
        && lsel_write(fx, "docs/link.md",
                      "<!-- claim: file-present lnk/x.h -->\n")
        && lsel_write(fx, "src/s.c", "int s;\n");
    (void)snprintf(link, sizeof(link), "%s/lnk", fx->repo);
    ok = ok && symlink("inc", link) == 0;
    (void)snprintf(link, sizeof(link), "%s/docs/selflink.md", fx->repo);
    ok = ok && symlink("plain.md", link) == 0 && lsel_commit_all(fx, "docs");
    /* Git keeps no empty directory, so only the file system has this one. */
    (void)snprintf(empty, sizeof(empty), "%s/empty", fx->repo);
    return ok && mkdir(empty, 0755) == 0;
}

/* Evaluate every fixture document; the first LSEL_BOUND want the given
 * reasons, the unbounded rest always want computed-include. */
static int lsel_doc_eval(struct lsel_fx *fx, const char *rel, const char *text,
                         const char *one, const char *two, const char *plain)
{
    const char *want[LSEL_DOCS] = { one, two, plain };
    for (size_t i = LSEL_BOUND; i < LSEL_DOCS; i++)
        want[i] = "computed-include";
    return lsel_units_eval(fx, &k_doc_gate, rel, text, k_doc_ids, want,
                           LSEL_DOCS);
}

static int test_lsel_doc_claims(void)
{
    int failures = 0;
    TEST_CASE("lint_selection: a document reruns on its own bytes and the "
              "files its claims name; an unbounded claim keeps it fresh") {
        struct lsel_fx fx;
        const char *eq = "premise-equal";
        char two[sizeof(k_doc_two) + 32];
        ASSERT(lsel_doc_fixture(&fx));
        ASSERT_EQ(lsel_doc_eval(&fx, NULL, NULL, eq, eq, eq), 0);
        /* A file a symbol claim names, directly or through a glob, reruns
         * that document alone; a fenced example still counts. */
        ASSERT_EQ(lsel_doc_eval(&fx, "inc/x.h", "#include \"y.h\"\n",
                                "closure-changed:inc/x.h", eq, eq), 0);
        ASSERT_EQ(lsel_doc_eval(&fx, "inc/x.h", "#include \"y.h\"\nint x;\n",
                                eq, eq, eq), 0);
        ASSERT_EQ(lsel_doc_eval(&fx, "src/s.c", "int s2;\n",
                                "closure-changed:src/s.c", eq, eq), 0);
        ASSERT_EQ(lsel_doc_eval(&fx, "src/s.c", "int s;\n", eq, eq, eq), 0);
        /* file-present reads the path set only; an oracle claim is the
         * global part's, so a.c's bytes and the named gate change nothing. */
        ASSERT_EQ(lsel_doc_eval(&fx, "a.c", "int a2;\n", eq, eq, eq), 0);
        ASSERT_EQ(lsel_doc_eval(&fx, "a.c", "#include \"x.h\"\nint a;\n",
                                eq, eq, eq), 0);
        /* The document's own text is its premise, oracle claims included. */
        (void)snprintf(two, sizeof(two), "%s", k_doc_two);
        memcpy(strstr(two, "gate-passes"), "gate-fails ", 11);
        ASSERT_EQ(lsel_doc_eval(&fx, "docs/two.md", two, eq,
                                "closure-changed:docs/two.md", eq), 0);
        ASSERT_EQ(lsel_doc_eval(&fx, "docs/two.md", k_doc_two, eq, eq, eq), 0);
        /* Gate code reruns every document. */
        ASSERT_EQ(lsel_doc_eval(&fx, "gate.sh", "#!/bin/sh\necho gate2\n",
                                "gate-code:gate.sh", "gate-code:gate.sh",
                                "gate-code:gate.sh"), 0);
        test_rm_rf_recursive(fx.dir);
    } TEST_END
    return failures;
}


int test_lint_selection(void)
{
    int failures = 0;
    failures += test_lsel_doc_claims();
    failures += test_lsel_per_file_gate();
    failures += test_lsel_gate_code_computed();
    failures += test_lsel_catalog_rows();
    failures += test_lsel_catalog_refusal();
    failures += test_lsel_unchanged_inherits();
    failures += test_lsel_deep_header();
    failures += test_lsel_shadow_header();
    failures += test_lsel_gate_inputs();
    failures += test_lsel_baseline_rows();
    failures += test_lsel_computed_include();
    failures += test_lsel_tampered_tree();
    failures += test_lsel_non_ancestor();
    failures += test_lsel_ux_declared_and_undeclared();
    failures += test_lsel_ux_read_dir();
    failures += test_lsel_ux_home();
    failures += test_lsel_ux_tcp();
    failures += test_lsel_ux_forced_off();
    failures += test_lsel_ux_compiler_premise();
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
