/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family - check-app-bundle-reproducible of the C23 lint
 * runtime, the replacement for the bash body of
 * tools/lint/lintc/gate_app_bundle_reproducible.c. The macOS .app bundler
 * (tools/scripts/make_app_bundle.sh) must be a pure function of its input
 * AND its product must launch. The subject compiles twice, the bundler runs
 * twice into two directories, and the trees must agree in the SHA-256 of
 * every file (signature included), in file mode and mtime, and in directory
 * shape; codesign must verify both bundles as ad-hoc signed and the bundled
 * executable must exit 0 with the expected output.
 *
 *   z23-lint check-app-bundle-reproducible [--selftest]
 *   z23-lint check-app-bundle-reproducible --bin <path> [--app-name <n>]
 *            [--probe-args <a>] [--probe-expect <s>]
 *
 * --bin swaps the jsonq subject for a prebuilt binary; with no
 * --probe-expect the probe demands non-empty stdout, otherwise the string
 * must occur in stdout. Host: Darwin with codesign; anywhere else the gate
 * prints SKIP and exits 0. Exit: 0 clean or skip, 1 violation, 2 malformed
 * run. SIGINT, SIGTERM and SIGHUP stop the running child group, remove the
 * scratch directory and are re-raised. Manifests, compare and file helpers:
 * _manifest.c; the proof and probe: _proof.c; selftests: _selftest.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#include "gate_app_bundle_reproducible_priv.h"
#include "lintc.h"
#include "lintc_sig.h"

int abr_fatal(const char *fmt, ...)
{
    va_list ap;
    fflush(stdout);
    fprintf(stderr, "%s: FATAL — ", ABR_GATE);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    return ABR_FATAL;
}

void abr_note(FILE *err, const char *fmt, ...)
{
    va_list ap;
    if (!err)
        return;
    fprintf(err, "%s: ", ABR_GATE);
    va_start(ap, fmt);
    vfprintf(err, fmt, ap);
    va_end(ap);
    fputc('\n', err);
}

int abr_pathf(char *out, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out, ABR_PATH, fmt, ap);
    va_end(ap);
    return n < 0 || n >= ABR_PATH ? abr_fatal("path too long") : ABR_OK;
}

/* Runs one child to completion. Returns ABR_OK with *code set, ABR_SIG when
 * a termination signal stopped it, ABR_FATAL when it cannot start or its
 * captured output is incomplete. in is a file to feed on stdin or NULL. */
int abr_exec(char *const argv[], enum lcp_mode mode, const char *in,
             struct lcp_buf *out, int *code)
{
    struct lcp_spec s = { .argv = argv, .mode = mode, .grace_ms = ABR_GRACE_MS,
                         .stdin_path = in };
    int rc;
    fflush(stdout);
    fflush(stderr);
    *code = 127;
    rc = lcp_run(&s, out, code);
    if (rc == 1)
        return ABR_SIG;
    if (rc != 0)
        return abr_fatal("cannot start %s", argv[0]);
    if (out && out->lost)
        return abr_fatal("output of %s could not be captured whole", argv[0]);
    return ABR_OK;
}

int abr_copy_tree(const char *from, const char *to)
{
    char *const argv[] = { (char *)"cp", (char *)"-R", (char *)from, (char *)to, NULL };
    int code, rc = abr_exec(argv, LCP_PASS, NULL, NULL, &code);
    if (rc == ABR_OK && code != 0)
        return abr_fatal("cp -R %s failed (exit %d)", from, code);
    return rc;
}

static int abr_on_path(const char *name)
{
    const char *p = getenv("PATH");
    char cand[ABR_PATH];
    while (p && *p) {
        size_t n = strcspn(p, ":");
        if (n > 0 && n < sizeof cand - strlen(name) - 2) {
            memcpy(cand, p, n);
            snprintf(cand + n, sizeof cand - n, "/%s", name);
            if (access(cand, X_OK) == 0)
                return 1;
        }
        p += n + (p[n] == ':');
    }
    return 0;
}

static int abr_host_ok(void)
{
    struct utsname u;
    return uname(&u) == 0 && strcmp(u.sysname, "Darwin") == 0
        && abr_on_path("codesign");
}

/* The tools the proof shells out to; a missing one is a malformed run. */
int abr_guard_tools(void)
{
    static const char *const need[] = { "plutil", "diff", "cp" };
    for (size_t i = 0; i < sizeof need / sizeof need[0]; i++) {
        if (!abr_on_path(need[i]))
            return abr_fatal("required tool '%s' not found on PATH", need[i]);
    }
    return ABR_OK;
}

/* Fills c from argv[0..argc); *selftest is set by --selftest. */
static int abr_parse(struct abr_ctx *c, int argc, char **argv, int *selftest)
{
    static const char *const names[] = { "--bin", "--app-name", "--probe-args", "--probe-expect" };
    const char *what[] = { "--bin needs a path", "--app-name needs a value",
                           "--probe-args needs a value", "--probe-expect needs a value" };
    for (int i = 0; i < argc; i++) {
        size_t k = 0;
        if (strcmp(argv[i], "--selftest") == 0) {
            *selftest = 1;
            continue;
        }
        while (k < 4 && strcmp(argv[i], names[k]) != 0)
            k++;
        if (k == 4)
            return abr_fatal("unknown argument '%s' (expected --selftest, --bin, --app-name, "
                             "--probe-args, --probe-expect, or nothing)", argv[i]);
        if (i + 1 >= argc || argv[i + 1][0] == '\0')
            return abr_fatal("%s", what[k]);
        const char **slot[] = { &c->bin, NULL, &c->probe_args, &c->probe_expect };
        if (slot[k])
            *slot[k] = argv[i + 1];
        else if (snprintf(c->app, sizeof c->app, "%s", argv[i + 1]) >= (int)sizeof c->app)
            return abr_fatal("app name too long");
        i++;
    }
    return ABR_OK;
}

static int abr_name_ok(const char *s)
{
    if (!*s || *s == '.')
        return 0;
    for (; *s; s++) {
        if (!((*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z')
              || (*s >= '0' && *s <= '9') || *s == '.' || *s == '_' || *s == '-'))
            return 0;
    }
    return 1;
}

static int abr_check_bin(struct abr_ctx *c)
{
    struct stat st;
    if (stat(c->bin, &st) != 0 || !S_ISREG(st.st_mode))
        return abr_fatal("subject binary not found: %s", c->bin);
    if (access(c->bin, X_OK) != 0)
        return abr_fatal("subject binary is not executable: %s", c->bin);
    if (strcmp(c->app, "jsonq") == 0) {
        const char *slash = strrchr(c->bin, '/');
        if (snprintf(c->app, sizeof c->app, "%s", slash ? slash + 1 : c->bin)
            >= (int)sizeof c->app)
            return abr_fatal("app name too long");
    }
    if (!abr_name_ok(c->app))
        return abr_fatal("app name must match [A-Za-z0-9][A-Za-z0-9._-]* — got '%s'", c->app);
    return ABR_OK;
}

static int abr_check_subject(struct abr_ctx *c, int selftest)
{
    struct stat st;
    if (c->bin) {
        if (selftest)
            return abr_fatal("--selftest proves this gate's own assertions and always runs on "
                             "the default jsonq subject; drop --bin");
        return abr_check_bin(c);
    }
    if (!abr_on_path("cc"))
        return abr_fatal("required tool 'cc' not found on PATH");
    if (stat("tools/jsonq.c", &st) != 0)
        return abr_fatal("subject source tools/jsonq.c not found — the subject moved, "
                         "update this gate");
    return ABR_OK;
}

static int abr_enter_root(void)
{
    char root[ABR_PATH];
    struct stat st;
    if (cic_repo_root(root, sizeof root) || chdir(root) != 0)
        return abr_fatal("cannot enter the repository root");
    if (stat(ABR_BUNDLER, &st) != 0 || !S_ISREG(st.st_mode))
        return abr_fatal("bundler not found at %s", ABR_BUNDLER);
    return ABR_OK;
}

static void abr_pass(const struct abr_ctx *c)
{
    if (c->bin) {
        printf("%s: PASS — two independent bundle runs over %s are byte-identical "
               "(%d files, signature included, manifest sha256 %s) "
               "and the bundled %s launches (exit 0, ", ABR_GATE, c->bin, c->lines, c->sha, c->app);
        if (c->probe_expect)
            printf("output contained '%s', ", c->probe_expect);
        puts("output non-empty)");
        return;
    }
    printf("%s: PASS — two independent bundle runs are byte-identical "
           "(%d files, signature included, manifest sha256 %s) "
           "and the bundled %s launches (printed '%s', exit 0)\n",
           ABR_GATE, c->lines, c->sha, c->app, c->probe_expect ? c->probe_expect : ABR_PROBE_EXPECT);
}

static int abr_work(struct abr_ctx *c, int selftest)
{
    int rc;
    char tmpl[ABR_PATH];
    const char *tmpdir = env_or("TMPDIR", ABR_TMP_DEFAULT);
    if (csr_mkdirs(tmpdir) != 0 || abr_pathf(tmpl, "%s/zcl-app-bundle-repro.XXXXXX", tmpdir))
        return abr_fatal("could not create a temp dir");
    if (lsc_install() != 0)
        return abr_fatal("could not install the signal handlers");
    if (!mkdtemp(tmpl))
        return abr_fatal("could not create a temp dir");
    memcpy(c->tmp, tmpl, sizeof c->tmp);
    rc = selftest ? abr_selftest_darwin(c) : abr_prove(c);
    if (rc == ABR_OK && !selftest)
        abr_pass(c);
    return rc;
}

/* Cleans the scratch directory with the signals still blocked, then lets a
 * recorded termination signal take its default action. */
static int abr_finish(struct abr_ctx *c, int rc)
{
    int sig;
    if (c->tmp[0] && rap_rm_rf(c->tmp) != 0 && rc == ABR_OK)
        rc = ABR_FATAL;
    fflush(stdout);
    lsc_unblock();
    sig = lsc_pending();
    if (sig)
        lsc_finish(sig);
    return rc == ABR_SIG ? ABR_FAIL : rc;
}

static int abr_main(int argc, char **argv)
{
    struct abr_ctx c = { .app = "jsonq" };
    int selftest = 0, rc;
    setenv("LC_ALL", "C", 1);
    if (!abr_host_ok()) {
        puts(ABR_GATE ": SKIP — .app bundles are a macOS artifact (need Darwin + codesign)");
        return 0;
    }
    if ((rc = abr_guard_tools()) || (rc = abr_enter_root())
        || (rc = abr_parse(&c, argc, argv, &selftest))
        || (rc = abr_check_subject(&c, selftest)))
        return rc;
    return abr_finish(&c, abr_work(&c, selftest));
}

int check_app_bundle_reproducible_run(int argc, char **argv)
{
    return abr_main(argc - 2, argv + 2);
}

int check_app_bundle_reproducible_selftest(void)
{
    char *args[] = { (char *)"--selftest" };
    if (abr_unit_checks() != 0)
        return 1;
    return abr_main(1, args);
}
