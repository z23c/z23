/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: selftest of check-tor-provenance. Builds a throwaway repository
 * root whose compiler, helper binary and identity tool are shell fixtures,
 * and proves: the helper receives the compiler statuses and logs, the
 * manifest check receives the vendor/tor commit and the derived compiler
 * identity, a failing helper stops the gate with status 1, and SIGINT (once
 * and twice), SIGTERM and SIGHUP delivered after a readiness handshake over
 * a pipe stop the compiler child, including one that ignores the signal,
 * remove the scratch directory and re-raise the signal. Also exercises the
 * actual Tor producer with a tiny isolated source/configure/Make fixture,
 * genuine provenance helper, compiler and archive tools.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "gate_tor_provenance_priv.h"
#include "lintc.h"

enum { TPS_BUF = 8192 };

struct tps_fx {
    char base[TP_PATH];
    char root[TP_PATH + 16];
    char calls[TP_PATH + 32];
};

static int tps_fail(const char *what)
{
    fprintf(stderr, "check_tor_provenance selftest: FAIL - %s\n", what);
    return 1;
}

static int tps_put(const char *path, const char *text, mode_t mode)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return -1;
    fputs(text, f);
    if (fclose(f) != 0)
        return -1;
    return chmod(path, mode);
}

static int tps_path(char *out, size_t cap, const char *a, const char *b)
{
    return snprintf(out, cap, "%s/%s", a, b) >= (int)cap ? -1 : 0;
}

static const char k_tps_cc[] =
    "#!/bin/sh\n"
    "case \"$TPS_MODE\" in\n"
    "hold) echo \"$$\" >&\"$TPS_READY_FD\"; exec sleep 30;;\n"
    "stubborn) trap '' INT TERM HUP; echo \"$$\" >&\"$TPS_READY_FD\"\n"
    "  while :; do sleep 1; done;;\n"
    "esac\n"
    "case \" $* \" in *base/include*) exit 0;; esac\n"
    "echo 'error: base include is missing' >&2\n"
    "exit 1\n";

static const char k_tps_tool[] =
    "#!/bin/sh\n"
    "echo \"$*\" >> \"$TPS_CALLS\"\n"
    "if [ \"$1\" = check-compiler-results ]; then cat \"$4\" \"$5\" >> \"$TPS_CALLS\"\n"
    "  [ \"$TPS_FAIL\" = 1 ] && exit 1; fi\n"
    "exit 0\n";

static const char k_tps_id[] = "#!/bin/sh\necho \"ID:$2\"\n";

static int tps_git(const char *vendor)
{
    char cmd[TP_PATH * 3], q[TP_PATH * 2], out[TPS_BUF];
    int code = 0;
    if (sh_single_quote(vendor, q, sizeof q)
        || snprintf(cmd, sizeof cmd,
                    "cd %s && GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null "
                    "git init -q . && GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t "
                    "GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t "
                    "git -c commit.gpgsign=false commit -q --allow-empty -m x 2>&1",
                    q) >= (int)sizeof cmd)
        return -1;
    return capture_cmd(cmd, out, sizeof out, &code) == 0 && code == 0 ? 0 : -1;
}

/* Absolute scratch parent: an absolute TMPDIR, else <root>/test-tmp. */
static int tps_scratch_parent(char *out, size_t cap)
{
    const char *tmp = getenv("TMPDIR");
    char root[TP_PATH], probe[TP_PATH + 32];
    if (tmp && tmp[0] == '/')
        return snprintf(out, cap, "%s", tmp) >= (int)cap ? -1 : 0;
    if (cic_repo_root(root, sizeof root)
        || snprintf(probe, sizeof probe, "%s/test-tmp/x", root) >= (int)sizeof probe
        || csr_mkdirs(probe) != 0)
        return -1;
    return snprintf(out, cap, "%s/test-tmp", root) >= (int)cap ? -1 : 0;
}

static int tps_build(struct tps_fx *fx)
{
    char p[TP_PATH * 2], d[TP_PATH * 2], parent[TP_PATH];
    if (tps_scratch_parent(parent, sizeof parent) != 0
        || snprintf(fx->base, sizeof fx->base, "%s/tor-gate-selftest.XXXXXX", parent)
               >= (int)sizeof fx->base
        || !mkdtemp(fx->base))
        return -1;
    snprintf(fx->root, sizeof fx->root, "%s/root", fx->base);
    snprintf(fx->calls, sizeof fx->calls, "%s/calls.txt", fx->base);
    static const char *const dirs[] = { "root", "root/tools", "root/tools/dev", "root/build",
                                        "root/build/bin", "root/vendor", "root/vendor/tor" };
    for (size_t i = 0; i < sizeof dirs / sizeof dirs[0]; i++) {
        if (tps_path(d, sizeof d, fx->base, dirs[i]) || mkdir(d, 0700) != 0)
            return -1;
    }
    if (tps_path(p, sizeof p, fx->base, "cc.sh") || tps_put(p, k_tps_cc, 0700))
        return -1;
    if (tps_path(p, sizeof p, fx->root, "build/bin/z23-tor-provenance")
        || tps_put(p, k_tps_tool, 0700))
        return -1;
    if (tps_path(p, sizeof p, fx->root, "tools/dev/build-epoch-key.sh")
        || tps_put(p, k_tps_id, 0700))
        return -1;
    tps_path(p, sizeof p, fx->root, "vendor/tor");
    return tps_git(p);
}

static void tps_env(const struct tps_fx *fx, const char *mode, int ready_fd)
{
    char cc[TP_PATH + 16], fd[16];
    snprintf(cc, sizeof cc, "%s/cc.sh", fx->base);
    snprintf(fd, sizeof fd, "%d", ready_fd);
    setenv("CC", cc, 1);
    setenv("VENDOR_CC", cc, 1);
    setenv("TMPDIR", fx->base, 1);
    setenv("TPS_CALLS", fx->calls, 1);
    setenv("TPS_MODE", mode, 1);
    setenv("TPS_READY_FD", fd, 1);
}

static int tps_slurp(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "r");
    size_t n = f ? fread(buf, 1, cap - 1, f) : 0;
    if (f)
        fclose(f);
    buf[n] = '\0';
    return f ? 0 : -1;
}

static int tps_scratch_left(const char *base)
{
    DIR *d = opendir(base);
    struct dirent *e;
    int left = 0;
    while (d && (e = readdir(d)) != NULL)
        left += strncmp(e->d_name, "tor-compiler.", 13) == 0;
    if (d)
        closedir(d);
    return left;
}

static pid_t tps_fork_gate(const struct tps_fx *fx, const char *mode, int *rfd, int grace)
{
    int fds[2];
    if (pipe(fds) != 0)
        return -1;
    pid_t pid = fork();
    if (pid == 0) {
        close(fds[0]);
        tps_env(fx, mode, fds[1]);
        _exit(tp_gate(fx->root, grace));
    }
    close(fds[1]);
    *rfd = fds[0];
    return pid;
}

static int tps_normal(const struct tps_fx *fx, int fail)
{
    char buf[TPS_BUF];
    int rfd, st = 0;
    unlink(fx->calls);
    setenv("TPS_FAIL", fail ? "1" : "0", 1);
    pid_t pid = tps_fork_gate(fx, "ok", &rfd, TP_GRACE_MS);
    if (pid < 0 || waitpid(pid, &st, 0) != pid)
        return tps_fail("the gate child did not finish");
    close(rfd);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != (fail ? 1 : 0))
        return tps_fail("the gate exit status does not follow the helper");
    if (tps_slurp(fx->calls, buf, sizeof buf))
        return tps_fail("the helper was never called");
    if (!strstr(buf, "check-compiler-results 0 1 ") || !strstr(buf, "error: base include is missing"))
        return tps_fail("the helper did not get both compiler statuses and the negative log");
    if (fail)
        return strstr(buf, "--selftest") ? tps_fail("a failing helper did not stop the gate") : 0;
    if (!strstr(buf, "--selftest") || !strstr(buf, "--tor-commit ") || !strstr(buf, "--compiler-id ID:"))
        return tps_fail("the manifest check did not get the commit and compiler identity");
    return 0;
}

static int tps_read_pid(int rfd, pid_t *child)
{
    char line[64];
    size_t used = 0;
    while (used + 1 < sizeof line) {
        ssize_t n = read(rfd, line + used, 1);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0 || line[used] == '\n')
            break;
        used++;
    }
    line[used] = '\0';
    *child = (pid_t)atoi(line);
    return *child > 0 ? 0 : -1;
}

static int tps_signal(const struct tps_fx *fx, const char *mode, int sig, int times)
{
    int rfd, st = 0;
    pid_t gate = tps_fork_gate(fx, mode, &rfd, 300), cc = 0;
    if (gate < 0)
        return tps_fail("fork failed");
    int ready = tps_read_pid(rfd, &cc);
    close(rfd);
    for (int i = 0; ready == 0 && i < times; i++)
        kill(gate, sig);
    if (waitpid(gate, &st, 0) != gate || ready != 0)
        return tps_fail("the gate never reached the compiler");
    if (!WIFSIGNALED(st) || WTERMSIG(st) != sig)
        return tps_fail("the gate did not re-raise the signal");
    if (tps_scratch_left(fx->base))
        return tps_fail("the scratch directory outlived the signal");
    return kill(cc, 0) == 0 ? tps_fail("the compiler child outlived the gate") : 0;
}

static int tps_cc_parse(void)
{
    char out[64];
    if (!tp_cc_from_line("CC = gcc -O2", out, sizeof out) || strcmp(out, "gcc -O2") != 0)
        return tps_fail("CC = value");
    if (!tp_cc_from_line("CC\t=\t clang", out, sizeof out) || strcmp(out, "clang") != 0)
        return tps_fail("CC with tabs");
    if (!tp_cc_from_line("CC=a=b", out, sizeof out) || strcmp(out, "a") != 0)
        return tps_fail("CC stops at the second equals sign");
    if (tp_cc_from_line("CCASFLAGS = x", out, sizeof out) || tp_cc_from_line(" CC = x", out, sizeof out))
        return tps_fail("only a line that starts with CC and an equals sign matches");
    return 0;
}

static int tps_all(const struct tps_fx *fx)
{
    return tps_normal(fx, 0) || tps_normal(fx, 1)
        || tps_signal(fx, "hold", SIGINT, 1) || tps_signal(fx, "hold", SIGINT, 2)
        || tps_signal(fx, "hold", SIGTERM, 1) || tps_signal(fx, "hold", SIGHUP, 1)
        || tps_signal(fx, "stubborn", SIGTERM, 1);
}

static char tpp_root[4096], tpp_source[4096];
static int tpp_serial;

static void tpp_die(const char *message)
{
    fprintf(stderr, "producer-acceptance: %s: %s\n", message, strerror(errno));
    _exit(1);
}

static void tpp_require(bool ok, const char *message)
{
    if (!ok) { fprintf(stderr, "FAIL: %s\n", message); _exit(1); }
}

static void tpp_path(char out[8192], const char *base, const char *leaf)
{
    int n = snprintf(out, 8192, "%s/%s", base, leaf);
    tpp_require(n > 0 && n < 8192, "path length");
}

static void tpp_dirs(const char *leaf)
{
    char p[8192]; tpp_path(p, tpp_root, leaf);
    for (char *c = p + 1; *c; c++) {
        if (*c != '/') continue;
        *c = 0; if (mkdir(p, 0700) && errno != EEXIST) tpp_die("mkdir parent"); *c = '/';
    }
    if (mkdir(p, 0700) && errno != EEXIST) tpp_die("mkdir");
}

static void tpp_write_file(const char *leaf, mode_t mode, const char *text)
{
    char p[8192]; tpp_path(p, tpp_root, leaf);
    FILE *f = fopen(p, "wb"); if (!f) tpp_die("create fixture file");
    bool ok = fwrite(text, 1, strlen(text), f) == strlen(text);
    if (fclose(f)) ok = false;
    if (!ok || chmod(p, mode)) tpp_die("write fixture file");
}

static void tpp_copy_file(const char *from, const char *leaf, mode_t mode)
{
    char p[8192]; tpp_path(p, tpp_root, leaf);
    FILE *in = fopen(from, "rb"), *out = fopen(p, "wb");
    if (!in || !out) tpp_die("open copy");
    char buf[8192]; size_t n; bool ok = true;
    while ((n = fread(buf, 1, sizeof(buf), in))) {
        if (fwrite(buf, 1, n, out) != n) { ok = false; break; }
    }
    if (ferror(in)) ok = false;
    if (fclose(in)) ok = false;
    if (fclose(out)) ok = false;
    if (!ok || chmod(p, mode)) tpp_die("copy");
}

/* Every command is argv, inherits only caller environment (then scoped child
 * fixture overrides), and retains its complete stdout/stderr in a numbered log.
 * There is no system/popen, shell command construction, or fake compiler. */
static void tpp_child_environment(const char *cflags)
{
    const char *clear[] = {"CFLAGS", "CPPFLAGS", "CXXFLAGS", "LDFLAGS", "LIBS",
        "MAKEFLAGS", "MFLAGS", "MAKEOVERRIDES", "VENDOR_TARGET", "VENDOR_CC",
        "VENDOR_AR", "VENDOR_RANLIB", "CC", "AR", "RANLIB", "GIT_DIR",
        "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", NULL};
    for (int i = 0; clear[i]; i++) if (unsetenv(clear[i])) _exit(125);
    if (cflags && setenv("CFLAGS", cflags, 1)) _exit(125);
#if defined(__APPLE__)
    if (setenv("MACOSX_DEPLOYMENT_TARGET", "14.0", 1)) _exit(125);
#endif
    if (setenv("ZCL_TOR_JOBS", "1", 1) || setenv("LC_ALL", "C", 1) ||
        setenv("GIT_CONFIG_NOSYSTEM", "1", 1) ||
        setenv("GIT_CONFIG_GLOBAL", "/dev/null", 1)) _exit(125);
}

static void tpp_child_exec(const char *cwd, const char *cflags,
                           char *const argv[], const char *log)
{
    int fd = open(log, O_WRONLY|O_CREAT|O_EXCL, 0600);
    if (fd < 0 || dup2(fd, 1) < 0 || dup2(fd, 2) < 0 || chdir(cwd)) _exit(125);
    close(fd);
    tpp_child_environment(cflags);
    execvp(argv[0], argv); _exit(127);
}

static int tpp_run(const char *cwd, const char *cflags, char *const argv[])
{
    char leaf[80], log[8192];
    snprintf(leaf, sizeof(leaf), "logs/%03d.log", ++tpp_serial); tpp_path(log, tpp_root, leaf);
    printf("COMMAND %03d cwd=%s argv=", tpp_serial, cwd);
    for (int i = 0; argv[i]; i++) printf(" [%s]", argv[i]);
    printf(" CFLAGS=%s\n", cflags ? cflags : "<UNSET>"); fflush(stdout);
    pid_t pid = fork(); if (pid < 0) tpp_die("fork");
    if (!pid) tpp_child_exec(cwd, cflags, argv, log);
    int status; pid_t got;
    do { got = waitpid(pid, &status, 0); } while (got < 0 && errno == EINTR);
    if (got != pid) tpp_die("waitpid");
    int rc = WIFEXITED(status) ? WEXITSTATUS(status) :
        WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 125;
    printf("RESULT %03d exit=%d log=%s\n", tpp_serial, rc, log); fflush(stdout);
    return rc;
}

#define tpp_RUN(cwd, flags, ...) tpp_run(cwd, flags, (char *const[]){__VA_ARGS__, NULL})

static bool tpp_contains(const char *leaf, const char *needle)
{
    char p[8192]; tpp_path(p, tpp_root, leaf); FILE *f = fopen(p, "rb");
    if (!f) return false;
    size_t len = strlen(needle), matched = 0; int c; bool found = false;
    while ((c = fgetc(f)) != EOF) {
        if ((unsigned char)c == (unsigned char)needle[matched]) matched++;
        else matched = (unsigned char)c == (unsigned char)needle[0] ? 1u : 0u;
        if (matched == len) { found = true; break; }
    }
    bool ok = !ferror(f); if (fclose(f)) ok = false;
    tpp_require(ok, "read fixture bytes"); return found;
}

static unsigned tpp_events(const char *event)
{
    char p[8192], line[256]; tpp_path(p, tpp_root, "vendor/tor/events");
    FILE *f = fopen(p, "r"); if (!f) return 0;
    unsigned n = 0; while (fgets(line, sizeof(line), f)) if (!strcmp(line, event)) n++;
    bool ok = !ferror(f); if (fclose(f)) ok = false;
    tpp_require(ok, "event read"); return n;
}

static void tpp_make_fixture(const char *binary)
{
    tpp_dirs("logs"); tpp_dirs("tools/scripts"); tpp_dirs("tools/dev"); tpp_dirs("build/bin");
    tpp_dirs("contexts/commons/packages/zsha256/src"); tpp_dirs("vendor/patches");
    tpp_dirs("vendor/tor/src/ext/ed25519/donna"); tpp_dirs("vendor/tor/src/ext/ed25519/ref10");
    tpp_dirs("vendor/tor/src/ext/keccak-tiny");
    const char *files[] = {"tools/scripts/build_tor_full.sh", "tools/scripts/tor_provenance_lib.sh",
        "tools/dev/build-epoch-key.sh", "tools/tor_provenance.c",
        "contexts/commons/packages/zsha256/src/zsha256.c", NULL};
    for (int i = 0; files[i]; i++) {
        char p[8192]; tpp_path(p, tpp_source, files[i]); tpp_copy_file(p, files[i], 0700);
    }
    tpp_copy_file(binary, "build/bin/z23-tor-provenance", 0700);
    /* ensure_bin calls actual make; this fixture target retains an already
     * qualified binary, never substitutes another provenance implementation. */
    tpp_write_file("Makefile", 0600,
        "build/bin/z23-tor-provenance:\n\t@test -x $@\n");
    tpp_write_file("vendor/tor/tiny.c", 0600,
        "const char *fixture_path(void) { return __FILE__; }\n"
        "int dynhost_stream_init(void) { return 1; }\n"
        "int fixture_patch(void) { return 0; }\n");
    /* Patch application/reversal is exercised on a separate fixture marker.
     * This isolates warm flag-cache behavior from patch-touched TU mtimes;
     * it does NOT test the production dynhost patch's semantic behavior. */
    tpp_write_file("vendor/tor/patch-marker", 0600, "before\n");
    tpp_write_file("vendor/patches/tor-dynhost-stream-shutdown.patch", 0600,
        "--- a/patch-marker\n+++ b/patch-marker\n@@ -1 +1 @@\n-before\n+after\n");
    const char *inputs[] = {"configure.ac", "Makefile.am", "autogen.sh", "Makefile.in",
        "orconfig.h.in", "ar-lib", "config.guess", "config.sub", "compile", "missing", "install-sh", NULL};
    for (int i = 0; inputs[i]; i++) {
        char leaf[512]; snprintf(leaf, sizeof(leaf), "vendor/tor/%s", inputs[i]);
        tpp_write_file(leaf, 0600, "# controlled tiny autotools seam\n");
    }
    tpp_write_file("vendor/tor/configure", 0700,
        "#!/bin/sh\nset -eu\nprintf 'configure\\n' >> events\n"
        "flags='-g -O2'\ncc=cc\n"
        "printf '%s\\n' '#!/bin/sh' 'cd -- \"$(dirname \"$0\")\"' 'cat config.args' > config.status\n"
        ": > config.args\n"
        "for arg do\n case $arg in CFLAGS=*) flags=${arg#CFLAGS=} ;; CC=*) cc=${arg#CC=} ;; esac\n"
        " printf \" '%s'\" \"$arg\" >> config.args\ndone\n"
        "printf '\\n' >> config.args\nchmod +x config.status\n"
        "printf '#undef HAVE_BACKTRACE\\n' > orconfig.h\n"
        "printf 'CC = %s\\nCFLAGS = %s\\n' \"$cc\" \"$flags\" > Makefile\n"
        "cat fixture-rules.mk >> Makefile\n");
    tpp_write_file("vendor/tor/fixture-rules.mk", 0600,
        "ARCHIVES = libtor.a src/ext/ed25519/donna/libed25519_donna.a src/ext/ed25519/ref10/libed25519_ref10.a src/ext/keccak-tiny/libkeccak-tiny.a\n"
        ".PHONY: clean\nlibtor.a: tiny.o\n"
        "\t@for a in $(ARCHIVES); do ar rcs $$a tiny.o || exit; done\n"
        "tiny.o: tiny.c\n\t@printf 'compile\\n' >> events\n"
        "\t@test ! -f fail-build\n"
        "\t@if test -f interrupt-build; then kill -TERM $$$$; fi\n"
        "\t$(CC) $(CPPFLAGS) $(CFLAGS) -std=c23 -c $(CURDIR)/tiny.c -o $@\n"
        "clean:\n\t@printf 'clean\\n' >> events\n\trm -f tiny.o $(ARCHIVES)\n");
#if defined(__APPLE__) || defined(__linux__)
    /* Presence-only configure seams, not actual dependency qualification. */
    tpp_dirs("vendor/lib"); tpp_dirs("vendor/include/openssl");
    tpp_dirs("vendor/include/event2");
    tpp_write_file("vendor/include/openssl/ssl.h", 0600, "/* fixture */\n");
    tpp_write_file("vendor/include/event2/event.h", 0600, "/* fixture */\n");
    tpp_write_file("vendor/include/zlib.h", 0600, "/* fixture */\n");
    const char *libraries[] = {"vendor/lib/libcrypto.a", "vendor/lib/libssl.a",
        "vendor/lib/libevent.a", "vendor/lib/libz.a", NULL};
    /* An empty archive is just its header; Apple ar requires a member. */
    for (int i = 0; libraries[i]; i++)
        tpp_write_file(libraries[i], 0600, "!<arch>\n");
#endif
    char tor[8192]; tpp_path(tor, tpp_root, "vendor/tor");
    tpp_require(tpp_RUN(tor, NULL, "git", "init", "-q") == 0, "Tor fixture git init");
    tpp_require(tpp_RUN(tor, NULL, "git", "add", ".") == 0, "Tor fixture git add");
    tpp_require(tpp_RUN(tor, NULL, "git", "-c", "user.name=Public Fixture", "-c",
        "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "tiny fixture") == 0,
        "Tor fixture commit");
    tpp_require(tpp_RUN(tpp_root, NULL, "git", "init", "-q") == 0, "parent fixture git init");
    tpp_require(tpp_RUN(tpp_root, NULL, "git", "add", "vendor/tor") == 0, "parent fixture gitlink pin");
}

static void tpp_check_ready(bool expected)
{
    char bin[8192], tor[8192]; tpp_path(bin, tpp_root, "build/bin/z23-tor-provenance");
    tpp_path(tor, tpp_root, "vendor/tor"); int rc = tpp_RUN(tpp_root, NULL, bin, "check", tor);
    tpp_require(rc == (expected ? 0 : 1), "actual native provenance readiness exact status");
}

static void tpp_produce(const char *flags, bool success)
{
    int rc = tpp_RUN(tpp_root, flags, "bash", "tools/scripts/build_tor_full.sh");
    tpp_require(rc == (success ? 0 : 2), "actual producer exit exact status");
    tpp_check_ready(success);
}

static void tpp_transition(const char *before, const char *after, const char *name)
{
    tpp_produce(before, true);
    unsigned c = tpp_events("configure\n"), clean = tpp_events("clean\n"), compile = tpp_events("compile\n");
    tpp_produce(after, true);
    unsigned changed = 1;
#if defined(__APPLE__)
    /* Darwin records floor-only CFLAGS for both unset and explicit empty. */
    changed = !((!before || !*before) && (!after || !*after));
#endif
    tpp_require(tpp_events("configure\n") == c + changed &&
        tpp_events("clean\n") == clean + changed &&
        tpp_events("compile\n") == compile + changed, "transition event counts");
    char line[512];
#if defined(__APPLE__)
    snprintf(line, sizeof(line), "CFLAGS = %s -mmacosx-version-min=14.0\n",
        after ? after : "");
#else
    snprintf(line, sizeof(line), "CFLAGS = %s\n", after ? after : "-g -O2");
#endif
    tpp_require(tpp_contains("vendor/tor/Makefile", line), "configure-selected CFLAGS preserved");
    printf("PASS %s\n", name);
}

static void tpp_controls(void)
{
    char tor[8192], bin[8192]; tpp_path(tor, tpp_root, "vendor/tor");
    tpp_path(bin, tpp_root, "build/bin/z23-tor-provenance");
    /* Seed actual unmapped object/archive with same build graph; production
     * must clean it rather than relabel existing archive bytes as mapped. */
    tpp_require(tpp_RUN(tor, NULL, "./configure") == 0, "seed configure");
    tpp_require(tpp_RUN(tor, NULL, "make", "-j1", "libtor.a") == 0, "seed unmapped objects");
    tpp_require(tpp_contains("vendor/tor/tiny.o", tpp_root), "seed object contains actual fixture root");
    tpp_check_ready(false);
    unsigned clean = tpp_events("clean\n"), compile = tpp_events("compile\n");
    tpp_produce(NULL, true);
    tpp_require(tpp_events("clean\n") == clean + 1 && tpp_events("compile\n") == compile + 1,
        "normal producer replaces unmapped seed via clean+compiler");
    tpp_require(!tpp_contains("vendor/tor/tiny.o", tpp_root) && tpp_contains("vendor/tor/tiny.o", "/zclassic23/vendor/tor/tiny.c"),
        "actual replacement object mapped, __FILE__ retained");
    tpp_require(tpp_RUN(tor, NULL, "ar", "x", "libtor.a", "tiny.o") == 0, "extract actual archive member");
    tpp_require(!tpp_contains("vendor/tor/tiny.o", tpp_root) && tpp_contains("vendor/tor/tiny.o", "/zclassic23/vendor/tor/tiny.c"),
        "actual archive member replaced");
    puts("PASS unmapped-seed-replaced");
    tpp_transition("", NULL, "empty-to-unset");
    tpp_transition("-g -O0 -DFIXTURE_CUSTOM=7", NULL, "custom-to-unset");
    tpp_transition(NULL, "", "unset-to-empty");
    unsigned c = tpp_events("configure\n"); clean = tpp_events("clean\n"); compile = tpp_events("compile\n");
    tpp_produce("", true);
    tpp_require(tpp_events("configure\n") == c && tpp_events("clean\n") == clean && tpp_events("compile\n") == compile,
        "unchanged warm producer preserves object and configure cache");
    puts("PASS warm-unchanged");
    char mf[8192]; tpp_path(mf, tpp_root, "vendor/tor/Makefile");
    FILE *f = fopen(mf, "ab"); tpp_require(f != NULL, "append later override");
    bool ok = fputs("\noverride CFLAGS = -O0\n", f) >= 0;
    if (fclose(f)) ok = false;
    tpp_require(ok, "write override");
    tpp_require(tpp_RUN(tpp_root, NULL, bin, "check-build-path", tor, tpp_root) == 1, "later override refused by native policy check");
    puts("PASS later-override-refused");
    tpp_write_file("vendor/tor/fail-build", 0600, "fail\n");
    clean = tpp_events("clean\n"); compile = tpp_events("compile\n");
    tpp_produce("-g -O1", false);
    char diagnostic[80]; snprintf(diagnostic, sizeof(diagnostic), "logs/%03d.log", tpp_serial - 1);
    tpp_require(tpp_contains(diagnostic, "tiny.o] Error 1") && tpp_events("clean\n") == clean + 1 &&
        tpp_events("compile\n") == compile + 1, "observed make failure in the selected actual recipe");
    char p[8192]; tpp_path(p, tpp_root, "vendor/tor/fail-build"); tpp_require(!unlink(p), "remove fail control");
    tpp_produce(NULL, true);
    puts("PASS failure-unready-and-recovery");
    tpp_write_file("vendor/tor/interrupt-build", 0600, "interrupt\n");
    clean = tpp_events("clean\n"); compile = tpp_events("compile\n");
    tpp_produce("-g -O1", false);
    snprintf(diagnostic, sizeof(diagnostic), "logs/%03d.log", tpp_serial - 1);
    tpp_require(tpp_contains(diagnostic, "tiny.o] Terminated") && tpp_events("clean\n") == clean + 1 &&
        tpp_events("compile\n") == compile + 1, "observed SIGTERM in the selected actual recipe");
    tpp_path(p, tpp_root, "vendor/tor/interrupt-build"); tpp_require(!unlink(p), "remove interrupt control");
    tpp_produce(NULL, true);
    puts("PASS interrupted-recipe-unready-and-recovery");
}


/* Assertions/body above are called only in this private child. */
static int tpp_body(const char *actual_root, const char *fixture)
{
    tpp_require(strlen(actual_root) < sizeof(tpp_source) &&
        strlen(fixture) < sizeof(tpp_root), "producer fixture path length");
    strcpy(tpp_source, actual_root);
    tpp_require(chdir(fixture) == 0, "enter private producer fixture");
    tpp_require(getcwd(tpp_root, sizeof(tpp_root)) != NULL, "resolve physical producer fixture path");
    char binary[8192]; tpp_path(binary, actual_root, "build/bin/z23-tor-provenance");
    tpp_make_fixture(binary);
    tpp_require(tpp_RUN(tpp_root, NULL, "sha256sum", binary,
        "build/bin/z23-tor-provenance", "tools/scripts/build_tor_full.sh",
        "tools/scripts/tor_provenance_lib.sh", "tools/dev/build-epoch-key.sh") == 0,
        "actual producer and helper identities");
    tpp_controls();
    return 0;
}

static int tpp_producer(void)
{
    char parent[TP_PATH], actual[TP_PATH], fixture[TP_PATH];
    if (cic_repo_root(actual, sizeof actual) ||
        tps_scratch_parent(parent, sizeof parent) ||
        snprintf(fixture, sizeof fixture, "%s/tor-producer-selftest.XXXXXX", parent)
            >= (int)sizeof fixture || !mkdtemp(fixture))
        return tps_fail("cannot allocate actual producer fixture");
    fflush(NULL);
    pid_t child = fork();
    if (child == 0) {
        int rc = tpp_body(actual, fixture);
        fflush(NULL);
        _exit(rc);
    }
    int status = 0; pid_t got = -1;
    if (child > 0)
        do { got = waitpid(child, &status, 0); } while (got < 0 && errno == EINTR);
    if (got != child || child < 0 || !WIFEXITED(status) || WEXITSTATUS(status)) {
        fprintf(stderr, "actual producer selftest failed; retained fixture: %s\n", fixture);
        return tps_fail("actual producer controls failed");
    }
    if (rap_rm_rf(fixture) != 0)
        return tps_fail("cannot remove successful actual producer fixture");
    return 0;
}

int check_tor_provenance_selftest(void)
{
    struct tps_fx fx = { { 0 }, { 0 }, { 0 } };
    int rc = tps_cc_parse();
    if (rc == 0 && tps_build(&fx) != 0)
        rc = tps_fail("cannot build the fixture root");
    if (rc == 0)
        rc = tps_all(&fx);
    if (fx.base[0] && access(fx.base, F_OK) == 0)
        rap_rm_rf(fx.base);
    if (rc == 0)
        rc = tpp_producer();
    if (rc == 0)
        puts("check_tor_provenance selftest: ok (cc parsing, helper hand-off, "
             "signal cleanup, actual producer controls)");
    return rc;
}
