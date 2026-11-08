/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_app_launch_skycombat - the real game through the real CLI:
 * `build/bin/z23-dev app open skycombat` against build/bin/z23-skycombat
 * (`make game`) on a private Xvfb display, with a temporary HOME.
 *
 *   open            -> opened, a pid, the raylib ready line seen
 *   open again      -> already_open, the same pid, raise delivered
 *                      (SIGUSR1 to the game's own handler), still alive
 *   kill, open      -> opened with a new pid
 *   open nosuchapp  -> UNKNOWN_APP
 *
 * First, on every Linux host, the build facts that keep the game free of
 * system -dev packages: its X11/GL header closure is vendored and the
 * binary links no X11/GL library. The display cases need Xvfb. Without it
 * the group prints a SKIP line for them; the host-need row keeps it out of
 * universal selection unless the operator sets ZCL_TEST_DISPLAY_APPS.
 *
 * make t-fast-exact ONLY=app_launch_skycombat */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_core.h"
#include "test/host_tool_capture.h"

#include "platform/time_compat.h"

#if defined(__linux__)
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#define SC_CLI "build/bin/z23-dev"
#define SC_GAME "build/bin/z23-skycombat"
#define SC_OUT 65536

static const char *sc_xvfb_path(void)
{
    static const char *const paths[] = {"/usr/bin/Xvfb", "/usr/local/bin/Xvfb",
                                        "/opt/X11/bin/Xvfb"};
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++)
        if (access(paths[i], X_OK) == 0)
            return paths[i];
    return NULL;
}

struct sc_xvfb {
    pid_t pid;
    char display[32];
};

/* Start Xvfb on a free display it picks itself (-displayfd), so parallel
 * runs never race for a number. */
static bool sc_xvfb_start(const char *xvfb, const char *log, struct sc_xvfb *x)
{
    int fds[2];
    posix_spawn_file_actions_t fa;
    char *argv[] = {(char *)xvfb, (char *)"-displayfd", (char *)"3",
                    (char *)"-nolisten", (char *)"tcp", (char *)"-screen",
                    (char *)"0", (char *)"1280x800x24", NULL};
    if (pipe(fds) != 0 || posix_spawn_file_actions_init(&fa) != 0)
        return false;
    bool ok =
        posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0) == 0 &&
        posix_spawn_file_actions_addopen(&fa, 1, log, O_WRONLY | O_CREAT |
                                         O_TRUNC, 0600) == 0 &&
        posix_spawn_file_actions_adddup2(&fa, 1, 2) == 0 &&
        posix_spawn_file_actions_adddup2(&fa, fds[1], 3) == 0 &&
        posix_spawn(&x->pid, xvfb, &fa, NULL, argv, environ) == 0;
    (void)posix_spawn_file_actions_destroy(&fa);
    close(fds[1]);
    size_t used = 0;
    while (ok && used + 1 < sizeof(x->display)) {
        struct pollfd p = {.fd = fds[0], .events = POLLIN};
        char c;
        if (poll(&p, 1, 15000) <= 0 || read(fds[0], &c, 1) != 1 || c == '\n')
            break;
        x->display[used++] = c;
    }
    close(fds[0]);
    x->display[used] = '\0';
    return ok && used > 0;
}

static void sc_xvfb_stop(struct sc_xvfb *x)
{
    int status;
    if (x->pid <= 0)
        return;
    (void)kill(x->pid, SIGTERM);
    (void)waitpid(x->pid, &status, 0);
    x->pid = 0;
}

/* Gone: no such process, or a zombie no one has reaped yet. */
static bool sc_gone(long pid)
{
    char path[64], buf[512];
    int status;
    (void)waitpid((pid_t)pid, &status, WNOHANG);
    if (kill((pid_t)pid, 0) != 0)
        return errno == ESRCH;
    snprintf(path, sizeof(path), "/proc/%ld/stat", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    ssize_t n = fd >= 0 ? read(fd, buf, sizeof(buf) - 1) : -1;
    if (fd >= 0)
        close(fd);
    buf[n > 0 ? n : 0] = '\0';
    const char *paren = strrchr(buf, ')');
    return paren && (paren[2] == 'Z' || paren[2] == 'X');
}

static bool sc_stop(long pid)
{
    if (pid <= 1)
        return true;
    (void)kill((pid_t)pid, SIGTERM);
    int64_t stop = platform_time_monotonic_ms() + 5000;
    while (!sc_gone(pid)) {
        if (platform_time_monotonic_ms() > stop) {
            (void)kill((pid_t)pid, SIGKILL);
            return false;
        }
        platform_sleep_ms(20); /* real-clock: waiting for a real game exit */
    }
    return true;
}

static int sc_open(const char *name, char *out)
{
    const char *argv[] = {SC_CLI, "app", "open", name, "--format=json", NULL};
    return test_host_tool_capture(argv, out, SC_OUT, 60000);
}

static long sc_pid(const char *out)
{
    const char *p = strstr(out, "\"pid\":");
    return p ? strtol(p + 6, NULL, 10) : 0;
}

static bool sc_log_has(const char *path, const char *needle)
{
    int64_t stop = platform_time_monotonic_ms() + 5000;
    static char buf[262144];
    for (;;) {
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        ssize_t n = fd >= 0 ? read(fd, buf, sizeof(buf) - 1) : -1;
        if (fd >= 0)
            close(fd);
        buf[n > 0 ? n : 0] = '\0';
        if (n > 0 && strstr(buf, needle))
            return true;
        if (platform_time_monotonic_ms() > stop)
            return false;
        platform_sleep_ms(50); /* real-clock: waiting on the real game's log */
    }
}

struct sc_env {
    const char *key;
    char *value;
};

static void sc_env_swap(struct sc_env *e, size_t n, bool restore)
{
    for (size_t i = 0; i < n; i++) {
        if (!restore) {
            const char *v = getenv(e[i].key);
            e[i].value = v ? strdup(v) : NULL;
            continue;
        }
        if (e[i].value)
            (void)setenv(e[i].key, e[i].value, 1);
        else
            (void)unsetenv(e[i].key);
        free(e[i].value);
        e[i].value = NULL;
    }
}

static int sc_run(const char *home, const char *log, long *pids)
{
    int failures = 0;
    static char out[SC_OUT];
    TEST("app open skycombat starts the real game on the display") {
        ASSERT_EQ(sc_open("skycombat", out), 0);
        ASSERT(strstr(out, "\"status\":\"opened\""));
        ASSERT(strstr(out, "\"ready_basis\":\"marker\""));
        pids[0] = sc_pid(out);
        ASSERT(pids[0] > 1);
        ASSERT(sc_log_has(log, "DISPLAY: Device initialized successfully"));
    PASS(); }
    TEST("app open sky again finds the same game instead of a copy") {
        ASSERT_EQ(sc_open("sky", out), 0);
        ASSERT(strstr(out, "\"status\":\"already_open\""));
        ASSERT_EQ(sc_pid(out), pids[0]);
        /* The game declares raise and handles SIGUSR1: the signal is
         * delivered, and the game is still the same live process after it. */
        ASSERT(strstr(out, "\"raise\":\"delivered\""));
        ASSERT(!sc_gone(pids[0]));
    PASS(); }
    TEST("after the game is killed, app open starts a new pid") {
        ASSERT(sc_stop(pids[0]));
        ASSERT_EQ(sc_open("airplane", out), 0);
        ASSERT(strstr(out, "\"status\":\"opened\""));
        pids[1] = sc_pid(out);
        ASSERT(pids[1] > 1);
        ASSERT(pids[1] != pids[0]);
    PASS(); }
    TEST("app list shows skycombat as a running desktop app") {
        const char *argv[] = {SC_CLI, "app", "list", "--format=json", NULL};
        ASSERT_EQ(test_host_tool_capture(argv, out, SC_OUT, 60000), 0);
        const char *sky = strstr(out, "\"id\":\"skycombat\"");
        ASSERT(sky != NULL);
        ASSERT(strstr(sky, "\"kind\":\"desktop\""));
        ASSERT(strstr(sky, "\"installed\":true"));
        ASSERT(strstr(sky, "\"raise\":\"sigusr1\""));
    PASS(); }
    TEST("app open nosuchapp is refused as unknown_app") {
        ASSERT(sc_open("nosuchapp", out) != 0);
        ASSERT(strstr(out, "UNKNOWN_APP"));
        ASSERT(strstr(out, "skycombat"));
    PASS(); }
_test_next:;
    (void)home;
    return failures;
}

/* ── No system -dev package: the closure and the link ────────────────
 * The game must build on a Linux host with no X11 or GL -dev package.
 * Two facts prove it, whether or not this host has those headers:
 *   1. every window-system header the RGFW translation unit read (the
 *      compiler's own -MD depfile for rcore.o, which includes
 *      rcore_desktop_rgfw.c) came from vendor/, and RGFW.h is raylib's;
 *   2. the linked game names no X11 or GL library in DT_NEEDED: XDL and
 *      RGFW load them at run time through dlopen. */
#define SC_RCORE_DEPS "build/raylib/rcore.d"
#define SC_DEPS_MAX (1u << 20)
#define SC_ELF_MAX (64u << 20)

struct sc_closure {
    int sdk, vendored, rgfw_raylib, rgfw_other;
    char offender[PATH_MAX];
};

/* Read a whole regular file into a fresh NUL-terminated buffer. */
static char *sc_slurp(const char *path, size_t max, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        test_note("cannot open %s: %s", path, strerror(errno));
        return NULL;
    }
    char *buf = malloc(max + 1);
    size_t n = buf ? fread(buf, 1, max + 1, f) : 0;
    bool bad = !buf || ferror(f) || n > max;
    fclose(f);
    if (bad) {
        test_note("cannot read %s within %zu bytes", path, max);
        free(buf);
        return NULL;
    }
    buf[n] = '\0';
    *len = n;
    return buf;
}

/* A header under one of the window-system SDK include directories, or the
 * XDL loader itself: each must resolve under vendor/. */
static bool sc_sdk_header(const char *tok)
{
    static const char *const dirs[] = {"X11/", "GL/", "KHR/", "EGL/"};
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        const char *p = strstr(tok, dirs[i]);
        if (p && (p == tok || p[-1] == '/'))
            return true;
    }
    const char *base = strrchr(tok, '/');
    return strcmp(base ? base + 1 : tok, "XDL.h") == 0;
}

static void sc_closure_token(struct sc_closure *c, const char *tok)
{
    bool vendored = strncmp(tok, "vendor/", 7) == 0;
    const char *base = strrchr(tok, '/');
    if (strcmp(base ? base + 1 : tok, "RGFW.h") == 0) {
        if (strncmp(tok, "vendor/raylib/src/", 18) == 0)
            c->rgfw_raylib++;
        else
            c->rgfw_other++;
    }
    if (!sc_sdk_header(tok))
        return;
    c->sdk++;
    if (vendored)
        c->vendored++;
    else if (!c->offender[0])
        snprintf(c->offender, sizeof(c->offender), "%s", tok);
}

/* Tokenize a make depfile: whitespace separated, `\` continuations, and a
 * trailing ':' on targets and on the -MP phony header rules. */
static bool sc_closure_read(const char *path, struct sc_closure *c)
{
    size_t len = 0;
    char *buf = sc_slurp(path, SC_DEPS_MAX, &len);
    if (!buf)
        return false;
    for (char *save = NULL, *tok = strtok_r(buf, " \t\r\n\\", &save); tok;
         tok = strtok_r(NULL, " \t\r\n\\", &save)) {
        size_t n = strlen(tok);
        if (n && tok[n - 1] == ':')
            tok[n - 1] = '\0';
        if (tok[0])
            sc_closure_token(c, tok);
    }
    free(buf);
    return true;
}

/* File offset of a virtual address inside a PT_LOAD segment, or 0. */
static size_t sc_elf_offset(const char *img, size_t len, uint64_t vaddr)
{
    Elf64_Ehdr eh;
    memcpy(&eh, img, sizeof(eh));
    for (size_t i = 0; i < eh.e_phnum; i++) {
        Elf64_Phdr ph;
        memcpy(&ph, img + eh.e_phoff + i * sizeof(ph), sizeof(ph));
        if (ph.p_type == PT_LOAD && vaddr >= ph.p_vaddr &&
            vaddr - ph.p_vaddr < ph.p_filesz && ph.p_offset < len)
            return (size_t)(ph.p_offset + (vaddr - ph.p_vaddr));
    }
    return 0;
}

/* The PT_DYNAMIC segment of a validated 64-bit ELF image, or false. */
static bool sc_elf_dynamic(const char *img, size_t len, Elf64_Phdr *dyn)
{
    Elf64_Ehdr eh;
    if (len < sizeof(eh) || memcmp(img, ELFMAG, SELFMAG) != 0)
        return false;
    memcpy(&eh, img, sizeof(eh));
    if (eh.e_ident[EI_CLASS] != ELFCLASS64 ||
        eh.e_phentsize != sizeof(Elf64_Phdr) || eh.e_phoff > len ||
        (len - eh.e_phoff) / sizeof(Elf64_Phdr) < eh.e_phnum)
        return false;
    for (size_t i = 0; i < eh.e_phnum; i++) {
        memcpy(dyn, img + eh.e_phoff + i * sizeof(*dyn), sizeof(*dyn));
        if (dyn->p_type == PT_DYNAMIC)
            return dyn->p_offset <= len && dyn->p_filesz <= len - dyn->p_offset;
    }
    return false;
}

/* Every DT_NEEDED name of an ELF image, space separated, into out. */
static bool sc_elf_needed(const char *img, size_t len, char *out, size_t cap)
{
    Elf64_Phdr dyn;
    Elf64_Dyn d;
    uint64_t strtab = 0, strsz = 0;
    if (!sc_elf_dynamic(img, len, &dyn))
        return false;
    size_t count = (size_t)(dyn.p_filesz / sizeof(d));
    for (size_t i = 0; i < count; i++) {
        memcpy(&d, img + dyn.p_offset + i * sizeof(d), sizeof(d));
        if (d.d_tag == DT_STRTAB)
            strtab = d.d_un.d_ptr;
        else if (d.d_tag == DT_STRSZ)
            strsz = d.d_un.d_val;
    }
    size_t base = sc_elf_offset(img, len, strtab);
    if (!base || strsz > len - base)
        return false;
    size_t used = 0;
    out[0] = '\0';
    for (size_t i = 0; i < count; i++) {
        memcpy(&d, img + dyn.p_offset + i * sizeof(d), sizeof(d));
        if (d.d_tag != DT_NEEDED || d.d_un.d_val >= strsz)
            continue;
        const char *name = img + base + d.d_un.d_val;
        if (!memchr(name, '\0', (size_t)(strsz - d.d_un.d_val)))
            return false;
        int n = snprintf(out + used, cap - used, "%s ", name);
        if (n < 0 || (size_t)n >= cap - used)
            return false;
        used += (size_t)n;
    }
    return true;
}

/* A needed library that only an X11 or GL -dev link would have added. */
static const char *sc_needed_sdk_lib(const char *needed)
{
    static const char *const libs[] = {"libX11.so", "libXrandr.so",
        "libXi.so", "libXcursor.so", "libXext.so", "libXrender.so",
        "libXfixes.so", "libGL.so", "libGLX.so", "libEGL.so",
        "libOpenGL.so"};
    for (size_t i = 0; i < sizeof(libs) / sizeof(libs[0]); i++) {
        for (const char *p = strstr(needed, libs[i]); p;
             p = strstr(p + 1, libs[i]))
            if (p == needed || p[-1] == ' ')
                return libs[i];
    }
    return NULL;
}

static int sc_closure_is_vendored(void)
{
    int failures = 0;
    TEST("the game's RGFW header closure resolves entirely under vendor/") {
        struct sc_closure c = {0};
        ASSERT(access(SC_GAME, X_OK) == 0);
        ASSERT(sc_closure_read(SC_RCORE_DEPS, &c));
        test_note("%s: %d SDK headers, %d vendored, first outside vendor: %s",
                  SC_RCORE_DEPS, c.sdk, c.vendored,
                  c.offender[0] ? c.offender : "none");
        ASSERT(c.offender[0] == '\0');
        /* Non-vacuous: Xlib, Xrandr, XInput2, Xcursor, GLX and XDL at least. */
        ASSERT(c.sdk >= 6);
        ASSERT_EQ(c.vendored, c.sdk);
        ASSERT(c.rgfw_raylib > 0);
        ASSERT_EQ(c.rgfw_other, 0);
    PASS(); }
_test_next:;
    return failures;
}

static int sc_link_has_no_sdk(void)
{
    int failures = 0;
    TEST("the linked game needs no X11 or GL library at link time") {
        static char needed[4096];
        size_t len = 0;
        char *img = sc_slurp(SC_GAME, SC_ELF_MAX, &len);
        ASSERT(img != NULL);
        bool parsed = sc_elf_needed(img, len, needed, sizeof(needed));
        free(img);
        ASSERT(parsed);
        test_note("%s DT_NEEDED: %s", SC_GAME, needed);
        ASSERT(strstr(needed, "libc.so"));
        const char *lib = sc_needed_sdk_lib(needed);
        test_note("first X11/GL library needed: %s", lib ? lib : "none");
        ASSERT(lib == NULL);
    PASS(); }
_test_next:;
    return failures;
}

int test_app_launch_skycombat(void);
int test_app_launch_skycombat(void)
{
    int failures = 0;
    const char *xvfb = sc_xvfb_path();
    struct sc_env saved[] = {{"HOME", NULL}, {"DISPLAY", NULL},
                             {"WAYLAND_DISPLAY", NULL},
                             {"XDG_CONFIG_HOME", NULL},
                             {"XDG_STATE_HOME", NULL}};
    size_t nsaved = sizeof(saved) / sizeof(saved[0]);
    struct sc_xvfb x = {0};
    long pids[2] = {0, 0};
    char home[PATH_MAX], xlog[PATH_MAX + 16], glog[PATH_MAX + 64];
    char display[40];
    /* The build facts need no display, so they hold on every Linux host. */
    failures += sc_closure_is_vendored();
    failures += sc_link_has_no_sdk();
    if (!xvfb) {
        printf("SKIP (app_launch_skycombat: Xvfb is not installed on this "
               "host, so there is no display to open the game on)\n");
        return 0;
    }
    sc_env_swap(saved, nsaved, false);
    TEST("fixture: the built game, a temporary HOME and a private Xvfb") {
        ASSERT(access(SC_GAME, X_OK) == 0);
        ASSERT(access(SC_CLI, X_OK) == 0);
        ASSERT(test_mkdtemp(home, sizeof(home), "app_launch_sky"));
        snprintf(xlog, sizeof(xlog), "%s/xvfb.log", home);
        snprintf(glog, sizeof(glog), "%s/.local/state/z23/apps/skycombat.log",
                 home);
        ASSERT(sc_xvfb_start(xvfb, xlog, &x));
        snprintf(display, sizeof(display), ":%s", x.display);
        ASSERT(setenv("HOME", home, 1) == 0);
        ASSERT(setenv("DISPLAY", display, 1) == 0);
        ASSERT(unsetenv("WAYLAND_DISPLAY") == 0);
        ASSERT(unsetenv("XDG_CONFIG_HOME") == 0);
        ASSERT(unsetenv("XDG_STATE_HOME") == 0);
        test_note("Xvfb display %s", display);
    PASS(); }
    failures += sc_run(home, glog, pids);
_test_next:;
    (void)sc_stop(pids[1]);
    (void)sc_stop(pids[0]);
    sc_xvfb_stop(&x);
    sc_env_swap(saved, nsaved, true);
    return failures;
}

#else

int test_app_launch_skycombat(void);
int test_app_launch_skycombat(void)
{
    printf("SKIP (app_launch_skycombat: the Xvfb game test is Linux-only)\n");
    return 0;
}

#endif
