/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_app_launch - `z23 app open`, the native desktop launcher
 * (tools/command/native_app_launch*.c), without a display.
 *
 * A stand-in app, build/bin/z23-app-launch-fixture, is copied into a
 * temporary directory once per behaviour (so a /proc scan for one copy never
 * finds another) and registered through a temporary apps.tsv. It prints the
 * ready marker, appends "raised" to a file on SIGUSR1 and exits on SIGTERM.
 * Every spawned copy is tracked and killed and reaped at the end, on every
 * path.
 *
 * make t-fast-exact ONLY=app_launch */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_core.h"
#include "test/app_seed_fixture.h"

#include <dirent.h>

#include "command/native_app_launch.h"
#include "command/native_app_share_command.h"
#include "command/native_app_library_command.h"
#include "command/native_app_host_browser.h"
#include "command/native_app_installed_copy.h"
#include "command/native_app_discover_view.h"
#include "command/native_app_share_reveal.h"
#include "controllers/rpc_client.h"
#include "command/native_zcode_package_copy.h"
#include "command/app_selection.h"
#include "presentation/model_render.h"
#include "presentation/canvas.h"
#include "base/hex.h"
#include "platform/positioned_file.h"
#include "platform/resident_launch.h"
#include "sha3/sha3.h"
#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/time_compat.h"

#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define AL_FIXTURE "build/bin/z23-app-launch-fixture"
#define AL_MARKER "FIXTURE: Device initialized successfully"
#define AL_PIDS_MAX 16

static long al_pids[AL_PIDS_MAX];
static unsigned al_npids;

static void al_track(long pid)
{
    if (pid > 1 && al_npids < AL_PIDS_MAX)
        al_pids[al_npids++] = pid;
}

/* SIGTERM every copy this group started, then reap it (SIGKILL after 3 s). */
static void al_kill_all(void)
{
    for (unsigned i = 0; i < al_npids; i++) {
        pid_t pid = (pid_t)al_pids[i];
        int status;
        (void)kill(pid, SIGTERM);
        int64_t stop = platform_time_monotonic_ms() + 3000;
        while (waitpid(pid, &status, WNOHANG) == 0) {
            if (platform_time_monotonic_ms() > stop) {
                (void)kill(pid, SIGKILL);
                (void)waitpid(pid, &status, 0);
                break;
            }
            platform_sleep_ms(10); /* real-clock: reaping a real child */
        }
    }
    al_npids = 0;
}

struct al_fx {
    char root[PATH_MAX];
    char raised[PATH_MAX];
    char bin_ready[PATH_MAX];
    char bin_exit[PATH_MAX];
    char bin_silent[PATH_MAX];
    char bin_quiet[PATH_MAX]; /* declares no raise, has no handler */
    char bin_liar[PATH_MAX];  /* declares raise, has no handler */
    char bin_die[PATH_MAX];   /* prints the marker, then dies */
    struct app_launch_env env;
    struct app_launch_registry reg;
    struct app_open_result res;
};

static bool al_path(char *out, size_t cap, const char *dir, const char *leaf)
{
    int n = snprintf(out, cap, "%s/%s", dir, leaf);
    return n > 0 && (size_t)n < cap;
}

static bool al_copy_exe(const char *from, const char *to, mode_t mode)
{
    char buf[65536];
    int in = open(from, O_RDONLY | O_CLOEXEC);
    int out = open(to, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0700);
    bool ok = in >= 0 && out >= 0;
    ssize_t n = 0;
    while (ok && (n = read(in, buf, sizeof(buf))) > 0)
        ok = write(out, buf, (size_t)n) == n;
    ok = ok && n == 0 && fchmod(out, mode) == 0;
    if (in >= 0)
        (void)close(in);
    if (out >= 0)
        ok = close(out) == 0 && ok;
    return ok;
}

static bool al_write_file(const char *path, const char *text, mode_t mode)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return false;
    bool ok = fputs(text, f) >= 0;
    ok = fclose(f) == 0 && ok;
    return ok && chmod(path, mode) == 0;
}

/* One tsv row: id, aliases, executable, marker, raise, then the fixture's
 * two arguments: mode and raise file. */
static int al_row(char *out, size_t cap, const char *id, const char *aliases,
                  const char *exe, const char *raise, const char *mode,
                  const char *raised)
{
    return snprintf(out, cap, "%s\t%s\t%s\t" AL_MARKER "\t%s\t%s\t%s\n", id,
                    aliases, exe, raise, mode, raised);
}

static bool al_write_tsv(struct al_fx *f)
{
    char text[8192];
    size_t at = 0;
    at += (size_t)snprintf(text + at, sizeof(text) - at,
                           "# test apps\n\n");
    at += (size_t)al_row(text + at, sizeof(text) - at, "fixtureapp",
                         "fx,fixture-alias", f->bin_ready, "sigusr1", "ready",
                         f->raised);
    at += (size_t)al_row(text + at, sizeof(text) - at, "crashy", "-",
                         f->bin_exit, "-", "exit", f->raised);
    at += (size_t)al_row(text + at, sizeof(text) - at, "slowapp", "-",
                         f->bin_silent, "-", "silent", f->raised);
    at += (size_t)al_row(text + at, sizeof(text) - at, "quietapp", "-",
                         f->bin_quiet, "-", "nohandler", f->raised);
    at += (size_t)al_row(text + at, sizeof(text) - at, "liarapp", "-",
                         f->bin_liar, "sigusr1", "nohandler", f->raised);
    at += (size_t)al_row(text + at, sizeof(text) - at, "dyingapp", "-",
                         f->bin_die, "-", "readydie", f->raised);
    return at < sizeof(text) &&
           al_write_file(f->env.config_path, text, 0600);
}

/* The fixture's paths under f->root. bin_dir is an empty directory, so the
 * built-in skycombat row is never installed here. */
static bool al_paths(struct al_fx *f)
{
    bool ok = al_path(f->env.bin_dir, sizeof(f->env.bin_dir), f->root, "bin") &&
              mkdir(f->env.bin_dir, 0700) == 0 &&
              al_path(f->env.config_path, sizeof(f->env.config_path),
                      f->root, "apps.tsv") &&
              al_path(f->env.state_dir, sizeof(f->env.state_dir), f->root,
                      "state/z23/apps") &&
              al_path(f->raised, sizeof(f->raised), f->root, "raised");
    return ok &&
           al_path(f->bin_ready, sizeof(f->bin_ready), f->root, "app-ready") &&
           al_path(f->bin_exit, sizeof(f->bin_exit), f->root, "app-exit") &&
           al_path(f->bin_silent, sizeof(f->bin_silent), f->root, "app-silent") &&
           al_path(f->bin_quiet, sizeof(f->bin_quiet), f->root, "app-quiet") &&
           al_path(f->bin_liar, sizeof(f->bin_liar), f->root, "app-liar") &&
           al_path(f->bin_die, sizeof(f->bin_die), f->root, "app-die");
}

static bool al_setup(struct al_fx *f)
{
    char fixture[PATH_MAX];
    memset(f, 0, sizeof(*f));
    if (!realpath(AL_FIXTURE, fixture) ||
        !test_mkdtemp(f->root, sizeof(f->root), "app_launch"))
        return false;
    f->env.desktop = true;
    f->env.ready_timeout_ms = 10000;
    f->env.settle_ms = 200;
    bool ok = al_paths(f);
    ok = ok && al_copy_exe(fixture, f->bin_ready, 0700) &&
         al_copy_exe(fixture, f->bin_exit, 0700) &&
         al_copy_exe(fixture, f->bin_silent, 0700) &&
         al_copy_exe(fixture, f->bin_quiet, 0700) &&
         al_copy_exe(fixture, f->bin_liar, 0700) &&
         al_copy_exe(fixture, f->bin_die, 0700) && al_write_tsv(f);
    if (ok)
        app_launch_registry_load(&f->env, &f->reg);
    return ok;
}

static void al_open(struct al_fx *f, const char *name)
{
    app_launch_open(&f->env, &f->reg, name, &f->res);
    al_track(f->res.pid);
}

/* Whether the fixture appended "raised" within 3 s. */
static bool al_wait_raised(const char *path)
{
    int64_t stop = platform_time_monotonic_ms() + 3000;
    for (;;) {
        char buf[64] = {0};
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            (void)close(fd);
            if (n > 0 && strstr(buf, "raised"))
                return true;
        }
        if (platform_time_monotonic_ms() > stop)
            return false;
        platform_sleep_ms(20); /* real-clock: waiting on a real child's signal */
    }
}

static bool al_alive(long pid)
{
    return kill((pid_t)pid, 0) == 0;
}

/* ── cases ────────────────────────────────────────────────────────────── */

static int case_open_raise_reopen(struct al_fx *f)
{
    int failures = 0;
    long first = 0;
    TEST("open starts the app and waits for its ready marker") {
        ASSERT(f->reg.config_error[0] == '\0');
        ASSERT(f->reg.count == 7u);
        al_open(f, "fixtureapp");
        ASSERT_STR_EQ(app_open_status_name(f->res.status), "opened");
        ASSERT(f->res.pid > 1);
        ASSERT_STR_EQ(f->res.ready_basis, "marker");
        ASSERT_STR_EQ(f->res.executable, f->bin_ready);
        ASSERT_EQ(strlen(f->res.sha256), 64u);
        ASSERT(strstr(f->res.log_path, "/state/z23/apps/fixtureapp.log"));
        struct app_launch_record rec;
        ASSERT(app_launch_record_load(f->env.state_dir, "fixtureapp", &rec));
        ASSERT_EQ(rec.pid, f->res.pid);
        ASSERT_STR_EQ(rec.executable, f->bin_ready);
        first = f->res.pid;
    PASS(); }
    TEST("open again by alias raises the same pid instead of a copy") {
        ASSERT(first > 1);
        al_open(f, "fx");
        ASSERT_STR_EQ(app_open_status_name(f->res.status), "already_open");
        ASSERT_EQ(f->res.pid, first);
        ASSERT_STR_EQ(f->res.found_by, "record");
        ASSERT_STR_EQ(app_raise_outcome_name(f->res.raise), "delivered");
        ASSERT(al_wait_raised(f->raised));
    PASS(); }
    TEST("after the app is killed, open starts a new pid") {
        ASSERT(first > 1);
        al_kill_all();
        ASSERT(!al_alive(first));
        al_open(f, "fixture-alias");
        ASSERT_STR_EQ(app_open_status_name(f->res.status), "opened");
        ASSERT(f->res.pid > 1);
        ASSERT(f->res.pid != first);
    PASS(); }
_test_next:;
    al_kill_all();
    return failures;
}

static int case_refusals(struct al_fx *f)
{
    int failures = 0;
    TEST("an unknown name is refused with the known names") {
        al_open(f, "nosuchapp");
        ASSERT_STR_EQ(app_open_status_name(f->res.status), "failed");
        ASSERT_STR_EQ(app_open_stage_name(f->res.stage), "unknown_app");
        ASSERT(strstr(f->res.message, "nosuchapp"));
        ASSERT(strstr(f->res.hint, "skycombat"));
        ASSERT(strstr(f->res.hint, "fixtureapp"));
        ASSERT_EQ(f->res.pid, 0);
    PASS(); }
    TEST("a known app whose executable is missing is not_installed") {
        al_open(f, "sky");
        ASSERT_STR_EQ(app_open_stage_name(f->res.stage), "not_installed");
        ASSERT_STR_EQ(f->res.id, "skycombat");
        ASSERT(strstr(f->res.message, "z23-skycombat"));
        ASSERT_STR_EQ(f->res.hint, "build it with make game");
    PASS(); }
    TEST("without a desktop session open is refused as no_desktop") {
        f->env.desktop = false;
        al_open(f, "fixtureapp");
        f->env.desktop = true;
        ASSERT_STR_EQ(app_open_stage_name(f->res.stage), "no_desktop");
        ASSERT(strstr(f->res.message, "no desktop session on this host"));
        ASSERT_EQ(f->res.pid, 0);
    PASS(); }
    TEST("an app that exits before ready is exited_early with its log") {
        al_open(f, "crashy");
        ASSERT_STR_EQ(app_open_stage_name(f->res.stage), "exited_early");
        ASSERT(f->res.exited);
        ASSERT_EQ(f->res.exit_code, 3);
        ASSERT(strstr(f->res.log_tail, "cannot open display"));
    PASS(); }
    TEST("an app that prints the marker then dies is not opened and says why") {
        al_open(f, "dyingapp");
        ASSERT(f->res.status != APP_OPEN_OPENED);
        ASSERT_STR_EQ(app_open_stage_name(f->res.stage), "exited_early");
        ASSERT(f->res.exited);
        ASSERT_EQ(f->res.exit_code, 1);
        ASSERT(strstr(f->res.message, "X connection broken"));
        ASSERT(strstr(f->res.message, "dyingapp.log"));
    PASS(); }
    TEST("an app with no ready marker in time is not_ready and running") {
        f->env.ready_timeout_ms = 400;
        al_open(f, "slowapp");
        f->env.ready_timeout_ms = 10000;
        ASSERT_STR_EQ(app_open_stage_name(f->res.stage), "not_ready");
        ASSERT(f->res.pid > 1);
        ASSERT(al_alive(f->res.pid));
        ASSERT(strstr(f->res.message, "still running as pid"));
    PASS(); }
_test_next:;
    f->env.desktop = true;
    f->env.ready_timeout_ms = 10000;
    al_kill_all();
    return failures;
}

/* An app that does not declare raise support is never signalled: the
 * nohandler fixture would die from SIGUSR1, so "still alive" proves it. */
static int case_raise_declaration(struct al_fx *f)
{
    int failures = 0;
    long pid = 0;
    TEST("already_open for an app without raise support sends nothing") {
        al_open(f, "quietapp");
        ASSERT_STR_EQ(app_open_status_name(f->res.status), "opened");
        pid = f->res.pid;
        al_open(f, "quietapp");
        ASSERT_STR_EQ(app_open_status_name(f->res.status), "already_open");
        ASSERT_EQ(f->res.pid, pid);
        ASSERT_STR_EQ(app_raise_outcome_name(f->res.raise),
                      "unsupported_by_app");
        ASSERT(strstr(f->res.raise_note, "no signal was sent"));
        platform_sleep_ms(100); /* real-clock: a stray signal would land */
        ASSERT(al_alive(pid));
        ASSERT(waitpid((pid_t)pid, &(int){0}, WNOHANG) == 0);
    PASS(); }
#if defined(__linux__)
    TEST("a declared raise is not sent to a copy with no handler") {
        al_open(f, "liarapp");
        ASSERT_STR_EQ(app_open_status_name(f->res.status), "opened");
        pid = f->res.pid;
        al_open(f, "liarapp");
        ASSERT_STR_EQ(app_open_status_name(f->res.status), "already_open");
        ASSERT_EQ(f->res.pid, pid);
        ASSERT_STR_EQ(app_raise_outcome_name(f->res.raise), "no_handler");
        platform_sleep_ms(100); /* real-clock: a stray signal would land */
        ASSERT(waitpid((pid_t)pid, &(int){0}, WNOHANG) == 0);
    PASS(); }
#endif
_test_next:;
    al_kill_all();
    return failures;
}

/* Load a one-row apps.tsv at <root>/<leaf> and return the registry error. */
static const char *al_load_tsv(struct al_fx *f, const char *leaf,
                               const char *row, mode_t mode)
{
    struct app_launch_env env = f->env;
    if (!al_path(env.config_path, sizeof(env.config_path), f->root, leaf) ||
        !al_write_file(env.config_path, row, mode))
        return "(fixture write failed)";
    app_launch_registry_load(&env, &f->reg);
    return f->reg.config_error;
}

static int case_unsafe_tsv(struct al_fx *f)
{
    int failures = 0;
    char row[PATH_MAX + 64], unsafe_exe[PATH_MAX];
    TEST("a group-writable apps.tsv is refused whole") {
        ASSERT(chmod(f->env.config_path, 0620) == 0);
        app_launch_registry_load(&f->env, &f->reg);
        ASSERT(chmod(f->env.config_path, 0600) == 0);
        ASSERT(strstr(f->reg.config_error, "not group- or world-writable"));
        ASSERT(f->reg.count == 1u); /* the built-in rows only */
        al_open(f, "fixtureapp");
        ASSERT_STR_EQ(app_open_stage_name(f->res.stage), "config_refused");
        ASSERT_EQ(f->res.pid, 0);
    PASS(); }
    TEST("a relative executable path refuses the file") {
        const char *why = al_load_tsv(f, "relative.tsv",
                                      "relapp\t-\tbin/app\t-\t-\n", 0600);
        ASSERT(strstr(why, "absolute path"));
        ASSERT(f->reg.count == 1u);
    PASS(); }
    TEST("a group-writable executable refuses the file") {
        ASSERT(al_path(unsafe_exe, sizeof(unsafe_exe), f->root, "app-gw"));
        ASSERT(al_copy_exe(f->bin_ready, unsafe_exe, 0770));
        snprintf(row, sizeof(row), "gwapp\t-\t%s\t-\t-\n", unsafe_exe);
        const char *why = al_load_tsv(f, "gw.tsv", row, 0600);
        ASSERT(strstr(why, "group- or world-writable"));
        ASSERT(f->reg.count == 1u);
    PASS(); }
    TEST("a name that collides with a built-in refuses the file") {
        snprintf(row, sizeof(row), "mine\tsky\t%s\t-\t-\n", f->bin_ready);
        const char *why = al_load_tsv(f, "dup.tsv", row, 0600);
        ASSERT(strstr(why, "name already used: sky"));
    PASS(); }
    TEST("a raise column other than sigusr1 or - refuses the file") {
        snprintf(row, sizeof(row), "mine\t-\t%s\t-\tyes\n", f->bin_ready);
        const char *why = al_load_tsv(f, "raise.tsv", row, 0600);
        ASSERT(strstr(why, "raise must be sigusr1 or -: yes"));
        snprintf(row, sizeof(row), "mine\t-\t%s\t-\n", f->bin_ready);
        why = al_load_tsv(f, "short.tsv", row, 0600);
        ASSERT(strstr(why, "need id, aliases, executable, ready marker and "
                           "raise"));
    PASS(); }
_test_next:;
    (void)chmod(f->env.config_path, 0600);
    app_launch_registry_load(&f->env, &f->reg);
    return failures;
}

static int case_stale_record(struct al_fx *f)
{
    int failures = 0;
    TEST("a pid record whose pid now runs another program is not open") {
        char self_exe[APP_LAUNCH_PATH_MAX];
        uint64_t self_start = 0;
        ASSERT(app_proc_identity((long)getpid(), self_exe, &self_start));
        /* The record names this test's own live pid: the pid exists, but it
         * runs the test binary, not the app. */
        struct app_launch_record rec = {.pid = getpid(),
                                        .start_time = self_start};
        snprintf(rec.id, sizeof(rec.id), "fixtureapp");
        snprintf(rec.executable, sizeof(rec.executable), "%s", f->bin_ready);
        ASSERT(app_launch_record_save(f->env.state_dir, &rec));
        const struct app_launch_entry *e =
            app_launch_registry_find(&f->reg, "fixtureapp");
        const char *found = NULL;
        ASSERT(e != NULL);
        ASSERT_EQ(app_launch_running_pid(&f->env, e, &found), 0);
        ASSERT(found == NULL);
    PASS(); }
    TEST("a pid record with the right program but another start time is "
              "not open") {
        struct app_launch_entry self = {.installed = false};
        struct app_launch_record rec = {.pid = getpid()};
        const char *found = NULL;
        snprintf(self.id, sizeof(self.id), "selfapp");
        snprintf(rec.id, sizeof(rec.id), "selfapp");
        ASSERT(app_proc_identity((long)getpid(), self.executable,
                                 &rec.start_time));
        snprintf(rec.executable, sizeof(rec.executable), "%s", self.executable);
        rec.start_time += 1;
        ASSERT(app_launch_record_save(f->env.state_dir, &rec));
        ASSERT_EQ(app_launch_running_pid(&f->env, &self, &found), 0);
        /* Positive control: the exact identity is accepted. */
        rec.start_time -= 1;
        ASSERT(app_launch_record_save(f->env.state_dir, &rec));
        ASSERT_EQ(app_launch_running_pid(&f->env, &self, &found),
                  (long)getpid());
        ASSERT_STR_EQ(found, "record");
    PASS(); }
    TEST("a malformed pid record is refused by validation") {
        struct app_launch_record rec = {.pid = 1, .start_time = 1};
        snprintf(rec.id, sizeof(rec.id), "Bad Id");
        snprintf(rec.executable, sizeof(rec.executable), "relative");
        ASSERT(!app_launch_record_save(f->env.state_dir, &rec));
    PASS(); }
_test_next:;
    return failures;
}

/* ── process environment and the native handlers ──────────────────────── */

struct al_saved_env {
    const char *key;
    char *value;
};

static void al_env_save(struct al_saved_env *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        const char *v = getenv(s[i].key);
        s[i].value = v ? strdup(v) : NULL;
    }
}

static void al_env_restore(struct al_saved_env *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (s[i].value)
            (void)setenv(s[i].key, s[i].value, 1);
        else
            (void)unsetenv(s[i].key);
        free(s[i].value);
        s[i].value = NULL;
    }
}

static int case_process_env(struct al_fx *f)
{
    int failures = 0;
    struct al_saved_env saved[] = {{"HOME", NULL}, {"DISPLAY", NULL},
                                   {"WAYLAND_DISPLAY", NULL},
                                   {"XDG_CONFIG_HOME", NULL},
                                   {"XDG_STATE_HOME", NULL}};
    size_t nsaved = sizeof(saved) / sizeof(saved[0]);
    struct app_launch_env env;
    char why[256], expect[PATH_MAX];
    al_env_save(saved, nsaved);
    TEST("the process environment names apps.tsv, the state dir and "
              "the desktop") {
        ASSERT(setenv("HOME", f->root, 1) == 0);
        ASSERT(unsetenv("XDG_CONFIG_HOME") == 0);
        ASSERT(unsetenv("XDG_STATE_HOME") == 0);
        ASSERT(unsetenv("DISPLAY") == 0);
        ASSERT(unsetenv("WAYLAND_DISPLAY") == 0);
        ASSERT(app_launch_env_from_process(&env, why, sizeof(why)));
        snprintf(expect, sizeof(expect), "%s/.config/z23/apps.tsv", f->root);
        ASSERT_STR_EQ(env.config_path, expect);
        snprintf(expect, sizeof(expect), "%s/.local/state/z23/apps", f->root);
        ASSERT_STR_EQ(env.state_dir, expect);
        ASSERT_EQ(env.ready_timeout_ms, APP_LAUNCH_READY_TIMEOUT_MS);
#if defined(__linux__)
        ASSERT(!env.desktop);
        ASSERT(setenv("WAYLAND_DISPLAY", "wayland-0", 1) == 0);
        ASSERT(app_launch_env_from_process(&env, why, sizeof(why)));
        ASSERT(env.desktop);
#endif
        ASSERT(env.bin_dir[0] == '/');
    PASS(); }
_test_next:;
    al_env_restore(saved, nsaved);
    return failures;
}

static int case_handlers(struct al_fx *f)
{
    int failures = 0;
    struct al_saved_env saved[] = {{"HOME", NULL}, {"XDG_CONFIG_HOME", NULL},
                                   {"XDG_STATE_HOME", NULL}};
    size_t nsaved = sizeof(saved) / sizeof(saved[0]);
    struct json_value input;
    struct zcl_command_reply reply = {0};
    struct zcl_command_request request = {.input = &input, .view = "normal"};
    al_env_save(saved, nsaved);
    json_init(&input);
    json_set_object(&input);
    TEST("app.open without a name is refused as MISSING_NAME") {
        ASSERT(setenv("HOME", f->root, 1) == 0);
        ASSERT(unsetenv("XDG_CONFIG_HOME") == 0);
        ASSERT(unsetenv("XDG_STATE_HOME") == 0);
        request.invoked_name = "app.open";
        zcl_command_reply_init(&reply, "zcl.app_open.v1");
        zcl_native_handle_app_open(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(reply.error.code, "MISSING_NAME");
        zcl_command_reply_free(&reply);
    PASS(); }
    TEST("app.open of an unknown name is UNKNOWN_APP with next app.list") {
        ASSERT(json_push_kv_str(&input, "name", "nosuchapp"));
        zcl_command_reply_init(&reply, "zcl.app_open.v1");
        zcl_native_handle_app_open(&request, &reply);
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_INVALID);
        ASSERT_STR_EQ(reply.error.code, "UNKNOWN_APP");
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "stage")),
                      "unknown_app");
        ASSERT(strstr(json_get_str(json_get(&reply.data, "hint")), "skycombat"));
        ASSERT_EQ(reply.next_count, 1u);
        ASSERT_STR_EQ(reply.next[0].command, "app.list");
    PASS(); }
    TEST("app.open of blog says it is a web app the node serves") {
        struct json_value blog_in;
        struct zcl_command_request blog_req = {.input = &blog_in,
                                               .view = "normal",
                                               .invoked_name = "app.open"};
        json_init(&blog_in);
        json_set_object(&blog_in);
        ASSERT(json_push_kv_str(&blog_in, "name", "blog"));
        zcl_command_reply_init(&reply, "zcl.app_open.v1");
        zcl_native_handle_app_open(&blog_req, &reply);
        json_free(&blog_in);
        ASSERT_STR_EQ(reply.error.code, "UNKNOWN_APP");
        const char *msg = json_get_str(json_get(&reply.data, "message"));
        ASSERT(msg != NULL);
        ASSERT(strstr(msg, "web app") != NULL);
        ASSERT(strstr(msg, "/blog") != NULL);
        ASSERT(strstr(msg, "skycombat") != NULL);
    PASS(); }
    TEST("app.list says what can be opened and offers open and copy of the "
         "first launchable app") {
        struct json_value empty;
        struct zcl_command_request list_request = {.input = &empty,
                                                   .view = "normal"};
        json_init(&empty);
        json_set_object(&empty);
        list_request.invoked_name = "app.list";
        zcl_command_reply_init(&reply, "zcl.app_list.v1");
        zcl_native_handle_app_list_launchable(&list_request, &reply);
        const struct json_value *launchable = json_get(&reply.data,
                                                       "launchable");
        ASSERT(launchable && launchable->num_children >= 1);
        /* the built-in catalog's first entry, not read back from the reply */
        ASSERT_STR_EQ(json_get_str(json_get(&launchable->children[0], "id")),
                      "skycombat");
        const char *summary = json_get_str(json_get(&reply.data, "summary"));
        ASSERT(summary && strstr(summary, "launchable") != NULL &&
               strstr(summary, "z23 app open") != NULL);
        ASSERT_EQ(reply.next_count, 2u);
        ASSERT_STR_EQ(reply.next[0].command, "app.open");
        ASSERT(strstr(reply.next[0].input_json, "\"skycombat\"") != NULL);
        ASSERT_STR_EQ(reply.next[1].command, "app.adopt");
        ASSERT_STR_EQ(reply.next[1].input_json, "{\"name\":\"skycombat\"}");
        json_free(&empty);
    PASS(); }
_test_next:;
    zcl_command_reply_free(&reply);
    json_free(&input);
    al_env_restore(saved, nsaved);
    return failures;
}

/* A stranger with only the public words finds app.open. */
static int case_discover(void)
{
    int failures = 0;
    static const char *const queries[] = {"airplane", "skycombat", "game",
                                          "sky combat", "play a game"};
    static char out[16384];
    const struct zcl_command_registry *reg = zcl_command_catalog();
    for (size_t q = 0; q < sizeof(queries) / sizeof(queries[0]); q++) {
        TEST("discover search finds app.open") {
            test_note("query: %s", queries[q]);
            size_t n = zcl_command_registry_search_json(reg, queries[q], out,
                                                        sizeof(out));
            ASSERT(n > 0 && n < sizeof(out));
            ASSERT(strstr(out, "\"path\":\"app.open\""));
        PASS(); }
    _test_next:;
    }
    return failures;
}

static bool al_accept_of(const char *path, struct resident_launch_accepted *a)
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot snap;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path) ||
        !platform_positioned_file_snapshot(&file, &snap)) {
        platform_positioned_file_close(&file);
        return false;
    }
    unsigned char digest[32];
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    unsigned char chunk[4096];
    uint64_t offset = 0;
    for (;;) {
        int64_t got = platform_positioned_file_read(&file, chunk, sizeof(chunk),
                                                    offset);
        if (got < 0) { platform_positioned_file_close(&file); return false; }
        if (got == 0) break;
        sha3_256_write(&ctx, chunk, (size_t)got);
        offset += (uint64_t)got;
    }
    sha3_256_finalize(&ctx, digest);
    platform_positioned_file_close(&file);
    zcl_hex_encode(digest, sizeof(digest), a->image_sha3_hex);
    a->image_volume = snap.volume;
    a->image_low = snap.file_low;
    a->image_high = snap.file_high;
    a->image_size = snap.size;
    return true;
}

static int al_fd_count(void)
{
    int count = 0;
    for (int fd = 3; fd < 1024; ++fd) if (fcntl(fd, F_GETFD) >= 0) ++count;
    return count;
}

static bool al_prepared(const char *image, struct resident_launch *launch)
{
    struct resident_launch_accepted accepted;
    char error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
    resident_launch_init(launch);
    return al_accept_of(image, &accepted) &&
        resident_launch_prepare(launch, image, &accepted, error, sizeof(error));
}

static int case_resident_app(struct al_fx *f, const char *image, const char *mode,
                             bool expect_ready, bool expect_exit)
{
    int failures = 0;
    int before = al_fd_count();
    char log[PATH_MAX], error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
    struct app_launch_entry entry = {0};
    struct resident_launch launch;
    struct resident_receipt receipt = {0};
    struct app_spawn_outcome out = {0};
    snprintf(entry.executable, sizeof(entry.executable), "%.*s", (int)sizeof(entry.executable) - 1, image);
    snprintf(entry.ready_marker, sizeof(entry.ready_marker), "%s", AL_MARKER);
    snprintf(entry.args[0], sizeof(entry.args[0]), "%s", mode);
    snprintf(entry.args[1], sizeof(entry.args[1]), "%.*s", (int)sizeof(entry.args[1]) - 1, f->raised);
    entry.arg_count = 2;
    TEST("prepared exact app uses marker readiness and retains receipt") {
        ASSERT(al_path(log, sizeof(log), f->root, "resident.log"));
        ASSERT(al_prepared(image, &launch));
        ASSERT(app_proc_resident_spawn_and_wait(&entry, &launch, log, 500, 100,
                                               &receipt, &out, error, sizeof(error)));
        if (!out.exited) al_track(out.pid);
        ASSERT(out.pid > 0 && receipt.pid == (uint64_t)out.pid && receipt.mapped_proof[0]);
        ASSERT(out.ready == expect_ready && out.exited == expect_exit);
        ASSERT_EQ(al_fd_count(), before);
    PASS(); }
_test_next:
    return failures;
}

static int case_resident_mutation(struct al_fx *f)
{
    int failures = 0;
    int before = al_fd_count();
    char log[PATH_MAX], error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
    struct app_launch_entry entry = {0};
    struct resident_launch launch;
    struct resident_receipt receipt = {0};
    struct app_spawn_outcome out = {0};
    char image[PATH_MAX], original[PATH_MAX];
    TEST("prepared app mutation is refused without pathname fallback") {
        ASSERT(al_path(log, sizeof(log), f->root, "resident-mutated.log"));
        ASSERT(al_path(image, sizeof(image), f->root, "mutation-image"));
        ASSERT(realpath(AL_FIXTURE, original) && al_copy_exe(original, image, 0700));
        snprintf(entry.executable, sizeof(entry.executable), "%.*s", (int)sizeof(entry.executable) - 1, image);
        ASSERT(al_prepared(image, &launch));
        int fd = open(image, O_WRONLY | O_APPEND);
        ASSERT(fd >= 0 && write(fd, "x", 1) == 1 && close(fd) == 0);
        ASSERT(!app_proc_resident_spawn_and_wait(&entry, &launch, log, 500, 100,
                                                &receipt, &out, error, sizeof(error)));
        ASSERT(out.pid == 0 && out.spawn_errno != 0);
        ASSERT_EQ(al_fd_count(), before);
    PASS(); }
_test_next:
    return failures;
}

static int case_preview(void)
{
    int failures = 0;
    struct app_launch_preview p;
    TEST("skycombat's launch row has a preview argv with the capture path "
         "filled from the copy directory") {
        ASSERT(app_launch_preview("skycombat", "/copies/sky-1", &p));
        ASSERT(p.arg_count == 2);
        ASSERT(strcmp(p.args[0], "--qa-frames=120") == 0);
        ASSERT(strcmp(p.args[1], "--capture=/copies/sky-1/preview.png") == 0);
        ASSERT(strcmp(p.capture_path, "/copies/sky-1/preview.png") == 0);
        /* no preview row, no directory, no name: no preview */
        ASSERT(!app_launch_preview("tinyapp", "/copies/x", &p) &&
               p.arg_count == 0);
        ASSERT(!app_launch_preview("skycombat", "", &p));
        ASSERT(!app_launch_preview(NULL, "/copies/x", &p));
    PASS(); }
    TEST("app_launch_preview_as refuses an empty or slashed file name and "
         "zeroes out; a plain name joins the directory") {
        memset(&p, 0xA5, sizeof(p));
        ASSERT(!app_launch_preview_as("skycombat", "/store/pv", "", &p));
        ASSERT(p.arg_count == 0 && p.capture_path[0] == '\0');
        memset(&p, 0xA5, sizeof(p));
        ASSERT(!app_launch_preview_as("skycombat", "/store/pv", "a/b.png", &p));
        ASSERT(p.arg_count == 0 && p.capture_path[0] == '\0');
        ASSERT(app_launch_preview_as("skycombat", "/store/pv", "x1.png", &p));
        ASSERT(strcmp(p.capture_path, "/store/pv/x1.png") == 0);
    PASS(); }
_test_next:
    return failures;
}

struct al_library_script {
    unsigned actions[40], count, calls, errors, home_calls;
    bool valid, saved_label, fresh_copy_prompt;
    char last_summary[241];
    char error_summary[241];
    char error_title[241];
    char error_copy[ZCL_PRESENT_COPY_TEXT_MAX + 1];
    char setup[ZCL_PRESENT_COPY_TEXT_MAX + 1];
    struct al_fx *change_fixture;
    unsigned change_at;
    unsigned preparations;
    unsigned share_calls; bool share_cancel, fail_share_result, mismatch_share_result; char shared[ZCL_PRESENT_COPY_TEXT_MAX + 1];
    bool fail_after_file; unsigned host_calls; bool cancel_host;
    bool cancel_preparation, stale_preparation;
    bool bad_preparation, fail_preparation, saw_share_review;
    unsigned share_choice, canceled_prepare_menu;
    unsigned second_preparation;
    bool fail_after_noop;
    bool saw_recovery;
    bool reveal_request, reveal_fail, fail_reveal_notice; unsigned reveal_calls, notice_calls; char revealed[ZCL_PRESENT_COPY_TEXT_MAX + 1];
    uint64_t shared_revision; bool refresh_changed, refreshed_card; unsigned break_selection;
    uint8_t shared_version[32];
};
/* Per-call owner preparation stand-in: these launcher unit fixtures have no
 * source CAS. Real personalization and descendant authorization have app tests. */
static void al_library_later_failure(struct al_library_script *s, struct zcl_command_reply *reply)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
        "FIXTURE_FAILED", "prepare", false, true, "Later preparation failed.", "fixture");
    struct json_value facts = {0}; json_set_object(&facts);
    s->valid = s->valid && json_push_kv_str(&facts, "later_effect", "preserve me") &&
        (s->second_preparation != 4 || (json_push_kv_str(&facts, "copy", "saved-copy") &&
            json_push_kv_str(&facts, "destination", "/fixture/received") &&
            json_push_kv_bool(&facts, "executed", true))) &&
        json_push_kv(&reply->data, "failure_facts", &facts);
    json_free(&facts);
}
static bool al_library_prepared_data(struct zcl_command_reply *reply,
    const struct app_selection *selection, bool noop)
{
    uint8_t source[32]; if (noop) memcpy(source, selection->version, sizeof(source));
    else memset(source, 2, sizeof(source));
    char version[65]; zcl_hex_encode(source, sizeof(source), version);
    return json_push_kv_str(&reply->data, "version", version) &&
        json_push_kv_str(&reply->data, "copy", selection->copy) &&
        json_push_kv_str(&reply->data, "datadir", selection->datadir) &&
        json_push_kv_bool(&reply->data, "key_created", !noop) &&
        json_push_kv_bool(&reply->data, "changed", !noop);
}
static void al_library_prepare(void *context, const struct app_selection *selection,
    struct zcl_command_reply *reply)
{
    struct al_library_script *s = context;
    ++s->preparations;
    if (s->fail_preparation) { zcl_package_copy_fail(reply, "FIXTURE_FAILED", false, "Fixture failed.", "fixture"); return; }
    if (s->bad_preparation) { s->valid = s->valid && json_push_kv_str(&reply->data, "version", "invalid"); return; }
    if (s->cancel_preparation || (s->preparations == 2 && s->second_preparation == 2)) {
        s->valid = s->valid && json_push_kv_str(&reply->data, "status", "canceled");
        return;
    }
    if (s->preparations == 2 && s->second_preparation >= 3) {
        al_library_later_failure(s, reply); return;
    }
    bool noop = s->preparations == 2 && s->second_preparation == 1;
    s->valid = s->valid && al_library_prepared_data(reply, selection, noop);
    reply->error.mutated = !noop;
    if (s->stale_preparation && s->change_fixture) {
        struct app_selection next;
        s->valid = s->valid && app_selection_save(s->change_fixture->env.state_dir,
            selection->revision, selection, &next) == APP_SELECTION_OK;
    }
}
static void al_library_prepared_same(void *context, const struct app_selection *selection,
    struct zcl_command_reply *reply)
{
    struct al_library_script *s = context; char version[65];
    ++s->preparations; zcl_hex_encode(selection->version, 32, version);
    s->valid = s->valid && json_push_kv_str(&reply->data, "version", version);
}
static void al_library_change(struct al_library_script *s)
{
        struct app_selection selection, updated;
        s->valid = s->valid && app_selection_load(s->change_fixture->env.state_dir,
            "fixtureapp", &selection) == APP_SELECTION_OK;
        if (s->break_selection) {
            char path[PATH_MAX], saved[PATH_MAX];
            s->valid = s->valid && al_path(path, sizeof(path), s->change_fixture->env.state_dir, "fixtureapp.selection") &&
                al_path(saved, sizeof(saved), s->change_fixture->env.state_dir, "fixtureapp.selection.saved") &&
                rename(path, saved) == 0;
            if (s->break_selection == 2) s->valid = s->valid && al_write_file(path, "invalid", 0600);
        } else {
            if (s->refresh_changed) memset(selection.version, 2, sizeof(selection.version));
            s->valid = s->valid && app_selection_save(s->change_fixture->env.state_dir,
                selection.revision, &selection, &updated) == APP_SELECTION_OK;
        }
}
static bool al_library_home(struct al_library_script *s, const struct zcl_present_model_v1 *model,
    struct zcl_present_window_event_v1 *event)
{
    s->valid = s->valid && model->action_count == 4 &&
        !strcmp(model->actions[0].id, "myapps") &&
        !strcmp(model->actions[1].id, "discover") &&
        !strcmp(model->actions[2].id, "hosting") &&
        !strcmp(model->actions[3].id, "cancel");
    event->action_index = s->home_calls++ ? 3 : 0;
    return true;
}
static void al_library_share_menu(struct al_library_script *s,
    const struct zcl_present_model_v1 *model, struct zcl_present_window_event_v1 *event)
{
    s->valid = s->valid && model->action_count == 4 &&
        !strcmp(model->actions[0].id, "share-file") &&
        !strcmp(model->actions[1].id, "share-link") &&
        !strcmp(model->actions[2].id, "more-sharing") &&
        !strcmp(model->actions[3].id, "share-back");
    if (s->cancel_preparation && s->preparations) {
        if (!s->canceled_prepare_menu) ++s->canceled_prepare_menu;
        event->action_index = 3;
    } else if (s->second_preparation == 2 && s->preparations >= 2) {
        ++s->canceled_prepare_menu; event->action_index = 3;
    } else if (s->host_calls) event->action_index = 3; /* after one hosting attempt, leave the menu */
    else event->action_index = s->share_cancel && s->share_calls ? 3 : s->share_choice;
}
static void al_library_error_card(struct al_library_script *s,
    const struct zcl_present_model_v1 *model, struct zcl_present_window_event_v1 *event)
{
    s->valid = s->valid && model->action_count == 1 && !strcmp(model->actions[0].id, "close");
    ++s->errors; event->action_index = 0;
    (void)snprintf(s->error_summary, sizeof(s->error_summary), "%s", model->summary);
    (void)snprintf(s->error_title, sizeof(s->error_title), "%s", model->title);
}
static bool al_library_render(const struct zcl_present_model_v1 *model, char *why, size_t cap)
{
    struct zcl_present_model_bitmap_v1 bitmap = {0};
    bool ok = zcl_present_model_validate_v1(model, why, cap) &&
        zcl_present_model_render_v1(model, &bitmap, why, cap) && bitmap.pixels;
    zcl_present_model_bitmap_free_v1(&bitmap); return ok;
}
static bool al_library_fresh_copy_prompt(const struct zcl_present_model_v1 *model)
{
    if (strcmp(model->request_id, "library-help")) return false;
    for (unsigned i = 0; i < model->item_count; ++i)
        if (strstr(model->items[i].value, "Ask your AI to request a copy.")) return true;
    return false;
}
static bool al_cancel_more_back(struct al_library_script *s,
    const struct zcl_present_model_v1 *model, struct zcl_present_window_event_v1 *event)
{
    ++s->canceled_prepare_menu;
    for (unsigned i = 0; i < model->action_count; ++i)
        if (!strcmp(model->actions[i].id, "more-share-back")) {
            event->action_index = i; return true;
        }
    s->valid = false; return false;
}
static bool al_library_special_menu(struct al_library_script *s,
    const struct zcl_present_model_v1 *model,
    struct zcl_present_window_event_v1 *event, bool *handled)
{
    *handled = true;
    if (!strcmp(model->request_id, "library-home")) return al_library_home(s, model, event);
    if (!strcmp(model->request_id, "library-share-options")) {
        al_library_share_menu(s, model, event); return true;
    }
    if (!strcmp(model->request_id, "library-more-share-options") &&
        s->cancel_preparation && s->preparations)
        return al_cancel_more_back(s, model, event);
    if (!strcmp(model->request_id, "library-error")) {
        al_library_error_card(s, model, event); return true;
    }
    *handled = false;
    return true;
}
static bool al_library_present(void *context, const struct zcl_present_model_v1 *model,
    const char *copy_text, struct zcl_present_window_event_v1 *event, char *why, size_t cap)
{
    struct al_library_script *s = context;
    s->valid = s->valid && al_library_render(model, why, cap);
    if (!strcmp(model->request_id, "library-error") && copy_text)
        (void)snprintf(s->error_copy, sizeof(s->error_copy), "%s", copy_text);
    event->struct_size = sizeof(*event); event->abi_version = ZCL_PRESENT_ABI_V1;
    event->outcome = ZCL_PRESENT_WINDOW_ACTION;
    bool handled = false;
    bool routed = al_library_special_menu(s, model, event, &handled);
    if (handled) return routed;
    if (s->fail_after_noop && s->calls == 4) {
        (void)snprintf(why, cap, "Fixture presentation stopped after the no-op.");
        return false;
    }
    if (copy_text) (void)snprintf(s->setup, sizeof(s->setup), "%s", copy_text);
    if (strstr(model->summary, "Review, preview and Keep the prepared draft, then choose Share again."))
        s->saw_share_review = true;
    s->fresh_copy_prompt |= al_library_fresh_copy_prompt(model);
    s->saved_label |= strstr(model->items[0].value, "Saved version") != NULL;
    if (s->refresh_changed && s->calls == 3)
        s->refreshed_card = strstr(model->items[0].value, "020202020202") != NULL;
    s->valid = s->valid && zcl_present_canvas_text_width(model->items[0].value,
        strlen(model->items[0].value), 14u) <= 296u;
    (void)snprintf(s->last_summary, sizeof(s->last_summary), "%s", model->summary);
    if (s->calls >= s->count) { s->valid = false; event->outcome = ZCL_PRESENT_WINDOW_DISMISSED; return true; }
    event->action_index = s->actions[s->calls++];
    if (s->change_fixture && s->calls == s->change_at) al_library_change(s);
    return true;
}
static bool al_selection(struct al_fx *f, const char *name, struct app_selection *saved)
{
    struct app_selection s = {0};
    (void)snprintf(s.app, sizeof(s.app), "%s", name);
    int n = snprintf(s.copy, sizeof(s.copy), "%s/My very long friendly airplane game name shared with friends and family version", f->root);
    if (n < 0 || (size_t)n >= sizeof(s.copy) || strlen(f->root) >= sizeof(s.datadir)) return false;
    if (mkdir(s.copy, 0700) != 0 && errno != EEXIST) return false;
    memcpy(s.datadir, f->root, strlen(f->root) + 1);
    uint8_t *roots[] = {s.fork, s.parent, s.version, s.package, s.env, s.dependencies, s.record, s.image};
    for (size_t i = 0; i < 8; ++i) memset(roots[i], 1, 32);
    return app_selection_save(f->env.state_dir, 0, &s, saved) == APP_SELECTION_OK;
}
/* Drives the un-kept share journey: home -> app list -> card -> Share.
 * Records whether the room shows the share-options page or an error card
 * (the old dead end) or returns to the same app card (the fixed journey). */
struct al_unsaved_share_script {
    unsigned calls;
    bool valid, saw_keep_hint, returned_to_card, saw_share_options, saw_error;
};
static bool al_unsaved_share_has(const struct zcl_present_model_v1 *model, const char *id)
{
    for (unsigned i = 0; i < model->action_count; ++i)
        if (!strcmp(model->actions[i].id, id)) return true;
    return false;
}
/* App list: choose the first app card. */
static bool al_unsaved_share_enter(struct al_unsaved_share_script *s,
    const struct zcl_present_model_v1 *model, struct zcl_present_window_event_v1 *event)
{
    if (s->calls != 1) return false;
    for (unsigned i = 0; i < model->action_count; ++i) {
        if (strcmp(model->actions[i].id, "choose")) continue;
        event->action_index = i; ++s->calls; return true;
    }
    return false;
}
/* App card: press Share and confirm the honest "Keep a version first." hint. */
static bool al_unsaved_share_press(struct al_unsaved_share_script *s,
    const struct zcl_present_model_v1 *model, struct zcl_present_window_event_v1 *event)
{
    if (s->calls != 2) return false;
    for (unsigned i = 0; i < model->action_count; ++i) {
        if (strcmp(model->actions[i].id, "share")) continue;
        s->saw_keep_hint = s->saw_keep_hint ||
            (i < model->item_count && !strcmp(model->items[i].value, "Keep a version first."));
        event->action_index = i; ++s->calls; return true;
    }
    return false;
}
/* After the refused share the room must show this app card again. */
static bool al_unsaved_share_step_back(struct al_unsaved_share_script *s,
    const struct zcl_present_model_v1 *model, struct zcl_present_window_event_v1 *event)
{
    if (s->calls != 3) return false;
    for (unsigned i = 0; i < model->action_count; ++i) {
        if (strcmp(model->actions[i].id, "back")) continue;
        s->returned_to_card = s->returned_to_card || !al_unsaved_share_has(model, "share-file");
        event->action_index = i; ++s->calls; return true;
    }
    return false;
}
static bool al_unsaved_share_home(struct al_unsaved_share_script *s,
    const struct zcl_present_model_v1 *model, struct zcl_present_window_event_v1 *event)
{
    if (strcmp(model->request_id, "library-home")) return false;
    s->valid = s->valid && s->calls == 0 && model->action_count == 4 &&
        !strcmp(model->actions[0].id, "myapps");
    event->action_index = 0; ++s->calls; return true;
}
static bool al_unsaved_share_present(void *context, const struct zcl_present_model_v1 *model,
    const char *copy_text, struct zcl_present_window_event_v1 *event, char *why, size_t cap)
{
    (void)copy_text;
    struct al_unsaved_share_script *s = context;
    s->valid = s->valid && al_library_render(model, why, cap);
    event->struct_size = sizeof(*event); event->abi_version = ZCL_PRESENT_ABI_V1;
    event->outcome = ZCL_PRESENT_WINDOW_ACTION;
    if (!strcmp(model->request_id, "library-error")) {
        s->saw_error = true; event->action_index = 0; return true;
    }
    if (!strcmp(model->request_id, "library-share-options")) {
        s->saw_share_options = true;
        /* Old dead end: take the first share action so the room refuses. */
        s->valid = s->valid && al_unsaved_share_has(model, "share-file");
        event->action_index = 0; return true;
    }
    if (al_unsaved_share_home(s, model, event)) return true;
    if (al_unsaved_share_enter(s, model, event)) return true;
    if (al_unsaved_share_press(s, model, event)) return true;
    if (al_unsaved_share_step_back(s, model, event)) return true;
    /* Journey finished: dismiss on the app list after stepping back. */
    if (s->calls < 4) s->valid = false;
    event->outcome = ZCL_PRESENT_WINDOW_DISMISSED;
    return true;
}
static int al_hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}
static bool al_notice_path_matches(const struct zcl_present_model_v1 *model, const char *path)
{
    char encoded[ZCL_PRESENT_COPY_TEXT_MAX * 4u + 1u]; size_t used = 0;
    for (unsigned i = 0; i < model->item_count; ++i) {
        const char *prefix = i ? "  " : "Path (escaped): ";
        const char *line = model->items[i].value; size_t n = strlen(prefix);
        if (strncmp(line, prefix, n)) return false;
        line += n; n = strlen(line);
        if (n >= sizeof(encoded) - used) return false;
        memcpy(encoded + used, line, n); used += n;
    }
    encoded[used] = 0; const unsigned char *raw = (const unsigned char *)path;
    for (size_t i = 0; i < used;) {
        unsigned char c = (unsigned char)encoded[i++];
        if (c == '\\') {
            if (i >= used) return false;
            if (encoded[i] == '\\') { ++i; c = '\\'; }
            else {
                if (encoded[i++] != 'x' || i + 1 >= used) return false;
                int hi = al_hex_digit(encoded[i++]), lo = al_hex_digit(encoded[i++]);
                if (hi < 0 || lo < 0) return false;
                c = (unsigned char)((hi << 4) | lo);
            }
        }
        if (!*raw || *raw++ != c) return false;
    }
    return *raw == 0;
}

static bool al_notice_refused(const struct al_library_script *s)
{
    return s->fail_share_result || (s->fail_reveal_notice && s->notice_calls == 2);
}
static bool al_recovery_notice(void *context, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_live_view_v1 *live, char *why, size_t cap)
{
    struct al_library_script *s = context; (void)pages; (void)why; (void)cap;
    bool copy = false, destination = false, execution = false;
    for (uint32_t i = 0; i < model->item_count; ++i) {
        copy |= strstr(model->items[i].value, "Copy: saved-copy") != NULL;
        destination |= strstr(model->items[i].value, "Destination: /fixture/received") != NULL;
        execution |= strstr(model->items[i].value, "Execution: The app was started.") != NULL;
    }
    s->saw_recovery = !strcmp(model->request_id, "library-recovery") && copy && destination && execution;
    struct zcl_present_window_event_v1 event = {.outcome = ZCL_PRESENT_WINDOW_ACTION, .action_index = 0};
    bool redraw = false, close = false;
    live->owner.update(live->owner.context, &event, false, &redraw, &close);
    return close;
}
/* The notice runs the real paginated model with an injected native boundary. */
static bool al_library_notice(void *context, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_live_view_v1 *live, char *why, size_t cap)
{
    struct al_library_script *s = context;
    (void)why; (void)cap;
    ++s->notice_calls;
    if (al_notice_refused(s)) return false;
    if (!pages || !pages->pages || !pages->pages[0].copy_text ||
        strcmp(pages->pages[0].copy_text, s->shared) ||
        strcmp(model->request_id, "library-share-result") || !al_notice_path_matches(model, s->shared)) return false;
    (void)snprintf(s->setup, sizeof(s->setup), "%s", pages->pages[0].copy_text);
    bool redraw = false, close = false;
    struct zcl_present_window_event_v1 event = {0};
    if (s->reveal_request && s->notice_calls == 1) {
        uint32_t count = 0;
        if (!zcl_present_model_page_count_v1(model, &count, why, cap)) return false;
        event.outcome = ZCL_PRESENT_WINDOW_ACTION;
        event.action_index = 3;
        live->owner.update(live->owner.context, &event, false, &redraw, &close);
        if (count > 1 && close) return false;
        for (uint32_t i = 1; i < count; ++i) {
            event.action_index = 2;
            live->owner.update(live->owner.context, &event, false, &redraw, &close);
        }
        event.action_index = 3;
        live->owner.update(live->owner.context, &event, false, &redraw, &close);
    } else live->owner.update(live->owner.context, &event, true, &redraw, &close);
    return close;
}

static void al_library_share(void *context, const struct app_selection *selection,
    const char *path, struct zcl_command_reply *reply)
{
    struct al_library_script *s = context; ++s->share_calls; s->shared_revision = selection->revision;
    memcpy(s->shared_version, selection->version, sizeof(s->shared_version));
    s->valid = s->valid && selection->revision > 0 && path[0] == 47;
    (void)snprintf(s->shared, sizeof(s->shared), "%s", path);
    if (s->share_cancel) { (void)json_push_kv_str(&reply->data, "status", "canceled"); return; }
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0 || close(fd)) { s->valid = false; return; }
    if (s->fail_after_file) {
        /* The real leaf shape: the file exists at the planned path, then the
         * reply fails (SHARE_RESULT_MISMATCH), with no share_file key. */
        zcl_package_copy_fail(reply, "SHARE_RESULT_MISMATCH", true,
            "The local share was created but its result could not be verified.", path);
        return;
    }
    if (s->mismatch_share_result) {
        /* The file exists at the requested path, but the result names another. */
        char other[ZCL_PRESENT_COPY_TEXT_MAX + 8];
        int n = snprintf(other, sizeof(other), "%s.mismatch", path);
        s->valid = s->valid && n > 0 && (size_t)n < sizeof(other) &&
            json_push_kv_str(&reply->data, "share_file", other);
        reply->error.mutated = true;
        return;
    }
    s->valid = s->valid && json_push_kv_str(&reply->data, "share_file", path);
    reply->error.mutated = true;
}
static bool al_fake_reveal(void *context, const char *path)
{
    struct al_library_script *s = context; ++s->reveal_calls;
    (void)snprintf(s->revealed, sizeof(s->revealed), "%s", path);
    return !s->reveal_fail;
}
/* Share-link host stand-in: completes, cancels, or fails the hosting reply. */
static void al_library_host(void *context, const struct app_selection *selection, const char *exe,
    app_confirm_presenter notice, struct zcl_command_reply *reply)
{
    struct al_library_script *s = context;
    (void)notice; ++s->host_calls;
    s->valid = s->valid && selection->revision > 0 && exe && exe[0] == '/';
    if (s->cancel_host) { s->valid = s->valid && json_push_kv_str(&reply->data, "status", "canceled"); return; }
    s->valid = s->valid && json_push_kv_str(&reply->data, "host_status", "stopped") &&
        json_push_kv_bool(&reply->data, "was_available", true);
}
#if defined(__APPLE__) || defined(__linux__)
static bool al_check_reveal_argv(void *context, const char *image, const char *const *argv)
{
    const char *path = context;
#if defined(__APPLE__)
    return !strcmp(image, "/usr/bin/open") && !strcmp(argv[1], "-R") &&
        !strcmp(argv[2], path) && !argv[3];
#else
    return !strcmp(image, "/usr/bin/gio") && !strcmp(argv[1], "open") &&
        !strcmp(argv[2], "/fixture/space \x27\xC3\xA9") && !argv[3] &&
        !strcmp(path, "/fixture/space \x27\xC3\xA9/file.z23share");
#endif
}
#endif
static int al_reveal_tests(struct al_fx *f, struct zcl_command_reply *reply)
{
    int failures = 0;
#if defined(__APPLE__) || defined(__linux__)
    TEST("Reveal uses one exact fixed-opener argument and refuses relative paths") {
        const char *path = "/fixture/space \x27\xC3\xA9/file.z23share";
        ASSERT(zcl_test_app_share_reveal(path, al_check_reveal_argv, (void *)path));
        ASSERT(!zcl_test_app_share_reveal("relative/file", al_check_reveal_argv, (void *)path));
        PASS();
    }
    TEST("Unavailable and failing opener processes report failure") {
        const char *missing[] = {"/missing-z23-opener", NULL};
        const char *failed[] = {"/usr/bin/false", NULL};
        ASSERT(!zcl_test_app_share_reveal_run(missing[0], missing));
        ASSERT(!zcl_test_app_share_reveal_run(failed[0], failed));
        PASS();
    }
    TEST("Only the final notice action reveals; failed reveal retains file and facts") {
        for (unsigned mode = 0; mode < 4; ++mode) {
            zcl_command_reply_free(reply); zcl_command_reply_init(reply, "zcl.app_open.v1");
            struct al_library_script s = {.actions = {0, 2}, .count = 2, .valid = true,
                .reveal_request = mode != 0, .reveal_fail = mode >= 2, .fail_reveal_notice = mode == 3};
            zcl_test_app_library_reveal(&f->env, reply, al_library_present, &s,
                al_library_prepared_same, al_library_share, al_library_notice, al_fake_reveal);
            ASSERT(s.valid && s.share_calls == 1 && s.reveal_calls == (mode ? 1u : 0u));
            ASSERT(access(s.shared, F_OK) == 0 && reply->error.mutated);
            if (mode) ASSERT(!strcmp(s.shared, s.revealed));
            if (mode >= 2) {
                ASSERT(!strcmp(reply->error.code, "REVEAL_FAILED") && s.notice_calls == 2);
                ASSERT(s.errors == (mode == 3 ? 1u : 0u));
                ASSERT(!strcmp(zcl_package_copy_str(json_get(&reply->data, "failure_facts"), "output"), s.shared));
                if (mode == 3) {
                    ASSERT(!strcmp(s.error_title, "Share file created"));
                    ASSERT(!strcmp(s.error_copy, s.shared));
                }
            }
            ASSERT(unlink(s.shared) == 0);
        }
        PASS();
    } _test_next:;
#else
    (void)f; (void)reply;
#endif
    return failures;
}

struct al_host_nav { unsigned step; bool valid; };
static char *al_host_empty_rpc(const char *method, const char *params)
{
    if (strcmp(method, "fleet_board") || !strstr(params, "app_host_list")) return NULL;
    return strdup("{\"ok\":true,\"items\":[],\"more\":false}");
}
static bool al_host_present(void *context, const struct zcl_present_model_v1 *model,
    const char *copy, struct zcl_present_window_event_v1 *event, char *why, size_t cap)
{
    (void)copy; (void)why; (void)cap; struct al_host_nav *s = context;
    event->struct_size = sizeof(*event); event->abi_version = ZCL_PRESENT_ABI_V1;
    event->outcome = ZCL_PRESENT_WINDOW_ACTION;
    const char *wanted = s->step == 0 ? "hosting" : s->step == 1 ? "back" : "cancel";
    s->valid &= !strcmp(model->request_id, s->step == 1 ? "hosting-browser" : "library-home");
    ++s->step;
    for (unsigned i = 0; i < model->action_count; ++i)
        if (!strcmp(model->actions[i].id, wanted)) { event->action_index = i; return true; }
    s->valid = false; return false;
}
static int case_library(struct al_fx *f)
{
    int failures = 0;
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.app_open.v1");
    TEST("My Apps opens the empty local hosting browser and returns home") {
        struct al_host_nav nav = {.valid = true};
        node_rpc_client_set_test_hook(al_host_empty_rpc);
        zcl_test_app_library_run(&f->env, &reply, al_host_present, &nav);
        node_rpc_client_set_test_hook(NULL);
        ASSERT(nav.valid && nav.step == 3 && reply.status == ZCL_COMMAND_STATUS_PASSED && !reply.error.mutated);
        zcl_command_reply_free(&reply); zcl_command_reply_init(&reply, "zcl.app_open.v1");
        PASS();
    }
    TEST("My Apps navigation and cancellation never execute; forged events refuse") {
        struct al_library_script s = {.actions = {2, 1, 3}, .count = 3, .valid = true};
        zcl_test_app_library_run(&f->env, &reply, al_library_present, &s);
        ASSERT(s.valid && s.calls == 3 && s.errors == 0);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "status")), "canceled");
        zcl_command_reply_free(&reply); zcl_command_reply_init(&reply, "zcl.app_open.v1");
        s = (struct al_library_script){.actions = {99}, .count = 1, .valid = true};
        zcl_test_app_library_run(&f->env, &reply, al_library_present, &s);
        ASSERT(s.valid && s.calls == 1 && s.errors == 1);
        ASSERT_STR_EQ(reply.error.code, "INVALID_SELECTION");
        ASSERT(!json_get(&reply.data, "pid"));
    PASS(); }
    TEST("Share on an un-kept app stays on its card instead of ejecting the user") {
        struct app_selection unused;
        ASSERT(app_selection_load(f->env.state_dir, "fixtureapp", &unused) != APP_SELECTION_OK);
        zcl_command_reply_free(&reply); zcl_command_reply_init(&reply, "zcl.app_open.v1");
        struct al_unsaved_share_script s = {.valid = true};
        zcl_test_app_library_run(&f->env, &reply, al_unsaved_share_present, &s);
        ASSERT(s.valid && s.saw_keep_hint && s.returned_to_card);
        ASSERT(!s.saw_share_options && !s.saw_error);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED && !reply.error.mutated);
        ASSERT(reply.error.code[0] == '\0');
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "status")), "canceled");
        zcl_command_reply_free(&reply); zcl_command_reply_init(&reply, "zcl.app_open.v1");
    PASS(); }
    TEST("My Apps absent snapshot refuses a concurrent Keep, including catalog IDs") {
        struct app_selection saved;
        const struct app_launch_entry *e = app_launch_registry_find(&f->reg, "fixtureapp");
        ASSERT(e && al_selection(f, e->id, &saved));
        zcl_command_reply_free(&reply); zcl_command_reply_init(&reply, "zcl.app_open.v1");
        zcl_native_app_open_snapshot(&f->env, e, NULL, &reply);
        ASSERT_STR_EQ(reply.error.code, "SELECTION_STALE");
        ASSERT(!json_get(&reply.data, "pid"));
        zcl_command_reply_free(&reply); zcl_command_reply_init(&reply, "zcl.app_open.v1");
        struct al_library_script s = {.actions = {3}, .count = 1, .valid = true};
        zcl_test_app_library_run(&f->env, &reply, al_library_present, &s);
        ASSERT(s.valid && s.saved_label && !s.errors);
        struct app_selection newer;
        ASSERT(app_selection_save(f->env.state_dir, saved.revision, &saved, &newer) == APP_SELECTION_OK);
        zcl_command_reply_free(&reply); zcl_command_reply_init(&reply, "zcl.app_open.v1");
        zcl_native_app_open_snapshot(&f->env, e, &saved, &reply);
        ASSERT_STR_EQ(reply.error.code, "SELECTION_STALE");
        saved.revision = (uint64_t)INT64_MAX + 1u;
        zcl_command_reply_free(&reply); zcl_command_reply_init(&reply, "zcl.app_open.v1");
        zcl_native_app_open_snapshot(&f->env, e, &saved, &reply);
        ASSERT_STR_EQ(reply.error.code, "SELECTION_UNREADABLE");
        ASSERT(!json_get(&reply.data, "pid"));
    PASS(); }
_test_next:;
    zcl_command_reply_free(&reply);
    return failures;
}

static bool al_share_snapshot_stale(struct al_fx *f, const char *home)
{
    char root[PATH_MAX], state[PATH_MAX], output[PATH_MAX];
    const char *prior = getenv("XDG_STATE_HOME"); char *old = prior ? strdup(prior) : NULL;
    if (prior && !old) return false;
    struct app_selection kept, altered;
    bool ok = realpath(f->root, root) && al_path(state, sizeof(state), root, "state") &&
        al_path(output, sizeof(output), home, "must-not-exist.z23share") &&
        app_selection_load(f->env.state_dir, "fixtureapp", &kept) == APP_SELECTION_OK &&
        setenv("XDG_STATE_HOME", state, 1) == 0;
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_share.v1");
    if (ok) { altered = kept; altered.image[0] ^= 1; zcl_native_app_share_snapshot("fixtureapp", output, &reply, &altered); }
    ok = ok && !strcmp(reply.error.code, "SELECTION_STALE") && !reply.error.mutated && access(output, F_OK) != 0;
    if (old) { (void)setenv("XDG_STATE_HOME", old, 1); free(old); } else (void)unsetenv("XDG_STATE_HOME");
    zcl_command_reply_free(&reply); return ok;
}

static int al_share_success_test(struct al_fx *f, struct zcl_command_reply *reply,
    struct al_library_script *s, const struct app_selection *before)
{
    int failures = 0; struct app_selection after;
    TEST("Share shows and copies the complete long UTF-8 escaped path") {
        zcl_command_reply_free(reply); zcl_command_reply_init(reply, "zcl.app_open.v1");
        *s = (struct al_library_script){.actions = {0, 2}, .count = 2, .valid = true};
        zcl_test_app_library_share(&f->env, reply, al_library_present, s, al_library_prepared_same, al_library_share, al_library_notice);
        ASSERT(s->valid && s->share_calls == 1 && reply->error.mutated && strlen(s->shared) > 105);
        ASSERT(!strcmp(s->shared, s->setup) && access(s->shared, F_OK) == 0);
        ASSERT(app_selection_load(f->env.state_dir, "fixtureapp", &after) == APP_SELECTION_OK);
        ASSERT(!memcmp(before, &after, sizeof(after)));
        ASSERT(unlink(s->shared) == 0); s->shared[0] = 0;
        PASS();
    } _test_next:;
    return failures;
}
static int al_share_leaf_failure_test(struct al_fx *f, struct zcl_command_reply *reply,
    struct al_library_script *s);
static int al_share_failure_test(struct al_fx *f, struct zcl_command_reply *reply,
    struct al_library_script *s, const char *home)
{
    int failures = 0;
    TEST("Share preserves output facts after result presentation fails") {
        zcl_command_reply_free(reply); zcl_command_reply_init(reply, "zcl.app_open.v1");
        *s = (struct al_library_script){.actions = {0, 2}, .count = 2, .valid = true, .fail_share_result = true};
        zcl_test_app_library_share(&f->env, reply, al_library_present, s, al_library_prepared_same, al_library_share, al_library_notice);
        ASSERT(reply->error.mutated && !strcmp(reply->error.code, "PRESENTATION_FAILED"));
        ASSERT(s->valid && s->errors == 1 && s->share_calls == 1);
        ASSERT(!strcmp(s->error_title, "Share file created") && !strcmp(s->error_copy, s->shared));
        const char *output = zcl_package_copy_str(json_get(&reply->data, "failure_facts"), "output");
        ASSERT(output && !strcmp(output, s->shared));
        ASSERT(unlink(s->shared) == 0); s->shared[0] = 0;
        ASSERT(al_share_snapshot_stale(f, home));
        PASS();
    }
    TEST("Share retains the file location when the result names another file") {
        zcl_command_reply_free(reply); zcl_command_reply_init(reply, "zcl.app_open.v1");
        *s = (struct al_library_script){.actions = {0, 2}, .count = 2, .valid = true, .mismatch_share_result = true};
        zcl_test_app_library_share(&f->env, reply, al_library_present, s, al_library_prepared_same, al_library_share, al_library_notice);
        ASSERT(reply->error.mutated && !strcmp(reply->error.code, "SHARE_RESULT_MISMATCH"));
        ASSERT(s->valid && s->errors == 1 && s->share_calls == 1);
        ASSERT(access(s->shared, F_OK) == 0);
        ASSERT(!strcmp(s->error_title, "Share file created") && !strcmp(s->error_copy, s->shared));
        const char *output = zcl_package_copy_str(json_get(&reply->data, "failure_facts"), "output");
        ASSERT(output && !strcmp(output, s->shared));
        ASSERT(unlink(s->shared) == 0); s->shared[0] = 0;
        PASS();
    } _test_next:;
    failures += al_share_leaf_failure_test(f, reply, s);
    return failures;
}
static int al_share_leaf_failure_test(struct al_fx *f, struct zcl_command_reply *reply,
    struct al_library_script *s)
{
    int failures = 0;
    TEST("Share keeps the card location when the leaf fails after creating the file") {
        zcl_command_reply_free(reply); zcl_command_reply_init(reply, "zcl.app_open.v1");
        *s = (struct al_library_script){.actions = {0, 2}, .count = 2, .valid = true, .fail_after_file = true};
        zcl_test_app_library_share(&f->env, reply, al_library_present, s, al_library_prepared_same, al_library_share, al_library_notice);
        ASSERT(reply->status != ZCL_COMMAND_STATUS_PASSED);
        ASSERT(reply->error.mutated && !strcmp(reply->error.code, "SHARE_RESULT_MISMATCH"));
        ASSERT(s->valid && s->errors == 1 && s->share_calls == 1 && s->notice_calls == 0);
        ASSERT(access(s->shared, F_OK) == 0);
        ASSERT(!strcmp(s->error_title, "Share file created") && !strcmp(s->error_copy, s->shared));
        const char *output = zcl_package_copy_str(json_get(&reply->data, "failure_facts"), "output");
        ASSERT(output && !strcmp(output, s->shared));
        ASSERT(unlink(s->shared) == 0); s->shared[0] = 0;
        PASS();
    } _test_next:;
    return failures;
}
static int al_share_refusal_test(struct al_fx *f, struct zcl_command_reply *reply,
    struct al_library_script *s, const char *root, const char *home, char invalid[PATH_MAX], bool *made)
{
    int failures = 0;
    TEST("Share refuses invalid UTF-8 and a stale library choice before sharing") {
        int n = snprintf(invalid, PATH_MAX, "%s/%c", root, 255);
        ASSERT(n > 0 && n < PATH_MAX);
        int created = mkdir(invalid, 0700);
        /* Some filesystems reject invalid UTF-8 before it can name a home. */
        ASSERT(created == 0 || errno == EILSEQ); *made = created == 0;
        const char *expected = *made ? "PATH_UNDISPLAYABLE" : "HOME_UNAVAILABLE";
        ASSERT(setenv("HOME", invalid, 1) == 0);
        zcl_command_reply_free(reply); zcl_command_reply_init(reply, "zcl.app_open.v1");
        *s = (struct al_library_script){.actions = {0, 2}, .count = 2, .valid = true};
        zcl_test_app_library_share(&f->env, reply, al_library_present, s, al_library_prepared_same, al_library_share, al_library_notice);
        ASSERT(!strcmp(reply->error.code, expected) && !reply->error.mutated && !s->share_calls);
        ASSERT(setenv("HOME", home, 1) == 0);
        zcl_command_reply_free(reply); zcl_command_reply_init(reply, "zcl.app_open.v1");
        *s = (struct al_library_script){.actions = {0, 2}, .count = 2, .valid = true, .change_fixture = f, .change_at = 2};
        zcl_test_app_library_share(&f->env, reply, al_library_present, s, al_library_prepared_same, al_library_share, al_library_notice);
        ASSERT(!strcmp(reply->error.code, "SELECTION_STALE") && s->share_calls == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int al_share_followups(struct al_fx *f, struct zcl_command_reply *reply,
    struct al_library_script *s, const struct app_selection *before,
    const char *root, const char *home, char invalid[PATH_MAX], bool *made)
{
    int failures = al_share_success_test(f, reply, s, before);
    if (!failures) failures += al_share_failure_test(f, reply, s, home);
    if (!failures) failures += al_share_refusal_test(f, reply, s, root, home, invalid, made);
    return failures;
}
static int al_host_link_test(struct al_fx *f, struct zcl_command_reply *reply)
{
    int failures = 0;
    TEST("A completed share-link ends the room with its receipt intact") {
        zcl_command_reply_free(reply); zcl_command_reply_init(reply, "zcl.app_open.v1");
        struct al_library_script s = {.actions = {0, 2}, .count = 2, .valid = true, .share_choice = 1};
        zcl_test_app_library_host(&f->env, reply, al_library_present, &s,
            al_library_prepared_same, NULL, NULL, al_library_host);
        ASSERT(s.valid && s.errors == 0 && s.host_calls == 1);
        ASSERT(reply->status == ZCL_COMMAND_STATUS_PASSED && !reply->error.mutated);
        ASSERT(!strcmp(json_get_str(json_get(&reply->data, "host_status")), "stopped"));
        ASSERT(json_get_bool(json_get(&reply->data, "was_available")));
        ASSERT(!json_get(&reply->data, "status"));
        PASS();
    }
    TEST("A canceled share-link keeps the room open for more sharing") {
        zcl_command_reply_free(reply); zcl_command_reply_init(reply, "zcl.app_open.v1");
        struct al_library_script s = {.actions = {0, 2, 3, 3}, .count = 4, .valid = true,
            .share_choice = 1, .cancel_host = true};
        zcl_test_app_library_host(&f->env, reply, al_library_present, &s,
            al_library_prepared_same, NULL, NULL, al_library_host);
        ASSERT(s.valid && s.errors == 0 && s.host_calls == 1);
        ASSERT(reply->status == ZCL_COMMAND_STATUS_PASSED && !reply->error.mutated);
        ASSERT_STR_EQ(json_get_str(json_get(&reply->data, "status")), "canceled");
        PASS();
    } _test_next:;
    return failures;
}

static int al_refresh_share_test(struct al_fx *f, struct zcl_command_reply *reply,
    const char *home)
{
    int failures = 0;
    TEST("AI help Back refreshes a newer Keep before a separate Share") {
        struct app_selection before;
        ASSERT(app_selection_load(f->env.state_dir, "fixtureapp", &before) == APP_SELECTION_OK);
        ASSERT(setenv("HOME", home, 1) == 0);
        struct al_library_script s = {.actions = {0, 1, 2, 0, 2, 3, 3}, .count = 7, .valid = true,
            .change_fixture = f, .change_at = 3, .refresh_changed = true, .share_cancel = true,
            .second_preparation = 1};
        zcl_test_app_library_refresh(&f->env, reply, al_library_present, &s,
            al_library_prepare, al_library_share, al_library_notice);
        ASSERT(s.valid && s.refreshed_card && s.share_calls == 1);
        ASSERT(s.shared_revision == before.revision + 1);
        ASSERT(reply->error.mutated && access(s.shared, F_OK) != 0);
        const struct json_value *prep = json_get(&reply->data, "preparation");
        ASSERT(prep && !strcmp(json_get_str(json_get(prep, "copy")), before.copy));
        ASSERT(json_get_bool(json_get(prep, "changed")));
        PASS();
    } _test_next:;
    return failures;
}

static int al_refresh_refusal_test(struct al_fx *f, struct zcl_command_reply *reply)
{
    int failures = 0;
    TEST("AI help Back refuses removed or unreadable saved choices") {
        char path[PATH_MAX], saved[PATH_MAX];
        ASSERT(al_path(path, sizeof(path), f->env.state_dir, "fixtureapp.selection"));
        ASSERT(al_path(saved, sizeof(saved), f->env.state_dir, "fixtureapp.selection.saved"));
        for (unsigned mode = 1; mode <= 2; ++mode) {
            zcl_command_reply_free(reply); zcl_command_reply_init(reply, "zcl.app_open.v1");
            struct al_library_script s = {.actions = {0, 1, 2}, .count = 3, .valid = true,
                .change_fixture = f, .change_at = 3, .break_selection = mode};
            zcl_test_app_library_refresh(&f->env, reply, al_library_present, &s,
                al_library_prepare, al_library_share, al_library_notice);
            ASSERT(s.valid && s.errors == 1 && s.share_calls == 0);
            ASSERT(!strcmp(reply->error.code, mode == 1 ? "SELECTION_UNAVAILABLE" : "SELECTION_UNREADABLE"));
            if (mode == 2) ASSERT(unlink(path) == 0);
            ASSERT(rename(saved, path) == 0);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int al_refresh_checks(struct al_fx *f, struct zcl_command_reply *reply, const char *home)
{
    zcl_command_reply_free(reply); zcl_command_reply_init(reply, "zcl.app_open.v1");
    int failures = al_refresh_share_test(f, reply, home);
    if (!failures) failures += al_refresh_refusal_test(f, reply);
    if (!failures) failures += al_reveal_tests(f, reply);
    return failures;
}

static bool al_share_canceled_snapshot(const struct al_library_script *s,
    const struct app_selection *before, const struct app_selection *after,
    const struct zcl_command_reply *reply)
{
    return s->valid && s->preparations == 1 && s->share_calls == 1 && access(s->shared, F_OK) != 0 &&
        s->shared_revision == before->revision && !memcmp(s->shared_version, before->version, 32) &&
        !reply->error.mutated && !memcmp(before, after, sizeof(*before)) && strstr(s->shared, "-1.z23share");
}
static int case_library_share(struct al_fx *f)
{
    int failures = 0; char root[PATH_MAX] = {0}, home[PATH_MAX] = {0}, occupied[PATH_MAX] = {0}, invalid[PATH_MAX] = {0};
    bool made_root = false, made_home = false, made_invalid = false;
    struct app_selection before, after;
    const char *prior = getenv("HOME"); char *old = prior ? strdup(prior) : NULL;
    if (prior && !old) return 1;
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_open.v1");
    struct al_library_script s = {.actions = {0, 2, 3, 3}, .count = 4, .valid = true, .share_cancel = true};
    TEST("My Apps share cancellation and collision preserve selected version") {
        ASSERT(test_mkdtemp(root, sizeof(root), "app_share")); made_root = true;
        char part[120]; memset(part, 97, 110); memcpy(part + 110, " \xc3\xa9\\\n", 6);
        ASSERT(al_path(home, sizeof(home), root, part)); ASSERT(mkdir(home, 0700) == 0); made_home = true;
        ASSERT(setenv("HOME", home, 1) == 0);
        ASSERT(app_selection_load(f->env.state_dir, "fixtureapp", &before) == APP_SELECTION_OK);
        int n = snprintf(occupied, sizeof(occupied), "%s/z23-share-010101010101-0.z23share", home);
        ASSERT(n > 0 && (size_t)n < sizeof(occupied));
        ASSERT(al_write_file(occupied, "occupied", 0600));
        zcl_test_app_library_share(&f->env, &reply, al_library_present, &s, al_library_prepared_same, al_library_share, al_library_notice);
        ASSERT(app_selection_load(f->env.state_dir, "fixtureapp", &after) == APP_SELECTION_OK);
        ASSERT(al_share_canceled_snapshot(&s, &before, &after, &reply));
        PASS();
    } _test_next:;
    if (!failures) failures += al_share_followups(f, &reply, &s, &before, root, home, invalid, &made_invalid);
    if (!failures) failures += al_host_link_test(f, &reply);
    if (!failures) failures += al_refresh_checks(f, &reply, home);
    if (s.shared[0]) (void)unlink(s.shared);
    if (occupied[0]) (void)unlink(occupied);
    if (made_home) (void)rmdir(home);
    if (made_invalid) (void)rmdir(invalid);
    if (made_root) (void)rmdir(root);
    if (old) { (void)setenv("HOME", old, 1); free(old); } else (void)unsetenv("HOME");
    zcl_command_reply_free(&reply); return failures;
}
static bool al_library_catalog(struct al_fx *f, unsigned count)
{
    char text[16384], name[33]; size_t at = 0;
    if (count > 16) return false;
    for (unsigned i = 0; i < count; ++i) {
        (void)snprintf(name, sizeof(name), "app-%02u", i);
        at += (size_t)al_row(text + at, sizeof(text) - at, name, "-", f->bin_ready, "-", "ready", f->raised);
    }
    return at < sizeof(text) && al_write_file(f->env.config_path, text, 0600);
}
struct al_create_view { unsigned step, count; bool valid; };
static int al_create_action(const struct zcl_present_model_v1 *m, const char *id, const char *label)
{
    for (unsigned i = 0; i < m->action_count; ++i)
        if (!strcmp(m->actions[i].id, id) && (!label || !strcmp(m->actions[i].label, label))) return (int)i;
    return -1;
}
static const char *al_create_first_card(struct al_create_view *s,
    const struct zcl_present_model_v1 *m)
{
    if (!s->count) {
        s->valid = al_create_action(m, "create", "Create from Sky Combat") >= 0 &&
            al_create_action(m, "home", "Back") >= 0;
        return "home";
    }
    s->valid = al_create_action(m, "next", "Next app") >= 0 &&
        al_create_action(m, "create", NULL) < 0;
    return "next";
}
static bool al_create_last_card(const struct zcl_present_model_v1 *m)
{
    return al_create_action(m, "create", "Create from Sky Combat") >= 0 &&
        al_create_action(m, "next", NULL) < 0 && al_create_action(m, "home", "Back") >= 0;
}
static const char *al_create_view_action(struct al_create_view *s,
    const struct zcl_present_model_v1 *m)
{
    if (s->step == 0 && !strcmp(m->request_id, "library-home")) return "myapps";
    if (s->step == 1 && !strcmp(m->request_id, "library-0")) return al_create_first_card(s, m);
    if (s->count && s->step == 2 && !strcmp(m->request_id, "library-1")) {
        s->valid = s->valid && al_create_last_card(m);
        return "home";
    }
    if (s->step == (s->count ? 3u : 2u) && !strcmp(m->request_id, "library-home")) return "cancel";
    return NULL;
}
static bool al_create_view_present(void *context, const struct zcl_present_model_v1 *m,
    const char *copy, struct zcl_present_window_event_v1 *event, char *why, size_t cap)
{
    struct al_create_view *s = context; (void)copy;
    if (!zcl_present_model_validate_v1(m, why, cap) || m->action_count > 4) return false;
    const char *action = al_create_view_action(s, m);
    if (!action) return false;
    int i = al_create_action(m, action, NULL); if (i < 0) return false;
    ++s->step; event->struct_size = sizeof(*event); event->abi_version = ZCL_PRESENT_ABI_V1;
    event->outcome = ZCL_PRESENT_WINDOW_ACTION; event->action_index = (unsigned)i; return true;
}
static int case_library_create_view(void)
{
    int failures = 0; static struct al_fx f; struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.app_open.v1");
    TEST("My Apps offers creation in empty and terminal views") {
        ASSERT(al_setup(&f)); ASSERT(al_write_file(f.env.config_path, "", 0600));
        struct al_create_view view = {.valid = true};
        zcl_test_app_library_run(&f.env, &reply, al_create_view_present, &view);
        ASSERT(view.valid && view.step == 3 && reply.status == ZCL_COMMAND_STATUS_PASSED && !reply.error.mutated);
        ASSERT(al_library_catalog(&f, 2));
        zcl_command_reply_free(&reply); zcl_command_reply_init(&reply, "zcl.app_open.v1");
        view = (struct al_create_view){.count = 2, .valid = true};
        zcl_test_app_library_run(&f.env, &reply, al_create_view_present, &view);
        ASSERT(view.valid && view.step == 4 && reply.status == ZCL_COMMAND_STATUS_PASSED && !reply.error.mutated);
        PASS();
    } _test_next:;
    zcl_command_reply_free(&reply); return failures;
}

struct al_create_fixture {
    struct al_fx *f; unsigned step, calls, mode, preparations, recovery_notices; bool valid, saw_kept;
    struct app_selection saved;
};
static bool al_create_notice(void *context, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *pages, const struct zcl_present_window_live_view_v1 *live,
    char *why, size_t cap)
{
    (void)context; (void)model; (void)pages; (void)live; (void)why; (void)cap; return false;
}
static bool al_create_facts(struct al_create_fixture *s, struct zcl_command_reply *r)
{
    char hex[65]; memset(hex, 'a', 64); hex[64] = 0;
    char long_copy[ZCL_PRESENT_COPY_TEXT_MAX + 2];
    memset(long_copy, 'x', sizeof(long_copy) - 1); long_copy[0] = '/'; long_copy[sizeof(long_copy) - 1] = 0;
    const char *copy = s->mode == 14 ? "relative-copy" : s->mode == 15 ? long_copy : s->f->root;
    return json_push_kv_str(&r->data, "copy", copy) &&
        json_push_kv_str(&r->data, "release_root", hex) &&
        json_push_kv_str(&r->data, "package_root", hex) &&
        json_push_kv_str(&r->data, "version", hex);
}
static bool al_create_kept(struct al_create_fixture *s, struct zcl_command_reply *r)
{
    if (!al_selection(s->f, "skycombat", &s->saved)) return false;
    char version[65], image[65], record[65];
    zcl_hex_encode(s->saved.version, 32, version); zcl_hex_encode(s->saved.image, 32, image);
    zcl_hex_encode(s->saved.record, 32, record);
    struct json_value kept; json_init(&kept); json_set_object(&kept);
    bool ok = json_push_kv_str(&kept, "name", s->mode == 4 ? "wrong" : "skycombat") &&
        json_push_kv_int(&kept, "selection_revision", (int64_t)s->saved.revision) &&
        json_push_kv_str(&kept, "version", version) && json_push_kv_str(&kept, "image_sha3", image) &&
        json_push_kv_str(&kept, "record_id", record) && json_push_kv(&r->data, "kept", &kept) &&
        json_push_kv_str(&r->data, "continuation", "kept");
    json_free(&kept); return ok;
}
static bool al_create_request_valid(const struct al_create_fixture *s,
    const struct zcl_command_request *request, app_confirm_presenter presenter)
{
    const char *name = json_get_str(json_get(request->input, "name"));
    const char *datadir = json_get_str(json_get(request->input, "datadir"));
    return name && !strcmp(name, "skycombat") && datadir &&
        !strcmp(datadir, s->f->root) && presenter == al_create_notice &&
        request->success_data_budget_provided && request->success_data_budget > 0;
}
static bool al_create_operations(struct zcl_command_reply *r)
{
    struct json_value items, row; json_init(&items); json_set_array(&items);
    json_init(&row); json_set_object(&row);
    bool ok = json_push_kv_str(&row, "stage", "preview") &&
        json_push_kv_bool(&row, "progress_displayed", true) &&
        json_push_kv_bool(&row, "close_notice_failed", true) &&
        json_push_back(&items, &row) && json_push_kv(&r->data, "operations", &items);
    json_free(&row); json_free(&items); return ok;
}
static bool al_create_progress_mode(unsigned mode)
{
    return mode == 10 || mode == 12 || mode == 13 || mode == 14 || mode == 15;
}
static bool al_create_continuation_data(struct zcl_command_reply *r, unsigned mode)
{
    if (!json_push_kv_bool(&r->data, "continuation_executed", false)) return false;
    if (mode == 9 && !al_create_operations(r)) return false;
    if (al_create_progress_mode(mode)) return json_push_kv_str(&r->data, "continuation", "adopted") &&
        json_push_kv_bool(&r->data, "copy_progress_ui_failed", true);
    struct json_value error; json_init(&error); json_set_object(&error);
    bool ok = json_push_kv_str(&error, "code", "PREVIEW_CLEANUP_FAILED") &&
        json_push_kv_str(&error, "message_excerpt", "Cleanup failed") &&
        json_push_kv_bool(&error, "copy_retained", true) &&
        json_push_kv_bool(&error, "automatic_retry", false) &&
        json_push_kv_str(&error, "retained_scratch", "/fixture/private-scratch") &&
        json_push_kv_str(&r->data, "continuation", "failed") &&
        json_push_kv(&r->data, "continuation_error", &error);
    json_free(&error); return ok;
}
static void al_create_committed(struct al_create_fixture *s, struct zcl_command_reply *r)
{
    s->valid = s->valid && al_create_facts(s, r); r->error.mutated = true;
    if (s->mode == 9 || al_create_progress_mode(s->mode)) {
        s->valid = s->valid && al_create_continuation_data(r, s->mode); return;
    }
    if (s->mode == 7) {
        zcl_package_copy_fail(r, "CONTINUATION_FAILED", true, "Continuation failed.", "fixture"); return;
    }
    if (s->mode == 1 || s->mode == 4) s->valid = s->valid && al_create_kept(s, r);
    else s->valid = s->valid && json_push_kv_str(&r->data, "continuation", s->mode == 8 ? "copied" : "previewed");
}
static void al_create_adopt(const struct zcl_command_request *request, struct zcl_command_reply *r,
    app_confirm_presenter presenter, void *context)
{
    struct al_create_fixture *s = context; ++s->calls;
    s->valid = s->valid && al_create_request_valid(s, request, presenter);
    if (s->calls == 2) {
        zcl_package_copy_fail(r, "FOLLOWUP_FAILED", true, "Later copy failed.", "later-copy"); return;
    }
    if (s->mode == 0) { s->valid = s->valid && json_push_kv_str(&r->data, "status", "canceled"); return; }
    if (s->mode == 3) { zcl_package_copy_fail(r, "TEMPLATE_UNAVAILABLE", false, "Template unavailable.", "fixture"); return; }
    al_create_committed(s, r);
}
static const char *al_create_history_action(struct al_create_fixture *s, const struct zcl_present_model_v1 *m);
static bool al_create_replacement(const struct al_create_fixture *s)
{
    return (s->mode == 9 || s->mode == 10) && s->calls == 1;
}
static const char *al_create_flow_action(struct al_create_fixture *s, const struct zcl_present_model_v1 *m)
{
    if (s->mode == 11) return al_create_history_action(s, m);
    if (!strcmp(m->request_id, "library-error")) return "close";
    if (!strcmp(m->request_id, "library-home")) {
        if (s->step == 1 || al_create_replacement(s)) return "myapps";
        return "cancel";
    }
    if (!strncmp(m->request_id, "library-", 8)) {
        if (!s->calls || al_create_replacement(s)) return "create";
        if (s->mode == 5) return NULL;
        if (al_create_action(m, "open", NULL) >= 0) {
            s->saw_kept = strstr(m->summary, "My very long friendly airplane") != NULL;
            return "back";
        }
        if (s->mode == 1) s->saw_kept = strstr(m->summary, "My very long friendly airplane") != NULL;
        return "home";
    }
    return NULL;
}
static bool al_create_recovery_valid(const struct al_create_fixture *s,
                                     const struct zcl_present_model_v1 *m, const char *copy)
{
    return copy && !strcmp(copy, s->f->root) && !strcmp(m->title, "Your copy was saved") &&
        m->action_count == 1 && !strcmp(m->actions[0].id, "close");
}
static bool al_create_flow_present(void *context, const struct zcl_present_model_v1 *m,
    const char *copy, struct zcl_present_window_event_v1 *event, char *why, size_t cap)
{
    struct al_create_fixture *s = context;
    if (++s->step > 8 || !zcl_present_model_validate_v1(m, why, cap)) return false;
    if (!strcmp(m->request_id, "library-created-copy")) {
        ++s->recovery_notices;
        s->valid = s->valid && al_create_recovery_valid(s, m, copy);
        if (s->mode == 13) return false; /* failure must retain the committed reply */
        event->struct_size = sizeof(*event); event->abi_version = ZCL_PRESENT_ABI_V1;
        event->outcome = ZCL_PRESENT_WINDOW_ACTION; event->action_index = 0; return true;
    }
    if (s->mode == 5 && s->calls && strcmp(m->request_id, "library-error")) return false;
    const char *action = al_create_flow_action(s, m);
    int i = action ? al_create_action(m, action, NULL) : -1;
    if (i < 0) return false;
    event->struct_size = sizeof(*event); event->abi_version = ZCL_PRESENT_ABI_V1;
    event->outcome = ZCL_PRESENT_WINDOW_ACTION; event->action_index = (unsigned)i; return true;
}
static bool al_create_kept_result(const struct al_create_fixture *s, const struct zcl_command_reply *r)
{
    struct app_selection loaded;
    return r->status == ZCL_COMMAND_STATUS_PASSED && r->error.mutated && s->saw_kept &&
        app_selection_load(s->f->env.state_dir, "skycombat", &loaded) == APP_SELECTION_OK &&
        loaded.revision == s->saved.revision && !memcmp(loaded.version, s->saved.version, 32);
}
static bool al_create_outcome_facts(const struct json_value *facts, unsigned mode)
{
    if (mode != 9 && mode != 10) return true;
    const struct json_value *executed = json_get(facts, "continuation_executed");
    if (!executed || executed->type != JSON_BOOL || json_get_bool(executed)) return false;
    if (mode == 10) return json_get_bool(json_get(facts, "copy_progress_ui_failed"));
    const struct json_value *row = json_at(json_get(facts, "operations"), 0);
    if (!json_get_bool(json_get(row, "progress_displayed")) ||
        !json_get_bool(json_get(row, "close_notice_failed"))) return false;
    const struct json_value *error = json_get(facts, "continuation_error");
    const char *scratch = json_get_str(json_get(error, "retained_scratch"));
    return scratch && !strcmp(scratch, "/fixture/private-scratch") &&
        json_get_bool(json_get(error, "copy_retained"));
}
static bool al_create_failure_wire(struct zcl_command_reply *reply, const char *copy, unsigned mode)
{
    const struct zcl_command_registry *reg = zcl_command_catalog(); bool alias = false;
    const struct zcl_command_spec *spec = zcl_command_registry_find(reg, "app.library", &alias);
    char wire[ZCL_COMMAND_ERROR_BUDGET + 1];
    size_t n = spec ? zcl_command_registry_test_reply_wire(reg, spec, reply, wire, sizeof(wire)) : 0;
    struct json_value doc = {0}; bool ok = n && json_read(&doc, wire, n);
    const struct json_value *error = json_get(&doc, "error"), *facts = json_get(error, "facts");
    if (mode == 9 || mode == 10) facts = json_get(facts, "historical_adoption");
    const char *actual = json_get_str(json_get(facts, "copy"));
    ok = ok && json_get_bool(json_get(error, "mutated")) && actual && !strcmp(actual, copy) &&
        json_get_str(json_get(facts, "release_root")) && json_get_str(json_get(facts, "package_root")) &&
        json_get_str(json_get(facts, "version")) && !json_get(facts, "destination") &&
        !json_get(facts, "historical_receive") && al_create_outcome_facts(facts, mode);
    json_free(&doc); return ok;
}
static bool al_create_preview_result(const struct zcl_command_reply *r, unsigned mode)
{
    const char *continuation = zcl_package_copy_str(&r->data, "continuation");
    return r->status == ZCL_COMMAND_STATUS_PASSED && r->error.mutated &&
        continuation && !strcmp(continuation, mode == 8 ? "copied" : "previewed");
}
static bool al_create_failure_result(const struct al_create_fixture *s, const struct zcl_command_reply *r)
{
    unsigned mode = s->mode;
    if ((mode == 9 || mode == 10) && strcmp(r->error.code, "FOLLOWUP_FAILED")) return false;
    if (mode == 4 || mode == 5 || mode == 7 || mode == 9 || mode == 10)
        return r->status != ZCL_COMMAND_STATUS_PASSED && r->error.mutated &&
            al_create_failure_wire((struct zcl_command_reply *)r, s->f->root, mode);
    return r->status != ZCL_COMMAND_STATUS_PASSED && !r->error.mutated;
}
static bool al_create_progress_roots(const struct json_value *data)
{
    static const char expected[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const char *keys[] = {"version", "release_root", "package_root"};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        const char *value = zcl_package_copy_str(data, keys[i]);
        if (!value || strcmp(value, expected)) return false;
    }
    return true;
}
static bool al_create_progress_continuation(const struct json_value *data)
{
    const char *continuation = zcl_package_copy_str(data, "continuation");
    const struct json_value *executed = json_get(data, "continuation_executed");
    return continuation && !strcmp(continuation, "adopted") && executed &&
        executed->type == JSON_BOOL && !json_get_bool(executed);
}
static bool al_create_progress_wire(struct zcl_command_reply *r, const char *expected)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(reg, "app.library", NULL);
    char wire[32768u + 1u];
    struct zcl_command_budget_fixture budget = {.budget_bytes = spec ? (size_t)spec->budget_bytes : 0};
    size_t n = spec ? zcl_command_registry_test_reply_wire_fixture(reg, spec, r, &budget, wire, sizeof(wire)) : 0;
    struct json_value doc; json_init(&doc);
    bool ok = n && n < sizeof(wire) && json_read(&doc, wire, n);
    const struct json_value *data = json_get(&doc, "data");
    const char *copy = zcl_package_copy_str(data, "copy");
    const char *status = zcl_package_copy_str(&doc, "status");
    ok = ok && status && !strcmp(status, "passed") && copy && !strcmp(copy, expected) &&
        al_create_progress_roots(data) && al_create_progress_continuation(data) &&
        json_get_bool(json_get(data, "copy_progress_ui_failed"));
    json_free(&doc); return ok;
}
static bool al_create_copy_matches(const struct al_create_fixture *s, const char *copy)
{
    if (!copy) return false;
    if (s->mode == 14) return !strcmp(copy, "relative-copy");
    if (s->mode == 15) return copy[0] == '/' && strlen(copy) == ZCL_PRESENT_COPY_TEXT_MAX + 1 &&
        strspn(copy + 1, "x") == ZCL_PRESENT_COPY_TEXT_MAX;
    return !strcmp(copy, s->f->root);
}
static bool al_create_progress_result(const struct al_create_fixture *s, struct zcl_command_reply *r)
{
    const char *copy = zcl_package_copy_str(&r->data, "copy");
    const char *continuation = zcl_package_copy_str(&r->data, "continuation");
    const struct json_value *executed = json_get(&r->data, "continuation_executed");
    unsigned notices = s->mode >= 14 ? 0u : 1u;
    return r->status == ZCL_COMMAND_STATUS_PASSED && r->error.mutated &&
        s->recovery_notices == notices && al_create_copy_matches(s, copy) &&
        continuation && !strcmp(continuation, "adopted") &&
        json_get_bool(json_get(&r->data, "copy_progress_ui_failed")) &&
        executed && executed->type == JSON_BOOL && !json_get_bool(executed) &&
        al_create_progress_wire(r, copy);
}
static bool al_create_case_result(const struct al_create_fixture *s, struct zcl_command_reply *r)
{
    unsigned mode = s->mode;
    unsigned expected_calls = mode == 6 ? 0u : ((mode == 9 || mode == 10) ? 2u : 1u);
    if (!s->valid || s->calls != expected_calls) return false;
    if (mode == 0) return r->status == ZCL_COMMAND_STATUS_PASSED && !r->error.mutated;
    if (mode == 1) return al_create_kept_result(s, r);
    if (mode >= 12 && mode <= 15) return al_create_progress_result(s, r);
    if (mode == 2 || mode == 8) return al_create_preview_result(r, mode);
    return al_create_failure_result(s, r);
}
static bool al_create_run_case(unsigned mode)
{
    static struct al_fx f; struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.app_open.v1");
    struct al_create_fixture s = {.f = &f, .mode = mode, .valid = true};
    bool setup = al_setup(&f) && al_write_file(f.env.config_path, "", 0600) &&
        app_launch_state_dir_ready(f.env.state_dir);
    if (setup) zcl_test_app_library_create(&f.env, f.root, &reply, al_create_flow_present,
        al_create_notice, &s, al_create_adopt, mode == 6 ? 0 : 30000);
    bool ok = setup && al_create_case_result(&s, &reply);
    printf("  create mode=%u setup=%d valid=%d calls=%u steps=%u notices=%u kept=%d status=%d mutated=%d code=%s\n",
        mode, setup, s.valid, s.calls, s.step, s.recovery_notices, s.saw_kept, reply.status, reply.error.mutated, reply.error.code);
    zcl_command_reply_free(&reply); return ok;
}
static bool al_create_real_tiny_budget(const char *datadir)
{
    struct json_value input; json_init(&input); json_set_object(&input);
    bool ok = json_push_kv_str(&input, "name", "skycombat") && json_push_kv_str(&input, "datadir", datadir);
    struct zcl_command_request req = {.input = &input, .success_data_budget_provided = true, .success_data_budget = 0};
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_adopt.v1");
    if (ok) app_installed_copy_run(&req, &reply, NULL, NULL);
    ok = ok && reply.status != ZCL_COMMAND_STATUS_PASSED && !reply.error.mutated &&
        !strcmp(reply.error.code, "RECEIPT_TOO_LARGE");
    zcl_command_reply_free(&reply); json_free(&input); return ok;
}
static void al_create_preparer(void *context, const struct app_selection *selection,
    struct zcl_command_reply *reply)
{
    struct al_create_fixture *s = context; ++s->preparations;
    s->valid = s->valid && al_library_prepared_data(reply, selection, false);
    reply->error.mutated = true;
}
static const char *al_create_history_action(struct al_create_fixture *s,
    const struct zcl_present_model_v1 *m)
{
    if (!strcmp(m->request_id, "library-home")) return s->step == 1 ? "myapps" : "cancel";
    if (!strcmp(m->request_id, "library-help")) return "back";
    if (strcmp(m->request_id, "library-0")) return NULL;
    if (al_create_action(m, "open", NULL) >= 0) return s->preparations ? "back" : "help";
    return s->preparations ? "create" : "choose";
}
static bool al_create_history_case(void)
{
    static struct al_fx f; struct app_selection saved; struct zcl_command_reply reply;
    struct al_create_fixture s = {.f = &f, .mode = 11, .valid = true};
    zcl_command_reply_init(&reply, "zcl.app_open.v1");
    bool setup = al_setup(&f) && al_library_catalog(&f, 1) &&
        app_launch_state_dir_ready(f.env.state_dir) && al_selection(&f, "app-00", &saved);
    if (setup) zcl_test_app_library_create_prepared(&f.env, f.root, &reply, al_create_flow_present,
        al_create_notice, &s, al_create_preparer, al_create_adopt, 30000);
    const struct json_value *prep = json_get(&reply.data, "preparation");
    const char *copy = json_get_str(json_get(prep, "copy"));
    const char *current = json_get_str(json_get(&reply.data, "copy"));
    bool ok = setup && s.valid && s.preparations == 1 && s.calls == 1 &&
        reply.status == ZCL_COMMAND_STATUS_PASSED && reply.error.mutated &&
        copy && !strcmp(copy, saved.copy) && json_get_bool(json_get(prep, "changed")) &&
        current && !strcmp(current, f.root);
    printf("  create history: setup=%d valid=%d preparations=%u calls=%u steps=%u status=%d mutated=%d code=%s\n",
        setup, s.valid, s.preparations, s.calls, s.step, reply.status, reply.error.mutated, reply.error.code);
    zcl_command_reply_free(&reply); return ok;
}
static int case_library_create_flow(void)
{
    int failures = 0;
    TEST("My Apps create preserves native adoption outcomes") {
        bool ok = true;
        for (unsigned mode = 0; mode <= 10; ++mode) if (!al_create_run_case(mode)) ok = false;
        if (!al_create_run_case(12)) ok = false;
        if (!al_create_run_case(13)) ok = false;
        if (!al_create_run_case(14)) ok = false;
        if (!al_create_run_case(15)) ok = false;
        if (!al_create_real_tiny_budget("/fixture-profile")) ok = false;
        if (!al_create_history_case()) ok = false;
        ASSERT(ok); PASS();
    } _test_next:;
    return failures;
}

/* Exercise the production envelope: failure data is only retained through
 * failure_facts, so checking reply.data alone would miss a lost receipt. */
static bool al_preparation_identity(const struct json_value *facts,
    const struct app_selection *selection, const char *version)
{
    const char *v = json_get_str(json_get(facts, "version"));
    const char *copy = json_get_str(json_get(facts, "copy"));
    const char *datadir = json_get_str(json_get(facts, "datadir"));
    return v && !strcmp(v, version) && copy && !strcmp(copy, selection->copy) &&
        datadir && !strcmp(datadir, selection->datadir) &&
        json_get_bool(json_get(facts, "key_created")) && json_get_bool(json_get(facts, "changed"));
}
static bool al_preparation_wire(struct zcl_command_reply *reply,
    const struct app_selection *selection, const char *visible)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    bool alias = false;
    const struct zcl_command_spec *spec = zcl_command_registry_find(reg, "app.library", &alias);
    char wire[ZCL_COMMAND_ERROR_BUDGET + 1], version[65];
    uint8_t source[32]; memset(source, 2, sizeof(source)); zcl_hex_encode(source, 32, version);
    size_t n = spec ? zcl_command_registry_test_reply_wire(reg, spec, reply, wire, sizeof(wire)) : 0;
    struct json_value doc = {0};
    bool ok = n && json_read(&doc, wire, n);
    const struct json_value *error = json_get(&doc, "error");
    const struct json_value *facts = json_get(error, "facts");
    const struct json_value *previous = json_get(facts, "library_preparation");
    if (previous) {
        const char *later = json_get_str(json_get(facts, "later_effect"));
        ok = ok && later && !strcmp(later, "preserve me");
        facts = previous;
    }
    ok = ok && reply->error.mutated && json_get_bool(json_get(error, "mutated")) &&
        al_preparation_identity(facts, selection, version) &&
        strstr(visible, version) && strstr(visible, "was saved; AI setup stopped");
    json_free(&doc); return ok;
}
static bool al_setup_request_valid(const struct json_value *setup)
{
    const char *request = json_get_str(json_get(setup, "request"));
    return request && strstr(request, "local stdio MCP server") &&
        strstr(request, "command and args as literal values") &&
        strstr(request, "z23_run with path=app.customize and input") &&
        strstr(request, "z23_run with path=app.edit") &&
        strstr(request, "returned version as the next source_version") &&
        strstr(request, "explicit Keep and Share");
}

struct al_help_probe { unsigned copies, exit_action; bool exact; };
static const char al_help_payload[] = "{\"command\":\"/caf\xc3\xa9/z23\",\"revision\":7}";
static bool al_help_copy_probe(const char *text, void *context)
{
    struct al_help_probe *probe = context;
    probe->exact = !strcmp(text, al_help_payload);
    return ++probe->copies != 1; /* First copy fails, retry succeeds. */
}
static bool al_help_pump(const struct zcl_present_window_live_view_v1 *live,
    uint32_t action, bool close, bool expected_redraw, bool expected_close)
{
    struct zcl_present_window_event_v1 event = {.struct_size = sizeof(event),
        .abi_version = ZCL_PRESENT_ABI_V1, .outcome = action == UINT32_MAX ?
        ZCL_PRESENT_WINDOW_DISMISSED : ZCL_PRESENT_WINDOW_ACTION, .action_index = action};
    bool redraw = false, allow_close = false;
    live->owner.update(live->owner.context, &event, close, &redraw, &allow_close);
    return redraw == expected_redraw && allow_close == expected_close;
}
static bool al_help_copy_inputs(struct al_help_probe *probe, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *pages, const struct zcl_present_window_live_view_v1 *live)
{
    uint32_t width = (ZCL_PRESENT_MODEL_ACTION_WIDTH - 3u * ZCL_PRESENT_MODEL_ACTION_GAP) / 4u;
    struct zcl_present_input_v1 inputs[] = {
        {.key = ZCL_PRESENT_INPUT_ENTER},
        {.key = ZCL_PRESENT_INPUT_CLICK, .x = ZCL_PRESENT_MODEL_ACTION_X + width / 2u,
            .y = ZCL_PRESENT_MODEL_ACTION_Y + ZCL_PRESENT_MODEL_ACTION_HEIGHT / 2u},
        {.key = ZCL_PRESENT_INPUT_TEXT, .character = ' '},
        {.key = ZCL_PRESENT_INPUT_TEXT, .character = '1'}, {.key = ZCL_PRESENT_INPUT_TEXT, .character = 'c'}
    };
    uint32_t focus = UINT32_MAX;
    for (unsigned i = 0; i < sizeof(inputs) / sizeof(inputs[0]); ++i) {
        uint32_t action = UINT32_MAX;
        if (!live->input(live->owner.context, &inputs[i], &focus, &action) || action != UINT32_MAX ||
            probe->copies != i + 1 || !probe->exact || !al_help_pump(live, action, false, true, false)) return false;
        if (!strstr(model->summary, i ? "Copied." : "Could not copy") || !pages->pages[0].pixels) return false;
    }
    return true;
}
static bool al_help_live_probe(void *context, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *pages, const struct zcl_present_window_live_view_v1 *live,
    char *why, size_t cap)
{
    (void)why; (void)cap;
    struct al_help_probe *probe = context;
    if (!al_help_copy_inputs(probe, model, pages, live)) return false;
    uint32_t focus = 1, action = UINT32_MAX;
    struct zcl_present_input_v1 input = {.key = ZCL_PRESENT_INPUT_ENTER};
    if (!live->input(live->owner.context, &input, &focus, &action) || action != UINT32_MAX ||
        !al_help_pump(live, action, false, false, false) || probe->copies != 5) return false;
    if (probe->exit_action == UINT32_MAX) return al_help_pump(live, UINT32_MAX, true, false, true);
    input.key = ZCL_PRESENT_INPUT_TAB;
    if (!live->input(live->owner.context, &input, &focus, &action) || focus != 2) return false;
    focus = probe->exit_action; input.key = ZCL_PRESENT_INPUT_ENTER;
    return live->input(live->owner.context, &input, &focus, &action) && action == probe->exit_action &&
        al_help_pump(live, action, true, false, true) && probe->copies == 5;
}
static int case_library_help_copy(void)
{
    int failures = 0;
    TEST("AI setup mouse and keyboard copy retain window, show failure/retry and preserve navigation") {
        struct zcl_present_model_v1 model; zcl_present_model_init_v1(&model, ZCL_PRESENT_MODEL_STATUS_CARD);
        (void)snprintf(model.request_id, sizeof(model.request_id), "library-help");
        (void)snprintf(model.title, sizeof(model.title), "Change with your AI");
        const char *ids[] = {"setup", "version", "back", "cancel"};
        for (unsigned i = 0; i < 4; ++i) app_library_choice(&model, ids[i], ids[i], "AI setup");
        const unsigned exits[] = {2, 3, UINT32_MAX};
        for (unsigned i = 0; i < 3; ++i) {
            struct al_help_probe probe = {.exit_action = exits[i]};
            struct zcl_present_window_event_v1 event = {0}; char why[128] = {0};
            ASSERT(zcl_test_app_library_help_present(&model, al_help_payload, &event,
                al_help_live_probe, &probe, al_help_copy_probe, why, sizeof(why)));
            ASSERT(probe.copies == 5 && probe.exact && event.action_index == exits[i]);
            ASSERT(event.struct_size == sizeof(event) && event.abi_version == ZCL_PRESENT_ABI_V1);
            ASSERT(event.outcome == (i == 2 ? ZCL_PRESENT_WINDOW_DISMISSED : ZCL_PRESENT_WINDOW_ACTION));
        }
    PASS(); }
_test_next:;
    return failures;
}
static int case_library_help(void)
{
    int failures = 0;
    static struct al_fx f;
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_open.v1");
    struct json_value setup = {0};
    const char *exe = "/installed path/quote\" back\\tick`$()/z23";
    TEST("AI help truthfully declines unknown catalog source and Back preserves index") {
        ASSERT(al_setup(&f));
        struct al_library_script s = {.actions = {0, 1, 2, 3, 3}, .count = 5, .valid = true};
        zcl_test_app_library_setup(&f.env, exe, "/unrelated-profile", &reply, al_library_present, &s);
        ASSERT(s.valid && s.calls == 5 && !s.errors && !s.setup[0]);
        ASSERT(strstr(s.last_summary, "App 1 of"));
        ASSERT(!json_get(&reply.data, "pid"));
    PASS(); }
    TEST("AI help JSON preserves literal executable and selected profile, full identity, no writes") {
        struct app_selection saved, after;
        ASSERT(app_launch_state_dir_ready(f.env.state_dir));
        ASSERT(al_selection(&f, "fixtureapp", &saved));
        struct al_library_script s = {.actions = {0, 1, 2, 3, 3}, .count = 5, .valid = true};
        zcl_test_app_library_setup_prepared(&f.env, exe, "/wrong-global-profile", &reply,
            al_library_present, &s, al_library_prepare);
        ASSERT(s.valid && s.calls == 5 && !s.errors && s.setup[0]);
        ASSERT(json_read(&setup, s.setup, strlen(s.setup)));
        ASSERT_STR_EQ(json_get_str(json_get(&setup, "command")), exe);
        const struct json_value *args = json_get(&setup, "args");
        ASSERT(args && args->type == JSON_ARR && args->num_children == 3);
        ASSERT_STR_EQ(json_get_str(&args->children[0]), "mcp");
        ASSERT_STR_EQ(json_get_str(&args->children[1]), "serve");
        char profile_arg[APP_SELECTION_PATH_MAX + 16];
        (void)snprintf(profile_arg, sizeof(profile_arg), "--datadir=%s", saved.datadir);
        ASSERT_STR_EQ(json_get_str(&args->children[2]), profile_arg);
        ASSERT_STR_EQ(json_get_str(json_get(&setup, "name")), "fixtureapp");
        ASSERT(json_get_int(json_get(&setup, "revision")) == (int64_t)saved.revision);
        char hex[65]; zcl_hex_encode(saved.version, 32, hex);
        ASSERT_STR_EQ(json_get_str(json_get(&setup, "version")), hex);
        uint8_t source[32]; memset(source, 2, sizeof(source)); zcl_hex_encode(source, 32, hex);
        ASSERT_STR_EQ(json_get_str(json_get(&setup, "source_version")), hex);
        ASSERT(s.preparations == 1);
        ASSERT(al_setup_request_valid(&setup));
        ASSERT(app_selection_load(f.env.state_dir, "fixtureapp", &after) == APP_SELECTION_OK);
        ASSERT(after.revision == saved.revision && !memcmp(after.version, saved.version, 32));
        ASSERT(!json_get(&reply.data, "pid"));
    PASS(); }
_test_next:;
    json_free(&setup); zcl_command_reply_free(&reply);
    return failures;
}
static bool al_help_fixture(struct al_fx *f)
{
    struct app_selection saved;
    return al_setup(f) && app_launch_state_dir_ready(f->env.state_dir) &&
        al_selection(f, "fixtureapp", &saved);
}
static int case_library_prepare_stop(void)
{
    int failures = 0;
    static struct al_fx f;
    if (!al_help_fixture(&f)) return 1;
    const char *exe = "/installed/z23";
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_open.v1");
    TEST("Cancel during owner preparation supplies no AI setup and leaves Keep unchanged") {
        struct app_selection before, after;
        ASSERT(app_selection_load(f.env.state_dir, "fixtureapp", &before) == APP_SELECTION_OK);
        struct al_library_script s = {.actions = {0, 1}, .count = 2, .valid = true,
            .cancel_preparation = true};
        zcl_command_reply_free(&reply); zcl_command_reply_init(&reply, "zcl.app_open.v1");
        zcl_test_app_library_setup_prepared(&f.env, exe, "/profile", &reply,
            al_library_present, &s, al_library_prepare);
        ASSERT(s.valid && s.preparations == 1 && s.calls == 2 && !s.setup[0] && !s.errors);
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "status")), "canceled");
        ASSERT(app_selection_load(f.env.state_dir, "fixtureapp", &after) == APP_SELECTION_OK);
        ASSERT(after.revision == before.revision && !memcmp(after.version, before.version, 32));
    PASS(); }
    TEST("Keep during owner preparation refuses handoff instead of substituting a new anchor") {
        struct app_selection before, after;
        ASSERT(app_selection_load(f.env.state_dir, "fixtureapp", &before) == APP_SELECTION_OK);
        struct al_library_script s = {.actions = {0, 1}, .count = 2, .valid = true,
            .stale_preparation = true, .change_fixture = &f};
        zcl_command_reply_free(&reply); zcl_command_reply_init(&reply, "zcl.app_open.v1");
        zcl_test_app_library_setup_prepared(&f.env, exe, "/profile", &reply,
            al_library_present, &s, al_library_prepare);
        ASSERT(s.valid && s.preparations == 1 && s.errors == 1 && !s.setup[0]);
        ASSERT_STR_EQ(reply.error.code, "SELECTION_STALE");
        ASSERT(al_preparation_wire(&reply, &before, s.error_summary));
        ASSERT(app_selection_load(f.env.state_dir, "fixtureapp", &after) == APP_SELECTION_OK);
        ASSERT(after.revision == before.revision + 1 && !memcmp(after.version, before.version, 32));
    PASS(); }
_test_next:;
    zcl_command_reply_free(&reply); return failures;
}
static bool al_share_prepare_review(struct al_fx *f, unsigned choice)
{
    struct app_selection before, after;
    if (app_selection_load(f->env.state_dir, "fixtureapp", &before) != APP_SELECTION_OK) return false;
    struct al_library_script s = {.actions = {0, 2, 3}, .count = 3, .valid = true, .share_choice = choice};
    if (choice == 2) { s.actions[2] = 0; s.actions[3] = 3; s.count = 4; }
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_open.v1");
    zcl_test_app_library_share(&f->env, &reply, al_library_present, &s,
        al_library_prepare, al_library_share, al_library_notice);
    const struct json_value *prep = json_get(&reply.data, "preparation");
    bool ok = s.valid && s.preparations == 1 && s.saw_share_review && !s.share_calls &&
        !s.errors && reply.error.mutated && prep && json_get_bool(json_get(prep, "changed")) &&
        app_selection_load(f->env.state_dir, "fixtureapp", &after) == APP_SELECTION_OK &&
        before.revision == after.revision && !memcmp(before.version, after.version, 32);
    zcl_command_reply_free(&reply); return ok;
}
static bool al_selection_identity_equal(const struct app_selection *a,
                                        const struct app_selection *b)
{
    return a->revision == b->revision && !strcmp(a->app, b->app) &&
        !strcmp(a->copy, b->copy) && !strcmp(a->datadir, b->datadir) &&
        !memcmp(a->version, b->version, 32) && !memcmp(a->image, b->image, 32) &&
        !memcmp(a->record, b->record, 32) && !memcmp(a->package, b->package, 32) &&
        !memcmp(a->fork, b->fork, 32) && !memcmp(a->parent, b->parent, 32) &&
        !memcmp(a->env, b->env, 32) && !memcmp(a->dependencies, b->dependencies, 32);
}
static bool al_share_cancel_checked(struct al_fx *f, const struct al_library_script *s,
    const struct app_selection *before, const struct zcl_command_reply *reply)
{
    struct app_selection after;
    return s->canceled_prepare_menu == 1 && s->calls == (s->share_choice == 2 ? 5u : 4u) &&
        app_selection_load(f->env.state_dir, "fixtureapp", &after) == APP_SELECTION_OK &&
        al_selection_identity_equal(before, &after) && !s->errors && !reply->error.mutated &&
        !strcmp(json_get_str(json_get(&reply->data, "status")), "canceled");
}
static bool al_share_prepare_refused(struct al_fx *f, unsigned mode, unsigned choice)
{
    struct al_library_script s = {.actions = {0, 2}, .count = 2, .valid = true};
    struct app_selection before;
    if (app_selection_load(f->env.state_dir, "fixtureapp", &before) != APP_SELECTION_OK) return false;
    if (mode == 0) {
        s.share_choice = choice;
        s.actions[2] = choice == 2 ? 0 : 3;
        s.actions[3] = 3; s.actions[4] = 3; s.count = choice == 2 ? 5 : 4;
    }
    s.cancel_preparation = mode == 0; s.fail_preparation = mode == 1;
    s.bad_preparation = mode == 2; s.stale_preparation = mode == 3; s.change_fixture = f;
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_open.v1");
    zcl_test_app_library_share(&f->env, &reply, al_library_present, &s,
        al_library_prepare, al_library_share, al_library_notice);
    static const char *const errors[] = {"", "FIXTURE_FAILED", "PREPARE_FAILED", "SELECTION_STALE"};
    bool ok = s.valid && s.preparations == 1 && !s.share_calls && !s.saw_share_review;
    if (mode == 0) ok = ok && al_share_cancel_checked(f, &s, &before, &reply);
    else ok = ok && s.errors == 1 && !strcmp(reply.error.code, errors[mode]);
    if (mode == 3) ok = ok && reply.error.mutated && json_get(&reply.data, "failure_facts");
    zcl_command_reply_free(&reply); return ok;
}

static bool al_share_cancel_with_history(struct al_fx *f)
{
    struct app_selection before, after;
    if (app_selection_load(f->env.state_dir, "fixtureapp", &before) != APP_SELECTION_OK) return false;
    struct al_library_script s = {.actions = {0, 1, 2, 2, 3, 3}, .count = 6,
        .valid = true, .second_preparation = 2};
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_open.v1");
    zcl_test_app_library_share(&f->env, &reply, al_library_present, &s,
        al_library_prepare, al_library_share, al_library_notice);
    const struct json_value *prep = json_get(&reply.data, "preparation");
    bool ok = s.valid && s.preparations == 2 && s.canceled_prepare_menu == 1 &&
        s.calls == 6 && !s.share_calls && !s.errors && reply.error.mutated && prep &&
        json_get_bool(json_get(prep, "changed")) &&
        !strcmp(json_get_str(json_get(prep, "copy")), before.copy) &&
        app_selection_load(f->env.state_dir, "fixtureapp", &after) == APP_SELECTION_OK &&
        al_selection_identity_equal(&before, &after);
    if (!ok) fprintf(stderr, "share cancel history valid=%d prepares=%u menus=%u calls=%u share=%u mutated=%d prep=%d\n",
                     s.valid, s.preparations, s.canceled_prepare_menu, s.calls,
                     s.share_calls, reply.error.mutated, prep != NULL);
    zcl_command_reply_free(&reply); return ok;
}
static int case_library_share_prepare(void)
{
    int failures = 0; static struct al_fx f;
    TEST("Share preparation requires separate review and Keep before file, link or publish") {
        ASSERT(al_help_fixture(&f));
        for (unsigned choice = 0; choice < 3; ++choice) ASSERT(al_share_prepare_review(&f, choice));
        PASS();
    }
    TEST("Share preparation cancellation, failure, malformed data and stale Keep never share") {
        for (unsigned choice = 0; choice < 3; ++choice) ASSERT(al_share_prepare_refused(&f, 0, choice));
        for (unsigned mode = 1; mode < 4; ++mode) ASSERT(al_share_prepare_refused(&f, mode, 0));
        PASS();
    }
    TEST("Canceling Share preparation returns to menu and retains prior preparation") {
        ASSERT(al_share_cancel_with_history(&f));
        PASS();
    } _test_next:;
    return failures;
}
static int case_library_setup_stop(void)
{
    int failures = 0;
    static struct al_fx f;
    if (!al_help_fixture(&f)) return 1;
    const char *exe = "/installed/z23";
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_open.v1");
    TEST("Setup overflow preserves serialized prepared-draft recovery and leaves Keep unchanged") {
        struct app_selection before, after;
        ASSERT(app_selection_load(f.env.state_dir, "fixtureapp", &before) == APP_SELECTION_OK);
        char long_path[4096]; memset(long_path, '"', sizeof(long_path) - 1);
        long_path[sizeof(long_path) - 1] = 0;
        struct al_library_script s = {.actions = {0, 1}, .count = 2, .valid = true};
        zcl_command_reply_free(&reply); zcl_command_reply_init(&reply, "zcl.app_open.v1");
        zcl_test_app_library_setup_prepared(&f.env, long_path, "/profile", &reply,
            al_library_present, &s, al_library_prepare);
        ASSERT(s.valid && s.preparations == 1 && s.errors == 1 && !s.setup[0]);
        ASSERT_STR_EQ(reply.error.code, "SETUP_TOO_LARGE");
        ASSERT(al_preparation_wire(&reply, &before, s.error_summary));
        ASSERT(app_selection_load(f.env.state_dir, "fixtureapp", &after) == APP_SELECTION_OK);
        ASSERT(after.revision == before.revision && !memcmp(after.version, before.version, 32));
    PASS(); }
    TEST("AI help refuses changed selection before handing off any setup") {
        struct al_library_script s = {.actions = {0, 1}, .count = 2, .valid = true,
            .change_fixture = &f, .change_at = 2};
        zcl_command_reply_free(&reply); zcl_command_reply_init(&reply, "zcl.app_open.v1");
        zcl_test_app_library_setup(&f.env, exe, "/profile", &reply, al_library_present, &s);
        ASSERT(s.valid && s.calls == 2 && s.errors == 1 && !s.setup[0]);
        ASSERT_STR_EQ(reply.error.code, "SELECTION_STALE");
    PASS(); }
_test_next:;
    zcl_command_reply_free(&reply); return failures;
}
static int case_library_repeat_prepare(void)
{
    int failures = 0;
    static struct al_fx f;
    if (!al_help_fixture(&f)) return 1;
    const char *exe = "/installed/z23";
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_open.v1");
    TEST("Back and no-op or later failed preparation preserve the first mutation and later facts") {
        struct app_selection before, after;
        ASSERT(app_selection_load(f.env.state_dir, "fixtureapp", &before) == APP_SELECTION_OK);
        for (unsigned kind = 1; kind <= 3; ++kind) {
            struct al_library_script s = {.actions = {0, 1, 2, 1}, .count = 4, .valid = true,
                .second_preparation = kind, .fail_after_noop = kind == 1};
            zcl_command_reply_free(&reply); zcl_command_reply_init(&reply, "zcl.app_open.v1");
            zcl_test_app_library_setup_prepared(&f.env, exe, "/profile", &reply,
                al_library_present, &s, al_library_prepare);
            ASSERT(s.valid && s.preparations == 2 && s.calls == 4);
            if (kind == 2) {
                ASSERT(!s.errors && reply.error.mutated);
                const struct json_value *p = json_get(&reply.data, "preparation");
                ASSERT(json_get_bool(json_get(p, "key_created")));
                ASSERT(json_get_bool(json_get(p, "changed")));
                ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "status")), "canceled");
            } else {
                ASSERT(s.errors == 1 && al_preparation_wire(&reply, &before, s.error_summary));
                ASSERT_STR_EQ(reply.error.code, kind == 1 ? "PRESENTATION_FAILED" : "FIXTURE_FAILED");
            }
            ASSERT(app_selection_load(f.env.state_dir, "fixtureapp", &after) == APP_SELECTION_OK);
            ASSERT(after.revision == before.revision && !memcmp(after.version, before.version, 32));
        }
    PASS(); }
_test_next:;
    zcl_command_reply_free(&reply);
    return failures;
}
static int case_library_received_recovery(void)
{
    int failures = 0; static struct al_fx f;
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_open.v1");
    TEST("My Apps does not label an AI preparation failure as a received app") {
        ASSERT(al_help_fixture(&f));
        struct al_library_script s = {.actions = {0, 1, 2, 1}, .count = 4,
            .valid = true, .second_preparation = 4};
        zcl_test_app_library_refresh(&f.env, &reply, al_library_present, &s,
            al_library_prepare, NULL, al_recovery_notice);
        ASSERT(s.valid && !s.saw_recovery && s.errors == 1 && s.preparations == 2);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_PASSED && reply.error.mutated);
        ASSERT_STR_EQ(reply.error.code, "FIXTURE_FAILED");
        PASS();
    } _test_next:;
    zcl_command_reply_free(&reply); return failures;
}
static int case_library_tight_budget(void)
{
    int failures = 0;
    TEST("My Apps refuses an insufficient reply budget before native UI") {
        struct zcl_command_request request = {.budget_bytes = 1024,
            .success_data_budget_provided = true, .success_data_budget = 128};
        struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_open.v1");
        zcl_native_handle_app_library(&request, &reply);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_PASSED && !reply.error.mutated);
        ASSERT_STR_EQ(reply.error.code, "BUDGET_TOO_SMALL");
        zcl_command_reply_free(&reply);
        request.budget_bytes = 256; request.success_data_budget = 0;
        zcl_command_reply_init(&reply, "zcl.app_open.v1");
        zcl_native_handle_app_library(&request, &reply);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_PASSED && !reply.error.mutated);
        ASSERT_STR_EQ(reply.error.code, "BUDGET_TOO_SMALL");
        zcl_command_reply_free(&reply);
        request.budget_bytes = 3072; request.success_data_budget_provided = false;
        zcl_command_reply_init(&reply, "zcl.app_open.v1");
        zcl_native_handle_app_library(&request, &reply);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_PASSED && !reply.error.mutated);
        ASSERT_STR_EQ(reply.error.code, "BUDGET_UNAVAILABLE");
        zcl_command_reply_free(&reply); PASS();
    }
    TEST("My Apps tight registry budgets preserve the established refusal boundary") {
        const struct zcl_command_registry *reg = zcl_command_catalog();
        const struct zcl_command_spec *spec = NULL;
        for (size_t i = 0; reg && i < reg->count; ++i)
            if (!strcmp(reg->commands[i].path, "app.library")) { spec = &reg->commands[i]; break; }
        ASSERT(spec);
        struct zcl_command_context ctx = {.registry = reg, .granted_capabilities = ~(uint64_t)0,
            .authority_ceiling = ZCL_COMMAND_AUTH_OWNER};
        struct json_value input; json_init(&input); json_set_object(&input);
        char wire[4096]; enum zcl_command_exit code = ZCL_COMMAND_EXIT_OK;
        size_t n = zcl_command_registry_execute_json(reg, spec, &ctx, &input, true, spec->path,
            "normal", 1024, 0, NULL, wire, sizeof(wire), &code);
        struct json_value doc; json_init(&doc);
        ASSERT(n && json_read(&doc, wire, n));
        const struct json_value *error = json_get(&doc, "error");
        const char *reason = zcl_package_copy_str(error, "code");
        ASSERT(reason && (!strcmp(reason, "BUDGET_TOO_SMALL") || !strcmp(reason, "RESPONSE_BUDGET_EXCEEDED")) &&
            !json_get_bool(json_get(error, "mutated")));
        json_free(&doc);
        n = zcl_command_registry_execute_json(reg, spec, &ctx, &input, false, spec->path,
            "normal", 256, 0, NULL, wire, sizeof(wire), &code);
        ASSERT(n == 0 && code == ZCL_COMMAND_EXIT_INTERNAL);
        json_free(&input); PASS();
    } _test_next:;
    return failures;
}
static int case_library_profile_input(void)
{
    int failures = 0;
    TEST("My Apps rejects malformed or relative app profiles before native UI") {
        const struct zcl_command_registry *reg = zcl_command_catalog(); bool alias = false;
        const struct zcl_command_spec *spec = zcl_command_registry_find(reg, "app.library", &alias);
        ASSERT(spec);
        struct zcl_command_input_descriptor descriptor;
        ASSERT(zcl_command_registry_input_descriptor(spec, "datadir", &descriptor));
        ASSERT(descriptor.type == JSON_STR && !descriptor.required && descriptor.max_bytes == 4096u);
        struct json_value input; json_init(&input); json_set_object(&input);
        char why[256] = {0};
        ASSERT(json_push_kv_int(&input, "datadir", 42));
        ASSERT(!zcl_command_registry_input_validate(spec, &input, why, sizeof(why)));
        struct zcl_command_request request = {.input = &input};
        struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_open.v1");
        zcl_native_handle_app_library(&request, &reply);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_PASSED && !reply.error.mutated);
        ASSERT_STR_EQ(reply.error.code, "BAD_INPUT");
        zcl_command_reply_free(&reply);
        json_free(&input); json_init(&input); json_set_object(&input);
        ASSERT(json_push_kv_str(&input, "datadir", "relative/profile"));
        zcl_command_reply_init(&reply, "zcl.app_open.v1");
        zcl_native_handle_app_library(&request, &reply);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_PASSED && !reply.error.mutated);
        ASSERT_STR_EQ(reply.error.code, "BAD_INPUT");
        zcl_command_reply_free(&reply); json_free(&input); PASS();
    } _test_next:;
    return failures;
}
static bool al_library_fill(struct al_fx *f)
{
    char builtin[PATH_MAX], name[33];
    if (!al_path(builtin, sizeof(builtin), f->env.bin_dir, "z23-skycombat") ||
        !al_copy_exe(AL_FIXTURE, builtin, 0700) || !al_library_catalog(f, 15) ||
        !app_launch_state_dir_ready(f->env.state_dir)) return false;
    for (unsigned i = 0; i < 16; ++i) {
        struct app_selection saved;
        (void)snprintf(name, sizeof(name), "kept:copy-%02u", i);
        if (!al_selection(f, name, &saved)) return false;
    }
    return true;
}
static int case_library_builtin_help(void)
{
    int failures = 0;
    static struct al_fx f;
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_open.v1");
    struct json_value setup = {0};
    TEST("Installed AI help preserves escaped profile and does not invent a selection") {
        ASSERT(al_setup(&f));
        char builtin[PATH_MAX];
        ASSERT(al_path(builtin, sizeof(builtin), f.env.bin_dir, "z23-skycombat"));
        ASSERT(al_copy_exe(AL_FIXTURE, builtin, 0700));
        ASSERT(al_write_file(f.env.config_path, "", 0600));
        const char *profile = "/literal profile/quote\" slash\\ newline\n $()`";
        struct al_library_script s = {.actions = {0, 1, 3}, .count = 3, .valid = true};
        zcl_test_app_library_setup(&f.env, "/installed/z23", profile, &reply, al_library_present, &s);
        ASSERT(s.valid && !s.errors && s.calls == 3 && s.fresh_copy_prompt);
        ASSERT(json_read(&setup, s.setup, strlen(s.setup)));
        const struct json_value *args = json_get(&setup, "args");
        ASSERT(args && args->num_children == 3);
        char profile_arg[512]; (void)snprintf(profile_arg, sizeof(profile_arg), "--datadir=%s", profile);
        ASSERT_STR_EQ(json_get_str(&args->children[2]), profile_arg);
        ASSERT(!json_get(&setup, "revision") && !json_get(&setup, "version"));
        const char *request = json_get_str(json_get(&setup, "request"));
        ASSERT(request && strstr(request, "Call apps_list") &&
               strstr(request, "apps_adopt with name skycombat"));
        ASSERT(strstr(request, "profile bound by those args"));
        ASSERT(strstr(request, "local owner must choose Make my copy"));
        ASSERT(strstr(request, "native preview and Keep"));
        ASSERT(strstr(request, "Stop if canceled, failed"));
        ASSERT(strstr(request, "data.kept name, selection_revision or version"));
        ASSERT(strstr(request, "Call apps_list again"));
        ASSERT(strstr(request, "verify the kept name is present"));
        ASSERT(strstr(request, "path=app.customize and input containing name=data.kept.name"));
        ASSERT(strstr(request, "expected_revision=data.kept.selection_revision"));
        ASSERT(strstr(request, "omitting source_version"));
        ASSERT(strstr(request, "head_version and source_version equal data.kept.version"));
        ASSERT(strstr(request, "fresh Change with your AI setup"));
        ASSERT(strstr(request, "source_version for every later source read and app.edit"));
        ASSERT(strstr(request, "exact expected_head"));
        ASSERT(strstr(request, "explicit Keep and Share"));
        struct app_selection no_selection;
        ASSERT(app_selection_load(f.env.state_dir, "skycombat", &no_selection) == APP_SELECTION_ABSENT);
        ASSERT(!json_get(&reply.data, "pid"));
    PASS(); }
    TEST("AI setup refuses clipboard overflow instead of truncating literal arguments") {
        char long_path[4096]; memset(long_path, '"', sizeof(long_path) - 1); long_path[sizeof(long_path) - 1] = 0;
        struct al_library_script s = {.actions = {0, 1}, .count = 2, .valid = true};
        zcl_command_reply_free(&reply); zcl_command_reply_init(&reply, "zcl.app_open.v1");
        zcl_test_app_library_setup(&f.env, long_path, "/profile", &reply, al_library_present, &s);
        ASSERT(s.valid && s.errors == 1 && !s.setup[0]);
        ASSERT_STR_EQ(reply.error.code, "SETUP_TOO_LARGE");
    PASS(); }
_test_next:;
    json_free(&setup); zcl_command_reply_free(&reply);
    return failures;
}
static int case_library_bounds(void)
{
    int failures = 0;
    static struct al_fx f;
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_open.v1");
    TEST("My Apps home leads to an empty library and Back returns home") {
        ASSERT(al_setup(&f));
        ASSERT(al_write_file(f.env.config_path, "", 0600));
        struct al_library_script s = {.actions = {1}, .count = 1, .valid = true};
        zcl_test_app_library_run(&f.env, &reply, al_library_present, &s);
        ASSERT(s.valid && s.calls == 1 && s.home_calls == 2 && !s.errors && strstr(s.last_summary, "No apps yet"));
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "status")), "canceled");
    PASS(); }
    TEST("My Apps reaches all32 rows including duplicate friendly saved labels") {
        ASSERT(al_library_fill(&f));
        struct al_library_script s = {.count = 32, .valid = true};
        for (unsigned i = 0; i < 31; ++i) s.actions[i] = 2;
        s.actions[31] = 3;
        zcl_command_reply_free(&reply); zcl_command_reply_init(&reply, "zcl.app_open.v1");
        zcl_test_app_library_run(&f.env, &reply, al_library_present, &s);
        ASSERT(s.valid && s.calls == 32 && s.saved_label && !s.errors);
        ASSERT(strstr(s.last_summary, "App 32 of 32."));
        ASSERT(!json_get(&reply.data, "pid"));
    PASS(); }
    TEST("My Apps refuses selection overflow without showing partial choices") {
        struct app_selection saved;
        ASSERT(al_selection(&f, "kept:overflow", &saved));
        struct al_library_script s = {.valid = true};
        zcl_command_reply_free(&reply); zcl_command_reply_init(&reply, "zcl.app_open.v1");
        zcl_test_app_library_run(&f.env, &reply, al_library_present, &s);
        ASSERT(s.valid && s.calls == 0 && s.errors == 1);
        ASSERT_STR_EQ(s.error_title, "Could not open My Apps");
        ASSERT_STR_EQ(reply.error.code, "SELECTIONS_REFUSED");
    PASS(); }
    TEST("My Apps refuses a malformed catalog before presenting any choices") {
        ASSERT(al_library_catalog(&f, 16));
        struct al_library_script overflow = {.valid = true};
        zcl_command_reply_free(&reply); zcl_command_reply_init(&reply, "zcl.app_open.v1");
        zcl_test_app_library_run(&f.env, &reply, al_library_present, &overflow);
        ASSERT(overflow.valid && overflow.calls == 0 && overflow.errors == 1);
        ASSERT_STR_EQ(reply.error.code, "CATALOG_REFUSED");
        ASSERT(al_write_file(f.env.config_path, "invalid catalog\n", 0600));
        struct al_library_script s = {.valid = true};
        zcl_command_reply_free(&reply); zcl_command_reply_init(&reply, "zcl.app_open.v1");
        zcl_test_app_library_run(&f.env, &reply, al_library_present, &s);
        ASSERT(s.valid && s.calls == 0 && s.errors == 1);
        ASSERT_STR_EQ(reply.error.code, "CATALOG_REFUSED");
    PASS(); }
_test_next:;
    zcl_command_reply_free(&reply);
    return failures;
}

static bool adv_field_exact(const struct zcl_present_model_v1 *m, const char *label, const char *value)
{
    char joined[256] = {0}; size_t used = 0; bool found = false;
    for (uint32_t i = 0; i < m->item_count; ++i) {
        const char *line = m->items[i].value;
        if (!found) {
            size_t n = strlen(label);
            if (strncmp(line, label, n)) continue;
            line += n; found = true;
        } else if (strncmp(line, "  ", 2)) break;
        else line += 2;
        size_t n = strlen(line);
        if (used + n >= sizeof(joined)) return false;
        memcpy(joined + used, line, n); used += n;
    }
    return found && !strcmp(joined, value);
}
static int case_advertisement_view(void)
{
    int failures = 0; struct zcl_app_offer_row row = {0};
    struct zcl_present_model_v1 model; struct zcl_present_model_bitmap_v1 bitmap = {0};
    char why[256]; uint32_t pages = 0;
    memset(row.offer.name, 'w', 63); row.offer.name[63] = '/';
    memset(row.offer.name + 64, 'w', 63);
    memset(row.offer.root, 'f', 64); memset(row.offer.publisher, 'f', 66);
    memset(row.offer.carrier, 'c', 64); memset(row.offer.sha256, 'd', 64);
    memset(row.post_id, 'e', 64); row.offer.size = 1;
    (void)snprintf(row.offer.onion, sizeof(row.offer.onion), "wvbpy5swzmxu2asl5pgausbbcok733mm2p32ytmylu5iqatewj3axcyd.onion:33133");
    TEST("discover card preserves exact identity and renders every page") {
        ASSERT(app_discover_view(&model, &row, 0, 1));
        ASSERT(adv_field_exact(&model, "App: ", row.offer.name));
        ASSERT(adv_field_exact(&model, "Publisher: ", row.offer.publisher));
        ASSERT(adv_field_exact(&model, "Package: ", row.offer.root));
        ASSERT(zcl_present_model_page_count_v1(&model, &pages, why, sizeof(why)));
        ASSERT(pages == 1);
        ASSERT(zcl_present_model_render_v1(&model, &bitmap, why, sizeof(why)));
        zcl_present_model_bitmap_free_v1(&bitmap);
        ASSERT(!app_discover_view(&model, &row, 1, 1));
        ASSERT(model.action_count == 0);
        row.offer.root[0] = 'x';
        ASSERT(!app_discover_view(&model, &row, 0, 1));
        ASSERT(app_discover_view(&model, NULL, 0, 0));
        ASSERT(model.action_count == 2 && strcmp(model.actions[0].id, "review"));
        ASSERT(!app_discover_view(&model, &row, 0, 0));
        PASS();
    } _test_next:;
    zcl_present_model_bitmap_free_v1(&bitmap); return failures;
}

static bool adv_has_action(const struct zcl_present_model_v1 *m,
    const char *id, const char *label)
{
    for (uint32_t i = 0; i < m->action_count; ++i)
        if (!strcmp(m->actions[i].id, id))
            return !label || !strcmp(m->actions[i].label, label);
    return false;
}
static bool adv_empty_guidance(const struct zcl_present_model_v1 *m, bool previous, bool more)
{
    return (strstr(m->summary, "Refresh") != NULL) == !(previous && more) &&
        (strstr(m->summary, "More apps") != NULL) == more &&
        (strstr(m->summary, "Previous page") != NULL) == previous;
}
static bool adv_empty_page(bool previous, bool more)
{
    struct zcl_present_model_v1 m; char why[256];
    if (!app_discover_page_view(&m, NULL, 0, 0, previous, more) ||
        !zcl_present_model_validate_v1(&m, why, sizeof(why))) return false;
    return m.action_count == (previous || more ? 3u : 2u) &&
        m.action_count <= 4 && !adv_has_action(&m, "review", NULL) &&
        adv_empty_guidance(&m, previous, more) &&
        adv_has_action(&m, "back", NULL) &&
        adv_has_action(&m, "next", "More apps") == more &&
        adv_has_action(&m, "previous", "Previous page") == previous &&
        adv_has_action(&m, "refresh", "Refresh") == !(previous && more);
}
static int case_discover_page_view(void)
{
    int failures = 0; struct zcl_app_offer_row row = {0};
    struct zcl_present_model_v1 m; char why[256];
    (void)snprintf(row.offer.name, sizeof(row.offer.name), "example/app");
    memset(row.offer.root, 'f', 64); memset(row.offer.publisher, 'f', 66);
    memset(row.offer.carrier, 'c', 64); memset(row.offer.sha256, 'd', 64);
    memset(row.post_id, 'e', 64); row.offer.size = 1;
    (void)snprintf(row.offer.onion, sizeof(row.offer.onion), "wvbpy5swzmxu2asl5pgausbbcok733mm2p32ytmylu5iqatewj3axcyd.onion:33133");
    TEST("paged discover card navigation is scoped to the current page") {
        ASSERT(app_discover_page_view(&m, &row, 0, 1, true, true));
        ASSERT(zcl_present_model_validate_v1(&m, why, sizeof(why)) && m.action_count <= 4);
        ASSERT(adv_has_action(&m, "review", NULL));
        ASSERT(adv_has_action(&m, "previous", "Previous page"));
        ASSERT(adv_has_action(&m, "next", "More apps"));
        ASSERT(strstr(m.summary, "page") || strstr(m.summary, "Page"));
        ASSERT(app_discover_page_view(&m, &row, 0, 1, false, false));
        ASSERT(zcl_present_model_validate_v1(&m, why, sizeof(why)) && m.action_count <= 4);
        ASSERT(adv_has_action(&m, "refresh", "Refresh"));
        ASSERT(!adv_has_action(&m, "next", NULL));
        /* Empty pages retain only available navigation. */
        ASSERT(adv_empty_page(true, true));
        ASSERT(adv_empty_page(false, true));
        ASSERT(adv_empty_page(true, false));
        ASSERT(adv_empty_page(false, false));
        PASS();
    } _test_next:;
    return failures;
}

/* ── A successful draft Keep with a pending Discover error ─────────────
 * The Keep advanced the selection on disk, so the error reply the caller
 * sees must still carry the kept receipt as bounded failure facts instead
 * of reporting the old Discover error with zero keep evidence. ── */

static const char k_al_keep_makefile[] =
    ".PHONY: app print-app-closure\n"
    "print-app-closure:\n"
    "\t@printf '%s\\n' Makefile include/tiny.h src/main.c\n"
    "app:\n"
    "\tcc -std=c2x -O2 -Iinclude -MD -MF $(APP_OUT)/main.d -c src/main.c "
    "-o $(APP_OUT)/main.o\n"
    "\tcc -o $(APP_OUT)/app $(APP_OUT)/main.o\n";

static const char k_al_keep_meta[] =
    "{\n  \"schema\": 1,\n  \"name\": \"stub/tinyapp\",\n"
    "  \"semver\": \"0.1.0\",\n  \"language\": \"c23\",\n"
    "  \"license\": \"Apache-2.0\",\n  \"include_dir\": \"include\",\n"
    "  \"source_dir\": \"src\",  \"dependencies\": []\n}\n";

static const char k_al_keep_main[] =
    "#include <stdio.h>\n#include <unistd.h>\n#include \"tiny.h\"\n"
    "int main(void) { puts(TINY_NAME \" ready\"); fflush(stdout);\n"
    "    pause(); return 0; }\n";

struct al_keep_xdg { char *config, *state, *home; bool entered; };

struct al_keep_world {
    char root[512], repo[600], worker[PATH_MAX], license[4096];
    char route[APP_SELECTION_ID_MAX + 1], copy_dir[PATH_MAX];
    struct al_keep_xdg xdg;
    struct asf_journey j;
};

/* The stub checkout app.seed accepts, mirroring the app_get journey tree. */
static bool al_keep_checkout(struct al_keep_world *w)
{
    static const char *const tree[][2] = {
        {"", NULL}, {"engine", NULL}, {"engine/composition", NULL},
        {"engine/composition/commands", NULL}, {"tools", NULL},
        {"tools/dev", NULL}, {"apps", NULL}, {"apps/tinyapp", NULL},
        {"apps/tinyapp/include", NULL}, {"apps/tinyapp/src", NULL},
        {"Makefile", "# fixture checkout\n"},
        {"engine/composition/commands/root.def", "\n"},
        {"tools/dev/test_group_catalog.def", "\n"},
        {"apps/tinyapp/zcode-package.json", k_al_keep_meta},
        {"apps/tinyapp/include/tiny.h", "#define TINY_NAME \"tinyapp\"\n"},
        {"apps/tinyapp/src/main.c", k_al_keep_main},
        {"apps/tinyapp/Makefile", k_al_keep_makefile},
        {"apps/tinyapp/LICENSE", ""}};
    bool ok = true;
    for (size_t i = 0; ok && i < sizeof(tree) / sizeof(tree[0]); ++i) {
        char path[PATH_MAX];
        const char *text = tree[i][1];
        if (text && !strcmp(tree[i][0], "apps/tinyapp/LICENSE")) text = w->license;
        ok = snprintf(path, sizeof(path), "%s/%s", w->repo, tree[i][0]) < (int)sizeof(path);
        ok = ok && (text ? asf_put(w->repo, tree[i][0], text)
                         : mkdir(path, 0700) == 0);
    }
    return ok;
}


static bool al_keep_xdg_enter(struct al_keep_xdg *x, const char *home)
{
    memset(x, 0, sizeof(*x));
    const char *config = getenv("XDG_CONFIG_HOME"), *state = getenv("XDG_STATE_HOME");
    const char *own = getenv("HOME");
    x->config = config ? strdup(config) : NULL;
    x->state = state ? strdup(state) : NULL;
    x->home = own ? strdup(own) : NULL;
    if ((config && !x->config) || (state && !x->state) || (own && !x->home)) return false;
    x->entered = true;
    return setenv("XDG_CONFIG_HOME", home, 1) == 0 &&
        setenv("XDG_STATE_HOME", home, 1) == 0 && setenv("HOME", home, 1) == 0;
}

static void al_keep_xdg_leave(struct al_keep_xdg *x)
{
    if (!x->entered) return;
    if (x->config) (void)setenv("XDG_CONFIG_HOME", x->config, 1);
    else (void)unsetenv("XDG_CONFIG_HOME");
    if (x->state) (void)setenv("XDG_STATE_HOME", x->state, 1);
    else (void)unsetenv("XDG_STATE_HOME");
    if (x->home) (void)setenv("HOME", x->home, 1);
    else (void)unsetenv("HOME");
    free(x->config);
    free(x->state);
    free(x->home);
    memset(x, 0, sizeof(*x));
}

/* The kept route name a receive of this copy commits under: the same
 * framed fork/copy/datadir hash the receive route domain names. */
static bool al_keep_route_name(const char *copy_dir, const char *datadir,
    char out[APP_SELECTION_ID_MAX + 1])
{
    struct zcl_package_copy copy;
    struct zcl_command_reply why;
    struct sha3_256_ctx sha;
    uint8_t digest[32];
    char hex[65], canonical[PATH_MAX], home[PATH_MAX];
    zcl_command_reply_init(&why, "zcl.test.app_launch.v1");
    bool ok = realpath(copy_dir, canonical) && realpath(datadir, home);
    if (!ok)
        printf("  [keep-receipt: route paths unavailable (%s, %s)]\n", copy_dir, datadir);
    if (ok) {
        /* READ opens the copy's own selected version. */
        ok = zcl_package_copy_open_selected_as(canonical, ZCL_PACKAGE_COPY_READ,
            &copy, &why, "test.app_launch", NULL);
        if (!ok)
            printf("  [keep-receipt: route copy open refused: %s (%.120s)]\n",
                   why.error.code, why.error.message);
    }
    if (ok) {
        sha3_256_init(&sha);
        sha3_256_write(&sha, (const unsigned char *)"zcl.app.receive.route.v1",
            sizeof("zcl.app.receive.route.v1"));
        sha3_256_write(&sha, copy.fork_version, 32);
        sha3_256_write(&sha, (const unsigned char *)canonical, strlen(canonical) + 1);
        sha3_256_write(&sha, (const unsigned char *)home, strlen(home) + 1);
        sha3_256_finalize(&sha, digest);
        zcl_hex_encode(digest, 32, hex);
        ok = snprintf(out, APP_SELECTION_ID_MAX + 1, "kept:received-%.18s", hex) <
            (int)(APP_SELECTION_ID_MAX + 1);
        zcl_package_copy_close(&copy);
    }
    zcl_command_reply_free(&why);
    return ok;
}

/* The keep input names the exact build identity the build leaf just named. */
static bool al_keep_input_from_build(struct asf_leaf *keep, const struct asf_leaf *build,
    const char *route, const char *copy_dir, const char *datadir)
{
    asf_open(keep);
    return json_push_kv_str(&keep->in, "name", route) &&
        json_push_kv_str(&keep->in, "version", asf_get(build, "version")) &&
        json_push_kv_str(&keep->in, "copy", copy_dir) &&
        json_push_kv_str(&keep->in, "datadir", datadir) &&
        json_push_kv_str(&keep->in, "env_root", asf_get(build, "env_root")) &&
        json_push_kv_str(&keep->in, "dependency_root", asf_get(build, "dependency_root")) &&
        json_push_kv_str(&keep->in, "image_sha3", asf_get(build, "image_sha3")) &&
        json_push_kv_str(&keep->in, "record_id", asf_get(build, "record_id")) &&
        json_push_kv_int(&keep->in, "expected_revision", 0) &&
        json_push_kv_bool(&keep->in, "accept_execution", true);
}

/* Keep B's received copy through the app.keep leaf: the build leaf names its
 * exact roots, and keep pins them as B's saved choice (revision 1). */
static bool al_keep_received_kept(struct al_keep_world *w)
{
    char route[APP_SELECTION_ID_MAX + 1], copy_dir[PATH_MAX];
    struct asf_leaf build, keep;
    int n = snprintf(copy_dir, sizeof(copy_dir), "%s/copies/%s", w->j.b_datadir, w->j.b_copy);
    if (n <= 0 || (size_t)n >= sizeof(copy_dir)) return false;
    (void)snprintf(w->copy_dir, sizeof(w->copy_dir), "%s", copy_dir);
    asf_build(&build, copy_dir, w->j.b_datadir);
    bool ok = build.out.status == ZCL_COMMAND_STATUS_PASSED;
    if (!ok)
        printf("  [keep-receipt: B's app.build refused: %s]\n", build.out.error.code);
    ok = ok && al_keep_route_name(copy_dir, w->j.b_datadir, route);
    if (ok) (void)snprintf(w->route, sizeof(w->route), "%s", route);
    if (!ok && build.out.status == ZCL_COMMAND_STATUS_PASSED)
        printf("  [keep-receipt: B's kept route name failed]\n");
    if (ok) {
        ok = al_keep_input_from_build(&keep, &build, route, copy_dir, w->j.b_datadir) &&
            asf_exec("app.keep", &keep) &&
            keep.out.status == ZCL_COMMAND_STATUS_PASSED &&
            !strcmp(asf_get(&keep, "status"), "kept");
        if (!ok)
            printf("  [keep-receipt: B's app.keep refused: %s]\n", keep.out.error.code);
        asf_close(&keep);
    }
    asf_close(&build);
    return ok;
}

/* A: seed, copy, one edit, then save, build, open and share. */
static bool al_keep_a_side(struct al_keep_world *w)
{
    if (!al_keep_xdg_enter(&w->xdg, w->j.a_home)) return false;
    bool ok = asf_journey_copy(&w->j) &&
        asf_put(w->j.a_copy, "include/tiny.h", "#define TINY_NAME \"tinyapp-shared\"\n") &&
        asf_journey_save_build_open(&w->j) && asf_journey_share(&w->j);
    al_keep_xdg_leave(&w->xdg);
    return ok;
}

/* B: receive A's share in her own home, then keep it (revision 1). */
static bool al_keep_b_side(struct al_keep_world *w)
{
    if (!al_keep_xdg_enter(&w->xdg, w->j.b_home)) return false;
    bool ok = asf_journey_receive(&w->j) && al_keep_received_kept(w);
    if (!ok) al_keep_xdg_leave(&w->xdg);
    return ok;
}

/* Real received and kept tinyapp in B's home, every step through the typed
 * leaves. A's HOME and XDG roots are entered for A's steps, B's for hers,
 * so B's receive commits its state into her own home instead of A's or the
 * runner's. */
static bool al_keep_world_init(struct al_keep_world *w)
{
    memset(w, 0, sizeof(*w));
    FILE *f = fopen("apps/skycombat/LICENSE", "rb");
    size_t n = f ? fread(w->license, 1, sizeof(w->license) - 1u, f) : 0;
    if (f) (void)fclose(f);
    w->license[n] = 0;
    if (!n || !test_mkdtemp(w->root, sizeof(w->root), "app_launch_keep") ||
        !realpath("build/bin/z23-dev", w->worker))
        return false;
    (void)snprintf(w->repo, sizeof(w->repo), "%s/repo", w->root);
    return al_keep_checkout(w) &&
        asf_journey_init(&w->j, "tinyapp", w->repo, w->root) &&
        al_keep_a_side(w) && al_keep_b_side(w);
}

struct al_keep_script {
    bool valid, saw_review, saw_preview, kept_card;
    unsigned home_calls, errors, notices, cards;
    char last_summary[241], card_value[128];
};

/* The node's board refusal, verbatim, so Discover fails with the real
 * named error instead of an offline transport guess. */
static char *al_keep_board_down(const char *method, const char *params)
{
    (void)params;
    if (strcmp(method, "fleet_board")) return NULL;
    return strdup("{\"ok\":false,\"code\":\"NODE_DB_UNAVAILABLE\",\"message\":"
        "\"the node database is not open; the board lives in it\"}");
}

static bool al_keep_press(const struct zcl_present_model_v1 *model,
    struct zcl_present_window_event_v1 *event, const char *id)
{
    for (unsigned i = 0; i < model->action_count; ++i)
        if (!strcmp(model->actions[i].id, id)) {
            event->struct_size = sizeof(*event);
            event->abi_version = ZCL_PRESENT_ABI_V1;
            event->outcome = ZCL_PRESENT_WINDOW_ACTION;
            event->action_index = i;
            return true;
        }
    return false;
}

/* home(discover) -> options(catalog) -> error(back) -> home(myapps)
 * -> list(choose) -> card(change-options) -> page(draft). */
static bool al_keep_room(void *context, const struct zcl_present_model_v1 *model,
    const char *copy, struct zcl_present_window_event_v1 *event, char *why, size_t cap)
{
    struct al_keep_script *s = context;
    (void)copy;
    s->valid = s->valid && zcl_present_model_validate_v1(model, why, cap);
    (void)snprintf(s->last_summary, sizeof(s->last_summary), "%s", model->summary);
    event->struct_size = sizeof(*event);
    event->abi_version = ZCL_PRESENT_ABI_V1;
    event->outcome = ZCL_PRESENT_WINDOW_ACTION;
    if (!strcmp(model->request_id, "library-home")) {
        ++s->home_calls;
        return al_keep_press(model, event, s->home_calls == 1 ? "discover" : "myapps");
    }
    if (!strcmp(model->request_id, "library-discover-options"))
        return al_keep_press(model, event, "catalog");
    if (!strcmp(model->request_id, "discover-error")) {
        ++s->errors;
        return al_keep_press(model, event, "back");
    }
    if (!strncmp(model->request_id, "library-", 8) && model->action_count) {
        if (!strcmp(model->actions[0].id, "choose"))
            return al_keep_press(model, event, "choose");
        if (!strcmp(model->actions[0].id, "open")) {
            /* The second app card is the kept one: this visit proves the room
             * stayed open after the Keep instead of ejecting the user. */
            if (++s->cards >= 2) {
                s->kept_card = true;
                if (model->item_count)
                    (void)snprintf(s->card_value, sizeof(s->card_value), "%s", model->items[0].value);
                event->outcome = ZCL_PRESENT_WINDOW_DISMISSED;
                return true;
            }
            return al_keep_press(model, event, "change-options");
        }
        if (!strcmp(model->actions[0].id, "draft"))
            return al_keep_press(model, event, "draft");
    }
    s->valid = false;
    event->outcome = ZCL_PRESENT_WINDOW_DISMISSED;
    return true;
}

/* The draft flow's own windows: press continue on each choice (every page
 * must be visited before Keep confirms) and wait out each progress window. */
static bool al_keep_notice(void *context, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_live_view_v1 *live, char *why, size_t cap)
{
    struct al_keep_script *s = context;
    (void)pages;
    s->valid = s->valid && zcl_present_model_validate_v1(model, why, cap);
    ++s->notices;
    s->saw_review |= model->action_count == 4 && !strcmp(model->title, "Review unkept changes");
    s->saw_preview |= model->action_count == 4 && !strcmp(model->title, "Preview opened");
    bool redraw = false, close = false;
    if (model->action_count == 4 && !strcmp(model->actions[3].id, "continue")) {
        for (unsigned i = 0; i < 16 && !close; ++i) {
            struct zcl_present_window_event_v1 event = {
                .outcome = ZCL_PRESENT_WINDOW_ACTION, .action_index = 3};
            live->owner.update(live->owner.context, &event, false, &redraw, &close);
        }
        s->valid = s->valid && close;
        return close;
    }
    if (!model->action_count) {
        const int64_t end = platform_time_monotonic_ms() + 120000;
        do {
            live->owner.update(live->owner.context, NULL, false, &redraw, &close);
            if (close) return true;
            platform_sleep_ms(1); /* real-clock: waiting on this owner's worker */
        } while (platform_time_monotonic_ms() < end);
        s->valid = false;
        return false;
    }
    s->valid = false;
    return false;
}

/* Stop the app the draft preview opened, identified by its kept image. */
static bool al_keep_stop_app(const struct json_value *kept, const char *datadir)
{
    const char *image = zcl_package_copy_str(kept, "image_sha3");
    char path[PATH_MAX], resolved[PATH_MAX];
    if (!image || strlen(image) != 64 ||
        snprintf(path, sizeof(path), "%s/app_build/images/%s", datadir, image) >= (int)sizeof(path) ||
        !realpath(path, resolved))
        return false;
    DIR *d = opendir("/proc");
    bool stopped = false;
    struct dirent *e;
    while (d && !stopped && (e = readdir(d))) {
        char link[128], exe[PATH_MAX];
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        int n = snprintf(link, sizeof(link), "/proc/%.60s/exe", e->d_name);
        ssize_t len = n > 0 && n < (int)sizeof(link) ? readlink(link, exe, sizeof(exe) - 1) : -1;
        if (len <= 0) continue;
        exe[len] = 0;
        if (!strcmp(exe, resolved)) stopped = asf_alive_then_stop(strtol(e->d_name, NULL, 10));
    }
    if (d) (void)closedir(d);
    return stopped;
}

/* The kept receipt names exactly the selection now on disk. */
static bool al_keep_receipt_matches(const struct json_value *kept,
    const struct app_selection *after)
{
    char version[65], image[65], record[65];
    zcl_hex_encode(after->version, 32, version);
    zcl_hex_encode(after->image, 32, image);
    zcl_hex_encode(after->record, 32, record);
    const struct json_value *revision = json_get(kept, "selection_revision");
    return !strcmp(zcl_package_copy_str(kept, "name"), after->app) &&
        !strcmp(zcl_package_copy_str(kept, "version"), version) &&
        !strcmp(zcl_package_copy_str(kept, "image_sha3"), image) &&
        !strcmp(zcl_package_copy_str(kept, "record_id"), record) &&
        revision && revision->type == JSON_INT &&
        json_get_int(revision) == (int64_t)after->revision;
}

static bool al_keep_edit(const struct al_keep_world *w, const struct app_selection *prior,
    char head[65])
{
    char prior_version[65];
    zcl_hex_encode(prior->version, 32, prior_version);
    struct asf_leaf leaf;
    asf_open(&leaf);
    bool ok = asf_put(w->copy_dir, "include/tiny.h", "#define TINY_NAME \"tinyapp-edited\"\n") &&
        json_push_kv_str(&leaf.in, "dir", w->copy_dir) &&
        asf_plan_confirm("zcode.package.version.save", &leaf);
    if (ok) (void)snprintf(head, 65, "%s", asf_get(&leaf, "version"));
    asf_close(&leaf);
    return ok && strlen(head) == 64 && strcmp(head, prior_version) != 0;
}

static int case_library_keep_receipt(void)
{
    int failures = 0;
    static struct al_keep_world w;
    struct al_keep_script s = {.valid = true};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.app_open.v1");
    if (!al_keep_world_init(&w)) {
        if (w.root[0]) (void)test_rm_rf_recursive(w.root);
        printf("  [keep-receipt: the tinyapp journey fixture could not be built]\n");
        return 1;
    }
    TEST("A pending Discover error does not bury a successful draft Keep") {
        struct app_launch_env env;
        char why[256];
        ASSERT(app_launch_env_from_process(&env, why, sizeof(why)));
        env.desktop = true; /* the draft preview opens the built app */

        struct app_selection prior, after;
        ASSERT(app_selection_load(env.state_dir, w.route, &prior) == APP_SELECTION_OK);
        char head[65];
        ASSERT(al_keep_edit(&w, &prior, head));
        node_rpc_client_set_test_hook(al_keep_board_down);
        /* The draft preview jobs spawn the worker with the bridge's datadir
         * and port; point them at B's profile for the room run. The preview
         * open needs a desktop session name: a synthetic one, as this child
         * has no windows and proves no GUI behavior. */
        char old_dir[PATH_MAX];
        (void)snprintf(old_dir, sizeof(old_dir), "%s", zcl_native_command_datadir());
        int old_port = zcl_native_command_rpc_port();
        const char *saved_display = getenv("DISPLAY");
        char *old_display = saved_display ? strdup(saved_display) : NULL;
        ASSERT(setenv("DISPLAY", ":synthetic-nonvisual", 1) == 0);
        zcl_native_bridge_bind_rpc(w.j.b_datadir, 39471);
        zcl_test_app_library_discover_worker(&env, w.j.b_datadir, &reply,
            al_keep_room, al_keep_notice, &s, w.worker);
        if (old_display) (void)setenv("DISPLAY", old_display, 1);
        else (void)unsetenv("DISPLAY");
        free(old_display);
        zcl_native_bridge_bind_rpc(old_dir, old_port);
        node_rpc_client_set_test_hook(NULL);
        ASSERT(s.valid && s.errors == 1 && s.home_calls == 2);
        ASSERT(s.saw_review && s.saw_preview);
        /* The defect: with the old guard the room closed after the Keep and
         * the caller got a kept reply also marked canceled, with the session's
         * receipts lost. The room must return to the kept card instead. */
        ASSERT(s.kept_card);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_PASSED && reply.error.mutated);
        ASSERT(reply.error.code[0] == '\0');
        ASSERT_STR_EQ(json_get_str(json_get(&reply.data, "continuation")), "kept");
        ASSERT(!json_get(&reply.data, "status")); /* not a canceled session */
        const struct json_value *kept = json_get(&reply.data, "kept");
        ASSERT(kept);
        ASSERT(app_selection_load(env.state_dir, w.route, &after) == APP_SELECTION_OK);
        ASSERT(after.revision == prior.revision + 1);
        char version[65];
        zcl_hex_encode(after.version, 32, version);
        ASSERT_STR_EQ(version, head);
        ASSERT(al_keep_receipt_matches(kept, &after));
        ASSERT(!json_get(&reply.data, "failure_facts"));
        ASSERT(al_keep_stop_app(kept, w.j.b_datadir));
        PASS();
    } _test_next:;
    zcl_command_reply_free(&reply);
    al_keep_xdg_leave(&w.xdg);
    if (w.root[0] && test_rm_rf_recursive(w.root) != 0) ++failures;
    return failures;
}

int test_app_launch(void);
int test_app_launch(void)
{
    int failures = 0;
    static struct al_fx f;
    TEST("fixture: the stand-in app and a temporary apps.tsv") {
        ASSERT(al_setup(&f));
    PASS(); }
_test_next:
    if (failures)
        return failures;
    failures += case_open_raise_reopen(&f);
    failures += case_refusals(&f);
    failures += case_raise_declaration(&f);
    failures += case_unsafe_tsv(&f);
    failures += case_stale_record(&f);
    failures += case_process_env(&f);
    failures += case_handlers(&f);
    failures += case_discover();
    failures += case_advertisement_view();
    failures += case_discover_page_view();
    failures += case_preview();
    failures += case_resident_app(&f, f.bin_ready, "ready", true, false);
    failures += case_resident_app(&f, f.bin_exit, "exit", false, true);
    failures += case_resident_app(&f, f.bin_silent, "silent", false, false);
    failures += case_resident_mutation(&f);
    failures += case_library(&f);
    failures += case_library_create_view();
    failures += case_library_create_flow();
    failures += case_library_share(&f);
    failures += case_library_help();
    failures += case_library_help_copy();
    failures += case_library_prepare_stop();
    failures += case_library_share_prepare();
    failures += case_library_setup_stop();
    failures += case_library_repeat_prepare();
    failures += case_library_received_recovery();
    failures += case_library_tight_budget();
    failures += case_library_profile_input();
    failures += case_library_builtin_help();
    failures += case_library_bounds();
    failures += case_library_keep_receipt();
    al_kill_all();
    return failures;
}

#else

int test_app_launch(void);
int test_app_launch(void)
{
    printf("SKIP (app_launch: desktop launch is POSIX-only)\n");
    return 0;
}

#endif
