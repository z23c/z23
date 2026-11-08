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

#include "command/native_app_launch.h"
#include "command/native_app_library_command.h"
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
    unsigned actions[40], count, calls, errors;
    bool valid, saved_label;
    char last_summary[241];
};
static bool al_library_present(void *context, const struct zcl_present_model_v1 *model,
    struct zcl_present_window_event_v1 *event, char *why, size_t cap)
{
    struct al_library_script *s = context;
    s->valid = s->valid && zcl_present_model_validate_v1(model, why, cap);
    struct zcl_present_model_bitmap_v1 bitmap = {0};
    s->valid = s->valid && zcl_present_model_render_v1(model, &bitmap, why, cap) && bitmap.pixels;
    zcl_present_model_bitmap_free_v1(&bitmap);
    event->struct_size = sizeof(*event); event->abi_version = ZCL_PRESENT_ABI_V1;
    event->outcome = ZCL_PRESENT_WINDOW_ACTION;
    if (!strcmp(model->request_id, "library-error")) { ++s->errors; event->action_index = 0; return true; }
    s->saved_label |= strstr(model->items[0].value, "Saved version") != NULL;
    s->valid = s->valid && zcl_present_canvas_text_width(model->items[0].value,
        strlen(model->items[0].value), 14u) <= 296u;
    (void)snprintf(s->last_summary, sizeof(s->last_summary), "%s", model->summary);
    if (s->calls >= s->count) { s->valid = false; event->outcome = ZCL_PRESENT_WINDOW_DISMISSED; return true; }
    event->action_index = s->actions[s->calls++];
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
static int case_library(struct al_fx *f)
{
    int failures = 0;
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.app_open.v1");
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
static int case_library_bounds(void)
{
    int failures = 0;
    static struct al_fx f;
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_open.v1");
    TEST("My Apps empty catalog has only Close and executes nothing") {
        ASSERT(al_setup(&f));
        ASSERT(al_write_file(f.env.config_path, "", 0600));
        struct al_library_script s = {.actions = {0}, .count = 1, .valid = true};
        zcl_test_app_library_run(&f.env, &reply, al_library_present, &s);
        ASSERT(s.valid && s.calls == 1 && !s.errors && strstr(s.last_summary, "No apps yet"));
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
    failures += case_preview();
    failures += case_resident_app(&f, f.bin_ready, "ready", true, false);
    failures += case_resident_app(&f, f.bin_exit, "exit", false, true);
    failures += case_resident_app(&f, f.bin_silent, "silent", false, false);
    failures += case_resident_mutation(&f);
    failures += case_library(&f);
    failures += case_library_bounds();
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
