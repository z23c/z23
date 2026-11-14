/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the whole app journey on the real game, with ONE owner key in
 * ONE ISO week, every step a `z23 app` front-door verb as typed:
 *
 *   A (in this checkout)  copy skycombat   app.seed publishes the game with
 *                                          A's key, then the copy adopts it
 *                         edit             DEFAULT_FOV 60 -> 65 in
 *                                          src/views/camera_controller.c
 *                         save, build      the copy's own image
 *                         open             the game on a private Xvfb
 *                         <image> --qa-frames=120 exits 0
 *                         share            skycombat-1.z23share, the second
 *                                          publish with A's key this week
 *   B (own HOME)          open skycombat-1.z23share   receive, build, open
 *                         <image> --qa-frames=120 exits 0
 *                         open retained copy, confirm execution, same image
 *                         fresh CLI --yes reopens the same saved image
 *
 * B's image_sha3 equals A's for the shared version. The build needs no
 * system -dev package (the X11/GL headers are vendored); the runs need
 * Xvfb. Without it the group prints SKIP, and the host-need row keeps it
 * out of universal selection unless the operator sets ZCL_TEST_DISPLAY_APPS.
 *
 * make t-fast-exact ONLY=app_journey_skycombat ZCL_TEST_DISPLAY_APPS=1 */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_core.h"
#include "test/app_seed_fixture.h"
#include "test/host_tool_capture.h"

#include "chain/chainparams.h"
#include "platform/time_compat.h"
#include "command/native_app_launch.h"

#if defined(__linux__)
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

struct ajs_world {
    char root[512];
    char source[1200];
    char saved_home[1024], saved_cwd[1200], saved_display[256];
    bool had_display;
    pid_t xvfb;
    struct asf_journey j;
};

static bool ajs_world_init(struct ajs_world *w)
{
    memset(w, 0, sizeof(*w));
    const char *home = getenv("HOME"), *display = getenv("DISPLAY");
    (void)snprintf(w->saved_home, sizeof(w->saved_home), "%s",
                   home ? home : "");
    w->had_display = display != NULL;
    (void)snprintf(w->saved_display, sizeof(w->saved_display), "%s",
                   display ? display : "");
    if (!getcwd(w->source, sizeof(w->source)) ||
        !test_mkdtemp(w->root, sizeof(w->root), "app_journey_skycombat"))
        return false;
    (void)snprintf(w->saved_cwd, sizeof(w->saved_cwd), "%s", w->source);
    return asf_journey_init(&w->j, "skycombat", w->source, w->root);
}

static void ajs_world_restore(const struct ajs_world *w)
{
    if (w->saved_cwd[0] && chdir(w->saved_cwd) != 0)
        printf("  [could not return to %s]\n", w->saved_cwd);
    if (w->saved_home[0])
        (void)setenv("HOME", w->saved_home, 1);
    if (w->had_display)
        (void)setenv("DISPLAY", w->saved_display, 1);
    else
        (void)unsetenv("DISPLAY");
}

static int ajs_a(struct ajs_world *w)
{
    int failures = 0;
    TEST("app journey skycombat A: copy seeds the game with the owner key, "
         "edit one constant, save, build, open, 120 QA frames, share") {
        ASSERT(asf_journey_copy(&w->j));
        ASSERT(asf_replace(w->j.a_copy, "src/views/camera_controller.c",
                           "#define DEFAULT_FOV 60.0f",
                           "#define DEFAULT_FOV 65.0f"));
        ASSERT(asf_journey_save_build_open(&w->j));
        ASSERT(asf_journey_share(&w->j));
        ASSERT_EQ(asf_qa_frames(w->j.path_shared), 0);
        PASS();
    } _test_next:;
    return failures;
}

/* The front-door handler runs in process; this does not claim a fresh CLI
 * process or My Apps recovery. Stop the launched game before assertions. */
static bool ajs_b_reopen(struct asf_journey *j)
{
    struct asf_door run;
    char image[80], question[512];
    asf_door_run(j->b_home, j->b_home, j->b_datadir, "open", j->b_copy,
                 ZCL_CLI_CONFIRM_ASK, &run);
    ++j->commands_b;
    bool stopped = asf_alive_then_stop(asf_door_pid(run.text));
    (void)asf_door_line(&run, "image_sha3", image, sizeof(image));
    int n = snprintf(question, sizeof(question), "Run %s's build %.16s?",
                     j->b_copy, j->image_b);
    bool consent = n > 0 && (size_t)n < sizeof(question) && run.asked &&
                   strcmp(run.question, question) == 0;
    bool same = !strcmp(image, j->image_b) && !strcmp(image, j->image_shared);
    if (run.rc || !stopped || !consent || !same)
        printf("  [receiver reopen: rc=%d stopped=%d consent=%d same=%d]\n%s",
               run.rc, stopped, consent, same, run.text);
    return run.rc == 0 && stopped && consent && same;
}

/* A fresh CLI process opens B's saved copy; always stop a reported game
 * before evaluating the response. */
static bool ajs_cli_prepare(const struct ajs_world *w, char *binary, size_t bcap,
                            char *datadir, size_t dcap)
{
    const struct asf_journey *j = &w->j;
    int n = snprintf(binary, bcap, "%s/build/bin/z23-dev", w->source);
    int d = snprintf(datadir, dcap, "-datadir=%s", j->b_datadir);
    if (n <= 0 || (size_t)n >= bcap || d <= 0 || (size_t)d >= dcap ||
        !j->b_copy[0] || strchr(j->b_copy, '/') || !strcmp(j->b_copy, ".") ||
        !strcmp(j->b_copy, "..") || setenv("HOME", j->b_home, 1) != 0 ||
        chdir(j->b_home) != 0) return false;
    return true;
}

/* The CLI's adopted descendants remain in this harness's custody even if
 * its output is lost. Enumerate only direct children, bounded and complete. */
static bool ajs_children(pid_t pids[32], size_t *count)
{
    char path[96], text[4096];
    *count = 0;
    (void)snprintf(path, sizeof(path), "/proc/self/task/%ld/children", (long)getpid());
    FILE *f = fopen(path, "r");
    if (!f) return false;
    size_t n = fread(text, 1, sizeof(text) - 1, f);
    bool read_ok = !ferror(f) && feof(f);
    bool close_ok = fclose(f) == 0;
    if (!read_ok || !close_ok) return false;
    text[n] = '\0';
    char *p = text;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;
        char *end = NULL; errno = 0;
        long pid = strtol(p, &end, 10);
        if (errno || end == p || pid <= 1 || pid > INT_MAX || *count == 32) return false;
        pids[(*count)++] = (pid_t)pid;
        p = end;
    }
    return true;
}

struct ajs_custody {
    pid_t display;
    const char *cli, *game;
    long reported;
    bool saw_game, saw_reported;
};

static bool ajs_child_identify(pid_t pid, struct ajs_custody *c)
{
    char image[APP_LAUNCH_PATH_MAX], again[APP_LAUNCH_PATH_MAX];
    uint64_t born = 0, check = 0;
    if (!app_proc_identity(pid, image, &born) || !born ||
        (strcmp(image, c->cli) && strcmp(image, c->game)) ||
        !app_proc_identity(pid, again, &check) || check != born || strcmp(image, again)) {
        fprintf(stderr, "receiver CLI: unknown adopted child pid=%ld\n", (long)pid);
        return false;
    }
    if (!strcmp(image, c->game)) {
        c->saw_game = true;
        if ((long)pid == c->reported) c->saw_reported = true;
    }
    return true;
}

static bool ajs_child_stop(pid_t pid, struct ajs_custody *c)
{
    int status = 0;
    pid_t reaped = waitpid(pid, &status, WNOHANG);
    if (reaped == pid) {
        fprintf(stderr, "receiver CLI: adopted child exited before identification pid=%ld\n", (long)pid);
        return false;
    }
    if (reaped != 0 || !ajs_child_identify(pid, c)) return false;
    if (kill(pid, SIGKILL) != 0 && errno != ESRCH) return false;
    for (int i = 0; i < 200; i++) {
        reaped = waitpid(pid, &status, WNOHANG);
        if (reaped == pid) return true;
        if (reaped < 0 && errno != EINTR) return false;
        platform_sleep_ms(10); /* real-clock: reap an owned CLI descendant */
    }
    return false;
}

static bool ajs_children_clean(struct ajs_custody *c)
{
    for (int pass = 0; pass < 8; pass++) {
        pid_t pids[32]; size_t n = 0; bool found = false;
        if (!ajs_children(pids, &n)) return false;
        for (size_t i = 0; i < n; i++) {
            if (pids[i] == c->display) continue;
            found = true;
            if (!ajs_child_stop(pids[i], c)) return false;
        }
        if (!found) return true;
    }
    return false;
}

static bool ajs_child_baseline(pid_t display)
{
    pid_t pids[32]; size_t n = 0;
    if (!ajs_children(pids, &n)) return false;
    for (size_t i = 0; i < n; i++) if (pids[i] != display) return false;
    return true;
}

struct ajs_env { const char *name; char *old; };

static bool ajs_env_restore(struct ajs_env env[3], size_t n)
{
    bool ok = true;
    for (size_t i = 0; i < n; i++) {
        int rc = env[i].old ? setenv(env[i].name, env[i].old, 1) : unsetenv(env[i].name);
        if (rc != 0) ok = false;
        free(env[i].old);
    }
    return ok;
}

static bool ajs_env_enter(struct ajs_env env[3], const char *home)
{
    for (size_t i = 0; i < 3; i++) {
        const char *old = getenv(env[i].name);
        env[i].old = old ? strdup(old) : NULL;
        if (old && !env[i].old) {
            for (size_t j = 0; j < i; j++) free(env[j].old);
            return false;
        }
    }
    for (size_t i = 0; i < 3; i++) {
        if (setenv(env[i].name, home, 1) != 0) {
            (void)ajs_env_restore(env, 3);
            return false;
        }
    }
    return true;
}

struct ajs_cli_result { bool clean, saw_game, saw_reported, accepted; int rc; };

static void ajs_cli_check(struct ajs_cli_result *result, struct asf_door *run,
                          const struct asf_journey *j, size_t cap)
{
    char image[80];
    (void)asf_door_line(run, "image_sha3", image, sizeof(image));
    bool complete = cap > 1 && strlen(run->text) < cap - 1;
    bool same = !strcmp(image, j->image_b) && !strcmp(image, j->image_shared);
    result->accepted = result->rc == 0 && result->clean && result->saw_reported && same && complete;
    if (!result->accepted)
        printf("  [receiver CLI reopen: rc=%d clean=%d game=%d reported=%d same=%d complete=%d]\n%s",
               result->rc, result->clean, result->saw_game, result->saw_reported, same, complete, run->text);
}

static struct ajs_cli_result ajs_b_cli_attempt(struct ajs_world *w, size_t cap)
{
    struct asf_journey *j = &w->j;
    struct asf_door run = {0};
    struct ajs_cli_result result = {.rc = -1};
    struct ajs_env env[3] = {{"XDG_STATE_HOME", NULL}, {"XDG_DATA_HOME", NULL},
                             {"XDG_CONFIG_HOME", NULL}};
    char binary[1400], datadir[800], cli_real[PATH_MAX], game_real[PATH_MAX];
    if (!ajs_cli_prepare(w, binary, sizeof(binary), datadir, sizeof(datadir)) ||
        !realpath(binary, cli_real) || !realpath(j->path_b, game_real) ||
        !ajs_child_baseline(w->xvfb) || !ajs_env_enter(env, j->b_home)) return result;
    int old_subreaper = 0;
    if (prctl(PR_GET_CHILD_SUBREAPER, &old_subreaper) != 0 ||
        prctl(PR_SET_CHILD_SUBREAPER, 1) != 0) {
        (void)ajs_env_restore(env, 3);
        return result;
    }
    const char *argv[] = {binary, datadir, "app", "open", j->b_copy, "--yes", NULL};
    result.rc = test_host_tool_capture(argv, run.text, cap, 60000);
    struct ajs_custody c = {.display = w->xvfb, .cli = cli_real, .game = game_real,
                            .reported = asf_door_pid(run.text)};
    bool clean = ajs_children_clean(&c) && ajs_child_baseline(w->xvfb);
    bool restored = clean && prctl(PR_SET_CHILD_SUBREAPER, old_subreaper) == 0;
    bool env_restored = ajs_env_restore(env, 3);
    result.clean = clean && restored && env_restored;
    result.saw_game = c.saw_game;
    result.saw_reported = c.saw_reported;
    ajs_cli_check(&result, &run, j, cap);
    if (result.rc == 0) ++j->commands_b;
    return result;
}

static int ajs_b(struct ajs_world *w)
{
    int failures = 0;
    TEST("app journey skycombat B: open the share file receives, builds A's "
         "image, opens it; 120 QA frames") {
        ASSERT(asf_journey_receive(&w->j));
        ASSERT_EQ(asf_qa_frames(w->j.path_b), 0);
        ASSERT(ajs_b_reopen(&w->j));
        struct ajs_cli_result cli = ajs_b_cli_attempt(w, ASF_DOOR_OUT);
        ASSERT(cli.accepted);
        struct ajs_cli_result lost = ajs_b_cli_attempt(w, 1);
        ASSERT(lost.rc == 0 && !lost.accepted && lost.clean && lost.saw_game && !lost.saw_reported);
        PASS();
    } _test_next:;
    return failures;
}

int test_app_journey_skycombat(void);
int test_app_journey_skycombat(void)
{
    int failures = 0;
    const char *xvfb = asf_xvfb_path();
    struct ajs_world w;
    chain_params_select(CHAIN_MAIN);
    if (!xvfb) {
        printf("app journey skycombat... SKIP (no Xvfb: the game cannot run "
               "here)\n");
        return 0;
    }
    TEST("app journey skycombat: two HOMEs and datadirs, a private Xvfb") {
        ASSERT(ajs_world_init(&w));
        ASSERT(asf_xvfb_start(xvfb, w.root, &w.xvfb));
        PASS();
    } _test_next:;
    if (!failures)
        failures += ajs_a(&w);
    if (!failures)
        failures += ajs_b(&w);
    asf_xvfb_stop(&w.xvfb);
    printf("app journey skycombat: %s image_sha3 A=%s B=%s; A typed %d "
           "commands, B typed %d\n", failures ? "FAIL" : "PASS",
           w.j.image_shared, w.j.image_b, w.j.commands_a, w.j.commands_b);
    ajs_world_restore(&w);
    if (!failures)
        (void)test_rm_rf_recursive(w.root);
    return failures;
}

#else

int test_app_journey_skycombat(void);
int test_app_journey_skycombat(void)
{
    printf("app_journey_skycombat... SKIP (Linux only: Xvfb)\n");
    return 0;
}

#endif
