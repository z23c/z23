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
#include "test/app_ui_fixture.h"

#include "chain/chainparams.h"
#include "platform/time_compat.h"
#include "command/native_app_launch.h"
#include "command/native_app_receive_preview.h"
#include "command/native_app_confirm.h"
#include "command/app_selection.h"
#include "base/hex.h"

#if defined(__linux__)
#include <errno.h>
#include <fcntl.h>
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
    const char *cli, *game, *make, *shell;
    long reported;
    uint64_t reported_token;
    bool saw_game, saw_reported;
};

static bool ajs_reported_matches(const struct ajs_custody *c, pid_t pid, uint64_t born)
{ return (long)pid == c->reported && (!c->reported_token || c->reported_token == born); }

static bool ajs_child_identify(pid_t pid, struct ajs_custody *c)
{
    char image[APP_LAUNCH_PATH_MAX], again[APP_LAUNCH_PATH_MAX];
    uint64_t born = 0, check = 0;
    if (!app_proc_identity(pid, image, &born) || !born ||
        (strcmp(image, c->cli) && strcmp(image, c->game) &&
         (!c->make || strcmp(image, c->make)) && (!c->shell || strcmp(image, c->shell))) ||
        !app_proc_identity(pid, again, &check) || check != born || strcmp(image, again)) {
        fprintf(stderr, "receiver CLI: unknown adopted child pid=%ld\n", (long)pid);
        return false;
    }
    if (!strcmp(image, c->game)) {
        c->saw_game = true;
        if (ajs_reported_matches(c, pid, born)) c->saw_reported = true;
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

struct ajs_recovery { struct json_value original; uint32_t ready_pages, keep_pages; };

static bool ajs_recovery_pages(const struct json_value *data, bool keep, uint32_t *count)
{
    struct app_confirm *view = calloc(1, sizeof(*view));
    if (!view) return false;
    zcl_present_model_init_v1(&view->model, ZCL_PRESENT_MODEL_STATUS_CARD);
    (void)snprintf(view->model.request_id, sizeof(view->model.request_id), "received-app");
    (void)snprintf(view->model.title, sizeof(view->model.title), "%s", keep ? "Preview opened" : "Your copy is ready");
    (void)snprintf(view->model.summary, sizeof(view->model.summary), "%s", keep ?
        "Check the app before choosing Keep. Closing ends this review." :
        "Build and preview the original received snapshot, even if newer edits exist. Keep is a separate choice.");
    view->model.action_count = 4;
    app_confirm_action(&view->model.actions[0], ZCL_PRESENT_ACTION_CANCEL, "close", "Close");
    app_confirm_action(&view->model.actions[1], ZCL_PRESENT_ACTION_SELECT, "back", "Back");
    app_confirm_action(&view->model.actions[2], ZCL_PRESENT_ACTION_SELECT, "next", "Next");
    app_confirm_action(&view->model.actions[3], ZCL_PRESENT_ACTION_CONFIRM, "continue", keep ? "Keep this version" : "Build and preview");
    char why[128];
    bool ok = app_confirm_field(&view->model, "App: ", json_get_str(json_get(data, "name"))) &&
        app_confirm_field(&view->model, "Saved version: ", json_get_str(json_get(data, "version"))) &&
        app_confirm_field(&view->model, "Publisher: ", json_get_str(json_get(data, "publisher_fingerprint"))) &&
        app_confirm_field(&view->model, "Package: ", json_get_str(json_get(data, "package_root"))) &&
        app_confirm_path(&view->model, "Copy location: ", json_get_str(json_get(data, "destination"))) &&
        zcl_present_model_page_count_v1(&view->model, count, why, sizeof(why));
    free(view);
    return ok && *count > 0 && *count <= ZCL_PRESENT_MODEL_PAGES_MAX;
}

static bool ajs_recovery_snapshot(struct ajs_world *w, struct ajs_recovery *r)
{
    char copy[1400];
    int n = snprintf(copy, sizeof(copy), "%s/copies/%s", w->j.b_datadir, w->j.b_copy);
    if (n <= 0 || (size_t)n >= sizeof(copy)) return false;
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.test.recovery.v1");
    struct app_receive_preview *preview = NULL;
    json_set_object(&r->original);
    bool ok = app_receive_preview_create_recovered(copy, w->j.b_datadir, NULL, &preview, &reply) &&
        app_receive_preview_describe_recovered(preview, &r->original) &&
        !strcmp(json_get_str(json_get(&r->original, "package_root")), w->j.share_root) &&
        !strcmp(json_get_str(json_get(&r->original, "publisher_fingerprint")), w->j.share_fp) &&
        ajs_recovery_pages(&r->original, false, &r->ready_pages) &&
        ajs_recovery_pages(&r->original, true, &r->keep_pages);
    if (!ok) printf("  [B recovery refused: %s]\n", reply.error.code);
    app_receive_preview_close(preview);
    zcl_command_reply_free(&reply);
    return ok;
}

static bool ajs_recovery_selection(const struct ajs_world *w, const struct ajs_recovery *r)
{
    struct app_launch_env env; struct app_selection_routes routes; struct app_selection selected;
    char why[256], datadir[PATH_MAX], image[65], version[65], fork[65], parent[65], package[65];
    if (!app_launch_env_from_process(&env, why, sizeof(why)) ||
        app_selection_routes_load(env.state_dir, &routes) != APP_SELECTION_OK || routes.count != 1 ||
        app_selection_load(env.state_dir, routes.names[0], &selected) != APP_SELECTION_OK ||
        !realpath(w->j.b_datadir, datadir)) return false;
    zcl_hex_encode(selected.image, 32, image); zcl_hex_encode(selected.version, 32, version);
    zcl_hex_encode(selected.fork, 32, fork);
    zcl_hex_encode(selected.parent, 32, parent); zcl_hex_encode(selected.package, 32, package);
    return selected.revision == 1 && !strcmp(selected.copy, json_get_str(json_get(&r->original, "destination"))) &&
        !strcmp(selected.datadir, datadir) && !strcmp(image, w->j.image_b) &&
        !strcmp(version, json_get_str(json_get(&r->original, "version"))) &&
        !strcmp(fork, json_get_str(json_get(&r->original, "version"))) &&
        !strcmp(parent, json_get_str(json_get(&r->original, "release_id"))) &&
        !strcmp(package, json_get_str(json_get(&r->original, "package_root")));
}

struct ajs_ui { char driver[PATH_MAX], log[PATH_MAX]; };

static bool ajs_ui_key(const struct ajs_ui *ui, const char *title,
                       const char *key, bool pixels, bool replaced, unsigned timeout)
{
    bool ok = app_ui_drive(ui->driver, title, key, ui->log, pixels, replaced, timeout);
    if (!ok) fprintf(stderr, "receiver recovery: window=%s action=%s failed (log %s)\n", title, key, ui->log);
    return ok;
}

static bool ajs_ui_confirm_pages(const struct ajs_ui *ui, const char *title,
                                 uint32_t pages, unsigned first_timeout)
{
    if (!ajs_ui_key(ui, title, "--expect-count=1", false, false, first_timeout)) return false;
    for (uint32_t i = 1; i < pages; i++)
        if (!ajs_ui_key(ui, title, "--key=3", true, false, 5000)) return false;
    return ajs_ui_key(ui, title, "--key=4", false, false, 5000);
}

static bool ajs_ui_recovery_flow(const struct ajs_ui *ui, const struct ajs_recovery *r)
{
    return ajs_ui_key(ui, "My Apps", "--key=2", false, true, 10000) &&
        ajs_ui_key(ui, "My Apps", "--key=4", false, true, 10000) &&
        ajs_ui_key(ui, "My Apps", "--key=1", false, false, 10000) &&
        ajs_ui_confirm_pages(ui, "Your copy is ready", r->ready_pages, 10000) &&
        ajs_ui_confirm_pages(ui, "Preview opened", r->keep_pages, 30000);
}

struct ajs_gui_paths {
    struct ajs_ui ui;
    char binary[1400], datadir[800], cli[PATH_MAX], game[PATH_MAX];
    char make[PATH_MAX], shell[PATH_MAX], output[PATH_MAX];
};

static bool ajs_gui_prepare(struct ajs_world *w, struct ajs_gui_paths *p)
{
    int n = snprintf(p->ui.driver, sizeof(p->ui.driver), "%s/build/bin/native_ui_driver", w->source);
    int l = snprintf(p->ui.log, sizeof(p->ui.log), "%s/recovery-driver.log", w->root);
    int o = snprintf(p->output, sizeof(p->output), "%s/recovery-cli.log", w->root);
    return n > 0 && (size_t)n < sizeof(p->ui.driver) && l > 0 && (size_t)l < sizeof(p->ui.log) &&
        o > 0 && (size_t)o < sizeof(p->output) &&
        ajs_cli_prepare(w, p->binary, sizeof(p->binary), p->datadir, sizeof(p->datadir)) &&
        realpath(p->binary, p->cli) && realpath(w->j.path_b, p->game) &&
        realpath("/usr/bin/make", p->make) && realpath("/bin/sh", p->shell);
}

struct ajs_gui_run {
    struct ajs_gui_paths paths;
    struct app_ui_child cli;
    struct sigaction old_signal;
    int prior;
    bool signal_saved, custody, started, flow, exited;
};

static bool ajs_gui_start(struct ajs_world *w, struct ajs_gui_run *g)
{
    struct ajs_gui_paths *p = &g->paths;
    if (!ajs_gui_prepare(w, p) || !ajs_child_baseline(w->xvfb)) return false;
    struct sigaction ignore = {.sa_handler = SIG_IGN};
    if (sigemptyset(&ignore.sa_mask) != 0 || sigaction(SIGPIPE, &ignore, &g->old_signal) != 0) return false;
    g->signal_saved = true;
    g->custody = prctl(PR_GET_CHILD_SUBREAPER, &g->prior) == 0 && prctl(PR_SET_CHILD_SUBREAPER, 1) == 0;
    int log = g->custody ? open(p->output, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600) : -1;
    int in = g->custody ? open("/dev/null", O_RDONLY | O_CLOEXEC) : -1;
    const char *argv[] = {p->binary, p->datadir, "app", "library", "--json", NULL};
    g->started = log >= 0 && in >= 0 && app_ui_spawn(&g->cli, argv, in, log, log);
    if (log >= 0) (void)close(log);
    if (in >= 0) (void)close(in);
    return g->started;
}

static void ajs_gui_log(const char *path)
{
    char text[4097];
    FILE *f = fopen(path, "rb");
    if (!f) return;
    size_t n = fread(text, 1, sizeof(text) - 1, f);
    text[n] = '\0';
    (void)fclose(f);
    fprintf(stderr, "receiver recovery log %s (first %zu bytes):\n%s\n", path, n, text);
}

static void ajs_gui_run_flow(struct ajs_gui_run *g, const struct ajs_recovery *r)
{
    g->flow = ajs_ui_recovery_flow(&g->paths.ui, r);
    uint32_t code = UINT32_MAX;
    g->exited = g->flow && app_ui_wait(&g->cli, 15000, &code) == PLATFORM_PROCESS_WAIT_EXITED && code == 0;
}

static bool ajs_gui_finish(struct ajs_world *w, const struct ajs_recovery *r, struct ajs_gui_run *g)
{
    struct ajs_gui_paths *p = &g->paths;
    bool stopped = app_ui_stop(&g->cli);
    struct ajs_custody c = {.display = w->xvfb, .cli = p->cli, .game = p->game, .make = p->make, .shell = p->shell};
    bool clean = g->custody && stopped && ajs_children_clean(&c) && ajs_child_baseline(w->xvfb);
    bool restored = clean && prctl(PR_SET_CHILD_SUBREAPER, g->prior) == 0;
    bool signals = !g->signal_saved || sigaction(SIGPIPE, &g->old_signal, NULL) == 0;
    bool selected = g->exited && ajs_recovery_selection(w, r);
    bool ok = g->flow && g->exited && clean && restored && signals && c.saw_game && selected;
    if (ok) printf("  [receiver GUI recovery: flow=1 exit=0 cleanup=1 selection=1 image=%s]\n", w->j.image_b);
    if (!ok) {
        fprintf(stderr, "receiver recovery: started=%d flow=%d exited=%d stopped=%d clean=%d game=%d selected=%d (logs %s, %s)\n",
                g->started, g->flow, g->exited, stopped, clean, c.saw_game, selected, p->output, p->ui.log);
        ajs_gui_log(p->output); ajs_gui_log(p->ui.log);
    }
    return ok;
}

static bool ajs_recovery_gui(struct ajs_world *w, const struct ajs_recovery *r)
{
    struct ajs_gui_run g = {.cli.pid = -1};
    if (ajs_gui_start(w, &g)) ajs_gui_run_flow(&g, r);
    return ajs_gui_finish(w, r, &g);
}

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

static bool ajs_kept_fields(const struct json_value *data, const char *route, const char *version,
                            const struct asf_journey *j, const struct app_selection *selected)
{
    char package[65], record[65];
    zcl_hex_encode(selected->package, 32, package); zcl_hex_encode(selected->record, 32, record);
    const struct json_value *revision = json_get(data, "selection_revision");
    return !strcmp(json_get_str(json_get(data, "name")), route) &&
        !strcmp(json_get_str(json_get(data, "version")), version) &&
        !strcmp(json_get_str(json_get(data, "package_root")), package) &&
        !strcmp(json_get_str(json_get(data, "record_id")), record) &&
        !strcmp(json_get_str(json_get(data, "image_path")), j->path_b) &&
        revision && revision->type == JSON_INT && json_get_int(revision) == 1 &&
        !strcmp(json_get_str(json_get(data, "image_sha3")), j->image_b) &&
        !strcmp(json_get_str(json_get(data, "image_sha3")), j->image_shared);
}

static bool ajs_kept_process(const struct json_value *data, long *pid, uint64_t *token)
{
    const struct json_value *p = json_get(data, "pid");
    const char *text = json_get_str(json_get(data, "start_token"));
    char *end = NULL; errno = 0;
    unsigned long long parsed = strtoull(text, &end, 10);
    if (!text[0] || !end || *end || errno || !parsed || !p || p->type != JSON_INT ||
        json_get_int(p) <= 1 || json_get_int(p) > INT_MAX) return false;
    *pid = (long)json_get_int(p); *token = (uint64_t)parsed; return true;
}

static bool ajs_kept_receipt(const char *text, const char *route, const char *version,
                             const struct asf_journey *j, const struct app_selection *selected,
                             long *pid, uint64_t *token)
{
    struct json_value doc; json_init(&doc);
    bool ok = json_read(&doc, text, strlen(text));
    const struct json_value *data = json_get(&doc, "data"), *success = json_get(&doc, "ok");
    ok = ok && success && success->type == JSON_BOOL && json_get_bool(success) &&
        !strcmp(json_get_str(json_get(&doc, "command")), "app.open") &&
        !strcmp(json_get_str(json_get(&doc, "status")), "passed") &&
        ajs_kept_fields(data, route, version, j, selected) && ajs_kept_process(data, pid, token);
    json_free(&doc); return ok;
}

static void ajs_cli_result_finish(struct ajs_cli_result *result, struct asf_door *run,
                                  const struct asf_journey *j, size_t cap, const char *version, bool receipt)
{
    if (version) result->accepted = result->rc == 0 && result->clean && result->saw_reported && receipt;
    else ajs_cli_check(result, run, j, cap);
    if (version && !result->accepted)
        printf("  [kept CLI reopen: rc=%d clean=%d reported=%d receipt=%d]\n%s", result->rc, result->clean, result->saw_reported, receipt, run->text);
}

static bool ajs_cli_receipt(const struct asf_door *run, size_t cap, const char *route,
                            const char *version, const struct asf_journey *j,
                            const struct app_selection *selected, long *pid, uint64_t *token)
{
    if (!version) { *pid = asf_door_pid(run->text); return false; }
    return cap > 1 && strlen(run->text) < cap - 1 &&
        ajs_kept_receipt(run->text, route, version, j, selected, pid, token);
}

static struct ajs_cli_result ajs_b_cli_attempt(struct ajs_world *w, size_t cap, const char *route, const char *version,
                                               const struct app_selection *selected)
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
    const char *argv[] = {binary, datadir, "app", "open", route, "--yes", NULL};
    result.rc = test_host_tool_capture(argv, run.text, cap, 60000);
    long pid = 0; uint64_t token = 0;
    bool receipt = ajs_cli_receipt(&run, cap, route, version, j, selected, &pid, &token);
    struct ajs_custody c = {.display = w->xvfb, .cli = cli_real, .game = game_real,
                            .reported = pid, .reported_token = token};
    bool clean = ajs_children_clean(&c) && ajs_child_baseline(w->xvfb);
    bool restored = clean && prctl(PR_SET_CHILD_SUBREAPER, old_subreaper) == 0;
    bool env_restored = ajs_env_restore(env, 3);
    result.clean = clean && restored && env_restored;
    result.saw_game = c.saw_game;
    result.saw_reported = c.saw_reported;
    ajs_cli_result_finish(&result, &run, j, cap, version, receipt);
    if (result.rc == 0) ++j->commands_b;
    return result;
}

static bool ajs_kept_reopen(struct ajs_world *w, const struct ajs_recovery *r)
{
    struct app_launch_env env; struct app_selection_routes routes; struct app_selection selected, after;
    char why[256];
    if (!ajs_recovery_selection(w, r) || !app_launch_env_from_process(&env, why, sizeof(why)) ||
        app_selection_routes_load(env.state_dir, &routes) != APP_SELECTION_OK || routes.count != 1 ||
        app_selection_load(env.state_dir, routes.names[0], &selected) != APP_SELECTION_OK)
        return false;
    struct ajs_cli_result opened = ajs_b_cli_attempt(w, ASF_DOOR_OUT, routes.names[0],
        json_get_str(json_get(&r->original, "version")), &selected);
    bool ok = opened.accepted && ajs_recovery_selection(w, r) &&
        app_selection_load(env.state_dir, routes.names[0], &after) == APP_SELECTION_OK &&
        !memcmp(selected.record, after.record, sizeof(selected.record));
    if (ok) printf("  [kept CLI reopen: receipt=passed selection=unchanged game=identified cleanup=1 image=%s]\n", w->j.image_b);
    return ok;
}

static int ajs_b(struct ajs_world *w)
{
    int failures = 0;
    struct ajs_env env[3] = {{"XDG_STATE_HOME", NULL}, {"XDG_DATA_HOME", NULL},
                             {"XDG_CONFIG_HOME", NULL}};
    bool env_set = false;
    struct ajs_recovery recovery = {0};
    json_init(&recovery.original);
    TEST("app journey skycombat B: open the share file receives, builds A's "
         "image, opens it; 120 QA frames") {
        ASSERT(ajs_env_enter(env, w->j.b_home));
        env_set = true;
        ASSERT(asf_journey_receive(&w->j));
        ASSERT_EQ(asf_qa_frames(w->j.path_b), 0);
        ASSERT(ajs_b_reopen(&w->j));
        struct ajs_cli_result cli = ajs_b_cli_attempt(w, ASF_DOOR_OUT, w->j.b_copy, NULL, NULL);
        ASSERT(cli.accepted);
        struct ajs_cli_result lost = ajs_b_cli_attempt(w, 1, w->j.b_copy, NULL, NULL);
        ASSERT(lost.rc == 0 && !lost.accepted && lost.clean && lost.saw_game && !lost.saw_reported);
        ASSERT(ajs_recovery_snapshot(w, &recovery));
        ASSERT(ajs_recovery_gui(w, &recovery));
        ASSERT(ajs_kept_reopen(w, &recovery));
        PASS();
    } _test_next:;
    json_free(&recovery.original);
    if (env_set && !ajs_env_restore(env, 3)) failures++;
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
