/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the app.seed and app journey groups' runner
 * (test/app_seed_fixture.h). */

#if defined(__linux__) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/app_seed_fixture.h"
#include "test/host_tool_capture.h"

#include "command/native_app_front_door.h"
#include "config/command_catalog.h"
#include "mcp/mcp_policy.h"
#include "platform/resident_launch.h"
#include "platform/time_compat.h"
#include "plugin/plugin_dist.h"
#include "vcs/package_rank.h"
#include "vcs/package_release.h"
#include "vcs/package_service.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#if defined(__linux__)
#include <fcntl.h>
#include <poll.h>
#include <spawn.h>
#include <sys/wait.h>

extern char **environ;
#endif

#define ASF_SCHEMA "zcl.test.app_seed.v1"

void asf_open(struct asf_leaf *l)
{
    memset(l, 0, sizeof(*l));
    json_init(&l->in);
    json_set_object(&l->in);
    zcl_command_reply_init(&l->out, ASF_SCHEMA);
}

void asf_close(struct asf_leaf *l)
{
    zcl_command_reply_free(&l->out);
    json_free(&l->in);
}

const struct zcl_command_spec *asf_spec(const char *path)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    for (size_t i = 0; reg && i < reg->count; i++)
        if (strcmp(reg->commands[i].path, path) == 0)
            return &reg->commands[i];
    return NULL;
}

bool asf_exec(const char *path, struct asf_leaf *l)
{
    char why[256] = "no such leaf";
    const struct zcl_command_spec *spec = asf_spec(path);
    if (!spec || !spec->handler ||
        !zcl_command_registry_input_validate(spec, &l->in, why, sizeof(why))) {
        printf("  [%s not runnable: %s]\n", path, why);
        return false;
    }
    l->req.spec = spec;
    l->req.input = &l->in;
    l->req.invoked_name = spec->path;
    spec->handler(&l->req, &l->out);
    size_t bytes = json_write(&l->out.data, NULL, 0) + 1024u;
    if (spec->budget_bytes && bytes > (size_t)spec->budget_bytes) {
        printf("  [%s reply %zu bytes over its budget]\n", path, bytes);
        return false;
    }
    return true;
}

bool asf_pass(const char *path, struct asf_leaf *l)
{
    if (!asf_exec(path, l))
        return false;
    if (l->out.status != ZCL_COMMAND_STATUS_PASSED)
        printf("  [%s refused %s: %s (%s)]\n", path, l->out.error.code,
               l->out.error.message, l->out.error.evidence);
    return l->out.status == ZCL_COMMAND_STATUS_PASSED;
}

bool asf_refusal(const struct asf_leaf *l, const char *code)
{
    if (l->out.status != ZCL_COMMAND_STATUS_PASSED &&
        strcmp(l->out.error.code, code) == 0)
        return true;
    printf("  [expected %s; status=%d code=%s: %s]\n", code,
           (int)l->out.status, l->out.error.code, l->out.error.message);
    return false;
}

const char *asf_get(const struct asf_leaf *l, const char *key)
{
    const char *s = json_get_str(json_get(&l->out.data, key));
    return s ? s : "";
}

bool asf_flag(const struct asf_leaf *l, const char *key)
{
    const struct json_value *v = json_get(&l->out.data, key);
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

bool asf_plan_confirm(const char *path, struct asf_leaf *l)
{
    char plan[65];
    if (!asf_pass(path, l) || strlen(asf_get(l, "plan_id")) != 64)
        return false;
    (void)snprintf(plan, sizeof(plan), "%s", asf_get(l, "plan_id"));
    zcl_command_reply_free(&l->out);
    zcl_command_reply_init(&l->out, ASF_SCHEMA);
    (void)json_push_kv_str(&l->in, "plan_id", plan);
    (void)json_push_kv_bool(&l->in, "confirm", true);
    return asf_pass(path, l);
}

bool asf_put(const char *dir, const char *rel, const char *text)
{
    char path[1200];
    if (snprintf(path, sizeof(path), "%s/%s", dir, rel) >= (int)sizeof(path))
        return false;
    FILE *f = fopen(path, "wb");
    bool ok = f && fputs(text, f) >= 0;
    return f ? fclose(f) == 0 && ok : false;
}

bool asf_seed(struct asf_leaf *l, const char *app, const char *source,
              const char *datadir)
{
    asf_open(l);
    (void)json_push_kv_str(&l->in, "app", app);
    if (source)
        (void)json_push_kv_str(&l->in, "source", source);
    (void)json_push_kv_str(&l->in, "datadir", datadir);
    return asf_plan_confirm("app.seed", l);
}

bool asf_adopt(const char *release, const char *datadir, char *copy,
               size_t cap)
{
    struct asf_leaf l;
    asf_open(&l);
    (void)json_push_kv_str(&l.in, "root", release);
    (void)json_push_kv_str(&l.in, "datadir", datadir);
    bool ok = asf_plan_confirm("zcode.package.adopt", &l);
    (void)snprintf(copy, cap, "%s", asf_get(&l, "copy"));
    asf_close(&l);
    return ok && copy[0] == '/';
}

bool asf_build(struct asf_leaf *l, const char *copy, const char *datadir)
{
    asf_open(l);
    (void)json_push_kv_str(&l->in, "copy", copy);
    (void)json_push_kv_str(&l->in, "datadir", datadir);
    return asf_plan_confirm("app.build", l);
}

/* ── editing a copy ───────────────────────────────────────────────────── */

#define ASF_EDIT_MAX (4u << 20)

static char *asf_slurp(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    char *text = NULL;
    *len = 0;
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) == 0) {
        long n = ftell(f);
        if (n >= 0 && (unsigned long)n < ASF_EDIT_MAX && fseek(f, 0, SEEK_SET) == 0)
            text = malloc((size_t)n + 1u);
        if (text && fread(text, 1, (size_t)n, f) == (size_t)n) {
            text[n] = '\0';
            *len = (size_t)n;
        } else {
            free(text);
            text = NULL;
        }
    }
    (void)fclose(f);
    return text;
}

bool asf_replace(const char *dir, const char *rel, const char *from,
                 const char *to)
{
    char path[1200];
    size_t len = 0;
    if (snprintf(path, sizeof(path), "%s/%s", dir, rel) >= (int)sizeof(path))
        return false;
    char *text = asf_slurp(path, &len);
    char *at = text ? strstr(text, from) : NULL;
    bool ok = at && !strstr(at + 1, from);
    FILE *f = ok ? fopen(path, "wb") : NULL;
    if (f) {
        size_t head = (size_t)(at - text), skip = strlen(from);
        ok = fwrite(text, 1, head, f) == head &&
             fputs(to, f) >= 0 &&
             fputs(at + skip, f) >= 0;
        ok = fclose(f) == 0 && ok;
    } else {
        ok = false;
    }
    if (!ok)
        printf("  [edit %s: \"%s\" not found exactly once]\n", path, from);
    free(text);
    return ok;
}

/* ── owner authority at MCP ───────────────────────────────────────────── */

static bool asf_fingerprint_at(const char *p)
{
    for (size_t i = 0; i < 19; i++) {
        char c = p[i];
        bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (i % 5 == 4 ? c != '-' : !hex)
            return false;
    }
    return true;
}

bool asf_short_fingerprint(const char *text)
{
    for (const char *p = text; *p; p++)
        if (asf_fingerprint_at(p))
            return true;
    return false;
}

bool asf_mcp_refuses_owner(const char *path, const char *key,
                           const char *value)
{
    const struct zcl_command_spec *spec = asf_spec(path);
    struct mcp_refusal why = {0};
    struct json_value in;
    if (!spec || spec->authority != ZCL_COMMAND_AUTH_OWNER) {
        printf("  [%s missing or not owner authority]\n", path);
        return false;
    }
    json_init(&in);
    json_set_object(&in);
    (void)json_push_kv_str(&in, key, value);
    bool plan = !mcp_policy_allows(spec, zcl_command_catalog(), &in, &why) &&
                strcmp(why.code, "MUTATION_REFUSED_OWNER_AUTHORITY") == 0;
    (void)json_push_kv_str(&in, "plan_id", "00");
    (void)json_push_kv_bool(&in, "confirm", true);
    bool commit = !mcp_policy_allows(spec, zcl_command_catalog(), &in, &why) &&
                  strcmp(why.code, "MUTATION_REFUSED_OWNER_AUTHORITY") == 0;
    json_free(&in);
    return plan && commit;
}

/* ── the front door as a person types it ──────────────────────────────── */

#if !defined(_WIN32)
static bool asf_answer_yes(void *ctx, const char *question)
{
    struct asf_door *run = ctx;
    (void)snprintf(run->question, sizeof(run->question), "%s", question);
    run->asked = true;
    return true;
}

void asf_door_run(const char *home, const char *cwd, const char *datadir,
                  const char *verb, const char *target,
                  enum zcl_cli_confirm_mode mode, struct asf_door *run)
{
    FILE *out = tmpfile();
    memset(run, 0, sizeof(*run));
    struct zcl_app_front_door d = {
        .verb = verb, .target = target, .datadir = datadir, .out = out,
        .confirm = {.mode = mode, .ask = asf_answer_yes, .ctx = run},
    };
    run->rc = -1;
    if (!out || setenv("HOME", home, 1) != 0 || chdir(cwd) != 0) {
        if (out)
            (void)fclose(out);
        return;
    }
    run->rc = zcl_app_front_door_run(&d);
    rewind(out);
    size_t n = fread(run->text, 1, sizeof(run->text) - 1u, out);
    run->text[n] = '\0';
    (void)fclose(out);
    if (run->rc != 0)
        printf("  [z23 app %s %s: rc=%d]\n%s", verb, target, run->rc,
               run->text);
}

const char *asf_door_line(const struct asf_door *run, const char *key,
                          char *out, size_t cap)
{
    char probe[96];
    out[0] = '\0';
    (void)snprintf(probe, sizeof(probe), "\n  %s: ", key);
    const char *at = strstr(run->text, probe);
    if (at) {
        at += strlen(probe);
        size_t n = strcspn(at, "\n");
        (void)snprintf(out, cap, "%.*s", (int)n, at);
    }
    return out;
}

long asf_door_pid(const char *text)
{
    const char *p = strstr(text, "pid ");
    return p ? strtol(p + 4, NULL, 10) : 0;
}

bool asf_alive_then_stop(long pid)
{
    bool alive = pid > 1 && kill((pid_t)pid, 0) == 0;
    int status = 0;
    bool reaped = pid > 1 &&
                  resident_launch_kill_reap((uint64_t)pid, 2000, &status);
    return alive && reaped;
}

/* ── the journey ──────────────────────────────────────────────────────── */

bool asf_journey_init(struct asf_journey *j, const char *app,
                      const char *source, const char *root)
{
    memset(j, 0, sizeof(*j));
    j->app = app;
    (void)snprintf(j->source, sizeof(j->source), "%s", source);
    (void)snprintf(j->root, sizeof(j->root), "%s", root);
    (void)snprintf(j->a_home, sizeof(j->a_home), "%s/a", j->root);
    (void)snprintf(j->a_datadir, sizeof(j->a_datadir), "%s/a/datadir",
                   j->root);
    (void)snprintf(j->b_home, sizeof(j->b_home), "%s/b", j->root);
    (void)snprintf(j->b_datadir, sizeof(j->b_datadir), "%s/b/datadir",
                   j->root);
    (void)snprintf(j->copy, sizeof(j->copy), "%.60s-1", app);
    (void)snprintf(j->a_copy, sizeof(j->a_copy), "%s/copies/%s",
                   j->a_datadir, j->copy);
    (void)snprintf(j->share, sizeof(j->share), "%s/%s.z23share", j->a_home,
                   j->copy);
    return mkdir(j->a_home, 0700) == 0 && mkdir(j->a_datadir, 0700) == 0 &&
           mkdir(j->b_home, 0700) == 0 && mkdir(j->b_datadir, 0700) == 0;
}

/* One typed verb: it must finish (rc 0); `count` is the person's tally. */
static bool asf_journey_verb(const char *home, const char *cwd,
                             const char *datadir, const char *verb,
                             const char *target, enum zcl_cli_confirm_mode mode,
                             struct asf_door *run, int *count)
{
    asf_door_run(home, cwd, datadir, verb, target, mode, run);
    if (run->rc != 0)
        return false;
    (*count)++;
    return true;
}

bool asf_journey_copy(struct asf_journey *j)
{
    static struct asf_door run;
    char seed[16];
    struct stat st;
    if (!asf_journey_verb(j->a_home, j->source, j->a_datadir, "copy", j->app,
                          ZCL_CLI_CONFIRM_YES, &run, &j->commands_a))
        return false;
    bool seeded = strcmp(asf_door_line(&run, "seed", seed, sizeof(seed)),
                         "yes") == 0;
    bool made = stat(j->a_copy, &st) == 0 && S_ISDIR(st.st_mode);
    if (!seeded || !made)
        printf("  [copy: seeded through app.seed=%d, %s made=%d]\n%s",
               seeded, j->a_copy, made, run.text);
    return seeded && made;
}

bool asf_journey_save_build_open(struct asf_journey *j)
{
    static struct asf_door run;
    if (!asf_journey_verb(j->a_home, j->a_home, j->a_datadir, "save",
                          j->copy, ZCL_CLI_CONFIRM_YES, &run,
                          &j->commands_a) ||
        !asf_journey_verb(j->a_home, j->a_home, j->a_datadir, "build",
                          j->copy, ZCL_CLI_CONFIRM_YES, &run,
                          &j->commands_a))
        return false;
    (void)asf_door_line(&run, "image_sha3", j->image_built,
                        sizeof(j->image_built));
    if (!asf_journey_verb(j->a_home, j->a_home, j->a_datadir, "open",
                          j->copy, ZCL_CLI_CONFIRM_YES, &run,
                          &j->commands_a))
        return false;
    bool stopped = asf_alive_then_stop(asf_door_pid(run.text));
    if (strlen(j->image_built) != 64 || !stopped)
        printf("  [build image \"%s\"; the open's pid stopped=%d]\n%s",
               j->image_built, stopped, run.text);
    return strlen(j->image_built) == 64 && stopped;
}

/* A's key published 1 + shares times (the seed and each share), all in
 * this ISO week
 * and recorded: the day is pinned by assertion, not injected. */
static bool asf_journey_week(const struct asf_journey *j, unsigned want)
{
    char key[800], zdir[800];
    uint8_t pub[VCS_PACKAGE_RELEASE_PUBKEY_BYTES];
    struct plugin_dist_published why;
    struct vcs_service_key_totals kt;
    memset(&kt, 0, sizeof(kt));
    (void)snprintf(key, sizeof(key), "%s/.z23/zcode_publisher.key",
                   j->a_home);
    (void)snprintf(zdir, sizeof(zdir), "%s/zcode", j->a_datadir);
    int64_t today = vcs_rank_day_from_unix(platform_time_wall_unix());
    struct vcs_service_book *book = vcs_service_book_load(zdir);
    bool ok = plugin_dist_release_key_sign(key, NULL, pub, NULL, &why) ==
                  PLUGIN_DIST_OK &&
              book && vcs_service_key_totals(book, pub, today, &kt) &&
              kt.publish_events == want && kt.publishes_this_week == want;
    printf("  [A's key on day %lld: %u publishes this ISO week, %u in all "
           "(want %u and %u: seed and each share)]\n", (long long)today,
           kt.publishes_this_week, kt.publish_events, want, want);
    vcs_service_book_free(book);
    return ok;
}

/* The build of the copy as it stands, through the build leaf (a cache hit
 * when nothing changed): its image hash and path. */
static bool asf_journey_image(const char *home, const char *copy,
                              const char *datadir, char sha[65],
                              char *path, size_t cap)
{
    struct asf_leaf l;
    bool ok = setenv("HOME", home, 1) == 0 && asf_build(&l, copy, datadir);
    (void)snprintf(sha, 65, "%s", asf_get(&l, "image_sha3"));
    (void)snprintf(path, cap, "%s", asf_get(&l, "image_path"));
    asf_close(&l);
    return ok && strlen(sha) == 64 && path[0] == '/';
}

bool asf_share_told(const char *text, char *fp, size_t fp_cap,
                    char root[65])
{
    const char *f = strstr(text, "(full ");
    const char *r = strstr(text, "version root ");
    fp[0] = root[0] = '\0';
    if (!f || !r)
        return false;
    f += strlen("(full ");
    r += strlen("version root ");
    size_t nf = strcspn(f, ")\n"), nr = strspn(r, "0123456789abcdef");
    if (nf == 0 || nf >= fp_cap || f[nf] != ')' || nr != 64)
        return false;
    (void)snprintf(fp, fp_cap, "%.*s", (int)nf, f);
    (void)snprintf(root, 65, "%.64s", r);
    return true;
}

/* A opens the copy right after share: the build from before share, with no
 * rebuild in between. */
static bool asf_journey_reopen(struct asf_journey *j)
{
    static struct asf_door run;
    char image[80];
    if (!asf_journey_verb(j->a_home, j->a_home, j->a_datadir, "open",
                          j->copy, ZCL_CLI_CONFIRM_YES, &run, &j->commands_a))
        return false;
    (void)asf_door_line(&run, "image_sha3", image, sizeof(image));
    bool same = strcmp(image, j->image_built) == 0;
    bool stopped = asf_alive_then_stop(asf_door_pid(run.text));
    if (!same || !stopped)
        printf("  [open after share: image \"%s\" (built \"%s\"), pid "
               "stopped=%d]\n%s", image, j->image_built, stopped, run.text);
    return same && stopped;
}

bool asf_journey_share(struct asf_journey *j)
{
    static struct asf_door run;
    struct stat st;
    char friend_cmd[160];
    if (!asf_journey_verb(j->a_home, j->a_home, j->a_datadir, "share",
                          j->copy, ZCL_CLI_CONFIRM_YES, &run,
                          &j->commands_a))
        return false;
    (void)snprintf(friend_cmd, sizeof(friend_cmd), "z23 app open %s.z23share",
                   j->copy);
    bool file = stat(j->share, &st) == 0 && S_ISREG(st.st_mode);
    bool fingerprint = asf_short_fingerprint(run.text);
    bool told = asf_share_told(run.text, j->share_fp, sizeof(j->share_fp),
                               j->share_root) &&
                strstr(run.text, "Tell them these another way") != NULL;
    bool needs = strstr(run.text, "a C compiler") != NULL &&
                 strstr(run.text, friend_cmd) != NULL;
    if (!file || !fingerprint || !told || !needs)
        printf("  [share: %s written=%d, fingerprint shown=%d, fingerprint "
               "and root to pass on=%d, friend's needs=%d]\n%s", j->share,
               file, fingerprint, told, needs, run.text);
    return file && fingerprint && told && needs && asf_journey_reopen(j) &&
           asf_journey_week(j, 1u + (unsigned)++j->shares) &&
           asf_journey_image(j->a_home, j->copy, j->a_datadir,
                             j->image_shared, j->path_shared,
                             sizeof(j->path_shared));
}

bool asf_journey_receive(struct asf_journey *j)
{
    static struct asf_door run;
    if (!asf_journey_verb(j->b_home, j->b_home, j->b_datadir, "open",
                          j->share, ZCL_CLI_CONFIRM_ASK, &run,
                          &j->commands_b))
        return false;
    bool asked = run.asked && asf_short_fingerprint(run.question);
    /* B is asked about exactly the fingerprint and root A was told */
    bool told = j->share_fp[0] && strlen(j->share_root) == 64 &&
                strstr(run.question, j->share_fp) != NULL &&
                strstr(run.question, j->share_root) != NULL;
    bool stopped = asf_alive_then_stop(asf_door_pid(run.text));
    (void)asf_door_line(&run, "copy", j->b_copy, sizeof(j->b_copy));
    if (!asked || !told || !stopped || !j->b_copy[0])
        printf("  [receive: asked with a fingerprint=%d, A's fingerprint %s "
               "and root %s=%d, pid stopped=%d, copy \"%s\"]\n%s\n  "
               "question: %s\n", asked, j->share_fp, j->share_root, told,
               stopped, j->b_copy, run.text, run.question);
    bool same = asked && told && stopped && j->b_copy[0] &&
                asf_journey_image(j->b_home, j->b_copy, j->b_datadir,
                                  j->image_b, j->path_b, sizeof(j->path_b)) &&
                strcmp(j->image_b, j->image_shared) == 0;
    printf("  [image_sha3 A=%s B=%s (A before share %s)]\n", j->image_shared,
           j->image_b, j->image_built);
    return same;
}
#endif /* !_WIN32 */

/* ── the real game on a private display ───────────────────────────────── */

#if defined(__linux__)
const char *asf_xvfb_path(void)
{
    static const char *const paths[] = {"/usr/bin/Xvfb", "/usr/local/bin/Xvfb"};
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++)
        if (access(paths[i], X_OK) == 0)
            return paths[i];
    return NULL;
}

/* Xvfb picks a free display itself (-displayfd), so parallel runs never
 * race for a number; DISPLAY is set to it. */
bool asf_xvfb_start(const char *xvfb, const char *logdir, pid_t *pid)
{
    int fds[2];
    char log[1200], display[32];
    posix_spawn_file_actions_t fa;
    char *argv[] = {(char *)xvfb, (char *)"-displayfd", (char *)"3",
                    (char *)"-nolisten", (char *)"tcp", (char *)"-screen",
                    (char *)"0", (char *)"1280x800x24", NULL};
    (void)snprintf(log, sizeof(log), "%s/xvfb.log", logdir);
    if (pipe(fds) != 0 || posix_spawn_file_actions_init(&fa) != 0)
        return false;
    bool ok =
        posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0) == 0 &&
        posix_spawn_file_actions_addopen(&fa, 1, log, O_WRONLY | O_CREAT |
                                         O_TRUNC, 0600) == 0 &&
        posix_spawn_file_actions_adddup2(&fa, 1, 2) == 0 &&
        posix_spawn_file_actions_adddup2(&fa, fds[1], 3) == 0 &&
        posix_spawn(pid, xvfb, &fa, NULL, argv, environ) == 0;
    (void)posix_spawn_file_actions_destroy(&fa);
    close(fds[1]);
    display[0] = ':';
    size_t used = 1;
    while (ok && used + 1 < sizeof(display)) {
        struct pollfd p = {.fd = fds[0], .events = POLLIN};
        char c;
        if (poll(&p, 1, 15000) <= 0 || read(fds[0], &c, 1) != 1 || c == '\n')
            break;
        display[used++] = c;
    }
    close(fds[0]);
    display[used] = '\0';
    return ok && used > 1 && setenv("DISPLAY", display, 1) == 0;
}

void asf_xvfb_stop(pid_t *pid)
{
    int status;
    if (*pid <= 0)
        return;
    (void)kill(*pid, SIGTERM);
    (void)waitpid(*pid, &status, 0);
    *pid = 0;
}

/* The repo Makefile's SKYCOMBAT_PLATFORM_HEADERS. */
const char *asf_missing_game_header(void)
{
    static const char *const headers[] = {
        "X11/Xlib.h", "X11/extensions/Xrandr.h", "X11/extensions/XInput2.h",
        "X11/Xcursor/Xcursor.h", "GL/glx.h"};
    char path[256];
    for (size_t i = 0; i < sizeof(headers) / sizeof(headers[0]); i++) {
        (void)snprintf(path, sizeof(path), "/usr/include/%s", headers[i]);
        if (access(path, R_OK) != 0)
            return headers[i];
    }
    return NULL;
}

int asf_qa_frames(const char *image)
{
    static char out[65536];
    const char *argv[] = {image, "--qa-frames=120", NULL};
    return test_host_tool_capture(argv, out, sizeof(out), 120000);
}
#endif /* __linux__ */
