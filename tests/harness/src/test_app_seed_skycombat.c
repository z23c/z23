/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_app_seed_skycombat - the real game, seeded from this checkout and
 * built from its copy alone:
 *
 *   app.seed skycombat      -> a release whose tree carries the trimmed
 *                              raylib, the support sources and the Makefile
 *   zcode.package.adopt     -> a copy under <datadir>/copies
 *   app.build {copy}        -> an image and a zcl.app_build.v1 record
 *   <image> --qa-frames=120 -> exit 0 on a private Xvfb display
 *
 * HOME and the datadir are temporary, so the owner key it makes is a
 * throwaway. The seed runs everywhere and prints its package root, so two
 * hosts at one commit can compare roots. The build needs no -dev package
 * (the tree carries the vendored X11/GL headers); the run needs Xvfb and
 * prints SKIP without it, and the host-need row keeps the group out of
 * universal selection unless the operator sets ZCL_TEST_DISPLAY_APPS.
 *
 * make t-fast-exact ONLY=app_seed_skycombat ZCL_TEST_DISPLAY_APPS=1 */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_core.h"
#include "test/app_seed_fixture.h"

#include "chain/chainparams.h"
#include "plugin/plugin_pack.h"
#include <stdlib.h>

#if defined(__linux__)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ASS_PATH 1200

struct ass_world {
    char root[512];
    char home[600], datadir[600];
    char source[ASS_PATH];
    char release[65];
    char copy[ASS_PATH];
    char image[ASS_PATH];
    char image_sha3[65];
    char build_keys[5][65];
    char saved_home[1024], saved_display[256];
    bool had_display;
    pid_t xvfb;
};

static bool ass_world_init(struct ass_world *w)
{
    memset(w, 0, sizeof(*w));
    const char *home = getenv("HOME"), *display = getenv("DISPLAY");
    (void)snprintf(w->saved_home, sizeof(w->saved_home), "%s",
                   home ? home : "");
    w->had_display = display != NULL;
    (void)snprintf(w->saved_display, sizeof(w->saved_display), "%s",
                   display ? display : "");
    if (!getcwd(w->source, sizeof(w->source)) ||
        !test_mkdtemp(w->root, sizeof(w->root), "app_seed_skycombat"))
        return false;
    (void)snprintf(w->home, sizeof(w->home), "%s/home", w->root);
    (void)snprintf(w->datadir, sizeof(w->datadir), "%s/datadir", w->root);
    return mkdir(w->home, 0700) == 0 && mkdir(w->datadir, 0700) == 0 &&
           setenv("HOME", w->home, 1) == 0;
}

static void ass_world_restore(const struct ass_world *w)
{
    if (w->saved_home[0])
        (void)setenv("HOME", w->saved_home, 1);
    if (w->had_display)
        (void)setenv("DISPLAY", w->saved_display, 1);
    else
        (void)unsetenv("DISPLAY");
}

/* Seeding reads no window-system header, so every host prints the package
 * root: equal roots across hosts at one commit are the determinism claim. */
static int ass_seed(struct ass_world *w)
{
    int failures = 0;
    TEST("app.seed skycombat: seed the game from this checkout") {
        struct asf_leaf l;
        ASSERT(asf_seed(&l, "skycombat", w->source, w->datadir));
        (void)snprintf(w->release, sizeof(w->release), "%s",
                       asf_get(&l, "release_id"));
        printf("  [seeded skycombat: release %s package_root %s files %lld]\n",
               w->release, asf_get(&l, "package_root"),
               (long long)json_get_int(json_get(&l.out.data, "file_count")));
        asf_close(&l);
        ASSERT(strlen(w->release) == 64);
        PASS();
    } _test_next:;
    return failures;
}

static int ass_adopt_build(struct ass_world *w)
{
    int failures = 0;
    TEST("app.seed skycombat: adopt and build the copy alone") {
        struct asf_leaf l;
        ASSERT(asf_adopt(w->release, w->datadir, w->copy, sizeof(w->copy)));
        bool built = asf_build(&l, w->copy, w->datadir);
        if (!built)
            printf("  [app.build log tail: %s]\n", asf_get(&l, "log_tail"));
        (void)snprintf(w->image, sizeof(w->image), "%s",
                       asf_get(&l, "image_path"));
        (void)snprintf(w->image_sha3, sizeof(w->image_sha3), "%s",
                       asf_get(&l, "image_sha3"));
        printf("  [built skycombat copy: image_sha3 %s confinement %s]\n",
               w->image_sha3, asf_get(&l, "confinement"));
        static const char *const keys[] = {"version", "env_root", "dependency_root", "record_id", "package_root"};
        for (size_t i = 0; i < 5; ++i)
            (void)snprintf(w->build_keys[i], sizeof(w->build_keys[i]), "%s", asf_get(&l, keys[i]));
        asf_close(&l);
        ASSERT(built && strlen(w->image_sha3) == 64 && w->image[0] == '/');
        PASS();
    } _test_next:;
    return failures;
}

static int ass_runs_qa_frames(struct ass_world *w, const char *xvfb)
{
    int failures = 0;
    TEST("app.seed skycombat: the built image runs 120 QA frames and exits "
         "0 on a private Xvfb") {
        ASSERT(asf_xvfb_start(xvfb, w->root, &w->xvfb));
        int rc = asf_qa_frames(w->image);
        asf_xvfb_stop(&w->xvfb);
        ASSERT_EQ(rc, 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Explicit installed acceptance. These environment inputs belong only to the
 * harness: production resolver still uses the running executable exclusively. */
#include "command/app_installed_source.h"
#include "command/native_zcode_package_copy.h"
#include "base/hex.h"
#include "crypto/sha256.h"
#include "platform/process_lifecycle.h"
#include "platform/time_compat.h"
#include "presentation/model_render.h"
#include "util/spawn.h"
#include "vcs/vcs_manifest.h"
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
extern char **environ;

struct asi_run {
    char bin[PATH_MAX], verifier[PATH_MAX], driver[PATH_MAX];
    char export_dir[ASS_PATH], release[ASS_PATH], home[ASS_PATH];
    char prefix[ASS_PATH], datadir[ASS_PATH], empty[ASS_PATH], tmp[ASS_PATH];
    char installed[ASS_PATH], pin[65];
    struct app_installed_source source;
    struct platform_process cli, display;
};
static const char *const asi_env_keys[] = {
    "HOME", "DISPLAY", "WAYLAND_DISPLAY", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
    "XDG_STATE_HOME", "Z23_SKIP_SYSTEMD", "Z23_INSTALL_PREFIX", "TMPDIR",
    "Z23_UNIT_DIR", "Z23_LAUNCHD_DIR", "Z23_DATADIR", "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS", "Z23_INSTALL_TEST_PLATFORM"
};
struct asi_env { char *value[sizeof(asi_env_keys)/sizeof(asi_env_keys[0])]; };
static bool asi_environment_save(struct asi_env *s)
{
    memset(s, 0, sizeof(*s));
    for (size_t i = 0; i < sizeof(s->value)/sizeof(s->value[0]); ++i) {
        const char *v = getenv(asi_env_keys[i]);
        if (v && !(s->value[i] = strdup(v))) {
            for (size_t j = 0; j < i; ++j) free(s->value[j]);
            memset(s, 0, sizeof(*s)); return false;
        }
    }
    return true;
}
static bool asi_environment_restore(struct asi_env *s)
{
    bool ok = true;
    for (size_t i = 0; i < sizeof(s->value)/sizeof(s->value[0]); ++i) {
        int rc = s->value[i] ? setenv(asi_env_keys[i], s->value[i], 1) : unsetenv(asi_env_keys[i]);
        if (rc != 0) ok = false;
        free(s->value[i]);
    }
    return ok;
}
static bool asi_path(char *out, size_t cap, const char *dir, const char *leaf)
{
    int n = snprintf(out, cap, "%s/%s", dir, leaf);
    return n > 0 && (size_t)n < cap;
}
static bool asi_executable(const char *dir, const char *leaf, char *out, size_t cap)
{
    return asi_path(out, cap, dir, leaf) && access(out, X_OK) == 0;
}
static bool asi_no_installer_hooks(void)
{
    for (char **at = environ; *at; ++at)
        if (!strncmp(*at, "Z23_INSTALL_TEST_", 17)) return false;
    return true;
}
static bool asi_prerequisites(struct ass_world *w, struct asi_run *r)
{
    const char *bins = getenv("ZCL_TEST_INSTALLED_APP_BIN_DIR");
    char path[PATH_MAX];
    if (!bins || bins[0] != '/' || !realpath(bins, r->bin)) return false;
    if (!asi_no_installer_hooks()) return false;
    static const char *const required[] = {"z23", "z23-package-verify", "z23-acme"};
    for (size_t i = 0; i < sizeof(required)/sizeof(required[0]); ++i)
        if (!asi_executable(r->bin, required[i], path, sizeof(path))) return false;
    if (!asi_executable(w->source, "build/bin/z23-dev", r->verifier, sizeof(r->verifier))) return false;
    if (!asi_executable(w->source, "build/bin/native_ui_driver", r->driver, sizeof(r->driver))) return false;
    if (!asi_executable(w->source, "build/bin/z23-lint", path, sizeof(path))) return false;
    if (!asf_xvfb_path()) return false;
    return access("/usr/bin/bash", X_OK) == 0 && access("/usr/bin/strip", X_OK) == 0;
}
static bool asi_paths(struct ass_world *w, struct asi_run *r)
{
    if (!asi_path(r->export_dir, sizeof(r->export_dir), w->root, "export")) return false;
    if (!asi_path(r->release, sizeof(r->release), w->root, "release")) return false;
    if (!asi_path(r->home, sizeof(r->home), w->root, "alice")) return false;
    if (!asi_path(r->empty, sizeof(r->empty), w->root, "outside-checkout")) return false;
    if (!asi_path(r->tmp, sizeof(r->tmp), w->root, "install-tmp")) return false;
    if (!asi_path(r->prefix, sizeof(r->prefix), r->home, ".local")) return false;
    if (!asi_path(r->datadir, sizeof(r->datadir), r->home, "apps-data")) return false;
    return asi_path(r->installed, sizeof(r->installed), r->prefix, "bin/z23") &&
        mkdir(r->home, 0755) == 0 && mkdir(r->empty, 0700) == 0 && mkdir(r->tmp, 0700) == 0;
}
static bool asi_export(struct ass_world *w, struct asi_run *r)
{
    static const char *const keys[] = {"version", "env_root", "dependency_root", "record_id"};
    struct asf_leaf leaf; asf_open(&leaf);
    bool ok = json_push_kv_str(&leaf.in, "app", "skycombat") &&
        json_push_kv_str(&leaf.in, "copy", w->copy) &&
        json_push_kv_str(&leaf.in, "datadir", w->datadir) &&
        json_push_kv_str(&leaf.in, "artifact_dir", r->export_dir);
    for (size_t i = 0; ok && i < 4; ++i)
        ok = strlen(w->build_keys[i]) == 64 && json_push_kv_str(&leaf.in, keys[i], w->build_keys[i]);
    if (ok) ok = asf_pass("app.source.export", &leaf);
    if (ok) ok = strlen(asf_get(&leaf, "projection_sha3")) == 64;
    if (ok) memcpy(r->pin, asf_get(&leaf, "projection_sha3"), 65);
    asf_close(&leaf);
    char image[ASS_PATH], why[256];
    if (ok) ok = asi_path(image, sizeof(image), r->export_dir, "image") &&
        app_installed_source_load(r->export_dir, r->pin, image, &r->source, why, sizeof(why));
    return ok;
}
static bool asi_original(struct ass_world *w, struct asi_run *r)
{
    struct zcl_package_copy copy = {0}; struct asf_leaf leaf; asf_open(&leaf);
    uint8_t package[32], record[32], image[32];
    bool ok = zcl_hex_decode_lower(w->build_keys[4], package, 32) &&
        zcl_hex_decode_lower(w->build_keys[3], record, 32) &&
        zcl_hex_decode_lower(w->image_sha3, image, 32) &&
        zcl_package_copy_open_selected_as(w->copy, ZCL_PACKAGE_COPY_READ, &copy,
            &leaf.out, "app.source.export", w->build_keys[0]);
    if (ok) ok = !memcmp(copy.selected_tree, r->source.tree_root, 32) &&
        !memcmp(package, r->source.package_root, 32) && !memcmp(record, r->source.record_id, 32) &&
        !memcmp(image, r->source.build.image_sha3, 32);
    zcl_package_copy_close(&copy); asf_close(&leaf); return ok;
}
static bool asi_tool_log(const struct ass_world *w, const char *log,
                         const char *text, const struct zcl_spawn_evidence *e)
{
    char path[ASS_PATH];
    if (!asi_path(path, sizeof(path), w->root, log)) return false;
    FILE *f = fopen(path, "ab"); if (!f) return false;
    size_t n = strlen(text);
    bool ok = fprintf(f, "exit=%d observed=%d timeout=%d truncated=%d\n",
        e->exit_code, e->exit_observed, e->timed_out, e->stdout_truncated) > 0 &&
        fwrite(text, 1, n, f) == n &&
        fwrite(e->stderr_tail, 1, e->stderr_len, f) == e->stderr_len;
    if (fclose(f) != 0) ok = false;
    return ok;
}
static bool asi_tool(const struct ass_world *w, const char *log,
                     const char *const *argv, int timeout)
{
    char text[65536]; struct zcl_spawn_evidence e;
    int rc = zcl_spawn_capture_evidence(argv, text, sizeof(text), timeout, &e);
    bool saved = asi_tool_log(w, log, text, &e);
    test_note("installed tool %s exit=%d observed=%d timeout=%d truncated=%d",
              log, rc, e.exit_observed, e.timed_out, e.stdout_truncated);
    test_note_bytes("installed tool stderr tail", e.stderr_tail, e.stderr_len);
    return saved && rc == 0 && e.exit_observed && !e.timed_out && !e.stdout_truncated && e.stdout_complete;
}
static bool asi_manifest_pin(const struct asi_run *r, char pin[65])
{
    char path[ASS_PATH]; unsigned char bytes[2049], hash[32];
    if (!asi_path(path, sizeof(path), r->release, "SHA256SUMS")) return false;
    FILE *f = fopen(path, "rb"); if (!f) return false;
    size_t n = fread(bytes, 1, sizeof(bytes), f);
    bool ok = n > 0 && n <= 2048 && feof(f) && !ferror(f);
    if (fclose(f) != 0) ok = false;
    if (!ok) return false;
    struct sha256_ctx h; sha256_init(&h); sha256_write(&h, bytes, n); sha256_finalize(&h, hash);
    zcl_hex_encode(hash, 32, pin); return true;
}
static bool asi_package(struct ass_world *w, struct asi_run *r)
{
    char script[PATH_MAX];
    if (!asi_path(script, sizeof(script), w->source, "platform/packaging/release/build_release.sh")) return false;
    const char *argv[] = {"/usr/bin/bash", script, "--bin", r->bin, "--out", r->release,
        "--platform", "linux-x86_64", "--app-source", r->export_dir,
        "--app-source-sha3", r->pin, "--app-verifier", r->verifier, NULL};
    return asi_tool(w, "installed-package.log", argv, 600000);
}
static bool asi_service_isolation(const struct asi_run *r)
{
    char units[ASS_PATH], launchd[ASS_PATH], runtime[ASS_PATH];
    if (!asi_path(units, sizeof(units), r->home, ".config/systemd/user") ||
        !asi_path(launchd, sizeof(launchd), r->home, "Library/LaunchAgents") ||
        !asi_path(runtime, sizeof(runtime), r->home, "runtime") || mkdir(runtime, 0700) != 0) return false;
    return setenv("Z23_UNIT_DIR", units, 1) == 0 && setenv("Z23_LAUNCHD_DIR", launchd, 1) == 0 &&
        setenv("XDG_RUNTIME_DIR", runtime, 1) == 0;
}
static bool asi_no_services(const struct asi_run *r)
{
    const char *const dirs[] = {".config/systemd/user", "Library/LaunchAgents"};
    for (size_t i = 0; i < sizeof(dirs)/sizeof(dirs[0]); ++i) {
        char path[ASS_PATH]; struct stat st;
        if (!asi_path(path, sizeof(path), r->home, dirs[i]) || lstat(path, &st) == 0 || errno != ENOENT)
            return false;
    }
    return true;
}
static bool asi_consumer_env(struct asi_run *r)
{
    static const char *const unset[] = {"WAYLAND_DISPLAY", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME",
        "Z23_SKIP_SYSTEMD", "Z23_DATADIR", "DBUS_SESSION_BUS_ADDRESS", "Z23_INSTALL_TEST_PLATFORM"};
    for (size_t i = 0; i < sizeof(unset)/sizeof(unset[0]); ++i)
        if (unsetenv(unset[i]) != 0) return false;
    return setenv("HOME", r->home, 1) == 0 && setenv("TMPDIR", r->tmp, 1) == 0 &&
        setenv("Z23_INSTALL_PREFIX", r->prefix, 1) == 0 && asi_service_isolation(r);
}
static bool asi_install(struct ass_world *w, struct asi_run *r)
{
    char script[PATH_MAX], pin[65];
    if (!asi_manifest_pin(r, pin) || !asi_consumer_env(r)) return false;
    if (!asi_path(script, sizeof(script), w->source, "tools/scripts/install_z23.sh")) return false;
    const char *argv[] = {"/usr/bin/bash", script, "--apps", "--source", r->release, "--manifest-sha256", pin, NULL};
    return asi_no_services(r) && asi_tool(w, "installed-install.log", argv, 300000) && asi_no_services(r);
}
/* These are retained direct posix_spawn children, never handed to an identity
 * helper which may reap them. No competing reaper; PID cannot be reused before
 * this wait. Reject inherited auto-reaping SIGCHLD at preflight. */
static bool asi_stop(struct platform_process *p)
{
    if (!p->pid) return true;
    enum platform_process_wait_result state = platform_process_wait(p, 0, NULL);
    if (state == PLATFORM_PROCESS_WAIT_EXITED) {
        platform_process_close(p); return true;
    }
    if (state != PLATFORM_PROCESS_WAIT_RUNNING) return false;
    if (!platform_process_terminate(p, 1) && errno != ESRCH) return false;
    state = platform_process_wait(p, 5000, NULL);
    if (state == PLATFORM_PROCESS_WAIT_RUNNING) {
        if (kill((pid_t)p->pid, SIGKILL) != 0 && errno != ESRCH) return false;
        state = platform_process_wait(p, 5000, NULL);
    }
    if (state != PLATFORM_PROCESS_WAIT_EXITED) return false;
    platform_process_close(p); return true;
}
static bool asi_spawn(struct platform_process *p, const char *const *argv, int output, int error)
{
    posix_spawn_file_actions_t actions;
    if (posix_spawn_file_actions_init(&actions) != 0) return false;
    bool ok = posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0) == 0 &&
        posix_spawn_file_actions_adddup2(&actions, output, 1) == 0 &&
        posix_spawn_file_actions_adddup2(&actions, error, 2) == 0;
    pid_t pid = -1;
    if (ok) ok = posix_spawn(&pid, argv[0], &actions, NULL, (char *const *)argv, environ) == 0;
    posix_spawn_file_actions_destroy(&actions);
    if (ok) { p->pid = (uint64_t)pid; p->native = (uintptr_t)pid; }
    return ok;
}
/* One deadline for the whole displayfd line, including interrupted/partial
 * reads. Nonblocking input prevents a readiness race from extending it. */
static int asi_display_poll(int fd, int64_t started, int64_t deadline)
{
    int64_t left = deadline - platform_time_monotonic_ms();
    if (left <= 0) {
        printf("installed display deadline elapsed_ms=%lld\n",
               (long long)(platform_time_monotonic_ms() - started));
        return -1;
    }
    struct pollfd p = {.fd = fd, .events = POLLIN};
    int rc = poll(&p, 1, (int)left), error = rc < 0 ? errno : 0;
    printf("installed display poll rc=%d revents=0x%x errno=%d elapsed_ms=%lld\n",
           rc, (unsigned short)p.revents, error,
           (long long)(platform_time_monotonic_ms() - started));
    if (rc < 0 && error == EINTR) return 0;
    if (rc <= 0 || (p.revents & POLLNVAL)) return -1;
    /* Drain readable bytes on HUP/ERR too; read distinguishes EOF/error. */
    return 1;
}
static bool asi_display_line(int fd, char *display, size_t cap, int64_t started)
{
    int64_t deadline = platform_time_monotonic_ms() + 15000;
    size_t used = 1; display[0] = ':';
    while (used + 1 < cap) {
        int ready = asi_display_poll(fd, started, deadline);
        if (ready < 0) return false;
        if (!ready) continue;
        char c;
        ssize_t n = read(fd, &c, 1); int error = n < 0 ? errno : 0;
        printf("installed display read n=%lld errno=%d bytes=%zu elapsed_ms=%lld\n",
               (long long)n, error, used - 1,
               (long long)(platform_time_monotonic_ms() - started));
        if (n < 0 && (error == EINTR || error == EAGAIN)) continue;
        if (n != 1) return false;
        if (c == '\n') { display[used] = 0; return used > 1; }
        if (c < '0' || c > '9') return false;
        display[used++] = c;
    }
    printf("installed display line exceeds bound=%zu\n", cap - 2);
    return false;
}
static bool asi_display(struct ass_world *w, struct asi_run *r)
{
    int fd[2]; char path[ASS_PATH], display[32];
    if (!asi_path(path, sizeof(path), w->root, "installed-xvfb.log") || pipe(fd) != 0) return false;
    int64_t started = platform_time_monotonic_ms();
    int log = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    bool ok = log >= 0 && fcntl(fd[0], F_SETFD, FD_CLOEXEC) == 0 &&
        fcntl(fd[1], F_SETFD, FD_CLOEXEC) == 0 && fcntl(fd[0], F_SETFL, O_NONBLOCK) == 0;
    const char *argv[] = {asf_xvfb_path(), "-displayfd", "1", "-nolisten", "tcp", "-screen", "0", "1280x800x24", NULL};
    if (ok) ok = asi_spawn(&r->display, argv, fd[1], log);
    printf("installed display start ok=%d pid=%llu elapsed_ms=%lld\n", ok,
           (unsigned long long)r->display.pid,
           (long long)(platform_time_monotonic_ms() - started));
    close(fd[1]); if (log >= 0) close(log);
    if (ok) ok = asi_display_line(fd[0], display, sizeof(display), started);
    close(fd[0]);
    return ok && setenv("DISPLAY", display, 1) == 0;
}

static bool asi_window_wait(struct ass_world *w, struct asi_run *r,
                           const char *title, const char *action, unsigned timeout)
{
    char limit[40];
    (void)snprintf(limit, sizeof(limit), "--timeout-ms=%u", timeout);
    const char *argv[] = {r->driver, title, action, limit, NULL};
    return asi_tool(w, "installed-driver.log", argv, timeout + 2000u);
}
static bool asi_window_driver(struct ass_world *w, struct asi_run *r,
                              const char *title, const char *action)
{
    return asi_window_wait(w, r, title, action, 5000);
}
static bool asi_driver(struct ass_world *w, struct asi_run *r, const char *action)
{
    return asi_window_driver(w, r, "--title=Make my copy", action);
}
static bool asi_json_file(const char *path, struct json_value *out)
{
    char wire[65537]; FILE *f = fopen(path, "rb"); if (!f) return false;
    size_t n = fread(wire, 1, sizeof(wire)-1, f);
    bool ok = feof(f) && !ferror(f) && n > 0;
    if (fclose(f) != 0) ok = false;
    return ok && json_read(out, wire, n);
}
static const char *asi_string(const struct json_value *v, const char *key)
{
    const char *s = json_get_str(json_get(v, key)); return s ? s : "";
}
static bool asi_passed(const struct json_value *reply)
{
    return json_get_bool(json_get(reply, "ok")) && !strcmp(asi_string(reply, "status"), "passed");
}
static bool asi_cli_start(struct ass_world *w, struct asi_run *r, const char *verb, const char *log)
{
    char path[ASS_PATH], errpath[ASS_PATH], data[ASS_PATH+16];
    if (!asi_path(path, sizeof(path), w->root, log) ||
        !asi_path(errpath, sizeof(errpath), w->root, "installed-cli.stderr")) return false;
    int n = snprintf(data, sizeof(data), "--datadir=%s", r->datadir);
    if (n < 0 || (size_t)n >= sizeof(data)) return false;
    int out = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    int err = open(errpath, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    const char *argv[] = {r->installed, "app", verb, "--json", data,
        !strcmp(verb, "adopt") ? "--name=skycombat" : NULL, NULL};
    bool ok = out >= 0 && err >= 0 && asi_spawn(&r->cli, argv, out, err);
    if (out >= 0) close(out);
    if (err >= 0) close(err);
    return ok;
}
static bool asi_cli_finish(struct ass_world *w, struct asi_run *r, const char *log, struct json_value *reply)
{
    uint32_t code = UINT32_MAX;
    enum platform_process_wait_result state = platform_process_wait(&r->cli, 120000, &code);
    if (state == PLATFORM_PROCESS_WAIT_EXITED) platform_process_close(&r->cli);
    bool ok = state == PLATFORM_PROCESS_WAIT_EXITED && code == 0;
    char path[ASS_PATH];
    return ok && asi_path(path, sizeof(path), w->root, log) && asi_json_file(path, reply) && asi_passed(reply);
}
static bool asi_discovery(struct ass_world *w, struct asi_run *r)
{
    struct json_value reply; json_init(&reply);
    bool ok = asi_cli_start(w, r, "list", "installed-list.json") &&
        asi_cli_finish(w, r, "installed-list.json", &reply);
    bool found = false;
    const struct json_value *list = json_get(json_get(&reply, "data"), "launchable");
    if (!list || list->type != JSON_ARR) ok = false;
    for (size_t i = 0; ok && i < json_size(list); ++i) {
        const struct json_value *row = json_at(list, i);
        if (!strcmp(asi_string(row, "id"), "skycombat"))
            found = json_get_bool(json_get(row, "installed")) &&
                !strcmp(asi_string(row, "source"), "builtin");
    }
    json_free(&reply); return ok && found;
}
static bool asi_no_consumer_state(const struct asi_run *r)
{
    static const char *const paths[] = {"apps-data", ".z23", ".zclassic-c23", ".zclassic-c23-dev", ".config", ".local/state"};
    struct stat st; char path[ASS_PATH];
    for (size_t i = 0; i < sizeof(paths)/sizeof(paths[0]); ++i) {
        if (!asi_path(path, sizeof(path), r->home, paths[i])) return false;
        if (lstat(path, &st) == 0 || errno != ENOENT) return false;
    }
    return true;
}

static bool asi_successor(struct asi_run *r, const struct json_value *data);

static bool asi_terminal_spawn(struct ass_world *w, struct asi_run *r,
    const char *log, const char *const *argv)
{
    char path[ASS_PATH], errpath[ASS_PATH];
    if (!asi_path(path, sizeof(path), w->root, log) ||
        !asi_path(errpath, sizeof(errpath), w->root, "installed-cli.stderr")) return false;
    int out = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    int err = open(errpath, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    bool ok = out >= 0 && err >= 0 && asi_spawn(&r->cli, argv, out, err);
    if (out >= 0) close(out);
    if (err >= 0) close(err);
    return ok;
}

static bool asi_terminal_refusal(struct ass_world *w, struct asi_run *r,
    const char *data, const char *plan_arg, const char *name, const char *code_name)
{
    char log[ASS_PATH];
    if (!asi_path(log, sizeof(log), w->root, name)) return false;
    const char *argv[] = {r->installed, "app", "copy", "--json", "--app=skycombat", data,
                          plan_arg, "--confirm=true", NULL};
    bool ok = asi_terminal_spawn(w, r, name, argv);
    uint32_t code = 0;
    if (ok) {
        enum platform_process_wait_result state = platform_process_wait(&r->cli, 120000, &code);
        ok = state == PLATFORM_PROCESS_WAIT_EXITED && code != 0;
        if (state == PLATFORM_PROCESS_WAIT_EXITED) platform_process_close(&r->cli);
        else if (!asi_stop(&r->cli)) return false;
    }
    struct json_value reply; json_init(&reply);
    if (ok) {
        ok = asi_json_file(log, &reply) && !json_get_bool(json_get(&reply, "ok")) &&
            !json_get_bool(json_get(json_get(&reply, "error"), "mutated")) &&
            (!code_name || !strcmp(asi_string(json_get(&reply, "error"), "code"), code_name));
    }
    json_free(&reply);
    return ok;
}

static bool asi_terminal_key_changed(struct ass_world *w, struct asi_run *r,
    const char *home, const char *data, const char *plan_arg)
{
    char dir[ASS_PATH], key[ASS_PATH], pub[PLUGIN_HEX_PUBLIC_KEY + 1];
    if (!asi_path(dir, sizeof(dir), home, ".z23") ||
        !asi_path(key, sizeof(key), dir, "zcode_publisher.key") ||
        mkdir(dir, 0700) != 0) return false;
    bool ok = plugin_keygen(key, pub) == PLUGIN_OK &&
        asi_terminal_refusal(w, r, data, plan_arg, "terminal-key-refused.json", "PLAN_MISMATCH");
    if (r->cli.pid) return false; /* preserve fixture while an unreaped child may use it */
    if (unlink(key) != 0 || rmdir(dir) != 0) ok = false;
    return ok;
}

static bool asi_terminal_source_changed(struct ass_world *w, struct asi_run *r,
    const char *data, const char *plan_arg)
{
    char selector[ASS_PATH], saved[ASS_PATH];
    if (!asi_path(selector, sizeof(selector), r->prefix, "share/z23/apps/skycombat") ||
        !asi_path(saved, sizeof(saved), r->prefix, "share/z23/apps/skycombat.saved-test") ||
        rename(selector, saved) != 0) return false;
    bool ok = symlink("missing-generation", selector) == 0 &&
        asi_terminal_refusal(w, r, data, plan_arg, "terminal-source-refused.json", NULL);
    if (r->cli.pid) return false; /* preserve fixture while an unreaped child may use it */
    if (unlink(selector) != 0 && errno != ENOENT) ok = false;
    if (rename(saved, selector) != 0) ok = false;
    return ok;
}

static bool asi_terminal_empty(const char *datadir)
{
    const char *const paths[] = {"zcode", "copies"};
    for (size_t i = 0; i < sizeof(paths)/sizeof(paths[0]); ++i) {
        char path[ASS_PATH]; struct stat st;
        if (!asi_path(path, sizeof(path), datadir, paths[i]) ||
            lstat(path, &st) == 0 || errno != ENOENT) return false;
    }
    return true;
}

static bool asi_terminal_plan(struct ass_world *w, struct asi_run *r,
    const char *datadir, const char *data, char plan_arg[80])
{
    char log[ASS_PATH];
    if (!asi_path(log, sizeof(log), w->root, "terminal-plan.json")) return false;
    const char *plan_argv[] = {r->installed, "app", "copy", "--json", "--app=skycombat", data, NULL};
    bool ok = asi_terminal_spawn(w, r, "terminal-plan.json", plan_argv);
    struct json_value plan; json_init(&plan);
    if (ok) ok = asi_cli_finish(w, r, "terminal-plan.json", &plan);
    const struct json_value *d = json_get(&plan, "data");
    const char *id = asi_string(d, "plan_id"), *root = asi_string(d, "package_root");
    char expected[65];
    zcl_hex_encode(r->source.package_root, 32, expected);
    ok = ok && strlen(id) == 64 && !strcmp(root, expected) &&
         json_get_bool(json_get(d, "key_will_create")) &&
         snprintf(plan_arg, 80, "--plan_id=%s", id) < 80;
    if (ok) {
        struct stat st; const char *key = asi_string(d, "key_path");
        ok = key[0] && lstat(key, &st) != 0 && errno == ENOENT;
        ok = ok && asi_terminal_empty(datadir);
    }
    json_free(&plan);
    return ok;
}

static bool asi_terminal_confirm(struct ass_world *w, struct asi_run *r,
    const char *data, const char *plan_arg)
{
    char log[ASS_PATH];
    if (!asi_path(log, sizeof(log), w->root, "terminal-confirm.json")) return false;
    const char *argv[] = {r->installed, "app", "copy", "--json", "--app=skycombat", data,
                          plan_arg, "--confirm=true", NULL};
    bool ok = asi_terminal_spawn(w, r, "terminal-confirm.json", argv);
    struct json_value reply; json_init(&reply);
    if (ok) ok = asi_cli_finish(w, r, "terminal-confirm.json", &reply);
    const struct json_value *d = json_get(&reply, "data");
    if (ok) ok = asi_successor(r, d) && json_get_bool(json_get(d, "key_created"));
    json_free(&reply);
    return ok;
}

/* Exercise installed terminal copy in a separate, isolated owner home. */
static bool asi_terminal_copy(struct ass_world *w, struct asi_run *r)
{
    char home[ASS_PATH], datadir[ASS_PATH], data[ASS_PATH + 16], plan_arg[80];
    if (!asi_path(home, sizeof(home), w->root, "terminal-home") ||
        !asi_path(datadir, sizeof(datadir), w->root, "terminal-data") ||
        mkdir(home, 0700) != 0 || mkdir(datadir, 0700) != 0 ||
        snprintf(data, sizeof(data), "--datadir=%s", datadir) >= (int)sizeof(data)) return false;
    if (setenv("HOME", home, 1) != 0) return false;
    bool ok = asi_terminal_plan(w, r, datadir, data, plan_arg) &&
        asi_terminal_key_changed(w, r, home, data, plan_arg) &&
        asi_terminal_empty(datadir) &&
        asi_terminal_source_changed(w, r, data, plan_arg) &&
        asi_terminal_empty(datadir) &&
        asi_terminal_confirm(w, r, data, plan_arg);
    return setenv("HOME", r->home, 1) == 0 && ok;
}
static bool asi_cancel(struct ass_world *w, struct asi_run *r)
{
    struct json_value reply; json_init(&reply);
    bool ok = asi_cli_start(w, r, "adopt", "installed-cancel.json") &&
        asi_driver(w, r, "--expect-count=1") && asi_no_consumer_state(r) &&
        asi_driver(w, r, "--key=tab") && asi_driver(w, r, "--key=enter") &&
        asi_cli_finish(w, r, "installed-cancel.json", &reply);
    if (ok) ok = !strcmp(asi_string(json_get(&reply, "data"), "status"), "canceled") &&
        asi_driver(w, r, "--expect-count=0") && asi_no_consumer_state(r);
    json_free(&reply); return ok;
}
static bool asi_payload(const struct vcs_manifest *a, const struct vcs_manifest *b)
{
    if (a->count != b->count || !a->count) return false;
    unsigned metadata = 0;
    for (size_t i = 0; i < a->count; ++i) {
        const struct vcs_entry *x = &a->entries[i], *y = &b->entries[i];
        if (strcmp(x->path, y->path) || x->mode != y->mode) return false;
        if (!strcmp(x->path, "zcode-package.json")) {
            if (!memcmp(x->blob, y->blob, 32)) return false;
            ++metadata;
        } else if (x->size != y->size || memcmp(x->blob, y->blob, 32)) return false;
    }
    return metadata == 1;
}
static bool asi_successor(struct asi_run *r, const struct json_value *data)
{
    struct zcl_package_copy copy = {0}; struct asf_leaf leaf; asf_open(&leaf);
    struct vcs_manifest original, successor; vcs_manifest_init(&original); vcs_manifest_init(&successor);
    const char *path = asi_string(data, "copy"), *version = asi_string(data, "version");
    uint8_t package[32];
    bool ok = strlen(version) == 64 && !strncmp(asi_string(data, "namespace"), "p-", 2) &&
        zcl_hex_decode_lower(asi_string(data, "package_root"), package, 32) &&
        !memcmp(package, r->source.package_root, 32) &&
        zcl_package_copy_open_selected_as(path, ZCL_PACKAGE_COPY_READ, &copy,
            &leaf.out, "app.source.export", version);
    if (ok) ok = !memcmp(copy.fork_tree, r->source.tree_root, 32) &&
        memcmp(copy.fork_version, copy.selected_version, 32) &&
        !memcmp(copy.selected_version, copy.head_version, 32);
    if (ok) ok = vcs_tree_load_readonly_bounded(path, copy.fork_tree, 8u*1024u*1024u, 8192, &original) &&
        vcs_tree_load_readonly_bounded(path, copy.selected_tree, 8u*1024u*1024u, 8192, &successor) &&
        asi_payload(&original, &successor);
    vcs_manifest_free(&original); vcs_manifest_free(&successor);
    zcl_package_copy_close(&copy); asf_close(&leaf); return ok;
}
static bool asi_adopted_only(struct asi_run *r, const struct json_value *data)
{
    const struct json_value *executed = json_get(data, "continuation_executed");
    if (!executed || executed->type != JSON_BOOL || json_get_bool(executed)) return false;
    if (strcmp(asi_string(data, "continuation"), "adopted")) return false;
    if (!json_get_bool(json_get(data, "adopted")) || json_get_bool(json_get(data, "executed"))) return false;
    char path[ASS_PATH]; struct stat st;
    if (!asi_path(path, sizeof(path), r->datadir, "app_build")) return false;
    if (lstat(path, &st) == 0 || errno != ENOENT) return false;
    if (!asi_path(path, sizeof(path), r->home, ".local/state")) return false;
    return lstat(path, &st) != 0 && errno == ENOENT;
}
static void asi_diagnostic_tail(struct ass_world *w, const char *leaf)
{
    char path[ASS_PATH], bytes[4096];
    if (!asi_path(path, sizeof(path), w->root, leaf)) return;
    FILE *f = fopen(path, "rb");
    if (!f) { test_note("installed diagnostic %s open errno=%d", leaf, errno); return; }
    bool ok = fseek(f, 0, SEEK_END) == 0;
    long size = ok ? ftell(f) : -1;
    long start = size > (long)sizeof(bytes) ? size - (long)sizeof(bytes) : 0;
    ok = size >= 0 && fseek(f, start, SEEK_SET) == 0;
    size_t n = ok ? fread(bytes, 1, sizeof(bytes), f) : 0;
    test_note("installed diagnostic %s size=%ld tail=%zu error=%d", leaf, size, n, ferror(f));
    test_note_bytes(leaf, bytes, n);
    (void)fclose(f);
}
static void asi_confirm_diagnostic(struct ass_world *w, struct asi_run *r, int64_t started)
{
    /* Failure is already latched. Read-only window query, no key injection.
     * RUNNING is observed direct-child state, not a claim of forward progress. */
    uint32_t code = UINT32_MAX;
    enum platform_process_wait_result state = platform_process_wait(&r->cli, 0, &code);
    test_note("installed confirm FAILED elapsed_ms=%lld child=%llu wait_state=%d exit=%u source_stage_timing=unavailable",
        (long long)(platform_time_monotonic_ms() - started),
        (unsigned long long)r->cli.pid, (int)state, (unsigned)code);
    if (state == PLATFORM_PROCESS_WAIT_EXITED) platform_process_close(&r->cli);
    const char *argv[] = {r->driver, "--title=Make my copy", "--expect-count=0", "--timeout-ms=20", NULL};
    (void)asi_tool(w, "installed-driver.log", argv, 1000);
    asi_diagnostic_tail(w, "installed-cli.stderr");
    asi_diagnostic_tail(w, "installed-confirm.json");
    test_note("installed confirm diagnostic complete; original failure retained");
}

static bool asi_copy_ready(struct ass_world *w, struct asi_run *r, int64_t started)
{
    /* One five-second responsiveness bound, including disappearance of the
     * consent window. The remaining copy window is progress or continuation. */
    bool visible = asi_driver(w, r, "--expect-count=0") &&
        asi_window_driver(w, r, "--title=copy", "--expect-count=1");
    int64_t feedback = platform_time_monotonic_ms() - started;
    printf("installed copy feedback_ms=%lld\n", (long long)feedback);
    if (!visible || feedback > 5000) return false;
    const int64_t deadline = started + 180000;
    while (platform_time_monotonic_ms() < deadline) {
        if (asi_window_wait(w, r, "--title=Your copy is ready", "--expect-count=1", 1000)) {
            printf("installed copy ready_ms=%lld\n", (long long)(platform_time_monotonic_ms() - started));
            return platform_time_monotonic_ms() <= deadline;
        }
        uint32_t code;
        if (platform_process_wait(&r->cli, 0, &code) != PLATFORM_PROCESS_WAIT_RUNNING) return false;
    }
    return false;
}
static bool asi_confirm_actions(struct ass_world *w, struct asi_run *r)
{
    if (!asi_cli_start(w, r, "adopt", "installed-confirm.json") ||
        !asi_driver(w, r, "--expect-count=1") || !asi_no_consumer_state(r)) return false;
    /* Unfocused -> Cancel -> Back -> Next. Owner refuses confirmation until
     * all pages visited. Repeat Next up to the maintained maximum; no copied
     * model/text or injected presenter, no per-page pixel/readability claim. */
    for (unsigned i = 0; i < 3; ++i) if (!asi_driver(w, r, "--key=tab")) return false;
    for (unsigned i = 1; i < ZCL_PRESENT_MODEL_PAGES_MAX; ++i)
        if (!asi_driver(w, r, "--key=enter") || !asi_no_consumer_state(r)) return false;
    if (!asi_driver(w, r, "--key=tab")) return false;
    int64_t started = platform_time_monotonic_ms();
    if (!asi_driver(w, r, "--key=enter")) return false;
    /* Adopt now offers the same explicit continuation as Receive. Close is
     * initially focused; do not request any build, preview, or Keep. */
    if (!asi_copy_ready(w, r, started)) {
        asi_confirm_diagnostic(w, r, started);
        return false;
    }
    if (!asi_window_driver(w, r, "--title=Your copy is ready", "--key=enter")) return false;
    return true;
}
static bool asi_confirm(struct ass_world *w, struct asi_run *r)
{
    if (!asi_confirm_actions(w, r)) return false;
    struct json_value reply; json_init(&reply);
    bool ok = asi_cli_finish(w, r, "installed-confirm.json", &reply) &&
        asi_adopted_only(r, json_get(&reply, "data")) && asi_successor(r, json_get(&reply, "data")) &&
        asi_driver(w, r, "--expect-count=0") &&
        asi_window_driver(w, r, "--title=Your copy is ready", "--expect-count=0");
    json_free(&reply); return ok;
}
static bool asi_copy_public(const char *from, const char *to)
{
    FILE *in = fopen(from, "rb"); if (!in) return false;
    FILE *out = fopen(to, "wbx"); if (!out) { fclose(in); return false; }
    unsigned char bytes[16384]; size_t n; bool ok = true;
    while ((n = fread(bytes, 1, sizeof(bytes), in)) != 0)
        if (fwrite(bytes, 1, n, out) != n) { ok = false; break; }
    ok = ok && !ferror(in) && feof(in);
    if (fclose(in) != 0) ok = false;
    if (fclose(out) != 0) ok = false;
    return ok;
}
static const char *const asi_desktop_names[] = {
    "org.zclassic.ZClassic23.desktop", "org.zclassic.ZClassic23.svg",
    "org.zclassic.ZClassic23.xml", "org.zclassic.SkyCombat.desktop"
};
/* Preserve optional Linux assets without silently accepting a partial set. */
static bool asi_desktop_count(const char *dir, unsigned *count)
{
    *count = 0;
    for (size_t i = 0; i < sizeof(asi_desktop_names)/sizeof(asi_desktop_names[0]); ++i) {
        char path[ASS_PATH]; struct stat st;
        if (!asi_path(path, sizeof(path), dir, asi_desktop_names[i])) return false;
        if (lstat(path, &st) != 0) { if (errno == ENOENT) continue; return false; }
        if (!S_ISREG(st.st_mode) || st.st_size < 1 || st.st_size > 65536) return false;
        ++*count;
    }
    return *count == 0 || *count == 4;
}
static bool asi_desktop_evidence(const struct asi_run *r, const char *dir)
{
    unsigned count;
    if (!asi_desktop_count(r->release, &count)) return false;
    for (unsigned i = 0; i < count; ++i) {
        char from[ASS_PATH], to[PATH_MAX];
        if (!asi_path(from, sizeof(from), r->release, asi_desktop_names[i]) ||
            !asi_path(to, sizeof(to), dir, asi_desktop_names[i]) || !asi_copy_public(from, to)) return false;
    }
    return true;
}
static bool asi_desktop_same(const char *a, const char *b)
{
    FILE *left = fopen(a, "rb"); if (!left) return false;
    FILE *right = fopen(b, "rb"); if (!right) { fclose(left); return false; }
    unsigned char x[4096], y[4096]; size_t nx, ny; bool ok = true;
    do {
        nx = fread(x, 1, sizeof(x), left); ny = fread(y, 1, sizeof(y), right);
        if (nx != ny || memcmp(x, y, nx)) { ok = false; break; }
    } while (nx == sizeof(x));
    ok = ok && feof(left) && feof(right) && !ferror(left) && !ferror(right);
    if (fclose(left) != 0) ok = false;
    if (fclose(right) != 0) ok = false;
    return ok;
}
static bool asi_desktop_installed(const struct asi_run *r)
{
    unsigned count, installed; char pin[65], generation[ASS_PATH], rel[100];
    if (!asi_desktop_count(r->release, &count) || !asi_manifest_pin(r, pin)) return false;
    int n = snprintf(rel, sizeof(rel), "share/z23/apps/%s", pin);
    if (n <= 0 || (size_t)n >= sizeof(rel) || !asi_path(generation, sizeof(generation), r->prefix, rel) ||
        !asi_desktop_count(generation, &installed) || installed != count) return false;
    for (unsigned i = 0; i < count; ++i) {
        char from[ASS_PATH], to[ASS_PATH];
        if (!asi_path(from, sizeof(from), r->release, asi_desktop_names[i]) ||
            !asi_path(to, sizeof(to), generation, asi_desktop_names[i]) || !asi_desktop_same(from, to)) return false;
    }
    return true;
}
#if defined(ZCL_TESTING)
/* Tests production parsing and desktop reads only; does not impersonate an
 * installed executable or grant the source authority returned by resolve(). */
bool zcl_test_installed_desktop_manifest(int dir, const char *wire, size_t length, bool mac);
bool zcl_test_installed_toolchain_manifest(int dir, const char *wire, size_t length, bool mac);
struct isd_fixture { int fd; char directory[ASS_PATH], wire[2049], digest[65]; };
static bool isd_wire(struct isd_fixture *f, unsigned base, unsigned desktop)
{
    static const char *const names[] = {"AGENT_CARD.md", "app-build.wire", "installed-source.json",
        "manifest.wire", "recipe.wire", "source.bundle", "z23", "z23-acme", "z23-package-verify",
        "z23-skycombat", "zclassic23", "zclassic23-acme", "zclassic23-package-verify"};
    char base_digest[65]; memset(base_digest, '1', 64); base_digest[64] = 0;
    size_t used = 0; f->wire[0] = 0;
    for (unsigned i = 0; i < 17; ++i) {
        bool present = i < 13 ? (base & (1u << i)) != 0 : (desktop & (1u << (i - 13))) != 0;
        if (!present) continue;
        const char *name = i < 13 ? names[i] : asi_desktop_names[i - 13];
        const char *digest = i < 13 ? base_digest : f->digest;
        int n = snprintf(f->wire + used, sizeof(f->wire) - used, "%s  %s\n", digest, name);
        if (n <= 0 || (size_t)n >= sizeof(f->wire) - used) return false;
        used += (size_t)n;
    }
    return true;
}
static bool isd_check(const struct isd_fixture *f, bool mac)
{
    return zcl_test_installed_desktop_manifest(f->fd, f->wire, strlen(f->wire), mac);
}
static bool isd_write_name(const struct isd_fixture *f, const char *name, const void *data, size_t size)
{
    int fd = openat(f->fd, name, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    FILE *out = fdopen(fd, "wb"); if (!out) { close(fd); return false; }
    bool ok = fwrite(data, 1, size, out) == size;
    if (fclose(out) != 0) ok = false;
    return ok;
}
static bool isd_write(const struct isd_fixture *f, unsigned index, const void *data, size_t size)
{
    return isd_write_name(f, asi_desktop_names[index], data, size);
}
static bool isd_payload(struct isd_fixture *f, size_t size)
{
    unsigned char *bytes = malloc(size); if (!bytes) return false;
    memset(bytes, 'x', size); uint8_t digest[32]; struct sha256_ctx hash;
    sha256_init(&hash); sha256_write(&hash, bytes, size); sha256_finalize(&hash, digest);
    zcl_hex_encode(digest, 32, f->digest);
    bool ok = true;
    for (unsigned i = 0; i < 4 && ok; ++i) ok = isd_write(f, i, bytes, size);
    free(bytes); return ok;
}
static bool isd_missing_base(struct isd_fixture *f)
{
    for (unsigned row = 0; row < 13; ++row)
        if (!isd_wire(f, 8191u ^ (1u << row), 15u) || isd_check(f, false)) return false;
    /* Exactly thirteen rows, but four base members replaced with desktops. */
    return isd_wire(f, 8191u ^ 15u, 15u) && !isd_check(f, false);
}
static bool isd_shapes(struct isd_fixture *f)
{
    if (!isd_wire(f, 8191u, 0) || !isd_check(f, false) || !isd_check(f, true)) return false;
    if (!isd_wire(f, 8191u, 15u) || !isd_check(f, false) || isd_check(f, true)) return false;
    for (unsigned mask = 1; mask < 15; ++mask)
        if (!isd_wire(f, 8191u, mask) || isd_check(f, false)) return false;
    return isd_missing_base(f);
}
static bool isd_bad_rows(struct isd_fixture *f)
{
    if (!isd_wire(f, 8191u, 15u)) return false;
    char *alias = strstr(f->wire, "  zclassic23\n");
    if (!alias) return false;
    alias[-64] = '2';
    if (isd_check(f, false) || !isd_wire(f, 8191u, 15u)) return false;
    char *name = strstr(f->wire, "org.zclassic.SkyCombat.desktop");
    if (!name) return false;
    name[0] = 'X';
    if (isd_check(f, false) || !isd_wire(f, 8191u, 15u)) return false;
    size_t used = strlen(f->wire);
    int n = snprintf(f->wire + used, sizeof(f->wire) - used, "%s  %s\n", f->digest, asi_desktop_names[0]);
    return n > 0 && (size_t)n < sizeof(f->wire) - used && !isd_check(f, false);
}
static bool isd_missing_link(struct isd_fixture *f)
{
    if (unlinkat(f->fd, asi_desktop_names[0], 0) != 0 || isd_check(f, false)) return false;
    if (symlinkat(asi_desktop_names[1], f->fd, asi_desktop_names[0]) != 0 || isd_check(f, false)) return false;
    return unlinkat(f->fd, asi_desktop_names[0], 0) == 0 && isd_write(f, 0, "x", 1) && isd_check(f, false);
}
static bool isd_tamper(struct isd_fixture *f)
{
    if (!isd_payload(f, 1) || !isd_wire(f, 8191u, 15u)) return false;
    for (unsigned i = 0; i < 4; ++i) {
        if (!isd_write(f, i, "y", 1) || isd_check(f, false) ||
            !isd_write(f, i, "x", 1) || !isd_check(f, false)) return false;
    }
    return isd_missing_link(f);
}
static bool isd_kit_wire(struct isd_fixture *f, unsigned desktop, unsigned kit)
{
    if (!isd_wire(f, 8191u, desktop)) return false;
    static const char *const names[] = {"app-toolchain.json", "app-toolchain.bundle"};
    for (unsigned i = 0; i < 2; ++i) {
        if (!(kit & (1u << i))) continue;
        size_t used = strlen(f->wire);
        int n = snprintf(f->wire + used, sizeof(f->wire) - used, "%s  %s\n", f->digest, names[i]);
        if (n <= 0 || (size_t)n >= sizeof(f->wire) - used) return false;
    }
    return true;
}
static bool isd_kit_shapes(struct isd_fixture *f)
{
    if (!isd_payload(f, 1) || !isd_write_name(f, "app-toolchain.json", "x", 1) ||
        !isd_write_name(f, "app-toolchain.bundle", "x", 1)) return false;
    for (unsigned mask = 1; mask < 3; ++mask)
        if (!isd_kit_wire(f, 15u, mask) || isd_check(f, false)) return false;
    if (!isd_kit_wire(f, 0, 3) || isd_check(f, false) ||
        !isd_kit_wire(f, 15u, 3) || !isd_check(f, false) || isd_check(f, true)) return false;
    return zcl_test_installed_toolchain_manifest(f->fd, f->wire, strlen(f->wire), false);
}
static bool isd_kit_members(struct isd_fixture *f)
{
    if (!isd_write_name(f, "app-toolchain.bundle", "y", 1) || !isd_check(f, false) ||
        zcl_test_installed_toolchain_manifest(f->fd, f->wire, strlen(f->wire), false) ||
        unlinkat(f->fd, "app-toolchain.bundle", 0) != 0 || !isd_check(f, false) ||
        zcl_test_installed_toolchain_manifest(f->fd, f->wire, strlen(f->wire), false) ||
        symlinkat("app-toolchain.json", f->fd, "app-toolchain.bundle") != 0 ||
        zcl_test_installed_toolchain_manifest(f->fd, f->wire, strlen(f->wire), false) ||
        unlinkat(f->fd, "app-toolchain.bundle", 0) != 0) return false;
    return true;
}
static bool isd_kit_bounds(struct isd_fixture *f)
{
    char bytes[4097]; memset(bytes, 'x', sizeof(bytes));
    for (size_t size = 4096; size <= sizeof(bytes); ++size) {
        if (!isd_payload(f, size) || !isd_write_name(f, "app-toolchain.json", bytes, size) ||
            !isd_write_name(f, "app-toolchain.bundle", bytes, size) ||
            !isd_kit_wire(f, 15u, 3) || !isd_check(f, false) ||
            zcl_test_installed_toolchain_manifest(f->fd, f->wire, strlen(f->wire), false) != (size == 4096)) return false;
    }
    return true;
}
static int isd_contract(struct ass_world *w)
{
    int failures = 0; struct isd_fixture f = {.fd = -1};
    TEST("installed source desktop set is exact, Linux-only, bounded and reverified") {
        ASSERT(asi_path(f.directory, sizeof(f.directory), w->root, "desktop-contract"));
        ASSERT(mkdir(f.directory, 0700) == 0);
        f.fd = open(f.directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        ASSERT(f.fd >= 0 && isd_payload(&f, 1));
        ASSERT(isd_shapes(&f));
        ASSERT(isd_bad_rows(&f));
        ASSERT(isd_tamper(&f));
        ASSERT(isd_payload(&f, 65536) && isd_wire(&f, 8191u, 15u) && isd_check(&f, false));
        ASSERT(isd_payload(&f, 65537) && isd_wire(&f, 8191u, 15u) && !isd_check(&f, false));
        ASSERT(isd_kit_shapes(&f));
        ASSERT(isd_kit_members(&f));
        ASSERT(isd_kit_bounds(&f));
        PASS();
    } _test_next:;
    if (f.fd >= 0 && close(f.fd) != 0) ++failures;
    return failures;
}
#endif

static bool asi_evidence(struct ass_world *w, struct asi_run *r)
{
    const char *dir = getenv("ZCL_TEST_INSTALLED_APP_EVIDENCE_DIR");
    if (!dir) return true;
    struct stat st;
    if (dir[0] != '/' || lstat(dir, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 022)) return false;
    static const char *const logs[] = {"installed-package.log", "installed-install.log",
        "installed-list.json", "installed-cancel.json", "installed-confirm.json", "installed-xvfb.log",
        "installed-driver.log", "installed-cli.stderr"};
    char from[ASS_PATH], to[PATH_MAX];
    for (size_t i = 0; i < sizeof(logs)/sizeof(logs[0]); ++i) {
        if (!asi_path(from, sizeof(from), w->root, logs[i]) ||
            !asi_path(to, sizeof(to), dir, logs[i]) || !asi_copy_public(from, to)) return false;
    }
    /* Retain the complete public release so a later fresh-recipient journey
     * can use this exact normal-packager output without producer state. */
    static const char *const assets[] = {"SHA256SUMS", "AGENT_CARD.md", "z23", "zclassic23",
        "z23-package-verify", "zclassic23-package-verify", "z23-acme", "zclassic23-acme",
        "z23-skycombat", "installed-source.json", "app-build.wire", "manifest.wire",
        "recipe.wire", "source.bundle"};
    for (size_t i = 0; i < sizeof(assets)/sizeof(assets[0]); ++i) {
        if (!asi_path(from, sizeof(from), r->release, assets[i]) ||
            !asi_path(to, sizeof(to), dir, assets[i]) || !asi_copy_public(from, to)) return false;
    }
    return asi_desktop_evidence(r, dir);
}
static bool asi_cleanup(struct ass_world *w, struct asi_run *r,
                         struct asi_env *saved, bool env_saved, bool cwd_changed)
{
    bool cli_stopped = asi_stop(&r->cli), display_stopped = asi_stop(&r->display);
    bool ok = cli_stopped && display_stopped;
    if (cwd_changed && chdir(w->source) != 0) ok = false;
    if (env_saved && !asi_environment_restore(saved)) ok = false;
    app_installed_source_free(&r->source);
    printf("  [installed acceptance cleanup=%d cli_pid=%llu display_pid=%llu root=%s]\n",
        ok, (unsigned long long)r->cli.pid, (unsigned long long)r->display.pid, w->root);
    return ok;
}
/* Fixture-only retirement of the single verified flat 13- or 17-member generation.
 * Never called after failed proof/export/process cleanup; no recursive chmod
 * and no following the mutable skycombat selector. */
static bool asi_cleanup_identity(int fd, const struct stat *before,
    dev_t device, bool private)
{
    struct stat now;
    if (fstat(fd, &now) != 0 || !S_ISDIR(now.st_mode) ||
        now.st_dev != before->st_dev || now.st_ino != before->st_ino) return false;
    if (private) return now.st_uid == geteuid() && now.st_dev == device;
    return now.st_uid == geteuid() || now.st_uid == 0;
}
static int asi_cleanup_child(int parent, const char *name, dev_t device, bool private)
{
    struct stat before;
    if (!name[0] || !strcmp(name, ".") || !strcmp(name, "..") || strchr(name, '/') ||
        fstatat(parent, name, &before, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISDIR(before.st_mode)) return -1;
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    if (!asi_cleanup_identity(fd, &before, device, private)) { close(fd); return -1; }
    return fd;
}
static int asi_cleanup_root(const char *root, dev_t *device)
{
    char path[ASS_PATH];
    if (root[0] != '/' || strlen(root) >= sizeof(path)) return -1;
    memcpy(path, root + 1, strlen(root));
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    char *at = path, *part;
    while ((part = strsep(&at, "/")) != NULL) {
        int child = asi_cleanup_child(fd, part, 0, false);
        if (close(fd) != 0) { if (child >= 0) close(child); return -1; }
        if (child < 0) return -1;
        fd = child;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_uid != geteuid() || (st.st_mode & 022)) {
        close(fd); return -1;
    }
    *device = st.st_dev;
    return fd;
}
static bool asi_unseal_fixture_generation(const struct ass_world *w, const struct asi_run *r)
{
    char pin[65]; dev_t device;
    if (!asi_manifest_pin(r, pin)) return false;
    /* Installer uses all64 SHA256 characters, not the truncated cleanup log. */
    const char *const parts[] = {"alice", ".local", "share", "z23", "apps", pin};
    int fd = asi_cleanup_root(w->root, &device);
    if (fd < 0) return false;
    for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); ++i) {
        int child = asi_cleanup_child(fd, parts[i], device, true);
        if (close(fd) != 0) { if (child >= 0) close(child); return false; }
        if (child < 0) return false;
        fd = child;
    }
    bool ok = fchmod(fd, 0700) == 0;
    if (close(fd) != 0) ok = false;
    printf("installed fixture generation unsealed=%d manifest=%s root=%s\n", ok, pin, w->root);
    return ok;
}
static int ass_installed(struct ass_world *w)
{
    if (!getenv("ZCL_TEST_INSTALLED_APP_BIN_DIR")) return 0;
    int failures = 0; struct asi_run r = {0}; struct asi_env saved;
    app_installed_source_init(&r.source); platform_process_init(&r.cli); platform_process_init(&r.display);
    bool env_saved = asi_environment_save(&saved), cwd_changed = false;
    TEST("normal release/install discovers SkyCombat and native consent creates an exact-source personal copy") {
        struct sigaction chld;
        ASSERT(env_saved && sigaction(SIGCHLD, NULL, &chld) == 0 && chld.sa_handler == SIG_DFL && !(chld.sa_flags & SA_NOCLDWAIT));
        ASSERT(asi_prerequisites(w, &r) && asi_paths(w, &r));
        ASSERT(asi_export(w, &r) && asi_original(w, &r));
        ASSERT(asi_package(w, &r) && asi_install(w, &r) && asi_desktop_installed(&r));
        ASSERT(asi_display(w, &r));
        ASSERT(chdir(r.empty) == 0); cwd_changed = true;
        ASSERT(asi_discovery(w, &r) && asi_no_consumer_state(&r));
        ASSERT(asi_terminal_copy(w, &r) && asi_no_consumer_state(&r));
        ASSERT(asi_cancel(w, &r) && asi_confirm(w, &r));
        ASSERT(asi_evidence(w, &r));
        PASS();
    } _test_next:;
    if (!asi_cleanup(w, &r, &saved, env_saved, cwd_changed)) ++failures;
    if (!failures && !asi_unseal_fixture_generation(w, &r)) {
        printf("installed fixture unseal refused; retained=%s\n", w->root);
        ++failures;
    }
    return failures;
}

static int ass_installed_preflight(struct ass_world *w)
{
    if (!getenv("ZCL_TEST_INSTALLED_APP_BIN_DIR")) return 0;
    int failures = 0;
    struct asi_run check = {0};
    TEST("installed opt-in requires qualified release tools, Xvfb and game headers") {
        ASSERT(asi_prerequisites(w, &check));
        PASS();
    } _test_next:;
    return failures;
}

static int ass_cleanup_success(const struct ass_world *w, int failures)
{
    if (!failures && test_rm_rf_recursive(w->root) != 0) {
        printf("app.seed skycombat: filesystem cleanup failed; retained=%s\n", w->root);
        ++failures;
    }
    return failures;
}

int test_app_seed_skycombat(void);
int test_app_seed_skycombat(void)
{
    int failures = 0;
    const char *xvfb = asf_xvfb_path();
    struct ass_world w;
    chain_params_select(CHAIN_MAIN);
    TEST("app.seed skycombat: a temporary HOME and datadir") {
        ASSERT(ass_world_init(&w));
        PASS();
    } _test_next:;
#if defined(ZCL_TESTING)
    if (!failures) failures += isd_contract(&w);
#endif
    if (!failures)
        failures += ass_installed_preflight(&w);
    if (!failures)
        failures += ass_seed(&w);
    /* The build needs no system -dev package: the seeded tree carries the
     * vendored X11/GL headers and XDL, so it builds on every Linux host. */
    if (!failures)
        failures += ass_adopt_build(&w);
    if (!failures && !xvfb)
        printf("app.seed skycombat: 120 QA frames... SKIP (no Xvfb on this "
               "host)\n");
    if (!failures && xvfb)
        failures += ass_runs_qa_frames(&w, xvfb);
    if (!failures)
        failures += ass_installed(&w);
    asf_xvfb_stop(&w.xvfb);
    ass_world_restore(&w);
    return ass_cleanup_success(&w, failures);
}

#else

int test_app_seed_skycombat(void);
int test_app_seed_skycombat(void)
{
    if (getenv("ZCL_TEST_INSTALLED_APP_BIN_DIR")) {
        printf("app_seed_skycombat... FAIL (installed acceptance requires Linux/Xvfb)\n");
        return 1;
    }
    printf("app_seed_skycombat... SKIP (Linux only: Xvfb)\n");
    return 0;
}

#endif
