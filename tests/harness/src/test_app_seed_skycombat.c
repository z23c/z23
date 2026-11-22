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
#include "command/app_installed_source_resolve.h"
#include "command/app_image.h"
#include "command/app_copy_build.h"
#include "command/app_toolchain.h"
#include "command/native_zcode_package_copy.h"
#include "base/hex.h"
#include "crypto/sha256.h"
#include "platform/process_lifecycle.h"
#include "platform/os_sandbox.h"
#include "platform/supervised_process.h"
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include "platform/time_compat.h"
#include "presentation/model_render.h"
#include "util/spawn.h"
#include "vcs/vcs_manifest.h"
#include "vcs/vcs.h"
#include "vcs/source_bundle.h"
#include "vcs/package_store.h"
#include "vcs/package_prepare.h"
#include "base/safe_alloc.h"
#include "sha3/sha3.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
extern char **environ;

struct asi_run {
    char bin[PATH_MAX], verifier[PATH_MAX], driver[PATH_MAX];
    char export_dir[ASS_PATH], release[ASS_PATH], home[ASS_PATH];
    char prefix[ASS_PATH], datadir[ASS_PATH], empty[ASS_PATH], tmp[ASS_PATH];
    char installed[ASS_PATH], pin[65];
    char kit[ASS_PATH], kit_digest[65], copy[ASS_PATH], version[65];
    struct app_installed_source source;
    struct platform_process cli, display;
    bool real_kit, offline, custody_live;
    uint8_t kit_env[32];
    uint8_t selected_package[32], selected_deps[32];
};
static bool asi_copy_public(const char *from, const char *to);
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
/* Optional installed-kit build qualification: set both
 * ZCL_TEST_INSTALLED_APP_KIT_DIR and ZCL_TEST_INSTALLED_APP_KIT_SHA3, alongside
 * the installed-app fixture inputs, and run the registered group with --no-cache. */
static bool asi_kit_optin(struct asi_run *r)
{
    const char *kit = getenv("ZCL_TEST_INSTALLED_APP_KIT_DIR");
    const char *pin = getenv("ZCL_TEST_INSTALLED_APP_KIT_SHA3");
    if (!!kit != !!pin || (kit && (!kit[0] || !pin[0]))) return false;
    r->real_kit = kit != NULL;
    return true;
}
static bool asi_prerequisites(struct ass_world *w, struct asi_run *r)
{
    const char *bins = getenv("ZCL_TEST_INSTALLED_APP_BIN_DIR");
    if (!asi_kit_optin(r)) return false;
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
/* The packager verifies these inert files; no fixture tool is executed. */
static bool asi_kit_tree(struct asi_run *r)
{
    static const char *const dirs[] = {"rootfs", "rootfs/bin", "rootfs/usr", "rootfs/usr/bin"};
    static const char *const files[] = {"rootfs/bin/sh", "rootfs/usr/bin/cc", "rootfs/usr/bin/make"};
    char path[ASS_PATH];
    if (mkdir(r->kit, 0700)) return false;
    for (size_t i = 0; i < sizeof(dirs)/sizeof(dirs[0]); ++i)
        if (!asi_path(path, sizeof(path), r->kit, dirs[i]) || mkdir(path, 0700)) return false;
    for (size_t i = 0; i < sizeof(files)/sizeof(files[0]); ++i)
        if (!asf_put(r->kit, files[i], "inert kit fixture\n") ||
            !asi_path(path, sizeof(path), r->kit, files[i]) || chmod(path, 0755)) return false;
    return true;
}
static bool asi_kit_write(const char *dir, const char *name, const void *bytes, size_t size)
{
    char path[ASS_PATH];
    if (!asi_path(path, sizeof(path), dir, name)) return false;
    FILE *f = fopen(path, "wbx");
    if (!f) return false;
    bool ok = fwrite(bytes, 1, size, f) == size;
    return fclose(f) == 0 && ok;
}
static bool asi_copy_kit_members(const char *source, const char *destination)
{
    static const char *const names[] = {APP_TOOLCHAIN_DESCRIPTOR, APP_TOOLCHAIN_BUNDLE};
    char from[PATH_MAX], to[ASS_PATH];
    for (size_t i = 0; i < sizeof(names)/sizeof(names[0]); ++i)
        if (!asi_path(from, sizeof(from), source, names[i]) || !asi_path(to, sizeof(to), destination, names[i]) ||
            !asi_copy_public(from, to)) return false;
    return true;
}
static bool asi_supplied_kit(struct ass_world *w, struct asi_run *r)
{
    const char *dir = getenv("ZCL_TEST_INSTALLED_APP_KIT_DIR");
    const char *pin = getenv("ZCL_TEST_INSTALLED_APP_KIT_SHA3");
    char canonical[PATH_MAX], why[256]; uint8_t digest[32];
    if (!dir || !pin || !realpath(dir, canonical) || strcmp(dir, canonical) || strlen(pin) != 64 ||
        !zcl_hex_decode_lower(pin, digest, sizeof(digest))) return false;
    struct app_toolchain kit = {0};
    bool ok = app_toolchain_artifact(&kit, canonical, pin, why, sizeof(why));
    app_toolchain_free(&kit);
    if (!ok || !asi_path(r->kit, sizeof(r->kit), w->root, "kit") || mkdir(r->kit, 0700)) return false;
    if (!asi_copy_kit_members(canonical, r->kit)) return false;
    ok = app_toolchain_artifact(&kit, r->kit, pin, why, sizeof(why));
    if (ok) memcpy(r->kit_env, kit.env, sizeof(r->kit_env));
    app_toolchain_free(&kit);
    if (ok) memcpy(r->kit_digest, pin, sizeof(r->kit_digest));
    return ok;
}
static bool asi_kit(struct ass_world *w, struct asi_run *r)
{
    if (r->real_kit) return asi_supplied_kit(w, r);
    uint8_t tree[32], digest[32], *wire = NULL; size_t length = 0;
    char root[65], hash[65], descriptor[1024];
    if (!asi_path(r->kit, sizeof(r->kit), w->root, "kit") || !asi_kit_tree(r)) return false;
    bool ok = vcs_tree_capture_path(r->kit, tree) == VCS_OK &&
        vcs_source_bundle_create(r->kit, tree, &wire, &length, NULL) == VCS_SOURCE_BUNDLE_OK;
    if (!ok) { free(wire); return false; }
    zcl_sha3_256(wire, length, digest); zcl_hex_encode(digest, 32, hash); zcl_hex_encode(tree, 32, root);
    int n = snprintf(descriptor, sizeof(descriptor),
        "{\"schema\":\"%s\",\"bundle_file\":\"%s\",\"bundle_sha3\":\"%s\","
        "\"tree_root\":\"%s\",\"target\":\"linux-x86_64-v3\",\"policy\":\"%s\"}",
        APP_TOOLCHAIN_SCHEMA, APP_TOOLCHAIN_BUNDLE, hash, root, APP_TOOLCHAIN_POLICY);
    ok = n > 0 && (size_t)n < sizeof(descriptor) &&
        asi_kit_write(r->kit, APP_TOOLCHAIN_BUNDLE, wire, length) &&
        asi_kit_write(r->kit, APP_TOOLCHAIN_DESCRIPTOR, descriptor, (size_t)n);
    free(wire);
    if (!ok) return false;
    zcl_sha3_256((const uint8_t *)descriptor, (size_t)n, digest);
    zcl_hex_encode(digest, 32, r->kit_digest); return true;
}
static bool asi_package(struct ass_world *w, struct asi_run *r)
{
    char script[PATH_MAX];
    if (!asi_path(script, sizeof(script), w->source, "platform/packaging/release/build_release.sh")) return false;
    const char *argv[] = {"/usr/bin/bash", script, "--bin", r->bin, "--out", r->release,
        "--platform", "linux-x86_64", "--app-source", r->export_dir,
        "--app-source-sha3", r->pin, "--app-verifier", r->verifier,
        "--app-toolchain", r->kit, "--app-toolchain-sha3", r->kit_digest, NULL};
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
static bool asi_share_hash(const char *path)
{
    FILE *f = fopen(path, "rb"); if (!f) return false;
    struct sha256_ctx h; sha256_init(&h); unsigned char buf[16384], digest[32];
    size_t n; while ((n = fread(buf, 1, sizeof(buf), f)) != 0) sha256_write(&h, buf, n);
    bool ok = feof(f) && !ferror(f); if (fclose(f) != 0) ok = false;
    sha256_finalize(&h, digest); char hex[65]; zcl_hex_encode(digest, 32, hex);
    return ok && !strcmp(hex, "6a714436ba1a66b98339cfeddbb68dbdf634fd4dea9d335db6fad663e1cb5cc9");
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

/* The sealed system trampoline execs the installed path so the runtime sees
 * its installed executable identity. Its subreaper owns all descendants. */
static int asi_supervised_image(void)
{
    const char *env_path = "/usr/bin/env";
    FILE *f = fopen(env_path, "rb"); if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long len = ftell(f);
    if (len <= 0 || len > (long)PLATFORM_SUPERVISED_IMAGE_MAX || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f); return -1;
    }
    uint8_t *bytes = malloc((size_t)len), hash[32];
    bool ok = bytes && fread(bytes, 1, (size_t)len, f) == (size_t)len && !ferror(f);
    if (fclose(f) != 0) ok = false;
    int image = -1;
    if (ok) {
        zcl_sha3_256(bytes, (size_t)len, hash);
        ok = platform_supervised_image_capture(bytes, (size_t)len, hash, &image) == PLATFORM_SUPERVISED_IMAGE_OK;
    }
    free(bytes); if (!ok) { dprintf(2, "offline supervisor image capture failed\n"); return -1; }
    return image;
}
static int asi_supervised_finish(struct platform_supervised_process *process, enum platform_supervised_state state);
static int asi_supervised_build(const char *const *argv)
{
    int image = asi_supervised_image(); if (image < 0) return 125;
    const char *args[32] = {"/usr/bin/env"}; size_t count = 0;

    while (argv[count] && count + 2 < sizeof(args)/sizeof(args[0])) { args[count + 1] = argv[count]; ++count; }
    if (argv[count]) { close(image); return 125; }
    size_t env_count = 0; while (environ[env_count]) ++env_count;
    const struct platform_supervised_fd_map maps[] = {{0, 0}, {1, 1}, {2, 2}};
    int64_t now = platform_time_monotonic_ms() * INT64_C(1000000);
    struct platform_supervised_spec spec = {.executable_fd = image, .argv = args,
        .env = (const char *const *)environ, .maps = maps, .map_count = 3,
        .launch_deadline_ns = now + INT64_C(10000000000), .cleanup_timeout_ms = 10000,
        .env_policy = PLATFORM_SUPERVISED_ENV_COMPLETE, .env_count = env_count};
    struct platform_supervised_process process; platform_supervised_init(&process);
    enum platform_supervised_state state = platform_supervised_start(&process, &spec);
    close(image);
    return asi_supervised_finish(&process, state);
}
static int asi_supervised_finish(struct platform_supervised_process *process, enum platform_supervised_state state)
{
    int64_t deadline = platform_time_monotonic_ms() + 280000;
    while (state == PLATFORM_SUPERVISED_RUNNING && platform_time_monotonic_ms() < deadline) {
        usleep(10000); state = platform_supervised_poll(process);
    }
    bool timed_out = state == PLATFORM_SUPERVISED_RUNNING || state == PLATFORM_SUPERVISED_INCOMPLETE;
    if (timed_out)
        state = platform_supervised_stop(process, (platform_time_monotonic_ms() + 10000) * INT64_C(1000000));
    /* An incomplete observation keeps this owner and its handle alive. The
     * caller may report its own deadline, but must not kill this owner. */
    while (process->supervisor_pid >= 0) {
        dprintf(2, "offline supervisor custody retained: state=%d supervisor=%lld\n",
            state, (long long)process->supervisor_pid);
        state = platform_supervised_stop(process,
            (platform_time_monotonic_ms() + 10000) * INT64_C(1000000));
    }

    dprintf(2, "offline supervisor: state=%d exit_observed=%d no_children=%d status=%d\n",
        state, process->observation.engine_exit_observed, process->observation.no_children,
        process->observation.engine_wait_status);
    return !timed_out && state == PLATFORM_SUPERVISED_CLEAN && process->observation.engine_exit_observed &&
        process->observation.no_children && WIFEXITED(process->observation.engine_wait_status) &&
        WEXITSTATUS(process->observation.engine_wait_status) == 0 ? 0 : 125;
}

/* The installed build parent and every descendant inherit the same denial. */
static _Noreturn void asi_offline_child(int out, int err, const char *const *argv);
static bool asi_offline_spawn(struct ass_world *w, struct asi_run *r,
                              const char *log, const char *const *argv)
{
    char path[ASS_PATH], errpath[ASS_PATH];
    if (!asi_path(path, sizeof(path), w->root, log) ||
        !asi_path(errpath, sizeof(errpath), w->root, "installed-cli.stderr")) return false;
    int out = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    int err = open(errpath, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (out < 0 || err < 0) { if (out >= 0) close(out); if (err >= 0) close(err); return false; }
    pid_t pid = fork();
    if (pid == 0) asi_offline_child(out, err, argv);
    close(out); close(err);
    if (pid < 0) return false;
    r->cli.pid = (uint64_t)pid; r->cli.native = (uintptr_t)pid; return true;
}

static _Noreturn void asi_offline_child(int out, int err, const char *const *argv)
{
    int in = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (setpgid(0, 0) || in < 0 || dup2(in, 0) < 0 || dup2(out, 1) < 0 || dup2(err, 2) < 0) _exit(120);
    long limit = sysconf(_SC_OPEN_MAX); if (limit < 0 || limit > 1048576) _exit(121);
    for (int fd = 3; fd < limit; ++fd) close(fd);
    const int denied[] = {

#ifdef SYS_pidfd_getfd
        SYS_pidfd_getfd,
#endif
#ifdef SYS_ptrace
        SYS_ptrace,
#endif
#ifdef SYS_process_vm_writev
        SYS_process_vm_writev,
#endif
        -1
    };
    const int absent[] = {SYS_socket,
#ifdef SYS_socketcall
        SYS_socketcall,
#endif
#ifdef SYS_io_uring_setup
        SYS_io_uring_setup,
#endif
    };
    if (!os_sandbox_no_new_privs() || !zcl_result_is_ok(os_sandbox_seccomp_deny_ext(
            denied, sizeof(denied)/sizeof(denied[0]), OS_SANDBOX_WX_OFF,
            absent, sizeof(absent)/sizeof(absent[0]), false))) {
        dprintf(2, "offline seccomp installation failed\n"); _exit(122);
    }
    errno = 0; int v4 = socket(AF_INET, SOCK_STREAM, 0), e4 = errno;
    errno = 0; int v6 = socket(AF_INET6, SOCK_STREAM, 0), e6 = errno;
    dprintf(2, "offline socket probes: ipv4=%d errno=%d ipv6=%d errno=%d\n", v4, e4, v6, e6);
    if (v4 != -1 || e4 != ENOSYS || v6 != -1 || e6 != ENOSYS) _exit(123);
    _exit(asi_supervised_build(argv));
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
    bool visible = asi_window_driver(w, r, r->offline ? "--title=Receive this app copy?" : "--title=Make my copy", "--expect-count=0") &&
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
static bool asi_confirm_launch(struct ass_world *w, struct asi_run *r)
{
    bool launched;
    if (r->offline) {
        const char *share = getenv("ZCL_TEST_INSTALLED_APP_ORIGINAL_SHARE");
        char file[ASS_PATH + 16], data[ASS_PATH + 16];
        int a = snprintf(file, sizeof(file), "--file=%s", share ? share : "");
        int b = snprintf(data, sizeof(data), "--datadir=%s", r->datadir);
        const char *argv[] = {r->installed, "app", "receive", "--json", file, data, "--preview=false", NULL};
        launched = share && share[0] == '/' && a > 0 && (size_t)a < sizeof(file) &&
            b > 0 && (size_t)b < sizeof(data) && asi_share_hash(share) &&
            asi_terminal_spawn(w, r, "installed-confirm.json", argv);
    } else launched = asi_cli_start(w, r, "adopt", "installed-confirm.json");
    return launched;
}
static bool asi_confirm_actions(struct ass_world *w, struct asi_run *r)
{
    const char *title = r->offline ? "--title=Receive this app copy?" : "--title=Make my copy";
    bool launched = asi_confirm_launch(w, r);
    if (!launched || !asi_window_driver(w, r, title, "--expect-count=1") || !asi_no_consumer_state(r)) return false;

    /* Unfocused -> Cancel -> Back -> Next. Owner refuses confirmation until
     * all pages visited. Repeat Next up to the maintained maximum; no copied
     * model/text or injected presenter, no per-page pixel/readability claim. */
    for (unsigned i = 0; i < 3; ++i) if (!asi_window_driver(w, r, title, "--key=tab")) return false;
    for (unsigned i = 1; i < ZCL_PRESENT_MODEL_PAGES_MAX; ++i)
        if (!asi_window_driver(w, r, title, "--key=enter") || !asi_no_consumer_state(r)) return false;
    if (!asi_window_driver(w, r, title, "--key=tab")) return false;
    int64_t started = platform_time_monotonic_ms();
    if (!asi_window_driver(w, r, title, "--key=enter")) return false;
    if (r->offline) return true;
    /* Adopt now offers the same explicit continuation as Receive. Close is
     * initially focused; do not request any build, preview, or Keep. */
    if (!asi_copy_ready(w, r, started)) {
        asi_confirm_diagnostic(w, r, started);
        return false;
    }
    if (!asi_window_driver(w, r, "--title=Your copy is ready", "--key=enter")) return false;
    return true;
}
static bool asi_receive_identity(const struct json_value *d)
{
    return !strcmp(asi_string(d, "stage"), "commit") &&
        !strcmp(asi_string(d, "package_root"), "01c23f95253ea5113c25d9b2f0026b53e1a0e5d4cfff15a186b58ef55cf98e0a") &&
        !strcmp(asi_string(d, "publisher_fingerprint"), "02f7291a387f374d10372fdec98443bac17388f418b9eb396c0e42e43f2019f28e") &&
        !strcmp(asi_string(d, "release_id"), "a37b750a00fbf982ac6083a3349486449c6dc69b502b7771616c7ada41582b8e") &&
        !strcmp(asi_string(d, "parent_release_root"), "10c5792d4375c21135be0608c87e90caf4e6455cd872eef11b893acf4efae6e8") &&
        strlen(asi_string(d, "version")) == 64 && asi_string(d, "trust_record")[0] &&
        !json_get_bool(json_get(d, "executed"));

}
static bool asi_confirm(struct ass_world *w, struct asi_run *r)
{
    if (!asi_confirm_actions(w, r)) return false;
    struct json_value reply; json_init(&reply);
    bool ok = asi_cli_finish(w, r, "installed-confirm.json", &reply);
    const struct json_value *d = json_get(&reply, "data");
    if (r->offline) {
        ok = ok && asi_receive_identity(d);
    } else ok = ok && asi_adopted_only(r, d) && asi_successor(r, d);
    ok = ok && asi_window_driver(w, r, r->offline ? "--title=Receive this app copy?" : "--title=Make my copy", "--expect-count=0") &&

        asi_window_driver(w, r, "--title=Your copy is ready", "--expect-count=0");
    if (ok) {
        const char *copy = asi_string(json_get(&reply, "data"), r->offline ? "destination" : "copy");
        int n = snprintf(r->copy, sizeof(r->copy), "%s", copy);
        const char *version = asi_string(json_get(&reply, "data"), "version");
        ok = n > 0 && (size_t)n < sizeof(r->copy) && strlen(version) == 64;
        if (ok) memcpy(r->version, version, sizeof(r->version));
    }
    json_free(&reply); return ok;
}
static bool asi_kit_refusal_valid(const char *path, uint32_t code, bool untrusted)
{
    struct json_value reply; json_init(&reply);
    bool ok = code != 0 && asi_json_file(path, &reply);
    const struct json_value *top_ok = json_get(&reply, "ok");
    const struct json_value *error = json_get(&reply, "error");
    const struct json_value *mutated = json_get(error, "mutated");
    ok = ok && top_ok && top_ok->type == JSON_BOOL && !json_get_bool(top_ok) &&
        !strcmp(asi_string(error, "code"), "ENV_UNAVAILABLE") &&
        !strcmp(asi_string(error, "evidence"), untrusted ?
            "Installed compiler kit refused: untrusted directory owner or mode" :
            "Installed compiler kit refused: layout, owner/mode, manifest, running image or member mismatch") &&
        !strcmp(asi_string(error, "message"), untrusted ?
            "Z23 could not verify the owner or permissions of the build tools folder. Check your Z23 installation, then try again." :
            "the selected compiler kit is unavailable") &&
        mutated && mutated->type == JSON_BOOL && !json_get_bool(mutated);
    json_free(&reply); return ok;
}
static bool asi_kit_refusal_reply(struct ass_world *w, struct asi_run *r, bool untrusted)
{
    char data[ASS_PATH+16], copy[ASS_PATH+16], version[80], path[ASS_PATH];
    const char *log = untrusted ? "kit-path-refusal.json" : "kit-refusal.json";
    int a = snprintf(data, sizeof(data), "--datadir=%s", r->datadir);
    int b = snprintf(copy, sizeof(copy), "--copy=%s", r->copy);
    if (a <= 0 || (size_t)a >= sizeof(data) || b <= 0 || (size_t)b >= sizeof(copy) ||
        !asi_path(path, sizeof(path), w->root, log)) return false;
    int v = snprintf(version, sizeof(version), "--version=%s", r->version);
    if (v <= 0 || (size_t)v >= sizeof(version)) return false;
    const char *argv[] = {r->installed, "app", "build", "--json", data, copy, version, NULL};
    if (!asi_terminal_spawn(w, r, log, argv)) return false;
    uint32_t code = 0;
    enum platform_process_wait_result state = platform_process_wait(&r->cli, 120000, &code);
    if (state != PLATFORM_PROCESS_WAIT_EXITED) { (void)asi_stop(&r->cli); return false; }
    platform_process_close(&r->cli);
    return asi_kit_refusal_valid(path, code, untrusted);
}
static bool asi_kit_refusal(struct ass_world *w, struct asi_run *r)
{
    char pin[65], dir[ASS_PATH], path[ASS_PATH]; struct stat st;
    if (!asi_manifest_pin(r, pin) ||
        snprintf(dir, sizeof(dir), "%s/share/z23/apps/%s", r->prefix, pin) >= (int)sizeof(dir) ||
        !asi_path(path, sizeof(path), dir, APP_TOOLCHAIN_DESCRIPTOR) || lstat(path, &st) ||
        !S_ISREG(st.st_mode) || chmod(path, st.st_mode | 022)) return false;
    bool ok = asi_kit_refusal_reply(w, r, false);
    bool restored = chmod(path, st.st_mode & 07777) == 0;
    if (!ok || !restored || lstat(r->prefix, &st) || !S_ISDIR(st.st_mode) || chmod(r->prefix, st.st_mode | 022)) return false;
    ok = asi_kit_refusal_reply(w, r, true);
    restored = chmod(r->prefix, st.st_mode & 07777) == 0;
    return ok && restored;
}

static bool asi_build_finish(struct asi_run *r, const char *path, struct json_value *reply)
{
    uint32_t code = 0;
    enum platform_process_wait_result state = platform_process_wait(&r->cli, r->offline ? 315000 : 300000, &code);
    bool timely = state == PLATFORM_PROCESS_WAIT_EXITED;
    while (r->offline && state != PLATFORM_PROCESS_WAIT_EXITED) {
        test_note("offline supervisor owner still holds custody: pid=%llu", (unsigned long long)r->cli.pid);
        state = platform_process_wait(&r->cli, 10000, &code);
    }
    if (state != PLATFORM_PROCESS_WAIT_EXITED) {
        if (r->offline) r->custody_live = true;
        else (void)asi_stop(&r->cli);
        return false;
    }
    platform_process_close(&r->cli);
    return timely && code == 0 && asi_json_file(path, reply) && asi_passed(reply);
}
static bool asi_build_call(struct ass_world *w, struct asi_run *r, const char *log,
                           const char *plan, struct json_value *reply)
{
    char data[ASS_PATH+16], copy[ASS_PATH+16], version[80], plan_arg[80], path[ASS_PATH];
    int a = snprintf(data, sizeof(data), "--datadir=%s", r->datadir);
    int b = snprintf(copy, sizeof(copy), "--copy=%s", r->copy);
    int c = snprintf(version, sizeof(version), "--version=%s", r->version);
    int d = snprintf(plan_arg, sizeof(plan_arg), "--plan_id=%s", plan ? plan : "");
    if (a <= 0 || (size_t)a >= sizeof(data) || b <= 0 || (size_t)b >= sizeof(copy) ||
        c <= 0 || (size_t)c >= sizeof(version) || d <= 0 || (size_t)d >= sizeof(plan_arg) ||
        !asi_path(path, sizeof(path), w->root, log)) return false;
    const char *argv[] = {r->installed, "app", "build", "--json", data, copy, version,
                          plan ? plan_arg : NULL, plan ? "--confirm=true" : NULL, NULL};
    if (!(r->offline ? asi_offline_spawn(w, r, log, argv) : asi_terminal_spawn(w, r, log, argv))) return false;
    return asi_build_finish(r, path, reply);
}

static bool asi_build_identity(const struct asi_run *r, const struct json_value *data,
                               const char *stage)
{
    char package[65], environment[65], dependency[65];
    zcl_hex_encode(r->selected_package, sizeof(r->selected_package), package);
    zcl_hex_encode(r->selected_deps, sizeof(r->selected_deps), dependency);
    zcl_hex_encode(r->kit_env, sizeof(r->kit_env), environment);
    const struct json_value *hit = json_get(data, "cache_hit");
    return !strcmp(asi_string(data, "stage"), stage) && !strcmp(asi_string(data, "copy"), r->copy) &&
        !strcmp(asi_string(data, "version"), r->version) && !strcmp(asi_string(data, "package_root"), package) &&
        !strcmp(asi_string(data, "dependency_root"), dependency) &&
        !strcmp(asi_string(data, "env_root"), environment) &&
        !strcmp(asi_string(data, "confinement"), "landlock") && hit && hit->type == JSON_BOOL && !json_get_bool(hit);
}

/* Re-derive the selected successor, whose personalized metadata changes its package root. */
static bool asi_selected_roots(struct ass_world *w, struct asi_run *r)
{
    char scratch[ASS_PATH];
    if (!asi_path(scratch, sizeof(scratch), w->root, "selected-source") || mkdir(scratch, 0700) != 0)
        return false;
    struct zcl_package_copy copy = {0};
    struct zcl_command_reply why; zcl_command_reply_init(&why, "zcl.app_build.test.v1");
    bool ok = zcl_package_copy_open_selected_as(r->copy, ZCL_PACKAGE_COPY_READ, &copy,
        &why, "app.build", r->version);
    if (ok) ok = vcs_tree_materialize_readonly_disposable(r->copy, copy.selected_tree, scratch,
        VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES, 0) == VCS_OK;
    if (ok) ok = app_copy_build_roots(r->datadir, scratch, &copy, r->selected_package, r->selected_deps, &why);
    zcl_package_copy_close(&copy); zcl_command_reply_free(&why);
    if (test_rm_rf_recursive(scratch) != 0) ok = false;
    return ok;
}

static bool asi_record_image_matches(const struct app_image_build *record, const char *path)
{
    struct app_image_build captured = {0};
    return app_image_capture(path, &captured).ok && record->image_volume == captured.image_volume &&
        record->image_low == captured.image_low && record->image_high == captured.image_high &&
        record->image_size == captured.image_size;
}
static bool asi_build_record(const struct asi_run *r, const struct json_value *data)
{
    static const char *const keys[] = {"package_root", "env_root", "dependency_root", "closure_root", "image_sha3", "record_id"};
    uint8_t values[6][32], id[32];
    for (size_t i = 0; i < sizeof(keys)/sizeof(keys[0]); ++i) {
        const char *hex = asi_string(data, keys[i]);
        if (strlen(hex) != 64 || !zcl_hex_decode_lower(hex, values[i], sizeof(values[i]))) return false;
    }
    char records[ASS_PATH];
    int n = snprintf(records, sizeof(records), "%s/app_build/records", r->datadir);
    struct app_image_build record = {0}; bool hit = false;
    return n > 0 && (size_t)n < sizeof(records) && !strcmp(asi_string(data, "record_store"), records) &&
        app_image_build_load(records, values[0], values[1], values[2], &record, &hit).ok && hit &&
        !memcmp(record.closure_root, values[3], 32) && !memcmp(record.image_sha3, values[4], 32) &&
        app_image_build_id(&record, id).ok && !memcmp(id, values[5], 32) &&
        asi_record_image_matches(&record, asi_string(data, "image_path"));
}

static bool asi_build_image(const struct asi_run *r, const struct json_value *data)
{
    const char *image = asi_string(data, "image_sha3"), *path = asi_string(data, "image_path");
    uint8_t expected[32], record[32]; char expected_path[ASS_PATH]; struct app_image_build captured = {0};
    int n = snprintf(expected_path, sizeof(expected_path), "%s/app_build/images/%s", r->datadir, image);
    return strlen(image) == 64 && zcl_hex_decode_lower(image, expected, sizeof(expected)) &&
        strlen(asi_string(data, "record_id")) == 64 &&
        zcl_hex_decode_lower(asi_string(data, "record_id"), record, sizeof(record)) &&
        n > 0 && (size_t)n < sizeof(expected_path) && !strcmp(path, expected_path) &&
        app_image_capture(path, &captured).ok && !memcmp(expected, captured.image_sha3, sizeof(expected));
}

static bool asi_build_consistent(const struct asi_run *r, const struct json_value *p, const struct json_value *b)
{
    const struct json_value *made = json_get(b, "make_ran"), *executed = json_get(b, "executed");
    const char *keys[] = {"plan_id", "package_root", "version", "closure_root", "env_root", "dependency_root"};
    for (size_t i = 0; i < sizeof(keys)/sizeof(keys[0]); ++i)
        if (!asi_string(p, keys[i])[0] || strcmp(asi_string(p, keys[i]), asi_string(b, keys[i]))) return false;
    return asi_build_identity(r, b, "commit") && made && made->type == JSON_BOOL && json_get_bool(made) &&
        executed && executed->type == JSON_BOOL && !json_get_bool(executed) &&
        asi_build_record(r, b) && asi_build_image(r, b);
}
static bool asi_real_build(struct ass_world *w, struct asi_run *r)
{
    struct json_value plan, built; json_init(&plan); json_init(&built);
    bool ok = asi_selected_roots(w, r) && asi_build_call(w, r, "kit-build-plan.json", NULL, &plan);
    const struct json_value *p = json_get(&plan, "data");
    const char *id = asi_string(p, "plan_id");
    ok = ok && asi_build_identity(r, p, "plan") && strlen(id) == 64 &&
        asi_build_call(w, r, "kit-build-commit.json", id, &built);
    const struct json_value *b = json_get(&built, "data");
    ok = ok && asi_build_consistent(r, p, b);
    if (r->offline) ok = ok && !strcmp(asi_string(b, "image_sha3"),
        "baf203b90f1f4149d93812ebee99695fec709aaacb5913e775fc52032f4ea0de");
    json_free(&plan); json_free(&built); return ok;
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
static bool asi_docs_installed(const struct asi_run *r)
{
    static const char *const names[] = {"docs.bundle", "docs.root"};
    char pin[65], generation[ASS_PATH], rel[100];
    if (!asi_manifest_pin(r, pin)) return false;
    int n = snprintf(rel, sizeof(rel), "share/z23/apps/%s", pin);
    if (n <= 0 || (size_t)n >= sizeof(rel) || !asi_path(generation, sizeof(generation), r->prefix, rel)) return false;
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        char from[ASS_PATH], to[ASS_PATH];
        if (!asi_path(from, sizeof(from), r->release, names[i]) ||
            !asi_path(to, sizeof(to), generation, names[i]) || !asi_desktop_same(from, to)) return false;
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
static bool isd_append_pair(struct isd_fixture *f, const char *const names[2], unsigned mask)
{
    for (unsigned i = 0; i < 2; ++i) {
        if (!(mask & (1u << i))) continue;
        size_t used = strlen(f->wire);
        int n = snprintf(f->wire + used, sizeof(f->wire) - used, "%s  %s\n", f->digest, names[i]);
        if (n <= 0 || (size_t)n >= sizeof(f->wire) - used) return false;
    }
    return true;
}

static bool isd_docs_pair(struct isd_fixture *f, unsigned mask, bool mac)
{
    static const char *const names[] = {"docs.bundle", "docs.root"};
    return isd_wire(f, 8191u, 0) && isd_append_pair(f, names, mask) &&
        isd_check(f, mac) == (mask == 0 || mask == 3);
}

static const char *const isd_tasks_names[] = {"tasks.z23share", "tasks-source.root"};
static bool isd_tasks_members(struct isd_fixture *f)
{
    const char *const *names = isd_tasks_names;
    if (!isd_write_name(f, names[0], "y", 1) || isd_check(f, false) ||
        unlinkat(f->fd, names[0], 0) != 0 || isd_check(f, false) ||
        symlinkat(names[1], f->fd, names[0]) != 0 || isd_check(f, false) ||
        unlinkat(f->fd, names[0], 0) != 0) return false;
    if (!isd_write_name(f, names[0], "x", 1) || !isd_check(f, false) ||
        !isd_write_name(f, names[1], "y", 1) || isd_check(f, false) ||
        !isd_write_name(f, names[1], "x", 1)) return false;
    return isd_check(f, false);
}


static bool isd_tasks_pair(struct isd_fixture *f)
{
    if (!isd_payload(f, 1) || !isd_write_name(f, isd_tasks_names[0], "x", 1) ||
        !isd_write_name(f, isd_tasks_names[1], "x", 1)) return false;
    for (unsigned mask = 0; mask < 4; ++mask)
        if (!isd_wire(f, 8191u, 15u) || !isd_append_pair(f, isd_tasks_names, mask) ||
            isd_check(f, false) != (mask == 0 || mask == 3)) return false;
    return isd_tasks_members(f);
}


static bool isd_docs_shapes(struct isd_fixture *f)
{
    unsigned char bytes[65]; memset(bytes, '1', 64); bytes[64] = '\n';
    struct sha256_ctx hash; uint8_t digest[32];
    sha256_init(&hash); sha256_write(&hash, bytes, sizeof(bytes)); sha256_finalize(&hash, digest);
    zcl_hex_encode(digest, sizeof(digest), f->digest);
    if (!isd_write_name(f, "docs.bundle", bytes, sizeof(bytes)) ||
        !isd_write_name(f, "docs.root", bytes, sizeof(bytes))) return false;
    for (unsigned mask = 0; mask < 4; ++mask)
        if (!isd_docs_pair(f, mask, false) || !isd_docs_pair(f, mask, true)) return false;
    if (!isd_wire(f, 8191u, 0)) return false;
    static const char *const names[] = {"docs.bundle", "docs.root"};
    if (!isd_append_pair(f, names, 3) || !isd_check(f, false)) return false;
    if (!isd_write_name(f, "docs.bundle", "corrupt", 7) || isd_check(f, false)) return false;
    return isd_write_name(f, "docs.bundle", bytes, sizeof(bytes)) && isd_check(f, false);
}
static bool isd_kit_wire(struct isd_fixture *f, unsigned desktop, unsigned kit)
{
    static const char *const names[] = {"app-toolchain.json", "app-toolchain.bundle"};
    return isd_wire(f, 8191u, desktop) && isd_append_pair(f, names, kit);
}
static bool isd_tasks_kit(struct isd_fixture *f)
{
    static const char *const names[] = {"tasks.z23share", "tasks-source.root"};
    if (!isd_payload(f, 1) || !isd_write_name(f, "app-toolchain.json", "x", 1) ||
        !isd_write_name(f, "app-toolchain.bundle", "x", 1) ||
        !isd_kit_wire(f, 15u, 3) || !isd_append_pair(f, names, 3) ||
        !zcl_test_installed_toolchain_manifest(f->fd, f->wire, strlen(f->wire), false)) return false;
    return isd_write_name(f, names[1], "y", 1) &&
        !zcl_test_installed_toolchain_manifest(f->fd, f->wire, strlen(f->wire), false);
}


static const char *const isd_mac_names[] = {"z23-app-macos", "Z23Apps-Info.plist"};
static bool isd_mac_append(struct isd_fixture *f, unsigned mask)
{
    return isd_append_pair(f, isd_mac_names, mask);
}
static bool isd_mac_shapes(struct isd_fixture *f)
{
    for (unsigned mask = 1; mask < 4; ++mask) {
        if (!isd_wire(f, 8191u, 0) || !isd_mac_append(f, mask) ||
            isd_check(f, false) || isd_check(f, true) != (mask == 3)) return false;
    }
    if (!isd_wire(f, 8191u, 15u) || !isd_mac_append(f, 3) ||
        isd_check(f, false) || isd_check(f, true)) return false;
    if (!isd_kit_wire(f, 0, 3) || !isd_mac_append(f, 3) ||
        isd_check(f, false) || isd_check(f, true)) return false;
    return isd_wire(f, 8191u, 0) && isd_mac_append(f, 3);
}
static bool isd_mac_member_refusals(struct isd_fixture *f, unsigned i)
{
    if (!isd_write_name(f, isd_mac_names[i], "y", 1) || isd_check(f, true) ||
        unlinkat(f->fd, isd_mac_names[i], 0) != 0 || isd_check(f, true) ||
        symlinkat(asi_desktop_names[0], f->fd, isd_mac_names[i]) != 0 ||
        isd_check(f, true) || unlinkat(f->fd, isd_mac_names[i], 0) != 0 ||
        !isd_write_name(f, isd_mac_names[i], "x", 1) || !isd_check(f, true)) return false;
    return true;
}
static bool isd_mac_members(struct isd_fixture *f)
{
    if (!isd_payload(f, 1)) return false;
    for (unsigned i = 0; i < 2; ++i)
        if (!isd_write_name(f, isd_mac_names[i], "x", 1)) return false;
    if (!isd_mac_shapes(f) || !isd_check(f, true)) return false;
    for (unsigned i = 0; i < 2; ++i)
        if (!isd_mac_member_refusals(f, i)) return false;
    return true;
}
static bool isd_mac_bounds(struct isd_fixture *f)
{
    for (size_t size = 65536; size <= 65537; ++size) {
        if (!isd_payload(f, size)) return false;
        char *bytes = malloc(size);
        if (!bytes) return false;
        memset(bytes, 'x', size);
        bool ok = isd_write_name(f, isd_mac_names[0], bytes, size) &&
            isd_write_name(f, isd_mac_names[1], bytes, size);
        free(bytes);
        if (!ok || !isd_wire(f, 8191u, 0) || !isd_mac_append(f, 3) ||
            isd_check(f, true) != (size == 65536)) return false;
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
bool zcl_test_installed_untrusted_directory(int fd);
static bool isd_owner_check(int fd)
{
    struct stat st;
    if (fstat(fd, &st) || zcl_test_installed_untrusted_directory(fd) || fchmod(fd, st.st_mode | 022)) return false;
    bool refused = zcl_test_installed_untrusted_directory(fd);
    bool restored = fchmod(fd, st.st_mode & 07777) == 0;
    return refused && restored && !zcl_test_installed_untrusted_directory(-1);
}
static int isd_contract(struct ass_world *w)
{
    int failures = 0; struct isd_fixture f = {.fd = -1};
    TEST("installed source desktop set is exact, Linux-only, bounded and reverified") {
        ASSERT(asi_path(f.directory, sizeof(f.directory), w->root, "desktop-contract"));
        ASSERT(mkdir(f.directory, 0700) == 0);
        f.fd = open(f.directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        ASSERT(f.fd >= 0 && isd_owner_check(f.fd) && isd_payload(&f, 1));
        ASSERT(isd_shapes(&f));
        ASSERT(isd_bad_rows(&f));
        ASSERT(isd_tamper(&f));
        ASSERT(isd_payload(&f, 65536) && isd_wire(&f, 8191u, 15u) && isd_check(&f, false));
        ASSERT(isd_payload(&f, 65537) && isd_wire(&f, 8191u, 15u) && !isd_check(&f, false));
        ASSERT(isd_kit_shapes(&f));
        ASSERT(isd_kit_members(&f));
        ASSERT(isd_kit_bounds(&f));
        ASSERT(isd_mac_members(&f));
        ASSERT(isd_mac_bounds(&f));
        ASSERT(isd_docs_shapes(&f));
        ASSERT(isd_tasks_pair(&f));
        ASSERT(isd_tasks_kit(&f));
        PASS();
    } _test_next:;
    if (f.fd >= 0 && close(f.fd) != 0) ++failures;
    return failures;
}
#endif

/* Evidence belongs to this run; never mix it with prior release artifacts. */
static bool asi_evidence_empty(const char *path)
{
    DIR *dir = opendir(path); if (!dir) return false;
    bool empty = true; struct dirent *entry;
    errno = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) { empty = false; break; }
    }
    if (errno != 0) empty = false;
    if (closedir(dir) != 0) empty = false;
    return empty;
}

static bool asi_evidence_copy(struct ass_world *w, const char *dir, const char *const *names, size_t count)
{
    char from[ASS_PATH], to[PATH_MAX];
    for (size_t i = 0; i < count; ++i)
        if (!asi_path(from, sizeof(from), w->root, names[i]) ||
            !asi_path(to, sizeof(to), dir, names[i]) || !asi_copy_public(from, to)) return false;
    return true;
}
static bool asi_evidence(struct ass_world *w, const struct asi_run *r)
{
    const char *dir = getenv("ZCL_TEST_INSTALLED_APP_EVIDENCE_DIR");
    if (!dir) return true;
    struct stat st;
    if (dir[0] != '/' || lstat(dir, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 022)) return false;
    if (!asi_evidence_empty(dir)) {
        test_note("installed evidence directory must be empty: %s", dir);
        return false;
    }
    if (r->offline) {
        static const char *const logs[] = {"installed-install.log",
            "installed-list.json", "installed-confirm.json", "installed-xvfb.log",
            "installed-driver.log", "installed-cli.stderr", "kit-build-plan.json", "kit-build-commit.json"};
        return asi_evidence_copy(w, dir, logs, sizeof(logs)/sizeof(logs[0]));
    }
    static const char *const logs[] = {"installed-package.log", "installed-install.log",

        "installed-list.json", "installed-cancel.json", "installed-confirm.json", "installed-xvfb.log",
        "installed-driver.log", "installed-cli.stderr", "kit-refusal.json", "kit-path-refusal.json"};
    if (!asi_evidence_copy(w, dir, logs, sizeof(logs)/sizeof(logs[0]))) return false;
    if (r->real_kit) {
        static const char *const build[] = {"kit-build-plan.json", "kit-build-commit.json"};
        if (!asi_evidence_copy(w, dir, build, sizeof(build)/sizeof(build[0]))) return false;
    }
    return true;
}
static bool asi_cleanup(struct ass_world *w, struct asi_run *r,
                         struct asi_env *saved, bool env_saved, bool cwd_changed)
{
    bool cli_stopped = !r->custody_live && asi_stop(&r->cli), display_stopped = asi_stop(&r->display);
    bool ok = cli_stopped && display_stopped;
    if (cwd_changed && chdir(w->source) != 0) ok = false;
    if (env_saved && !asi_environment_restore(saved)) ok = false;
    app_installed_source_free(&r->source);
    printf("  [installed acceptance cleanup=%d cli_pid=%llu display_pid=%llu root=%s]\n",
        ok, (unsigned long long)r->cli.pid, (unsigned long long)r->display.pid, w->root);
    return ok;
}
/* Fixture-only retirement of the single verified kit-bearing generation.
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
static bool asi_prepare_installed(struct ass_world *w, struct asi_run *r)
{
    return asi_export(w, r) && asi_original(w, r) && asi_kit(w, r) &&
        asi_package(w, r) && asi_install(w, r) && asi_desktop_installed(r) && asi_docs_installed(r);
}

/* ── installed Tasks source: a staged generation resolves as the only source ──
 *
 * The SOURCE_UNKNOWN scenario: a fresh install has no checkout in the working
 * directory, so `app copy tasks` must resolve its source from the staged
 * installed generation (share/z23/apps/<hash>/ plus bin/z23-tasks) through
 * app_installed_source_resolve. This fixture stages that generation by hand —
 * real ztasks package bytes, a real captured ZVCS tree and source bundle, the
 * real manifest/recipe wires, a fabricated-but-bound build record and image —
 * then runs the actual installed node from an empty working directory. It is
 * the skycombat staging+resolve+verify pattern applied to tasks. */

#define ATS_TASKS_DIR "contexts/commons/packages/ztasks"
#define ATS_NODE "build/bin/z23"
static const char *const ats_files[] = {
    "LICENSE", "README.md", "app/main.c", "include/ztasks/ztasks.h",
    "src/ztasks.c", "tests/test_ztasks.c", "zcode-package.json"
};
/* The 13 base manifest rows of a tasks source release, in resolver enum order. */
static const char *const ats_rows[] = {
    "AGENT_CARD.md", "app-build.wire", "installed-source.json",
    "manifest.wire", "recipe.wire", "source.bundle", "z23", "z23-acme",
    "z23-package-verify", "z23-tasks", "zclassic23", "zclassic23-acme",
    "zclassic23-package-verify"
};
#define ATS_ROW_COUNT (sizeof(ats_rows) / sizeof(ats_rows[0]))

static bool ats_write(const char *path, const void *bytes, size_t len, mode_t mode)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool ok = (len == 0 || fwrite(bytes, 1, len, f) == len) && fclose(f) == 0 &&
        chmod(path, mode) == 0;
    if (!ok) (void)unlink(path);
    return ok;
}
static bool ats_copy_file(const char *from, const char *to, mode_t mode)
{
    FILE *in = fopen(from, "rb"), *out = to && in ? fopen(to, "wb") : NULL;
    bool ok = in && out;
    while (ok) {
        char block[65536];
        size_t n = fread(block, 1, sizeof(block), in);
        if (n == 0) break;
        ok = fwrite(block, 1, n, out) == n;
    }
    if (in) ok = feof(in) && !ferror(in) && fclose(in) == 0 && ok;
    if (out) ok = fclose(out) == 0 && chmod(to, mode) == 0 && ok;
    if (!ok && to) (void)unlink(to);
    return ok;
}
static bool ats_slurp(const char *path, char *buf, size_t cap, size_t *len)
{
    *len = 0;
    FILE *f = path ? fopen(path, "rb") : NULL;
    if (!f) return false;
    *len = fread(buf, 1, cap, f);
    bool ok = ferror(f) == 0 && feof(f) && fclose(f) == 0;
    return ok;
}
static bool ats_sha256_bytes(const void *bytes, size_t len, char hex[65])
{
    struct sha256_ctx h; uint8_t d[32];
    sha256_init(&h); sha256_write(&h, bytes, len); sha256_finalize(&h, d);
    zcl_hex_encode(d, sizeof(d), hex);
    return true;
}
static bool ats_sha256_file(const char *path, char hex[65])
{
    FILE *f = path ? fopen(path, "rb") : NULL;
    if (!f) return false;
    struct sha256_ctx h; uint8_t d[32]; char block[65536]; size_t n;
    sha256_init(&h);
    while ((n = fread(block, 1, sizeof(block), f)) != 0)
        sha256_write(&h, (const uint8_t *)block, n);
    bool ok = feof(f) && !ferror(f) && fclose(f) == 0;
    sha256_finalize(&h, d);
    zcl_hex_encode(d, sizeof(d), hex);
    return ok;
}
static void ats_sha3_hex(const void *bytes, size_t len, char hex[65])
{
    uint8_t d[32];
    zcl_sha3_256(bytes, len, d);
    zcl_hex_encode(d, sizeof(d), hex);
}
static bool ats_mkdir_p(const char *base, const char *rel)
{
    char path[ASS_PATH];
    if (!asi_path(path, sizeof(path), base, rel)) return false;
    for (char *at = path + strlen(base) + 1; *at; at++)
        if (*at == '/') {
            *at = 0;
            if (mkdir(path, 0700) != 0 && errno != EEXIST) return false;
            *at = '/';
        }
    return mkdir(path, 0700) == 0 || errno == EEXIST;
}

struct ats_stage {
    const struct ass_world *w;
    char base[ASS_PATH];
    char node[ASS_PATH], prefix[ASS_PATH], gen[ASS_PATH];
    char home[ASS_PATH], datadir[ASS_PATH], empty[ASS_PATH], src[ASS_PATH];
    struct vcs_package_prepared prepared;
    uint8_t record_wire[APP_IMAGE_BUILD_WIRE_BYTES];
    uint8_t *bundle;
    char *projection, *image;
    size_t bundle_len, projection_len, image_len;
    char tree_hex[65], package_hex[65], recipe_root_hex[65], record_id_hex[65];
    char image_hex[65], bundle_hex[65], manifest_hex[65], recipe_hex[65];
    char record_hex[65], node_hex[65];
};
static void ats_stage_free(struct ats_stage *s)
{
    vcs_package_prepared_free(&s->prepared);
    free(s->bundle); free(s->projection); free(s->image);
    memset(s, 0, sizeof(*s));
}
/* Copy the shipped ztasks package into a private source dir. The staging
 * base is the caller-owned directory (see ass_tasks_installed: it must sit
 * under trusted ancestors, so never a group/other-writable temp root). */
static bool ats_prepare_source(struct ats_stage *s)
{
    if (!asi_path(s->src, sizeof(s->src), s->base, "tasks-src") ||
        mkdir(s->src, 0700) != 0)
        return false;
    for (size_t i = 0; i < sizeof(ats_files) / sizeof(ats_files[0]); ++i) {
        char from[ASS_PATH], rel[128], to[ASS_PATH];
        if (!asi_path(from, sizeof(from), s->w->source, ATS_TASKS_DIR) ||
            (int)snprintf(rel, sizeof(rel), "%s/%s", ATS_TASKS_DIR,
                          ats_files[i]) >= (int)sizeof(rel) ||
            !asi_path(from, sizeof(from), s->w->source, rel) ||
            !asi_path(to, sizeof(to), s->src, ats_files[i]))
            return false;
        char *slash = strrchr(to, '/');
        if (!slash) return false;
        *slash = 0;
        if (!ats_mkdir_p(s->base, to + strlen(s->base) + 1)) return false;
        *slash = '/';
        char body[65536]; size_t n = 0;
        if (!ats_slurp(from, body, sizeof(body), &n) ||
            !ats_write(to, body, n, 0600))
            return false;
    }
    return true;
}
/* Real retained wires from the real ztasks bytes: a captured ZVCS tree, the
 * transport bundle over it, and the package manifest/recipe wires. */
static bool ats_source(struct ats_stage *s)
{
    struct vcs_source_bundle_metrics metrics;
    uint8_t tree[32]; char detail[256] = "";
    if (!ats_prepare_source(s)) {
        printf("  [tasks fixture: package copy failed]\n");
        return false;
    }
    if (vcs_tree_capture_path(s->src, tree) != VCS_OK) {
        printf("  [tasks fixture: ZVCS capture failed]\n");
        return false;
    }
    if (vcs_source_bundle_create(s->src, tree, &s->bundle, &s->bundle_len,
                                 &metrics) != VCS_SOURCE_BUNDLE_OK) {
        printf("  [tasks fixture: source bundle create failed]\n");
        return false;
    }
    if (vcs_package_prepare_content(s->src, &s->prepared, detail,
                                    sizeof(detail)) != VCS_PACKAGE_PREPARE_OK) {
        printf("  [tasks fixture: package prepare failed: %s]\n", detail);
        return false;
    }
    zcl_hex_encode(tree, sizeof(tree), s->tree_hex);
    zcl_hex_encode(s->prepared.package_root, 32, s->package_hex);
    zcl_hex_encode(s->prepared.recipe_root, 32, s->recipe_root_hex);
    ats_sha3_hex(s->bundle, s->bundle_len, s->bundle_hex);
    ats_sha3_hex(s->prepared.manifest_wire, s->prepared.manifest_wire_len,
                 s->manifest_hex);
    ats_sha3_hex(s->prepared.recipe_wire, s->prepared.recipe_wire_len,
                 s->recipe_hex);
    return true;
}
/* A build record bound to the staged package root and the image bytes. */
static bool ats_record(struct ats_stage *s)
{
    static const uint8_t root[32] = {1};
    struct app_image_build rec;
    uint8_t digest[32], record_id[32];
    s->image_len = 8192;
    s->image = zcl_malloc(s->image_len, "ats.tasks.image");
    if (!s->image) return false;
    for (size_t i = 0; i < s->image_len; ++i)
        s->image[i] = (uint8_t)(i * 7 + 3);
    zcl_sha3_256((const unsigned char *)s->image, s->image_len, digest);
    zcl_hex_encode(digest, sizeof(digest), s->image_hex);
    memset(&rec, 0, sizeof(rec));
    memcpy(rec.package_root, s->prepared.package_root, 32);
    memcpy(rec.closure_root, root, 32);
    memcpy(rec.env_root, root, 32);
    memcpy(rec.dependency_root, root, 32);
    memcpy(rec.image_sha3, digest, 32);
    rec.image_volume = 1;
    rec.image_size = (uint64_t)s->image_len;
    bool ok = app_image_build_encode(&rec, s->record_wire).ok &&
        app_image_build_id(&rec, record_id).ok;
    ats_sha3_hex(s->record_wire, sizeof(s->record_wire), s->record_hex);
    zcl_hex_encode(record_id, sizeof(record_id), s->record_id_hex);
    return ok;
}
/* The canonical installed-source projection, written by the JSON writer so
 * the loader's canonical round-trip check holds by construction. */
static bool ats_projection(struct ats_stage *s)
{
    static const struct { const char *key; } keys[] = {
        {"schema"}, {"app"}, {"bundle_file"}, {"bundle_sha3"}, {"tree_root"},
        {"manifest_file"}, {"manifest_sha3"}, {"package_root"},
        {"recipe_file"}, {"recipe_sha3"}, {"recipe_root"}, {"record_file"},
        {"record_sha3"}, {"record_id"}, {"image_sha3"}
    };
    const char *values[] = {
        APP_INSTALLED_SOURCE_SCHEMA, "tasks", APP_INSTALLED_SOURCE_BUNDLE,
        s->bundle_hex, s->tree_hex, APP_INSTALLED_SOURCE_MANIFEST,
        s->manifest_hex, s->package_hex, APP_INSTALLED_SOURCE_RECIPE,
        s->recipe_hex, s->recipe_root_hex, APP_INSTALLED_SOURCE_RECORD,
        s->record_hex, s->record_id_hex, s->image_hex
    };
    struct json_value doc; json_init(&doc); json_set_object(&doc);
    bool ok = true;
    for (size_t i = 0; ok && i < sizeof(keys) / sizeof(keys[0]); ++i)
        ok = json_push_kv_str(&doc, keys[i].key, values[i]);
    if (ok) {
        s->projection_len = json_write(&doc, s->projection,
                                       APP_INSTALLED_SOURCE_PROJECTION_MAX);
        ok = s->projection_len > 0 &&
            s->projection_len < APP_INSTALLED_SOURCE_PROJECTION_MAX;
    }
    json_free(&doc);
    return ok;
}
/* Member bytes for manifest row `row`; the node row (z23) is a file digest. */
static const char *ats_inert_tag(int row)
{
    if (row == 11) return ats_rows[7];
    if (row == 12) return ats_rows[8];
    return ats_rows[row];
}
static bool ats_row_bytes(const struct ats_stage *s, int row,
                          const void **bytes, size_t *len)
{
    static char inert[256];
    *bytes = NULL; *len = 0;
    switch (row) {
    case 1: *bytes = s->record_wire; *len = sizeof(s->record_wire); return true;
    case 2: *bytes = s->projection; *len = s->projection_len; return true;
    case 3: *bytes = s->prepared.manifest_wire; *len = s->prepared.manifest_wire_len; return true;
    case 4: *bytes = s->prepared.recipe_wire; *len = s->prepared.recipe_wire_len; return true;
    case 5: *bytes = s->bundle; *len = s->bundle_len; return true;
    case 9: *bytes = s->image; *len = s->image_len; return true;
    case 0: case 7: case 8: case 11: case 12: break;
    default: return false;
    }
    /* The zclassic23 rows are the z23 rows under legacy names: one digest,
     * identical bytes (the resolver refuses a differing alias pair). */
    const char *tag = ats_inert_tag(row);
    int n = snprintf(inert, sizeof(inert), "inert installed %s row: tasks fixture\n",
                     tag);
    if (n <= 0 || n >= (int)sizeof(inert)) return false;
    *bytes = inert; *len = (size_t)n;
    return true;
}
static bool ats_row_file(const struct ats_stage *s, int row)
{
    char path[ASS_PATH];
    if (!asi_path(path, sizeof(path), s->gen, ats_rows[row])) return false;
    if (row == 6 || row == 10) return ats_copy_file(s->node, path, 0555);
    const void *bytes; size_t len;
    return ats_row_bytes(s, row, &bytes, &len) &&
        ats_write(path, bytes, len, 0444);
}
static bool ats_sums(const struct ats_stage *s, char *sums, size_t cap, char id_hex[65])
{
    size_t at = 0;
    for (int row = 0; row < (int)ATS_ROW_COUNT; ++row) {
        char hex[65]; bool ok;
        if (row == 6 || row == 10) ok = ats_sha256_file(s->node, hex);
        else {
            const void *bytes; size_t len;
            ok = ats_row_bytes(s, row, &bytes, &len) &&
                ats_sha256_bytes(bytes, len, hex);
        }
        if (!ok) return false;
        int n = snprintf(sums + at, cap - at, "%s  %s\n", hex, ats_rows[row]);
        if (n <= 0 || (size_t)n >= cap - at) return false;
        at += (size_t)n;
    }
    return ats_sha256_bytes(sums, at, id_hex);
}
static bool ats_fill_generation(struct ats_stage *s, const char *sums)
{
    for (int row = 0; row < (int)ATS_ROW_COUNT; ++row)
        if (!ats_row_file(s, row)) return false;
    char sums_path[ASS_PATH];
    return asi_path(sums_path, sizeof(sums_path), s->gen, "SHA256SUMS") &&
        ats_write(sums_path, sums, strlen(sums), 0444);
}
/* The trusted install prefix: directories, per-app bin link and selector. */
static bool ats_prefix_dirs(struct ats_stage *s)
{
    int n = snprintf(s->prefix, sizeof(s->prefix), "%s/tasks-prefix", s->base);
    return n > 0 && (size_t)n < sizeof(s->prefix) &&
        asi_path(s->home, sizeof(s->home), s->base, "tasks-home") &&
        asi_path(s->datadir, sizeof(s->datadir), s->base, "tasks-data") &&
        asi_path(s->empty, sizeof(s->empty), s->base, "tasks-empty") &&
        ats_mkdir_p(s->base, "tasks-prefix/bin") &&
        ats_mkdir_p(s->base, "tasks-prefix/share/z23/apps") &&
        ats_mkdir_p(s->base, "tasks-home") &&
        ats_mkdir_p(s->base, "tasks-data") &&
        ats_mkdir_p(s->base, "tasks-empty");
}
static bool ats_generation_dir(struct ats_stage *s, char *sums, size_t cap,
                               char *id_hex, char *apps, size_t apps_cap)
{
    if (!ats_sums(s, sums, cap, id_hex) ||
        !asi_path(apps, apps_cap, s->prefix, "share/z23/apps") ||
        (int)snprintf(s->gen, sizeof(s->gen), "%s/%s", apps, id_hex) >=
            (int)sizeof(s->gen) || mkdir(s->gen, 0700) != 0)
        return false;
    return ats_fill_generation(s, sums) && chmod(s->gen, 0555) == 0;
}
static bool ats_links(struct ats_stage *s, const char *id_hex, const char *apps)
{
    char bin[ASS_PATH], leaf[ASS_PATH];
    return asi_path(bin, sizeof(bin), s->prefix, "bin/z23") &&
        ats_copy_file(s->node, bin, 0555) &&
        asi_path(leaf, sizeof(leaf), s->prefix, "bin/z23-tasks") &&
        symlink("../share/z23/apps/tasks/z23-tasks", leaf) == 0 &&
        asi_path(leaf, sizeof(leaf), apps, "tasks") &&
        symlink(id_hex, leaf) == 0;
}
/* Stage prefix, generation and per-app links; returns the generation dir. */
static bool ats_stage_all(struct ats_stage *s)
{
    char sums[16384], id_hex[65], apps[ASS_PATH];
    bool ok = asi_path(s->node, sizeof(s->node), s->w->source, ATS_NODE) &&
        access(s->node, X_OK) == 0 && ats_prefix_dirs(s) &&
        ats_source(s) && ats_record(s);
    s->projection = zcl_malloc(APP_INSTALLED_SOURCE_PROJECTION_MAX,
                               "ats.tasks.projection");
    ok = ok && s->projection && ats_projection(s) &&
        ats_generation_dir(s, sums, sizeof(sums), id_hex, apps, sizeof(apps));
    return ok && ats_links(s, id_hex, apps);
}
/* One installed-node run of `app copy tasks` from an empty working dir. */
static int ats_run_copy(const struct ats_stage *s, char *out, size_t cap,
                        bool *timed_out)
{
    char data[ASS_PATH + 64], self[ASS_PATH];
    int n = snprintf(data, sizeof(data), "--datadir=%s", s->datadir);
    if (n <= 0 || (size_t)n >= sizeof(data) ||
        !asi_path(self, sizeof(self), s->prefix, "bin/z23"))
        return -1;
    const char *const argv[] = {self, "app", "copy", "--json", "--app=tasks",
                                data, NULL};
    return zcl_spawn_capture_in_dir_observed(argv, s->empty, out, cap,
                                             180000, timed_out);
}
static int ats_copy_with_home(const struct ats_stage *s, char *out, size_t cap,
                              bool *timed_out)
{
    char saved_home[1024];
    const char *home = getenv("HOME");
    (void)snprintf(saved_home, sizeof(saved_home), "%s", home ? home : "");
    if (setenv("HOME", s->home, 1) != 0) return -1;
    int rc = ats_run_copy(s, out, cap, timed_out);
    if (saved_home[0]) (void)setenv("HOME", saved_home, 1);
    else (void)unsetenv("HOME");
    return rc;
}
/* One node run from an empty cwd must come back `ok` with the installed-
 * source plan: the generation, not the checkout, resolved the source. */
static bool ats_resolves_installed(const struct ats_stage *s)
{
    char out[65536];
    bool timed = false;
    int rc = ats_copy_with_home(s, out, sizeof(out), &timed);
    if (rc != 0 || timed)
        printf("  [tasks fixture copy child rc=%d timed=%d stdout: %s]\n",
               rc, timed, out);
    if (rc != 0 || timed) return false;
    struct json_value reply; json_init(&reply);
    bool ok = json_read(&reply, out, strlen(out)) &&
        json_get_bool(json_get(&reply, "ok"));
    const struct json_value *data = ok ? json_get(&reply, "data") : NULL;
    ok = ok && data != NULL &&
        !strcmp(json_get_str(json_get(data, "stage")), "plan") &&
        !strcmp(json_get_str(json_get(data, "source")),
                "verified installed app") &&
        !strcmp(json_get_str(json_get(data, "app")), "tasks");
    json_free(&reply);
    return ok;
}
/* Flip one image byte: the same run must now refuse, end to end. */
static bool ats_tamper_refuses(const struct ats_stage *s)
{
    char path[ASS_PATH], body[8192 + 1u], out[65536];
    size_t n = 0;
    bool timed = false;
    if (!asi_path(path, sizeof(path), s->gen, "z23-tasks") ||
        !ats_slurp(path, body, sizeof(body), &n) || n != s->image_len)
        return false;
    body[0] ^= 0xff;
    if (chmod(path, 0600) != 0 || !ats_write(path, body, n, 0444))
        return false;
    int rc = ats_copy_with_home(s, out, sizeof(out), &timed);
    return rc != 0 && !timed;
}
/* The staging base must sit under trusted ancestors (the resolver refuses
 * group/other-writable parents), and the runner relocates HOME into its
 * scratch; the owner's passwd home is the one path that carries the trusted
 * ancestors a real install would resolve through. */
static bool ats_stage_root(char *root, size_t cap)
{
    const char *home = getenv("HOME");
    struct stat st;
    errno = 0;
    struct passwd *pw = getpwuid(geteuid());
    if (pw && pw->pw_dir && pw->pw_dir[0] == '/') home = pw->pw_dir;
    if (!home || home[0] != '/' || lstat(home, &st) != 0 ||
        !S_ISDIR(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 022))
        return false;
    int n = snprintf(root, cap, "%s/.z23-tasks-XXXXXX", home);
    return n > 0 && (size_t)n < cap && mkdtemp(root) != NULL;
}
/* The fixture-level proof: one staged tasks generation, the real node, an
 * empty working directory. Skips loudly when this host has no node binary,
 * or when no trusted-ancestor staging root exists: the resolver refuses
 * group/other-writable parents, and the runner scratch under /dev/shm (and
 * this repo lane under a group-writable development directory) never
 * qualifies. The owner's HOME does, on exactly the hosts where a real
 * install would also resolve. */
static int ass_tasks_installed(struct ass_world *w)
{
    int failures = 0;
    struct ats_stage s; memset(&s, 0, sizeof(s)); s.w = w;
    char probe[ASS_PATH], root[ASS_PATH];
    if (!asi_path(probe, sizeof(probe), w->source, ATS_NODE) ||
        access(probe, X_OK) != 0) {
        printf("app.seed skycombat: tasks installed resolve... SKIP (no "
               "build/bin/z23 on this host)\n");
        return 0;
    }
    if (!ats_stage_root(root, sizeof(root))) {
        printf("app.seed skycombat: tasks installed resolve... SKIP (no "
               "trusted-ancestor staging root on this host)\n");
        return 0;
    }
    (void)snprintf(s.base, sizeof(s.base), "%s", root);
    TEST("a staged tasks generation resolves app copy tasks with no checkout "
         "in cwd; a tampered image member fails closed") {
        ASSERT(ats_stage_all(&s));
        ASSERT(ats_resolves_installed(&s));
        ASSERT(ats_tamper_refuses(&s));
        PASS();
    } _test_next:;
    ats_stage_free(&s);
    if (test_rm_rf_recursive(root) != 0) {
        printf("app.seed skycombat: tasks fixture cleanup failed; retained=%s\n",
               root);
        ++failures;
    }
    return failures;
}
/* The name gates themselves: tasks behaves like skycombat, others stay out. */
static int ass_tasks_gates(struct ass_world *w)
{
    (void)w;
    int failures = 0;
    TEST("installed-source gates admit tasks beside skycombat and refuse "
         "other names") {
        struct app_installed_source source; app_installed_source_init(&source);
        char why[256] = "";
        ASSERT(app_installed_source_select("tasks", &source, why,
                                           sizeof(why)) ==
               APP_INSTALLED_SOURCE_UNSELECTED);
        ASSERT(app_installed_source_select("skycombat", &source, why,
                                           sizeof(why)) ==
               APP_INSTALLED_SOURCE_UNSELECTED);
        ASSERT(app_installed_source_select("soundboard", &source, why,
                                           sizeof(why)) ==
               APP_INSTALLED_SOURCE_REFUSED);
        why[0] = 0;
        ASSERT(!app_installed_source_resolve("tasks", &source, why,
                                             sizeof(why)));
        ASSERT(!strstr(why, "Only installed skycombat"));
        app_installed_source_free(&source);
        PASS();
    } _test_next:;
    return failures;
}
static bool asi_prepare_mode(struct ass_world *w, struct asi_run *r)
{
    r->offline = getenv("ZCL_TEST_INSTALLED_APP_ORIGINAL_SHARE") != NULL;
    if (!r->offline) return asi_prepare_installed(w, r);
    const char *release = getenv("ZCL_TEST_INSTALLED_APP_BIN_DIR");
    const char *evidence = getenv("ZCL_TEST_INSTALLED_APP_EVIDENCE_DIR");
    if (!r->real_kit || !release || strlen(release) >= sizeof(r->release) ||
        !evidence || !asi_evidence_empty(evidence)) return false;
    memcpy(r->release, release, strlen(release) + 1);
    return asi_supplied_kit(w, r) && asi_install(w, r) &&
        asi_desktop_installed(r) && asi_docs_installed(r);
}
static bool asi_installed_flow(struct ass_world *w, struct asi_run *r)
{
    if (!asi_discovery(w, r) || !asi_no_consumer_state(r)) return false;
    if (!r->offline && (!asi_terminal_copy(w, r) || !asi_no_consumer_state(r) || !asi_cancel(w, r))) return false;
    if (!asi_confirm(w, r) || (r->real_kit && !asi_real_build(w, r))) return false;
    return (r->offline || asi_kit_refusal(w, r)) && asi_evidence(w, r);
}
static int ass_installed(struct ass_world *w)
{
    if (!getenv("ZCL_TEST_INSTALLED_APP_BIN_DIR")) return 0;
    int failures = 0; struct asi_run r = {0}; struct asi_env saved;
    app_installed_source_init(&r.source); platform_process_init(&r.cli); platform_process_init(&r.display);
    bool env_saved = asi_environment_save(&saved), cwd_changed = false;
    TEST("kit-bearing release/install discovers SkyCombat, adopts its copy and reports kit refusal") {
        struct sigaction chld;
        ASSERT(env_saved && sigaction(SIGCHLD, NULL, &chld) == 0 && chld.sa_handler == SIG_DFL && !(chld.sa_flags & SA_NOCLDWAIT));
        ASSERT(asi_prerequisites(w, &r) && asi_paths(w, &r));
        ASSERT(asi_prepare_mode(w, &r));
        ASSERT(asi_display(w, &r));
        ASSERT(chdir(r.empty) == 0); cwd_changed = true;
        ASSERT(asi_installed_flow(w, &r));
        PASS();
    } _test_next:;
    if (!asi_cleanup(w, &r, &saved, env_saved, cwd_changed)) ++failures;
    if (!failures && r.offline) { test_note("offline fixture retained for separate preview: %s", w->root); return 0; }
    if (!failures && !asi_unseal_fixture_generation(w, &r)) {
        printf("installed fixture unseal refused; retained=%s\n", w->root);
        ++failures;
    }
    return failures;
}

static int ass_installed_preflight(struct ass_world *w)
{
    if (!getenv("ZCL_TEST_INSTALLED_APP_BIN_DIR")) {
        if (getenv("ZCL_TEST_INSTALLED_APP_KIT_DIR") || getenv("ZCL_TEST_INSTALLED_APP_KIT_SHA3")) {
            test_note("installed kit qualification requires ZCL_TEST_INSTALLED_APP_BIN_DIR");
            return 1;
        }
        return 0;
    }
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
    if (!failures)
        failures += ass_tasks_gates(&w);
    if (!failures)
        failures += ass_tasks_installed(&w);
    asf_xvfb_stop(&w.xvfb);
    ass_world_restore(&w);
    if (!failures && getenv("ZCL_TEST_INSTALLED_APP_ORIGINAL_SHARE")) return 0;
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
