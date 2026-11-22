/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: app.run.copy, the copy open (`z23 app open skycombat-1`).
 *
 * Plan: resolve the copy, require it adopted (or received and trusted),
 * refuse unsaved edits as STALE_BUILD, derive the saved tree's package and
 * dependency roots and the toolchain env root exactly as app.build does,
 * and load that build record. No record: STALE_BUILD when this copy was
 * built before (its build directory exists), else NOT_BUILT. The plan_id
 * binds the copy's fork and head versions, the image hash and the record.
 *
 * Confirm: the same plan_id, accept_execution:true and the record's exact
 * image_sha3. app_image_build_prepare pins the stored image and checks its
 * bytes and identity against the record (IMAGE_HASH_MISMATCH otherwise);
 * resident_launch_spawn fexecve's that pinned inode in a new session, with
 * stdin from /dev/null and stdout and stderr to the copy's log under
 * ~/.local/state/z23/apps. The reply carries the pid once the app is still
 * running after the settle time; an early exit is APP_EXITED with the log
 * tail. The app runs unconfined, as the owner's own build of their own
 * copy, which is why only an adopted or owner-trusted copy opens.
 *
 * Recipe form: a copy without a root Makefile whose package is the kept
 * lifecycle install opens to the tasks preview offer instead of a window
 * (the ntd_offer_render contract's candidate keys plus the exact app
 * invoke next action). Nothing is spawned, so no exit can be observed;
 * the open confirm accepts the same recipe plan identity app.build's
 * recipe form binds. A make-form copy keeps every byte of the path
 * above. */

#include "command/native_command.h"

#include "command/app_copy_build.h"
#include "command/app_image.h"
#include "command/app_toolchain.h"
#include "command/native_app_compose.h"
#include "command/native_app_launch.h"
#include "command/native_zcode_package_copy.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/resident_launch.h"
#include "services/package_lifecycle.h"
#include "services/package_resident.h"
#include "sha3/sha3.h"
#include "util/path_util.h"

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
extern char **environ;
#endif

#define ZRC_COMMAND "app.run.copy"
#define ZRC_PLAN_DOMAIN "zcl.app_run_copy.plan.v1"
#define ZRC_POLL_MS 50

struct zrc {
    const struct json_value *input;
    struct zcl_command_reply *reply;
    const char *datadir;
    const char *name;
    char copy_dir[APP_COPY_BUILD_PATH];
    struct zcl_package_copy copy;
    bool copy_open;
    uint8_t package_root[32];
    uint8_t env_root[32];
    uint8_t dependency_root[32];
    struct app_copy_build_store store;
    struct app_image_build rec;
    char image_hex[65];
    char image_path[APP_COPY_BUILD_PATH];
    uint8_t plan_id[32];
    bool recipe;
    struct package_resident_artifact installed;
};

static void zrc_fail(struct zrc *z, const char *code, const char *message,
                     const char *evidence)
{
    zcl_package_copy_fail(z->reply, code, false, message, evidence);
}

static bool zrc_adopted(struct zrc *z)
{
    enum zcl_package_copy_adoption a =
        zcl_package_copy_adopted(z->datadir, &z->copy, NULL);
    if (a == ZCL_PACKAGE_COPY_ADOPTED || a == ZCL_PACKAGE_COPY_RECEIVED_TRUSTED)
        return true;
    zrc_fail(z, "NOT_ADOPTED", "only an adopted copy, or a received copy "
             "whose publisher and root the owner confirmed, opens",
             zcl_package_copy_adoption_name(a));
    return false;
}

static bool zrc_saved(struct zrc *z)
{
    size_t changes = 0;
    if (!zcl_package_copy_unsaved(&z->copy, &changes)) {
        zrc_fail(z, "STATUS_FAILED", "the copy's status scan failed",
                 z->copy_dir);
        return false;
    }
    if (changes > 0) {
        zrc_fail(z, "STALE_BUILD", "the copy has unsaved edits; save and "
                 "build it first", z->copy_dir);
        return false;
    }
    return true;
}

/* The build record of the saved tree, and its stored image. */
static bool zrc_record(struct zrc *z)
{
    struct stat st;
    bool hit = false;
    struct app_toolchain kit = {0}; char why[256] = "";
    bool resolved = app_toolchain_resolve(&kit, why, sizeof(why));
    struct zcl_result env = ZCL_OK;
    if (resolved && kit.selected) memcpy(z->env_root, kit.env, 32);
    else if (resolved) env = app_image_env_root(z->env_root);
    app_toolchain_free(&kit);
    if (!resolved) {
        zrc_fail(z, "ENV_UNAVAILABLE", "the selected compiler kit is unavailable", why);
        return false;
    }
    if (!env.ok) {
        zrc_fail(z, "ENV_UNAVAILABLE", "the toolchain capsule could not be "
                 "captured", env.message);
        return false;
    }
    struct zcl_result r = app_image_build_load(
        z->store.records, z->package_root, z->env_root, z->dependency_root,
        &z->rec, &hit);
    if (!r.ok) {
        zrc_fail(z, "RECORD_INVALID", "a stored build record for this copy "
                 "is unreadable", r.message);
        return false;
    }
    zcl_hex_encode(z->rec.image_sha3, 32, z->image_hex);
    if (hit && zcl_path_join(z->image_path, sizeof(z->image_path),
                             z->store.images, z->image_hex) &&
        lstat(z->image_path, &st) == 0 && S_ISREG(st.st_mode))
        return true;
    if (stat(z->store.work, &st) == 0)
        zrc_fail(z, "STALE_BUILD", "this saved version (or toolchain) is not "
                 "built yet; run z23 app build first", z->name);
    else
        zrc_fail(z, "NOT_BUILT", "this copy has not been built; run z23 app "
                 "build first", z->name);
    return false;
}
/* ── the recipe form: the kept install opens to a preview offer ──────── */

#if !defined(_WIN32)
/* The build-form rule app.build routes by: a root Makefile is the make
 * fragment path, and this open stays byte-identical there. */
static bool zrc_recipe_form(const struct zrc *z)
{
    char path[APP_COPY_BUILD_PATH];
    struct stat st;
    return zcl_path_join(path, sizeof(path), z->copy_dir, "Makefile") &&
        !(lstat(path, &st) == 0 && S_ISREG(st.st_mode));
}

/* The same recipe plan app.build's recipe form binds for this copy, so the
 * open confirm accepts exactly the identity the build installed. */
static void zrc_recipe_plan_id(struct zrc *z)
{
    static const char domain[] = "zcl.app_build.recipe_plan.v1";
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, z->copy.fork_version, 32);
    sha3_256_write(&sha, z->copy.selected_version, 32);
    sha3_256_write(&sha, z->package_root, 32);
    sha3_256_write(&sha, z->installed.recipe_root, 32);
    sha3_256_write(&sha, z->dependency_root, 32);
    sha3_256_finalize(&sha, z->plan_id);
}

/* The kept install of this exact package: the filed, revalidated receipt,
 * one bin/ program, and the artifact verified against that receipt. Any
 * weaker state refuses; a copy that was never lifecycle-installed reports
 * 0 and falls through to the make-form record path's own refusal.
 * Returns 1 when the recipe identity is ready, 0 for the make path. */
static int zrc_recipe_kept(struct zrc *z)
{
    struct package_lifecycle_step step;
    struct package_lifecycle_programs programs;
    bool installed = false;
    struct zcl_result r = package_lifecycle_installed_inspect(z->datadir,
        z->package_root, &step, &installed);
    if (!r.ok) {
        zrc_fail(z, "RECIPE_OPEN_REFUSED", "the kept install could not be "
                 "inspected", r.message);
        return -1;
    }
    if (!installed) return 0;
    if (!step.has_receipt) {
        zrc_fail(z, "RECIPE_OPEN_REFUSED", "the kept install has no build "
                 "receipt", z->copy_dir);
        return -1;
    }
    r = package_lifecycle_installed_programs(z->datadir, z->package_root,
                                             &programs);
    if (!r.ok || programs.count == 0 ||
        strncmp(programs.output[0], "bin/", 4) != 0) {
        zrc_fail(z, "RECIPE_OPEN_REFUSED", "the kept install names no bin/ "
                 "program", r.ok ? z->copy_dir : r.message);
        return -1;
    }
    r = package_resident_artifact_read(z->datadir, z->package_root,
        step.receipt_id, programs.output[0], &z->installed);
    if (!r.ok) {
        zrc_fail(z, "RECIPE_OPEN_REFUSED", "the installed program did not "
                 "verify against its receipt", r.message);
        return -1;
    }
    memcpy(z->image_hex, z->installed.accepted.image_sha3_hex,
           sizeof(z->image_hex));
    z->recipe = true;
    zrc_recipe_plan_id(z);
    return 1;
}
#else
static int zrc_recipe_kept(struct zrc *z)
{
    (void)z;
    return 0;
}
#endif

static bool zrc_derive(struct zrc *z)
{
    char fork[65], head[65], record[65];
    uint8_t record_id[32];
    if (!app_copy_build_dir(z->datadir, z->name, z->copy_dir,
                            sizeof(z->copy_dir), z->reply) ||
        !zcl_package_copy_open(z->copy_dir, &z->copy, z->reply, ZRC_COMMAND))
        return false;
    z->copy_open = true;
    if (!zrc_adopted(z) || !zrc_saved(z) ||
        !app_copy_build_roots(z->datadir, z->copy_dir, &z->copy,
                              z->package_root, z->dependency_root, z->reply) ||
        !app_copy_build_store(z->datadir, z->copy.fork_version, &z->store,
                              z->reply))
        return false;
#if !defined(_WIN32)
    if (zrc_recipe_form(z)) {
        int recipe = zrc_recipe_kept(z);
        if (recipe != 0) return recipe > 0;
    }
#endif
    if (!zrc_record(z))
        return false;
    if (!app_image_build_id(&z->rec, record_id).ok) {
        zrc_fail(z, "RECORD_INVALID", "the build record has no id", z->name);
        return false;
    }
    zcl_hex_encode(z->copy.fork_version, 32, fork);
    zcl_hex_encode(z->copy.head_version, 32, head);
    zcl_hex_encode(record_id, 32, record);
    const char *parts[] = {fork, head, z->image_hex, record};
    zcl_app_plan_id(ZRC_PLAN_DOMAIN, parts, 4, z->plan_id);
    return true;
}

static void zrc_describe(struct zrc *z, const char *stage)
{
    struct json_value *d = &z->reply->data;
    (void)json_push_kv_str(d, "stage", stage);
    (void)json_push_kv_str(d, "copy", z->name);
    (void)json_push_kv_str(d, "copy_dir", z->copy_dir);
    (void)json_push_kv_str(d, "image_sha3", z->image_hex);
    zcl_package_copy_push_root(d, "package_root", z->package_root);
    zcl_package_copy_push_root(d, "head_version", z->copy.head_version);
    if (z->recipe) {
        (void)json_push_kv_bool(d, "recipe_build", true);
        (void)json_push_kv_str(d, "recipe_program", z->installed.output);
        zcl_package_copy_push_root(d, "recipe_root", z->installed.recipe_root);
    }
}

/* The tasks preview offer contract (native_task_document_command.c's
 * ntd_offer_render candidate keys): the exact installed identity a tasks
 * offer or an app invoke reads back. */
static bool zrc_offer_render(struct zrc *z, struct json_value *d)
{
    return zcl_package_copy_push_root(d, "preview_root", z->package_root) &&
        zcl_package_copy_push_root(d, "preview_receipt",
                                   z->installed.receipt_id) &&
        json_push_kv_str(d, "preview_program", z->installed.output) &&
        json_push_kv_str(d, "artifact_sha3",
                         z->installed.accepted.image_sha3_hex);
}

/* The one interactive path for these exact bytes: app invoke package on
 * the receipt identity, as a pasteable command. */
static bool zrc_invoke_next(struct zrc *z, char *out, size_t cap)
{
    char root[65], receipt[65];
    zcl_hex_encode(z->package_root, 32, root);
    zcl_hex_encode(z->installed.receipt_id, 32, receipt);
    struct json_value invoke_args; json_init(&invoke_args); json_set_object(&invoke_args);
    bool ok = json_push_kv_str(&invoke_args, "datadir", z->datadir) &&
        json_push_kv_str(&invoke_args, "package_root", root) &&
        json_push_kv_str(&invoke_args, "receipt_id", receipt) &&
        json_push_kv_str(&invoke_args, "artifact_sha3", z->installed.accepted.image_sha3_hex) &&
        json_push_kv_str(&invoke_args, "program", z->installed.output) &&
        json_push_kv_str(&invoke_args, "input_text", "list") &&
        json_push_kv_bool(&invoke_args, "accept_execution", true);
    char arg[2 * APP_COPY_BUILD_PATH + 1024] = "--input=";
    size_t n = ok ? json_write(&invoke_args, arg + 8, sizeof(arg) - 8) : 0;
    ok = n && n < sizeof(arg) - 8 &&
        zcl_app_hint(out, cap, z->datadir, "invoke package %s", arg);
    json_free(&invoke_args);
    return ok;
}


/* The recipe form's open: success is the preview offer, never a live
 * process. Nothing is spawned, so no exit can be observed here. The
 * empty process observation is the truth: no pid, no settled state. */
static void zrc_recipe_open(struct zrc *z)
{
    struct json_value *d = &z->reply->data;
    char next[6 * APP_COPY_BUILD_PATH + 2048];
    zrc_describe(z, "commit");
    bool ok = zrc_invoke_next(z, next, sizeof(next)) &&
        zrc_offer_render(z, d) &&
        json_push_kv_str(d, "next", next) &&
        json_push_kv_str(d, "status", "preview") &&
        json_push_kv_int(d, "pid", 0) &&
        json_push_kv_str(d, "start_token", "") &&
        json_push_kv_str(d, "mapped_proof", "") &&
        json_push_kv_bool(d, "settled_alive", false) &&
        json_push_kv_bool(d, "executed", true);
    if (!ok)
        zcl_command_reply_fail(z->reply, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_FAILED, "OBSERVATION_UNAVAILABLE", "open",
            false, true, "the preview offer could not be retained", z->name);
}

/* ── confirm ─────────────────────────────────────────────────────────── */

static bool zrc_accepted(struct zrc *z)
{
    const struct json_value *acc = json_get(z->input, "accept_execution");
    const char *want = zcl_package_copy_str(z->input, "image_sha3");
    if (!acc || acc->type != JSON_BOOL || !json_get_bool(acc)) {
        zrc_fail(z, "EXECUTION_NOT_ACCEPTED", "opening runs this build; pass "
                 "accept_execution:true", z->name);
        return false;
    }
    if (!want || strcmp(want, z->image_hex) != 0) {
        zrc_fail(z, "IMAGE_HASH_MISMATCH", "image_sha3 must be this copy's "
                 "built image, exactly", z->image_hex);
        return false;
    }
    return true;
}

#if !defined(_WIN32)

static bool zrc_log_path(struct zrc *z, char *out, size_t cap)
{
    struct app_launch_env env;
    char why[256] = "", file[64];
    (void)snprintf(file, sizeof(file), "%s.log", z->name);
    if (strchr(z->name, '/'))
        (void)snprintf(file, sizeof(file), "copy-%.12s.log", z->image_hex);
    if (app_launch_env_from_process(&env, why, sizeof(why)) &&
        app_launch_state_dir_ready(env.state_dir) &&
        zcl_path_join(out, cap, env.state_dir, file))
        return true;
    zrc_fail(z, "STATE_FAILED", "the app log directory could not be made",
             why[0] ? why : env.state_dir);
    return false;
}

/* Spawn with fds 0..2 pointed at /dev/null and the log for the fork only;
 * the caller's own stdio is restored before this returns. */
static bool zrc_spawn(struct resident_launch *launch, char *const argv[],
                      const char *log, struct resident_receipt *receipt,
                      char *err, size_t cap)
{
    int saved[3] = {-1, -1, -1};
    int null = open("/dev/null", O_RDONLY | O_CLOEXEC);
    int out = open(log, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                   0600);
    bool ok = null >= 0 && out >= 0;
    (void)fflush(stdout);
    (void)fflush(stderr);
    for (int fd = 0; ok && fd < 3; fd++)
        ok = (saved[fd] = fcntl(fd, F_DUPFD_CLOEXEC, 3)) >= 0;
    ok = ok && dup2(null, 0) == 0 && dup2(out, 1) == 1 && dup2(out, 2) == 2;
    if (ok)
        ok = resident_launch_spawn(launch, argv, environ, receipt, err, cap);
    else
        (void)snprintf(err, cap, "the app log %s could not be opened", log);
    for (int fd = 0; fd < 3; fd++)
        if (saved[fd] >= 0) {
            (void)dup2(saved[fd], fd);
            (void)close(saved[fd]);
        }
    if (null >= 0)
        (void)close(null);
    if (out >= 0)
        (void)close(out);
    return ok;
}

/* Still running after the settle time? An early exit is reaped here. */
enum zrc_settle { ZRC_ALIVE, ZRC_EXITED, ZRC_UNOBSERVED };
static enum zrc_settle zrc_poll(long pid, int *status)
{
    pid_t result;
    do result = waitpid((pid_t)pid, status, WNOHANG); while (result < 0 && errno == EINTR);
    return result == 0 ? ZRC_ALIVE : result == (pid_t)pid ? ZRC_EXITED : ZRC_UNOBSERVED;
}
#ifdef ZCL_TESTING
int zcl_test_app_run_copy_poll(long pid)
{
    int status = 0;
    return (int)zrc_poll(pid, &status);
}
#endif
static enum zrc_settle zrc_settled(long pid, int *status)
{
    const struct timespec step = {0, ZRC_POLL_MS * 1000000L};
    for (int waited = 0; waited < APP_LAUNCH_SETTLE_MS; waited += ZRC_POLL_MS) {
        enum zrc_settle observed = zrc_poll(pid, status);
        if (observed != ZRC_ALIVE) return observed;
        (void)nanosleep(&step, NULL);
    }
    return zrc_poll(pid, status);
}

static void zrc_open(struct zrc *z)
{
    struct resident_launch launch;
    struct resident_receipt receipt;
    char log[APP_LAUNCH_PATH_MAX], tail[APP_LAUNCH_TAIL_MAX] = "";
    char err[RESIDENT_LAUNCH_ERROR_MAX] = "";
    char name[APP_LAUNCH_ID_MAX + 1];
    char *argv[] = {name, NULL};
    int status = 0;
    (void)snprintf(name, sizeof(name), "%s", z->name);
    if (!zrc_log_path(z, log, sizeof(log)))
        return;
    resident_launch_init(&launch);
    struct zcl_result prep =
        app_image_build_prepare(&z->rec, z->image_path, &launch);
    if (!prep.ok) {
        zrc_fail(z, "IMAGE_HASH_MISMATCH", "the stored image no longer "
                 "matches its build record", prep.message);
        resident_launch_close(&launch);
        return;
    }
    if (!zrc_spawn(&launch, argv, log, &receipt, err, sizeof(err))) {
        zrc_fail(z, "SPAWN_FAILED", "the app could not be started", err);
        resident_launch_close(&launch);
        return;
    }
    resident_launch_close(&launch);
    (void)json_push_kv_int(&z->reply->data, "pid", (int64_t)receipt.pid);
    (void)json_push_kv_bool(&z->reply->data, "executed", true);
    enum zrc_settle settled = zrc_settled((long)receipt.pid, &status);
    if (settled != ZRC_ALIVE) {
        app_proc_log_tail(log, tail, sizeof(tail));
        zcl_package_copy_fail(z->reply, settled == ZRC_EXITED ? "APP_EXITED" : "PROCESS_UNOBSERVED", true,
                              settled == ZRC_EXITED ? "the app exited right after it started; see the log tail" :
                              "the app started but its settled state could not be observed",
                              tail);
        return;
    }
    zrc_describe(z, "commit");
    char token[32];
    (void)snprintf(token, sizeof(token), "%llu", (unsigned long long)receipt.start_token);
    if (!json_push_kv_str(&z->reply->data, "start_token", token) ||
        !json_push_kv_bool(&z->reply->data, "settled_alive", true)) {
        zcl_package_copy_fail(z->reply, "OBSERVATION_UNAVAILABLE", true,
                              "the app started but its process observation could not be retained", log);
        return;
    }
    (void)json_push_kv_str(&z->reply->data, "mapped_proof",
                           receipt.mapped_proof);
    (void)json_push_kv_str(&z->reply->data, "log", log);
}

#else

static void zrc_open(struct zrc *z)
{
    zrc_fail(z, "UNSUPPORTED", "opening a built copy needs a POSIX host",
             z->name);
}

#endif

void zcl_native_handle_app_run_copy(const struct zcl_command_request *request,
                                    struct zcl_command_reply *reply)
{
    struct zrc *z = request && reply
                        ? zcl_calloc(1, sizeof(*z), "app.run.copy.state")
                        : NULL;
    if (!z) {
        if (reply)
            zcl_package_copy_fail(reply, "ALLOC", false, "app.run.copy state",
                                  ZRC_COMMAND);
        return;
    }
    z->input = request->input;
    z->reply = reply;
    z->name = zcl_package_copy_str(request->input, "copy");
    z->datadir = zcl_package_copy_datadir(request->input, reply, ZRC_COMMAND);
    if (z->datadir && zrc_derive(z)) {
        if (!zcl_package_copy_confirmed(request->input)) {
            zrc_describe(z, "plan");
            zcl_package_copy_push_root(&reply->data, "plan_id", z->plan_id);
            (void)json_push_kv_bool(&reply->data, "executed", false);
        } else if (zcl_package_copy_plan_matches(request->input, z->plan_id,
                                                 reply, ZRC_COMMAND) &&
                   zrc_accepted(z)) {
            if (z->recipe) zrc_recipe_open(z);
            else zrc_open(z);
        }
    }
    if (z->copy_open)
        zcl_package_copy_close(&z->copy);
    free(z);
}
