/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Native keeper dry previews preserve isolated Windows state. */
#if defined(_WIN32)
#include "command/native_command.h"
#include "command/native_dev_train_command.h"
#include "devloop.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/state_root.h"
#include "platform/process_lock.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

static unsigned execution_calls;

/* Only the unrelated build/landing executor is replaced. Any attempt to
 * execute it fails and is counted; the keeper, shared train helpers, state
 * resolution and JSON implementation are the real production code. */
bool zcl_devloop_process_run(const char *cwd, const char *const argv[],
                             int timeout_ms, struct zcl_devloop_process_result *out)
{
    (void)cwd; (void)argv; (void)timeout_ms;
    execution_calls++;
    memset(out, 0, sizeof(*out));
    return false;
}

void zcl_command_reply_fail(struct zcl_command_reply *reply,
                           enum zcl_command_status status,
                           enum zcl_command_exit exit_code,
                           const char *code, const char *phase,
                           bool retryable, bool mutated,
                           const char *message, const char *evidence)
{
    (void)phase; (void)retryable; (void)mutated; (void)evidence;
    reply->status = status;
    reply->exit_code = exit_code;
    (void)snprintf(reply->error.code, sizeof(reply->error.code), "%s", code);
    (void)snprintf(reply->error.message, sizeof(reply->error.message), "%s", message);
}

struct keep_fixture { char root[512], train[560], land[640]; };

static bool keep_path(const char *root, const char *name, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s/%s", root, name);
    return n > 0 && (size_t)n < cap;
}

static bool keep_write(const char *root, const char *name, const char *text)
{
    char path[1024];
    if (!keep_path(root, name, path, sizeof(path))) return false;
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool ok = fwrite(text, 1, strlen(text), f) == strlen(text);
    return fclose(f) == 0 && ok;
}

static bool keep_equal(const char *root, const char *name, const char *text)
{
    char path[1024], bytes[1024];
    if (!keep_path(root, name, path, sizeof(path))) return false;
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    size_t n = fread(bytes, 1, sizeof(bytes), f);
    bool ok = !ferror(f) && n == strlen(text) && memcmp(bytes, text, n) == 0;
    return fclose(f) == 0 && ok;
}

static bool keep_absent(const char *root, const char *name)
{
    char path[1024];
    if (!keep_path(root, name, path, sizeof(path))) return false;
    DWORD attributes = GetFileAttributesA(path);
    return attributes == INVALID_FILE_ATTRIBUTES &&
        (GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND);
}

static bool keep_no_effects(const struct keep_fixture *f)
{
    const char *names[] = {"keep.lock", "keep.log", "board_post.txt", "READY"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        if (!keep_absent(f->train, names[i])) return false;
    return execution_calls == 0 && keep_absent(f->root, "train8");
}

static void keep_call(const struct keep_fixture *f, const char *train, bool dry_run,
                       struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "train", train);
    (void)json_push_kv_bool(&input, "dry_run", dry_run);
    memset(reply, 0, sizeof(*reply));
    json_init(&reply->data);
    json_set_object(&reply->data);
    struct zcl_command_context context = {.source_root = f->root};
    struct zcl_command_request request = {.context = &context, .input = &input};
    zcl_native_handle_dev_train_keep(&request, reply);
    json_free(&input);
}

static bool keep_empty(const struct keep_fixture *f, const char *train,
                        const char *code)
{
    struct zcl_command_reply reply;
    keep_call(f, train, true, &reply);
    bool ok = reply.status == ZCL_COMMAND_STATUS_BLOCKED &&
        strcmp(reply.error.code, code) == 0;
    json_free(&reply.data);
    return ok && keep_no_effects(f) && keep_absent(f->train, "KEEP.json");
}

static bool keep_saved(const struct keep_fixture *f, const char *state,
                        enum zcl_command_status expected)
{
    char saved[256];
    int n = snprintf(saved, sizeof(saved),
        "{\"state\":\"%s\",\"tip\":\"1111111111111111111111111111111111111111\","
        "\"reason\":\"original bytes\"}\n", state);
    if (n < 0 || (size_t)n >= sizeof(saved) ||
        !keep_write(f->train, "KEEP.json", saved)) return false;
    struct zcl_command_reply reply;
    keep_call(f, "7", true, &reply);
    const char *observed = json_get_str(json_get(&reply.data, "state"));
    bool ok = reply.status == expected && observed && strcmp(observed, state) == 0;
    if (strcmp(state, "landing") == 0) {
        const char *outcome = json_get_str(json_get(&reply.data, "observed_outcome"));
        ok = ok && outcome && strcmp(outcome, "landed") == 0;
    } else {
        ok = ok && strcmp(reply.error.code, "KEEPER_CRASHED") == 0;
    }
    json_free(&reply.data);
    return ok && keep_equal(f->train, "KEEP.json", saved) && keep_no_effects(f);
}

static bool keep_git_refusal(const struct keep_fixture *f)
{
    char row[800];
    int n = snprintf(row, sizeof(row),
        "lanea 1111111111111111111111111111111111111111 %s/verdict.txt\n", f->train);
    if (n < 0 || (size_t)n >= sizeof(row) ||
        !keep_write(f->train, "verdict.txt", "LAND 1111111111111111111111111111111111111111\n") ||
        !keep_write(f->train, "late_picks.txt", row)) return false;
    return keep_empty(f, "7", "NO_BASE");
}

static bool keep_missing_state(const struct keep_fixture *f)
{
    char missing[640];
    if (!keep_path(f->root, "missing-state", missing, sizeof(missing)) ||
        _putenv_s("ZCL_STATE_ROOT", missing)) return false;
    bool ok = keep_empty(f, "7", "NO_STATE_ROOT") &&
        keep_absent(f->root, "missing-state");
    if (_putenv_s("ZCL_STATE_ROOT", f->root)) return false;
    return ok;
}

static bool keep_setup(struct keep_fixture *f)
{
    char relative[128];
    int n = snprintf(relative, sizeof(relative), "test-tmp/keep-win-%lu-%llu",
                     (unsigned long)GetCurrentProcessId(), (unsigned long long)GetTickCount64());
    if (n < 0 || (size_t)n >= sizeof(relative) ||
        !platform_directory_ensure("test-tmp", 0700) ||
        !platform_directory_ensure(relative, 0700) ||
        !platform_directory_canonical_real(relative, f->root, sizeof(f->root))) return false;
    if (_putenv_s("ZCL_TRAIN_SCRATCH_ROOT", f->root) ||
        _putenv_s("ZCL_TRAIN_WORKTREE_ROOT", f->root) ||
        _putenv_s("ZCL_TRAIN_HELPER_DIR", f->root) ||
        _putenv_s("ZCL_STATE_ROOT", f->root)) return false;
    return keep_path(f->root, "train7", f->train, sizeof(f->train)) &&
        platform_directory_ensure(f->train, 0700) &&
        zcl_dev_train_land_dir(f->land, sizeof(f->land)) &&
        platform_directory_ensure(f->land, 0700);
}

static bool keep_locked_request(const struct keep_fixture *f, bool busy)
{
    struct zcl_command_reply reply;
    keep_call(f, "7", false, &reply);
    bool ok = busy
        ? reply.status == ZCL_COMMAND_STATUS_BLOCKED &&
          strcmp(reply.error.code, "KEEPER_BUSY") == 0
        : reply.status == ZCL_COMMAND_STATUS_PASSED;
    json_free(&reply.data);
    return ok && execution_calls == 0 &&
        keep_equal(f->train, "KEEP.json", "{\"state\":\"blocked\",\"reason\":\"retained\"}\n");
}

static bool keep_contention(const struct keep_fixture *f)
{
    char path[1024];
    struct platform_process_lock lock;
    platform_process_lock_init(&lock);
    if (!keep_write(f->train, "KEEP.json", "{\"state\":\"blocked\",\"reason\":\"retained\"}\n") ||
        !keep_path(f->train, "keep.lock", path, sizeof(path)) ||
        !platform_process_lock_try_acquire(&lock, path, true)) return false;
    bool ok = keep_locked_request(f, true);
    platform_process_lock_release(&lock);
    if (!ok || !keep_locked_request(f, false)) return false;
    /* Reacquisition proves the handler released its retained lock. */
    if (!platform_process_lock_try_acquire(&lock, path, false)) return false;
    platform_process_lock_release(&lock);
    return DeleteFileA(path) != 0 && keep_no_effects(f);
}

static bool keep_saved_states(const struct keep_fixture *f)
{
    return keep_saved(f, "landing", ZCL_COMMAND_STATUS_PASSED) &&
        keep_saved(f, "picking", ZCL_COMMAND_STATUS_BLOCKED) &&
        keep_saved(f, "unknown", ZCL_COMMAND_STATUS_BLOCKED);
}

static bool keep_cleanup(const struct keep_fixture *f)
{
    char path[1024];
    const char *names[] = {"KEEP.json", "late_picks.txt", "picks.txt", "verdict.txt"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if (!keep_path(f->train, names[i], path, sizeof(path))) return false;
        if (!DeleteFileA(path)) return false;
    }
    if (!keep_path(f->land, "outcomes.jsonl", path, sizeof(path)) ||
        !DeleteFileA(path) || !RemoveDirectoryA(f->train) ||
        !RemoveDirectoryA(f->land)) return false;
    /* platform_state_root may add a z23 child beneath the explicit root. */
    char state[640];
    if (!platform_state_root(state, sizeof(state))) return false;
    if (strcmp(state, f->root) != 0 && !RemoveDirectoryA(state)) return false;
    if (!keep_path(f->root, "z23", path, sizeof(path)) || !RemoveDirectoryA(path)) return false;
    return RemoveDirectoryA(f->root) != 0;
}

int main(void)
{
    struct keep_fixture f = {0};
    if (!keep_setup(&f)) goto failed;
    if (!keep_missing_state(&f)) goto failed;
    if (!keep_empty(&f, "0", "INVALID_TRAIN") ||
        !keep_empty(&f, "8", "NO_TRAIN_DIR") ||
        !keep_empty(&f, "7", "NO_PICKS")) goto failed;
    if (!keep_write(f.train, "late_picks.txt", "# empty\n") ||
        !keep_empty(&f, "7", "NO_PICKS")) goto failed;
    if (!keep_git_refusal(&f)) goto failed;
    if (!keep_write(f.train, "picks.txt", "lanea 1111111111111111111111111111111111111111\n") ||
        !keep_write(f.land, "outcomes.jsonl",
            "{\"tip\":\"1111111111111111111111111111111111111111\",\"state\":\"landed\"}\n")) goto failed;
    if (!keep_saved_states(&f)) goto failed;
    if (!keep_contention(&f)) goto failed;
    if (!keep_cleanup(&f)) goto failed;
    puts("dev_train_keep_windows_acceptance: PASS (native dry state and lock contention; no Git planning claim)");
    return 0;
failed:
    fprintf(stderr, "dev_train_keep_windows_acceptance: FAIL fixture=%s executor_calls=%u\n",
            f.root, execution_calls);
    return 1;
}
#else
typedef int dev_train_keep_windows_acceptance_not_built;
#endif
