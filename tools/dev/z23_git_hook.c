/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Fail-fast Git admission for exact local development receipts. */

#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L

#include "dev_proof_receipt.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "platform/positioned_file.h"
#if defined(_WIN32)
#include "platform/private_file.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <wchar.h>
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <io.h>
#else
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define HOOK_LINE_MAX 1024u
#define HOOK_OUTPUT_MAX 8192u

static void clear_git_local_environment(void)
{
    static const char *const names[] = {
        "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_DIR",
        "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_PREFIX",
        "GIT_QUARANTINE_PATH", "GIT_WORK_TREE",
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
#if defined(_WIN32)
        (void)_putenv_s(names[i], "");
#else
        (void)unsetenv(names[i]);
#endif
}

static const char *program_basename(const char *path)
{
    const char *slash = path ? strrchr(path, '/') : NULL;
#if defined(_WIN32)
    const char *backslash = path ? strrchr(path, '\\') : NULL;
    if (!slash || (backslash && backslash > slash)) slash = backslash;
#endif
    return slash ? slash + 1 : (path ? path : "");
}

static bool oid_text(const char *text)
{
    uint8_t oid[ZCL_DEV_PROOF_OID_MAX], len = 0;
    return zcl_dev_proof_oid_decode(text, oid, &len);
}

static bool oid_zero(const char *text)
{
    if (!text || (strlen(text) != 40 && strlen(text) != 64)) return false;
    for (const char *p = text; *p; p++)
        if (*p != '0') return false;
    return true;
}

static bool read_exact_at(const char *root, const char *path,
                          uint8_t *out, size_t size)
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    uint64_t actual = 0;
    platform_positioned_file_init(&file);
    bool opened = path && (root
        ? platform_positioned_file_open_beneath(&file, root, path)
        : platform_positioned_file_open(&file, path));
    bool ok = path && out && opened &&
              platform_positioned_file_is_current_user_only(&file) &&
              platform_positioned_file_snapshot(&file, &before) &&
              platform_positioned_file_size(&file, &actual) && actual == size &&
              platform_positioned_file_read(&file, out, size, 0) ==
                  (int64_t)size &&
              platform_positioned_file_snapshot(&file, &after) &&
              platform_positioned_file_snapshot_equal(&before, &after);
    platform_positioned_file_close(&file);
    return ok;
}

static bool read_exact(const char *path, uint8_t *out, size_t size)
{
    return read_exact_at(NULL, path, out, size);
}

#if defined(_WIN32)
static wchar_t *hook_utf16(const char *text)
{
    if (!text) return NULL;
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1,
                                    NULL, 0);
    wchar_t *wide = count > 0
        ? zcl_malloc((size_t)count * sizeof(*wide), "git-hook-utf16") : NULL;
    if (!wide || MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1,
                                     wide, count) != count) {
        free(wide);
        return NULL;
    }
    return wide;
}

static bool hook_append_char(wchar_t **buffer, size_t *used, size_t *capacity,
                             wchar_t value)
{
    if (*used == *capacity) {
        size_t next = *capacity ? *capacity * 2u : 256u;
        if (next < *capacity || next > 32768u) return false;
        wchar_t *grown = zcl_realloc(
            *buffer, next * sizeof(**buffer), "git-hook-command-line");
        if (!grown) return false;
        *buffer = grown;
        *capacity = next;
    }
    (*buffer)[(*used)++] = value;
    return true;
}

/* CommandLineToArgvW-compatible quoting: backslashes are doubled only when
 * they precede a quote or the closing quote. */
static bool hook_append_arg(wchar_t **line, size_t *used, size_t *capacity,
                            const wchar_t *arg)
{
    if (*used && !hook_append_char(line, used, capacity, L' ')) return false;
    bool quote = !arg[0] || wcspbrk(arg, L" \t\n\v\"") != NULL;
    if (quote && !hook_append_char(line, used, capacity, L'\"')) return false;
    size_t slashes = 0;
    for (const wchar_t *p = arg;; p++) {
        if (*p == L'\\') { slashes++; continue; }
        if (*p == L'\"') {
            for (size_t i = 0; i < slashes * 2u + 1u; i++)
                if (!hook_append_char(line, used, capacity, L'\\')) return false;
            if (!hook_append_char(line, used, capacity, L'\"')) return false;
        } else {
            if (*p == 0 && quote) slashes *= 2u;
            for (size_t i = 0; i < slashes; i++)
                if (!hook_append_char(line, used, capacity, L'\\')) return false;
            if (*p == 0) break;
            if (!hook_append_char(line, used, capacity, *p)) return false;
        }
        slashes = 0;
    }
    return (!quote || hook_append_char(line, used, capacity, L'\"')) &&
           hook_append_char(line, used, capacity, 0);
}

static wchar_t *hook_command_line(const char *const argv[])
{
    if (!argv || !argv[0]) return NULL;
    wchar_t *line = NULL;
    size_t used = 0, capacity = 0;
    for (size_t i = 0; argv[i]; i++) {
        wchar_t *arg = hook_utf16(argv[i]);
        if (!arg) { free(line); return NULL; }
        if (used) used--;
        bool ok = hook_append_arg(&line, &used, &capacity, arg);
        free(arg);
        if (!ok) { free(line); return NULL; }
    }
    return line;
}

static bool hook_absolute_path(const char *path)
{
    if (!path || !path[0]) return false;
    return (path[0] == '/' || path[0] == '\\' ||
            (((path[0] >= 'A' && path[0] <= 'Z') ||
              (path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':' &&
             (path[2] == '/' || path[2] == '\\')));
}

/* Find Git for Windows in the hook's bounded process ancestry and reuse that
 * exact image; searching CWD or PATH would let a checked-out git.exe acquire
 * admission. */
static DWORD hook_parent_pid(DWORD process_id)
{
    DWORD parent = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W entry = {.dwSize = sizeof(entry)};
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    for (BOOL more = Process32FirstW(snapshot, &entry); more;
         more = Process32NextW(snapshot, &entry))
        if (entry.th32ProcessID == process_id) {
            parent = entry.th32ParentProcessID;
            break;
        }
    CloseHandle(snapshot);
    return parent;
}

static wchar_t *hook_parent_git(void)
{
    DWORD candidate = GetCurrentProcessId();
    for (unsigned depth = 0; depth < 8 && candidate; depth++) {
        candidate = hook_parent_pid(candidate);
        HANDLE process = candidate ? OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, FALSE, candidate) : NULL;
        wchar_t image[32768];
        DWORD count = 32768;
        bool queried = process && QueryFullProcessImageNameW(
            process, 0, image, &count) != 0;
        if (process) CloseHandle(process);
        if (!queried) continue;
        const wchar_t *leaf = wcsrchr(image, L'\\');
        leaf = leaf ? leaf + 1 : image;
        if (_wcsicmp(leaf, L"git.exe") == 0) {
            wchar_t *result = zcl_malloc(
                ((size_t)count + 1u) * sizeof(*result),
                "git-hook-parent-image");
            if (result) wmemcpy(result, image, (size_t)count + 1u);
            return result;
        }
    }
    return NULL;
}

static int child_capture(const char *const argv[], char *out, size_t out_size)
{
    if (!argv || !argv[0] || !out || out_size == 0) return -1;
    out[0] = 0;
    clear_git_local_environment();
    wchar_t *line = hook_command_line(argv);
    wchar_t *application = hook_absolute_path(argv[0])
        ? hook_utf16(argv[0]) : hook_parent_git();
    if (!line || !application) { free(line); free(application); return -1; }
    SECURITY_ATTRIBUTES security = {
        .nLength = sizeof(security), .bInheritHandle = TRUE};
    HANDLE read_pipe = NULL, write_pipe = NULL;
    HANDLE null_handle = INVALID_HANDLE_VALUE;
    HANDLE job = NULL;
    LPPROC_THREAD_ATTRIBUTE_LIST attributes = NULL;
    bool attributes_initialized = false;
    PROCESS_INFORMATION process = {0};
    bool started = false;
    const char *failure_reason = "setup";
    if (!CreatePipe(&read_pipe, &write_pipe, &security, 0) ||
        !SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0))
        goto done;
    null_handle = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, 0, NULL);
    if (null_handle == INVALID_HANDLE_VALUE) goto done;
    job = CreateJobObjectW(NULL, NULL);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!job || !SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                         &limits, sizeof(limits)))
        goto done;
    SIZE_T attribute_size = 0;
    (void)InitializeProcThreadAttributeList(NULL, 1, 0, &attribute_size);
    attributes = zcl_malloc(attribute_size, "git-hook-attributes");
    HANDLE inherited[] = {write_pipe, null_handle};
    if (!attributes ||
        !(attributes_initialized = InitializeProcThreadAttributeList(
              attributes, 1, 0, &attribute_size) != 0) ||
        !UpdateProcThreadAttribute(attributes, 0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited),
            NULL, NULL))
        goto done;
    STARTUPINFOEXW startup = {0};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startup.StartupInfo.wShowWindow = SW_HIDE;
    startup.StartupInfo.hStdInput = null_handle;
    startup.StartupInfo.hStdOutput = write_pipe;
    startup.StartupInfo.hStdError = write_pipe;
    startup.lpAttributeList = attributes;
    UINT prior_mode = SetErrorMode(
        SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    DWORD flags = CREATE_NO_WINDOW | CREATE_SUSPENDED |
                  EXTENDED_STARTUPINFO_PRESENT;
    started = CreateProcessW(application, line, NULL, NULL, TRUE, flags,
                                         NULL, NULL, &startup.StartupInfo,
                                         &process) &&
              AssignProcessToJobObject(job, process.hProcess) &&
              ResumeThread(process.hThread) != (DWORD)-1;
    (void)SetErrorMode(prior_mode);
    if (!started) { failure_reason = "spawn"; goto done; }
    CloseHandle(process.hThread);
    process.hThread = NULL;
    CloseHandle(write_pipe);
    write_pipe = NULL;
    size_t used = 0;
    bool truncated = false, failed = false, finished = false;
    ULONGLONG deadline = GetTickCount64() + 1000u;
    for (;;) {
        if (GetTickCount64() >= deadline) { failed = true; break; }
        DWORD available = 0;
        if (!PeekNamedPipe(read_pipe, NULL, 0, NULL, &available, NULL)) {
            DWORD pipe_error = GetLastError();
            if (pipe_error == ERROR_BROKEN_PIPE) {
                ULONGLONG now = GetTickCount64();
                DWORD remaining = now < deadline
                    ? (DWORD)(deadline - now) : 0;
                if (WaitForSingleObject(process.hProcess, remaining) ==
                    WAIT_OBJECT_0) {
                    finished = true;
                    break;
                }
            }
            SetLastError(pipe_error);
            failed = true;
            break;
        }
        if (available) {
            char discard[1024];
            char *target = used + 1u < out_size ? out + used : discard;
            DWORD capacity = target == discard ? sizeof(discard) :
                (DWORD)(out_size - used - 1u);
            DWORD amount = 0;
            if (!ReadFile(read_pipe, target,
                          available < capacity ? available : capacity,
                          &amount, NULL) || amount == 0) {
                failed = true;
                break;
            }
            if (target == discard) truncated = true;
            else used += amount;
            continue;
        }
        DWORD waited = WaitForSingleObject(process.hProcess, 10);
        if (waited == WAIT_OBJECT_0) finished = true;
        else if (waited != WAIT_TIMEOUT) { failed = true; break; }
        if (finished) {
            DWORD final_available = 0;
            if (!PeekNamedPipe(read_pipe, NULL, 0, NULL, &final_available,
                               NULL)) {
                if (GetLastError() == ERROR_BROKEN_PIPE) break;
                failed = true;
            }
            if (failed || final_available == 0) break;
        }
    }
    out[used] = 0;
    if (failed || truncated) { failure_reason = "capture"; goto done; }
    DWORD exit_code = 0;
    if (!GetExitCodeProcess(process.hProcess, &exit_code) || exit_code > 255u)
        { failure_reason = "exit-code"; goto done; }
    CloseHandle(process.hProcess);
    process.hProcess = NULL;
    CloseHandle(job);
    job = NULL;
    if (read_pipe) CloseHandle(read_pipe);
    if (null_handle != INVALID_HANDLE_VALUE) CloseHandle(null_handle);
    DeleteProcThreadAttributeList(attributes);
    free(attributes);
    free(line);
    free(application);
    return (int)exit_code;
done:
    DWORD failure = GetLastError();
    if (process.hThread) CloseHandle(process.hThread);
    if (process.hProcess) {
        (void)TerminateProcess(process.hProcess, 127);
        CloseHandle(process.hProcess);
    }
    if (job) CloseHandle(job);
    if (read_pipe) CloseHandle(read_pipe);
    if (write_pipe) CloseHandle(write_pipe);
    if (null_handle != INVALID_HANDLE_VALUE) CloseHandle(null_handle);
    if (attributes) {
        if (attributes_initialized)
            DeleteProcThreadAttributeList(attributes);
        free(attributes);
    }
    free(line);
    free(application);
    (void)fprintf(stderr,
                  "z23-git-hook: child query failed stage=%s win32=%lu\n",
                  failure_reason, (unsigned long)failure);
    return -1;
}
#else
static int child_capture(const char *const argv[], char *out, size_t out_size)
{
    int pipefd[2];
    if (!argv || !argv[0] || !out || out_size == 0 || pipe(pipefd) != 0)
        return -1;
    pid_t child = fork();
    if (child < 0) {
        (void)close(pipefd[0]);
        (void)close(pipefd[1]);
        return -1;
    }
    if (child == 0) {
        (void)close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0 ||
            dup2(pipefd[1], STDERR_FILENO) < 0)
            _exit(127);
        if (pipefd[1] > STDERR_FILENO) (void)close(pipefd[1]);
        clear_git_local_environment();
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    (void)close(pipefd[1]);
    size_t used = 0;
    bool truncated = false;
    for (;;) {
        char discard[1024];
        void *target = used + 1 < out_size ? out + used : discard;
        size_t capacity = used + 1 < out_size ? out_size - used - 1
                                               : sizeof(discard);
        ssize_t n = read(pipefd[0], target, capacity);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) truncated = true;
        if (n <= 0) break;
        if (target == discard) truncated = true;
        else used += (size_t)n;
    }
    (void)close(pipefd[0]);
    out[used] = 0;
    int status = 0;
    while (waitpid(child, &status, 0) < 0)
        if (errno != EINTR) return -1;
    if (truncated || !WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}
#endif

static bool repo_root(char out[PATH_MAX])
{
    const char *argv[] = {"git", "rev-parse", "--show-toplevel", NULL};
    if (child_capture(argv, out, PATH_MAX) != 0) return false;
    size_t len = strlen(out);
    while (len && (out[len - 1] == '\n' || out[len - 1] == '\r'))
        out[--len] = 0;
#if defined(_WIN32)
    return hook_absolute_path(out);
#else
    return len > 0 && out[0] == '/';
#endif
}

static bool ancestor(const char *base, const char *local)
{
    char output[HOOK_OUTPUT_MAX];
    const char *argv[] = {"git", "--no-replace-objects", "merge-base",
                          "--is-ancestor", base,
                          local, NULL};
#if defined(_WIN32)
    (void)_putenv_s("GIT_NO_LAZY_FETCH", "1");
#else
    (void)setenv("GIT_NO_LAZY_FETCH", "1", 1);
#endif
    return child_capture(argv, output, sizeof(output)) == 0;
}

static int refusal(const char *state, const char *local, const char *base,
                   int64_t eta_ms)
{
    (void)fprintf(stderr,
        "pre-push: REFUSED status=%s eta_ms=%lld local=%s base=%s; "
        "run build/bin/z23-dev dev proof wait --input='"
        "{\"local_commit\":\"%s\",\"remote_base\":\"%s\"}'\n",
        state, (long long)eta_ms, local, base, local, base);
    return 1;
}

static int64_t running_eta(const char *root, const char *local,
                           const char *base)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path),
                     "%s/.cache/zcl-dev-proof/%s-%s.running",
                     root, local, base);
    if (n <= 0 || (size_t)n >= sizeof(path)) return -1;
#if defined(_WIN32)
    uint8_t marker[128] = {0};
    struct platform_positioned_file file;
    uint64_t marker_size = 0;
    platform_positioned_file_init(&file);
    bool opened = platform_positioned_file_open(&file, path) &&
                  platform_positioned_file_is_current_user_only(&file) &&
                  platform_positioned_file_size(&file, &marker_size) &&
                  marker_size > 0 && marker_size < sizeof(marker) &&
                  platform_positioned_file_read(&file, marker,
                      (size_t)marker_size, 0) == (int64_t)marker_size;
    platform_positioned_file_close(&file);
    long long pid = 0, started = 0;
    if (!opened || sscanf((const char *)marker, "%lld %lld", &pid,
                          &started) != 2 || pid <= 1 || started <= 0 ||
        (unsigned long long)pid > UINT32_MAX)
        return -1;
    HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, (DWORD)pid);
    bool alive = process && WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
    if (process) CloseHandle(process);
    if (!alive) return -1;
#else
    struct stat st;
    if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode) ||
        S_ISLNK(st.st_mode) || (st.st_mode & (S_IWGRP | S_IWOTH)) != 0)
        return -1;
    FILE *file = fopen(path, "r");
    if (!file) return -1;
    long long pid = 0, started = 0;
    bool parsed = fscanf(file, "%lld %lld", &pid, &started) == 2;
    (void)fclose(file);
    if (!parsed || pid <= 1 || started <= 0 || kill((pid_t)pid, 0) != 0)
        return -1;
#endif
    struct timespec now = {0};
    if (timespec_get(&now, TIME_UTC) != TIME_UTC) return -1;
    int64_t elapsed = (int64_t)now.tv_sec - (int64_t)started;
    int64_t eta = 900000 - (elapsed > 0 ? elapsed * 1000 : 0);
    return eta > 0 ? eta : 0;
}

static int admit_pair(const char *root, const char *local, const char *base)
{
    if (!ancestor(base, local)) return refusal("remote-base-not-ancestor",
                                                local, base, 0);
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path),
                     ".cache/zcl-dev-proof/receipts/%s-%s.receipt",
                     local, base);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return refusal("receipt-path-invalid", local, base, 0);
    uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES];
    struct zcl_dev_acceptance_receipt_v1 receipt;
    char why[128] = {0};
    if (!read_exact_at(root, path, wire, sizeof(wire))) {
        int64_t eta = running_eta(root, local, base);
        return refusal(eta >= 0 ? "running" : "receipt-missing",
                       local, base, eta >= 0 ? eta : 0);
    }
    if (!zcl_dev_proof_receipt_parse(wire, sizeof(wire), &receipt) ||
        !zcl_dev_proof_receipt_validate(&receipt, local, base,
                                        why, sizeof(why)))
        return refusal(why[0] ? why : "receipt-invalid", local, base, 0);
    for (size_t i = 0; i < ZCL_DEV_PROOF_DIMENSIONS; i++) {
        const struct zcl_dev_proof_dimension *dimension =
            &receipt.dimensions[i];
        if (!dimension->selected) continue;
        char root_hex[65], child_path[PATH_MAX];
        zcl_hex_encode(dimension->receipt_root, ZCL_DEV_PROOF_ROOT_BYTES,
                       root_hex);
        n = snprintf(child_path, sizeof(child_path),
                     ".cache/zcl-dev-proof/children/%s.child", root_hex);
        uint8_t child[ZCL_DEV_PROOF_CHILD_WIRE_BYTES];
        if (n <= 0 || (size_t)n >= sizeof(child_path) ||
            !read_exact_at(root, child_path, child, sizeof(child)) ||
            !zcl_dev_proof_child_receipt_validate(
                child, sizeof(child), (enum zcl_dev_proof_dimension_id)i,
                dimension))
            return refusal("child-receipt-missing-or-invalid", local, base, 0);
    }
    return 0;
}

static int pre_push(void)
{
    char root[PATH_MAX];
    if (!repo_root(root)) {
        (void)fprintf(stderr, "pre-push: REFUSED status=repository-unavailable\n");
        return 1;
    }
    char line[HOOK_LINE_MAX];
    bool saw_update = false;
    while (fgets(line, sizeof(line), stdin)) {
        if (!strchr(line, '\n') && !feof(stdin)) {
            (void)fprintf(stderr, "pre-push: REFUSED status=ref-tuple-truncated\n");
            return 1;
        }
        char local_ref[256], local[65], remote_ref[256], base[65], extra;
        int fields = sscanf(line, "%255s %64s %255s %64s %c", local_ref,
                            local, remote_ref, base, &extra);
        if (fields != 4 || !oid_text(local) || !oid_text(base)) {
            (void)fprintf(stderr, "pre-push: REFUSED status=ref-tuple-invalid\n");
            return 1;
        }
        if (strcmp(remote_ref, "refs/heads/main") != 0) {
            (void)fprintf(stderr,
                          "pre-push: REFUSED status=remote-ref-not-main ref=%s\n",
                          remote_ref);
            return 1;
        }
        if (oid_zero(local))
            return refusal("main-deletion-forbidden", local, base, 0);
        if (oid_zero(base))
            return refusal("advertised-base-missing", local, base, 0);
        if (saw_update) {
            (void)fprintf(stderr,
                          "pre-push: REFUSED status=multiple-updates\n");
            return 1;
        }
        saw_update = true;
        if (admit_pair(root, local, base) != 0) return 1;
    }
    if (ferror(stdin)) {
        (void)fprintf(stderr, "pre-push: REFUSED status=ref-input-failed\n");
        return 1;
    }
    if (saw_update)
        (void)fprintf(stderr, "pre-push: PASS exact local receipt admitted\n");
    return 0;
}

static int notify_proof(void)
{
#if defined(_WIN32)
    /* The native Windows proof producer is deliberately unavailable until it
     * can retain directories and contain the entire compiler/test tree in a
     * kill-on-close Job Object.  A post-* hook must therefore remain a tiny,
     * synchronous no-op: launching the full dev PE here cannot create an
     * admissible receipt and can strand image-validation processes. */
    return 0;
#else
    char root[PATH_MAX], binary[PATH_MAX];
    if (!repo_root(root)) return 0;
    int n = snprintf(binary, sizeof(binary), "%s/build/bin/z23-dev", root);
    if (n <= 0 || (size_t)n >= sizeof(binary))
        return 0;
    if (access(binary, X_OK) != 0) return 0;
    pid_t child = fork();
    if (child != 0) return 0;
    if (setsid() < 0) _exit(0);
    int devnull = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (devnull >= 0) {
        (void)dup2(devnull, STDIN_FILENO);
        (void)dup2(devnull, STDOUT_FILENO);
        (void)dup2(devnull, STDERR_FILENO);
        if (devnull > STDERR_FILENO) (void)close(devnull);
    }
    if (chdir(root) != 0) _exit(0);
    clear_git_local_environment();
    execl(binary, binary, "dev", "proof", "ensure", (char *)NULL);
    _exit(0);
#endif
}

static int compare_u64(const void *a, const void *b)
{
    uint64_t left = *(const uint64_t *)a, right = *(const uint64_t *)b;
    return left < right ? -1 : left > right;
}

static uint64_t sample_clock_ns(void)
{
    struct timespec now = {0};
    if (timespec_get(&now, TIME_UTC) != TIME_UTC) return 0;
    return (uint64_t)now.tv_sec * 1000000000u + (uint64_t)now.tv_nsec;
}

#if defined(_WIN32)
static bool selftest_fixture_create(char path[PATH_MAX],
                                    struct platform_private_file *file)
{
    wchar_t temp[32768];
    DWORD len = GetTempPathW(32768, temp);
    if (!len || len >= 32768) return false;
    for (unsigned attempt = 0; attempt < 32; attempt++) {
        wchar_t wide[32768];
        int n = swprintf(wide, 32768, L"%lsz23-git-hook-%lu-%llu-%u.receipt",
                         temp, (unsigned long)GetCurrentProcessId(),
                         (unsigned long long)GetTickCount64(), attempt);
        if (n <= 0 || n >= 32768) return false;
        int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, -1,
                                        path, PATH_MAX, NULL, NULL);
        if (bytes > 0 && platform_private_file_create(path, file)) return true;
    }
    return false;
}

static bool selftest_fixture_remove(const char *path)
{
    wchar_t *wide = hook_utf16(path);
    bool removed = wide && DeleteFileW(wide) != 0;
    free(wide);
    return removed;
}
#endif

static int selftest(void)
{
    static const char local[] =
        "1111111111111111111111111111111111111111";
    static const char base[] =
        "2222222222222222222222222222222222222222";
    struct zcl_dev_acceptance_receipt_v1 receipt = {0};
    if (!zcl_dev_proof_oid_decode(local, receipt.local_commit,
                                  &receipt.local_commit_len) ||
        !zcl_dev_proof_oid_decode(base, receipt.remote_base,
                                  &receipt.remote_base_len))
        return 1;
    uint8_t *roots[] = {
        receipt.source_root, receipt.source_cas_root, receipt.mutation_root,
        receipt.changed_set_root, receipt.impact_policy_root,
        receipt.compiler_root, receipt.flags_root, receipt.environment_root,
        receipt.build_graph_root, receipt.child_set_root,
    };
    for (size_t root = 0; root < sizeof(roots) / sizeof(roots[0]); root++)
        for (size_t i = 0; i < ZCL_DEV_PROOF_ROOT_BYTES; i++)
            roots[root][i] = (uint8_t)(root + i + 1u);
    for (size_t i = 0; i < ZCL_DEV_PROOF_DIMENSIONS; i++) {
        memset(receipt.dimensions[i].receipt_root, (int)i + 1,
               ZCL_DEV_PROOF_ROOT_BYTES);
        receipt.dimensions[i].selected = 1;
        receipt.dimensions[i].reused = 1;
    }
    receipt.policy_version = 1;
    receipt.complete = 1;
    if (!zcl_dev_proof_receipt_child_set_root(
            &receipt, receipt.child_set_root) ||
        !zcl_dev_proof_receipt_seal(&receipt))
        return 1;
    struct zcl_dev_proof_dimension child_dimension =
        receipt.dimensions[ZCL_DEV_PROOF_TEST];
    uint8_t child[ZCL_DEV_PROOF_CHILD_WIRE_BYTES];
    if (!zcl_dev_proof_child_receipt_create(ZCL_DEV_PROOF_TEST,
                                             &child_dimension, child) ||
        !zcl_dev_proof_child_receipt_validate(
            child, sizeof(child), ZCL_DEV_PROOF_TEST, &child_dimension))
        return 1;
    child[40] ^= 1u;
    if (zcl_dev_proof_child_receipt_validate(
            child, sizeof(child), ZCL_DEV_PROOF_TEST, &child_dimension))
        return 1;
    uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES];
    if (!zcl_dev_proof_receipt_serialize(&receipt, wire)) return 1;
    char fixture[PATH_MAX];
#if defined(_WIN32)
    struct platform_private_file fixture_file;
    platform_private_file_init(&fixture_file);
    if (!selftest_fixture_create(fixture, &fixture_file) ||
        !platform_private_file_write_at(&fixture_file, wire, sizeof(wire), 0) ||
        !platform_private_file_flush(&fixture_file)) {
        platform_private_file_close(&fixture_file);
        return 1;
    }
    platform_private_file_close(&fixture_file);
#else
    memcpy(fixture, "/tmp/z23-git-hook-receipt.XXXXXX",
           sizeof("/tmp/z23-git-hook-receipt.XXXXXX"));
    int fixture_fd = mkstemp(fixture);
    if (fixture_fd < 0) return 1;
    size_t written = 0;
    while (written < sizeof(wire)) {
        ssize_t n = write(fixture_fd, wire + written, sizeof(wire) - written);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            (void)close(fixture_fd);
            (void)unlink(fixture);
            return 1;
        }
        written += (size_t)n;
    }
    if (fsync(fixture_fd) != 0 || close(fixture_fd) != 0) {
        (void)unlink(fixture);
        return 1;
    }
#endif
    uint64_t samples[1000];
    char why[128];
    for (size_t i = 0; i < 1000; i++) {
        struct zcl_dev_acceptance_receipt_v1 parsed;
        uint8_t admitted[ZCL_DEV_PROOF_WIRE_BYTES];
        uint64_t start = sample_clock_ns();
        if (!read_exact(fixture, admitted, sizeof(admitted)) ||
            !zcl_dev_proof_receipt_parse(admitted, sizeof(admitted), &parsed) ||
            !zcl_dev_proof_receipt_validate(&parsed, local, base,
                                            why, sizeof(why))) {
#if defined(_WIN32)
            (void)selftest_fixture_remove(fixture);
#else
            (void)unlink(fixture);
#endif
            return 1;
        }
        samples[i] = sample_clock_ns() - start;
    }
#if defined(_WIN32)
    if (!selftest_fixture_remove(fixture)) return 1;
#else
    if (unlink(fixture) != 0) return 1;
#endif
    qsort(samples, 1000, sizeof(samples[0]), compare_u64);
    struct zcl_dev_acceptance_receipt_v1 tampered = receipt;
    tampered.dimensions[ZCL_DEV_PROOF_TEST].skipped = 1;
    if (zcl_dev_proof_receipt_validate(&tampered, local, base,
                                       why, sizeof(why)))
        return 1;
    tampered = receipt;
    memset(tampered.compiler_root, 0, sizeof(tampered.compiler_root));
    if (!zcl_dev_proof_receipt_seal(&tampered) ||
        zcl_dev_proof_receipt_validate(&tampered, local, base,
                                       why, sizeof(why)))
        return 1;
    tampered = receipt;
    tampered.complete = 0;
    if (!zcl_dev_proof_receipt_seal(&tampered) ||
        zcl_dev_proof_receipt_validate(&tampered, local, base,
                                       why, sizeof(why)))
        return 1;
    tampered = receipt;
    tampered.child_set_root[0] ^= 1u;
    if (!zcl_dev_proof_receipt_seal(&tampered) ||
        zcl_dev_proof_receipt_validate(&tampered, local, base,
                                       why, sizeof(why)))
        return 1;
    if (zcl_dev_proof_receipt_validate(&receipt, local,
          "3333333333333333333333333333333333333333", why, sizeof(why)))
        return 1;
    wire[100] ^= 1u;
    struct zcl_dev_acceptance_receipt_v1 parsed;
    if (!zcl_dev_proof_receipt_parse(wire, sizeof(wire), &parsed) ||
        zcl_dev_proof_receipt_validate(&parsed, local, base,
                                       why, sizeof(why)))
        return 1;
    (void)printf("git-hook-selftest: PASS checks=1000 p95_us=%llu "
                 "tamper_refused=true incomplete_refused=true "
                 "hollow_refused=true stale_refused=true child_processes=0\n",
                 (unsigned long long)(samples[949] / 1000u));
    return samples[949] < 250000000u ? 0 : 1;
}

int main(int argc, char **argv)
{
    char mode_buffer[64];
    const char *mode = program_basename(argv[0]);
    size_t mode_len = strlen(mode);
    if (mode_len > 4 && mode_len < sizeof(mode_buffer) &&
        strcmp(mode + mode_len - 4, ".exe") == 0) {
        memcpy(mode_buffer, mode, mode_len - 4);
        mode_buffer[mode_len - 4] = 0;
        mode = mode_buffer;
    }
    if (argc == 2 && strcmp(argv[1], "--selftest") == 0) return selftest();
    if (argc >= 2 && strncmp(argv[1], "--hook=", 7) == 0)
        mode = argv[1] + 7;
    if (strcmp(mode, "pre-push") == 0) return pre_push();
    if (strcmp(mode, "post-commit") == 0 ||
        strcmp(mode, "post-merge") == 0 ||
        strcmp(mode, "post-checkout") == 0)
        return notify_proof();
    (void)fprintf(stderr, "z23-git-hook: unknown hook mode '%s'\n", mode);
    return 2;
}
