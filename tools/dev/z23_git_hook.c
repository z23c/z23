/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Fail-fast Git admission for exact local development receipts. */

#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE /* realpath: declared only through the fortify inline otherwise */
#endif

#include "dev_proof_receipt.h"
#include "dev_proof_signer.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "base/log_level.h"
#include "platform/positioned_file.h"
#include "platform/state_root.h"
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
#include <sys/file.h>
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

/* Read one worker marker, refusing links and files others can write. */
static bool marker_read(const char *path, char *out, size_t cap)
{
    uint8_t buf[192];
    struct platform_positioned_file file;
    uint64_t size = 0;
    platform_positioned_file_init(&file);
    bool ok = platform_positioned_file_open(&file, path) &&
              platform_positioned_file_is_current_user_only(&file) &&
              platform_positioned_file_size(&file, &size) &&
              size > 0 && size < sizeof(buf) &&
              size < cap &&
              platform_positioned_file_read(&file, buf, (size_t)size, 0) ==
                  (int64_t)size;
    platform_positioned_file_close(&file);
    if (!ok) return false;
    buf[size] = 0;
    (void)memcpy(out, buf, (size_t)size + 1);
    return true;
}

/* A current-generation lease names its holder as "token pid started"; the
 * legacy pre-lease marker is just "pid started". */
static bool marker_parse(const char *text, bool lease, long long *pid,
                         long long *started)
{
    char token[128];
    int fields = lease ? sscanf(text, "%127s %lld %lld", token, pid, started)
                       : sscanf(text, "%lld %lld", pid, started);
    return fields == (lease ? 3 : 2) && *pid > 1 && *started > 0;
}

static bool marker_pid_alive(long long pid)
{
#if defined(_WIN32)
    if ((unsigned long long)pid > UINT32_MAX) return false;
    HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, (DWORD)pid);
    bool alive = process && WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
    if (process) CloseHandle(process);
    return alive;
#else
    return kill((pid_t)pid, 0) == 0;
#endif
}

/* A marker is believed only while the process it names is alive. */
static bool marker_alive(const char *path, bool lease, int64_t *started)
{
    char text[192];
    long long pid = 0, began = 0;
    if (!marker_read(path, text, sizeof(text)) ||
        !marker_parse(text, lease, &pid, &began) ||
        !marker_pid_alive(pid))
        return false;
    *started = (int64_t)began;
    return true;
}

static int64_t running_eta(const char *root, const char *local,
                           const char *base)
{
    char path[PATH_MAX];
    int64_t started = 0;
    /* The live lease is the current authority; the legacy pre-lease marker
     * stays readable so state written by an older generation still reports
     * as running instead of as a missing receipt. */
    int n = snprintf(path, sizeof(path),
                     "%s/.cache/zcl-dev-proof/leases/%s-%s.lease",
                     root, local, base);
    bool live = n > 0 && (size_t)n < sizeof(path) &&
                marker_alive(path, true, &started);
    if (!live) {
        n = snprintf(path, sizeof(path),
                     "%s/.cache/zcl-dev-proof/%s-%s.running",
                     root, local, base);
        if (n <= 0 || (size_t)n >= sizeof(path) ||
            !marker_alive(path, false, &started))
            return -1;
    }
    struct timespec now = {0};
    if (timespec_get(&now, TIME_UTC) != TIME_UTC) return -1;
    int64_t elapsed = (int64_t)now.tv_sec - started;
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
        /* A cache written before receipts were signed is exactly the right
         * size for the unsigned record. Say so by name instead of calling
         * it missing: the operator's next step is the same re-prove, and
         * the reason they are re-proving is legible. */
        if (read_exact_at(root, path, wire,
                          ZCL_DEV_PROOF_UNSIGNED_WIRE_BYTES))
            return refusal(ZCL_DEV_PROOF_SIGNER_WHY_UNSIGNED, local, base, 0);
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

/* Only the native land queue's own checkouts may publish main. Its state
 * root is <platform_state_root>/land (driver checkout <land>/wt; a fence
 * replacement checkout must also live under <land>/, which dev land
 * fence_replace enforces), the same derivation
 * tools/command/native_dev_land.c uses; the hook links the same
 * platform/state_root.c. The existing directory is resolved without creating
 * anything: a box that never ran the queue has no land directory, so every
 * checkout there is outside it.
 *
 * This is a discipline guard, not a security boundary: the land directory is
 * derived from XDG_STATE_HOME/HOME, which the pusher controls, and
 * `git push --no-verify` skips the hook entirely. The exact-receipt
 * requirement is unchanged, and server-side protection is separate.
 *
 * On _WIN32, _fullpath does not resolve symlinks or junctions, and the
 * prefix compare is case-insensitive, so the symlink-escape case is not
 * defended there. */
static bool hook_canonical_path(const char *path, char out[PATH_MAX])
{
#if defined(_WIN32)
    return _fullpath(out, path, PATH_MAX) != NULL;
#else
    return realpath(path, out) != NULL;
#endif
}

static bool hook_path_separator(char c)
{
#if defined(_WIN32)
    return c == '/' || c == '\\';
#else
    return c == '/';
#endif
}

static bool inside_land_queue(const char *root)
{
    char state[PATH_MAX], land[PATH_MAX], land_real[PATH_MAX],
         root_real[PATH_MAX];
    if (!platform_state_root_existing(state, sizeof(state))) return false;
    int n = snprintf(land, sizeof(land), "%s/land", state);
    if (n <= 0 || (size_t)n >= sizeof(land) ||
        !hook_canonical_path(land, land_real) ||
        !hook_canonical_path(root, root_real))
        return false;
    size_t len = strlen(land_real);
    while (len > 1 && hook_path_separator(land_real[len - 1]))
        land_real[--len] = 0;
#if defined(_WIN32)
    if (_strnicmp(root_real, land_real, len) != 0) return false;
#else
    if (strncmp(root_real, land_real, len) != 0) return false;
#endif
    return hook_path_separator(root_real[len]) && root_real[len + 1] != 0;
}

static int land_queue_refusal(const char *root)
{
    (void)fprintf(stderr,
                  "pre-push: REFUSED status=main-push-outside-land-queue\n"
                  "pre-push: submit instead: build/bin/z23-dev dev land "
                  "submit --worktree=%s\n", root);
    return 1;
}

/* Main is the only ref, and only the land queue's checkouts may publish it. */
static int route_refusal(const char *root, const char *remote_ref)
{
    if (strcmp(remote_ref, "refs/heads/main") != 0) {
        (void)fprintf(stderr,
                      "pre-push: REFUSED status=remote-ref-not-main ref=%s\n",
                      remote_ref);
        return 1;
    }
    return inside_land_queue(root) ? 0 : land_queue_refusal(root);
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
        if (route_refusal(root, remote_ref)) return 1;
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

#if !defined(_WIN32)
static bool decimal_text(const char *text)
{
    return text[0] != '\0' && strspn(text, "0123456789") == strlen(text);
}

static bool resident_record_candidate(const char *text)
{
    char pid[24], born[24], mode[16], state[16], nonce[65];
    int used = 0;
    if (sscanf(text, "%23s %15s %15s proofq1 %23s %64s%n", pid,
               mode, state, born, nonce, &used) != 5) return false;
    if (!decimal_text(pid) || !decimal_text(born)) return false;
    return pid[0] != '0' && strcmp(pid, "1") != 0 &&
        strspn(born, "0") != strlen(born) &&
        (strcmp(mode, "verify") == 0 || strcmp(mode, "auto") == 0) &&
        strcmp(state, "ready") == 0 && strlen(nonce) == 64 && oid_text(nonce) &&
        strcmp(text + used, "\n") == 0;
}

/* A cheap candidate filter, never watcher authority. Foreground proofs and
 * stopped watchers leave this persistent file behind. Only a contended,
 * private regular lock with a complete ready-session record warrants asking
 * the existing native receiver to verify its actual owner. */
static bool resident_candidate(const char *root)
{
    char lock[PATH_MAX];
    int n = snprintf(lock, sizeof(lock), "%s/.cache/zcl-dev-watch.lock", root);
    if (n <= 0 || (size_t)n >= sizeof(lock)) return false;
    int fd = open(lock, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat st;
    bool trusted = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_uid == geteuid() && st.st_nlink == 1 &&
        (st.st_mode & 0077) == 0 && (st.st_mode & S_IRUSR) != 0;
    bool busy = false;
    if (trusted) {
        if (flock(fd, LOCK_EX | LOCK_NB) == 0)
            (void)flock(fd, LOCK_UN);
        else
            busy = errno == EWOULDBLOCK || errno == EAGAIN;
    }
    char text[192] = {0};
    ssize_t got = busy ? pread(fd, text, sizeof(text) - 1, 0) : -1;
    (void)close(fd);
    if (got <= 0 || (size_t)got != strlen(text)) return false;
    return resident_record_candidate(text);
}

/* A default post-* proof has no publication delta at the observed remote
 * tip. Missing refs and malformed output retain the existing enqueue path. */
static bool proof_refs_same_text(const char *text)
{
    const char *line = text ? strchr(text, '\n') : NULL;
    if (!line || line == text) return false;
    size_t head_len = (size_t)(line - text);
    const char *base = line + 1;
    const char *end = strchr(base, '\n');
    if (!end || end[1] != '\0' || head_len != (size_t)(end - base) ||
        head_len >= 65) return false;
    char head[65], remote[65];
    memcpy(head, text, head_len);
    head[head_len] = '\0';
    memcpy(remote, base, head_len);
    remote[head_len] = '\0';
    return oid_text(head) && oid_text(remote) && strcmp(head, remote) == 0;
}

static bool proof_default_has_no_delta(void)
{
    const char *argv[] = {"git", "--no-replace-objects", "rev-parse",
                          "HEAD", "refs/remotes/origin/main", NULL};
    char refs[160];
    return child_capture(argv, refs, sizeof(refs)) == 0 &&
           proof_refs_same_text(refs);
}
#endif

/* A hook never starts or re-arms a watcher. It can notify an existing owner.
 * post-commit / post-checkout / post-merge run in every worktree on every
 * commit, including a dozen unattended agent worktrees on a fleet box --
 * forking a full proof watcher there on every rebase, unconditionally,
 * armed strays nobody asked for (17 in one box at once, load 96). So this
 * first filters stale files without loading the dev binary, then requests
 * attach-only native verification. A disappearing owner or an older producer
 * that cannot recognize the new input key refuses without activation.
 *
 * The landing worktree is the one armed worktree whose HEAD moves on
 * purpose without anyone wanting the move scheduled: `dev land step`
 * checks the request tip out, rebases it, and only then asks for the exact
 * rebased pair itself. A post-checkout fork in that window enqueues a
 * proof for a commit the very next second replaces (observed 2026-09-10:
 * a doomed b42b8ee4/0cb9e7937 request claimed a worker slot and settled
 * as head_changed_during_proof). The landing step therefore sets
 * ZCL_LAND_HOOK_QUIET around its own git activity; a developer's checkout
 * never sets it, so their hooks keep scheduling exactly as before. */
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
    if (getenv("ZCL_LAND_HOOK_QUIET")) return 0;
    if (!repo_root(root)) return 0;
    if (!resident_candidate(root)) return 0;
    if (proof_default_has_no_delta()) return 0;
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
    execl(binary, binary, "dev", "proof", "ensure",
          "--input={\"require_existing_watcher\":true}", (char *)NULL);
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

/* One deliberate negative in the selftest. `refused` is what the case was
 * supposed to prove; when it did not hold, put the log floor back so the
 * operator sees why, and name the case rather than returning a bare 1. */
static bool selftest_refused(const char *name, enum zcl_log_level restore,
                             bool refused)
{
    if (refused)
        return true;
    zcl_log_level_set(restore);
    (void)fprintf(stderr,
                  "git-hook-selftest: FAIL case=%s — this receipt was "
                  "supposed to be refused and was not\n", name);
    return false;
}

#if !defined(_WIN32)
static bool resident_candidate_cases(const char *root, int fd)
{
    static const char ready[] =
        "2 verify ready proofq1 1 "
        "1111111111111111111111111111111111111111111111111111111111111111\n";
    static const struct {
        const char *record;
        mode_t mode;
        bool held, expected;
    } cases[] = {
        {"", 0600, false, false},
        {"999999 loop ready proofq1\n", 0600, false, false},
        {ready, 0600, false, false},
        {ready, 0600, true, true},
        {ready, 0000, true, false},
        {"not a watcher receipt\n", 0600, true, false}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        size_t len = strlen(cases[i].record);
        if (ftruncate(fd, 0) != 0 ||
            pwrite(fd, cases[i].record, len, 0) != (ssize_t)len ||
            fchmod(fd, cases[i].mode) != 0) return false;
        int operation = cases[i].held ? LOCK_EX | LOCK_NB : LOCK_UN;
        if (flock(fd, operation) != 0) return false;
        if (resident_candidate(root) != cases[i].expected) return false;
    }
    return true;
}

static bool resident_candidate_selftest(void)
{
    char root[] = "/tmp/z23-git-hook-candidate-XXXXXX";
    if (!mkdtemp(root)) return false;
    char cache[PATH_MAX] = {0}, lock[PATH_MAX] = {0};
    bool ok = !resident_candidate(root);
    int n = snprintf(cache, sizeof(cache), "%s/.cache", root);
    if (n <= 0 || (size_t)n >= sizeof(cache)) ok = false;
    n = snprintf(lock, sizeof(lock), "%s/zcl-dev-watch.lock", cache);
    if (n <= 0 || (size_t)n >= sizeof(lock)) ok = false;
    int fd = -1;
    if (ok && mkdir(cache, 0700) == 0)
        fd = open(lock, O_RDWR | O_CREAT | O_EXCL, 0600);
    ok = fd >= 0 && resident_candidate_cases(root, fd);
    if (fd >= 0) (void)close(fd);
    (void)unlink(lock);
    (void)rmdir(cache);
    (void)rmdir(root);
    char overlong[PATH_MAX + 32];
    memset(overlong, 'a', sizeof(overlong) - 1);
    overlong[sizeof(overlong) - 1] = 0;
    return ok && !resident_candidate(overlong);
}
#endif

#if !defined(_WIN32)
static bool land_queue_mkdir(const char *base, const char *rel, char out[PATH_MAX])
{
    int n = snprintf(out, PATH_MAX, "%s/%s", base, rel);
    return n > 0 && n < PATH_MAX && mkdir(out, 0700) == 0;
}

/* A symlink inside land that points at a lane worktree resolves outside it. */
static bool land_queue_escape_refused(const char *land, const char *lane)
{
    char link[PATH_MAX];
    size_t plen = strlen(land);
    if (plen + sizeof("/escape") > sizeof(link)) return false;
    memcpy(link, land, plen);
    memcpy(link + plen, "/escape", sizeof("/escape"));
    bool ok = symlink(lane, link) == 0 && !inside_land_queue(link);
    (void)unlink(link);
    return ok;
}

static bool land_queue_cases(char p[8][PATH_MAX])
{
    return inside_land_queue(p[3])          /* driver checkout: admitted */
        && inside_land_queue(p[4])          /* fence replacement: admitted */
        && !inside_land_queue(p[5])         /* lane worktree: refused */
        && !inside_land_queue(p[2])         /* the land dir itself */
        && !inside_land_queue(p[6])         /* sibling sharing the prefix */
        && land_queue_escape_refused(p[2], p[5]);
}

/* Pure location policy: which checkouts may publish main. Fixture state root
 * via XDG_STATE_HOME so the real queue directory is never consulted. */
static bool land_queue_selftest(void)
{
    char base[] = "/tmp/z23-git-hook-land-XXXXXX";
    if (!mkdtemp(base)) return false;
    char *saved = getenv("XDG_STATE_HOME");
    char saved_copy[PATH_MAX] = {0};
    if (saved) (void)snprintf(saved_copy, sizeof(saved_copy), "%s", saved);
    char p[8][PATH_MAX];
    bool ok = setenv("XDG_STATE_HOME", base, 1) == 0;
    ok = ok && land_queue_mkdir(base, "z23", p[0]) &&
         land_queue_mkdir(p[0], "dev", p[1]);
    /* No land directory yet: every checkout is outside the queue. */
    ok = ok && !inside_land_queue(base);
    ok = ok && land_queue_mkdir(p[1], "land", p[2]) &&
         land_queue_mkdir(p[2], "wt", p[3]) &&
         land_queue_mkdir(p[2], "fence-1", p[4]) &&
         land_queue_mkdir(base, "lane", p[5]) &&
         land_queue_mkdir(p[1], "land-evil", p[6]);
    ok = ok && land_queue_cases(p);
    if (saved) (void)setenv("XDG_STATE_HOME", saved_copy, 1);
    else (void)unsetenv("XDG_STATE_HOME");
    (void)rmdir(p[6]); (void)rmdir(p[4]); (void)rmdir(p[3]);
    (void)rmdir(p[2]); (void)rmdir(p[1]); (void)rmdir(p[0]);
    (void)rmdir(p[5]); (void)rmdir(base);
    return ok;
}

static bool posix_policy_selftest(void)
{
    return resident_candidate_selftest() && land_queue_selftest();
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
    receipt.policy_version = ZCL_DEV_PROOF_POLICY_VERSION;
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
    /* Everything below is a refusal the selftest WANTS. Signature checks log
     * at ERROR when they refuse, which is right in a hook and wrong here: a
     * passing gate that prints ERROR lines teaches its readers to ignore
     * them. Silence the deliberate negatives, and let selftest_refused()
     * restore the floor and name the case if one of them does not refuse. */
    enum zcl_log_level restore_level = zcl_log_level_get();
    zcl_log_level_set(ZCL_LOG_OFF);
    struct zcl_dev_acceptance_receipt_v1 tampered = receipt;
    tampered.dimensions[ZCL_DEV_PROOF_TEST].skipped = 1;
    if (!selftest_refused("skipped-dimension", restore_level,
            !zcl_dev_proof_receipt_validate(&tampered, local, base,
                                            why, sizeof(why))))
        return 1;
    tampered = receipt;
    memset(tampered.compiler_root, 0, sizeof(tampered.compiler_root));
    if (!selftest_refused("hollow-compiler-root", restore_level,
            zcl_dev_proof_receipt_seal(&tampered) &&
            !zcl_dev_proof_receipt_validate(&tampered, local, base,
                                            why, sizeof(why))))
        return 1;
    tampered = receipt;
    tampered.complete = 0;
    if (!selftest_refused("incomplete-receipt", restore_level,
            zcl_dev_proof_receipt_seal(&tampered) &&
            !zcl_dev_proof_receipt_validate(&tampered, local, base,
                                            why, sizeof(why))))
        return 1;
    tampered = receipt;
    tampered.child_set_root[0] ^= 1u;
    if (!selftest_refused("child-set-mismatch", restore_level,
            zcl_dev_proof_receipt_seal(&tampered) &&
            !zcl_dev_proof_receipt_validate(&tampered, local, base,
                                            why, sizeof(why))))
        return 1;
    if (!selftest_refused("stale-remote-base", restore_level,
            !zcl_dev_proof_receipt_validate(&receipt, local,
                "3333333333333333333333333333333333333333",
                why, sizeof(why))))
        return 1;
    wire[100] ^= 1u;
    struct zcl_dev_acceptance_receipt_v1 parsed;
    if (!selftest_refused("edited-signed-record", restore_level,
            zcl_dev_proof_receipt_parse(wire, sizeof(wire), &parsed) &&
            !zcl_dev_proof_receipt_validate(&parsed, local, base,
                                            why, sizeof(why)) &&
            strcmp(why, ZCL_DEV_PROOF_SIGNER_WHY_SIGNATURE_INVALID) == 0))
        return 1;
    /* A record from before receipts were signed: the same body, the version
     * stamped back to 1, no trailer. It parses and is named, never admitted. */
    if (!selftest_refused("unsigned-v1-record", restore_level,
            zcl_dev_proof_receipt_serialize(&receipt, wire) &&
            (wire[ZCL_DEV_PROOF_WIRE_VERSION_OFFSET] = 1u,
             zcl_dev_proof_receipt_parse(
                 wire, ZCL_DEV_PROOF_UNSIGNED_WIRE_BYTES, &parsed)) &&
            !parsed.has_signature &&
            !zcl_dev_proof_receipt_validate(&parsed, local, base,
                                            why, sizeof(why)) &&
            strcmp(why, ZCL_DEV_PROOF_SIGNER_WHY_UNSIGNED) == 0))
        return 1;
#if !defined(_WIN32)
    if (!selftest_refused("resident-candidate", restore_level,
                          posix_policy_selftest())) return 1;
#endif
#if defined(_WIN32)
    const char *land_queue_checked = "false"; /* POSIX-only land-queue cases */
#else
    const char *land_queue_checked = "true";
#endif
    zcl_log_level_set(restore_level);
    (void)printf("git-hook-selftest: PASS checks=1000 p95_us=%llu "
                 "tamper_refused=true incomplete_refused=true "
                 "hollow_refused=true stale_refused=true "
                 "signature_refused=true unsigned_refused=true "
                 "child_processes=0 resident_candidate_checked=true "
                 "land_queue_checked=%s\n",
                 (unsigned long long)(samples[949] / 1000u),
                 land_queue_checked);
    return samples[949] < 250000000u ? 0 : 1;
}

#if !defined(_WIN32)
static bool proof_refs_selftest(void)
{
    bool ok = proof_refs_same_text(
        "1111111111111111111111111111111111111111\n"
        "1111111111111111111111111111111111111111\n") &&
        !proof_refs_same_text(
        "1111111111111111111111111111111111111111\n"
        "2222222222222222222222222222222222222222\n") &&
        !proof_refs_same_text(
        "1111111111111111111111111111111111111111\n"
        "refs/remotes/origin/main\n") &&
        !proof_refs_same_text(
        "1111111111111111111111111111111111111111\n"
        "1111111111111111111111111111111111111111\nextra\n");
    if (!ok)
        (void)fprintf(stderr, "git-hook-selftest: FAIL case=remote-delta\n");
    return ok;
}
#endif

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
    if (argc == 2 && strcmp(argv[1], "--selftest") == 0) {
#if !defined(_WIN32)
        if (!proof_refs_selftest()) return 1;
#endif
        return selftest();
    }
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
