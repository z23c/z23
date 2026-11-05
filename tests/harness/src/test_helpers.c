/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Shared test helper functions. */

#include "test/test_core.h"
#include "consensus/params.h"
#include "services/chain_evidence_authority_service.h"
#include "storage/body_history.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "validation/chain_linkage_check.h"
#include "jobs/tip_finalize_stage.h"
#include "platform/private_directory.h"
#include "platform/file_metadata.h"
#include <signal.h>

/* Reset the process-global singletons that leak across groups in the
 * single-process monolith (test_zcl); the forked runner starts clean. Call at
 * the top of any group whose assertions consult a shared global. Idempotent. */
void test_reset_shared_globals(void)
{
    /* active_chain_tip() consults this authority + its block_map; a leaked
     * pair points into a freed main_state -> dangling reads / SIGSEGV. */
    active_chain_register_authority(&(struct active_chain_authority){0});
    active_chain_register_block_map(NULL);
    /* the served-tip height backing that authority (a separate file-static;
     * resetting the authority struct alone leaves it stale -> NULL tip reads). */
    tip_finalize_stage_test_reset();
    /* chain-linkage HOLD / refuse-from cursor (survives until a witnessed
     * success otherwise). */
    chain_linkage_reset_for_testing();
    /* pending finalized-tip slot (health drain side-effect). */
    chain_evidence_pending_tip_test_reset();
    /* Body-history verdict gates every at-tip/synced/healthy claim; reset to
     * the fail-closed UNKNOWN. A case needing a proven archive calls
     * body_history_test_publish_proven(). */
    body_history_reset();
    /* A prior group may leave crash handlers armed; postmortem_install()
     * requires SIG_DFL. Restore the baseline. */
    signal(SIGABRT, SIG_DFL);
    signal(SIGSEGV, SIG_DFL);
    signal(SIGBUS, SIG_DFL);
    signal(SIGFPE, SIG_DFL);
#if !defined(_WIN32)
    /* A prior alerts_init() leaves SA_NOCLDWAIT set, so waitpid() returns
     * ECHILD; clear the flag via sigaction. No SIGCHLD on Windows. */
    struct sigaction chld_dfl;
    memset(&chld_dfl, 0, sizeof(chld_dfl));
    chld_dfl.sa_handler = SIG_DFL;
    sigemptyset(&chld_dfl.sa_mask);
    sigaction(SIGCHLD, &chld_dfl, NULL);
#endif
}

int check_hex(const unsigned char *data, size_t len, const char *expected)
{
    char buf[256];
    for (size_t i = 0; i < len; i++)
        snprintf(buf + i * 2, 3, "%02x", data[i]);
    if (strcmp(buf, expected) != 0) {
        printf("FAIL\n  got:      %s\n  expected: %s\n", buf, expected);
        return 1;
    }
    printf("OK\n");
    return 0;
}

void test_hex_to_bytes_rev(const char *hex, uint8_t *out, int len)
{
    for (int i = 0; i < len; i++) {
        unsigned int b;
        sscanf(hex + 2*i, "%02x", &b);
        out[len - 1 - i] = (uint8_t)b;
    }
}

void test_hex_to_bytes(const char *hex, uint8_t *out, int len)
{
    for (int i = 0; i < len; i++) {
        unsigned int b;
        sscanf(hex + 2*i, "%02x", &b);
        out[i] = (uint8_t)b;
    }
}

void test_rm_rf(const char *dir)
{
    if (!dir || !dir[0]) return;
    char cmd[4200];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
    (void)!system(cmd);
}

static int test_cleanup_error(const char *path, int error)
{
    fprintf(stderr, "test cleanup refused %.160s: %s\n",
            path ? path : "(null)", strerror(error));
    errno = error;
    return -1;
}

static int test_cleanup_unlink(const char *path)
{
    return unlink(path) == 0 ? 0 : test_cleanup_error(path, errno);
}

static int test_cleanup_entries(DIR *d, const char *normalized)
{
    struct dirent *de;
    int error = 0;
    for (;;) {
        errno = 0;
        de = readdir(d);
        if (!de) { error = errno; break; }
        if (strcmp(de->d_name, ".") == 0 ||
            strcmp(de->d_name, "..") == 0) {
            continue;
        }
        char child[768];
        int n = snprintf(child, sizeof(child), "%s/%s", normalized, de->d_name);
        if (n < 0 || (size_t)n >= sizeof(child)) { error = ENAMETOOLONG; break; }
        if (test_rm_rf_recursive(child) != 0) { error = errno; break; }
    }
    if (closedir(d) != 0 && !error) error = errno;
    if (error) return test_cleanup_error(normalized, error);
    return rmdir(normalized) == 0 ? 0 : test_cleanup_error(normalized, errno);
}

int test_rm_rf_recursive(const char *path)
{
    char normalized[768];
    if (!test_cleanup_path(path, normalized)) return test_cleanup_error(path, errno);
    enum platform_file_shape shape = platform_file_shape_read(normalized);
    /* Nothing at the path is already removed: rm -rf semantics, no refusal. */
    if (shape == PLATFORM_FILE_SHAPE_MISSING) return 0;
    if (shape == PLATFORM_FILE_SHAPE_SYMLINK) {
#if defined(_WIN32)
        /* Source-qualified reparse refusal; not exercised on Linux. */
        return test_cleanup_error(normalized, EPERM);
#else
        return test_cleanup_unlink(normalized);
#endif
    }
    if (shape == PLATFORM_FILE_SHAPE_UNREADABLE)
        return test_cleanup_error(normalized, EACCES);
    if (shape != PLATFORM_FILE_SHAPE_OTHER)
        return test_cleanup_unlink(normalized);
    DIR *d = opendir(normalized);
    if (!d) {
        if (errno == ENOTDIR) return test_cleanup_unlink(normalized);
        return test_cleanup_error(normalized, errno);
    }
    return test_cleanup_entries(d, normalized);
}

void test_make_tmpdir(char *buf, size_t n, const char *prefix,
                      const char *tag)
{
    test_fmt_tmpdir(buf, n, prefix, tag);
    if (test_rm_rf_recursive(buf) != 0 && errno != ENOENT) abort();
    if (!test_ensure_tmproot()) {
        (void)test_cleanup_error("test-tmp", errno);
        abort();
    }
    /* 0700: platform_private_directory_ensure() refuses any other mode. */
#if defined(_WIN32)
    /* MSVCRT ignores the mkdir mode; create through the W-API boundary as production does. */
    if (!platform_private_directory_ensure(buf)) {
        (void)test_cleanup_error(buf, EACCES);
        abort();
    }
#else
    if (mkdir(buf, 0700) != 0) {
        (void)test_cleanup_error(buf, errno);
        abort();
    }
#endif
}

#if defined(_WIN32)
/* True when `path` is drive-qualified or UNC: already absolute for Win32. */
static bool test_win_path_is_absolute(const char *path)
{
    return ((path[0] == '\\' || path[0] == '/') &&
            (path[1] == '\\' || path[1] == '/')) ||
           (path[0] && path[1] == ':' &&
            (path[2] == '\\' || path[2] == '/'));
}
#endif

/* Absolutize `path` against the process cwd into `abs`; the
 * platform_private_* seam is absolute-only (POSIX-rooted, drive-absolute on
 * Windows). Copies `path` unchanged when cwd is unavailable; returns whether
 * the result is absolute. */
bool test_abs_path(const char *path, char *abs, size_t n)
{
    if (!path || !abs || n == 0)
        return false;
#if defined(_WIN32)
    /* A leading slash is rooted only in POSIX/MSYS pathname syntax; native
     * Win32 APIs require either a drive-qualified path or a UNC path. */
    if (test_win_path_is_absolute(path)) {
        snprintf(abs, n, "%s", path);
        return strlen(path) < n;
    }
#else
    if (path[0] == '/') {
        snprintf(abs, n, "%s", path);
        return strlen(path) < n;
    }
#endif
    char cwd[1024];
    if (!getcwd(cwd, sizeof(cwd))) {
        snprintf(abs, n, "%s", path);
        return false;
    }
#if defined(_WIN32)
    if (path[0] == '/' && cwd[0] && cwd[1] == ':') {
        int w = snprintf(abs, n, "%c:%s", cwd[0], path);
        return w > 0 && (size_t)w < n;
    }
#endif
    int w = snprintf(abs, n, "%s/%s", cwd, path);
    return w > 0 && (size_t)w < n;
}

bool test_complete_genesis_shielded_replay(sqlite3 *db)
{
    if (!db || !shielded_history_begin_full_replay(db, 0))
        return false;
    progress_store_tx_lock();
    char *err = NULL;
    bool ok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) ==
                  SQLITE_OK &&
              shielded_history_full_replay_advance_in_tx(db, 0, 0) &&
              sqlite3_exec(db, "COMMIT", NULL, NULL, &err) == SQLITE_OK;
    if (!ok)
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    if (err) sqlite3_free(err);
    progress_store_tx_unlock();
    return ok && shielded_history_publish_full_replay_complete(db, 0);
}

void test_make_easy_consensus_params(struct consensus_params *p)
{
    memset(p, 0, sizeof(*p));
    for (int i = 0; i < 32; i++) p->powLimit.data[i] = 0xff;
}

/* True when every string in the NULL-terminated `needles` array occurs in
 * `out`. */
bool test_out_has_all_needles(const char *out,
                              const char *const *needles)
{
    bool all = true;
    for (size_t i = 0; needles[i]; i++)
        if (!strstr(out, needles[i])) { all = false; break; }
    return all;
}

#if defined(_WIN32)

#include <windows.h>

/* See test_core.h for the contract. _putenv_s (not setenv) so this file also
 * compiles into binaries that do not force-include test/windows_compat.h. */
void *test_spawn_self_with_role(const char *group, const char *role,
                                const char *log_path)
{
    if (!group || !group[0] || !role || !role[0]) {
        fprintf(stderr, "test_spawn_self_with_role: bad group/role\n");
        return NULL;
    }
    char exe[PATH_MAX];
    DWORD n = GetModuleFileNameA(NULL, exe, (DWORD)sizeof(exe));
    if (n == 0 || n >= (DWORD)sizeof(exe)) {
        fprintf(stderr, "test_spawn_self_with_role: GetModuleFileName failed "
                "(%lu)\n", (unsigned long)GetLastError());
        return NULL;
    }
    if (_putenv_s("ZCL_TEST_FORK_GROUP", group) != 0 ||
        _putenv_s("ZCL_TEST_FORK_ROLE", role) != 0) {
        fprintf(stderr, "test_spawn_self_with_role: _putenv_s failed\n");
        return NULL;
    }

    SECURITY_ATTRIBUTES sa;
    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE log = CreateFileA(log_path, GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (log == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "test_spawn_self_with_role: CreateFile(%s) failed "
                "(%lu)\n", log_path, (unsigned long)GetLastError());
        return NULL;
    }

    char cmd[PATH_MAX + 4];
    int len = snprintf(cmd, sizeof(cmd), "\"%s\"", exe);
    if (len < 0 || (size_t)len >= sizeof(cmd)) {
        fprintf(stderr, "test_spawn_self_with_role: path too long\n");
        CloseHandle(log);
        return NULL;
    }
    STARTUPINFOA si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = log;
    si.hStdError = log;
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                        NULL, NULL,
                        &si, &pi)) {
        fprintf(stderr, "test_spawn_self_with_role: CreateProcess failed "
                "(%lu)\n", (unsigned long)GetLastError());
        CloseHandle(log);
        return NULL;
    }
    CloseHandle(pi.hThread);
    CloseHandle(log);
    return (void *)pi.hProcess;
}

int test_self_child_wait(void *handle)
{
    if (!handle) return -1;
    HANDLE h = (HANDLE)handle;
    if (WaitForSingleObject(h, INFINITE) != WAIT_OBJECT_0) {
        fprintf(stderr, "test_self_child_wait: wait failed (%lu)\n",
                (unsigned long)GetLastError());
        CloseHandle(h);
        return -1;
    }
    DWORD code = 0;
    if (!GetExitCodeProcess(h, &code)) {
        fprintf(stderr, "test_self_child_wait: GetExitCodeProcess failed "
                "(%lu)\n", (unsigned long)GetLastError());
        CloseHandle(h);
        return -1;
    }
    CloseHandle(h);
    return (int)code;
}

void test_self_child_kill(void *handle)
{
    if (!handle) return;
    /* 137 = 128+9: a reaped exit code still reads as hard-killed. */
    (void)TerminateProcess((HANDLE)handle, 137);
}

/* Quote one argument for a CreateProcess command line. */
static size_t test_quote_arg(char *out, size_t out_n, const char *arg)
{
    size_t len = 0;
    if (len + 1 < out_n) out[len++] = '"';
    for (const char *p = arg; *p && len + 1 < out_n; p++) {
        if (*p == '"' && len + 1 < out_n)
            out[len++] = '\\';
        if (len + 1 < out_n)
            out[len++] = *p;
    }
    if (len + 1 < out_n) out[len++] = '"';
    out[len] = '\0';
    return len;
}

/* True when argv and argv[0] are non-NULL. */
static bool test_argv_nonempty(const char *const argv[])
{
    return argv && argv[0];
}

/* Copy execve-style "KEY=VALUE" envp strings into a NUL-separated Win32
 * environment block: each string keeps its NUL and one more NUL closes the
 * block, so a non-empty envp ends double-NUL while an empty envp yields a
 * single NUL. *env_arg stays NULL when envp is NULL. False when the block
 * overflows. */
static bool test_envp_to_env_block(const char *const envp[],
                                   char *block, size_t block_n,
                                   void **env_arg)
{
    if (!envp)
        return true;
    size_t pos = 0;
    for (size_t i = 0; envp[i]; i++) {
        size_t len = strlen(envp[i]) + 1;
        if (pos + len + 1 >= block_n)
            return false;
        memcpy(block + pos, envp[i], len);
        pos += len;
    }
    block[pos] = '\0';
    *env_arg = block;
    return true;
}

/* Append `got` bytes from `buf` to `out` at `pos`, clamped to the room left
 * below the terminating NUL; returns the advanced position. */
static size_t test_append_clamped(char *out, size_t pos, size_t cap,
                                  const char *buf, size_t got)
{
    size_t take = got;
    size_t room = (pos + 1 < cap) ? (cap - 1 - pos) : 0;
    if (take > room)
        take = room;
    if (take > 0) {
        memcpy(out + pos, buf, take);
        pos += take;
    }
    return pos;
}

/* Read up to one bufferful of the bytes queued on `rd` into `out`; *found
 * reports that every needle now occurs in `out`. Returns the advanced
 * position. */
static size_t test_read_queued_bytes(HANDLE rd, char *out, size_t pos,
                                     size_t cap, DWORD avail,
                                     const char *const *needles, bool *found,
                                     struct test_child_merged *capture, bool *read_error)
{
    char buf[4096];
    DWORD want = avail > sizeof(buf) ? (DWORD)sizeof(buf) : avail;
    DWORD got = 0;
    BOOL read_ok = ReadFile(rd, buf, want, &got, NULL);
    if (read_ok && got > 0) {
        test_child_merged_add(capture, buf, got);
        pos = test_append_clamped(out, pos, cap, buf, got);
        out[pos] = '\0';
        *found = test_out_has_all_needles(out, needles);
    } else if (!read_ok && GetLastError() != ERROR_BROKEN_PIPE) *read_error = true;
    return pos;
}

/* Read `rd` to EOF into `out`, clamped to cap-1 bytes, and NUL-terminate. */
static void test_drain_pipe_to_buf(HANDLE rd, char *out, size_t cap,
                                   struct test_child_merged *capture, bool *eof, bool *read_error)
{
    size_t pos = 0;
    for (;;) {
        char buf[4096];
        DWORD got = 0;
        if (!ReadFile(rd, buf, sizeof(buf), &got, NULL)) {
            if (GetLastError() == ERROR_BROKEN_PIPE) *eof = true;
            else *read_error = true;
            break;
        }
        if (got == 0) { *eof = true; break; }
        test_child_merged_add(capture, buf, got);
        pos = test_append_clamped(out, pos, cap, buf, got);
    }
    out[pos < cap ? pos : cap - 1] = '\0';
}

/* Drain the bytes still queued on `rd` into `out`, clamped, and
 * NUL-terminate; returns the advanced position. */
static size_t test_drain_pipe_leftovers(HANDLE rd, char *out, size_t pos,
                                        size_t cap, struct test_child_merged *capture,
                                        bool *eof, bool *read_error)
{
    DWORD avail = 0;
    DWORD got = 0;
    char buf[4096];
    for (;;) {
        if (!PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL)) {
            if (GetLastError() == ERROR_BROKEN_PIPE) *eof = true;
            else *read_error = true;
            break;
        }
        if (avail == 0) break;
        if (!ReadFile(rd, buf, sizeof(buf), &got, NULL)) {
            if (GetLastError() == ERROR_BROKEN_PIPE) *eof = true;
            else *read_error = true;
            break;
        }
        if (got == 0) { *eof = true; break; }
        test_child_merged_add(capture, buf, got);
        pos = test_append_clamped(out, pos, cap, buf, got);
    }
    out[pos < cap ? pos : cap - 1] = '\0';
    return pos;
}

/* Drain without blocking: PeekNamedPipe reports the queued byte count,
 * so ReadFile is only ever asked for bytes already in the pipe — the
 * poll()+O_NONBLOCK shape, minus the socket-only WSAPoll. */
static bool test_poll_pipe_for_needles(HANDLE rd, HANDLE proc,
                                       const char *const *needles, int max_ms,
                                      char *out, size_t cap, struct test_child_merged *capture,
                                      bool *eof, bool *read_error, bool *timeout)
{
    size_t pos = 0;
    bool found = false;
    ULONGLONG deadline = GetTickCount64() + (ULONGLONG)(max_ms > 0 ? max_ms : 0);
    for (;;) {
        DWORD avail = 0;
        if (!PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL)) {
            if (GetLastError() == ERROR_BROKEN_PIPE) *eof = true;
            else *read_error = true;
            break; /* child hung up */
        }
        if (avail > 0) {
            pos = test_read_queued_bytes(rd, out, pos, cap, avail, needles,
                                         &found, capture, read_error);
            if (found)
                return true;
        } else {
            if (GetTickCount64() >= deadline) {
                *timeout = true;
                break;
            }
            if (WaitForSingleObject(proc, 0) == WAIT_OBJECT_0) {
                /* Child exited: one last drain so its final bytes count. */
                pos = test_drain_pipe_leftovers(rd, out, pos, cap, capture, eof, read_error);
                break;
            }
            Sleep(10);
        }
    }
    out[pos < cap ? pos : cap - 1] = '\0';
    return false;
}

int test_spawn_argv_wait(const char *const argv[])
{
    if (!argv || !argv[0]) {
        fprintf(stderr, "test_spawn_argv_wait: empty argv\n");
        return -1;
    }
    char cmd[8192];
    size_t used = 0;
    cmd[0] = '\0';
    for (size_t i = 0; argv[i]; i++) {
        if (i > 0 && used + 1 < sizeof(cmd))
            cmd[used++] = ' ';
        cmd[used] = '\0';
        if (used + 1 >= sizeof(cmd)) {
            fprintf(stderr, "test_spawn_argv_wait: command line too long\n");
            return -1;
        }
        used += test_quote_arg(cmd + used, sizeof(cmd) - used, argv[i]);
    }
    STARTUPINFOA si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                        NULL, NULL,
                        &si, &pi)) {
        fprintf(stderr, "test_spawn_argv_wait: CreateProcess(%s) failed "
                "(%lu)\n", argv[0], (unsigned long)GetLastError());
        return -1;
    }
    CloseHandle(pi.hThread);
    if (WaitForSingleObject(pi.hProcess, INFINITE) != WAIT_OBJECT_0) {
        fprintf(stderr, "test_spawn_argv_wait: wait failed (%lu)\n",
                (unsigned long)GetLastError());
        CloseHandle(pi.hProcess);
        return -1;
    }
    DWORD code = 0;
    if (!GetExitCodeProcess(pi.hProcess, &code)) {
        fprintf(stderr, "test_spawn_argv_wait: GetExitCodeProcess failed "
                "(%lu)\n", (unsigned long)GetLastError());
        CloseHandle(pi.hProcess);
        return -1;
    }
    CloseHandle(pi.hProcess);
    return (int)code;
}

static int test_spawn_capture_env_impl(const char *const argv[],
                                       const char *const envp[],
                                       char *out, size_t cap, bool safe_bytes)
{
    if (!test_argv_nonempty(argv) || !out || cap == 0) {
        fprintf(stderr, "test_spawn_capture_env: bad args\n");
        return -1;
    }
    out[0] = '\0';

    char cmd[8192];
    size_t used = 0;
    cmd[0] = '\0';
    for (size_t i = 0; argv[i]; i++) {
        if (i > 0 && used + 1 < sizeof(cmd))
            cmd[used++] = ' ';
        cmd[used] = '\0';
        if (used + 1 >= sizeof(cmd)) {
            fprintf(stderr, "test_spawn_capture_env: command line too long\n");
            return -1;
        }
        used += test_quote_arg(cmd + used, sizeof(cmd) - used, argv[i]);
    }

    /* execve-style full environment: envp is "KEY=VALUE" strings; the Win32
     * environment block is the same strings back-to-back, NUL-separated,
     * double-NUL terminated. */
    char env_block[16384];
    void *env_arg = NULL;
    if (!test_envp_to_env_block(envp, env_block, sizeof(env_block), &env_arg)) {
        fprintf(stderr, "test_spawn_capture_env: env block too long\n");
        return -1;
    }

    SECURITY_ATTRIBUTES sa;
    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE rd = NULL, wr = NULL;
    if (!CreatePipe(&rd, &wr, &sa, 0)) {
        DWORD error = GetLastError();
        test_note("cli child rc=-1 launched=0 observed=0 reason=pipe");
        fprintf(stderr, "test_spawn_capture_env: CreatePipe failed (%lu)\n",
                (unsigned long)error);
        return -1;
    }
    /* The parent must not inherit the read end into the child. */
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = wr;
    si.hStdError = wr;
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                        env_arg, NULL,
                        &si, &pi)) {
        DWORD error = GetLastError();
        test_note("cli child rc=-1 launched=0 observed=0 reason=create-process");
        fprintf(stderr, "test_spawn_capture_env: CreateProcess(%s) failed "
                "(%lu)\n", argv[0], (unsigned long)error);
        CloseHandle(rd);
        CloseHandle(wr);
        return -1;
    }
    CloseHandle(pi.hThread);
    CloseHandle(wr); /* child's copy is inherited; ours must close to see EOF */

    struct test_child_merged capture = {0};
    bool eof = false, read_error = false;
    test_drain_pipe_to_buf(rd, out, cap, &capture, &eof, &read_error);
    CloseHandle(rd);

    if (WaitForSingleObject(pi.hProcess, INFINITE) != WAIT_OBJECT_0) {
        DWORD error = GetLastError();
        test_note("cli child rc=-1 observed=0 eof=%d read_error=%d", eof, read_error);
        test_child_merged_note(&capture, safe_bytes);
        fprintf(stderr, "test_spawn_capture_env: wait failed (%lu)\n",
                (unsigned long)error);
        CloseHandle(pi.hProcess);
        return -1;
    }
    DWORD code = 0;
    if (!GetExitCodeProcess(pi.hProcess, &code)) {
        test_note("cli child rc=-1 observed=0 eof=%d read_error=%d", eof, read_error);
        test_child_merged_note(&capture, safe_bytes);
        CloseHandle(pi.hProcess);
        return -1;
    }
    CloseHandle(pi.hProcess);
    test_note("cli child rc=%lu observed=1 eof=%d read_error=%d truncated=%d",
              (unsigned long)code, eof, read_error, capture.observed >= cap);
    test_child_merged_note(&capture, safe_bytes);
    return (int)code;
}

int test_spawn_capture_env(const char *const argv[], const char *const envp[],
                           char *out, size_t cap)
{
    return test_spawn_capture_env_impl(argv, envp, out, cap, false);
}

int test_spawn_capture_env_public(const char *const argv[], const char *const envp[],
                                  char *out, size_t cap)
{
    return test_spawn_capture_env_impl(argv, envp, out, cap, true);
}

bool test_spawn_capture_kill(const char *const argv[],
                             const char *const envp[],
                             const char *const *needles, int max_ms,
                             char *out, size_t cap)
{
    if (!test_argv_nonempty(argv) || !needles || !out || cap == 0) {
        fprintf(stderr, "test_spawn_capture_kill: bad args\n");
        return false;
    }
    out[0] = '\0';

    char cmd[8192];
    size_t used = 0;
    cmd[0] = '\0';
    for (size_t i = 0; argv[i]; i++) {
        if (i > 0 && used + 1 < sizeof(cmd))
            cmd[used++] = ' ';
        cmd[used] = '\0';
        if (used + 1 >= sizeof(cmd)) {
            fprintf(stderr, "test_spawn_capture_kill: command line too long\n");
            return false;
        }
        used += test_quote_arg(cmd + used, sizeof(cmd) - used, argv[i]);
    }

    char env_block[16384];
    void *env_arg = NULL;
    if (!test_envp_to_env_block(envp, env_block, sizeof(env_block), &env_arg)) {
        fprintf(stderr, "test_spawn_capture_kill: env block too long\n");
        return false;
    }

    SECURITY_ATTRIBUTES sa;
    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE rd = NULL, wr = NULL;
    if (!CreatePipe(&rd, &wr, &sa, 0)) {
        DWORD error = GetLastError();
        test_note("cli daemon launched=0 observed=0 reason=pipe");
        fprintf(stderr, "test_spawn_capture_kill: CreatePipe failed (%lu)\n",
                (unsigned long)error);
        return false;
    }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = wr;
    si.hStdError = wr;
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                        env_arg, NULL,
                        &si, &pi)) {
        DWORD error = GetLastError();
        test_note("cli daemon launched=0 observed=0 reason=create-process");
        fprintf(stderr, "test_spawn_capture_kill: CreateProcess(%s) failed "
                "(%lu)\n", argv[0], (unsigned long)error);
        CloseHandle(rd);
        CloseHandle(wr);
        return false;
    }
    CloseHandle(pi.hThread);
    CloseHandle(wr); /* child's copy is inherited; ours must close to see EOF */

    struct test_child_merged capture = {0};
    bool eof = false, read_error = false, timeout = false;
    bool found = test_poll_pipe_for_needles(rd, pi.hProcess, needles, max_ms,
                                            out, cap, &capture, &eof, &read_error, &timeout);
    CloseHandle(rd);

    /* SIGKILL analogue, then reap. */
    BOOL killed = TerminateProcess(pi.hProcess, 137);
    bool observed = WaitForSingleObject(pi.hProcess, INFINITE) == WAIT_OBJECT_0;
    DWORD code = 0;
    bool exit_known = observed && GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    test_note("cli daemon stop=%s eof=%d observed=%d killed=%d exit=%lu read_error=%d truncated=%d",
              found ? "needle" : timeout ? "timeout" : "hangup", eof, exit_known,
              killed != 0, (unsigned long)code, read_error, capture.observed >= cap);
    test_child_merged_note(&capture, false);

    if (found)
        return true;
    return test_out_has_all_needles(out, needles);
}

#endif /* _WIN32 */

void test_projection_paths(const char *dir, const char *name,
                           char *elog, size_t elog_n,
                           char *proj, size_t proj_n)
{
    snprintf(elog, elog_n, "%s/event_log.dat", dir);
    snprintf(proj, proj_n, "%s/%s_projection.db", dir, name);
}

long long test_forked_exec_data_mb(long long budget_mb)
{
    long long data_kb = 0;
    char line[256];
    FILE *f = fopen("/proc/self/status", "r");
    while (f && fgets(line, sizeof(line), f))
        if (sscanf(line, "VmData: %lld kB", &data_kb) == 1)
            break;
    if (f)
        (void)fclose(f);
    return budget_mb + (data_kb > 0 ? (data_kb + 1023) / 1024 : 0);
}

void test_child_merged_add(struct test_child_merged *capture, const void *bytes, size_t len)
{
    if (!capture || (!bytes && len)) return;
    const unsigned char *input = bytes;
    capture->observed = UINT64_MAX - capture->observed < len ? UINT64_MAX : capture->observed + len;
    if (len >= TEST_CHILD_MERGED_TAIL) {
        memcpy(capture->tail, input + len - TEST_CHILD_MERGED_TAIL, TEST_CHILD_MERGED_TAIL);
        capture->len = TEST_CHILD_MERGED_TAIL; return;
    }
    size_t drop = capture->len + len > TEST_CHILD_MERGED_TAIL
                      ? capture->len + len - TEST_CHILD_MERGED_TAIL : 0;
    if (drop) { memmove(capture->tail, capture->tail + drop, capture->len - drop); capture->len -= drop; }
    if (len) memcpy(capture->tail + capture->len, input, len);
    capture->len += len;
}

void test_child_merged_note(const struct test_child_merged *capture, bool safe_bytes)
{
    if (!capture) return;
    test_note("child merged_observed=%llu", (unsigned long long)capture->observed);
    if (safe_bytes) test_note_bytes("child merged observed tail", capture->tail, capture->len);
}

/* ── Failure flight recorder ──────────────────────────────────────────
 *
 * A bounded per-TEST record of what the test just observed (child exit
 * status and output tails, response bodies, observation fields). TEST resets
 * it; a passing test prints nothing; an ASSERT failure prints it once, framed
 * by "--- evidence <file>:<line> ---" / "--- end evidence ---". The record
 * keeps the first TEST_EVIDENCE_HEAD bytes and the last TEST_EVIDENCE_TAIL
 * bytes, so the total never exceeds TEST_EVIDENCE_CAP whatever is noted. */
#include <stdarg.h>
#include <stdatomic.h>

enum {
    TEST_EVIDENCE_HEAD = 1024,
    TEST_EVIDENCE_TAIL = TEST_EVIDENCE_CAP - TEST_EVIDENCE_HEAD,
    TEST_EVIDENCE_NOTE = 1024,      /* longest single formatted note */
    TEST_EVIDENCE_BYTES_HEAD = 384, /* test_note_bytes keeps head+tail */
    TEST_EVIDENCE_BYTES_TAIL = 1152,
};

static struct {
    char head[TEST_EVIDENCE_HEAD];
    char tail[TEST_EVIDENCE_TAIL];
    uint64_t total;
} g_evidence;
static atomic_flag g_evidence_lock = ATOMIC_FLAG_INIT;

static void evidence_lock(void)
{
    while (atomic_flag_test_and_set_explicit(&g_evidence_lock,
                                             memory_order_acquire)) {
    }
}

static void evidence_unlock(void)
{
    atomic_flag_clear_explicit(&g_evidence_lock, memory_order_release);
}

static void evidence_append(const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        uint64_t at = g_evidence.total++;
        if (at < TEST_EVIDENCE_HEAD)
            g_evidence.head[at] = s[i];
        else
            g_evidence.tail[(at - TEST_EVIDENCE_HEAD) % TEST_EVIDENCE_TAIL] =
                s[i];
    }
}

void test_evidence_reset(void)
{
    evidence_lock();
    g_evidence.total = 0;
    evidence_unlock();
}

void test_note(const char *fmt, ...)
{
    char line[TEST_EVIDENCE_NOTE];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line, sizeof(line) - 1, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    size_t len = (size_t)n < sizeof(line) - 1 ? (size_t)n : sizeof(line) - 2;
    line[len++] = '\n';
    evidence_lock();
    evidence_append(line, len);
    evidence_unlock();
}

/* Text passes through; a control byte other than newline and tab becomes
 * \xNN so a binary reply cannot garble the transcript. */
static void evidence_note_span(const unsigned char *p, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        char esc[5];
        if (p[i] == '\n' || p[i] == '\t' || (p[i] >= 32 && p[i] < 127)) {
            esc[0] = (char)p[i];
            evidence_append(esc, 1);
        } else {
            int w = snprintf(esc, sizeof(esc), "\\x%02x", p[i]);
            evidence_append(esc, (size_t)w);
        }
    }
}

void test_note_bytes(const char *label, const void *buf, size_t len)
{
    const unsigned char *p = buf;
    char hdr[TEST_EVIDENCE_NOTE];
    int n = snprintf(hdr, sizeof(hdr), "%s (%zu bytes):\n",
                     label ? label : "bytes", len);
    if (n < 0) return;
    bool cut = len > TEST_EVIDENCE_BYTES_HEAD + TEST_EVIDENCE_BYTES_TAIL;
    size_t head = cut ? TEST_EVIDENCE_BYTES_HEAD : len;
    evidence_lock();
    evidence_append(hdr, (size_t)n < sizeof(hdr) ? (size_t)n : sizeof(hdr) - 1);
    if (p) evidence_note_span(p, head);
    if (p && cut) {
        char gap[64];
        int w = snprintf(gap, sizeof(gap), "\n...[%zu bytes elided]...\n",
                         len - head - TEST_EVIDENCE_BYTES_TAIL);
        evidence_append(gap, (size_t)w);
        evidence_note_span(p + len - TEST_EVIDENCE_BYTES_TAIL,
                           TEST_EVIDENCE_BYTES_TAIL);
    }
    evidence_append("\n", 1);
    evidence_unlock();
}

void test_note_child(const char *label, int rc, const char *out)
{
    test_note("%s: exit=%d%s", label ? label : "child", rc,
              rc < 0 ? " (spawn, timeout or harness failure)" : "");
    if (out) test_note_bytes("output", out, strlen(out));
}

/* Appends n bytes of src (or a formatted gap) to out at *used, never past
 * cap - 1. */
static void evidence_put(char *out, size_t cap, size_t *used, const char *src,
                         size_t n)
{
    size_t room = cap - 1 - *used;
    if (n > room) n = room;
    memcpy(out + *used, src, n);
    *used += n;
}

static char evidence_tail_byte(uint64_t tail_index)
{
    return g_evidence.tail[tail_index % TEST_EVIDENCE_TAIL];
}

size_t test_evidence_render(char *out, size_t cap, const char *file, int line)
{
    if (!out || cap == 0) return 0;
    char text[96];
    size_t used = 0;
    int n = snprintf(text, sizeof(text), "--- evidence %s:%d ---\n", file, line);
    size_t header_len = n > 0 ? (size_t)n : 0;
    if (header_len >= sizeof(text)) header_len = sizeof(text) - 1;
    evidence_put(out, cap, &used, text, header_len);
    if (header_len && text[header_len - 1] != '\n')
        evidence_put(out, cap, &used, "\n", 1);
    evidence_lock();
    uint64_t total = g_evidence.total;
    uint64_t head = total < TEST_EVIDENCE_HEAD ? total : TEST_EVIDENCE_HEAD;
    evidence_put(out, cap, &used, g_evidence.head, (size_t)head);
    if (total > TEST_EVIDENCE_CAP) {
        n = snprintf(text, sizeof(text), "\n...[%llu bytes elided]...\n",
                     (unsigned long long)(total - TEST_EVIDENCE_CAP));
        evidence_put(out, cap, &used, text, n > 0 ? (size_t)n : 0);
    }
    uint64_t tail_len = total > head ? total - head : 0;
    uint64_t first = tail_len > TEST_EVIDENCE_TAIL ? tail_len - TEST_EVIDENCE_TAIL
                                                   : 0;
    for (uint64_t i = first; i < tail_len; i++) {
        char c = evidence_tail_byte(i);
        evidence_put(out, cap, &used, &c, 1);
    }
    evidence_unlock();
    if (used > 0 && out[used - 1] != '\n') evidence_put(out, cap, &used, "\n", 1);
    evidence_put(out, cap, &used, "--- end evidence ---\n",
                 sizeof("--- end evidence ---\n") - 1);
    out[used] = '\0';
    return used;
}

/* Called by every ASSERT variant just before it fails the test. Prints
 * nothing when nothing was noted; clears the record so it prints once. */
void test_evidence_dump(const char *file, int line)
{
    char block[TEST_EVIDENCE_CAP + 512];
    evidence_lock();
    bool empty = g_evidence.total == 0;
    evidence_unlock();
    if (empty) return;
    size_t n = test_evidence_render(block, sizeof(block), file, line);
    (void)fwrite(block, 1, n, stdout);
    test_evidence_reset();
}
