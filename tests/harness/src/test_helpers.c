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
#include <signal.h>

/* Reset the process-global singletons that leak across groups in the
 * single-process monolith (test_zcl). The forked runner (test_parallel)
 * gets fresh globals per group, so it never sees this; the monolith shares
 * one address space, so a group that arms a global — e.g.
 * tip_finalize_stage_init() registers an active-chain authority bound to
 * its local main_state, which dangles once that group returns — pollutes
 * every later group that reads it. Call this at the TOP of any group whose
 * assertions consult a shared global. Idempotent and safe to call anytime;
 * it only clears to the clean baseline the forked runner starts from. */
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
    /* the published "can I prove I hold my own block bodies?" verdict. It
     * gates every at-tip / synced / healthy claim, so a leaked COMPLETE from
     * an earlier case lets a later one assert a green status it never
     * established — the accidental green this module exists to prevent.
     * Resetting returns it to UNKNOWN, which is the fail-closed default a
     * fresh node has. A case that needs a proven archive must say so with
     * body_history_test_publish_proven(). */
    body_history_reset();
    /* fatal-signal disposition: a prior group that installed the node crash
     * handlers leaves SIGABRT/SIGSEGV/SIGBUS/SIGFPE armed, which makes
     * postmortem_install() refuse (it requires SIG_DFL) and breaks the
     * fork-and-raise crash tests. Restore the baseline the forked runner has. */
    signal(SIGABRT, SIG_DFL);
    signal(SIGSEGV, SIG_DFL);
    signal(SIGBUS, SIG_DFL);
    signal(SIGFPE, SIG_DFL);
#if !defined(_WIN32)
    /* SIGCHLD: a prior alerts_init() installs SA_NOCLDWAIT (the kernel
     * auto-reaps children), so waitpid() in fork-based tests returns ECHILD.
     * Restore default disposition with flags cleared (sigaction, not signal(),
     * because the SA_NOCLDWAIT *flag* must be cleared, not just the handler).
     * No SIGCHLD exists on Windows, and no fork-based test runs there. */
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

int test_rm_rf_recursive(const char *path)
{
    DIR *d = opendir(path);
    if (!d) return unlink(path);

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 ||
            strcmp(de->d_name, "..") == 0) {
            continue;
        }
        char child[768];
        int n = snprintf(child, sizeof(child), "%s/%s", path, de->d_name);
        if (n < 0 || (size_t)n >= sizeof(child)) continue;
        test_rm_rf_recursive(child);
    }
    closedir(d);
    return rmdir(path);
}

void test_make_tmpdir(char *buf, size_t n, const char *prefix,
                      const char *tag)
{
    test_fmt_tmpdir(buf, n, prefix, tag);
    test_rm_rf_recursive(buf);
    mkdir("test-tmp", 0755);
    /* 0700, not 0755: a fixture directory stands in for a datadir, and
     * platform_private_directory_ensure() (platform/modules/platform/src/private_directory.c)
     * refuses any directory whose mode is not exactly 0700 — so every
     * production atomic write a fixture drives through this directory fails
     * with EACCES while the directory is group/other-readable. A real datadir
     * is 0700 too, so this makes the fixture match what the write path has
     * always required rather than relaxing the requirement. The shared
     * test-tmp/ parent stays 0755: only the leaf is validated. */
#if defined(_WIN32)
    /* The MSVCRT mkdir mode is ignored, so a pre-created fixture inherits the
     * parent ACL and correctly fails the production owner+SYSTEM-only datadir
     * check.  Create Windows datadir fixtures through the same W-API boundary
     * as production instead of weakening that check. */
    (void)platform_private_directory_ensure(buf);
#else
    mkdir(buf, 0700);
#endif
}

/* Absolutize `path` against the process cwd into `abs`. The
 * platform_private_* seam (private_destination / private_file) is
 * absolute-only by contract — '/'-rooted on POSIX, drive-absolute on
 * Windows — so any fixture path handed to code that resolves a private
 * destination (checkpoint flush, wallet backup dir, ...) must be in
 * absolute form. Copies `path` through unchanged when cwd is unavailable;
 * returns whether the result is absolute. */
bool test_abs_path(const char *path, char *abs, size_t n)
{
    if (!path || !abs || n == 0)
        return false;
#if defined(_WIN32)
    /* A leading slash is rooted only in POSIX/MSYS pathname syntax; native
     * Win32 APIs require either a drive-qualified path or a UNC path. */
    if (((path[0] == '\\' || path[0] == '/') &&
         (path[1] == '\\' || path[1] == '/')) ||
        (path[0] && path[1] == ':' &&
         (path[2] == '\\' || path[2] == '/'))) {
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
    /* 137 = 128+9, the kill -9 flavor, so a reaped exit code still reads as
     * "was hard-killed" rather than as an ordinary failure. */
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

int test_spawn_capture_env(const char *const argv[],
                           const char *const envp[],
                           char *out, size_t cap)
{
    if (!argv || !argv[0] || !out || cap == 0) {
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
    if (envp) {
        size_t pos = 0;
        for (size_t i = 0; envp[i]; i++) {
            size_t len = strlen(envp[i]) + 1;
            if (pos + len + 1 >= sizeof(env_block)) {
                fprintf(stderr, "test_spawn_capture_env: env block too long\n");
                return -1;
            }
            memcpy(env_block + pos, envp[i], len);
            pos += len;
        }
        env_block[pos] = '\0';
        env_arg = env_block;
    }

    SECURITY_ATTRIBUTES sa;
    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE rd = NULL, wr = NULL;
    if (!CreatePipe(&rd, &wr, &sa, 0)) {
        fprintf(stderr, "test_spawn_capture_env: CreatePipe failed (%lu)\n",
                (unsigned long)GetLastError());
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
        fprintf(stderr, "test_spawn_capture_env: CreateProcess(%s) failed "
                "(%lu)\n", argv[0], (unsigned long)GetLastError());
        CloseHandle(rd);
        CloseHandle(wr);
        return -1;
    }
    CloseHandle(pi.hThread);
    CloseHandle(wr); /* child's copy is inherited; ours must close to see EOF */

    size_t pos = 0;
    for (;;) {
        char buf[4096];
        DWORD got = 0;
        if (!ReadFile(rd, buf, sizeof(buf), &got, NULL) || got == 0)
            break;
        size_t take = got;
        size_t room = (pos + 1 < cap) ? (cap - 1 - pos) : 0;
        if (take > room)
            take = room;
        if (take > 0) {
            memcpy(out + pos, buf, take);
            pos += take;
        }
    }
    out[pos < cap ? pos : cap - 1] = '\0';
    CloseHandle(rd);

    if (WaitForSingleObject(pi.hProcess, INFINITE) != WAIT_OBJECT_0) {
        fprintf(stderr, "test_spawn_capture_env: wait failed (%lu)\n",
                (unsigned long)GetLastError());
        CloseHandle(pi.hProcess);
        return -1;
    }
    DWORD code = 0;
    if (!GetExitCodeProcess(pi.hProcess, &code)) {
        CloseHandle(pi.hProcess);
        return -1;
    }
    CloseHandle(pi.hProcess);
    return (int)code;
}

bool test_spawn_capture_kill(const char *const argv[],
                             const char *const envp[],
                             const char *const *needles, int max_ms,
                             char *out, size_t cap)
{
    if (!argv || !argv[0] || !needles || !out || cap == 0) {
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
    if (envp) {
        size_t pos = 0;
        for (size_t i = 0; envp[i]; i++) {
            size_t len = strlen(envp[i]) + 1;
            if (pos + len + 1 >= sizeof(env_block)) {
                fprintf(stderr, "test_spawn_capture_kill: env block too long\n");
                return false;
            }
            memcpy(env_block + pos, envp[i], len);
            pos += len;
        }
        env_block[pos] = '\0';
        env_arg = env_block;
    }

    SECURITY_ATTRIBUTES sa;
    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE rd = NULL, wr = NULL;
    if (!CreatePipe(&rd, &wr, &sa, 0)) {
        fprintf(stderr, "test_spawn_capture_kill: CreatePipe failed (%lu)\n",
                (unsigned long)GetLastError());
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
        fprintf(stderr, "test_spawn_capture_kill: CreateProcess(%s) failed "
                "(%lu)\n", argv[0], (unsigned long)GetLastError());
        CloseHandle(rd);
        CloseHandle(wr);
        return false;
    }
    CloseHandle(pi.hThread);
    CloseHandle(wr); /* child's copy is inherited; ours must close to see EOF */

    /* Drain without blocking: PeekNamedPipe reports the queued byte count,
     * so ReadFile is only ever asked for bytes already in the pipe — the
     * poll()+O_NONBLOCK shape, minus the socket-only WSAPoll. */
    size_t pos = 0;
    bool found = false;
    ULONGLONG deadline = GetTickCount64() + (ULONGLONG)(max_ms > 0 ? max_ms : 0);
    for (;;) {
        DWORD avail = 0;
        if (!PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL))
            break; /* child hung up */
        if (avail > 0) {
            char buf[4096];
            DWORD want = avail > sizeof(buf) ? (DWORD)sizeof(buf) : avail;
            DWORD got = 0;
            if (ReadFile(rd, buf, want, &got, NULL) && got > 0) {
                size_t take = got;
                size_t room = (pos + 1 < cap) ? (cap - 1 - pos) : 0;
                if (take > room)
                    take = room;
                if (take > 0) {
                    memcpy(out + pos, buf, take);
                    pos += take;
                    out[pos] = '\0';
                }
                bool all = true;
                for (size_t i = 0; needles[i]; i++)
                    if (!strstr(out, needles[i])) { all = false; break; }
                if (all) { found = true; break; }
            }
        } else {
            if (GetTickCount64() >= deadline)
                break;
            if (WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0) {
                /* Child exited: one last drain so its final bytes count. */
                DWORD got = 0;
                char buf[4096];
                while (PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL) &&
                       avail > 0 &&
                       ReadFile(rd, buf, sizeof(buf), &got, NULL) && got > 0) {
                    size_t take = got;
                    size_t room = (pos + 1 < cap) ? (cap - 1 - pos) : 0;
                    if (take > room)
                        take = room;
                    if (take > 0) {
                        memcpy(out + pos, buf, take);
                        pos += take;
                    }
                }
                out[pos < cap ? pos : cap - 1] = '\0';
                break;
            }
            Sleep(10);
        }
    }
    out[pos < cap ? pos : cap - 1] = '\0';
    CloseHandle(rd);

    /* SIGKILL analogue, then reap. */
    TerminateProcess(pi.hProcess, 137);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);

    if (found)
        return true;
    for (size_t i = 0; needles[i]; i++)
        if (!strstr(out, needles[i]))
            return false;
    return true;
}

#endif /* _WIN32 */

void test_projection_paths(const char *dir, const char *name,
                           char *elog, size_t elog_n,
                           char *proj, size_t proj_n)
{
    snprintf(elog, elog_n, "%s/event_log.dat", dir);
    snprintf(proj, proj_n, "%s/%s_projection.db", dir, name);
}
