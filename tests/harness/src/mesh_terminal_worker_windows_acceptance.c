/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Windows acceptance for the terminal worker's ConPTY arm. Spawns
 * real shells on a pseudoconsole and proves, on a Windows machine: a command
 * round-trips (cmd.exe always, powershell.exe when present), resize is
 * applied and bounds-checked, the input and output byte budgets and the
 * lifetime budget end the session by name, every ending removes the shell's
 * whole process tree. A separate undrained named-pipe fixture proves input
 * cancellation and subsequent lifetime cleanup; it does not claim ConPTY
 * itself stopped draining input. Exit 0 = pass, 77 = ConPTY unavailable on this host
 * (honest refusal), 1 = failure. The worker is the mechanism under test; the
 * terminal lane's own refusal of an unconfined shell is not exercised here. */

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "session/mesh_terminal_worker.h"

#define ACCEPT_REFUSED 77
#define OUT_CAP 65536u
#define PIDS_MAX 16u
#define DSR_QUERY "\x1b[6n"
#define DSR_REPLY "\x1b[1;1R"

/* The worker names the close reason in two refusal messages. The protocol
 * module that owns the real table links the signature and hash stack, which
 * this program does not exercise, so the name is provided here. */
const char *mesh_terminal_close_reason_string(
    enum mesh_terminal_close_reason reason)
{
    (void)reason;
    return "closed";
}

static int g_failures;

static void expect(bool ok, const char *label)
{
    printf("mesh_terminal_worker_windows: %s... %s\n", label,
           ok ? "OK" : "FAIL");
    if (!ok)
        g_failures++;
}

struct session {
    struct mesh_terminal_worker worker;
    char out[OUT_CAP];
    size_t out_len;
    size_t dsr_seen;
    struct zcl_result last;
};

static bool make_workdir(char *out, size_t cap)
{
    char tmp[MAX_PATH];
    DWORD n = GetTempPathA(sizeof(tmp), tmp);
    if (n == 0 || n >= sizeof(tmp))
        return false;
    if (snprintf(out, cap, "%sz23-terminal-accept-%lu", tmp,
                 GetCurrentProcessId()) >= (int)cap)
        return false;
    return CreateDirectoryA(out, NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
}

static bool system_path(const char *tail, char *out, size_t cap)
{
    char root[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("SystemRoot", root, sizeof(root));
    if (n == 0 || n >= sizeof(root))
        return false;
    return snprintf(out, cap, "%s%s", root, tail) < (int)cap;
}

static struct mesh_terminal_worker_config base_config(const char *shell,
                                                      const char *workdir)
{
    struct mesh_terminal_worker_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.shell_path = shell;
    cfg.workdir = workdir;
    cfg.cols = 80;
    cfg.rows = 24;
    cfg.max_bytes_in = 1u << 20;
    cfg.max_bytes_out = 1u << 24;
    cfg.lifetime_seconds = 120;
    cfg.idle_seconds = 0;
    return cfg;
}

/* Collect output until `needle` appears or `ms` elapse. A pseudoconsole
 * may ask the terminal for its cursor position before it prints; an
 * emulator answers, so this harness does too. Returns true when the needle
 * was seen. A non-ok result from the worker is kept in s->last. */
static bool pump(struct session *s, unsigned ms, const char *needle)
{
    ULONGLONG deadline = GetTickCount64() + ms;
    do {
        uint8_t chunk[MESH_TERMINAL_WORKER_IO_CHUNK];
        size_t got = 0;
        s->last = mesh_terminal_worker_output(&s->worker, chunk, sizeof(chunk),
                                              &got, (int64_t)time(NULL));
        if (!s->last.ok)
            return false;
        if (got > OUT_CAP - 1u - s->out_len)
            got = OUT_CAP - 1u - s->out_len;
        memcpy(s->out + s->out_len, chunk, got);
        s->out_len += got;
        s->out[s->out_len] = '\0';
        size_t queries = 0;
        for (const char *p = s->out; (p = strstr(p, DSR_QUERY)); p++)
            queries++;
        for (; s->dsr_seen < queries; s->dsr_seen++)
            (void)mesh_terminal_worker_input(
                &s->worker, (const uint8_t *)DSR_REPLY, sizeof(DSR_REPLY) - 1u,
                (int64_t)time(NULL));
        if (needle && strstr(s->out, needle))
            return true;
        if (got == 0)
            Sleep(50);
    } while (GetTickCount64() < deadline);
    return needle == NULL;
}

static bool send_line(struct session *s, const char *line)
{
    struct zcl_result r = mesh_terminal_worker_input(
        &s->worker, (const uint8_t *)line, strlen(line), (int64_t)time(NULL));
    return r.ok;
}

static bool process_gone(DWORD pid)
{
    HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, pid);
    if (!h)
        return true;
    bool gone = WaitForSingleObject(h, 5000) == WAIT_OBJECT_0;
    CloseHandle(h);
    return gone;
}

static size_t job_pids(const struct mesh_terminal_worker *w, DWORD *pids)
{
    union {
        JOBOBJECT_BASIC_PROCESS_ID_LIST list;
        char raw[sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) +
                 PIDS_MAX * sizeof(ULONG_PTR)];
    } info;
    memset(&info, 0, sizeof(info));
    if (!QueryInformationJobObject((HANDLE)w->win_job,
                                   JobObjectBasicProcessIdList, &info,
                                   sizeof(info), NULL))
        return 0;
    size_t n = info.list.NumberOfProcessIdsInList;
    if (n > PIDS_MAX)
        n = PIDS_MAX;
    for (size_t i = 0; i < n; i++)
        pids[i] = (DWORD)info.list.ProcessIdList[i];
    return n;
}

/* One shell, one command, one marker that appears only in the executed
 * output: the typed line contains the factors, never the product. */
static int roundtrip(const char *shell, const char *workdir,
                     const char *command, const char *label)
{
    struct session *s = calloc(1, sizeof(*s));
    if (!s)
        return 1;
    struct mesh_terminal_worker_config cfg = base_config(shell, workdir);
    struct zcl_result r = mesh_terminal_worker_spawn(&cfg, (int64_t)time(NULL),
                                                     &s->worker);
    if (!r.ok) {
        printf("mesh_terminal_worker_windows: %s spawn: %s\n", label,
               r.message);
        int refused = r.code == MESH_TERMINAL_WORKER_ERR_PTY;
        free(s);
        return refused ? ACCEPT_REFUSED : 1;
    }
    expect(send_line(s, command), label);
    expect(pump(s, 20000, "864192"), "command output round-trips");
    expect(mesh_terminal_worker_resize(&s->worker, 100, 30).ok,
           "resize applies");
    expect(mesh_terminal_worker_resize(&s->worker, 0, 0).code ==
               MESH_TERMINAL_WORKER_ERR_GEOMETRY,
           "resize refuses zero geometry");
    mesh_terminal_worker_kill(&s->worker);
    expect(!s->worker.running && s->worker.win_job == NULL,
           "kill ends the session and closes the job");
    free(s);
    return 0;
}

static void test_tree_dies(const char *shell, const char *workdir)
{
    struct session *s = calloc(1, sizeof(*s));
    if (!s)
        return;
    struct mesh_terminal_worker_config cfg = base_config(shell, workdir);
    if (!mesh_terminal_worker_spawn(&cfg, (int64_t)time(NULL), &s->worker).ok) {
        expect(false, "tree: spawn");
        free(s);
        return;
    }
    DWORD pids[PIDS_MAX];
    size_t count = 0;
    (void)send_line(s, "start /b ping -n 120 127.0.0.1 >nul\r\n");
    for (int i = 0; i < 200 && count < 2; i++) {
        (void)pump(s, 50, NULL);
        count = job_pids(&s->worker, pids);
    }
    expect(count >= 2, "a started child joins the shell's job");
    mesh_terminal_worker_kill(&s->worker);
    bool all_gone = true;
    for (size_t i = 0; i < count; i++)
        all_gone = process_gone(pids[i]) && all_gone;
    expect(all_gone, "kill removes the shell and every descendant");
    free(s);
}

static void test_budgets(const char *shell, const char *workdir)
{
    struct session *s = calloc(1, sizeof(*s));
    if (!s)
        return;
    struct mesh_terminal_worker_config cfg = base_config(shell, workdir);
    cfg.max_bytes_in = 16;
    cfg.lifetime_seconds = 5;
    if (!mesh_terminal_worker_spawn(&cfg, 1000, &s->worker).ok) {
        expect(false, "budgets: spawn");
        free(s);
        return;
    }
    expect(mesh_terminal_worker_budget_exceeded(&s->worker, 1005) &&
               s->worker.close_reason == MESH_TERMINAL_CLOSE_LIFETIME_LIMIT,
           "lifetime budget ends the session by name");
    free(s);
    s = calloc(1, sizeof(*s));
    if (!s)
        return;
    cfg.lifetime_seconds = 120;
    if (!mesh_terminal_worker_spawn(&cfg, 1000, &s->worker).ok) {
        expect(false, "budgets: respawn");
        free(s);
        return;
    }
    uint8_t seventeen[17] = { 0 };
    struct zcl_result r =
        mesh_terminal_worker_input(&s->worker, seventeen, 17, 1001);
    expect(r.code == MESH_TERMINAL_WORKER_ERR_BYTE_LIMIT &&
               s->worker.close_reason == MESH_TERMINAL_CLOSE_BYTE_LIMIT &&
               !s->worker.running,
           "input budget overrun kills the session by name");
    free(s);
}

static void test_output_budget(const char *shell, const char *workdir)
{
    struct session *s = calloc(1, sizeof(*s));
    if (!s)
        return;
    struct mesh_terminal_worker_config cfg = base_config(shell, workdir);
    cfg.max_bytes_out = 2048;
    if (!mesh_terminal_worker_spawn(&cfg, (int64_t)time(NULL), &s->worker).ok) {
        expect(false, "output budget: spawn");
        free(s);
        return;
    }
    (void)send_line(s, "dir /s /b %SystemRoot%\\System32\r\n");
    (void)pump(s, 20000, "\x01never");
    expect(s->last.code == MESH_TERMINAL_WORKER_ERR_BYTE_LIMIT &&
               s->worker.close_reason == MESH_TERMINAL_CLOSE_BYTE_LIMIT &&
               !s->worker.running,
           "output budget overrun kills the session by name");
    free(s);
}

typedef LONG(NTAPI *nt_process_fn)(HANDLE);

static nt_process_fn nt_proc(HMODULE module, const char *name)
{
    FARPROC proc = GetProcAddress(module, name);
    nt_process_fn fn = NULL;
    static_assert(sizeof(fn) == sizeof(proc), "function pointers match");
    memcpy(&fn, &proc, sizeof(fn));
    return fn;
}

/* A suspended shell reads nothing. Each input call must still return inside
 * its bound whether the console host buffers the bytes or stops accepting
 * them; a stall is reported as the IO refusal, never waited out. */
static void test_input_bounded(const char *shell, const char *workdir)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    nt_process_fn suspend = ntdll ? nt_proc(ntdll, "NtSuspendProcess") : NULL;
    nt_process_fn resume = ntdll ? nt_proc(ntdll, "NtResumeProcess") : NULL;
    struct session *s = calloc(1, sizeof(*s));
    if (!s || !suspend || !resume) {
        printf("mesh_terminal_worker_windows: bounded input SKIPPED "
               "(no NtSuspendProcess)\n");
        free(s);
        return;
    }
    struct mesh_terminal_worker_config cfg = base_config(shell, workdir);
    if (!mesh_terminal_worker_spawn(&cfg, (int64_t)time(NULL), &s->worker).ok) {
        expect(false, "bounded input: spawn");
        free(s);
        return;
    }
    (void)pump(s, 1500, NULL);
    (void)suspend(s->worker.win_process);
    uint8_t block[3072];
    memset(block, 'a', sizeof(block));
    ULONGLONG worst = 0;
    bool stalled = false;
    for (int i = 0; i < 80 && !stalled; i++) {
        ULONGLONG t0 = GetTickCount64();
        struct zcl_result r = mesh_terminal_worker_input(
            &s->worker, block, sizeof(block), (int64_t)time(NULL));
        ULONGLONG took = GetTickCount64() - t0;
        worst = took > worst ? took : worst;
        stalled = !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_IO;
    }
    printf("mesh_terminal_worker_windows: stall %s, slowest write %llu ms\n",
           stalled ? "observed" : "not reached", (unsigned long long)worst);
    expect(worst < 4000, "no input write outlives its bound");
    (void)resume(s->worker.win_process);
    mesh_terminal_worker_kill(&s->worker);
    free(s);
}

/* The public worker handle is the seam: keep the real ConPTY alive, but send
 * input to a connected pipe whose fixture-owned reader never drains bytes. */
static bool blocked_input_pipe(HANDLE *writer, HANDLE *reader)
{
    wchar_t name[128];
    int n = swprintf(name, sizeof(name) / sizeof(name[0]),
        L"\\\\.\\pipe\\z23-terminal-blocked-%lu-%llu", GetCurrentProcessId(),
        (unsigned long long)GetTickCount64());
    if (n < 0 || (size_t)n >= sizeof(name) / sizeof(name[0]))
        return false;
    *writer = CreateNamedPipeW(name, PIPE_ACCESS_OUTBOUND |
        FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, 4096, 0, 0, NULL);
    if (*writer == INVALID_HANDLE_VALUE) {
        *writer = NULL;
        return false;
    }
    *reader = CreateFileW(name, GENERIC_READ, 0, NULL, OPEN_EXISTING,
                          FILE_ATTRIBUTE_NORMAL, NULL);
    if (*reader == INVALID_HANDLE_VALUE) {
        *reader = NULL;
        CloseHandle(*writer);
        *writer = NULL;
        return false;
    }
    return true;
}

static void require_blocked_input(struct mesh_terminal_worker *w, HANDLE reader)
{
    uint8_t block[4096];
    memset(block, 'b', sizeof(block));
    bool stalled = false, accounted = true;
    uint64_t initial = w->bytes_in;
    ULONGLONG worst = 0;
    for (int i = 0; i < 32 && !stalled; i++) {
        uint64_t before = w->bytes_in;
        ULONGLONG start = GetTickCount64();
        struct zcl_result r = mesh_terminal_worker_input(w, block,
                                                         sizeof(block), 1001);
        ULONGLONG elapsed = GetTickCount64() - start;
        if (elapsed > worst)
            worst = elapsed;
        accounted = accounted && w->bytes_in >= before &&
            w->bytes_in - before <= sizeof(block);
        if (r.ok)
            accounted = accounted && w->bytes_in - before == sizeof(block);
        else {
            stalled = r.code == MESH_TERMINAL_WORKER_ERR_IO &&
                strstr(r.message, "pty input stalled (wrote ") == r.message &&
                elapsed >= 900;
            break;
        }
    }
    expect(stalled && worst < 4000,
        "undrained fixture pipe reaches cancellation and settles within 4 seconds");
    DWORD available = 0;
    bool observed = PeekNamedPipe(reader, NULL, 0, NULL, &available, NULL) != 0;
    printf("mesh_terminal_worker_windows: undrained fixture slowest=%llu ms, buffered=%lu, accounted=%llu\n",
        (unsigned long long)worst, (unsigned long)available,
        (unsigned long long)(w->bytes_in - initial));
    expect(accounted && observed && available != 0 &&
        w->bytes_in - initial == available && w->running,
        "cancelled input accounting matches bytes retained by undrained fixture reader");
}

static void test_blocked_input_lifetime(const char *shell, const char *workdir)
{
    struct session *s = calloc(1, sizeof(*s));
    expect(s != NULL, "blocked input fixture allocation");
    if (!s)
        return;
    struct mesh_terminal_worker_config cfg = base_config(shell, workdir);
    cfg.lifetime_seconds = 5;
    struct zcl_result r = mesh_terminal_worker_spawn(&cfg, 1000, &s->worker);
    expect(r.ok, "blocked input fixture real ConPTY spawn");
    if (!r.ok) {
        free(s);
        return;
    }
    HANDLE writer = NULL, reader = NULL;
    bool connected = blocked_input_pipe(&writer, &reader);
    expect(connected, "blocked input fixture pipe connects without a draining reader");
    if (connected) {
        HANDLE original = s->worker.win_input_write;
        s->worker.win_input_write = writer;
        require_blocked_input(&s->worker, reader);
        s->worker.win_input_write = original;
        CloseHandle(writer);
        CloseHandle(reader);
        ULONGLONG start = GetTickCount64();
        bool ended = mesh_terminal_worker_budget_exceeded(&s->worker, 1005);
        expect(ended && GetTickCount64() - start < 4000 && !s->worker.running &&
            s->worker.close_reason == MESH_TERMINAL_CLOSE_LIFETIME_LIMIT &&
            !s->worker.win_process && !s->worker.win_job && !s->worker.win_pc &&
            !s->worker.win_input_write && !s->worker.win_output_read,
            "after cancelled fixture input real worker lifetime cleanup stays bounded and releases handles");
    }
    mesh_terminal_worker_kill(&s->worker);
    free(s);
}

static bool exact_child_args(int argc, wchar_t **argv)
{
    static const wchar_t *const expected[] = { L"--worker-argv-child",
        L"two words", L"", L"quote\"value", L"space tail\\",
        L"slash\\\"quote", L"caf\u00e9-\u96ea" };
    if (argc != 8)
        return false;
    for (int i = 1; i < argc; i++)
        if (wcscmp(argv[i], expected[i - 1]))
            return false;
    return true;
}

/* Parse wide command-line data directly: the CRT's narrow argv may use ACP. */
static int argv_child(void)
{
    int argc = 0;
    wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv)
        return 91;
    if (argc > 1 && !wcscmp(argv[1], L"--worker-count-child")) {
        bool ok = argc == MESH_TERMINAL_WORKER_ARGV_MAX;
        for (int i = 2; i < argc; i++)
            ok = ok && !wcscmp(argv[i], L"x");
        LocalFree(argv);
        puts(ok ? "MAX_ARGV_OK" : "MAX_ARGV_BAD");
        fflush(stdout);
        return ok ? 38 : 93;
    }
    bool child = argc > 1 && !wcscmp(argv[1], L"--worker-argv-child");
    bool exact = child && exact_child_args(argc, argv);
    LocalFree(argv);
    if (!child)
        return -1;
    puts(exact ? "EXACT_ARGV_OK" : "EXACT_ARGV_BAD");
    fflush(stdout);
    return exact ? 37 : 92;
}

static bool config_refused(struct mesh_terminal_worker_config *cfg)
{
    struct mesh_terminal_worker w;
    struct zcl_result r = mesh_terminal_worker_spawn(cfg, (int64_t)time(NULL), &w);
    bool refused = !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_CONFIG &&
        !w.running && !w.win_process && !w.win_job && !w.win_pc;
    if (r.ok)
        mesh_terminal_worker_kill(&w);
    return refused;
}

static void test_argv_launch(struct mesh_terminal_worker_config *cfg,
                             const char *marker, int code, const char *label)
{
    struct session *s = calloc(1, sizeof(*s));
    expect(s != NULL, "argv fixture allocation");
    if (!s)
        return;
    struct zcl_result r = mesh_terminal_worker_spawn(cfg, (int64_t)time(NULL), &s->worker);
    bool exact = r.ok && pump(s, 5000, marker);
    ULONGLONG until = GetTickCount64() + 5000;
    while (r.ok && mesh_terminal_worker_alive(&s->worker) && GetTickCount64() < until)
        (void)pump(s, 50, NULL);
    expect(exact && !s->worker.running && s->worker.exit_code == code &&
           s->worker.close_reason == MESH_TERMINAL_CLOSE_WORKER_EXITED, label);
    mesh_terminal_worker_kill(&s->worker);
    free(s);
}

static void test_argv_refusals(struct mesh_terminal_worker_config cfg,
                               const char *self)
{
    const char *bad[] = { self, "\xc0\xaf", NULL };
    cfg.argv = bad;
    expect(config_refused(&cfg), "invalid UTF-8 argv refuses before creating a process");
    const char *empty[] = { NULL };
    cfg.argv = empty;
    expect(config_refused(&cfg), "empty argv refuses before creating a process");
    const char *many[MESH_TERMINAL_WORKER_ARGV_MAX + 2];
    many[0] = self;
    for (size_t i = 1; i <= MESH_TERMINAL_WORKER_ARGV_MAX; i++)
        many[i] = "x";
    many[MESH_TERMINAL_WORKER_ARGV_MAX + 1] = NULL;
    cfg.argv = many;
    expect(config_refused(&cfg), "excess argument count refuses before creating a process");
    char *large = malloc(32768);
    expect(large != NULL, "oversize argv fixture allocation");
    if (large) {
        memset(large, 'x', 32767); large[32767] = 0;
        const char *oversize[] = { self, large, NULL };
        cfg.argv = oversize;
        expect(config_refused(&cfg), "oversize argv bytes refuse before creating a process");
        memset(large, '"', 17000); large[17000] = 0;
        expect(config_refused(&cfg), "quote expansion beyond the UTF-16 limit refuses before creating a process");
        free(large);
    }
    const char *relative[] = { "cmd.exe", NULL };
    cfg.argv = relative;
    expect(config_refused(&cfg), "relative requested image refuses before creating a process");
}

static void test_exact_argv(const char *shell, const char *workdir)
{
    wchar_t wide[MAX_PATH];
    char self[MAX_PATH * 4];
    DWORD n = GetModuleFileNameW(NULL, wide, MAX_PATH);
    bool have_self = n > 0 && n < MAX_PATH &&
        WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, -1,
                            self, sizeof(self), NULL, NULL) > 0;
    expect(have_self, "argv fixture has an absolute UTF-8 image");
    if (!have_self)
        return;
    const char *args[] = { self, "--worker-argv-child", "two words", "",
        "quote\"value", "space tail\\", "slash\\\"quote", "caf\xc3\xa9-\xe9\x9b\xaa", NULL };
    struct mesh_terminal_worker_config cfg = base_config(shell, workdir);
    cfg.argv = args;
    test_argv_launch(&cfg, "EXACT_ARGV_OK", 37,
        "explicit image receives exact spaces, empty, quotes, slashes and Unicode argv and exit");

    const char *maximum[MESH_TERMINAL_WORKER_ARGV_MAX + 1];
    maximum[0] = self;
    maximum[1] = "--worker-count-child";
    for (size_t i = 2; i < MESH_TERMINAL_WORKER_ARGV_MAX; i++)
        maximum[i] = "x";
    maximum[MESH_TERMINAL_WORKER_ARGV_MAX] = NULL;
    cfg.argv = maximum;
    test_argv_launch(&cfg, "MAX_ARGV_OK", 38,
        "exact maximum argument count is admitted intact");
    test_argv_refusals(cfg, self);
}

static void test_exit_259(const char *shell, const char *workdir, bool budget_first)
{
    struct mesh_terminal_worker w;
    struct mesh_terminal_worker_config cfg = base_config(shell, workdir);
    const char *argv[] = {shell, "/d", "/c", "exit /b 259", NULL};
    cfg.argv = argv;
    int64_t now = (int64_t)time(NULL);
    struct zcl_result r = mesh_terminal_worker_spawn(&cfg, now, &w);
    expect(r.ok, "exit259: spawn");
    if (!r.ok)
        return;
    DWORD code = 0;
    DWORD waited = WaitForSingleObject((HANDLE)w.win_process, 5000);
    bool queried = GetExitCodeProcess((HANDLE)w.win_process, &code) != 0;
    printf("exit259: observed wait=%lu code=%lu budget_first=%d\n",
           (unsigned long)waited, (unsigned long)code, budget_first);
    expect(waited == WAIT_OBJECT_0 && queried && code == 259,
           "exit259: native process really exited with 259");
    if (budget_first)
        expect(mesh_terminal_worker_budget_exceeded(&w, now + 121),
               "exit259: budget poll observes exited process");
    else
        expect(!mesh_terminal_worker_alive(&w),
               "exit259: alive poll observes exited process");
    expect(!w.running && w.exit_code == 259 &&
               w.close_reason == MESH_TERMINAL_CLOSE_WORKER_EXITED,
           "exit259: natural exit takes precedence over expired lifetime");
    mesh_terminal_worker_kill(&w);
    expect(!w.win_process && !w.win_job && !w.win_pc &&
               !w.win_input_write && !w.win_output_read,
           "exit259: cleanup closes every worker handle");
}
int main(void)
{
    int child = argv_child();
    if (child >= 0)
        return child;
    char workdir[MAX_PATH], cmd[MAX_PATH], pwsh[MAX_PATH];
    if (!make_workdir(workdir, sizeof(workdir)) ||
        !system_path("\\System32\\cmd.exe", cmd, sizeof(cmd))) {
        fputs("mesh_terminal_worker_windows: environment unavailable\n", stderr);
        return 1;
    }
    test_exit_259(cmd, workdir, false);
    test_exit_259(cmd, workdir, true);
    int rc = roundtrip(cmd, workdir, "set /a 123456*7\r\n", "cmd.exe command");
    if (rc != 0)
        return rc;
    test_tree_dies(cmd, workdir);
    test_budgets(cmd, workdir);
    test_output_budget(cmd, workdir);
    test_input_bounded(cmd, workdir);
    test_blocked_input_lifetime(cmd, workdir);
    test_exact_argv(cmd, workdir);
    if (system_path("\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", pwsh,
                    sizeof(pwsh)) &&
        GetFileAttributesA(pwsh) != INVALID_FILE_ATTRIBUTES) {
        rc = roundtrip(pwsh, workdir, "Write-Output (123456*7)\r\n",
                       "powershell.exe command");
        if (rc == 1)
            g_failures++;
    }
    RemoveDirectoryA(workdir);
    printf("mesh_terminal_worker_windows: %d failures\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}

#else
typedef int mesh_terminal_worker_windows_acceptance_not_built;
#endif
