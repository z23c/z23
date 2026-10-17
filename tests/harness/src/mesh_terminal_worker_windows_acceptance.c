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
#if defined(ZCL_TESTING) && defined(MESH_TERMINAL_WORKER_CLOSE_FAILURE_FIXTURE)
static bool fail_close_thread;
static bool fail_read_cancel;
static bool fail_job_quit;
static unsigned fixture_process_limit = 32;
bool mesh_terminal_worker_testing_close_thread_failure(void)
{
    return fail_close_thread;
}
unsigned mesh_terminal_worker_testing_process_limit(void)
{
    return fixture_process_limit;
}
bool mesh_terminal_worker_testing_read_cancel_failure(void)
{
    return fail_read_cancel;
}
bool mesh_terminal_worker_testing_job_quit_failure(void)
{
    return fail_job_quit;
}
#endif

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
        if (got == 0) {
            ULONGLONG now = GetTickCount64();
            DWORD left = now < deadline ? (DWORD)(deadline - now) : 0;
            HANDLE ready = (HANDLE)mesh_terminal_worker_output_wait_handle(&s->worker);
            if (!ready || WaitForSingleObject(ready, left) == WAIT_FAILED)
                return false;
        }
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

static int output_blocks(unsigned blocks)
{
    char block[1024];
    memset(block, 'x', sizeof(block));
    for (unsigned i = 0; i < blocks; i++)
        if (fwrite(block, 1, sizeof(block), stdout) != sizeof(block)) return 95;
    puts("OUTPUT_DRAIN_COMPLETE");
    fflush(stdout);
    return 42;
}

static bool spawn_output_holder(bool new_console)
{
    wchar_t image[MAX_PATH], line[MAX_PATH + 64];
    DWORD n = GetModuleFileNameW(NULL, image, MAX_PATH);
    if (!n || n >= MAX_PATH) return false;
    int count = swprintf(line, sizeof(line) / sizeof(line[0]),
                        L"\"%ls\" --worker-sleep-child", image);
    if (count < 0 || (size_t)count >= sizeof(line) / sizeof(line[0])) return false;
    STARTUPINFOW startup = {.cb = sizeof(startup)};
    PROCESS_INFORMATION child = {0};
    if (!CreateProcessW(image, line, NULL, NULL, FALSE,
        new_console ? CREATE_NEW_CONSOLE : 0, NULL, NULL, &startup, &child)) return false;
    CloseHandle(child.hThread); CloseHandle(child.hProcess);
    return true;
}

#if defined(ZCL_TESTING) && defined(MESH_TERMINAL_WORKER_CLOSE_FAILURE_FIXTURE)
static unsigned retained_failure_count(bool watch)
{
    return watch ? mesh_terminal_worker_testing_retained_watches() :
                   mesh_terminal_worker_testing_retained_reads();
}

static bool teardown_fields_closed(const struct mesh_terminal_worker *w)
{
    return !w->win_output_read && !w->win_output_state && !w->win_process && !w->win_job &&
        !w->win_membership_state && !w->win_pc && !w->win_close_state;
}

static int teardown_failure_child(bool watch)
{
    char shell[MAX_PATH], cwd[MAX_PATH];
    if (!system_path("\\System32\\cmd.exe", shell, sizeof(shell)) ||
        !GetCurrentDirectoryA(sizeof(cwd), cwd)) return 97;
    struct mesh_terminal_worker_config cfg = base_config(shell, cwd);
    struct mesh_terminal_worker w = {0}, refused = {0};
    struct zcl_result r = mesh_terminal_worker_spawn(&cfg, time(NULL), &w);
    if (!r.ok) return 98;
    unsigned before = retained_failure_count(watch);
    fail_read_cancel = !watch;
    fail_job_quit = watch;
    ULONGLONG began = GetTickCount64();
    mesh_terminal_worker_kill(&w);
    ULONGLONG took = GetTickCount64() - began;
    fail_read_cancel = false;
    fail_job_quit = false;
    r = mesh_terminal_worker_spawn(&cfg, time(NULL), &refused);
    bool safe = !r.ok && r.code == MESH_TERMINAL_WORKER_ERR_PTY &&
        retained_failure_count(watch) == before + 1 && took < 4500 && teardown_fields_closed(&w);
    puts(safe ? "TEARDOWN_RETAIN_OK" : "TEARDOWN_RETAIN_BAD");
    fflush(stdout);
    return safe ? (watch ? 40 : 39) : 99;
}
#endif

static int output_child_mode(int argc, wchar_t **argv)
{
    if (argc != 2) return -1;
#if defined(ZCL_TESTING) && defined(MESH_TERMINAL_WORKER_CLOSE_FAILURE_FIXTURE)
    if (!wcscmp(argv[1], L"--worker-read-cancel-child")) return teardown_failure_child(false);
    if (!wcscmp(argv[1], L"--worker-job-quit-child")) return teardown_failure_child(true);
#endif
    if (!wcscmp(argv[1], L"--worker-sleep-child")) { Sleep(30000); return 0; }
    if (!wcscmp(argv[1], L"--worker-held-output-child"))
        return spawn_output_holder(false) ? output_blocks(128) : 96;
    if (!wcscmp(argv[1], L"--worker-family-child")) {
        if (!spawn_output_holder(true)) return 96;
        puts("CENSUS_FAMILY_READY"); fflush(stdout); Sleep(30000); return 0;
    }
    if (!wcscmp(argv[1], L"--worker-output-child")) return output_blocks(128);
    if (!wcscmp(argv[1], L"--worker-flood-child")) return output_blocks(32768);
    return -1;
}

/* Parse wide command-line data directly: the CRT's narrow argv may use ACP. */
static int argv_child(void)
{
    int argc = 0;
    wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return 91;
    int mode = output_child_mode(argc, argv);
    if (mode >= 0) { LocalFree(argv); return mode; }
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
static void test_output_readiness(const char *shell, const char *workdir)
{
    struct session s = {0};
    struct mesh_terminal_worker_config cfg = base_config(shell, workdir);
    struct zcl_result r = mesh_terminal_worker_spawn(&cfg, time(NULL), &s.worker);
    expect(r.ok, "output readiness worker launches");
    if (!r.ok) return;
    expect(mesh_terminal_worker_output_wait_handle(&s.worker) != 0,
           "worker exposes a borrowed output event");
    expect(send_line(&s, "echo EVENT_OUTPUT_READY\r\n") &&
           pump(&s, 5000, "EVENT_OUTPUT_READY"),
           "output event wakes and drains a real ConPTY");
    ULONGLONG begin = GetTickCount64();
    mesh_terminal_worker_kill(&s.worker);
    expect(GetTickCount64() - begin < 4000 &&
           mesh_terminal_worker_output_wait_handle(&s.worker) == 0 &&
           s.worker.win_output_state == NULL && s.worker.win_output_read == NULL,
           "pending output cancellation settles before state release");
}

static bool fixture_self_image(char *self, size_t cap)
{
    wchar_t wide[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, wide, MAX_PATH);
    return len && len < MAX_PATH && WideCharToMultiByte(CP_UTF8,
        WC_ERR_INVALID_CHARS, wide, -1, self, (int)cap, NULL, NULL) > 0;
}

static void require_close_thread_retry(struct mesh_terminal_worker *w, bool held)
{
#if defined(ZCL_TESTING) && defined(MESH_TERMINAL_WORKER_CLOSE_FAILURE_FIXTURE)
    if (!held) {
        fail_close_thread = true;
        struct zcl_result refused = mesh_terminal_worker_begin_output_close(w);
        expect(!refused.ok && !w->win_pc && w->win_close_state && w->win_output_read &&
            !mesh_terminal_worker_close_wait_handle(w),
            "failed close-thread creation retains private console and readable output ownership");
        fail_close_thread = false;
    }
#else
    (void)w; (void)held;
#endif
}

static bool drain_worker_to_eof(struct mesh_terminal_worker *w, ULONGLONG deadline)
{
    while (GetTickCount64() < deadline) {
        uint8_t bytes[257];
        size_t got = 0;
        struct zcl_result r = mesh_terminal_worker_output(w, bytes, sizeof(bytes), &got, time(NULL));
        HANDLE ready = (HANDLE)mesh_terminal_worker_output_wait_handle(w);
        if (!r.ok) return false;
        if (!ready) return true;
        if (!got) {
            ULONGLONG now = GetTickCount64();
            DWORD left = now < deadline ? (DWORD)(deadline - now) : 0;
            if (WaitForSingleObject(ready, left) == WAIT_FAILED) break;
        }
    }
    return false;
}

static void require_output_eof(struct mesh_terminal_worker *w, bool held)
{
    expect(WaitForSingleObject((HANDLE)w->win_process, 5000) == WAIT_OBJECT_0,
           "large final burst child exits naturally");
    DWORD pids[PIDS_MAX];
    size_t count = job_pids(w, pids);
    if (held) expect(count > 0, "real descendant retains the console after its parent exits");
    require_close_thread_retry(w, held);
    struct zcl_result closing = mesh_terminal_worker_begin_output_close(w);
    HANDLE closer = (HANDLE)mesh_terminal_worker_close_wait_handle(w);
    expect(closing.ok && closer, "worker starts its owned console close while output remains readable");
    if (!closing.ok || !closer) return;
    struct zcl_result repeated = mesh_terminal_worker_begin_output_close(w);
    expect(repeated.ok && mesh_terminal_worker_close_wait_handle(w) == (uintptr_t)closer,
           "repeated begin-close preserves one closer and its original budget");
    bool eof = drain_worker_to_eof(w, GetTickCount64() + 3000);
    if (!eof) mesh_terminal_worker_kill(w); /* Closing read breaks a stuck conhost write. */
    bool settled = eof && WaitForSingleObject(closer, 1000) == WAIT_OBJECT_0;
    expect(eof && settled, "real ConPTY close drains and exposes settled EOF without a dangling read");
    for (size_t i = 0; i < count; i++)
        expect(process_gone(pids[i]), "output close removes a descendant retaining the console");
}

static void require_output_burst(struct mesh_terminal_worker *w)
{
    ULONGLONG deadline = GetTickCount64() + 10000;
    uint64_t total = 0;
    char tail[512] = {0};
    bool marker = false, ok = true;
    while (!marker && GetTickCount64() < deadline) {
        uint8_t bytes[257];
        size_t got = 0;
        struct zcl_result r = mesh_terminal_worker_output(w, bytes, sizeof(bytes), &got, time(NULL));
        if (!r.ok) { ok = false; break; }
        total += got;
        memmove(tail, tail + got, sizeof(tail) - got - 1);
        memcpy(tail + sizeof(tail) - got - 1, bytes, got);
        tail[sizeof(tail) - 1] = 0;
        if (strstr(tail, DSR_QUERY)) {
            (void)mesh_terminal_worker_input(w, (const uint8_t *)DSR_REPLY,
                                            sizeof(DSR_REPLY) - 1, time(NULL));
            memset(tail, ' ', sizeof(tail) - 1);
        }
        marker = strstr(tail, "OUTPUT_DRAIN_COMPLETE") != NULL;
        if (!got) {
            ULONGLONG now = GetTickCount64();
            DWORD left = now < deadline ? (DWORD)(deadline - now) : 0;
            HANDLE event = (HANDLE)mesh_terminal_worker_output_wait_handle(w);
            if (WaitForSingleObject(event, left) == WAIT_FAILED) { ok = false; break; }
        }
    }
    expect(ok && marker && total >= 131072 && total == w->bytes_out,
           "event-driven small reads drain more than pipe capacity with exact accounting");
}

static void test_output_burst(const char *shell, const char *workdir, bool held)
{
    char self[MAX_PATH * 4];
    if (!fixture_self_image(self, sizeof(self))) {
        expect(false, "burst fixture resolves its own image"); return;
    }
    const char *args[] = { self, held ? "--worker-held-output-child" : "--worker-output-child", NULL };
    struct mesh_terminal_worker_config cfg = base_config(shell, workdir);
    cfg.argv = args;
    struct mesh_terminal_worker w = {0};
    struct zcl_result r = mesh_terminal_worker_spawn(&cfg, time(NULL), &w);
    expect(r.ok, "burst output worker launches");
    if (!r.ok) return;
    require_output_burst(&w);
    require_output_eof(&w, held);
    mesh_terminal_worker_kill(&w);
    mesh_terminal_worker_kill(&w);
    expect(!w.win_close_state && !w.win_output_state && !w.win_pc,
           "repeated kill releases settled close and read state exactly once");
}

static void test_output_cancel(const char *shell, const char *workdir, bool lifetime)
{
    char self[MAX_PATH * 4];
    if (!fixture_self_image(self, sizeof(self))) { expect(false, "flood image resolves"); return; }
    const char *args[] = {self, "--worker-flood-child", NULL};
    struct mesh_terminal_worker_config cfg = base_config(shell, workdir);
    cfg.argv = args; cfg.lifetime_seconds = 1;
    struct mesh_terminal_worker w = {0};
    struct zcl_result r = mesh_terminal_worker_spawn(&cfg, time(NULL), &w);
    expect(r.ok, "undrained output producer launches");
    if (!r.ok) return;
    HANDLE ready = (HANDLE)mesh_terminal_worker_output_wait_handle(&w);
    expect(ready && WaitForSingleObject(ready, 2000) == WAIT_OBJECT_0 &&
        WaitForSingleObject((HANDLE)w.win_process, 250) == WAIT_TIMEOUT,
        "real output producer remains live while output is not consumed");
    ULONGLONG began = GetTickCount64();
    if (lifetime) {
        expect(mesh_terminal_worker_budget_exceeded(&w, w.started_unix + 2) &&
            w.close_reason == MESH_TERMINAL_CLOSE_LIFETIME_LIMIT,
            "lifetime budget ends an undrained output producer by name");
    } else {
        r = mesh_terminal_worker_begin_output_close(&w);
        expect(r.ok, "caller starts close with undrained output");
    }
    mesh_terminal_worker_kill(&w);
    mesh_terminal_worker_kill(&w);
    expect(GetTickCount64() - began < 4500 && !w.win_output_read && !w.win_output_state &&
        !w.win_close_state && !w.win_pc && !w.win_job && !w.win_process,
        "stop or deadline cancels undrained output and settles all owned resources within one close budget");
}

#if defined(ZCL_TESTING) && defined(MESH_TERMINAL_WORKER_CLOSE_FAILURE_FIXTURE)
static bool job_observed_empty(HANDLE job)
{
    union {
        JOBOBJECT_BASIC_PROCESS_ID_LIST list;
        uint8_t bytes[sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) + PIDS_MAX * sizeof(ULONG_PTR)];
    } members = {0};
    return QueryInformationJobObject(job, JobObjectBasicProcessIdList, &members,
        sizeof(members), NULL) && members.list.NumberOfAssignedProcesses == 0;
}

static void test_all_member_census(const char *shell, const char *workdir)
{
    char self[MAX_PATH * 4];
    if (!fixture_self_image(self, sizeof(self))) { expect(false, "census image resolves"); return; }
    const char *args[] = {self, "--worker-family-child", NULL};
    struct session s = {0};
    struct mesh_terminal_worker_config cfg = base_config(shell, workdir);
    cfg.argv = args;
    struct zcl_result r = mesh_terminal_worker_spawn(&cfg, time(NULL), &s.worker);
    expect(r.ok, "native console family launches under worker Job");
    if (!r.ok) return;
    expect(pump(&s, 5000, "CENSUS_FAMILY_READY"), "console family reaches child-created marker");
    HANDLE changed = (HANDLE)mesh_terminal_worker_budget_wait_handle(&s.worker);
    expect(changed && WaitForSingleObject(changed, 1000) == WAIT_OBJECT_0,
           "real Job membership changes wake the worker without an idle tick");
    DWORD pids[PIDS_MAX];
    size_t count = job_pids(&s.worker, pids);
    printf("mesh_terminal_worker_windows: ordinary Job assigned members=%zu; protected OS-host coverage is separate\n", count);
    expect(count >= 2 && count <= 32, "all-member Job census sees the real native console family");
    HANDLE observed = NULL;
    bool retained = DuplicateHandle(GetCurrentProcess(), (HANDLE)s.worker.win_job,
        GetCurrentProcess(), &observed, JOB_OBJECT_QUERY, FALSE, 0) != 0;
    expect(retained, "fixture retains a read-only observation lifetime for the Job");
    fixture_process_limit = count > 1 ? (unsigned)count - 1 : 1;
    bool ended = mesh_terminal_worker_budget_exceeded(&s.worker, time(NULL));
    fixture_process_limit = 32;
    expect(ended && s.worker.close_reason == MESH_TERMINAL_CLOSE_SESSION_LOST,
           "all-member census over fixture-only limit ends session by name");
    mesh_terminal_worker_kill(&s.worker);
    for (size_t i = 0; i < count; i++) expect(process_gone(pids[i]), "census cleanup removes each observed Job member");
    expect(retained && job_observed_empty(observed), "over-budget native Job is empty after cleanup");
    expect(!mesh_terminal_worker_budget_wait_handle(&s.worker) && !s.worker.win_membership_state,
           "census cleanup settles and releases the Job wake owner");
    if (observed) CloseHandle(observed);
}

static void test_teardown_retention(const char *shell, const char *workdir, bool watch)
{
    char self[MAX_PATH * 4];
    if (!fixture_self_image(self, sizeof(self))) { expect(false, "cancel-failure image resolves"); return; }
    const char *args[] = {self, watch ? "--worker-job-quit-child" : "--worker-read-cancel-child", NULL};
    struct mesh_terminal_worker_config cfg = base_config(shell, workdir);
    cfg.argv = args;
    test_argv_launch(&cfg, "TEARDOWN_RETAIN_OK", watch ? 40 : 39,
        watch ? "isolated Job quit failure retains live handle/state and refuses new workers" :
                "isolated cancellation failure retains pending heap and refuses new workers within close budget");
}
#endif

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
    test_output_readiness(cmd, workdir);
    test_output_burst(cmd, workdir, false);
    test_output_burst(cmd, workdir, true);
    test_output_cancel(cmd, workdir, false);
    test_output_cancel(cmd, workdir, true);
#if defined(ZCL_TESTING) && defined(MESH_TERMINAL_WORKER_CLOSE_FAILURE_FIXTURE)
    test_all_member_census(cmd, workdir);
    test_teardown_retention(cmd, workdir, false);
    test_teardown_retention(cmd, workdir, true);
#endif
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
