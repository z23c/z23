/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Native ConPTY worker custody, bounded I/O and Job lifecycle.
 * Public dispatch and POSIX implementations live in mesh_terminal_worker.c. */
#if defined(_WIN32)
/* ConPTY needs NTDDI_VERSION at NTDDI_WIN10_RS5 (0x0A000006) or newer, which
 * <sdkddkver.h> does not derive from _WIN32_WINNT alone. Pin it here (as
 * logical_cpu.c pins its own floor) so the standalone check-windows-cross-syntax
 * compile sees the real API surface, and refuse a lower floor set elsewhere. */
#if !defined(NTDDI_VERSION)
#define NTDDI_VERSION 0x0A000006
#elif NTDDI_VERSION < 0x0A000006
#error "mesh_terminal_worker's Windows arm requires NTDDI_WIN10_RS5 (ConPTY) or newer"
#endif
#if !defined(_WIN32_WINNT)
#define _WIN32_WINNT 0x0A00
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include "platform/process_lifecycle.h"

#include <bcrypt.h>
#include <sddl.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "util/safe_alloc.h" /* zcl_malloc: checked, logged OOM */

#include "mesh_terminal_worker_internal.h"
#include "platform/os_proc.h"
#define MESH_TERMINAL_WORKER_MAX_PROCESSES 32u


/* Every path this worker widens is bounded well under MAX_PATH-class
 * limits by spawn's own refusal below; a fixed stack buffer needs no
 * heap and adds no failure mode beyond "too long", which spawn already
 * refuses by name. */
#define MESH_TERMINAL_WIN_PATH_MAX 512u

/* Windows path shape check for the working directory, mirroring the POSIX
 * arm's absolute-path refusal: a drive-letter root ("C:\" or "C:/") or a
 * UNC root ("\\server\share"). The shell image is judged by the stricter
 * mesh_terminal_shell_path_valid. */
static bool win_path_is_absolute(const char *path)
{
    if (!path || !path[0])
        return false;
    if (path[0] == '\\' && path[1] == '\\')
        return true;
    bool letter = (path[0] >= 'A' && path[0] <= 'Z') ||
                  (path[0] >= 'a' && path[0] <= 'z');
    return letter && path[1] == ':' && (path[2] == '\\' || path[2] == '/');
}

static bool win_widen(const char *utf8, wchar_t *out, size_t out_count)
{
    if (!utf8 || !out || out_count == 0)
        return false;
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8, -1, out,
                                (int)out_count);
    return n > 0;
}

/* Append one "KEY=VALUE\0" entry to a CreateProcessW environment block;
 * silently a no-op past `cap` so a caller that sized the block generously
 * (as spawn does) never overruns it. Returns the offset of the NEXT free
 * slot. */
static size_t win_env_put(wchar_t *block, size_t cap, size_t off,
                          const wchar_t *key, const wchar_t *value)
{
    size_t klen = wcslen(key), vlen = wcslen(value);
    if (off + klen + 1u + vlen + 1u > cap)
        return off;
    wmemcpy(block + off, key, klen);
    off += klen;
    block[off++] = L'=';
    wmemcpy(block + off, value, vlen);
    off += vlen;
    block[off++] = L'\0';
    return off;
}

static void tw_win_close(void **handle)
{
    if (!handle)
        return;
    if (*handle && *handle != INVALID_HANDLE_VALUE)
        CloseHandle((HANDLE)*handle);
    *handle = NULL;
}

/* The pipe buffer both directions share: generous headroom over one wire
 * DATA frame's payload (MESH_TERMINAL_DATA_PAYLOAD_MAX, 3072 bytes) so an
 * ordinary mesh_terminal_worker_input() write completes without the shell
 * having to drain first. */
#define MESH_TERMINAL_WIN_PIPE_BYTES 65536ul

/* How long one input write may wait for a shell that has stopped reading
 * its console, mirroring the POSIX arm's poll(POLLOUT, 1000 ms). */
#define MESH_TERMINAL_WIN_WRITE_WAIT_MS 1000u

static volatile LONG tw_win_close_poison;
static volatile LONG tw_win_retained_watch_count;

struct tw_win_job_watch {
    HANDLE port, event, thread;
};

static DWORD WINAPI tw_win_job_watch_thread(void *opaque)
{
    struct tw_win_job_watch *watch = opaque;
    HANDLE port = watch->port; /* Immutable until the watcher has joined. */
    DWORD message = 0;
    ULONG_PTR key = 0;
    OVERLAPPED *pid = NULL;
    while (GetQueuedCompletionStatus(port, &message, &key, &pid, INFINITE)) {
        if (key == UINTPTR_MAX) break;
        (void)SetEvent(watch->event); /* A wake hint, never a process count. */
    }
    return 0;
}

static void tw_win_job_watch_close(struct tw_win_job_watch *watch, ULONGLONG deadline)
{
    if (!watch) return;
    if (watch->thread) {
        BOOL posted;
#if defined(ZCL_TESTING) && defined(MESH_TERMINAL_WORKER_CLOSE_FAILURE_FIXTURE)
        if (mesh_terminal_worker_testing_job_quit_failure()) {
            SetLastError(ERROR_ACCESS_DENIED); posted = FALSE;
        } else
#endif
            posted = PostQueuedCompletionStatus(watch->port, 0, UINTPTR_MAX, NULL);
        if (!posted) {
            DWORD error = GetLastError();
            InterlockedIncrement(&tw_win_retained_watch_count);
            InterlockedExchange(&tw_win_close_poison, 1);
            fprintf(stderr, "terminal worker: Job wake quit failed error=%lu; retaining live port and private state, refusing new workers\n", error);
            return; /* Never close/recycle a handle a late watcher may use. */
        }
        ULONGLONG now = GetTickCount64();
        ULONGLONG left = deadline ? (now < deadline ? deadline - now : 0) : 2000;
        DWORD wait = left < 2000 ? (DWORD)left : 2000;
        if (WaitForSingleObject(watch->thread, wait) != WAIT_OBJECT_0) {
            InterlockedIncrement(&tw_win_retained_watch_count);
            InterlockedExchange(&tw_win_close_poison, 1);
            fprintf(stderr, "terminal worker: Job wake thread did not settle; retaining private state and refusing new workers\n");
            return;
        }
        CloseHandle(watch->thread);
    }
    if (watch->port) CloseHandle(watch->port);
    if (watch->event) CloseHandle(watch->event);
    free(watch);
}

static struct tw_win_job_watch *tw_win_job_watch_open(HANDLE job)
{
    struct tw_win_job_watch *watch = zcl_calloc(1, sizeof(*watch), "terminal-job-wake");
    if (!watch) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }
    watch->port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
    watch->event = CreateEventW(NULL, TRUE, FALSE, NULL);
    JOBOBJECT_ASSOCIATE_COMPLETION_PORT association = {
        .CompletionKey = (void *)(uintptr_t)1, .CompletionPort = watch->port};
    if (watch->port && watch->event && SetInformationJobObject(job,
        JobObjectAssociateCompletionPortInformation, &association, sizeof(association)))
        watch->thread = CreateThread(NULL, 0, tw_win_job_watch_thread, watch, 0, NULL);
    if (watch->thread) return watch;
    DWORD error = GetLastError();
    tw_win_job_watch_close(watch, 0);
    SetLastError(error);
    return NULL;
}

/* Kill-on-close Job Object holding the shell and everything it starts.
 * Closing the last handle, or TerminateJobObject, ends the whole tree, so a
 * shell that forks and exits leaves nothing behind. The live-process limit
 * is the POSIX arm's census budget. */
static HANDLE tw_win_job_create(void)
{
    HANDLE job = CreateJobObjectW(NULL, NULL);
    if (!job)
        return NULL;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
    memset(&limits, 0, sizeof(limits));
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    limits.BasicLimitInformation.ActiveProcessLimit =
        MESH_TERMINAL_WORKER_MAX_PROCESSES;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                 &limits, sizeof(limits))) {
        CloseHandle(job);
        return NULL;
    }
    return job;
}

/* SDDL granting full access to the current user and nobody else. */
static bool tw_win_owner_sddl(wchar_t *out, size_t cap)
{
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    union {
        TOKEN_USER user;
        char raw[256];
    } info;
    DWORD got = 0;
    wchar_t *sid_text = NULL;
    bool ok = GetTokenInformation(token, TokenUser, &info, sizeof(info),
                                  &got) &&
              ConvertSidToStringSidW(info.user.User.Sid, &sid_text) &&
              swprintf(out, cap, L"D:P(A;;GA;;;%ls)", sid_text) > 0;
    if (sid_text)
        LocalFree(sid_text);
    CloseHandle(token);
    return ok;
}

/* A pipe name nobody can predict: process id plus 64 bits from the system
 * generator. */
static bool tw_win_pipe_name(wchar_t *name, size_t cap)
{
    unsigned long random[2];
    if (BCryptGenRandom(NULL, (PUCHAR)random, sizeof(random),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        return false;
    return swprintf(name, cap, L"\\\\.\\pipe\\z23-terminal-%lu-%08lx%08lx",
                    GetCurrentProcessId(), random[0], random[1]) > 0;
}

/* The shell's input pipe: a named pipe opened overlapped on OUR end, so a
 * write can be abandoned after a bounded wait (an anonymous pipe cannot be
 * opened overlapped). The shell's end is a plain synchronous read handle.
 * The pipe has an unpredictable name, one instance, no remote client, and a
 * DACL that admits only the current user. */
static bool tw_win_pipe_pair(bool outbound, HANDLE *ours, HANDLE *theirs)
{
    wchar_t name[96], sddl[160];
    SECURITY_ATTRIBUTES sa = { .nLength = sizeof(sa), .bInheritHandle = FALSE };
    if (!tw_win_pipe_name(name, sizeof(name) / sizeof(name[0])) ||
        !tw_win_owner_sddl(sddl, sizeof(sddl) / sizeof(sddl[0])) ||
        !ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &sa.lpSecurityDescriptor, NULL))
        return false;
    HANDLE server = CreateNamedPipeW(
        name,
        (outbound ? PIPE_ACCESS_OUTBOUND : PIPE_ACCESS_INBOUND) | FILE_FLAG_OVERLAPPED |
            FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1,
        outbound ? (DWORD)MESH_TERMINAL_WIN_PIPE_BYTES : 0,
        outbound ? 0 : (DWORD)MESH_TERMINAL_WIN_PIPE_BYTES, 0, &sa);
    LocalFree(sa.lpSecurityDescriptor);
    if (server == INVALID_HANDLE_VALUE)
        return false;
    HANDLE client = CreateFileW(name, outbound ? GENERIC_READ : GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, NULL);
    if (client == INVALID_HANDLE_VALUE) {
        CloseHandle(server);
        return false;
    }
    *ours = server;
    *theirs = client;
    return true;
}

struct tw_win_read {
    OVERLAPPED op;
    uint8_t bytes[MESH_TERMINAL_WORKER_IO_CHUNK];
    DWORD used, at, error;
    bool pending, eof;
};

static volatile LONG tw_win_retained_read_count;

static DWORD tw_win_wait_left(ULONGLONG deadline)
{
    ULONGLONG now = GetTickCount64();
    ULONGLONG left = deadline ? (now < deadline ? deadline - now : 0) : 2000;
    return left < 2000 ? (DWORD)left : 2000;
}

static void tw_win_read_retain(struct tw_win_read *r, DWORD error, DWORD waited)
{
    /* Deliberately retain this allocation and event until process exit. No
     * future spawn is admitted, so no orphan collection or retry list exists. */
    (void)r;
    InterlockedIncrement(&tw_win_retained_read_count);
    InterlockedExchange(&tw_win_close_poison, 1);
    fprintf(stderr, "terminal worker: pending output cancellation did not settle error=%lu wait=%lu; retaining private read state and refusing new workers\n",
            error, waited);
}

static bool tw_win_read_settle(HANDLE pipe, struct tw_win_read *r, ULONGLONG deadline)
{
    BOOL cancelled = CancelIoEx(pipe, &r->op);
    DWORD error = cancelled ? 0 : GetLastError();
    DWORD waited = WaitForSingleObject(r->op.hEvent, tw_win_wait_left(deadline));
    DWORD ignored = 0;
    if (waited == WAIT_OBJECT_0) {
        if (GetOverlappedResult(pipe, &r->op, &ignored, FALSE)) return true;
        DWORD completion = GetLastError();
        if (completion == ERROR_OPERATION_ABORTED || completion == ERROR_BROKEN_PIPE ||
            completion == ERROR_HANDLE_EOF) return true;
        error = completion;
    }
    tw_win_read_retain(r, error, waited);
    return false;
}

static void tw_win_read_arm(HANDLE pipe, struct tw_win_read *r)
{
    HANDLE event = r->op.hEvent;
    memset(&r->op, 0, sizeof(r->op));
    r->op.hEvent = event;
    ResetEvent(event);
    r->used = r->at = 0;
    r->pending = ReadFile(pipe, r->bytes, sizeof(r->bytes), NULL, &r->op) != 0;
    if (r->pending) return;
    DWORD error = GetLastError();
    if (error == ERROR_IO_PENDING) { r->pending = true; return; }
    r->eof = error == ERROR_BROKEN_PIPE || error == ERROR_HANDLE_EOF;
    r->error = r->eof ? 0 : error;
    SetEvent(event); /* Completion, including EOF, wakes the sole consumer. */
}

static void tw_win_read_close(HANDLE pipe, struct tw_win_read *r, ULONGLONG deadline)
{
    if (!r) return;
    if (r->pending) {
#if defined(ZCL_TESTING) && defined(MESH_TERMINAL_WORKER_CLOSE_FAILURE_FIXTURE)
        if (mesh_terminal_worker_testing_read_cancel_failure()) {
            tw_win_read_retain(r, ERROR_ACCESS_DENIED, WAIT_TIMEOUT); return;
        }
#endif
        if (!tw_win_read_settle(pipe, r, deadline)) return;
    }
    CloseHandle(r->op.hEvent);
    free(r);
}

static struct tw_win_read *tw_win_read_open(HANDLE pipe)
{
    struct tw_win_read *r = zcl_calloc(1, sizeof(*r), "terminal-output-read");
    if (!r) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }
    r->op.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!r->op.hEvent) {
        DWORD error = GetLastError();
        free(r);
        SetLastError(error);
        return NULL;
    }
    tw_win_read_arm(pipe, r);
    if (!r->error) return r;
    DWORD error = r->error;
    tw_win_read_close(pipe, r, 0);
    SetLastError(error);
    return NULL;
}

static void tw_win_read_collect(HANDLE pipe, struct tw_win_read *r)
{
    if (!r->pending) return;
    DWORD got = 0;
    if (!GetOverlappedResult(pipe, &r->op, &got, FALSE)) {
        DWORD error = GetLastError();
        if (error == ERROR_IO_INCOMPLETE) return;
        r->eof = error == ERROR_BROKEN_PIPE || error == ERROR_HANDLE_EOF;
        r->error = r->eof ? 0 : error;
    } else {
        r->used = got;
        r->eof = got == 0;
    }
    r->pending = false;
    if (!r->used) ResetEvent(r->op.hEvent);
}

struct tw_win_close {
    HPCON console;
    HANDLE event, thread;
    ULONGLONG deadline;
};

static DWORD WINAPI tw_win_close_thread(void *opaque)
{
    struct tw_win_close *c = opaque;
    ClosePseudoConsole(c->console);
    SetEvent(c->event);
    return 0;
}

static struct tw_win_close *tw_win_close_open(void)
{
    struct tw_win_close *c = zcl_calloc(1, sizeof(*c), "terminal-console-close");
    if (!c) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }
    c->event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!c->event) {
        DWORD error = GetLastError(); free(c); SetLastError(error); return NULL;
    }
    return c;
}

static bool tw_win_close_start(struct tw_win_close *c, HPCON console)
{
    if (!c) return false;
    if (console) c->console = console;
    if (!c->console || c->thread) return true;
    if (!c->deadline) c->deadline = GetTickCount64() + 4000;
#if defined(ZCL_TESTING) && defined(MESH_TERMINAL_WORKER_CLOSE_FAILURE_FIXTURE)
    if (mesh_terminal_worker_testing_close_thread_failure()) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY); return false;
    }
#endif
    c->thread = CreateThread(NULL, 0, tw_win_close_thread, c, 0, NULL);
    return c->thread != NULL;
}

static DWORD tw_win_close_wait_ms(struct tw_win_close *c)
{
    return tw_win_wait_left(c ? c->deadline : 0);
}

static void tw_win_close_drain(HANDLE pipe, struct tw_win_read *r,
                               struct tw_win_close *c)
{
    if (!r || !c || !c->thread) return;
#if defined(ZCL_TESTING) && defined(MESH_TERMINAL_WORKER_CLOSE_FAILURE_FIXTURE)
    if (mesh_terminal_worker_testing_read_cancel_failure()) return;
#endif
    /* Teardown discards bytes, never reports them as delivered output. The
     * producer's Job has ended; drain only while the original close budget
     * remains. Closing the read end alone does not reliably unblock conhost. */
    while (GetTickCount64() < c->deadline) {
        tw_win_read_collect(pipe, r);
        if (r->eof || r->error) return;
        if (r->used != r->at) {
            r->at = r->used;
            tw_win_read_arm(pipe, r);
            continue;
        }
        HANDLE events[2] = {r->op.hEvent, c->thread};
        DWORD result = WaitForMultipleObjects(2, events, FALSE, tw_win_close_wait_ms(c));
        if (result != WAIT_OBJECT_0) return;
    }
}

static void tw_win_close_settle(struct tw_win_close *c)
{
    if (!c) return;
    bool settled = !c->console || (c->thread &&
        WaitForSingleObject(c->thread, tw_win_close_wait_ms(c)) == WAIT_OBJECT_0);
    if (!settled) {
        /* No caller or pending-read memory is referenced by this orphan. The
         * process lifetime owns it; future spawns refuse. Existing concurrent
         * workers can each retain one closer (at most max_active in a hub). */
        InterlockedExchange(&tw_win_close_poison, 1);
        fprintf(stderr, "terminal worker: ConPTY close did not settle; retaining private close state and refusing new workers\n");
        return;
    }
    if (c->thread) CloseHandle(c->thread);
    CloseHandle(c->event);
    free(c);
}

/* Our two retained pipe ends plus the pseudoconsole they feed. */
struct tw_win_pty {
    HPCON console;
    HANDLE input_write;
    HANDLE output_read;
    struct tw_win_read *output_state;
    struct tw_win_close *close_state;
};

static void tw_win_pty_close(struct tw_win_pty *pty)
{
    /* End input, start the closer, drain output within its original deadline,
     * then cancel/settle and close the output read before releasing state. */
    if (pty->input_write)
        CloseHandle(pty->input_write);
    (void)tw_win_close_start(pty->close_state, pty->console);
    tw_win_close_drain(pty->output_read, pty->output_state, pty->close_state);
    tw_win_read_close(pty->output_read, pty->output_state,
                      pty->close_state ? pty->close_state->deadline : 0);
    if (pty->output_read)
        CloseHandle(pty->output_read);
    tw_win_close_settle(pty->close_state);
    memset(pty, 0, sizeof(*pty));
}

static struct zcl_result tw_win_pty_open(uint16_t cols, uint16_t rows,
                                         struct tw_win_pty *pty)
{
    memset(pty, 0, sizeof(*pty));
    pty->close_state = tw_win_close_open();
    if (!pty->close_state)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_PTY,
                       "console close state failed error=%lu", GetLastError());
    HANDLE conin_read = NULL, conout_write = NULL;
    if (!tw_win_pipe_pair(true, &pty->input_write, &conin_read)) {
        DWORD error = GetLastError();
        tw_win_pty_close(pty);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_PTY,
                       "input pipe failed error=%lu", error);
    }
    if (!tw_win_pipe_pair(false, &pty->output_read, &conout_write)) {
        DWORD error = GetLastError();
        CloseHandle(conin_read);
        tw_win_pty_close(pty);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_PTY,
                       "named output pipe failed error=%lu", error);
    }
    pty->output_state = tw_win_read_open(pty->output_read);
    if (!pty->output_state) {
        DWORD error = GetLastError();
        CloseHandle(conin_read); CloseHandle(conout_write);
        tw_win_pty_close(pty);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_PTY,
                       "output readiness setup failed error=%lu", error);
    }
    COORD size = { .X = (SHORT)cols, .Y = (SHORT)rows };
    HRESULT hr =
        CreatePseudoConsole(size, conin_read, conout_write, 0, &pty->console);
    /* ConPTY duplicates whichever ends it needs; our copies of the ends it
     * now owns are always closed, success or failure. */
    CloseHandle(conin_read);
    CloseHandle(conout_write);
    if (FAILED(hr)) {
        pty->console = NULL;
        tw_win_pty_close(pty);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_PTY,
                       "CreatePseudoConsole failed hr=0x%lx",
                       (unsigned long)hr);
    }
    return ZCL_OK;
}

/* The shell's environment, drawn only from tw_env_table: nothing else of
 * the node's environment crosses, so no credential or token variable can
 * leak. Variables the node lacks are omitted. The block is sorted because
 * the table is. Caller frees. */
#define MESH_TERMINAL_WIN_ENV_CHARS 65536u
#define MESH_TERMINAL_WIN_ENV_VALUE_CHARS 32768u

static bool tw_win_env_value(const struct tw_env_entry *e,
                             const wchar_t *workdir, wchar_t *scratch,
                             const wchar_t **value)
{
    wchar_t wname[32];
    if (e->source == TW_ENV_WORKDIR)
        *value = workdir;
    else if (e->source == TW_ENV_TERM)
        *value = L"xterm";
    else {
        DWORD n;
        if (!win_widen(e->name, wname, 32))
            return false;
        n = GetEnvironmentVariableW(wname, scratch,
                                    MESH_TERMINAL_WIN_ENV_VALUE_CHARS);
        if (n == 0 || n >= MESH_TERMINAL_WIN_ENV_VALUE_CHARS)
            return false;
        *value = scratch;
    }
    return true;
}

static wchar_t *tw_win_env_build(const wchar_t *workdir)
{
    wchar_t *block = zcl_malloc(MESH_TERMINAL_WIN_ENV_CHARS * sizeof(wchar_t),
                                "mesh_terminal_worker_win_env");
    wchar_t *scratch = zcl_malloc(
        MESH_TERMINAL_WIN_ENV_VALUE_CHARS * sizeof(wchar_t),
        "mesh_terminal_worker_win_env_value");
    size_t off = 0;
    for (size_t i = 0; block && scratch &&
                       i < sizeof(tw_env_table) / sizeof(tw_env_table[0]);
         i++) {
        wchar_t wkey[32];
        const wchar_t *value = NULL;
        if (tw_win_env_value(&tw_env_table[i], workdir, scratch, &value) &&
            win_widen(tw_env_table[i].name, wkey, 32))
            off = win_env_put(block, MESH_TERMINAL_WIN_ENV_CHARS - 1u, off,
                              wkey, value);
    }
    free(scratch);
    if (block && off > 0)
        block[off] = L'\0'; /* final NUL terminates the block */
    else {
        free(block);
        block = NULL;
    }
    return block;
}

/* Start the shell SUSPENDED on the pseudoconsole so the caller can place it
 * in the job before it runs a single instruction. */
static struct zcl_result tw_win_create_shell(HPCON console,
                                             const wchar_t *wshell,
                                             const wchar_t *wworkdir,
                                             wchar_t *cmdline,
                                             PROCESS_INFORMATION *pi)
{
    SIZE_T attr_size = 0;
    (void)InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);
    void *attr_buf = attr_size ? zcl_malloc(attr_size, "mesh_terminal_worker_win_attr_list") : NULL;
    LPPROC_THREAD_ATTRIBUTE_LIST attr_list =
        (LPPROC_THREAD_ATTRIBUTE_LIST)attr_buf;
    if (!attr_buf)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_SPAWN,
                       "attribute list allocation failed");
    if (!InitializeProcThreadAttributeList(attr_list, 1, 0, &attr_size) ||
        !UpdateProcThreadAttribute(attr_list, 0,
                                   PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                                   console, sizeof(console), NULL, NULL)) {
        DWORD error = GetLastError();
        free(attr_buf);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_SPAWN,
                       "attribute list setup failed error=%lu", error);
    }

    wchar_t *env = tw_win_env_build(wworkdir);
    if (!env) {
        DeleteProcThreadAttributeList(attr_list);
        free(attr_buf);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_SPAWN,
                       "environment block allocation failed");
    }
    STARTUPINFOEXW startup;
    memset(&startup, 0, sizeof(startup));
    startup.StartupInfo.cb = sizeof(startup);
    /* Do not carry the launcher's redirected standard handles into the
     * shell: NULL slots let its attached pseudoconsole supply the streams. */
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.lpAttributeList = attr_list;
    memset(pi, 0, sizeof(*pi));
    DWORD flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT |
                  CREATE_SUSPENDED;
    BOOL started = CreateProcessW(wshell, cmdline, NULL, NULL, FALSE, flags,
                                  env, wworkdir, &startup.StartupInfo, pi);
    DWORD error = started ? 0 : GetLastError();
    DeleteProcThreadAttributeList(attr_list);
    free(attr_buf);
    free(env);
    if (!started)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_EXEC,
                       "CreateProcessW failed error=%lu", error);
    return ZCL_OK;
}

/* Put the suspended shell in the job, then let it run. A shell that cannot
 * be contained never runs: it is terminated and the spawn is refused by
 * name. */
static struct zcl_result tw_win_contain_and_resume(HANDLE job,
                                                   PROCESS_INFORMATION *pi)
{
    if (!AssignProcessToJobObject(job, pi->hProcess)) {
        DWORD error = GetLastError();
        (void)TerminateProcess(pi->hProcess, 137);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_JOB_ASSIGN,
                       "job-object-assign: the shell could not join its job "
                       "(the node may run inside a job that forbids "
                       "nesting; start it outside a restrictive job) "
                       "error=%lu", error);
    }
    if (ResumeThread(pi->hThread) == (DWORD)-1) {
        DWORD error = GetLastError();
        (void)TerminateJobObject(job, 137);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_SPAWN,
                       "ResumeThread failed error=%lu", error);
    }
    return ZCL_OK;
}

static struct zcl_result tw_win_spawn_config_check(
    const struct mesh_terminal_worker_config *cfg)
{
    if (InterlockedCompareExchange(&tw_win_close_poison, 0, 0))
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_PTY,
                       "spawn refused after an unsettled ConPTY close");
    const char *image = cfg->argv ? cfg->argv[0] : cfg->shell_path;
    if (!image ||
        !mesh_terminal_shell_path_valid(MESH_TERMINAL_PLATFORM_WINDOWS,
                                        image) ||
        !cfg->workdir || !win_path_is_absolute(cfg->workdir))
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFIG,
                       "spawn: shell_path and workdir must be absolute");
    if (!geometry_in_bounds(cfg->cols, cfg->rows))
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFIG,
                       "spawn: cols/rows out of proto bounds");
    if (cfg->max_bytes_in == 0 || cfg->max_bytes_out == 0 ||
        cfg->lifetime_seconds == 0)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFIG,
                       "spawn: byte and lifetime budgets must be nonzero");
    if (strlen(cfg->workdir) >= MESH_TERMINAL_WIN_PATH_MAX)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFIG,
                       "spawn: workdir path too long");
    return ZCL_OK;
}

/* Validate arguments before creating a job, console or process. The shared
 * encoder owns quoting and strict UTF-8 conversion. Byte and count bounds
 * keep its input scan and allocation bounded as well. */
static wchar_t *tw_win_command_line(const struct mesh_terminal_worker_config *cfg)
{
    const char *const fallback[] = { cfg->shell_path, NULL };
    const char *const *argv = cfg->argv ? cfg->argv : fallback;
    size_t count = 0, bytes = 0;
    while (count < MESH_TERMINAL_WORKER_ARGV_MAX && argv[count]) {
        size_t n = strnlen(argv[count], 32767u);
        if (n == 32767u || n + 1u > 32767u - bytes)
            return NULL;
        bytes += n + 1u;
        count++;
    }
    if (!count || argv[count])
        return NULL;
    wchar_t *line = platform_process_windows_command_line(argv);
    if (line && wcslen(line) + 1u > 32767u) {
        free(line);
        line = NULL;
    }
    return line;
}

struct zcl_result mesh_terminal_worker_spawn_platform_arm(
    const struct mesh_terminal_worker_config *cfg, int64_t now_unix,
    struct mesh_terminal_worker *out)
{
    if (!cfg || !out)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NULL,
                       "spawn: cfg/out required");
    memset(out, 0, sizeof(*out));
    out->master_fd = -1;
    struct zcl_result checked = tw_win_spawn_config_check(cfg);
    if (!checked.ok)
        return checked;
    wchar_t wshell[MESH_TERMINAL_WIN_PATH_MAX];
    wchar_t wworkdir[MESH_TERMINAL_WIN_PATH_MAX];
    const char *image = cfg->argv ? cfg->argv[0] : cfg->shell_path;
    if (!win_widen(image, wshell, MESH_TERMINAL_WIN_PATH_MAX) ||
        !win_widen(cfg->workdir, wworkdir, MESH_TERMINAL_WIN_PATH_MAX))
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFIG,
                       "spawn: shell_path/workdir is not valid UTF-8");

    wchar_t *cmdline = tw_win_command_line(cfg);
    if (!cmdline)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFIG,
                       "spawn: argv is invalid UTF-8, unterminated or exceeds the command-line budget");

    HANDLE job = tw_win_job_create();
    if (!job) {
        DWORD error = GetLastError();
        free(cmdline);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFINEMENT,
                       "job object setup failed error=%lu", error);
    }
    struct tw_win_job_watch *watch = tw_win_job_watch_open(job);
    if (!watch) {
        DWORD error = GetLastError(); free(cmdline); CloseHandle(job);
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_CONFINEMENT,
                       "job membership wake setup failed error=%lu", error);
    }
    struct tw_win_pty pty;
    struct zcl_result r = tw_win_pty_open(cfg->cols, cfg->rows, &pty);
    PROCESS_INFORMATION pi;
    if (r.ok)
        r = tw_win_create_shell(pty.console, wshell, wworkdir, cmdline, &pi);
    free(cmdline);
    if (r.ok) {
        r = tw_win_contain_and_resume(job, &pi);
        CloseHandle(pi.hThread);
        if (!r.ok)
            CloseHandle(pi.hProcess);
    }
    if (!r.ok) {
        tw_win_pty_close(&pty);
        CloseHandle(job);
        tw_win_job_watch_close(watch, 0);
        return r;
    }

    out->pid = (pid_t)pi.dwProcessId;
    out->pgid = out->pid; /* the job is the group; see kill */
    out->win_pc = pty.console;
    out->win_job = job;
    out->win_process = pi.hProcess;
    out->win_input_write = pty.input_write;
    out->win_output_read = pty.output_read;
    out->win_output_state = pty.output_state;
    out->win_close_state = pty.close_state;
    out->win_membership_state = watch;
    out->max_bytes_in = cfg->max_bytes_in;
    out->max_bytes_out = cfg->max_bytes_out;
    out->lifetime_seconds = cfg->lifetime_seconds;
    out->idle_seconds = cfg->idle_seconds;
    out->close_reason = MESH_TERMINAL_CLOSE_REQUESTED;
    out->started_unix = now_unix;
    out->last_activity_unix = now_unix;
    out->running = true;
    return ZCL_OK;
}

enum tw_win_write_outcome {
    TW_WIN_WRITE_OK,
    TW_WIN_WRITE_STALLED,
    TW_WIN_WRITE_FAILED
};

/* One overlapped write bounded by MESH_TERMINAL_WIN_WRITE_WAIT_MS. A write
 * still pending at the deadline is cancelled and reports STALLED together
 * with however many bytes the pipe did take; the caller decides, and the
 * session's lifetime/idle enforcement owns any kill. */
static enum tw_win_write_outcome tw_win_write_bounded(
    HANDLE pipe, const uint8_t *bytes, size_t n, DWORD *wrote, DWORD *error)
{
    *wrote = 0;
    *error = 0;
    OVERLAPPED op;
    memset(&op, 0, sizeof(op));
    op.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!op.hEvent) {
        *error = GetLastError();
        return TW_WIN_WRITE_FAILED;
    }
    enum tw_win_write_outcome outcome = TW_WIN_WRITE_OK;
    if (!WriteFile(pipe, bytes, (DWORD)n, NULL, &op) &&
        GetLastError() != ERROR_IO_PENDING) {
        *error = GetLastError();
        outcome = TW_WIN_WRITE_FAILED;
    } else {
        if (WaitForSingleObject(op.hEvent, MESH_TERMINAL_WIN_WRITE_WAIT_MS) !=
            WAIT_OBJECT_0) {
            (void)CancelIoEx(pipe, &op);
            outcome = TW_WIN_WRITE_STALLED;
        }
        if (!GetOverlappedResult(pipe, &op, wrote, TRUE) &&
            outcome == TW_WIN_WRITE_OK) {
            *error = GetLastError();
            outcome = TW_WIN_WRITE_FAILED;
        }
    }
    CloseHandle(op.hEvent);
    return outcome;
}

struct zcl_result mesh_terminal_worker_input_platform_arm(struct mesh_terminal_worker *w,
                                             const uint8_t *bytes, size_t n,
                                             int64_t now_unix)
{
    if (!w || (!bytes && n != 0))
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NULL,
                       "input: worker/bytes required");
    if (n == 0)
        return ZCL_OK;
    if (!w->running || !w->win_input_write)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NOT_RUNNING,
                       "input: session is over (%s)",
                       mesh_terminal_close_reason_string(w->close_reason));
    if (mesh_terminal_worker_budget_would_overrun(w->bytes_in,
                                                  w->max_bytes_in, n)) {
        mesh_terminal_worker_kill(w);
        w->close_reason = MESH_TERMINAL_CLOSE_BYTE_LIMIT;
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_BYTE_LIMIT,
                       "input budget %llu exceeded (%llu used, %zu offered)",
                       (unsigned long long)w->max_bytes_in,
                       (unsigned long long)w->bytes_in, n);
    }

    /* The POSIX arm's bounded-wait shape: a shell that stops reading its
     * console is an IO refusal after MESH_TERMINAL_WIN_WRITE_WAIT_MS per
     * write, never an unbounded block of the caller's tick. */
    size_t total = 0;
    while (total < n) {
        DWORD wrote = 0, error = 0;
        enum tw_win_write_outcome outcome = tw_win_write_bounded(
            (HANDLE)w->win_input_write, bytes + total, n - total, &wrote,
            &error);
        total += wrote;
        w->bytes_in += wrote;
        if (wrote != 0)
            w->last_activity_unix = now_unix;
        if (outcome == TW_WIN_WRITE_FAILED)
            return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_IO,
                           "pty input failed error=%lu (wrote %zu/%zu)",
                           error, total, n);
        if (outcome == TW_WIN_WRITE_STALLED || wrote == 0)
            return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_IO,
                           "pty input stalled (wrote %zu/%zu)", total, n);
    }
    return ZCL_OK;
}

struct zcl_result mesh_terminal_worker_output_platform_arm(struct mesh_terminal_worker *w,
                                              uint8_t *buf, size_t cap,
                                              size_t *out_len,
                                              int64_t now_unix)
{
    if (out_len)
        *out_len = 0;
    if (!w || !buf || !out_len)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NULL,
                       "output: worker/buf/out_len required");
    if (cap == 0)
        return ZCL_OK;
    if (!w->win_output_read)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NOT_RUNNING,
                       "output: pty closed");

    struct tw_win_read *r = w->win_output_state;
    if (!r) return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_IO, "output readiness state missing");
    tw_win_read_collect((HANDLE)w->win_output_read, r);
    if (r->error)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_IO,
                       "overlapped pty read failed error=%lu", r->error);
    size_t n = r->used - r->at;
    if (n > cap) n = cap;
    if (!n) return ZCL_OK;
    memcpy(buf, r->bytes + r->at, n);
    r->at += (DWORD)n;
    *out_len = n;
    w->bytes_out += n;
    w->last_activity_unix = now_unix;
    if (w->bytes_out > w->max_bytes_out) {
        mesh_terminal_worker_kill(w);
        w->close_reason = MESH_TERMINAL_CLOSE_BYTE_LIMIT;
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_BYTE_LIMIT,
                       "output budget %llu exceeded (%llu produced)",
                       (unsigned long long)w->max_bytes_out,
                       (unsigned long long)w->bytes_out);
    }
    if (r->at == r->used && !r->eof)
        tw_win_read_arm((HANDLE)w->win_output_read, r);
    return ZCL_OK;
}

struct zcl_result mesh_terminal_worker_resize_platform_arm(struct mesh_terminal_worker *w,
                                              uint16_t cols, uint16_t rows)
{
    if (!w)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NULL,
                       "resize: worker required");
    if (!w->win_pc)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NOT_RUNNING,
                       "resize: pty closed");
    if (!geometry_in_bounds(cols, rows))
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_GEOMETRY,
                       "resize: cols/rows out of proto bounds");
    COORD size = { .X = (SHORT)cols, .Y = (SHORT)rows };
    HRESULT hr = ResizePseudoConsole((HPCON)w->win_pc, size);
    if (FAILED(hr))
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_IO,
                       "ResizePseudoConsole failed hr=0x%lx",
                       (unsigned long)hr);
    /* The console host raises its own resize signal to the child; nothing
     * to forward by hand, mirroring the POSIX arm's SIGWINCH comment. */
    return ZCL_OK;
}

static int tw_win_job_census(HANDLE job)
{
    union {
        JOBOBJECT_BASIC_PROCESS_ID_LIST list;
        uint8_t bytes[sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) +
            4u * MESH_TERMINAL_WORKER_MAX_PROCESSES * sizeof(ULONG_PTR)];
    } members = {0};
    if (!QueryInformationJobObject(job, JobObjectBasicProcessIdList,
                                   &members, sizeof(members), NULL)) {
        DWORD error = GetLastError();
        fprintf(stderr, "terminal worker: all-member Job census failed error=%lu assigned=%lu listed=%lu\n",
                error, members.list.NumberOfAssignedProcesses, members.list.NumberOfProcessIdsInList);
        return -1; /* Includes ERROR_MORE_DATA: never treat overflow as empty. */
    }
    return (int)members.list.NumberOfAssignedProcesses;
}

static unsigned tw_win_process_limit(void)
{
#if defined(ZCL_TESTING) && defined(MESH_TERMINAL_WORKER_CLOSE_FAILURE_FIXTURE)
    unsigned limit = mesh_terminal_worker_testing_process_limit();
    if (limit && limit < MESH_TERMINAL_WORKER_MAX_PROCESSES) return limit;
#endif
    return MESH_TERMINAL_WORKER_MAX_PROCESSES;
}

bool mesh_terminal_worker_budget_exceeded_platform_arm(struct mesh_terminal_worker *w,
                                          int64_t now_unix)
{
    if (!w)
        return true;
    struct tw_win_job_watch *watch = w->win_membership_state;
    if (watch) ResetEvent(watch->event); /* Before census: later changes remain signalled. */
    if (!w->running)
        return true;
    DWORD code = 0;
    if (w->win_process &&
        WaitForSingleObject((HANDLE)w->win_process, 0) == WAIT_OBJECT_0 &&
        GetExitCodeProcess((HANDLE)w->win_process, &code)) {
        w->exit_code = (int)code;
        w->running = false;
        if (w->close_reason == MESH_TERMINAL_CLOSE_REQUESTED)
            w->close_reason = MESH_TERMINAL_CLOSE_WORKER_EXITED;
        return true;
    }
    if (w->lifetime_seconds != 0 &&
        now_unix - w->started_unix >= (int64_t)w->lifetime_seconds) {
        w->close_reason = MESH_TERMINAL_CLOSE_LIFETIME_LIMIT;
        mesh_terminal_worker_kill(w);
        return true;
    }
    if (w->idle_seconds != 0 &&
        now_unix - w->last_activity_unix >= (int64_t)w->idle_seconds) {
        w->close_reason = MESH_TERMINAL_CLOSE_IDLE_TIMEOUT;
        mesh_terminal_worker_kill(w);
        return true;
    }
    /* The Job active-process limit does not count every OS console host.
     * Sample all assigned members too, matching the POSIX census authority. */
    int members = tw_win_job_census((HANDLE)w->win_job);
    if (members < 0 || (unsigned)members > tw_win_process_limit()) {
        w->close_reason = members < 0 ? MESH_TERMINAL_CLOSE_INTERNAL :
                                     MESH_TERMINAL_CLOSE_SESSION_LOST;
        mesh_terminal_worker_kill(w);
        return true;
    }
    return false;
}

bool mesh_terminal_worker_alive_platform_arm(struct mesh_terminal_worker *w)
{
    if (!w || !w->running)
        return false;
    DWORD code = 0;
    if (w->win_process &&
        WaitForSingleObject((HANDLE)w->win_process, 0) == WAIT_OBJECT_0 &&
        GetExitCodeProcess((HANDLE)w->win_process, &code)) {
        w->exit_code = (int)code;
        w->running = false;
        if (w->close_reason == MESH_TERMINAL_CLOSE_REQUESTED)
            w->close_reason = MESH_TERMINAL_CLOSE_WORKER_EXITED;
        return false;
    }
    return w->running;
}

/* Release the console side. The job has already ended the shell, and our
 * pipe ends are closed before the pseudoconsole so its host cannot block
 * on a reader that will never come. */
static void tw_win_release_console(struct mesh_terminal_worker *w)
{
    tw_win_close(&w->win_input_write);
    (void)tw_win_close_start(w->win_close_state, (HPCON)w->win_pc);
    w->win_pc = NULL;
    tw_win_close_drain((HANDLE)w->win_output_read, w->win_output_state, w->win_close_state);
    struct tw_win_close *closing = w->win_close_state;
    tw_win_read_close((HANDLE)w->win_output_read, w->win_output_state,
                      closing ? closing->deadline : 0);
    w->win_output_state = NULL;
    tw_win_close(&w->win_output_read);
    tw_win_close_settle(w->win_close_state);
    w->win_close_state = NULL;
}

/* Wait (bounded) for the terminated shell and record its exit code. */
static void tw_win_reap(struct mesh_terminal_worker *w)
{
    DWORD code = 0;
    DWORD waited = WaitForSingleObject((HANDLE)w->win_process,
        tw_win_close_wait_ms(w->win_close_state));
    if (waited == WAIT_OBJECT_0 &&
        GetExitCodeProcess((HANDLE)w->win_process, &code))
        w->exit_code = (int)code;
    else
        w->exit_code = 137;
}

/* Ends the whole process tree: TerminateJobObject takes the shell and every
 * descendant, and closing the kill-on-close job afterwards takes anything
 * that raced it. Safe to call again and after the shell exited on its own,
 * when it still removes the descendants that outlived it. */
void mesh_terminal_worker_kill_platform_arm(struct mesh_terminal_worker *w)
{
    if (!w)
        return;
    struct tw_win_close *closing = w->win_close_state;
    if (closing && !closing->deadline) closing->deadline = GetTickCount64() + 4000;
    ULONGLONG deadline = closing ? closing->deadline : GetTickCount64() + 4000;
    /* 128 + SIGKILL(9), matching the POSIX arm's forced-kill exit code
     * convention so a caller reading exit_code cannot tell the two arms
     * apart. */
    if (w->win_job)
        (void)TerminateJobObject((HANDLE)w->win_job, 137);
    else if (w->running && w->win_process)
        (void)TerminateProcess((HANDLE)w->win_process, 137);
    if (w->running && w->win_process)
        tw_win_reap(w);
    tw_win_job_watch_close(w->win_membership_state, deadline);
    w->win_membership_state = NULL;
    tw_win_release_console(w);
    tw_win_close(&w->win_job);
    tw_win_close(&w->win_process);
    if (!w->running)
        return;
    w->running = false;
    if (w->close_reason == MESH_TERMINAL_CLOSE_REQUESTED)
        w->close_reason = MESH_TERMINAL_CLOSE_INTERNAL;
}


uintptr_t mesh_terminal_worker_output_wait_handle(struct mesh_terminal_worker *w)
{
    struct tw_win_read *r = w ? w->win_output_state : NULL;
    return r && !r->eof ? (uintptr_t)r->op.hEvent : 0;

}

struct zcl_result mesh_terminal_worker_begin_output_close(struct mesh_terminal_worker *w)
{
    if (!w || !w->win_close_state)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_NOT_RUNNING, "console close state unavailable");
    struct tw_win_close *state = w->win_close_state;
    if (!state->deadline) state->deadline = GetTickCount64() + 4000;
    (void)mesh_terminal_worker_alive(w);
    if (w->win_job && !TerminateJobObject((HANDLE)w->win_job, 137))
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_IO,
                       "console close subtree termination failed error=%lu", GetLastError());
    if (w->running && w->win_process) {
        tw_win_reap(w);
        if (WaitForSingleObject((HANDLE)w->win_process, 0) != WAIT_OBJECT_0)
            return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_IO,
                           "console close shell did not settle after termination");
        w->running = false;
    }
    tw_win_job_watch_close(w->win_membership_state, state->deadline);
    w->win_membership_state = NULL;
    tw_win_close(&w->win_input_write);
    bool started = tw_win_close_start(w->win_close_state, (HPCON)w->win_pc);
    DWORD error = started ? 0 : GetLastError();
    w->win_pc = NULL; /* The preallocated close state owns it, even on failure. */
    if (!started)
        return ZCL_ERR(MESH_TERMINAL_WORKER_ERR_IO,
                       "console close thread failed error=%lu; output remains owned until kill", error);
    return ZCL_OK;

}

uintptr_t mesh_terminal_worker_close_wait_handle(struct mesh_terminal_worker *w)
{
    struct tw_win_close *c = w ? w->win_close_state : NULL;
    return c && c->thread ? (uintptr_t)c->event : 0;

}

uintptr_t mesh_terminal_worker_budget_wait_handle(struct mesh_terminal_worker *w)
{
    struct tw_win_job_watch *watch = w ? w->win_membership_state : NULL;
    return watch ? (uintptr_t)watch->event : 0;

}

#if defined(_WIN32) && defined(ZCL_TESTING) && defined(MESH_TERMINAL_WORKER_CLOSE_FAILURE_FIXTURE)
unsigned mesh_terminal_worker_testing_retained_reads(void)
{
    return (unsigned)InterlockedCompareExchange(&tw_win_retained_read_count, 0, 0);
}
unsigned mesh_terminal_worker_testing_retained_watches(void)
{
    return (unsigned)InterlockedCompareExchange(&tw_win_retained_watch_count, 0, 0);
}
#endif


#else
/* Keep the platform-selected translation unit valid on every compiler. */
typedef int mesh_terminal_worker_windows_unavailable;
#endif
