/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: prove dev.agent.worker's Windows confinement backend natively.
 *
 * This program is its own confined child: the backend re-enters the
 * running image with WKR_CHILD_FLAG, exactly as the production binary is
 * re-entered, and this image's child entry wires the fixture executor
 * below instead of the Muse executor. Each case drives the REAL spawn
 * (zcl_devagent_worker_spawn_confined) and the REAL receipt mapping
 * (zcl_devagent_worker_outcome / _parse_result / _gate):
 *
 *   write   the child writes inside its run dir (and a pre-existing
 *           subdirectory), cannot write a sibling directory outside it,
 *           sees no parent secret in its environment, and the run dir is
 *           relabelled medium once the run ends;
 *   memory  the child allocates until the job memory cap denies it and
 *           dies by an out-of-memory exception -> crashed, rc 130, with
 *           its last successful total under the cap;
 *   tree    the child starts a grandchild and both hang; the wall cap
 *           kills the whole job -> timeout, rc 124, grandchild gone;
 *   cpu     the child spins past the job CPU cap -> crashed, rc 130,
 *           well before the wall cap;
 *   fail    the executor fails with rc 3 -> failed verdict, receipt rc 1;
 *   refuse  the child entry run OUTSIDE the confinement runs nothing.
 *
 * Exit 77 is an honest runtime refusal (Wine, or a host where the backend
 * cannot arm, named on stdout). Run natively from MSYS2 UCRT64:
 *   make build/tests/windows/devagent_worker_confine.exe && \
 *     build/tests/windows/devagent_worker_confine.exe
 */
#if defined(_WIN32)
#include "../../../tools/command/native_devagent.h"
#include "platform/confined_process.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <aclapi.h>

#define ACC_SLEEPER "--acc-sleeper"
#define ACC_SECRET "Z23_ACC_SECRET"
#define ACC_MEM_MB 128
#define ACC_CHUNK (4u * 1024u * 1024u)

/* ── the fixture executor (runs in the confined child) ─────────────────── */

static bool acc_task(const struct wkr_job *job, const char *key, char *out,
                     size_t cap)
{
    const char *p = strstr(job->task, key);
    size_t n = 0;
    if (!p)
        return false;
    p += strlen(key);
    while (p[n] && p[n] != '\n' && n + 1 < cap) {
        out[n] = p[n];
        n++;
    }
    out[n] = '\0';
    return true;
}

static bool acc_try_write(const char *path)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    (void)fputs("written by the confined child\n", f);
    return fclose(f) == 0;
}

static void acc_result(struct wkr_result *res, const char *terminal,
                       long long rc, const char *evidence)
{
    memset(res, 0, sizeof(*res));
    (void)snprintf(res->terminal, sizeof(res->terminal), "%s", terminal);
    res->rc = rc;
    (void)snprintf(res->evidence, sizeof(res->evidence), "%s", evidence);
}

static bool acc_mode_write(const struct wkr_job *job, struct wkr_result *res)
{
    char inside[4200], nested[4200], outside[4096], target[4200];
    bool in_ok, nested_ok, out_denied, clean_env;
    (void)snprintf(inside, sizeof(inside), "%s/inside.txt", job->rundir);
    (void)snprintf(nested, sizeof(nested), "%s/sub/nested.txt", job->rundir);
    if (!acc_task(job, "outside=", outside, sizeof(outside)))
        outside[0] = '\0';
    (void)snprintf(target, sizeof(target), "%s/escaped.txt", outside);
    in_ok = acc_try_write(inside);
    nested_ok = acc_try_write(nested);
    out_denied = outside[0] && !acc_try_write(target);
    clean_env = getenv(ACC_SECRET) == NULL;
    acc_result(res, "probe",
               in_ok && nested_ok && out_denied && clean_env ? 0 : 1,
               in_ok ? (nested_ok ? (out_denied ? (clean_env ? "ok"
                                                             : "secret-seen")
                                                : "escaped")
                                  : "nested-denied")
                     : "inside-denied");
    return true;
}

static bool acc_mode_memory(const struct wkr_job *job, struct wkr_result *res)
{
    char progress[4200];
    unsigned long long total = 0;
    (void)res;
    (void)snprintf(progress, sizeof(progress), "%s/allocated.txt",
                   job->rundir);
    for (;;) {
        unsigned char *chunk = malloc(ACC_CHUNK);
        FILE *f;
        if (!chunk)
            break;
        memset(chunk, 0xA5, ACC_CHUNK); /* commit every page */
        total += ACC_CHUNK;
        f = fopen(progress, "wb");
        if (f) {
            (void)fprintf(f, "%llu\n", total);
            (void)fclose(f);
        }
    }
    /* Out of memory under the job cap: die the way an allocation failure
     * kills a real adapter, by an exception. */
    RaiseException(0xC0000017u /* STATUS_NO_MEMORY */,
                   EXCEPTION_NONCONTINUABLE, 0, NULL);
    return true;
}

static bool acc_mode_tree(const struct wkr_job *job, struct wkr_result *res)
{
    wchar_t image[32768], line[40000], dir[4096];
    STARTUPINFOW startup;
    PROCESS_INFORMATION child;
    (void)res;
    if (!GetModuleFileNameW(NULL, image, 32768) ||
        !MultiByteToWideChar(CP_UTF8, 0, job->rundir, -1, dir, 4096) ||
        swprintf(line, 40000, L"\"%ls\" " ACC_SLEEPER " \"%ls\"", image,
                 dir) <= 0)
        return false;
    memset(&startup, 0, sizeof(startup));
    startup.cb = sizeof(startup);
    memset(&child, 0, sizeof(child));
    if (!CreateProcessW(image, line, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &startup, &child))
        return false;
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    Sleep(INFINITE);
    return true;
}

static bool acc_mode_cpu(const struct wkr_job *job, struct wkr_result *res)
{
    volatile unsigned long long spin = 0;
    ULONGLONG until = GetTickCount64() + 30000u;
    (void)job;
    while (GetTickCount64() < until)
        spin++;
    acc_result(res, "spun", 0, "cpu cap never fired");
    return true;
}

static bool acc_executor(const struct wkr_job *job, struct wkr_result *res)
{
    char mode[32];
    if (!acc_task(job, "mode=", mode, sizeof(mode)))
        return false;
    if (strcmp(mode, "write") == 0)
        return acc_mode_write(job, res);
    if (strcmp(mode, "memory") == 0)
        return acc_mode_memory(job, res);
    if (strcmp(mode, "tree") == 0)
        return acc_mode_tree(job, res);
    if (strcmp(mode, "cpu") == 0)
        return acc_mode_cpu(job, res);
    acc_result(res, "failed", 3, "fixture failed on purpose");
    return true;
}

/* The grandchild: publish its pid in the run dir, then hang. */
static int acc_sleeper(const char *rundir)
{
    char path[4200];
    FILE *f;
    (void)snprintf(path, sizeof(path), "%s/grandchild.pid", rundir);
    f = fopen(path, "wb");
    if (f) {
        (void)fprintf(f, "%lu\n", (unsigned long)GetCurrentProcessId());
        (void)fclose(f);
    }
    Sleep(INFINITE);
    return 0;
}

/* ── parent side ───────────────────────────────────────────────────────── */

static char g_base[4096];

static bool acc_dir(const char *leaf, char *out, size_t cap)
{
    if (snprintf(out, cap, "%s\\%s", g_base, leaf) >= (int)cap)
        return false;
    return CreateDirectoryA(out, NULL) ||
           GetLastError() == ERROR_ALREADY_EXISTS;
}

static bool acc_base(void)
{
    char temp[MAX_PATH + 1];
    DWORD n = GetTempPathA(sizeof(temp), temp);
    if (n == 0 || n >= sizeof(temp))
        return false;
    if (snprintf(g_base, sizeof(g_base), "%sz23-wconfine-%lu", temp,
                 (unsigned long)GetCurrentProcessId()) >= (int)sizeof(g_base))
        return false;
    return CreateDirectoryA(g_base, NULL) ||
           GetLastError() == ERROR_ALREADY_EXISTS;
}

static void acc_opts(struct wkr_drive_opts *o, long long wall_s,
                     long long cpu_s)
{
    memset(o, 0, sizeof(*o));
    (void)snprintf(o->worker, sizeof(o->worker), "%s", "acc");
    (void)snprintf(o->session, sizeof(o->session), "%s", "s-acc");
    o->time_cap_s = wall_s;
    o->cpu_s = cpu_s;
    o->mem_mb = ACC_MEM_MB;
    o->token_cap = 32000;
}

static struct wkr_job *acc_job(const char *leaf, const char *task)
{
    struct wkr_job *job = calloc(1, sizeof(*job));
    if (!job || !acc_dir(leaf, job->rundir, sizeof(job->rundir))) {
        free(job);
        return NULL;
    }
    (void)snprintf(job->name, sizeof(job->name), "acc-%s", leaf);
    (void)snprintf(job->kind, sizeof(job->kind), "%s", "leaf");
    (void)snprintf(job->task, sizeof(job->task), "%s", task);
    job->attempt = 1;
    job->token_cap = 32000;
    job->time_cap_s = 30;
    return job;
}

/* Run one case through the real spawn and the real receipt mapping. */
static struct wkr_outcome acc_run(const struct wkr_job *job, long long wall_s,
                                  long long cpu_s, struct wkr_spawn_out *out)
{
    struct wkr_drive_opts o;
    struct wkr_outcome oc;
    acc_opts(&o, wall_s, cpu_s);
    *out = zcl_devagent_worker_spawn_confined(&o, job, NULL);
    zcl_devagent_worker_outcome(out, false, &oc);
    return oc;
}

static bool acc_fail(const char *name, const char *why)
{
    printf("devagent_worker_confine: FAIL %s: %s\n", name, why);
    return false;
}

/* The mandatory label on path is medium (explicit or absent). */
static bool acc_label_medium(const char *path)
{
    PSECURITY_DESCRIPTOR sd = NULL;
    PACL sacl = NULL;
    bool medium = false;
    if (GetNamedSecurityInfoA(path, SE_FILE_OBJECT,
                              LABEL_SECURITY_INFORMATION, NULL, NULL, NULL,
                              &sacl, &sd) != ERROR_SUCCESS)
        return false;
    if (!sacl || sacl->AceCount == 0) {
        medium = true;
    } else {
        void *ace = NULL;
        if (GetAce(sacl, 0, &ace)) {
            SYSTEM_MANDATORY_LABEL_ACE *label = ace;
            PSID sid = (PSID)&label->SidStart;
            DWORD rid = *GetSidSubAuthority(
                sid, (DWORD)(*GetSidSubAuthorityCount(sid) - 1u));
            medium = rid == SECURITY_MANDATORY_MEDIUM_RID;
        }
    }
    LocalFree(sd);
    return medium;
}

static bool acc_case_write(void)
{
    char outside[4096], task[4600], sub[4200], escaped[4200];
    struct wkr_spawn_out out;
    struct wkr_outcome oc;
    struct wkr_result res;
    struct wkr_job *job;
    bool ok;
    if (!acc_dir("outside", outside, sizeof(outside)))
        return acc_fail("write", "cannot make the outside dir");
    (void)snprintf(task, sizeof(task), "mode=write\noutside=%s\n", outside);
    job = acc_job("write", task);
    if (!job)
        return acc_fail("write", "cannot make the run dir");
    (void)snprintf(sub, sizeof(sub), "%s\\sub", job->rundir);
    (void)CreateDirectoryA(sub, NULL);
    (void)SetEnvironmentVariableA(ACC_SECRET, "must-not-cross");
    oc = acc_run(job, 60, 30, &out);
    (void)SetEnvironmentVariableA(ACC_SECRET, NULL);
    (void)snprintf(escaped, sizeof(escaped), "%s\\escaped.txt", outside);
    ok = oc.gate && zcl_devagent_worker_parse_result(job->rundir, &res);
    if (!ok)
        acc_fail("write", "no gated result from the confined child");
    else if (res.rc != 0)
        ok = acc_fail("write", res.evidence);
    else if (GetFileAttributesA(escaped) != INVALID_FILE_ATTRIBUTES)
        ok = acc_fail("write", "a file appeared outside the write root");
    else if (!acc_label_medium(job->rundir) || !acc_label_medium(sub))
        ok = acc_fail("write", "the run dir kept its low label");
    free(job);
    return ok;
}

static unsigned long long acc_read_ull(const char *path)
{
    FILE *f = fopen(path, "rb");
    unsigned long long v = 0;
    if (f) {
        if (fscanf(f, "%llu", &v) != 1)
            v = 0;
        (void)fclose(f);
    }
    return v;
}

static bool acc_case_memory(void)
{
    struct wkr_spawn_out out;
    struct wkr_outcome oc;
    struct wkr_job *job = acc_job("memory", "mode=memory\n");
    char progress[4200];
    unsigned long long total, cap = (unsigned long long)ACC_MEM_MB << 20;
    bool ok;
    if (!job)
        return acc_fail("memory", "cannot make the run dir");
    oc = acc_run(job, 60, 30, &out);
    (void)snprintf(progress, sizeof(progress), "%s/allocated.txt",
                   job->rundir);
    total = acc_read_ull(progress);
    ok = !oc.gate && oc.rc == 130 && strcmp(oc.note, "executor-signaled") == 0;
    if (!ok)
        acc_fail("memory", "the memory cap did not end in the crashed verdict");
    else if (total >= cap || total < cap / 4u)
        ok = acc_fail("memory", "the allocation stopped away from the cap");
    free(job);
    return ok;
}

static bool acc_grandchild_gone(const char *rundir)
{
    char path[4200];
    unsigned long long pid;
    HANDLE h;
    DWORD waited;
    (void)snprintf(path, sizeof(path), "%s/grandchild.pid", rundir);
    pid = acc_read_ull(path);
    if (pid == 0)
        return false; /* it never started: the case proves nothing */
    h = OpenProcess(SYNCHRONIZE, FALSE, (DWORD)pid);
    if (!h)
        return true;
    waited = WaitForSingleObject(h, 2000);
    CloseHandle(h);
    return waited == WAIT_OBJECT_0;
}

static bool acc_case_tree(void)
{
    struct wkr_spawn_out out;
    struct wkr_outcome oc;
    struct wkr_job *job = acc_job("tree", "mode=tree\n");
    bool ok;
    if (!job)
        return acc_fail("tree", "cannot make the run dir");
    oc = acc_run(job, 4, 30, &out);
    ok = out.status == 0 && oc.rc == 124 &&
         strcmp(oc.note, "executor-time-cap") == 0;
    if (!ok)
        acc_fail("tree", "the wall cap did not end in the timeout verdict");
    else if (!acc_grandchild_gone(job->rundir))
        ok = acc_fail("tree", "the grandchild outlived the job");
    free(job);
    return ok;
}

static bool acc_case_cpu(void)
{
    struct wkr_spawn_out out;
    struct wkr_outcome oc;
    struct wkr_job *job = acc_job("cpu", "mode=cpu\n");
    bool ok;
    if (!job)
        return acc_fail("cpu", "cannot make the run dir");
    oc = acc_run(job, 25, 1, &out);
    ok = out.status == 1 && oc.rc == 130 && out.wall_ms < 20000;
    if (!ok)
        acc_fail("cpu", "the CPU cap did not end in the crashed verdict");
    free(job);
    return ok;
}

static bool acc_case_fail(void)
{
    struct wkr_spawn_out out;
    struct wkr_outcome oc;
    struct wkr_result res;
    struct wkr_job *job = acc_job("fail", "mode=fail\n");
    char verdict[32];
    bool ok;
    if (!job)
        return acc_fail("fail", "cannot make the run dir");
    oc = acc_run(job, 60, 30, &out);
    ok = oc.gate && zcl_devagent_worker_parse_result(job->rundir, &res) &&
         res.rc == 3 &&
         zcl_devagent_worker_gate(job, &res, verdict, sizeof(verdict), NULL,
                                  0, NULL) == 1 &&
         strcmp(verdict, "failed") == 0;
    if (!ok)
        acc_fail("fail", "a failing executor did not gate to failed");
    free(job);
    return ok;
}

/* The child entry itself, run in THIS (unconfined) process: nothing runs
 * and no result appears. */
static bool acc_case_refuse(void)
{
    struct wkr_job *job = acc_job("refuse", "mode=fail\n");
    char path[4200];
    bool ok;
    if (!job)
        return acc_fail("refuse", "cannot make the run dir");
    ok = zcl_devagent_worker_job_store(job, 64ull << 20) &&
         zcl_devagent_worker_child_main(job->rundir, acc_executor) != 0;
    (void)snprintf(path, sizeof(path), "%s/executor_result.json",
                   job->rundir);
    if (!ok || GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES)
        ok = acc_fail("refuse", "the unconfined child entry ran the executor");
    free(job);
    return ok;
}

static bool runtime_is_wine(void)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    return ntdll && GetProcAddress(ntdll, "wine_get_version") != NULL;
}

int main(int argc, char **argv)
{
    enum platform_confine_missing m;
    int failed = 0;
    if (argc == 3 && strcmp(argv[1], WKR_CHILD_FLAG) == 0)
        return zcl_devagent_worker_child_main(argv[2], acc_executor);
    if (argc == 3 && strcmp(argv[1], ACC_SLEEPER) == 0)
        return acc_sleeper(argv[2]);
    if (runtime_is_wine()) {
        puts("devagent_worker_confine: REFUSE Wine is not native Windows");
        return 77;
    }
    m = platform_confined_probe();
    if (m != PLATFORM_CONFINE_ARMED) {
        printf("devagent_worker_confine: REFUSE missing=%s\n",
               platform_confine_missing_name(m));
        return 77;
    }
    if (!acc_base()) {
        puts("devagent_worker_confine: FAIL cannot make the scratch base");
        return 1;
    }
    failed += !acc_case_write();
    failed += !acc_case_memory();
    failed += !acc_case_tree();
    failed += !acc_case_cpu();
    failed += !acc_case_fail();
    failed += !acc_case_refuse();
    if (failed) {
        printf("devagent_worker_confine: %d case(s) FAILED (scratch %s)\n",
               failed, g_base);
        return 1;
    }
    puts("devagent_worker_confine: PASS (write scope, memory cap, job-tree "
         "timeout, CPU cap, failed verdict, unconfined refusal)");
    return 0;
}
#else
typedef int devagent_worker_confine_windows_acceptance_not_built;
#endif
