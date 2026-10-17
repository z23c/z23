/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Windows confinement backend for one bounded executor child: a
 * restricted low-integrity token, a kill-on-close Job Object carrying the
 * memory, CPU-time and active-process caps, low-writable labels on exactly
 * the named write roots, and an explicit NUL-only handle list. Every public
 * entry has ONE body; the Windows mechanics are static helpers above it and
 * every other host answers PLATFORM_CONFINE_MISSING_OS. */
#include "platform/confined_process.h"
#include "process_lifecycle_internal.h"
#include "base/safe_alloc.h"
#include "util/log_macros.h"

#include <stdlib.h>
#include <string.h>

#define CF_MAX_ROOTS 8u
#define CF_MAX_CPU_SECONDS 1000000000ull
#define CF_SCAN_DEPTH 64
#define CF_SCAN_ENTRIES 2000000ull
#define CF_DRAIN_SLICES 200 /* x 25 ms: bounded wait for an empty job */

const char *platform_confine_missing_name(enum platform_confine_missing m)
{
    switch (m) {
    case PLATFORM_CONFINE_ARMED: return "armed";
    case PLATFORM_CONFINE_MISSING_OS: return "os";
    case PLATFORM_CONFINE_MISSING_JOB_OBJECT: return "job-object";
    case PLATFORM_CONFINE_MISSING_RESTRICTED_TOKEN: return "restricted-token";
    case PLATFORM_CONFINE_MISSING_LOW_INTEGRITY: return "low-integrity";
    case PLATFORM_CONFINE_MISSING_WRITE_LABEL: return "write-label";
    case PLATFORM_CONFINE_MISSING_HANDLE_LIST: return "handle-list";
    case PLATFORM_CONFINE_MISSING_LAUNCH: return "launch";
    case PLATFORM_CONFINE_BAD_SPEC: return "bad-spec";
    }
    return "unknown";
}

bool platform_confined_exit_is_crash(uint32_t exit_code)
{
    /* NTSTATUS severity 3 (error): 0xC0000005 access violation,
     * 0xC0000409 fast-fail/abort, 0xC00000FD stack overflow, ... */
    return (exit_code & 0xC0000000u) == 0xC0000000u;
}

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#define CF_LABEL_LOW L"S:(ML;OICI;NW;;;LW)"
#define CF_LABEL_MEDIUM L"S:(ML;OICI;NW;;;ME)"
#define CF_REQUIRED_LIMITS                                                   \
    (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS |  \
     JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_JOB_TIME)

/* Group SIDs a confined child never holds enabled: each one present in the
 * caller's token becomes deny-only in the child's token. */
static const WELL_KNOWN_SID_TYPE cf_privileged_sids[] = {
    WinBuiltinAdministratorsSid,     WinBuiltinPowerUsersSid,
    WinBuiltinAccountOperatorsSid,   WinBuiltinSystemOperatorsSid,
    WinBuiltinPrintOperatorsSid,     WinBuiltinBackupOperatorsSid,
    WinBuiltinNetworkConfigurationOperatorsSid,
};

/* ── token: restricted, privileges stripped, low integrity ─────────────── */

static bool cf_sid_privileged(PSID sid)
{
    for (size_t i = 0;
         i < sizeof(cf_privileged_sids) / sizeof(cf_privileged_sids[0]); i++)
        if (IsWellKnownSid(sid, cf_privileged_sids[i]))
            return true;
    return false;
}

static void *cf_token_info(HANDLE token, TOKEN_INFORMATION_CLASS klass)
{
    DWORD size = 0;
    void *info;
    (void)GetTokenInformation(token, klass, NULL, 0, &size);
    if (size == 0)
        return NULL;
    info = zcl_malloc(size, "confine-token-info");
    if (info && !GetTokenInformation(token, klass, info, size, &size)) {
        free(info);
        info = NULL;
    }
    return info;
}

static bool cf_restrict(HANDLE self, HANDLE *out)
{
    TOKEN_GROUPS *groups = cf_token_info(self, TokenGroups);
    SID_AND_ATTRIBUTES *deny;
    DWORD n = 0;
    bool ok;
    if (!groups)
        return false;
    deny = zcl_calloc((size_t)groups->GroupCount + 1u, sizeof(*deny),
                      "confine-deny-sids");
    for (DWORD i = 0; deny && i < groups->GroupCount; i++)
        if (cf_sid_privileged(groups->Groups[i].Sid))
            deny[n++].Sid = groups->Groups[i].Sid;
    ok = deny && CreateRestrictedToken(self, DISABLE_MAX_PRIVILEGE | LUA_TOKEN,
                                       n, n ? deny : NULL, 0, NULL, 0, NULL,
                                       out) != 0;
    free(deny);
    free(groups);
    return ok;
}

static bool cf_lower(HANDLE token)
{
    BYTE sid[SECURITY_MAX_SID_SIZE];
    DWORD size = sizeof(sid);
    TOKEN_MANDATORY_LABEL label;
    if (!CreateWellKnownSid(WinLowLabelSid, NULL, sid, &size))
        return false;
    memset(&label, 0, sizeof(label));
    label.Label.Attributes = SE_GROUP_INTEGRITY;
    label.Label.Sid = (PSID)sid;
    return SetTokenInformation(token, TokenIntegrityLevel, &label,
                               (DWORD)sizeof(label) +
                                   GetLengthSid((PSID)sid)) != 0;
}

static enum platform_confine_missing cf_token(HANDLE *out)
{
    HANDLE self = NULL;
    bool made;
    *out = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_DUPLICATE | TOKEN_QUERY |
                              TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT,
                          &self))
        return PLATFORM_CONFINE_MISSING_RESTRICTED_TOKEN;
    made = cf_restrict(self, out);
    CloseHandle(self);
    if (!made) {
        *out = NULL;
        return PLATFORM_CONFINE_MISSING_RESTRICTED_TOKEN;
    }
    if (!cf_lower(*out)) {
        CloseHandle(*out);
        *out = NULL;
        return PLATFORM_CONFINE_MISSING_LOW_INTEGRITY;
    }
    return PLATFORM_CONFINE_ARMED;
}

/* ── job: kill-on-close plus every cap, UI isolated ─────────────────────── */

static enum platform_confine_missing cf_job(uint64_t memory_bytes,
                                            uint64_t cpu_seconds,
                                            uint32_t active_processes,
                                            HANDLE *out)
{
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
    JOBOBJECT_BASIC_UI_RESTRICTIONS ui;
    HANDLE job = CreateJobObjectW(NULL, NULL);
    *out = NULL;
    if (!job)
        return PLATFORM_CONFINE_MISSING_JOB_OBJECT;
    memset(&limits, 0, sizeof(limits));
    limits.BasicLimitInformation.LimitFlags =
        CF_REQUIRED_LIMITS | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    limits.BasicLimitInformation.ActiveProcessLimit = active_processes;
    limits.BasicLimitInformation.PerJobUserTimeLimit.QuadPart =
        (LONGLONG)cpu_seconds * 10000000LL;
    limits.JobMemoryLimit = (SIZE_T)memory_bytes;
    memset(&ui, 0, sizeof(ui));
    ui.UIRestrictionsClass =
        JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
        JOB_OBJECT_UILIMIT_EXITWINDOWS | JOB_OBJECT_UILIMIT_GLOBALATOMS |
        JOB_OBJECT_UILIMIT_HANDLES | JOB_OBJECT_UILIMIT_READCLIPBOARD |
        JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS | JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                 &limits, sizeof(limits)) ||
        !SetInformationJobObject(job, JobObjectBasicUIRestrictions, &ui,
                                 sizeof(ui))) {
        CloseHandle(job);
        return PLATFORM_CONFINE_MISSING_JOB_OBJECT;
    }
    *out = job;
    return PLATFORM_CONFINE_ARMED;
}

/* ── write roots: low-writable label on exactly the named trees ─────────
 * The relabel propagates through the tree, so a reparse point anywhere
 * inside would carry the grant (or its release) to whatever it names. A
 * root that holds one — including one a previous child planted — is
 * refused before any label is written. */

static bool cf_scan_clean(const wchar_t *dir, int depth,
                          unsigned long long *seen);

static bool cf_scan_entry(const wchar_t *dir, const WIN32_FIND_DATAW *e,
                          int depth, unsigned long long *seen)
{
    wchar_t *child;
    size_t n;
    bool ok;
    if (wcscmp(e->cFileName, L".") == 0 || wcscmp(e->cFileName, L"..") == 0)
        return true;
    if (++*seen > CF_SCAN_ENTRIES ||
        (e->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
        return false;
    if (!(e->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        return true;
    n = wcslen(dir) + wcslen(e->cFileName) + 2u;
    child = zcl_calloc(n, sizeof(*child), "confine-scan-path");
    if (!child)
        return false;
    (void)swprintf(child, n, L"%ls\\%ls", dir, e->cFileName);
    ok = cf_scan_clean(child, depth + 1, seen);
    free(child);
    return ok;
}

static bool cf_scan_clean(const wchar_t *dir, int depth,
                          unsigned long long *seen)
{
    WIN32_FIND_DATAW entry;
    wchar_t *pattern;
    HANDLE find;
    size_t n = wcslen(dir) + 3u;
    bool ok = true;
    if (depth > CF_SCAN_DEPTH)
        return false;
    pattern = zcl_calloc(n, sizeof(*pattern), "confine-scan-pattern");
    if (!pattern)
        return false;
    (void)swprintf(pattern, n, L"%ls\\*", dir);
    find = FindFirstFileExW(pattern, FindExInfoBasic, &entry,
                            FindExSearchNameMatch, NULL, 0);
    free(pattern);
    if (find == INVALID_HANDLE_VALUE)
        return GetLastError() == ERROR_FILE_NOT_FOUND;
    do {
        ok = cf_scan_entry(dir, &entry, depth, seen);
    } while (ok && FindNextFileW(find, &entry));
    if (ok && GetLastError() != ERROR_NO_MORE_FILES)
        ok = false;
    FindClose(find);
    return ok;
}

/* A root is a real, absolute directory with no reparse point at the root
 * or anywhere beneath it. */
static bool cf_root_clean(const wchar_t *path)
{
    DWORD attrs;
    unsigned long long seen = 0;
    if (!platform_process_windows_absolute(path))
        return false;
    attrs = GetFileAttributesW(path);
    if (attrs == INVALID_FILE_ATTRIBUTES ||
        !(attrs & FILE_ATTRIBUTE_DIRECTORY) ||
        (attrs & FILE_ATTRIBUTE_REPARSE_POINT))
        return false;
    return cf_scan_clean(path, 0, &seen);
}

/* Apply one inheritable label to the root and every object beneath it.
 * TREE_SEC_INFO_SET (grant) propagates the low label to what already
 * exists; TREE_SEC_INFO_RESET (release) also replaces any explicit label
 * the child stamped on its own files, so nothing it made stays low. */
static bool cf_label(const char *root, const wchar_t *sddl, DWORD action)
{
    PSECURITY_DESCRIPTOR sd = NULL;
    PACL sacl = NULL;
    BOOL present = FALSE, defaulted = FALSE;
    wchar_t *path = platform_process_windows_utf16(root);
    bool ok = path && cf_root_clean(path) &&
              ConvertStringSecurityDescriptorToSecurityDescriptorW(
                  sddl, SDDL_REVISION_1, &sd, NULL) &&
              GetSecurityDescriptorSacl(sd, &present, &sacl, &defaulted) &&
              present && sacl;
    if (ok) {
        DWORD error = TreeSetNamedSecurityInfoW(
            path, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, NULL,
            NULL, NULL, sacl, action, NULL, ProgressInvokeNever, NULL);
        ok = error == ERROR_SUCCESS;
        if (!ok)
            LOG_ERROR("confined_process",
                      "write-root label refused: api=TreeSetNamedSecurityInfoW "
                      "action=%lu win32=%lu", (unsigned long)action,
                      (unsigned long)error);
    }
    if (sd)
        LocalFree(sd);
    free(path);
    return ok;
}
static enum platform_confine_missing
cf_grant_roots(const struct platform_confined_spec *spec)
{
    for (size_t i = 0; i < spec->write_root_count; i++) {
        if (!cf_label(spec->write_roots[i], CF_LABEL_LOW,
                      TREE_SEC_INFO_SET)) {
            (void)platform_confined_release_roots(spec->write_roots, i + 1u);
            return PLATFORM_CONFINE_MISSING_WRITE_LABEL;
        }
    }
    return PLATFORM_CONFINE_ARMED;
}

/* ── launch: suspended, NUL-only handle list, assigned, then resumed ──── */

struct cf_launch_text {
    wchar_t *image;
    wchar_t *line;
    wchar_t *env;
    wchar_t *cwd;
};

static void cf_text_free(struct cf_launch_text *t)
{
    free(t->image);
    free(t->line);
    free(t->env);
    free(t->cwd);
}

static bool cf_text_make(const struct platform_confined_spec *spec,
                         struct cf_launch_text *t)
{
    memset(t, 0, sizeof(*t));
    t->image = platform_process_windows_utf16(spec->image);
    t->line = platform_process_windows_command_line(spec->argv);
    t->env = platform_process_windows_environment(spec->env);
    if (spec->cwd)
        t->cwd = platform_process_windows_utf16(spec->cwd);
    return t->image && platform_process_windows_absolute(t->image) &&
           t->line && t->env &&
           (!spec->cwd ||
            (t->cwd && platform_process_windows_absolute(t->cwd)));
}

/* The one inheritable handle: NUL, as stdin, stdout and stderr. */
static LPPROC_THREAD_ATTRIBUTE_LIST cf_handle_list(HANDLE *nul)
{
    SIZE_T size = 0;
    LPPROC_THREAD_ATTRIBUTE_LIST attrs;
    (void)InitializeProcThreadAttributeList(NULL, 1, 0, &size);
    attrs = zcl_malloc(size, "confine-attribute-list");
    if (!attrs)
        return NULL;
    if (!InitializeProcThreadAttributeList(attrs, 1, 0, &size)) {
        free(attrs);
        return NULL;
    }
    if (!UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                   nul, sizeof(*nul), NULL, NULL)) {
        DeleteProcThreadAttributeList(attrs);
        free(attrs);
        return NULL;
    }
    return attrs;
}

static HANDLE cf_null_handle(void)
{
    SECURITY_ATTRIBUTES security;
    memset(&security, 0, sizeof(security));
    security.nLength = sizeof(security);
    security.bInheritHandle = TRUE;
    return CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE, &security,
                       OPEN_EXISTING, 0, NULL);
}

static bool cf_create(HANDLE token, HANDLE job, struct cf_launch_text *t,
                      HANDLE nul, LPPROC_THREAD_ATTRIBUTE_LIST attrs,
                      PROCESS_INFORMATION *pi)
{
    STARTUPINFOEXW startup;
    DWORD flags = CREATE_NO_WINDOW | CREATE_SUSPENDED |
                  CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT;
    UINT previous;
    bool started, assigned, resumed;
    memset(&startup, 0, sizeof(startup));
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startup.StartupInfo.wShowWindow = SW_HIDE;
    startup.StartupInfo.hStdInput = nul;
    startup.StartupInfo.hStdOutput = nul;
    startup.StartupInfo.hStdError = nul;
    startup.lpAttributeList = attrs;
    previous = SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX |
                            SEM_NOOPENFILEERRORBOX);
    started = CreateProcessAsUserW(token, t->image, t->line, NULL, NULL, TRUE,
                                   flags, t->env, t->cwd, &startup.StartupInfo,
                                   pi) != 0;
    if (!started) {
        DWORD error = GetLastError();
        LOG_ERROR("confined_process",
                  "launch refused: api=CreateProcessAsUserW win32=%lu",
                  (unsigned long)error);
    }
    assigned = started && AssignProcessToJobObject(job, pi->hProcess) != 0;
    if (started && !assigned) {
        DWORD error = GetLastError();
        LOG_ERROR("confined_process",
                  "launch refused: api=AssignProcessToJobObject win32=%lu",
                  (unsigned long)error);
    }
    resumed = assigned && ResumeThread(pi->hThread) != (DWORD)-1;
    if (assigned && !resumed) {
        DWORD error = GetLastError();
        LOG_ERROR("confined_process",
                  "launch refused: api=ResumeThread win32=%lu",
                  (unsigned long)error);
    }
    (void)SetErrorMode(previous);
    if (started && !resumed) {
        (void)TerminateProcess(pi->hProcess, 125u);
        CloseHandle(pi->hThread);
        CloseHandle(pi->hProcess);
    }
    return resumed;
}

static enum platform_confine_missing
cf_launch(struct platform_process *process,
          const struct platform_confined_spec *spec, HANDLE token, HANDLE job)
{
    struct cf_launch_text text;
    PROCESS_INFORMATION pi;
    LPPROC_THREAD_ATTRIBUTE_LIST attrs = NULL;
    HANDLE nul = INVALID_HANDLE_VALUE;
    enum platform_confine_missing m = PLATFORM_CONFINE_MISSING_LAUNCH;
    memset(&pi, 0, sizeof(pi));
    if (!cf_text_make(spec, &text)) {
        cf_text_free(&text);
        return PLATFORM_CONFINE_BAD_SPEC;
    }
    nul = cf_null_handle();
    if (nul != INVALID_HANDLE_VALUE)
        attrs = cf_handle_list(&nul);
    if (!attrs)
        m = PLATFORM_CONFINE_MISSING_HANDLE_LIST;
    else if (cf_create(token, job, &text, nul, attrs, &pi)) {
        CloseHandle(pi.hThread);
        process->native = (uintptr_t)pi.hProcess;
        process->containment = (uintptr_t)job;
        process->pid = pi.dwProcessId;
        m = PLATFORM_CONFINE_ARMED;
    }
    if (attrs) {
        DeleteProcThreadAttributeList(attrs);
        free(attrs);
    }
    if (nul != INVALID_HANDLE_VALUE)
        CloseHandle(nul);
    cf_text_free(&text);
    return m;
}

static bool cf_roots_ok(const char *const *roots, size_t count)
{
    if (!roots || count == 0 || count > CF_MAX_ROOTS)
        return false;
    for (size_t i = 0; i < count; i++)
        if (!roots[i] || !roots[i][0])
            return false;
    return true;
}

static bool cf_spec_ok(const struct platform_process *process,
                       const struct platform_confined_spec *spec)
{
    if (!process || process->native != UINTPTR_MAX || !spec ||
        !spec->image || !spec->argv || !spec->argv[0] || !spec->env)
        return false;
    return cf_roots_ok(spec->write_roots, spec->write_root_count) &&
           spec->memory_bytes > 0 && spec->cpu_seconds > 0 &&
           spec->cpu_seconds <= CF_MAX_CPU_SECONDS &&
           spec->active_processes > 0;
}

static enum platform_confine_missing
cf_start(struct platform_process *process,
         const struct platform_confined_spec *spec)
{
    HANDLE token = NULL, job = NULL;
    enum platform_confine_missing m;
    if (!cf_spec_ok(process, spec))
        return PLATFORM_CONFINE_BAD_SPEC;
    m = cf_token(&token);
    if (m == PLATFORM_CONFINE_ARMED)
        m = cf_job(spec->memory_bytes, spec->cpu_seconds,
                   spec->active_processes, &job);
    if (m == PLATFORM_CONFINE_ARMED)
        m = cf_grant_roots(spec);
    if (m == PLATFORM_CONFINE_ARMED) {
        m = cf_launch(process, spec, token, job);
        if (m != PLATFORM_CONFINE_ARMED)
            (void)platform_confined_release_roots(spec->write_roots,
                                                  spec->write_root_count);
    }
    if (token)
        CloseHandle(token);
    if (m != PLATFORM_CONFINE_ARMED && job)
        CloseHandle(job);
    return m;
}

static enum platform_confine_missing cf_probe(void)
{
    HANDLE token = NULL, job = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;
    enum platform_confine_missing m = cf_token(&token);
    if (m == PLATFORM_CONFINE_ARMED)
        m = cf_job(64u * 1024u * 1024u, 1u, 1u, &job);
    if (m == PLATFORM_CONFINE_ARMED &&
        !ConvertStringSecurityDescriptorToSecurityDescriptorW(
            CF_LABEL_LOW, SDDL_REVISION_1, &sd, NULL))
        m = PLATFORM_CONFINE_MISSING_WRITE_LABEL;
    if (sd)
        LocalFree(sd);
    if (token)
        CloseHandle(token);
    if (job)
        CloseHandle(job);
    return m;
}

/* Kill anything still alive in the job, wait (bounded) until it is empty,
 * then read the exit code and the job's accounting. */
static bool cf_report(const struct platform_process *process,
                      struct platform_confined_report *report)
{
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION acct;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
    HANDLE job = (HANDLE)process->containment;
    DWORD code = 0;
    LONGLONG cap;
    (void)TerminateJobObject(job, 1u);
    for (int i = 0; i < CF_DRAIN_SLICES; i++) {
        if (!QueryInformationJobObject(job, JobObjectBasicAccountingInformation,
                                       &acct, sizeof(acct), NULL))
            return false;
        if (acct.ActiveProcesses == 0)
            break;
        Sleep(25);
    }
    if (!QueryInformationJobObject(job, JobObjectExtendedLimitInformation,
                                   &limits, sizeof(limits), NULL) ||
        !GetExitCodeProcess((HANDLE)process->native, &code))
        return false;
    cap = limits.BasicLimitInformation.PerJobUserTimeLimit.QuadPart;
    report->exit_code = code;
    report->crashed = platform_confined_exit_is_crash(code);
    report->cpu_limit_hit = cap > 0 && acct.TotalUserTime.QuadPart >= cap;
    report->peak_memory_bytes = (uint64_t)limits.PeakJobMemoryUsed;
    return acct.ActiveProcesses == 0;
}

static enum platform_confine_missing cf_self_token(void)
{
    HANDLE token = NULL;
    TOKEN_MANDATORY_LABEL *label;
    BYTE admin[SECURITY_MAX_SID_SIZE];
    DWORD size = sizeof(admin), rid = 0xFFFFFFFFu;
    BOOL member = TRUE;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return PLATFORM_CONFINE_MISSING_LOW_INTEGRITY;
    label = cf_token_info(token, TokenIntegrityLevel);
    CloseHandle(token);
    if (label) {
        PUCHAR count = GetSidSubAuthorityCount(label->Label.Sid);
        if (count && *count > 0)
            rid = *GetSidSubAuthority(label->Label.Sid, (DWORD)(*count - 1u));
        free(label);
    }
    if (rid > SECURITY_MANDATORY_LOW_RID)
        return PLATFORM_CONFINE_MISSING_LOW_INTEGRITY;
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, admin, &size) ||
        !CheckTokenMembership(NULL, (PSID)admin, &member) || member)
        return PLATFORM_CONFINE_MISSING_RESTRICTED_TOKEN;
    return PLATFORM_CONFINE_ARMED;
}

static enum platform_confine_missing cf_self_check(uint64_t max_memory_bytes)
{
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
    BOOL in_job = FALSE;
    if (!IsProcessInJob(GetCurrentProcess(), NULL, &in_job) || !in_job)
        return PLATFORM_CONFINE_MISSING_JOB_OBJECT;
    memset(&limits, 0, sizeof(limits));
    if (!QueryInformationJobObject(NULL, JobObjectExtendedLimitInformation,
                                   &limits, sizeof(limits), NULL))
        return PLATFORM_CONFINE_MISSING_JOB_OBJECT;
    if ((limits.BasicLimitInformation.LimitFlags & CF_REQUIRED_LIMITS) !=
            CF_REQUIRED_LIMITS ||
        limits.JobMemoryLimit == 0 ||
        (uint64_t)limits.JobMemoryLimit > max_memory_bytes)
        return PLATFORM_CONFINE_MISSING_JOB_OBJECT;
    return cf_self_token();
}
#endif /* _WIN32 */

/* ── public entries: one body each ──────────────────────────────────────── */

enum platform_confine_missing platform_confined_probe(void)
{
#if defined(_WIN32)
    return cf_probe();
#else
    return PLATFORM_CONFINE_MISSING_OS;
#endif
}

enum platform_confine_missing platform_confined_start(
    struct platform_process *process,
    const struct platform_confined_spec *spec)
{
#if defined(_WIN32)
    return cf_start(process, spec);
#else
    (void)process;
    (void)spec;
    return PLATFORM_CONFINE_MISSING_OS;
#endif
}

bool platform_confined_report(const struct platform_process *process,
                              struct platform_confined_report *report)
{
    if (!process || !report || process->native == UINTPTR_MAX ||
        process->containment == UINTPTR_MAX)
        return false;
    memset(report, 0, sizeof(*report));
#if defined(_WIN32)
    return cf_report(process, report);
#else
    return false;
#endif
}

bool platform_confined_release_roots(const char *const *roots, size_t count)
{
    bool ok = roots != NULL && count > 0;
    /* Every root is attempted even after one fails: a failure must never
     * leave a later root carrying the low grant. */
    for (size_t i = 0; roots && i < count; i++) {
#if defined(_WIN32)
        if (!roots[i] || !cf_label(roots[i], CF_LABEL_MEDIUM,
                                   TREE_SEC_INFO_RESET))
            ok = false;
#else
        ok = false;
#endif
    }
    return ok;
}

enum platform_confine_missing platform_confined_self_check(
    uint64_t max_memory_bytes)
{
#if defined(_WIN32)
    return cf_self_check(max_memory_bytes);
#else
    (void)max_memory_bytes;
    return PLATFORM_CONFINE_MISSING_OS;
#endif
}
