/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Verify watcher launch and stop capabilities on Windows. */
#include "platform/process_lifecycle.h"
#include "platform/watcher_lease.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <aclapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

static const char hash_a[] =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static const char hash_b[] =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

static bool runtime_is_wine(void)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    return ntdll && GetProcAddress(ntdll, "wine_get_version") != NULL;
}

static bool protected_stop_acl(HANDLE event)
{
    PSECURITY_DESCRIPTOR descriptor = NULL;
    PACL dacl = NULL;
    DWORD rc = GetSecurityInfo(event, SE_KERNEL_OBJECT,
        DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &descriptor);
    SECURITY_DESCRIPTOR_CONTROL control = 0; DWORD revision = 0;
    bool ok = rc == ERROR_SUCCESS && dacl &&
              GetSecurityDescriptorControl(descriptor, &control, &revision) &&
              (control & SE_DACL_PROTECTED) != 0;
    BYTE everyone[SECURITY_MAX_SID_SIZE]; DWORD size = sizeof(everyone);
    ok = ok && CreateWellKnownSid(WinWorldSid, NULL, everyone, &size);
    ACL_SIZE_INFORMATION info = {0};
    ok = ok && GetAclInformation(dacl, &info, sizeof(info), AclSizeInformation);
    for (DWORD i = 0; ok && i < info.AceCount; ++i) {
        void *raw = NULL; ok = GetAce(dacl, i, &raw) != 0;
        if (ok && ((ACE_HEADER *)raw)->AceType == ACCESS_ALLOWED_ACE_TYPE)
            ok = !EqualSid(&((ACCESS_ALLOWED_ACE *)raw)->SidStart, everyone);
    }
    if (descriptor) LocalFree(descriptor);
    return ok;
}

static int child_main(int argc, char **argv)
{
    if (argc != 7) return 20;
    uintptr_t inherited = (uintptr_t)_strtoui64(argv[3], NULL, 10);
    struct platform_watcher_lease lease;
    platform_watcher_lease_init(&lease);
    bool accepted = platform_watcher_lease_accept(
        &lease, inherited, argv[4], argv[5], argv[2][2] == 'r' ? hash_b : hash_a);
    if (strcmp(argv[2], "--reject") == 0)
        return accepted ? 21 : 0;
    if (!accepted || !platform_watcher_lease_wait_stop(&lease, 5000))
        return 22;
    platform_watcher_lease_close(&lease);
    return 0;
}

static bool spawn_case(const char *self, const char *root, bool reject)
{
    struct platform_watcher_launch launch;
    platform_watcher_launch_init(&launch);
    if (!platform_watcher_launch_prepare(&launch, root, self, hash_a))
        return false;
    if (!protected_stop_acl((HANDLE)launch.stop_native))
        return false;
    char handle[32];
    snprintf(handle, sizeof(handle), "%llu",
             (unsigned long long)platform_watcher_launch_inherited(&launch));
    const char *argv[] = {self, "--child", reject ? "--reject" : "--accept",
                          handle, root, self, "reserved", NULL};
    char system_root[512];
    DWORD got = GetEnvironmentVariableA("SystemRoot", system_root,
                                        sizeof(system_root));
    char system_env[560];
    if (!got || got >= sizeof(system_root) ||
        snprintf(system_env, sizeof(system_env), "SystemRoot=%s", system_root) <= 0)
        return false;
    const char *env[] = {system_env, NULL};
    uintptr_t inherited[] = {platform_watcher_launch_inherited(&launch)};
    struct platform_process_options options = {
        .image = self, .argv = argv, .cwd = root, .env = env,
        .inherited = inherited, .inherited_count = 1};
    struct platform_process process; platform_process_init(&process);
    bool ok = platform_process_start_hidden(&process, &options) &&
              platform_watcher_launch_publish(&launch);
    CloseHandle((HANDLE)launch.inherited_read);
    launch.inherited_read = UINTPTR_MAX;
    if (ok && !reject) {
        Sleep(100);
        ok = platform_watcher_lease_signal_stop(launch.nonce);
    }
    uint32_t exit_code = UINT32_MAX;
    ok = ok && platform_process_wait(&process, 5000, &exit_code) ==
                   PLATFORM_PROCESS_WAIT_EXITED && exit_code == 0;
    platform_process_close(&process);
    platform_watcher_launch_close(&launch);
    return ok;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--child") == 0)
        return child_main(argc, argv);
    struct platform_watcher_lease empty;
    platform_watcher_lease_init(&empty);
    if (platform_watcher_lease_accept(&empty, UINTPTR_MAX, ".", argv[0], hash_a) ||
        platform_watcher_lease_signal_stop(hash_b)) {
        fputs("watcher_lease_acceptance: absent capability accepted\n", stderr);
        return 1;
    }
    char self[4096], root[4096];
    DWORD self_n = GetModuleFileNameA(NULL, self, sizeof(self));
    DWORD root_n = GetCurrentDirectoryA(sizeof(root), root);
    if (!self_n || self_n >= sizeof(self) || !root_n || root_n >= sizeof(root) ||
        !spawn_case(self, root, false) || !spawn_case(self, root, true)) {
        if (runtime_is_wine()) {
            fputs("watcher_lease_acceptance: REFUSE: Wine cannot prove private "
                  "event ACL and inherited-handle lifecycle\n", stderr);
            return 77;
        }
        fputs("watcher_lease_acceptance: launch/refusal/stop failed\n", stderr);
        return 1;
    }
    puts("watcher_lease_acceptance: PASS");
    return 0;
}
