/* Headless acceptance for durable watcher ownership records. */
#include "platform/private_directory.h"
#include "platform/watcher_store.h"

#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <string.h>
#include <windows.h>

static int fail(const char *message)
{
    fprintf(stderr, "watcher_store_acceptance: %s\n", message);
    return 1;
}

int main(void)
{
    wchar_t temp[MAX_PATH], root[MAX_PATH], spoof[MAX_PATH], link[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, temp) ||
        swprintf(root, MAX_PATH, L"%lsz23-watcher-store-%lu", temp,
                 (unsigned long)GetCurrentProcessId()) <= 0 ||
        swprintf(spoof, MAX_PATH, L"%ls\\spoof.record", root) <= 0 ||
        swprintf(link, MAX_PATH, L"%ls\\link.record", root) <= 0)
        return fail("fixture path failed");
    char root_utf8[MAX_PATH * 3];
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, root, -1,
                             root_utf8, sizeof(root_utf8), NULL, NULL) ||
        !platform_private_directory_create(root_utf8))
        return fail("private root create failed");

    struct platform_watcher_store owner, observer;
    platform_watcher_store_init(&owner);
    platform_watcher_store_init(&observer);
    if (platform_watcher_store_open(&owner, root_utf8) !=
            PLATFORM_WATCHER_STORE_OK ||
        platform_watcher_store_open(&observer, root_utf8) !=
            PLATFORM_WATCHER_STORE_OK ||
        platform_watcher_store_try_acquire(&owner, "watch.lock", true) !=
            PLATFORM_WATCHER_STORE_OK ||
        platform_watcher_store_try_acquire(&observer, "watch.lock", false) !=
            PLATFORM_WATCHER_STORE_BUSY)
        return fail("exclusive busy ownership failed");

    struct platform_watcher_record_identity starting, ready;
    const char first[] = "starting", second[] = "ready";
    if (platform_watcher_store_publish(&owner, "watch.record", first,
            sizeof(first) - 1, NULL, &starting) != PLATFORM_WATCHER_STORE_OK)
        return fail("initial publication failed");
    char body[32] = {0}; size_t length = 0;
    if (platform_watcher_store_read_while_busy(&observer, "watch.lock",
            "watch.record", body, sizeof(body), &length, NULL) !=
            PLATFORM_WATCHER_STORE_OK || length != sizeof(first) - 1 ||
        memcmp(body, first, length) != 0)
        return fail("stable busy read failed");
    if (platform_watcher_store_publish(&owner, "watch.record", second,
            sizeof(second) - 1, &starting, &ready) != PLATFORM_WATCHER_STORE_OK ||
        platform_watcher_store_retire_exact(&owner, "watch.record", &starting) !=
            PLATFORM_WATCHER_STORE_REFUSED)
        return fail("atomic update/stale identity refusal failed");

    HANDLE bad = CreateFileW(spoof, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                             FILE_ATTRIBUTE_NORMAL, NULL);
    if (bad == INVALID_HANDLE_VALUE ||
        WriteFile(bad, first, sizeof(first) - 1, &(DWORD){0}, NULL) == 0) {
        if (bad != INVALID_HANDLE_VALUE) CloseHandle(bad);
        return fail("spoof fixture failed");
    }
    CloseHandle(bad);
    if (platform_watcher_store_read_while_busy(&observer, "watch.lock",
            "spoof.record", body, sizeof(body), &length, NULL) !=
            PLATFORM_WATCHER_STORE_REFUSED)
        return fail("inherited/spoof ACL accepted");
    DWORD link_flags = 0;
#ifdef SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
    link_flags |= SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
#endif
    if (CreateSymbolicLinkW(link, spoof, link_flags)) {
        enum platform_watcher_store_result linked =
            platform_watcher_store_read_while_busy(
                &observer, "watch.lock", "link.record", body,
                sizeof(body), &length, NULL);
        if (linked != PLATFORM_WATCHER_STORE_REFUSED)
            return fail("record reparse point accepted");
        DeleteFileW(link);
    }

    struct platform_directory_child residue;
    platform_directory_child_init(&residue);
    if (!platform_directory_child_create(&owner.directory,
                                          ".watcher-crash.tmp", &residue))
        return fail("crash residue fixture failed");
    platform_directory_child_close(&residue);
    memset(body, 0, sizeof(body));
    if (platform_watcher_store_read_while_busy(&observer, "watch.lock",
            "watch.record", body, sizeof(body), &length, NULL) !=
            PLATFORM_WATCHER_STORE_OK || length != sizeof(second) - 1 ||
        memcmp(body, second, length) != 0 ||
        platform_watcher_store_retire_exact(&owner, "watch.record", &ready) !=
            PLATFORM_WATCHER_STORE_OK)
        return fail("residue isolation/exact retirement failed");

    platform_watcher_store_release(&owner);
    if (platform_watcher_store_read_while_busy(&observer, "watch.lock",
            "watch.record", body, sizeof(body), &length, NULL) !=
            PLATFORM_WATCHER_STORE_IDLE)
        return fail("idle classification failed");
    (void)platform_directory_child_unlink(&owner.directory,
                                          ".watcher-crash.tmp", true);
    (void)platform_directory_child_unlink(&owner.directory, "spoof.record", true);
    (void)platform_directory_child_unlink(&owner.directory, "watch.lock", true);
    platform_watcher_store_close(&observer);
    platform_watcher_store_close(&owner);
    RemoveDirectoryW(root);
    puts("watcher_store_acceptance: PASS");
    return 0;
}
