/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Verify durable watcher ownership records on Windows. */
#include "platform/private_directory.h"
#include "platform/watcher_store.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <stdio.h>
#include <string.h>
#include <windows.h>

static bool runtime_is_wine(void)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    return ntdll && GetProcAddress(ntdll, "wine_get_version") != NULL;
}

static int fail(const char *message)
{
    fprintf(stderr, "watcher_store_acceptance: %s\n", message);
    return 1;
}

struct ws_ctx {
    wchar_t root[MAX_PATH], spoof[MAX_PATH], link[MAX_PATH];
    char root_utf8[MAX_PATH * 3];
    struct platform_watcher_store owner, observer;
    struct platform_watcher_record_identity starting, ready;
    char body[32];
    size_t length;
};

static const char ws_first[] = "starting", ws_second[] = "ready";

static bool ws_fixture_paths(struct ws_ctx *c)
{
    wchar_t temp[MAX_PATH];
    return GetTempPathW(MAX_PATH, temp) &&
           swprintf(c->root, MAX_PATH, L"%lsz23-watcher-store-%lu-%llu", temp,
                    (unsigned long)GetCurrentProcessId(),
                    (unsigned long long)GetTickCount64()) > 0 &&
           swprintf(c->spoof, MAX_PATH, L"%ls\\spoof.record", c->root) > 0 &&
           swprintf(c->link, MAX_PATH, L"%ls\\link.record", c->root) > 0;
}

static bool ws_private_root_create(struct ws_ctx *c)
{
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, c->root, -1,
                               c->root_utf8, sizeof(c->root_utf8), NULL,
                               NULL) &&
           platform_private_directory_create(c->root_utf8);
}

static bool ws_exclusive_busy_ok(struct ws_ctx *c)
{
    return platform_watcher_store_open(&c->owner, c->root_utf8) ==
               PLATFORM_WATCHER_STORE_OK &&
           platform_watcher_store_open(&c->observer, c->root_utf8) ==
               PLATFORM_WATCHER_STORE_OK &&
           platform_watcher_store_try_acquire(&c->owner, "watch.lock", true) ==
               PLATFORM_WATCHER_STORE_OK &&
           platform_watcher_store_try_acquire(&c->observer, "watch.lock",
                                              false) ==
               PLATFORM_WATCHER_STORE_BUSY;
}

static bool ws_stable_busy_read_ok(struct ws_ctx *c)
{
    return platform_watcher_store_read_while_busy(
               &c->observer, "watch.lock", "watch.record", c->body,
               sizeof(c->body), &c->length, NULL) ==
               PLATFORM_WATCHER_STORE_OK &&
           c->length == sizeof(ws_first) - 1 &&
           memcmp(c->body, ws_first, c->length) == 0;
}

static bool ws_atomic_update_ok(struct ws_ctx *c)
{
    return platform_watcher_store_publish(&c->owner, "watch.record", ws_second,
                                          sizeof(ws_second) - 1, &c->starting,
                                          &c->ready) ==
               PLATFORM_WATCHER_STORE_OK &&
           platform_watcher_store_retire_exact(&c->owner, "watch.record",
                                               &c->starting) ==
               PLATFORM_WATCHER_STORE_REFUSED;
}

static bool ws_spoof_fixture_create(const struct ws_ctx *c)
{
    HANDLE bad = CreateFileW(c->spoof, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                             FILE_ATTRIBUTE_NORMAL, NULL);
    if (bad == INVALID_HANDLE_VALUE ||
        WriteFile(bad, ws_first, sizeof(ws_first) - 1, &(DWORD){0}, NULL) == 0) {
        if (bad != INVALID_HANDLE_VALUE) CloseHandle(bad);
        return false;
    }
    CloseHandle(bad);
    return true;
}

static bool ws_spoof_refused(struct ws_ctx *c)
{
    return platform_watcher_store_read_while_busy(
               &c->observer, "watch.lock", "spoof.record", c->body,
               sizeof(c->body), &c->length, NULL) ==
           PLATFORM_WATCHER_STORE_REFUSED;
}

static bool ws_reparse_refused(struct ws_ctx *c)
{
    DWORD link_flags = 0;
#ifdef SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
    link_flags |= SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
#endif
    if (CreateSymbolicLinkW(c->link, c->spoof, link_flags)) {
        enum platform_watcher_store_result linked =
            platform_watcher_store_read_while_busy(
                &c->observer, "watch.lock", "link.record", c->body,
                sizeof(c->body), &c->length, NULL);
        if (linked != PLATFORM_WATCHER_STORE_REFUSED)
            return false;
        DeleteFileW(c->link);
    }
    return true;
}

static bool ws_residue_fixture_create(struct ws_ctx *c)
{
    struct platform_directory_child residue;
    platform_directory_child_init(&residue);
    if (!platform_directory_child_create(&c->owner.directory,
                                          ".watcher-crash.tmp", &residue))
        return false;
    platform_directory_child_close(&residue);
    return true;
}

static bool ws_residue_isolated_and_retired(struct ws_ctx *c)
{
    memset(c->body, 0, sizeof(c->body));
    return platform_watcher_store_read_while_busy(
               &c->observer, "watch.lock", "watch.record", c->body,
               sizeof(c->body), &c->length, NULL) ==
               PLATFORM_WATCHER_STORE_OK &&
           c->length == sizeof(ws_second) - 1 &&
           memcmp(c->body, ws_second, c->length) == 0 &&
           platform_watcher_store_retire_exact(&c->owner, "watch.record",
                                               &c->ready) ==
               PLATFORM_WATCHER_STORE_OK;
}

static bool ws_idle_after_release(struct ws_ctx *c)
{
    platform_watcher_store_release(&c->owner);
    return platform_watcher_store_read_while_busy(
               &c->observer, "watch.lock", "watch.record", c->body,
               sizeof(c->body), &c->length, NULL) ==
           PLATFORM_WATCHER_STORE_IDLE;
}

static void ws_cleanup(struct ws_ctx *c)
{
    (void)platform_directory_child_unlink(&c->owner.directory,
                                          ".watcher-crash.tmp", true);
    (void)platform_directory_child_unlink(&c->owner.directory, "spoof.record",
                                          true);
    (void)platform_directory_child_unlink(&c->owner.directory, "watch.lock",
                                          true);
    platform_watcher_store_close(&c->observer);
    platform_watcher_store_close(&c->owner);
    RemoveDirectoryW(c->root);
}

int main(void)
{
    struct ws_ctx c = {0};
    if (!ws_fixture_paths(&c))
        return fail("fixture path failed");
    if (!ws_private_root_create(&c)) {
        if (runtime_is_wine()) {
            fputs("watcher_store_acceptance: REFUSE: Wine cannot prove native "
                  "SID/DACL semantics\n", stderr);
            return 77;
        }
        return fail("private root create failed");
    }

    platform_watcher_store_init(&c.owner);
    platform_watcher_store_init(&c.observer);
    if (!ws_exclusive_busy_ok(&c))
        return fail("exclusive busy ownership failed");

    if (platform_watcher_store_publish(&c.owner, "watch.record", ws_first,
            sizeof(ws_first) - 1, NULL, &c.starting) != PLATFORM_WATCHER_STORE_OK)
        return fail("initial publication failed");
    if (!ws_stable_busy_read_ok(&c))
        return fail("stable busy read failed");
    if (!ws_atomic_update_ok(&c))
        return fail("atomic update/stale identity refusal failed");

    if (!ws_spoof_fixture_create(&c))
        return fail("spoof fixture failed");
    if (!ws_spoof_refused(&c))
        return fail("inherited/spoof ACL accepted");
    if (!ws_reparse_refused(&c))
        return fail("record reparse point accepted");

    if (!ws_residue_fixture_create(&c))
        return fail("crash residue fixture failed");
    if (!ws_residue_isolated_and_retired(&c))
        return fail("residue isolation/exact retirement failed");

    if (!ws_idle_after_release(&c))
        return fail("idle classification failed");
    ws_cleanup(&c);
    puts("watcher_store_acceptance: PASS");
    return 0;
}
