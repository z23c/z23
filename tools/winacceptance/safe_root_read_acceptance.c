/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Windows-only acceptance for platform_safe_root_read() -- reads a
 * UTF-8 nested path beneath a trusted root, then proves each refusal is
 * reported distinctly rather than collapsed: parent traversal, a backslash
 * separator, a directory, an oversize file, a missing name, and a leaf
 * reparse point escaping the root. Exits 77 (skip) off Windows. */
#include "platform/safe_root_read.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

static int failures;
#define CHECK(label, expression) do {                                         \
    if (!(expression)) { fprintf(stderr, "FAIL: %s\n", label); failures++; } \
} while (0)

static bool write_utf8(const char *path, const char *bytes)
{
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1,
                                NULL, 0);
    wchar_t *wide = n > 0 ? malloc((size_t)n * sizeof(*wide)) : NULL;
    if (!wide || !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1,
                                      wide, n)) { free(wide); return false; }
    HANDLE h = CreateFileW(wide, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    free(wide);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD wrote = 0;
    bool ok = WriteFile(h, bytes, (DWORD)strlen(bytes), &wrote, NULL) &&
              wrote == strlen(bytes);
    CloseHandle(h);
    return ok;
}

int main(void)
{
    wchar_t temp[MAX_PATH], root_wide[MAX_PATH];
    CHECK("temporary directory", GetTempPathW(MAX_PATH, temp) != 0);
    CHECK("temporary name", GetTempFileNameW(temp, L"zsr", 0, root_wide) != 0);
    DeleteFileW(root_wide);
    CHECK("create root", CreateDirectoryW(root_wide, NULL));
    char root[MAX_PATH * 4];
    CHECK("root UTF-8", WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
          root_wide, -1, root, sizeof(root), NULL, NULL) != 0);
    char sub[MAX_PATH * 4], file[MAX_PATH * 4];
    snprintf(sub, sizeof(sub), "%s/%s", root, "caf\xc3\xa9");
    wchar_t sub_wide[MAX_PATH];
    CHECK("sub UTF-16", MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
          sub, -1, sub_wide, MAX_PATH) != 0);
    CHECK("create unicode directory", CreateDirectoryW(sub_wide, NULL));
    snprintf(file, sizeof(file), "%s/page.txt", sub);
    CHECK("write unicode file", write_utf8(file, "native-c23"));

    uint8_t *data = NULL;
    size_t size = 0;
    CHECK("read unicode nested file", platform_safe_root_read(
          root, "caf\xc3\xa9/page.txt", 64, &data, &size) ==
          PLATFORM_SAFE_ROOT_READ_OK);
    CHECK("exact bytes", size == 10 && memcmp(data, "native-c23", 10) == 0);
    free(data);
    CHECK("traversal refused", platform_safe_root_read(root, "../page.txt", 64,
          &data, &size) == PLATFORM_SAFE_ROOT_READ_FORBIDDEN);
    CHECK("backslash refused", platform_safe_root_read(root, "caf\xc3\xa9\\page.txt",
          64, &data, &size) == PLATFORM_SAFE_ROOT_READ_FORBIDDEN);
    CHECK("directory refused", platform_safe_root_read(root, "caf\xc3\xa9", 64,
          &data, &size) == PLATFORM_SAFE_ROOT_READ_FORBIDDEN);
    CHECK("size bounded", platform_safe_root_read(root, "caf\xc3\xa9/page.txt", 9,
          &data, &size) == PLATFORM_SAFE_ROOT_READ_TOO_LARGE);
    CHECK("missing distinguished", platform_safe_root_read(root, "missing", 64,
          &data, &size) == PLATFORM_SAFE_ROOT_READ_NOT_FOUND);

    wchar_t outside_wide[MAX_PATH], link_wide[MAX_PATH];
    CHECK("temporary outside name",
          GetTempFileNameW(temp, L"zso", 0, outside_wide) != 0);
    char outside[MAX_PATH * 4];
    CHECK("outside UTF-8", WideCharToMultiByte(CP_UTF8,
          WC_ERR_INVALID_CHARS, outside_wide, -1, outside, sizeof(outside),
          NULL, NULL) != 0);
    CHECK("write outside file", write_utf8(outside, "outside"));
    wcscpy_s(link_wide, MAX_PATH, root_wide);
    wcscat_s(link_wide, MAX_PATH, L"\\escape.txt");
    if (CreateSymbolicLinkW(link_wide, outside_wide,
            SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)) {
        CHECK("leaf reparse refused", platform_safe_root_read(
              root, "escape.txt", 64, &data, &size) ==
              PLATFORM_SAFE_ROOT_READ_FORBIDDEN);
        DeleteFileW(link_wide);
    }
    DeleteFileW(outside_wide);

    wchar_t file_wide[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, file, -1, file_wide, MAX_PATH);
    DeleteFileW(file_wide);
    RemoveDirectoryW(sub_wide);
    RemoveDirectoryW(root_wide);
    if (!failures) puts("PASS: safe-root read Windows seam");
    return failures ? 1 : 0;
}
#else
int main(void) { return 77; }
#endif
