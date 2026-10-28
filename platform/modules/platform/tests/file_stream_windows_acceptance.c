/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Native acceptance for UTF-8 read paths and non-inheritable streams. */
#include "platform/file_stream.h"

#include <errno.h>
#include <io.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>

static bool fail(const char *message)
{
    fprintf(stderr, "file_stream: FAIL %s (win32=%lu errno=%d)\n", message,
            (unsigned long)GetLastError(), errno);
    return false;
}

static bool fixture_name(wchar_t path[MAX_PATH])
{
    wchar_t temp[MAX_PATH], seed[MAX_PATH];
    DWORD n = GetTempPathW(MAX_PATH, temp);
    if (!n || n >= MAX_PATH) return fail("temporary directory");
    if (!GetTempFileNameW(temp, L"zfs", 0, seed)) return fail("temporary name");
    if (!DeleteFileW(seed)) return fail("temporary seed cleanup");
    int written = swprintf(path, MAX_PATH, L"%ls-\x4e2d\x6587", seed);
    return (written > 0 && written < MAX_PATH) || fail("Unicode path length");
}

static bool fixture_write(const wchar_t *path, bool *created)
{
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return fail("Unicode fixture create");
    *created = true;
    static const char content[] = "one\r\ntwo\n";
    DWORD written = 0;
    bool ok = WriteFile(file, content, sizeof(content) - 1, &written, NULL) &&
              written == sizeof(content) - 1;
    if (!ok) fail("fixture write");
    if (!CloseHandle(file)) { fail("fixture close"); ok = false; }
    return ok;
}

static bool verify_stream(const char *path)
{
    FILE *stream = platform_file_stream_open_read(path);
    if (!stream) return fail("Unicode open");
    static const char expected[] = "one\r\ntwo\n";
    char actual[sizeof(expected)] = {0};
    bool ok = fread(actual, 1, sizeof(expected) - 1, stream) ==
              sizeof(expected) - 1 &&
              memcmp(actual, expected, sizeof(expected) - 1) == 0;
    if (!ok) fail("binary bytes");
    intptr_t native = _get_osfhandle(_fileno(stream));
    DWORD flags = 0;
    if (native == -1 || !GetHandleInformation((HANDLE)native, &flags) ||
        (flags & HANDLE_FLAG_INHERIT) != 0) {
        fail("handle inheritance");
        ok = false;
    }
    if (fclose(stream) != 0) { fail("stream close"); ok = false; }
    return ok;
}

static bool expect_refusal(const char *path, int expected_errno)
{
    errno = 0;
    FILE *stream = platform_file_stream_open_read(path);
    if (stream) {
        fail("unexpected open");
        if (fclose(stream) != 0) fail("unexpected stream close");
        return false;
    }
    return errno == expected_errno || fail("unexpected refusal errno");
}

static bool expect_empty_refusal(const char *path)
{
    FILE *stream = platform_file_stream_open_read(path);
    if (!stream) return true;
    fail("empty path opened");
    if (fclose(stream) != 0) fail("unexpected stream close");
    return false;
}

int main(void)
{
    printf("file_stream: Windows ACP=%u\n", (unsigned)GetACP());
    wchar_t path[MAX_PATH];
    if (!fixture_name(path)) return 1;
    bool created = false;
    if (!fixture_write(path, &created)) {
        if (created && !DeleteFileW(path)) fail("failed fixture cleanup");
        return 1;
    }
    char utf8[4 * MAX_PATH];
    bool ok = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path, -1,
                                  utf8, sizeof(utf8), NULL, NULL) != 0;
    if (!ok) fail("UTF-8 path encoding");
    if (ok) ok = verify_stream(utf8);
    if (!DeleteFileW(path)) { fail("fixture cleanup"); return 1; }
    if (!ok) return 1;
    if (!expect_refusal(utf8, ENOENT) || !expect_refusal("\xc0\xaf", EILSEQ))
        return 1;
    if (!expect_empty_refusal(NULL) || !expect_empty_refusal(""))
        return 1;
    puts("file_stream: PASS Unicode, binary, non-inheritance and refusals");
    return 0;
}
