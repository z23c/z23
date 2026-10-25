/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Focused native acceptance for UTF-8 regular-file pathname metadata. */
#include "platform/file_metadata.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <stdbool.h>
#include <stdio.h>
#include <wchar.h>
#include <windows.h>

static int fail(const char *message)
{
    fprintf(stderr, "FAIL: %s (win32=%lu)\n", message,
            (unsigned long)GetLastError());
    return 1;
}

/* UTF-8 is self-synchronising: every byte of a multi-byte sequence has the
 * high bit set, so none of them can be a backslash. Rewriting separators
 * byte-wise therefore cannot corrupt a non-ASCII name. */
static bool forward_slash_copy(const char *source, char *out, size_t out_size)
{
    size_t i = 0;
    for (; source[i]; i++) {
        if (i + 1 >= out_size) return false;
        out[i] = source[i] == '\\' ? '/' : source[i];
    }
    if (i >= out_size) return false;
    out[i] = '\0';
    return true;
}

struct metadata_fixture {
    wchar_t directory[MAX_PATH], file_path[MAX_PATH];
    char utf8_file[4 * MAX_PATH], utf8_directory[4 * MAX_PATH];
    struct platform_file_metadata metadata;
};

static const char payload[] = "metadata";

static int create_unicode_file(struct metadata_fixture *fixture)
{
    wchar_t temp[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, temp) ||
        !GetTempFileNameW(temp, L"zfm", 0, fixture->directory) ||
        !DeleteFileW(fixture->directory) ||
        !CreateDirectoryW(fixture->directory, NULL))
        return fail("temporary directory");
    if (swprintf(fixture->file_path, MAX_PATH, L"%ls\\m\x00e9tadata.bin",
                 fixture->directory) < 0)
        return fail("unicode path");
    HANDLE file = CreateFileW(fixture->file_path, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD written = 0;
    if (file == INVALID_HANDLE_VALUE ||
        !WriteFile(file, payload, sizeof(payload), &written, NULL) ||
        written != sizeof(payload) || !FlushFileBuffers(file) ||
        !CloseHandle(file))
        return fail("fixture write");

    return 0;
}

static int check_regular_metadata(struct metadata_fixture *fixture)
{
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, fixture->file_path, -1,
                             fixture->utf8_file, sizeof(fixture->utf8_file),
                             NULL, NULL) ||
        !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, fixture->directory, -1,
                             fixture->utf8_directory,
                             sizeof(fixture->utf8_directory), NULL, NULL))
        return fail("UTF-8 conversion");

    if (platform_file_metadata_read(fixture->utf8_file, &fixture->metadata) !=
            PLATFORM_FILE_METADATA_OK ||
        fixture->metadata.size != sizeof(payload) || fixture->metadata.links != 1 ||
        fixture->metadata.modified_seconds <= 0)
        return fail("regular UTF-8 file metadata");

    return 0;
}

static int check_hardlink_counts(struct metadata_fixture *fixture)
{
    wchar_t alias_path[MAX_PATH];
    /* UCRT stat/fstat reports one link for this NTFS shape.  The platform
     * seam must expose GetFileInformationByHandle's real count so storage
     * never appends through a foreign hard link. */
    if (swprintf(alias_path, MAX_PATH, L"%ls\\hardlink.bin", fixture->directory) < 0 ||
        !CreateHardLinkW(alias_path, fixture->file_path, NULL) ||
        platform_file_metadata_read(fixture->utf8_file, &fixture->metadata) !=
            PLATFORM_FILE_METADATA_OK || fixture->metadata.links != 2 ||
        !DeleteFileW(alias_path) ||
        platform_file_metadata_read(fixture->utf8_file, &fixture->metadata) !=
            PLATFORM_FILE_METADATA_OK || fixture->metadata.links != 1)
        return fail("NTFS hard-link metadata");

    return 0;
}

static int check_path_spellings_and_missing(struct metadata_fixture *fixture)
{
    /* The same existing file spelled with forward slashes. Callers join
     * paths with '/' and plain Win32 rewrites those for them -- but the
     * \\?\ prefix this implementation prepends turns every path parse OFF,
     * so a '/' that survives into the extended form reaches the object
     * manager as a filename character, CreateFileW fails with
     * ERROR_INVALID_NAME, and an existing file grades REFUSED. Every other
     * case in this program spells the separator '\\', which is exactly how
     * that survived. */
    char utf8_forward[4 * MAX_PATH];
    if (!forward_slash_copy(fixture->utf8_file, utf8_forward, sizeof(utf8_forward)))
        return fail("forward-slash path build");
    struct platform_file_metadata forward = {0};
    if (platform_file_metadata_read(utf8_forward, &forward) !=
            PLATFORM_FILE_METADATA_OK ||
        forward.size != fixture->metadata.size)
        return fail("forward-slash UTF-8 file metadata");
    if (platform_file_shape_read(utf8_forward) != PLATFORM_FILE_SHAPE_REGULAR)
        return fail("forward-slash file shape");
    if (!DeleteFileW(fixture->file_path) ||
        platform_file_metadata_read(fixture->utf8_file, &fixture->metadata) !=
            PLATFORM_FILE_METADATA_MISSING)
        return fail("missing verdict");
    for (char *p = fixture->utf8_file; *p; ++p)
        if (*p == '\\') *p = '/';
    if (platform_file_metadata_read(fixture->utf8_file, &fixture->metadata) !=
            PLATFORM_FILE_METADATA_MISSING)
        return fail("missing forward-slash verdict");
    if (platform_file_metadata_read(fixture->utf8_directory, &fixture->metadata) !=
            PLATFORM_FILE_METADATA_NOT_REGULAR)
        return fail("directory shape verdict");
    if (!RemoveDirectoryW(fixture->directory))
        return fail("cleanup");
    return 0;
}

int main(void)
{
    struct metadata_fixture fixture = {0};
    if (create_unicode_file(&fixture) ||
        check_regular_metadata(&fixture) ||
        check_hardlink_counts(&fixture) ||
        check_path_spellings_and_missing(&fixture))
        return 1;
    puts("file_metadata_acceptance: PASS");
    return 0;
}
