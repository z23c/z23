/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "platform/process_lifecycle.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

static bool utf8(const wchar_t *wide, char *out, size_t out_size)
{
    int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, -1,
                                     NULL, 0, NULL, NULL);
    return needed > 0 && (size_t)needed <= out_size &&
           WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, -1, out,
                               (int)out_size, NULL, NULL) == needed;
}

static int child_mode(int argc, char **argv)
{
    if (argc != 8 || strcmp(argv[2], "space value") != 0 ||
        strcmp(argv[3], "quote\"value") != 0 ||
        strcmp(argv[4], "trailing\\") != 0 ||
        !getenv("Z23_PROCESS_TEST") ||
        strcmp(getenv("Z23_PROCESS_TEST"), "controlled") != 0 ||
        getenv("Z23_PROCESS_UNEXPECTED") != NULL)
        return 20;
    wchar_t image[32768], cwd[32768], expected_image[32768], expected_cwd[32768];
    if (!GetModuleFileNameW(NULL, image, 32768) ||
        !GetCurrentDirectoryW(32768, cwd) ||
        !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, argv[5], -1,
                             expected_image, 32768) ||
        !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, argv[6], -1,
                             expected_cwd, 32768) ||
        _wcsicmp(image, expected_image) != 0 ||
        _wcsicmp(cwd, expected_cwd) != 0)
        return 21;
    uintptr_t inherited = (uintptr_t)_strtoui64(argv[7], NULL, 10);
    DWORD flags = 0;
    if (GetHandleInformation((HANDLE)inherited, &flags) ||
        GetLastError() != ERROR_INVALID_HANDLE)
        return 22;
    FILE *proof = fopen("process-lifecycle.proof", "wb");
    if (!proof) return 23;
    bool ok = fputs("ok\n", proof) >= 0 && fclose(proof) == 0;
    return ok ? 0 : 24;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--child") == 0)
        return child_mode(argc, argv);
    wchar_t image_w[32768], temp_w[32768];
    if (!GetModuleFileNameW(NULL, image_w, 32768) ||
        !GetTempPathW(32768, temp_w)) return 1;
    size_t used = wcslen(temp_w);
    int written = swprintf(temp_w + used, 32768 - used,
                           L"z23-process-%lu", (unsigned long)GetCurrentProcessId());
    if (written <= 0 || !CreateDirectoryW(temp_w, NULL)) return 2;
    char image[32768], cwd[32768], handle_text[32];
    HANDLE inherited = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!inherited || !SetHandleInformation(inherited, HANDLE_FLAG_INHERIT,
                                            HANDLE_FLAG_INHERIT) ||
        !utf8(image_w, image, sizeof(image)) || !utf8(temp_w, cwd, sizeof(cwd)))
        return 3;
    (void)snprintf(handle_text, sizeof(handle_text), "%llu",
                   (unsigned long long)(uintptr_t)inherited);
    const char *const child_argv[] = {
        image, "--child", "space value", "quote\"value", "trailing\\",
        image, cwd, handle_text, NULL};
    const char *const child_env[] = {"Z23_PROCESS_TEST=controlled", NULL};
    (void)SetEnvironmentVariableW(L"Z23_PROCESS_UNEXPECTED", L"inherited");
    struct platform_process process;
    platform_process_init(&process);
    struct platform_process_options options = {
        .image = image, .argv = child_argv, .cwd = cwd, .env = child_env,
        .inherit_environment = false};
    bool started = platform_process_start_hidden(&process, &options);
    uint32_t code = UINT32_MAX;
    enum platform_process_wait_result waited = started
        ? platform_process_wait(&process, 10000, &code)
        : PLATFORM_PROCESS_WAIT_FAILED;
    platform_process_close(&process);
    CloseHandle(inherited);
    wchar_t proof[32768];
    (void)swprintf(proof, 32768, L"%ls\\process-lifecycle.proof", temp_w);
    DWORD attributes = GetFileAttributesW(proof);
    bool ok = waited == PLATFORM_PROCESS_WAIT_EXITED && code == 0 &&
              attributes != INVALID_FILE_ATTRIBUTES;
    (void)DeleteFileW(proof);
    (void)RemoveDirectoryW(temp_w);
    (void)SetEnvironmentVariableW(L"Z23_PROCESS_UNEXPECTED", NULL);
    if (!ok) {
        fprintf(stderr, "process lifecycle failed: started=%d wait=%d exit=%lu\n",
                started, (int)waited, (unsigned long)code);
        return 4;
    }
    puts("process-lifecycle-acceptance: ok");
    return 0;
}
#else
int main(void)
{
    puts("process-lifecycle-acceptance: skipped (non-Windows)");
    return 0;
}
#endif
