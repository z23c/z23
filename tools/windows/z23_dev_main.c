/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "z23_dev_journey.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

static void usage(void)
{
    fputs("Usage: z23-dev bootstrap | create <name> | "
          "develop [project] [--once] | ship [project]\n",
          stderr);
}

static void json_step(const wchar_t *command, const wchar_t *step,
                      uint64_t elapsed_ms, DWORD exit_code)
{
    wprintf(L"{\"command\":\"%ls\",\"step\":\"%ls\","
            L"\"elapsed_ms\":%llu,\"exit_code\":%lu}\n",
            command, step, (unsigned long long)elapsed_ms,
            (unsigned long)exit_code);
}

static bool write_utf8_file(const wchar_t *path, const char *content)
{
    HANDLE file;
    DWORD size = (DWORD)strlen(content);
    DWORD written = 0;
    file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_NEW,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return false;
    if (!WriteFile(file, content, size, &written, NULL) || written != size) {
        CloseHandle(file);
        return false;
    }
    return CloseHandle(file) != 0;
}

static bool valid_name(const wchar_t *name)
{
    size_t i;
    if (name == NULL || name[0] == L'\0' || wcslen(name) > 63)
        return false;
    for (i = 0; name[i] != L'\0'; ++i) {
        if (!((name[i] >= L'a' && name[i] <= L'z') ||
              (name[i] >= L'A' && name[i] <= L'Z') ||
              (i != 0 && name[i] >= L'0' && name[i] <= L'9') ||
              (i != 0 && name[i] == L'_')))
            return false;
    }
    return true;
}

static int create_project(const wchar_t *name, const wchar_t *controller)
{
    wchar_t source_path[32768];
    wchar_t cmake_path[32768];
    char cmake[2048];
    static const char source[] =
        "#define WIN32_LEAN_AND_MEAN\n"
        "#include <windows.h>\n\n"
        "int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, "
        "PWSTR command_line, int show)\n"
        "{\n"
        "    (void)instance; (void)previous; (void)command_line; (void)show;\n"
        "    MessageBoxW(NULL, L\"Your native C23 app is running.\", "
        "L\"Z23\", MB_OK | MB_ICONINFORMATION);\n"
        "    return 0;\n"
        "}\n";

    if (!valid_name(name)) {
        fputs("create: name must be a C identifier (letters, digits, underscore)\n",
              stderr);
        return 2;
    }
    if (!CreateDirectoryW(name, NULL)) {
        fputs("create: destination already exists or cannot be created\n", stderr);
        return 1;
    }
    if (swprintf(source_path, 32768, L"%ls\\main.c", name) < 0 ||
        swprintf(cmake_path, 32768, L"%ls\\CMakeLists.txt", name) < 0) {
        fputs("create: project path is too long\n", stderr);
        return 1;
    }
    if (snprintf(cmake, sizeof(cmake),
        "cmake_minimum_required(VERSION 3.28)\n"
        "project(%ls VERSION 0.1.0 LANGUAGES C)\n"
        "set(CMAKE_C_STANDARD 23)\n"
        "set(CMAKE_C_STANDARD_REQUIRED ON)\n"
        "set(CMAKE_C_EXTENSIONS OFF)\n"
        "add_executable(%ls WIN32 main.c)\n"
        "target_compile_options(%ls PRIVATE -Wall -Wextra -Wpedantic -Werror)\n"
        "# Ship one self-contained executable; compiler runtimes must never be DLLs.\n"
        "target_link_options(%ls PRIVATE -municode -static)\n",
        name, name, name, name) < 0 ||
        !write_utf8_file(source_path, source) ||
        !write_utf8_file(cmake_path, cmake)) {
        fputs("create: failed to write project files\n", stderr);
        return 1;
    }
    wprintf(L"Created %ls. Next: \"%ls\" develop \"%ls\"\n",
            name, controller, name);
    return 0;
}

static DWORD run_process(const wchar_t *command, const wchar_t *arguments,
                         const wchar_t *label, const wchar_t *verb,
                         bool wait_for_exit)
{
    STARTUPINFOW startup = { .cb = sizeof(startup) };
    PROCESS_INFORMATION process = {0};
    LARGE_INTEGER start, finish, frequency;
    wchar_t command_line[32768];
    wchar_t environment[65536];
    wchar_t system_root[32768];
    wchar_t temporary[32768];
    wchar_t tool_directory[32768];
    wchar_t command_shell[32768];
    wchar_t *separator;
    size_t environment_length;
    DWORD exit_code = 1;

    if (swprintf(command_line, 32768, L"\"%ls\" %ls", command, arguments) < 0)
        return ERROR_BUFFER_OVERFLOW;
    if (GetWindowsDirectoryW(system_root, 32768) == 0 ||
        GetTempPathW(32768, temporary) == 0)
        return GetLastError();
    if (wcslen(command) >= 32768)
        return ERROR_BUFFER_OVERFLOW;
    wcscpy(tool_directory, command);
    separator = wcsrchr(tool_directory, L'\\');
    if (!separator)
        return ERROR_BAD_PATHNAME;
    *separator = L'\0';
    if (swprintf(command_shell, 32768, L"%ls\\System32\\cmd.exe",
                 system_root) < 0)
        return ERROR_BUFFER_OVERFLOW;
    /* The child sees only the directory of the exact executable selected by
     * the controller. This permits adjacent portable runtime DLLs while
     * making ambient compiler/SDK/shell discovery impossible. */
    if (swprintf(environment, 65536, L"ComSpec=%ls", command_shell) < 0)
        return ERROR_BUFFER_OVERFLOW;
    environment_length = wcslen(environment) + 1;
    if (swprintf(environment + environment_length,
                 65536 - environment_length, L"PATH=%ls", tool_directory) < 0)
        return ERROR_BUFFER_OVERFLOW;
    environment_length += wcslen(environment + environment_length) + 1;
    if (swprintf(environment + environment_length,
                 65536 - environment_length, L"SystemRoot=%ls", system_root) < 0)
        return ERROR_BUFFER_OVERFLOW;
    environment_length += wcslen(environment + environment_length) + 1;
    if (swprintf(environment + environment_length,
                 65536 - environment_length, L"TEMP=%ls", temporary) < 0)
        return ERROR_BUFFER_OVERFLOW;
    environment_length += wcslen(environment + environment_length) + 1;
    if (swprintf(environment + environment_length,
                 65536 - environment_length, L"TMP=%ls", temporary) < 0)
        return ERROR_BUFFER_OVERFLOW;
    environment_length += wcslen(environment + environment_length) + 1;
    if (environment_length >= 65536)
        return ERROR_BUFFER_OVERFLOW;
    environment[environment_length] = L'\0';
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);
    if (!CreateProcessW(command, command_line, NULL, NULL, FALSE,
                        CREATE_UNICODE_ENVIRONMENT, environment, NULL, &startup,
                        &process))
        return GetLastError();
    CloseHandle(process.hThread);
    if (!wait_for_exit) {
        CloseHandle(process.hProcess);
        json_step(verb, label, 0, 0);
        return 0;
    }
    WaitForSingleObject(process.hProcess, INFINITE);
    if (!GetExitCodeProcess(process.hProcess, &exit_code))
        exit_code = 1;
    CloseHandle(process.hProcess);
    QueryPerformanceCounter(&finish);
    json_step(verb, label,
              z23_dev_elapsed_ms(start.QuadPart, finish.QuadPart,
                                 frequency.QuadPart), exit_code);
    return exit_code;
}

static int read_project_name(wchar_t *name, size_t capacity)
{
    wchar_t current[32768];
    wchar_t *leaf;
    if (GetCurrentDirectoryW(32768, current) == 0)
        return 1;
    leaf = wcsrchr(current, L'\\');
    leaf = leaf == NULL ? current : leaf + 1;
    if (!valid_name(leaf) || wcslen(leaf) >= capacity)
        return 1;
    wcscpy(name, leaf);
    return 0;
}

static bool prepare_empty_dist(void)
{
    WIN32_FIND_DATAW found;
    HANDLE search;
    wchar_t path[32768];

    if (!CreateDirectoryW(L"dist", NULL) &&
        GetLastError() != ERROR_ALREADY_EXISTS)
        return false;
    search = FindFirstFileW(L"dist\\*", &found);
    if (search == INVALID_HANDLE_VALUE)
        return GetLastError() == ERROR_FILE_NOT_FOUND;
    do {
        if (wcscmp(found.cFileName, L".") == 0 ||
            wcscmp(found.cFileName, L"..") == 0)
            continue;
        if ((found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ||
            swprintf(path, 32768, L"dist\\%ls", found.cFileName) < 0 ||
            !DeleteFileW(path)) {
            FindClose(search);
            return false;
        }
    } while (FindNextFileW(search, &found));
    FindClose(search);
    return GetLastError() == ERROR_NO_MORE_FILES;
}

static int develop(const struct z23_dev_layout *layout, bool once)
{
    struct z23_dev_step steps[3];
    wchar_t name[64];
    wchar_t executable[32768];
    size_t count = z23_dev_plan(Z23_DEV_DEVELOP, layout, steps, 3);
    size_t i;
    DWORD result;
    for (i = 0; i < count; ++i) {
        result = run_process(steps[i].executable, steps[i].arguments,
                             steps[i].name, L"develop", true);
        if (result != 0)
            return 1;
    }
    if (once)
        return 0;
    if (read_project_name(name, 64) != 0 ||
        swprintf(executable, 32768, L".z23\\build\\develop\\%ls.exe", name) < 0) {
        fputs("develop: project directory must match its C identifier name\n",
              stderr);
        return 1;
    }
    result = run_process(executable, L"", L"launch", L"develop", false);
    return result == 0 ? 0 : 1;
}

static int ship(const struct z23_dev_layout *layout)
{
    struct z23_dev_step steps[3];
    wchar_t name[64], built[32768], shipped[32768], manifest[32768];
    wchar_t archive[32768];
    wchar_t tar_arguments[32768];
    char manifest_content[512];
    size_t i;
    DWORD result;
    if (read_project_name(name, 64) != 0)
        return 1;
    for (i = 0; i < 2; ++i) {
        if (z23_dev_plan(Z23_DEV_SHIP, layout, steps, 3) != 3)
            return 1;
        result = run_process(steps[i].executable, steps[i].arguments,
                             steps[i].name, L"ship", true);
        if (result != 0)
            return 1;
    }
    if (!prepare_empty_dist()) {
        fputs("ship: dist contains a directory or cannot be cleaned safely\n",
              stderr);
        return 1;
    }
    swprintf(built, 32768, L".z23\\build\\ship\\%ls.exe", name);
    swprintf(shipped, 32768, L"dist\\%ls.exe", name);
    swprintf(manifest, 32768, L"dist\\manifest.json");
    swprintf(archive, 32768, L"dist\\%ls-windows-x64.zip", name);
    if (!CopyFileW(built, shipped, TRUE)) {
        fputs("ship: release executable was not produced\n", stderr);
        return 1;
    }
    snprintf(manifest_content, sizeof(manifest_content),
             "{\"schema\":\"z23.c23.windows.ship.v1\","
             "\"application\":\"%ls\",\"unsigned\":true}\n", name);
    if (!write_utf8_file(manifest, manifest_content))
        return 1;
    swprintf(tar_arguments, 32768,
             L"-E tar cf \"%ls\" --format=zip \"%ls\" \"%ls\"",
             archive, shipped, manifest);
    result = run_process(layout->cmake, tar_arguments, L"archive", L"ship", true);
    if (result == 0)
        wprintf(L"Shipped dist\\%ls-windows-x64.zip\n", name);
    return result == 0 ? 0 : 1;
}

int wmain(int argc, wchar_t **argv)
{
    wchar_t executable[32768];
    struct z23_dev_layout layout;
    char error[192];
    DWORD length = GetModuleFileNameW(NULL, executable, 32768);

    if (argc < 2 || length == 0 || length >= 32768) {
        usage();
        return 2;
    }
    if (wcscmp(argv[1], L"--help") == 0 || wcscmp(argv[1], L"-h") == 0 ||
        (argc >= 3 && (wcscmp(argv[2], L"--help") == 0 ||
                       wcscmp(argv[2], L"-h") == 0))) {
        usage();
        return 0;
    }
    if (!z23_dev_layout_from_executable(executable, &layout, error,
                                        sizeof(error))) {
        fprintf(stderr, "z23-dev: %s\n", error);
        return 1;
    }
    if (wcscmp(argv[1], L"create") == 0)
        return argc == 3 ? create_project(argv[2], executable) : (usage(), 2);
    if (!z23_dev_layout_validate(&layout, error, sizeof(error))) {
        fprintf(stderr, "z23-dev: %s\n", error);
        return 1;
    }
    if (wcscmp(argv[1], L"bootstrap") == 0) {
        puts("Z23 Windows devkit ready: create | develop | ship");
        return 0;
    }
    if (wcscmp(argv[1], L"develop") == 0) {
        const wchar_t *project = L".";
        bool once = false;
        int i;
        for (i = 2; i < argc; ++i) {
            if (wcscmp(argv[i], L"--once") == 0)
                once = true;
            else if (wcscmp(project, L".") == 0)
                project = argv[i];
            else {
                usage();
                return 2;
            }
        }
        if (!SetCurrentDirectoryW(project)) {
            fputs("develop: project directory is unavailable\n", stderr);
            return 1;
        }
        return develop(&layout, once);
    }
    if (wcscmp(argv[1], L"ship") == 0) {
        if (argc > 3) {
            usage();
            return 2;
        }
        if (argc == 3 && !SetCurrentDirectoryW(argv[2])) {
            fputs("ship: project directory is unavailable\n", stderr);
            return 1;
        }
        return ship(&layout);
    }
    usage();
    return 2;
}
#else
int main(void) { return 1; }
#endif
