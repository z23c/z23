/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Native Windows latency and determinism acceptance for the exact
 * code-index source metadata root used by every warm source-view query. */
#if defined(_WIN32)

#include "codeindex_priv.h"
#include "codeindex/codeindex_merkle.h"
#include "platform/private_directory.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

static const char *const lib_modules[] = {
#define LIB_MODULE(name_) name_,
#include "../../../engine/composition/lib_module_order.def"
#undef LIB_MODULE
};

static const char *const app_shapes[] = {
    "conditions", "controllers", "jobs", "models",
    "services", "supervisors", "views",
};

const char *const *ci_lib_modules(size_t *count)
{
    if (count) *count = sizeof(lib_modules) / sizeof(lib_modules[0]);
    return lib_modules;
}

const char *const *ci_app_shapes(size_t *count)
{
    if (count) *count = sizeof(app_shapes) / sizeof(app_shapes[0]);
    return app_shapes;
}

static int fail(const char *message)
{
    fprintf(stderr, "codeindex_freshness_windows_acceptance: FAIL: %s\n",
            message);
    return 1;
}

static uint64_t elapsed_us(LARGE_INTEGER start, LARGE_INTEGER end,
                           LARGE_INTEGER frequency)
{
    if (end.QuadPart < start.QuadPart || frequency.QuadPart <= 0) return 0;
    uint64_t ticks = (uint64_t)(end.QuadPart - start.QuadPart);
    uint64_t whole = ticks / (uint64_t)frequency.QuadPart;
    uint64_t remainder = ticks % (uint64_t)frequency.QuadPart;
    if (whole > UINT64_MAX / UINT64_C(1000000)) return UINT64_MAX;
    return whole * UINT64_C(1000000) +
           remainder * UINT64_C(1000000) /
               (uint64_t)frequency.QuadPart;
}

static bool fixture_write(const wchar_t *path, char digit)
{
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return false;
    char text[] = "int x=1;\n";
    text[6] = digit;
    DWORD written = 0;
    /* Old, nonzero subsecond stamps avoid sleeping for the settled-file rule.
     * The edit changes just 100 ns within the same second, at the same size. */
    ULARGE_INTEGER ticks = {.QuadPart = UINT64_C(132223104001234567) +
                                        (uint64_t)(digit - '1')};
    FILETIME modified = {ticks.LowPart, ticks.HighPart};
    bool ok = WriteFile(file, text, sizeof(text) - 1, &written, NULL) &&
              written == sizeof(text) - 1 &&
              SetFileTime(file, NULL, NULL, &modified) && FlushFileBuffers(file);
    if (!CloseHandle(file)) ok = false;
    return ok;
}

static bool mutation_acceptance(void)
{
    wchar_t temp[MAX_PATH], root_wide[MAX_PATH];
    wchar_t source_dir[MAX_PATH + 32], source[MAX_PATH + 64];
    wchar_t index_dir[MAX_PATH + 32];
    char root[2048];
    DWORD n = GetTempPathW(MAX_PATH, temp);
    if (!n || n >= MAX_PATH ||
        !GetTempFileNameW(temp, L"zci", 0, root_wide)) return false;
    if (!DeleteFileW(root_wide) ||
        WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, root_wide, -1,
                            root, sizeof(root), NULL, NULL) <= 0 ||
        !platform_private_directory_create(root)) return false;
    (void)swprintf(source_dir, MAX_PATH + 32, L"%ls\\platform", root_wide);
    (void)swprintf(source, MAX_PATH + 64, L"%ls\\item.c", source_dir);
    (void)swprintf(index_dir, MAX_PATH + 32, L"%ls\\.codeindex", root_wide);
    bool ok = CreateDirectoryW(source_dir, NULL) && fixture_write(source, '1');
    struct ci_merkle_cost cost = {0};
    struct ci_merkle_node initial, changed, reference;
    struct ci_merkle *tree = ok ? ci_merkle_refresh(root, &cost) : NULL;
    ok = tree && ci_merkle_root(tree, &initial) && cost.files_total == 1 &&
         cost.files_read == 1;
    ci_merkle_free(tree);
    tree = ok ? ci_merkle_refresh(root, &cost) : NULL;
    ok = tree && ci_merkle_root(tree, &reference) && cost.snapshot_used &&
         cost.files_read == 0 && cost.bytes_read == 0 && cost.leaves_reused == 1 &&
         memcmp(initial.digest.bytes, reference.digest.bytes, 32) == 0;
    ci_merkle_free(tree);
    ok = ok && fixture_write(source, '2');
    tree = ok ? ci_merkle_refresh(root, &cost) : NULL;
    ok = tree && ci_merkle_root(tree, &changed) && cost.files_read == 1 &&
         memcmp(initial.digest.bytes, changed.digest.bytes, 32) != 0;
    ci_merkle_free(tree);
    tree = ok ? ci_merkle_build_cold(root, &cost) : NULL;
    ok = tree && ci_merkle_root(tree, &reference) &&
         memcmp(changed.digest.bytes, reference.digest.bytes, 32) == 0;
    ci_merkle_free(tree);
    bool cleaned = ci_merkle_forget(root);
    if (!RemoveDirectoryW(index_dir)) cleaned = false;
    if (!DeleteFileW(source)) cleaned = false;
    if (!RemoveDirectoryW(source_dir)) cleaned = false;
    if (!RemoveDirectoryW(root_wide)) cleaned = false;
    return ok && cleaned;
}

int main(void)
{
    static const uint64_t budget_us = UINT64_C(150000);
    LARGE_INTEGER frequency, start, end;
    uint8_t first[32], second[32];
    if (!QueryPerformanceFrequency(&frequency) ||
        !ci_source_stat_root_sha3(".", first) ||
        !QueryPerformanceCounter(&start) ||
        !ci_source_stat_root_sha3(".", second) ||
        !QueryPerformanceCounter(&end))
        return fail("source metadata root capture");
    if (memcmp(first, second, sizeof(first)) != 0)
        return fail("unchanged source metadata root changed");
    uint64_t microseconds = elapsed_us(start, end, frequency);
    if (microseconds > budget_us) {
        fprintf(stderr,
                "codeindex_freshness_windows_acceptance: FAIL: "
                "elapsed_us=%llu budget_us=%llu\n",
                (unsigned long long)microseconds,
                (unsigned long long)budget_us);
        return 1;
    }
    printf("codeindex_freshness_windows_acceptance: PASS elapsed_us=%llu\n",
           (unsigned long long)microseconds);
    if (!mutation_acceptance())
        return fail("native Merkle reuse or same-size subsecond edit detection");
    struct ci_merkle_cost cost = {0};
    struct ci_merkle_node prepared, reused;
    struct ci_merkle *tree = ci_merkle_refresh(".", &cost);
    bool ok = tree && ci_merkle_root(tree, &prepared);
    ci_merkle_free(tree);
    if (!ok || !QueryPerformanceCounter(&start))
        return fail("prepare native Merkle refresh");
    tree = ci_merkle_refresh(".", &cost);
    ok = tree && ci_merkle_root(tree, &reused) &&
         QueryPerformanceCounter(&end);
    ci_merkle_free(tree);
    if (!ok || !cost.snapshot_used || cost.files_total == 0 ||
        cost.files_read != 0 || cost.bytes_read != 0 ||
        cost.leaves_reused != cost.files_total ||
        memcmp(prepared.digest.bytes, reused.digest.bytes, 32) != 0)
        return fail("unchanged source tree was not fully reused");
    microseconds = elapsed_us(start, end, frequency);
    if (microseconds > budget_us)
        return fail("warm native Merkle refresh exceeded the latency budget");
    printf("codeindex_freshness_windows_acceptance: Merkle PASS "
           "files_reused=%u bytes_read=%llu elapsed_us=%llu\n",
           cost.leaves_reused, (unsigned long long)cost.bytes_read,
           (unsigned long long)microseconds);
    return 0;
}

#else
typedef int codeindex_freshness_windows_acceptance_not_built;
#endif
