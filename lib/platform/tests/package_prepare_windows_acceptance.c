/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Prove Windows package traversal retains valid checkout behavior
 * and refuses reparse-point content instead of omitting it. */
#include "vcs/package_prepare.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

/* scan_layout initializes these fixed-size evidence objects but does not
 * derive them. Keeping the acceptance link focused avoids pulling the release
 * and signature pipeline into a filesystem seam test. */
void vcs_package_lock_init(struct vcs_package_lock *lock)
{
    if (lock)
        memset(lock, 0, sizeof(*lock));
}

void vcs_package_capsule_init(struct vcs_package_capsule *capsule)
{
    if (capsule)
        memset(capsule, 0, sizeof(*capsule));
}

const char *vcs_package_deps_error_string(enum vcs_package_deps_error error)
{
    (void)error;
    return "unused";
}

enum vcs_package_deps_error vcs_package_deps_parse_meta(
    const uint8_t *text, size_t len, struct vcs_package_deps *out,
    char *detail, size_t detail_cap)
{
    (void)text; (void)len; (void)out; (void)detail; (void)detail_cap;
    return VCS_PACKAGE_DEPS_ERR_NULL;
}

enum vcs_package_deps_error vcs_package_lock_serialize(
    const struct vcs_package_lock *lock, uint8_t **out, size_t *out_len)
{
    (void)lock; (void)out; (void)out_len;
    return VCS_PACKAGE_DEPS_ERR_NULL;
}

enum vcs_package_deps_error vcs_package_lock_root(
    const struct vcs_package_lock *lock, uint8_t out[32])
{
    (void)lock; (void)out;
    return VCS_PACKAGE_DEPS_ERR_NULL;
}

const char *vcs_package_capsule_error_string(
    enum vcs_package_capsule_error error)
{
    (void)error;
    return "unused";
}

enum vcs_package_capsule_error vcs_package_capsule_derive(
    const struct vcs_package_manifest *manifest,
    const struct vcs_package_recipe *recipe,
    struct vcs_package_capsule *out)
{
    (void)manifest; (void)recipe; (void)out;
    return VCS_PACKAGE_CAPSULE_ERR_NULL;
}

enum vcs_package_capsule_error vcs_package_capsule_serialize(
    const struct vcs_package_capsule *capsule, uint8_t **wire,
    size_t *wire_len)
{
    (void)capsule; (void)wire; (void)wire_len;
    return VCS_PACKAGE_CAPSULE_ERR_NULL;
}

enum vcs_package_capsule_error vcs_package_capsule_root(
    const struct vcs_package_capsule *capsule, uint8_t out[32])
{
    (void)capsule; (void)out;
    return VCS_PACKAGE_CAPSULE_ERR_NULL;
}

enum vcs_package_release_error vcs_package_release_validate(
    const struct vcs_package_release *release)
{
    (void)release;
    return VCS_PACKAGE_RELEASE_ERR_NULL;
}

enum vcs_package_release_error vcs_package_release_id(
    const struct vcs_package_release *release,
    uint8_t out[VCS_PACKAGE_RELEASE_ID_BYTES])
{
    (void)release; (void)out;
    return VCS_PACKAGE_RELEASE_ERR_NULL;
}

enum vcs_package_release_error vcs_package_release_serialize(
    const struct vcs_package_release *release, uint8_t **out,
    size_t *out_len)
{
    (void)release; (void)out; (void)out_len;
    return VCS_PACKAGE_RELEASE_ERR_NULL;
}

static bool write_file(const wchar_t *path, const char *content)
{
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return false;
    DWORD wanted = (DWORD)strlen(content);
    DWORD written = 0;
    bool ok = WriteFile(file, content, wanted, &written, NULL) &&
              written == wanted;
    CloseHandle(file);
    return ok;
}

static int fail(const char *message)
{
    fprintf(stderr, "package_prepare_windows_acceptance: %s\n", message);
    return 1;
}

int main(void)
{
    wchar_t temporary[MAX_PATH];
    wchar_t root[MAX_PATH];
    wchar_t source[MAX_PATH];
    wchar_t source_file[MAX_PATH];
    wchar_t metadata[MAX_PATH];
    wchar_t outside[MAX_PATH];
    wchar_t link[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, temporary) ||
        swprintf(root, MAX_PATH, L"%lsz23-package-prepare-%lu-%llu",
                 temporary, (unsigned long)GetCurrentProcessId(),
                 (unsigned long long)GetTickCount64()) <= 0 ||
        swprintf(source, MAX_PATH, L"%ls\\src", root) <= 0 ||
        swprintf(source_file, MAX_PATH, L"%ls\\x.c", source) <= 0 ||
        swprintf(metadata, MAX_PATH, L"%ls\\zcode-package.json", root) <= 0 ||
        swprintf(outside, MAX_PATH, L"%lsz23-package-outside-%lu.c",
                 temporary, (unsigned long)GetCurrentProcessId()) <= 0 ||
        swprintf(link, MAX_PATH, L"%ls\\escape.c", root) <= 0 ||
        !CreateDirectoryW(root, NULL) || !CreateDirectoryW(source, NULL) ||
        !write_file(source_file, "int x(void) { return 23; }\n") ||
        !write_file(metadata, "{}\n") ||
        !write_file(outside, "int outside(void) { return 1; }\n"))
        return fail("fixture creation failed");

    char root_utf8[MAX_PATH * 3];
    if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, root, -1,
                             root_utf8, sizeof(root_utf8), NULL, NULL))
        return fail("root UTF-8 conversion failed");
    struct vcs_package_prepared prepared;
    bool has_package_config = false;
    char detail[256];
    if (vcs_package_scan_layout(root_utf8, &prepared, &has_package_config,
                                detail, sizeof(detail)) !=
            VCS_PACKAGE_PREPARE_OK ||
        !has_package_config || prepared.manifest.count != 2)
        return fail("real package checkout did not scan");
    vcs_package_prepared_free(&prepared);

    DWORD flags = 0;
#ifdef SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
    flags |= SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
#endif
    if (!CreateSymbolicLinkW(link, outside, flags)) {
        DeleteFileW(outside);
        DeleteFileW(metadata);
        DeleteFileW(source_file);
        RemoveDirectoryW(source);
        RemoveDirectoryW(root);
        fputs("package_prepare_windows_acceptance: REFUSE: runtime cannot "
              "create a file reparse point\n", stderr);
        return 77;
    }
    enum vcs_package_prepare_error result = vcs_package_scan_layout(
        root_utf8, &prepared, &has_package_config, detail, sizeof(detail));
    if (result != VCS_PACKAGE_PREPARE_ERR_FILE_TYPE)
        return fail("file reparse point was omitted or traversed");

    DeleteFileW(link);
    DeleteFileW(outside);
    DeleteFileW(metadata);
    DeleteFileW(source_file);
    RemoveDirectoryW(source);
    RemoveDirectoryW(root);
    puts("package_prepare_windows_acceptance: PASS");
    return 0;
}

#else
int main(void) { return 77; }
#endif
