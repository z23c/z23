/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: native Windows signed-plugin storage acceptance in isolated fixtures. */
#if defined(_WIN32)
#include "base/cleanse.h"
#include "platform/directory_compat.h"
#include "platform/directory_transaction.h"
#include "platform/private_directory.h"
#include "platform/windows_path.h"
#include "plugin_internal.h"
#include <errno.h>
#include <sddl.h>
#include <stdio.h>
#include <string.h>
#include <winioctl.h>

#define REQUIRE(expr)                                                                  \
    do {                                                                               \
        if (!(expr)) {                                                                 \
            fprintf(stderr, "FAIL line %d: %s (win32=%lu errno=%d)\n", __LINE__,       \
                    #expr, (unsigned long)GetLastError(), errno);                      \
            return 1;                                                                  \
        }                                                                              \
    } while (0)
#define STATUS(expr, want)                                                             \
    do {                                                                               \
        enum plugin_status actual = (expr);                                            \
        if (actual != (want)) {                                                        \
            fprintf(stderr, "FAIL line %d: %s got=%d want=%d win32=%lu errno=%d\n",    \
                    __LINE__, #expr, actual, (want), (unsigned long)GetLastError(),    \
                    errno);                                                            \
            return 1;                                                                  \
        }                                                                              \
    } while (0)

/* Junction creation is an isolated fixture operation, requiring no symlink
 * privilege or Developer Mode. The target is another fixture-owned directory. */
static bool fixture_junction(const char *path, const char *target) {
    wchar_t link[32768], plain[32768], absolute[32768];
    if (!platform_windows_wide_path(path, link) ||
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, target, -1, plain, 32768) <=
            0 ||
        !GetFullPathNameW(plain, 32768, absolute, NULL) ||
        !CreateDirectoryW(link, NULL))
        return false;
    HANDLE h =
        CreateFileW(link, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    struct junction_data {
        DWORD tag;
        USHORT length, reserved;
        USHORT substitute_offset, substitute_length, print_offset, print_length;
        WCHAR path[2048];
    } data = {.tag = IO_REPARSE_TAG_MOUNT_POINT};
    size_t count = wcslen(absolute);
    bool ok = count < 900u;
    if (ok) {
        memcpy(data.path, L"\\??\\", 4 * sizeof(WCHAR));
        memcpy(data.path + 4, absolute, (count + 1u) * sizeof(WCHAR));
        data.substitute_length = (USHORT)((count + 4u) * sizeof(WCHAR));
        data.print_offset = (USHORT)(data.substitute_length + sizeof(WCHAR));
        data.print_length = (USHORT)(count * sizeof(WCHAR));
        memcpy((BYTE *)data.path + data.print_offset, absolute,
               (count + 1u) * sizeof(WCHAR));
        data.length =
            (USHORT)(8u + data.print_offset + data.print_length + sizeof(WCHAR));
        DWORD transferred = 0;
        ok = DeviceIoControl(h, FSCTL_SET_REPARSE_POINT, &data, (DWORD)data.length + 8u,
                             NULL, 0, &transferred, NULL) != 0;
    }
    CloseHandle(h);
    return ok;
}

static int fixture_namespace(const char *root) {
    struct platform_directory_transaction parent, source, replacement, destination,
        outside, destination_move;
    platform_directory_transaction_init(&parent);
    platform_directory_transaction_init(&source);
    platform_directory_transaction_init(&replacement);
    platform_directory_transaction_init(&destination);
    platform_directory_transaction_init(&outside);
    platform_directory_transaction_init(&destination_move);
    REQUIRE(platform_directory_transaction_open(&parent, root));
    REQUIRE(platform_directory_transaction_open_child_namespace(
                &parent, "source", true, &source) == PLATFORM_DIRECTORY_OK);
    REQUIRE(platform_directory_transaction_move_directory(&parent, "source", &source,
                                                          &parent, "saved-source") ==
            PLATFORM_DIRECTORY_OK);
    REQUIRE(platform_directory_transaction_open_child_namespace(
                &parent, "source", true, &replacement) == PLATFORM_DIRECTORY_OK);
    REQUIRE(platform_directory_transaction_move_directory(&parent, "source", &source,
                                                          &parent, "must-not-exist") ==
            PLATFORM_DIRECTORY_REFUSED);
    REQUIRE(platform_directory_transaction_open_child_namespace(
                &parent, "destination", true, &destination_move) ==
            PLATFORM_DIRECTORY_OK);
    REQUIRE(platform_directory_transaction_open_child(
                &parent, "destination", false, &destination) == PLATFORM_DIRECTORY_OK);
    REQUIRE(platform_directory_transaction_open_child_namespace(
                &parent, "outside", true, &outside) == PLATFORM_DIRECTORY_OK);
    REQUIRE(platform_directory_transaction_move_directory(
                &parent, "destination", &destination_move, &parent,
                "saved-destination") == PLATFORM_DIRECTORY_OK);
    platform_directory_transaction_close(&destination_move);
    char junction[PLUGIN_PATH_MAX], target[PLUGIN_PATH_MAX];
    REQUIRE(plugin_join(junction, sizeof(junction), root, "destination", NULL, NULL));
    REQUIRE(plugin_join(target, sizeof(target), root, "outside", NULL, NULL));
    REQUIRE(fixture_junction(junction, target));
    struct platform_directory_transaction refused;
    platform_directory_transaction_init(&refused);
    REQUIRE(!platform_directory_transaction_open(&refused, junction));
    REQUIRE(platform_directory_transaction_move_directory(
                &parent, "source", &replacement, &destination, "published") ==
            PLATFORM_DIRECTORY_OK);
    REQUIRE(platform_directory_transaction_open_child(
                &outside, "published", false, &refused) == PLATFORM_DIRECTORY_MISSING);
    REQUIRE(platform_directory_transaction_open_child(
                &destination, "published", false, &refused) == PLATFORM_DIRECTORY_OK);
    platform_directory_transaction_close(&refused);
    platform_directory_transaction_close(&source);
    platform_directory_transaction_close(&replacement);
    platform_directory_transaction_close(&destination);
    platform_directory_transaction_close(&outside);
    platform_directory_transaction_close(&parent);
    wchar_t junction_wide[32768];
    REQUIRE(platform_windows_wide_path(junction, junction_wide));
    REQUIRE(RemoveDirectoryW(junction_wide)); /* Remove the fixture junction itself. */
    puts("PASS source-name substitution refusal and destination-junction "
         "refusal/non-redirection");
    return 0;
}

struct fixture_key_paths {
    wchar_t broad_directory[32768], broad_file[32768];
};

static int fixture_keys(const char *root, char key[PLUGIN_PATH_MAX],
                        char pub[PLUGIN_HEX_PUBLIC_KEY + 1],
                        struct fixture_key_paths *paths)
{
    char broad[PLUGIN_PATH_MAX], badkey[PLUGIN_PATH_MAX];
    char again[PLUGIN_HEX_PUBLIC_KEY + 1];
    REQUIRE(plugin_join(key, PLUGIN_PATH_MAX, root, "publisher.key", NULL, NULL));
    STATUS(plugin_keygen(key, pub), PLUGIN_OK);
    STATUS(plugin_keygen(key, again), PLUGIN_ERR_KEY_EXISTS);
    uint8_t seed[PLUGIN_KEY_FILE_BYTES];
    STATUS(plugin_key_load(key, seed), PLUGIN_OK);
    memory_cleanse(seed, sizeof(seed));
    char malformed_key[PLUGIN_PATH_MAX];
    REQUIRE(plugin_join(malformed_key, sizeof(malformed_key), root, "malformed.key",
                        NULL, NULL));
    uint8_t short_seed[31] = {0};
    REQUIRE(platform_directory_transaction_write_atomic(malformed_key, short_seed,
                                                        sizeof(short_seed)));
    memset(seed, 0xA5, sizeof(seed));
    STATUS(plugin_key_load(malformed_key, seed), PLUGIN_ERR_KEY_MALFORMED);
    for (size_t i = 0; i < sizeof(seed); i++)
        REQUIRE(seed[i] == 0);
    REQUIRE(plugin_join(broad, sizeof(broad), root, "broad", NULL, NULL));

    REQUIRE(platform_windows_wide_path(broad, paths->broad_directory));
    PSECURITY_DESCRIPTOR acl = NULL;
    REQUIRE(ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:P(A;;FA;;;SY)(A;;FA;;;OW)(A;;GR;;;WD)", SDDL_REVISION_1, &acl, NULL));
    SECURITY_ATTRIBUTES sa = {.nLength = sizeof(sa), .lpSecurityDescriptor = acl};
    REQUIRE(CreateDirectoryW(paths->broad_directory, &sa));
    char broad_file[PLUGIN_PATH_MAX];

    REQUIRE(plugin_join(broad_file, sizeof(broad_file), root, "broad-file.key", NULL,
                        NULL));
    REQUIRE(platform_windows_wide_path(broad_file, paths->broad_file));
    HANDLE broad_handle = CreateFileW(paths->broad_file, GENERIC_WRITE, 0, &sa,
                                      CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    REQUIRE(broad_handle != INVALID_HANDLE_VALUE);
    DWORD written = 0;
    uint8_t fixture_seed[32] = {0};
    REQUIRE(
        WriteFile(broad_handle, fixture_seed, sizeof(fixture_seed), &written, NULL) &&
        written == 32);
    REQUIRE(CloseHandle(broad_handle));
    LocalFree(acl);
    memset(seed, 0xA5, sizeof(seed));
    STATUS(plugin_key_load(broad_file, seed), PLUGIN_ERR_KEY_INSECURE);
    for (size_t i = 0; i < sizeof(seed); i++)
        REQUIRE(seed[i] == 0);
    REQUIRE(plugin_join(badkey, sizeof(badkey), broad, "refused.key", NULL, NULL));
    STATUS(plugin_keygen(badkey, again), PLUGIN_ERR_KEY_INSECURE);
    wchar_t bad_wide[32768];
    REQUIRE(platform_windows_wide_path(badkey, bad_wide));
    REQUIRE(GetFileAttributesW(bad_wide) == INVALID_FILE_ATTRIBUTES &&
            GetLastError() == ERROR_FILE_NOT_FOUND);
    STATUS(plugin_key_load(badkey, seed), PLUGIN_ERR_KEY_INSECURE);
    for (size_t i = 0; i < sizeof(seed); i++)
        REQUIRE(seed[i] == 0);
    puts("PASS key create/load/existing-key, malformed cleanse, broad-file ACL and "
         "broad-parent refusal/no mutation");
    return 0;
}

static int fixture_cleanup(const char *root, const struct fixture_key_paths *paths)
{
    REQUIRE(DeleteFileW(paths->broad_file));
    REQUIRE(RemoveDirectoryW(paths->broad_directory));
    /* The fixture root itself lives under the operator temp directory, which
     * deliberately is not required to have the private plugin-store ACL.
     * Bind cleanup to the validated exact fixture root, never traverse temp. */
    struct platform_directory_transaction validated_root, cleanup_root;
    platform_directory_transaction_init(&validated_root);
    platform_directory_transaction_init(&cleanup_root);
    REQUIRE(platform_directory_transaction_open(&validated_root, root));
    wchar_t root_wide[32768];
    REQUIRE(platform_windows_wide_path(root, root_wide));
    HANDLE cleanup_handle = CreateFileW(
        root_wide, FILE_LIST_DIRECTORY | DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    REQUIRE(cleanup_handle != INVALID_HANDLE_VALUE);
    BY_HANDLE_FILE_INFORMATION checked_identity, cleanup_identity;
    REQUIRE(
        GetFileInformationByHandle((HANDLE)validated_root.native, &checked_identity));
    REQUIRE(GetFileInformationByHandle(cleanup_handle, &cleanup_identity));
    REQUIRE(checked_identity.dwVolumeSerialNumber ==
                cleanup_identity.dwVolumeSerialNumber &&
            checked_identity.nFileIndexHigh == cleanup_identity.nFileIndexHigh &&
            checked_identity.nFileIndexLow == cleanup_identity.nFileIndexLow);
    cleanup_root.native = (uintptr_t)cleanup_handle;
    platform_directory_transaction_close(&validated_root);
    REQUIRE(platform_directory_transaction_remove_retained(&cleanup_root, 0));
    platform_directory_transaction_close(&cleanup_root);
    puts("plugin_store_windows_acceptance: PASS (isolated fixture cleanup complete)");
    return 0;
}

int main(void)
{
    char root[PLUGIN_PATH_MAX], key[PLUGIN_PATH_MAX];
    struct fixture_key_paths key_paths;
    char store[PLUGIN_PATH_MAX], dist[PLUGIN_PATH_MAX], exe[PLUGIN_PATH_MAX],
        keys_file[PLUGIN_PATH_MAX];
    char pub[PLUGIN_HEX_PUBLIC_KEY + 1], keys_bytes[PLUGIN_HEX_PUBLIC_KEY + 2];
    wchar_t temp_wide[32768];
    char temp[PLUGIN_PATH_MAX];
    DWORD temp_count = GetTempPathW(32768, temp_wide);
    REQUIRE(temp_count > 0 && temp_count < 32768);
    REQUIRE(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, temp_wide, -1, temp,
                                sizeof(temp), NULL, NULL) > 0);
    size_t temp_length = strlen(temp);
    while (temp_length &&
           (temp[temp_length - 1u] == '/' || temp[temp_length - 1u] == '\\'))
        temp[--temp_length] = '\0';
    int n = snprintf(root, sizeof(root), "%s/z23-plugin-store-%lu", temp,
                     (unsigned long)GetCurrentProcessId());
    REQUIRE(n > 0 && (size_t)n < sizeof(root));
    REQUIRE(platform_private_directory_create(root));
    REQUIRE(fixture_keys(root, key, pub, &key_paths) == 0);
    REQUIRE(plugin_join(store, sizeof(store), root, "store", NULL, NULL));
    REQUIRE(plugin_join(dist, sizeof(dist), root, "dist", NULL, NULL));
    REQUIRE(plugin_join(exe, sizeof(exe), root, "input.exe", NULL, NULL));
    REQUIRE(platform_private_directory_create(store));
    REQUIRE(
        platform_directory_transaction_write_atomic(exe, "first executable bytes", 22));
    REQUIRE(plugin_join(keys_file, sizeof(keys_file), store, "publisher_keys", NULL, NULL));
    n = snprintf(keys_bytes, sizeof(keys_bytes), "%s\n", pub);
    REQUIRE(n == 65 &&
            platform_directory_transaction_write_atomic(keys_file, keys_bytes, (size_t)n));
    struct plugin_pack_request request = {.exe_path = exe,
                                          .key_path = key,
                                          .name = "hello",
                                          .version = "1.0.0",
                                          .out_dir = dist,
                                          .capabilities = 1u};
    struct plugin_pack_result first, second;
    struct plugin_manifest manifest;
    int present = -1;
    STATUS(plugin_pack(&request, &first), PLUGIN_OK);
    STATUS(plugin_pack(&request, &second), PLUGIN_OK);
    REQUIRE(!strcmp(first.generation, second.generation));
    STATUS(plugin_store_install(store, first.manifest_path, &manifest, &present),
           PLUGIN_OK);
    REQUIRE(present == 0 && !strcmp(manifest.generation, first.generation));
    STATUS(plugin_store_install(store, first.manifest_path, &manifest, &present),
           PLUGIN_OK);
    REQUIRE(present == 1);
    STATUS(plugin_store_switch(store, "hello", first.generation), PLUGIN_OK);
    char plugdir[PLUGIN_PATH_MAX], pointer_path[PLUGIN_PATH_MAX], gens[PLUGIN_PATH_MAX];
    REQUIRE(plugin_join(plugdir, sizeof(plugdir), store, "hello", NULL, NULL));
    REQUIRE(plugin_join(pointer_path, sizeof(pointer_path), plugdir, "current", NULL,
                        NULL));
    REQUIRE(plugin_join(gens, sizeof(gens), plugdir, "generations", NULL, NULL));
    char *pointer_bytes = NULL;
    size_t pointer_size = 0;
    REQUIRE(plugin_read_file(pointer_path, 142,
                             PLUGIN_OPEN_NOFOLLOW | PLUGIN_OPEN_OWNER_ONLY,
                             &pointer_bytes, &pointer_size));
    REQUIRE(pointer_size == 141 && pointer_bytes[140] == '\n' &&
            !memcmp(pointer_bytes, "generations/", 12));
    char malformed[142];
    memcpy(malformed, pointer_bytes, 141);
    malformed[141] = 'X';
    free(pointer_bytes);
    REQUIRE(platform_directory_transaction_write_atomic(pointer_path, malformed,
                                                        sizeof(malformed)));
    char slot[PLUGIN_HEX_SHA3_512 + 1];
    REQUIRE(plugin_link_slot(plugdir, "current", slot) == PLUGIN_SLOT_CORRUPT);
    STATUS(plugin_store_switch(store, "hello", first.generation), PLUGIN_OK);
    puts("PASS exact 141-byte current pointer and trailing-byte refusal");
    REQUIRE(platform_directory_transaction_write_atomic(exe, "second executable bytes",
                                                        23));
    request.version = "2.0.0";
    STATUS(plugin_pack(&request, &second), PLUGIN_OK);
    REQUIRE(strcmp(first.generation, second.generation));
    STATUS(plugin_store_install(store, second.manifest_path, &manifest, &present),
           PLUGIN_OK);
    STATUS(plugin_store_switch(store, "hello", second.generation), PLUGIN_OK);
    char restored[PLUGIN_HEX_SHA3_512 + 1];
    STATUS(plugin_store_rollback(store, "hello", restored), PLUGIN_OK);
    REQUIRE(!strcmp(restored, first.generation));
    struct plugin_info *infos = NULL;
    size_t count = 0;
    STATUS(plugin_store_list(store, &infos, &count), PLUGIN_OK);
    REQUIRE(count == 1 && !strcmp(infos[0].current, first.generation) &&
            infos[0].generation_count == 2);
    plugin_store_list_free(infos, count);
    puts("PASS deterministic pack/install/reinstall/switch/two "
         "generations/rollback/list");
    /* Corrupt a stored generation, then reinstall its exact signed source.
     * The old directory must be moved aside, the staged replacement published,
     * and only the retained old object removed after successful publication. */
    char generation[PLUGIN_PATH_MAX], stored_exe[PLUGIN_PATH_MAX];
    REQUIRE(plugin_join(generation, sizeof(generation), gens, first.generation, NULL,
                        NULL));
    REQUIRE(
        plugin_join(stored_exe, sizeof(stored_exe), generation, "hello", NULL, NULL));
    REQUIRE(platform_directory_transaction_write_atomic(stored_exe, "corrupt", 7));
    REQUIRE(
        platform_directory_transaction_write_atomic(exe, "first executable bytes", 22));
    request.version = "1.0.0";
    STATUS(plugin_pack(&request, &first), PLUGIN_OK);
    STATUS(plugin_store_install(store, first.manifest_path, &manifest, &present),
           PLUGIN_OK);
    REQUIRE(present == 0);
    STATUS(plugin_verify_generation(store, "hello", first.generation), PLUGIN_OK);
    struct platform_directory_list directories = {0};
    REQUIRE(platform_directory_list_real_sorted(gens, &directories));
    REQUIRE(directories.count == 2);
    platform_directory_list_free(&directories);
    puts("PASS corrupt-generation replacement and retained-old cleanup");
    REQUIRE(
        platform_directory_transaction_write_atomic(exe, "third executable bytes", 22));
    request.version = "3.0.0";
    struct plugin_pack_result third;
    STATUS(plugin_pack(&request, &third), PLUGIN_OK);
    platform_directory_transaction_move_directory_test_fail_durability_once();
    STATUS(plugin_store_install(store, third.manifest_path, &manifest, &present),
           PLUGIN_ERR_IO);
    /* A completed move with failed post-move proof must not delete its result.
     * A fresh exact verification reconciles it as an already-present object. */
    STATUS(plugin_store_install(store, third.manifest_path, &manifest, &present),
           PLUGIN_OK);
    REQUIRE(present == 1);
    REQUIRE(plugin_link_slot(plugdir, "current", slot) == PLUGIN_SLOT_OK &&
            !strcmp(slot, first.generation));
    puts("PASS unknown-publication outcome preserves exact object and current pointer");
    /* Exercise an unknown outcome while the old corrupt directory is being
     * moved aside. Neither the verified staging copy nor the retained prior
     * may be deleted until a fresh observation reconciles namespace identity. */
    REQUIRE(
        platform_directory_transaction_write_atomic(stored_exe, "corrupt-again", 13));
    request.version = "1.0.0";
    REQUIRE(
        platform_directory_transaction_write_atomic(exe, "first executable bytes", 22));
    STATUS(plugin_pack(&request, &first), PLUGIN_OK);
    platform_directory_transaction_move_directory_test_fail_durability_once();
    STATUS(plugin_store_install(store, first.manifest_path, &manifest, &present),
           PLUGIN_ERR_IO);
    char aside[PLUGIN_PATH_MAX], aside_leaf[PLATFORM_DIRECTORY_CHILD_LEAF_MAX + 1u];
    n = snprintf(aside_leaf, sizeof(aside_leaf), "%s.old.%lu", first.generation,
                 (unsigned long)GetCurrentProcessId());
    REQUIRE(n > 0 && (size_t)n < sizeof(aside_leaf));
    REQUIRE(plugin_join(aside, sizeof(aside), gens, aside_leaf, NULL, NULL));
    REQUIRE(plugin_check_dir(aside) == PLUGIN_OK);
    STATUS(plugin_store_install(store, first.manifest_path, &manifest, &present),
           PLUGIN_OK);
    REQUIRE(present == 0);
    STATUS(plugin_verify_generation(store, "hello", first.generation), PLUGIN_OK);
    REQUIRE(plugin_check_dir(aside) ==
            PLUGIN_OK); /* Reconciliation evidence retained. */
    puts("PASS unknown prior-aside outcome retains reconciliation evidence and retry "
         "repairs exact generation");
    REQUIRE(fixture_namespace(root) == 0);
    REQUIRE(fixture_cleanup(root, &key_paths) == 0);
    return 0;
}

#else
typedef int plugin_store_windows_acceptance_not_built;
#endif
