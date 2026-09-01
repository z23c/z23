/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Adversarial acceptance for handle/path identity checks. */
#include "platform/private_file.h"

#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <stdlib.h>
#include <unistd.h>
#endif

static bool append(char *out, size_t capacity, const char *root,
                   const char *suffix)
{
    size_t root_size = strlen(root), suffix_size = strlen(suffix);
    if (root_size >= capacity || suffix_size >= capacity - root_size)
        return false;
    memcpy(out, root, root_size);
    memcpy(out + root_size, suffix, suffix_size + 1u);
    return true;
}

int main(void)
{
    char root[1024], source[1200], held_name[1200], destination[1200];
#if defined(_WIN32)
    char temp[MAX_PATH];
    if (!GetTempPathA(MAX_PATH, temp)) return 1;
    int n = snprintf(root, sizeof(root), "%sz23-pfs-%lu", temp,
                     (unsigned long)GetCurrentProcessId());
    if (n <= 0 || (size_t)n >= sizeof(root) || !CreateDirectoryA(root, NULL))
        return 2;
    const char separator[] = "\\";
#else
    char template[] = "/tmp/z23-pfs-XXXXXX";
    const char *created = mkdtemp(template);
    if (!created || strlen(created) >= sizeof(root)) return 1;
    memcpy(root, created, strlen(created) + 1u);
    const char separator[] = "/";
#endif
    if (!append(source, sizeof(source), root, separator) ||
        !append(source, sizeof(source), source, "source") ||
        !append(held_name, sizeof(held_name), root, separator) ||
        !append(held_name, sizeof(held_name), held_name, "held") ||
        !append(destination, sizeof(destination), root, separator) ||
        !append(destination, sizeof(destination), destination, "destination"))
        return 3;

    struct platform_private_file held, replacement;
    platform_private_file_init(&held);
    platform_private_file_init(&replacement);
    if (!platform_private_file_create(source, &held)) return 4;
    struct platform_private_file_identity identity;
    if (!platform_private_file_identity(&held, &identity)) return 5;
#if defined(_WIN32)
    platform_private_file_close(&held);
    if (!MoveFileExA(source, held_name, MOVEFILE_WRITE_THROUGH) ||
        !platform_private_file_open_locked(held_name, &held)) return 6;
#else
    if (rename(source, held_name) != 0) return 6;
#endif
    if (!platform_private_file_create(source, &replacement)) return 7;
    platform_private_file_close(&replacement);
    bool same = false;
    if (platform_private_file_link_no_clobber(source, destination, &identity,
                                              &same) || same)
        return 8;
    bool retired = platform_private_file_retire(&held, source);
#if defined(_WIN32)
    if (!retired) return 9;
#else
    if (retired) return 9;
#endif
    platform_private_file_close(&held);
    if (platform_private_path_absent(source)) return 10;

    (void)platform_private_file_unlink_missing_ok(destination);
    (void)platform_private_file_unlink_missing_ok(source);
    (void)platform_private_file_unlink_missing_ok(held_name);
#if defined(_WIN32)
    (void)RemoveDirectoryA(root);
#else
    (void)rmdir(root);
#endif
    puts("private_file_path_swap_acceptance: PASS");
    return 0;
}
