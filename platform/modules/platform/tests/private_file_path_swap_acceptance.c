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

/* Creates the per-run scratch directory; returns 0 or the exit status. */
static int create_scratch_root(char *root, size_t capacity)
{
#if defined(_WIN32)
    char temp[MAX_PATH];
    if (!GetTempPathA(MAX_PATH, temp)) return 1;
    int n = snprintf(root, capacity, "%sz23-pfs-%lu", temp,
                     (unsigned long)GetCurrentProcessId());
    if (n <= 0 || (size_t)n >= capacity || !CreateDirectoryA(root, NULL))
        return 2;
#else
    char template[] = "/tmp/z23-pfs-XXXXXX";
    const char *created = mkdtemp(template);
    if (!created || strlen(created) >= capacity) return 1;
    memcpy(root, created, strlen(created) + 1u);
#endif
    return 0;
}

/* Builds the source, held and destination paths under root. */
static int append_case_paths(char *source, size_t source_capacity,
                             char *held_name, size_t held_name_capacity,
                             char *destination, size_t destination_capacity,
                             const char *root, const char *separator)
{
    if (!append(source, source_capacity, root, separator) ||
        !append(source, source_capacity, source, "source") ||
        !append(held_name, held_name_capacity, root, separator) ||
        !append(held_name, held_name_capacity, held_name, "held") ||
        !append(destination, destination_capacity, root, separator) ||
        !append(destination, destination_capacity, destination,
                "destination"))
        return 3;
    return 0;
}

/* Creates the source file, records its identity and moves it to held_name. */
static int stage_held_file(char *source, char *held_name,
                           struct platform_private_file *held,
                           struct platform_private_file_identity *identity)
{
    if (!platform_private_file_create(source, held)) return 4;
    if (!platform_private_file_identity(held, identity)) return 5;
#if defined(_WIN32)
    platform_private_file_close(held);
    if (!MoveFileExA(source, held_name, MOVEFILE_WRITE_THROUGH) ||
        !platform_private_file_open_locked(held_name, held)) return 6;
#else
    if (rename(source, held_name) != 0) return 6;
#endif
    return 0;
}

/* Retires the held handle and checks the source path is still present. */
static int retire_held_and_check_source(struct platform_private_file *held,
                                        char *source)
{
    bool retired = platform_private_file_retire(held, source);
#if defined(_WIN32)
    if (!retired) return 9;
#else
    if (retired) return 9;
#endif
    platform_private_file_close(held);
    if (platform_private_path_absent(source)) return 10;
    return 0;
}

/* Unlinks the case files and removes the scratch directory. */
static void remove_scratch_files(char *source, char *held_name,
                                 char *destination, char *root)
{
    (void)platform_private_file_unlink_missing_ok(destination);
    (void)platform_private_file_unlink_missing_ok(source);
    (void)platform_private_file_unlink_missing_ok(held_name);
#if defined(_WIN32)
    (void)RemoveDirectoryA(root);
#else
    (void)rmdir(root);
#endif
}

int main(void)
{
    char root[1024], source[1200], held_name[1200], destination[1200];
    int status = create_scratch_root(root, sizeof(root));
    if (status != 0) return status;
#if defined(_WIN32)
    const char separator[] = "\\";
#else
    const char separator[] = "/";
#endif
    status = append_case_paths(source, sizeof(source), held_name,
                               sizeof(held_name), destination,
                               sizeof(destination), root, separator);
    if (status != 0) return status;

    struct platform_private_file held, replacement;
    platform_private_file_init(&held);
    platform_private_file_init(&replacement);
    struct platform_private_file_identity identity;
    status = stage_held_file(source, held_name, &held, &identity);
    if (status != 0) return status;
    if (!platform_private_file_create(source, &replacement)) return 7;
    platform_private_file_close(&replacement);
    bool same = false;
    if (platform_private_file_link_no_clobber(source, destination, &identity,
                                              &same) || same)
        return 8;
    status = retire_held_and_check_source(&held, source);
    if (status != 0) return status;
    remove_scratch_files(source, held_name, destination, root);
    puts("private_file_path_swap_acceptance: PASS");
    return 0;
}
