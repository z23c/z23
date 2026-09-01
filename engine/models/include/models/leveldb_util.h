/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_MODELS_LEVELDB_UTIL_H
#define ZCL_MODELS_LEVELDB_UTIL_H

#include <dirent.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>

/* Scan a LevelDB directory for SST files, MANIFEST, and CURRENT.
 * Inline to avoid duplicate symbol errors across translation units. */
static inline void scan_leveldb_dir(const char *dir, int *sst_count,
                                    int64_t *total, bool *has_manifest,
                                    bool *has_current)
{
    *sst_count = 0;
    *total = 0;
    *has_manifest = false;
    *has_current = false;

    DIR *d = opendir(dir);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char path[1024];
        int written = snprintf(path, sizeof(path), "%s/%s",
                               dir, ent->d_name);
        if (written < 0 || (size_t)written >= sizeof(path))
            continue;
        struct stat st;
        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
            continue;
        *total += st.st_size;

        if (strstr(ent->d_name, ".ldb") || strstr(ent->d_name, ".sst"))
            (*sst_count)++;
        if (strncmp(ent->d_name, "MANIFEST", 8) == 0)
            *has_manifest = true;
        if (strcmp(ent->d_name, "CURRENT") == 0)
            *has_current = true;
    }
    closedir(d);
}

#endif
