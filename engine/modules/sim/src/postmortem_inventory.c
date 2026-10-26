/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the postmortem capsule DIRECTORY surface — enumerate what is on
 * disk, summarise each capsule from its manifest, and enforce the retention
 * policy (keep-latest N, drop older than max_age).
 *
 * Split out of postmortem.c along the file-size ceiling seam: that file keeps
 * the capsule itself (crash hook, async-signal-safe capture, manifest write,
 * load/validate/compress). Nothing here writes a capsule — it only reads the
 * ones already there and decides which stop existing. The two filesystem
 * primitives that cross back the other way (postmortem_has_suffix,
 * postmortem_remove_tree) are declared in postmortem_internal.h.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "sim/postmortem.h"

#if !defined(_WIN32)
#include "postmortem_internal.h"

#include "util/safe_alloc.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

static int64_t parse_capsule_time(const char *name)
{
    if (!name) return 0;
    char *end = NULL;
    long long v = strtoll(name, &end, 10);
    if (end == name) return 0;
    return (int64_t)v;
}

static size_t capsule_regular_bytes(const char *path)
{
    if (!path) return 0;
    struct stat pst;
    if (stat(path, &pst) == 0 && S_ISREG(pst.st_mode))
        return pst.st_size > 0 ? (size_t)pst.st_size : 0;

    DIR *d = opendir(path);
    if (!d) return 0;
    size_t total = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        char child[576];
        int n = snprintf(child, sizeof(child), "%s/%s", path, de->d_name);
        if (n < 0 || (size_t)n >= sizeof(child)) continue;
        struct stat st;
        if (stat(child, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0)
            total += (size_t)st.st_size;
    }
    closedir(d);
    return total;
}

static int entry_newer(const struct postmortem_capsule_entry *a,
                       const struct postmortem_capsule_entry *b)
{
    if (a->crash_unix != b->crash_unix)
        return a->crash_unix > b->crash_unix;
    return strcmp(a->name, b->name) > 0;
}

static int compare_entries_newest_first(const void *va, const void *vb)
{
    const struct postmortem_capsule_entry *a =
        (const struct postmortem_capsule_entry *)va;
    const struct postmortem_capsule_entry *b =
        (const struct postmortem_capsule_entry *)vb;
    if (entry_newer(a, b)) return -1;
    if (entry_newer(b, a)) return 1;
    return 0;
}

static int find_oldest_entry(const struct postmortem_capsule_entry *entries,
                             size_t count)
{
    if (!entries || count == 0) return -1;
    size_t oldest = 0;
    for (size_t i = 1; i < count; i++) {
        if (entry_newer(&entries[oldest], &entries[i]))
            oldest = i;
    }
    return (int)oldest;
}

static int64_t parse_manifest_i64(const char *manifest, const char *key,
                                  int64_t fallback)
{
    if (!manifest || !key) return fallback;
    const char *p = strstr(manifest, key);
    if (!p) return fallback;
    p = strchr(p, ':');
    if (!p) return fallback;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    char *end = NULL;
    long long v = strtoll(p, &end, 10);
    if (end == p) return fallback;
    return (int64_t)v;
}

static void read_manifest_summary(struct postmortem_capsule_entry *entry)
{
    if (!entry) return;

    char manifest_path[576];
    int n = snprintf(manifest_path, sizeof(manifest_path),
                     "%s/manifest.json", entry->path);
    if (n < 0 || (size_t)n >= sizeof(manifest_path)) return;

    FILE *fp = fopen(manifest_path, "rb");
    if (!fp) return;
    char buf[2048];
    size_t got = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[got] = '\0';

    entry->crash_signal = (int)parse_manifest_i64(buf, "\"crash_signal\"",
                                                  entry->crash_signal);
    int64_t tape_size = parse_manifest_i64(buf, "\"tape_size_bytes\"",
                                           (int64_t)entry->tape_size_bytes);
    if (tape_size >= 0)
        entry->tape_size_bytes = (size_t)tape_size;
}

static void read_manifest_summary_gz(struct postmortem_capsule_entry *entry)
{
    if (!entry) return;

    uint8_t *buf = NULL;
    size_t len = 0;
    int rc = gz_read_tar_member(entry->path, "manifest.json", &buf, &len,
                                64u * 1024u);
    if (rc != 0 || !buf) return;

    entry->crash_signal = (int)parse_manifest_i64((const char *)buf,
                                                  "\"crash_signal\"",
                                                  entry->crash_signal);
    int64_t tape_size = parse_manifest_i64((const char *)buf,
                                           "\"tape_size_bytes\"",
                                           (int64_t)entry->tape_size_bytes);
    if (tape_size >= 0)
        entry->tape_size_bytes = (size_t)tape_size;
    free(buf);
}

static int capsule_candidate_from_dirent(const char *dir,
                                         const struct dirent *de,
                                         struct postmortem_capsule_entry *out)
{
    bool packed = postmortem_has_suffix(de->d_name, ".cap.gz");
    bool unpacked = postmortem_has_suffix(de->d_name, ".cap");
    if (!packed && !unpacked) return -1;

    memset(out, 0, sizeof(*out));
    snprintf(out->name, sizeof(out->name), "%.*s",
             (int)sizeof(out->name) - 1, de->d_name);
    snprintf(out->path, sizeof(out->path), "%s/%s", dir, de->d_name);
    out->crash_unix = parse_capsule_time(de->d_name);

    struct stat st;
    if (stat(out->path, &st) != 0)
        return -1;
    if (unpacked) {
        if (!S_ISDIR(st.st_mode)) return -1;
        read_manifest_summary(out);
    } else {
        if (!S_ISREG(st.st_mode)) return -1;
        read_manifest_summary_gz(out);
    }
    return 0;
}

static void insert_keep_newest(struct postmortem_capsule_entry *entries,
                               size_t entry_cap, size_t *count_out,
                               const struct postmortem_capsule_entry *entry)
{
    if (entry_cap > 0) {
        if (*count_out < entry_cap) {
            entries[*count_out] = *entry;
        } else {
            int oldest = find_oldest_entry(entries, entry_cap);
            if (oldest >= 0 && entry_newer(entry, &entries[oldest]))
                entries[oldest] = *entry;
        }
    }
}

int postmortem_capsule_list(const char *dir,
                            struct postmortem_capsule_entry *entries,
                            size_t entry_cap,
                            size_t *count_out)
{
    if (!dir || !count_out || (entry_cap > 0 && !entries)) return -EINVAL;
    *count_out = 0;
    DIR *d = opendir(dir);
    if (!d) return errno == ENOENT ? 0 : -errno;

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        struct postmortem_capsule_entry candidate;
        if (capsule_candidate_from_dirent(dir, de, &candidate) != 0)
            continue;

        insert_keep_newest(entries, entry_cap, count_out, &candidate);
        (*count_out)++;
    }
    closedir(d);
    if (entry_cap > 1) {
        size_t filled = *count_out < entry_cap ? *count_out : entry_cap;
        qsort(entries, filled, sizeof(entries[0]),
              compare_entries_newest_first);
    }
    return 0;
}

int postmortem_list(const char *dir,
                    struct postmortem_summary *out,
                    size_t out_cap,
                    size_t *count_out)
{
    if (!count_out || (out_cap > 0 && !out)) return -EINVAL;
    *count_out = 0;

    struct postmortem_capsule_entry *entries = NULL;
    if (out_cap > 0) {
        entries = (struct postmortem_capsule_entry *)
            zcl_malloc(sizeof(entries[0]) * out_cap, "postmortem.list");
        if (!entries) return -ENOMEM;
    }

    int rc = postmortem_capsule_list(dir, entries, out_cap, count_out);
    if (rc != 0) {
        free(entries);
        return rc;
    }

    size_t filled = *count_out < out_cap ? *count_out : out_cap;
    for (size_t i = 0; i < filled; i++) {
        memset(&out[i], 0, sizeof(out[i]));
        snprintf(out[i].path, sizeof(out[i].path), "%s", entries[i].path);
        out[i].crash_unix = entries[i].crash_unix;
        out[i].crash_signal = entries[i].crash_signal;
        out[i].tape_size_bytes = entries[i].tape_size_bytes;
        out[i].capsule_bytes = capsule_regular_bytes(entries[i].path);
    }
    free(entries);
    return 0;
}

static bool capsule_entry_past_retention(size_t index,
                                         size_t keep_latest,
                                         int64_t max_age_seconds,
                                         int64_t now_unix,
                                         int64_t crash_unix)
{
    bool over_count = keep_latest > 0 && index >= keep_latest;
    bool over_age = false;
    if (max_age_seconds > 0 && now_unix > 0 && crash_unix > 0) {
        over_age = crash_unix < now_unix &&
                   now_unix - crash_unix > max_age_seconds;
    }
    return over_count || over_age;
}

static int prune_past_retention(struct postmortem_capsule_entry *entries,
                                size_t filled,
                                size_t keep_latest,
                                int64_t max_age_seconds,
                                int64_t now_unix,
                                size_t *pruned_out)
{
    int first_err = 0;
    for (size_t i = 0; i < filled; i++) {
        if (!capsule_entry_past_retention(i, keep_latest, max_age_seconds,
                                          now_unix, entries[i].crash_unix))
            continue;

        int rc = postmortem_remove_tree(entries[i].path);
        if (rc == 0) {
            (*pruned_out)++;
        } else if (first_err == 0) {
            first_err = rc;
        }
    }
    return first_err;
}

int postmortem_capsule_prune(const char *dir,
                             int64_t now_unix,
                             int64_t max_age_seconds,
                             size_t keep_latest,
                             size_t *pruned_out)
{
    if (!dir || !*dir || !pruned_out) return -EINVAL;
    *pruned_out = 0;

    size_t total = 0;
    int rc = postmortem_capsule_list(dir, NULL, 0, &total);
    if (rc != 0 || total == 0) return rc;

    struct postmortem_capsule_entry *entries =
        zcl_malloc(sizeof(entries[0]) * total, "postmortem.prune.entries");
    if (!entries) return -ENOMEM;

    size_t listed = 0;
    rc = postmortem_capsule_list(dir, entries, total, &listed);
    if (rc != 0) {
        free(entries);
        return rc;
    }

    size_t filled = listed < total ? listed : total;
    int first_err = prune_past_retention(entries, filled, keep_latest,
                                         max_age_seconds, now_unix,
                                         pruned_out);
    free(entries);
    return first_err;
}
#endif /* !defined(_WIN32) */
