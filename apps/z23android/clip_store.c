/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "clip_store.h"
#include "json/json.h"
#include "sha3/sha3.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SIDECAR_MAX 2048u

static bool fail(char *error, size_t cap, const char *message)
{
    if (error != NULL && cap != 0) (void)snprintf(error, cap, "%s", message);
    return false;
}

bool zapp_clip_id_valid(const char *id)
{
    if (id == NULL || strlen(id) != ZAPP_CLIP_ID_LEN) return false;
    for (size_t i = 0; i < ZAPP_CLIP_ID_LEN; ++i)
        if (!((id[i] >= '0' && id[i] <= '9') || (id[i] >= 'a' && id[i] <= 'f'))) return false;
    return true;
}

bool zapp_clip_hash_fd(int fd, char id[ZAPP_CLIP_ID_CAP])
{
    static const char hex[] = "0123456789abcdef";
    struct sha3_512_ctx ctx;
    unsigned char block[16384], digest[SHA3_512_OUTPUT_SIZE];
    sha3_512_init(&ctx);
    off_t at = 0;
    for (;;) {
        ssize_t n = pread(fd, block, sizeof(block), at);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return false;
        if (n == 0) break;
        sha3_512_write(&ctx, block, (size_t)n);
        at += n;
    }
    sha3_512_finalize(&ctx, digest);
    for (size_t i = 0; i < sizeof(digest); ++i) {
        id[2 * i] = hex[digest[i] >> 4];
        id[2 * i + 1] = hex[digest[i] & 15];
    }
    id[ZAPP_CLIP_ID_LEN] = '\0';
    return true;
}

bool zapp_clip_hash_file(const char *path, char id[ZAPP_CLIP_ID_CAP])
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    bool ok = zapp_clip_hash_fd(fd, id);
    return close(fd) == 0 && ok;
}

bool zapp_clip_meta_valid(const struct zapp_clip_meta *meta)
{
    return meta != NULL && meta->level >= 1 && meta->level <= ZAPP_CLIP_LEVEL_MAX &&
        (meta->descriptors & ~ZAPP_CLIP_DESCRIPTOR_MASK) == 0 &&
        memchr(meta->caption, '\0', sizeof(meta->caption)) != NULL &&
        meta->duration_ms > 0 && meta->created_at >= 0;
}

static bool entry_path(const char *dir, const char *id, const char *ext, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s/%s.%s", dir, id, ext);
    return zapp_clip_id_valid(id) && n > 0 && (size_t)n < cap;
}

bool zapp_clip_store_path(const char *dir, const char *id, char *out, size_t cap)
{
    return entry_path(dir, id, "mp4", out, cap);
}

static bool sidecar_json(const struct zapp_clip_meta *meta, char *out, size_t cap)
{
    struct json_value root = {0};
    json_set_object(&root);
    bool ok = json_push_kv_int(&root, "level", meta->level) &&
        json_push_kv_int(&root, "descriptors", meta->descriptors) &&
        json_push_kv_str(&root, "caption", meta->caption) &&
        json_push_kv_int(&root, "created_at", meta->created_at) &&
        json_push_kv_int(&root, "duration_ms", meta->duration_ms);
    size_t n = ok ? json_write(&root, out, cap) : 0;
    json_free(&root);
    return ok && n > 0 && n < cap;
}

/* Writes text to path through a temporary name in the same directory, then renames it into place. */
static bool write_atomic(const char *path, const char *text)
{
    char temp[1100];
    int n = snprintf(temp, sizeof(temp), "%s.tmp", path);
    if (n < 0 || (size_t)n >= sizeof(temp)) return false;
    int fd = open(temp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    size_t length = strlen(text);
    bool ok = write(fd, text, length) == (ssize_t)length && fsync(fd) == 0;
    ok = close(fd) == 0 && ok;
    if (ok) ok = rename(temp, path) == 0;
    if (!ok) (void)unlink(temp);
    return ok;
}

static bool exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static bool sync_file(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    bool ok = fsync(fd) == 0;
    return close(fd) == 0 && ok;
}

bool zapp_clip_store_commit(const char *dir, const char *source, const struct zapp_clip_meta *meta,
                            char id[ZAPP_CLIP_ID_CAP], char *error, size_t error_cap)
{
    char media[1100], sidecar[1100], text[SIDECAR_MAX];
    if (!zapp_clip_meta_valid(meta))
        return fail(error, error_cap, "Choose a content level before saving.");
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) return fail(error, error_cap, "Could not create the clips folder.");
    if (!zapp_clip_hash_file(source, id)) return fail(error, error_cap, "Could not read the recording.");
    if (!entry_path(dir, id, "mp4", media, sizeof(media)) || !entry_path(dir, id, "json", sidecar, sizeof(sidecar)) ||
        !sidecar_json(meta, text, sizeof(text)))
        return fail(error, error_cap, "Could not describe the clip.");
    if (!sync_file(source)) return fail(error, error_cap, "Could not write the recording to storage.");
    bool created = !exists(media);
    if (rename(source, media) != 0) return fail(error, error_cap, "Could not store the recording.");
    if (!write_atomic(sidecar, text)) {
        if (created) (void)rename(media, source);
        return fail(error, error_cap, "Could not store the clip details.");
    }
    return true;
}

static bool read_text(const char *path, char *out, size_t cap)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL) return false;
    size_t n = fread(out, 1, cap - 1, file);
    bool ok = !ferror(file) && feof(file);
    ok = fclose(file) == 0 && ok;
    out[ok ? n : 0] = '\0';
    return ok;
}

static bool parse_meta(const char *text, struct zapp_clip_meta *meta)
{
    struct json_value root = {0};
    if (!json_read(&root, text, strlen(text))) return false;
    const char *words = json_get_str(json_get(&root, "caption"));
    memset(meta, 0, sizeof(*meta));
    meta->level = (uint8_t)json_get_int(json_get(&root, "level"));
    meta->descriptors = (uint8_t)json_get_int(json_get(&root, "descriptors"));
    meta->created_at = json_get_int(json_get(&root, "created_at"));
    meta->duration_ms = json_get_int(json_get(&root, "duration_ms"));
    bool ok = root.type == JSON_OBJ && words != NULL && strlen(words) < sizeof(meta->caption) &&
        json_get_int(json_get(&root, "level")) == meta->level &&
        json_get_int(json_get(&root, "descriptors")) == meta->descriptors;
    if (ok) memcpy(meta->caption, words, strlen(words) + 1);
    json_free(&root);
    return ok && zapp_clip_meta_valid(meta);
}

static bool load_clip(const char *dir, const char *name, struct zapp_clip *clip)
{
    char id[ZAPP_CLIP_ID_CAP], media[1100], sidecar[1100], text[SIDECAR_MAX];
    size_t length = strlen(name);
    if (length != ZAPP_CLIP_ID_LEN + 5 || strcmp(name + ZAPP_CLIP_ID_LEN, ".json") != 0) return false;
    memcpy(id, name, ZAPP_CLIP_ID_LEN);
    id[ZAPP_CLIP_ID_LEN] = '\0';
    if (!entry_path(dir, id, "mp4", media, sizeof(media)) || !entry_path(dir, id, "json", sidecar, sizeof(sidecar)) ||
        !exists(media) || !read_text(sidecar, text, sizeof(text)) || !parse_meta(text, &clip->meta))
        return false;
    memcpy(clip->id, id, sizeof(clip->id));
    return true;
}

/* Newest first; equal times order by id so a listing is stable. */
static bool newer(const struct zapp_clip *a, const struct zapp_clip *b)
{
    return a->meta.created_at != b->meta.created_at ? a->meta.created_at > b->meta.created_at :
        strcmp(a->id, b->id) < 0;
}

/* Keeps the newest max entries in out, ordered, by insertion. */
static size_t insert_newest(struct zapp_clip *out, size_t count, size_t max, const struct zapp_clip *clip)
{
    size_t at = count;
    while (at > 0 && newer(clip, &out[at - 1])) --at;
    if (at >= max) return count;
    size_t last = count < max ? count : max - 1;
    for (size_t i = last; i > at; --i) out[i] = out[i - 1];
    out[at] = *clip;
    return count < max ? count + 1 : count;
}

size_t zapp_clip_store_list(const char *dir, struct zapp_clip *out, size_t max, size_t *total)
{
    size_t count = 0, all = 0;
    DIR *handle = max != 0 && out != NULL ? opendir(dir) : NULL;
    struct zapp_clip clip;
    if (handle != NULL) {
        for (const struct dirent *entry; (entry = readdir(handle)) != NULL;) {
            if (!load_clip(dir, entry->d_name, &clip)) continue;
            count = insert_newest(out, count, max, &clip);
            ++all;
        }
        (void)closedir(handle);
    }
    if (total != NULL) *total = all;
    return count;
}

/* Whether name is an <id>.mp4 without its <id>.json or a leftover <id>.json.tmp. */
static bool stale_entry(const char *dir, const char *name)
{
    char id[ZAPP_CLIP_ID_CAP], sidecar[1100];
    if (strlen(name) < ZAPP_CLIP_ID_LEN) return false;
    memcpy(id, name, ZAPP_CLIP_ID_LEN);
    id[ZAPP_CLIP_ID_LEN] = '\0';
    if (!zapp_clip_id_valid(id)) return false;
    if (strcmp(name + ZAPP_CLIP_ID_LEN, ".json.tmp") == 0) return true;
    return strcmp(name + ZAPP_CLIP_ID_LEN, ".mp4") == 0 && entry_path(dir, id, "json", sidecar, sizeof(sidecar)) &&
        !exists(sidecar);
}

size_t zapp_clip_store_clean(const char *dir)
{
    DIR *handle = opendir(dir);
    char path[1100];
    size_t removed = 0;
    if (handle == NULL) return 0;
    for (const struct dirent *entry; (entry = readdir(handle)) != NULL;) {
        if (!stale_entry(dir, entry->d_name)) continue;
        if (snprintf(path, sizeof(path), "%s/%s", dir, entry->d_name) < (int)sizeof(path) && unlink(path) == 0) ++removed;
    }
    (void)closedir(handle);
    return removed;
}

bool zapp_clip_store_verify(int fd, const char *id, char *error, size_t error_cap)
{
    char actual[ZAPP_CLIP_ID_CAP];
    if (!zapp_clip_id_valid(id)) return fail(error, error_cap, "Not a clip name.");
    if (!zapp_clip_hash_fd(fd, actual)) return fail(error, error_cap, "The clip cannot be read.");
    if (strcmp(actual, id) != 0) return fail(error, error_cap, "This clip changed after it was saved and will not play.");
    return true;
}

bool zapp_clip_store_delete(const char *dir, const char *id)
{
    char media[1100], sidecar[1100];
    if (!entry_path(dir, id, "mp4", media, sizeof(media)) || !entry_path(dir, id, "json", sidecar, sizeof(sidecar)))
        return false;
    bool sidecar_gone = unlink(sidecar) == 0 || errno == ENOENT;
    bool media_gone = unlink(media) == 0 || errno == ENOENT;
    return sidecar_gone && media_gone;
}
