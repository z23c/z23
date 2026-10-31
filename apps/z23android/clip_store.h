/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_CLIP_STORE_H
#define ZAPP_CLIP_STORE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* A clip is files/clips/<id>.mp4 plus <id>.json, where id is the lowercase hex SHA3-512 of the mp4
 * bytes. The functions take the clips directory itself. */
#define ZAPP_CLIP_ID_LEN 128
#define ZAPP_CLIP_ID_CAP (ZAPP_CLIP_ID_LEN + 1)
#define ZAPP_CLIP_CAPTION_CAP 281 /* 280 UTF-8 bytes and the terminator */
#define ZAPP_CLIP_LEVEL_MAX 5
#define ZAPP_CLIP_DESCRIPTOR_MASK 0x7fu
#define ZAPP_CLIP_LIST_MAX 64

struct zapp_clip_meta {
    uint8_t level;       /* 1 General, 2 Mild, 3 Sensitive, 4 Mature, 5 Explicit; 0 is unset and refused */
    uint8_t descriptors; /* bit set: nudity, sexual, violence, language, drugs, self-harm, hate */
    char caption[ZAPP_CLIP_CAPTION_CAP];
    int64_t created_at;  /* seconds since the Unix epoch */
    int64_t duration_ms;
};

struct zapp_clip {
    char id[ZAPP_CLIP_ID_CAP];
    struct zapp_clip_meta meta;
};

/* Whether id is 128 lowercase hexadecimal digits. */
bool zapp_clip_id_valid(const char *id);

/* Writes the SHA3-512 of the whole file behind fd, read from offset 0, as lowercase hex. */
bool zapp_clip_hash_fd(int fd, char id[ZAPP_CLIP_ID_CAP]);

/* Writes the SHA3-512 of the file at path as lowercase hex. */
bool zapp_clip_hash_file(const char *path, char id[ZAPP_CLIP_ID_CAP]);

/* Whether the metadata may be saved: a level 1 to 5, only defined descriptor bits, a caption that
 * fits and a duration above zero. Level 0 is refused. */
bool zapp_clip_meta_valid(const struct zapp_clip_meta *meta);

/* Moves the recording at source (inside dir, same filesystem) to dir/<id>.mp4 and writes the sidecar,
 * both by atomic rename after the mp4 is synced to storage. Nothing is stored when the metadata is
 * invalid or a step fails. */
bool zapp_clip_store_commit(const char *dir, const char *source, const struct zapp_clip_meta *meta,
                            char id[ZAPP_CLIP_ID_CAP], char *error, size_t error_cap);

/* Lists up to max clips, newest first, and returns how many. When more than max clips are stored the
 * newest max are kept; *total (when not NULL) receives the number of stored clips so the caller can
 * say that older ones exist. Entries without a valid sidecar and mp4 pair are skipped. */
size_t zapp_clip_store_list(const char *dir, struct zapp_clip *out, size_t max, size_t *total);

/* Removes mp4 files left without a sidecar by an interrupted save, and leftover temporary sidecars.
 * Call it when the store is opened, never while a save is running. Returns how many files it removed. */
size_t zapp_clip_store_clean(const char *dir);

bool zapp_clip_store_path(const char *dir, const char *id, char *out, size_t cap);

/* Hashes the opened mp4 and fails when its bytes do not match id. The caller plays the same descriptor. */
bool zapp_clip_store_verify(int fd, const char *id, char *error, size_t error_cap);

bool zapp_clip_store_delete(const char *dir, const char *id);
#endif
