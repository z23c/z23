/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_CLIP_PLAYER_H
#define ZAPP_CLIP_PLAYER_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* Byte source behind the media extractor: the clip file now, the node's ranged media route later.
 * read_at follows the AMediaDataSource contract. */
struct zapp_clip_source {
    int fd;
    int64_t size;
    ssize_t (*pread_fn)(int fd, void *buffer, size_t size, off_t offset);
    void *trace_user;
    void (*trace)(void *user, int64_t offset, size_t size, ssize_t result);
};

bool zapp_clip_source_open(struct zapp_clip_source *source, const char *path);
void zapp_clip_source_close(struct zapp_clip_source *source);

/* Reads up to size bytes at offset. A request that crosses the end returns the bytes that exist, a
 * request at or beyond the end or at a negative offset returns -1, an empty request returns 0, and a
 * short read from the file is repeated until the request is filled or the file ends. */
ssize_t zapp_clip_source_read_at(const struct zapp_clip_source *source, int64_t offset, void *buffer, size_t size);

/* Largest box of the clip's aspect that fits the screen, in pixels. */
void zapp_clip_fit(int screen_width, int screen_height, int clip_width, int clip_height, int *width, int *height);

#ifdef __ANDROID__
#include <android/native_window.h>

struct zapp_clip_player;

/* Starts playing the clip dir/<id>.mp4 onto window. The file is opened once, hashed through that
 * descriptor and refused when its bytes differ from its name, then played from that same descriptor.
 * zapp_clip_player_error then holds the reason. */
struct zapp_clip_player *zapp_clip_player_open(const char *dir, const char *id, ANativeWindow *window);

void zapp_clip_player_set_paused(struct zapp_clip_player *player, bool paused);
bool zapp_clip_player_paused(const struct zapp_clip_player *player);

/* True once playback reached the end of the clip or failed. */
bool zapp_clip_player_finished(const struct zapp_clip_player *player);

/* Copies the reason playback was refused or failed into out; false while there is none. */
bool zapp_clip_player_error(const struct zapp_clip_player *player, char *out, size_t cap);

/* Stops playback, logs dropped frames and drift, and frees the player. */
void zapp_clip_player_close(struct zapp_clip_player *player);
#endif
#endif
