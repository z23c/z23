/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pure, bounded codec for a watcher ownership claim.  This module performs
 * no I/O; callers must obtain identities from retained operating-system
 * handles before constructing a binding. */
#ifndef ZCL_PLATFORM_WATCHER_RECORD_H
#define ZCL_PLATFORM_WATCHER_RECORD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PLATFORM_WATCHER_RECORD_VERSION 1u
#define PLATFORM_WATCHER_RECORD_NONCE_HEX 64u
#define PLATFORM_WATCHER_RECORD_HASH_HEX 64u
#define PLATFORM_WATCHER_RECORD_PATH_MAX 4096u
#define PLATFORM_WATCHER_RECORD_ENCODED_MAX 9216u

enum platform_watcher_mode {
    PLATFORM_WATCHER_MODE_VERIFY = 1,
    PLATFORM_WATCHER_MODE_AUTO = 2
};

enum platform_watcher_state {
    PLATFORM_WATCHER_STATE_STARTING = 1,
    PLATFORM_WATCHER_STATE_READY = 2,
    PLATFORM_WATCHER_STATE_STOPPING = 3
};

struct platform_watcher_file_identity {
    uint64_t volume;
    uint64_t file_low;
    uint64_t file_high;
};

struct platform_watcher_record {
    uint32_t version;
    char nonce[PLATFORM_WATCHER_RECORD_NONCE_HEX + 1u];
    uint64_t pid;
    uint64_t start_token;
    enum platform_watcher_mode mode;
    char canonical_root[PLATFORM_WATCHER_RECORD_PATH_MAX];
    struct platform_watcher_file_identity root_identity;
    char canonical_image[PLATFORM_WATCHER_RECORD_PATH_MAX];
    struct platform_watcher_file_identity image_identity;
    uint64_t image_size;
    char image_sha256[PLATFORM_WATCHER_RECORD_HASH_HEX + 1u];
    enum platform_watcher_state state;
};

/* Every member is security-significant.  Validation succeeds only when the
 * decoded record is canonical and exactly equals this independently observed
 * binding. */
struct platform_watcher_record_binding {
    char nonce[PLATFORM_WATCHER_RECORD_NONCE_HEX + 1u];
    uint64_t pid;
    uint64_t start_token;
    enum platform_watcher_mode mode;
    char canonical_root[PLATFORM_WATCHER_RECORD_PATH_MAX];
    struct platform_watcher_file_identity root_identity;
    char canonical_image[PLATFORM_WATCHER_RECORD_PATH_MAX];
    struct platform_watcher_file_identity image_identity;
    uint64_t image_size;
    char image_sha256[PLATFORM_WATCHER_RECORD_HASH_HEX + 1u];
    enum platform_watcher_state state;
};

bool platform_watcher_record_is_valid(const struct platform_watcher_record *record);
bool platform_watcher_record_serialize(const struct platform_watcher_record *record,
                                       char *out, size_t out_size,
                                       size_t *written);
bool platform_watcher_record_parse(const char *encoded, size_t encoded_size,
                                   struct platform_watcher_record *out);
bool platform_watcher_record_matches(
    const struct platform_watcher_record *record,
    const struct platform_watcher_record_binding *binding);

#endif
