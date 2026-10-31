/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the Clips formats of spec 2.2 to 2.4: the signed record envelope,
 * the ten body kinds and the ZCLM meta file of a clip package (2.4). Pure: no I/O, no clock,
 * no filesystem. Integers are little-endian, as the codec cursor writes them. */

#ifndef ZCL_CLIPS_CODEC_H
#define ZCL_CLIPS_CODEC_H

#include "clips_rating/clips_rating.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum clips_error {
    CLIPS_OK = 0,
    CLIPS_ERR_ARGUMENT,
    CLIPS_ERR_TRUNCATED,
    CLIPS_ERR_TRAILING,
    CLIPS_ERR_MAGIC,
    CLIPS_ERR_VERSION,
    CLIPS_ERR_ALG,
    CLIPS_ERR_KIND,
    CLIPS_ERR_LANE,
    CLIPS_ERR_BODY_LEN,
    CLIPS_ERR_BODY,
    CLIPS_ERR_FIELD,
    CLIPS_ERR_LEVEL,
    CLIPS_ERR_DESCRIPTOR,
    CLIPS_ERR_RESERVED_FLAGS,
    CLIPS_ERR_TEXT,
    CLIPS_ERR_SIGNATURE,
    CLIPS_ERR_TIME,
    CLIPS_ERR_CHAIN_SEQ,
    CLIPS_ERR_CHAIN_PREV,
    CLIPS_ERR_CHUNK_SIZE,
    CLIPS_ERR_CHUNK_COUNT,
};

enum clips_lane {
    CLIPS_LANE_CONTENT = 0,
    CLIPS_LANE_SOCIAL = 1,
    CLIPS_LANE_RATING = 2,
};

enum clips_kind {
    CLIPS_KIND_POST = 1,
    CLIPS_KIND_PROFILE = 2,
    CLIPS_KIND_TOMBSTONE = 3,
    CLIPS_KIND_LIST = 4,
    CLIPS_KIND_RATING = 5,
    CLIPS_KIND_REACTION = 10,
    CLIPS_KIND_COMMENT = 11,
    CLIPS_KIND_FOLLOW = 12,
    CLIPS_KIND_BLOCK = 13,
    CLIPS_KIND_REPORT = 14,
};

#define CLIPS_HASH_LEN 64
#define CLIPS_RECORD_HEADER_LEN 130
#define CLIPS_RECORD_SIG_LEN 64
#define CLIPS_RECORD_BODY_MAX 1024
#define CLIPS_RECORD_MAX_LEN 1218
#define CLIPS_RECORD_MAX_FUTURE_SECS 600

#define CLIPS_CAPTION_MAX 500
#define CLIPS_TAGS_MAX 8
#define CLIPS_TAG_MAX 32
#define CLIPS_PROFILE_NAME_MAX 48
#define CLIPS_PROFILE_BIO_MAX 160
#define CLIPS_PROFILE_TIP_MAX 128
#define CLIPS_LIST_ENTRIES_MAX 4000
#define CLIPS_LIST_TITLE_MAX 64
#define CLIPS_RATING_NOTE_MAX 120
#define CLIPS_COMMENT_MAX 280
#define CLIPS_REPORT_NOTE_MAX 280

#define CLIPS_CHUNK_SIZE 262144u
#define CLIPS_CHUNK_LOG2 18
#define CLIPS_CHUNK_MAX 96
#define CLIPS_MANIFEST_TOTAL_MAX 25165824u
#define CLIPS_MANIFEST_HEADER_LEN 95

struct clips_record {
    uint8_t kind;
    uint8_t lane;
    uint8_t author[32];
    uint64_t seq;
    uint8_t prev[CLIPS_HASH_LEN];
    int64_t created_at;
    uint64_t stamp;
    uint16_t body_len;
    uint8_t body[CLIPS_RECORD_BODY_MAX];
    uint8_t signature[CLIPS_RECORD_SIG_LEN];
};

/* The previous record of one (author, lane). present = false means none. */
struct clips_chain_tip {
    bool present;
    uint8_t author[32];
    uint8_t lane;
    uint64_t seq;
    uint8_t id[CLIPS_HASH_LEN];
};

struct clips_post {
    uint8_t level;
    uint16_t descriptors;
    bool has_manifest;
    bool has_reply_to;
    bool has_reshare_of;
    uint8_t manifest_id[CLIPS_HASH_LEN];
    uint8_t reply_to[CLIPS_HASH_LEN];
    uint8_t reshare_of[CLIPS_HASH_LEN];
    uint16_t caption_len;
    uint8_t caption[CLIPS_CAPTION_MAX];
    uint8_t tag_count;
    uint8_t tag_len[CLIPS_TAGS_MAX];
    uint8_t tags[CLIPS_TAGS_MAX][CLIPS_TAG_MAX];
};

struct clips_profile {
    uint8_t level;
    uint8_t name_len;
    uint8_t name[CLIPS_PROFILE_NAME_MAX];
    uint8_t bio_len;
    uint8_t bio[CLIPS_PROFILE_BIO_MAX];
    bool has_avatar;
    uint8_t avatar_id[CLIPS_HASH_LEN];
    uint8_t tip_len;
    uint8_t tip[CLIPS_PROFILE_TIP_MAX];
};

struct clips_tombstone {
    uint8_t target[CLIPS_HASH_LEN];
    uint8_t reason;
};

struct clips_list {
    uint8_t list_object_id[CLIPS_HASH_LEN];
    uint32_t entry_count;
    uint8_t title_len;
    uint8_t title[CLIPS_LIST_TITLE_MAX];
    uint8_t list_kind;
};

struct clips_rating_body {
    uint8_t target[CLIPS_HASH_LEN];
    uint8_t level;
    uint16_t descriptors;
    uint8_t method;
    uint8_t note_len;
    uint8_t note[CLIPS_RATING_NOTE_MAX];
};

struct clips_reaction {
    uint8_t target[CLIPS_HASH_LEN];
    uint8_t reaction;
};

struct clips_comment {
    uint8_t target[CLIPS_HASH_LEN];
    uint8_t parent[CLIPS_HASH_LEN];
    uint16_t text_len;
    uint8_t text[CLIPS_COMMENT_MAX];
};

struct clips_follow {
    uint8_t target_author[32];
    uint8_t flags;
};

struct clips_block {
    uint8_t target_type;
    uint8_t target[CLIPS_HASH_LEN];
    uint8_t flags;
};

struct clips_report {
    uint8_t target[CLIPS_HASH_LEN];
    uint8_t reason;
    uint16_t note_len;
    uint8_t note[CLIPS_REPORT_NOTE_MAX];
};

struct clips_body {
    uint8_t kind;
    union {
        struct clips_post post;
        struct clips_profile profile;
        struct clips_tombstone tombstone;
        struct clips_list list;
        struct clips_rating_body rating;
        struct clips_reaction reaction;
        struct clips_comment comment;
        struct clips_follow follow;
        struct clips_block block;
        struct clips_report report;
    } u;
};

/* The ZCLM meta file of a clip package (2.4). The post manifest_id names the
 * package root, not this file. */
struct clips_manifest {
    uint8_t container;
    uint8_t video_codec;
    uint8_t audio_codec;
    uint16_t width;
    uint16_t height;
    uint32_t duration_ms;
    uint16_t bitrate_kbps;
    uint8_t fps;
    uint8_t rotation;
    uint8_t chunk_size_log2;
    uint32_t total_size;
    uint16_t chunk_count;
    uint8_t thumb_id[CLIPS_HASH_LEN];
    uint16_t thumb_width;
    uint16_t thumb_height;
    uint8_t chunk_ids[CLIPS_CHUNK_MAX][CLIPS_HASH_LEN];
};

enum clips_error clips_record_encode(const struct clips_record *rec, uint8_t *out,
                                     size_t cap, size_t *written);
enum clips_error clips_record_decode(const uint8_t *in, size_t len,
                                     struct clips_record *out);
enum clips_error clips_record_id(const struct clips_record *rec, uint8_t id[CLIPS_HASH_LEN]);
enum clips_error clips_record_sign(struct clips_record *rec, const uint8_t seed[32]);
/* Checks the signature over the record id. It does not decode the body:
 * callers must also call clips_record_check_body. */
enum clips_error clips_record_verify(const struct clips_record *rec);
enum clips_error clips_record_check_body(const struct clips_record *rec);
enum clips_error clips_record_time_check(const struct clips_record *rec, int64_t now);
enum clips_error clips_record_fork_check(const struct clips_record *a,
                                         const struct clips_record *b, bool *forked);
enum clips_error clips_chain_check(const struct clips_record *rec,
                                   const struct clips_chain_tip *tip);

enum clips_error clips_body_decode(uint8_t kind, const uint8_t *in, size_t len,
                                   struct clips_body *out);
enum clips_error clips_body_encode(const struct clips_body *in, uint8_t *out,
                                   size_t cap, size_t *written);

enum clips_error clips_manifest_encode(const struct clips_manifest *m, uint8_t *out,
                                       size_t cap, size_t *written);
enum clips_error clips_manifest_decode(const uint8_t *in, size_t len,
                                       struct clips_manifest *out);

#endif /* ZCL_CLIPS_CODEC_H */
