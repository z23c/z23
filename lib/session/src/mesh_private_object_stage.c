/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Durable private-object ciphertext staging and resume validation. */

#include "session/mesh_private_object_stage.h"

#include "base/cleanse.h"
#include "base/hex.h"
#include "base/serialize_le.h"
#include "platform/directory_transaction.h"
#include "session/mesh_private_object_crypto.h"
#include "session/mesh_private_object_root.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STAGE_SUBSYS "mesh_private_object_stage"
#define STAGE_HEADER_BYTES 176u
#define STAGE_BITMAP_MAX_BYTES 2049u

static const uint8_t stage_magic[8] = {'Z','2','3','M','P','S','0','1'};

struct mesh_private_object_stage {
    struct platform_directory_transaction directory;
    struct platform_directory_child data;
    struct platform_directory_child journal;
    struct platform_directory_lock lock;
    struct mesh_private_object_offer_v1 offer;
    uint8_t target_secret[32];
    uint8_t transfer_id[32];
    uint8_t key_context[32];
    uint8_t bitmap[STAGE_BITMAP_MAX_BYTES];
    uint32_t bitmap_bytes;
    uint32_t done;
    bool cancelled;
    struct mesh_private_object_cancel_v1 cancel;
};

_Static_assert(
    ((MESH_PRIVATE_OBJECT_MAX_OBJECT_BYTES +
       MESH_PRIVATE_OBJECT_CHUNK_PLAINTEXT_BYTES - 1u) /
      MESH_PRIVATE_OBJECT_CHUNK_PLAINTEXT_BYTES + 7u) / 8u <=
        STAGE_BITMAP_MAX_BYTES,
    "private-object stage bitmap must cover the protocol maximum");

const char *mesh_private_object_stage_error_string(
    enum mesh_private_object_stage_error error)
{
    switch (error) {
    case MESH_PRIVATE_OBJECT_STAGE_OK: return "ok";
    case MESH_PRIVATE_OBJECT_STAGE_NULL: return "null";
    case MESH_PRIVATE_OBJECT_STAGE_OFFER: return "offer";
    case MESH_PRIVATE_OBJECT_STAGE_MEMORY: return "memory";
    case MESH_PRIVATE_OBJECT_STAGE_BUSY: return "busy";
    case MESH_PRIVATE_OBJECT_STAGE_IO: return "io";
    case MESH_PRIVATE_OBJECT_STAGE_IDENTITY: return "identity";
    case MESH_PRIVATE_OBJECT_STAGE_CORRUPT: return "corrupt";
    case MESH_PRIVATE_OBJECT_STAGE_INDEX: return "index";
    case MESH_PRIVATE_OBJECT_STAGE_SIZE: return "size";
    case MESH_PRIVATE_OBJECT_STAGE_AUTH: return "auth";
    case MESH_PRIVATE_OBJECT_STAGE_INCOMPLETE: return "incomplete";
    case MESH_PRIVATE_OBJECT_STAGE_ROOT: return "root";
    case MESH_PRIVATE_OBJECT_STAGE_CANCELLED: return "cancelled";
    }
    return "unknown";
}

static void stage_leaf(char out[80], const uint8_t id[32], const char *suffix)
{
    memcpy(out, "mpos-", 5);
    zcl_hex_encode(id, 32, out + 5);
    (void)snprintf(out + 69, 11, ".%s", suffix);
}

static void stage_header_encode(const struct mesh_private_object_stage *stage,
                                uint8_t out[STAGE_HEADER_BYTES])
{
    memset(out, 0, STAGE_HEADER_BYTES);
    memcpy(out, stage_magic, sizeof(stage_magic));
    zcl_write_u32_le(out + 8, 1);
    zcl_write_u32_le(out + 12, STAGE_HEADER_BYTES);
    memcpy(out + 16, stage->transfer_id, 32);
    memcpy(out + 48, stage->key_context, 32);
    memcpy(out + 80, stage->offer.plaintext_root, 32);
    memcpy(out + 112, stage->offer.ciphertext_root, 32);
    zcl_write_u64_le(out + 144, stage->offer.object_size_bytes);
    zcl_write_u64_le(out + 152, stage->offer.ciphertext_size_bytes);
    zcl_write_u32_le(out + 160, stage->offer.chunk_count);
    zcl_write_u32_le(out + 164, stage->offer.chunk_size);
    zcl_write_u32_le(out + 168, stage->bitmap_bytes);
}

static bool stage_header_matches(const struct mesh_private_object_stage *stage,
                                 const uint8_t in[STAGE_HEADER_BYTES])
{
    uint8_t expected[STAGE_HEADER_BYTES];
    stage_header_encode(stage, expected);
    bool matches = memcmp(in, expected, sizeof(expected)) == 0;
    memory_cleanse(expected, sizeof(expected));
    return matches;
}

static uint32_t stage_count_bits(const uint8_t *bitmap, uint32_t bytes)
{
    uint32_t count = 0;
    for (uint32_t i = 0; i < bytes; i++) {
        uint8_t value = bitmap[i];
        while (value) {
            count += value & 1u;
            value >>= 1;
        }
    }
    return count;
}

static bool stage_stray_bits(const struct mesh_private_object_stage *stage)
{
    uint32_t tail = stage->offer.chunk_count & 7u;
    if (tail == 0) return false;
    uint8_t allowed = (uint8_t)((1u << tail) - 1u);
    return (stage->bitmap[stage->bitmap_bytes - 1u] &
            (uint8_t)~allowed) != 0;
}

static uint64_t stage_chunk_offset(uint32_t index)
{
    return (uint64_t)index * MESH_PRIVATE_OBJECT_CHUNK_BYTES;
}

static uint64_t stage_journal_base_size(
    const struct mesh_private_object_stage *stage)
{
    return STAGE_HEADER_BYTES + (uint64_t)stage->bitmap_bytes;
}

static enum mesh_private_object_stage_error stage_read_cancel(
    struct mesh_private_object_stage *stage, uint64_t journal_size)
{
    uint64_t base = stage_journal_base_size(stage);
    if (journal_size == base)
        return MESH_PRIVATE_OBJECT_STAGE_OK;
    if (journal_size != base + MESH_PRIVATE_OBJECT_FRAME_CANCEL_BYTES) {
        LOG_ERROR(STAGE_SUBSYS, "resume journal has a torn cancel record");
        return MESH_PRIVATE_OBJECT_STAGE_CORRUPT;
    }
    uint8_t wire[MESH_PRIVATE_OBJECT_FRAME_CANCEL_BYTES];
    struct mesh_private_object_frame_view_v1 view;
    if (!platform_directory_child_read_exact(
            &stage->journal, wire, sizeof(wire), base) ||
        mesh_private_object_frame_v1_decode(&view, wire, sizeof(wire)) !=
            MESH_PRIVATE_OBJECT_FRAME_OK ||
        view.kind != MESH_PRIVATE_OBJECT_FRAME_CANCEL ||
        memcmp(view.body.cancel.transfer_id, stage->transfer_id, 32) != 0) {
        memory_cleanse(wire, sizeof(wire));
        LOG_ERROR(STAGE_SUBSYS, "resume journal cancel record is invalid");
        return MESH_PRIVATE_OBJECT_STAGE_CORRUPT;
    }
    stage->cancel = view.body.cancel;
    stage->cancelled = true;
    memory_cleanse(wire, sizeof(wire));
    return MESH_PRIVATE_OBJECT_STAGE_OK;
}

static enum mesh_private_object_stage_error stage_authenticate(
    const struct mesh_private_object_stage *stage, uint32_t index,
    const uint8_t *sealed, size_t sealed_len)
{
    uint8_t plaintext[MESH_PRIVATE_OBJECT_CHUNK_PLAINTEXT_BYTES];
    size_t plaintext_len = 0;
    enum mesh_private_object_chunk_error error =
        mesh_private_object_chunk_open_v1(
            &stage->offer, stage->target_secret, index, sealed, sealed_len,
            plaintext, sizeof(plaintext), &plaintext_len);
    memory_cleanse(plaintext, sizeof(plaintext));
    if (error == MESH_PRIVATE_OBJECT_CHUNK_AUTH ||
        error == MESH_PRIVATE_OBJECT_CHUNK_KEY_MISMATCH)
        return MESH_PRIVATE_OBJECT_STAGE_AUTH;
    if (error == MESH_PRIVATE_OBJECT_CHUNK_INDEX)
        return MESH_PRIVATE_OBJECT_STAGE_INDEX;
    if (error == MESH_PRIVATE_OBJECT_CHUNK_SIZE)
        return MESH_PRIVATE_OBJECT_STAGE_SIZE;
    return error == MESH_PRIVATE_OBJECT_CHUNK_OK
        ? MESH_PRIVATE_OBJECT_STAGE_OK : MESH_PRIVATE_OBJECT_STAGE_OFFER;
}

static enum mesh_private_object_stage_error stage_verify_recorded(
    struct mesh_private_object_stage *stage)
{
    uint8_t sealed[MESH_PRIVATE_OBJECT_CHUNK_BYTES];
    for (uint32_t i = 0; i < stage->offer.chunk_count; i++) {
        if (!mesh_private_object_stage_has_v1(stage, i)) continue;
        uint32_t plain_len = 0, sealed_len = 0;
        if (mesh_private_object_chunk_shape_v1(
                &stage->offer, i, &plain_len, &sealed_len) !=
                MESH_PRIVATE_OBJECT_CHUNK_OK ||
            !platform_directory_child_read_exact(
                &stage->data, sealed, sealed_len, stage_chunk_offset(i)) ||
            stage_authenticate(stage, i, sealed, sealed_len) !=
                MESH_PRIVATE_OBJECT_STAGE_OK) {
            memory_cleanse(sealed, sizeof(sealed));
            LOG_ERROR(STAGE_SUBSYS,
                      "reopen refused unauthenticated recorded chunk %u", i);
            return MESH_PRIVATE_OBJECT_STAGE_CORRUPT;
        }
    }
    memory_cleanse(sealed, sizeof(sealed));
    return MESH_PRIVATE_OBJECT_STAGE_OK;
}

static enum mesh_private_object_stage_error stage_fresh_files(
    struct mesh_private_object_stage *stage, const char *data_leaf,
    const char *journal_leaf, bool data_exists)
{
    if (data_exists) {
        if (!platform_directory_child_open(
                &stage->directory, data_leaf, &stage->data))
            return MESH_PRIVATE_OBJECT_STAGE_IO;
    } else if (!platform_directory_child_create(
                   &stage->directory, data_leaf, &stage->data)) {
        return MESH_PRIVATE_OBJECT_STAGE_IO;
    }
    if (!platform_directory_child_truncate(
            &stage->data, stage->offer.ciphertext_size_bytes) ||
        !platform_directory_child_flush(&stage->data))
        return MESH_PRIVATE_OBJECT_STAGE_IO;
    if (!platform_directory_child_create(
            &stage->directory, journal_leaf, &stage->journal))
        return MESH_PRIVATE_OBJECT_STAGE_IO;
    uint8_t header[STAGE_HEADER_BYTES];
    stage_header_encode(stage, header);
    bool ok = platform_directory_child_write_exact(
                  &stage->journal, header, sizeof(header), 0) &&
              platform_directory_child_write_exact(
                  &stage->journal, stage->bitmap, stage->bitmap_bytes,
                  STAGE_HEADER_BYTES) &&
              platform_directory_child_truncate(
                  &stage->journal,
                  STAGE_HEADER_BYTES + stage->bitmap_bytes) &&
              platform_directory_child_flush(&stage->journal);
    memory_cleanse(header, sizeof(header));
    return ok ? MESH_PRIVATE_OBJECT_STAGE_OK : MESH_PRIVATE_OBJECT_STAGE_IO;
}

static enum mesh_private_object_stage_error stage_open_files(
    struct mesh_private_object_stage *stage, const char *data_leaf,
    const char *journal_leaf)
{
    bool journal_created = false;
    enum platform_directory_result jr = platform_directory_child_open_result(
        &stage->directory, journal_leaf, false, false, &stage->journal,
        &journal_created);
    (void)journal_created;
    if (jr == PLATFORM_DIRECTORY_MISSING) {
        struct platform_directory_child probe;
        platform_directory_child_init(&probe);
        bool data_exists = platform_directory_child_open(
            &stage->directory, data_leaf, &probe);
        platform_directory_child_close(&probe);
        return stage_fresh_files(
            stage, data_leaf, journal_leaf, data_exists);
    }
    if (jr != PLATFORM_DIRECTORY_OK)
        return MESH_PRIVATE_OBJECT_STAGE_IO;
    if (!platform_directory_child_open(
            &stage->directory, data_leaf, &stage->data))
        return MESH_PRIVATE_OBJECT_STAGE_CORRUPT;
    struct platform_directory_child_info ji, di;
    uint8_t header[STAGE_HEADER_BYTES];
    bool readable = platform_directory_child_info(&stage->journal, &ji) &&
        platform_directory_child_info(&stage->data, &di) &&
        (ji.size == stage_journal_base_size(stage) ||
         ji.size == stage_journal_base_size(stage) +
                        MESH_PRIVATE_OBJECT_FRAME_CANCEL_BYTES) &&
        di.size == stage->offer.ciphertext_size_bytes &&
        platform_directory_child_read_exact(
            &stage->journal, header, sizeof(header), 0);
    if (!readable) {
        LOG_ERROR(STAGE_SUBSYS, "resume files have non-canonical sizes");
        return MESH_PRIVATE_OBJECT_STAGE_CORRUPT;
    }
    if (!stage_header_matches(stage, header)) {
        memory_cleanse(header, sizeof(header));
        LOG_ERROR(STAGE_SUBSYS, "resume journal identity does not match offer");
        return MESH_PRIVATE_OBJECT_STAGE_IDENTITY;
    }
    memory_cleanse(header, sizeof(header));
    if (!platform_directory_child_read_exact(
            &stage->journal, stage->bitmap, stage->bitmap_bytes,
            STAGE_HEADER_BYTES) || stage_stray_bits(stage)) {
        LOG_ERROR(STAGE_SUBSYS, "resume journal bitmap is malformed");
        return MESH_PRIVATE_OBJECT_STAGE_CORRUPT;
    }
    stage->done = stage_count_bits(stage->bitmap, stage->bitmap_bytes);
    enum mesh_private_object_stage_error cancel_error =
        stage_read_cancel(stage, ji.size);
    return cancel_error == MESH_PRIVATE_OBJECT_STAGE_OK
        ? stage_verify_recorded(stage) : cancel_error;
}

enum mesh_private_object_stage_error mesh_private_object_stage_open_v1(
    struct mesh_private_object_stage **out, const char *private_root,
    const struct mesh_private_object_offer_v1 *offer,
    const uint8_t target_noise_static_secret[32])
{
    if (!out || !private_root || !offer || !target_noise_static_secret)
        return MESH_PRIVATE_OBJECT_STAGE_NULL;
    *out = NULL;
    uint8_t transfer_id[32], key_context[32];
    if (mesh_private_object_offer_v1_validate(offer) !=
            MESH_PRIVATE_OBJECT_PROTO_OK ||
        mesh_private_object_offer_transfer_id_v1(offer, transfer_id) !=
            MESH_PRIVATE_OBJECT_PROTO_OK ||
        mesh_private_object_offer_key_context_v1(offer, key_context) !=
            MESH_PRIVATE_OBJECT_PROTO_OK)
        return MESH_PRIVATE_OBJECT_STAGE_OFFER;
    struct mesh_private_object_stage *stage =
        zcl_calloc(1, sizeof(*stage), "mesh_private_object_stage");
    if (!stage) {
        memory_cleanse(transfer_id, sizeof(transfer_id));
        memory_cleanse(key_context, sizeof(key_context));
        return MESH_PRIVATE_OBJECT_STAGE_MEMORY;
    }
    platform_directory_transaction_init(&stage->directory);
    platform_directory_child_init(&stage->data);
    platform_directory_child_init(&stage->journal);
    platform_directory_lock_init(&stage->lock);
    stage->offer = *offer;
    memcpy(stage->target_secret, target_noise_static_secret, 32);
    memcpy(stage->transfer_id, transfer_id, 32);
    memcpy(stage->key_context, key_context, 32);
    stage->bitmap_bytes = (offer->chunk_count + 7u) / 8u;
    memory_cleanse(transfer_id, sizeof(transfer_id));
    memory_cleanse(key_context, sizeof(key_context));
    if (stage->bitmap_bytes == 0 ||
        stage->bitmap_bytes > STAGE_BITMAP_MAX_BYTES ||
        !platform_directory_transaction_open(
            &stage->directory, private_root)) {
        mesh_private_object_stage_close(stage);
        return MESH_PRIVATE_OBJECT_STAGE_IO;
    }
    char data_leaf[80], journal_leaf[80], lock_leaf[80];
    stage_leaf(data_leaf, stage->transfer_id, "data");
    stage_leaf(journal_leaf, stage->transfer_id, "journal");
    stage_leaf(lock_leaf, stage->transfer_id, "lock");
    enum platform_directory_result locked = platform_directory_lock_acquire(
        &stage->directory, lock_leaf, true,
        PLATFORM_DIRECTORY_LOCK_EXCLUSIVE, &stage->lock);
    if (locked != PLATFORM_DIRECTORY_OK) {
        mesh_private_object_stage_close(stage);
        return locked == PLATFORM_DIRECTORY_REFUSED
            ? MESH_PRIVATE_OBJECT_STAGE_BUSY : MESH_PRIVATE_OBJECT_STAGE_IO;
    }
    enum mesh_private_object_stage_error error =
        stage_open_files(stage, data_leaf, journal_leaf);
    if (error != MESH_PRIVATE_OBJECT_STAGE_OK) {
        mesh_private_object_stage_close(stage);
        return error;
    }
    *out = stage;
    return MESH_PRIVATE_OBJECT_STAGE_OK;
}

void mesh_private_object_stage_close(struct mesh_private_object_stage *stage)
{
    if (!stage) return;
    platform_directory_child_close(&stage->journal);
    platform_directory_child_close(&stage->data);
    platform_directory_lock_release(&stage->lock);
    platform_directory_transaction_close(&stage->directory);
    memory_cleanse(stage, sizeof(*stage));
    free(stage);
}

bool mesh_private_object_stage_has_v1(
    const struct mesh_private_object_stage *stage, uint32_t chunk_index)
{
    return stage && chunk_index < stage->offer.chunk_count &&
        (stage->bitmap[chunk_index >> 3] &
         (uint8_t)(1u << (chunk_index & 7u))) != 0;
}

uint32_t mesh_private_object_stage_count_v1(
    const struct mesh_private_object_stage *stage)
{
    return stage ? stage->done : 0;
}

enum mesh_private_object_stage_error mesh_private_object_stage_put_v1(
    struct mesh_private_object_stage *stage, uint32_t chunk_index,
    const uint8_t *sealed, size_t sealed_len)
{
    if (!stage || !sealed) return MESH_PRIVATE_OBJECT_STAGE_NULL;
    if (stage->cancelled) return MESH_PRIVATE_OBJECT_STAGE_CANCELLED;
    if (chunk_index >= stage->offer.chunk_count)
        return MESH_PRIVATE_OBJECT_STAGE_INDEX;
    uint32_t plain_expected = 0, sealed_expected = 0;
    if (mesh_private_object_chunk_shape_v1(
            &stage->offer, chunk_index, &plain_expected, &sealed_expected) !=
            MESH_PRIVATE_OBJECT_CHUNK_OK)
        return MESH_PRIVATE_OBJECT_STAGE_OFFER;
    (void)plain_expected;
    if (sealed_len != sealed_expected)
        return MESH_PRIVATE_OBJECT_STAGE_SIZE;
    enum mesh_private_object_stage_error error =
        stage_authenticate(stage, chunk_index, sealed, sealed_len);
    if (error != MESH_PRIVATE_OBJECT_STAGE_OK) return error;
    if (mesh_private_object_stage_has_v1(stage, chunk_index)) {
        uint8_t existing[MESH_PRIVATE_OBJECT_CHUNK_BYTES];
        bool exact = platform_directory_child_read_exact(
            &stage->data, existing, sealed_len,
            stage_chunk_offset(chunk_index)) &&
            memcmp(existing, sealed, sealed_len) == 0;
        memory_cleanse(existing, sizeof(existing));
        return exact ? MESH_PRIVATE_OBJECT_STAGE_OK
                     : MESH_PRIVATE_OBJECT_STAGE_CORRUPT;
    }
    if (!platform_directory_child_write_exact(
            &stage->data, sealed, sealed_len, stage_chunk_offset(chunk_index)) ||
        !platform_directory_child_flush(&stage->data)) {
        LOG_ERROR(STAGE_SUBSYS, "failed to durably stage chunk %u", chunk_index);
        return MESH_PRIVATE_OBJECT_STAGE_IO;
    }
    uint32_t byte = chunk_index >> 3;
    uint8_t bit = (uint8_t)(1u << (chunk_index & 7u));
    stage->bitmap[byte] |= bit;
    if (!platform_directory_child_write_exact(
            &stage->journal, &stage->bitmap[byte], 1,
            STAGE_HEADER_BYTES + byte) ||
        !platform_directory_child_flush(&stage->journal)) {
        stage->bitmap[byte] &= (uint8_t)~bit;
        LOG_ERROR(STAGE_SUBSYS, "failed to durably record chunk %u", chunk_index);
        return MESH_PRIVATE_OBJECT_STAGE_IO;
    }
    stage->done++;
    return MESH_PRIVATE_OBJECT_STAGE_OK;
}

bool mesh_private_object_stage_cancelled_v1(
    const struct mesh_private_object_stage *stage,
    struct mesh_private_object_cancel_v1 *cancel_out)
{
    if (!stage || !stage->cancelled) return false;
    if (cancel_out) *cancel_out = stage->cancel;
    return true;
}

enum mesh_private_object_stage_error mesh_private_object_stage_cancel_v1(
    struct mesh_private_object_stage *stage,
    const struct mesh_private_object_cancel_v1 *cancel)
{
    if (!stage || !cancel) return MESH_PRIVATE_OBJECT_STAGE_NULL;
    if (stage->cancelled) {
        return memcmp(stage->cancel.transfer_id, cancel->transfer_id, 32) == 0 &&
                       memcmp(stage->cancel.offer_request_id,
                              cancel->offer_request_id, 32) == 0 &&
                       stage->cancel.cancel_id == cancel->cancel_id
                   ? MESH_PRIVATE_OBJECT_STAGE_OK
                   : MESH_PRIVATE_OBJECT_STAGE_CANCELLED;
    }
    if (memcmp(cancel->transfer_id, stage->transfer_id, 32) != 0)
        return MESH_PRIVATE_OBJECT_STAGE_IDENTITY;
    uint8_t wire[MESH_PRIVATE_OBJECT_FRAME_CANCEL_BYTES];
    size_t wire_len = 0;
    if (mesh_private_object_frame_cancel_v1_encode(
            cancel, wire, sizeof(wire), &wire_len) !=
            MESH_PRIVATE_OBJECT_FRAME_OK || wire_len != sizeof(wire)) {
        memory_cleanse(wire, sizeof(wire));
        return MESH_PRIVATE_OBJECT_STAGE_OFFER;
    }
    stage->cancelled = true;
    stage->cancel = *cancel;
    uint64_t base = stage_journal_base_size(stage);
    bool stored = platform_directory_child_write_exact(
                      &stage->journal, wire, sizeof(wire), base) &&
                  platform_directory_child_truncate(
                      &stage->journal, base + sizeof(wire)) &&
                  platform_directory_child_flush(&stage->journal);
    memory_cleanse(wire, sizeof(wire));
    return stored ? MESH_PRIVATE_OBJECT_STAGE_OK
                  : MESH_PRIVATE_OBJECT_STAGE_IO;
}

enum mesh_private_object_stage_error mesh_private_object_stage_verify_v1(
    struct mesh_private_object_stage *stage)
{
    if (!stage) return MESH_PRIVATE_OBJECT_STAGE_NULL;
    if (stage->cancelled) return MESH_PRIVATE_OBJECT_STAGE_CANCELLED;
    if (stage->done != stage->offer.chunk_count)
        return MESH_PRIVATE_OBJECT_STAGE_INCOMPLETE;
    struct mesh_private_object_root_v1 root;
    if (mesh_private_object_root_v1_init(
            &root, MESH_PRIVATE_OBJECT_ROOT_CIPHERTEXT,
            stage->offer.object_size_bytes,
            stage->offer.ciphertext_size_bytes, stage->offer.chunk_count) !=
        MESH_PRIVATE_OBJECT_ROOT_OK)
        return MESH_PRIVATE_OBJECT_STAGE_OFFER;
    uint8_t sealed[MESH_PRIVATE_OBJECT_CHUNK_BYTES];
    for (uint32_t i = 0; i < stage->offer.chunk_count; i++) {
        uint32_t plain_len = 0, sealed_len = 0;
        if (mesh_private_object_chunk_shape_v1(
                &stage->offer, i, &plain_len, &sealed_len) !=
                MESH_PRIVATE_OBJECT_CHUNK_OK ||
            !platform_directory_child_read_exact(
                &stage->data, sealed, sealed_len, stage_chunk_offset(i)) ||
            mesh_private_object_root_v1_update(
                &root, i, sealed, sealed_len) !=
                MESH_PRIVATE_OBJECT_ROOT_OK) {
            memory_cleanse(sealed, sizeof(sealed));
            return MESH_PRIVATE_OBJECT_STAGE_IO;
        }
    }
    uint8_t actual[32];
    enum mesh_private_object_root_error root_error =
        mesh_private_object_root_v1_finalize(&root, actual);
    memory_cleanse(sealed, sizeof(sealed));
    bool matches = root_error == MESH_PRIVATE_OBJECT_ROOT_OK &&
        memcmp(actual, stage->offer.ciphertext_root, sizeof(actual)) == 0;
    memory_cleanse(actual, sizeof(actual));
    return matches ? MESH_PRIVATE_OBJECT_STAGE_OK
                   : MESH_PRIVATE_OBJECT_STAGE_ROOT;
}
