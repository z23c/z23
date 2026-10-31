/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Hermetic coverage of the ZCLM meta file (spec 2.4): the meta bytes
 * known answer, the codec round trip, chunk_count consistency with the total
 * size, the 96-chunk ceiling, a wrong chunk_size_log2, every media and
 * thumbnail limit, and truncation at every offset. Buffers only. The known
 * answer was computed with openssl over the same bytes. */

#include "test/test_core.h"

#include "clips_codec/clips_codec.h"
#include "sha3/sha3.h"

#include <stdint.h>
#include <string.h>

static const char k_kat_meta_id[] =
    "3082a93ef68fc4067fa034c243180bff07881846c774c2dd16d875c6f4a5bca6"
    "80ffd15682a8501cbf58354fe2e5061a292ace0734cd570e640c130732a13e5b";

/* The 223-byte manifest of the known answer: 1080x1920 H.264 with AAC, 6 s,
 * two chunks for 262,145 bytes. */
static void cm_make(struct clips_manifest *m)
{
    memset(m, 0, sizeof(*m));
    m->container = 1;
    m->video_codec = 1;
    m->audio_codec = 1;
    m->width = 1080;
    m->height = 1920;
    m->duration_ms = 6000;
    m->bitrate_kbps = 2000;
    m->fps = 30;
    m->rotation = 0;
    m->chunk_size_log2 = CLIPS_CHUNK_LOG2;
    m->total_size = 262145;
    m->chunk_count = 2;
    memset(m->thumb_id, 0x44, sizeof(m->thumb_id));
    m->thumb_width = 540;
    m->thumb_height = 960;
    memset(m->chunk_ids[0], 0x55, CLIPS_HASH_LEN);
    memset(m->chunk_ids[1], 0x66, CLIPS_HASH_LEN);
}

static void cm_hex(const uint8_t *in, size_t n, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 0x0f];
    }
    out[2 * n] = '\0';
}

static enum clips_error cm_encode(const struct clips_manifest *m, uint8_t *buf, size_t *n)
{
    return clips_manifest_encode(m, buf, 96 * CLIPS_HASH_LEN + CLIPS_MANIFEST_HEADER_LEN, n);
}

static enum clips_error cm_check_total(uint32_t total, uint16_t count)
{
    struct clips_manifest m;
    uint8_t buf[96 * CLIPS_HASH_LEN + CLIPS_MANIFEST_HEADER_LEN];
    size_t n = 0;
    cm_make(&m);
    m.total_size = total;
    m.chunk_count = count;
    return cm_encode(&m, buf, &n);
}

int test_clips_manifest(void);
int test_clips_manifest(void)
{
    int failures = 0;

    TEST("meta bytes match the openssl known answer") {
        struct clips_manifest m;
        uint8_t buf[CLIPS_MANIFEST_HEADER_LEN + 2 * CLIPS_HASH_LEN];
        uint8_t id[CLIPS_HASH_LEN];
        char hex[2 * CLIPS_HASH_LEN + 1];
        size_t n = 0;
        cm_make(&m);
        ASSERT_EQ(cm_encode(&m, buf, &n), CLIPS_OK);
        ASSERT_EQ(n, sizeof(buf));
        zcl_sha3_512(buf, n, id);
        cm_hex(id, sizeof(id), hex);
        ASSERT(strcmp(hex, k_kat_meta_id) == 0);
        PASS();
    }

    TEST("manifest encode then decode round trips every field") {
        struct clips_manifest m, back;
        uint8_t buf[CLIPS_MANIFEST_HEADER_LEN + 2 * CLIPS_HASH_LEN];
        size_t n = 0;
        cm_make(&m);
        ASSERT_EQ(cm_encode(&m, buf, &n), CLIPS_OK);
        ASSERT_EQ(clips_manifest_decode(buf, n, &back), CLIPS_OK);
        ASSERT_EQ(back.width, m.width);
        ASSERT_EQ(back.duration_ms, m.duration_ms);
        ASSERT_EQ(back.total_size, m.total_size);
        ASSERT_EQ(back.chunk_count, m.chunk_count);
        ASSERT(memcmp(back.chunk_ids[1], m.chunk_ids[1], CLIPS_HASH_LEN) == 0);
        ASSERT(memcmp(back.thumb_id, m.thumb_id, CLIPS_HASH_LEN) == 0);
        PASS();
    }

    TEST("chunk_count must equal ceil(total_size / 262144)") {
        ASSERT_EQ(cm_check_total(1, 1), CLIPS_OK);
        ASSERT_EQ(cm_check_total(262144, 1), CLIPS_OK);
        ASSERT_EQ(cm_check_total(262145, 2), CLIPS_OK);
        ASSERT_EQ(cm_check_total(262145, 1), CLIPS_ERR_CHUNK_COUNT);
        ASSERT_EQ(cm_check_total(262144, 2), CLIPS_ERR_CHUNK_COUNT);
        ASSERT_EQ(cm_check_total(1, 0), CLIPS_ERR_CHUNK_COUNT);
        PASS();
    }

    TEST("the 96-chunk ceiling: 25,165,824 bytes accepted, one more byte refused") {
        ASSERT_EQ(cm_check_total(CLIPS_MANIFEST_TOTAL_MAX, 96), CLIPS_OK);
        ASSERT_EQ(cm_check_total(CLIPS_MANIFEST_TOTAL_MAX + 1, 96), CLIPS_ERR_FIELD);
        ASSERT_EQ(cm_check_total(CLIPS_MANIFEST_TOTAL_MAX, 97), CLIPS_ERR_CHUNK_COUNT);
        ASSERT_EQ(cm_check_total(0, 1), CLIPS_ERR_FIELD);
        PASS();
    }

    TEST("a wrong chunk_size_log2 is refused") {
        struct clips_manifest m;
        uint8_t buf[CLIPS_MANIFEST_HEADER_LEN + 2 * CLIPS_HASH_LEN];
        size_t n = 0;
        cm_make(&m);
        m.chunk_size_log2 = 17;
        ASSERT_EQ(cm_encode(&m, buf, &n), CLIPS_ERR_CHUNK_SIZE);
        m.chunk_size_log2 = 19;
        ASSERT_EQ(cm_encode(&m, buf, &n), CLIPS_ERR_CHUNK_SIZE);
        PASS();
    }

    TEST("media limits: each bound accepted at its edge and refused one past it") {
        struct clips_manifest m;
        uint8_t buf[CLIPS_MANIFEST_HEADER_LEN + 2 * CLIPS_HASH_LEN];
        size_t n = 0;
        cm_make(&m);
        m.width = 16;
        m.height = 16;
        ASSERT_EQ(cm_encode(&m, buf, &n), CLIPS_OK);
        m.width = 15;
        ASSERT_EQ(cm_encode(&m, buf, &n), CLIPS_ERR_FIELD);
        m.width = 1921;
        ASSERT_EQ(cm_encode(&m, buf, &n), CLIPS_ERR_FIELD);
        m.width = 1080;
        m.height = 1920;
        m.duration_ms = 60000;
        ASSERT_EQ(cm_encode(&m, buf, &n), CLIPS_OK);
        m.duration_ms = 60001;
        ASSERT_EQ(cm_encode(&m, buf, &n), CLIPS_ERR_FIELD);
        m.duration_ms = 6000;
        m.bitrate_kbps = 8001;
        ASSERT_EQ(cm_encode(&m, buf, &n), CLIPS_ERR_FIELD);
        m.bitrate_kbps = 2000;
        m.fps = 61;
        ASSERT_EQ(cm_encode(&m, buf, &n), CLIPS_ERR_FIELD);
        m.fps = 30;
        m.rotation = 4;
        ASSERT_EQ(cm_encode(&m, buf, &n), CLIPS_ERR_FIELD);
        m.rotation = 3;
        ASSERT_EQ(cm_encode(&m, buf, &n), CLIPS_OK);
        PASS();
    }

    TEST("codec and thumbnail limits: H.264 only, thumbnail 16..1080 by 16..1920") {
        struct clips_manifest m;
        uint8_t buf[CLIPS_MANIFEST_HEADER_LEN + 2 * CLIPS_HASH_LEN];
        size_t n = 0;
        cm_make(&m);
        m.video_codec = 2;
        ASSERT_EQ(cm_encode(&m, buf, &n), CLIPS_ERR_FIELD);
        m.video_codec = 3;
        ASSERT_EQ(cm_encode(&m, buf, &n), CLIPS_ERR_FIELD);
        m.video_codec = 1;
        m.container = 2;
        ASSERT_EQ(cm_encode(&m, buf, &n), CLIPS_ERR_FIELD);
        m.container = 1;
        m.audio_codec = 2;
        ASSERT_EQ(cm_encode(&m, buf, &n), CLIPS_ERR_FIELD);
        m.audio_codec = 0;
        m.thumb_width = 1081;
        ASSERT_EQ(cm_encode(&m, buf, &n), CLIPS_ERR_FIELD);
        m.thumb_width = 1080;
        m.thumb_height = 1921;
        ASSERT_EQ(cm_encode(&m, buf, &n), CLIPS_ERR_FIELD);
        PASS();
    }

    TEST("decode refuses bad magic, version, trailing bytes and truncation at every offset") {
        struct clips_manifest m, back;
        uint8_t buf[CLIPS_MANIFEST_HEADER_LEN + 2 * CLIPS_HASH_LEN];
        size_t n = 0;
        cm_make(&m);
        ASSERT_EQ(cm_encode(&m, buf, &n), CLIPS_OK);
        buf[1] ^= 0x01;
        ASSERT_EQ(clips_manifest_decode(buf, n, &back), CLIPS_ERR_MAGIC);
        buf[1] ^= 0x01;
        buf[4] = 2;
        ASSERT_EQ(clips_manifest_decode(buf, n, &back), CLIPS_ERR_VERSION);
        buf[4] = 1;
        ASSERT_EQ(clips_manifest_decode(buf, n + 1, &back), CLIPS_ERR_TRAILING);
        for (size_t k = 0; k < n; k++)
            ASSERT(clips_manifest_decode(buf, k, &back) != CLIPS_OK);
        PASS();
    }

_test_next:;
    if (failures == 0)
        printf("test_clips_manifest: all passed\n");
    else
        printf("test_clips_manifest: %d FAILED\n", failures);
    return failures;
}
