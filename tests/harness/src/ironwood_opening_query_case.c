/* purpose: Check every opening query against independent one- and two-action traces. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_postnu63_query.h"
#include "base/hex.h"
#include "base/serialize_le.h"
#include "crypto/sha256.h"
#include <string.h>

static void hash_word(struct sha256_ctx *h, size_t value)
{
    uint8_t word[8];
    zcl_write_u64_le(word, (uint64_t)value);
    sha256_write(h, word, sizeof word);
}
static bool matches(struct sha256_ctx *h, const char *hex)
{
    uint8_t expected[32], got[32];
    sha256_finalize(h, got);
    return zcl_hex_decode(hex, expected, sizeof expected) && !memcmp(expected, got, sizeof got);
}
static bool query_limits(void)
{
    struct ironwood_opening_query q, before;
    memset(&q, 0xa5, sizeof q);
    memcpy(&before, &q, sizeof before);
    if (ironwood_postnu63_query_at(0, 0, &q).ok || ironwood_postnu63_query_at(UINT64_MAX, 0, &q).ok ||
        ironwood_postnu63_query_at(1, 69, &q).ok || memcmp(&q, &before, sizeof q)) return false;
    size_t n = (SIZE_MAX - 2720) / 2272;
    size_t end = IRONWOOD_SHARED_OPENING_QUERIES + n * IRONWOOD_ACTION_OPENING_QUERIES;
    return ironwood_postnu63_query_at(n, end - 1, &q).ok && q.source == IRONWOOD_QUERY_INSTANCE &&
        q.point == 0 && q.count == 1 && q.evaluation[0] == 0 && !ironwood_postnu63_query_at(n, end, &q).ok;
}

/* Each reference row is source,set,count then uint64le(point) and the
 * ordered uint64le evaluation indices. Each map was extracted from the
 * upstream Halo2 commitment and scalar traces for the public wire fixture. */
bool ironwood_opening_query_case(size_t actions)
{
    static const char *const digests[] = {
        "73a859803d8a819e3227e98cc3d60b0645832f918b105f725ae1c74490d71397",
        "9aed5ddc244280bca137e6438d6dd929c1bcc4d9aebf638827de712188559ed5"
    };
    if (!actions || actions > 2 || !query_limits()) return false;
    struct sha256_ctx rows, vk;
    sha256_init(&rows); sha256_init(&vk);
    size_t end = IRONWOOD_SHARED_OPENING_QUERIES + actions * IRONWOOD_ACTION_OPENING_QUERIES;
    for (size_t i = 0; i < end; ++i) {
        struct ironwood_opening_query q;
        if (!ironwood_postnu63_query_at(actions, i, &q).ok || q.count > 3) return false;
        const uint8_t tags[] = {(uint8_t)q.source, (uint8_t)q.set, (uint8_t)q.count};
        sha256_write(&rows, tags, sizeof tags);
        hash_word(&rows, q.point);
        for (size_t j = 0; j < q.count; ++j) hash_word(&rows, q.evaluation[j]);
        if ((q.source == IRONWOOD_QUERY_VK) != (q.vk != NULL)) return false;
        if (q.vk) sha256_write(&vk, q.vk, 32);
    }
    return matches(&rows, digests[actions - 1]) &&
        matches(&vk, "7b2a808a3677c2f3559a00a6fbe755df7f8fb0e78152b071ceb8a42de6dffc5b");
}
