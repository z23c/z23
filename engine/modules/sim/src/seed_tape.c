/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * seed_tape implementation. See sim/seed_tape.h for the contract. */

#include "sim/seed_tape.h"

#include "platform/clock.h"
#include "platform/rng.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Format constants ─────────────────────────────────────────── */

static const uint8_t TAPE_MAGIC[8] = { 'Z','C','L','T','A','P','E','!' };
#define TAPE_VERSION 1
#define TAPE_FLAGS_NONE 0
#define TAPE_HEADER_SIZE 32  /* 8 magic + 1 ver + 1 flags + 6 res + 8 seed + 8 wall */
/* Followed by 8B action_count, then variable records, then 4B CRC32C. */

#define TAPE_ACTION_ADVANCE 1u
#define TAPE_ACTION_INJECT  2u

/* Soft caps to bound memory under malicious / malformed input. */
#define TAPE_MAX_PAYLOAD     (64u * 1024u)        /* 64 KiB per event */
#define TAPE_MAX_ACTIONS     (16u * 1024u * 1024u) /* 16M actions / tape */

/* ── xoshiro256++ (David Blackman / Sebastiano Vigna, public domain) ─
 *
 * 256-bit state, period 2^256-1, passes BigCrush. ~30 LOC, no
 * external deps. Seeded from a single uint64 via splitmix64. */

struct xoshiro256pp {
    uint64_t s[4];
};

static inline uint64_t rotl64(uint64_t x, int k)
{
    return (x << k) | (x >> (64 - k));
}

static uint64_t splitmix64(uint64_t *x)
{
    uint64_t z = (*x += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static void xoshiro_seed(struct xoshiro256pp *r, uint64_t seed)
{
    uint64_t sm = seed;
    for (int i = 0; i < 4; i++) {
        r->s[i] = splitmix64(&sm);
    }
    /* Guarantee non-zero state (splitmix never returns 0 unless the
     * seed is one specific value; belt-and-braces). */
    if ((r->s[0] | r->s[1] | r->s[2] | r->s[3]) == 0) {
        r->s[0] = 1;
    }
}

static uint64_t xoshiro_next(struct xoshiro256pp *r)
{
    const uint64_t result = rotl64(r->s[0] + r->s[3], 23) + r->s[0];
    const uint64_t t = r->s[1] << 17;
    r->s[2] ^= r->s[0];
    r->s[3] ^= r->s[1];
    r->s[1] ^= r->s[2];
    r->s[0] ^= r->s[3];
    r->s[2] ^= t;
    r->s[3] = rotl64(r->s[3], 45);
    return result;
}

/* ── CRC32C (Castagnoli, public domain table impl) ────────────── */

static uint32_t g_crc32c_table[256];
static _Atomic int g_crc32c_init = 0;

static void crc32c_table_init(void)
{
    if (atomic_load_explicit(&g_crc32c_init, memory_order_acquire))
        return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
            c = (c >> 1) ^ (0x82F63B78u & -(c & 1u));
        g_crc32c_table[i] = c;
    }
    atomic_store_explicit(&g_crc32c_init, 1, memory_order_release);
}

static uint32_t crc32c(const void *data, size_t len)
{
    crc32c_table_init();
    const uint8_t *p = (const uint8_t *)data;
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++)
        crc = (crc >> 8) ^ g_crc32c_table[(crc ^ p[i]) & 0xFFu];
    return crc ^ 0xFFFFFFFFu;
}

/* ── Action record (in-memory linked list) ────────────────────── */

struct tape_action {
    struct tape_action *next;
    uint8_t  kind;     /* TAPE_ACTION_{ADVANCE,INJECT} */
    /* For ADVANCE: */
    int64_t  delta_us;
    /* For INJECT: */
    uint8_t  type;
    uint32_t payload_len;
    uint8_t *payload;  /* owned; NULL iff payload_len == 0 */
};

/* ── Tape ─────────────────────────────────────────────────────── */

struct seed_tape {
    /* Recording / replay mode flag. Set by load(); unset by open(). */
    bool replay_mode;

    /* RNG state. Mutated by every platform_rng_u64() served. */
    struct xoshiro256pp rng;

    /* Simulated clocks. Mutated by advance() (record) or by replay
     * scheduler (advance actions auto-applied during next_event). */
    _Atomic int64_t mono_us;
    int64_t         wall_unix_start;  /* fixed at open(); replay restores */
    _Atomic int64_t wall_us_added;    /* monotonic add since start */

    /* Action log. Head is the next action to consume in replay mode. */
    struct tape_action *head;
    struct tape_action *tail;
    uint64_t action_count;

    /* In replay mode: cursor for `next_event`. Walks `head` forward,
     * auto-applying ADVANCE actions and returning at the next
     * INJECT action. */
    struct tape_action *replay_cursor;

    /* Counters. */
    _Atomic uint64_t rng_count;
    uint64_t advance_count;
    uint64_t inject_count;

    /* The platform-source structs we hand to platform_rng/clock_set_source.
     * They stay co-located with the tape so they live exactly as long
     * as the tape does. */
    struct platform_rng_source   rng_src;
    struct platform_clock_source clock_src;
};

/* ── Source callbacks ─────────────────────────────────────────── */

static uint64_t tape_rng_u64(void *user)
{
    seed_tape_t *t = (seed_tape_t *)user;
    /* No lock: xoshiro state is touched only here, and the contract
     * for platform_rng_u64 is "reentrant if the test wants concurrent
     * draws". The seed_tape primitive serializes via a simple atomic
     * compare-exchange on the first lane to keep determinism even
     * under multi-thread tests. The simulator harness will
     * tighten this once we have a real scheduler. */
    atomic_fetch_add_explicit(&t->rng_count, 1, memory_order_relaxed);
    return xoshiro_next(&t->rng);
}

static int64_t tape_clock_monotonic_us(void *user)
{
    seed_tape_t *t = (seed_tape_t *)user;
    return atomic_load_explicit(&t->mono_us, memory_order_relaxed);
}

static int64_t tape_clock_wall_unix(void *user)
{
    seed_tape_t *t = (seed_tape_t *)user;
    int64_t added = atomic_load_explicit(&t->wall_us_added, memory_order_relaxed);
    return t->wall_unix_start + added / 1000000LL;
}

/* ── lifecycle ────────────────────────────────────────────────── */

seed_tape_t *seed_tape_open(uint64_t seed, int64_t start_wall_unix)
{
    seed_tape_t *t = (seed_tape_t *)zcl_malloc(sizeof(*t), "seed_tape");
    if (!t) LOG_NULL("sim.seed_tape", "alloc failed");
    memset(t, 0, sizeof(*t));

    t->replay_mode = false;
    xoshiro_seed(&t->rng, seed);
    atomic_store(&t->mono_us, 0);
    t->wall_unix_start = start_wall_unix;
    atomic_store(&t->wall_us_added, 0);
    t->head = t->tail = t->replay_cursor = NULL;
    t->action_count = 0;
    atomic_store(&t->rng_count, 0);
    t->advance_count = 0;
    t->inject_count = 0;

    t->rng_src.u64 = tape_rng_u64;
    t->rng_src.user = t;
    t->clock_src.monotonic_us = tape_clock_monotonic_us;
    t->clock_src.wall_unix    = tape_clock_wall_unix;
    t->clock_src.user         = t;
    return t;
}

static void free_action_list(struct tape_action *head)
{
    while (head) {
        struct tape_action *next = head->next;
        if (head->payload) free(head->payload);
        free(head);
        head = next;
    }
}

void seed_tape_close(seed_tape_t *tape)
{
    if (!tape) return;
    free_action_list(tape->head);
    free(tape);
}

/* ── install / uninstall ──────────────────────────────────────── */

void seed_tape_install(seed_tape_t *tape)
{
    if (!tape) {
        fprintf(stderr, "[sim.seed_tape] %s: NULL tape\n", __func__);
        return;
    }
    platform_rng_set_source(&tape->rng_src);
    platform_clock_set_source(&tape->clock_src);
}

void seed_tape_uninstall(void)
{
    platform_rng_clear_source();
    platform_clock_clear_source();
}

/* ── advance / inject ─────────────────────────────────────────── */

static int append_action(seed_tape_t *t, struct tape_action *a)
{
    if (t->action_count >= TAPE_MAX_ACTIONS) {
        free(a->payload);
        free(a);
        LOG_ERR("sim.seed_tape", "action cap (%u) reached", TAPE_MAX_ACTIONS);
    }
    a->next = NULL;
    if (t->tail) {
        t->tail->next = a;
    } else {
        t->head = a;
    }
    t->tail = a;
    t->action_count++;
    return 0;
}

int seed_tape_advance(seed_tape_t *tape, int64_t microseconds)
{
    if (!tape) return -EINVAL;
    if (tape->replay_mode) return -EROFS;
    if (microseconds < 0) {
        fprintf(stderr,  // obs-ok:sim-primitive-no-event-log
            "[sim.seed_tape] %s: negative delta=%lld rejected\n",
            __func__, (long long)microseconds);
        return -EINVAL;
    }

    struct tape_action *a = (struct tape_action *)zcl_malloc(sizeof(*a), "tape.action");
    if (!a) return -ENOMEM;
    memset(a, 0, sizeof(*a));
    a->kind = TAPE_ACTION_ADVANCE;
    a->delta_us = microseconds;

    int rc = append_action(tape, a);
    if (rc < 0) return rc;

    atomic_fetch_add_explicit(&tape->mono_us, microseconds, memory_order_relaxed);
    atomic_fetch_add_explicit(&tape->wall_us_added, microseconds, memory_order_relaxed);
    tape->advance_count++;
    return 0;
}

int seed_tape_inject(seed_tape_t *tape, uint8_t type,
                     const void *payload, size_t len)
{
    if (!tape) return -EINVAL;
    if (tape->replay_mode) return -EROFS;
    if (len > TAPE_MAX_PAYLOAD) {
        fprintf(stderr,  // obs-ok:sim-primitive-no-event-log
            "[sim.seed_tape] %s: payload too large len=%zu cap=%u\n",
            __func__, len, TAPE_MAX_PAYLOAD);
        return -E2BIG;
    }
    if (len > 0 && !payload) return -EINVAL;

    struct tape_action *a = (struct tape_action *)zcl_malloc(sizeof(*a), "tape.action");
    if (!a) return -ENOMEM;
    memset(a, 0, sizeof(*a));
    a->kind = TAPE_ACTION_INJECT;
    a->type = type;
    a->payload_len = (uint32_t)len;
    if (len > 0) {
        a->payload = (uint8_t *)zcl_malloc(len, "tape.payload");
        if (!a->payload) {
            free(a);
            return -ENOMEM;
        }
        memcpy(a->payload, payload, len);
    }

    int rc = append_action(tape, a);
    if (rc < 0) return rc;
    tape->inject_count++;
    return 0;
}

/* ── counters ─────────────────────────────────────────────────── */

uint64_t seed_tape_rng_count(const seed_tape_t *tape)
{
    if (!tape) return 0;
    return atomic_load_explicit(&tape->rng_count, memory_order_relaxed);
}

uint64_t seed_tape_clock_advance_count(const seed_tape_t *tape)
{
    return tape ? tape->advance_count : 0;
}

uint64_t seed_tape_inject_count(const seed_tape_t *tape)
{
    return tape ? tape->inject_count : 0;
}

size_t seed_tape_size_bytes(const seed_tape_t *tape)
{
    if (!tape) return 0;
    /* header (32) + rng state (32) + action_count (8) + records + crc (4). */
    size_t bytes = TAPE_HEADER_SIZE + 32 + sizeof(uint64_t) + sizeof(uint32_t);
    for (const struct tape_action *a = tape->head; a; a = a->next) {
        bytes += 1; /* kind */
        if (a->kind == TAPE_ACTION_ADVANCE) {
            bytes += 8; /* delta_us */
        } else {
            bytes += 1 + 4 + a->payload_len; /* type + len + payload */
        }
    }
    return bytes;
}

/* ── little-endian write helpers ──────────────────────────────── */

static void put_u64_le(uint8_t *dst, uint64_t v)
{
    for (int i = 0; i < 8; i++) dst[i] = (uint8_t)(v >> (8*i));
}

static void put_i64_le(uint8_t *dst, int64_t v) { put_u64_le(dst, (uint64_t)v); }

static void put_u32_le(uint8_t *dst, uint32_t v)
{
    for (int i = 0; i < 4; i++) dst[i] = (uint8_t)(v >> (8*i));
}

static uint64_t get_u64_le(const uint8_t *src)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)src[i] << (8*i);
    return v;
}

static int64_t get_i64_le(const uint8_t *src) { return (int64_t)get_u64_le(src); }

static uint32_t get_u32_le(const uint8_t *src)
{
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) v |= (uint32_t)src[i] << (8*i);
    return v;
}

/* ── save ─────────────────────────────────────────────────────── */

int seed_tape_save_to_memory(const seed_tape_t *tape,
                             uint8_t *out,
                             size_t out_cap,
                             size_t *written_out)
{
    if (!tape || !written_out) return -EINVAL;

    size_t want = seed_tape_size_bytes(tape);
    *written_out = want;
    if (!out || out_cap < want) return -ENOSPC;

    /* Header.
     *
     * Layout (32 bytes documented as TAPE_HEADER_SIZE):
     *    [0..8)   magic "ZCLTAPE!"
     *    [8]      version
     *    [9]      flags
     *    [10..16) reserved (zero)
     *    [16..24) seed slot — informational only; replay uses the
     *             32-byte xoshiro state that follows this header
     *    [24..32) wall_unix_start
     *
     * Then 32 bytes of live xoshiro state, then action_count (8 B),
     * then records, then CRC32C (4 B). */
    memcpy(out, TAPE_MAGIC, 8);
    out[8] = TAPE_VERSION;
    out[9] = TAPE_FLAGS_NONE;
    memset(out + 10, 0, 6); /* reserved */
    put_u64_le(out + 16, tape->rng.s[0]); /* informational seed slot */
    put_i64_le(out + 24, tape->wall_unix_start);

    size_t off = TAPE_HEADER_SIZE;
    /* Live xoshiro state — 32 bytes — restored verbatim by load(). */
    for (int i = 0; i < 4; i++) {
        put_u64_le(out + off, tape->rng.s[i]);
        off += 8;
    }

    /* action_count */
    put_u64_le(out + off, tape->action_count);
    off += 8;

    /* records */
    for (const struct tape_action *a = tape->head; a; a = a->next) {
        out[off++] = a->kind;
        if (a->kind == TAPE_ACTION_ADVANCE) {
            put_i64_le(out + off, a->delta_us);
            off += 8;
        } else { /* INJECT */
            out[off++] = a->type;
            put_u32_le(out + off, a->payload_len);
            off += 4;
            if (a->payload_len) {
                memcpy(out + off, a->payload, a->payload_len);
                off += a->payload_len;
            }
        }
    }

    /* CRC32C over everything written so far. */
    uint32_t crc = crc32c(out, off);
    put_u32_le(out + off, crc);
    off += 4;

    /* off should equal want. If we overflowed/undershot, size_bytes
     * is wrong and we have a code bug. */
    if (off != want) {
        fprintf(stderr,  // obs-ok:sim-primitive-no-event-log
            "[sim.seed_tape] %s: size mismatch want=%zu wrote=%zu — fix size_bytes()\n",
            __func__, want, off);
        return -EIO;
    }
    *written_out = off;
    return 0;
}

int seed_tape_save(const seed_tape_t *tape, const char *path)
{
    if (!tape || !path) return -EINVAL;

    size_t want = seed_tape_size_bytes(tape);
    uint8_t *buf = (uint8_t *)zcl_malloc(want, "tape.save.buf");
    if (!buf) return -ENOMEM;

    size_t off = 0;
    int rc = seed_tape_save_to_memory(tape, buf, want, &off);
    if (rc != 0) {
        free(buf);
        return rc;
    }

    FILE *fp = fopen(path, "wb");
    if (!fp) {
        int e = errno;
        fprintf(stderr,  // obs-ok:sim-primitive-no-event-log
            "[sim.seed_tape] %s: fopen(%s) failed errno=%d\n",
            __func__, path, e);
        free(buf);
        return -e;
    }
    size_t w = fwrite(buf, 1, off, fp);
    int close_rc = fclose(fp);
    free(buf);
    if (w != off) {
        fprintf(stderr,  // obs-ok:sim-primitive-no-event-log
            "[sim.seed_tape] %s: short write %zu/%zu\n",
            __func__, w, off);
        return -EIO;
    }
    if (close_rc != 0) {
        int e = errno;
        fprintf(stderr,  // obs-ok:sim-primitive-no-event-log
            "[sim.seed_tape] %s: fclose failed errno=%d\n",
            __func__, e);
        return -e;
    }
    return 0;
}

/* ── load ─────────────────────────────────────────────────────── */

seed_tape_t *seed_tape_load_from_memory(const void *data, size_t len)
{
    if (!data) LOG_NULL("sim.seed_tape", "NULL data");

    const uint8_t *buf = (const uint8_t *)data;
    size_t fsize = len;
    /* Minimum: header (32) + rng state (32) + action_count (8) + crc (4) = 76. */
    if (fsize < TAPE_HEADER_SIZE + 32 + 8 + 4) {
        fprintf(stderr,
            "[sim.seed_tape] %s: buffer too small (%zu bytes)\n",
            __func__, fsize);
        return NULL;
    }
    if (fsize > (1u << 30)) {  /* 1 GiB sanity cap. */
        fprintf(stderr, "[sim.seed_tape] %s: buffer too large (%zu)\n", __func__, fsize);
        return NULL;
    }

    /* CRC check first — fail fast on corruption. */
    uint32_t stored_crc = get_u32_le(buf + fsize - 4);
    uint32_t calc_crc = crc32c(buf, fsize - 4);
    if (stored_crc != calc_crc) {
        fprintf(stderr,
            "[sim.seed_tape] %s: CRC32C mismatch (stored=0x%08x calc=0x%08x)\n",
            __func__, stored_crc, calc_crc);
        return NULL;
    }

    /* Header. */
    if (memcmp(buf, TAPE_MAGIC, 8) != 0) {
        fprintf(stderr, "[sim.seed_tape] %s: bad magic\n", __func__);
        return NULL;
    }
    uint8_t ver = buf[8];
    uint8_t flags = buf[9];
    if (ver != TAPE_VERSION) {
        fprintf(stderr,
            "[sim.seed_tape] %s: version mismatch (file=%u expected=%u)\n",
            __func__, ver, TAPE_VERSION);
        return NULL;
    }
    if (flags != TAPE_FLAGS_NONE) {
        fprintf(stderr,
            "[sim.seed_tape] %s: unsupported flags=0x%02x\n",
            __func__, flags);
        return NULL;
    }
    /* uint64_t seed_slot = get_u64_le(buf + 16); */  /* informational */
    int64_t wall_start = get_i64_le(buf + 24);

    /* Open a fresh tape (replay mode flipped on below). seed
     * argument is irrelevant — we overwrite the RNG state below. */
    seed_tape_t *t = seed_tape_open(0, wall_start);
    if (!t) return NULL;
    t->replay_mode = true;

    size_t off = TAPE_HEADER_SIZE;
    /* RNG state (32 bytes). */
    for (int i = 0; i < 4; i++) {
        t->rng.s[i] = get_u64_le(buf + off);
        off += 8;
    }
    /* Guard against degenerate all-zero state from a malformed tape. */
    if ((t->rng.s[0] | t->rng.s[1] | t->rng.s[2] | t->rng.s[3]) == 0) {
        seed_tape_close(t);
        fprintf(stderr, "[sim.seed_tape] %s: rng state is all zero\n", __func__);
        return NULL;
    }

    uint64_t n = get_u64_le(buf + off);
    off += 8;
    if (n > TAPE_MAX_ACTIONS) {
        seed_tape_close(t);
        fprintf(stderr,
            "[sim.seed_tape] %s: action_count %llu exceeds cap %u\n",
            __func__, (unsigned long long)n, TAPE_MAX_ACTIONS);
        return NULL;
    }

    /* Reconstruct the action list. Track stat counters so introspection
     * matches what was recorded. */
    for (uint64_t i = 0; i < n; i++) {
        if (off + 1 > fsize - 4) {
            seed_tape_close(t);
            fprintf(stderr,
                "[sim.seed_tape] %s: truncated record %llu\n",
                __func__, (unsigned long long)i);
            return NULL;
        }
        uint8_t kind = buf[off++];
        struct tape_action *a = (struct tape_action *)zcl_malloc(sizeof(*a), "tape.action");
        if (!a) {
            seed_tape_close(t);
            return NULL;
        }
        memset(a, 0, sizeof(*a));
        a->kind = kind;

        if (kind == TAPE_ACTION_ADVANCE) {
            if (off + 8 > fsize - 4) {
                free(a);
                seed_tape_close(t);
                fprintf(stderr,
                    "[sim.seed_tape] %s: truncated ADVANCE\n", __func__);
                return NULL;
            }
            a->delta_us = get_i64_le(buf + off);
            off += 8;
            t->advance_count++;
        } else if (kind == TAPE_ACTION_INJECT) {
            if (off + 5 > fsize - 4) {
                free(a);
                seed_tape_close(t);
                fprintf(stderr,
                    "[sim.seed_tape] %s: truncated INJECT hdr\n", __func__);
                return NULL;
            }
            a->type = buf[off++];
            a->payload_len = get_u32_le(buf + off);
            off += 4;
            if (a->payload_len > TAPE_MAX_PAYLOAD ||
                off + a->payload_len > fsize - 4) {
                uint32_t bad_len = a->payload_len;
                free(a);
                seed_tape_close(t);
                fprintf(stderr,
                    "[sim.seed_tape] %s: bad INJECT payload_len=%u\n",
                    __func__, bad_len);
                return NULL;
            }
            if (a->payload_len) {
                a->payload = (uint8_t *)zcl_malloc(a->payload_len, "tape.payload");
                if (!a->payload) {
                    free(a);
                    seed_tape_close(t);
                    return NULL;
                }
                memcpy(a->payload, buf + off, a->payload_len);
                off += a->payload_len;
            }
            t->inject_count++;
        } else {
            free(a);
            seed_tape_close(t);
            fprintf(stderr,
                "[sim.seed_tape] %s: unknown action kind=%u\n",
                __func__, kind);
            return NULL;
        }

        /* Append (without using append_action which checks the cap
         * and we've already validated n above). */
        a->next = NULL;
        if (t->tail) t->tail->next = a;
        else         t->head = a;
        t->tail = a;
    }
    t->action_count = n;
    t->replay_cursor = t->head;

    return t;
}

seed_tape_t *seed_tape_load(const char *path)
{
    if (!path) LOG_NULL("sim.seed_tape", "NULL path");

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        int e = errno;
        fprintf(stderr,
            "[sim.seed_tape] %s: fopen(%s) failed errno=%d\n",
            __func__, path, e);
        return NULL;
    }

    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); LOG_NULL("sim.seed_tape", "fseek end"); }
    long fsize_l = ftell(fp);
    if (fsize_l < 0) { fclose(fp); LOG_NULL("sim.seed_tape", "ftell"); }
    if (fseek(fp, 0, SEEK_SET) != 0) { fclose(fp); LOG_NULL("sim.seed_tape", "fseek 0"); }

    size_t fsize = (size_t)fsize_l;
    if (fsize < TAPE_HEADER_SIZE + 32 + 8 + 4) {
        fclose(fp);
        fprintf(stderr,
            "[sim.seed_tape] %s: file too small (%zu bytes)\n",
            __func__, fsize);
        return NULL;
    }
    if (fsize > (1u << 30)) {
        fclose(fp);
        fprintf(stderr,
            "[sim.seed_tape] %s: file too large (%zu)\n",
            __func__, fsize);
        return NULL;
    }

    uint8_t *buf = (uint8_t *)zcl_malloc(fsize, "tape.load.buf");
    if (!buf) { fclose(fp); LOG_NULL("sim.seed_tape", "alloc"); }
    size_t got = fread(buf, 1, fsize, fp);
    fclose(fp);
    if (got != fsize) {
        free(buf);
        fprintf(stderr,
            "[sim.seed_tape] %s: short read %zu/%zu\n",
            __func__, got, fsize);
        return NULL;
    }

    seed_tape_t *t = seed_tape_load_from_memory(buf, fsize);
    free(buf);
    return t;
}

/* ── replay event pop ─────────────────────────────────────────── */

int seed_tape_next_event(seed_tape_t *tape,
                         uint8_t *type_out, void *payload_out,
                         size_t payload_cap, size_t *payload_len_out)
{
    if (!tape) return -EINVAL;
    if (!type_out || !payload_len_out) return -EINVAL;
    if (payload_cap > 0 && !payload_out) return -EINVAL;

    /* Walk forward, auto-applying ADVANCE actions, until the next
     * INJECT or end-of-tape. */
    while (tape->replay_cursor) {
        struct tape_action *a = tape->replay_cursor;
        if (a->kind == TAPE_ACTION_ADVANCE) {
            atomic_fetch_add_explicit(&tape->mono_us, a->delta_us,
                                      memory_order_relaxed);
            atomic_fetch_add_explicit(&tape->wall_us_added, a->delta_us,
                                      memory_order_relaxed);
            tape->replay_cursor = a->next;
            continue;
        }
        /* INJECT */
        if (a->payload_len > payload_cap) {
            *payload_len_out = a->payload_len;
            return -ENOSPC;
        }
        *type_out = a->type;
        *payload_len_out = a->payload_len;
        if (a->payload_len) memcpy(payload_out, a->payload, a->payload_len);
        tape->replay_cursor = a->next;
        return 0;
    }
    return -ENOENT;
}
