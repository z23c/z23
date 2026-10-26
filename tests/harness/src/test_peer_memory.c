/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * PEER MEMORY - a node that has met this network must be able to get back on
 * it without a hardcoded seed: it remembers the peers it talked to, keeps
 * them across an unclean stop, and prefers its own measured experience over
 * any list it was handed.
 *
 *   1.  An ONION peer survives a peers.dat round-trip, and distinct onion
 *       peers stay distinct (net_addr_from_onion() leaves ip[16] zero; format
 *       v1 wrote only ip[16]).
 *   2.  The ranking fields survive: last_success, last_try, attempts.
 *   3.  A peer learned by a process that is then SIGKILLed is still there for
 *       the next boot, in both stores.
 *   4.  Hostile input degrades to empty and never crashes: truncated body,
 *       random bytes, a bogus torv3 flag, an oversized version, a legacy v1
 *       onion row, and a negative-attempts entry.
 *   5.  Bounded aging: a proven-dead record does not come back, and a peer
 *       that keeps failing is deprioritised.
 *   6.  addrman_proven_count() counts only addresses we actually connected to.
 *
 * Not proved here: the full two-node boot leg over a real socket (see test
 * 3). All file I/O is local (./test-tmp); no network, no live datadir.
 */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"
#include "net/addrman.h"
#include "net/anchor_peers.h"
#include "net/connman.h"
#include "net/netaddr.h"
#include "core/serialize.h"
#include "platform/time_compat.h"
#include "test/setup_result.h"

#include <dirent.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif
#include <signal.h>
#include <unistd.h>
#if !defined(_WIN32)

#define PM_SCRATCH_ROOT "./test-tmp"

/* ── scratch helpers (mirrors test_anchor_peers) ───────────────────────── */

static void pm_tmp_dir(char *out, size_t cap, const char *tag)
{
    mkdir(PM_SCRATCH_ROOT, 0755);
    snprintf(out, cap, PM_SCRATCH_ROOT "/peermem_%d_%s", (int)getpid(), tag);
    mkdir(out, 0755);
}

static void pm_cleanup(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *ent;
    char fpath[1024];
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.' &&
            (ent->d_name[1] == '\0' ||
             (ent->d_name[1] == '.' && ent->d_name[2] == '\0')))
            continue;
        snprintf(fpath, sizeof(fpath), "%s/%s", dir, ent->d_name);
        unlink(fpath);
    }
    closedir(d);
    rmdir(dir);
}

/* An onion net_addr in exactly the shape net_addr_from_onion() produces:
 * ip[16] all zero, the whole identity in torv3[32]. Built directly so the
 * test does not need a checksum-valid base32 hostname. */
static void pm_set_onion(struct net_addr *a, unsigned char seed)
{
    net_addr_init(a);
    for (size_t i = 0; i < TORV3_ADDR_SIZE; i++)
        a->torv3[i] = (unsigned char)(seed + i);
    a->has_torv3 = true;
}

static void pm_set_ipv4(struct net_addr *a, unsigned char o1, unsigned char o2,
                        unsigned char o3, unsigned char o4)
{
    unsigned char ip4[4] = { o1, o2, o3, o4 };
    net_addr_init(a);
    net_addr_set_ipv4(a, ip4);
}

/* Round-trip an addrman through the serializer into a fresh one. */
static bool pm_roundtrip(struct addr_man *in, struct addr_man *out)
{
    struct byte_stream s;
    stream_init(&s, 65536);
    bool ok = addrman_serialize(in, &s);
    if (ok) {
        struct byte_stream r;
        stream_init_from_data(&r, s.data, s.size);
        addrman_init(out);
        ok = addrman_deserialize(out, &r);
        stream_free(&r);
    }
    stream_free(&s);
    return ok;
}

/* Feed arbitrary bytes to the loader. Returns true when the loader survived
 * (whatever verdict it reached) and left a coherent table behind. */
static bool pm_load_bytes_survives(const unsigned char *buf, size_t len,
                                   size_t *loaded_out)
{
    struct addr_man am;
    addrman_init(&am);
    struct byte_stream r;
    stream_init_from_data(&r, (unsigned char *)buf, len);
    /* As connman_load_addrman: a store that fails to parse is discarded,
     * never partially adopted. */
    if (!addrman_deserialize(&am, &r))
        addrman_clear(&am);
    size_t n = addrman_size(&am);
    char err[256];
    bool coherent = addrman_consistency_check(&am, err, sizeof(err)) == 0 &&
                    addrman_index_verify(&am, err, sizeof(err)) == 0;
    stream_free(&r);
    addrman_free(&am);
    if (loaded_out) *loaded_out = n;
    return coherent;
}

/* Write an addrman to <dir>/peers.dat the way connman_save_addrman does
 * (body only; the SHA3 sidecar is exercised by test_addrman_integrity). */
static bool pm_write_peers_dat(const char *dir, struct addr_man *am)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/peers.dat", dir);
    struct byte_stream s;
    stream_init(&s, 65536);
    bool ok = addrman_serialize(am, &s);
    if (ok) {
        FILE *f = fopen(path, "wb");
        ok = f != NULL;
        if (f) {
            ok = fwrite(s.data, 1, s.size, f) == s.size;
            fflush(f);
            int fd = fileno(f);
            if (fd >= 0) (void)fsync(fd);
            fclose(f);
        }
    }
    stream_free(&s);
    return ok;
}

static bool pm_read_peers_dat(const char *dir, struct addr_man *out)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/peers.dat", dir);
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return false; }
    unsigned char *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return false; }
    bool ok = fread(buf, 1, (size_t)sz, f) == (size_t)sz;
    fclose(f);
    if (ok) {
        struct byte_stream r;
        stream_init_from_data(&r, buf, (size_t)sz);
        addrman_init(out);
        ok = addrman_deserialize(out, &r);
        stream_free(&r);
    }
    free(buf);
    return ok;
}

/* Hand-build a store body so a single field can be made hostile without
 * disturbing anything else. `version` selects the record width; the tail
 * fields are only written for version 2. One NEW entry, empty bucket table. */
struct pm_forged {
    uint8_t  version;
    struct net_addr addr;
    uint8_t  addr_flag;       /* raw has_torv3 byte, may be nonsense */
    uint16_t port;
    int64_t  last_success;
    int32_t  attempts;
    int64_t  last_try;
    int      bucket_count;    /* 0 == this build's ADDRMAN_NEW_BUCKET_COUNT */
};

static bool pm_forge_write_header(struct byte_stream *s, uint8_t version,
                                  const unsigned char *key, int nbuckets)
{
    return stream_write_u8(s, version) && stream_write_u8(s, 32) &&
           stream_write_bytes(s, key, 32) &&
           stream_write_i32_le(s, 1) &&              /* nNew   */
           stream_write_i32_le(s, 0) &&              /* nTried */
           stream_write_i32_le(s, nbuckets ^ (1 << 30));
}

static bool pm_forge_write_addr_record(struct byte_stream *s,
                                       const struct pm_forged *f,
                                       const unsigned char *zero16)
{
    return stream_write_bytes(s, f->addr.ip, 16) &&
           stream_write_u16_le(s, f->port) &&
           stream_write_u64_le(s, 1) &&
           stream_write_u32_le(s, (uint32_t)platform_time_wall_time_t()) &&
           stream_write_bytes(s, zero16, 16) &&
           stream_write_i64_le(s, f->last_success) &&
           stream_write_i32_le(s, f->attempts);
}

static bool pm_forge_write_v2_fields(struct byte_stream *s,
                                    const struct pm_forged *f,
                                    const unsigned char *zero32)
{
    return stream_write_bytes(s, f->addr.torv3, TORV3_ADDR_SIZE) &&
           stream_write_u8(s, f->addr_flag) &&
           stream_write_bytes(s, zero32, TORV3_ADDR_SIZE) && /* source */
           stream_write_u8(s, 0) &&
           stream_write_i64_le(s, f->last_try);
}

static bool pm_forge_write_empty_buckets(struct byte_stream *s, int nbuckets)
{
    bool ok = true;
    for (int b = 0; ok && b < nbuckets; b++)
        ok = stream_write_i32_le(s, 0);
    return ok;
}

static bool pm_forge_store(struct byte_stream *s, const struct pm_forged *f)
{
    unsigned char key[32];
    memset(key, 0xa5, sizeof(key));
    unsigned char zero16[16];
    memset(zero16, 0, sizeof(zero16));
    unsigned char zero32[TORV3_ADDR_SIZE];
    memset(zero32, 0, sizeof(zero32));
    const int nbuckets = f->bucket_count > 0 ? f->bucket_count
                                             : ADDRMAN_NEW_BUCKET_COUNT;

    bool ok = pm_forge_write_header(s, f->version, key, nbuckets);
    ok = ok && pm_forge_write_addr_record(s, f, zero16);
    if (ok && f->version >= 2)
        ok = pm_forge_write_v2_fields(s, f, zero32);
    ok = ok && pm_forge_write_empty_buckets(s, nbuckets);
    return ok;
}

static bool pm_both_onions_came_back(struct addr_man *am2,
                                    const struct net_address *a1,
                                    const struct net_address *a2)
{
    bool ok = addrman_size(am2) == 2;

    struct addr_info got;
    struct net_service want1 = { .addr = a1->svc.addr, .port = 8033 };
    struct net_service want2 = { .addr = a2->svc.addr, .port = 8034 };
    /* The exact torv3 pubkey and port must come back. */
    ok = ok && addrman_find_info(am2, &want1, &got);
    ok = ok && got.addr.svc.addr.has_torv3;
    ok = ok && memcmp(got.addr.svc.addr.torv3, a1->svc.addr.torv3,
                      TORV3_ADDR_SIZE) == 0;
    ok = ok && got.addr.svc.port == 8033;
    ok = ok && addrman_find_info(am2, &want2, &got);
    ok = ok && memcmp(got.addr.svc.addr.torv3, a2->svc.addr.torv3,
                      TORV3_ADDR_SIZE) == 0;
    return ok;
}

static int pm_onion_peer_roundtrip(void)
{
    int failures = 0;
    /* ── 1. an onion peer survives a peers.dat round-trip ──────────────── */
    printf("peer_memory: onion peer survives peers.dat round-trip... ");
    struct addr_man am;
    addrman_init(&am);
    struct net_addr src;
    pm_set_ipv4(&src, 5, 5, 5, 5);

    struct net_address a1, a2;
    net_address_init(&a1);
    pm_set_onion(&a1.svc.addr, 0x11);
    a1.svc.port = 8033;
    a1.nServices = 1;
    a1.nTime = (uint32_t)platform_time_wall_time_t();

    net_address_init(&a2);
    pm_set_onion(&a2.svc.addr, 0x77);
    a2.svc.port = 8034;
    a2.nServices = 1;
    a2.nTime = (uint32_t)platform_time_wall_time_t();

    bool ok = addrman_add(&am, &a1, &src, 0);
    ok = ok && addrman_add(&am, &a2, &src, 0);
    /* Two distinct onion peers in memory (both serialized identically
     * under format v1). */
    ok = ok && addrman_size(&am) == 2;

    struct addr_man am2;
    ok = ok && pm_roundtrip(&am, &am2);
    if (ok) {
        ok = pm_both_onions_came_back(&am2, &a1, &a2);
        addrman_free(&am2);
    }
    addrman_free(&am);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

static int pm_ranking_fields_roundtrip(void)
{
    int failures = 0;
    /* ── 2. ranking fields survive the round-trip ──────────────────────── */
    printf("peer_memory: last_success/last_try/attempts survive... ");
    struct addr_man am;
    addrman_init(&am);
    struct net_addr src;
    pm_set_ipv4(&src, 5, 5, 5, 5);

    struct net_address a;
    net_address_init(&a);
    pm_set_onion(&a.svc.addr, 0x33);
    a.svc.port = 8033;
    a.nTime = (uint32_t)platform_time_wall_time_t();

    int64_t t_ok = (int64_t)platform_time_wall_time_t() - 900;
    int64_t t_try = (int64_t)platform_time_wall_time_t() - 120;

    bool ok = addrman_add(&am, &a, &src, 0);
    addrman_good(&am, &a.svc, t_ok);      /* promotes to the tried table */
    addrman_attempt(&am, &a.svc, t_try);  /* and records a later attempt */

    struct addr_man am2;
    ok = ok && pm_roundtrip(&am, &am2);
    if (ok) {
        struct addr_info got;
        ok = addrman_find_info(&am2, &a.svc, &got);
        /* Without last_try on disk the ten-minute cooldown in
         * addr_info_get_chance() is dropped at every restart. */
        ok = ok && got.last_success == t_ok;
        ok = ok && got.last_try == t_try;
        ok = ok && got.attempts >= 1;
        addrman_free(&am2);
    }
    addrman_free(&am);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

/* child: learn + persist, then die uncleanly */
static void pm_sigkill_child_persist(const char *dir, const struct net_addr *onion)
{
    struct addr_man am;
    addrman_init(&am);
    struct net_addr src;
    pm_set_ipv4(&src, 9, 9, 9, 9);
    struct net_address a;
    net_address_init(&a);
    a.svc.addr = *onion;
    a.svc.port = 8033;
    a.nTime = (uint32_t)platform_time_wall_time_t();
    if (!addrman_add(&am, &a, &src, 0)) _exit(2);
    addrman_good(&am, &a.svc, (int64_t)platform_time_wall_time_t());
    if (!pm_write_peers_dat(dir, &am)) _exit(3);

    struct anchor_peer_set set;
    memset(&set, 0, sizeof(set));
    set.count = 1;
    set.peers[0].addr = *onion;
    set.peers[0].port = 8033;
    set.peers[0].services = 1;
    set.peers[0].last_height = 3117000;
    set.peers[0].last_success = (int64_t)platform_time_wall_time_t();
    if (!anchor_peers_save(dir, &set).ok) _exit(4);

    raise(SIGKILL);
    _exit(5);            /* unreachable */
}

static bool pm_child_died_by_sigkill(pid_t pid)
{
    int st = 0;
    bool waited = pid > 0;
    if (waited)
        while (waitpid(pid, &st, 0) < 0 && errno == EINTR) { }
    /* The child must really have died to a SIGKILL, or this test is
     * proving nothing about an unclean stop. */
    return waited && WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL;
}

static bool pm_reloaded_onion_in_peers(const char *dir,
                                      const struct net_addr *onion)
{
    struct addr_man reloaded;
    bool ok = pm_read_peers_dat(dir, &reloaded);
    if (ok) {
        struct net_service want = { .addr = *onion, .port = 8033 };
        struct addr_info got;
        ok = addrman_find_info(&reloaded, &want, &got) &&
             got.addr.svc.addr.has_torv3 &&
             memcmp(got.addr.svc.addr.torv3, onion->torv3,
                    TORV3_ADDR_SIZE) == 0;
        addrman_free(&reloaded);
    }
    return ok;
}

static bool pm_reloaded_onion_in_anchors(const char *dir,
                                        const struct net_addr *onion)
{
    struct anchor_peer_set back;
    return anchor_peers_load(dir, &back) == ANCHOR_LOAD_OK &&
           back.count == 1 &&
           net_addr_eq(&back.peers[0].addr, onion) &&
           back.peers[0].port == 8033;
}

static int pm_sigkill_peer_survives(void)
{
    int failures = 0;
    /* 3. A SIGKILLed process still leaves its peers behind: the child persists
     * a peer through peers.dat and anchors.dat and is killed with no graceful
     * shutdown; the parent must find the onion peer intact. The socket leg
     * (handshake, dial-scheduler thread) is not exercised; the persistence
     * entry points are called directly. */
    printf("peer_memory: peer learned before SIGKILL survives... ");
    char dir[256]; pm_tmp_dir(dir, sizeof(dir), "kill9");
    struct net_addr onion;
    pm_set_onion(&onion, 0x5a);

    pid_t pid = fork();
    if (pid == 0)
        pm_sigkill_child_persist(dir, &onion);

    bool ok = pm_child_died_by_sigkill(pid);
    if (ok)
        ok = pm_reloaded_onion_in_peers(dir, &onion);
    if (ok)
        ok = pm_reloaded_onion_in_anchors(dir, &onion);
    pm_cleanup(dir);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

static int pm_truncated_store_loads_empty(void)
{
    int failures = 0;
    /* ── 4a. a truncated store degrades to empty, never crashes ────────── */
    printf("peer_memory: truncated store loads empty... ");
    struct addr_man am;
    addrman_init(&am);
    struct net_addr src;
    pm_set_ipv4(&src, 5, 5, 5, 5);
    for (int i = 0; i < 6; i++) {
        struct net_address a;
        net_address_init(&a);
        pm_set_onion(&a.svc.addr, (unsigned char)(0x20 + i));
        a.svc.port = (uint16_t)(8033 + i);
        a.nTime = (uint32_t)platform_time_wall_time_t();
        (void)addrman_add(&am, &a, &src, 0);
    }
    struct byte_stream s;
    stream_init(&s, 65536);
    bool ok = addrman_serialize(&am, &s) && s.size > 64;

    /* Cut the body at several points; every prefix must be survivable. */
    for (size_t cut = 1; ok && cut < s.size; cut += (s.size / 17) + 1) {
        size_t loaded = 0;
        ok = pm_load_bytes_survives(s.data, cut, &loaded);
    }
    stream_free(&s);
    addrman_free(&am);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

static int pm_garbage_and_future_versions_load_empty(void)
{
    int failures = 0;
    /* ── 4b. random bytes and a future version number ──────────────────── */
    printf("peer_memory: garbage and future versions load empty... ");
    bool ok = true;
    unsigned char junk[512];
    unsigned int seed = 0x2718u;
    for (int round = 0; ok && round < 24; round++) {
        for (size_t i = 0; i < sizeof(junk); i++) {
            seed = seed * 1103515245u + 12345u;
            junk[i] = (unsigned char)(seed >> 16);
        }
        size_t loaded = 0;
        ok = pm_load_bytes_survives(junk, sizeof(junk), &loaded);
    }
    /* A future-version store has different row widths and is refused
     * whole. */
    if (ok) {
        unsigned char hdr[128];
        memset(hdr, 0, sizeof(hdr));
        hdr[0] = 200;   /* version far beyond anything we can read */
        hdr[1] = 32;
        size_t loaded = 1;
        ok = pm_load_bytes_survives(hdr, sizeof(hdr), &loaded) &&
             loaded == 0;
    }
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

static bool pm_loaded_entries_have_bounded_chance(struct addr_man *am,
                                                 int64_t now)
{
    bool ok = true;
    for (int i = 0; i < am->id_count; i++) {
        if (!am->entries[i].used) continue;
        if (am->entries[i].attempts < 0) ok = false;
        double c = addr_info_get_chance(am, &am->entries[i], now);
        if (!isfinite(c) || c > 1.0) ok = false;
    }
    return ok;
}

static bool pm_bogus_torv3_rows_dropped(void)
{
    bool ok = true;
    const uint8_t bogus_flags[] = { 2, 0xff, 1 };
    for (size_t k = 0; ok && k < sizeof(bogus_flags); k++) {
        struct pm_forged f;
        memset(&f, 0, sizeof(f));
        f.version = 2;
        net_addr_init(&f.addr);      /* all-zero ip AND all-zero torv3 */
        f.addr_flag = bogus_flags[k];
        f.port = 8033;
        struct byte_stream s;
        stream_init(&s, 8192);
        ok = pm_forge_store(&s, &f);
        if (ok) {
            size_t loaded = 1;
            ok = pm_load_bytes_survives(s.data, s.size, &loaded) &&
                 loaded == 0;
        }
        stream_free(&s);
    }
    return ok;
}

static int pm_negative_attempts_cannot_win(void)
{
    int failures = 0;
    /* 4c. The negative-attempts selection bomb is defused: addr_info_get_chance()
     * computes pow(0.66, attempts), so a negative count grows instead of
     * decaying and would win every draw. The value is never trusted on the
     * way in. */
    printf("peer_memory: negative attempts cannot win every draw... ");
    struct addr_info bomb;
    memset(&bomb, 0, sizeof(bomb));
    pm_set_ipv4(&bomb.addr.svc.addr, 198, 51, 100, 4);
    bomb.addr.svc.port = 8033;
    bomb.addr.nTime = (uint32_t)platform_time_wall_time_t();
    bomb.used = true;
    bomb.attempts = -100;

    int64_t now = (int64_t)platform_time_wall_time_t();
    double chance = addr_info_get_chance(NULL, &bomb, now);
    bool ok = isfinite(chance) && chance <= 1.0;

    /* A store carrying that value must not hand it to selection. */
    if (ok) {
        struct pm_forged f;
        memset(&f, 0, sizeof(f));
        f.version = 2;
        pm_set_ipv4(&f.addr, 198, 51, 100, 4);
        f.port = 8033;
        f.last_success = now - 100;
        f.attempts = -1000;
        f.last_try = now - 100;

        struct byte_stream s;
        stream_init(&s, 8192);
        ok = pm_forge_store(&s, &f);
        if (ok) {
            struct addr_man am2;
            addrman_init(&am2);
            struct byte_stream r;
            stream_init_from_data(&r, s.data, s.size);
            if (!addrman_deserialize(&am2, &r))
                addrman_clear(&am2);
            ok = pm_loaded_entries_have_bounded_chance(&am2, now);
            stream_free(&r);
            addrman_free(&am2);
        }
        stream_free(&s);
    }

    /* A torv3 flag that is neither 0 nor 1, or claims an onion identity
     * with an all-zero pubkey, resolves to "not an onion"; with an all-zero
     * ip the row is dropped. */
    if (ok)
        ok = pm_bogus_torv3_rows_dropped();
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

static int pm_legacy_v1_onion_rows_discarded(void)
{
    int failures = 0;
    /* 4d. A legacy v1 onion row (all-zero ip, real port) is discarded rather
     * than resurrected as an undialable endpoint. */
    printf("peer_memory: legacy v1 onion rows are discarded... ");
    /* A version-1 row for an onion peer: all-zero ip, real port. */
    struct pm_forged f;
    memset(&f, 0, sizeof(f));
    f.version = 1;
    net_addr_init(&f.addr);
    f.port = 8033;
    f.last_success = (int64_t)platform_time_wall_time_t();

    struct byte_stream s;
    stream_init(&s, 8192);
    bool ok = pm_forge_store(&s, &f);
    if (ok) {
        struct addr_man am;
        addrman_init(&am);
        struct byte_stream r;
        stream_init_from_data(&r, s.data, s.size);
        /* Parses cleanly (the old format is still readable) AND keeps
         * nothing: the row named no address we could ever dial. */
        ok = addrman_deserialize(&am, &r);
        ok = ok && addrman_size(&am) == 0;
        char err[256];
        ok = ok && addrman_consistency_check(&am, err, sizeof(err)) == 0;
        ok = ok && addrman_index_verify(&am, err, sizeof(err)) == 0;
        stream_free(&r);
        addrman_free(&am);
    }
    stream_free(&s);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

static bool pm_deserialized_onion_is_bucketed(struct addr_man *am,
                                             const struct net_addr *addr)
{
    bool ok = addrman_size(am) == 1;
    /* Present AND dialable: in a bucket, so selection can find it. */
    ok = ok && am->id_count == 1 && am->entries[0].ref_count > 0;
    struct net_service want = { .addr = *addr, .port = 8033 };
    struct addr_info got;
    ok = ok && addrman_find_info(am, &want, &got);
    char err[256];
    ok = ok && addrman_consistency_check(am, err, sizeof(err)) == 0;
    ok = ok && addrman_index_verify(am, err, sizeof(err)) == 0;
    return ok;
}

static bool pm_truncated_bucket_table_keeps_address(void)
{
    struct pm_forged f;
    memset(&f, 0, sizeof(f));
    f.version = 2;
    pm_set_onion(&f.addr, 0xd0);
    f.addr_flag = 1;
    f.port = 8033;
    f.last_success = (int64_t)platform_time_wall_time_t() - 300;

    struct byte_stream s;
    stream_init(&s, 32768);
    bool ok = pm_forge_store(&s, &f);
    if (ok) {
        /* Keep the header and the record, drop most of the table. */
        size_t cut = s.size - 2000;
        struct addr_man am;
        addrman_init(&am);
        struct byte_stream r;
        stream_init_from_data(&r, s.data, cut);
        ok = addrman_deserialize(&am, &r);
        ok = ok && addrman_size(&am) == 1;
        ok = ok && am.id_count == 1 && am.entries[0].ref_count > 0;
        char err[256];
        ok = ok && addrman_consistency_check(&am, err, sizeof(err)) == 0;
        stream_free(&r);
        addrman_free(&am);
    }
    stream_free(&s);
    return ok;
}

static int pm_unusable_bucket_table_keeps_addresses(void)
{
    int failures = 0;
    /* 4e. An unusable bucket-table hint (different geometry, or truncated
     * table) costs the layout, not the peers: addresses are re-bucketed under
     * our own key, and must land in a bucket or they can never be selected. */
    printf("peer_memory: an unusable bucket table keeps the addresses... ");
    bool ok = true;
    const int geometries[] = { 512, 2048, ADDRMAN_NEW_BUCKET_COUNT };
    for (size_t k = 0; ok && k < sizeof(geometries) / sizeof(geometries[0]);
         k++) {
        struct pm_forged f;
        memset(&f, 0, sizeof(f));
        f.version = 2;
        pm_set_onion(&f.addr, 0xc0);
        f.addr_flag = 1;
        f.port = 8033;
        f.last_success = (int64_t)platform_time_wall_time_t() - 300;
        f.bucket_count = geometries[k];

        struct byte_stream s;
        stream_init(&s, 32768);
        ok = pm_forge_store(&s, &f);
        if (ok) {
            struct addr_man am;
            addrman_init(&am);
            struct byte_stream r;
            stream_init_from_data(&r, s.data, s.size);
            ok = addrman_deserialize(&am, &r);
            ok = ok && pm_deserialized_onion_is_bucketed(&am, &f.addr);
            stream_free(&r);
            addrman_free(&am);
        }
        stream_free(&s);
        if (!ok)
            printf("[geometry=%d] ", geometries[k]);
    }

    /* Same claim when the table is cut off partway through. */
    if (ok)
        ok = pm_truncated_bucket_table_keeps_address();
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

static int pm_proven_dead_records_age_out(void)
{
    int failures = 0;
    /* ── 5a. bounded aging: a proven-dead record does not come back ────── */
    printf("peer_memory: proven-dead records age out on reload... ");
    struct addr_man am;
    addrman_init(&am);
    struct net_addr src;
    pm_set_ipv4(&src, 5, 5, 5, 5);
    int64_t now = (int64_t)platform_time_wall_time_t();

    /* dead: never reached, tried past the retry budget */
    struct net_address dead;
    net_address_init(&dead);
    pm_set_onion(&dead.svc.addr, 0x60);
    dead.svc.port = 8033;
    dead.nTime = (uint32_t)now;
    bool ok = addrman_add(&am, &dead, &src, 0);
    for (int i = 0; i < ADDRMAN_RETRIES + 1; i++)
        addrman_attempt(&am, &dead.svc, now - (i * 60));

    /* alive: we connected to it, so it stays no matter the attempts */
    struct net_address alive;
    net_address_init(&alive);
    pm_set_onion(&alive.svc.addr, 0x90);
    alive.svc.port = 8034;
    alive.nTime = (uint32_t)now;
    ok = ok && addrman_add(&am, &alive, &src, 0);
    addrman_good(&am, &alive.svc, now - 60);
    for (int i = 0; i < ADDRMAN_RETRIES + 2; i++)
        addrman_attempt(&am, &alive.svc, now);

    struct addr_man am2;
    ok = ok && pm_roundtrip(&am, &am2);
    if (ok) {
        struct addr_info got;
        ok = !addrman_find_info(&am2, &dead.svc, &got);
        ok = ok && addrman_find_info(&am2, &alive.svc, &got);
        char err[256];
        ok = ok && addrman_consistency_check(&am2, err, sizeof(err)) == 0;
        ok = ok && addrman_index_verify(&am2, err, sizeof(err)) == 0;
        addrman_free(&am2);
    }
    addrman_free(&am);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

static int pm_repeated_failures_lower_dial_chance(void)
{
    int failures = 0;
    /* ── 5b. repeated failure is deprioritised, not retried at full rate ─ */
    printf("peer_memory: repeated failures lower the dial chance... ");
    int64_t now = (int64_t)platform_time_wall_time_t();
    struct addr_info fresh, failing;
    memset(&fresh, 0, sizeof(fresh));
    memset(&failing, 0, sizeof(failing));
    pm_set_ipv4(&fresh.addr.svc.addr, 203, 0, 113, 1);
    pm_set_ipv4(&failing.addr.svc.addr, 203, 0, 113, 2);
    fresh.addr.svc.port = failing.addr.svc.port = 8033;
    fresh.addr.nTime = failing.addr.nTime = (uint32_t)now;
    fresh.used = failing.used = true;
    /* Both last tried long enough ago that the cooldown is not what
     * separates them — only the failure count is. */
    fresh.last_try = failing.last_try = now - 3600;
    fresh.attempts = 0;
    failing.attempts = 6;

    double c_fresh = addr_info_get_chance(NULL, &fresh, now);
    double c_fail = addr_info_get_chance(NULL, &failing, now);
    bool ok = c_fail < c_fresh && c_fail > 0.0 && c_fresh <= 1.0;

    /* And a peer tried moments ago is held off regardless of history —
     * this is the clause that only works because last_try is persisted. */
    struct addr_info justtried = fresh;
    justtried.last_try = now - 5;
    ok = ok && addr_info_get_chance(NULL, &justtried, now) < c_fresh;

    if (ok) printf("OK\n");
    else { printf("FAIL (fresh=%g failing=%g)\n", c_fresh, c_fail); failures++; }
    return failures;
}

static int pm_proven_count_ignores_hearsay(void)
{
    int failures = 0;
    /* 6. proven_count separates measured peers from hearsay. The bootstrap
     * path reads it (not addrman_size(), which counts fixed seeds too) to
     * decide whether it still needs the shipped seed list. */
    printf("peer_memory: proven_count ignores hearsay and seed injections... ");
    struct addr_man am;
    addrman_init(&am);
    struct net_addr src;
    pm_set_ipv4(&src, 5, 5, 5, 5);
    int64_t now = (int64_t)platform_time_wall_time_t();

    /* Routable addresses: addrman_add() refuses the RFC 5737
     * documentation ranges. */
    bool ok = true;
    for (int i = 0; i < 5; i++) {
        struct net_address a;
        net_address_init(&a);
        pm_set_ipv4(&a.svc.addr, 45, 79, 100, (unsigned char)(10 + i));
        a.svc.port = 8033;
        a.nTime = (uint32_t)now;
        ok = ok && addrman_add(&am, &a, &src, 0);
    }
    size_t sz = addrman_size(&am);
    size_t proven_before = addrman_proven_count(&am);
    ok = ok && sz == 5;
    /* Nothing connected to yet: five addresses, zero experience. */
    ok = ok && proven_before == 0;

    struct net_service met;
    net_addr_init(&met.addr);
    pm_set_ipv4(&met.addr, 45, 79, 100, 12);
    met.port = 8033;
    addrman_good(&am, &met, now);
    size_t proven_after = addrman_proven_count(&am);
    ok = ok && proven_after == 1;

    /* The proven count survives a restart. */
    size_t proven_reloaded = 0;
    struct addr_man am2;
    ok = ok && pm_roundtrip(&am, &am2);
    if (ok) {
        proven_reloaded = addrman_proven_count(&am2);
        ok = proven_reloaded == 1;
        addrman_free(&am2);
    }
    addrman_free(&am);
    if (ok) printf("OK\n");
    else {
        printf("FAIL (size=%zu want 5, proven before=%zu want 0, "
               "after=%zu want 1, reloaded=%zu want 1)\n",
               sz, proven_before, proven_after, proven_reloaded);
        failures++;
    }
    return failures;
}

static int pm_anchor_set_comparison_ignores_order(void)
{
    int failures = 0;
    /* 7. anchor-set equivalence is membership, not order: the live node array
     * reorders on every eviction, so an order-sensitive compare would rewrite
     * anchors.dat continuously. */
    printf("peer_memory: anchor set comparison ignores ordering... ");
    struct anchor_peer_set a, b, c;
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    memset(&c, 0, sizeof(c));
    a.count = b.count = c.count = 2;
    pm_set_onion(&a.peers[0].addr, 0x11); a.peers[0].port = 8033;
    pm_set_ipv4(&a.peers[1].addr, 203, 0, 113, 5); a.peers[1].port = 8033;
    /* same two peers, swapped, and with the volatile fields differing */
    b.peers[0] = a.peers[1];
    b.peers[1] = a.peers[0];
    b.peers[0].last_success = 12345;
    b.peers[1].last_height = 999;
    /* a genuinely different set */
    c.peers[0] = a.peers[0];
    pm_set_ipv4(&c.peers[1].addr, 203, 0, 113, 6); c.peers[1].port = 8033;

    bool ok = connman_anchor_sets_equivalent(&a, &b);
    ok = ok && !connman_anchor_sets_equivalent(&a, &c);
    /* a port change is a different endpoint */
    struct anchor_peer_set d = a;
    d.peers[0].port = 9999;
    ok = ok && !connman_anchor_sets_equivalent(&a, &d);
    if (ok) printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    return failures;
}

static int test_peer_memory_platform_arm(void);

static int test_peer_memory_platform_arm(void)
{
    int failures = 0;
    printf("\n=== peer memory tests ===\n");

    failures += pm_onion_peer_roundtrip();

    failures += pm_ranking_fields_roundtrip();

    failures += pm_sigkill_peer_survives();

    failures += pm_truncated_store_loads_empty();

    failures += pm_garbage_and_future_versions_load_empty();

    failures += pm_negative_attempts_cannot_win();

    failures += pm_legacy_v1_onion_rows_discarded();

    failures += pm_unusable_bucket_table_keeps_addresses();

    failures += pm_proven_dead_records_age_out();

    failures += pm_repeated_failures_lower_dial_chance();

    failures += pm_proven_count_ignores_hearsay();

    failures += pm_anchor_set_comparison_ignores_order();

    return failures + ZCL_TEST_SETUP_FAILURES();
}
#else  /* _WIN32 */
/* Windows has no fork()/waitpid process model; this group's forked memory-bound child lane
 * cannot run here. Skipped loudly rather than faked. */
static int test_peer_memory_platform_arm(void)
{
    printf("peer_memory: SKIP (Windows): forked memory-bound child lane\n");
    return 0;
}
#endif

int test_peer_memory(void)
{
    return test_peer_memory_platform_arm();
}
