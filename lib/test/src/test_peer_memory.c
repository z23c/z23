/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * PEER MEMORY — a node that has ever met this network must be able to get
 * back on it without contacting a hardcoded seed.
 *
 * Bootstrap used to lean on a tiny shipped onion seed array, and the single
 * onion seed we shipped had been dead for weeks without any node noticing.
 * The structural answer is that a node remembers the peers it actually
 * talked to, keeps them across an unclean stop, and prefers its own measured
 * experience over any list it was handed. These tests hold that answer to
 * account.
 *
 *   1.  An ONION peer survives a peers.dat round-trip, and two distinct
 *       onion peers stay distinct. This is the regression test for the
 *       defect that made the whole store a no-op on a Tor-first network:
 *       format version 1 wrote only ip[16], and net_addr_from_onion() leaves
 *       ip[16] all zero, so every onion peer serialized to the same sixteen
 *       zero bytes and reloaded as an unroutable address.
 *   2.  The ranking fields survive: last_success, last_try, attempts.
 *   3.  A peer learned by a process that is then SIGKILLed is still there
 *       for the next boot — both stores, no graceful shutdown involved.
 *   4.  Hostile input degrades to empty and never crashes: truncated body,
 *       random bytes, a bogus torv3 flag, an oversized version, a legacy v1
 *       onion row, and the negative-attempts entry that would otherwise win
 *       every selection draw.
 *   5.  Bounded aging: a record this node proved dead does not come back,
 *       and a peer that keeps failing is deprioritised rather than re-drawn
 *       at full preference.
 *   6.  addrman_proven_count() counts only addresses we actually connected
 *       to — the input to "do I still need the shipped seed list?".
 *
 * NOT proved here: the full two-node boot leg (node A learns node B over a
 * real socket, A is killed, A reboots with an empty seed array and
 * reconnects). See the header comment on test 3 for exactly where the seam
 * is. All file I/O is local (./test-tmp); no network, no live datadir.
 */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"
#include "net/addrman.h"
#include "net/anchor_peers.h"
#include "net/connman.h"
#include "net/netaddr.h"
#include "core/serialize.h"
#include "test/setup_result.h"

#include <dirent.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>

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
    /* Mirror the node's own contract (connman_load_addrman): a store that
     * fails to parse is DISCARDED, never partially adopted. A half-read table
     * is exactly the state an attacker would want us to keep. */
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
};

static bool pm_forge_store(struct byte_stream *s, const struct pm_forged *f)
{
    unsigned char key[32];
    memset(key, 0xa5, sizeof(key));
    unsigned char zero16[16];
    memset(zero16, 0, sizeof(zero16));
    unsigned char zero32[TORV3_ADDR_SIZE];
    memset(zero32, 0, sizeof(zero32));

    bool ok = stream_write_u8(s, f->version) && stream_write_u8(s, 32) &&
              stream_write_bytes(s, key, 32) &&
              stream_write_i32_le(s, 1) &&              /* nNew   */
              stream_write_i32_le(s, 0) &&              /* nTried */
              stream_write_i32_le(s, 1024 ^ (1 << 30));

    ok = ok && stream_write_bytes(s, f->addr.ip, 16) &&
         stream_write_u16_le(s, f->port) &&
         stream_write_u64_le(s, 1) &&
         stream_write_u32_le(s, (uint32_t)time(NULL)) &&
         stream_write_bytes(s, zero16, 16) &&
         stream_write_i64_le(s, f->last_success) &&
         stream_write_i32_le(s, f->attempts);

    if (ok && f->version >= 2) {
        ok = stream_write_bytes(s, f->addr.torv3, TORV3_ADDR_SIZE) &&
             stream_write_u8(s, f->addr_flag) &&
             stream_write_bytes(s, zero32, TORV3_ADDR_SIZE) && /* source */
             stream_write_u8(s, 0) &&
             stream_write_i64_le(s, f->last_try);
    }
    for (int b = 0; ok && b < 1024; b++)
        ok = stream_write_i32_le(s, 0);
    return ok;
}

int test_peer_memory(void);

int test_peer_memory(void)
{
    int failures = 0;
    printf("\n=== peer memory tests ===\n");

    /* ── 1. an onion peer survives a peers.dat round-trip ──────────────── */
    printf("peer_memory: onion peer survives peers.dat round-trip... ");
    {
        struct addr_man am;
        addrman_init(&am);
        struct net_addr src;
        pm_set_ipv4(&src, 5, 5, 5, 5);

        struct net_address a1, a2;
        net_address_init(&a1);
        pm_set_onion(&a1.svc.addr, 0x11);
        a1.svc.port = 8033;
        a1.nServices = 1;
        a1.nTime = (uint32_t)time(NULL);

        net_address_init(&a2);
        pm_set_onion(&a2.svc.addr, 0x77);
        a2.svc.port = 8034;
        a2.nServices = 1;
        a2.nTime = (uint32_t)time(NULL);

        bool ok = addrman_add(&am, &a1, &src, 0);
        ok = ok && addrman_add(&am, &a2, &src, 0);
        /* Two DISTINCT onion peers in memory — under format version 1 both
         * serialized to the same sixteen zero bytes. */
        ok = ok && addrman_size(&am) == 2;

        struct addr_man am2;
        ok = ok && pm_roundtrip(&am, &am2);
        if (ok) {
            ok = addrman_size(&am2) == 2;

            struct addr_info got;
            struct net_service want1 = { .addr = a1.svc.addr, .port = 8033 };
            struct net_service want2 = { .addr = a2.svc.addr, .port = 8034 };
            /* The exact torv3 pubkey and port must come back, or a reboot
             * cannot dial the peer it remembers. */
            ok = ok && addrman_find_info(&am2, &want1, &got);
            ok = ok && got.addr.svc.addr.has_torv3;
            ok = ok && memcmp(got.addr.svc.addr.torv3, a1.svc.addr.torv3,
                              TORV3_ADDR_SIZE) == 0;
            ok = ok && got.addr.svc.port == 8033;
            ok = ok && addrman_find_info(&am2, &want2, &got);
            ok = ok && memcmp(got.addr.svc.addr.torv3, a2.svc.addr.torv3,
                              TORV3_ADDR_SIZE) == 0;
            addrman_free(&am2);
        }
        addrman_free(&am);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── 2. ranking fields survive the round-trip ──────────────────────── */
    printf("peer_memory: last_success/last_try/attempts survive... ");
    {
        struct addr_man am;
        addrman_init(&am);
        struct net_addr src;
        pm_set_ipv4(&src, 5, 5, 5, 5);

        struct net_address a;
        net_address_init(&a);
        pm_set_onion(&a.svc.addr, 0x33);
        a.svc.port = 8033;
        a.nTime = (uint32_t)time(NULL);

        int64_t t_ok = (int64_t)time(NULL) - 900;   /* connected 15 min ago */
        int64_t t_try = (int64_t)time(NULL) - 120;  /* tried 2 min ago      */

        bool ok = addrman_add(&am, &a, &src, 0);
        addrman_good(&am, &a.svc, t_ok);      /* promotes to the tried table */
        addrman_attempt(&am, &a.svc, t_try);  /* and records a later attempt */

        struct addr_man am2;
        ok = ok && pm_roundtrip(&am, &am2);
        if (ok) {
            struct addr_info got;
            ok = addrman_find_info(&am2, &a.svc, &got);
            /* Without last_try on disk, every entry reloads as "never
             * tried" and the ten-minute cooldown in addr_info_get_chance()
             * is silently dropped at every restart. */
            ok = ok && got.last_success == t_ok;
            ok = ok && got.last_try == t_try;
            ok = ok && got.attempts >= 1;
            addrman_free(&am2);
        }
        addrman_free(&am);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── 3. a SIGKILLed process still leaves its peers behind ──────────
     *
     * The child learns a peer, persists it through the same two stores the
     * node uses (peers.dat and anchors.dat), and is then killed with SIGKILL
     * — no graceful shutdown, no atexit, no flush. The parent reads both
     * files back and must find the onion peer intact.
     *
     * WHAT THIS DOES NOT PROVE: the socket leg. A real node learns the peer
     * from a completed handshake and writes it from the dial-scheduler
     * thread; here the test calls the persistence entry points directly. The
     * store layer and the kill are real; "node A handshakes node B over a
     * socket" is not exercised. */
    printf("peer_memory: peer learned before SIGKILL survives... ");
    {
        char dir[256]; pm_tmp_dir(dir, sizeof(dir), "kill9");
        struct net_addr onion;
        pm_set_onion(&onion, 0x5a);

        pid_t pid = fork();
        if (pid == 0) {
            /* child: learn + persist, then die uncleanly */
            struct addr_man am;
            addrman_init(&am);
            struct net_addr src;
            pm_set_ipv4(&src, 9, 9, 9, 9);
            struct net_address a;
            net_address_init(&a);
            a.svc.addr = onion;
            a.svc.port = 8033;
            a.nTime = (uint32_t)time(NULL);
            if (!addrman_add(&am, &a, &src, 0)) _exit(2);
            addrman_good(&am, &a.svc, (int64_t)time(NULL));
            if (!pm_write_peers_dat(dir, &am)) _exit(3);

            struct anchor_peer_set set;
            memset(&set, 0, sizeof(set));
            set.count = 1;
            set.peers[0].addr = onion;
            set.peers[0].port = 8033;
            set.peers[0].services = 1;
            set.peers[0].last_height = 3117000;
            set.peers[0].last_success = (int64_t)time(NULL);
            if (!anchor_peers_save(dir, &set).ok) _exit(4);

            raise(SIGKILL);
            _exit(5);            /* unreachable */
        }

        bool ok = pid > 0;
        if (ok) {
            int st = 0;
            while (waitpid(pid, &st, 0) < 0 && errno == EINTR) { }
            /* The child must really have died to a SIGKILL, or this test is
             * proving nothing about an unclean stop. */
            ok = WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL;
        }
        if (ok) {
            struct addr_man reloaded;
            ok = pm_read_peers_dat(dir, &reloaded);
            if (ok) {
                struct net_service want = { .addr = onion, .port = 8033 };
                struct addr_info got;
                ok = addrman_find_info(&reloaded, &want, &got) &&
                     got.addr.svc.addr.has_torv3 &&
                     memcmp(got.addr.svc.addr.torv3, onion.torv3,
                            TORV3_ADDR_SIZE) == 0;
                addrman_free(&reloaded);
            }
        }
        if (ok) {
            struct anchor_peer_set back;
            ok = anchor_peers_load(dir, &back) == ANCHOR_LOAD_OK &&
                 back.count == 1 &&
                 net_addr_eq(&back.peers[0].addr, &onion) &&
                 back.peers[0].port == 8033;
        }
        pm_cleanup(dir);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── 4a. a truncated store degrades to empty, never crashes ────────── */
    printf("peer_memory: truncated store loads empty... ");
    {
        struct addr_man am;
        addrman_init(&am);
        struct net_addr src;
        pm_set_ipv4(&src, 5, 5, 5, 5);
        for (int i = 0; i < 6; i++) {
            struct net_address a;
            net_address_init(&a);
            pm_set_onion(&a.svc.addr, (unsigned char)(0x20 + i));
            a.svc.port = (uint16_t)(8033 + i);
            a.nTime = (uint32_t)time(NULL);
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
    }

    /* ── 4b. random bytes and a future version number ──────────────────── */
    printf("peer_memory: garbage and future versions load empty... ");
    {
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
        /* A store written by a future build cannot be parsed record-by-record
         * — its rows are a different width — so it must be refused whole
         * rather than mis-read into plausible-looking addresses. */
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
    }

    /* ── 4c. the negative-attempts selection bomb is defused ───────────
     *
     * addr_info_get_chance() computes pow(0.66, attempts). A negative
     * attempts count turns that decay into growth: at -100 the chance is
     * 0.66^-100, so the entry wins every draw it appears in and outbound
     * selection collapses onto one address. peers.dat records what peers
     * told us, so the value must never be trusted on the way in. */
    printf("peer_memory: negative attempts cannot win every draw... ");
    {
        struct addr_info bomb;
        memset(&bomb, 0, sizeof(bomb));
        pm_set_ipv4(&bomb.addr.svc.addr, 198, 51, 100, 4);
        bomb.addr.svc.port = 8033;
        bomb.addr.nTime = (uint32_t)time(NULL);
        bomb.used = true;
        bomb.attempts = -100;

        int64_t now = (int64_t)time(NULL);
        double chance = addr_info_get_chance(NULL, &bomb, now);
        bool ok = isfinite(chance) && chance <= 1.0;

        /* And a store carrying that value must not hand it to selection. A
         * forged body changes exactly the attempts field, so the load path is
         * what is under test rather than some incidental header damage. */
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
                for (int i = 0; i < am2.id_count; i++) {
                    if (!am2.entries[i].used) continue;
                    if (am2.entries[i].attempts < 0) ok = false;
                    double c = addr_info_get_chance(&am2, &am2.entries[i], now);
                    if (!isfinite(c) || c > 1.0) ok = false;
                }
                stream_free(&r);
                addrman_free(&am2);
            }
            stream_free(&s);
        }

        /* A torv3 flag byte that is neither 0 nor 1, and a flag that claims
         * an onion identity backed by an all-zero pubkey, must both resolve
         * to "not an onion" rather than to a half-built address. Combined
         * with an all-zero ip that leaves nothing dialable, so the row is
         * dropped outright. */
        if (ok) {
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
        }
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    /* ── 4d. a legacy v1 onion row is dropped, not resurrected as junk ──
     *
     * Under format version 1 an onion peer wrote sixteen zero bytes. Reading
     * such a row back as an address would produce an all-zero endpoint with
     * a real port, which the dialer would then try — repeatedly, for every
     * onion peer the old build ever saw. Those rows must be discarded. */
    printf("peer_memory: legacy v1 onion rows are discarded... ");
    {
        /* A version-1 row for an onion peer: all-zero ip, real port. */
        struct pm_forged f;
        memset(&f, 0, sizeof(f));
        f.version = 1;
        net_addr_init(&f.addr);
        f.port = 8033;
        f.last_success = (int64_t)time(NULL);

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
    }

    /* ── 5a. bounded aging: a proven-dead record does not come back ────── */
    printf("peer_memory: proven-dead records age out on reload... ");
    {
        struct addr_man am;
        addrman_init(&am);
        struct net_addr src;
        pm_set_ipv4(&src, 5, 5, 5, 5);
        int64_t now = (int64_t)time(NULL);

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
    }

    /* ── 5b. repeated failure is deprioritised, not retried at full rate ─ */
    printf("peer_memory: repeated failures lower the dial chance... ");
    {
        int64_t now = (int64_t)time(NULL);
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
    }

    /* ── 6. proven_count separates measured peers from hearsay ─────────
     *
     * This is the number the bootstrap path reads to decide whether it still
     * needs the shipped seed list. Table size is the wrong number: the fixed
     * seeds land in addrman on a cold boot and persist there forever, so
     * addrman_size() would report "I remember peers" for a node that has
     * never completed a single connection. */
    printf("peer_memory: proven_count ignores hearsay and seed injections... ");
    {
        struct addr_man am;
        addrman_init(&am);
        struct net_addr src;
        pm_set_ipv4(&src, 5, 5, 5, 5);
        int64_t now = (int64_t)time(NULL);

        /* Routable addresses on purpose: addrman_add() refuses the RFC 5737
         * documentation ranges (192.0.2/24, 198.51.100/24, 203.0.113/24)
         * outright, so a test written with those would add nothing and then
         * "pass" whatever it asserted about an empty table. */
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

        /* And it survives the restart, which is what makes the decision
         * stable across boots rather than resetting to "cold node". */
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
    }

    /* ── 7. anchor-set equivalence is membership, not order ───────────
     *
     * The prompt flush writes anchors.dat whenever the healthy outbound set
     * changes. The live node array reorders on every eviction, so an
     * order-sensitive compare would rewrite the file continuously. */
    printf("peer_memory: anchor set comparison ignores ordering... ");
    {
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
    }

    return failures + ZCL_TEST_SETUP_FAILURES();
}
