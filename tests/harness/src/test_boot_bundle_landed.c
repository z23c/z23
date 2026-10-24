/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_boot_bundle_landed — the warm-boot path of the bundle fetch
 * (engine/composition/src/boot_bundle_fetch_landed.c).
 *
 * Pins, on a local fixture (never a real datadir):
 *   (a) boot_bundle_fetch_download of an already-landed bundle returns before
 *       the rom_seed registration ran (the registration is held on a latch),
 *       and registers only after the latch releases;
 *   (b) a verified stamp is recorded and lets the next boot skip the hash;
 *   (c) a bundle corrupted after the stamp (same size, mtime and inode) is
 *       never registered: the manifest's whole-file digest refuses it;
 *   (d) a corrupted bundle with no stamp fails the full verify and is never
 *       registered.
 */

#include "test/test_core.h"

#include "config/boot_bundle_fetch.h"
#include "net/rom_fetch.h"
#include "net/rom_seed.h"
#include "platform/time_compat.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define BL_NAME "consensus-state-bundle-3056758.sqlite"

static void bl_fill(uint8_t *buf, size_t size)
{
    static const uint8_t magic[16] = "SQLite format 3";
    for (size_t i = 0; i < size; i++)
        buf[i] = (uint8_t)((i * 131u + 7u) & 0xffu);
    if (size >= 16)
        memcpy(buf, magic, 16);
}

static bool bl_write(const char *path, const uint8_t *buf, size_t size)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return false;
    bool ok = write(fd, buf, size) == (ssize_t)size;
    close(fd);
    return ok;
}

static bool bl_registered(void)
{
    struct rom_artifact cat[ROM_SEED_MAX_ARTIFACTS];
    int cn = rom_seed_list(cat, ROM_SEED_MAX_ARTIFACTS);
    for (int i = 0; i < cn; i++)
        if (strstr(cat[i].filename, BL_NAME) != NULL)
            return true;
    return false;
}

/* Land `size` bytes of fixture as <dir>/bundles/<name>; fill `m` from it. */
static bool bl_fixture(const char *dir, size_t size,
                       struct rom_fetch_manifest *m, uint8_t **content)
{
    char b[PATH_MAX], p[PATH_MAX];
    snprintf(b, sizeof(b), "%s/bundles", dir);
    snprintf(p, sizeof(p), "%s/%s", b, BL_NAME);
    *content = malloc(size);
    if (!*content || mkdir(b, 0700) != 0)
        return false;
    bl_fill(*content, size);
    if (!bl_write(p, *content, size))
        return false;
    struct rom_artifact art;
    if (rom_seed_register(dir, "bundles/" BL_NAME, NULL, &art) != ROM_REG_OK)
        return false;
    rom_seed_reset();
    memset(m, 0, sizeof(*m));
    m->used = true;
    snprintf(m->filename, sizeof(m->filename), "%s", BL_NAME);
    m->size_bytes = art.size_bytes;
    m->chunk_size = ROM_SEED_CHUNK_SIZE;
    m->num_chunks = art.num_chunks;
    memcpy(m->chunk_root, art.chunk_root, 32);
    memcpy(m->whole_sha3, art.whole_sha3, 32);
    m->kind = art.kind;
    return true;
}

static struct rom_fetch_peer bl_dead_peer(void)
{
    struct rom_fetch_peer p;
    memset(&p, 0, sizeof(p));
    snprintf(p.addr, sizeof(p.addr), "%s", "127.0.0.1");
    p.port = 1;
    return p;
}

static int bl_case_offpath_and_stamp(void)
{
    int failures = 0;
    TEST("boot_bundle_landed: warm call returns before registration; stamp "
         "recorded; registration only after release") {
        rom_seed_reset();
        char root[PATH_MAX];
        char *dir = test_mkdtemp(root, sizeof(root), "zcl_bbl_a");
        ASSERT(dir != NULL);
        struct rom_fetch_manifest m;
        uint8_t *content = NULL;
        ASSERT(bl_fixture(dir, (size_t)ROM_SEED_CHUNK_SIZE + 4096, &m,
                          &content));
        struct rom_fetch_peer dead = bl_dead_peer();
        boot_bundle_fetch_reseed_test_hold(true);
        ASSERT(boot_bundle_fetch_download(dir, &dead, 1, &m));
        ASSERT(!bl_registered()); /* returned, still unserved */
        char stamp[PATH_MAX + 16];
        snprintf(stamp, sizeof(stamp), "%s/bundles/%s.verified", dir, BL_NAME);
        struct stat sst;
        ASSERT(stat(stamp, &sst) == 0);
        boot_bundle_fetch_reseed_test_hold(false);
        boot_bundle_fetch_reseed_wait();
        ASSERT(bl_registered());

        /* (c) corrupt after the stamp, size/mtime/inode preserved. */
        rom_seed_reset();
        char p[PATH_MAX];
        snprintf(p, sizeof(p), "%s/bundles/%s", dir, BL_NAME);
        struct stat st;
        ASSERT(stat(p, &st) == 0);
        int fd = open(p, O_WRONLY);
        ASSERT(fd >= 0);
        uint8_t flip = (uint8_t)(content[1000] ^ 0x01);
        ASSERT(pwrite(fd, &flip, 1, 1000) == 1);
        close(fd);
        struct timespec ts[2] = { st.st_atim, st.st_mtim };
        ASSERT(utimensat(AT_FDCWD, p, ts, 0) == 0);
        ASSERT(boot_bundle_fetch_download(dir, &dead, 1, &m)); /* stamp hit */
        boot_bundle_fetch_reseed_wait();
        ASSERT(!bl_registered()); /* whole-file digest refused it */

        free(content);
        test_rm_rf_recursive(dir);
        rom_seed_reset();
    } _test_next:;
    return failures;
}

static int bl_case_corrupt_unstamped(void)
{
    int failures = 0;
    TEST("boot_bundle_landed: a corrupted unstamped bundle is never registered") {
        rom_seed_reset();
        char root[PATH_MAX];
        char *dir = test_mkdtemp(root, sizeof(root), "zcl_bbl_b");
        ASSERT(dir != NULL);
        struct rom_fetch_manifest m;
        uint8_t *content = NULL;
        ASSERT(bl_fixture(dir, (size_t)ROM_SEED_CHUNK_SIZE + 4096, &m,
                          &content));
        char p[PATH_MAX];
        snprintf(p, sizeof(p), "%s/bundles/%s", dir, BL_NAME);
        content[2000] ^= 0x01;
        ASSERT(bl_write(p, content, (size_t)m.size_bytes));
        struct rom_fetch_peer dead = bl_dead_peer();
        ASSERT(!boot_bundle_fetch_download(dir, &dead, 1, &m));
        boot_bundle_fetch_reseed_wait();
        ASSERT(!bl_registered());
        free(content);
        test_rm_rf_recursive(dir);
        rom_seed_reset();
    } _test_next:;
    return failures;
}

int test_boot_bundle_landed(void)
{
    int failures = 0;
    failures += bl_case_offpath_and_stamp();
    failures += bl_case_corrupt_unstamped();
    return failures;
}
