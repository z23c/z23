/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for core/modules/net/addrman_integrity.
 *
 * Each case creates a scratch datadir (`./test-tmp/aii_<pid>_*`)
 * containing a synthetic `peers.dat` body, exercises the sidecar
 * lifecycle (write → verify → corrupt → verify → quarantine),
 * and cleans up. All file I/O is local — no network, no SQLite.
 */

#include "test/test_core.h"
#include "net/addrman_integrity.h"
#include "event/event.h"

#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "test/setup_result.h"

#define AII_SCRATCH_ROOT "./test-tmp"

/* ── Event observer ─────────────────────────────────────────── */

static _Atomic int g_ev_corrupt;

static void aii_ev_observer(enum event_type type, uint32_t peer_id,
                             const void *payload, uint32_t payload_len,
                             void *ctx)
{
    (void)peer_id; (void)payload; (void)payload_len; (void)ctx;
    if (type == EV_ADDRMAN_CORRUPT) atomic_fetch_add(&g_ev_corrupt, 1);
}

static void aii_install_observer(void)
{
    event_clear_observers(EV_ADDRMAN_CORRUPT);
    atomic_store(&g_ev_corrupt, 0);
    event_observe(EV_ADDRMAN_CORRUPT, aii_ev_observer, NULL);
}

/* ── Scratch dir + body helpers ─────────────────────────────── */

static void aii_tmp_dir(char *out, size_t cap, const char *tag)
{
    mkdir(AII_SCRATCH_ROOT, 0755);
    snprintf(out, cap, AII_SCRATCH_ROOT "/aii_%d_%s", (int)getpid(), tag);
    mkdir(out, 0755);
}

static bool aii_write_body(const char *dir,
                            const void *data, size_t len)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/peers.dat", dir);
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    size_t n = fwrite(data, 1, len, f);
    fclose(f);
    return n == len;
}

static bool aii_file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

/* Remove everything inside a directory and the directory itself.
 * Handles .corrupt.* quarantine files + sidecar + body. */
static void aii_cleanup(const char *dir)
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

/* ── Byte-level mutation helpers ────────────────────────────── */

/* Overwrite len bytes at offset in an existing file; a no-op when
 * the file cannot be opened. */
static void aii_overwrite_bytes_at(const char *path, long offset,
                                    const void *data, size_t len)
{
    FILE *f = fopen(path, "r+b");
    if (f) {
        fseek(f, offset, SEEK_SET);
        fwrite(data, 1, len, f);
        fclose(f);
    }
}

/* Append a 256-byte zero pad to the end of path; a no-op when the
 * file cannot be opened. */
static void aii_append_zero_pad(const char *path)
{
    FILE *f = fopen(path, "ab");
    if (f) {
        uint8_t pad[256] = {0};
        fwrite(pad, 1, sizeof(pad), f);
        fclose(f);
    }
}

/* True when any entry name in dir contains ".corrupt.". */
static bool aii_dir_has_corrupt_entry(const char *dir)
{
    bool renamed_exists = false;
    DIR *d = opendir(dir);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (strstr(ent->d_name, ".corrupt.")) {
                renamed_exists = true;
                break;
            }
        }
        closedir(d);
    }
    return renamed_exists;
}

/* ── Tests ──────────────────────────────────────────────────── */

/* Case 1: no body file in the datadir. Returns the failure count. */
static int aii_case_body_missing(void)
{
    int failures = 0;
    printf("aii: body missing... ");
    char dir[256]; aii_tmp_dir(dir, sizeof(dir), "body_missing");
    char err[256] = {0};
    enum aii_verdict v = aii_verify(dir, err, sizeof(err));
    bool ok = v == AII_BODY_MISSING;
    aii_cleanup(dir);
    if (ok) printf("OK\n"); else { printf("FAIL (%s)\n", aii_verdict_name(v)); failures++; }
    return failures;
}

/* Case 2: first-run upgrade path (body present, no sidecar). */
static int aii_case_sidecar_missing_accepted(void)
{
    int failures = 0;
    printf("aii: sidecar missing is accepted... ");
    char dir[256]; aii_tmp_dir(dir, sizeof(dir), "side_missing");
    uint8_t body[] = {0xAB, 0xCD, 0xEF, 0x12, 0x34};
    aii_write_body(dir, body, sizeof(body));
    char err[256] = {0};
    enum aii_verdict v = aii_verify(dir, err, sizeof(err));
    bool ok = v == AII_SIDECAR_MISSING;
    aii_cleanup(dir);
    if (ok) printf("OK\n"); else { printf("FAIL (%s)\n", aii_verdict_name(v)); failures++; }
    return failures;
}

/* Case 3: write the sidecar, then verify reports AII_OK. */
static int aii_case_write_and_verify(void)
{
    int failures = 0;
    printf("aii: write sidecar + verify ok... ");
    char dir[256]; aii_tmp_dir(dir, sizeof(dir), "write_ok");
    uint8_t body[4096];
    for (size_t i = 0; i < sizeof(body); i++) body[i] = (uint8_t)(i * 7 + 1);
    aii_write_body(dir, body, sizeof(body));

    bool wrote = aii_write_sidecar(dir).ok;
    char side[1024];
    snprintf(side, sizeof(side), "%s/peers.dat.sha3", dir);
    bool exists = aii_file_exists(side);

    char err[256] = {0};
    enum aii_verdict v = aii_verify(dir, err, sizeof(err));
    bool ok = wrote && exists && v == AII_OK;

    struct stat st;
    if (stat(side, &st) == 0) ok = ok && st.st_size == AII_SIDECAR_BYTES;

    aii_cleanup(dir);
    if (ok) printf("OK\n"); else { printf("FAIL (wrote=%d exists=%d verdict=%s)\n", wrote, exists, aii_verdict_name(v)); failures++; }
    return failures;
}

/* Case 10: repeated sidecar writes are idempotent. */
static int aii_case_overwrite_idempotent(void)
{
    int failures = 0;
    printf("aii: sidecar overwrite is idempotent... ");
    char dir[256]; aii_tmp_dir(dir, sizeof(dir), "rewrite");
    uint8_t body[128];
    for (size_t i = 0; i < sizeof(body); i++) body[i] = (uint8_t)i;
    aii_write_body(dir, body, sizeof(body));

    bool w1 = aii_write_sidecar(dir).ok;
    bool w2 = aii_write_sidecar(dir).ok;
    bool w3 = aii_write_sidecar(dir).ok;
    enum aii_verdict v = aii_verify(dir, NULL, 0);
    bool ok = w1 && w2 && w3 && v == AII_OK;
    aii_cleanup(dir);
    if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    return failures;
}

/* Case 11: the verdict-to-name strings must stay stable. */
static int aii_case_verdict_names(void)
{
    int failures = 0;
    printf("aii: verdict name table stable... ");
    bool ok = true;
    ok = ok && strcmp(aii_verdict_name(AII_OK), "ok") == 0;
    ok = ok && strcmp(aii_verdict_name(AII_HASH_MISMATCH), "hash_mismatch") == 0;
    ok = ok && strcmp(aii_verdict_name(AII_SIDECAR_MISSING), "sidecar_missing") == 0;
    ok = ok && strcmp(aii_verdict_name(AII_BODY_MISSING), "body_missing") == 0;
    ok = ok && strcmp(aii_verdict_name(AII_SIDECAR_STALE), "sidecar_stale") == 0;
    ok = ok && strcmp(aii_verdict_name(AII_SIDECAR_BAD_MAGIC), "sidecar_bad_magic") == 0;
    ok = ok && strcmp(aii_verdict_name(AII_SIDECAR_UNSUPPORTED), "sidecar_unsupported") == 0;
    if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    return failures;
}

int test_addrman_integrity(void);

int test_addrman_integrity(void)
{
    int failures = 0;
    aii_install_observer();

    /* ── 1. body missing ───────────────────────────────────── */
    failures += aii_case_body_missing();

    /* ── 2. sidecar missing (first-run upgrade path) ────────── */
    failures += aii_case_sidecar_missing_accepted();

    /* ── 3. write sidecar + verify OK ──────────────────────── */
    failures += aii_case_write_and_verify();

    /* ── 4. detect byte-level corruption (hash mismatch) ────── */
    printf("aii: detect hash mismatch... ");
    {
        char dir[256]; aii_tmp_dir(dir, sizeof(dir), "hash_mismatch");
        uint8_t body[1024];
        memset(body, 0x5A, sizeof(body));
        aii_write_body(dir, body, sizeof(body));
        ZCL_TEST_SETUP(aii_write_sidecar(dir));

        /* Flip a single byte in the middle. */
        char body_path[1024];
        snprintf(body_path, sizeof(body_path), "%s/peers.dat", dir);
        uint8_t tainted = 0xFF;
        aii_overwrite_bytes_at(body_path, 500, &tainted, 1);

        char err[256] = {0};
        enum aii_verdict v = aii_verify(dir, err, sizeof(err));
        bool ok = v == AII_HASH_MISMATCH;
        bool err_contains = strstr(err, "sha3") != NULL;
        aii_cleanup(dir);
        if (ok && err_contains) printf("OK\n");
        else { printf("FAIL (verdict=%s err=%s)\n", aii_verdict_name(v), err); failures++; }
    }

    /* ── 5. detect truncation (size drift) ──────────────────── */
    printf("aii: detect size drift... ");
    {
        char dir[256]; aii_tmp_dir(dir, sizeof(dir), "size_drift");
        uint8_t body[2048];
        memset(body, 0x11, sizeof(body));
        aii_write_body(dir, body, sizeof(body));
        ZCL_TEST_SETUP(aii_write_sidecar(dir));

        /* Truncate to half its size. */
        char body_path[1024];
        snprintf(body_path, sizeof(body_path), "%s/peers.dat", dir);
 TEST_DISCARD(truncate(body_path, 1024));

        char err[256] = {0};
        enum aii_verdict v = aii_verify(dir, err, sizeof(err));
        bool ok = v == AII_SIDECAR_STALE;
        aii_cleanup(dir);
        if (ok) printf("OK\n"); else { printf("FAIL (%s)\n", aii_verdict_name(v)); failures++; }
    }

    /* ── 6. bad magic ──────────────────────────────────────── */
    printf("aii: detect bad magic... ");
    {
        char dir[256]; aii_tmp_dir(dir, sizeof(dir), "bad_magic");
        uint8_t body[] = "hello world";
        aii_write_body(dir, body, sizeof(body) - 1);
        ZCL_TEST_SETUP(aii_write_sidecar(dir));

        /* Flip the first byte of the sidecar magic. */
        char side[1024];
        snprintf(side, sizeof(side), "%s/peers.dat.sha3", dir);
        uint8_t bogus = 'X';
        aii_overwrite_bytes_at(side, 0, &bogus, 1);

        char err[256] = {0};
        enum aii_verdict v = aii_verify(dir, err, sizeof(err));
        bool ok = v == AII_SIDECAR_BAD_MAGIC;
        aii_cleanup(dir);
        if (ok) printf("OK\n"); else { printf("FAIL (%s)\n", aii_verdict_name(v)); failures++; }
    }

    /* ── 7. unsupported version ─────────────────────────────── */
    printf("aii: detect unsupported version... ");
    {
        char dir[256]; aii_tmp_dir(dir, sizeof(dir), "bad_version");
        uint8_t body[] = "version test";
        aii_write_body(dir, body, sizeof(body) - 1);
        ZCL_TEST_SETUP(aii_write_sidecar(dir));

        char side[1024];
        snprintf(side, sizeof(side), "%s/peers.dat.sha3", dir);
        uint32_t v99 = 99;
        aii_overwrite_bytes_at(side, 4, &v99, sizeof(v99));

        char err[256] = {0};
        enum aii_verdict v = aii_verify(dir, err, sizeof(err));
        bool ok = v == AII_SIDECAR_UNSUPPORTED;
        aii_cleanup(dir);
        if (ok) printf("OK\n"); else { printf("FAIL (%s)\n", aii_verdict_name(v)); failures++; }
    }

    /* ── 8. quarantine renames both files ───────────────────── */
    printf("aii: quarantine renames body + sidecar... ");
    {
        char dir[256]; aii_tmp_dir(dir, sizeof(dir), "quarantine");
        uint8_t body[] = "quarantine me";
        aii_write_body(dir, body, sizeof(body) - 1);
        ZCL_TEST_SETUP(aii_write_sidecar(dir));

        char body_path[1024], side_path[1024];
        snprintf(body_path, sizeof(body_path), "%s/peers.dat", dir);
        snprintf(side_path, sizeof(side_path), "%s/peers.dat.sha3", dir);

        atomic_store(&g_ev_corrupt, 0);
        aii_quarantine_corrupt(dir, AII_HASH_MISMATCH);

        bool body_gone = !aii_file_exists(body_path);
        bool side_gone = !aii_file_exists(side_path);
        bool event_emitted = atomic_load(&g_ev_corrupt) >= 1;

        /* At least one .corrupt.* file must exist now. */
        bool renamed_exists = aii_dir_has_corrupt_entry(dir);

        bool ok = body_gone && side_gone && event_emitted && renamed_exists;
        aii_cleanup(dir);
        if (ok) printf("OK\n");
        else { printf("FAIL (body_gone=%d side_gone=%d evt=%d renamed=%d)\n",
                       body_gone, side_gone, event_emitted, renamed_exists); failures++; }
    }

    /* ── 9. verify detects concurrent body growth ───────────── */
    printf("aii: verify detects body grown past sidecar... ");
    {
        char dir[256]; aii_tmp_dir(dir, sizeof(dir), "grown_body");
        uint8_t body[1024];
        memset(body, 0x22, sizeof(body));
        aii_write_body(dir, body, sizeof(body));
        ZCL_TEST_SETUP(aii_write_sidecar(dir));

        /* Append bytes to body after sidecar was committed. */
        char body_path[1024];
        snprintf(body_path, sizeof(body_path), "%s/peers.dat", dir);
        aii_append_zero_pad(body_path);

        char err[256] = {0};
        enum aii_verdict v = aii_verify(dir, err, sizeof(err));
        bool ok = v == AII_SIDECAR_STALE;
        aii_cleanup(dir);
        if (ok) printf("OK\n"); else { printf("FAIL (%s)\n", aii_verdict_name(v)); failures++; }
    }

    /* ── 10. write sidecar is idempotent ────────────────────── */
    failures += aii_case_overwrite_idempotent();

    /* ── 11. verdict names stable ───────────────────────────── */
    failures += aii_case_verdict_names();

    event_clear_observers(EV_ADDRMAN_CORRUPT);
    return failures + ZCL_TEST_SETUP_FAILURES();
}
