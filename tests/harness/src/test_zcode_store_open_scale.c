/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * zcode_store open cost on a long-lived host: the recovery temp sweep must
 * not walk the unbounded package-service event log under <root>/service,
 * must still sweep dead-owner temps in every store directory, and a
 * corrupted CAS object must still be refused (never served) after the
 * cheap reopen. Prints the measured open time so a regression is visible. */

#include "test/test_core.h"

#include "vcs/package_store.h"

#include "test/test_zcode_store_priv.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifndef ZS_SCALE_EVENT_FILES
#define ZS_SCALE_EVENT_FILES 100000u
#endif

static double zs_scale_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static bool zs_scale_touch(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT, 0600);
    if (fd < 0) return false;
    return close(fd) == 0;
}

/* A flat event log like a package host accumulates under <root>/service. */
static bool zs_scale_plant_events(const char *dd, unsigned count)
{
    char dir[512], path[600];
    zs_store_path(dir, sizeof(dir), dd, "service");
    if (mkdir(dir, 0700) != 0) return false;
    zs_store_path(dir, sizeof(dir), dd, "service/events");
    if (mkdir(dir, 0700) != 0) return false;
    for (unsigned i = 0; i < count; i++) {
        snprintf(path, sizeof(path), "%s/%064x", dir, i);
        if (!zs_scale_touch(path)) return false;
    }
    return true;
}

int t_store_open_scale(void)
{
    int failures = 0;
    char dd[256];
    struct vcs_package_store *s =
        zs_open(dd, sizeof(dd), "open-scale", 1000000u);
    ZS_CHECK("open scale: store opens", s != NULL);
    if (!s)
        return failures;

    const char *paths[] = { "source/a.bin" };
    const size_t lens[] = { 600 };
    struct zs_pkg p;
    ZS_CHECK("open scale: fixture builds",
             zs_make_package(&p, 1, paths, lens, 0x4d));
    ZS_CHECK("open scale: package completes",
             vcs_package_store_put_manifest(s, p.wire, p.wire_len, NULL) ==
                     VCS_PACKAGE_STORE_OK &&
                 zs_put_all(s, &p) == VCS_PACKAGE_STORE_OK);
    vcs_package_store_close(s);

    ZS_CHECK("open scale: event log planted",
             zs_scale_plant_events(dd, ZS_SCALE_EVENT_FILES));
    char svc_tmp[512], cas_tmp[512];
    zs_store_path(svc_tmp, sizeof(svc_tmp), dd,
                  "service/events/e.zstmp.2147483647.1");
    zs_store_path(cas_tmp, sizeof(cas_tmp), dd,
                  "cas/dead.zstmp.2147483647.2");
    ZS_CHECK("open scale: temps planted",
             zs_scale_touch(svc_tmp) && zs_scale_touch(cas_tmp));

    double began = zs_scale_now_ms();
    s = vcs_package_store_open(dd, 1000000u);
    double took = zs_scale_now_ms() - began;
    printf("  zcode_store: open scale: reopen with %u event files took "
           "%.1f ms\n", (unsigned)ZS_SCALE_EVENT_FILES, took);
    ZS_CHECK("open scale: store reopens", s != NULL);
    ZS_CHECK("open scale: dead temp in a store directory is still swept",
             !zs_path_exists(cas_tmp));
    ZS_CHECK("open scale: the event log is not walked",
             zs_path_exists(svc_tmp));
    if (!s) {
        zs_free_package(&p);
        return failures;
    }
    uint8_t *got = NULL;
    size_t got_len = 0;
    ZS_CHECK("open scale: intact chunk is served after reopen",
             vcs_package_store_get_chunk(s, p.root, paths[0], 0, &got,
                                         &got_len) == VCS_PACKAGE_STORE_OK &&
                 got_len == lens[0]);
    free(got);
    vcs_package_store_close(s);

    char hash_hex[65], suffix[160], cas_path[512];
    zs_hex32(p.manifest.files[0].chunk_hashes, hash_hex);
    snprintf(suffix, sizeof(suffix), "cas/sha3/%.2s/%s", hash_hex, hash_hex);
    zs_store_path(cas_path, sizeof(cas_path), dd, suffix);
    FILE *f = fopen(cas_path, "r+b");
    ZS_CHECK("open scale: CAS object opens for fault injection", f != NULL);
    if (f) {
        int first = fgetc(f);
        rewind(f);
        bool wrote = first != EOF && fputc(first ^ 0x80, f) != EOF;
        ZS_CHECK("open scale: same-size corruption lands",
                 fclose(f) == 0 && wrote);
    }
    s = vcs_package_store_open(dd, 1000000u);
    ZS_CHECK("open scale: store reopens over corrupt object", s != NULL);
    if (s) {
        got = NULL;
        got_len = 0;
        ZS_CHECK("open scale: corrupt object is refused, never served",
                 vcs_package_store_get_chunk(s, p.root, paths[0], 0, &got,
                                             &got_len) !=
                         VCS_PACKAGE_STORE_OK && got == NULL);
        free(got);
        vcs_package_store_close(s);
    }
    zs_free_package(&p);
    test_rm_rf_recursive(dd);
    return failures;
}
