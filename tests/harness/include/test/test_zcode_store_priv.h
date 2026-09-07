/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Private facet shared by the zcode_store test scenario check files
 * (test_zcode_store.c and its test_zcode_store_*.c siblings). The
 * ZS_CHECK macro, the shared package fixture struct, and the fixture
 * helpers below are defined once in test_zcode_store.c; every sibling
 * uses them through this header instead of declaring its own copy. No
 * sibling declares its own file-scope mutable state. */

#ifndef TEST_ZCODE_STORE_PRIV_H
#define TEST_ZCODE_STORE_PRIV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "vcs/package_manifest.h"
#include "vcs/package_store.h"
#include "vcs/package_release.h"
#include "keys/key.h"
#include "keys/pubkey.h"

#define ZS_CHECK(name, expr) do {                                     \
    if (expr) { printf("  zcode_store: %s... OK\n", (name)); }        \
    else { printf("  zcode_store: %s... FAIL\n", (name)); failures++; } \
} while (0)

#define ZS_MAX_FILES 12u
#define ZS_MAX_FILE 1024u

struct zs_pkg {
    struct vcs_package_manifest manifest;
    uint8_t *wire;
    size_t wire_len;
    uint8_t root[32];
    char root_hex[65];
    size_t count;
    char paths[ZS_MAX_FILES][64];
    uint8_t contents[ZS_MAX_FILES][ZS_MAX_FILE];
    size_t lens[ZS_MAX_FILES];
};

/* Fixture helpers, defined in test_zcode_store.c and used by scenarios
 * across more than one sibling file. */
void zs_hex32(const uint8_t in[32], char out[65]);
bool zs_make_package(struct zs_pkg *p, size_t count,
                     const char *const paths[], const size_t lens[],
                     uint8_t seed);
void zs_free_package(struct zs_pkg *p);
size_t zs_raw_wire(uint8_t *out, const char *path, uint32_t mode);
bool zs_path_exists(const char *path);
void zs_store_path(char *out, size_t n, const char *datadir,
                   const char *suffix);
enum vcs_package_store_result zs_put_all(
    struct vcs_package_store *store, const struct zs_pkg *p);
struct vcs_package_store *zs_open(char *datadir, size_t n,
                                  const char *tag, uint64_t quota);
bool zs_keypair(uint8_t seed, struct privkey *sk, struct pubkey *pk);
bool zs_sign(struct vcs_package_release *r, struct privkey *sk);
bool zs_t1(char *out, size_t out_size);
bool zs_release(struct vcs_package_release *r, uint8_t seed,
                uint64_t sequence, const char *name);

/* Scenario group runners — test_zcode_store.c's entry point calls every
 * one of these in order; each lives in the sibling file its scenario
 * names.
 *
 * test_zcode_store_admission.c — flags/layout, manifest admission,
 * chunk flow, dedup, crash recovery, corrupt-read repair, and
 * serialized recovery. */
int t_store_layout_and_flags(void);
int t_store_manifest_admission(void);
int t_store_chunk_flow(void);
int t_store_dedup(void);
int t_store_recovery(void);
int t_store_corrupt_read_repair(void);
int t_store_serialized_recovery(void);

/* test_zcode_store_quota.c — staging pool exhaustion, HOT/RARE
 * eviction, pins, the possession scheduler, and the release envelope. */
int t_store_staging_quota(void);
int t_store_hot_eviction(void);
int t_store_rare_eviction(void);
int t_store_pins(void);
int t_store_possession_scheduler(void);
int t_store_releases(void);

/* test_zcode_store_content.c — blob surface, zcode work output, and
 * exact-cache restore. */
int t_store_blob(void);
int t_store_work_output(void);
int t_store_exact_cache_restore(void);

#endif
