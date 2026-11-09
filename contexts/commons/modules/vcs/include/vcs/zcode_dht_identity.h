/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Durable local key and delegation files for the ZCODE DHT. */

#ifndef ZCL_VCS_ZCODE_DHT_IDENTITY_H
#define ZCL_VCS_ZCODE_DHT_IDENTITY_H

#include "vcs/zcode_dht_delegation.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_DHT_IDENTITY_DIR "zcode/dht"
#define VCS_ZCODE_DHT_ONLINE_KEY_FILE "online_ed25519.key"
#define VCS_ZCODE_DHT_DELEGATION_FILE "delegation.v1"

enum vcs_zcode_dht_key_probe {
    VCS_DHT_IDENTITY_PROBE_ERROR = 0,
    VCS_DHT_IDENTITY_ABSENT,
    VCS_DHT_IDENTITY_PRESENT,
};
enum vcs_zcode_dht_key_create {
    VCS_DHT_IDENTITY_CREATE_ERROR = 0,
    VCS_DHT_IDENTITY_PREEXISTING,
    VCS_DHT_IDENTITY_CREATED,
};

/* Probe never creates identity material or returns its private seed. Public
 * output is zero on ABSENT or ERROR. */
enum vcs_zcode_dht_key_probe vcs_zcode_dht_online_key_probe(
    const char *datadir, uint8_t pubkey_out[32], char *error_out,
    size_t error_capacity);
/* A competing winner is refused and never returned or adopted. Both outputs
 * are zero on PREEXISTING or ERROR. ERROR can follow publication if the parent
 * durability flush failed; re-probe rather than assuming no file was created. */
enum vcs_zcode_dht_key_create vcs_zcode_dht_online_key_create_if_absent(
    const char *datadir, uint8_t seed_out[32], uint8_t pubkey_out[32],
    char *error_out, size_t error_capacity);
#ifdef ZCL_TESTING
typedef void (*vcs_zcode_dht_create_test_hook)(const char *datadir, void *ctx);
enum vcs_zcode_dht_key_create vcs_zcode_dht_online_key_create_if_absent_test(
    const char *datadir, uint8_t seed_out[32], uint8_t pubkey_out[32],
    char *error_out, size_t error_capacity, vcs_zcode_dht_create_test_hook hook,
    void *ctx);
#endif

/* Load or atomically create the separate online Ed25519 seed (mode 0600).
 * Existing malformed or over-permissive files fail closed and are untouched. */
bool vcs_zcode_dht_online_key_load_or_create(
    const char *datadir, uint8_t seed_out[32], uint8_t pubkey_out[32],
    char *error_out, size_t error_capacity);

/* Load only. Used at node boot so missing identity material disables the DHT
 * without silently provisioning an operator identity. */
bool vcs_zcode_dht_online_key_load(
    const char *datadir, uint8_t seed_out[32], uint8_t pubkey_out[32],
    char *error_out, size_t error_capacity);

/* Atomic delegation publication: temp file, file fsync, rename, directory
 * fsync.  The file contains only the canonical signed public document. */
bool vcs_zcode_dht_delegation_save(
    const char *datadir, const struct vcs_zcode_dht_delegation *delegation,
    char *error_out, size_t error_capacity);

bool vcs_zcode_dht_delegation_load(
    const char *datadir, struct vcs_zcode_dht_delegation *delegation_out,
    char *error_out, size_t error_capacity);

#endif /* ZCL_VCS_ZCODE_DHT_IDENTITY_H */
