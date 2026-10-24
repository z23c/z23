/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: file and encoding helpers shared by the plugin store sources. */
#ifndef ZCL_PLUGIN_INTERNAL_H
#define ZCL_PLUGIN_INTERNAL_H

#include "plugin/plugin_pack.h"
#include "plugin/plugin_store.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    PLUGIN_PATH_MAX = 4096,
    PLUGIN_FILE_MAX = 65536,
    PLUGIN_DIGEST_BYTES = 64
};

bool plugin_name_valid(const char *name);
bool plugin_version_valid(const char *version);

/* SHA3-512 of "z23.plugin.manifest.v1", one NUL and the manifest bytes: the
 * message that is signed. */
void plugin_manifest_digest(const char *manifest, size_t len,
                            uint8_t digest[PLUGIN_DIGEST_BYTES]);

/* Read a regular signing key of exactly PLUGIN_KEY_FILE_BYTES. POSIX requires
 * current-user ownership and no group/other access; Windows requires a
 * protected owner+SYSTEM-only ACL and a retained owner-private parent. */
enum plugin_status plugin_key_load(const char *path,
                                   uint8_t seed[PLUGIN_KEY_FILE_BYTES]);
void plugin_key_public(const uint8_t seed[PLUGIN_KEY_FILE_BYTES],
                       uint8_t pk[32]);
/* True for exactly len lowercase hex characters (len even, at most 128). */
bool plugin_hex_valid(const char *hex, size_t len);

enum { PLUGIN_OPEN_NOFOLLOW = 1, PLUGIN_OPEN_OWNER_ONLY = 2 };

/* Open a regular file read-only. NOFOLLOW refuses a symbolic link; OWNER_ONLY
 * requires the file to belong to the effective user and not be group or world
 * writable. Windows OWNER_ONLY requires a protected owner+SYSTEM-only file ACL
 * and a retained private parent; reparse points are refused. A security refusal
 * returns -1 with errno EPERM or ELOOP. */
int plugin_open_read(const char *path, unsigned flags);

/* Read a whole file of at most max bytes into a NUL-terminated heap buffer.
 * Returns false on error (errno set); too large sets errno to EFBIG. */
bool plugin_read_file(const char *path, size_t max, unsigned flags,
                      char **out, size_t *len);

/* SHA3-512 of a file opened with plugin_open_read flags. */
enum plugin_status plugin_hash_path(const char *path, unsigned flags,
                                    char hex[PLUGIN_HEX_SHA3_512 + 1]);

/* Copy src to an exclusive destination, hashing the written bytes. POSIX uses
 * mode; Windows creates a private file under a retained private parent. */
enum plugin_status plugin_copy_file(const char *src, const char *dst,
                                    unsigned mode,
                                    char hex[PLUGIN_HEX_SHA3_512 + 1]);

/* Validate a real directory: POSIX requires current-user ownership and no
 * group/other writes; Windows requires the protected owner+SYSTEM-only ACL.
 * Missing is PLUGIN_ERR_NOT_INSTALLED,
 * anything else wrong is PLUGIN_ERR_KEYS_INSECURE. */
enum plugin_status plugin_check_dir(const char *path);

/* Apply the platform directory durability barrier to a validated directory. */
bool plugin_fsync_dir(const char *path);

bool plugin_mkdirs(const char *path);

/* Write data to path through an exclusive sibling file and a rename, so a
 * reader never sees a partial file. Used by plugin_pack and plugin_attest. */
bool plugin_write_atomic(const char *path, const char *data, size_t len);

/* SHA3-512 of domain (domain_len bytes, include the NUL when the tag is a C
 * string), then data. The one domain-separated digest the manifest signature
 * and the builder attestation share. Never truncates. */
void plugin_domain_digest(const unsigned char *domain, size_t domain_len,
                          const void *data, size_t len,
                          uint8_t out[PLUGIN_DIGEST_BYTES]);

/* Per-plugin mutation lock (plugdir/.lock, plus the waiter gate
 * plugdir/.lock.q that keeps a returning holder from starving a waiter) held
 * across the whole read-verify-modify of install, switch and rollback. Waits
 * until a monotonic deadline PLUGIN_LOCK_WAIT_MS after the call that restarts each
 * time the lock changes hands, then refuses PLUGIN_ERR_BUSY. Readers never take it. A leftover unlocked .lock.q is
 * harmless. */
enum { PLUGIN_LOCK_WAIT_MS = 5000 };
struct plugin_lock {
    int fd;
};
enum plugin_status plugin_lock_acquire(const char *plugdir, struct plugin_lock *lock);
void plugin_lock_release(struct plugin_lock *lock);
#ifdef ZCL_TESTING
/* Test seam: override the lock wait budget and add a pause inside every hold,
 * modelling a loaded host where holds are long against the budget. A budget
 * <= 0 restores PLUGIN_LOCK_WAIT_MS; a pause <= 0 removes the pause. */
void plugin_lock_test_timing(int64_t budget_ms, int64_t hold_pause_ms);
#endif
/* Create one new owner-private directory; false if it exists. */
bool plugin_mkdir_new(const char *path);
bool plugin_join(char *out, size_t cap, const char *a, const char *b,
                 const char *c, const char *d);
bool plugin_remove_tree(const char *path);

/* Parse a POSIX generation symlink or exact Windows private pointer file. */
bool plugin_link_generation(const char *dir, const char *link,
                            char hex[PLUGIN_HEX_SHA3_512 + 1]);

/* As plugin_link_generation, and says why a slot did not read: missing,
 * corrupt (invalid platform generation pointer) or unreadable
 * (any other failure). hex is written only for PLUGIN_SLOT_OK. */
enum plugin_slot_state plugin_link_slot(const char *dir, const char *link,
                                        char hex[PLUGIN_HEX_SHA3_512 + 1]);

/* Verify a stored generation directory against the publisher key file. */
enum plugin_status plugin_verify_generation(const char *root, const char *name,
                                            const char *generation);

/* As plugin_verify_generation, and returns the manifest whose signature was
 * verified, so a caller binds to the signed fields and not to a second read. */
enum plugin_status plugin_verify_generation_manifest(const char *root,
                                                     const char *name,
                                                     const char *generation,
                                                     struct plugin_manifest *out);

/* Read the publisher key file once, no-follow and owner-only, into a heap buffer the
 * caller frees. Failures map as plugin_verify_manifest maps them. */
enum plugin_status plugin_keys_load(const char *path, char **bytes, size_t *len);

/* As plugin_verify_manifest, against key bytes the caller already holds, so
 * the decision and anything the caller remembers about it share one read. */
enum plugin_status plugin_verify_manifest_keys(const char *manifest, size_t manifest_len,
                                                const char *sig, size_t sig_len,
                                                const char *keys, size_t keys_len,
                                                struct plugin_manifest *out);

/* The store root, the plugin directory, its generations directory and the
 * generation directory must each be a real directory owned by the user and
 * closed to group and others. Needs no key list and reads no file. */
enum plugin_status plugin_check_generation_dirs(const char *root, const char *name,
                                                const char *generation);

/* As plugin_verify_generation_manifest, verifying under key bytes the caller
 * already read with plugin_keys_load. */
enum plugin_status plugin_verify_generation_manifest_keys(const char *root,
                                                           const char *name,
                                                           const char *generation,
                                                           const char *keys,
                                                           size_t keys_len,
                                                           struct plugin_manifest *out);

#endif
