/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * vcs_object — the sharded content-addressed object store for ZVCS.
 *
 * Objects live at <repo_root>/.zvcs/objects/<2-hex>/<62-hex>, where the
 * 64-hex name is the object id: the SHA3-256 of (domain_tag || content).
 * The tag byte is a domain separator so a blob and a manifest with identical
 * bytes are never confused. Writes are atomic (tmp file, fsync, rename) and
 * idempotent (a put of already-present content is a no-op). Reads ALWAYS
 * recompute the hash and reject a mismatch — recompute, never trust.
 *
 * This store is beside .git/ in the working copy and is NOT a node.db model;
 * it sits below the ActiveRecord lifecycle by design (same doctrine as the
 * progress.kv / seal_kv kernel stores). */

#ifndef ZCL_VCS_OBJECT_H
#define ZCL_VCS_OBJECT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Domain tags — the first byte hashed for every object kind. PERMANENT:
 * once assigned, a tag value is never reused for a different kind. */
enum vcs_object_tag {
    VCS_TAG_BLOB     = 0x20,  /* raw file content */
    VCS_TAG_ENTRY    = 0x21,  /* a single manifest entry (path/mode/size/blob) */
    VCS_TAG_MANIFEST = 0x22,  /* a serialized path-sorted manifest */
    VCS_TAG_COMMIT   = 0x23,  /* a commit preimage (addressed by commit_id) */
    VCS_TAG_SEALSET  = 0x24,  /* the sealed-path set commitment */
    VCS_TAG_ANCHOR   = 0x25,  /* an anchor binding (reserved for later waves) */
    VCS_TAG_DEV_PROOF = 0x26, /* complete dev-cycle proof receipt */
    VCS_TAG_PUBLICATION_JOB = 0x27, /* proof-to-publication job spec */
    VCS_TAG_PUBLICATION_RECEIPT = 0x28, /* append-only scheduler progress */
    VCS_TAG_PACKAGE_BLOB_MAP = 0x29, /* ZVCS blob -> content.v2 chunks */
    VCS_TAG_PACKAGE_MAPPING_SET = 0x2a, /* source/lane mapping inventory */
    VCS_TAG_DEV_MIRROR_RECEIPT = 0x2b, /* optional declared Git mirror */
    VCS_TAG_PUBLICATION_ACK_SET = 0x2c, /* sorted authoritative DHT ACK roots */
};

/* Ensure the object store directory tree exists under <repo_root>/.zvcs/
 * (objects/ and objects/tmp/). Idempotent. Returns false only on a real
 * mkdir error (not EEXIST). */
bool vcs_object_store_init(const char *repo_root);
/* Read-only exact probe for the directory tree created by store_init. */
bool vcs_object_store_initialized(const char *repo_root);

/* Store content[0..len) under tag. Writes out_hash[32] = SHA3(tag||content)
 * on success (even when the object already existed). Atomic + idempotent:
 * an existing object is left untouched and the call succeeds. Returns false
 * on a null arg or any filesystem error. len==0 is valid. */
bool vcs_object_put(const char *repo_root, const uint8_t *content, size_t len,
                    uint8_t tag, uint8_t out_hash[32]);

/* Load the object addressed by hash[32], verifying SHA3(tag||content)==hash
 * before returning. On success allocates *out_content (caller frees with
 * free()) and writes *out_len. Returns 0 on success, -1 on any error
 * (missing object, read error, hash/tag mismatch, allocation failure). */
int vcs_object_get(const char *repo_root, const uint8_t hash[32], uint8_t tag,
                   uint8_t **out_content, size_t *out_len);

/* True iff an object with this id exists on disk. Cheap existence check
 * (no read, no verify). */
bool vcs_object_has(const char *repo_root, const uint8_t hash[32]);

/* Store content at an EXPLICIT 32-byte address (not derived from content).
 * Used for manifests, which are addressed by their structural tree_hash
 * (SHA3 over per-entry hashes) rather than the raw-byte hash. Atomic +
 * idempotent. The caller is responsible for re-deriving and verifying the
 * address on read (see vcs_object_load_raw). Returns false on error. */
bool vcs_object_put_addressed(const char *repo_root, const uint8_t address[32],
                              const uint8_t *content, size_t len);

/* Verified-recovery variants for an exact known address. They preserve an
 * existing byte-identical object and atomically replace only a corrupt object
 * at that same address. The caller supplies the authoritative bytes; the
 * tagged form derives and checks its own address. */
bool vcs_object_put_repair(const char *repo_root, const uint8_t *content,
                           size_t len, uint8_t tag, uint8_t out_hash[32],
                           bool *repaired);
bool vcs_object_put_addressed_repair(const char *repo_root,
                                     const uint8_t address[32],
                                     const uint8_t *content, size_t len,
                                     bool *repaired);

/* Load the raw bytes of the object at address, WITHOUT verifying any hash —
 * the caller MUST verify (e.g. the manifest layer re-derives tree_hash from
 * the parsed content and checks it equals the address). Allocates
 * *out_content (caller frees). Returns 0 on success, -1 on error. */
int vcs_object_load_raw(const char *repo_root, const uint8_t address[32],
                        uint8_t **out_content, size_t *out_len);

/* Same raw addressed read, but rejects from fstat before allocating or reading
 * when the object exceeds maximum_bytes. Returns -2 for that exact bound and
 * -1 for ordinary read/corruption errors. */
int vcs_object_load_raw_bounded(const char *repo_root,
                                const uint8_t address[32],
                                size_t maximum_bytes,
                                uint8_t **out_content, size_t *out_len);

#endif /* ZCL_VCS_OBJECT_H */
