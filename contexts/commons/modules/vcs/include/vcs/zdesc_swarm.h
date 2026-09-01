/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zdesc_swarm — publish and fetch signed onion-service descriptors over
 * the content-addressed swarm. The flagship application of the sovereign
 * identity layer (docs/spec/sovereign-identity-layer.md, "A1"): a
 * service's introduction-point set is a SIGNED DOCUMENT served as
 * content, addressed by a blinded key, verified against a key — not a
 * record handed to a directory authority.
 *
 * WHAT IS NEW HERE: nothing on the wire. A descriptor is a zid_doc
 * (body tag "ZIDD", zid/zdesc.h) carried as a blob (vcs/blob_store.h),
 * which is a one-file content.v2 package on the already-frozen
 * 'zpkgswm' codec. No new message, no new bound, no new store.
 *
 * WHAT THIS BUYS, concretely:
 *   - no HSDir address harvesting: the record is addressed by
 *     zdesc_record_key(master_pubkey, period), so an index of record
 *     keys is not a directory of services. Only someone who already
 *     knows the master key can compute the address.
 *   - rotation is free: a new introduction-point set is a new seq and a
 *     new signature. No transaction, no fee, no re-registration.
 *   - no naming certificate authority: verification is a signature
 *     check against a key, never a vouch from an operator.
 *
 * THE DIRECTORY is a projection, never a second source of truth. It
 * holds, per identity, the current record key and the blob root of the
 * last accepted descriptor — all of it re-derivable from the blob bytes
 * in the store. One entry per master_pubkey: a descriptor is current or
 * it is superseded, and the seq rule (zid_doc_supersedes) decides.
 *
 * PERIOD ADDRESSING, and the consequence a publisher must accept: a
 * record is addressable only at the period it was published in and the
 * one after (the fetch path tries zdesc_period_at(now) and then
 * zdesc_period_prev of it, so a publisher on the other side of midnight
 * is still findable). A service therefore REPUBLISHES each period — the
 * same discipline Tor v3 imposes, and the reason rotation had to be
 * free.
 *
 * ── THE OPEN EDGE, stated plainly ──────────────────────────────────
 * The record_key -> blob_root mapping has no distribution mechanism in
 * this slice. A fetcher can derive the record key and can pull a blob
 * once it knows the root, but learning the root from a stranger needs
 * either a gossip carrier or the chain-anchored identity lookup named
 * in zdesc_swarm.c's CHAIN-BINDING SEAM comment. zdesc_swarm_fetch
 * therefore returns ZDESC_ERR_ABSENT when the record key has no local
 * witness, and says so by name rather than inventing a lookup.
 *
 * ── VERIFICATION STATUS, stated plainly ────────────────────────────
 * Everything here verifies against a CALLER-SUPPLIED master_pubkey. A
 * descriptor accepted by this file is "signed by the key you handed
 * me", NOT "signed by a chain-anchored key". Nothing in this file
 * consults the chain. Do not report a descriptor as chain-verified. */

#ifndef ZCL_VCS_ZDESC_SWARM_H
#define ZCL_VCS_ZDESC_SWARM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zid/zdesc.h"
#include "zid/zid.h"

struct vcs_package_store;
struct vcs_swarm_engine;

/* Identities tracked locally. One entry per master_pubkey. */
#define ZDESC_DIR_MAX 16

struct zdesc_entry {
    bool used;
    uint8_t record_key[32];   /* zdesc_record_key(master_pubkey, period) */
    uint64_t period;
    uint8_t master_pubkey[32];
    uint8_t root[32];         /* blob root of the canonical doc wire */
    struct zid_doc doc;       /* the accepted doc — the seq authority */
    struct zdesc desc;        /* its decoded ZIDD body */
};

struct zdesc_directory {
    struct zdesc_entry e[ZDESC_DIR_MAX];
    size_t count;
};

enum zdesc_result {
    ZDESC_OK = 0,
    ZDESC_ERR_NULL,          /* null argument */
    ZDESC_ERR_ONION,         /* hostname is not a v3 onion */
    ZDESC_ERR_ENCODE,        /* ZIDD body would not encode */
    ZDESC_ERR_SIGN,          /* zdesc_sign refused (bad window / seed) */
    ZDESC_ERR_BLOB,          /* blob put/get refused (named in the log) */
    ZDESC_ERR_ABSENT,        /* no local witness for the record key */
    ZDESC_ERR_DECODE,        /* bytes are not a well-formed zid doc */
    ZDESC_ERR_VERIFY,        /* signature or validity window failed */
    ZDESC_ERR_BODY,          /* doc verified but body is not a ZIDD */
    ZDESC_ERR_KEY_MISMATCH,  /* doc is signed by a different identity */
    ZDESC_ERR_STALE,         /* seq does not supersede what we hold */
    ZDESC_ERR_FULL,          /* directory has no free slot */
    ZDESC_ERR_FETCH,         /* swarm refused the download */
};

const char *zdesc_result_string(enum zdesc_result r);

/* ── directory (a caller-owned projection) ─────────────────────────── */

void zdesc_directory_init(struct zdesc_directory *dir);

/* Find by the blinded record key — the anti-enumeration address. */
bool zdesc_directory_lookup(const struct zdesc_directory *dir,
                            const uint8_t record_key[32],
                            const struct zdesc_entry **out);

/* Find by identity. */
bool zdesc_directory_find(const struct zdesc_directory *dir,
                          const uint8_t master_pubkey[32],
                          const struct zdesc_entry **out);

/* Copy out the service hostnames of every entry still inside its
 * validity window at now_unix (not_before <= now < doc.expiry).
 * Returns how many were written. This is the discovery projection the
 * net layer consumes; it never allocates and never blocks on I/O. */
size_t zdesc_directory_onions(const struct zdesc_directory *dir,
                              uint64_t now_unix,
                              char out[][ZDESC_ONION_LEN + 1], size_t max);

/* The one process-wide directory. Mutating entry points take an
 * internal lock; the accessors above are for caller-owned directories
 * (tests) and for use under zdesc_directory_global_read). */
struct zdesc_directory *zdesc_directory_global(void);

/* Snapshot the global directory's live hostnames. Locked; safe from any
 * thread. */
size_t zdesc_global_onions(uint64_t now_unix,
                           char out[][ZDESC_ONION_LEN + 1], size_t max);

/* ── publish ───────────────────────────────────────────────────────── */

/* Sign `desc` with `seed`, store the canonical doc wire as a blob in
 * `store`, and install the directory entry under
 * zdesc_record_key(pubkey, zdesc_period_at(now_unix)).
 *
 * Monotonic by construction: if the directory already holds a
 * descriptor for this identity, `seq` must strictly exceed it or the
 * call is refused ZDESC_ERR_STALE with NOTHING written to the store.
 * out_root / out_pubkey may be NULL. */
enum zdesc_result zdesc_publish_to(struct vcs_package_store *store,
                                   struct zdesc_directory *dir,
                                   const struct zdesc *desc, uint64_t seq,
                                   uint64_t expiry, const uint8_t seed[32],
                                   uint64_t now_unix, uint8_t out_root[32],
                                   uint8_t out_pubkey[32]);

/* ── accept / fetch ────────────────────────────────────────────────── */

/* Ingest caller-supplied descriptor wire bytes (the shape a post-swarm
 * download uses): verify against `master_pubkey`, enforce the seq rule,
 * and install. The stored root is derived from the CONTENT
 * (vcs_blob_root_of), never from a claim. desc_out may be NULL.
 *
 * Verified against the SUPPLIED key. Not chain-anchored. */
enum zdesc_result zdesc_accept(struct zdesc_directory *dir,
                               const uint8_t master_pubkey[32],
                               const uint8_t *wire, size_t wire_len,
                               uint64_t now_unix, struct zdesc *desc_out);

/* Resolve an identity's current descriptor: derive the record key for
 * zdesc_period_at(now_unix), fall back to the previous period, read the
 * blob back out of `store`, and re-run the full verify pipeline on the
 * bytes that came off disk. Read-only: the directory is not mutated.
 *
 * Verified against the SUPPLIED key. Not chain-anchored. */
enum zdesc_result zdesc_fetch_from(struct vcs_package_store *store,
                                   const struct zdesc_directory *dir,
                                   const uint8_t master_pubkey[32],
                                   uint64_t now_unix, struct zdesc *desc_out);

/* Schedule a swarm download of the identity's descriptor blob. Requires
 * a local witness for the record key -> root mapping (see THE OPEN EDGE
 * above); without one this is ZDESC_ERR_ABSENT, by name. */
enum zdesc_result zdesc_swarm_fetch(struct vcs_swarm_engine *engine,
                                    const struct zdesc_directory *dir,
                                    const uint8_t master_pubkey[32],
                                    int64_t day, uint64_t now_unix);

#endif /* ZCL_VCS_ZDESC_SWARM_H */
