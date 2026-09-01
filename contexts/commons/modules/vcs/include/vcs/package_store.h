/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_store — the node's local content-addressed ZCODE package store
 * (slice 2: LOCAL STORE ONLY — no P2P, no RPC spend, no reward credit).
 * Hosting is disabled by default and gated on -packagehost=1; the store
 * never compiles, executes, installs, or publishes what it holds.
 *
 * Layout under <datadir>/zcode/:
 *   manifests/<root-hex>        committed content.v2 manifest wire; the
 *                               package's existence record
 *   releases/<release-id-hex>   accepted signed release envelope wire
 *   recipes/<recipe-root-hex>   validated declarative build recipe wire
 *                               (slice 5; committed by the envelope's
 *                               recipe_root)
 *   attestations/<id-hex>       signed external-verifier attestation wire
 *                               (slice 6; committed by zclassic23-package-verify)
 *   badges/                     created empty; a later slice fills it
 *   cas/sha3/<hh>/<hash-hex>    verified chunk bytes, named by SHA3-256
 *                               (<hh> is the hash's first byte, hex)
 *   staging/<root-hex>/manifest in-flight manifest, not yet complete
 *   pins/<root-hex>             zero-byte operator pin marker
 * Every committed file is written to <dest>.zstmp.<pid>.<seq> beside its
 * destination, fsynced, then atomically renamed (the contexts/commons/modules/vcs revert
 * convention). A leftover temp is never a valid object.
 *
 * Verify-before-store: a chunk is written only after its SHA3-256 equals
 * the hash committed at those exact manifest coordinates. Identical chunk
 * content is stored once (dedup by hash). A package is COMPLETE exactly
 * when every chunk hash of its manifest is present in the CAS — completion
 * is a pure function of CAS state, never a marker, so it is rebuilt from
 * the CAS after any crash. Only complete packages count as hosted content;
 * unverified bytes and incomplete packages earn no hosting credit.
 *
 * Crash recovery — RESUMABLE staging (documented choice): at open the
 * store serializes recovery/GC against manifest and CAS transactions with
 * an exact-root process lock. A one-shot observer therefore cannot snapshot
 * "no manifest" and delete chunks the resident writes moments later. Then
 * the store
 * (1) deletes leftover *.zstmp.* temps, (2) reloads committed and
 * staged manifests (a staged manifest that fails to parse is discarded
 * with its staging dir, logged), (3) deletes CAS objects no loaded
 * manifest references (orphan GC; also non-hex filenames), then (4)
 * commits any staged package the CAS already completes, in ascending
 * root-hex order. Work in flight survives a crash; torn writes never do.
 *
 * Quota pools (-packagequota bytes, default 10 GiB; frozen fractions):
 *   PINS     20%  operator-pinned packages — NEVER evicted
 *   HOT      40%  complete, verified, frequently-requested
 *   RARE     30%  complete, verified, few observed replicas
 *   STAGING  10%  incomplete (in-flight), unpinned packages
 * Pool assignment: pinned -> PINS; incomplete -> STAGING; complete -> its
 * class pool. New packages start RARE (no observed demand or replication
 * yet); promotion is explicit via vcs_package_store_set_class(). A
 * package's charge is its present unique-chunk bytes, counted per package:
 * a chunk shared by N packages charges all N (conservative — the pools
 * together may over-count real disk usage, never under-count it). Quota is
 * enforced BEFORE new bytes are accepted: a put that would exceed its
 * pool first tries deterministic eviction (HOT/RARE only), then fails
 * VCS_PACKAGE_STORE_ERR_QUOTA. STAGING and PINS never evict — full is
 * full; in-flight work is never auto-discarded. The chunk that completes
 * a package is charged against the pool the package moves INTO (the whole
 * package's bytes move with it), so a completion that cannot fit fails
 * before the byte is stored and the package stays incomplete.
 *
 * Deterministic eviction order (victims never include the incoming or a
 * pinned package):
 *   HOT  — smallest access_count, then smallest last_access, then
 *          ascending root hex (least-recently-requested first);
 *   RARE — LARGEST replicas first (best-replicated elsewhere is safest
 *          to drop locally), then smallest access_count, then ascending
 *          root hex.
 * Eviction deletes the victim's manifest and its CAS chunks no other
 * tracked package references.
 *
 * v1 per-package cap: 64 MiB (VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES).
 *
 * Release envelopes (slice 1) are admitted through the node-bound
 * acceptance layer: the store owns one in-memory vcs_package_accept
 * context; an envelope is persisted only when acceptance returns OK or
 * DUPLICATE (idempotent redelivery). Acceptance cursors are in-memory by
 * design, so they replay fresh across restarts; stored envelopes are
 * keyed by release id and writes are idempotent.
 *
 * Package file paths are validated by the manifest grammar itself
 * (vcs_package_path_valid rejects dot/dot-dot segments, backslashes,
 * drive letters, and every non-regular-file mode including symlinks);
 * the store only ever writes beneath cas/, manifests/, staging/, and
 * pins/ at names it computes from hashes, so a package path can never
 * become a filesystem path. */

#ifndef ZCL_VCS_PACKAGE_STORE_H
#define ZCL_VCS_PACKAGE_STORE_H

#include "vcs/package_accept.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES UINT64_C(10737418240) /* 10 GiB */
#define VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES (UINT64_C(64) * 1024u * 1024u)
#define VCS_PACKAGE_STORE_MAX_TRACKED 4096u

/* Frozen pool fractions of the total quota (tenths). */
#define VCS_PACKAGE_STORE_PINS_TENTHS 2u
#define VCS_PACKAGE_STORE_HOT_TENTHS 4u
#define VCS_PACKAGE_STORE_RARE_TENTHS 3u
#define VCS_PACKAGE_STORE_STAGING_TENTHS 1u

enum vcs_package_store_result {
    VCS_PACKAGE_STORE_OK = 0,
    VCS_PACKAGE_STORE_ERR_NULL,        /* null argument */
    VCS_PACKAGE_STORE_ERR_IO,          /* filesystem failure (logged) */
    VCS_PACKAGE_STORE_ERR_MANIFEST,    /* manifest grammar/parse failure */
    VCS_PACKAGE_STORE_ERR_PACKAGE_CAP, /* package exceeds the 64 MiB cap */
    VCS_PACKAGE_STORE_ERR_CHUNK_HASH,  /* chunk bytes != committed hash */
    VCS_PACKAGE_STORE_ERR_CHUNK_COORD, /* path/index not in the manifest */
    VCS_PACKAGE_STORE_ERR_CHUNK_MISSING, /* valid coords, chunk absent */
    VCS_PACKAGE_STORE_ERR_UNKNOWN_PACKAGE, /* root not tracked */
    VCS_PACKAGE_STORE_ERR_QUOTA,       /* pool full, no eviction victim */
    VCS_PACKAGE_STORE_ERR_ACCEPT,      /* release failed acceptance */
    VCS_PACKAGE_STORE_ERR_ALLOC,       /* allocation failed */
    VCS_PACKAGE_STORE_ERR_LIMIT,       /* tracked-package bound reached */
    VCS_PACKAGE_STORE_ERR_RECIPE,      /* recipe grammar/parse failure */
};

enum vcs_package_store_class {
    VCS_PACKAGE_STORE_CLASS_HOT = 0, /* frequently requested */
    VCS_PACKAGE_STORE_CLASS_RARE,    /* few observed replicas (default) */
};

enum vcs_package_store_pool {
    VCS_PACKAGE_STORE_POOL_PINS = 0,
    VCS_PACKAGE_STORE_POOL_HOT,
    VCS_PACKAGE_STORE_POOL_RARE,
    VCS_PACKAGE_STORE_POOL_STAGING,
};

struct vcs_package_store; /* opaque */

struct vcs_package_store_status {
    bool tracked;
    bool pinned;
    bool complete;
    enum vcs_package_store_class class_;
    enum vcs_package_store_pool pool;
    uint32_t replicas;
    uint64_t access_count;
    uint64_t present_bytes;   /* unique-in-package chunk bytes in the CAS */
    uint64_t total_bytes;     /* manifest total */
    uint32_t present_chunks;  /* unique-in-package chunks present */
    uint32_t total_chunks;    /* unique-in-package chunks committed */
    uint64_t mutation_generation; /* changes on byte/completion/pin mutation */
};

enum vcs_package_possession_failure {
    VCS_PACKAGE_POSSESSION_NONE = 0,
    VCS_PACKAGE_POSSESSION_UNTRACKED,
    VCS_PACKAGE_POSSESSION_INCOMPLETE,
    VCS_PACKAGE_POSSESSION_UNPINNED,
    VCS_PACKAGE_POSSESSION_MANIFEST,
    VCS_PACKAGE_POSSESSION_CHUNK_MISSING,
    VCS_PACKAGE_POSSESSION_CHUNK_HASH,
    VCS_PACKAGE_POSSESSION_MUTATED,
    VCS_PACKAGE_POSSESSION_ALLOC,
};

enum vcs_package_possession_step {
    VCS_PACKAGE_POSSESSION_PROGRESS = 0,
    VCS_PACKAGE_POSSESSION_BUDGET,
    VCS_PACKAGE_POSSESSION_SUCCESS,
    VCS_PACKAGE_POSSESSION_FAILED,
};

struct vcs_package_possession_receipt {
    uint64_t mutation_generation;
    uint64_t bytes_verified;
    uint32_t chunks_verified;
    bool complete;
    bool pinned;
    enum vcs_package_possession_failure failure;
};

struct vcs_package_possession_proof; /* opaque, one in-progress proof */

const char *vcs_package_store_result_string(
    enum vcs_package_store_result result);
const char *vcs_package_store_pool_string(enum vcs_package_store_pool pool);

/* Flag accessors: -packagehost=0|1 (default 0, hosting off) and
 * -packagequota=<bytes> (default 10 GiB; a negative value means the
 * default, zero means a store that accepts nothing). */
bool vcs_package_store_hosting_enabled(void);
uint64_t vcs_package_store_quota_bytes(void);

/* Open (creating + recovering) the store beneath <datadir>/zcode with the
 * given quota, or close it. Open runs the full crash recovery described
 * above; returns NULL on I/O or allocation failure (logged). */
struct vcs_package_store *vcs_package_store_open(const char *datadir,
                                                 uint64_t quota_bytes);
void vcs_package_store_close(struct vcs_package_store *store);

/* The directory this handle owns, exactly as it was built: "<datadir>/zcode".
 * A caller that must decide whether the resident store already covers the
 * datadir it was handed compares against this rather than guessing. */
const char *vcs_package_store_root_dir(const struct vcs_package_store *store);

/* Bind a pin/unpin plan token to the pin-relevant package facts observed
 * under the store's in-process lock: root, desired pin, current pin,
 * tracked, complete, and pool. Access counts and replica counters are not
 * in the token, so a concurrent read cannot stale a pin commit. False means
 * the root is not tracked. Shared by the resident RPC and the offline
 * native fallback so plan/commit cannot drift. */
bool vcs_package_store_pin_plan(
    struct vcs_package_store *store, const uint8_t root[32], bool pinned,
    struct vcs_package_store_status *status_out, uint8_t token_out[32]);

/* The node-global instance: open_global reads the flags and GetDataDir
 * (base, not network-specific — content is chain-agnostic; chain binding
 * happens at release acceptance) and is a no-op returning false when
 * hosting is disabled. */
bool vcs_package_store_open_global(void);
struct vcs_package_store *vcs_package_store_global(void);
void vcs_package_store_close_global(void);

/* Admit a content.v2 manifest wire. Parses and validates it, enforces the
 * 64 MiB package cap and the tracked-package bound, computes the package
 * root into root_out (when non-NULL), and stages it atomically. A package
 * whose chunks are all already in the CAS (full dedup hit) commits
 * immediately. Re-admitting an identical manifest is an idempotent OK. */
enum vcs_package_store_result vcs_package_store_put_manifest(
    struct vcs_package_store *store, const uint8_t *wire, size_t wire_len,
    uint8_t root_out[32]);

/* Admit one chunk for a tracked package at exact manifest coordinates.
 * The SHA3-256 of the bytes must equal the hash committed there; only
 * then is it stored (dedup by hash) — never before. Enforces the pool
 * quota (with eviction) before accepting new bytes and runs the
 * completion commit sweep afterwards. */
enum vcs_package_store_result vcs_package_store_put_chunk(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const char *path, uint32_t chunk_index, const uint8_t *chunk,
    size_t chunk_len);

/* Read one chunk back (allocates *out; caller frees). The CAS bytes are
 * re-hashed before return. A missing or corrupt object is removed from the
 * presence index so a swarm fetch can repair the coordinate; corrupt bytes
 * return VCS_PACKAGE_STORE_ERR_CHUNK_HASH. A successful read counts as a
 * logical access: it bumps the package's access_count/last_access, the
 * "frequently-requested" signal the HOT pool evicts by. */
enum vcs_package_store_result vcs_package_store_get_chunk(
    struct vcs_package_store *store, const uint8_t package_root[32],
    const char *path, uint32_t chunk_index, uint8_t **out, size_t *out_len);

/* Slice 12 (package swarm) index-addressed reads. get_chunk_at resolves
 * (file_index, chunk_index) — the manifest's canonical ascending path-order
 * coordinates the swarm wire speaks — to the file and behaves exactly like
 * get_chunk (same logical-access bump). get_manifest_wire reads back the
 * stored canonical manifest wire (staged or committed; allocates *out).
 * chunk_present is a pure CAS-presence probe at exact coordinates (no
 * access bump, no bytes read) for resumable-download bitmap rebuilds. */
enum vcs_package_store_result vcs_package_store_get_chunk_at(
    struct vcs_package_store *store, const uint8_t package_root[32],
    uint32_t file_index, uint32_t chunk_index, uint8_t **out,
    size_t *out_len);
enum vcs_package_store_result vcs_package_store_get_manifest_wire(
    struct vcs_package_store *store, const uint8_t package_root[32],
    uint8_t **out, size_t *out_len);
bool vcs_package_store_chunk_present(
    struct vcs_package_store *store, const uint8_t package_root[32],
    uint32_t file_index, uint32_t chunk_index);

/* Bounded tracked-package enumeration for swarm announcements (slice
 * 12). Fills up to `max` summaries in tracked (insertion) order and
 * returns the row count written. complete_only skips staged packages. */
struct vcs_package_store_summary {
    uint8_t root[32];
    uint32_t manifest_bytes;
    uint32_t file_count;
    uint64_t total_bytes;
    uint32_t total_chunks;
    bool complete;
    bool pinned;
};
size_t vcs_package_store_list_summaries(
    struct vcs_package_store *store, bool complete_only,
    struct vcs_package_store_summary *out, size_t max);

/* Admit a signed release envelope through the acceptance layer. OK and
 * DUPLICATE persist the envelope under releases/<release-id-hex>; any
 * other acceptance result stores nothing and returns ERR_ACCEPT with
 * *accept_out (when non-NULL) naming the acceptance failure. */
enum vcs_package_store_result vcs_package_store_put_release(
    struct vcs_package_store *store,
    const struct vcs_package_release *release,
    enum vcs_package_accept_result *accept_out);

/* Admit a declarative build recipe wire (slice 5). Parses and validates it
 * against the closed recipe grammar, computes the recipe root into
 * root_out (when non-NULL), and persists the wire atomically under
 * recipes/<recipe-root-hex>. Re-admitting an identical recipe is an
 * idempotent OK. The release-envelope binding (recipe root ==
 * release.recipe_root) is the publication layer's rule; the store checks
 * the wire itself. */
enum vcs_package_store_result vcs_package_store_put_recipe(
    struct vcs_package_store *store, const uint8_t *wire, size_t wire_len,
    uint8_t root_out[32]);

/* Operator pin: pinned packages charge the PINS pool and are never
 * evicted. Pinning fails with ERR_QUOTA when the package's bytes do not
 * fit the pins budget — pins are never made room for by eviction. The
 * package must be tracked. */
enum vcs_package_store_result vcs_package_store_pin(
    struct vcs_package_store *store, const uint8_t package_root[32],
    bool pinned);

/* Reclassify a tracked package (hot/rare) and set its observed replica
 * count. Moving a complete package into a pool enforces that pool's
 * budget (with eviction) first. */
enum vcs_package_store_result vcs_package_store_set_class(
    struct vcs_package_store *store, const uint8_t package_root[32],
    enum vcs_package_store_class class_, uint32_t replicas);

/* Snapshot one package's derived state. Returns false when untracked. */
bool vcs_package_store_package_status(
    struct vcs_package_store *store, const uint8_t package_root[32],
    struct vcs_package_store_status *out);

/* O(1), lock-bounded possession metadata. Unlike package_status this never
 * walks the package's chunk set or touches the filesystem: committed means
 * that the store completed its crash-safe commit, and generation changes on
 * every store-mediated byte/completion/pin mutation. */
bool vcs_package_store_possession_snapshot(
    struct vcs_package_store *store, const uint8_t package_root[32],
    struct vcs_package_possession_receipt *out);

/* The store-wide mutation counter: strictly increasing across every
 * store-mediated mutation of ANY package, including eviction. A per-package
 * generation cannot see a sibling change, so a cached decision that depended
 * on more than one package (a dependency closure, say) must key on this
 * instead. O(1), lock-bounded. Zero when `store` is NULL. */
uint64_t vcs_package_store_mutation_epoch(struct vcs_package_store *store);

/* Expensive possession proof for STORAGE_ACK authorship. Requires a complete
 * package (and, when requested, a current local pin), re-parses and root-binds
 * the manifest, reads every chunk, re-hashes every coordinate, then rechecks
 * derived status to close unpin/eviction races. */
bool vcs_package_store_verify_possession(
    struct vcs_package_store *store, const uint8_t package_root[32],
    bool require_pinned);
bool vcs_package_store_verify_possession_receipt(
    struct vcs_package_store *store, const uint8_t package_root[32],
    bool require_pinned, struct vcs_package_possession_receipt *receipt);

/* Incremental form used by the bounded STORAGE_ACK proof scheduler. Begin
 * snapshots the package generation and manifest under the store lock. Step
 * verifies at most `chunk_budget` chunks and never starts a chunk larger than
 * `byte_budget`; callers must provide at least VCS_PACKAGE_CHUNK_BYTES when
 * they want a full-size chunk to advance. Final success is recorded only
 * while the store lock confirms generation, complete state and pin state are
 * unchanged from the snapshot. */
struct vcs_package_possession_proof *vcs_package_store_possession_begin(
    struct vcs_package_store *store, const uint8_t package_root[32],
    bool require_pinned, struct vcs_package_possession_receipt *receipt);
enum vcs_package_possession_step vcs_package_store_possession_step(
    struct vcs_package_possession_proof *proof, uint64_t byte_budget,
    uint32_t chunk_budget, struct vcs_package_possession_receipt *receipt,
    uint64_t *bytes_used);
void vcs_package_store_possession_free(
    struct vcs_package_possession_proof *proof);
const char *vcs_package_possession_failure_string(
    enum vcs_package_possession_failure failure);

typedef void (*vcs_package_possession_apply_fn)(void *context, bool current);
/* Atomically recheck a successful receipt and invoke `apply` before any
 * store-mediated mutation can advance the package generation. The callback
 * must not re-enter this package store. */
void vcs_package_store_possession_apply_if_current(
    struct vcs_package_store *store, const uint8_t package_root[32],
    uint64_t successful_generation, bool require_pinned,
    vcs_package_possession_apply_fn apply, void *context);

/* Read-only CAS presence probe, addressed by DIRECTORY rather than by an
 * open store. vcs_package_store_open() runs the mutating recovery sweep,
 * so a read-only projection over <datadir>/zcode (the property catalog,
 * contexts/commons/modules/metaverse) cannot use it; this is the getter that lets such a
 * reader answer "are these bytes here?" without writing anything. True
 * when <zcode_dir>/cas/sha3/<hh>/<hex> is a non-empty regular file. It
 * proves PRESENCE only — the bytes are not re-hashed here. */
bool vcs_package_cas_present_in(const char *zcode_dir,
                                const uint8_t hash[32]);

/* Current charge of one pool in bytes (diagnostics/tests). */
uint64_t vcs_package_store_pool_usage(struct vcs_package_store *store,
                                      enum vcs_package_store_pool pool);

/* See AGENTS.md "Adding state introspection". Reentrant-safe.
 * Store-wide totals with a NULL/empty key; a 64-hex package root as the
 * key drills into that package's status. Reports {"enabled":false} when
 * no global store is open. */
struct json_value;
bool vcs_package_store_dump_state_json(struct json_value *out,
                                       const char *key);

/* ── the NON-BLOCKING totals read (telemetry collector plane) ─────────
 *
 * WHY THIS EXISTS AND WHY IT IS NOT THE DUMPER ABOVE. The dumper takes the
 * global lock and then the store lock BLOCKING, and both are held across
 * real work: the global lock spans the whole crash-recovery open, and the
 * store lock spans CAS file writes. A telemetry collector runs on the same
 * native/RPC thread that serves `status`, so blocking behind either one
 * makes this node go dark exactly while it is busiest. This is the same
 * trylock-or-say-so shape progress_store_tx_trylock() gives the reducer
 * frontier dumper.
 *
 * Cost, so the never-blocks contract can be checked by reading it: every
 * field is an O(1) load off the store struct except manifest_bytes_total,
 * which is one integer sum over at most VCS_PACKAGE_STORE_MAX_TRACKED
 * entries. No filesystem access, no hashing, no allocation. In particular
 * it does NOT count persisted releases or compute pool usage — both walk
 * per-package chunk sets or the releases directory.
 *
 * BUSY and CLOSED are different answers and the caller must keep them
 * different: CLOSED is a fact about this node ("no store is open"), BUSY is
 * a fact about this call ("someone else held the lock"). Collapsing BUSY
 * into zeros publishes a plausible empty store that never existed. */
enum vcs_package_store_totals_result {
    VCS_PACKAGE_STORE_TOTALS_OK = 0,
    VCS_PACKAGE_STORE_TOTALS_CLOSED, /* no node-global store is open */
    VCS_PACKAGE_STORE_TOTALS_BUSY,   /* a lock was held; nothing was read */
    VCS_PACKAGE_STORE_TOTALS_NULL,   /* caller passed no output */
};

struct vcs_package_store_totals {
    uint64_t quota_bytes;
    uint64_t tracked_packages;
    uint64_t cas_chunks;
    uint64_t manifest_bytes_total; /* sum of DECLARED manifest totals */
    uint64_t evictions_total;
    uint64_t gc_orphans_total;
    uint64_t quota_rejects_total;
    /* Static string with program lifetime; "none" until a release has been
     * offered. Never a pointer into store memory. */
    const char *last_release_accept;
};

/* Fill *out from the node-global store without ever blocking. *out is
 * zeroed (and last_release_accept set to "none") on every path, so a caller
 * that ignores the result still cannot read indeterminate memory — but a
 * caller that ignores it publishes zeros for BUSY, which is the one thing
 * this enum exists to prevent. */
enum vcs_package_store_totals_result vcs_package_store_try_totals(
    struct vcs_package_store_totals *out);

#endif /* ZCL_VCS_PACKAGE_STORE_H */
