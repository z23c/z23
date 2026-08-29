/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ROM artifact seeding — the free, fast, capped P2P delivery tier for the
 * network's own bootstrap ROM: the consensus-state bundle
 * (zcl.consensus_state_bundle.v1, "consensus-state-bundle-<h>.sqlite") and
 * header-chain seed data. A fresh node fetches these P2P and reaches the
 * compiled checkpoint in minutes instead of folding for hours.
 *
 * Trust model: DELIVERY is untrusted transport. Registration re-derives every
 * digest from the bytes on disk (never a sidecar), and a downloader re-verifies
 * each chunk's SHA3 against the manifest and the whole file against the
 * checkpoint content proof. A malicious seeder wastes bandwidth, never poisons
 * state — so seeding is generous (price 0, no payment gate) but bounded by hard
 * per-peer concurrency + per-peer/global byte-rate caps and served off the
 * file-service's own thread pool so it never starves consensus P2P.
 *
 * This module is pure registry + policy + caps + stats. It owns no threads and
 * no sockets; the boot scan worker (config/) drives registration and the file
 * service (lib/net/file_service.c) drives the serve path through the decision
 * functions below. Every wire-derived field is bounded and validated here. */

#ifndef ZCL_NET_ROM_SEED_H
#define ZCL_NET_ROM_SEED_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── Layout constants ───────────────────────────────────────────────── */

/* 8 MB serving chunk: a ~490 MB consensus bundle is ~62 chunks; a full ~15-20 GB
 * starter package is a few thousand. The default per-peer rate window
 * (ROM_SEED_DEFAULT_PEER_BPS_CAP below) is sized to a MULTIPLE of one chunk so a
 * dedicated seeder can feed every in-flight serve slot within one wall-second
 * (the _Static_assert after the cap defaults pins that coupling); a smaller
 * chunk would need more chunks (bigger per-artifact digest table + manifest
 * blob) for the same byte reach. */
#define ROM_SEED_CHUNK_SIZE       (8u * 1024u * 1024u)

/* Bounds. MAX_CHUNKS * CHUNK_SIZE = 32 GiB caps a single artifact (comfortably
 * over the ~15-20 GB starter-package target); MAX_ARTIFACTS bounds the registry.
 * Both tables are static — never sized from a wire value. The per-artifact
 * chunk-digest table is MAX_CHUNKS * 32 B = 128 KiB (registry 1 MiB static). */
#define ROM_SEED_MAX_CHUNKS       4096u
#define ROM_SEED_MAX_ARTIFACTS    8u
#define ROM_SEED_NAME_MAX         128u

/* A ROM artifact must be at least one SQLite page and at most MAX_CHUNKS worth
 * of CHUNK_SIZE. Anything outside is not a bundle we will serve. */
#define ROM_SEED_MIN_ARTIFACT_BYTES  4096ull
#define ROM_SEED_MAX_ARTIFACT_BYTES  \
    ((uint64_t)ROM_SEED_MAX_CHUNKS * (uint64_t)ROM_SEED_CHUNK_SIZE)

/* Per-peer accounting table size (bounds memory under an IP flood). */
#define ROM_SEED_PEER_TABLE_CAP   256u

/* Bounded directory scan: never walk more than this many entries. The cap is
 * a runaway stop for a pathological directory, NOT a routine limit — when it
 * fires the scan says so rather than quietly returning a short list, and the
 * exactly-named artifacts are looked up by name so no walk order can hide
 * them. Declared here because the acceptance asserts against it; a second
 * copy in the test would let the two drift. */
#define ROM_SEED_SCAN_ENTRY_CAP   4096u

/* The ONE datadir subdirectory rom_seed reaches one level into (besides the
 * datadir root): where config/src/boot_bundle_fetch.c lands verified swarm
 * downloads, and where the unified installer deliberately RETAINS the source
 * .sqlite after install (it only ever unlinks a stale prior-generation OUTPUT
 * artifact, never the source it read from). rom_seed_scan_datadir() recurses
 * into it and rom_seed_register()/rom_filename_ok accept a filename shaped
 * "ROM_SEED_BUNDLES_SUBDIR/<basename>" for exactly this reason: a bundle this
 * node fetched (or installed from) keeps seeding the swarm afterward — BitTorrent-
 * style swarm widening with zero operator input. */
#define ROM_SEED_BUNDLES_SUBDIR   "bundles"

/* Sane default caps (generous but bounded). Overridable via the setters.
 *
 * The per-peer inflight cap matches a fresh node's verified-parallel fetch
 * worker count (rom_fetch.c, ROM_FETCH_MAX_WORKERS == 8): a fresh node opens up
 * to 8 concurrent chunk serves against ONE dedicated seeder, so an inflight cap
 * below 8 would refuse most of its workers and collapse the download. The
 * per-peer byte window is sized to inflight * CHUNK_SIZE (64 MB/s = 8 chunks/s)
 * so one wall-second can feed every in-flight slot instead of throttling a
 * whole chunk to one-per-second-per-peer. The global window bounds the node's
 * total ROM uplink across all peers (the DoS ceiling) and stays >= per-peer. */
#define ROM_SEED_DEFAULT_MAX_INFLIGHT_PER_PEER  8u
#define ROM_SEED_DEFAULT_PEER_BPS_CAP   (64ull * 1024 * 1024)   /*  64 MB/s / peer = 8 chunks/s */
#define ROM_SEED_DEFAULT_GLOBAL_BPS_CAP (256ull * 1024 * 1024)  /* 256 MB/s total  */

/* The free-tier byte-rate cap is charged whole-chunk in one shot
 * (rom_seed_rate_charge). Keep the per-peer window an integer multiple of
 * CHUNK_SIZE AND >= inflight * CHUNK_SIZE so every in-flight serve slot can be
 * fed within one wall-second (otherwise the second-and-later concurrent chunk
 * is refused every window and 8 parallel workers thrash); keep one chunk within
 * the global window and per-peer <= global. Raising CHUNK_SIZE or the inflight
 * cap requires raising these caps in lockstep — the asserts pin it. */
_Static_assert((uint64_t)ROM_SEED_DEFAULT_PEER_BPS_CAP >=
                   (uint64_t)ROM_SEED_DEFAULT_MAX_INFLIGHT_PER_PEER *
                   (uint64_t)ROM_SEED_CHUNK_SIZE,
               "per-peer window must feed every in-flight ROM serve slot");
_Static_assert((uint64_t)ROM_SEED_CHUNK_SIZE <= ROM_SEED_DEFAULT_PEER_BPS_CAP,
               "ROM chunk must fit the default per-peer rate window");
_Static_assert((uint64_t)ROM_SEED_CHUNK_SIZE <= ROM_SEED_DEFAULT_GLOBAL_BPS_CAP,
               "ROM chunk must fit the default global rate window");
_Static_assert((uint64_t)ROM_SEED_DEFAULT_PEER_BPS_CAP <=
                   (uint64_t)ROM_SEED_DEFAULT_GLOBAL_BPS_CAP,
               "per-peer window must not exceed the global window");

/* ── Artifact kinds ─────────────────────────────────────────────────── */

enum rom_artifact_kind {
    ROM_ARTIFACT_UNKNOWN = 0,
    ROM_ARTIFACT_CONSENSUS_BUNDLE = 1,  /* consensus-state-bundle-<h>.sqlite */
    ROM_ARTIFACT_HEADER_SEED = 2,       /* header-chain seed (block_index.bin) */
};

/* A registered, content-verified artifact. `chunk_root` (SHA3 over the
 * concatenated per-chunk digests) is the artifact's content identity — it is
 * the root_hash used in gossip and the key serve requests carry. */
struct rom_artifact {
    enum rom_artifact_kind kind;
    char     filename[ROM_SEED_NAME_MAX]; /* basename within the datadir       */
    uint64_t size_bytes;
    uint32_t chunk_size;
    uint32_t num_chunks;
    int64_t  height;                      /* artifact-known height (bundle name
                                           * or header-seed tip); 0 = unknown  */
    uint8_t  whole_sha3[32];              /* SHA3-256 of the whole file        */
    uint8_t  chunk_root[32];              /* SHA3-256 over per-chunk digests   */
    uint8_t  chunk_sha3[ROM_SEED_MAX_CHUNKS][32];
    int64_t  registered_at;
    bool     used;
};

/* ── Registration ───────────────────────────────────────────────────── */

enum rom_register_result {
    ROM_REG_OK = 0,
    ROM_REG_ERR_ARGS,          /* NULL / empty / traversal in filename        */
    ROM_REG_ERR_NOT_FOUND,     /* file missing or unopenable                  */
    ROM_REG_ERR_UNKNOWN_KIND,  /* filename matches no known artifact kind     */
    ROM_REG_ERR_TOO_SMALL,     /* below ROM_SEED_MIN_ARTIFACT_BYTES           */
    ROM_REG_ERR_TOO_LARGE,     /* above ROM_SEED_MAX_ARTIFACT_BYTES           */
    ROM_REG_ERR_CORRUPT,       /* structural check failed OR digest mismatch  */
    ROM_REG_ERR_IO,            /* read error mid-stream                        */
    ROM_REG_ERR_FULL,          /* registry full                               */
};

/* Classify an artifact kind from its basename (no I/O). */
enum rom_artifact_kind rom_seed_classify(const char *filename);

/* Inverse of the wire "kind" string (the token rom_seed_directory_json emits:
 * "consensus_bundle" / "header_seed"). Returns ROM_ARTIFACT_UNKNOWN for a NULL
 * or unrecognized name — the back-compat default a legacy directory (no kind
 * field) parses to. Pure, no I/O. */
enum rom_artifact_kind rom_seed_kind_from_name(const char *name);

/* Structural content check for a kind, given the first `n` header bytes and the
 * total file size. Pure — this is what makes a corrupt/truncated file fail
 * registration BEFORE it is ever offered. */
bool rom_seed_kind_content_ok(enum rom_artifact_kind kind,
                              const uint8_t *header, size_t n,
                              uint64_t size_bytes);

/* Register (or re-register) `filename` inside `datadir`. Computes every digest
 * from the bytes on disk in one bounded pass. If `expected_whole_sha3` is
 * non-NULL it must match the computed whole-file digest or registration is
 * refused as ROM_REG_ERR_CORRUPT. On ROM_REG_OK the artifact is in the registry
 * and (if `out` non-NULL) copied out. `filename` must be a bare basename, OR
 * "ROM_SEED_BUNDLES_SUBDIR/<basename>" (i.e. "bundles/<basename>") naming a
 * file one level under `datadir` — the ONLY subdirectory shape accepted; any
 * other separator or a second '/' is refused. Either way `datadir` + `/` +
 * `filename` is the file actually opened, hashed, and later re-opened by
 * rom_seed_read_chunk, so the registered artifact always serves the exact
 * bytes it was registered from. */
enum rom_register_result rom_seed_register(const char *datadir,
                                           const char *filename,
                                           const uint8_t *expected_whole_sha3,
                                           struct rom_artifact *out);

/* Drop `filename` from the registry so it stops being served — the inverse of
 * rom_seed_register. The rotation path (config/src/bundle_exporter_generations.c bx_rotate)
 * calls this immediately BEFORE it unlinks a rotated-out generation, so a
 * deleted file is never left advertised in the served directory / serve_lookup.
 *
 * `filename` is matched by BARE BASENAME against the stored artifact names, so a
 * caller may pass either the bare basename ("consensus-state-bundle-<h>.sqlite")
 * or the "ROM_SEED_BUNDLES_SUBDIR/<basename>" ("bundles/<name>") shape the
 * reseed path registered it under — both resolve to the same entry. The same
 * arg rules as rom_seed_register apply (rom_filename_ok): a NULL/empty datadir
 * or an unsafe filename returns ROM_REG_ERR_ARGS. IDEMPOTENT: removing an entry
 * that is not present is not an error (ROM_REG_OK). No per-artifact refcounts —
 * an artifact is either registered or it is not. */
enum rom_register_result rom_seed_deregister(const char *datadir,
                                             const char *filename);

/* Bounded datadir scan: register every entry matching a known artifact kind
 * (today: consensus-state-bundle-*.sqlite) found directly under `datadir`,
 * PLUS one level into `datadir`/ROM_SEED_BUNDLES_SUBDIR ("bundles/") — where
 * boot_bundle_fetch.c lands verified swarm downloads and the installer leaves
 * the source bundle after install, so a bundle this node fetched keeps
 * seeding the swarm. Returns the number registered (both locations combined).
 * Bounded by ROM_SEED_MAX_ARTIFACTS and a fixed per-directory entry ceiling.
 * An absent bundles/ subdirectory is normal, not an error. */
int rom_seed_scan_datadir(const char *datadir);

/* Supervised, single-shot background scan of `datadir`: registers matching
 * artifacts (one bounded digest pass) and announces each as a price-0 offer
 * into the in-memory market. `fs_port` is stamped on the offers. Idempotent;
 * a no-op when seeding is disabled. Joined by rom_seed_stop_scan(). */
void rom_seed_start_scan(const char *datadir, uint16_t fs_port);
void rom_seed_stop_scan(void);

/* ── Registry queries ───────────────────────────────────────────────── */

void rom_seed_reset(void);                    /* clear registry + caps + stats */
int  rom_seed_count(void);
int  rom_seed_list(struct rom_artifact *out, size_t max);
bool rom_seed_find_by_root(const uint8_t root_hash[32], struct rom_artifact *out);

/* Read chunk `idx` of a registered artifact from disk into `buf` (capacity
 * `buf_cap`), verifying its SHA3 against the registered per-chunk digest.
 * `*out_sz` gets the actual bytes (the last chunk may be short). */
bool rom_seed_read_chunk(const struct rom_artifact *a, const char *datadir,
                         uint32_t idx, uint8_t *buf, uint32_t buf_cap,
                         uint32_t *out_sz);

/* ── Free-tier serve policy ─────────────────────────────────────────── */

enum rom_serve_verdict {
    ROM_SERVE_FREE_OK = 0,     /* registered free artifact, chunk in range     */
    ROM_SERVE_DISABLED,        /* seeding disabled by config                   */
    ROM_SERVE_NOT_ARTIFACT,    /* unknown root — NOT free (payment path owns it)*/
    ROM_SERVE_OUT_OF_RANGE,    /* chunk_index >= num_chunks                    */
};

/* Stateless: is (root_hash, chunk_index) a free ROM chunk we should serve
 * without payment? Fills `out` with the matched artifact on ROM_SERVE_FREE_OK.
 * The caller still applies the concurrency + rate caps below. */
enum rom_serve_verdict rom_seed_serve_lookup(const uint8_t root_hash[32],
                                             uint32_t chunk_index,
                                             struct rom_artifact *out);

/* Convenience: true iff root_hash names a registered (free) ROM artifact. The
 * market payment gate consults this to skip payment verification. */
bool rom_seed_offer_is_free(const uint8_t root_hash[32]);

/* ── Caps (in-memory DDoS bound; nothing here is consensus) ─────────── */

void     rom_seed_set_enabled(bool on);
bool     rom_seed_enabled(void);
void     rom_seed_set_max_inflight_per_peer(uint32_t n);
void     rom_seed_set_peer_bps_cap(uint64_t bytes_per_sec);
void     rom_seed_set_global_bps_cap(uint64_t bytes_per_sec);

/* Per-peer in-flight concurrency. acquire() returns false once the peer holds
 * max_inflight_per_peer active serves; each success MUST be released exactly
 * once. */
bool rom_seed_peer_acquire(const uint8_t peer_ip[16]);
void rom_seed_peer_release(const uint8_t peer_ip[16]);

/* Charge `n` bytes to the peer's and the global rolling-1s byte-rate windows.
 * Returns false (serve should stop) once either window would exceed its cap.
 * Records served-bytes + unique-peer + chunk stats on success. */
bool rom_seed_rate_charge(const uint8_t peer_ip[16], uint64_t n, int64_t now);

/* Note a chunk actually served (for stats). Call once per delivered chunk. */
void rom_seed_note_chunk_served(void);

/* ── Announce + introspection ───────────────────────────────────────── */

struct file_offer;

/* Build a price-0 market offer advertising a registered artifact. root_hash is
 * the artifact's chunk_root. Returns false on NULL args. */
bool rom_seed_build_offer(const struct rom_artifact *a,
                          const uint8_t self_ip[16], uint16_t fs_port,
                          struct file_offer *out);

/* Append the artifacts JSON array body (no enclosing key) to `buf`, e.g.
 *   [{"kind":"consensus_bundle","digest":"..","size":N,"chunks":M}, ...]
 * Returns the number of bytes written (0 on overflow / no artifacts). */
size_t rom_seed_directory_json(char *buf, size_t max);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe. */
struct json_value;
bool rom_seed_dump_state_json(struct json_value *out, const char *key);

/* ── Per-chunk manifest serialization (WF2 artifact-protocol, serve side) ──
 *
 * The seeder already holds every per-chunk SHA3 in RAM (rom_artifact.chunk_sha3);
 * this serializes them for the "RMF" manifest reply:
 *   [u32 version][u32 num_chunks][num_chunks × 32B chunk_sha3]
 * under the existing file-service MAC scheme. */

/* Max serialized manifest-blob size: header (8) + one 32-byte digest per
 * chunk, bounded by ROM_SEED_MAX_CHUNKS. */
#define ROM_SEED_MANIFEST_BLOB_MAX (8u + ROM_SEED_MAX_CHUNKS * 32u)

/* Serialize `a`'s per-chunk digest manifest into `buf` (capacity `cap`).
 * Returns the number of bytes written, or 0 on NULL args / overflow. Pure. */
size_t rom_seed_manifest_blob(const struct rom_artifact *a,
                              uint8_t *buf, size_t cap);

#endif /* ZCL_NET_ROM_SEED_H */
