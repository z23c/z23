/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ROM artifact fetching — the CLIENT half of docs/ROM_DELIVERY.md. Downloads
 * a ROM artifact (today: the consensus-state bundle) from a seeding peer over
 * the file-service transport and verifies it BY CONTENT against digests the
 * caller committed to before the first byte was requested.
 *
 * Trust model: delivery is untrusted transport. This module verifies bytes —
 * per-chunk transport MACs on the wire, then a whole-file re-hash against the
 * committed (chunk_root, whole_sha3, size) after the download — and nothing
 * more. It NEVER installs, activates, or validates consensus state: the only
 * activation door is the unified installer's RECEIPT / CHECKPOINT_CONTENT
 * authority (engine/composition/src/boot_install_consensus_bundle.c), which an operator
 * runs separately against the verified file this module leaves on disk.
 *
 * Wire protocol (mirrors the serve side, core/modules/net/src/file_service.c):
 *   - TCP connect to the peer's file-service port; fs_handshake with an
 *     all-zero utxo_root (the ROM serve path keys its sessions on zeros —
 *     see fs_handle_client_fd, file_service.c:984-986).
 *   - One FS_REQUEST frame, body ["ROM"(3)][chunk_root(32)][chunk_index(4 LE)]
 *     (FS_ROM_REQUEST_SIZE, net/file_service.h).
 *   - Success reply: raw stream [4-byte size LE][data][32-byte MAC] with
 *     MAC = SHA3(key || counter || chunk_sha3 || data). The client learns the
 *     chunk's content digest only by hashing the received bytes — per-chunk
 *     digests are not on the wire today, so CONTENT verification happens at
 *     whole-file granularity (chunk_root fold + whole_sha3), exactly as
 *     docs/ROM_DELIVERY.md's trust model specifies.
 *   - Refusal reply: an FS_DONE frame — indistinguishable from a corrupt
 *     stream at this layer, so it surfaces as a chunk failure the caller may
 *     retry. Fail-closed either way.
 *
 * This module owns no threads and no sockets beyond one short-lived
 * connection per rom_fetch_chunk() call. The caller drives pacing,
 * parallelism, and resume. */

#ifndef ZCL_NET_ROM_FETCH_H
#define ZCL_NET_ROM_FETCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "net/rom_seed.h" /* ROM_SEED_* bounds shared with the serve side */

/* Bounds on the manifest table a caller holds while discovering artifacts. */
#define ROM_FETCH_MAX_ARTIFACTS  ROM_SEED_MAX_ARTIFACTS
#define ROM_FETCH_NAME_MAX       ROM_SEED_NAME_MAX

/* Staging suffix for the in-progress download; renamed to the committed
 * filename only after whole-file verification passes. */
#define ROM_FETCH_PART_SUFFIX    ".part"

/* A manifest the caller has COMMITTED to before downloading. Every field is
 * either operator-supplied or parsed (and range-checked) from a peer's
 * directory document; the digests are the whole trust anchor of the
 * download. */
struct rom_fetch_manifest {
    bool     used;
    char     filename[ROM_FETCH_NAME_MAX]; /* bare basename, sanitized     */
    uint64_t size_bytes;
    uint32_t chunk_size;                   /* must be ROM_SEED_CHUNK_SIZE  */
    uint32_t num_chunks;
    uint8_t  chunk_root[32];               /* serve-request key            */
    uint8_t  whole_sha3[32];               /* whole-file digest            */
    /* Artifact kind parsed from the directory.json "kind" token (untrusted,
     * cosmetic to the download — the digests are the trust anchor). Lets the
     * boot picker select the consensus bundle vs the header-chain seed by kind
     * rather than by size alone. ROM_ARTIFACT_UNKNOWN when the directory entry
     * carried no (or an unrecognized) kind — the back-compat legacy shape. */
    enum rom_artifact_kind kind;
    /* Advertised chain height (parsed from the directory.json "height" field,
     * itself derived from the canonical consensus-state-bundle-<h>.sqlite name;
     * 0 for the header seed / a legacy directory carrying no height). Like
     * `kind`, this is DOWNLOAD-COSMETIC and untrusted — it is NOT checked by
     * rom_fetch_manifest_sane and grants no trust; it only lets the boot picker
     * prefer the NEWEST bundle across mixed-height seeds. The digests remain the
     * sole content anchor and CHECKPOINT_ROM binds the installed state. */
    int64_t height;
    /* ROM_ARTIFACT_SOURCE_BUNDLE entries only: the ZVCS tree root the seeder
     * SAYS this bundle carries (directory.json "source_root"). Like `kind` and
     * `height` this is an untrusted peer claim and is NOT checked by
     * rom_fetch_manifest_sane. It exists so a caller holding only a 64-hex
     * source root can pick WHICH artifact to ask for; the caller then proves
     * the delivered bytes against its OWN copy of that root. A peer that lies
     * here buys one wasted download and nothing else. */
    uint8_t source_root[32];
    bool has_source_root;
};

/* Progress callback for rom_fetch_download: called after each chunk lands
 * (chunks_done of num_chunks). Returning false aborts the download. */
typedef bool (*rom_fetch_progress_cb)(uint32_t chunks_done,
                                      uint32_t num_chunks,
                                      uint64_t bytes_done, void *ctx);

/* ── Manifest validation + discovery parse ──────────────────────────── */

/* Validate internal consistency + sanitize `filename` of a caller-filled
 * manifest: chunk_size == ROM_SEED_CHUNK_SIZE, num_chunks ==
 * ceil(size/chunk_size), size within [ROM_SEED_MIN_ARTIFACT_BYTES,
 * ROM_SEED_MAX_ARTIFACT_BYTES], filename a bare basename (no separators, no
 * traversal). An empty filename is allowed (directory.json entries carry no
 * name; the caller assigns one before downloading). Pure, does not mutate. */
bool rom_fetch_manifest_sane(const struct rom_fetch_manifest *m);

/* Parse the "artifacts" array of a peer's /directory.json body into out[]
 * (capacity max, capped at ROM_FETCH_MAX_ARTIFACTS). Each entry is
 * range-checked with rom_fetch_manifest_sane(); malformed entries are
 * skipped, not fatal. Returns the number of valid manifests, or -1 if the
 * JSON itself is unparseable. Peer-supplied: the digests are the ONLY thing
 * carried forward. */
int rom_fetch_parse_directory(const char *json_body,
                              struct rom_fetch_manifest *out, size_t max);

/* Fetch a peer's directory listing over the file-service wire (the "RLS"
 * request) into `buf` (NUL-terminated on success, bounded by `cap`). The reply
 * is the same {"artifacts":[...]} body the onion /directory.json path serves —
 * feed it straight to rom_fetch_parse_directory / boot_bundle_pick_manifest.
 * This is the clearnet counterpart of the onion directory fetch: a fresh node
 * with an empty datadir uses it to discover WHO seeds WHAT with zero operator
 * input. Transport-MAC-verified against an "RLS"-tagged MAC; the manifest
 * digests inside remain untrusted (trust binds only at install). Returns false
 * (a clean skip-discovery signal, not a peer offence) on connect/handshake/
 * transport/MAC failure or an implausible/over-cap reply — e.g. a legacy seeder
 * that does not know RLS replies FS_DONE, which surfaces here as a size-cap or
 * read failure. One short-lived connection per call; fast (15 s) recv timeout so
 * an unaware seeder falls back promptly. */
bool rom_fetch_get_directory(const char *peer_addr, uint16_t port,
                             char *buf, size_t cap);

/* ── Verified chunk fetch ───────────────────────────────────────────── */

/* Fetch chunk `idx` of the artifact keyed by `chunk_root` from
 * peer_addr:port over the file-service transport. buf must hold at least
 * ROM_SEED_CHUNK_SIZE bytes; *out_sz gets the actual bytes (the last chunk
 * may be short). Transport-MAC-verified; content is NOT digest-checked here
 * (see the header comment). Returns false on connect/handshake/transport/
 * refusal/MAC failure. One connection per call; 120 s socket timeouts. */
bool rom_fetch_chunk(const char *peer_addr, uint16_t port,
                     const uint8_t chunk_root[32], uint32_t idx,
                     uint8_t *buf, uint32_t buf_cap, uint32_t *out_sz);

/* Pure decode of a chunk-reply's 4-byte LE size field: true iff it is the
 * server's typed refusal sentinel (FS_ROM_REFUSAL_SENTINEL) — i.e. the reply is
 * a "peer busy/declined" refusal frame, not a data chunk. A real chunk size is
 * bounded by ROM_SEED_CHUNK_SIZE and never reaches the sentinel, and a corrupt
 * garbage size is NOT mistaken for a refusal (only the exact sentinel matches).
 * Exposed for the refusal-frame decode unit test. */
bool rom_fetch_wire_is_refusal(const uint8_t hdr4[4]);

/* Stable human label for a fs_rom_refusal_reason code (unknown codes fold to
 * "declined"). Used for clean "peer busy (<reason>)" logging and in tests. */
const char *rom_fetch_refusal_reason_name(uint8_t reason);

/* ── Whole-file verification + download driver ──────────────────────── */

/* Re-hash `path` in one bounded streaming pass and require ALL of:
 * file size == m->size_bytes, per-chunk SHA3 fold == m->chunk_root,
 * whole-file SHA3 == m->whole_sha3. Pure disk + SHA3; no network. */
bool rom_fetch_verify_file(const char *path,
                           const struct rom_fetch_manifest *m);

/* Sequential download: fetch every chunk of `m` from peer_addr:port into
 * <out_dir>/<filename>.part (pwrite at chunk offsets), then
 * rom_fetch_verify_file and rename to <out_dir>/<filename>. On a digest
 * mismatch the .part file is UNLINKED (no partial trust); on a transport
 * failure the .part is left in place for a future resume. A refused chunk
 * (seeder rate window / in-flight cap — both clear in ~1 s) is retried a
 * bounded number of times with backoff before it counts as failed; the
 * download therefore self-paces to a stock seeder's default 8 MB/s window
 * instead of dying at the second chunk. The installed file is delivered
 * read-only (mode 0444) — the unified installer's immutable admission
 * accepts it with no manual chmod. Returns false with a logged reason
 * on any failure. The optional cb runs after each chunk. Every attempt is
 * recorded in the fetch status below. */
bool rom_fetch_download(const char *peer_addr, uint16_t port,
                        const struct rom_fetch_manifest *m,
                        const char *out_dir,
                        rom_fetch_progress_cb cb, void *cb_ctx);

/* ── Parallel multi-seeder download ─────────────────────────────────── */

/* One seeder endpoint (host + file-service port). */
struct rom_fetch_peer {
    char     addr[128];
    uint16_t port;
};

/* Hard cap on worker threads per parallel download. The serve-side per-peer
 * in-flight cap is small (default 2), so the caller should size workers at
 * ~2x the peer count; more workers than that just queue on refusals. */
#define ROM_FETCH_MAX_WORKERS 8u

/* Parallel download: worker threads pull chunk indices from a shared queue;
 * chunk i is first tried on peers[i % npeers], and on failure retried on
 * each subsequent peer (round-robin) — a chunk is declared failed only
 * after EVERY peer refused/failed it. Each chunk is transport-MAC-verified
 * on arrival and pwrite()n at its offset into <out_dir>/<filename>.part;
 * the whole-file content proof + atomic rename (or unlink on mismatch) is
 * identical to rom_fetch_download. `workers` is clamped to
 * [1, ROM_FETCH_MAX_WORKERS]. Returns false (leaving .part for resume) if
 * any chunk failed on all peers. */
bool rom_fetch_download_parallel(const struct rom_fetch_peer *peers,
                                 size_t npeers,
                                 const struct rom_fetch_manifest *m,
                                 const char *out_dir, uint32_t workers,
                                 rom_fetch_progress_cb cb, void *cb_ctx);

/* ── Fetch status (observability; powers dumpstate rom_fetch) ───────── */

struct rom_fetch_status {
    bool     ever_attempted;
    bool     in_progress;
    bool     last_ok;
    char     peer[80];        /* "addr:port" of the last attempt          */
    char     filename[ROM_FETCH_NAME_MAX];
    char     detail[192];     /* installed path or a short failure reason */
    uint64_t size_bytes;
    uint32_t num_chunks;
    uint32_t chunks_done;
    uint64_t bytes_done;
    int64_t  started_unix;
    int64_t  finished_unix;
    /* Cumulative counters over the process lifetime. */
    uint64_t attempts;
    uint64_t successes;
    uint64_t failures;
    uint64_t bytes_total;     /* verified-and-installed bytes             */
};

/* Copy out a consistent snapshot of the fetch status. Safe from any thread. */
void rom_fetch_status_snapshot(struct rom_fetch_status *out);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe. */
struct json_value;
bool rom_fetch_dump_state_json(struct json_value *out, const char *key);

/* ── Per-chunk manifest fetch + verified download (WF2 artifact-protocol) ──
 *
 * These upgrade the whole-file-only content check above to per-chunk
 * verification, so a resume can trust individual chunks. Back-compat is the
 * refusal: a legacy seeder that does not understand the "RMF" manifest request
 * replies FS_DONE, rom_fetch_get_manifest returns false, and the caller falls
 * back to the whole-file path — never an offence. */

/* Fetch the per-chunk SHA3 manifest for the artifact keyed by `chunk_root`
 * from peer_addr:port (the "RMF" request, FS_ROM_MANIFEST_REQUEST_SIZE). Fills
 * out_chunk_sha3[0..*out_num_chunks) (capacity out_cap rows of 32 bytes).
 * Returns false on refusal (legacy seeder), transport/MAC failure, or if the
 * reply's num_chunks exceeds out_cap. A false return is the signal to fall
 * back to whole-file verification, not a peer offence. */
bool rom_fetch_get_manifest(const char *peer_addr, uint16_t port,
                            const uint8_t chunk_root[32],
                            uint8_t (*out_chunk_sha3)[32], uint32_t out_cap,
                            uint32_t *out_num_chunks);

/* Pure per-chunk content check: SHA3-256(data[0..len)) == expected. No IO. */
bool rom_fetch_verify_chunk(const uint8_t *data, uint32_t len,
                            const uint8_t expected_chunk_sha3[32]);

/* Pure: parse + verify a received "RMF" manifest blob
 * ([u32 version=1 LE][u32 num_chunks LE][num_chunks × 32B]) against the
 * caller-committed `chunk_root`. Enforces version == 1, that `len` is exactly
 * 8 + num_chunks*32, that num_chunks is in (0, ROM_SEED_MAX_CHUNKS] and fits
 * `out_cap`, and — the content bind — that the per-chunk digests fold (SHA3
 * over their concatenation) to `chunk_root`. On success fills
 * out_chunk_sha3[0..*out_num_chunks) and returns true. Any inconsistency
 * returns false and leaves *out_num_chunks = 0 (the caller's fall-back
 * signal). No IO — this is the testable core of rom_fetch_get_manifest. */
bool rom_fetch_parse_manifest_blob(const uint8_t *blob, size_t len,
                                   const uint8_t chunk_root[32],
                                   uint8_t (*out_chunk_sha3)[32],
                                   uint32_t out_cap, uint32_t *out_num_chunks);

/* Per-chunk-verified sequential download with durable resume. `chunk_sha3`
 * holds the manifest's num_chunks per-chunk digests (from
 * rom_fetch_get_manifest). Writes <out_dir>/<filename>.part with a
 * <...>.part.journal sidecar; on restart, chunks the journal marks done (and
 * that pass a random spot-check re-hash) are skipped. Each freshly received
 * chunk is rom_fetch_verify_chunk'd BEFORE its journal bit is set, and the
 * whole-file SHA3 is still checked before the atomic rename. Returns false
 * (leaving .part + journal for a later resume) on any failure. */
bool rom_fetch_download_verified(const char *peer_addr, uint16_t port,
                                 const struct rom_fetch_manifest *m,
                                 const uint8_t (*chunk_sha3)[32],
                                 uint32_t num_chunks, const char *out_dir,
                                 rom_fetch_progress_cb cb, void *cb_ctx);

/* Multi-seeder per-chunk-verified download with durable resume — the parallel
 * generalization of rom_fetch_download_verified. Worker threads pull chunk
 * indices from one shared queue; each chunk is fetched from peers in
 * round-robin (starting at i % npeers) and CONTENT-verified against
 * chunk_sha3[i] BEFORE its journal bit is set, so a corrupt/unreachable seeder
 * fails OVER to the next peer for that chunk (a peer that serves non-committed
 * bytes is scored via rom_peer_note_bad_chunk and skipped) rather than failing
 * the whole download. Every peer's addr must be non-empty and port non-zero.
 * Resume, spot-check, whole-file gate, and atomic read-only install are
 * identical to the single-peer path; npeers==1 reproduces it exactly. Returns
 * false (leaving .part + journal for a later resume) when some chunk fails
 * content-verify on ALL peers. */
bool rom_fetch_download_verified_parallel(const struct rom_fetch_peer *peers,
                                          size_t npeers,
                                          const struct rom_fetch_manifest *m,
                                          const uint8_t (*chunk_sha3)[32],
                                          uint32_t num_chunks,
                                          const char *out_dir,
                                          rom_fetch_progress_cb cb,
                                          void *cb_ctx);

#ifdef ZCL_TESTING
/* Test-only control of the peer-DISCOVERY stall bound (rom_fetch_get_directory's
 * recv window). It shortens a WAIT; it changes no digest check, no MAC check,
 * no size bound and no refusal — the identical verification runs whatever this
 * is set to. A test uses it to prove "a seed that accepts and never speaks is
 * abandoned and the next seed is still tried" without spending the production
 * wait, and asserts the DEFAULT against
 * rom_fetch_directory_io_timeout_default_ms_for_test() rather than asserting a
 * wall-clock duration. Passing ms <= 0 restores the default. */
void rom_fetch_set_directory_io_timeout_ms_for_test(int ms);
int  rom_fetch_directory_io_timeout_ms_for_test(void);
int  rom_fetch_directory_io_timeout_default_ms_for_test(void);

/* ── Transport seam (test-only) ──────────────────────────────────────────
 *
 * rom_fetch reaches a seeder over one of two routes, chosen by the address
 * itself (core/modules/net/src/rom_fetch_transport.c): getaddrinfo + connect(2) for a
 * clearnet peer, or a Tor circuit via net/onion_stream.h for a ".onion" peer.
 * This tree has no SOCKS client -- dynhost replaces it -- so there is no
 * proxy endpoint to configure or hardcode.
 *
 * These entry points let a test prove WHICH route an address took, and that
 * the two budgets stay separate, without a live Tor network. They compile
 * out of a release build. */
#include "platform/socket_compat.h"

struct onion_stream_backend;

/* Bind the raw-stream backend the onion route dials through. A non-NULL
 * backend makes the onion route use onion_stream_connect_backend_for_test
 * (skipping the Tor-runtime gates); NULL restores production dialing. */
void rom_fetch_set_onion_backend_for_test(const struct onion_stream_backend *be);

/* The dial rom_fetch_chunk/_get_manifest/_get_directory all perform. */
platform_socket_t rom_fetch_dial_for_test(const char *peer_addr, uint16_t port);

/* Reachability (connect) and speed (per-recv silence) are separate axes on
 * each transport; a test asserts the shape rather than an elapsed duration. */
struct rom_fetch_dial_budgets {
    int clearnet_connect_ms;
    int clearnet_io_ms;
    int clearnet_probe_io_ms;
    int onion_connect_ms;
    int onion_io_ms;
    int onion_probe_io_ms;
};
void rom_fetch_dial_budgets_for_test(struct rom_fetch_dial_budgets *out);

/* Count of SUCCESSFUL dials (rf_connect returning a live fd) since the last
 * reset. A dial is the expensive unit on a slow link — a TCP handshake plus
 * the two-round-trip X25519/HKDF key confirmation, or a whole Tor circuit —
 * so "how many dials does one download cost" is the boot-latency number this
 * counter exists to pin. It counts CONNECTIONS, never milliseconds: it must
 * not be read as a statement about how fast a peer is allowed to be. */
void     rom_fetch_dial_count_reset_for_test(void);
uint64_t rom_fetch_dial_count_for_test(void);

/* Count of FAILED dials (rf_connect returning no socket) since the same reset.
 * A failed dial is a stall the boot paid in full: a refused port, or the whole
 * transport-scaled connect budget elapsing on a peer that is gone. It is the
 * instrument for "how many times did one download pay to discover the same
 * peer is unreachable", and, like its sibling, it counts EVENTS and says
 * nothing about how long any peer is allowed to take. */
uint64_t rom_fetch_dial_fail_count_for_test(void);
#endif

#endif /* ZCL_NET_ROM_FETCH_H */
