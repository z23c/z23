/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ROM-fetch controller: the native command handlers for
 * `ops.debug.rom_fetch.*` — the operator surface of the fetch engine
 * (docs/ROM_DELIVERY.md, docs/work/wt-rom-fetch-engine.md). Each handler
 * parses its input, delegates to net/rom_fetch.h, and renders one bounded
 * JSON document into reply->data (parse -> authorize -> call one service,
 * per the controller shape). Every failure path sets a structured error
 * body via zcl_command_reply_fail.
 *
 * Trust model: the `bundle` leaf takes the expected digests as EXPLICIT
 * operator input (root/whole_sha3/size) — the operator commits to the
 * content before a single byte is requested. The engine downloads +
 * content-verifies the file and leaves it at <datadir>/<filename>; it
 * NEVER installs or activates it. Activation funnels only through the
 * unified installer's RECEIPT / CHECKPOINT_CONTENT authority
 * (-install-consensus-bundle), which the operator runs separately.
 *
 * Nested under `ops.debug` for the same reason ops.debug.rom_seed is (the
 * top-level ops menu is at its ZCL_COMMAND_BRANCH_BUDGET ceiling). */

#include "kernel/command_registry.h"
#include "command/native_command.h"
#include "controllers/diagnostics_internal.h"
#include "net/rom_fetch.h"
#include "net/rom_journal.h"      /* pre-download reused-bytes accounting */
#include "net/file_service.h"     /* FS_PORT default */
#include "net/rom_seed.h"         /* ROM_SEED_* bounds */
#include "services/sync_benchmark_service.h" /* zcl.sync_benchmark.v1 receipt */
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "util/safe_alloc.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RFC_SUBSYS "ops.debug.rom_fetch"

/* ── ops.debug.rom_fetch.status ─────────────────────────────────────── */
void zcl_native_handle_rom_fetch_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    (void)request;
    struct json_value body;
    json_init(&body);
    (void)rom_fetch_dump_state_json(&body, NULL);
    json_copy(&reply->data, &body);
    json_free(&body);
}

/* ── ops.debug.rom_fetch.bundle ─────────────────────────────────────── */

static const char *rfc_input(const struct zcl_command_request *request,
                             const char *key)
{
    const char *v = json_get_str(json_get(request->input, key));
    return v ? v : "";
}

static bool rfc_parse_hex32(const char *hex, uint8_t out[32])
{
    return hex && strlen(hex) == 64 && ParseHex(hex, out, 32) == 32;
}

/* Mirrors the filename-from-digest fallback the download drivers apply
 * internally (rom_fetch.c) when the operator gave no `filename` — needed
 * here too so the pre-download journal accounting below looks at the exact
 * same `.part.journal` path the driver will open. Idempotent: a no-op if
 * `m->filename` is already set. */
static void rfc_derive_filename(struct rom_fetch_manifest *m)
{
    if (m->filename[0])
        return;
    char hex[17];
    HexStr(m->chunk_root, 8, false, hex, sizeof(hex));
    snprintf(m->filename, sizeof(m->filename), "rom-artifact-%s", hex);
}

/* Best-effort pre-download accounting: how much of this artifact is already
 * durable + digest-verified in a prior download's resume journal (a set
 * journal bit always implies verified data — net/rom_journal.h). Opening the
 * journal here is side-effect-free with respect to the download that follows:
 * same (chunk_root, whole_sha3, chunk_size, num_chunks) identity, so the
 * driver's own rom_journal_open() reads back exactly what this left behind
 * (or, on a genuinely stale/mismatched journal, both calls independently
 * discard-and-recreate the same way). Returns false (0/0) if there is no
 * journal yet or it could not be opened — never fatal to the caller. */
static void rfc_journal_reused(const char *out_dir,
                               const struct rom_fetch_manifest *m,
                               uint32_t *out_chunks, uint64_t *out_bytes)
{
    *out_chunks = 0;
    *out_bytes = 0;

    char part_path[1200];
    int pn = snprintf(part_path, sizeof(part_path), "%s/%s%s",
                      out_dir, m->filename, ROM_FETCH_PART_SUFFIX);
    if (pn <= 0 || (size_t)pn >= sizeof(part_path))
        return;
    char jrnl_path[1264];
    pn = snprintf(jrnl_path, sizeof(jrnl_path), "%s.journal", part_path);
    if (pn <= 0 || (size_t)pn >= sizeof(jrnl_path))
        return;

    struct rom_journal *j = rom_journal_open(jrnl_path, m->chunk_root,
                                             m->whole_sha3, m->chunk_size,
                                             m->num_chunks);
    if (!j)
        return;

    uint32_t done = 0;
    uint64_t bytes = 0;
    for (uint32_t i = 0; i < m->num_chunks; i++) {
        if (!rom_journal_is_done(j, i))
            continue;
        uint64_t offset = (uint64_t)i * m->chunk_size;
        uint32_t want = m->chunk_size;
        uint64_t remaining = m->size_bytes - offset;
        if (remaining < want)
            want = (uint32_t)remaining;
        done++;
        bytes += want;
    }
    rom_journal_close(j);
    *out_chunks = done;
    *out_bytes = bytes;
}

void zcl_native_handle_rom_fetch_bundle(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    const char *peer = rfc_input(request, "peer");
    const char *port_s = rfc_input(request, "port");
    const char *root_s = rfc_input(request, "root");
    const char *whole_s = rfc_input(request, "whole_sha3");
    const char *size_s = rfc_input(request, "size");
    const char *filename = rfc_input(request, "filename");
    const char *out_dir = rfc_input(request, "out_dir");

    if (!peer[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_PEER",
                               "parse", false, false,
                               "input.peer is required (the seeder's "
                               "file-service host)", RFC_SUBSYS);
        return;
    }
    if (!out_dir[0])
        out_dir = diag_datadir();
    if (!out_dir[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "NO_OUT_DIR",
                               "parse", false, false,
                               "no input.out_dir given and the node datadir "
                               "is not available to this process", RFC_SUBSYS);
        return;
    }

    uint16_t port = FS_PORT;
    if (port_s[0]) {
        char *end = NULL;
        long p = strtol(port_s, &end, 10);
        if (!end || *end != '\0' || p < 1 || p > 65535) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INVALID, "BAD_PORT",
                                   "parse", false, false,
                                   "input.port must be 1..65535", RFC_SUBSYS);
            return;
        }
        port = (uint16_t)p;
    }

    struct rom_fetch_manifest m;
    memset(&m, 0, sizeof(m));
    m.used = true;
    if (!rfc_parse_hex32(root_s, m.chunk_root)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_ROOT",
                               "parse", false, false,
                               "input.root must be the 64-hex chunk_root the "
                               "operator committed to (from a trusted "
                               "directory listing or the bundle publisher)",
                               RFC_SUBSYS);
        return;
    }
    if (!rfc_parse_hex32(whole_s, m.whole_sha3)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_WHOLE_SHA3",
                               "parse", false, false,
                               "input.whole_sha3 must be the 64-hex "
                               "whole-file digest the operator committed to",
                               RFC_SUBSYS);
        return;
    }
    if (!size_s[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_SIZE",
                               "parse", false, false,
                               "input.size (bytes, decimal) is required",
                               RFC_SUBSYS);
        return;
    }
    {
        char *end = NULL;
        unsigned long long sz = strtoull(size_s, &end, 10);
        if (!end || *end != '\0' || sz == 0) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INVALID, "BAD_SIZE",
                                   "parse", false, false,
                                   "input.size must be a positive decimal "
                                   "byte count", RFC_SUBSYS);
            return;
        }
        m.size_bytes = (uint64_t)sz;
    }
    m.chunk_size = ROM_SEED_CHUNK_SIZE;
    m.num_chunks =
        (uint32_t)((m.size_bytes + m.chunk_size - 1) / m.chunk_size);
    if (filename[0]) {
        if (strlen(filename) >= sizeof(m.filename)) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INVALID, "BAD_FILENAME",
                                   "parse", false, false,
                                   "input.filename is too long", RFC_SUBSYS);
            return;
        }
        snprintf(m.filename, sizeof(m.filename), "%s", filename);
    }
    if (!rom_fetch_manifest_sane(&m)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID,
                               "MANIFEST_NOT_SANE", "parse", false, false,
                               "the committed (size, chunking, filename) "
                               "tuple fails the ROM artifact bounds — check "
                               "size/filename against the publisher's "
                               "manifest", RFC_SUBSYS);
        return;
    }
    rfc_derive_filename(&m);

    /* zcl.sync_benchmark.v1: instrument the artifact-fetch slice of fast sync.
     * This command drives only the manifest + artifact_download phases; the
     * peer_discovery / headers / verify / install / tail phases belong to the
     * boot sync orchestrator, so the receipt written below is deliberately
     * marked incomplete and its other phases stay null-with-reason. Real reuse
     * accounting comes from rfc_journal_reused() (the ROM resume journal). */
    {
        char artifact_hex[65];
        HexStr(m.chunk_root, 32, false, artifact_hex, sizeof(artifact_hex));
        sync_benchmark_init(out_dir);
        sync_benchmark_set_artifact(artifact_hex);
    }

    /* Synchronous download + content proof. Blocks this command worker for
     * the duration (minutes for a full bundle over a slow peer); a
     * background/scheduling engine is the follow-up lane.
     * `peer` may be a comma-separated host list (all sharing `port`): a
     * single peer prefers the per-chunk-verified manifest path (falling back
     * to the whole-file-only driver if the seeder doesn't serve a manifest —
     * a legacy seeder, never an offence); several peers ALSO prefer the
     * per-chunk-verified path (rom_fetch_download_verified_parallel: round-robin
     * chunk fetch with content-verify-and-failover across seeders), and fall
     * back to the whole-file-only multi-seeder scheduler only when no reachable
     * peer serves a manifest. */
    bool fetched = false;
    bool fallback_used = false;
    bool used_manifest_path = false;
    uint32_t chunks_verified = 0;
    uint32_t reused_chunks = 0;
    uint64_t reused_bytes = 0;
    if (strchr(peer, ',')) {
        struct rom_fetch_peer peers[4];
        size_t npeers = 0;
        char list[512];
        snprintf(list, sizeof(list), "%s", peer);
        for (char *tok = strtok(list, ","); tok && npeers < 4;
             tok = strtok(NULL, ",")) {
            while (*tok == ' ')
                tok++;
            size_t tl = strlen(tok);
            while (tl > 0 && tok[tl - 1] == ' ')
                tok[--tl] = '\0';
            if (tl == 0 || tl >= sizeof(peers[0].addr))
                continue;
            snprintf(peers[npeers].addr, sizeof(peers[npeers].addr),
                     "%s", tok);
            peers[npeers].port = port;
            npeers++;
        }
        if (npeers == 0) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INVALID, "BAD_PEER_LIST",
                                   "parse", false, false,
                                   "input.peer held a comma but no usable "
                                   "host", RFC_SUBSYS);
            return;
        }
        uint32_t workers = (uint32_t)(2 * npeers);
        if (workers > ROM_FETCH_MAX_WORKERS)
            workers = ROM_FETCH_MAX_WORKERS;

        /* Prefer the per-chunk-verified multi-seeder path: probe reachable
         * peers for the "RMF" manifest and, on the first that serves one
         * matching the committed num_chunks, run the content-verify-and-failover
         * download (trustable resume + per-chunk content proof across flaky
         * seeders). Only if NO peer serves a manifest — an all-legacy seeder
         * set — do we take the whole-file-only multi-seeder scheduler. */
        uint8_t (*chunk_sha3)[32] = zcl_malloc(
            (size_t)ROM_SEED_MAX_CHUNKS * 32, "rfc_par_chunk_sha3");
        uint32_t manifest_chunks = 0;
        bool have_manifest = false;
        sync_benchmark_phase_begin(SYNC_BENCH_MANIFEST);
        for (size_t i = 0; chunk_sha3 && i < npeers && !have_manifest; i++) {
            if (rom_fetch_get_manifest(peers[i].addr, peers[i].port,
                                       m.chunk_root, chunk_sha3,
                                       ROM_SEED_MAX_CHUNKS, &manifest_chunks) &&
                manifest_chunks == m.num_chunks)
                have_manifest = true;
        }
        sync_benchmark_phase_end(SYNC_BENCH_MANIFEST);
        if (have_manifest) {
            rfc_journal_reused(out_dir, &m, &reused_chunks, &reused_bytes);
            sync_benchmark_note_reused(reused_bytes);
            sync_benchmark_phase_begin(SYNC_BENCH_ARTIFACT_DOWNLOAD);
            fetched = rom_fetch_download_verified_parallel(
                peers, npeers, &m, chunk_sha3, manifest_chunks, out_dir,
                NULL, NULL);
            sync_benchmark_phase_end(SYNC_BENCH_ARTIFACT_DOWNLOAD);
            used_manifest_path = true;
            chunks_verified = manifest_chunks;
        } else {
            sync_benchmark_phase_begin(SYNC_BENCH_ARTIFACT_DOWNLOAD);
            fetched = rom_fetch_download_parallel(peers, npeers, &m, out_dir,
                                                  workers, NULL, NULL);
            sync_benchmark_phase_end(SYNC_BENCH_ARTIFACT_DOWNLOAD);
            fallback_used = true; /* whole-file-only path across seeders */
        }
        free(chunk_sha3);
    } else {
        uint8_t (*chunk_sha3)[32] = zcl_malloc(
            (size_t)ROM_SEED_MAX_CHUNKS * 32, "rfc_manifest_chunk_sha3");
        uint32_t manifest_chunks = 0;
        sync_benchmark_phase_begin(SYNC_BENCH_MANIFEST);
        bool have_manifest = chunk_sha3 &&
            rom_fetch_get_manifest(peer, port, m.chunk_root, chunk_sha3,
                                   ROM_SEED_MAX_CHUNKS, &manifest_chunks);
        sync_benchmark_phase_end(SYNC_BENCH_MANIFEST);
        if (have_manifest && manifest_chunks == m.num_chunks) {
            rfc_journal_reused(out_dir, &m, &reused_chunks, &reused_bytes);
            sync_benchmark_note_reused(reused_bytes);
            sync_benchmark_phase_begin(SYNC_BENCH_ARTIFACT_DOWNLOAD);
            fetched = rom_fetch_download_verified(peer, port, &m, chunk_sha3,
                                                  manifest_chunks, out_dir,
                                                  NULL, NULL);
            sync_benchmark_phase_end(SYNC_BENCH_ARTIFACT_DOWNLOAD);
            used_manifest_path = true;
            chunks_verified = manifest_chunks;
        } else {
            if (have_manifest)
                LOG_WARN(RFC_SUBSYS, "manifest chunk count %u != committed "
                         "num_chunks %u from %s:%u — falling back to "
                         "whole-file verify", manifest_chunks, m.num_chunks,
                         peer, (unsigned)port);
            fallback_used = true;
            sync_benchmark_phase_begin(SYNC_BENCH_ARTIFACT_DOWNLOAD);
            fetched = rom_fetch_download(peer, port, &m, out_dir, NULL, NULL);
            sync_benchmark_phase_end(SYNC_BENCH_ARTIFACT_DOWNLOAD);
        }
        free(chunk_sha3);
    }
    if (!fetched) {
        /* Honest abort receipt: only the phases that DID finish are recorded
         * (artifact_download is left in-progress → null-with-reason), never a
         * receipt implying a full fast sync happened. */
        (void)sync_benchmark_write_receipt(
            false, "artifact_download_failed via ops.debug.rom_fetch.bundle");
        struct rom_fetch_status st;
        rom_fetch_status_snapshot(&st);
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "fetch from %s:%u failed: %s", peer, (unsigned)port,
                 st.detail[0] ? st.detail : "see node log");
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "ROM_FETCH_FAILED",
                               "execute", true, false, msg, RFC_SUBSYS);
        (void)zcl_command_reply_add_next(reply, "ops.debug.rom_fetch.status",
                                         "{}", "inspect the fetch status");
        return;
    }

    /* The download derives a name from the digest when none was given; the
     * status snapshot holds the post-derivation name. */
    struct rom_fetch_status st;
    rom_fetch_status_snapshot(&st);
    (void)json_push_kv_str(&reply->data, "installed", st.filename);
    char path[1200];
    snprintf(path, sizeof(path), "%s/%s", out_dir, st.filename);
    (void)json_push_kv_str(&reply->data, "path", path);
    (void)json_push_kv_int(&reply->data, "size_bytes",
                           (int64_t)m.size_bytes);
    (void)json_push_kv_int(&reply->data, "num_chunks",
                           (int64_t)m.num_chunks);
    (void)json_push_kv_bool(&reply->data, "verified", true);
    char root_hex[65];
    HexStr(m.chunk_root, 32, false, root_hex, sizeof(root_hex));
    (void)json_push_kv_str(&reply->data, "chunk_root", root_hex);

    /* Per-chunk protocol observability (lane 2C/2D, wf/artifact-protocol). */
    (void)json_push_kv_bool(&reply->data, "used_manifest_path",
                            used_manifest_path);
    (void)json_push_kv_bool(&reply->data, "fallback_used", fallback_used);
    if (used_manifest_path) {
        (void)json_push_kv_int(&reply->data, "chunks_verified",
                               (int64_t)chunks_verified);
        (void)json_push_kv_int(&reply->data, "bytes_reused_from_journal",
                               (int64_t)reused_bytes);
        (void)json_push_kv_int(&reply->data, "chunks_reused_from_journal",
                               (int64_t)reused_chunks);
    }

    (void)json_push_kv_str(&reply->data, "next",
                           "reboot with -install-consensus-bundle=<path> to "
                           "activate through the unified installer");

    /* Record the download-side resource counters and write the durable
     * zcl.sync_benchmark.v1 receipt. Marked incomplete: this command exercises
     * the artifact fetch only, not the whole T_ready/T_sovereign sync. The
     * downloaded byte count nets out journal-reused bytes (the resume path). */
    uint64_t fresh_bytes =
        (m.size_bytes > reused_bytes) ? (m.size_bytes - reused_bytes) : 0;
    sync_benchmark_note_downloaded(fresh_bytes);
    if (sync_benchmark_write_receipt(
            false, "artifact_fetch_only via ops.debug.rom_fetch.bundle; "
                   "peer_discovery/headers/verify/install/tail phases not "
                   "exercised by this command")) {
        char bench_path[640];
        snprintf(bench_path, sizeof(bench_path), "%s/sync_benchmark.json",
                 out_dir);
        (void)json_push_kv_str(&reply->data, "benchmark_receipt", bench_path);
    }
}

/* ── Hot-swappable leaves ──────────────────────────────────────────────────
 * Read-only ROM FETCH diagnostics. Every mutating sibling in this file is
 * absent from the table; the loader refuses to re-point a leaf that is
 * missing from this file's row in config/hotswap_swappable.def. */
#if defined(ZCL_HOTSWAP_GEN) || defined(ZCL_HOTSWAP_MODULE_GEN)
#define ZCL_HOTSWAP_PROBE_LEAF "ops.debug.rom_fetch.status"
#include "hotswap/hotswap_register.h"
ZCL_HOTSWAP_LEAVES_BEGIN(rom_fetch)
ZCL_HOTSWAP_LEAF("ops.debug.rom_fetch.status", zcl_native_handle_rom_fetch_status)
ZCL_HOTSWAP_LEAVES_END(rom_fetch)
#endif
