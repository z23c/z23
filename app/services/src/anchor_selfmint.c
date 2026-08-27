// one-result-type-ok:selfmint-best-effort-semantics
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * anchor_selfmint — implementation. See services/anchor_selfmint.h.
 *
 * Return type is bare void (NOT struct zcl_result), same as seal_service: this
 * is OBSERVE-ONLY and BEST-EFFORT — a write/verify failure here MUST NOT fail
 * the block, so there is nothing for a caller to branch on. A failure is logged
 * (LOG_WARN) and dropped.
 *
 * The snapshot writer (coins_kv_snapshot_write) carries the raw-sqlite hatch for
 * the cross-thread progress.kv handle; this TU only resolves a path, probes an
 * existing file via uss_open (read-only mmap), and calls that writer. No raw
 * sqlite here.
 */

#include "services/anchor_selfmint.h"

#include "chain/checkpoints.h"
#include "chain/utxo_snapshot_loader.h"
#include "storage/coins_kv.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void anchor_hex32(const uint8_t in[32], char out[65])
{
    if (!out)
        return;
    for (int i = 0; i < 32; i++)
        snprintf(out + 2 * i, 3, "%02x", in ? in[i] : 0);
}

bool anchor_selfmint_resolve_path(const char *datadir, char *buf, size_t cap)
{
    if (!buf || cap == 0)
        return false;
    const char *env_out = getenv("ZCL_MINT_ANCHOR_OUT");
    if (env_out && env_out[0]) {
        int n = snprintf(buf, cap, "%s", env_out);
        return n > 0 && (size_t)n < cap;
    }
    const char *dir = (datadir && datadir[0]) ? datadir : ".";
    int n = snprintf(buf, cap, "%s/utxo-anchor.snapshot", dir);
    return n > 0 && (size_t)n < cap;
}

bool anchor_selfmint_snapshot_status(const char *datadir,
                                     struct anchor_snapshot_status *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));

    const char *env_out = getenv("ZCL_MINT_ANCHOR_OUT");
    snprintf(out->path_source, sizeof(out->path_source), "%s",
             (env_out && env_out[0]) ? "ZCL_MINT_ANCHOR_OUT" : "datadir");

    out->path_resolved =
        anchor_selfmint_resolve_path(datadir, out->path, sizeof(out->path));
    if (!out->path_resolved) {
        snprintf(out->verification, sizeof(out->verification),
                 "path_unresolved");
        snprintf(out->error, sizeof(out->error),
                 "could not resolve anchor snapshot path");
        snprintf(out->next_action, sizeof(out->next_action),
                 "fix datadir or ZCL_MINT_ANCHOR_OUT path");
        return true;
    }

    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    out->checkpoint_present = cp != NULL;
    if (!cp) {
        snprintf(out->verification, sizeof(out->verification),
                 "checkpoint_missing");
        snprintf(out->error, sizeof(out->error),
                 "compiled SHA3 UTXO checkpoint is unavailable");
        snprintf(out->next_action, sizeof(out->next_action),
                 "rebuild with a compiled SHA3 UTXO checkpoint");
        return true;
    }

    out->checkpoint_height = cp->height;
    out->checkpoint_utxo_count = cp->utxo_count;
    out->checkpoint_total_supply = cp->total_supply;
    anchor_hex32(cp->sha3_hash, out->checkpoint_sha3_hex);
    anchor_hex32(cp->block_hash, out->checkpoint_block_hash_hex);

    struct stat st;
    if (stat(out->path, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_size <= 0) {
        out->stat_present = false;
        out->stat_size = 0;
        snprintf(out->verification, sizeof(out->verification),
                 "missing");
        snprintf(out->error, sizeof(out->error),
                 "anchor snapshot candidate is absent");
        snprintf(out->next_action, sizeof(out->next_action),
                 "mint or stage %.180s, then run refold copy proof",
                 out->path);
        return true;
    }

    out->stat_present = true;
    out->stat_size = (int64_t)st.st_size;

    char err[256] = {0};
    struct uss_header hdr;
    memset(&hdr, 0, sizeof(hdr));
    struct uss_handle *peek = uss_open(out->path, /*verify_full_sha3=*/false,
                                       NULL, &hdr, err, sizeof(err));
    if (peek) {
        out->header_read = true;
        out->snapshot_height = hdr.height;
        out->snapshot_count = hdr.count;
        out->snapshot_total_supply = hdr.total_supply;
        anchor_hex32(hdr.sha3_hash, out->snapshot_sha3_hex);
        anchor_hex32(hdr.anchor_block_hash, out->snapshot_block_hash_hex);
        out->height_match = (int32_t)hdr.height == cp->height;
        out->count_match = hdr.count == cp->utxo_count;
        /* sha3_match is NOT a header-hash compare: the compiled checkpoint pins
         * the COINS-ONLY commitment, while hdr.sha3_hash is the artifact's OWN
         * full-body hash (coins-only for a v1 artifact, coins+shielded for a v3
         * one). A direct compare here false-rejects every valid v3 snapshot. It
         * is set below from the recomputed coins-only component vs cp->sha3_hash
         * (the value the checkpoint actually pins), mirroring
         * boot_legacy_uss_matches_checkpoint. Left at its zeroed default here. */
        out->block_hash_match =
            memcmp(hdr.anchor_block_hash, cp->block_hash, 32) == 0;
        uss_close(peek);
    } else {
        snprintf(out->verification, sizeof(out->verification),
                 "header_unreadable");
        snprintf(out->error, sizeof(out->error), "%s",
                 err[0] ? err : "uss_open header read failed");
        snprintf(out->next_action, sizeof(out->next_action),
                 "replace %.180s with a minted checkpoint snapshot",
                 out->path);
        return true;
    }

    /* Admission is the SAME two-step predicate the cold-start gate uses
     * (boot_legacy_uss_matches_checkpoint via anchor_snapshot_verified_reachable):
     *   1. uss_open(verify_full_sha3=true, expected_sha3=NULL) — bind the WHOLE
     *      artifact (coins + any v3 shielded section) to its OWN header hash;
     *      NULL so we do NOT compare that full-body hash to the checkpoint.
     *   2. uss_utxo_component_compute() — recompute the COINS-ONLY commitment and
     *      bind THAT to cp->sha3_hash, the value the compiled checkpoint pins.
     * Passing cp->sha3_hash as expected_sha3 in step 1 was the bug: for a v3
     * artifact the header carries the coins+shielded hash, so it could NEVER
     * equal the coins-only checkpoint and every valid v3 snapshot was rejected
     * as "sha3_or_format_mismatch". Verification is NOT weakened — the coins
     * commitment still must equal the checkpoint exactly; only WHICH hash is
     * compared is corrected. */
    err[0] = '\0';
    struct uss_header verified_hdr;
    memset(&verified_hdr, 0, sizeof(verified_hdr));
    struct uss_handle *h = uss_open(out->path, /*verify_full_sha3=*/true,
                                    /*expected_sha3=*/NULL, &verified_hdr, err,
                                    sizeof(err));
    if (h) {
        struct uss_utxo_component comp;
        char cerr[256] = {0};
        bool comp_ok =
            uss_utxo_component_compute(h, &comp, cerr, sizeof(cerr));
        uss_close(h);
        bool sha3_ok = comp_ok && memcmp(comp.sha3_hash, cp->sha3_hash, 32) == 0;
        bool count_ok = comp_ok && comp.count == cp->utxo_count;
        out->sha3_match = sha3_ok;
        out->count_match = count_ok;
        out->verified = sha3_ok && count_ok;
        if (out->verified) {
            snprintf(out->verification, sizeof(out->verification),
                     "verified");
            snprintf(out->next_action, sizeof(out->next_action),
                     "run repro-on-copy with -refold-from-anchor and "
                     "CLIMB_PAST=%d", cp->height);
        } else if (!comp_ok) {
            snprintf(out->verification, sizeof(out->verification),
                     "component_unreadable");
            snprintf(out->error, sizeof(out->error), "%s",
                     cerr[0] ? cerr : "coins-only component recompute failed");
            snprintf(out->next_action, sizeof(out->next_action),
                     "replace %.180s with a checkpoint-matching minted snapshot",
                     out->path);
        } else if (!sha3_ok) {
            snprintf(out->verification, sizeof(out->verification),
                     "sha3_mismatch");
            snprintf(out->error, sizeof(out->error),
                     "coins-only commitment does not match checkpoint");
            snprintf(out->next_action, sizeof(out->next_action),
                     "replace %.170s with a snapshot minted at checkpoint height %d",
                     out->path, cp->height);
        } else {
            snprintf(out->verification, sizeof(out->verification),
                     "count_mismatch");
            snprintf(out->error, sizeof(out->error),
                     "snapshot count does not match checkpoint");
            snprintf(out->next_action, sizeof(out->next_action),
                     "replace %.170s with a snapshot minted at checkpoint height %d",
                     out->path, cp->height);
        }
        return true;
    }

    out->verified = false;
    snprintf(out->verification, sizeof(out->verification),
             "sha3_or_format_mismatch");
    snprintf(out->error, sizeof(out->error), "%s",
             err[0] ? err : "full SHA3 verification failed");
    snprintf(out->next_action, sizeof(out->next_action),
             "replace %.180s with a SHA3/count-verified minted snapshot",
             out->path);
    return true;
}

/* True iff a SHA3-verified snapshot bound to `cp` already exists at `path`.
 * Reuses the existing loader's verification (full-body SHA3 + expected_sha3 ==
 * cp->sha3_hash + count match) — never reimplemented. Read-only mmap, closed
 * immediately. A NULL handle means absent / wrong-magic / wrong-version /
 * SHA3-mismatch — every "no usable verified snapshot" case. */
static bool verified_snapshot_present(const char *path,
                                      const struct sha3_utxo_checkpoint *cp)
{
    char err[256] = {0};
    struct uss_header hdr;
    struct uss_handle *h = uss_open(path, /*verify_full_sha3=*/true,
                                    cp->sha3_hash, &hdr, err, sizeof(err));
    if (!h)
        return false;
    bool ok = (hdr.count == cp->utxo_count);
    uss_close(h);
    return ok;
}

void anchor_selfmint_hook_in_tx(struct sqlite3 *db, const char *datadir,
                                int32_t next_cursor)
{
    if (!db)
        return;

    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    if (!cp)
        return;  /* no compiled checkpoint to mint toward */

    /* One-shot at the EXACT anchor crossing. next_cursor is the just-applied
     * frontier (cursor_in + 1); == cp->height is the apply that lands the anchor
     * block, when coins_kv provably holds the applied-through-anchor set inside
     * the caller's stage txn. Below or above the anchor coins_kv is NOT the
     * anchor set — never mint then. Gated on the EXACT height, NOT on
     * is_initial_block_download (the anchor crossing is during IBD on a cold
     * sync). */
    if (next_cursor != cp->height)
        return;

    char path[1100];
    if (!anchor_selfmint_resolve_path(datadir, path, sizeof(path))) {
        LOG_WARN("selfmint", "[selfmint] could not resolve snapshot path "
                 "(datadir=%s) — skipping anchor self-mint",
                 datadir ? datadir : "(null)");
        return;
    }

    /* Idempotency: a valid SHA3-verified snapshot already at the path is left
     * untouched — never rewrite a good artifact (and never pay the scan twice).
     * A stale/corrupt/wrong-height file is treated as absent: the write below
     * atomically replaces it (tmp + rename), then HARD-VERIFY gates trust. */
    if (verified_snapshot_present(path, cp)) {
        LOG_INFO("selfmint", "[selfmint] verified anchor snapshot already "
                 "present at %s — not re-minting", path);
        return;
    }

    /* WRITE: stream the live coins_kv set (the committed applied-through-anchor
     * set) to the snapshot. coins_kv_snapshot_write writes atomically
     * (out_path.tmp then rename) and fills got_sha3 / got_count. This is a
     * read-only SELECT over coins; it does NOT mutate the fold or the txn's
     * consensus state — it only PERSISTS already-validated state. */
    uint8_t got_sha3[32] = {0};
    uint64_t got_count = 0;
    int64_t got_supply = 0;
    if (!coins_kv_snapshot_write(db, path, cp->height, cp->block_hash,
                                 /*shielded=*/NULL,
                                 got_sha3, &got_count, &got_supply)) {
        LOG_WARN("selfmint", "[selfmint] snapshot write to %s failed — leaving "
                 "no artifact (the offline -mint-anchor ceremony remains the "
                 "fallback)", path);
        return;  /* writer already removed its temp file on error */
    }

    /* HARD-VERIFY the written set == the compiled checkpoint. The writer's body
     * SHA3 equals coins_kv_commitment (same record encoder), so a match here
     * proves our independently-folded anchor set reproduces the compiled
     * checkpoint exactly. A MISMATCH means our fold disagrees with the
     * checkpoint (the h=478544 class) — UNLINK the artifact so a later
     * -refold-from-anchor can NEVER load an unverified set, and LOG_WARN (NOT
     * fatal — this is observe-only and must not fail the block). */
    bool sha3_match = memcmp(got_sha3, cp->sha3_hash, 32) == 0;
    bool count_match = got_count == cp->utxo_count;
    if (!sha3_match || !count_match) {
        char want_hex[65], got_hex[65];
        for (int i = 0; i < 32; i++) {
            snprintf(want_hex + 2 * i, 3, "%02x", cp->sha3_hash[i]);
            snprintf(got_hex + 2 * i, 3, "%02x", got_sha3[i]);
        }
        LOG_WARN("selfmint", "[selfmint] minted anchor set FAILED the SHA3/count "
                 "check (count=%llu want=%llu sha3=%s want=%s) — our fold "
                 "disagrees with the compiled checkpoint; UNLINKING %s (never "
                 "publish an unverified artifact)",
                 (unsigned long long)got_count,
                 (unsigned long long)cp->utxo_count, got_hex, want_hex, path);
        unlink(path);
        return;
    }

    char sha3_hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(sha3_hex + 2 * i, 3, "%02x", got_sha3[i]);
    LOG_INFO("selfmint", "[selfmint] SELF-MINTED the verified anchor UTXO set at "
             "h=%d (count=%llu, supply=%lld zatoshi, sha3=%s) from the live fold "
             "— matches the compiled checkpoint. Snapshot artifact: %s (the "
             "torn-import self-heal can now re-seed from it)",
             cp->height, (unsigned long long)got_count, (long long)got_supply,
             sha3_hex, path);
}
