/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Load Zcash zkSNARK verification keys from params files. */

#include "sapling/params_init.h"
#include "sapling/bls12_381.h"
#include "sapling/bn254.h"
#include "sapling/sapling.h"
#include "sapling/sapling_prover.h"
#include "sapling/sprout.h"
#include "chain/chainparams.h"
#include "crypto/sha256.h"
#include "crypto/sha512.h"
#include "sapling/params_vk_embedded.h"
#include "encoding/utilstrencodings.h"
#include "util/file_io.h"
#include "util/log_macros.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Expected SHA-512 digests of the full Zcash parameter files, as produced
 * by Zcash's canonical fetch-params.sh distribution (MPC-ceremony output,
 * deterministic across downloads — every correctly-fetched file has these
 * hashes). Baked in here so the integrity check cannot be disabled at
 * runtime; if they fail to match, the param files on disk were tampered
 * with and the node refuses to start rather than feed unknown params into
 * Groth16/PHGR13 verification. */
#define SAPLING_SPEND_PARAMS_SHA512                                          \
    "320fbb5754c8b3f4ecb3dd4c2e3dbe1d138c4b343f073c7e31612d26fe769cdb"       \
    "a8edab426a7f2c42e317bebdb2ca6f73af1312affa1fcf599a31d499ad4cb4e5"
#define SAPLING_OUTPUT_PARAMS_SHA512                                         \
    "a7c87f52c0c1eb05b4da1e1e70d986bde95a2a74047b0679d0163ade7ced3cbf"       \
    "93c1c7e3954416e5baacff614e1d0d5dfaed7b9b7d3141fa595259b23c32f152"
#define SPROUT_GROTH16_PARAMS_SHA512                                         \
    "20bc1f6bd89d0321b90a3f1b7e2050a7dafb427e86e7ef33b0b7a5c06077f5bf"       \
    "5695846952eac2b6231222df633e258682e9b6e2545f732c30fd76ae230ac65d"
/* sprout-verifying.key was the ONE required file with no integrity pin: it
 * was read and handed straight to ppzksnark_vk_read with only a parse check,
 * and a parse check is not an integrity check. A tampered key that still
 * parses would have been installed as the PHGR13 verifying key and used to
 * validate every pre-Sapling JoinSplit proof (blocks 0-581876). Pinned here
 * so all four required files are checked the same way. */
#define SPROUT_VERIFYING_KEY_SHA512                                          \
    "2fe237bd39739b17e1d078931a5ccfc1f5ab81ea6457738fc5f0a1a487af994f"       \
    "f4e3323792ff657e79d833f320b87a015e3939d3d9af246af1c46d207ab1a797"

/* Canonical BLAKE2b-512 ceremony-file digests retained for the optional
 * reference oracle ABI. They are intentionally separate from the mandatory
 * SHA-512 integrity gate above. The production native C23 prover consumes the
 * already-verified parameter bytes directly. */
#define SAPLING_SPEND_PARAMS_BLAKE2B                                        \
    "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca639"       \
    "91ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c"
#define SAPLING_OUTPUT_PARAMS_BLAKE2B                                       \
    "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60b"       \
    "f593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028"
#define SPROUT_GROTH16_PARAMS_BLAKE2B                                       \
    "e9b238411bd6c0ec4791e9d04245ec350c9c5744f5610dfcce4365d5ca49dfef"       \
    "d5054e371842b3f88fa1b9d7e8e075249b3ebabd167fa8b0f3161292d36c180a"

/* Compute SHA-512 of a buffer and compare against the expected hex digest
 * in constant time. On mismatch, print expected/actual and return false so
 * startup fails loud — parameter-file tampering is consensus-critical. */
static bool params_sha512_matches(const uint8_t *data, size_t len,
                                   const char *expected_hex,
                                   const char *path)
{
    uint8_t got[64];
    struct sha512_ctx ctx;
    sha512_init(&ctx);
    sha512_write(&ctx, data, len);
    sha512_finalize(&ctx, got);

    uint8_t want[64];
    if (ParseHex(expected_hex, want, 64) != 64) {
        LOG_FAIL("sapling",
                 "internal: malformed expected SHA-512 literal for %s",
                 path);
    }

    /* Constant-time comparison — not strictly needed here (no timing
     * oracle on param files) but cheap insurance. */
    uint32_t diff = 0;
    for (int i = 0; i < 64; i++) diff |= (uint32_t)(got[i] ^ want[i]);
    if (diff != 0) {
        char got_hex[129], want_hex[129];
        for (int i = 0; i < 64; i++) {
            snprintf(got_hex + 2 * i, 3, "%02x", got[i]);
            snprintf(want_hex + 2 * i, 3, "%02x", want[i]);
        }
        LOG_FAIL("sapling",
                 "params file SHA-512 mismatch: path=%s\n"
                 "  expected=%s\n  actual  =%s",
                 path, want_hex, got_hex);
    }
    return true;
}

static struct groth16_vk spend_vk;
static struct groth16_vk output_vk;
static struct groth16_vk sprout_groth16_vk;
static _Atomic bool params_loaded = false;
/* True when the running key set came from the compiled-in blobs rather than
 * a parameter directory. Declared here, beside params_loaded, because
 * sapling_free_params() clears both. */
static _Atomic bool vks_embedded = false;

/* params_loaded says the VERIFYING keys are published, and the compiled-in
 * fallback sets it too. This says the PROVING keys are loaded as well — a
 * strictly stronger claim, and the one sapling_init_params() has to gate on.
 * A node that came up on the fallback has params_loaded set and not one byte
 * of proving key, and gating the loader on params_loaded turned that node away
 * when its parameters finally arrived: shielded sending stayed dead, with a
 * fully verified parameter set sitting on disk, until the process restarted. */
static _Atomic bool proving_params_loaded = false;

static uint8_t *spend_pk_data = NULL;
static size_t spend_pk_len = 0;
static uint8_t *output_pk_data = NULL;
static size_t output_pk_len = 0;

/* ── Serialising the loaders ─────────────────────────────────────────────
 *
 * sapling_init_params(), sapling_install_embedded_vks() and
 * sapling_free_params() all move the same globals, and on a live node they are
 * reached from different threads: the boot loader thread, the parameter
 * fetcher's completion path once a download verifies, and shutdown. This mutex
 * makes each of those transitions run to completion alone, so no two of them
 * can interleave a publish with a free.
 *
 * It deliberately does NOT cover the consensus verifiers. They read the
 * published VK pointers with no lock, on the hot path, and must keep doing so.
 * What keeps them safe is the publish/free invariant below plus one rule this
 * file now obeys without exception:
 *
 *   ONCE PUBLISHED, NEVER REPLACED. After a verifying key becomes visible to
 *   the verifiers, no later call re-parses it, points the global somewhere
 *   else, or frees it. A second load only ever ADDS the proving keys. The one
 *   unpublish is sapling_free_params(), at shutdown.
 *
 * That rule is what makes a late upgrade safe without an RCU grace period:
 * there is nothing for a verifier to be reading that anybody is about to
 * change.
 *
 * LOG_FAIL expands to `return`, so anything holding this mutex would leak it
 * on the first failure. Every entry point is therefore a thin wrapper that
 * locks, calls a _locked() body, and unlocks — the wrapper is the only place
 * that unlocks, and the body is free to use LOG_FAIL. */
static pthread_mutex_t params_mu = PTHREAD_MUTEX_INITIALIZER;

static uint8_t *read_file(const char *path, size_t *len)
{
    uint8_t *buf = NULL;
    size_t n = 0;
    if (!zcl_read_whole_file(path, 0, &buf, &n, "sapling_params"))
        return NULL;
    if (n == 0)
        LOG_NULL("sapling_params", "read_file: %s is empty", path);
    *len = n;
    return buf;
}

/* ── The publish/free invariant ──────────────────────────────────────────
 *
 * INVARIANT: a verifying key is visible to the verifiers — sapling_spend_vk,
 * sapling_output_vk (sapling.c), sprout_vk (sprout.c), phgr_vk (bn254.c) —
 * only while its storage is fully built and no later step can free it.
 *
 * Two rules enforce it, and BOTH are required:
 *
 *   PUBLISH LAST     params_publish_groth16_vks() runs only after the last
 *                    step that can fail. No failure path can therefore leave
 *                    a pointer published.
 *   UNPUBLISH FIRST  params_release_groth16_vks() clears the globals BEFORE
 *                    it frees anything, and NULLs every freed field, so a
 *                    teardown never leaves a published pointer aimed at freed
 *                    storage — not even for an instant.
 *
 * This is load-bearing, not hygiene. The fail-closed guards in
 * sapling_check_spend / sapling_check_output / sprout_verify_groth16 all read
 * "a NULL VK means the keys are not ready, so reject". That reading is only
 * true while every failure path actually produces NULL. Publishing at the top
 * of the Sprout PHGR13 section and freeing at the bottom of it — which is what
 * this file used to do — made the guards blind to a struct whose ic[] and comb
 * tables had already been freed: non-NULL, so the guard passed, and
 * groth16_verify then read freed heap. Keep the publish below every fallible
 * step. */
static void params_publish_groth16_vks(void)
{
    sapling_set_spend_vk(&spend_vk);
    sapling_set_output_vk(&output_vk);
    sprout_set_vk(&sprout_groth16_vk);
}

static void params_release_groth16_vks(void)
{
    /* Unpublish first: after these three stores no verifier can be inside
     * groth16_verify with one of these pointers on a path it entered after
     * the store, and the guards reject rather than dereference. */
    sapling_set_spend_vk(NULL);
    sapling_set_output_vk(NULL);
    sprout_set_vk(NULL);

    groth16_vk_free_combs(&spend_vk);
    groth16_vk_free_combs(&output_vk);
    groth16_vk_free_combs(&sprout_groth16_vk);
    free(spend_vk.ic);
    free(output_vk.ic);
    free(sprout_groth16_vk.ic);
    memset(&spend_vk, 0, sizeof(spend_vk));
    memset(&output_vk, 0, sizeof(output_vk));
    memset(&sprout_groth16_vk, 0, sizeof(sprout_groth16_vk));
}

/* Read `name` out of `params_dir` and verify its pinned SHA-512 BEFORE the
 * bytes are handed back. Returns NULL — having freed whatever it read — when
 * the file is unreadable or fails its pin, so no caller can be given bytes
 * that did not match. */
static uint8_t *params_read_pinned(const char *params_dir, const char *name,
                                   const char *want_sha512, size_t *len)
{
    char path[1400];
    snprintf(path, sizeof(path), "%s/%s", params_dir, name);
    uint8_t *data = read_file(path, len);
    if (!data)
        LOG_NULL("sapling_params", "init: read_file failed for %s", name);
    if (!params_sha512_matches(data, *len, want_sha512, path)) {
        free(data);
        LOG_NULL("sapling_params", "init: SHA-512 mismatch on %s", name);
    }
    return data;
}

/* Install the proving keys and arm the proving backend. Takes ownership of
 * both buffers, which have already passed their pinned SHA-512.
 *
 * Nothing here is a consensus input, so nothing here can fail the load: a node
 * whose proving backend does not arm still validates every shielded proof.
 * What it must never do is arm on incomplete input.
 * zclassic_init_zksnark_params() refuses when either proving key is absent,
 * and zclassic_sapling_prover_is_ready() turns true only after the self-test
 * has produced a real Spend + Output + binding bundle and had THIS node's
 * consensus verifier accept it — against the verifying keys published above.
 * A proving key that did not belong to the published verifying key therefore
 * cannot arm sending; it fails the gate.
 *
 * Ordering is load-bearing for the reader. The two pointer stores happen
 * before the sequentially-consistent store that moves the prover to READY, and
 * every consumer of sapling_get_spend_pk()/_output_pk() reaches them only
 * through a caller that checked zclassic_sapling_prover_is_ready() first
 * (wallet_shielded_send.c, wallet_shielded_send_shielded.c). That
 * store/load pair is what publishes these bytes to another thread.
 *
 * Reached only with no proving key resident — the caller returns early once
 * proving_params_loaded is set, and that flag is set whenever these two
 * pointers are — so this deliberately does not free the old values. Assigning
 * over a live proving-key pointer would be the free-while-published bug in
 * another shape. */
static void params_arm_proving_locked(const char *params_dir,
                                      uint8_t *spend_bytes, size_t spend_len,
                                      uint8_t *output_bytes, size_t output_len)
{
    spend_pk_data = spend_bytes;
    spend_pk_len = spend_len;
    output_pk_data = output_bytes;
    output_pk_len = output_len;

    LOG_INFO("sapling_params",
             "Loaded sapling-output proving key: %zu bytes", output_pk_len);
    LOG_INFO("sapling_params",
             "Loaded sapling-spend proving key: %zu bytes", spend_pk_len);

    char spend_path[1400], output_path[1400], sprout_path[1400];
    snprintf(spend_path, sizeof(spend_path),
             "%s/sapling-spend.params", params_dir);
    snprintf(output_path, sizeof(output_path),
             "%s/sapling-output.params", params_dir);
    snprintf(sprout_path, sizeof(sprout_path),
             "%s/sprout-groth16.params", params_dir);

    zclassic_init_zksnark_params(
        (const uint8_t *)spend_path, strlen(spend_path),
        SAPLING_SPEND_PARAMS_BLAKE2B,
        (const uint8_t *)output_path, strlen(output_path),
        SAPLING_OUTPUT_PARAMS_BLAKE2B,
        (const uint8_t *)sprout_path, strlen(sprout_path),
        SPROUT_GROTH16_PARAMS_BLAKE2B);

    if (!zclassic_sapling_prover_run_self_test())
        LOG_WARN("sapling_params",
                 "proving capability unavailable: backend=%s status=%s; "
                 "consensus verification remains active",
                 zclassic_sapling_prover_backend(),
                 zclassic_sapling_prover_status());
}

/* The FIRST load: nothing of ours is published yet, so this parses every key,
 * publishes the three Groth16 VKs at the single publish point, and then arms
 * proving. Caller holds params_mu. */
static bool params_load_first_locked(const char *params_dir)
{
    size_t len = 0;

    /* Sapling spend. The verifying key is the leading prefix of this same
     * buffer, so it is read once and then kept as the proving key rather than
     * read a second time. */
    size_t spend_len = 0;
    uint8_t *spend_bytes = params_read_pinned(params_dir,
                                              "sapling-spend.params",
                                              SAPLING_SPEND_PARAMS_SHA512,
                                              &spend_len);
    if (!spend_bytes)
        LOG_FAIL("sapling_params", "init: sapling-spend.params unusable");
    if (!groth16_vk_read(&spend_vk, spend_bytes, spend_len)) {
        free(spend_bytes);
        LOG_FAIL("sapling_params", "init: groth16_vk_read failed for spend VK");
    }

    /* Sapling output */
    size_t output_len = 0;
    uint8_t *output_bytes = params_read_pinned(params_dir,
                                               "sapling-output.params",
                                               SAPLING_OUTPUT_PARAMS_SHA512,
                                               &output_len);
    if (!output_bytes) {
        free(spend_bytes);
        params_release_groth16_vks();
        LOG_FAIL("sapling_params", "init: sapling-output.params unusable");
    }
    if (!groth16_vk_read(&output_vk, output_bytes, output_len)) {
        free(spend_bytes); free(output_bytes);
        params_release_groth16_vks();
        LOG_FAIL("sapling_params", "init: groth16_vk_read failed for output VK");
    }

    /* Sprout Groth16. Only its verifying key is retained; the proving half is
     * reached through the path handed to the backend, so the buffer goes. */
    {
        uint8_t *data = params_read_pinned(params_dir, "sprout-groth16.params",
                                           SPROUT_GROTH16_PARAMS_SHA512, &len);
        if (!data) {
            free(spend_bytes); free(output_bytes);
            params_release_groth16_vks();
            LOG_FAIL("sapling_params", "init: sprout-groth16.params unusable");
        }
        bool ok = groth16_vk_read(&sprout_groth16_vk, data, len);
        free(data);
        if (!ok) {
            free(spend_bytes); free(output_bytes);
            params_release_groth16_vks();
            LOG_FAIL("sapling_params",
                     "init: groth16_vk_read failed for sprout-groth16 VK");
        }
    }

    /* Precompute the windowed tables over each VK's constant IC[] points, so a
     * per-verify public-input scalar-mul costs table lookups instead of a
     * 256-bit double-and-add. Built before the VKs are published so verifier
     * threads only ever observe a fully-built table; read-only afterwards.
     * Value-identical to the naive path, so verdicts are unchanged — an
     * allocation failure just leaves the naive fallback in place. */
    if (!groth16_vk_build_combs(&spend_vk))
        LOG_WARN("sapling_params",
                 "spend VK IC precompute unavailable; using naive scalar-mul");
    if (!groth16_vk_build_combs(&output_vk))
        LOG_WARN("sapling_params",
                 "output VK IC precompute unavailable; using naive scalar-mul");
    if (!groth16_vk_build_combs(&sprout_groth16_vk))
        LOG_WARN("sapling_params",
                 "sprout-groth16 VK IC precompute unavailable; using naive scalar-mul");

    /* NOT published here. The Sprout PHGR13 section below can still fail, and
     * its mainnet failure path frees these three structs — see the
     * publish/free invariant above. Publication happens after it. */

    /* Sprout PHGR13 VK (pre-Sapling proofs, blocks 0-581876) */
    static struct ppzksnark_vk phgr_vk;
    bool phgr_ok = false;
    {
        uint8_t *phgr_data = params_read_pinned(params_dir,
                                                "sprout-verifying.key",
                                                SPROUT_VERIFYING_KEY_SHA512,
                                                &len);
        if (phgr_data) {
            /* Parsed, not published: publication is deferred to the single
             * publish point below, with the three Groth16 VKs. */
            if (ppzksnark_vk_read(&phgr_vk, phgr_data, len)) {
                LOG_INFO("sapling_params",
                         "Loaded Sprout PHGR13 verification key: %zu bytes "
                         "(%zu IC points)", len, phgr_vk.ic_len);
                phgr_ok = true;
            } else {
                LOG_WARN("sapling_params",
                         "ERROR: Failed to parse sprout-verifying.key");
            }
            free(phgr_data);
        } else {
            /* Unreadable, or present but failed its SHA-512 pin —
             * params_read_pinned logs the expected/actual digests itself, so
             * do not claim "not found" here for what may have been
             * tampering. */
            LOG_WARN("sapling_params",
                     "ERROR: sprout-verifying.key unusable in %s "
                     "(missing/unreadable, or failed its pinned SHA-512)",
                     params_dir);
        }

        /* Hard-fail on mainnet — PHGR13 proofs are consensus-critical for
         * pre-Sapling blocks. The silent non-fatal path let this bug survive
         * for months (see PHGR13_INVESTIGATION.md). */
        if (!phgr_ok) {
            const struct chain_params *cp = chain_params_get();
            if (cp && strcmp(cp->strNetworkID, "main") == 0) {
                /* Nothing is published yet, so this only frees. The release
                 * helper still clears the globals first and NULLs every field
                 * it frees, so the invariant holds by construction rather than
                 * by this call site happening to sit above the publish. */
                free(spend_bytes); free(output_bytes);
                params_release_groth16_vks();
                LOG_FAIL("sapling_params",
                         "FATAL: Sprout PHGR13 verification key failed to load.\n"
                         "Mainnet requires this key to validate pre-Sapling blocks.\n"
                         "Ensure sprout-verifying.key exists in: %s",
                         params_dir);
            }
            LOG_WARN("sapling_params",
                     "WARNING: PHGR13 VK not loaded (non-mainnet, continuing)");
        }
    }

    /* ── The single publish point ────────────────────────────────────────
     * Every fallible step is above this line, so from here on nothing can
     * free what is about to become visible to the verifiers. Everything
     * below (the proving keys, the prover self-test) is best-effort and
     * cannot fail the function. The prover self-test verifies through
     * sapling_check_spend/_output, so it must run after this. */
    params_publish_groth16_vks();
    if (phgr_ok)
        sprout_phgr_set_vk(&phgr_vk);
    atomic_store(&params_loaded, true);

    params_arm_proving_locked(params_dir, spend_bytes, spend_len,
                              output_bytes, output_len);
    return true;
}

/* The LATE load: the verifying keys are already published — by the compiled-in
 * fallback (the common case: a node booted with no ~/.zcash-params, and the
 * proving parameters arrived afterwards) or by an earlier load of a directory.
 *
 * This adds the proving keys and NOTHING else. It does not parse, replace or
 * free a single published verifying key, which is what makes it safe to run on
 * a background thread while consensus verifiers are reading those keys with no
 * lock: there is nothing for them to be reading that this is about to change.
 *
 * The whole pinned set is still checked, not just the two files whose bytes it
 * keeps. A directory is accepted as a proving parameter set only if every file
 * in it matches its compiled-in digest, exactly as on the first load — the
 * claim being made is "these are the ceremony parameters", and half a set does
 * not support it. Cheapest pin first, so a refusal need not cost 777 MB of
 * hashing.
 *
 * Caller holds params_mu. */
static bool params_load_late_proving_locked(const char *params_dir)
{
    size_t len = 0;

    /* sprout-verifying.key: 1449 bytes, and the whole reason to start here.
     * Its verifying key is already published and is not re-parsed; only its
     * integrity is confirmed. */
    {
        uint8_t *data = params_read_pinned(params_dir, "sprout-verifying.key",
                                           SPROUT_VERIFYING_KEY_SHA512, &len);
        if (!data)
            LOG_FAIL("sapling_params",
                     "late proving load: sprout-verifying.key unusable in %s "
                     "— refusing the directory; the published verifying keys "
                     "are untouched and validation continues",
                     params_dir);
        free(data);
    }

    /* Sapling output, then spend: read once, pinned, and kept as the proving
     * keys. The verifying key each one starts with is already published. */
    size_t output_len = 0;
    uint8_t *output_bytes = params_read_pinned(params_dir,
                                               "sapling-output.params",
                                               SAPLING_OUTPUT_PARAMS_SHA512,
                                               &output_len);
    if (!output_bytes)
        LOG_FAIL("sapling_params",
                 "late proving load: sapling-output.params unusable");

    size_t spend_len = 0;
    uint8_t *spend_bytes = params_read_pinned(params_dir,
                                              "sapling-spend.params",
                                              SAPLING_SPEND_PARAMS_SHA512,
                                              &spend_len);
    if (!spend_bytes) {
        free(output_bytes);
        LOG_FAIL("sapling_params",
                 "late proving load: sapling-spend.params unusable");
    }

    /* sprout-groth16.params: 725 MB, hashed but not retained — the backend is
     * given its path. Last, because it is the most expensive check. */
    {
        uint8_t *data = params_read_pinned(params_dir, "sprout-groth16.params",
                                           SPROUT_GROTH16_PARAMS_SHA512, &len);
        if (!data) {
            free(output_bytes); free(spend_bytes);
            LOG_FAIL("sapling_params",
                     "late proving load: sprout-groth16.params unusable");
        }
        free(data);
    }

    /* The published verifying keys have to belong to these proving keys. Two
     * independent pins already imply it — the file matched its SHA-512 and the
     * compiled-in blob matched its SHA-256, and the blob is that file's
     * prefix — but the bytes are in hand, so check it rather than infer it.
     * Only meaningful when the published keys came from the blobs; when they
     * came from a directory they came from a file with this same pinned
     * digest, so they are the same bytes by the pin alone. */
    if (atomic_load(&vks_embedded)) {
        const struct zcl_embedded_vk *es = &zcl_embedded_vks[0];
        const struct zcl_embedded_vk *eo = &zcl_embedded_vks[1];
        if (spend_len < es->len || output_len < eo->len ||
            memcmp(spend_bytes, es->bytes, es->len) != 0 ||
            memcmp(output_bytes, eo->bytes, eo->len) != 0) {
            free(output_bytes); free(spend_bytes);
            LOG_FAIL("sapling_params",
                     "late proving load: the parameter files do not begin with "
                     "this build's compiled-in verifying keys — refusing to "
                     "prove against a key set the verifier does not hold");
        }
    }

    params_arm_proving_locked(params_dir, spend_bytes, spend_len,
                              output_bytes, output_len);
    return true;
}

static bool params_init_locked(const char *params_dir)
{
    /* Re-checked under the mutex: two threads can both have seen this clear. */
    if (atomic_load(&proving_params_loaded)) return true;

    /* THE GUARD THAT USED TO BE WRONG. It read params_loaded, which the
     * compiled-in fallback sets, so on the one node this call exists for — a
     * node running on verifying keys alone, whose proving parameters have just
     * arrived — it returned true without reading a byte. Gating on the
     * stronger flag is strictly stricter: every case that used to reach the
     * loader still reaches it, and the case that used to be turned away now
     * gets the load it asked for. Nothing new is claimed ready. */
    bool ok = atomic_load(&params_loaded)
                  ? params_load_late_proving_locked(params_dir)
                  : params_load_first_locked(params_dir);
    if (!ok) return false;

    /* Set last, and only with both proving keys resident. It is what stops the
     * next call re-reading 777 MB, so it must not be set by a path that left
     * the proving keys absent. A prover whose self-test failed still sets it:
     * the parameters ARE loaded, re-reading the identical bytes cannot change
     * the verdict, and zclassic_sapling_prover_status() reports the failure. */
    if (spend_pk_data && output_pk_data)
        atomic_store(&proving_params_loaded, true);
    return true;
}

bool sapling_init_params(const char *params_dir)
{
    if (atomic_load(&proving_params_loaded)) return true;
    pthread_mutex_lock(&params_mu);
    bool ok = params_init_locked(params_dir);
    pthread_mutex_unlock(&params_mu);
    return ok;
}

bool sapling_params_loaded(void)
{
    return atomic_load(&params_loaded);
}

const uint8_t *sapling_get_output_pk(size_t *len)
{
    if (len) *len = output_pk_len;
    return output_pk_data;
}

const uint8_t *sapling_get_spend_pk(size_t *len)
{
    if (len) *len = spend_pk_len;
    return spend_pk_data;
}

void sapling_free_params(void)
{
    pthread_mutex_lock(&params_mu);
    if (!atomic_load(&params_loaded)) {
        pthread_mutex_unlock(&params_mu);
        return;
    }
    /* Unpublish-then-free, in that order: this used to free the ic[] arrays
     * and comb tables and only then clear the globals, which is the same
     * published-pointer-to-freed-storage window the loader used to leave
     * behind. params_release_groth16_vks() does both halves in the safe
     * order.
     *
     * This is the ONE unpublish. It runs at shutdown, when no verifier is
     * running; the mutex only keeps it from interleaving with a loader on
     * another thread. */
    params_release_groth16_vks();
    free(spend_pk_data);
    free(output_pk_data);
    spend_pk_data = NULL; spend_pk_len = 0;
    output_pk_data = NULL; output_pk_len = 0;
    atomic_store(&proving_params_loaded, false);
    atomic_store(&vks_embedded, false);
    atomic_store(&params_loaded, false);
    pthread_mutex_unlock(&params_mu);
}

/* ── Embedded verifying keys ─────────────────────────────────────────────
 *
 * A validating node needs the verifying keys and nothing else. Those are the
 * leading 868 + ic_len*96 bytes of each Groth16 parameter file plus the
 * standalone PHGR13 key — 6357 bytes against 777 MB — so they are compiled in
 * (params_vk_embedded.c) rather than acquired at runtime.
 *
 * This path installs exactly the values sapling_init_params() would install
 * from a full parameter directory, and deliberately installs nothing else:
 * no proving keys are loaded, so zclassic_init_zksnark_params() never runs,
 * the native prover stays NATIVE_PROVER_UNINITIALIZED, and every wallet entry
 * point that would build a shielded output refuses on
 * zclassic_sapling_prover_is_ready(). Validation is whole; proving is absent
 * and says so. */

/* Hash one embedded blob and compare against its pinned digest. A build whose
 * key material has been patched must fail here, before the bytes are parsed
 * and long before a proof is checked against them. */
static bool embedded_vk_sha256_ok(const struct zcl_embedded_vk *e)
{
    uint8_t got[32];
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_write(&ctx, e->bytes, e->len);
    sha256_finalize(&ctx, got);

    uint8_t want[32];
    if (ParseHex(e->sha256_hex, want, 32) != 32)
        LOG_FAIL("sapling_params",
                 "internal: malformed embedded VK digest literal for %s",
                 e->name);

    uint32_t diff = 0;
    for (int i = 0; i < 32; i++) diff |= (uint32_t)(got[i] ^ want[i]);
    if (diff != 0) {
        char got_hex[65];
        for (int i = 0; i < 32; i++)
            snprintf(got_hex + 2 * i, 3, "%02x", got[i]);
        LOG_FAIL("sapling_params",
                 "embedded verifying key SHA-256 mismatch: name=%s\n"
                 "  expected=%s\n  actual  =%s\n"
                 "  This build's compiled-in verifying keys are not the ones "
                 "this source tree pins. Refusing to validate shielded proofs "
                 "against unknown key material.",
                 e->name, e->sha256_hex, got_hex);
    }
    return true;
}

bool sapling_vks_are_embedded(void) { return atomic_load(&vks_embedded); }

static bool params_install_embedded_locked(void)
{
    /* Any published key wins. If a directory was loaded the process already
     * has verifying and proving keys, and re-installing would be a downgrade;
     * if the blobs are already installed there is nothing to do. Either way
     * the ONCE PUBLISHED, NEVER REPLACED rule forbids touching them. */
    if (atomic_load(&params_loaded)) return true;

    /* Verify every digest before installing any of them, so a failure cannot
     * leave a half-installed key set behind. */
    for (size_t i = 0; i < ZCL_EMBEDDED_VK_COUNT; i++) {
        if (!embedded_vk_sha256_ok(&zcl_embedded_vks[i]))
            LOG_FAIL("sapling_params",
                     "embedded verifying keys failed integrity check "
                     "(blob %zu: %s) — not installing any",
                     i, zcl_embedded_vks[i].name);
    }

    if (!groth16_vk_read(&spend_vk, zcl_embedded_vks[0].bytes,
                         zcl_embedded_vks[0].len)) {
        params_release_groth16_vks();
        LOG_FAIL("sapling_params",
                 "embedded spend VK failed to parse (%zu bytes)",
                 zcl_embedded_vks[0].len);
    }

    if (!groth16_vk_read(&output_vk, zcl_embedded_vks[1].bytes,
                         zcl_embedded_vks[1].len)) {
        params_release_groth16_vks();
        LOG_FAIL("sapling_params",
                 "embedded output VK failed to parse (%zu bytes)",
                 zcl_embedded_vks[1].len);
    }

    if (!groth16_vk_read(&sprout_groth16_vk, zcl_embedded_vks[2].bytes,
                         zcl_embedded_vks[2].len)) {
        params_release_groth16_vks();
        LOG_FAIL("sapling_params",
                 "embedded sprout-groth16 VK failed to parse (%zu bytes)",
                 zcl_embedded_vks[2].len);
    }

    static struct ppzksnark_vk phgr_vk;
    if (!ppzksnark_vk_read(&phgr_vk, zcl_embedded_vks[3].bytes,
                           zcl_embedded_vks[3].len)) {
        params_release_groth16_vks();
        LOG_FAIL("sapling_params",
                 "embedded Sprout PHGR13 VK failed to parse (%zu bytes) — "
                 "pre-Sapling blocks could not be validated",
                 zcl_embedded_vks[3].len);
    }

    /* Same precompute the full-parameter path performs; value-identical, so a
     * failure only costs speed. Built before publication so verifier threads
     * never observe a half-built table. */
    if (!groth16_vk_build_combs(&spend_vk))
        LOG_WARN("sapling_params",
                 "spend VK IC precompute unavailable; using naive scalar-mul");
    if (!groth16_vk_build_combs(&output_vk))
        LOG_WARN("sapling_params",
                 "output VK IC precompute unavailable; using naive scalar-mul");
    if (!groth16_vk_build_combs(&sprout_groth16_vk))
        LOG_WARN("sapling_params",
                 "sprout-groth16 VK IC precompute unavailable; using naive scalar-mul");

    /* Publish last: every fallible step is above. */
    params_publish_groth16_vks();
    sprout_phgr_set_vk(&phgr_vk);

    atomic_store(&vks_embedded, true);
    atomic_store(&params_loaded, true);

    LOG_INFO("sapling_params",
             "installed compiled-in verifying keys (%zu+%zu+%zu+%zu bytes): "
             "shielded proof VALIDATION active; shielded spend CREATION "
             "unavailable until proving parameters are installed",
             zcl_embedded_vks[0].len, zcl_embedded_vks[1].len,
             zcl_embedded_vks[2].len, zcl_embedded_vks[3].len);
    return true;
}

bool sapling_install_embedded_vks(void)
{
    pthread_mutex_lock(&params_mu);
    bool ok = params_install_embedded_locked();
    pthread_mutex_unlock(&params_mu);
    return ok;
}

#ifdef ZCL_TESTING
/* Exposes the embedded-blob integrity check so a test can hand it a planted
 * bad blob and prove the refusal is real, rather than asserting on a
 * reimplementation of the same comparison. */
bool sapling_test_embedded_vk_sha256_ok(const char *name, const uint8_t *bytes,
                                        size_t len, const char *sha256_hex)
{
    struct zcl_embedded_vk e = { name, bytes, len, sha256_hex };
    return embedded_vk_sha256_ok(&e);
}
#endif
