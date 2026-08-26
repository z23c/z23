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
/* Sprout PHGR13 verifying key (pre-Sapling JoinSplits, blocks 0-581876).
 * ONE instance, at file scope beside the three Groth16 VKs, deliberately:
 * both load paths — sapling_init_params() from a parameter directory and
 * sapling_install_embedded_vks() from the compiled-in blobs — parse into this
 * struct, and sapling_free_params() frees it. It used to be a function-local
 * static in each of those two functions, which put it out of reach of the
 * teardown helper and made it the one key of the four that stayed armed after
 * sapling_free_params() and leaked its ic[] on every reload. */
static struct ppzksnark_vk phgr_vk;
static _Atomic bool params_loaded = false;
/* True when the running key set came from the compiled-in blobs rather than
 * a parameter directory. Declared here, beside params_loaded, because
 * sapling_free_params() clears both. */
static _Atomic bool vks_embedded = false;

static uint8_t *spend_pk_data = NULL;
static size_t spend_pk_len = 0;
static uint8_t *output_pk_data = NULL;
static size_t output_pk_len = 0;

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
 * sapling_check_spend / sapling_check_output / sprout_verify_groth16 /
 * sprout_verify_phgr13 all read "a NULL VK means the keys are not ready, so
 * reject". That reading is only true while every failure path actually
 * produces NULL. Publishing at the top of the Sprout PHGR13 section and
 * freeing at the bottom of it — which is what this file used to do — made the
 * guards blind to a struct whose ic[] and comb tables had already been freed:
 * non-NULL, so the guard passed, and groth16_verify then read freed heap.
 * Keep the publish below every fallible step.
 *
 * ── Which helper covers which key, and which call sites are which ───────
 *
 * The four keys split across two publish/release pairs because their storage
 * is parsed at two different points in the load, not because their rules
 * differ. Both pairs obey PUBLISH LAST and UNPUBLISH FIRST.
 *
 *   trio   spend_vk, output_vk, sprout_groth16_vk
 *          params_publish_groth16_vks() / params_release_groth16_vks()
 *   phgr   phgr_vk
 *          params_publish_phgr_vk()     / params_release_phgr_vk()
 *
 * PRE-PUBLICATION release sites (abandoning a load that never published):
 *   every params_release_groth16_vks() call inside sapling_init_params() and
 *   sapling_install_embedded_vks(). Each one sits above that function's single
 *   publish point, and — the part that makes it provable rather than a reading
 *   of the current line order — BOTH entry points return early when
 *   params_loaded is set, and params_loaded is stored true in the same
 *   straight-line run that publishes, with nothing fallible in between. So
 *   "published" and "params_loaded" are the same state, and a function that
 *   reaches a release site necessarily entered with nothing of ours published.
 *   Those releases are therefore free-only in effect; their unpublish half is
 *   defence in depth.
 *
 * POST-PUBLICATION release site: sapling_free_params(), and only that. It is
 * the one place that runs with keys live, so it is the one place that releases
 * all four.
 *
 * DO NOT add params_release_phgr_vk() to the pre-publication sites. A node that
 * came up on the compiled-in keys and later ran a failing load would then
 * disarm a working PHGR13 verifier and lose the ability to validate blocks
 * 0-581876 — turning a recoverable load failure into a validation regression.
 * The early-return above means that sequence cannot happen today; keeping the
 * failure paths off phgr_vk means it still cannot if that changes. */
static void params_publish_groth16_vks(void)
{
    sapling_set_spend_vk(&spend_vk);
    sapling_set_output_vk(&output_vk);
    sprout_set_vk(&sprout_groth16_vk);
}

static void params_publish_phgr_vk(void)
{
    sprout_phgr_set_vk(&phgr_vk);
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

/* Same two rules as the trio, for the fourth key. Call ONLY from
 * sapling_free_params() — see the call-site split documented above.
 *
 * The free is not optional bookkeeping: ppzksnark_vk_read() memsets its output
 * struct before parsing (bn254.c), so a reload that did not free first would
 * drop the previous ic[] allocation on the floor. The trio avoids that because
 * params_release_groth16_vks() frees and memsets them; phgr_vk needs the same
 * treatment for the same reason. */
static void params_release_phgr_vk(void)
{
    sprout_phgr_set_vk(NULL);
    ppzksnark_vk_free(&phgr_vk);
    memset(&phgr_vk, 0, sizeof(phgr_vk));
}

bool sapling_init_params(const char *params_dir)
{
    if (atomic_load(&params_loaded)) return true;

    char path[1024];
    size_t len;
    uint8_t *data;

    /* Sapling spend VK */
    snprintf(path, sizeof(path), "%s/sapling-spend.params", params_dir);
    data = read_file(path, &len);
    if (!data)
        LOG_FAIL("sapling_params", "init: read_file failed for sapling-spend.params");
    if (!params_sha512_matches(data, len, SAPLING_SPEND_PARAMS_SHA512, path)) {
        free(data);
        LOG_FAIL("sapling_params", "init: SHA-512 mismatch on sapling-spend.params");
    }
    bool ok = groth16_vk_read(&spend_vk, data, len);
    free(data);
    if (!ok)
        LOG_FAIL("sapling_params", "init: groth16_vk_read failed for spend VK");

    /* Sapling output VK */
    snprintf(path, sizeof(path), "%s/sapling-output.params", params_dir);
    data = read_file(path, &len);
    if (!data) {
        params_release_groth16_vks();
        LOG_FAIL("sapling_params", "init: read_file failed for sapling-output.params");
    }
    if (!params_sha512_matches(data, len, SAPLING_OUTPUT_PARAMS_SHA512, path)) {
        free(data); params_release_groth16_vks();
        LOG_FAIL("sapling_params", "init: SHA-512 mismatch on sapling-output.params");
    }
    ok = groth16_vk_read(&output_vk, data, len);
    free(data);
    if (!ok) {
        params_release_groth16_vks();
        LOG_FAIL("sapling_params", "init: groth16_vk_read failed for output VK");
    }

    /* Sprout Groth16 VK */
    snprintf(path, sizeof(path), "%s/sprout-groth16.params", params_dir);
    data = read_file(path, &len);
    if (!data) {
        params_release_groth16_vks();
        LOG_FAIL("sapling_params", "init: read_file failed for sprout-groth16.params");
    }
    if (!params_sha512_matches(data, len, SPROUT_GROTH16_PARAMS_SHA512, path)) {
        free(data); params_release_groth16_vks();
        LOG_FAIL("sapling_params", "init: SHA-512 mismatch on sprout-groth16.params");
    }
    ok = groth16_vk_read(&sprout_groth16_vk, data, len);
    free(data);
    if (!ok) {
        params_release_groth16_vks();
        LOG_FAIL("sapling_params", "init: groth16_vk_read failed for sprout-groth16 VK");
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

    /* Sprout PHGR13 VK (pre-Sapling proofs, blocks 0-581876). Parses into the
     * file-scope phgr_vk; published below with the trio, released by
     * sapling_free_params(). */
    bool phgr_ok = false;
    {
        char phgr_path[1024];
        snprintf(phgr_path, sizeof(phgr_path),
                 "%s/sprout-verifying.key", params_dir);
        uint8_t *phgr_data = read_file(phgr_path, &len);
        if (phgr_data &&
            !params_sha512_matches(phgr_data, len,
                                   SPROUT_VERIFYING_KEY_SHA512, phgr_path)) {
            /* Integrity failed. Drop the bytes and fall through to the
             * not-loaded path below, which hard-fails on mainnet. Never parse
             * key material that did not match its pin. */
            free(phgr_data);
            phgr_data = NULL;
        }
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
            /* Unreadable, or present but failed its SHA-512 pin — the pin
             * check above logs the expected/actual digests itself, so do not
             * claim "not found" here for what may have been tampering. */
            LOG_WARN("sapling_params",
                     "ERROR: sprout-verifying.key unusable at %s "
                     "(missing/unreadable, or failed its pinned SHA-512)",
                     phgr_path);
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
     * below (proving-key reads, the prover self-test) is best-effort and
     * cannot fail the function. The prover self-test verifies through
     * sapling_check_spend/_output, so it must run after this. */
    params_publish_groth16_vks();
    if (phgr_ok)
        params_publish_phgr_vk();

    /* Keep raw PK data for proving (VK is a subset of PK data) */
    snprintf(path, sizeof(path), "%s/sapling-spend.params", params_dir);
    spend_pk_data = read_file(path, &spend_pk_len);

    snprintf(path, sizeof(path), "%s/sapling-output.params", params_dir);
    output_pk_data = read_file(path, &output_pk_len);

    if (output_pk_data)
        LOG_INFO("sapling_params",
                 "Loaded sapling-output proving key: %zu bytes",
                 output_pk_len);
    if (spend_pk_data)
        LOG_INFO("sapling_params",
                 "Loaded sapling-spend proving key: %zu bytes",
                 spend_pk_len);

    /* Initialize the pinned canonical proving backend. Consensus verification
     * has already installed the independent C23 VKs above. */
    {
        char spend_path[1024], output_path2[1024], sprout_path[1024];
        snprintf(spend_path, sizeof(spend_path),
                 "%s/sapling-spend.params", params_dir);
        snprintf(output_path2, sizeof(output_path2),
                 "%s/sapling-output.params", params_dir);
        snprintf(sprout_path, sizeof(sprout_path),
                 "%s/sprout-groth16.params", params_dir);

        zclassic_init_zksnark_params(
            (const uint8_t *)spend_path, strlen(spend_path),
            SAPLING_SPEND_PARAMS_BLAKE2B,
            (const uint8_t *)output_path2, strlen(output_path2),
            SAPLING_OUTPUT_PARAMS_BLAKE2B,
            (const uint8_t *)sprout_path, strlen(sprout_path),
            SPROUT_GROTH16_PARAMS_BLAKE2B);

        if (!zclassic_sapling_prover_run_self_test()) {
            LOG_WARN("sapling_params",
                     "proving capability unavailable: backend=%s status=%s; consensus verification remains active",
                     zclassic_sapling_prover_backend(),
                     zclassic_sapling_prover_status());
        }
    }

    atomic_store(&params_loaded, true);
    return true;
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
    if (!atomic_load(&params_loaded)) return;
    /* Unpublish-then-free, in that order: this used to free the ic[] arrays
     * and comb tables and only then clear the globals, which is the same
     * published-pointer-to-freed-storage window the loader used to leave
     * behind. params_release_groth16_vks() does both halves in the safe
     * order.
     *
     * All FOUR keys, not three. This is the only post-publication release site
     * in the file, so it is the only one that may touch phgr_vk; leaving it out
     * used to disarm three of the four shielded verifiers and leave
     * sprout_verify_phgr13 still verifying pre-Sapling JoinSplits against a key
     * the process had declared released. */
    params_release_phgr_vk();
    params_release_groth16_vks();
    free(spend_pk_data);
    free(output_pk_data);
    spend_pk_data = NULL; spend_pk_len = 0;
    output_pk_data = NULL; output_pk_len = 0;
    atomic_store(&vks_embedded, false);
    atomic_store(&params_loaded, false);
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

bool sapling_install_embedded_vks(void)
{
    /* Full parameters win: if they are already loaded the process has both
     * verifying and proving keys, and re-installing would be a downgrade. */
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
    params_publish_phgr_vk();

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
