/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The compiled-in verifying keys, and the boundary between validating and
 * proving.
 *
 * What this pins down:
 *
 *   1. The embedded blobs are exactly the verifying-key prefix of the real
 *      parameter files — byte-for-byte, and exactly 868 + ic_len*96 long, so
 *      neither short (a truncated key) nor long (proving-key material that
 *      does not belong in the binary).
 *   2. Installing them arms shielded proof VALIDATION.
 *   3. Installing them does NOT arm proving. A node with no proving
 *      parameters must refuse to build a shielded output, never emit an
 *      unproven one.
 *   4. A planted bad blob is refused. This is the check that stands between
 *      a patched binary and proofs being verified against an attacker's key,
 *      so it is tested against the production comparison, not a copy of it.
 *
 *   1b. A parameter directory that is PRESENT but corrupt is refused whole,
 *      strands no published key, and falls back to the compiled-in ones.
 *      Section 1b builds a real planted-corruption fixture (one flipped byte
 *      in a private copy of sprout-verifying.key, the three big files by
 *      symlink) and drives the production loader over it.
 *
 * The byte-for-byte file comparison, complete-directory corruption fixture,
 * and late proving upgrade need a real parameter directory.  Its absence is
 * the normal validation-only node state, not skipped coverage: sections 2-4
 * still prove the embedded digests, fail-closed proving boundary, planted bad
 * blob refusal, and acceptance of a real mainnet shielded proof.  When the
 * external files are present the three additional comparisons remain
 * mandatory and fail normally.
 */

#include "test/test_core.h"

#include "chain/chainparams.h"
#include "chain/chainparamsbase.h"
#include "core/serialize.h"
#include "primitives/transaction.h"
#include "sapling/bls12_381.h"
#include "sapling/bn254.h"
#include "sapling/constants.h"
#include "sapling/params_init.h"
#include "sapling/params_vk_embedded.h"
#include "sapling/sapling.h"
#include "sapling/sapling_prover.h"
#include "sapling/sprout.h"
#include "validation/check_transaction.h"
#include "validation/contextual_check_tx.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Canonical mainnet height-241 JoinSplit transaction (txid 55c6c3a2…48fd),
 * shared with test_sprout_phgr13_kat.c. A real pre-Sapling shielded proof from
 * the real chain — the strongest positive available without a prover. */
extern const unsigned char g_fixture_tx_sprout_241[];
extern const size_t g_fixture_tx_sprout_241_len;

#define VK_CHECK(name, expr) do { \
    printf("params_vk_embedded: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Groth16 verifying-key layout, matching groth16_vk_read_raw(). */
#define VK_HEADER_BYTES   868
#define VK_IC_LEN_OFFSET  864
#define VK_IC_POINT_BYTES 96

static uint32_t be32_at(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* The parameter file each Groth16 blob was cut from. sprout-phgr is embedded
 * whole from sprout-verifying.key, so it has no prefix relationship to check
 * beyond equality. */
static const char *const vk_source_file[ZCL_EMBEDDED_VK_COUNT] = {
    "sapling-spend.params",
    "sapling-output.params",
    "sprout-groth16.params",
    "sprout-verifying.key",
};

/* Scratch root. Never /tmp when a project scratch dir is available, and never
 * inside a parameter directory or a datadir. */
static bool vk_scratch_root(char *out, size_t cap)
{
    const char *t = getenv("TMPDIR");
    if (t && *t) { snprintf(out, cap, "%s", t); return true; }
    const char *home = getenv("HOME");
    if (home && *home) {
        snprintf(out, cap, "%s/.local/state/zclassic23/scratch", home);
        /* Best-effort mkdir -p of the two leaf components. */
        char p[1024];
        snprintf(p, sizeof(p), "%s/.local/state/zclassic23", home);
        (void)mkdir(p, 0700);
        (void)mkdir(out, 0700);
        return access(out, W_OK) == 0;
    }
    snprintf(out, cap, "/tmp");
    return true;
}

/* The three large files a planted-corruption fixture links rather than copies.
 * sprout-verifying.key is the one it corrupts, so it is not in this list. */
static const char *const vk_planted_links[] = {
    "sapling-spend.params", "sapling-output.params", "sprout-groth16.params",
};

/* Remove a staged fixture. Only files vk_stage_planted_dir() created. */
static void vk_unstage_planted_dir(const char *scratch)
{
    char dst[1400];
    for (size_t i = 0; i < 3; i++) {
        snprintf(dst, sizeof(dst), "%s/%s", scratch, vk_planted_links[i]);
        (void)unlink(dst);
    }
    snprintf(dst, sizeof(dst), "%s/sprout-verifying.key", scratch);
    (void)unlink(dst);
    (void)rmdir(scratch);
}

/* Stage a parameter directory that is COMPLETE but corrupt: the three large
 * files by symlink (read-only, and no copy of 777 MB) and ONE flipped bit in
 * a private copy of sprout-verifying.key. `real_dir` is never written.
 * Returns false having left nothing behind. */
static bool vk_stage_planted_dir(const char *real_dir, char *scratch,
                                 size_t cap)
{
    char scratch_root[1024];
    if (!vk_scratch_root(scratch_root, sizeof(scratch_root)))
        return false;
    snprintf(scratch, cap, "%s/zcl_vk_refused_params_XXXXXX", scratch_root);
    if (mkdtemp(scratch) == NULL)
        return false;

    bool staged = true;
    for (size_t i = 0; i < 3 && staged; i++) {
        char src[1200], dst[1400];
        snprintf(src, sizeof(src), "%s/%s", real_dir, vk_planted_links[i]);
        snprintf(dst, sizeof(dst), "%s/%s", scratch, vk_planted_links[i]);
        staged = (symlink(src, dst) == 0);
    }

    uint8_t phgr[1449];
    size_t phgr_len = 0;
    if (staged) {
        char src[1200];
        snprintf(src, sizeof(src), "%s/sprout-verifying.key", real_dir);
        FILE *f = fopen(src, "rb");
        staged = (f != NULL);
        if (f) { phgr_len = fread(phgr, 1, sizeof(phgr), f); fclose(f); }
        staged = staged && phgr_len == sizeof(phgr);
    }
    if (staged) {
        /* ONE flipped bit, in the middle of the key material. */
        phgr[phgr_len / 2] ^= 0x01u;
        char dst[1400];
        snprintf(dst, sizeof(dst), "%s/sprout-verifying.key", scratch);
        FILE *f = fopen(dst, "wb");
        staged = (f != NULL);
        if (f) {
            staged = (fwrite(phgr, 1, phgr_len, f) == phgr_len);
            staged = (fclose(f) == 0) && staged;
        }
    }
    if (!staged)
        vk_unstage_planted_dir(scratch);
    return staged;
}

/* Compare two verifying keys for exact equality, ic[] included. ic_combs is a
 * derived precompute and deliberately not compared. */
static bool vk_equal(const struct groth16_vk *a, const struct groth16_vk *b)
{
    if (!a || !b) return false;
    if (a->ic_len != b->ic_len) return false;
    if (memcmp(&a->alpha_g1, &b->alpha_g1, sizeof(a->alpha_g1)) != 0) return false;
    if (memcmp(&a->beta_g2,  &b->beta_g2,  sizeof(a->beta_g2))  != 0) return false;
    if (memcmp(&a->gamma_g2, &b->gamma_g2, sizeof(a->gamma_g2)) != 0) return false;
    if (memcmp(&a->delta_g2, &b->delta_g2, sizeof(a->delta_g2)) != 0) return false;
    if (a->ic_len && (!a->ic || !b->ic)) return false;
    for (size_t i = 0; i < a->ic_len; i++)
        if (memcmp(&a->ic[i], &b->ic[i], sizeof(a->ic[i])) != 0) return false;
    return true;
}

/* Parse the verifying-key prefix out of a real parameter file, so the test can
 * compare what a good directory WOULD have installed against what the fallback
 * did install. Reads only the prefix — never the ~777 MB of proving key. */
static bool vk_from_real_file(struct groth16_vk *out, const char *path,
                              size_t prefix_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    uint8_t *buf = malloc(prefix_len);
    if (!buf) { fclose(f); return false; }
    size_t got = fread(buf, 1, prefix_len, f);
    fclose(f);
    bool ok = (got == prefix_len) && groth16_vk_read(out, buf, prefix_len);
    free(buf);
    return ok;
}

/* The PHGR13 public inputs of the canonical fixture's single JoinSplit, lifted
 * off the parsed transaction so a direct-verifier negative control uses the
 * same values the consensus path used. */
struct vk_js_inputs {
    uint8_t proof[PHGR_PROOF_SIZE];
    uint8_t rt[32], h_sig[32], mac1[32], mac2[32];
    uint8_t nf1[32], nf2[32], cm1[32], cm2[32];
    uint64_t vpub_old, vpub_new;
    bool valid;
};

/* Run the canonical mainnet height-241 JoinSplit transaction through the
 * production contextual consensus entry point and return its verdict.
 * Requires chain_params_select(CHAIN_MAIN). Optionally hands back the
 * JoinSplit's public inputs. */
static bool vk_contextual_ok(struct vk_js_inputs *js_out)
{
    if (js_out) js_out->valid = false;

    struct byte_stream stream;
    stream_init_from_data(&stream, g_fixture_tx_sprout_241,
                          g_fixture_tx_sprout_241_len);
    struct transaction tx;
    transaction_init(&tx);
    if (!transaction_deserialize(&tx, &stream)) {
        transaction_free(&tx);
        return false;
    }

    const struct chain_params *cp = chain_params_get();
    /* The local deferral policy would otherwise skip shielded proofs below a
     * height; this test is about whether the proof verifies, so run it. */
    int saved = atomic_exchange(&g_deferred_proof_validation_below_height, -1);
    struct validation_state st;
    validation_state_init(&st);
    bool ok = cp && contextual_check_transaction(&tx, &st, &cp->consensus,
                                                 241, 100);
    atomic_store(&g_deferred_proof_validation_below_height, saved);

    if (js_out && tx.num_joinsplit > 0 && tx.v_joinsplit) {
        const struct js_description *js = &tx.v_joinsplit[0];
        memcpy(js_out->proof, js->proof, PHGR_PROOF_SIZE);
        memcpy(js_out->rt, js->anchor.data, 32);
        memcpy(js_out->mac1, js->macs[0].data, 32);
        memcpy(js_out->mac2, js->macs[1].data, 32);
        memcpy(js_out->nf1, js->nullifiers[0].data, 32);
        memcpy(js_out->nf2, js->nullifiers[1].data, 32);
        memcpy(js_out->cm1, js->commitments[0].data, 32);
        memcpy(js_out->cm2, js->commitments[1].data, 32);
        js_out->vpub_old = (uint64_t)js->vpub_old;
        js_out->vpub_new = (uint64_t)js->vpub_new;
        sprout_h_sig(js->random_seed.data, js->nullifiers[0].data,
                     js->nullifiers[1].data, tx.joinsplit_pubkey.data,
                     js_out->h_sig);
        js_out->valid = true;
    }
    transaction_free(&tx);
    return ok;
}

int test_params_vk_embedded(void);
int test_params_vk_embedded(void)
{
    int failures = 0;

    /* ── 1. Each blob is exactly the verifying-key prefix ─────────────── */
    {
        /* The first three blobs are Groth16 keys and must be self-describing:
         * the ic_len they carry has to account for their own length exactly.
         * This runs with or without a parameter directory. */
        for (size_t i = 0; i < 3; i++) {
            const struct zcl_embedded_vk *e = &zcl_embedded_vks[i];
            char name[128];

            snprintf(name, sizeof(name),
                     "%s blob is long enough to carry an ic_len", e->name);
            VK_CHECK(name, e->len > VK_HEADER_BYTES);
            if (e->len <= VK_HEADER_BYTES) continue;

            uint32_t ic_len = be32_at(e->bytes + VK_IC_LEN_OFFSET);
            size_t want = (size_t)VK_HEADER_BYTES +
                          (size_t)ic_len * VK_IC_POINT_BYTES;

            snprintf(name, sizeof(name),
                     "%s is exactly 868+%u*96=%zu bytes (got %zu)",
                     e->name, ic_len, want, e->len);
            VK_CHECK(name, e->len == want);
        }

        /* Byte-for-byte against the real files, when this machine has them.
         * Read-only: never write into a parameter directory. */
        const char *home = getenv("HOME");
        char dir[1024];
        snprintf(dir, sizeof(dir), "%s/.zcash-params", home ? home : "");

        char probe[1200];
        snprintf(probe, sizeof(probe), "%s/%s", dir, vk_source_file[0]);
        if (!home || access(probe, R_OK) != 0) {
            printf("params_vk_embedded: external prefix comparison... "
                   "NOT INSTALLED (no readable %s; the params-free "
                   "validation contract remains mandatory below)\n", dir);
        } else {
            for (size_t i = 0; i < ZCL_EMBEDDED_VK_COUNT; i++) {
                const struct zcl_embedded_vk *e = &zcl_embedded_vks[i];
                char path[1200], name[256];
                snprintf(path, sizeof(path), "%s/%s", dir, vk_source_file[i]);

                FILE *f = fopen(path, "rb");
                snprintf(name, sizeof(name), "%s: opened %s",
                         e->name, vk_source_file[i]);
                VK_CHECK(name, f != NULL);
                if (!f) continue;

                uint8_t *buf = malloc(e->len);
                snprintf(name, sizeof(name), "%s: allocated %zu bytes",
                         e->name, e->len);
                VK_CHECK(name, buf != NULL);
                if (!buf) { fclose(f); continue; }

                size_t got = fread(buf, 1, e->len, f);
                fclose(f);

                snprintf(name, sizeof(name),
                         "%s: read %zu bytes of prefix", e->name, e->len);
                VK_CHECK(name, got == e->len);

                snprintf(name, sizeof(name),
                         "%s: embedded blob equals the leading %zu bytes of %s",
                         e->name, e->len, vk_source_file[i]);
                VK_CHECK(name, got == e->len &&
                               memcmp(buf, e->bytes, e->len) == 0);
                free(buf);
            }
        }
    }

    /* ── 1b. A REFUSED parameter directory falls back, strands nothing ──
     *
     * The case this section exists for: the four files are present, so the
     * boot gate says PRESENT and the loader runs, but one of them is corrupt.
     * Two separate things then have to hold.
     *
     *   Refusal is total. sapling_init_params returns false and NOTHING it
     *   parsed is left published. The fail-closed guards in
     *   sapling_check_spend/_output/sprout_verify_groth16 read "a NULL VK
     *   means not ready", so a failure path that leaves a non-NULL pointer to
     *   freed storage is not a leak — it is a verifier reading freed heap and
     *   returning whatever that heap says. The pointer is the observable, so
     *   this asserts on the pointer.
     *
     *   Validation survives it. The verifying keys are compiled in and were
     *   never on disk, so a corrupt download costs the PROVING capability and
     *   nothing else.
     *
     * The scratch directory symlinks the three big files (read-only, and no
     * copy of 777 MB) and plants ONE flipped bit in a private copy of
     * sprout-verifying.key. That specific file is the only one whose failure
     * lands AFTER the three Groth16 keys are parsed, which is exactly the
     * ordering that used to strand them. ~/.zcash-params is never written. */
    {
        const char *home = getenv("HOME");
        char real_dir[1024];
        snprintf(real_dir, sizeof(real_dir), "%s/.zcash-params", home ? home : "");

        char probe[1200];
        snprintf(probe, sizeof(probe), "%s/sprout-verifying.key", real_dir);
        char scratch[1200];
        bool staged = false;
        if (!home || access(probe, R_OK) != 0) {
            printf("params_vk_embedded: external complete-directory "
                   "corruption fixture... NOT INSTALLED (needs readable %s; "
                   "embedded fallback and bad-blob refusal remain mandatory "
                   "below)\n", real_dir);
        } else {
            /* The machine HAS the files, so a staging failure is a failure,
             * not a skip. */
            staged = vk_stage_planted_dir(real_dir, scratch, sizeof(scratch));
            VK_CHECK("planted-corruption fixture staged", staged);
        }

        if (staged) {
            {
                /* Mainnet: the network where a PHGR13 failure is fatal to the
                 * load, which is the ordering under test. Restored below so
                 * this section cannot change the network another group in this
                 * process is running on. */
                const struct chain_params *prev = chain_params_get();
                bool had_prev = (prev != NULL);
                enum chain_network prev_net = CHAIN_MAIN;
                if (had_prev) {
                    if (strcmp(prev->strNetworkID, "test") == 0)
                        prev_net = CHAIN_TESTNET;
                    else if (strcmp(prev->strNetworkID, "regtest") == 0)
                        prev_net = CHAIN_REGTEST;
                }
                chain_params_select(CHAIN_MAIN);

                /* Deterministic baseline. Another group in this process may
                 * have loaded parameters or installed a PHGR13 fixture VK. */
                sapling_free_params();
                sprout_phgr_set_vk(NULL);

                VK_CHECK("a corrupt sprout-verifying.key is REFUSED",
                         !sapling_init_params(scratch));
                VK_CHECK("a refused directory reports params as NOT loaded",
                         !sapling_params_loaded());

                /* The publish/free invariant: nothing is published. */
                VK_CHECK("refused load publishes NO spend VK",
                         sapling_test_published_spend_vk() == NULL);
                VK_CHECK("refused load publishes NO output VK",
                         sapling_test_published_output_vk() == NULL);
                VK_CHECK("refused load publishes NO sprout-groth16 VK",
                         sprout_test_published_vk() == NULL);
                VK_CHECK("refused load publishes NO PHGR13 VK",
                         sprout_test_published_phgr_vk() == NULL);

#ifdef ZCL_UAF_PROBE
                /* Opt-in reproducer for the defect the assertions above pin.
                 * Build with -DZCL_UAF_PROBE and run under valgrind or ASan:
                 * it drives the exact dereference the production verifier
                 * performs (bls12_381.c groth16_verify, "struct g1_point vk_x
                 * = vk->ic[0];") against whatever the refused load left
                 * published. Against the current code the pointer is NULL and
                 * nothing is dereferenced; against the pre-fix ordering it
                 * reported "Invalid read of size 32 ... free'd by
                 * sapling_init_params", which is a consensus verifier reading
                 * freed heap. Off by default — a plain run must not depend on
                 * a checker being present. */
                {
                    const struct groth16_vk *pub_vk =
                        sapling_test_published_spend_vk();
                    fprintf(stderr, "[uaf-probe] published spend vk=%p\n",
                            (const void *)pub_vk);
                    if (pub_vk) {
                        struct groth16_proof pr;
                        memset(&pr, 0, sizeof(pr));
                        uint64_t pub[7][4];
                        memset(pub, 0, sizeof(pub));
                        pub[0][0] = 1;
                        fprintf(stderr, "[uaf-probe] groth16_verify -> %d\n",
                                (int)groth16_verify(pub_vk, &pr, pub, 7));
                    }
                }
#endif

                /* Fail-closed is therefore still reachable: with nothing
                 * published the consensus entry points reject. */
                {
                    struct sapling_verification_ctx vctx;
                    sapling_verification_ctx_init(&vctx);
                    uint8_t cv[32], cm[32], epk[32], zk[192];
                    memset(cv, 0x11, 32); memset(cm, 0x22, 32);
                    memset(epk, 0x33, 32); memset(zk, 0x44, 192);
                    VK_CHECK("with nothing published, check_output rejects",
                             !sapling_check_output(&vctx, cv, cm, epk, zk));
                }

                /* The A side of the A/B below: the SAME real mainnet shielded
                 * transaction, through the SAME production entry point, is
                 * REJECTED while no verifying key is published. Without this,
                 * the acceptance after the fallback would not prove that the
                 * fallback is what made validation work. */
                VK_CHECK("before the fallback, a real mainnet shielded proof "
                         "is REJECTED (fail-closed)",
                         !vk_contextual_ok(NULL));

                /* Now the fallback. */
                VK_CHECK("embedded VKs install after a refused directory",
                         sapling_install_embedded_vks());
                VK_CHECK("fallback arms proof validation",
                         sapling_params_loaded());
                VK_CHECK("fallback reports keys as compiled-in",
                         sapling_vks_are_embedded());
                VK_CHECK("fallback does NOT arm proving",
                         !zclassic_sapling_prover_is_ready());

                /* The installed Sapling keys are the SAME keys a good
                 * parameter directory would have installed — parsed here from
                 * the real files' prefixes and compared field by field. This
                 * is the property that makes the fallback consensus-safe: no
                 * proof is accepted that a fully-parameterised node would
                 * reject, because the verifier is bit-for-bit identical. */
                {
                    struct groth16_vk from_file = {0};
                    char p[1200];
                    snprintf(p, sizeof(p), "%s/sapling-spend.params", real_dir);
                    bool ok = vk_from_real_file(&from_file, p,
                                                zcl_embedded_vks[0].len);
                    VK_CHECK("real sapling-spend VK prefix parses", ok);
                    VK_CHECK("published spend VK == the real file's spend VK",
                             ok && vk_equal(sapling_test_published_spend_vk(),
                                            &from_file));
                    free(from_file.ic);

                    struct groth16_vk out_file = {0};
                    snprintf(p, sizeof(p), "%s/sapling-output.params", real_dir);
                    ok = vk_from_real_file(&out_file, p,
                                           zcl_embedded_vks[1].len);
                    VK_CHECK("real sapling-output VK prefix parses", ok);
                    VK_CHECK("published output VK == the real file's output VK",
                             ok && vk_equal(sapling_test_published_output_vk(),
                                            &out_file));
                    free(out_file.ic);
                }

                /* The B side: the SAME transaction, the SAME entry point, now
                 * ACCEPTED — against the compiled-in PHGR13 key, which is the
                 * very key whose file was the one corrupted above. A/B against
                 * the rejection asserted before the install, so acceptance
                 * here is attributable to the fallback and nothing else. */
                {
                    struct vk_js_inputs js;
                    VK_CHECK("a REAL mainnet shielded proof validates on the "
                             "fallback keys", vk_contextual_ok(&js));

                    /* And the verifier is not a rubber stamp: one flipped
                     * proof byte, same public inputs, must be rejected. Driven
                     * through sprout_verify_phgr13 rather than the contextual
                     * path because every byte of the transaction is covered by
                     * the JoinSplit signature, so a tampered tx would be
                     * rejected for its signature before the proof was ever
                     * checked — which would test nothing about the key. */
                    VK_CHECK("fixture JoinSplit public inputs recovered",
                             js.valid);
                    if (js.valid) {
                        VK_CHECK("the fallback PHGR13 key accepts the real "
                                 "proof directly",
                                 sprout_verify_phgr13(js.proof, js.rt,
                                     js.h_sig, js.mac1, js.mac2, js.nf1,
                                     js.nf2, js.cm1, js.cm2,
                                     js.vpub_old, js.vpub_new));
                        uint8_t bad_proof[PHGR_PROOF_SIZE];
                        memcpy(bad_proof, js.proof, sizeof(bad_proof));
                        bad_proof[17] ^= 0x01u;
                        VK_CHECK("one flipped proof byte is REJECTED by the "
                                 "fallback PHGR13 key",
                                 !sprout_verify_phgr13(bad_proof, js.rt,
                                     js.h_sig, js.mac1, js.mac2, js.nf1,
                                     js.nf2, js.cm1, js.cm2,
                                     js.vpub_old, js.vpub_new));
                    }
                }

                /* Leave the process as this section found it: nothing loaded,
                 * so a later group's sapling_init_params does a real load. */
                sapling_free_params();
                sprout_phgr_set_vk(NULL);
                if (had_prev) chain_params_select(prev_net);
            }

            vk_unstage_planted_dir(scratch);
        }
    }

    /* ── 2. Installing the embedded keys arms validation ──────────────── */
    {
        VK_CHECK("install succeeds", sapling_install_embedded_vks());
        VK_CHECK("params report as loaded (proof validation armed)",
                 sapling_params_loaded());
        VK_CHECK("keys report as embedded, not from a parameter directory",
                 sapling_vks_are_embedded());
        VK_CHECK("install is idempotent", sapling_install_embedded_vks());
        VK_CHECK("a real mainnet shielded proof validates with the embedded "
                 "keys", vk_contextual_ok(NULL));
    }

    /* ── 3. Proving stays fail-closed ─────────────────────────────────── */
    {
        /* This is the safety property that lets the boot gate stand down.
         * No proving keys were loaded, so the prover must not claim to be
         * ready — sapling.c's build_output_description() writes a 192-byte
         * zero proof when no proving key is present, and the wallet's refusal
         * on this flag is what keeps that branch unreachable. */
        VK_CHECK("prover is NOT ready with verifying keys alone",
                 !zclassic_sapling_prover_is_ready());

        const char *status = zclassic_sapling_prover_status();
        VK_CHECK("prover status names the missing parameters",
                 status != NULL &&
                 strcmp(status, "params_not_initialized") == 0);
    }

    /* ── 4. A planted bad blob is refused ─────────────────────────────── */
    {
        const struct zcl_embedded_vk *e = &zcl_embedded_vks[0];

        /* Control: the genuine blob passes, so a later refusal means the
         * planted damage was detected and not that the check refuses
         * everything. */
        VK_CHECK("genuine blob passes its own digest",
                 sapling_test_embedded_vk_sha256_ok(e->name, e->bytes, e->len,
                                                    e->sha256_hex));

        uint8_t *bad = malloc(e->len);
        VK_CHECK("allocated planted-bad-blob copy", bad != NULL);
        if (bad) {
            /* One flipped bit, in the middle of the key material. */
            memcpy(bad, e->bytes, e->len);
            bad[e->len / 2] ^= 0x01u;
            VK_CHECK("one flipped bit is refused",
                     !sapling_test_embedded_vk_sha256_ok(e->name, bad, e->len,
                                                         e->sha256_hex));

            /* First byte, last byte, and a truncation: a length-only or
             * prefix-only comparison would let at least one of these pass. */
            memcpy(bad, e->bytes, e->len);
            bad[0] ^= 0xffu;
            VK_CHECK("a corrupt first byte is refused",
                     !sapling_test_embedded_vk_sha256_ok(e->name, bad, e->len,
                                                         e->sha256_hex));

            memcpy(bad, e->bytes, e->len);
            bad[e->len - 1] ^= 0xffu;
            VK_CHECK("a corrupt last byte is refused",
                     !sapling_test_embedded_vk_sha256_ok(e->name, bad, e->len,
                                                         e->sha256_hex));

            VK_CHECK("a truncated blob is refused",
                     !sapling_test_embedded_vk_sha256_ok(e->name, e->bytes,
                                                         e->len - 1,
                                                         e->sha256_hex));
            free(bad);
        }

        /* Cross-wiring: the right bytes under the wrong name's digest must
         * fail, so the table cannot be reordered without being noticed. */
        VK_CHECK("spend bytes under the output digest are refused",
                 !sapling_test_embedded_vk_sha256_ok(
                     zcl_embedded_vks[0].name, zcl_embedded_vks[0].bytes,
                     zcl_embedded_vks[0].len, zcl_embedded_vks[1].sha256_hex));
    }

    /* ── 5. Proving parameters that arrive AFTER the fallback ──────────
     *
     * The whole point of the fallback is that the missing capability can come
     * back. A node boots with no ~/.zcash-params, installs the compiled-in
     * verifying keys, syncs and validates; later the proving parameters are
     * fetched (core/modules/sapling/params_fetch.c) and sapling_init_params() is called
     * on the directory that now holds them. Shielded sending has to work from
     * that moment, without a restart.
     *
     * Three states are asserted in one sequence, because only the sequence
     * shows the transitions:
     *
     *   verifying keys only  → prover NOT ready, sending refused
     *   a directory that FAILS its pin → still NOT ready, still refused, and
     *                          nothing published or freed from those bytes
     *   the real directory   → ready, and the readiness is earned by a real
     *                          Spend+Output+binding bundle that the node's own
     *                          consensus verifier accepted
     *
     * This section runs last on purpose: it leaves proving parameters resident
     * in the process, and sections 2-4 assert the opposite. It restores the
     * process to "nothing loaded" on the way out anyway.
     *
     * Needs a real parameter directory for the upgrade half.  Without one,
     * the validation-only state is asserted explicitly instead of emitting a
     * SKIP that would make an exact proof incomplete. */
    {
        const char *home = getenv("HOME");
        char real_dir[1024];
        snprintf(real_dir, sizeof(real_dir), "%s/.zcash-params",
                 home ? home : "");
        char probe[1200];
        snprintf(probe, sizeof(probe), "%s/sprout-verifying.key", real_dir);

        char scratch[1200];
        bool staged = false;
        if (!home || access(probe, R_OK) != 0) {
            printf("params_vk_embedded: external late-proving upgrade... "
                   "NOT INSTALLED (no readable %s; asserting the honest "
                   "validation-only state)\n", real_dir);
            VK_CHECK("without external proving parameters the prover remains "
                     "unavailable", !zclassic_sapling_prover_is_ready());
            VK_CHECK("without external proving parameters status remains "
                     "params_not_initialized",
                     strcmp(zclassic_sapling_prover_status(),
                            "params_not_initialized") == 0);
        } else {
            staged = vk_stage_planted_dir(real_dir, scratch, sizeof(scratch));
            VK_CHECK("late-load fixture staged", staged);
        }

        if (staged) {
            const struct chain_params *prev = chain_params_get();
            bool had_prev = (prev != NULL);
            enum chain_network prev_net = CHAIN_MAIN;
            if (had_prev) {
                if (strcmp(prev->strNetworkID, "test") == 0)
                    prev_net = CHAIN_TESTNET;
                else if (strcmp(prev->strNetworkID, "regtest") == 0)
                    prev_net = CHAIN_REGTEST;
            }
            chain_params_select(CHAIN_MAIN);

            /* Deterministic baseline: no keys, no proving backend. Another
             * group in this process may have done a full load already. */
            sapling_free_params();
            sprout_phgr_set_vk(NULL);
            zclassic_test_prover_reset();

            /* ── State A: verifying keys only ─────────────────────────── */
            VK_CHECK("A: the fallback installs", sapling_install_embedded_vks());
            VK_CHECK("A: validation is armed", sapling_params_loaded());
            VK_CHECK("A: proving is NOT armed — sending is refused",
                     !zclassic_sapling_prover_is_ready());
            VK_CHECK("A: no proving key is resident",
                     sapling_get_spend_pk(NULL) == NULL &&
                     sapling_get_output_pk(NULL) == NULL);

            /* The exact pointers the consensus verifiers are reading. A later
             * load must not swap or free what these point at while validation
             * is running — this process's verifiers hold no lock. */
            const struct groth16_vk *spend_pub =
                sapling_test_published_spend_vk();
            const struct groth16_vk *output_pub =
                sapling_test_published_output_vk();
            const struct groth16_vk *sprout_pub = sprout_test_published_vk();
            VK_CHECK("A: all three Groth16 VKs are published",
                     spend_pub && output_pub && sprout_pub);

            /* ── State B: a directory that fails its pin ───────────────── */
            VK_CHECK("B: a directory failing its SHA-512 pin is REFUSED",
                     !sapling_init_params(scratch));
            VK_CHECK("B: proving is still NOT armed",
                     !zclassic_sapling_prover_is_ready());
            VK_CHECK("B: no proving key was published from refused bytes",
                     sapling_get_spend_pk(NULL) == NULL &&
                     sapling_get_output_pk(NULL) == NULL);
            /* And the refusal did not cost the node its validation. The
             * published pointers are the SAME objects, not merely non-NULL:
             * a refused upgrade that freed and reinstalled them would be a
             * verifier reading freed heap. */
            VK_CHECK("B: validation survives the refusal, same VK objects",
                     sapling_test_published_spend_vk() == spend_pub &&
                     sapling_test_published_output_vk() == output_pub &&
                     sprout_test_published_vk() == sprout_pub);
            {
                struct vk_js_inputs js;
                VK_CHECK("B: a real mainnet shielded proof still validates",
                         vk_contextual_ok(&js));
            }

            /* ── State C: the real directory ──────────────────────────── */
            VK_CHECK("C: the late proving parameters LOAD",
                     sapling_init_params(real_dir));

            /* THE regression. Before the fix, sapling_init_params() saw the
             * params_loaded flag that the fallback had set and returned true
             * without reading a byte, so this stayed false forever and
             * shielded sending stayed dead until the process restarted. */
            VK_CHECK("C: proving is armed — sending is possible",
                     zclassic_sapling_prover_is_ready());
            VK_CHECK("C: the proving keys are resident",
                     sapling_get_spend_pk(NULL) != NULL &&
                     sapling_get_output_pk(NULL) != NULL);
            {
                size_t sn = 0, on = 0;
                (void)sapling_get_spend_pk(&sn);
                (void)sapling_get_output_pk(&on);
                VK_CHECK("C: the proving keys are whole files, not prefixes",
                         sn > zcl_embedded_vks[0].len &&
                         on > zcl_embedded_vks[1].len);
            }
            /* Readiness is not a flag someone set: the backend reached READY
             * only by proving a Spend + Output + binding bundle and having
             * this node's own consensus verifier accept it. Re-running the
             * gate from the READY state must agree. */
            VK_CHECK("C: the prover->verifier gate agrees",
                     zclassic_sapling_prover_run_self_test());
            VK_CHECK("C: status says ready",
                     strcmp(zclassic_sapling_prover_status(), "ready") == 0);

            /* The upgrade must not have touched the keys the verifiers are
             * reading. Same objects, same values, no window. */
            VK_CHECK("C: the upgrade did NOT republish the verifying keys",
                     sapling_test_published_spend_vk() == spend_pub &&
                     sapling_test_published_output_vk() == output_pub &&
                     sprout_test_published_vk() == sprout_pub);
            {
                struct groth16_vk from_file = {0};
                char p[1200];
                snprintf(p, sizeof(p), "%s/sapling-spend.params", real_dir);
                bool ok = vk_from_real_file(&from_file, p,
                                            zcl_embedded_vks[0].len);
                VK_CHECK("C: published spend VK still equals the real file's",
                         ok && vk_equal(sapling_test_published_spend_vk(),
                                        &from_file));
                free(from_file.ic);
            }
            {
                struct vk_js_inputs js;
                VK_CHECK("C: a real mainnet shielded proof still validates",
                         vk_contextual_ok(&js));
            }

            /* Idempotent: a second call after a full load does nothing and
             * says so, rather than re-reading 777 MB or re-publishing. */
            VK_CHECK("C: a repeat call is a no-op that still reports loaded",
                     sapling_init_params(real_dir) &&
                     sapling_test_published_spend_vk() == spend_pub);

            /* Leave the process as this section found it. */
            sapling_free_params();
            sprout_phgr_set_vk(NULL);
            zclassic_test_prover_reset();
            if (had_prev) chain_params_select(prev_net);
            vk_unstage_planted_dir(scratch);
        }
    }

    printf("params_vk_embedded tests: %s\n", failures ? "FAILED" : "PASSED");
    return failures;
}
