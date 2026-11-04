/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Append-only signed MMR over accepted-proof verdict leaves, plus
 *          the pure admission, sampling and divergence rules a later reuse
 *          path would apply to it.
 *
 * ZCL_DEV_PROOF_VERDICT_MMR names a persistent directory (absolute, unset =
 * off). After a proof ENDS ACCEPTED, the signed PASS leaves the cold runner
 * emitted for that pair are re-verified, copied into <dir>/objects, and
 * their roots appended to <dir>/chain.log as MMR checkpoints signed by this
 * box's proof identity. Nothing here skips a test: the test dimension still
 * runs every selected group cold, and test_log_account still demands
 * reused == 0.
 *

 * Every leaf recorded here is signed by the proof producer, which is
 * candidate code running as the candidate's uid: it is AUDIT data, logged as
 * admissible=0, and the admission below ignores it unless a separate
 * verifier account signed it (see "Who may make a leaf ADMISSIBLE").
 *
 * chain.log is a sequence of records: count u8 (1..64) || checkpoint wire
 * [VCS_ZCODE_OBSERVATION_MMR_WIRE_BYTES] || count roots [32]. Loading
 * replays every record from the empty log with verify_extension, so a
 * rewritten, reordered or foreign-issuer history is refused as a whole. A
 * truncated tail also refuses; dropping whole trailing records only
 * forgets leaves (fewer groups admitted), it cannot add one. */
#ifndef ZCL_DEV_PROOF_VERDICT_MMR_H
#define ZCL_DEV_PROOF_VERDICT_MMR_H

#include "dev_proof_observation.h"
#include "vcs/zcode_observation_mmr.h"

#define ZCL_DEV_VMMR_ENV "ZCL_DEV_PROOF_VERDICT_MMR"
#define ZCL_DEV_VMMR_MAX_LEAVES 65536u
#define ZCL_DEV_VMMR_SAMPLE_MASK 7u /* about 1/8 of keys */

struct zcl_dev_vmmr_chain {
    uint8_t *roots;       /* leaf_count * 32, in append order */
    uint32_t leaf_count;
    uint32_t records;
    uint8_t head_root[32]; /* root of the newest checkpoint; 0 when empty */
    struct vcs_zcode_observation_mmr_checkpoint head; /* valid when records */
};

/* The armed directory: ZCL_DEV_PROOF_VERDICT_MMR when absolute and bounded,
 * else NULL. */
const char *zcl_dev_vmmr_dir(void);

/* Load and fully verify <dir>/chain.log against this box's proof identity.
 * An absent log is an empty chain. Any defect refuses by name. */
bool zcl_dev_vmmr_load(const char *dir, struct zcl_dev_vmmr_chain *out,
                       char *why, size_t why_len);
void zcl_dev_vmmr_release(struct zcl_dev_vmmr_chain *chain);

/* Verify the existing chain, extend it with `roots` (chunked to the MMR batch
 * limit, each chunk checked with verify_extension) and append. `out` is
 * reloaded from disk, so it reports what a later reader will see. */
bool zcl_dev_vmmr_append(const char *dir, const uint8_t (*roots)[32],
                         size_t count, int64_t now_unix,
                         struct zcl_dev_vmmr_chain *out,
                         char *why, size_t why_len);

/* The test dimension's argv when armed: the runner's cold audit with partial
 * observation collection. Returns the argc written or 0 when too small. */
#define ZCL_DEV_VMMR_TEST_ARGC 5u
size_t zcl_dev_vmmr_test_argv(const char *binary, const char *only,
                              const char **argv, size_t argv_cap);

struct zcl_dev_vmmr_adopt {
    uint32_t seen;      /* OBSERVATION ... PASS lines in the log */
    uint32_t adopted;   /* leaves newly appended to the chain */
    uint32_t refused;   /* lines whose leaf did not verify; never adopted */
    uint32_t leaf_count;
    uint8_t head_root[32];
};

/* After an ACCEPTED proof: adopt the PASS leaves named by the cold log from
 * the per-pair store into <dir>. Every leaf is re-read, re-rooted and
 * re-verified for its exact key and group; a line without a verifying leaf
 * is counted refused and adopts nothing. */
bool zcl_dev_vmmr_adopt_log(const char *dir, const char *pair_store,
                            const char *log, size_t log_len,
                            struct zcl_dev_vmmr_adopt *out,
                            char *why, size_t why_len);

/* ── Who may make a leaf ADMISSIBLE ───────────────────────────────────────
 * Leaves this module's recorder writes are signed by the proof producer,
 * which is candidate code running as the candidate's uid: they are AUDIT
 * data and never admit a group. Admission accepts a PASS only from a leaf
 * signed by a key listed in the verifier key file named by
 * ZCL_DEV_PROOF_VERIFIER_KEYS (one 64-hex key per line, # comments). That
 * file must be absolute, a regular file owned by a uid other than the
 * caller's effective uid, and writable by neither group nor world, in a
 * directory with the same properties. Unset or failing any check means no
 * verifier account: reuse stays unqualified, exactly as before. */
#define ZCL_DEV_VMMR_KEYS_MAX 64u
struct zcl_dev_vmmr_keys {
    uint8_t key[ZCL_DEV_VMMR_KEYS_MAX][32];
    size_t count;
};
#define ZCL_DEV_VMMR_UNQUALIFIED "test-reuse: unqualified(no_verifier_account)"
/* Parse key text (no ownership check; for fixtures and the strict loader). */
bool zcl_dev_vmmr_keys_parse(const char *text, size_t len,
                             struct zcl_dev_vmmr_keys *out);
/* The strict loader over ZCL_DEV_PROOF_VERIFIER_KEYS. Refuses by writing
 * ZCL_DEV_VMMR_UNQUALIFIED into `why`. */
bool zcl_dev_vmmr_keys_load(struct zcl_dev_vmmr_keys *out,
                            char *why, size_t why_len);

/* Reuse admission against a verified chain. Opening loads every leaf of the
 * chain once; one unreadable or re-rooting-mismatched object makes the index
 * unavailable (every group MISSING). */
struct zcl_dev_vmmr_index;
struct zcl_dev_vmmr_index *zcl_dev_vmmr_index_open(
    const char *dir, const struct zcl_dev_vmmr_chain *chain,
    const struct zcl_dev_vmmr_keys *verifiers,
    char *why, size_t why_len);
void zcl_dev_vmmr_index_close(struct zcl_dev_vmmr_index *index);

/* PASS only when an eligible signed PASS for exactly (key, group) is in the
 * chain, signed by a listed verifier key, and no eligible FAIL (from any
 * signer) contradicts it. Producer-signed PASS leaves yield MISSING. `elapsed_ms` receives the
 * newest eligible PASS leaf's cold time. */
enum zcl_dev_observation_verdict zcl_dev_vmmr_admit(
    const struct zcl_dev_vmmr_index *index,
    const uint8_t key[ZCL_DEV_VERDICT_LEAF_KEY_BYTES], const char *group,
    uint64_t *elapsed_ms, char *why, size_t why_len);

/* Deterministic sample: SHA3 over a domain tag, the key and the proof pair. */
bool zcl_dev_vmmr_sampled(const uint8_t key[ZCL_DEV_VERDICT_LEAF_KEY_BYTES],
                          const char *pair);

struct zcl_dev_vmmr_item {
    enum zcl_dev_observation_verdict admitted;
    uint64_t elapsed_ms;
    bool sampled;
    bool cold_pass; /* meaningful only when sampled: the cold rerun's verdict */
};
struct zcl_dev_vmmr_plan {
    uint32_t reused;   /* groups that may be skipped */
    uint32_t sampled;  /* admitted PASS groups that still run cold */
    uint64_t saved_ms; /* estimate: sum of skipped groups' leaf elapsed_ms */
    bool divergence;   /* a sampled group disagreed: reuse_divergence */
};
/* skip[i] is set only for an admitted, unsampled PASS. Any sampled
 * disagreement clears every skip (the caller reruns them all cold) and
 * zeroes reused and saved_ms. MISSING, FAIL and CONFLICT never skip. */
void zcl_dev_vmmr_resolve(const struct zcl_dev_vmmr_item *items, size_t count,
                          bool *skip, struct zcl_dev_vmmr_plan *plan);

#endif
