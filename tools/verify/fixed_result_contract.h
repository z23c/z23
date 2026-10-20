/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0.
 * purpose: The one versioned byte contract, z23verify.fixed_result.v2, that
 *          every producer and consumer of the fixed result.c verifier uses:
 *          the framing, the pins file, the launch request, the worker result
 *          packet, the launch receipt, and the record-to-receipt binding.
 *
 * Every v2 byte string is one framing: F(domain) then F(label) F(value) for
 * each field in a fixed order, where F(x) is an unsigned 64-bit
 * little-endian byte count followed by the bytes of x. Hash preimages use
 * the same framing and are hashed with SHA3-256. docs/work/
 * verifier-contract-v2.md spells out every artifact byte for byte.
 *
 * This module is pure: it reads and writes only caller buffers. Parsing a
 * receipt or pins file never makes it trustworthy; the caller must still
 * prove root ownership, the separate UIDs and the live jail. Every refusal
 * is a stable token. */
#ifndef Z23_FIXED_RESULT_CONTRACT_H
#define Z23_FIXED_RESULT_CONTRACT_H

#include "dev/verify_attest.h"
#include "verify/fixed_result_key_v2.h"
#include "sha3/sha3.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_FR_CONTRACT "z23verify.fixed_result.v2"
#define ZCL_FR_PROFILE "test_fast"
#define ZCL_FR_PROFILE_SHA3 \
    "5e8a1cafce7350ff3c335c6a714f59c75c1e646de82eb03d076f68bdad244e1c"
/* The retired strict profile's digest, named only so it refuses by name. */
#define ZCL_FR_RETIRED_STRICT_SHA3 \
    "5fb3b13597488c20a9f5aeca2b654fad92b39714d93069c12c082206977aadaf"
#define ZCL_FR_CWD "/zclassic23"
#define ZCL_FR_SOURCE "platform/modules/base/src/result.c"
#define ZCL_FR_TOOLCHAIN_PREFIX "z23.gcc14.fast_result.v2:"
#define ZCL_FR_COMPILER_UID 60093u

#define ZCL_FR_DOMAIN_PINS "z23verify.fixed_result.pins.v2"
#define ZCL_FR_DOMAIN_REQUEST "z23verify.fixed_result.request.v2"
#define ZCL_FR_DOMAIN_PACKET "z23verify.fixed_result.packet.v2"
#define ZCL_FR_DOMAIN_RECEIPT "z23verify.fixed_result.receipt.v2"
#define ZCL_FR_DOMAIN_ENV "z23verify.fixed_result.env.v2"
#define ZCL_FR_DOMAIN_EXEC_ARGV "z23verify.fixed_result.exec_argv.v2"
#define ZCL_FR_DOMAIN_CLOSURE "z23verify.fixed_result.closure.v2"

#define ZCL_FR_ROOT_COUNT 12u
#define ZCL_FR_ARTIFACT_COUNT 4u
#define ZCL_FR_TARGET_LEN 121u  /* build/test-obj/epochs/<64>/…/result.o */
#define ZCL_FR_SCRATCH_LEN 19u  /* /work/result.<6 alphanumeric> */
#define ZCL_FR_ID_LEN 32u       /* launch_id and request_nonce hex */
#define ZCL_FR_TOOLCHAIN_LEN (sizeof(ZCL_FR_TOOLCHAIN_PREFIX) - 1u + 64u)
#define ZCL_FR_TEXT_MAX 4096u
#define ZCL_FR_LABEL_MAX 64u
#define ZCL_FR_DOMAIN_MAX 64u

/* Refusal tokens. */
#define ZCL_FR_WHY_ARGUMENTS "contract_arguments_invalid"
#define ZCL_FR_WHY_BUFFER "contract_buffer_limit"
#define ZCL_FR_WHY_V1_RETIRED "contract_version_v1_retired"
#define ZCL_FR_WHY_VERSION_UNKNOWN "contract_version_unknown"
#define ZCL_FR_WHY_WRONG_ARTIFACT "contract_artifact_kind_mismatch"
#define ZCL_FR_WHY_DOMAIN_MALFORMED "contract_domain_malformed"
#define ZCL_FR_WHY_TRUNCATED "contract_frame_truncated"
#define ZCL_FR_WHY_OVERSIZE "contract_frame_oversize"
#define ZCL_FR_WHY_FIELD_MISSING "contract_field_missing"
#define ZCL_FR_WHY_FIELD_ORDER "contract_field_order"
#define ZCL_FR_WHY_FIELD_MALFORMED "contract_field_malformed"
#define ZCL_FR_WHY_HASH_ZERO "contract_hash_zero"
#define ZCL_FR_WHY_TRAILING "contract_trailing_bytes"
#define ZCL_FR_WHY_PROFILE "contract_profile_mismatch"
#define ZCL_FR_WHY_TARGET "contract_target_invalid"
#define ZCL_FR_WHY_TOOLCHAIN "contract_toolchain_unsupported"
#define ZCL_FR_WHY_ENV "contract_env_mismatch"
#define ZCL_FR_WHY_CWD "contract_cwd_mismatch"
#define ZCL_FR_WHY_SOURCE "contract_source_mismatch"
#define ZCL_FR_WHY_SCRATCH "contract_scratch_invalid"
#define ZCL_FR_WHY_IDENTITY "contract_identity_mismatch"
#define ZCL_FR_WHY_WORKER_EXIT "contract_worker_exit_nonzero"
#define ZCL_FR_WHY_ARTIFACT_DUPLICATE "contract_artifact_duplicate"
#define ZCL_FR_WHY_ARTIFACT_UNKNOWN "contract_artifact_unknown"
#define ZCL_FR_WHY_ARTIFACT_ORDER "contract_artifact_order"
#define ZCL_FR_WHY_PIN_MISMATCH "contract_pin_mismatch"
#define ZCL_FR_WHY_RECEIPT_ARTIFACT "contract_receipt_artifact_mismatch"
#define ZCL_FR_WHY_RECEIPT_INPUT "contract_receipt_input_mismatch"
#define ZCL_FR_WHY_DEPFILE_TARGET "contract_depfile_target_mismatch"

/* ── Framing ─────────────────────────────────────────────────────────── */

/* Appends frames to `buf`, or, when `hash` is set, feeds them to it
 * instead. `ok` turns false on the first overflow and stays false. */
struct zcl_fr_writer {
    uint8_t *buf;
    size_t cap;
    size_t len;
    struct sha3_256_ctx *hash;
    bool ok;
};

void zcl_fr_writer_buffer(struct zcl_fr_writer *w, uint8_t *buf, size_t cap);
void zcl_fr_writer_hash(struct zcl_fr_writer *w, struct sha3_256_ctx *hash);
void zcl_fr_put(struct zcl_fr_writer *w, const void *bytes, size_t len);
void zcl_fr_put_text(struct zcl_fr_writer *w, const char *label,
                     const char *text);
void zcl_fr_put_hash(struct zcl_fr_writer *w, const char *label,
                     const uint8_t hash[32]);
void zcl_fr_put_u64(struct zcl_fr_writer *w, const char *label,
                    uint64_t value);

enum zcl_fr_kind {
    ZCL_FR_KIND_TEXT = 0,  /* 1..max bytes, each 0x21..0x7e */
    ZCL_FR_KIND_ROOT = 1,  /* exactly 32 bytes, not all zero */
    ZCL_FR_KIND_U64 = 2,   /* exactly 8 bytes, little-endian */
    ZCL_FR_KIND_BLOB = 3,  /* 0..max bytes, no NUL (record text values) */
    ZCL_FR_KIND_EXACT = 4, /* exactly max bytes, any value */
};

struct zcl_fr_spec {
    const char *label;
    enum zcl_fr_kind kind;
    size_t max;
};

struct zcl_fr_value {
    const uint8_t *bytes; /* borrowed from the parsed buffer */
    size_t len;
    uint64_t u64;
};

/* Decode `bytes` as F(domain) plus exactly `count` labeled fields. A v1
 * text header refuses contract_version_v1_retired before any framing
 * check. Returns NULL on success or a refusal token. */
const char *zcl_fr_decode(const uint8_t *bytes, size_t len,
                          const char *domain,
                          const struct zcl_fr_spec *spec, size_t count,
                          struct zcl_fr_value *out);

/* Decode a prefix of `bytes`; `*used` is its length. Trailing bytes are
 * the caller's (a signed record's trailer). */
const char *zcl_fr_decode_prefix(const uint8_t *bytes, size_t len,
                                 const char *domain,
                                 const struct zcl_fr_spec *spec, size_t count,
                                 struct zcl_fr_value *out, size_t *used);

/* Decode `count` labeled fields with no domain frame (a signed record's
 * trailer); `*used` is their length. */
const char *zcl_fr_decode_fields(const uint8_t *bytes, size_t len,
                                 const struct zcl_fr_spec *spec, size_t count,
                                 struct zcl_fr_value *out, size_t *used);

/* Write F(domain) and the `count` fields of `values` after checking each
 * against its spec, so an encoder cannot emit what the decoder refuses.
 * U64 fields take `u64`; every other kind takes `bytes`/`len`. */
const char *zcl_fr_encode(struct zcl_fr_writer *w, const char *domain,
                          const struct zcl_fr_spec *spec, size_t count,
                          const struct zcl_fr_value *values);

/* ── Fixed inputs ─────────────────────────────────────────────────────── */

/* SHA3-256 of F(ZCL_FR_DOMAIN_ENV) then F("env") F(entry) per entry. */
void zcl_fr_env_root(const char *const *envp, size_t count, uint8_t out[32]);
/* The only v2 environment: LC_ALL=C, TZ=UTC, TMPDIR=/tmp, PATH=/usr/bin:/bin. */
void zcl_fr_env_fixed_root(uint8_t out[32]);
const char *zcl_fr_env_check(const char *const *envp, size_t count);
/* SHA3-256 of F(ZCL_FR_DOMAIN_EXEC_ARGV) then F("arg") F(arg) per arg. */
bool zcl_fr_exec_argv_sha3(const char *const *argv, size_t count,
                           uint8_t out[32]);
const char *zcl_fr_target_check(const char *target, size_t len);
const char *zcl_fr_scratch_check(const char *scratch, size_t len);
/* The depfile's first rule must name exactly `target` before ':'. */
const char *zcl_fr_depfile_target_check(const uint8_t *dep, size_t dep_len,
                                        const char *target);

/* ── Pins v2: the twelve root-owned roots, in key v2 order ───────────── */

/* Label of root `index` (0..11), e.g. "tree_checker_sha3". */
const char *zcl_fr_root_label(size_t index);
uint8_t *zcl_fr_root_slot(struct zcl_fixed_result_v2_roots *roots,
                          size_t index);
const uint8_t *zcl_fr_root_at(const struct zcl_fixed_result_v2_roots *roots,
                              size_t index);
/* Every root nonzero, profile_args is the test-fast profile and
 * environment is the fixed v2 environment root. */
const char *zcl_fr_roots_check(const struct zcl_fixed_result_v2_roots *r);
bool zcl_fr_pins_encode(const struct zcl_fixed_result_v2_roots *roots,
                        uint8_t *out, size_t cap, size_t *len,
                        const char **why);
bool zcl_fr_pins_parse(const uint8_t *bytes, size_t len,
                       struct zcl_fixed_result_v2_roots *out,
                       const char **why);

/* ── Launch request v2 (launcher to worker) ───────────────────────────── */

bool zcl_fr_request_encode(const char *target, uint8_t *out, size_t cap,
                           size_t *len, const char **why);
bool zcl_fr_request_parse(const uint8_t *bytes, size_t len,
                          char target[ZCL_FR_TARGET_LEN + 1u],
                          const char **why);

/* ── Worker result packet v2 (worker to launcher, four FDs) ───────────── */

const char *zcl_fr_artifact_names_check(const char *const *names,
                                        size_t count);

struct zcl_fr_packet {
    char scratch[ZCL_FR_SCRATCH_LEN + 1u];
    char target[ZCL_FR_TARGET_LEN + 1u];
    uint8_t compile_argv_sha3[32];
    uint8_t preprocess_argv_sha3[32];
    uint8_t environment_sha3[32];
};

bool zcl_fr_packet_encode(const struct zcl_fr_packet *packet, uint8_t *out,
                          size_t cap, size_t *len, const char **why);
bool zcl_fr_packet_parse(const uint8_t *bytes, size_t len,
                         struct zcl_fr_packet *out, const char **why);

/* ── Launch receipt v2 (root launcher, one per execution) ─────────────── */

struct zcl_fr_artifact_digest {
    uint64_t size;
    uint8_t sha3[32];
};

/* Fixed fields (profile, recorded_cwd, source, the compiler identity and
 * worker_exit) are not stored: parse refuses any other value and encode
 * writes the one allowed value. */
struct zcl_fr_receipt {
    char launch_id[ZCL_FR_ID_LEN + 1u];
    char request_nonce[ZCL_FR_ID_LEN + 1u];
    char target[ZCL_FR_TARGET_LEN + 1u];
    char toolchain_id[ZCL_FR_TOOLCHAIN_LEN + 1u];
    struct zcl_fixed_result_v2_roots pins;
    char scratch[ZCL_FR_SCRATCH_LEN + 1u];
    uint8_t compile_argv_sha3[32];
    uint8_t preprocess_argv_sha3[32];
    uint64_t mount_namespace_dev;
    uint64_t mount_namespace_ino;
    struct zcl_fr_artifact_digest artifacts[ZCL_FR_ARTIFACT_COUNT];
};

bool zcl_fr_receipt_encode(const struct zcl_fr_receipt *receipt,
                           uint8_t *out, size_t cap, size_t *len,
                           const char **why);
bool zcl_fr_receipt_parse(const uint8_t *bytes, size_t len,
                          struct zcl_fr_receipt *out, const char **why);

/* ── Record-to-receipt binding ────────────────────────────────────────── */

struct zcl_fr_artifact_bytes {
    const uint8_t *object;
    size_t object_len;
    const uint8_t *depfile;
    size_t depfile_len;
    const uint8_t *stderr_bytes;
    size_t stderr_len;
};

struct zcl_fr_binding {
    char target[ZCL_FR_TARGET_LEN + 1u];
    struct zcl_verify_attest_binding binding; /* borrows `target` */
};

/* The receiver's independent expectation for one observation. It parses
 * the root-published receipt, requires its twelve roots to equal the
 * receiver's own pins, its toolchain, cwd and preprocessed stream to equal
 * `expected`, its artifact sizes and hashes to equal the fetched bytes,
 * and the fetched depfile to name the receipt's target. On success `out`
 * holds the contract, profile, target and receipt hash that the signed
 * record must repeat. Do not move `out` after the call. */
bool zcl_fr_receipt_bind(const uint8_t *receipt, size_t receipt_len,
                         const struct zcl_fixed_result_v2_roots *pins,
                         const struct zcl_verify_attest_expected *expected,
                         const struct zcl_fr_artifact_bytes *artifacts,
                         struct zcl_fr_binding *out, const char **why);

/* ── Failure receipt v2 (root launcher, one per failed compile) ───────── */

/* A launch receipt never carries a failure (worker_exit is fixed at 0), so
 * a failed compile has its own root-written artifact. The launcher writes
 * it instead of launch.bin when the worker's fresh -E succeeded and its -c
 * then exited nonzero; the signer seals a FAIL record bound to its hash.
 * Fields 1-37 are the launch receipt's, then compile_exit (1..255), and
 * size plus SHA3 of stderr and of the preprocessed stream. It names no
 * object and no depfile. */
#define ZCL_FR_DOMAIN_FAILURE "z23verify.fixed_result.failure.v2"
#define ZCL_FR_WHY_FAILURE_EXIT "contract_failure_exit_invalid"

struct zcl_fr_failure {
    /* artifacts[0] (object) and [1] (depfile) must be all zero; [2] is
     * stderr and [3] the preprocessed stream. */
    struct zcl_fr_receipt launch;
    uint64_t compile_exit;
};

bool zcl_fr_failure_encode(const struct zcl_fr_failure *failure,
                           uint8_t *out, size_t cap, size_t *len,
                           const char **why);
bool zcl_fr_failure_parse(const uint8_t *bytes, size_t len,
                          struct zcl_fr_failure *out, const char **why);
/* ── Source content root v2 ───────────────────────────────────────────── */

/* The portable source identity pinned as `source_content_sha3`: SHA3-256
 * of F(ZCL_FR_DOMAIN_SOURCE_CONTENT) then, for each file,
 * F("path") F(relative path) F("bytes") F(file bytes). Paths must be
 * strictly ascending by strcmp (so sorted and unique), relative, and free
 * of empty, "." and ".." components. Owner, mode and file type are not
 * part of it. The receiver hashes the files its own -E read; the launcher
 * hashes the fixed result.c chain in the installed source image.
 * Refusals: contract_arguments_invalid, contract_field_malformed,
 * contract_field_order. */
#define ZCL_FR_DOMAIN_SOURCE_CONTENT "z23verify.fixed_result.source_content.v2"
bool zcl_fr_source_content_v2(const char *const *paths,
                              const uint8_t *const *bytes,
                              const size_t *lens, size_t count,
                              uint8_t out[32], const char **why);

#endif
