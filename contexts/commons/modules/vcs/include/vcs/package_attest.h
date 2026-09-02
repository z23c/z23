/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_attest — the signed ZCODE external-verifier attestation (slice 6).
 * One attestation binds a package root, the exact signed release envelope
 * attested, the declarative build recipe root used, the per-compiler
 * outcomes (gcc/clang, each with id + version + outcome), the sanitizer
 * outcomes (ASan/UBSan), the overall result class with a detail code, the
 * test-run facts, the isolation level the build actually ran under, and the
 * verifier's secp256k1 key — all under one signature. This layer parses,
 * serializes, hashes, and verifies only; it has no filesystem, network,
 * compiler, execution, wallet, or node-state authority. Signing happens
 * outside this layer (the external verifier program,
 * zclassic23-package-verify); private keys never enter contexts/commons/modules/vcs.
 *
 * The ZClassic23 node itself NEVER compiles or executes downloaded code:
 * an attestation is produced only by the SEPARATE verifier program running
 * the slice-5 recipe, and this codec is the shared contract between that
 * program (writer) and the node (reader / quorum evaluator). JSON is
 * display-only and is never signed or hashed.
 *
 * Canonical wire encoding (all integers little-endian, exactly one legal
 * encoding per attestation):
 *   [8  magic = "ZCLATT\r\n"]
 *   [2  schema_version = 1]
 *   [32 package_root]          content.v2 package root
 *   [32 release_id]            the exact envelope attested
 *   [32 recipe_root]           the slice-5 recipe the build followed
 *   [1  result_class]          1=build-pass 2=build-fail 3=test-pass
 *                              4=test-fail 5=sanitizer-fail
 *   [1  detail_code]           0=none 1=compile-error 2=compile-timeout
 *                              3=link-error 4=test-exit-mismatch
 *                              5=test-timeout 6=test-signal
 *                              7=asan-findings 8=ubsan-findings
 *                              9=resource-limit
 *   [2  detail_len][detail]    0..160 printable ASCII bytes (0x20..0x7e)
 *   [1  compiler_count]        1..4, entries strictly ascending by
 *                              (id bytes, version bytes):
 *     [1 id_len][id]           1..16 of [a-z0-9.+-]   ("gcc", "clang")
 *     [1 version_len][version] 1..48 printable ASCII
 *     [1 outcome]              0=pass 1=fail 2=unavailable
 *   [1  sanitizer_count]       0..2, entries strictly ascending by name:
 *     [1 name_len][name]       1..16 of [a-z0-9.+-]   ("asan", "ubsan")
 *     [1 outcome]              0=clean 1=findings 2=unavailable
 *   [1  test_ran (0|1)]
 *   [4  test_exit_code]        meaningful when test_ran=1; MUST be 0 when
 *                              test_ran=0 (closed grammar: one encoding)
 *   [1  isolation]             1=full (Landlock+seccomp+rlimits)
 *                              2=degraded (seccomp+rlimits only, named
 *                              loudly — see the verifier's usage text)
 *   [33 verifier_pubkey]       compressed secp256k1
 *   [64 signature]             secp256k1 ECDSA compact r||s, low-S, over
 *                              the attestation id
 *
 * The ATTESTATION ID is SHA3-256 over (domain || the canonical encoding
 * above minus the trailing 64-byte signature). The domain is the ASCII
 * string "zcl.zcode_attest.v1" hashed WITH its single trailing 0x00 byte
 * (sizeof the string literal), the package_manifest convention.
 *
 * Consistency rules (frozen for v1; validate() enforces):
 *   roots    — package_root, release_id, and recipe_root must not be
 *              all-zero (the "no object" sentinel is never a commitment).
 *   class    — PASS classes (build-pass, test-pass) require detail_code 0
 *              and an empty detail; FAIL classes require detail_code != 0.
 *   tests    — build-pass and build-fail require test_ran=0 (build-fail
 *              never reached the test phase; a package with tests that
 *              built is test-pass/test-fail/sanitizer-fail). test-pass and
 *              test-fail require test_ran=1. sanitizer-fail requires at
 *              least one sanitizer outcome=findings; every OTHER class
 *              forbids any findings outcome.
 *   outcomes — a compiler outcome=fail requires a FAIL result class (the
 *              overall verdict cannot pass when a compiler failed);
 *              outcome=unavailable entries carry no verdict weight.
 *   quorum   — what COUNTS as verified (>=2 approved independent keys
 *              signing matching attestations) is the policy layer's rule
 *              (contexts/commons/modules/vcs/package_verify_policy.*), not this codec's. */

#ifndef ZCL_VCS_PACKAGE_ATTEST_H
#define ZCL_VCS_PACKAGE_ATTEST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_PACKAGE_ATTEST_VERSION 1u
#define VCS_PACKAGE_ATTEST_ID_DOMAIN "zcl.zcode_attest.v1"
#define VCS_PACKAGE_ATTEST_WIRE_MAGIC_BYTES 8u
#define VCS_PACKAGE_ATTEST_DETAIL_MAX 160u
#define VCS_PACKAGE_ATTEST_MAX_COMPILERS 4u
#define VCS_PACKAGE_ATTEST_COMPILER_ID_MAX 16u
#define VCS_PACKAGE_ATTEST_COMPILER_VERSION_MAX 48u
#define VCS_PACKAGE_ATTEST_MAX_SANITIZERS 2u
#define VCS_PACKAGE_ATTEST_SANITIZER_NAME_MAX 16u
#define VCS_PACKAGE_ATTEST_PUBKEY_BYTES 33u
#define VCS_PACKAGE_ATTEST_SIGNATURE_BYTES 64u
#define VCS_PACKAGE_ATTEST_ID_BYTES 32u

/* Largest possible canonical attestation: every bounded field full. */
#define VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES \
    (VCS_PACKAGE_ATTEST_WIRE_MAGIC_BYTES + 2u + 32u + 32u + 32u + \
     1u + 1u + 2u + VCS_PACKAGE_ATTEST_DETAIL_MAX + 1u + \
     VCS_PACKAGE_ATTEST_MAX_COMPILERS * \
         (2u + VCS_PACKAGE_ATTEST_COMPILER_ID_MAX + \
          VCS_PACKAGE_ATTEST_COMPILER_VERSION_MAX + 1u) + \
     1u + VCS_PACKAGE_ATTEST_MAX_SANITIZERS * \
         (2u + VCS_PACKAGE_ATTEST_SANITIZER_NAME_MAX + 1u) + \
     1u + 4u + 1u + \
     VCS_PACKAGE_ATTEST_PUBKEY_BYTES + VCS_PACKAGE_ATTEST_SIGNATURE_BYTES)

enum vcs_package_attest_result {
    VCS_PACKAGE_ATTEST_RESULT_BUILD_PASS = 1, /* built; recipe has no tests */
    VCS_PACKAGE_ATTEST_RESULT_BUILD_FAIL = 2,
    VCS_PACKAGE_ATTEST_RESULT_TEST_PASS = 3,
    VCS_PACKAGE_ATTEST_RESULT_TEST_FAIL = 4,
    VCS_PACKAGE_ATTEST_RESULT_SANITIZER_FAIL = 5,
};

enum vcs_package_attest_detail {
    VCS_PACKAGE_ATTEST_DETAIL_NONE = 0,
    VCS_PACKAGE_ATTEST_DETAIL_COMPILE_ERROR = 1,
    VCS_PACKAGE_ATTEST_DETAIL_COMPILE_TIMEOUT = 2,
    VCS_PACKAGE_ATTEST_DETAIL_LINK_ERROR = 3,
    VCS_PACKAGE_ATTEST_DETAIL_TEST_EXIT_MISMATCH = 4,
    VCS_PACKAGE_ATTEST_DETAIL_TEST_TIMEOUT = 5,
    VCS_PACKAGE_ATTEST_DETAIL_TEST_SIGNAL = 6,
    VCS_PACKAGE_ATTEST_DETAIL_ASAN_FINDINGS = 7,
    VCS_PACKAGE_ATTEST_DETAIL_UBSAN_FINDINGS = 8,
    VCS_PACKAGE_ATTEST_DETAIL_RESOURCE_LIMIT = 9,
};

enum vcs_package_attest_outcome {
    VCS_PACKAGE_ATTEST_OUTCOME_PASS = 0,    /* compiler: pass; sanitizer: clean */
    VCS_PACKAGE_ATTEST_OUTCOME_FAIL = 1,    /* compiler: fail; sanitizer: findings */
    VCS_PACKAGE_ATTEST_OUTCOME_UNAVAILABLE = 2,
};

enum vcs_package_attest_isolation {
    VCS_PACKAGE_ATTEST_ISOLATION_FULL = 1,     /* scoped fs+no net+rlimits */
    VCS_PACKAGE_ATTEST_ISOLATION_DEGRADED = 2, /* one or more absent */
};

/* Every rejection names the failed rule. The enum order is frozen. */
enum vcs_package_attest_error {
    VCS_PACKAGE_ATTEST_OK = 0,
    VCS_PACKAGE_ATTEST_ERR_NULL,           /* null argument */
    VCS_PACKAGE_ATTEST_ERR_ALLOC,          /* allocation failure */
    VCS_PACKAGE_ATTEST_ERR_SCHEMA_VERSION, /* schema_version != 1 */
    VCS_PACKAGE_ATTEST_ERR_WIRE_MAGIC,     /* bad magic */
    VCS_PACKAGE_ATTEST_ERR_WIRE_OVERSIZE,  /* exceeds MAX_WIRE_BYTES */
    VCS_PACKAGE_ATTEST_ERR_WIRE_TRUNCATED, /* a field runs past the end */
    VCS_PACKAGE_ATTEST_ERR_WIRE_TRAILING,  /* bytes after the signature */
    VCS_PACKAGE_ATTEST_ERR_PACKAGE_ROOT,   /* all-zero package root */
    VCS_PACKAGE_ATTEST_ERR_RELEASE_ID,     /* all-zero release id */
    VCS_PACKAGE_ATTEST_ERR_RECIPE_ROOT,    /* all-zero recipe root */
    VCS_PACKAGE_ATTEST_ERR_RESULT_CLASS,   /* unknown result class */
    VCS_PACKAGE_ATTEST_ERR_DETAIL_CODE,    /* unknown detail code */
    VCS_PACKAGE_ATTEST_ERR_DETAIL_TEXT,    /* non-printable or over bound */
    VCS_PACKAGE_ATTEST_ERR_DETAIL_REQUIRED, /* fail class with detail_code 0 */
    VCS_PACKAGE_ATTEST_ERR_DETAIL_FORBIDDEN, /* pass class carrying detail */
    VCS_PACKAGE_ATTEST_ERR_COMPILER_COUNT, /* 0 or > MAX compilers */
    VCS_PACKAGE_ATTEST_ERR_COMPILER_ID,    /* id charset/bound */
    VCS_PACKAGE_ATTEST_ERR_COMPILER_VERSION, /* version charset/bound */
    VCS_PACKAGE_ATTEST_ERR_COMPILER_OUTCOME, /* unknown compiler outcome */
    VCS_PACKAGE_ATTEST_ERR_COMPILER_ORDER, /* unsorted or duplicate entry */
    VCS_PACKAGE_ATTEST_ERR_SANITIZER_COUNT, /* > MAX sanitizers */
    VCS_PACKAGE_ATTEST_ERR_SANITIZER_NAME, /* name charset/bound */
    VCS_PACKAGE_ATTEST_ERR_SANITIZER_OUTCOME, /* unknown sanitizer outcome */
    VCS_PACKAGE_ATTEST_ERR_SANITIZER_ORDER, /* unsorted or duplicate entry */
    VCS_PACKAGE_ATTEST_ERR_SANITIZER_FINDINGS, /* findings in a non-
                                                  sanitizer-fail class, or
                                                  sanitizer-fail without one */
    VCS_PACKAGE_ATTEST_ERR_TEST_FLAG,      /* test_ran byte not 0/1 */
    VCS_PACKAGE_ATTEST_ERR_TEST_EXIT,      /* exit code nonzero when
                                              test_ran=0 (non-canonical) */
    VCS_PACKAGE_ATTEST_ERR_TEST_CLASS,     /* test_ran inconsistent with
                                              the result class */
    VCS_PACKAGE_ATTEST_ERR_OUTCOME_CLASS,  /* a compiler failed but the
                                              class is a PASS class */
    VCS_PACKAGE_ATTEST_ERR_ISOLATION,      /* unknown isolation level */
    VCS_PACKAGE_ATTEST_ERR_PUBKEY,         /* not a compressed curve point */
    VCS_PACKAGE_ATTEST_ERR_SIG_LOW_S,      /* high-S (malleated) signature */
    VCS_PACKAGE_ATTEST_ERR_SIG_VERIFY,     /* ECDSA verification failed */
};

struct vcs_package_attest_compiler {
    char id[VCS_PACKAGE_ATTEST_COMPILER_ID_MAX + 1u];      /* NUL-terminated */
    char version[VCS_PACKAGE_ATTEST_COMPILER_VERSION_MAX + 1u];
    uint8_t outcome; /* enum vcs_package_attest_outcome */
};

struct vcs_package_attest_sanitizer {
    char name[VCS_PACKAGE_ATTEST_SANITIZER_NAME_MAX + 1u]; /* NUL-terminated */
    uint8_t outcome; /* enum vcs_package_attest_outcome */
};

/* Value type: fixed-size buffers, no heap, no init/free needed. Zeroing the
 * whole struct is a defined (invalid) state — validate() rejects it. */
struct vcs_package_attest {
    uint16_t schema_version; /* must be VCS_PACKAGE_ATTEST_VERSION */
    uint8_t package_root[32];
    uint8_t release_id[32];
    uint8_t recipe_root[32];
    uint8_t result_class; /* enum vcs_package_attest_result */
    uint8_t detail_code;  /* enum vcs_package_attest_detail */
    char detail[VCS_PACKAGE_ATTEST_DETAIL_MAX + 1u]; /* NUL-terminated */
    struct vcs_package_attest_compiler
        compilers[VCS_PACKAGE_ATTEST_MAX_COMPILERS];
    size_t compiler_count;
    struct vcs_package_attest_sanitizer
        sanitizers[VCS_PACKAGE_ATTEST_MAX_SANITIZERS];
    size_t sanitizer_count;
    bool test_ran;
    uint32_t test_exit_code;
    uint8_t isolation; /* enum vcs_package_attest_isolation */
    uint8_t verifier_pubkey[VCS_PACKAGE_ATTEST_PUBKEY_BYTES];
    uint8_t signature[VCS_PACKAGE_ATTEST_SIGNATURE_BYTES];
};

/* Stable strings (for logs/JSON/tests); never NULL. result_string returns
 * "build-pass"/"build-fail"/"test-pass"/"test-fail"/"sanitizer-fail" or
 * "unknown"; detail_string returns "none"/"compile-error"/... ; outcome
 * returns "pass"/"fail"/"unavailable" (compilers) — sanitizers display the
 * same bytes via outcome_string with clean/findings aliases provided by
 * sanitizer_outcome_string; isolation_string returns "full"/"degraded". */
const char *vcs_package_attest_error_string(
    enum vcs_package_attest_error error);
const char *vcs_package_attest_result_string(uint8_t result_class);
const char *vcs_package_attest_detail_string(uint8_t detail_code);
const char *vcs_package_attest_outcome_string(uint8_t outcome);
const char *vcs_package_attest_sanitizer_outcome_string(uint8_t outcome);
const char *vcs_package_attest_isolation_string(uint8_t isolation);

/* True when the class is a positive verdict (build-pass or test-pass). */
bool vcs_package_attest_result_is_pass(uint8_t result_class);

/* Validate every field against the v1 grammars and consistency rules
 * above. Does NOT look at the signature. Returns VCS_PACKAGE_ATTEST_OK or
 * the first failed rule. */
enum vcs_package_attest_error vcs_package_attest_validate(
    const struct vcs_package_attest *attest);

/* Compute the attestation id: SHA3-256 over the frozen domain (with its
 * NUL) and the canonical encoding of every field except the signature.
 * Fields are validated first; an invalid attestation has no id. */
enum vcs_package_attest_error vcs_package_attest_id(
    const struct vcs_package_attest *attest,
    uint8_t out[VCS_PACKAGE_ATTEST_ID_BYTES]);

/* Canonically serialize a validated attestation (signature included).
 * Allocates *out; caller frees. On failure *out is NULL and *out_len 0. */
enum vcs_package_attest_error vcs_package_attest_serialize(
    const struct vcs_package_attest *attest, uint8_t **out, size_t *out_len);

/* Parse only the exact canonical wire form. *out is zeroed on entry and on
 * every rejection. Bad grammars, consistency violations, an off-curve
 * pubkey, truncation, oversize input, and any trailing byte are rejected
 * with the matching error. The signature is NOT verified here — call
 * vcs_package_attest_verify() after parsing. */
enum vcs_package_attest_error vcs_package_attest_parse(
    const uint8_t *wire, size_t wire_len, struct vcs_package_attest *out);

/* Full envelope check: validate fields, recompute the attestation id,
 * require the low-S canonical form, and verify the secp256k1 ECDSA
 * signature over the id against the embedded verifier pubkey. Every
 * rejection returns the distinct error naming the failed rule. This proves
 * authorship of the exact bytes only; whether the signer COUNTS (approved,
 * independent, quorum) is the policy layer's rule. */
enum vcs_package_attest_error vcs_package_attest_verify(
    const struct vcs_package_attest *attest);

/* The quorum matching predicate (codec half): two attestations MATCH when
 * package root, release id, recipe root, and result class are all equal —
 * the exact tuple package_verify_policy clusters on. */
bool vcs_package_attest_matches(const struct vcs_package_attest *a,
                                const struct vcs_package_attest *b);

#endif /* ZCL_VCS_PACKAGE_ATTEST_H */
