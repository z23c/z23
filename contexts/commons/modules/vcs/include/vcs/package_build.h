/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_build — the ZCODE reproducible BUILD RECEIPT. One receipt records
 * everything needed to say what was built, from what, with what, and what
 * came out: the package root, the recipe root, the dependency-lock root and
 * every locked dependency root, the compiler identity, the exact flag
 * string, the isolation level, the test verdict, and the SHA3-256 of every
 * emitted artifact.
 *
 * This layer is a PURE CODEC — parse, serialize, validate, hash. It never
 * compiles, executes, installs, or touches the filesystem. The isolated
 * build worker (build/bin/zclassic23-package-verify --emit=...) writes one
 * of these wires beside the artifacts it emitted; the PARENT process then
 * independently re-hashes every emitted file and compares it against the
 * receipt before anything is installed. A worker that lied about an output
 * hash therefore cannot get that output installed.
 *
 * Canonical wire encoding (all integers little-endian, exactly one legal
 * encoding per receipt):
 *   [8  magic = "ZCLBLD\r\n"]
 *   [2  schema_version = 1|2]
 *   [32 package_root][32 recipe_root][32 lock_root]
 *   [2  dep_count]        count x [32 dependency root]   (ascending)
 *   [2  id_len][compiler id bytes]
 *   [2  version_len][compiler version bytes]
 *   [2  flags_len][flags bytes]
 *   [32 toolchain_capsule_root]                  schema v2 only
 *   [1  result_class][1 isolation][1 test_ran][4 test_exit_code]
 *   [2  output_count]     count x ([2 path_len][path bytes][32 sha3]
 *                                  [8 bytes])            (ascending path)
 *
 * Schema v2 binds the toolchain capsule root (vcs/build_action.h —
 * compiler driver bytes, cc1 backend bytes, assembler identity, sysroot,
 * target probes, ABI files) into the receipt itself, so "same toolchain"
 * is a receipt property rather than a side-band comparison. A receipt
 * carries a capsule iff it is schema v2; v1 receipts remain parseable and
 * are never rewritten or relabeled. The receipt id domain is unchanged —
 * it names the receipt's purpose, and the schema version inside the wire
 * distinguishes the grammar.
 *
 * Canonical-order rules: dependency roots strictly ascending (so
 * duplicate-free), output paths strictly ascending by path bytes. The
 * grammar is CLOSED: unknown version, bad magic, truncation, any trailing
 * byte, an unsorted list, and every bound overflow are rejections.
 *
 * The receipt id is SHA3-256 over the frozen domain (hashed WITH its
 * trailing 0x00 byte, the package_manifest convention) followed by the
 * canonical wire. It names the receipt on disk. */

#ifndef ZCL_VCS_PACKAGE_BUILD_H
#define ZCL_VCS_PACKAGE_BUILD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_PACKAGE_BUILD_VERSION 2u
/* Oldest schema the parser still accepts; older evidence is never
 * rewritten, so v1 receipts on disk stay readable forever. */
#define VCS_PACKAGE_BUILD_VERSION_MIN 1u
#define VCS_PACKAGE_BUILD_RECEIPT_DOMAIN "zcl.zcode_build.v1"
#define VCS_PACKAGE_BUILD_WIRE_MAGIC_BYTES 8u
#define VCS_PACKAGE_BUILD_MAX_DEPS 64u
#define VCS_PACKAGE_BUILD_MAX_OUTPUTS 64u
#define VCS_PACKAGE_BUILD_ID_MAX 31u
#define VCS_PACKAGE_BUILD_VERSION_MAX 127u
#define VCS_PACKAGE_BUILD_FLAGS_MAX 255u
#define VCS_PACKAGE_BUILD_FLAGS_QUICK_V1 \
    "-std=c23 -O1 -fno-omit-frame-pointer -D_POSIX_C_SOURCE=200809L " \
    "-ffile-prefix-map=SOURCE=. -c"
#define VCS_PACKAGE_BUILD_FLAGS_STANDARD_V1 \
    "-std=c23 -O1 -fno-omit-frame-pointer -D_POSIX_C_SOURCE=200809L " \
    "-ffile-prefix-map=SOURCE=. -Wall -Wextra -Werror;asan,ubsan=clean;" \
    "sanitizer_pie=off;sanitizer_aslr=off"
#define VCS_PACKAGE_BUILD_PATH_MAX 255u
#define VCS_PACKAGE_BUILD_MAX_WIRE_BYTES (64u * 1024u)

/* Frozen wire ids. BUILD_PASS is a package that declares no tests; the
 * lifecycle refuses to install anything below TEST_PASS when tests exist. */
enum vcs_package_build_result {
    VCS_PACKAGE_BUILD_RESULT_BUILD_FAIL = 0,
    VCS_PACKAGE_BUILD_RESULT_TEST_FAIL = 1,
    VCS_PACKAGE_BUILD_RESULT_BUILD_PASS = 2,
    VCS_PACKAGE_BUILD_RESULT_TEST_PASS = 3,
};

/* Mirrors package_attest's isolation vocabulary: a build produced without
 * Landlock filesystem scoping is DEGRADED and says so. */
enum vcs_package_build_isolation {
    VCS_PACKAGE_BUILD_ISOLATION_FULL = 0,
    VCS_PACKAGE_BUILD_ISOLATION_DEGRADED = 1,
};

enum vcs_package_build_error {
    VCS_PACKAGE_BUILD_OK = 0,
    VCS_PACKAGE_BUILD_ERR_NULL,
    VCS_PACKAGE_BUILD_ERR_ALLOC,
    VCS_PACKAGE_BUILD_ERR_SCHEMA_VERSION,
    VCS_PACKAGE_BUILD_ERR_WIRE_MAGIC,
    VCS_PACKAGE_BUILD_ERR_WIRE_OVERSIZE,
    VCS_PACKAGE_BUILD_ERR_WIRE_TRUNCATED,
    VCS_PACKAGE_BUILD_ERR_WIRE_TRAILING,
    VCS_PACKAGE_BUILD_ERR_ROOT,        /* an all-zero package/recipe root */
    VCS_PACKAGE_BUILD_ERR_DEP_ORDER,   /* deps unsorted/duplicated/zero */
    VCS_PACKAGE_BUILD_ERR_DEP_COUNT,
    VCS_PACKAGE_BUILD_ERR_COMPILER,    /* empty/oversize id or version */
    VCS_PACKAGE_BUILD_ERR_FLAGS,       /* empty/oversize/non-printable flags */
    VCS_PACKAGE_BUILD_ERR_RESULT,      /* result class not on the wire list */
    VCS_PACKAGE_BUILD_ERR_ISOLATION,   /* isolation not on the wire list */
    VCS_PACKAGE_BUILD_ERR_TEST_STATE,  /* test_ran/exit-code inconsistency */
    VCS_PACKAGE_BUILD_ERR_OUTPUT_PATH, /* path grammar/bound */
    VCS_PACKAGE_BUILD_ERR_OUTPUT_ORDER,/* outputs unsorted or duplicated */
    VCS_PACKAGE_BUILD_ERR_OUTPUT_COUNT,
    VCS_PACKAGE_BUILD_ERR_OUTPUT_EMPTY,/* a passing build emitted nothing */
    VCS_PACKAGE_BUILD_ERR_CAPSULE,     /* v2: missing/inconsistent capsule */
};

const char *vcs_package_build_error_string(enum vcs_package_build_error error);
const char *vcs_package_build_result_string(enum vcs_package_build_result r);
const char *vcs_package_build_isolation_string(
    enum vcs_package_build_isolation i);

struct vcs_package_build_output {
    char path[VCS_PACKAGE_BUILD_PATH_MAX + 1u]; /* install-relative */
    uint8_t sha3[32];
    uint64_t bytes;
};

/* Value type: fixed buffers, no heap, no init/free. Zeroing it is a defined
 * (invalid) state — validate() rejects it. */
struct vcs_package_build_receipt {
    uint16_t schema_version;
    uint8_t package_root[32];
    uint8_t recipe_root[32];
    uint8_t lock_root[32];
    uint8_t dep_roots[VCS_PACKAGE_BUILD_MAX_DEPS][32];
    size_t dep_count;
    char compiler_id[VCS_PACKAGE_BUILD_ID_MAX + 1u];
    char compiler_version[VCS_PACKAGE_BUILD_VERSION_MAX + 1u];
    char flags[VCS_PACKAGE_BUILD_FLAGS_MAX + 1u];
    /* Schema v2: the toolchain capsule root this build ran under. Exactly
     * when has_toolchain_capsule is true, schema_version is 2 and the wire
     * carries the 32-byte root after the flags string. */
    bool has_toolchain_capsule;
    uint8_t toolchain_capsule_root[32];
    uint8_t result_class; /* enum vcs_package_build_result */
    uint8_t isolation;    /* enum vcs_package_build_isolation */
    bool test_ran;
    uint32_t test_exit_code;
    struct vcs_package_build_output outputs[VCS_PACKAGE_BUILD_MAX_OUTPUTS];
    size_t output_count;
};

void vcs_package_build_receipt_init(struct vcs_package_build_receipt *r);

/* Bind the toolchain capsule root (vcs/build_action.h) to the receipt:
 * copies the root, sets has_toolchain_capsule, and bumps the schema to v2.
 * A NULL or all-zero root is rejected (an all-zero root is the "no object"
 * sentinel, never a real commitment) and the receipt is left unchanged. */
enum vcs_package_build_error vcs_package_build_set_toolchain_capsule(
    struct vcs_package_build_receipt *r, const uint8_t capsule_root[32]);

/* Insert one dependency root in ascending order (duplicate = rejection). */
enum vcs_package_build_error vcs_package_build_add_dep(
    struct vcs_package_build_receipt *r, const uint8_t root[32]);

/* Insert one output in ascending path order (duplicate path = rejection).
 * The path is install-relative and carries the manifest path grammar. */
enum vcs_package_build_error vcs_package_build_add_output(
    struct vcs_package_build_receipt *r, const char *path,
    const uint8_t sha3[32], uint64_t bytes);

enum vcs_package_build_error vcs_package_build_validate(
    const struct vcs_package_build_receipt *r);
enum vcs_package_build_error vcs_package_build_serialize(
    const struct vcs_package_build_receipt *r, uint8_t **out, size_t *out_len);
enum vcs_package_build_error vcs_package_build_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_package_build_receipt *out);
enum vcs_package_build_error vcs_package_build_id(
    const struct vcs_package_build_receipt *r, uint8_t out[32]);

/* True when the receipt is a verdict the install lifecycle may act on: a
 * build that passed, and (when the recipe declared tests) tests that
 * passed. A BUILD_FAIL/TEST_FAIL receipt is still a durable, storable fact
 * — it just never installs. */
bool vcs_package_build_installable(const struct vcs_package_build_receipt *r);

#endif /* ZCL_VCS_PACKAGE_BUILD_H */
