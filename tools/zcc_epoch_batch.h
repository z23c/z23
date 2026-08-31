/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 *
 * Public wire views and refusal results for epoch-batch manifest preflight. */

#ifndef ZCC_EPOCH_BATCH_H
#define ZCC_EPOCH_BATCH_H

#include <stddef.h>
#include <stdint.h>

#define ZCC_EPOCH_BATCH_VERSION UINT32_C(1)
/* Admission limits are independent: the wire is bounded at 64 MiB, a batch
 * at 32,768 translation units, and all common plus per-job arguments at
 * 1,048,576 slices. On a 64-bit host the maximum decoder-owned job, argument,
 * and destination arrays are approximately 2 MiB, 16 MiB, and 512 KiB.
 * Limits are checked before their corresponding allocation. */
#define ZCC_EPOCH_BATCH_MAX_WIRE \
    (UINT32_C(64) * UINT32_C(1024) * UINT32_C(1024))
#define ZCC_EPOCH_BATCH_MAX_JOBS UINT32_C(32768)
#define ZCC_EPOCH_BATCH_MAX_ARGS UINT32_C(1048576)
#define ZCC_EPOCH_BATCH_MAX_FIELD UINT32_C(1048576)
#define ZCC_EPOCH_BATCH_MAX_PATH UINT32_C(131072)
#define ZCC_EPOCH_BATCH_MAX_PROFILE UINT32_C(128)
#define ZCC_EPOCH_BATCH_ROOT_BYTES UINT32_C(32)

enum zcc_epoch_batch_mode {
    ZCC_EPOCH_BATCH_DEP = 1,
    ZCC_EPOCH_BATCH_COVERAGE = 2
};

enum zcc_epoch_batch_result {
    ZCC_EPOCH_BATCH_OK = 0,
    ZCC_EPOCH_BATCH_ARGUMENT,
    ZCC_EPOCH_BATCH_TRUNCATED,
    ZCC_EPOCH_BATCH_FORMAT,
    ZCC_EPOCH_BATCH_UNSUPPORTED_VERSION,
    ZCC_EPOCH_BATCH_LIMIT,
    ZCC_EPOCH_BATCH_ALLOCATION,
    ZCC_EPOCH_BATCH_JOB_COUNT,
    ZCC_EPOCH_BATCH_AUTHORITY,
    ZCC_EPOCH_BATCH_ARGV,
    ZCC_EPOCH_BATCH_PATH,
    ZCC_EPOCH_BATCH_DESTINATION_COLLISION,
    ZCC_EPOCH_BATCH_TRAILING_BYTES
};

struct zcc_epoch_batch_bytes {
    const uint8_t *data;
    uint32_t length;
};

struct zcc_epoch_batch_job {
    struct zcc_epoch_batch_bytes source;
    struct zcc_epoch_batch_bytes output;
    struct zcc_epoch_batch_bytes depfile;
    enum zcc_epoch_batch_mode mode;
    uint32_t argv_offset;
    uint32_t argv_count;
};

struct zcc_epoch_batch_manifest {
    struct zcc_epoch_batch_bytes profile;
    struct zcc_epoch_batch_bytes source_id;
    uint32_t source_complete;
    struct zcc_epoch_batch_bytes mutation;
    struct zcc_epoch_batch_bytes epoch;
    struct zcc_epoch_batch_bytes compiler_id;
    struct zcc_epoch_batch_bytes environment_root;
    struct zcc_epoch_batch_bytes build_root;
    struct zcc_epoch_batch_bytes session;
    struct zcc_epoch_batch_bytes *common_argv;
    uint32_t common_argc;
    struct zcc_epoch_batch_job *jobs;
    uint32_t job_count;
    struct zcc_epoch_batch_bytes *job_argv;
    uint32_t job_argc;
};

struct zcc_epoch_batch_error {
    enum zcc_epoch_batch_result code;
    size_t offset;
    uint32_t job_index;
};

struct zcc_epoch_batch_wire {
    uint8_t *data;
    size_t length;
};

/* Wire schema, in order: a length-prefixed magic field, version, profile,
 * source id, source-complete, mutation, epoch, compiler id, environment root,
 * build-system root, session path, common argc and arguments, then job count
 * and jobs. Every scalar and every byte-field length prefix is one unsigned
 * 32-bit little-endian integer. Content identities are raw 32-byte roots;
 * source-complete must be one. common_argv[0] is the compiler command, with
 * compiler-wide arguments following it. Each job contains source, output,
 * depfile, mode, suffix argc, and suffix arguments. Mode values are the exact
 * enum zcc_epoch_batch_mode wire values above. Each output ends in `.o`; its
 * depfile is the same path with that suffix replaced by `.d`.
 *
 * Source paths are canonical relative to the admitted source root. Session,
 * output, and depfile paths are canonical relative to the admitted object-set
 * root. Rejecting absolute paths, native separators, colons, and parent
 * traversal preserves lexical containment when those paths are joined. The
 * Output and depfile uniqueness uses a conservative ASCII case-folded key so
 * case aliases refuse even on a case-sensitive host. The executor remains
 * responsible for native Unicode/path normalization, refusing symlinks or
 * reparse points during filesystem traversal, and rechecking session identity.
 *
 * `out` must be zero-initialized or previously released. A manifest holding
 * owned arrays returns ZCC_EPOCH_BATCH_ARGUMENT without changing `out`.
 * Returned byte slices borrow `wire`; the three arrays are owned by `out` and
 * released by zcc_epoch_batch_manifest_free(). The decoder writes nothing
 * except `out` and `error` and performs structural preflight before success.
 * Separate path-valued compiler-option operands are intentionally refused;
 * they remain unavailable until an executor admits their exact input closure. */
[[nodiscard]] enum zcc_epoch_batch_result zcc_epoch_batch_manifest_decode(
    const uint8_t *wire, size_t wire_size,
    struct zcc_epoch_batch_manifest *out,
    struct zcc_epoch_batch_error *error);

/* Encode one semantically complete manifest into the unique v1 wire form.
 * Every job must own one contiguous, ordered slice of job_argv: the first
 * offset is zero, each following offset equals the preceding slice end, and
 * the final end equals job_argc. `out` must be zero-initialized or previously
 * released. On refusal it remains unchanged. The returned allocation is
 * released by zcc_epoch_batch_wire_free(). Validation and encoding have no
 * filesystem or process effects. Encoder errors have offset zero because the
 * input is a semantic manifest rather than a wire position. */
[[nodiscard]] enum zcc_epoch_batch_result zcc_epoch_batch_manifest_encode(
    const struct zcc_epoch_batch_manifest *manifest,
    struct zcc_epoch_batch_wire *out,
    struct zcc_epoch_batch_error *error);

void zcc_epoch_batch_manifest_free(struct zcc_epoch_batch_manifest *manifest);

void zcc_epoch_batch_wire_free(struct zcc_epoch_batch_wire *wire);

[[nodiscard]] const char *zcc_epoch_batch_result_name(
    enum zcc_epoch_batch_result result);

#endif
