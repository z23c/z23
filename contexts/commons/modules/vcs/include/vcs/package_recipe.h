/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_recipe — the declarative C23 build recipe (slice 5). One recipe
 * declares EVERYTHING an external verifier needs to build and test a
 * package without ever running downloaded code: the public headers, the
 * sources, the test sources, the include directories, the preprocessor
 * defines, the allowed system libraries (v1: libc, libm, pthread ONLY),
 * the expected test exit code, and the time/memory bounds. The recipe is
 * DECLARATIVE ONLY — this layer parses, serializes, hashes, and validates
 * bytes; it has no filesystem, network, compiler, execution, install,
 * wallet, or node-state authority. Nothing in contexts/commons/modules/vcs ever invokes a
 * compiler: actual compilation and execution belong to the EXTERNAL
 * verifier (slice 6, zclassic23-package-verify), never to the node.
 *
 * The signed release envelope (contexts/commons/modules/vcs/package_release.*) commits the
 * recipe by its root: recipe_root is SHA3-256 over the domain
 * "zcl.zcode_recipe.v1" (hashed WITH its trailing 0x00 byte, the
 * package_manifest convention) followed by the canonical wire encoding
 * below. JSON is display-only and is never hashed.
 *
 * Canonical wire encoding (all integers little-endian, exactly one legal
 * encoding per recipe):
 *   [8  magic = "ZCLRCP\r\n"]
 *   [2  schema_version = 1]
 *   [2  public_header_count]  count x ([2 len][path bytes])
 *   [2  source_count]         count x ([2 len][path bytes])   (>= 1)
 *   [2  test_source_count]    count x ([2 len][path bytes])
 *   [2  include_dir_count]    count x ([2 len][dir bytes])
 *   [2  define_count]         count x ([2 len][define bytes])
 *   [2  library_count]        count x [1 library id]
 *   [1  expected_test_exit_code]
 *   [4  maximum_test_seconds]
 *   [8  maximum_memory_bytes]
 *
 * Canonical-order rule: every string list is in strictly ascending byte
 * order (so it is also duplicate-free) and the library ids are strictly
 * ascending. Unsorted or duplicate entries are not a legal encoding.
 * The grammar is CLOSED: unknown trailing bytes, an unknown version, an
 * unknown library id, and every bound overflow are rejections — there is
 * no field a future extension could smuggle through a v1 parser.
 *
 * Field grammars (frozen for v1):
 *   paths   — vcs_package_path_valid (the manifest grammar: package-
 *             relative, no absolute/traversal/dot segments/backslash/
 *             drive bytes). public_headers end in ".h"; sources and
 *             test_sources end in ".c". include_dirs carry the same
 *             segment grammar and no extension rule. Membership in the
 *             package manifest is a PUBLICATION rule (slice 3 layer),
 *             not a codec rule — see vcs_package_recipe_files_in_manifest.
 *   defines — NAME or NAME=VALUE: NAME is [A-Za-z_][A-Za-z0-9_]{0,31},
 *             VALUE is 0..31 of [A-Za-z0-9_+.,:-]; total <= 64.
 *   libraries — ids 1=libc, 2=libm, 3=pthread; the v1 allowlist. Any
 *             other id (libssl, libcurl, ...) is a rejection.
 *   scalars — expected_test_exit_code is 0..255; maximum_test_seconds is
 *             1..3600; maximum_memory_bytes is 1 MiB..16 GiB. */

#ifndef ZCL_VCS_PACKAGE_RECIPE_H
#define ZCL_VCS_PACKAGE_RECIPE_H

#include "vcs/package_manifest.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_PACKAGE_RECIPE_VERSION 1u
#define VCS_PACKAGE_RECIPE_ROOT_DOMAIN "zcl.zcode_recipe.v1"
#define VCS_PACKAGE_RECIPE_WIRE_MAGIC_BYTES 8u
#define VCS_PACKAGE_RECIPE_MAX_PATHS_PER_LIST 256u
#define VCS_PACKAGE_RECIPE_MAX_DEFINES 64u
#define VCS_PACKAGE_RECIPE_MAX_LIBRARIES 8u
#define VCS_PACKAGE_RECIPE_DEFINE_MAX 64u
#define VCS_PACKAGE_RECIPE_MAX_TEST_SECONDS 3600u
#define VCS_PACKAGE_RECIPE_MIN_MEMORY_BYTES (UINT64_C(1024) * 1024u)
#define VCS_PACKAGE_RECIPE_MAX_MEMORY_BYTES \
    (UINT64_C(16) * 1024u * 1024u * 1024u)
#define VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES (256u * 1024u)

/* The v1 system-library allowlist (wire ids, frozen). */
enum vcs_package_recipe_library {
    VCS_PACKAGE_RECIPE_LIB_LIBC = 1,
    VCS_PACKAGE_RECIPE_LIB_LIBM = 2,
    VCS_PACKAGE_RECIPE_LIB_PTHREAD = 3,
};

/* Every rejection names the failed rule. The enum order is frozen. */
enum vcs_package_recipe_error {
    VCS_PACKAGE_RECIPE_OK = 0,
    VCS_PACKAGE_RECIPE_ERR_NULL,           /* null argument */
    VCS_PACKAGE_RECIPE_ERR_ALLOC,          /* allocation failure */
    VCS_PACKAGE_RECIPE_ERR_SCHEMA_VERSION, /* schema_version != 1 */
    VCS_PACKAGE_RECIPE_ERR_WIRE_MAGIC,     /* bad magic */
    VCS_PACKAGE_RECIPE_ERR_WIRE_OVERSIZE,  /* exceeds MAX_WIRE_BYTES */
    VCS_PACKAGE_RECIPE_ERR_WIRE_TRUNCATED, /* a field runs past the end */
    VCS_PACKAGE_RECIPE_ERR_WIRE_TRAILING,  /* bytes after the last field */
    VCS_PACKAGE_RECIPE_ERR_LIST_ORDER,     /* unsorted or duplicate entry */
    VCS_PACKAGE_RECIPE_ERR_COUNT_BOUND,    /* too many entries in a list */
    VCS_PACKAGE_RECIPE_ERR_PATH,           /* path grammar/extension */
    VCS_PACKAGE_RECIPE_ERR_DEFINE,         /* define grammar */
    VCS_PACKAGE_RECIPE_ERR_LIBRARY,        /* id not on the v1 allowlist */
    VCS_PACKAGE_RECIPE_ERR_SOURCES_EMPTY,  /* sources[] must not be empty */
    VCS_PACKAGE_RECIPE_ERR_TEST_SECONDS,   /* outside 1..3600 */
    VCS_PACKAGE_RECIPE_ERR_MEMORY_BYTES,   /* outside 1 MiB..16 GiB */
};

/* One bounded, canonically-ordered string list. */
struct vcs_package_recipe_strings {
    char **items; /* heap, each NUL-terminated, strictly ascending */
    size_t count;
    size_t cap;
};

struct vcs_package_recipe {
    uint16_t schema_version; /* must be VCS_PACKAGE_RECIPE_VERSION */
    struct vcs_package_recipe_strings public_headers;
    struct vcs_package_recipe_strings sources;
    struct vcs_package_recipe_strings test_sources;
    struct vcs_package_recipe_strings include_dirs;
    struct vcs_package_recipe_strings defines;
    uint8_t libraries[VCS_PACKAGE_RECIPE_MAX_LIBRARIES]; /* ascending ids */
    size_t library_count;
    uint8_t expected_test_exit_code;
    uint32_t maximum_test_seconds;
    uint64_t maximum_memory_bytes;
};

void vcs_package_recipe_init(struct vcs_package_recipe *recipe);
void vcs_package_recipe_free(struct vcs_package_recipe *recipe);

const char *vcs_package_recipe_error_string(
    enum vcs_package_recipe_error error);

/* "libc" <-> VCS_PACKAGE_RECIPE_LIB_LIBC etc. library_id returns 0 for an
 * unknown name; library_name returns NULL for an unknown id. */
uint8_t vcs_package_recipe_library_id(const char *name);
const char *vcs_package_recipe_library_name(uint8_t id);

/* Builders: insert one entry in canonical order, copying the string. The
 * entry grammar and the list bound are enforced at insertion; a duplicate
 * is a LIST_ORDER rejection. False with *err_out set on any rejection. */
bool vcs_package_recipe_add_header(struct vcs_package_recipe *r,
                                   const char *path,
                                   enum vcs_package_recipe_error *err_out);
bool vcs_package_recipe_add_source(struct vcs_package_recipe *r,
                                   const char *path,
                                   enum vcs_package_recipe_error *err_out);
bool vcs_package_recipe_add_test_source(
    struct vcs_package_recipe *r, const char *path,
    enum vcs_package_recipe_error *err_out);
bool vcs_package_recipe_add_include_dir(
    struct vcs_package_recipe *r, const char *dir,
    enum vcs_package_recipe_error *err_out);
bool vcs_package_recipe_add_define(struct vcs_package_recipe *r,
                                   const char *define,
                                   enum vcs_package_recipe_error *err_out);
bool vcs_package_recipe_add_library(struct vcs_package_recipe *r,
                                    uint8_t library_id,
                                    enum vcs_package_recipe_error *err_out);

/* Plain scalar setter; the ranges are enforced by validate(). */
void vcs_package_recipe_set_test_limits(struct vcs_package_recipe *r,
                                        uint8_t expected_exit_code,
                                        uint32_t maximum_seconds,
                                        uint64_t maximum_memory_bytes);

/* Validate every field against the v1 grammars above. Returns
 * VCS_PACKAGE_RECIPE_OK or the first failed rule. */
enum vcs_package_recipe_error vcs_package_recipe_validate(
    const struct vcs_package_recipe *recipe);

/* Canonically serialize a validated recipe. Allocates *out; caller frees.
 * On failure *out is NULL and *out_len is zero. */
enum vcs_package_recipe_error vcs_package_recipe_serialize(
    const struct vcs_package_recipe *recipe, uint8_t **out, size_t *out_len);

/* Parse only the exact canonical wire form. *out is init'd on entry and
 * cleared on every rejection. Oversize input, truncation, unsorted or
 * duplicate entries, unknown library ids, bound overflows, and any
 * trailing byte are rejected with the matching error. */
enum vcs_package_recipe_error vcs_package_recipe_parse(
    const uint8_t *wire, size_t wire_len, struct vcs_package_recipe *out);

/* The recipe root: SHA3-256 over the frozen domain (with its NUL) and the
 * canonical encoding. Fields are validated first; an invalid recipe has no
 * root. This is the value the release envelope's recipe_root commits. */
enum vcs_package_recipe_error vcs_package_recipe_root(
    const struct vcs_package_recipe *recipe, uint8_t out[32]);

/* Publication cross-check (pure, no filesystem): every public header,
 * source, and test source must name a FILE in the package manifest, and
 * every include dir must be the directory prefix of at least one manifest
 * path. On a miss, false and detail_out names the offending list and path
 * (bounded). True when every reference resolves. */
bool vcs_package_recipe_files_in_manifest(
    const struct vcs_package_recipe *recipe,
    const struct vcs_package_manifest *manifest, char *detail_out,
    size_t detail_cap);

/* Development-workspace equivalent over the existing path-sorted ZVCS
 * manifest. It applies the same file/include-dir membership rules. */
struct vcs_manifest;
bool vcs_package_recipe_files_in_vcs_manifest(
    const struct vcs_package_recipe *recipe,
    const struct vcs_manifest *manifest, char *detail_out,
    size_t detail_cap);

#endif /* ZCL_VCS_PACKAGE_RECIPE_H */
