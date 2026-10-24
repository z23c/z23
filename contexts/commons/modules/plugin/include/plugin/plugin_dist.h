/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: peer-to-peer distribution of signed plugin generations over the
 *          existing package store and swarm. No second store or cache.
 *
 * PUBLISH puts one installed or packed generation (NAME, NAME.plugin.json,
 * NAME.plugin.sig, plus a LICENSE) into the content.v2 package store as a
 * package root and files the signed release envelope that lets a hosting node
 * announce and serve it. FETCH starts after the swarm has delivered a root to
 * the receiver's store: it re-derives everything the swarm and the publisher
 * claim and refuses, by name, before the existing install path stores the
 * bytes as a NEW generation. It never switches and never runs anything.
 *
 * Refusals, in the order they are checked:
 *   NOT_FETCHED       the root is not in the local store at all
 *   ROOT_MISMATCH     the root the transfer delivered, or that the stored
 *                     manifest hashes to, is not the root that was requested
 *   TRUNCATED         the root is tracked but its bytes are not all present
 *   SHAPE             the package is not exactly LICENSE, NAME and its
 *                     manifest and signature
 *   PUBLISHER_UNPINNED the signing key is not in the receiver's
 *                     publisher_keys (no trust on first use)
 *   IMAGE_HASH        the image does not match the signed manifest sha3_512
 *   DOWNGRADE         the version is lower than (or cannot be compared with)
 *                     the installed current generation, without the owner
 *                     flag */
#ifndef ZCL_PLUGIN_DIST_H
#define ZCL_PLUGIN_DIST_H

#include "plugin/plugin_store.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct vcs_package_store;

enum plugin_dist_status {
    PLUGIN_DIST_OK = 0,
    PLUGIN_DIST_ERR_ARGUMENT,
    PLUGIN_DIST_ERR_SOURCE,       /* generation unreadable or inconsistent */
    PLUGIN_DIST_ERR_LICENSE,      /* license text does not match the SPDX id */
    PLUGIN_DIST_ERR_RELEASE,      /* release key, sequence or acceptance */
    PLUGIN_DIST_ERR_STORE,        /* package store refused the bytes */
    PLUGIN_DIST_ERR_NOT_FETCHED,
    PLUGIN_DIST_ERR_ROOT_MISMATCH,
    PLUGIN_DIST_ERR_TRUNCATED,
    PLUGIN_DIST_ERR_SHAPE,
    PLUGIN_DIST_ERR_PUBLISHER_UNPINNED,
    PLUGIN_DIST_ERR_IMAGE_HASH,
    PLUGIN_DIST_ERR_DOWNGRADE,
    PLUGIN_DIST_ERR_PLUGIN,       /* the plugin store refused; see plugin_status */
    PLUGIN_DIST_ERR_IO,
    PLUGIN_DIST_ERR_TOO_LARGE     /* image over the 48 MiB plugin image cap */
};

const char *plugin_dist_status_code(enum plugin_dist_status status);
const char *plugin_dist_status_next_action(enum plugin_dist_status status);

/* True for a plain dotted-decimal version of one to four components; false
 * for anything else (a prerelease or build tail is not comparable). */
bool plugin_dist_version_parse(const char *version, uint64_t out[4]);
/* -1, 0, 1; sets *comparable false when either side does not parse. */
int plugin_dist_version_compare(const char *a, const char *b, bool *comparable);

struct plugin_dist_publish_request {
    const char *plugins_dir;   /* ~/.z23/plugins; used when src_dir is NULL */
    const char *name;
    const char *generation;    /* 128 hex, or NULL for the current one */
    const char *src_dir;       /* packed output directory, instead of the store */
    const char *license_file;  /* LICENSE text shipped inside the package */
    const char *spdx;          /* SPDX id the license must match; NULL = MIT */
    const char *release_key;   /* 32-byte secp256k1 package signing key file */
    uint64_t sequence;         /* publisher sequence; 0 means 1 */
};

struct plugin_dist_published {
    uint8_t root[32];
    char root_hex[65];
    char name[PLUGIN_NAME_MAX + 1];
    char version[PLUGIN_VERSION_MAX + 1];
    char generation[PLUGIN_HEX_SHA3_512 + 1]; /* signed-manifest SHA3-512 */
    char exe_sha3[PLUGIN_HEX_SHA3_512 + 1];
    uint64_t bytes;
    uint32_t files;
    char detail[192];          /* why a refusal happened */
};

enum plugin_dist_status plugin_dist_publish(
    struct vcs_package_store *store,
    const struct plugin_dist_publish_request *request,
    struct plugin_dist_published *out);

/* Publish in three steps so a resident node can commit what a CLI signed.
 * prepare hashes the plugin files and computes the package root; it needs no
 * store. sign_release loads the key file, signs the prepared root and returns
 * the serialized release (caller frees); the key bytes never leave it. commit
 * writes the manifest, the chunks, the release and the pin into a GIVEN store,
 * and refuses before any write when the release names another root or
 * another plugin than the prepared one. plugin_dist_publish is the three in
 * order. */
struct plugin_dist_prepared;

enum plugin_dist_status plugin_dist_prepare(
    const struct plugin_dist_publish_request *request,
    struct plugin_dist_prepared **prepared_out,
    struct plugin_dist_published *out);
void plugin_dist_prepared_free(struct plugin_dist_prepared *prepared);

enum plugin_dist_status plugin_dist_sign_release(
    const struct plugin_dist_prepared *prepared,
    const struct plugin_dist_publish_request *request,
    uint8_t **release_wire_out, size_t *release_len_out,
    struct plugin_dist_published *out);

enum plugin_dist_status plugin_dist_commit(
    struct vcs_package_store *store, const struct plugin_dist_prepared *prepared,
    const uint8_t *release_wire, size_t release_len,
    struct plugin_dist_published *out);

struct plugin_dist_receive_request {
    struct vcs_package_store *store;
    uint8_t requested_root[32];
    /* The root the transfer says it delivered, or NULL to rely on the
     * stored manifest alone. A value that differs is ROOT_MISMATCH. */
    const uint8_t *delivered_root;
    const char *name;          /* expected plugin name */
    const char *plugins_dir;   /* receiver plugin store, ~/.z23/plugins */
    const char *scratch_dir;   /* existing private directory for the checkout */
    bool allow_downgrade;      /* explicit owner flag */
};

struct plugin_dist_received {
    char name[PLUGIN_NAME_MAX + 1];
    char version[PLUGIN_VERSION_MAX + 1];
    char generation[PLUGIN_HEX_SHA3_512 + 1];
    char current_version[PLUGIN_VERSION_MAX + 1]; /* empty: none installed */
    bool already_present;
    bool downgrade_allowed;    /* the owner flag was needed and used */
    enum plugin_status plugin; /* meaningful with PLUGIN_DIST_ERR_PLUGIN */
    char detail[192];
};

/* Verifies the delivered package and, only if every check passes, stores it
 * as a new generation. The current and last-good links are never changed. */
enum plugin_dist_status plugin_dist_receive(
    const struct plugin_dist_receive_request *request,
    struct plugin_dist_received *out);

#ifdef ZCL_TESTING
/* Lets a test play a publisher that does not check its own image. */
void plugin_dist_test_skip_source_check(bool skip);
/* Lowers the image cap (0 restores the default) so a small fixture can be "too large". */
void plugin_dist_test_set_image_max(uint64_t bytes);
#endif

#endif
