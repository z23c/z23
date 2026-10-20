/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: signed plugin index entries and a local index directory, so what
 * plugins exist can be found without a central registry. An entry says that
 * one publisher key vouches for (name, version, interface, capabilities,
 * package root) at a time. It is a claim about where to look, never an
 * install: search lists and verifies entries, marks each publisher pinned or
 * unpinned against a local key list, and fetches, installs and runs nothing.
 * The index directory is a set of small content-named files, so the directory
 * itself can be carried as a package root. docs/dev/PLUGINS.md describes it.
 *
 * Entry file, canonical and byte-exact (one line, LF-terminated):
 *   {"schema":"z23.plugin.index.v1","name":..,"version":..,
 *    "interface_version":1|2,"capabilities":[..vocabulary order..],
 *    "root":"<64 hex>","publisher":"<64 hex>","timestamp":N,
 *    "signature":"<128 hex>"}
 * The signature is Ed25519 over SHA3-512("z23.plugin.index.v1" NUL body) where
 * body is the entry text up to and including the timestamp value. The parser
 * accepts an entry only if re-encoding it reproduces the input bytes. */
#ifndef ZCL_PLUGIN_INDEX_H
#define ZCL_PLUGIN_INDEX_H

#include "plugin/plugin_store.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    PLUGIN_INDEX_ENTRY_MAX = 2048,   /* bytes of one entry file */
    PLUGIN_INDEX_FILES_MAX = 4096,   /* entry files read from one directory */
    PLUGIN_INDEX_HEX_KEY = 64,
    PLUGIN_INDEX_FILE_MAX = 255
};

#define PLUGIN_INDEX_SUFFIX ".plugin-index.json"

enum plugin_index_status {
    PLUGIN_INDEX_OK = 0,
    PLUGIN_INDEX_ARGUMENT,
    PLUGIN_INDEX_MALFORMED,     /* not the canonical entry encoding */
    PLUGIN_INDEX_BAD_SIGNATURE, /* well formed, signature does not verify */
    PLUGIN_INDEX_ROLLBACK,      /* version lower than one already seen */
    PLUGIN_INDEX_EQUIVOCATION,  /* same version, different content */
    PLUGIN_INDEX_SOURCE,        /* manifest, signature or key refused; see cause */
    PLUGIN_INDEX_PINS,          /* the pin file is missing, insecure or malformed */
    PLUGIN_INDEX_TOO_MANY,
    PLUGIN_INDEX_IO
};

const char *plugin_index_status_code(enum plugin_index_status status);

struct plugin_index_entry {
    char name[PLUGIN_NAME_MAX + 1];
    char version[PLUGIN_VERSION_MAX + 1];
    int64_t interface_version;       /* 1 or 2 */
    unsigned capabilities;           /* bit i is plugin_capability_name(i) */
    char root[PLUGIN_INDEX_HEX_KEY + 1];      /* package root, 32 bytes hex */
    char publisher[PLUGIN_INDEX_HEX_KEY + 1]; /* Ed25519 public key hex */
    int64_t timestamp;               /* unix seconds, >= 0 */
    char digest[PLUGIN_HEX_SHA3_512 + 1]; /* SHA3-512 of the entry bytes */
};

/* Numeric-aware order of two version strings: digit runs compare as numbers,
 * everything else bytewise. Not full SemVer: a pre-release suffix sorts after
 * its release. Negative, zero or positive. */
int plugin_index_version_cmp(const char *a, const char *b);

/* Signs and encodes an entry. The caller fills name, version,
 * interface_version, capabilities, root and timestamp; publisher is derived
 * from the 32-byte seed. Writes the canonical bytes (NUL-terminated) and fills
 * digest. PLUGIN_INDEX_ARGUMENT for an invalid field or a short buffer. */
enum plugin_index_status plugin_index_encode(struct plugin_index_entry *entry,
                                             const uint8_t seed[32],
                                             char *out, size_t cap,
                                             size_t *len);

/* Total parser: any bytes give OK, MALFORMED or BAD_SIGNATURE and never read
 * past len. OK means canonical encoding and a verifying signature by the
 * entry's own publisher key. It says nothing about whether you trust it. */
enum plugin_index_status plugin_index_parse(const char *bytes, size_t len,
                                            struct plugin_index_entry *out);

/* Verifies the entry bytes, then writes them to dir under
 * <SHA3-512 of the bytes>.plugin-index.json. Refuses an entry whose version
 * is lower than one already in dir from the same publisher and name
 * (ROLLBACK) or equal with different content (EQUIVOCATION). The same bytes
 * again are accepted and write nothing (*already_present). Creates dir. */
enum plugin_index_status plugin_index_add(const char *dir, const char *bytes,
                                          size_t len,
                                          struct plugin_index_entry *out,
                                          bool *already_present);

struct plugin_index_publish {
    const char *dir;           /* index directory, created when missing */
    const char *root;          /* package root, 64 lowercase hex */
    const char *manifest_path; /* NAME.plugin.json; NAME.plugin.sig beside it */
    const char *key_path;      /* publisher signing key file (32-byte seed) */
    int64_t timestamp;         /* unix seconds */
};

/* Signs and adds an entry for a packed plugin. The manifest and its detached
 * signature must verify under the very key that signs the entry, so an index
 * entry never vouches for a plugin its own key did not sign. On SOURCE, cause
 * is the plugin_status that refused. */
enum plugin_index_status plugin_index_publish(
    const struct plugin_index_publish *request, struct plugin_index_entry *out,
    bool *already_present, enum plugin_status *cause);

struct plugin_index_row {
    struct plugin_index_entry entry;
    bool pinned; /* publisher key is listed in the pin file */
};

struct plugin_index_refusal {
    char file[PLUGIN_INDEX_FILE_MAX + 1];
    const char *code; /* plugin_index_status_code, static */
};

struct plugin_index_report {
    struct plugin_index_row *rows;
    size_t row_count;
    struct plugin_index_refusal *refusals;
    size_t refusal_count;
    size_t scanned;    /* entry files read */
    size_t duplicates; /* byte-identical copies folded away */
    size_t superseded; /* valid older entries folded under a newer version */
};

struct plugin_index_query {
    const char *name; /* exact plugin name, or NULL */
    unsigned capabilities; /* entry must declare all of these bits */
};

/* Reads every entry file in dir, verifies each, folds to the latest version
 * per (publisher, name), refuses rollbacks and equivocations, filters by the
 * query and marks each row pinned against the publisher key file at
 * pins_path (one 64-hex key per line, owner-only like publisher_keys; an
 * empty file pins nothing). Reads files only. Free with
 * plugin_index_report_free. */
enum plugin_index_status plugin_index_search(
    const char *dir, const char *pins_path,
    const struct plugin_index_query *query, struct plugin_index_report *report);

void plugin_index_report_free(struct plugin_index_report *report);

#ifdef ZCL_TESTING
/* Test seam: when armed, the directory read fails with EIO after `after`
 * successful entries. plugin_index_test_fail_readdir(false, 0) clears it. */
void plugin_index_test_fail_readdir(bool armed, unsigned after);
#endif

#endif
