/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: signed plugin store under ~/.z23/plugins. A plugin executable is
 * installed only when its manifest is strictly formed, its detached Ed25519
 * signature verifies against a locally listed publisher key, and the executable
 * matches the manifest SHA3-512. Generations are content addressed;
 * "current" and "last-good" are replaced atomically: POSIX symbolic links,
 * or Windows validated private files containing exactly "generations/",
 * 128 lowercase hex characters and LF (141 bytes, no NUL or trailing bytes).
 * This storage contract grants no execution or confinement authority.
 * docs/dev/PLUGINS.md is the operator-facing description. */
#ifndef ZCL_PLUGIN_STORE_H
#define ZCL_PLUGIN_STORE_H

#include <stddef.h>
#include <stdint.h>

enum {
    PLUGIN_NAME_MAX = 32,
    PLUGIN_VERSION_MAX = 64,
    PLUGIN_HEX_SHA3_512 = 128
};

enum plugin_status {
    PLUGIN_OK = 0,
    PLUGIN_ERR_ARGUMENT,
    PLUGIN_ERR_NO_KEYS,
    PLUGIN_ERR_KEYS_MALFORMED,
    PLUGIN_ERR_MANIFEST_MISSING,
    PLUGIN_ERR_MANIFEST_INVALID,
    PLUGIN_ERR_MANIFEST_DUPLICATE_KEY,
    PLUGIN_ERR_MANIFEST_UNKNOWN_KEY,
    PLUGIN_ERR_SIG_MISSING,
    PLUGIN_ERR_SIG_INVALID,
    PLUGIN_ERR_SIG_ALG,
    PLUGIN_ERR_KEY_UNKNOWN,
    PLUGIN_ERR_SIG_BAD,
    PLUGIN_ERR_EXE_MISSING,
    PLUGIN_ERR_EXE_HASH,
    PLUGIN_ERR_NOT_INSTALLED,
    PLUGIN_ERR_NO_GENERATION,
    PLUGIN_ERR_NO_LAST_GOOD,
    PLUGIN_ERR_IO,
    PLUGIN_ERR_KEYS_INSECURE,
    PLUGIN_ERR_KEY_MISSING,
    PLUGIN_ERR_KEY_INSECURE,
    PLUGIN_ERR_KEY_MALFORMED,
    PLUGIN_ERR_KEY_EXISTS,
    PLUGIN_ERR_INTERFACE /* the command does not run this interface version */
};

/* Stable refusal code, for example "PLUGIN_KEY_UNKNOWN". */
const char *plugin_status_code(enum plugin_status status);

/* The operator action that resolves the refusal. */
const char *plugin_status_next_action(enum plugin_status status);

struct plugin_manifest {
    char name[PLUGIN_NAME_MAX + 1];
    char version[PLUGIN_VERSION_MAX + 1];
    int64_t interface_version;
    char exe_sha3[PLUGIN_HEX_SHA3_512 + 1];
    char generation[PLUGIN_HEX_SHA3_512 + 1]; /* signed manifest digest, set by plugin_verify_manifest */
    unsigned capabilities; /* bit i is the i-th entry of plugin_capability_name */
};

/* Fixed capability vocabulary; index is the bit position. NULL past the end. */
const char *plugin_capability_name(unsigned index);

/* Strict parse of NAME.plugin.json bytes. Unknown keys, duplicate keys,
 * malformed values and capabilities outside the vocabulary are refused. */
enum plugin_status plugin_manifest_parse(const char *bytes, size_t len,
                                         struct plugin_manifest *out);

/* Verify manifest bytes against the detached signature bytes and the publisher key
 * file at keys_path. Succeeds only for a well-formed manifest signed by a
 * listed key. On success fills out. */
enum plugin_status plugin_verify_manifest(const char *manifest, size_t manifest_len,
                                          const char *sig, size_t sig_len,
                                          const char *keys_path,
                                          struct plugin_manifest *out);

/* SHA3-512 of a file as 128 lowercase hex characters plus terminator. */
enum plugin_status plugin_hash_file(const char *path,
                                    char hex[PLUGIN_HEX_SHA3_512 + 1]);

/* Install the plugin described by manifest_path (NAME.plugin.json). The
 * signature is NAME.plugin.sig and the executable is NAME, both in the same
 * directory. root is the plugin store, normally ~/.z23/plugins. Installing
 * does not change the current pointer. A generation is named by the signed
 * manifest digest (out->generation), so the same executable under different
 * capabilities is a distinct generation. already_present is set when that
 * exact manifest and executable were stored earlier. */
enum plugin_status plugin_store_install(const char *root,
                                        const char *manifest_path,
                                        struct plugin_manifest *out,
                                        int *already_present);

/* Appends the 64 lowercase hex character public key to root/publisher_keys,
 * creating the store root and its parent at mode 0700 and a new publisher key file at
 * mode 0600. Existing directories or publisher key file that are not owner-only are
 * refused with PLUGIN_ERR_KEYS_INSECURE before anything is written. A key
 * already listed sets already_listed and writes nothing. */
enum plugin_status plugin_store_add_key(const char *root, const char *key,
                                      int *already_listed);

/* Make generation (128 hex characters) the current one, recording the
 * previous current generation as last-good. The generation is verified again
 * first. */
enum plugin_status plugin_store_switch(const char *root, const char *name,
                                       const char *generation);

/* Resolve the current generation of name for a one-shot call: verify its
 * signature, publisher key and executable SHA3-512 in full, then return the signed
 * manifest and the absolute path of the executable. Refuses PLUGIN_ERR_NO_GENERATION
 * when nothing is current. */
enum plugin_status plugin_store_current(const char *root, const char *name,
                                        struct plugin_manifest *out,
                                        char *exe, size_t exe_cap);

/* Make the last-good generation current. restored receives its id. */
enum plugin_status plugin_store_rollback(const char *root, const char *name,
                                         char restored[PLUGIN_HEX_SHA3_512 + 1]);

/* What reading one part of a plugin's stored state found. Absent is not the
 * same as unreadable: only PLUGIN_SLOT_MISSING means the part is not there.
 * PLUGIN_SLOT_UNREADABLE is a permission or I/O failure, so the part may
 * exist and nothing may be inferred from its empty value. PLUGIN_SLOT_CORRUPT
 * is present but not what the store writes (an invalid POSIX symbolic link,
 * a malformed Windows generation pointer file, or a generations entry that
 * is not a directory). */
enum plugin_slot_state {
    PLUGIN_SLOT_OK = 0,
    PLUGIN_SLOT_MISSING,
    PLUGIN_SLOT_UNREADABLE,
    PLUGIN_SLOT_CORRUPT
};

/* "ok", "missing", "unreadable" or "corrupt". */
const char *plugin_slot_state_name(enum plugin_slot_state state);

struct plugin_info {
    char name[PLUGIN_NAME_MAX + 1];
    char current[PLUGIN_HEX_SHA3_512 + 1];   /* empty when unset */
    char last_good[PLUGIN_HEX_SHA3_512 + 1]; /* empty when unset */
    char (*generations)[PLUGIN_HEX_SHA3_512 + 1];
    size_t generation_count;
    /* How current, last-good and the generations directory were read. An
     * empty id with PLUGIN_SLOT_OK cannot happen; an empty id or a zero count
     * is a fact only when the matching state is OK or MISSING. */
    enum plugin_slot_state current_state;
    enum plugin_slot_state last_good_state;
    enum plugin_slot_state generations_state;
};

/* List installed plugins, sorted by name, generations sorted by id. */
enum plugin_status plugin_store_list(const char *root,
                                     struct plugin_info **out, size_t *count);
void plugin_store_list_free(struct plugin_info *infos, size_t count);

#ifdef ZCL_TESTING
/* Test seam: after `after` successful entries, a directory read whose path
 * ends in suffix fails with EIO. NULL clears it. */
void plugin_store_test_fail_readdir(const char *suffix, unsigned after);
#endif

#endif
