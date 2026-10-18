/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: publisher side of the signed plugin store. plugin_pack writes the
 * strict manifest NAME.plugin.json, the detached Ed25519 signature
 * NAME.plugin.sig and a copy of the executable that
 * plugin_store_install accepts; plugin_keygen creates the signing key file.
 * A key file is exactly the 32-byte Ed25519 seed (RFC 8032), the same form as
 * the onion vanity seed. POSIX creates it with mode 0600; Windows requires a protected
 * owner+SYSTEM-only ACL and an owner-private parent. docs/PLUGINS.md describes
 * publishing. Storage support does not grant plugin execution or confinement. */
#ifndef ZCL_PLUGIN_PACK_H
#define ZCL_PLUGIN_PACK_H

#include "plugin/plugin_store.h"

#include <stdbool.h>
#include <stddef.h>

enum {
    PLUGIN_KEY_FILE_BYTES = 32,
    PLUGIN_HEX_PUBLIC_KEY = 64
};

struct plugin_pack_request {
    const char *exe_path;
    const char *name;
    const char *version;
    const char *key_path;
    const char *out_dir;      /* created when missing; NULL means "." */
    unsigned capabilities;    /* bit i is plugin_capability_name(i) */
    int interface_version;    /* 1 resident daemon, 2 one-shot; 0 means 1 */
};

struct plugin_pack_result {
    char generation[PLUGIN_HEX_SHA3_512 + 1];
    char public_key[PLUGIN_HEX_PUBLIC_KEY + 1];
    char manifest_path[4096];
};

/* Adds the capability named by the len bytes at name to mask. False for a
 * name outside the vocabulary or one already present. */
bool plugin_capability_add(const char *name, size_t len, unsigned *mask);

/* Writes NAME, NAME.plugin.json and NAME.plugin.sig into the output
 * directory. The manifest lists capabilities in vocabulary order, so equal
 * inputs give byte-identical files. The executable is hashed while it is
 * copied, so the signed digest is that of the stored bytes. */
enum plugin_status plugin_pack(const struct plugin_pack_request *request,
                               struct plugin_pack_result *result);

/* Exclusively creates a host-CSPRNG key (mode 0600 on POSIX; protected
 * owner+SYSTEM-only ACL beneath a validated private parent on Windows) and
 * returns the public key as 64 hex characters, the line for trusted_keys. An
 * existing path is refused with PLUGIN_ERR_KEY_EXISTS; the secret is never
 * returned. */
enum plugin_status plugin_keygen(const char *key_path,
                                 char public_key[PLUGIN_HEX_PUBLIC_KEY + 1]);

#endif
