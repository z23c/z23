/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: share a personal package copy by one file — the .z23share writer,
 * zcode.package.bundle.verify and the owner-only zcode.package.bundle.receive,
 * plus the receive trust record. Layout and record: native_zcode_package_bundle.h. */

#include "command/native_zcode_package_bundle.h"

#include "base/hex.h"
#include "util/file_io.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ZPB_PATH_MAX 4400
#define ZPB_RECORD_MAX 1024u

/* ── receive trust record ───────────────────────────────────────────── */

static bool zpb_record_path(const char *datadir, const uint8_t copy_root[32],
                            const uint8_t release_id[32], char *out,
                            size_t cap)
{
    char copy_hex[65], release_hex[65];
    zcl_hex_encode(copy_root, 32, copy_hex);
    zcl_hex_encode(release_id, 32, release_hex);
    int n = snprintf(out, cap, "%s/%s/%s.%s.trust", datadir,
                     ZCL_PACKAGE_RECEIVE_TRUST_DIR, copy_hex, release_hex);
    return n > 0 && (size_t)n < cap;
}

/* The one canonical text of a record; the reader re-renders and compares. */
static bool zpb_record_render(const struct zcl_package_receive_trust *t,
                              char *out, size_t cap)
{
    char copy[65], release[65], publisher[67], package[65], parent[65];
    zcl_hex_encode(t->copy_root, 32, copy);
    zcl_hex_encode(t->release_id, 32, release);
    zcl_hex_encode(t->publisher, 33, publisher);
    zcl_hex_encode(t->package_root, 32, package);
    if (t->has_parent)
        zcl_hex_encode(t->parent_release, 32, parent);
    else
        (void)snprintf(parent, sizeof(parent), "none");
    int n = snprintf(out, cap,
                     "%s\ncopy_root %s\nrelease_id %s\npublisher %s\n"
                     "package_root %s\nparent_release_root %s\n"
                     "confirmed owner\n",
                     ZCL_PACKAGE_RECEIVE_TRUST_SCHEMA, copy, release,
                     publisher, package, parent);
    return n > 0 && (size_t)n < cap;
}

/* Field values of a record, decoded; the caller re-renders to prove shape. */
static bool zpb_record_parse(const char *text,
                             struct zcl_package_receive_trust *t)
{
    char copy[65], release[65], publisher[67], package[65], parent[65];
    int n = sscanf(text,
                   ZCL_PACKAGE_RECEIVE_TRUST_SCHEMA
                   " copy_root %64s release_id %64s publisher %66s"
                   " package_root %64s parent_release_root %64s",
                   copy, release, publisher, package, parent);
    memset(t, 0, sizeof(*t));
    t->has_parent = n == 5 && strcmp(parent, "none") != 0;
    return n == 5 && zcl_hex_decode_lower(copy, t->copy_root, 32) &&
           zcl_hex_decode_lower(release, t->release_id, 32) &&
           zcl_hex_decode_lower(publisher, t->publisher, 33) &&
           zcl_hex_decode_lower(package, t->package_root, 32) &&
           (!t->has_parent ||
            zcl_hex_decode_lower(parent, t->parent_release, 32));
}

bool zcl_package_receive_trust_read(const char *datadir,
                                    const uint8_t copy_root[32],
                                    const uint8_t release_id[32],
                                    struct zcl_package_receive_trust *out)
{
    char path[ZPB_PATH_MAX], canonical[ZPB_RECORD_MAX];
    char *text = NULL;
    size_t len = 0;
    if (!datadir || !copy_root || !release_id || !out ||
        !zpb_record_path(datadir, copy_root, release_id, path, sizeof(path)) ||
        !zcl_read_whole_file_text(path, ZPB_RECORD_MAX, &text, &len,
                                  "zcode.package.receive_trust"))
        return false;
    bool ok = zpb_record_parse(text, out) &&
              zpb_record_render(out, canonical, sizeof(canonical)) &&
              strcmp(canonical, text) == 0 &&
              memcmp(out->copy_root, copy_root, 32) == 0 &&
              memcmp(out->release_id, release_id, 32) == 0;
    free(text);
    return ok;
}
