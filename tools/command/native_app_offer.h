/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * native_app_offer — the public app catalog entry (zcl.app_offer.v1) that
 * `z23 app publish COPY` posts to board room `apps` and `z23 app get`
 * reads back. One entry names one saved, signed app version and where its
 * .z23share bytes can be fetched: the version root, the publisher's full
 * fingerprint, the bundle carrier root, the sha256 and size of the file,
 * and the publisher node's v3 onion.
 *
 * A post is untrusted data. The catalog keeps only posts whose board
 * signature verifies here (the id re-derived from the bytes, then the host
 * key's Ed25519 signature), in room `apps`, kind offer, whose text parses
 * STRICTLY: exactly the eight keys, 64-hex roots, a 66-hex publisher, a v3
 * onion and a size of 1 B to 5 MiB. Anything else is dropped. Nothing on
 * the board is a verdict: `app get` still checks the fetched bytes against
 * the entry, and app.receive-copy still asks the owner.
 *
 * The transport (board list, board post, bundle offer and fetch) runs
 * through one call seam so a registered test can stand in for the node. */

#ifndef ZCL_TOOLS_NATIVE_APP_OFFER_H
#define ZCL_TOOLS_NATIVE_APP_OFFER_H

#include "command/native_command.h"
#include "json/json.h"
#include "vcs/app_offer.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_APP_OFFER_ROOM "apps"
#define ZCL_APP_OFFER_KIND "offer"
#define ZCL_APP_OFFER_ROWS_MAX 256u
/* The board path every inner call names, and the node method a catalog
 * read uses directly (the leaf's reply budget would page it). */
#define ZCL_APP_OFFER_BOARD_LIST "fleet.board.list.raw"
#define ZCL_APP_OFFER_BOARD_SHOW "fleet.board.show"
#define ZCL_APP_OFFER_BOARD_POST "fleet.board.post"
#define ZCL_APP_OFFER_BUNDLE_OFFER "fleet.bundle.offer"
#define ZCL_APP_OFFER_BUNDLE_FETCH "fleet.bundle.fetch"
#define ZCL_APP_HOST_ENABLE "app.host.enable"

/* Read-only local onion publication status and its one installed P2P port. */
bool zcl_app_offer_local_endpoint(char host[static 63],
                                  char endpoint[static ZCL_APP_OFFER_ONION_MAX + 1u],
                                  bool *status_read);

/* One catalog row: a verified entry and the post that carried it. */
struct zcl_app_offer_row {
    struct zcl_app_offer offer;
    char post_id[65];
    char host[65];
    int64_t created_at;
};

/* A host-signed observation, not a proof of independent execution. */
struct zcl_app_rebuild {
    char publisher[67], release_root[65], package_root[65], version[65];
    char image[65], closure[65], environment[65], dependency[65], record[65];
    char target[96];
};

bool zcl_app_rebuild_format(const struct zcl_app_rebuild *observation,
                            char *out, size_t cap);
bool zcl_app_rebuild_count(const struct zcl_app_rebuild *local, size_t *count,
                           struct zcl_command_reply *why);

/* Every field well formed (the same rules parse applies). */
bool zcl_app_offer_valid(const struct zcl_app_offer *o);

/* The entry as the exact text a post carries; false when a field is
 * malformed or it does not fit `cap` (at most ZCL_APP_OFFER_TEXT_MAX). */
bool zcl_app_offer_format(const struct zcl_app_offer *o, char *out,
                          size_t cap);

/* Strict parse of a post's text; false (and `o` zeroed) for anything that
 * is not exactly one well-formed entry. */
bool zcl_app_offer_parse(const char *text, size_t len,
                         struct zcl_app_offer *o);

/* One post object as fleet.board.list renders it: true only when its
 * signature verifies here, it is a public kind=offer post in room `apps`
 * and its text is a well-formed entry. */
bool zcl_app_offer_from_post(const struct json_value *post,
                             struct zcl_app_offer_row *row);

/* Verified host-signed advertisements, with identical host offers coalesced,
 * newest first. False with `why` failed for malformed, saturated, unreadable
 * or capacity-limited results. A short response is not proof of a globally
 * complete board; the node may not have received every post. */
bool zcl_app_offer_catalog(struct zcl_app_offer_row *rows, size_t cap,
                           size_t *count, struct zcl_command_reply *why);

/* Read and verify one exact current signed offer without a catalog scan. */
bool zcl_app_offer_exact(const char *id, struct zcl_app_offer_row *row,
                         struct zcl_command_reply *why);

/* "12s", "5m", "3h" or "2d" since `created_at`. */
void zcl_app_offer_age(int64_t created_at, int64_t now, char *out,
                       size_t cap);

/* The transport seam. A call names one of the ZCL_APP_OFFER_* paths and
 * gets that leaf's reply in `out` (always initialized). The default runs
 * the registered leaf; ZCL_APP_OFFER_BOARD_LIST asks the node's board for
 * {"posts":[...]} directly. A test passes its own; NULL restores. */
typedef bool (*zcl_app_offer_call_fn)(const char *path,
                                      const struct json_value *input,
                                      struct zcl_command_reply *out);
void zcl_app_offer_set_call(zcl_app_offer_call_fn fn);
bool zcl_app_offer_call(const char *path, const struct json_value *input,
                        struct zcl_command_reply *out);

#endif /* ZCL_TOOLS_NATIVE_APP_OFFER_H */
