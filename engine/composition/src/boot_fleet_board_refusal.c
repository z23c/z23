/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The words a refused local board or wiki write is answered with:
 * the fixed refusal phrase plus the limit hit and the command that clears it. */

#include "config/boot_fleet_board.h"

#include <stdio.h>

/* A refusal of this node's own write: the fixed phrase plus what clears it.
 * Remote peers never see these hints; the phrase alone is the wire text. */
static const char *write_hint(enum fleet_board_result r, char *buf, size_t cap)
{
    switch (r) {
    case FLEET_BOARD_ERR_ROLE:
        return "admit the writer key with: z23 fleet roles grant --fp=<64-hex "
               "key fingerprint> --role=worker";
    case FLEET_BOARD_ERR_WIKI_QUOTA:
        (void)snprintf(buf, cap, "this node's key may write %d wiki revisions "
            "per %d seconds, and a node replaces at most %d superseded revisions "
            "per %d seconds; retry after the window clears",
            (int)FLEET_BOARD_WIKI_QUOTA_WINDOW_MAX,
            (int)FLEET_BOARD_PUBLIC_QUOTA_WINDOW_SECONDS,
            (int)FLEET_BOARD_WIKI_EVICT_MAX, (int)FLEET_BOARD_WIKI_EVICT_SECONDS);
        return buf;
    case FLEET_BOARD_ERR_QUOTA:
        (void)snprintf(buf, cap, "this node's key may post %d messages per %d "
            "seconds and keep %d stored; retry after the window clears",
            (int)FLEET_BOARD_PUBLIC_QUOTA_WINDOW_MAX,
            (int)FLEET_BOARD_PUBLIC_QUOTA_WINDOW_SECONDS,
            (int)FLEET_BOARD_PUBLIC_QUOTA_STORED_MAX);
        return buf;
    case FLEET_BOARD_ERR_WIKI_FULL:
        (void)snprintf(buf, cap, "this node's key holds %d wiki revisions and "
            "none is superseded; revise an existing page (same slug) instead of "
            "adding a new one, or write the page from another node",
            (int)FLEET_BOARD_WIKI_QUOTA_STORED_MAX);
        return buf;
    case FLEET_BOARD_ERR_SIGNATURE:
        return "this node could not sign with its identity key; the node log "
               "names the cause";
    default:
        return NULL;
    }
}

const char *boot_fleet_board_write_message(enum fleet_board_result r, char *buf, size_t cap)
{
    char hint_buf[256];
    const char *hint = write_hint(r, hint_buf, sizeof(hint_buf));
    if (hint)
        (void)snprintf(buf, cap, "%s; %s", fleet_board_result_string(r), hint);
    else
        (void)snprintf(buf, cap, "%s", fleet_board_result_string(r));
    return buf;
}
