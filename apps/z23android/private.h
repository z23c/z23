/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_PRIVATE_H
#define ZAPP_PRIVATE_H
#include <stdbool.h>
#include <stddef.h>

/* Private mode is the phone node's only mode: it dials Tor onion peers and nothing else, does no DNS
 * seeding and never falls back to clearnet. These arguments are the node's -onlynet=onion contract
 * (engine/composition: app_onlynet_onion_refusal), plus the owner's fleet onion peers as -addnode. */
enum { ZAPP_ONION_PEER_MAX = 72, ZAPP_PRIVATE_PEERS_MAX = 8, ZAPP_PRIVATE_ARGV_MAX = 12, ZAPP_FLEET_NAME_MAX = 15,
       ZAPP_ROSTER_MAX = ZAPP_PRIVATE_PEERS_MAX * (ZAPP_ONION_PEER_MAX + 1 + ZAPP_FLEET_NAME_MAX + 1) + 1 };

/* True for "<56 characters of a-z2-7>.onion:<port 1-65535>" and nothing else. */
bool zapp_onion_peer_valid(const char *text);

/* Collects the valid "onion" fields (host:port) of a fleet snapshot's host rows, one per line, without
 * repeats, each followed by a space and the row's "host" name when that is 1 to ZAPP_FLEET_NAME_MAX characters
 * of a-z, 0-9 and "-". At most ZAPP_PRIVATE_PEERS_MAX lines. Readers take the first token as the peer and the
 * second, when present, as its name. Returns how many were written; out is empty for none. */
size_t zapp_fleet_onion_peers(const char *json, char *out, size_t cap);

/* Keeps the peers of a fleet snapshot in directory/fleet-onion-peers for the next node start. A snapshot
 * without a valid onion peer leaves the file as it was. True when the file was replaced. */
bool zapp_private_roster_save(const char *directory, const char *json);
/* Reads that file into out (empty when absent or unreadable). Returns its length. */
size_t zapp_private_roster_load(const char *directory, char *out, size_t cap);

struct zapp_private_args {
    char peer[ZAPP_PRIVATE_PEERS_MAX][ZAPP_ONION_PEER_MAX + 16];
    char *argv[ZAPP_PRIVATE_ARGV_MAX + ZAPP_PRIVATE_PEERS_MAX]; /* NULL-terminated */
    size_t argc;
};
/* Fills a with -onlynet=onion, -bind=127.0.0.1 and one -addnode= for each valid line of roster_text (NULL
 * for none). Invalid, repeated and surplus lines are dropped. A node started with these dials no clearnet
 * host and resolves no DNS seed. */
void zapp_private_args(struct zapp_private_args *a, const char *roster_text);
#endif
