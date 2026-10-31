/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "private.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define A "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
#define B "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion"

static void validation(void)
{
    assert(zapp_onion_peer_valid(A ":8033") && zapp_onion_peer_valid(B ":1") && zapp_onion_peer_valid(A ":65535"));
    assert(!zapp_onion_peer_valid(NULL) && !zapp_onion_peer_valid("") && !zapp_onion_peer_valid(A));    /* no port */
    assert(!zapp_onion_peer_valid(A ":") && !zapp_onion_peer_valid(A ":0") && !zapp_onion_peer_valid(A ":65536"));
    assert(!zapp_onion_peer_valid(A ":80x") && !zapp_onion_peer_valid(A ":008033") && !zapp_onion_peer_valid(A ":-1"));
    assert(!zapp_onion_peer_valid("1.2.3.4:8033") && !zapp_onion_peer_valid("seed.zclassic.org:8033"));
    assert(!zapp_onion_peer_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion:8033"));   /* 55 characters */
    assert(!zapp_onion_peer_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion:8033")); /* 57 characters */
    assert(!zapp_onion_peer_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1.onion:8033"));  /* 1 is not base32 */
    assert(!zapp_onion_peer_valid("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.onion:8033"));  /* upper case */
    assert(!zapp_onion_peer_valid(A ".evil.com:8033") && !zapp_onion_peer_valid(A ":8033 -addnode=1.2.3.4"));
    assert(!zapp_onion_peer_valid("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.clear:8033"));   /* wrong suffix */
}
static void arguments(void)
{
    struct zapp_private_args a;
    zapp_private_args(&a, NULL);
    assert(a.argc == 2 && !strcmp(a.argv[0], "-onlynet=onion") && !strcmp(a.argv[1], "-bind=127.0.0.1") && !a.argv[2]);
    /* Only valid onion peers become -addnode; clearnet, malformed and repeated lines are dropped. */
    zapp_private_args(&a, A ":8033\n1.2.3.4:8033\n" B ":8034\n" A ":8033\njunk\n\n" A ":0\n");
    assert(a.argc == 4 && !strcmp(a.argv[2], "-addnode=" A ":8033") && !strcmp(a.argv[3], "-addnode=" B ":8034") && !a.argv[4]);
    for (size_t i = 0; i < a.argc; i++) assert(strncmp(a.argv[i], "-connect", 8) && !strstr(a.argv[i], "seed"));
    char many[ZAPP_PRIVATE_PEERS_MAX * 80 + 160] = "";
    for (int i = 0; i < ZAPP_PRIVATE_PEERS_MAX + 3; i++)
        snprintf(many + strlen(many), sizeof(many) - strlen(many), "%.*s%c.onion:%d\n", 55, A, 'a' + i, 8000 + i);
    zapp_private_args(&a, many);
    assert(a.argc == 2 + ZAPP_PRIVATE_PEERS_MAX && !a.argv[a.argc]);
}
static void roster(void)
{
    char snapshot[1024], peers[ZAPP_PRIVATE_PEERS_MAX * (ZAPP_ONION_PEER_MAX + 1) + 1];
    snprintf(snapshot, sizeof(snapshot), "{\"hosts\":[{\"host\":\"r1\",\"onion\":\"%s:8033\"},{\"host\":\"r2\",\"onion\":\"%s:8033\"},"
             "{\"host\":\"r3\",\"onion\":\"1.2.3.4:8033\"},{\"host\":\"r4\"},{\"host\":\"r5\",\"onion\":\"%s:8033\"}]}", A, B, A);
    assert(zapp_fleet_onion_peers(snapshot, peers, sizeof(peers)) == 2);
    assert(!strcmp(peers, A ":8033\n" B ":8033\n"));
    assert(zapp_fleet_onion_peers("{\"hosts\":[{\"host\":\"r1\"}]}", peers, sizeof(peers)) == 0 && !peers[0]);
    assert(zapp_fleet_onion_peers("nope", peers, sizeof(peers)) == 0 && zapp_fleet_onion_peers(NULL, peers, sizeof(peers)) == 0);
    assert(zapp_fleet_onion_peers(snapshot, peers, 70) == 1);                 /* too small for the second line */

    char dir[] = "/tmp/zapp-private-XXXXXX", text[512], file[128];
    assert(mkdtemp(dir));
    assert(zapp_private_roster_load(dir, text, sizeof(text)) == 0 && !text[0]);
    assert(zapp_private_roster_save(dir, snapshot) && zapp_private_roster_load(dir, text, sizeof(text)) > 0);
    assert(!strcmp(text, A ":8033\n" B ":8033\n"));
    /* A snapshot without a valid peer keeps what the app already holds. */
    assert(!zapp_private_roster_save(dir, "{\"hosts\":[{\"host\":\"r1\"}]}") && !zapp_private_roster_save(dir, "nope"));
    assert(zapp_private_roster_load(dir, text, sizeof(text)) > 0 && !strcmp(text, A ":8033\n" B ":8033\n"));
    assert(!zapp_private_roster_save("/nonexistent-zapp-dir", snapshot));
    snprintf(file, sizeof(file), "%s/fleet-onion-peers", dir);
    assert(unlink(file) == 0 && rmdir(dir) == 0);
}
int main(void)
{
    validation();
    arguments();
    roster();
    puts("private tests passed");
    return 0;
}
