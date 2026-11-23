/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "private.h"
#include "review_stage.h"
#include "review_event.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
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
static void roster(const char *dir)
{
    char snapshot[1024], peers[ZAPP_PRIVATE_PEERS_MAX * (ZAPP_ONION_PEER_MAX + 1) + 1];
    snprintf(snapshot, sizeof(snapshot), "{\"hosts\":[{\"host\":\"r1\",\"onion\":\"%s:8033\"},{\"host\":\"r2\",\"onion\":\"%s:8033\"},"
             "{\"host\":\"r3\",\"onion\":\"1.2.3.4:8033\"},{\"host\":\"r4\"},{\"host\":\"r5\",\"onion\":\"%s:8033\"}]}", A, B, A);
    assert(zapp_fleet_onion_peers(snapshot, peers, sizeof(peers)) == 2);
    assert(!strcmp(peers, A ":8033 r1\n" B ":8033 r2\n"));
    assert(zapp_fleet_onion_peers("{\"hosts\":[{\"host\":\"r1\"}]}", peers, sizeof(peers)) == 0 && !peers[0]);
    assert(zapp_fleet_onion_peers("nope", peers, sizeof(peers)) == 0 && zapp_fleet_onion_peers(NULL, peers, sizeof(peers)) == 0);
    assert(zapp_fleet_onion_peers(snapshot, peers, 80) == 1);                 /* too small for the second line */

    char text[512], file[128];
    assert(zapp_private_roster_load(dir, text, sizeof(text)) == 0 && !text[0]);
    assert(zapp_private_roster_save(dir, snapshot) && zapp_private_roster_load(dir, text, sizeof(text)) > 0);
    assert(!strcmp(text, A ":8033 r1\n" B ":8033 r2\n"));
    /* A snapshot without a valid peer keeps what the app already holds. */
    assert(!zapp_private_roster_save(dir, "{\"hosts\":[{\"host\":\"r1\"}]}") && !zapp_private_roster_save(dir, "nope"));
    assert(zapp_private_roster_load(dir, text, sizeof(text)) > 0 && !strcmp(text, A ":8033 r1\n" B ":8033 r2\n"));
    assert(!zapp_private_roster_save("/nonexistent-zapp-dir", snapshot));
    snprintf(file, sizeof(file), "%s/fleet-onion-peers", dir);
    assert(unlink(file) == 0);
}
/* A roster line is "onion" or "onion name": a name is kept only when it is a short host label, and dialing
 * reads the onion token alone. */
static void named_roster(void)
{
    char peers[ZAPP_ROSTER_MAX], row[512];
    snprintf(row, sizeof(row), "{\"hosts\":[{\"host\":\"Bad Name\",\"onion\":\"%s:8033\"},{\"host\":\"mac-1\",\"onion\":\"%s:8033\"},"
             "{\"host\":\"r1\",\"onion\":\"%s:8033\"},{\"host\":\"averyveryverylonghost\",\"onion\":\"%s:8033\"}]}", A, B, B, A);
    assert(zapp_fleet_onion_peers(row, peers, sizeof(peers)) == 2);
    assert(!strcmp(peers, A ":8033\n" B ":8033 mac-1\n"));
    struct zapp_private_args a;
    zapp_private_args(&a, A ":8033 r1\n" B ":8033\n" A ":8033 again\n" B ":8033 r2\n");
    assert(a.argc == 4 && !strcmp(a.argv[2], "-addnode=" A ":8033") && !strcmp(a.argv[3], "-addnode=" B ":8033"));
    zapp_private_args(&a, A ":8033 r1 extra\nbogus.example:1 name\n");
    assert(a.argc == 3 && !strcmp(a.argv[2], "-addnode=" A ":8033"));
}
static void receipt(const char *dir)
{
    char token[ZAPP_FLEET_RECEIPT_MAX + 2], out[sizeof(token)], path[512], target[512];
    memset(token, 65, 128); token[128] = 0;
    assert(zapp_fleet_receipt_save(dir, token));
    assert(zapp_fleet_receipt_load(dir, out, sizeof(out)) == 128 && !strcmp(out, token));
    snprintf(path, sizeof(path), "%s/fleet-join-receipt", dir);
    struct stat st; assert(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);
    token[0] = 61;
    assert(!zapp_fleet_receipt_save(dir, token));
    assert(zapp_fleet_receipt_load(dir, out, sizeof(out)) == 128 && out[0] == 65);
    assert(zapp_fleet_receipt_load(dir, out, 128) == 0 && !out[0]);
    token[0] = 65;
    assert(chmod(dir, 0500) == 0);
    assert(!zapp_fleet_receipt_save(dir, token));
    assert(chmod(dir, 0700) == 0);
    assert(zapp_fleet_receipt_load(dir, out, sizeof(out)) == 128 && out[0] == 65);
    int fd = open(path, O_WRONLY | O_TRUNC); assert(fd >= 0);
    memset(token, 66, sizeof(token));
    assert(write(fd, token, sizeof(token)) == (ssize_t)sizeof(token)); assert(close(fd) == 0);
    assert(zapp_fleet_receipt_load(dir, out, sizeof(out)) == 0 && !out[0]);
    fd = open(path, O_WRONLY | O_TRUNC); assert(fd >= 0);
    assert(write(fd, token, 127) == 127); assert(close(fd) == 0);
    assert(zapp_fleet_receipt_load(dir, out, sizeof(out)) == 0 && !out[0]);
    assert(unlink(path) == 0);
    snprintf(target, sizeof(target), "%s/receipt-target", dir);
    fd = open(target, O_WRONLY | O_CREAT | O_EXCL, 0600); assert(fd >= 0); assert(close(fd) == 0);
    assert(symlink(target, path) == 0);
    assert(zapp_fleet_receipt_load(dir, out, sizeof(out)) == 0 && !out[0]);
    assert(unlink(path) == 0); assert(mkfifo(path, 0600) == 0);
    assert(zapp_fleet_receipt_load(dir, out, sizeof(out)) == 0 && !out[0]);
    assert(unlink(path) == 0); assert(unlink(target) == 0);
}
static void peer_mode(const char *dir)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/direct-peers", dir);
    struct zapp_private_args args;
    zapp_peer_args(&args, NULL, true);
    assert(args.argc == 1 && !strcmp(args.argv[0], "-bind=127.0.0.1") && !args.argv[1]);
    assert(!zapp_direct_peers_load(dir));
    assert(zapp_direct_peers_save(dir, true));
    assert(zapp_direct_peers_load(dir));
    int fd = open(path, O_WRONLY | O_TRUNC); assert(fd >= 0);
    assert(write(fd, "allow\nX", 7) == 7); assert(close(fd) == 0);
    assert(!zapp_direct_peers_load(dir));
    assert(zapp_direct_peers_save(dir, false));
    assert(!zapp_direct_peers_load(dir));
    assert(unlink(path) == 0);
}
static void review_cleanup_tests(const char *dir)
{
    char spool[1024], stale[1100], other[1100];
    assert(snprintf(spool, sizeof(spool), "%s/review-spool", dir) > 0);
    assert(mkdir(spool, 0700) == 0);
    assert(snprintf(stale, sizeof(stale), "%s/z23-review-ABC123", spool) > 0);
    assert(snprintf(other, sizeof(other), "%s/keep", spool) > 0);
    int old = open(stale, O_WRONLY | O_CREAT | O_EXCL, 0600), keep = open(other, O_WRONLY | O_CREAT | O_EXCL, 0600);
    assert(old >= 0 && keep >= 0 && close(old) == 0 && close(keep) == 0);
    assert(zapp_review_stage_cleanup(spool));
    assert(access(stale, F_OK) != 0 && access(other, F_OK) == 0);
    assert(symlink("keep", stale) == 0 && !zapp_review_stage_cleanup(spool));
    assert(unlink(stale) == 0 && chmod(spool, 0775) == 0 && !zapp_review_stage_cleanup(spool));
    assert(chmod(spool, 0700) == 0 && unlink(other) == 0 && rmdir(spool) == 0);
}
static void review_event_tests(void)
{
    bool wake = true, timer = true, remove_timer = false;
    assert(zapp_review_take_wake(7, 4, 7, 4, &wake, &timer, &remove_timer));
    assert(!wake && !timer && remove_timer);
    /* Both were ready: after the wake, the queued timer callback must not read. */
    assert(!zapp_review_event_matches(7, timer, 5, 7, 5));
    /* A later job can reuse the same descriptor, but never the old generation. */
    assert(!zapp_review_event_matches(8, true, 5, 7, 5));
    assert(!zapp_review_event_matches(8, true, 5, 8, 4));
    assert(!zapp_review_event_matches(0, true, 5, 0, 5));
}
static void review_stage_tests(const char *dir)
{
    char path[1024], result[4] = {0};
    assert(snprintf(path, sizeof(path), "%s/review-stage", dir) > 0);
    int out = open(path, O_RDWR | O_CREAT | O_EXCL, 0600), p[2];
    assert(out >= 0 && pipe(p) == 0);
    assert(write(p[1], "abc", 3) == 3 && close(p[1]) == 0);
    assert(zapp_review_stage_copy(p[0], out, 3, 1000, NULL) == ZAPP_STAGE_OK);
    assert(lseek(out, 0, SEEK_SET) == 0 && read(out, result, 3) == 3 && !strcmp(result, "abc"));
    assert(close(p[0]) == 0 && ftruncate(out, 0) == 0 && lseek(out, 0, SEEK_SET) == 0);
    assert(pipe(p) == 0 && write(p[1], "abcd", 4) == 4 && close(p[1]) == 0);
    assert(zapp_review_stage_copy(p[0], out, 3, 1000, NULL) == ZAPP_STAGE_TOO_LARGE);
    assert(close(p[0]) == 0 && pipe(p) == 0 && close(p[1]) == 0);
    assert(zapp_review_stage_copy(p[0], out, 3, 1000, NULL) == ZAPP_STAGE_EMPTY);
    assert(close(p[0]) == 0 && pipe(p) == 0);
    atomic_bool cancel = true;
    assert(zapp_review_stage_copy(p[0], out, 3, 1000, &cancel) == ZAPP_STAGE_CANCELED);
    atomic_store(&cancel, false);
    assert(zapp_review_stage_copy(p[0], out, 3, 10, &cancel) == ZAPP_STAGE_UNAVAILABLE);
    assert(close(p[0]) == 0 && close(p[1]) == 0 && close(out) == 0 && unlink(path) == 0);
}
int main(int argc, char **argv)
{
    assert(argc > 1);
    review_stage_tests(argv[1]);
    review_cleanup_tests(argv[1]);
    review_event_tests();
    assert(argc == 2);
    validation();
    arguments();
    roster(argv[1]);
    named_roster();
    receipt(argv[1]);
    peer_mode(argv[1]);
    puts("private tests passed");
    return 0;
}
