/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "private.h"
#include "json/json.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

bool zapp_onion_peer_valid(const char *text)
{
    if (!text || strlen(text) < 63) return false;
    for (size_t i = 0; i < 56; i++)
        if (!((text[i] >= 'a' && text[i] <= 'z') || (text[i] >= '2' && text[i] <= '7'))) return false;
    if (memcmp(text + 56, ".onion:", 7) != 0) return false;
    long port = 0;
    size_t digits = 0;
    for (const char *p = text + 63; *p; p++, digits++) {
        if (*p < '0' || *p > '9' || digits >= 5) return false;
        port = port * 10 + (*p - '0');
    }
    return digits && port >= 1 && port <= 65535;
}
/* True when peer is the first token of one of the first count lines of list. */
static bool listed(const char *list, size_t count, const char *peer)
{
    const size_t want = strlen(peer);
    for (size_t i = 0; i < count && *list; i++) {
        size_t n = strcspn(list, "\n");
        if (strcspn(list, " \n") == want && !memcmp(list, peer, want)) return true;
        list += n + (list[n] == '\n');
    }
    return false;
}
/* The host name a roster line may carry: 1 to ZAPP_FLEET_NAME_MAX characters of a-z, 0-9 and "-". */
static bool name_valid(const char *name)
{
    size_t n = name ? strlen(name) : 0;
    if (!n || n > ZAPP_FLEET_NAME_MAX) return false;
    for (size_t i = 0; i < n; i++)
        if (!((name[i] >= 'a' && name[i] <= 'z') || (name[i] >= '0' && name[i] <= '9') || name[i] == '-')) return false;
    return true;
}
size_t zapp_fleet_onion_peers(const char *json, char *out, size_t cap)
{
    struct json_value root = {0};
    size_t count = 0, used = 0;
    if (cap) out[0] = 0;
    const struct json_value *hosts = cap && json && json_read(&root, json, strlen(json)) ? json_get(&root, "hosts") : NULL;
    for (size_t i = 0; hosts && hosts->type == JSON_ARR && i < hosts->num_children && count < ZAPP_PRIVATE_PEERS_MAX; i++) {
        const struct json_value *row = json_at(hosts, i);
        const char *peer = json_get_str(json_get(row, "onion")), *name = json_get_str(json_get(row, "host"));
        if (!peer || !zapp_onion_peer_valid(peer) || listed(out, count, peer)) continue;
        int n = name_valid(name) ? snprintf(out + used, cap - used, "%s %s\n", peer, name) : snprintf(out + used, cap - used, "%s\n", peer);
        if (n < 0 || (size_t)n >= cap - used) break;
        used += (size_t)n;
        count++;
    }
    json_free(&root);
    return count;
}
static bool roster_path(const char *directory, const char *name, char *out, size_t cap)
{
    int n = directory ? snprintf(out, cap, "%s/%s", directory, name) : -1;
    return n > 0 && (size_t)n < cap;
}
bool zapp_private_roster_save(const char *directory, const char *json)
{
    char peers[ZAPP_ROSTER_MAX], final[1100], temporary[1110];
    if (!zapp_fleet_onion_peers(json, peers, sizeof(peers)) || !roster_path(directory, "fleet-onion-peers", final, sizeof(final)) ||
        !roster_path(directory, "fleet-onion-peers.tmp", temporary, sizeof(temporary))) return false;
    int fd = open(temporary, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    size_t length = strlen(peers), done = 0;
    bool ok = true;
    while (ok && done < length) {
        ssize_t n = write(fd, peers + done, length - done);
        if (n > 0) done += (size_t)n; else if (n < 0 && errno == EINTR) continue; else ok = false;
    }
    ok = ok && fsync(fd) == 0;
    if (close(fd) != 0) ok = false;
    ok = ok && rename(temporary, final) == 0;
    if (!ok) (void)unlink(temporary);
    return ok;
}
size_t zapp_private_roster_load(const char *directory, char *out, size_t cap)
{
    char file[1100];
    if (!cap) return 0;
    out[0] = 0;
    int fd = roster_path(directory, "fleet-onion-peers", file, sizeof(file)) ? open(file, O_RDONLY | O_CLOEXEC | O_NOFOLLOW) : -1;
    if (fd < 0) return 0;
    ssize_t n;
    do n = read(fd, out, cap - 1); while (n < 0 && errno == EINTR);
    (void)close(fd);
    out[n > 0 ? n : 0] = 0;
    return n > 0 ? (size_t)n : 0;
}
void zapp_private_args(struct zapp_private_args *a, const char *roster_text)
{
    memset(a, 0, sizeof(*a));
    a->argv[a->argc++] = "-onlynet=onion";
    a->argv[a->argc++] = "-bind=127.0.0.1";
    size_t peers = 0;
    for (const char *line = roster_text; line && *line && peers < ZAPP_PRIVATE_PEERS_MAX;) {
        size_t n = strcspn(line, " \n");
        char one[ZAPP_ONION_PEER_MAX + 1];
        if (n < sizeof(one)) {
            memcpy(one, line, n);
            one[n] = 0;
            bool repeat = false;
            for (size_t i = 0; i < peers; i++) repeat = repeat || !strcmp(a->peer[i] + strlen("-addnode="), one);
            if (zapp_onion_peer_valid(one) && !repeat) {
                snprintf(a->peer[peers], sizeof(a->peer[peers]), "-addnode=%s", one);
                a->argv[a->argc++] = a->peer[peers++];
            }
        }
        line += strcspn(line, "\n");
        line += *line == '\n';
    }
}
