/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * connman_onion_seeds — the onion-directory seed walk: how a node with no
 * peers finds a supplier over Tor alone. Split out of lib/net/src/connman.c
 * (which is at its shrink-only file-size baseline) because this is one
 * self-contained concern with one entry point per caller, and because the
 * concurrency it now owns — the seed RACE, net/onion_seed_race.h — deserves
 * to be readable next to the tier ordering it feeds, not buried in the
 * middle of connman's lifecycle file.
 *
 * The split moved code only. Every tier, bound, dedupe ring and trust rule
 * below is byte-for-byte the one connman.c had; the two functions connman.c
 * still calls were renamed from file-static to the connman_ prefix and
 * declared in net/connman.h:
 *
 *   run_onion_seed_pass()  -> connman_run_onion_seed_pass()
 *   try_onion_seed_fetch() -> connman_onion_seed_fetch_one()
 *
 * Trust discipline is unchanged and unchangeable here: a directory record
 * is a HINT about WHERE to look, never proof of WHO is there. Harvested
 * onions are only ADDED (INSERT OR IGNORE), and a row is credited with
 * CONTACT only when WE complete a fetch against it. */

#include "connman_internal.h"

#include "net/connman.h"
#include "net/addrman.h"
#include "net/net.h"
#include "net/onion_discovery.h"
#include "net/onion_peer_merge.h"
#include "net/onion_seed_race.h"
#include "net/onion_service.h"
#include "net/tor_integration.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Onion-directory seed walk ──────────────────────────────────────
 *
 * A /directory.json response carries BOTH a clearnet endpoint and the
 * advertising node's `onion` field. Consuming only the clearnet half means
 * a node can never learn about an onion peer from another onion peer: the
 * onion graph is never transitively walked, and an onion-only node is
 * invisible to everyone it has not personally met. So we harvest both,
 * strictly ALONGSIDE the clearnet half (which is untouched and still runs
 * first). A relayed hostname buys exactly one thing — one more place to
 * look.
 *
 * Discipline (docs/work/NAT_AND_ONION_TRANSPORT.md): a directory record is
 * a HINT about WHERE to look, never proof of WHO is there. Harvested
 * onions are therefore only ADDED (onion_service_directory_learn — INSERT
 * OR IGNORE, so hearsay never overwrites a row we measured), and a row is
 * credited with CONTACT only when WE complete a fetch against it.
 *
 * Bounded on every axis a hostile directory could inflate: one extra hop
 * of depth, a per-response hint cap, a follow budget per window and a
 * dedupe ring so a cycle (A lists B, B lists A) terminates. Caps, parser
 * and follow budget: onion_service.h. The budget is a WALL-CLOCK bound as
 * much as a fan-out one — this runs on the discovery thread and each fetch
 * blocks — so depth-1 fetches also get a shorter deadline than a
 * configured seed, and g_stop aborts between hops. */
#define ONION_RELAY_FETCH_TIMEOUT 20

static int try_onion_seed_fetch_depth(struct connman *cm, const char *onion,
                                      int depth, bool pin_endpoints);

/* Fetch /directory.json from ONE .onion seed and add its clearnet IPs.
 * The single-host, depth-0 entry point: connman.c's boot-time discovery
 * pass uses it for the .onion peers the on-chain projection named, once
 * the node is already above the peer floor. Below the floor the seed
 * RACE below is the path — that is where a dead door costs nothing. */
void connman_onion_seed_fetch_one(struct connman *cm, const char *onion)
{
    (void)try_onion_seed_fetch_depth(cm, onion, 0, false);
}

/* Record one MEASURED dial outcome — the census bridge in
 * net/onion_service.h, which refreshes an EXISTING row and never inserts.
 * A successful fetch calls learn() first so the row exists to refresh. */
static void onion_seed_note_dial(const char *onion, bool reachable)
{
    struct onion_directory_observation obs;
    memset(&obs, 0, sizeof(obs));
    snprintf(obs.hostname, sizeof(obs.hostname), "%s", onion ? onion : "");
    obs.reachable = reachable;
    obs.observed_unix = (int64_t)platform_time_wall_time_t();
    obs.best_height = -1;
    (void)onion_service_directory_observe(&obs, 1, NULL);
}

static int apply_onion_seed_directory(struct connman *cm, const char *onion,
                                      const uint8_t *body, size_t body_len,
                                      int depth, bool pin_endpoints);

static int try_onion_seed_fetch_depth(struct connman *cm, const char *onion,
                                      int depth, bool pin_endpoints)
{
    if (!cm || !onion) return -1;
    printf("Onion seed: fetching /directory.json from %s (depth=%d)...\n",
           onion, depth);
    fflush(stdout);

    struct onion_fetch_result result = {0};
    int rc = tor_integration_fetch_onion_blocking(
        onion, "/directory.json", &result,
        depth == 0 ? 60 : ONION_RELAY_FETCH_TIMEOUT);
    if (rc < 0 || result.status != 200 || !result.body) {
        printf("Onion seed: fetch failed (rc=%d status=%d)\n",
               rc, result.status);
        /* Bumps this row's failure count only; never inserts, never
         * refreshes last_seen — a failed dial carries no identity. */
        onion_seed_note_dial(onion, false);
        if (result.body) free(result.body);
        return -1;
    }

    int added = apply_onion_seed_directory(cm, onion, result.body,
                                           result.body_len, depth,
                                           pin_endpoints);
    free(result.body);
    return added;
}

static int apply_onion_seed_directory(struct connman *cm, const char *onion,
                                      const uint8_t *body, size_t body_len,
                                      int depth, bool pin_endpoints)
{
    if (!cm || !onion || !body)
        return -1;
    (void)body_len;

    /* We reached it ourselves: this one IS contact, not hearsay. learn()
     * makes sure the row exists (a configured seed may never have been
     * advertised to us); the observation then stamps last_success. The
     * node's OWN app advertisement rides along — its self row is skipped
     * by the relay-hint learn loop below, so it is extracted here. */
    char self_apps[ONION_DIR_APPS_CSV_MAX + 1];
    (void)onion_directory_apps_for_onion((const char *)body, onion,
                                         self_apps, sizeof(self_apps));
    (void)onion_service_directory_learn(onion, 0, 0, 0, self_apps);
    onion_seed_note_dial(onion, true);

    /* Fallback when a directory response omits/malforms clearnet_port —
     * the advertising node's OWN configured P2P port, not a literal that
     * silently assumes mainnet. */
    uint16_t default_port = (cm->params && cm->params->nDefaultPort > 0 &&
                             cm->params->nDefaultPort <= 65535)
                                ? (uint16_t)cm->params->nDefaultPort
                                : 8033;

    /* Parse minimal JSON: extract clearnet_ip and clearnet_port fields */
    const char *p = (const char *)body;
    int added = 0;
    while ((p = strstr(p, "\"clearnet_ip\":\"")) != NULL) {
        p += 15; /* skip "clearnet_ip":" */
        const char *end = strchr(p, '"');
        if (!end || end == p) { p++; continue; }

        char ip[64];
        size_t iplen = (size_t)(end - p);
        if (iplen >= sizeof(ip)) { p = end; continue; }
        memcpy(ip, p, iplen);
        ip[iplen] = '\0';
        p = end + 1;

        /* Find clearnet_port */
        uint16_t port = default_port;
        const char *pp = strstr(p, "\"clearnet_port\":");
        if (pp && pp - p < 50) {
            const char *port_text = pp + 16;
            char *port_end = NULL;
            unsigned long parsed_port = strtoul(port_text, &port_end, 10);
            if (port_end != port_text && parsed_port > 0 &&
                parsed_port <= 65535)
                port = (uint16_t)parsed_port;
        }

        /* Add to address manager */
        if (ip[0] && strcmp(ip, "0.0.0.0") != 0) {
            struct net_address addr;
            memset(&addr, 0, sizeof(addr));
            /* Parse IPv4 */
            unsigned a, b, c, d;
            char trailing;
            if (sscanf(ip, "%u.%u.%u.%u%c", &a, &b, &c, &d,
                       &trailing) == 4 &&
                a <= 255 && b <= 255 && c <= 255 && d <= 255) {
                /* IPv4-mapped IPv6 */
                unsigned char ip4[4] = {(unsigned char)a, (unsigned char)b,
                                        (unsigned char)c, (unsigned char)d};
                net_addr_set_ipv4(&addr.svc.addr, ip4);
                addr.svc.port = port;
                addr.nServices = NODE_NETWORK;
                struct net_addr src;
                net_addr_init(&src);
                addrman_add(&cm->manager.addrman, &addr, &src, 0);
                if (pin_endpoints)
                    connman_open_connection(cm, &addr);
                added++;
                printf("Onion seed: discovered clearnet peer %s:%d\n",
                       ip, port);
            }
        }
    }

    /* ── Second, ADDITIVE pass: the onion half of the same response ──
     * Runs after the clearnet loop above and cannot alter anything it
     * did. Every hint is persisted into our own directory (INSERT OR
     * IGNORE — hearsay never overwrites a row we measured) so the
     * transitive knowledge survives a restart and is re-served by our own
     * /directory + /search, and a bounded few are followed one hop for
     * their clearnet entries. The parser drops our own hostname and the
     * one we just fetched from, so a walk cannot bounce between two
     * nodes. */
    const char *self_onion = tor_integration_get_onion_address();
    struct onion_relay_hint hints[ONION_RELAY_PER_RESPONSE];
    int nh = onion_directory_parse_relay_hints(
        (const char *)body,
        (self_onion && self_onion[0]) ? self_onion : onion,
        hints, ONION_RELAY_PER_RESPONSE);
    int learned = 0, followed = 0;
    for (int i = 0; i < nh; i++) {
        if (strcmp(hints[i].hostname, onion) == 0)
            continue;                       /* the node we just fetched */
        if (onion_service_directory_learn(hints[i].hostname, hints[i].port,
                                          hints[i].height, hints[i].last_seen,
                                          hints[i].apps))
            learned++;
    }

    /* GETTING A FIRST PEER OUTRANKS ENRICHING THE GRAPH. The depth-1
     * follow is up to ONION_RELAY_FOLLOW_BUDGET blocking fetches of
     * ONION_RELAY_FETCH_TIMEOUT each, and it runs on the same discovery
     * thread as the peer-of-last-resort onion pass. Transitive discovery
     * only matters once we already HAVE peers, so below the healthy floor
     * it is skipped outright rather than delaying the last-resort path by
     * minutes on a cold boot. */
    if (depth < ONION_RELAY_MAX_DEPTH &&
        cm->manager.num_nodes >= (size_t)ZCL_PEER_FLOOR_HEALTHY) {
        int64_t now = (int64_t)platform_time_wall_time_t();
        for (int i = 0; i < nh && !g_stop; i++) {
            if (strcmp(hints[i].hostname, onion) == 0)
                continue;
            if (!onion_directory_claim_relay_follow(hints[i].hostname, now))
                continue;
            followed++;
            (void)try_onion_seed_fetch_depth(cm, hints[i].hostname,
                                             depth + 1, false);
        }
    }
    printf("Onion seed: added %d clearnet peers, %d onion peers advertised "
           "by %s (%d recorded, %d followed)\n",
           added, nh, onion, learned, followed);

    return added;
}

int connman_add_onion_seed(struct connman *cm, const char *onion)
{
    if (!cm || !onion_hostname_valid(onion) || g_stop ||
        !tor_integration_is_dial_ready())
        return -1;
    return try_onion_seed_fetch_depth(cm, onion, 0, true);
}


/* How many hosts from our OWN persisted onion directory one pass may offer
 * to the seed race. Each concurrent fetch is a Tor circuit, so this is a
 * circuit-budget bound as much as a fan-out one. ENOUGH caps how many of
 * those directory hosts occupy race slots so compiled-in doors still start. */
#define ONION_DIR_DIAL_CANDIDATES 8
#define ONION_DIR_DIAL_ENOUGH     8
/* Ring for the per-pass dedupe: 32 operator lines + this tier + the
 * chainparams array + 8 on-chain hosts all fit with room to spare. */
#define ONION_PASS_SEEN_MAX       64

/* One pass's already-fetched set, so a host that appears in two tiers
 * (operator file AND the directory, say) costs one fetch, not two. Small,
 * stack-local, linear — the whole pass is bounded at a few dozen entries. */
struct onion_pass_seen {
    char host[ONION_PASS_SEEN_MAX][64];
    int  n;
};

static bool onion_pass_claim(struct onion_pass_seen *seen, const char *host)
{
    if (!seen || !host || !host[0]) return false;
    for (int i = 0; i < seen->n; i++)
        if (strcmp(seen->host[i], host) == 0)
            return false;
    if (seen->n >= ONION_PASS_SEEN_MAX)
        return true;    /* over the ring: still fetch, just stop tracking */
    size_t host_len = strlen(host);
    if (host_len >= sizeof(seen->host[0]))
        return false;
    memcpy(seen->host[seen->n], host, host_len + 1u);
    seen->n++;
    return true;
}

/* Run the onion-directory bootstrap pass. Tiers, in order:
 *
 *   1. the operator-curated file (~/.config/zclassic23/onion-seeds),
 *   2. THIS NODE'S OWN persisted onion directory — every host it has
 *      learned from a peer's /directory.json or measured itself,
 *   3. the chainparams onionSeeds[] array,
 *   4. any .onion peers the on-chain ZDIR projection named.
 *
 * The two RUNTIME sources come first on purpose. Both can change without a
 * rebuild; tier 3 is a constant compiled months ago that ages the moment it
 * ships, and its entries have in fact been found dead (see the seed block in
 * core/chainparams/src/chainparams.c). Ordering the doors that a running
 * network can repair ahead of the one only a release can repair is what stops
 * the binary from being a single point of failure.
 *
 * Tier 2 is the loop this pass used to leave open: the node already LEARNED
 * hostnames from every directory it fetched and RE-SERVED them to others, but
 * nothing ever read them back as somewhere to dial, so all that knowledge was
 * thrown away at every boot. On a fresh node the tier is simply empty and the
 * pass behaves exactly as it did before.
 *
 * Shared by the discovery thread's below-floor branch and the public
 * connman_kick_onion_seeds() peer-of-last-resort entry so both reach an
 * identical supplier set. Requires outbound dynhost queueing; it deliberately
 * does not wait for our own descriptor publication.
 *
 * Depth-0 seeds are raced concurrently (capped) so a dead door cannot delay
 * a live one. The first usable 200-body is applied immediately; the blocking
 * Tor fetch cannot be cancelled, so losers finish into discarded results
 * and are joined before the pass returns. Validation of a body is still
 * apply_onion_seed_directory — this pass changed WHEN attempts happen, not
 * which answer is accepted. */
static int onion_seed_pass_fetch(const char *onion, const char *path,
                                 struct onion_fetch_result *result,
                                 int timeout_secs, void *ctx)
{
    (void)ctx;
    int rc = tor_integration_fetch_onion_blocking(onion, path, result,
                                                  timeout_secs);
    if (rc < 0 || !result || result->status != 200 || !result->body)
        onion_seed_note_dial(onion, false);
    return rc;
}

void connman_run_onion_seed_pass(struct connman *cm)
{
    if (!cm || !cm->params || g_stop) return;
    if (g_connect_only) return;
    if (!tor_integration_is_dial_ready()) return;

    struct onion_pass_seen seen;
    seen.n = 0;

    /* Tier 1 — operator-curated onion seeds (one .onion per line, #
     * comments). The zero-rebuild primary: an operator adds a supplier
     * with no code change and no restart of anybody else. */
    const char *home = getenv("HOME");
    if (home) {
        char path[512];
        snprintf(path, sizeof(path),
                 "%s/.config/zclassic23/onion-seeds", home);
        FILE *fp = fopen(path, "re");
        if (fp) {
            char line[256];
            int n = 0;
            while (n < 32 && !g_stop && fgets(line, sizeof(line), fp)) {
                char *p = line;
                while (*p == ' ' || *p == '\t') p++;
                if (*p == '#' || *p == '\n' || *p == '\0') continue;
                char *end = strpbrk(p, " \t\r\n#");
                if (end) *end = '\0';
                if (strstr(p, ".onion") && onion_pass_claim(&seen, p))
                    n++;
            }
            fclose(fp);
        }
    }

    /* Tier 2 — our own persisted directory, measured contacts first.
     * Bounded by ONION_DIR_DIAL_CANDIDATES / ONION_DIR_DIAL_ENOUGH so a
     * large directory cannot fill the race with hearsay before the
     * compiled-in doors get a slot. */
    {
        struct onion_dial_candidate cand[ONION_DIR_DIAL_CANDIDATES];
        memset(cand, 0, sizeof(cand));
        int n = onion_service_directory_dial_candidates(
            cand, ONION_DIR_DIAL_CANDIDATES);
        int claimed = 0;
        for (int i = 0; i < n && !g_stop && claimed < ONION_DIR_DIAL_ENOUGH; i++) {
            if (onion_pass_claim(&seen, cand[i].hostname))
                claimed++;
        }
        if (n > 0)
            LOG_INFO("connman",
                     "onion bootstrap: own directory offered %d host%s, "
                     "claimed %d for the seed race",
                     n, n == 1 ? "" : "s", claimed);
    }

    /* Tier 3 — hardcoded chainparams onion seeds. */
    for (size_t i = 0; i < cm->params->nOnionSeeds && !g_stop; i++)
        (void)onion_pass_claim(&seen, cm->params->onionSeeds[i]);

    /* Tier 4 — .onion peers discovered on-chain (ZSLP scan) — same
     * Tor-native source the boot-time discovery pass uses. */
    if (cm->onion_peer_discover && cm->onion_peer_datadir) {
        struct onion_peer peers[16];
        int found = cm->onion_peer_discover(cm->onion_peer_datadir,
                                            peers, 16);
        for (int i = 0; i < found && i < 8 && !g_stop; i++) {
            if (peers[i].hostname[0] && strstr(peers[i].hostname, ".onion"))
                (void)onion_pass_claim(&seen, peers[i].hostname);
        }
    }

    if (seen.n <= 0 || g_stop)
        return;

    const char *hostptrs[ONION_PASS_SEEN_MAX];
    for (int i = 0; i < seen.n; i++)
        hostptrs[i] = seen.host[i];

    struct onion_fetch_result winner;
    memset(&winner, 0, sizeof(winner));
    size_t winner_index = (size_t)-1;
    struct onion_seed_race_join *join = NULL;
    int rc = onion_seed_race_first_usable(hostptrs, (size_t)seen.n,
                                          onion_seed_pass_fetch, NULL,
                                          60, &g_stop,
                                          &winner, &winner_index, &join);
    if (rc == 0 && winner.body && winner_index < (size_t)seen.n && !g_stop) {
        printf("Onion seed: first usable door %s\n", hostptrs[winner_index]);
        fflush(stdout);
        (void)apply_onion_seed_directory(cm, hostptrs[winner_index],
                                         winner.body, winner.body_len,
                                         0, false);
    }
    if (winner.body)
        free(winner.body);
    /* Losers cannot be cancelled; wait them out so connman_join / Tor
     * teardown cannot free the fetch path underneath a live worker. */
    onion_seed_race_join_wait(join);
    onion_seed_race_join_free(join);
}

void connman_kick_onion_seeds(struct connman *cm)
{
    if (!cm || g_stop || g_connect_only) return;
    LOG_INFO("connman", "peer-of-last-resort: querying onion-directory seeds");
    connman_run_onion_seed_pass(cm);
    /* Persist whatever clearnet hosts we just harvested so a subsequent
     * crash/restart before the periodic flush does not lose them. */
    connman_save_addrman(cm);
}
