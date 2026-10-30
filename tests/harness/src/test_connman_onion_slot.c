/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * connman addnode-fallback scenario checks: onion relay hints from a seed
 * directory become addrman candidates only with a known P2P port; the
 * once-per-boot onion walk runs independent of the healthy-peer floor; the
 * dialer reserves one batch position for an onion candidate while Tor can
 * dial and no outbound onion peer exists, and releases it on failure; onion
 * rows are never gossiped in a legacy addr message. */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "net/addrman.h"
#include "net/connman.h"
#include "net/onion_v3_address.h"
#include "net/protocol.h"
#include "net/tor_integration.h"
#include "platform/clock.h"
#include "util/timedata.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "test/test_connman_addnode_fallback_priv.h"

/* Real v3 addresses (checksummed), derived from fixed public keys. */
static char slot_host_a[ONION_V3_ADDRESS_LEN + 1];
static char slot_host_b[ONION_V3_ADDRESS_LEN + 1];
static char slot_host_c[ONION_V3_ADDRESS_LEN + 1];
static char slot_host_d[ONION_V3_ADDRESS_LEN + 1];

static bool slot_make_host(char *host, uint8_t seed)
{
    uint8_t pub[32];
    memset(pub, seed, sizeof(pub));
    return onion_v3_address_from_pubkey(pub, host);
}

static bool slot_make_hosts(void)
{
    return slot_make_host(slot_host_a, 0x21) &&
           slot_make_host(slot_host_b, 0x22) &&
           slot_make_host(slot_host_c, 0x23) &&
           slot_make_host(slot_host_d, 0x24);
}

static bool slot_init(struct connman *cm)
{
    chain_params_select(CHAIN_MAIN);
    struct node_signals sigs;
    memset(&sigs, 0, sizeof(sigs));
    return connman_init(cm, chain_params_get(), &sigs);
}

static bool slot_onion_address(const char *host, uint16_t port,
                               struct net_address *out)
{
    net_address_init(out);
    out->svc.port = port;
    out->nServices = NODE_NETWORK;
    return net_addr_from_onion(host, &out->svc.addr);
}

static size_t slot_onion_rows(struct connman *cm)
{
    struct addr_man *am = &cm->manager.addrman;
    size_t n = 0;
    zcl_mutex_lock(&am->cs);
    for (int i = 0; i < am->id_count; i++)
        if (am->entries[i].used && net_addr_is_tor(&am->entries[i].addr.svc.addr))
            n++;
    zcl_mutex_unlock(&am->cs);
    return n;
}

static bool slot_has_row(struct connman *cm, const char *host, uint16_t port)
{
    struct net_address a;
    struct addr_info info;
    return slot_onion_address(host, port, &a) &&
           addrman_find_info(&cm->manager.addrman, &a.svc, &info);
}

static void slot_report(const char *name, bool ok, int *failures)
{
    printf("connman_addnode_fallback: %s... %s\n", name, ok ? "OK" : "FAIL");
    if (!ok)
        (*failures)++;
}

static int slot_directory_hints(void)
{
    char dir[512];
    int failures = 0;
    struct connman cm;
    bool ok = slot_make_hosts() && slot_init(&cm);
    int dlen = snprintf(dir, sizeof(dir),
        "{\"nodes\":[{\"onion\":\"%s\",\"port\":8033,"
        "\"clearnet_ip\":\"93.184.216.34\",\"clearnet_port\":8033},"
        "{\"onion\":\"%s\",\"port\":null,"
        "\"clearnet_ip\":\"1.1.1.1\",\"clearnet_port\":8033}]}",
        slot_host_b, slot_host_c);
    ok = ok && dlen > 0 && (size_t)dlen < sizeof(dir);
    size_t before = ok ? cm.manager.addrman.new_count : 0;
    int added = ok ? connman_apply_onion_seed_directory_for_test(
                         &cm, slot_host_a, (const uint8_t *)dir,
                         (size_t)dlen) : -1;
    slot_report("directory onion hint with a P2P port becomes a torv3 "
                "addrman row",
                ok && slot_has_row(&cm, slot_host_b, 8033), &failures);
    slot_report("directory onion hint with port null is not guessed",
                ok && !slot_has_row(&cm, slot_host_c, 8033) &&
                    !slot_has_row(&cm, slot_host_c, 0) &&
                    slot_onion_rows(&cm) == 1, &failures);
    slot_report("clearnet entries of the same directory are unchanged",
                ok && added == 2 &&
                    (size_t)cm.manager.addrman.new_count == before + 3,
                &failures);
    if (ok)
        connman_free(&cm);
    return failures;
}

static void slot_add_healthy(struct connman *cm, bool *ok, uint8_t count)
{
    for (uint8_t i = 0; i < count; i++)
        *ok = *ok && add_test_peer(cm, (uint8_t)(11 + i), 1, 0, 1,
                                   PEER_HANDSHAKE_COMPLETE, false, false);
}

static bool slot_add_onion_row(struct connman *cm, const char *host)
{
    struct net_address a;
    struct net_addr src;
    net_addr_init(&src);
    return slot_onion_address(host, 8033, &a) &&
           addrman_add(&cm->manager.addrman, &a, &src, 0);
}

/* Put an onion row into a chosen failure state: `attempts` failures, the last
 * one `ago` seconds in the past. */
static bool slot_set_row(struct connman *cm, const char *host, int attempts,
                         int64_t ago)
{
    struct net_address a;
    bool found = false;
    if (!slot_onion_address(host, 8033, &a))
        return false;
    zcl_mutex_lock(&cm->manager.addrman.cs);
    for (int i = 0; i < cm->manager.addrman.id_count; i++) {
        struct addr_info *info = &cm->manager.addrman.entries[i];
        if (!info->used || !net_addr_eq(&info->addr.svc.addr, &a.svc.addr))
            continue;
        info->attempts = attempts;
        info->last_try = (int64_t)platform_time_wall_time_t() - ago;
        found = true;
    }
    zcl_mutex_unlock(&cm->manager.addrman.cs);
    return found;
}

static int slot_row_attempts(struct connman *cm, const char *host)
{
    struct net_address a;
    struct addr_info info;
    if (!slot_onion_address(host, 8033, &a) ||
        !addrman_find_info(&cm->manager.addrman, &a.svc, &info))
        return -1;
    return info.attempts;
}

struct slot_fx {
    struct connman cm;
    bool ok;
    int failures;
    struct connman_dial_candidate out[8];
    size_t n;
};

static void slot_fx_open(struct slot_fx *fx)
{
    fx->ok = slot_make_hosts() && slot_init(&fx->cm);
}

static void slot_fx_close(struct slot_fx *fx)
{
    tor_integration_set_dial_ready_for_test(false);
    if (fx->ok)
        connman_free(&fx->cm);
    fx->ok = false;
}

static void slot_walk_boot(struct slot_fx *fx)
{
    struct chain_params params = *chain_params_get();
    params.nOnionSeeds = 0;
    fx->cm.params = &params;
    slot_add_healthy(&fx->cm, &fx->ok, 4);
    tor_integration_set_dial_ready_for_test(false);
    slot_report("onion walk is not due while Tor cannot dial",
                fx->ok && !connman_onion_walk_due(&fx->cm), &fx->failures);
    tor_integration_set_dial_ready_for_test(true);
    slot_report("onion walk is due with 4 healthy clearnet peers once Tor "
                "can dial",
                fx->ok && connman_onion_walk_due(&fx->cm), &fx->failures);
    bool first = fx->ok && connman_onion_walk_once(&fx->cm);
    bool second = fx->ok && connman_onion_walk_once(&fx->cm);
    slot_report("onion walk runs once and not again",
                first && !second &&
                    atomic_load(&fx->cm.onion_walk_runs) == 1,
                &fx->failures);
    fx->cm.params = chain_params_get();
}

static void slot_walk_rows(struct slot_fx *fx)
{
    fx->ok = fx->ok && slot_add_onion_row(&fx->cm, slot_host_b);
    slot_report("onion walk is not due while a dialable onion row exists",
                fx->ok && !connman_onion_walk_due(&fx->cm), &fx->failures);
    fx->ok = fx->ok && slot_set_row(&fx->cm, slot_host_b, 4, 5);
    slot_report("onion walk is due when every onion row is cooling down",
                fx->ok && connman_onion_walk_due(&fx->cm), &fx->failures);
}

static int slot_walk_once(void)
{
    struct slot_fx fx = { .ok = false };
    char home_dir[256];
    char *home = getenv("HOME") ? strdup(getenv("HOME")) : NULL;
    slot_fx_open(&fx);
    fx.ok = fx.ok && test_mkdtemp(home_dir, sizeof(home_dir), "onion_walk") &&
            setenv("HOME", home_dir, 1) == 0;
    slot_walk_boot(&fx);
    slot_fx_close(&fx);
    slot_fx_open(&fx);
    tor_integration_set_dial_ready_for_test(true);
    slot_walk_rows(&fx);
    slot_fx_close(&fx);
    if (home) {
        setenv("HOME", home, 1);
        free(home);
    }
    return fx.failures;
}

static struct p2p_node *slot_add_onion_peer(struct connman *cm)
{
    struct net_address a;
    if (!slot_onion_address(slot_host_c, 8033, &a))
        return NULL;
    struct p2p_node *node = p2p_node_create(&cm->manager, ZCL_INVALID_SOCKET,
                                            &a, "onion-test", false);
    if (!node)
        return NULL;
    node->state = PEER_HANDSHAKE_COMPLETE;
    cm->manager.nodes[cm->manager.num_nodes++] = node;
    return node;
}

static size_t slot_count_tor(const struct connman_dial_candidate *c, size_t n)
{
    size_t k = 0;
    for (size_t i = 0; i < n; i++)
        k += net_addr_is_tor(&c[i].addr.svc.addr) ? 1u : 0u;
    return k;
}

static const uint16_t slot_ports[8] = { 20022, 20023, 20024, 20025, 20026,
                                        20027, 20028, 8033 };

static bool slot_queue_hints(struct connman *cm, size_t count)
{
    bool ok = true;
    for (size_t i = 0; i < count; i++) {
        struct net_address hint;
        test_set_ipv4(&hint, 127, 0, 0, 1, slot_ports[i]);
        ok = ok && connman_queue_dht_hint(cm, &hint);
    }
    return ok;
}

/* Injected monotonic clock for the 240 s gap; the wall clock stays real. */
static int64_t slot_mono_us;

static int64_t slot_clock_mono(void *user)
{
    (void)user;
    return slot_mono_us;
}

static int64_t slot_wall_offset;

static int64_t slot_clock_wall(void *user)
{
    (void)user;
    return (int64_t)time(NULL) + slot_wall_offset;
}

static struct platform_clock_source slot_clock = {
    .monotonic_us = slot_clock_mono,
    .wall_unix = slot_clock_wall,
};

/* One gather and its shape: `want` candidates of which `tor` are onions. */
static void slot_step(struct slot_fx *fx, const char *name, size_t max,
                      size_t want, size_t tor)
{
    fx->n = fx->ok ? connman_gather_dial_candidates(&fx->cm, fx->out, max) : 0;
    slot_report(name, fx->ok && fx->n == want &&
                          slot_count_tor(fx->out, fx->n) == tor,
                &fx->failures);
}

static bool slot_queue_hint_port(struct connman *cm, uint16_t port)
{
    struct net_address hint;
    test_set_ipv4(&hint, 127, 0, 0, 1, port);
    return connman_queue_dht_hint(cm, &hint);
}

/* Batch shape with Tor off and on, the failure backoff, and the 240 s gap. */
static int slot_dialer_batch(void)
{
    struct slot_fx fx = { .ok = false };
    slot_fx_open(&fx);
    slot_mono_us = 5000LL * 1000000LL;
    platform_clock_set_source(&slot_clock);
    fx.ok = fx.ok && slot_add_onion_row(&fx.cm, slot_host_b) &&
            slot_queue_hints(&fx.cm, 8);
    slot_add_healthy(&fx.cm, &fx.ok, 4);
    tor_integration_set_dial_ready_for_test(false);
    slot_step(&fx, "Tor not ready: batch is clearnet only, as before", 2, 2, 0);
    tor_integration_set_dial_ready_for_test(true);
    slot_step(&fx, "Tor ready: batch is one onion plus clearnet up to max-1",
              4, 4, 1);
    slot_report("the onion is appended last, on its P2P port",
                fx.ok && net_addr_is_tor(&fx.out[3].addr.svc.addr) &&
                    fx.out[3].addr.svc.port == 8033, &fx.failures);
    slot_step(&fx, "the onion is charged at pick time; its cooldown returns the slot",
              2, 2, 0);
    fx.ok = fx.ok && slot_set_row(&fx.cm, slot_host_b, 1, 121);
    slot_step(&fx, "a row past its 60 s cooldown is not re-offered inside "
                   "240 s", 1, 1, 0);
    /* One clearnet hint is waiting: a closed gap yields [hint], an open
     * gap yields [onion]. */
    fx.ok = fx.ok && slot_queue_hint_port(&fx.cm, 18033);
    slot_mono_us += 241LL * 1000000LL;
    slot_step(&fx, "after 240 s the slot is offered ahead of a waiting hint",
              1, 1, 1);
    platform_clock_clear_source();
    slot_fx_close(&fx);
    return fx.failures;
}

/* A wall-clock step back after an offer must not hold the slot closed: the
 * gap is measured on the monotonic clock. */
static int slot_wall_step_back(void)
{
    struct slot_fx fx = { .ok = false };
    slot_fx_open(&fx);
    slot_mono_us = 5000LL * 1000000LL;
    slot_wall_offset = 0;
    platform_clock_set_source(&slot_clock);
    tor_integration_set_dial_ready_for_test(true);
    fx.ok = fx.ok && slot_add_onion_row(&fx.cm, slot_host_b);
    slot_add_healthy(&fx.cm, &fx.ok, 4);
    slot_step(&fx, "wall step back: the first offer goes to the onion", 1, 1, 1);
    slot_wall_offset = -86400;
    fx.ok = fx.ok && slot_set_row(&fx.cm, slot_host_b, 1, 121) &&
            slot_queue_hint_port(&fx.cm, 18033);
    slot_mono_us += 241LL * 1000000LL;
    slot_step(&fx, "wall clock stepped back a day: the slot reopens after "
                   "240 s of monotonic time", 1, 1, 1);
    platform_clock_clear_source();
    slot_wall_offset = 0;
    slot_fx_close(&fx);
    return fx.failures;
}

static int slot_gate_floor(void)
{
    struct slot_fx fx = { .ok = false };
    slot_fx_open(&fx);
    tor_integration_set_dial_ready_for_test(true);
    fx.ok = fx.ok && slot_add_onion_row(&fx.cm, slot_host_b) &&
            slot_queue_hints(&fx.cm, 3);
    slot_add_healthy(&fx.cm, &fx.ok, 2);
    slot_step(&fx, "2 healthy peers (below the floor) at width one: clearnet "
                   "only", 1, 1, 0);
    slot_fx_close(&fx);
    return fx.failures;
}

static int slot_gate_onion_peer(void)
{
    struct slot_fx fx = { .ok = false };
    slot_fx_open(&fx);
    tor_integration_set_dial_ready_for_test(true);
    fx.ok = fx.ok && slot_add_onion_row(&fx.cm, slot_host_b) &&
            slot_queue_hints(&fx.cm, 3);
    slot_add_healthy(&fx.cm, &fx.ok, 4);
    slot_step(&fx, "a width-one batch with 4 healthy peers goes to the onion",
              1, 1, 1);
    fx.ok = fx.ok && slot_add_onion_peer(&fx.cm) &&
            slot_add_onion_row(&fx.cm, slot_host_d);
    atomic_store(&fx.cm.onion_slot_last_ts, 0);
    slot_step(&fx, "with an outbound onion peer the slot is not reserved",
              2, 2, 0);
    slot_fx_close(&fx);
    return fx.failures;
}

static int slot_gate_ordinary_draw(void)
{
    struct slot_fx fx = { .ok = false };
    slot_fx_open(&fx);
    tor_integration_set_dial_ready_for_test(true);
    fx.ok = fx.ok && slot_add_onion_row(&fx.cm, slot_host_b);
    slot_step(&fx, "bootstrap (0 healthy peers): the ordinary draw skips "
                   "onions", 1, 0, 0);
    slot_report("bootstrap: the skipped onion is not charged an attempt",
                fx.ok && slot_row_attempts(&fx.cm, slot_host_b) == 0,
                &fx.failures);
    slot_fx_close(&fx);

    slot_fx_open(&fx);
    fx.ok = fx.ok && slot_add_onion_row(&fx.cm, slot_host_b);
    slot_add_healthy(&fx.cm, &fx.ok, 4);
    slot_step(&fx, "Tor not ready: the ordinary draw skips onions", 1, 0, 0);
    slot_report("Tor not ready: the skipped onion is not charged an attempt",
                fx.ok && slot_row_attempts(&fx.cm, slot_host_b) == 0,
                &fx.failures);
    slot_fx_close(&fx);
    return fx.failures;
}

static int slot_dialer_gates(void)
{
    return slot_gate_floor() + slot_gate_onion_peer() +
           slot_gate_ordinary_draw();
}

static size_t slot_count_zero_ip(const struct net_address *a, size_t n)
{
    static const uint8_t zeros[16];
    size_t k = 0;
    for (size_t i = 0; i < n; i++)
        k += memcmp(a[i].svc.addr.ip, zeros, 16) == 0 ? 1u : 0u;
    return k;
}

static size_t slot_count_tor_addrs(const struct net_address *a, size_t n)
{
    size_t k = 0;
    for (size_t i = 0; i < n; i++)
        k += net_addr_is_tor(&a[i].svc.addr) ? 1u : 0u;
    return k;
}

static void slot_fill_mixed_addrman(struct connman *cm, bool *ok)
{
    struct net_addr src;
    net_addr_init(&src);
    for (uint8_t i = 0; *ok && i < 120; i++) {
        struct net_address a;
        test_set_ipv4(&a, (uint8_t)(20 + i / 8), (uint8_t)(i * 7), 1, 9, 8033);
        a.nServices = NODE_NETWORK;
        a.nTime = (uint32_t)platform_time_wall_time_t();
        (void)addrman_add(&cm->manager.addrman, &a, &src, 0);
    }
    for (uint8_t i = 0; *ok && i < 60; i++) {
        uint8_t pub[32];
        char host[ONION_V3_ADDRESS_LEN + 1];
        struct net_address a;
        memset(pub, (int)(0x40 + i), sizeof(pub));
        *ok = onion_v3_address_from_pubkey(pub, host) &&
              slot_onion_address(host, 8033, &a);
        a.nTime = (uint32_t)platform_time_wall_time_t();
        (void)addrman_add(&cm->manager.addrman, &a, &src, 0);
    }
}

/* Directory rows reach addrman with a usable nTime: not terrible, sampled by
 * the census, and eligible for the slot. */
static bool slot_apply_hints(struct connman *cm, const char *src, int first,
                             const int64_t last_seen[4])
{
    char body[1024];
    size_t off = (size_t)snprintf(body, sizeof(body), "{\"nodes\":[");
    for (int i = 0; i < 8; i++) {
        char host[ONION_V3_ADDRESS_LEN + 1];
        char seen[48] = "";
        uint8_t pub[32];
        memset(pub, first + i, sizeof(pub));
        if (!onion_v3_address_from_pubkey(pub, host))
            return false;
        if (i < 4 && last_seen[i] != 0)
            snprintf(seen, sizeof(seen), ",\"last_seen\":%lld",
                     (long long)last_seen[i]);
        off += (size_t)snprintf(body + off, sizeof(body) - off,
                                "%s{\"onion\":\"%s\",\"port\":8033%s}",
                                i ? "," : "", host, seen);
    }
    off += (size_t)snprintf(body + off, sizeof(body) - off, "]}");
    return connman_apply_onion_seed_directory_for_test(
               cm, src, (const uint8_t *)body, off) == 0;
}

static size_t slot_nonterrible_rows(struct connman *cm)
{
    struct addr_man *am = &cm->manager.addrman;
    int64_t now = GetAdjustedTime();
    size_t n = 0;
    zcl_mutex_lock(&am->cs);
    for (int i = 0; i < am->id_count; i++) {
        const struct addr_info *info = &am->entries[i];
        if (!info->used || !net_addr_is_tor(&info->addr.svc.addr) ||
            addr_info_is_terrible(info, now))
            continue;
        n++;
    }
    zcl_mutex_unlock(&am->cs);
    return n;
}

/* nTime of the directory row generated from public-key byte `seed`, or -1. */
static int64_t slot_row_ntime(struct connman *cm, uint8_t seed)
{
    uint8_t pub[32];
    char host[ONION_V3_ADDRESS_LEN + 1];
    struct net_address a;
    struct addr_info info;
    memset(pub, seed, sizeof(pub));
    if (!onion_v3_address_from_pubkey(pub, host) ||
        !slot_onion_address(host, 8033, &a) ||
        !addrman_find_info(&cm->manager.addrman, &a.svc, &info))
        return -1;
    return (int64_t)info.addr.nTime;
}

static bool slot_near(int64_t value, int64_t want)
{
    return value >= want - 5 && value <= want + 5;
}

static int slot_hint_times(void)
{
    struct slot_fx fx = { .ok = false };
    int64_t now = GetAdjustedTime();
    const int64_t seen[4] = { now - 3600, 0, now + 3 * 24 * 3600,
                              now - 90LL * 24 * 3600 };
    slot_fx_open(&fx);
    tor_integration_set_dial_ready_for_test(true);
    fx.ok = fx.ok && slot_apply_hints(&fx.cm, slot_host_a, 0x50, seen);
    slot_add_healthy(&fx.cm, &fx.ok, 4);
    slot_report("directory hints are not terrible, whatever their last_seen",
                fx.ok && slot_nonterrible_rows(&fx.cm) == 8,
                &fx.failures);
    slot_report("last_seen is kept when recent and clamped to now when future",
                fx.ok && slot_near(slot_row_ntime(&fx.cm, 0x50), now - 3600) &&
                    slot_near(slot_row_ntime(&fx.cm, 0x52), now),
                &fx.failures);
    slot_report("no last_seen is stamped 5 days old; a 90-day-old one is "
                "clamped to the horizon",
                fx.ok &&
                    slot_near(slot_row_ntime(&fx.cm, 0x51),
                              now - 5 * 24 * 3600) &&
                    slot_near(slot_row_ntime(&fx.cm, 0x53),
                              now - 29 * 24 * 3600), &fx.failures);
    static struct net_address out[ADDRMAN_GETADDR_MAX];
    size_t census = fx.ok ? addrman_get_census(&fx.cm.manager.addrman, out,
                                               ADDRMAN_GETADDR_MAX) : 0;
    slot_report("the crawler census returns directory onion rows",
                census > 0 && slot_count_tor_addrs(out, census) == census,
                &fx.failures);
    slot_step(&fx, "the onion slot can pick a directory row", 1, 1, 1);
    slot_fx_close(&fx);
    return fx.failures;
}

static int slot_no_gossip(void)
{
    int failures = 0;
    struct connman cm;
    bool ok = slot_make_hosts() && slot_init(&cm);
    slot_fill_mixed_addrman(&cm, &ok);
    static struct net_address out[ADDRMAN_GETADDR_MAX];
    size_t got = ok ? addrman_get_addr(&cm.manager.addrman, out,
                                       ADDRMAN_GETADDR_MAX) : 0;
    slot_report("addr gossip from an addrman holding torv3 rows has no "
                ":: entries",
                ok && slot_onion_rows(&cm) > 0 && got > 0 &&
                    slot_count_zero_ip(out, got) == 0 &&
                    slot_count_tor_addrs(out, got) == 0, &failures);
    size_t census = ok ? addrman_get_census(&cm.manager.addrman, out,
                                            ADDRMAN_GETADDR_MAX) : 0;
    slot_report("the crawler census sample still includes onion rows",
                ok && census > 0 && slot_count_tor_addrs(out, census) > 0,
                &failures);
    if (ok)
        connman_free(&cm);
    return failures;
}

int check_connman_onion_slot(void)
{
    int failures = 0;
    failures += slot_directory_hints();
    failures += slot_walk_once();
    failures += slot_dialer_batch();
    failures += slot_wall_step_back();
    failures += slot_dialer_gates();
    failures += slot_no_gossip();
    failures += slot_hint_times();
    return failures;
}
