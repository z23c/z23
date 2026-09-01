/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Net-robustness bootstrap-surface tests:
 *   1. addnode_file_parse_line() / addnode_file_load() (core/modules/net/src/addnode_file.c)
 *      — pure line parsing plus the pedantic "bad lines skipped with a log,
 *      not fatal" file-load contract.
 *   2. addrman save/load round-trip via connman_save_addrman()/
 *      connman_load_addrman() (core/modules/net/src/connman.c) across two independent
 *      connman instances sharing a datadir — proves known-good peers survive
 *      a restart. */

#include "test/test_core.h"
#include "net/connman.h"

#include "net/addnode_file.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define NBOOT_CHECK(name, expr) do {                                  \
    printf("net_bootstrap: %s... ", (name));                          \
    if (expr) { printf("OK\n"); }                                     \
    else { printf("FAIL\n"); failures++; }                            \
} while (0)

static void bootstrap_set_ipv4(struct net_address *addr,
                               uint8_t a, uint8_t b, uint8_t c, uint8_t d,
                               uint16_t port)
{
    net_address_init(addr);
    addr->svc.addr.ip[10] = 0xff;
    addr->svc.addr.ip[11] = 0xff;
    addr->svc.addr.ip[12] = a;
    addr->svc.addr.ip[13] = b;
    addr->svc.addr.ip[14] = c;
    addr->svc.addr.ip[15] = d;
    addr->svc.port = port;
}

struct captured_addnode {
    char host[256];
    uint16_t port;
};

static struct captured_addnode g_captured[16];
static int g_captured_count;

static void capture_addnode_cb(const char *host, uint16_t port, void *ctx)
{
    (void)ctx;
    if (g_captured_count >= 16)
        return;
    snprintf(g_captured[g_captured_count].host,
             sizeof(g_captured[g_captured_count].host), "%s", host);
    g_captured[g_captured_count].port = port;
    g_captured_count++;
}

int test_net_bootstrap(void)
{
    printf("\n=== net bootstrap-surface tests ===\n");
    int failures = 0;

    /* ── addnode_file_parse_line: pure cases ─────────────────────── */
    {
        char host[64];
        uint16_t port;

        port = 999;
        NBOOT_CHECK("parse: host:port",
                    addnode_file_parse_line("203.0.113.7:9033\n", host,
                                             sizeof(host), &port) &&
                    strcmp(host, "203.0.113.7") == 0 && port == 9033);

        port = 999;
        NBOOT_CHECK("parse: host with no port leaves port 0",
                    addnode_file_parse_line("example.com\n", host,
                                             sizeof(host), &port) &&
                    strcmp(host, "example.com") == 0 && port == 0);

        port = 999;
        NBOOT_CHECK("parse: blank line rejected (not a parse result)",
                    !addnode_file_parse_line("\n", host, sizeof(host), &port));

        port = 999;
        NBOOT_CHECK("parse: comment line rejected",
                    !addnode_file_parse_line("  # comment\n", host,
                                              sizeof(host), &port));

        port = 999;
        NBOOT_CHECK("parse: out-of-range port keeps whole token as host",
                    addnode_file_parse_line("host:99999999\n", host,
                                             sizeof(host), &port) &&
                    strcmp(host, "host:99999999") == 0 && port == 0);

        NBOOT_CHECK("parse: NULL args rejected",
                    !addnode_file_parse_line(NULL, host, sizeof(host), &port));

        {
            char oversized[400];
            memset(oversized, 'a', sizeof(oversized) - 1);
            oversized[sizeof(oversized) - 1] = '\0';
            port = 999;
            NBOOT_CHECK("parse: oversized token rejected as malformed",
                        !addnode_file_parse_line(oversized, host,
                                                  sizeof(host), &port));
        }

        NBOOT_CHECK("line_is_blank: comment/blank true, content false",
                    addnode_file_line_is_blank("  # x\n") &&
                    addnode_file_line_is_blank("\n") &&
                    addnode_file_line_is_blank("") &&
                    !addnode_file_line_is_blank("host.example.com\n"));
    }

    /* ── addnode_file_load: missing file is a clean no-op ────────── */
    {
        char tmpdir[] = "/tmp/zcl_addnode_file_XXXXXX";
        bool ok = mkdtemp(tmpdir) != NULL;
        char missing[600];
        snprintf(missing, sizeof(missing), "%s/does-not-exist", tmpdir);
        g_captured_count = 0;
        int rc = addnode_file_load(missing, capture_addnode_cb, NULL);
        ok = ok && rc == 0 && g_captured_count == 0;
        NBOOT_CHECK("load: missing file is a clean no-op (rc=0)", ok);
        char cmd[700];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
        (void)system(cmd);
    }

    /* ── addnode_file_load: pedantic parse — bad lines skipped, ────
     * good lines still load; never fatal. */
    {
        char tmpdir[] = "/tmp/zcl_addnode_file_XXXXXX";
        bool ok = mkdtemp(tmpdir) != NULL;
        char path[600];
        snprintf(path, sizeof(path), "%s/peers.txt", tmpdir);

        FILE *f = ok ? fopen(path, "w") : NULL;
        ok = ok && f != NULL;
        if (f) {
            fprintf(f, "# operator peers list\n");
            fprintf(f, "\n");
            fprintf(f, "host1.example.com:9033\n");
            fprintf(f, "host2.example.com\n");
            fprintf(f, "   \n");
            fprintf(f, "203.0.113.7:18033\n");
            /* One genuinely malformed line: a host longer than the 256-byte
             * host_out buffer, skipped with a logged warning, not fatal to
             * the rest of the file. Kept under addnode_file_load's 320-byte
             * fgets() line buffer so it reads as a single line (a longer
             * token would split across two fgets() calls and the tail
             * would parse as its own — unrelated — "line"). */
            char big[300];
            memset(big, 'z', sizeof(big) - 1);
            big[sizeof(big) - 1] = '\0';
            fprintf(f, "%s\n", big);
            fprintf(f, "203.0.113.8:8033\n");
            fclose(f);
        }

        g_captured_count = 0;
        int rc = ok ? addnode_file_load(path, capture_addnode_cb, NULL) : -1;
        ok = ok && rc == 4 && g_captured_count == 4;
        ok = ok && strcmp(g_captured[0].host, "host1.example.com") == 0 &&
             g_captured[0].port == 9033;
        ok = ok && strcmp(g_captured[1].host, "host2.example.com") == 0 &&
             g_captured[1].port == 0;
        ok = ok && strcmp(g_captured[2].host, "203.0.113.7") == 0 &&
             g_captured[2].port == 18033;
        ok = ok && strcmp(g_captured[3].host, "203.0.113.8") == 0 &&
             g_captured[3].port == 8033;
        NBOOT_CHECK("load: good lines loaded, one bad line skipped (not fatal)", ok);

        char cmd[700];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
        (void)system(cmd);
    }

    /* ── addrman save/load round-trip across independent connman
     * instances sharing a datadir: known-good peers survive a restart. */
    {
        char tmpdir[] = "/tmp/zcl_addrman_roundtrip_XXXXXX";
        bool ok = mkdtemp(tmpdir) != NULL;

        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();

        /* Both connman instances are always init'd and freed unconditionally
         * below — resource lifecycle must never hang off the accumulated
         * `ok` (an early false would otherwise skip connman_init(&cm2) and
         * leave it uninitialized garbage for the unconditional
         * connman_free(&cm2) at the end to dereference). `ok` gates
         * correctness assertions only. */
        struct connman cm1, cm2;
        struct node_signals sigs1, sigs2;
        memset(&sigs1, 0, sizeof(sigs1));
        memset(&sigs2, 0, sizeof(sigs2));
        ok = connman_init(&cm1, params, &sigs1) && ok;
        ok = connman_init(&cm2, params, &sigs2) && ok;
        cm1.datadir = tmpdir;
        cm2.datadir = tmpdir;

        /* Three DISTINCT allocated, routable /16 groups (Linode, and two other
         * public ranges). addrman buckets by network group with a per-instance
         * random key, so three addresses in the SAME group can collide into one
         * bucket slot and collapse 3->2 non-deterministically; distinct groups
         * keep all three regardless of the key. addrman_add rejects
         * non-routable ranges (e.g. the 203.0.113.0/24 documentation range used
         * elsewhere in this file) outright, which would make the test vacuous. */
        struct net_address a1, a2, a3;
        bootstrap_set_ipv4(&a1, 45, 33, 10, 1, 8033);
        bootstrap_set_ipv4(&a2, 66, 42, 20, 2, 8033);
        bootstrap_set_ipv4(&a3, 129, 153, 30, 3, 18033);
        struct net_addr src;
        net_addr_init(&src);
        ok = addrman_add(&cm1.manager.addrman, &a1, &src, 0) && ok;
        ok = addrman_add(&cm1.manager.addrman, &a2, &src, 0) && ok;
        ok = addrman_add(&cm1.manager.addrman, &a3, &src, 0) && ok;

        size_t saved_size = addrman_size(&cm1.manager.addrman);
        ok = ok && saved_size == 3;

        connman_save_addrman(&cm1);
        connman_load_addrman(&cm2);

        size_t loaded_size = addrman_size(&cm2.manager.addrman);
        ok = ok && loaded_size == saved_size;

        if (ok) {
            /* addrman_get_addr() deliberately samples only
             * ADDRMAN_GETADDR_MAX_PCT (23%) of the table (the GETADDR
             * wire-response anti-scraping cap) — with only 3 entries that
             * truncates to 0, so it can't prove membership here. Scan the
             * deserialized table's entries[] directly instead (whitebox,
             * matches addrman_consistency_check's own access pattern). */
            struct addr_man *am2 = &cm2.manager.addrman;
            bool found_a1 = false, found_a3 = false;
            for (size_t i = 0; i < am2->entries_cap; i++) {
                struct addr_info *ai = &am2->entries[i];
                if (!ai->used)
                    continue;
                if (net_addr_eq(&ai->addr.svc.addr, &a1.svc.addr) &&
                    ai->addr.svc.port == a1.svc.port)
                    found_a1 = true;
                if (net_addr_eq(&ai->addr.svc.addr, &a3.svc.addr) &&
                    ai->addr.svc.port == a3.svc.port)
                    found_a3 = true;
            }
            ok = ok && found_a1 && found_a3;
        }

        NBOOT_CHECK("addrman: save then load in a fresh connman recovers "
                    "every known-good peer", ok);

        connman_free(&cm1);
        connman_free(&cm2);
        char cmd[700];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
        (void)system(cmd);
    }

    return failures;
}
