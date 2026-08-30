/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the anchor-peers subsystem (lib/net/anchor_peers.c) and the
 * anchors-first parallel-dial candidate selection + the peer-floor
 * single-source lint gate.
 *
 *   1. save → load round-trip (values survive a restart).
 *   2. empty-set round-trip.
 *   3. corrupt-body quarantine (a tampered anchors.dat is renamed aside and
 *      the loaded set is empty — a bad file never steers outbound selection).
 *   4. missing file → EMPTY (never blocks boot).
 *   5. connman_collect_healthy_anchors excludes inbound / disconnecting /
 *      pre-handshake / feeler / non-NODE_NETWORK peers.
 *   6. connman_gather_dial_candidates returns ANCHOR candidates BEFORE any
 *      addrman pick (anchors-first ordering, unit-level).
 *   7. (ZCL_TESTING) the check-peer-floor-single-source lint gate TRIPS on a
 *      planted floor-literal fixture and PASSES on a clean one.
 *
 * All file I/O is local (./test-tmp), no network, no SQLite.
 */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"
#include "coins/undo.h"
#include "net/anchor_peers.h"
#include "net/connman.h"
#include "net/addrman.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "test/setup_result.h"

#define ANCHOR_SCRATCH_ROOT "./test-tmp"

/* ── scratch dir helpers (mirrors test_addrman_integrity) ─────────────── */

static void anchor_tmp_dir(char *out, size_t cap, const char *tag)
{
    mkdir(ANCHOR_SCRATCH_ROOT, 0755);
    snprintf(out, cap, ANCHOR_SCRATCH_ROOT "/anchor_%d_%s", (int)getpid(), tag);
    mkdir(out, 0755);
}

static bool anchor_file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static void anchor_cleanup(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *ent;
    char fpath[1024];
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.' &&
            (ent->d_name[1] == '\0' ||
             (ent->d_name[1] == '.' && ent->d_name[2] == '\0')))
            continue;
        snprintf(fpath, sizeof(fpath), "%s/%s", dir, ent->d_name);
        unlink(fpath);
    }
    closedir(d);
    rmdir(dir);
}

static void anchor_set_ipv4(struct net_addr *a, uint8_t o1, uint8_t o2,
                            uint8_t o3, uint8_t o4)
{
    net_addr_init(a);
    unsigned char ip4[4] = { o1, o2, o3, o4 };
    net_addr_set_ipv4(a, ip4);
}

static bool anchor_eq(const struct anchor_peer *x, const struct anchor_peer *y)
{
    return net_addr_eq(&x->addr, &y->addr) &&
           x->port == y->port &&
           x->services == y->services &&
           x->last_height == y->last_height &&
           x->last_success == y->last_success;
}

/* ── connman test-peer helper (mirrors test_connman_addnode_fallback) ─── */

static struct p2p_node *anchor_add_peer(struct connman *cm,
                                        uint8_t o3, uint8_t o4,
                                        enum peer_state state,
                                        bool inbound, bool disconnect,
                                        bool feeler, uint64_t services)
{
    if (!cm) return NULL;
    if (!cm->manager.nodes) {
        cm->manager.nodes = zcl_calloc(16, sizeof(*cm->manager.nodes),
                                       "anchor_test_nodes");
        cm->manager.nodes_cap = 16;
    }
    struct net_address addr;
    net_address_init(&addr);
    unsigned char ip4[4] = { 203, 0, o3, o4 };
    net_addr_set_ipv4(&addr.svc.addr, ip4);
    addr.svc.port = 8033;
    struct p2p_node *n = p2p_node_create(&cm->manager, ZCL_INVALID_SOCKET,
                                         &addr, "anchor-test", inbound);
    if (!n) return NULL;
    n->state = state;
    n->disconnect = disconnect;
    n->is_feeler = feeler;
    n->services = services;
    n->starting_height = 3100000 + o4;
    n->time_connected = 1700000000 + o4;
    cm->manager.nodes[cm->manager.num_nodes++] = n;
    return n;
}

#ifdef ZCL_TESTING
/* Fork+exec the floor lint gate in isolated selftest mode; return exit code. */
#if !defined(_WIN32)
#include <sys/wait.h>
#endif
#include <fcntl.h>
static int run_floor_gate_selftest(const char *fixture_path)
{
#if defined(_WIN32)
    /* No fork()/execl on Windows: CreateProcess through the MSYS2 sh (the
     * lint gate is POSIX shell); the env is inherited across the spawn. */
    if (_putenv_s("ZCL_PEER_FLOOR_SELFTEST", "1") != 0 ||
        _putenv_s("ZCL_PEER_FLOOR_SELFTEST_FILE", fixture_path) != 0)
        return -1;
    const char *const argv[] = {
        "sh", "tools/lint/check_peer_floor_single_source.sh", NULL,
    };
    int rc = test_spawn_argv_wait(argv);
    _putenv_s("ZCL_PEER_FLOOR_SELFTEST", "");
    _putenv_s("ZCL_PEER_FLOOR_SELFTEST_FILE", "");
    return rc;
#else
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int fd = open("/dev/null", O_WRONLY);
        if (fd >= 0) { dup2(fd, STDOUT_FILENO); dup2(fd, STDERR_FILENO); close(fd); }
        setenv("ZCL_PEER_FLOOR_SELFTEST", "1", 1);
        setenv("ZCL_PEER_FLOOR_SELFTEST_FILE", fixture_path, 1);
        execl("tools/lint/check_peer_floor_single_source.sh",
              "check_peer_floor_single_source.sh", (char *)NULL);
        _exit(127);
    }
    int rc = 0;
    while (waitpid(pid, &rc, 0) < 0) { if (errno != EINTR) return -1; }
    if (WIFEXITED(rc)) return WEXITSTATUS(rc);
    return -1;
#endif
}
#endif

int test_anchor_peers(void);

int test_anchor_peers(void)
{
    int failures = 0;
    printf("\n=== anchor peers tests ===\n");

    /* ── 1. round-trip ─────────────────────────────────────────── */
    printf("anchor_peers: save/load round-trip... ");
    {
        char dir[256]; anchor_tmp_dir(dir, sizeof(dir), "roundtrip");
        struct anchor_peer_set in;
        memset(&in, 0, sizeof(in));
        in.count = 3;
        anchor_set_ipv4(&in.peers[0].addr, 203, 0, 113, 7);
        in.peers[0].port = 8033; in.peers[0].services = 1;
        in.peers[0].last_height = 3117000; in.peers[0].last_success = 1700000001;
        anchor_set_ipv4(&in.peers[1].addr, 198, 51, 100, 9);
        in.peers[1].port = 8033; in.peers[1].services = 5;
        in.peers[1].last_height = 3117005; in.peers[1].last_success = 1700000050;
        anchor_set_ipv4(&in.peers[2].addr, 192, 0, 2, 3);
        in.peers[2].port = 18033; in.peers[2].services = 9;
        in.peers[2].last_height = -1; in.peers[2].last_success = 0;

        bool saved = anchor_peers_save(dir, &in).ok;

        struct anchor_peer_set out;
        enum anchor_load_status st = anchor_peers_load(dir, &out);
        bool ok = saved && st == ANCHOR_LOAD_OK && out.count == in.count;
        for (size_t i = 0; ok && i < in.count; i++)
            ok = ok && anchor_eq(&in.peers[i], &out.peers[i]);

        anchor_cleanup(dir);
        if (ok) printf("OK\n");
        else { printf("FAIL (saved=%d st=%s count=%zu)\n",
                      saved, anchor_load_status_name(st), out.count); failures++; }
    }

    /* ── 2. empty-set round-trip ───────────────────────────────── */
    printf("anchor_peers: empty set round-trip... ");
    {
        char dir[256]; anchor_tmp_dir(dir, sizeof(dir), "empty");
        struct anchor_peer_set in; memset(&in, 0, sizeof(in)); in.count = 0;
        bool saved = anchor_peers_save(dir, &in).ok;
        struct anchor_peer_set out;
        enum anchor_load_status st = anchor_peers_load(dir, &out);
        bool ok = saved && st == ANCHOR_LOAD_OK && out.count == 0;
        anchor_cleanup(dir);
        if (ok) printf("OK\n");
        else { printf("FAIL (saved=%d st=%s)\n", saved, anchor_load_status_name(st)); failures++; }
    }

    /* ── 3. corrupt body → quarantine ──────────────────────────── */
    printf("anchor_peers: corrupt body is quarantined... ");
    {
        char dir[256]; anchor_tmp_dir(dir, sizeof(dir), "quarantine");
        struct anchor_peer_set in; memset(&in, 0, sizeof(in));
        in.count = 2;
        anchor_set_ipv4(&in.peers[0].addr, 203, 0, 113, 1);
        in.peers[0].port = 8033; in.peers[0].services = 1;
        anchor_set_ipv4(&in.peers[1].addr, 198, 51, 100, 1);
        in.peers[1].port = 8033; in.peers[1].services = 1;
        ZCL_TEST_SETUP(anchor_peers_save(dir, &in));

        /* Flip a byte in the body without updating the sidecar. */
        char body[1024];
        snprintf(body, sizeof(body), "%s/anchors.dat", dir);
        FILE *f = fopen(body, "r+b");
        bool tampered = false;
        if (f) { fseek(f, 3, SEEK_SET); uint8_t x = 0xFF; fwrite(&x, 1, 1, f); fclose(f); tampered = true; }

        struct anchor_peer_set out;
        enum anchor_load_status st = anchor_peers_load(dir, &out);
        bool quarantined = (st == ANCHOR_LOAD_QUARANTINED) && out.count == 0;
        bool body_gone = !anchor_file_exists(body);

        bool renamed = false;
        DIR *d = opendir(dir);
        if (d) { struct dirent *e;
            while ((e = readdir(d))) if (strstr(e->d_name, ".corrupt.")) { renamed = true; break; }
            closedir(d); }

        anchor_cleanup(dir);
        if (tampered && quarantined && body_gone && renamed) printf("OK\n");
        else { printf("FAIL (tampered=%d st=%s body_gone=%d renamed=%d)\n",
                      tampered, anchor_load_status_name(st), body_gone, renamed); failures++; }
    }

    /* ── 4. missing file → EMPTY ───────────────────────────────── */
    printf("anchor_peers: missing file loads empty... ");
    {
        char dir[256]; anchor_tmp_dir(dir, sizeof(dir), "missing");
        struct anchor_peer_set out;
        memset(&out, 0xAB, sizeof(out)); /* poison to prove it's reset */
        enum anchor_load_status st = anchor_peers_load(dir, &out);
        bool ok = st == ANCHOR_LOAD_EMPTY && out.count == 0;
        anchor_cleanup(dir);
        if (ok) printf("OK\n");
        else { printf("FAIL (st=%s count=%zu)\n", anchor_load_status_name(st), out.count); failures++; }
    }

    /* ── 5. collect_healthy_anchors filters the node table ─────── */
    printf("anchor_peers: collect_healthy_anchors filters... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm; struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        /* 2 genuinely-healthy outbound peers … */
        anchor_add_peer(&cm, 113, 10, PEER_HANDSHAKE_COMPLETE, false, false, false, NODE_NETWORK);
        anchor_add_peer(&cm, 114, 11, PEER_HANDSHAKE_COMPLETE, false, false, false, NODE_NETWORK);
        /* … and four that must be EXCLUDED: */
        anchor_add_peer(&cm, 115, 12, PEER_HANDSHAKE_COMPLETE, true,  false, false, NODE_NETWORK); /* inbound */
        anchor_add_peer(&cm, 116, 13, PEER_HANDSHAKE_COMPLETE, false, true,  false, NODE_NETWORK); /* disconnecting */
        anchor_add_peer(&cm, 117, 14, PEER_CONNECTING,         false, false, false, NODE_NETWORK); /* pre-handshake */
        anchor_add_peer(&cm, 118, 15, PEER_HANDSHAKE_COMPLETE, false, false, true,  NODE_NETWORK); /* feeler */
        anchor_add_peer(&cm, 119, 16, PEER_HANDSHAKE_COMPLETE, false, false, false, 0);            /* not NODE_NETWORK */

        struct anchor_peer_set set;
        connman_collect_healthy_anchors(&cm, &set);
        ok = ok && set.count == 2;
        /* both collected anchors carry NODE_NETWORK and a real height */
        for (size_t i = 0; ok && i < set.count; i++)
            ok = ok && (set.peers[i].services & NODE_NETWORK) != 0 &&
                       set.peers[i].port == 8033;
        if (ok) printf("OK\n");
        else { printf("FAIL (collected=%zu, want 2)\n", set.count); failures++; }
    }

    /* ── 6. anchors are gathered BEFORE addrman picks ──────────── */
    printf("anchor_peers: gather returns anchors before addrman... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *params = chain_params_get();
        struct connman cm; struct node_signals sigs;
        memset(&sigs, 0, sizeof(sigs));
        bool ok = connman_init(&cm, params, &sigs);

        /* Load 3 anchors (distinct /16s so the diversity tally passes). */
        memset(&cm.anchors, 0, sizeof(cm.anchors));
        memset(cm.anchors_tried, 0, sizeof(cm.anchors_tried));
        cm.anchors.count = 3;
        anchor_set_ipv4(&cm.anchors.peers[0].addr, 203, 0, 113, 21);
        cm.anchors.peers[0].port = 8033; cm.anchors.peers[0].services = NODE_NETWORK;
        anchor_set_ipv4(&cm.anchors.peers[1].addr, 198, 51, 100, 22);
        cm.anchors.peers[1].port = 8033; cm.anchors.peers[1].services = NODE_NETWORK;
        anchor_set_ipv4(&cm.anchors.peers[2].addr, 192, 0, 2, 23);
        cm.anchors.peers[2].port = 8033; cm.anchors.peers[2].services = NODE_NETWORK;

        /* Populate addrman with a couple of distinct-/16 addresses. */
        for (int i = 0; i < 4; i++) {
            struct net_address a; net_address_init(&a);
            unsigned char ip4[4] = { (unsigned char)(11 + i), 22, 33, (unsigned char)(40 + i) };
            net_addr_set_ipv4(&a.svc.addr, ip4);
            a.svc.port = 8033; a.nServices = NODE_NETWORK;
            struct net_addr src; net_addr_init(&src);
            addrman_add(&cm.manager.addrman, &a, &src, 0);
        }

        struct connman_dial_candidate batch[8];
        size_t n = connman_gather_dial_candidates(&cm, batch, 8);

        /* The first 3 must be ANCHOR, matching the loaded anchors in order,
         * and NO anchor may appear after a non-anchor candidate. */
        size_t anchor_count = 0;
        bool seen_nonanchor = false;
        bool order_ok = true;
        for (size_t i = 0; i < n; i++) {
            if (batch[i].source == CONNMAN_TARGET_ANCHOR) {
                if (seen_nonanchor) order_ok = false;  /* anchor after addrman */
                anchor_count++;
            } else {
                seen_nonanchor = true;
            }
        }
        ok = ok && anchor_count == 3 && order_ok;
        for (size_t i = 0; ok && i < 3; i++)
            ok = ok && batch[i].source == CONNMAN_TARGET_ANCHOR &&
                       net_addr_eq(&batch[i].addr.svc.addr,
                                   &cm.anchors.peers[i].addr);

        /* A second gather returns NO anchors (each got its one attempt). */
        struct connman_dial_candidate batch2[8];
        size_t n2 = connman_gather_dial_candidates(&cm, batch2, 8);
        for (size_t i = 0; ok && i < n2; i++)
            ok = ok && batch2[i].source != CONNMAN_TARGET_ANCHOR;

        if (ok) printf("OK\n");
        else { printf("FAIL (n=%zu anchors=%zu order_ok=%d)\n", n, anchor_count, order_ok); failures++; }
    }

#ifdef ZCL_TESTING
    /* ── 7. floor lint gate trips on a planted literal, passes clean ── */
    printf("anchor_peers: floor lint gate trips then passes... ");
    {
        char dir[256]; anchor_tmp_dir(dir, sizeof(dir), "floorlint");
        char bad[512], good[512];
        snprintf(bad, sizeof(bad), "%s/bad_fixture.c", dir);
        snprintf(good, sizeof(good), "%s/good_fixture.c", dir);

        FILE *fb = fopen(bad, "w");
        if (fb) { fprintf(fb, "#define PEER_FLOOR_MIN 3\n"); fclose(fb); }
        FILE *fg = fopen(good, "w");
        if (fg) { fprintf(fg, "int x = ZCL_PEER_FLOOR_HEALTHY;\n"); fclose(fg); }

        int rc_bad = run_floor_gate_selftest(bad);
        int rc_good = run_floor_gate_selftest(good);
        bool ok = (rc_bad == 1) && (rc_good == 0);
        anchor_cleanup(dir);
        if (ok) printf("OK\n");
        else { printf("FAIL (rc_bad=%d want 1, rc_good=%d want 0)\n", rc_bad, rc_good); failures++; }
    }
#endif

    return failures + ZCL_TEST_SETUP_FAILURES();
}
