/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

/* Regression test for the connect_node TOCTOU use-after-free fix
 * (find_node_by_service_locked): the find-and-ref of an existing peer now
 * happens atomically under cs_nodes, and disconnect-flagged nodes are skipped
 * so connect_node never re-refs a peer the socket sweep is about to free.
 *
 * Also covers the symmetric-ref contract (UAF + dedupe leak fix): connect_node
 * ALWAYS returns either NULL or a node with a +1 CALLER-owned ref —
 *   - the new-node path publishes the node at ref==2 (MANAGER + CALLER), so the
 *     returned pointer cannot be freed under the caller; and
 *   - releasing that caller ref balances the count, so a deduped/new return
 *     does not leak into deferred_free forever and a release-to-zero frees. */

#include "test/test_core.h"
#include "coins/undo.h"

#include "net/net.h"
#include "net/netaddr.h"
#include "net/netbase.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "platform/socket_compat.h"

/* Manually splice a pre-built node into nm->nodes[] the way nm_add_node does
 * internally (nm_add_node is declared only in net_internal.h).
 * net_manager_free() will free both the array and every node still
 * parked in it, so the caller must NOT free the node separately. */
static void manager_insert_node(struct net_manager *nm, struct p2p_node *node)
{
    struct p2p_node **grown =
        zcl_realloc(nm->nodes, (nm->num_nodes + 1) * sizeof(*grown),
                    "test_node_list");
    nm->nodes = grown;
    nm->nodes_cap = nm->num_nodes + 1;
    nm->nodes[nm->num_nodes++] = node;
}

int test_connect_node_locked(void)
{
    printf("\n=== connect_node find_node_by_service_locked tests ===\n");
    int failures = 0;

    TEST_CASE("connect_node dedupes (ref+1) and skips disconnect-flagged nodes")
    {
        /* Case 1: an existing live node for service S is deduped — connect_node
         * returns the SAME pointer with exactly one extra ref and appends no
         * new node (the find-and-ref happens atomically under cs_nodes). */
        struct net_manager nm;
        net_manager_init(&nm);
        memcpy(nm.message_start, "\xfa\x1a\xf9\xbf", 4);

        struct net_address addr;
        net_address_init(&addr);
        unsigned char ip4[4] = {50, 0, 0, 1};
        net_addr_set_ipv4(&addr.svc.addr, ip4);
        addr.svc.port = 8233;

        struct p2p_node *node =
            p2p_node_create(&nm, ZCL_INVALID_SOCKET, &addr, "dedupe-peer",
                            false);
        ASSERT(node != NULL);
        manager_insert_node(&nm, node);

        int ref_before = p2p_node_get_ref(node);
        size_t nodes_before = nm.num_nodes;

        /* dest=NULL: dedupe must short-circuit before any socket connect. */
        struct p2p_node *got = connect_node(&nm, &addr, NULL);
        ASSERT(got == node);
        ASSERT(p2p_node_get_ref(node) == ref_before + 1);
        ASSERT(nm.num_nodes == nodes_before);

        /* Symmetric-ref contract: the deduped +1 is a CALLER-owned ref the
         * caller releases under cs_nodes once done. Releasing it must restore
         * the original count exactly (no leak into deferred_free, no over-free
         * that would drive the still-published manager ref negative). */
        zcl_mutex_lock(&nm.cs_nodes);
        p2p_node_release(got);
        ASSERT(p2p_node_get_ref(node) == ref_before);
        zcl_mutex_unlock(&nm.cs_nodes);

        net_manager_free(&nm);

        /* Case 2: the node for service S is flagged disconnect before the call.
         * The lookup must skip it, so connect_node never returns it and never
         * re-refs it — closing the use-after-free window. Loopback port 1 makes
         * the fall-through socket connect refuse immediately, so connect_node
         * returns NULL fast and deterministically without touching node. */
        struct net_manager nm2;
        net_manager_init(&nm2);
        memcpy(nm2.message_start, "\xfa\x1a\xf9\xbf", 4);

        struct net_address addr2;
        net_address_init(&addr2);
        unsigned char lo4[4] = {127, 0, 0, 1};
        net_addr_set_ipv4(&addr2.svc.addr, lo4);
        addr2.svc.port = 1;

        struct p2p_node *dnode =
            p2p_node_create(&nm2, ZCL_INVALID_SOCKET, &addr2, "disc-peer",
                            false);
        ASSERT(dnode != NULL);
        dnode->disconnect = true;
        manager_insert_node(&nm2, dnode);

        int dref_before = p2p_node_get_ref(dnode);

        struct p2p_node *dgot = connect_node(&nm2, &addr2, NULL);
        ASSERT(dgot != dnode);
        ASSERT(p2p_node_get_ref(dnode) == dref_before);

        net_manager_free(&nm2);
    }

    /* Case 3: new-node path returns a releasable +1 caller ref.
     * (Folded into this single TEST_CASE because TEST_END defines a fixed
     * _test_next label, so only one TEST_CASE/TEST_END pair is allowed per
     * function — a second pair would redefine the label.) */
    printf("\n  new-node path returns a releasable +1 caller ref... ");
    {
        /* Stand up a real loopback listener so the new-node path's TCP connect
         * completes deterministically. After connect_node returns the freshly
         * created node is published in nodes[] at ref==2: the MANAGER ref
         * (dropped by the socket-sweep reap) + the CALLER ref (this contract).
         * Two refs at publish time are exactly what pins the node across the
         * window between connect_node returning and the dialer's first deref —
         * the UAF the fix closes. */
        platform_socket_t lsock = platform_socket_open(AF_INET, SOCK_STREAM,
                                                       0, true, false);
        ASSERT(lsock != PLATFORM_SOCKET_INVALID);
        (void)platform_socket_set_reuse_address(lsock, true);

        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sa.sin_port = 0; /* ephemeral — kernel picks a free port */
        ASSERT(platform_socket_bind(lsock, (struct sockaddr *)&sa,
                                    sizeof(sa)) == 0);
        ASSERT(platform_socket_listen(lsock, 4) == 0);

        size_t salen = sizeof(sa);
        ASSERT(platform_socket_local_address(lsock, (struct sockaddr *)&sa,
                                             &salen) == 0);
        uint16_t listen_port = ntohs(sa.sin_port);

        struct net_manager nm3;
        net_manager_init(&nm3);
        memcpy(nm3.message_start, "\xfa\x1a\xf9\xbf", 4);

        struct net_address addr3;
        net_address_init(&addr3);
        unsigned char lo4[4] = {127, 0, 0, 1};
        net_addr_set_ipv4(&addr3.svc.addr, lo4);
        addr3.svc.port = listen_port;

        size_t nodes_before = nm3.num_nodes;
        /* dest non-NULL so connect_node skips the is_local refusal for
         * loopback; this is the addnode/localhost dial path. */
        struct p2p_node *node = connect_node(&nm3, &addr3, "loopback-peer");
        ASSERT(node != NULL);
        /* Published exactly once. */
        ASSERT(nm3.num_nodes == nodes_before + 1);
        ASSERT(nm3.nodes[nm3.num_nodes - 1] == node);
        /* ref==2: MANAGER + CALLER. */
        ASSERT(p2p_node_get_ref(node) == 2);

        /* Caller releases its ref under cs_nodes (what
         * connman_release_connect_node_ref does in connman.c). The node is
         * still in nodes[] holding the manager ref, so it must NOT reach 0. */
        zcl_mutex_lock(&nm3.cs_nodes);
        p2p_node_release(node);
        ASSERT(p2p_node_get_ref(node) == 1);
        zcl_mutex_unlock(&nm3.cs_nodes);

        /* Release-to-zero-frees: simulate the reap dropping the manager ref
         * after the node has left nodes[]. Once both refs are gone the node is
         * freeable with no remaining owner — net_manager_free would otherwise
         * double-account it, so we remove + free it here explicitly and assert
         * the manager list is empty. */
        zcl_mutex_lock(&nm3.cs_nodes);
        nm3.nodes[nm3.num_nodes - 1] = NULL;
        nm3.num_nodes--;
        p2p_node_release(node); /* manager ref 1 -> 0 */
        ASSERT(p2p_node_get_ref(node) == 0);
        p2p_node_free(node);    /* reaches zero -> frees, no UAF, no leak */
        zcl_mutex_unlock(&nm3.cs_nodes);
        ASSERT(nm3.num_nodes == nodes_before);

        net_manager_free(&nm3);
        platform_socket_close(lsock);
    }
    TEST_END

    return failures;
}
