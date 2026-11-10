/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_p2p_bind_refusal — boot_p2p_listen
 * (engine/composition/src/boot_p2p_listen.c).
 *
 * listen left false stays quiet: the call returns true before any bind and
 * does not latch a boot error. A NULL ctx on that same zeroed manager returns
 * false and does not latch. An explicit bind with p2p_port -1 returns
 * false and reports BOOT_P2P_BIND_REFUSED with phase p2p.listen and evidence
 * stage=p2p_bind_invalid. The invalid port is rejected before bind.
 */

#include "test/test_core.h"

#include "net/net.h"
#include "config/boot.h"
#include "config/boot_error.h"

#include <stdio.h>
#include <string.h>

#define CHECK(name, expr) do {                                  \
    printf("  p2p_bind_refusal: %s... ", (name));               \
    if (expr) printf("OK\n");                                   \
    else { printf("FAIL\n"); failures++; }                      \
} while (0)

static bool pbr_render_names_refusal(void)
{
    char rendered[BOOT_ERROR_RENDER_MAX];
    size_t n = boot_error_last_render(rendered, sizeof(rendered));
    return n > 0 &&
           strstr(rendered, "phase:    p2p.listen") != NULL &&
           strstr(rendered, "stage=p2p_bind_invalid") != NULL;
}

int test_p2p_bind_refusal(void);
int test_p2p_bind_refusal(void)
{
    test_reset_shared_globals();
    printf("\n=== p2p_bind_refusal tests ===\n");
    int failures = 0;
    struct net_manager manager;
    struct app_context ctx;

    boot_error_reset_for_testing();
    memset(&manager, 0, sizeof(manager));
    memset(&ctx, 0, sizeof(ctx));
    bool quiet = boot_p2p_listen(&manager, &ctx);
    CHECK("listen off returns true", quiet == true);
    CHECK("listen off does not latch", boot_error_reported() == false);

    boot_error_reset_for_testing();
    bool null_ctx = boot_p2p_listen(&manager, NULL);
    CHECK("NULL ctx returns false", null_ctx == false);
    CHECK("NULL ctx does not latch", boot_error_reported() == false);

    boot_error_reset_for_testing();
    memset(&manager, 0, sizeof(manager));
    memset(&ctx, 0, sizeof(ctx));
    ctx.listen = true;
    ctx.p2p_bind_address = "127.0.0.1";
    ctx.p2p_port = -1;
    bool refused = boot_p2p_listen(&manager, &ctx);
    CHECK("invalid port returns false", refused == false);
    CHECK("invalid port does not bind", manager.num_listen_sockets == 0);
    CHECK("invalid port latches", boot_error_reported() == true);
    CHECK("invalid port code",
          strcmp(boot_error_first_code(), "BOOT_P2P_BIND_REFUSED") == 0);
    CHECK("invalid port names stage", pbr_render_names_refusal());

    return failures;
}
