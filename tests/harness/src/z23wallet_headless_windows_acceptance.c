/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Windows acceptance of the whole z23-wallet pipeline on the headless
 * backend: a fixture node on loopback (cookie file, JSON-RPC over real Winsock
 * sockets), the real worker thread, model, layout and paint, one PNG shot and a
 * clean exit. Nothing here opens a window, touches a real datadir or needs a
 * running node. Prints PASS or the failing step and exits non-zero. */
#if defined(_WIN32)
#include <direct.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../apps/z23wallet/src/zw.h"
#include "z23wallet_mock_node.h"

#define ROOT "z23wallet_headless_acc"
#define COOKIE "__cookie__:acceptancecookie0123456789"

static bool fail(const char *msg)
{
    printf("z23wallet_headless: FAIL %s\n", msg);
    return false;
}

static bool write_text(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool ok = fputs(text, f) >= 0;
    return fclose(f) == 0 && ok;
}

static bool make_scenario(void)
{
    static const struct { const char *name, *json; } files[] = {
        { ROOT "/scn/getblockchaininfo.json",
          "{\"chain\":\"main\",\"blocks\":1234567,\"headers\":1234567,\"verificationprogress\":0.9999}" },
        { ROOT "/scn/getnetworkinfo.json",
          "{\"version\":2010000,\"subversion\":\"/Z23:2.1.0/\",\"connections\":8,"
          "\"inbound_connections\":3,\"outbound_connections\":5}" },
        { ROOT "/scn/walletsummary.json",
          "{\"schema\":\"zcl.wallet_summary.v1\",\"spendable_zat\":1250000000,\"pending_zat\":0,"
          "\"public_zat\":0,\"immature_zat\":0,\"scanned_through_height\":1234567,\"blocks_behind\":0,"
          "\"current\":true,\"locked\":false,\"encrypted\":false,\"send_allowed\":true,"
          "\"send_blocked_reason\":\"\",\"balance_available\":true}" },
    };
    /* zw_mock_write_cookie creates the directory (one level) and a .cookie in it. */
    if (!zw_mock_write_cookie(ROOT, "x") || !zw_mock_write_cookie(ROOT "/scn", "x") ||
        !zw_mock_write_cookie(ROOT "/data", COOKIE))
        return fail("create the scratch directories");
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++)
        if (!write_text(files[i].name, files[i].json)) return fail("write a scenario file");
    return true;
}

static bool png_written(const char *path)
{
    static const unsigned char sig[8] = { 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A };
    unsigned char head[8] = { 0 };
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    size_t n = fread(head, 1, sizeof(head), f);
    long size = fseek(f, 0, SEEK_END) == 0 ? ftell(f) : -1;
    fclose(f);
    return n == 8 && memcmp(head, sig, 8) == 0 && size > 4000;
}

static bool run_wallet(uint16_t port)
{
    char rp[16];
    snprintf(rp, sizeof(rp), "--rpcport=%u", (unsigned)port);
    char *argv[] = { "z23-wallet", "--backend=headless", "--datadir=" ROOT "/data", rp,
                     "--size=900x600", "--shot=" ROOT "/home.png", "--shot-after-ms=600",
                     "--exit-after-shot" };
    struct zw_options o;
    char err[160];
    if (!zw_args_parse((int)(sizeof(argv) / sizeof(argv[0])), argv, &o, err, sizeof(err)))
        return fail("parse the wallet arguments");
    if (zw_app_run(&o) != 0) return fail("zw_app_run did not exit 0");
    return true;
}

/* Best effort: leave nothing behind in the working directory. */
static void cleanup(void)
{
    static const char *const names[] = {
        ROOT "/home.png", ROOT "/scn/getblockchaininfo.json", ROOT "/scn/getnetworkinfo.json",
        ROOT "/scn/walletsummary.json", ROOT "/scn/.cookie", ROOT "/data/.cookie",
        ROOT "/data/.rpcport", ROOT "/.cookie",
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) (void)remove(names[i]);
    (void)_rmdir(ROOT "/scn");
    (void)_rmdir(ROOT "/data");
    (void)_rmdir(ROOT);
}

int main(void)
{
    if (!make_scenario()) return 1;
    uint16_t port = 0;
    struct zw_mock *m = zw_mock_start(ROOT "/scn", ROOT "/data", &port);
    if (!m) {
        printf("z23wallet_headless: FAIL start the fixture node\n");
        return 1;
    }
    bool ok = run_wallet(port);
    ok = ok && (zw_mock_saw(m, "getblockchaininfo") || fail("the wallet never asked for the chain")) &&
         (zw_mock_saw(m, "walletsummary") || fail("the wallet never asked for the wallet summary")) &&
         (png_written(ROOT "/home.png") || fail("the screenshot is missing or not a PNG"));
    zw_mock_stop(m);
    cleanup();
    if (ok) printf("z23wallet_headless: PASS\n");
    return ok ? 0 : 1;
}
#else
typedef int z23wallet_headless_windows_acceptance_not_built;
#endif
