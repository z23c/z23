/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * A failed write of the private relay's pending record must not be silent.
 * When marking a send expired or seen back cannot be written, the record on
 * disk still names the send as live; the relay keeps the change dirty and
 * writes it on a later tick once the datadir is writable again. Local
 * fixture only: a relay with no wallet, no peers and no keys. Called from
 * test_wallet_private_relay. */

#include "test/test_core.h"

#include "platform/file_stream.h"
#include "primitives/transaction.h"
#include "services/wallet_private_relay.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <string.h>

#define WPRP_BAD_DIR "/nonexistent/wallet-private-relay-persist"

struct wprp_fx {
    struct wpr *r;
    char dir[256];
    char hex[65];
    struct uint256 id;
};

static void wprp_report(const char *name, bool ok, int *failures)
{
    printf("wallet_private_relay_persist: %s... %s\n", name,
           ok ? "OK" : "FAIL");
    if (!ok)
        (*failures)++;
}

static void wprp_point_at(struct wprp_fx *f, const char *dir)
{
    struct wpr_env env;
    memset(&env, 0, sizeof(env));
    env.datadir = dir;
    wpr_configure(f->r, WPR_MODE_PRIVATE, &env);
}

static bool wprp_open(struct wprp_fx *f)
{
    memset(f, 0, sizeof(*f));
    f->r = zcl_calloc(1, sizeof(*f->r), "wprp_fx");
    if (!f->r)
        return false;
    wpr_init(f->r);
    if (!test_mkdtemp(f->dir, sizeof(f->dir), "wprp"))
        return false;
    wprp_point_at(f, f->dir);
    memset(f->id.data, 0x5a, sizeof(f->id.data));
    f->id.data[31] = 1;
    uint256_get_hex(&f->id, f->hex);
    return wpr_prepare(f->r, &f->id).ok;
}

static void wprp_close(struct wprp_fx *f)
{
    if (f->r) {
        wpr_free(f->r);
        free(f->r);
    }
    if (f->dir[0])
        test_rm_rf(f->dir);
}

/* The pending record's line for the send: 'x' expired, 'a' handed, ' ' live,
 * '-' no line at all. */
static char wprp_disk_line(const struct wprp_fx *f)
{
    char path[400];
    char buf[8192];
    snprintf(path, sizeof(path), "%s/wallet_private_relay.pending", f->dir);
    FILE *fp = platform_file_stream_open_read(path);
    if (!fp)
        return '?';
    size_t len = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[len] = '\0';
    const char *at = strstr(buf, f->hex);
    if (!at)
        return '-';
    return at > buf && at[-1] != '\n' ? at[-1] : ' ';
}

static void wprp_tick(struct wprp_fx *f)
{
    struct wpr_tick_result res;
    wpr_tick(f->r, -1, &res);
}

static int wprp_case_expired(void)
{
    int failures = 0;
    struct wprp_fx f;
    if (!wprp_open(&f)) {
        wprp_report("fixture opens and records a send", false, &failures);
        wprp_close(&f);
        return failures;
    }
    wprp_report("a recorded send is live on disk",
                wprp_disk_line(&f) == ' ', &failures);
    wprp_point_at(&f, WPRP_BAD_DIR);
    wpr_mark_expired(f.r, &f.id);
    wprp_point_at(&f, f.dir);
    wprp_report("the failed write left the live line on disk",
                wprp_disk_line(&f) == ' ', &failures);
    wprp_tick(&f);
    wprp_report("a later tick writes the expired mark once the datadir works",
                wprp_disk_line(&f) == 'x', &failures);
    wprp_close(&f);
    return failures;
}

static int wprp_case_seen(void)
{
    int failures = 0;
    struct wprp_fx f;
    if (!wprp_open(&f)) {
        wprp_report("fixture opens and records a send", false, &failures);
        wprp_close(&f);
        return failures;
    }
    wprp_point_at(&f, WPRP_BAD_DIR);
    wpr_note_seen(f.r, &f.id);
    wprp_point_at(&f, f.dir);
    wprp_report("the failed write left the live line on disk",
                wprp_disk_line(&f) == ' ', &failures);
    wprp_tick(&f);
    wprp_report("a later tick drops the seen-back send from the record",
                wprp_disk_line(&f) == '-', &failures);
    wprp_close(&f);
    return failures;
}

int wprp_run_tests(void);
int wprp_run_tests(void)
{
    int failures = 0;
    failures += wprp_case_expired();
    failures += wprp_case_seen();
    return failures;
}
