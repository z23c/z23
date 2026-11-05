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

static int64_t wprp_clock_ms;

static int64_t wprp_now_ms(void)
{
    return ++wprp_clock_ms;
}

static void wprp_id(struct uint256 *id, uint32_t n)
{
    memset(id->data, 0x33, sizeof(id->data));
    id->data[0] = (uint8_t)(n & 0xff);
    id->data[1] = (uint8_t)(n >> 8);
}

/* Lines in the pending record, and the marker of the line naming `id`:
 * 'x' expired, ' ' live, '-' no line. */
static size_t wprp_record(const struct wprp_fx *f, const struct uint256 *id,
                          char *mark)
{
    char path[400];
    char buf[20000];
    char hex[65];
    snprintf(path, sizeof(path), "%s/wallet_private_relay.pending", f->dir);
    FILE *fp = platform_file_stream_open_read(path);
    *mark = '?';
    if (!fp)
        return 0;
    size_t len = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[len] = '\0';
    uint256_get_hex(id, hex);
    const char *at = strstr(buf, hex);
    *mark = !at ? '-' : (at > buf && at[-1] != '\n' ? at[-1] : ' ');
    size_t lines = 0;
    for (const char *p = buf; *p; p++)
        if (*p == '\n')
            lines++;
    return lines - 1; /* the header line */
}

static bool wprp_has(struct wprp_fx *f, const struct uint256 *id)
{
    enum wpr_state st;
    bool handed;
    return wpr_entry_state(f->r, id, &st, &handed);
}

/* A full table of expired records plus one live send: an insert whose write
 * fails must not cost a record, and one that succeeds must replace the oldest
 * expired record on disk too, never the live send. */
static int wprp_case_evict(void)
{
    int failures = 0;
    struct wprp_fx f;
    struct uint256 id, fresh;
    bool filled = wprp_open(&f);
    wprp_clock_ms = 0;
    if (filled)
        f.r->now_ms = wprp_now_ms;
    for (uint32_t i = 0; filled && i < WPR_MAX_ENTRIES - 1; i++) {
        wprp_id(&id, i);
        filled = wpr_prepare(f.r, &id).ok;
        wpr_mark_expired(f.r, &id);
    }
    if (!filled) {
        wprp_report("fixture fills the table", false, &failures);
        wprp_close(&f);
        return failures;
    }
    wprp_id(&fresh, 5000);
    wprp_id(&id, 0);
    wprp_point_at(&f, WPRP_BAD_DIR);
    bool refused = !wpr_prepare(f.r, &fresh).ok;
    wprp_point_at(&f, f.dir);
    wprp_report("an insert whose write fails is refused", refused, &failures);
    wprp_report("it did not evict the oldest expired record",
                wprp_has(&f, &id), &failures);
    wprp_report("it left no half-made record", !wprp_has(&f, &fresh),
                &failures);
    char mark;
    bool inserted = wpr_prepare(f.r, &fresh).ok;
    wprp_report("the same insert succeeds once the write works", inserted,
                &failures);
    wprp_report("it replaced the oldest expired record in memory",
                !wprp_has(&f, &id), &failures);
    size_t lines = wprp_record(&f, &id, &mark);
    wprp_report("and removed that row from the store", mark == '-' &&
                lines <= WPR_MAX_ENTRIES, &failures);
    wprp_record(&f, &f.id, &mark);
    wprp_report("the live send is still in the store", mark == ' ', &failures);
    for (uint32_t i = 6000; i < 6000 + 2 * WPR_MAX_ENTRIES; i++) {
        wprp_id(&id, i);
        if (!wpr_prepare(f.r, &id).ok) {
            wprp_report("a long run of inserts is accepted", false, &failures);
            break;
        }
        wpr_mark_expired(f.r, &id);
    }
    lines = wprp_record(&f, &f.id, &mark);
    wprp_report("after more inserts than the table holds the store fits it",
                lines <= WPR_MAX_ENTRIES, &failures);
    wprp_report("and the live send is still live in memory and on disk",
                mark == ' ' && wprp_has(&f, &f.id), &failures);
    wprp_close(&f);
    return failures;
}

int wprp_run_tests(void);
int wprp_run_tests(void)
{
    int failures = 0;
    failures += wprp_case_evict();
    failures += wprp_case_expired();
    failures += wprp_case_seen();
    return failures;
}
