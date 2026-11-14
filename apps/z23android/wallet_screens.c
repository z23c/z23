/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "wallet_screens.h"
#include "domain/encoding/bech32.h"
#include "base/cleanse.h"
#include "json/json.h"
#include "payment_code.h"
#include "wallet_view.h"
#include "zutf8/zutf8.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define OUT_CAP 65536u
#define PAGES_MAX 64u
#define TXID_MAX (WALLET_TXID_LEN + 1u)
#define MEMO_MAX 1025u /* 512 bytes of text, or 512 bytes as hex, and the NUL */
#define NOTE_MAX 192u
#define WALLET_COPIED_NOTE "Address copied. It clears after a minute."
#define WALLET_COPY_FAILED_NOTE "Could not copy the address."
#define MAX_UNIX 253402300799LL
#define MACHINES_MAX 64u
#define CHUNK_MAX 280u
#define CHUNKS_MAX 8u
#define TOKEN_MAX 16u

enum direction { DIR_UNKNOWN, DIR_SENT, DIR_RECEIVED, DIR_INTERNAL };
/* What the node reports in fully_shielded: true, false, or null (or nothing) when the wallet cannot tell. */
enum shield { SHIELD_UNKNOWN, SHIELD_FULL, SHIELD_PART };
enum status { STATUS_UNKNOWN, STATUS_CONFIRMED, STATUS_PENDING };
/* What the node says about private payments in a history page: complete, hidden because a locked wallet holds no viewing
 * key, or nothing usable. Only a page that says "ok" is the whole history. */
enum history_state { HIST_UNSAID, HIST_OK, HIST_HIDDEN };
enum kind { K_SUMMARY, K_FLEET, K_LATEST, K_PRELOAD, K_NEW, K_HISTORY, K_DETAIL, K_COUNT };

struct entry {
    enum direction direction;
    enum shield shield;
    enum status status;
    bool amount_known, time_known, memo_present;
    uint64_t amount_zat;
    int64_t time;
    char txid[TXID_MAX]; /* empty when the node gave none that is a transaction id */
};

/* The lines of the last balance the node gave, as read from the cache file: the amount, what is pending and what is public. */
struct cache {
    bool valid;
    int64_t at;      /* Unix seconds when the node gave it */
    int64_t minutes; /* the age last drawn, so a screen redraws when the label would change */
    char balance[WALLET_VIEW_LINE], pending[WALLET_VIEW_LINE], public_line[WALLET_VIEW_LINE];
};

/* Everything a wallet screen holds that is wiped when the owner leaves. */
struct data {
    bool funds_loaded, fleet_loaded, funds_fresh, fleet_fresh, node_silent, summary_failed;
    int cutover_status;
    char cutover_sync[96];
    uint64_t summary_at, fleet_at, requested_at;
    unsigned initial_failures;
    bool initial_retry_wait, summary_validated;
    uint64_t initial_retry_at;
    struct wallet_view view;
    char fleet[WALLET_TEXT_MAX];
    bool address_pending, has_amount, no_receive, address_fallback, setup_bound, offline_bound, address_unavailable;
    bool preload_tried, address_read_failed;
    char offline_identity[82];
    uint64_t address_generation;
    uint64_t amount_zat;
    enum zapp_pay_network network;
    char setup_anchor[ZAPP_PAY_ADDRESS_MAX];
    char address[ZAPP_PAY_ADDRESS_MAX], code[ZAPP_RECEIVE_CODE_MAX], note[NOTE_MAX], scan_note[NOTE_MAX];
    bool share_notice;
    bool history_pending, history_failed, has_more;
    enum history_state history_state;
    unsigned page, detail;
    size_t rows;
    char cursor[PAGES_MAX][WALLET_CURSOR_MAX], next[WALLET_CURSOR_MAX];
    struct entry entry[WALLET_PAGE_ROWS];
    bool detail_pending, detail_failed, memo_loaded, memo_hex, memo_over;
    char memo[MEMO_MAX];
    struct cache cache; /* the last balance the node gave, read from the files directory when Funds opened */
    char send_line[WALLET_TEXT_MAX]; /* the payment line the send flow gave, read when Funds opened and on every refresh */
    enum wallet_reveal reveal; /* the private balance request as last read from the environment */
};

struct job {
    struct wallet_env env;
    char op[12], arg[WALLET_CURSOR_MAX];
    unsigned epoch;
    enum kind kind;
};
struct flight { bool running, queued; struct job next; };

static struct {
    pthread_mutex_t lock;
    struct wallet_env env;
    bool ready, secure, blocked, held;
    uint64_t held_at; /* when the pause kept the protection */
    unsigned held_ticks; /* settle calls since then */
    char why[96]; /* what the refused protection could not do, for the notice shown instead of the wallet */
    unsigned epoch, version, dropped;
    enum wallet_page page;
    struct data d;
    char pending_share[96];
    struct { bool valid; uint64_t amount; char identity[82], address[ZAPP_PAY_ADDRESS_MAX]; } request;
    struct flight flight[K_COUNT];
} st = {.lock = PTHREAD_MUTEX_INITIALIZER};

/* ---- small helpers ---- */

/* The protection a pause kept goes only after this long and this many ticks, so a stalled UI thread cannot
 * release it before a screen without wallet data has been drawn. */
enum { WALLET_SETTLE_MS = 250, WALLET_SETTLE_TICKS = 2 };

static void touch(void) { ++st.version; }
static void copy(char *dst, size_t cap, const char *src) { snprintf(dst, cap, "%s", src); }
static void clear_pending_share_notice(void) { st.pending_share[0] = '\0'; }
static void clear_committed_share_notice(void)
{
    st.d.share_notice = false;
    st.d.note[0] = '\0';
}
static void clear_share_notice(void)
{
    clear_committed_share_notice();
    clear_pending_share_notice();
}
static uint64_t now(void) { return st.env.now_ms ? st.env.now_ms(st.env.ctx) : 0; }
/* The JSON object in command output: at its start, or on the first line that begins with a brace. */
static const char *json_start(const char *text)
{
    const char *at = !text ? NULL : text[0] == '{' ? text : strstr(text, "\n{");
    return at && at[0] == '\n' ? at + 1 : at;
}
/* The data object of a successful reply, or NULL. */
static const struct json_value *data_of(const struct json_value *root)
{
    const struct json_value *ok = json_get(root, "ok"), *data = json_get(root, "data");
    return ok && ok->type == JSON_BOOL && json_get_bool(ok) && data && data->type == JSON_OBJ ? data : NULL;
}
/* The member of the given type, or NULL when it is missing or of another type. */
static const struct json_value *typed(const struct json_value *object, const char *key, enum json_type type)
{
    const struct json_value *value = json_get(object, key);
    return value && value->type == type ? value : NULL;
}
static const char *text_of(const struct json_value *object, const char *key)
{
    const struct json_value *value = typed(object, key, JSON_STR);
    return value ? json_get_str(value) : NULL;
}
static bool is(const char *text, const char *want) { return text && !strcmp(text, want); }
/* Frees a parsed reply after overwriting the text in it. */
static void drop_tree(struct json_value *root)
{
    json_cleanse_strings(root);
    json_free(root);
}

/* ---- text from other people ---- */

/* The visible form of the character at in: itself, or its code point or byte in angle brackets. */
static size_t visible_token(const char *in, size_t len, char tok[TOKEN_MAX])
{
    uint32_t cp = 0;
    size_t used = 0;
    if (zutf8_decode_n(in, len, &cp, &used) != ZUTF8_OK) {
        snprintf(tok, TOKEN_MAX, "<x%02X>", (unsigned)(unsigned char)in[0]);
        return 1;
    }
    if (zapp_pay_cp_hidden(cp)) snprintf(tok, TOKEN_MAX, "<U+%04X>", (unsigned)cp);
    else { memcpy(tok, in, used); tok[used] = '\0'; }
    return used;
}

/* ---- items ---- */

static struct wallet_item *add(struct wallet_screen *s, enum wallet_item_kind kind, enum wallet_action action, const char *text)
{
    if (s->count >= WALLET_ITEMS_MAX) return NULL;
    struct wallet_item *item = &s->items[s->count++];
    memset(item, 0, sizeof(*item));
    item->kind = kind;
    item->action = action;
    copy(item->text, sizeof(item->text), text);
    return item;
}
static void line(struct wallet_screen *s, const char *text) { (void)add(s, WALLET_ITEM_TEXT, WALLET_ACT_NONE, text); }
static void note(struct wallet_screen *s, const char *text) { (void)add(s, WALLET_ITEM_NOTE, WALLET_ACT_NONE, text); }
static void button(struct wallet_screen *s, enum wallet_action action, const char *text) { (void)add(s, WALLET_ITEM_BUTTON, action, text); }
/* The title of a page. When another window has been drawing over the app and taps were dropped, the reason follows it. */
static void title(struct wallet_screen *s, const char *text)
{
    (void)add(s, WALLET_ITEM_TITLE, WALLET_ACT_NONE, text);
    if (st.dropped) note(s, "Another app is drawing over this screen, so your taps were ignored. Turn off screen dimmers and overlays, then tap again.");
}

/* ---- last known balance ----
 * Funds shows the last balance the node gave while the node has not answered yet. It is kept in one small file in the
 * app's private files directory (0600, never through a link, replaced whole), sealed with the environment's key, so no
 * amount reaches the disk as plain text. It is written from a summary the node gave whose amounts the wallet shows without
 * the owner's screen lock, or as the zero of a wallet that setup has just made, and read back only for the wallet it was
 * written for: the sealed body names the wallet's key file by a hash of its bytes and the seal is bound to that name, so a
 * wallet set aside or replaced never shows another wallet's balance. A file that does not open and read back exactly is
 * deleted, and so is the plain text file of earlier builds. */
#define CACHE_FILE "wallet_balance_sealed"
#define CACHE_PLAIN_FILE "wallet_balance_cache"
#define CACHE_TAG "z23-balance-cache-v1"
#define CACHE_BODY_MAX 640u
#define CACHE_PATH_MAX 512u
#define CACHE_REFRESH_S 60 /* an unchanged balance is written again after this long, so its age stays honest */
#define CACHE_FUTURE_S 120 /* a file dated further ahead than this was not written by this clock, and is deleted */
#define KEY_FILE_MAX 65536u
#define WALLET_ID_LEN 16u
/* The file is SEALED_TAG, the nonce, then the body sealed with its tag. The seal is bound to SEALED_TAG and the wallet. */
#define SEALED_TAG "z23-balance-sealed-v1\n"
#define SEALED_TAG_LEN (sizeof(SEALED_TAG) - 1u)
#define SEALED_HEAD (SEALED_TAG_LEN + WALLET_SEAL_IV)
#define SEALED_MAX (SEALED_HEAD + CACHE_BODY_MAX - 1u + WALLET_SEAL_TAG)
#define CACHE_AAD_LEN (SEALED_TAG_LEN + WALLET_ID_LEN)

struct cache_job {
    bool go, drop;
    char path[CACHE_PATH_MAX], wallet[WALLET_ID_LEN + 1], body[CACHE_BODY_MAX];
    struct wallet_env env; /* the seal, as it was under the lock */
};
/* One writer of the file at a time, so two never share its temporary. */
static pthread_mutex_t cache_write = PTHREAD_MUTEX_INITIALIZER;

static void send_lines(struct wallet_screen *s, const struct data *d);
static int64_t wall_s(void) { return st.env.wall_s ? st.env.wall_s(st.env.ctx) : (int64_t)time(NULL); }
static bool files_path(char *out, const char *name)
{
    return st.env.files_dir && st.env.files_dir[0] && snprintf(out, CACHE_PATH_MAX, "%s/%s", st.env.files_dir, name) < (int)CACHE_PATH_MAX;
}
/* 16 hex digits of the FNV-1a hash of the wallet's key file. It tells wallets apart; it is not a secret and not a check against an attacker. */
static bool wallet_identity(char out[WALLET_ID_LEN + 1])
{
    char path[CACHE_PATH_MAX];
    unsigned char bytes[256];
    uint64_t hash = 1469598103934665603ull;
    size_t total = 0;
    ssize_t n = -1;
    if (!files_path(path, "wallet_key.blob")) return false;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    while ((n = read(fd, bytes, sizeof(bytes))) > 0 && total <= KEY_FILE_MAX) {
        for (ssize_t i = 0; i < n; ++i) { hash ^= bytes[i]; hash *= 1099511628211ull; }
        total += (size_t)n;
    }
    (void)close(fd);
    if (n != 0 || total == 0 || total > KEY_FILE_MAX) return false;
    snprintf(out, WALLET_ID_LEN + 1, "%016llx", (unsigned long long)hash);
    return true;
}
/* What the seal is bound to: the format and the wallet. */
static size_t cache_aad(const char *wallet, uint8_t out[CACHE_AAD_LEN])
{
    memcpy(out, SEALED_TAG, SEALED_TAG_LEN);
    memcpy(out + SEALED_TAG_LEN, wallet, WALLET_ID_LEN);
    return CACHE_AAD_LEN;
}
static bool ends_in_zcl(const char *amount)
{
    size_t n = strlen(amount);
    return n > 4 && !strcmp(amount + n - 4, " ZCL");
}
static bool plain_line(const char *text)
{
    size_t n = strlen(text);
    for (size_t i = 0; i < n; ++i) if ((unsigned char)text[i] < 0x20 || (unsigned char)text[i] >= 0x7f) return false;
    return n < WALLET_VIEW_LINE;
}
/* The body is: tag, wallet, time, balance, pending, public, each ended by a newline, and nothing after. */
static bool cache_parse(char *body, const char *wallet, int64_t now_s, struct cache *out)
{
    char *line[6], *end = NULL;
    for (int i = 0; i < 6; ++i) {
        char *nl = strchr(body, '\n');
        if (!nl) return false;
        *nl = '\0';
        line[i] = body;
        body = nl + 1;
    }
    long long at = line[2][0] ? strtoll(line[2], &end, 10) : 0;
    if (*body || strcmp(line[0], CACHE_TAG) || strcmp(line[1], wallet) || !end || *end || at <= 0 || at > now_s + CACHE_FUTURE_S) return false;
    for (int i = 3; i < 6; ++i) if (!plain_line(line[i])) return false;
    if (!ends_in_zcl(line[3])) return false;
    out->valid = true;
    out->at = at;
    snprintf(out->balance, sizeof(out->balance), "%s", line[3]);
    snprintf(out->pending, sizeof(out->pending), "%s", line[4]);
    snprintf(out->public_line, sizeof(out->public_line), "%s", line[5]);
    return true;
}
/* Reads the sealed file and opens it for this wallet into body, as text. False for another format, version, length or wallet,
 * for any changed byte, and when there is no key to open it with. */
static bool cache_unseal(int fd, const char *wallet, char body[CACHE_BODY_MAX])
{
    uint8_t sealed[SEALED_MAX + 1], aad[CACHE_AAD_LEN];
    ssize_t n = read(fd, sealed, sizeof(sealed));
    size_t len = n > (ssize_t)(SEALED_HEAD + WALLET_SEAL_TAG) && n <= (ssize_t)SEALED_MAX ? (size_t)n - SEALED_HEAD : 0;
    size_t aad_len = cache_aad(wallet, aad);
    bool ok = len && !memcmp(sealed, SEALED_TAG, SEALED_TAG_LEN) && st.env.unseal &&
              st.env.unseal(st.env.ctx, aad, aad_len, sealed + SEALED_TAG_LEN, sealed + SEALED_HEAD, len, (uint8_t *)body);
    size_t plain = ok ? len - WALLET_SEAL_TAG : 0;
    if (ok) body[plain] = '\0';
    return ok && strlen(body) == plain;
}
static void cache_load(void)
{
    char path[CACHE_PATH_MAX], wallet[WALLET_ID_LEN + 1], body[CACHE_BODY_MAX];
    memset(&st.d.cache, 0, sizeof(st.d.cache));
    if (files_path(path, CACHE_PLAIN_FILE)) (void)unlink(path);
    if (!files_path(path, CACHE_FILE)) return;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return;
    bool ok = wallet_identity(wallet) && cache_unseal(fd, wallet, body) && cache_parse(body, wallet, wall_s(), &st.d.cache);
    (void)close(fd);
    if (!ok) { memset(&st.d.cache, 0, sizeof(st.d.cache)); (void)unlink(path); }
    memory_cleanse(body, sizeof(body));
}
/* Under the lock: the write of these lines, dated at, for the wallet whose key file is there now. False when none can be kept. */
static bool cache_body(struct cache_job *job, int64_t at, const char *balance, const char *pending, const char *public_line)
{
    if (!st.env.seal || !files_path(job->path, CACHE_FILE) || !wallet_identity(job->wallet)) return false;
    int n = snprintf(job->body, sizeof(job->body), "%s\n%s\n%lld\n%s\n%s\n%s\n", CACHE_TAG, job->wallet, (long long)at, balance, pending, public_line);
    if (n < 0 || n >= (int)sizeof(job->body)) return false;
    job->env = st.env;
    job->go = true;
    return true;
}
/* Under the lock, after a summary reply: what to write, if the reply is a real balance that is new or old enough to date again.
 * Only what the wallet shows without the owner's screen lock is kept: an encrypted wallet that is unlocked may be showing amounts
 * its lock hides, so that read changes nothing. A reply that hides the private amounts removes the file, so no kept amount is
 * shown for a wallet that hides it now. */
static void cache_prepare(struct cache_job *job)
{
    const struct wallet_view *v = &st.d.view;
    struct cache *c = &st.d.cache;
    int64_t at = wall_s();
    if (v->known && !ends_in_zcl(v->balance)) {
        memset(c, 0, sizeof(*c));
        job->drop = files_path(job->path, CACHE_FILE);
        return;
    }
    bool same = c->valid && !strcmp(c->balance, v->balance) && !strcmp(c->pending, v->pending) && !strcmp(c->public_line, v->public_line);
    if (!v->known || (v->encrypted && !v->locked) || (same && at >= c->at && at - c->at < CACHE_REFRESH_S)) return;
    if (!cache_body(job, at, v->balance, v->pending, v->public_line)) return;
    c->valid = true;
    c->at = at;
    snprintf(c->balance, sizeof(c->balance), "%s", v->balance);
    snprintf(c->pending, sizeof(c->pending), "%s", v->pending);
    snprintf(c->public_line, sizeof(c->public_line), "%s", v->public_line);
}
/* Temporary file (new, 0600, never through a link), flushed, then renamed over path. A failure leaves the old file and no temporary. */
static void replace_file(const char *tmp, const char *path, const uint8_t *bytes, size_t len)
{
    (void)unlink(tmp);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    size_t put = 0;
    bool ok = fd >= 0;
    while (ok && put < len) {
        ssize_t w = write(fd, bytes + put, len - put);
        if (w > 0) put += (size_t)w;
        else if (w == 0 || errno != EINTR) ok = false;
    }
    ok = ok && fsync(fd) == 0;
    if (fd >= 0 && close(fd) != 0) ok = false;
    if (!ok || rename(tmp, path) != 0) (void)unlink(tmp);
}
/* Outside the lock: seals the body and replaces the file with it, or removes the file. A seal that fails writes nothing. */
static void cache_commit(struct cache_job *job)
{
    char tmp[CACHE_PATH_MAX + 8];
    uint8_t sealed[SEALED_MAX], aad[CACHE_AAD_LEN];
    if (job->go || job->drop) {
        size_t len = strlen(job->body), aad_len = cache_aad(job->wallet, aad);
        pthread_mutex_lock(&cache_write);
        if (job->drop) (void)unlink(job->path);
        memcpy(sealed, SEALED_TAG, SEALED_TAG_LEN);
        if (job->go && snprintf(tmp, sizeof(tmp), "%s.tmp", job->path) < (int)sizeof(tmp) &&
            job->env.seal(job->env.ctx, aad, aad_len, (const uint8_t *)job->body, len, sealed + SEALED_TAG_LEN, sealed + SEALED_HEAD))
            replace_file(tmp, job->path, sealed, SEALED_HEAD + len + WALLET_SEAL_TAG);
        pthread_mutex_unlock(&cache_write);
        memory_cleanse(sealed, sizeof(sealed));
    }
    memory_cleanse(job, sizeof(*job));
}
/* Whole minutes since the kept balance was given; a clock that went back reads as 0. */
static int64_t cache_minutes(const struct cache *c)
{
    int64_t seconds = wall_s() - c->at;
    return seconds > 0 ? seconds / 60 : 0;
}
/* ---- the payment in flight ---- */
#define SENDING_PREFIX "Sending "
static bool send_finished(const char *line) { return strncmp(line, SENDING_PREFIX, strlen(SENDING_PREFIX)) != 0; }
/* Under the lock, on the UI thread: asks the send flow for its line and redraws when it changed. */
static void send_refresh(void)
{
    char line[WALLET_TEXT_MAX] = "";
    if (!(st.env.send_progress && st.env.send_progress(st.env.ctx, line, sizeof(line)))) line[0] = '\0';
    if (strcmp(line, st.d.send_line)) { copy(st.d.send_line, sizeof(st.d.send_line), line); touch(); }
    memory_cleanse(line, sizeof(line));
}
/* The line under the balance; an ended payment also gets Dismiss, and one in flight does not. */
static void send_lines(struct wallet_screen *s, const struct data *d)
{
    if (!d->send_line[0]) return;
    line(s, d->send_line);
    if (send_finished(d->send_line)) button(s, WALLET_ACT_DISMISS_SEND, "Dismiss");
}
static void dismiss_send(void)
{
    if (!st.d.send_line[0] || !send_finished(st.d.send_line)) return;
    if (st.env.send_dismiss) st.env.send_dismiss(st.env.ctx);
    memory_cleanse(st.d.send_line, sizeof(st.d.send_line));
    touch();
}

/* A memo in items of their own kind, every hazardous character shown as its code point. What does not
 * fit in the items allowed says so. */
static void memo_items(struct wallet_screen *s, const char *raw)
{
    char chunk[CHUNK_MAX + TOKEN_MAX], tok[TOKEN_MAX];
    size_t used = 0, items = 0, len = strlen(raw);
    for (size_t at = 0; at < len;) {
        size_t n = visible_token(raw + at, len - at, tok), tok_len = strlen(tok);
        if (used + tok_len > CHUNK_MAX) {
            (void)add(s, WALLET_ITEM_MEMO, WALLET_ACT_NONE, chunk);
            used = 0;
            if (++items == CHUNKS_MAX) { note(s, "The memo is longer than this screen shows."); return; }
        }
        memcpy(chunk + used, tok, tok_len + 1);
        used += tok_len;
        at += n;
    }
    if (used) { chunk[used] = '\0'; (void)add(s, WALLET_ITEM_MEMO, WALLET_ACT_NONE, chunk); }
}

/* ---- private balance on request ---- */

#define REVEAL_ASKING "Confirm with your screen lock to show your private balance."
#define REVEAL_OPEN "Your private balance hides again after a short time, or when you leave this screen."
#define REVEAL_CANCELLED "Cancelled. Your private balance is still hidden."
#define REVEAL_NO_SCREEN_LOCK "Set a screen lock on this phone to show your private balance."
#define REVEAL_KEY_GONE "The wallet key on this phone is gone. Restore the wallet from its recovery phrase."
#define REVEAL_FAILED "Could not unlock the wallet. Your private balance is still hidden. Try again."
#define REVEAL_SENDING "A payment is in progress. Try again when it ends."

static const char *reveal_words(enum wallet_reveal state)
{
    switch (state) {
    case WALLET_REVEAL_ASKING: return REVEAL_ASKING;
    case WALLET_REVEAL_OPEN: return REVEAL_OPEN;
    case WALLET_REVEAL_CANCELLED: return REVEAL_CANCELLED;
    case WALLET_REVEAL_NO_SCREEN_LOCK: return REVEAL_NO_SCREEN_LOCK;
    case WALLET_REVEAL_KEY_GONE: return REVEAL_KEY_GONE;
    case WALLET_REVEAL_FAILED: return REVEAL_FAILED;
    case WALLET_REVEAL_SENDING: return REVEAL_SENDING;
    case WALLET_REVEAL_NONE: break;
    }
    return NULL;
}
/* The words about the request and, on a locked wallet that hides its private balance, the button that asks to show it. */
static void reveal_items(struct wallet_screen *s, const struct data *d)
{
    const char *words = reveal_words(d->reveal);
    bool idle = d->reveal != WALLET_REVEAL_ASKING && d->reveal != WALLET_REVEAL_OPEN;
    if (words) note(s, words);
    if (d->view.can_reveal && idle && st.env.reveal_start) button(s, WALLET_ACT_SHOW_PRIVATE, "Show private balance");
}
/* What the node reported, in the order the owner asks: spendable now, what is arriving, waiting, public and maturing, then
 * how current it is. */
static void funds_sync_lines(struct wallet_screen *s, const struct data *d, bool retained)
{
    if (retained) {
        note(s, "Could not refresh your wallet. This balance may be out of date.");
        if (d->view.scanning) line(s, d->view.sync);
    } else if (d->funds_fresh || !d->view.known) line(s, d->view.sync);
    else note(s, "Last read more than 30 seconds ago, so these amounts and the sync state may be out of date. Check that your node is running.");
}

static void funds_lines(struct wallet_screen *s, const struct data *d)
{
    bool retained = d->summary_failed && d->view.known;
    line(s, retained ? "Last known balance" : "Balance");
    (void)add(s, WALLET_ITEM_AMOUNT, WALLET_ACT_NONE, d->view.balance);
    send_lines(s, d);
    if (!d->summary_failed) reveal_items(s, d);
    if (d->view.pending[0]) line(s, d->view.pending);
    if (d->view.unready_line[0]) line(s, d->view.unready_line);
    if (d->view.total_line[0]) line(s, d->view.total_line);
    if (d->view.public_line[0]) line(s, d->view.public_line);
    if (!d->summary_failed && d->view.can_make_private) button(s, WALLET_ACT_MAKE_PRIVATE, "Make private");
    if (d->view.immature_line[0]) line(s, d->view.immature_line);
    funds_sync_lines(s, d, retained);
    if (!d->view.known) note(s, "The wallet could not be read. Check that your node is running, then open this screen again.");
    if (retained) note(s, "Sending waits until your wallet answers.");
    else if (d->view.send[0]) note(s, d->view.send);
}

/* A node that gave no answer. A process known to run is starting or busy: Start would only be refused, so the owner is told to
 * wait. Otherwise it is stopped, or not answering when the app cannot tell, and Start is offered. */
static void silent_node_items(struct wallet_screen *s)
{
    if (st.env.node_running && st.env.node_running(st.env.ctx)) {
        line(s, "Waiting for your node to answer. After a restart, this can take a few minutes.");
        return;
    }
    line(s, st.env.node_running ? "Node stopped. Start it to see your funds." : "The node is not answering. Start it to see your funds.");
    button(s, WALLET_ACT_START_NODE, "Start node");
}
static bool funds_unavailable(const struct data *d)
{
    return d->funds_loaded && d->summary_failed && !d->node_silent;
}

static void funds_unavailable_items(struct wallet_screen *s, const struct data *d)
{
    line(s, "Balance unknown");
    send_lines(s, d);
    note(s, "The wallet could not be read. Try again.");
    button(s, WALLET_ACT_RETRY_SUMMARY, "Try again");
}

static void funds_balance_items(struct wallet_screen *s, const struct data *d)
{
    if (!d->funds_loaded) { line(s, "Balance"); (void)add(s, WALLET_ITEM_AMOUNT, WALLET_ACT_NONE, "Loading…"); send_lines(s, d); }
    else if (d->node_silent) { send_lines(s, d); silent_node_items(s); }
    else if (d->cutover_status) {
        line(s, d->cutover_status == 2 ? "Updating wallet history" : "Wallet status unavailable");
        if (d->cutover_sync[0]) line(s, d->cutover_sync);
        send_lines(s, d);
    }
    else if (funds_unavailable(d)) funds_unavailable_items(s, d);
    else funds_lines(s, d);
}

static void funds_items(struct wallet_screen *s)
{
    const struct data *d = &st.d;
    title(s, "Wallet");
    button(s, WALLET_ACT_RECEIVE, "Receive");
    if (d->funds_fresh && !d->summary_failed)
        button(s, WALLET_ACT_SEND, d->scan_note[0] ? "Scan again" : "Send");
    button(s, WALLET_ACT_HISTORY, "History");
    if (d->scan_note[0]) note(s, d->scan_note);
    funds_balance_items(s, d);
    if (d->fleet_loaded && !d->node_silent) line(s, d->fleet_fresh ? d->fleet : WALLET_FLEET_UNCHECKED);
    button(s, WALLET_ACT_BACK, "Home");
}

static void share_request_items(struct wallet_screen *s)
{
    button(s, WALLET_ACT_SHARE_TEXT, "Share request");
    note(s, "You choose where to share it.");
    button(s, WALLET_ACT_SHARE_REQUEST, "Share with photos or videos");
}
static void receive_address_actions(struct wallet_screen *s, const struct data *d)
{
    if ((d->address_unavailable || d->address_read_failed) && !d->address_pending) button(s, WALLET_ACT_RETRY_ADDRESS, "Retry");
    else if (!d->address_pending && !d->address_unavailable && !d->address_read_failed && !d->no_receive) button(s, WALLET_ACT_NEW_ADDRESS, "New address");
}
static void receive_items(struct wallet_screen *s)
{
#ifdef ZAPP_SHARE_FIXTURE
    title(s, "Receive");
    (void)add(s, WALLET_ITEM_QR, WALLET_ACT_NONE, "zclassic:t1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?amount=0.001");
    (void)add(s, WALLET_ITEM_ADDRESS, WALLET_ACT_NONE, "t1 aaaa aaaa aaaa aaaa aaaa aaaa aaaa aaaa a");
    share_request_items(s);
    if (st.pending_share[0]) note(s, st.pending_share);
    if (st.d.note[0]) note(s, st.d.note);
    button(s, WALLET_ACT_BACK, "Back");
    return;
#endif
    const struct data *d = &st.d;
    char grouped[ZAPP_PAY_ADDRESS_MAX * 2], text[WALLET_TEXT_MAX];
    title(s, "Receive");
    if (st.pending_share[0]) note(s, st.pending_share);
    if (d->note[0]) note(s, d->note);
    bool shown = d->address[0] && wallet_view_group_address(d->address, grouped, sizeof(grouped));
    if (shown) {
        (void)add(s, WALLET_ITEM_QR, WALLET_ACT_NONE, d->code);
        (void)add(s, WALLET_ITEM_ADDRESS, WALLET_ACT_NONE, grouped);
        button(s, WALLET_ACT_COPY_ADDRESS, "Copy address");
        share_request_items(s);
        if (d->has_amount && zapp_zat_format(d->amount_zat, grouped, sizeof(grouped))) {
            snprintf(text, sizeof(text), "Asking for %s ZCL", grouped);
            line(s, text);
        }
    } else if (d->address_pending) line(s, "Loading your receiving address…");
    receive_address_actions(s, d);
    (void)add(s, WALLET_ITEM_INPUT, WALLET_ACT_NONE, "Amount in ZCL (optional)");
    button(s, WALLET_ACT_SET_AMOUNT, "Set amount");
    button(s, WALLET_ACT_BACK, "Back");
}

/* ---- history ---- */

static const char *direction_label(enum direction direction)
{
    return direction == DIR_SENT ? "Sent" : direction == DIR_RECEIVED ? "Received" :
           direction == DIR_INTERNAL ? "Moved inside your wallet" : "Direction unknown";
}
/* What the entry says about privacy, or "" when the node makes no claim. Only the node's fully_shielded says: true
 * when every input and output of the transaction is shielded, false when any is transparent. A payment from a
 * private balance to a public address, or from a public sender to a private one, is not private in either direction. */
static const char *pool_label(const struct entry *e)
{
    return e->shield == SHIELD_FULL ? "Private" : e->shield == SHIELD_PART ? "Public" : "";
}
static const char *state_label(enum status status)
{
    return status == STATUS_CONFIRMED ? "Confirmed" : status == STATUS_PENDING ? "Pending" : "State unknown";
}
static void amount_label(const struct entry *e, char *out, size_t cap)
{
    char zcl[32];
    if (e->amount_known && zapp_zat_format(e->amount_zat, zcl, sizeof(zcl))) snprintf(out, cap, "%s ZCL", zcl);
    else copy(out, cap, "Amount unknown");
}
/* Calendar arithmetic on the proleptic Gregorian calendar, in days since 1970-01-01. */
static int64_t days_of(int64_t year, int64_t month, int64_t day)
{
    year -= month <= 2;
    int64_t era = (year >= 0 ? year : year - 399) / 400, yoe = year - era * 400;
    int64_t doy = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;
    return era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468;
}
static void civil_of(int64_t days, int64_t *year, int64_t *month, int64_t *day)
{
    days += 719468;
    int64_t era = (days >= 0 ? days : days - 146096) / 146097, doe = days - era * 146097;
    int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100), mp = (5 * doy + 2) / 153;
    *day = doy - (153 * mp + 2) / 5 + 1;
    *month = mp < 10 ? mp + 3 : mp - 9;
    *year = yoe + era * 400 + (*month <= 2);
}
static int64_t floor_div(int64_t a, int64_t b) { return a / b - (a % b < 0); }
static int64_t tm_seconds(const struct tm *t)
{
    return days_of(t->tm_year + 1900, t->tm_mon + 1, t->tm_mday) * 86400 + t->tm_hour * 3600 + t->tm_min * 60 + t->tm_sec;
}
void wallet_time_label(int64_t now, int64_t when, int64_t offset, char *out, size_t cap)
{
    static const char *const months[12] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    int64_t local = when + offset, day = floor_div(local, 86400), today = floor_div(now + offset, 86400);
    int64_t secs = local - day * 86400, year, month, dom, this_year, this_month, this_day;
    char clock[32];
    snprintf(clock, sizeof(clock), "%02lld:%02lld", (long long)(secs / 3600), (long long)(secs % 3600 / 60));
    civil_of(day, &year, &month, &dom);
    civil_of(today, &this_year, &this_month, &this_day);
    if (day == today) snprintf(out, cap, "Today %s", clock);
    else if (day == today - 1) snprintf(out, cap, "Yesterday %s", clock);
    else if (year == this_year) snprintf(out, cap, "%lld %s %s", (long long)dom, months[month - 1], clock);
    else snprintf(out, cap, "%lld %s %lld %s", (long long)dom, months[month - 1], (long long)year, clock);
}
int64_t wallet_utc_offset(int64_t when)
{
    struct tm local;
    time_t at = (time_t)when;
    return localtime_r(&at, &local) ? tm_seconds(&local) - when : 0;
}
/* The time of an entry in the phone's time zone, or "Date unknown". The entry keeps its time in UTC. */
static void date_label(const struct entry *e, char *out, size_t cap)
{
    if (!e->time_known) { copy(out, cap, "Date unknown"); return; }
    wallet_time_label(wall_s(), e->time, wallet_utc_offset(e->time), out, cap);
}
static void row_text(const struct entry *e, char *out, size_t cap)
{
    char amount[48], date[32];
    amount_label(e, amount, sizeof(amount));
    date_label(e, date, sizeof(date));
    const char *pool = pool_label(e);
    snprintf(out, cap, "%s\n%s%s%s · %s · %s", amount, direction_label(e->direction), pool[0] ? " · " : "", pool, state_label(e->status), date);
}

/* The sentence for a first page with no rows. "No transactions yet." only when the node says it is current. */
static const char *empty_history_text(const struct data *d)
{
    if (!d->funds_loaded || !d->view.known) return "None found so far.";
    if (d->view.scanning) return "None found so far. The wallet is still scanning the chain.";
    return d->view.current ? "No transactions yet." : "None found so far. The node is not up to date.";
}
/* The line above the rows: loading, a failure, what the node says is missing from the list, or why it is empty. An
 * empty list is never called empty unless the node says it holds every payment. */
static void history_status(struct wallet_screen *s, const struct data *d)
{
    if (d->history_pending) { line(s, "Loading…"); return; }
    if (d->history_failed) { note(s, "History could not be read. Check that your node is running, then open History again."); return; }
    if (d->history_state == HIST_HIDDEN) {
        note(s, "Private payments are hidden while the wallet is locked. Only public ones are listed.");
        return;
    }
    if (d->history_state != HIST_OK) {
        note(s, "The node did not say whether this list is complete, so private payments may be missing.");
        return;
    }
    if (!d->rows) line(s, d->page ? "No older transactions." : empty_history_text(d));
}

static void history_items(struct wallet_screen *s)
{
    const struct data *d = &st.d;
    char text[WALLET_TEXT_MAX];
    title(s, "History");
    history_status(s, d);
    for (size_t i = 0; i < d->rows; ++i) {
        row_text(&d->entry[i], text, sizeof(text));
        struct wallet_item *item = add(s, WALLET_ITEM_BUTTON, WALLET_ACT_DETAIL, text);
        if (item) item->arg = (unsigned)i;
    }
    if (d->page) button(s, WALLET_ACT_NEWER, "Newer");
    if (d->has_more && d->page + 1 < PAGES_MAX) button(s, WALLET_ACT_OLDER, "Older");
    else if (d->has_more) note(s, "Older transactions are not listed here.");
    button(s, WALLET_ACT_BACK, "Back");
}

static void detail_memo_items(struct wallet_screen *s, const struct data *d)
{
    line(s, "Memo, written by the sender");
    if (d->detail_pending) line(s, "Loading…");
    else if (d->detail_failed) note(s, "The memo could not be read. Check that your node is running, then open this transaction again.");
    else if (!d->memo_loaded) note(s, "The wallet reports a memo but gave none.");
    else {
        if (d->memo_hex) line(s, "Not text, so shown as hexadecimal");
        memo_items(s, d->memo);
        if (d->memo_over) note(s, "The memo was longer than the 512 bytes the wallet keeps, so it is cut.");
    }
}

static void detail_items(struct wallet_screen *s)
{
    const struct data *d = &st.d;
    const struct entry *e = &d->entry[d->detail < d->rows ? d->detail : 0];
    char text[WALLET_TEXT_MAX];
    title(s, direction_label(e->direction));
    line(s, e->shield == SHIELD_PART ? "Public: at least one amount or address in this payment is visible to everyone." :
            e->shield == SHIELD_FULL ? "Private" : "The node does not say whether every part of this payment was private.");
    amount_label(e, text, sizeof(text));
    (void)add(s, WALLET_ITEM_AMOUNT, WALLET_ACT_NONE, text);
    line(s, state_label(e->status));
    date_label(e, text, sizeof(text));
    line(s, text);
    line(s, "Transaction id");
    line(s, e->txid[0] ? e->txid : "unknown");
    if (e->memo_present) detail_memo_items(s, d);
    button(s, WALLET_ACT_BACK, "Back");
}

/* Whether two copies of a screen hold the same items, so that a redraw with nothing new keeps the widgets it has. */
bool wallet_screen_same(const struct wallet_screen *a, const struct wallet_screen *b)
{
    if (a->page != b->page || a->count != b->count) return false;
    for (size_t i = 0; i < a->count; ++i) {
        const struct wallet_item *x = &a->items[i], *y = &b->items[i];
        if (x->kind != y->kind || x->action != y->action || x->arg != y->arg || strcmp(x->text, y->text)) return false;
    }
    return true;
}

static void request_guard(void);
static bool fallback_current(void)
{
    request_guard();
    if (st.d.offline_bound) {
        char identity[82];
        if (st.env.setup_identity && st.env.setup_identity(st.env.ctx, identity) && !strcmp(identity, st.d.offline_identity)) return true;
        st.d.address[0] = 0; st.d.code[0] = 0; st.d.address_fallback = false; st.d.offline_bound = false;
        clear_share_notice(); st.d.address_pending = false; ++st.epoch; touch();
        return false;
    }
    if (!st.d.setup_bound) return true;
    char address[ZAPP_PAY_ADDRESS_MAX];
    uint64_t generation = 0;
    if (st.env.setup_address && st.env.setup_address(st.env.ctx, address, sizeof(address), &generation) &&
        generation == st.d.address_generation && !strcmp(address, st.d.setup_anchor)) return true;
    st.d.address[0] = 0; st.d.code[0] = 0; st.d.address_fallback = false; st.d.setup_bound = false;
    clear_share_notice(); st.d.address_pending = false; ++st.epoch; touch();
    return false;
}
unsigned wallet_screens_snapshot(struct wallet_screen *out)
{
    unsigned version;
    pthread_mutex_lock(&st.lock);
    (void)fallback_current();
    out->page = st.page;
    out->count = 0;
    if (st.blocked) {
        (void)add(out, WALLET_ITEM_TITLE, WALLET_ACT_NONE, "Wallet");
        char notice[WALLET_TEXT_MAX];
        snprintf(notice, sizeof(notice), "The wallet is not shown because this phone would not let the app %s.",
                 st.why[0] ? st.why : "protect the screen");
        note(out, notice);
        button(out, WALLET_ACT_BACK, "Home");
    } else if (st.page == WALLET_PAGE_FUNDS) funds_items(out);
    else if (st.page == WALLET_PAGE_RECEIVE) receive_items(out);
    else if (st.page == WALLET_PAGE_HISTORY) history_items(out);
    else if (st.page == WALLET_PAGE_DETAIL) detail_items(out);
    version = st.version;
    pthread_mutex_unlock(&st.lock);
    return version;
}

/* ---- replies ---- */

/* A cached or legacy response cannot establish current cutover authority. */
static int summary_readiness_status(const struct json_value *data)
{
    const struct json_value *available = data ? json_get(data, "balance_available") : NULL;
    const char *readiness = data ? json_get_str(json_get(data, "wallet_readiness")) : NULL;
    int status = 0;
    if (available && available->type == JSON_BOOL && readiness) {
        if (json_get_bool(available) && strcmp(readiness, "ready") == 0) status = 1;
        else if (!json_get_bool(available) && strcmp(readiness, "pending") == 0) status = 2;
        else if (!json_get_bool(available) && strcmp(readiness, "unknown") == 0) status = 3;
    }
    return status;
}

static void summary_format_sync(const struct json_value *data, int status,
                                char *sync, size_t cap)
{
    const struct json_value *tip = data ? json_get(data, "tip_height") : NULL;
    const struct json_value *behind = data ? json_get(data, "blocks_behind") : NULL;
    if (status >= 2 && tip && tip->type == JSON_INT && json_get_int(tip) >= 0 &&
        behind && behind->type == JSON_INT && json_get_int(behind) >= 0)
        snprintf(sync, cap, "Block %lld; %lld blocks left", (long long)json_get_int(tip),
                 (long long)json_get_int(behind));
}

static int summary_status(const char *text, char *sync, size_t cap)
{
    struct json_value root = {0};
    const char *start = json_start(text);
    bool ok = start && json_read(&root, start, strlen(start));
    const struct json_value *data = ok ? data_of(&root) : NULL;
    int status = summary_readiness_status(data);
    summary_format_sync(data, status, sync, cap);
    json_cleanse_strings(&root);
    json_free(&root);
    return status;
}

static bool defer_initial_summary(bool valid, bool silent, bool received)
{
    if (st.d.summary_validated || valid || silent || !received ||
        st.d.initial_failures >= 3 || ++st.d.initial_failures >= 3) return false;
    st.d.funds_loaded = false;
    st.d.node_silent = false;
    st.d.summary_failed = true;
    st.d.initial_retry_wait = true;
    st.d.initial_retry_at = now();
    return true;
}

/* silent: the node did not answer at all, as opposed to answering with an error of its own. */
static void apply_summary(bool ok, bool silent, bool received, const char *json)
{
    struct wallet_view next;
    char sync[96] = {0};
    int status = ok ? summary_status(json, sync, sizeof(sync)) : 0;
    bool valid = status == 1 && wallet_view_from_summary(json, &next);
    if (!valid) memset(&next, 0, sizeof(next));
    if (defer_initial_summary(valid || status >= 2, silent, received)) {
        memory_cleanse(&next, sizeof(next));
        return;
    }
    st.d.initial_retry_wait = false;
    st.d.cutover_status = status >= 2 ? status : 0;
    copy(st.d.cutover_sync, sizeof(st.d.cutover_sync), sync);

    st.d.funds_loaded = true;
    st.d.summary_failed = !valid;
    st.d.funds_fresh = valid;
    st.d.node_silent = !ok && silent;
    if (valid) { st.d.summary_at = now(); st.d.initial_failures = 0; st.d.summary_validated = true; }
    st.d.view = next;
    memory_cleanse(&next, sizeof(next));
}

enum how { HOW_INVALID, HOW_UNKNOWN, HOW_AGREES, HOW_AHEAD, HOW_APART };
/* The agreement a machine row names, by the words the node uses. A machine one or more blocks behind on this
 * chain agrees with it; one ahead of this node has not been compared and counts as neither agreeing nor apart. */
static enum how how_of(const char *how)
{
    if (is(how, "agrees") || is(how, "machine_behind")) return HOW_AGREES;
    if (is(how, "phone_behind")) return HOW_AHEAD;
    if (is(how, "disagree")) return HOW_APART;
    return is(how, "unknown") ? HOW_UNKNOWN : HOW_INVALID;
}
/* Counts the machines by agreement. False when they are not exactly the typed list: a machine that is not
 * connected is "unknown", and every agreement is one the node names. */
static bool count_machines(const struct json_value *list, int *connected, int *agrees, int *apart)
{
    *connected = *agrees = *apart = 0;
    for (size_t i = 0; i < json_size(list); ++i) {
        const struct json_value *m = json_at(list, i);
        const struct json_value *up = typed(m, "connected", JSON_BOOL);
        enum how how = how_of(text_of(m, "agreement"));
        if (!m || m->type != JSON_OBJ || !up || !typed(m, "name", JSON_STR) || how == HOW_INVALID) return false;
        if (!json_get_bool(up)) { if (how != HOW_UNKNOWN) return false; continue; }
        ++*connected;
        if (how == HOW_AGREES) ++*agrees;
        else if (how == HOW_APART) ++*apart;
    }
    return true;
}
/* Whether the reply is exactly the typed fleet status; the counts of machines are returned. */
static bool fleet_shape(const struct json_value *data, int *connected, int *agrees, int *apart)
{
    const struct json_value *list = typed(data, "machines", JSON_ARR), *total = typed(data, "machines_total", JSON_INT);
    const struct json_value *up = typed(data, "machines_connected", JSON_INT);
    if (!is(text_of(data, "schema"), "zcl.fleet_status.v1") || !list || !total || !up || !typed(data, "member", JSON_BOOL) ||
        !typed(data, "refuses_send", JSON_BOOL) || !text_of(data, "verdict") || !typed(data, "local_tip", JSON_INT) ||
        json_size(list) > MACHINES_MAX || json_get_int(total) != (int64_t)json_size(list) ||
        !count_machines(list, connected, agrees, apart) || json_get_int(up) != *connected) return false;
    return true;
}
/* The fleet line, or false when the reply is not exactly the typed shape and the fleet counts as not checked.
 * "Sending waits" is worded from the node's own refuses_send, and only a disagreement the machines show can
 * come with it; a verdict the machines do not bear out is not shown. */
static bool fleet_text(const struct json_value *data, char *out, size_t cap)
{
    int connected, agrees, apart;
    if (!fleet_shape(data, &connected, &agrees, &apart)) return false;
    const char *verdict = text_of(data, "verdict");
    bool member = json_get_bool(typed(data, "member", JSON_BOOL)), refuses = json_get_bool(typed(data, "refuses_send", JSON_BOOL));
    if (!member) return false;
    if (is(verdict, "agree") && agrees > 0 && apart == 0 && !refuses) {
        if (agrees == 1) copy(out, cap, "1 fleet machine agrees");
        else snprintf(out, cap, "%d fleet machines agree", agrees);
        return true;
    }
    if (is(verdict, "disagree") && apart > 0) {
        snprintf(out, cap, refuses ? "%d of %d fleet machines disagree: sending waits until they agree" :
                 "%d of %d fleet machines last reported another chain at a lower height: sending is not held back", apart, connected);
        return true;
    }
    return false;
}
static void apply_fleet(bool ok, const char *json)
{
    struct json_value root;
    const struct json_value *data;
    json_init(&root);
    st.d.fleet_loaded = st.d.fleet_fresh = true;
    st.d.fleet_at = now();
    if (!(ok && json && json_read(&root, json, strlen(json)) && (data = data_of(&root)) && fleet_text(data, st.d.fleet, sizeof(st.d.fleet))))
        copy(st.d.fleet, sizeof(st.d.fleet), WALLET_FLEET_UNCHECKED);
    drop_tree(&root);
}

/* The network whose private address this is, or false for anything else, a public address included. */
static bool private_network(const char *address, enum zapp_pay_network *network)
{
    struct zapp_payment parsed;
    for (int n = ZAPP_PAY_MAINNET; n <= ZAPP_PAY_REGTEST; ++n) {
        if (zapp_payment_parse(address, strlen(address), (enum zapp_pay_network)n, &parsed) == ZAPP_PAY_OK && parsed.kind == ZAPP_PAY_PRIVATE) {
            *network = (enum zapp_pay_network)n;
            return true;
        }
    }
    return false;
}
/* The code for the address and amount, kept only when the parser reads it back as the same payment. */
static void rebuild_code(void)
{
    struct zapp_payment got;
    struct data *d = &st.d;
    d->code[0] = '\0';
    if (zapp_payment_receive_code(d->address, d->has_amount, d->amount_zat, d->code, sizeof(d->code)) &&
        zapp_payment_parse(d->code, strlen(d->code), d->network, &got) == ZAPP_PAY_OK && !strcmp(got.address, d->address) &&
        got.has_amount == d->has_amount && (!d->has_amount || got.amount_zat == d->amount_zat)) return;
    memory_cleanse(d->address, sizeof(d->address));
    memory_cleanse(d->code, sizeof(d->code));
    copy(d->note, sizeof(d->note), "A code could not be made for this address. Tap New address.");
}

static void request_clear(void) { memory_cleanse(&st.request, sizeof(st.request)); }
static void request_guard(void)
{
    char identity[82];
    if (!st.request.valid) return;
    if (st.env.setup_identity && st.env.setup_identity(st.env.ctx, identity) &&
        !strcmp(identity, st.request.identity)) return;
    request_clear(); st.d.has_amount = false; st.d.amount_zat = 0; clear_share_notice();
    if (st.d.address[0]) rebuild_code();
    touch();
}
static void request_save(void)
{
    char identity[82];
    request_clear();
    if (!st.d.has_amount || !st.d.address[0] || !st.env.setup_identity ||
        !st.env.setup_identity(st.env.ctx, identity)) return;
    st.request.valid = true; st.request.amount = st.d.amount_zat;
    copy(st.request.identity, sizeof(st.request.identity), identity);
    copy(st.request.address, sizeof(st.request.address), st.d.address);
}
static void request_restore(const char *address)
{
    char identity[82];
    if (!st.request.valid) return;
    if (!st.env.setup_identity || !st.env.setup_identity(st.env.ctx, identity) ||
        strcmp(identity, st.request.identity) || strcmp(address, st.request.address)) {
        request_clear(); st.d.has_amount = false; st.d.amount_zat = 0; clear_share_notice(); return;
    }
    st.d.has_amount = true; st.d.amount_zat = st.request.amount;
}
static void show_address(const char *address)
{
    if (st.d.address[0] && strcmp(st.d.address, address)) clear_share_notice();
    if (!st.d.share_notice) st.d.note[0] = '\0';
    if (!private_network(address, &st.d.network)) {
        clear_share_notice();
        copy(st.d.note, sizeof(st.d.note), "The wallet returned an address that is not private, so it is not shown. Tap New address.");
    }
    else {
        copy(st.d.address, sizeof(st.d.address), address);
        request_restore(address);
        rebuild_code();
        if (st.d.has_amount && !st.request.valid) request_save();
        if (st.pending_share[0] && st.page == WALLET_PAGE_RECEIVE) {
            st.d.share_notice = true;
            copy(st.d.note, sizeof(st.d.note), st.pending_share);
            clear_pending_share_notice();
        }
    }
}
/* A reply that names an address: {"address":"zs1..."}. latest may answer null when the wallet has none. */
static bool strict_private(const char *address)
{
    char hrp[32]; uint8_t data[69]; size_t len = 0;
    enum zapp_pay_network network;
    return private_network(address, &network) &&
           domain_encoding_bech32_decode(hrp, sizeof(hrp), data, sizeof(data), &len, address) &&
           len == 69 && (data[68] & 1u) == 0;
}
static void address_unavailable(void)
{
    request_clear(); st.d.has_amount = false; st.d.amount_zat = 0; clear_share_notice();
    memory_cleanse(st.d.address, sizeof(st.d.address));
    memory_cleanse(st.d.code, sizeof(st.d.code));
    st.d.address_fallback = false;
    st.d.offline_bound = false;
    st.d.setup_bound = false;
    st.d.address_pending = false;
    st.d.address_unavailable = true;
    st.d.address_read_failed = false;
    copy(st.d.note, sizeof(st.d.note),
         "The receive address cannot be checked. Retry or check your wallet.");
}

static void latest_address_failure(const struct json_value *data, bool missing)
{
    if (st.d.address_unavailable) address_unavailable();
    else if (st.d.address_fallback && (missing || (data && typed(data, "address", JSON_NULL)))) st.d.note[0] = 0;
    else if (data && typed(data, "address", JSON_NULL)) copy(st.d.note, sizeof(st.d.note), "This wallet has no receive address yet. Tap New address.");
    else if (missing) copy(st.d.note, sizeof(st.d.note), "This node cannot report its latest address yet. Tap New address to make one.");
    else {
        st.d.address_read_failed = true;
        copy(st.d.note, sizeof(st.d.note), st.d.address[0] ?
             "Could not refresh your receiving address." : "Your receiving address is not available yet.");
    }
}
static void address_failure(const struct json_value *data, bool missing, bool latest, bool preserve_share)
{
    if (preserve_share) return;
    clear_committed_share_notice();
    if (latest) latest_address_failure(data, missing);
    else if (missing) {
        st.d.no_receive = true;
        copy(st.d.note, sizeof(st.d.note), "This build cannot make a new address.");
    } else copy(st.d.note, sizeof(st.d.note), "No address was made. Check that your node is running.");
}
static bool address_reply_unavailable(const struct json_value *data)
{
    const char *state = text_of(data, "state");
    return is(state, "address_unavailable") || is(state, "keys_unavailable");
}
static bool address_is_showable(const char *address)
{
    return address && address[0] && strlen(address) < sizeof(st.d.address) &&
           (!(st.d.setup_bound || st.d.offline_bound) || strict_private(address));
}

static bool share_notice_survives_silence(bool latest, bool silent)
{
    return latest && silent && st.d.share_notice && st.d.address[0];
}

static void apply_address(bool ok, bool missing, bool latest, const char *json, bool silent)
{
    struct json_value root;
    const struct json_value *data;
    const char *address = NULL;
    if (!fallback_current()) return;
    st.d.address_pending = false;
    if (latest) st.d.address_read_failed = false;
    json_init(&root);
    data = ok && json && json_read(&root, json, strlen(json)) ? data_of(&root) : NULL;
    address = text_of(data, "address");
    if (latest && address_reply_unavailable(data)) {
        address_unavailable();
        drop_tree(&root);
        return;
    }
    if (latest && data && typed(data, "address", JSON_NULL) &&
        is(text_of(data, "state"), "none")) st.d.address_unavailable = false;
    if (address_is_showable(address)) {
        show_address(address);
        if (st.d.address[0]) { st.d.address_unavailable = false; st.d.address_read_failed = false; }
        st.d.offline_bound = false;
        st.d.address_fallback = false;
    }
    else address_failure(data, missing, latest, share_notice_survives_silence(latest, silent));
    drop_tree(&root);
}

static enum direction read_direction(const char *text)
{
    return is(text, "sent") ? DIR_SENT : is(text, "received") ? DIR_RECEIVED : is(text, "internal") ? DIR_INTERNAL : DIR_UNKNOWN;
}
static void read_entry(const struct json_value *row, struct entry *e)
{
    const struct json_value *amount = typed(row, "amount_zat", JSON_INT), *time = typed(row, "time", JSON_INT);
    const struct json_value *memo = typed(row, "memo_present", JSON_BOOL), *shielded = typed(row, "fully_shielded", JSON_BOOL);
    const char *status = text_of(row, "status"), *txid = text_of(row, "txid");
    memset(e, 0, sizeof(*e));
    e->direction = read_direction(text_of(row, "direction"));
    e->status = is(status, "confirmed") ? STATUS_CONFIRMED : is(status, "pending") ? STATUS_PENDING : STATUS_UNKNOWN;
    if (amount && json_get_int(amount) >= 0 && (uint64_t)json_get_int(amount) <= ZAPP_PAY_MAX_ZAT) {
        e->amount_known = true;
        e->amount_zat = (uint64_t)json_get_int(amount);
    }
    if (time && json_get_int(time) > 0 && json_get_int(time) <= MAX_UNIX) {
        e->time_known = true;
        e->time = json_get_int(time);
    }
    if (wallet_txid_valid(txid)) copy(e->txid, sizeof(e->txid), txid);
    e->memo_present = memo && json_get_bool(memo);
    e->shield = !shielded ? SHIELD_UNKNOWN : json_get_bool(shielded) ? SHIELD_FULL : SHIELD_PART;
}
/* Reads the page. False when the reply is not exactly the typed frame, which is an error and not an empty wallet. */
static enum history_state read_history_state(const struct json_value *data)
{
    const char *state = text_of(data, "shielded_state");
    return is(state, "ok") ? HIST_OK : is(state, "keys_unavailable") ? HIST_HIDDEN : HIST_UNSAID;
}
static bool read_page(const struct json_value *data)
{
    const struct json_value *entries = typed(data, "entries", JSON_ARR), *count = typed(data, "count", JSON_INT);
    const struct json_value *next = json_get(data, "next_cursor");
    if (!is(text_of(data, "schema"), "zcl.wallet_history.v1") || !entries || !count || !next ||
        json_get_int(count) != (int64_t)json_size(entries) || json_size(entries) > WALLET_PAGE_ROWS) return false;
    if (next->type != JSON_NULL && !(next->type == JSON_STR && wallet_cursor_valid(json_get_str(next)))) return false;
    for (size_t i = 0; i < json_size(entries); ++i) if (json_at(entries, i)->type != JSON_OBJ) return false;
    for (size_t i = 0; i < json_size(entries); ++i) read_entry(json_at(entries, i), &st.d.entry[i]);
    st.d.history_state = read_history_state(data);
    st.d.rows = json_size(entries);
    st.d.has_more = next->type == JSON_STR;
    if (st.d.has_more) copy(st.d.next, sizeof(st.d.next), json_get_str(next));
    return true;
}
static void apply_history(bool ok, const char *json)
{
    struct json_value root;
    const struct json_value *data;
    st.d.history_pending = false;
    st.d.history_state = HIST_UNSAID;
    st.d.rows = 0;
    st.d.has_more = false;
    json_init(&root);
    data = ok && json && json_read(&root, json, strlen(json)) ? data_of(&root) : NULL;
    st.d.history_failed = !data || !read_page(data);
    if (st.d.history_failed) { st.d.rows = 0; st.d.has_more = false; }
    drop_tree(&root);
}

enum memo_read { MEMO_NONE, MEMO_OK, MEMO_BAD };
/* The memo of a detail: text, or hexadecimal when it is not text. Neither member is no memo; both, or one
 * that is of another type or not hexadecimal, is a memo that cannot be read. */
static enum memo_read memo_from(const struct json_value *entry)
{
    const char *text = text_of(entry, "memo"), *hex = text_of(entry, "memo_hex");
    size_t n, limit;
    if (!json_get(entry, "memo") && !json_get(entry, "memo_hex")) return MEMO_NONE;
    if (text && !hex) n = strlen(text);
    else if (hex && !text) {
        n = strlen(hex);
        if (n % 2 || !wallet_hex_valid(hex, n)) return MEMO_BAD;
    } else return MEMO_BAD;
    st.d.memo_hex = hex != NULL;
    limit = st.d.memo_hex ? 1024u : 512u;
    st.d.memo_over = n > limit;
    snprintf(st.d.memo, sizeof(st.d.memo), "%.*s", (int)(n < limit ? n : limit), text ? text : hex);
    return MEMO_OK;
}
static void apply_detail(bool ok, const char *json)
{
    struct json_value root;
    const struct json_value *data, *entry;
    const struct entry *row = &st.d.entry[st.d.detail < st.d.rows ? st.d.detail : 0];
    st.d.detail_pending = false;
    json_init(&root);
    data = ok && json && json_read(&root, json, strlen(json)) ? data_of(&root) : NULL;
    entry = typed(data, "entry", JSON_OBJ);
    enum memo_read memo = MEMO_NONE;
    st.d.detail_failed = !entry || !is(text_of(data, "schema"), "zcl.wallet_history.v1") || !is(text_of(entry, "txid"), row->txid);
    if (!st.d.detail_failed) memo = memo_from(entry);
    st.d.detail_failed = st.d.detail_failed || memo == MEMO_BAD;
    st.d.memo_loaded = memo == MEMO_OK;
    drop_tree(&root);
}

/* ---- commands ---- */

struct reply { bool ok, missing, silent, received, offline, preloaded; char identity[82]; uint64_t preload_epoch; const char *json; };

static bool offline_envelope_ok(const struct reply *r, const struct json_value *root)
{
    const struct json_value *ok = typed(root, "ok", JSON_BOOL);
    const struct json_value *err = typed(root, "error", JSON_OBJ);
    const char *code = text_of(err, "code");
    if (!ok) return false;
    if (json_get_bool(ok)) return r->ok;
    return !r->ok && code && !strcmp(code, "WALLET_LOCKED");
}

static bool offline_address_valid(const struct reply *r, const char *address)
{
    char now[82];
    return address && strict_private(address) && st.env.setup_identity &&
           st.env.setup_identity(st.env.ctx, now) && !strcmp(now, r->identity);
}

static bool preload_current(const struct reply *r)
{
    if (!r->preloaded) return true;
    char text[8192], identity[65];
    uint64_t epoch = 0;
    bool command_ok = false;
    return st.env.preload_get &&
           st.env.preload_get(st.env.ctx, text, sizeof(text), identity, &epoch, &command_ok) &&
           epoch == r->preload_epoch && command_ok == r->ok &&
           !strncmp(identity, r->identity, 64);
}

static bool offline_unavailable(const struct reply *r, const struct json_value *root,
                                const struct json_value *source, const char *address)
{
    char current_identity[82];
    return !address && offline_envelope_ok(r, root) &&
        is(text_of(source, "receive_address_status"), "unavailable") &&
        st.env.setup_identity && st.env.setup_identity(st.env.ctx, current_identity) &&
        !strcmp(current_identity, r->identity) && preload_current(r);
}

static bool apply_offline(const struct reply *r)
{
    struct json_value root;
    json_init(&root);
    bool parsed = r->json && json_read(&root, r->json, strlen(r->json));
    const struct json_value *data = parsed ? typed(&root, "data", JSON_OBJ) : NULL;
    const struct json_value *error = parsed ? typed(&root, "error", JSON_OBJ) : NULL;
    const struct json_value *facts = typed(error, "facts", JSON_OBJ);
    const char *address = text_of(r->ok ? data : facts, "persisted_shielded_address");
    const struct json_value *source = r->ok ? data : facts;
    bool unavailable = parsed && offline_unavailable(r, &root, source, address);
    bool valid = parsed && offline_envelope_ok(r, &root) && offline_address_valid(r, address) && preload_current(r);
    if (unavailable) address_unavailable();

    if (valid) {
        show_address(address);
        if (st.d.address[0]) { st.d.address_unavailable = false; st.d.address_read_failed = false; }
        copy(st.d.offline_identity, sizeof(st.d.offline_identity), r->identity);
        st.d.offline_bound = st.d.address[0] != 0;
        st.d.address_fallback = st.d.offline_bound;
        st.d.address_pending = false;
        if (!st.d.share_notice) st.d.note[0] = 0;
    }
    drop_tree(&root);
    return valid || unavailable;
}

static void apply(const struct job *j, const struct reply *r)
{
    if (!strcmp(j->op, "summary")) apply_summary(r->ok, r->silent, r->received, r->json);
    else if (!strcmp(j->op, "fleet")) apply_fleet(r->ok, r->json);
    else if (!strcmp(j->op, "history")) apply_history(r->ok, r->json);
    else if (!strcmp(j->op, "detail")) apply_detail(r->ok, r->json);
    else if (!strcmp(j->op, "preload")) {
        if (r->preloaded && (!st.d.address[0] || st.d.address_fallback)) (void)apply_offline(r);
    }
    else if (r->offline) { if (!apply_offline(r)) apply_address(false, r->missing, true, NULL, r->silent); }
    else apply_address(r->ok, r->missing, !strcmp(j->op, "latest"), r->json, r->silent);
}

static void finish(const struct job *j, const struct reply *r)
{
    bool live;
    struct cache_job keep = {0};
    pthread_mutex_lock(&st.lock);
    live = st.ready && j->epoch == st.epoch;
    if (live) { apply(j, r); touch(); }
    if (live && !strcmp(j->op, "summary") && !st.d.summary_failed) cache_prepare(&keep);
    pthread_mutex_unlock(&st.lock);
    cache_commit(&keep);
    if (live && j->env.changed) j->env.changed(j->env.ctx);
}

static bool offline_eligible(const struct job *j, char identity[82])
{
    return !strcmp(j->op, "latest") && j->env.node_running &&
           !j->env.node_running(j->env.ctx) && j->env.setup_identity &&
           j->env.setup_identity(j->env.ctx, identity);
}

static void run_offline(const struct job *j, char *out, struct reply *r)
{
    char after[82];
    out[0] = 0;
    r->ok = j->env.run(j->env.ctx, "offline_address", "", out, OUT_CAP);
    r->offline = offline_eligible(j, after) && !strcmp(after, r->identity);
    if (!r->offline) { out[0] = 0; r->ok = false; }
}

static void classify_reply(struct reply *r, char *out)
{
    r->missing = out && !r->ok && strstr(out, "UNKNOWN_COMMAND");
    r->silent = out && !r->ok && (strstr(out, "NODE_UNAVAILABLE") || strstr(out, "The command timed out."));
    r->received = r->ok || (out && out[0]);
    r->json = json_start(out ? out : "");
}

static void run_preloaded(const struct job *j, char *out, struct reply *r)
{
    char before[82], after[82], identity[65];
    uint64_t epoch = 0;
    bool command_ok = false;
    if (!j->env.setup_identity || !j->env.preload_get ||
        !j->env.setup_identity(j->env.ctx, before) ||
        !j->env.preload_get(j->env.ctx, out, OUT_CAP, identity, &epoch, &command_ok) ||
        !j->env.setup_identity(j->env.ctx, after) || strcmp(before, after) ||
        strncmp(identity, before, 64)) return;
    copy(r->identity, sizeof(r->identity), before);
    r->preload_epoch = epoch;
    r->preloaded = true;
    r->offline = true;
    r->ok = command_ok;
}

static void run_job(const struct job *j)
{
    char *out = calloc(1, OUT_CAP);
    struct reply r = {0};
    if (out && !strcmp(j->op, "preload")) {
        run_preloaded(j, out, &r);
        classify_reply(&r, out);
        finish(j, &r);
        memory_cleanse(out, OUT_CAP); free(out);
        return;
    }
    bool offline_first = out && offline_eligible(j, r.identity);
    if (offline_first)
        run_offline(j, out, &r);
    else {
        r.ok = out && j->env.run && j->env.run(j->env.ctx, j->op, j->arg, out, OUT_CAP);
        if (out && !r.ok && offline_eligible(j, r.identity)) run_offline(j, out, &r);
    }
    classify_reply(&r, out);
    finish(j, &r);
    if (out) memory_cleanse(out, OUT_CAP);
    free(out);
}

static void *job_main(void *opaque)
{
    struct job *j = opaque;
    for (;;) {
        run_job(j);
        pthread_mutex_lock(&st.lock);
        struct flight *f = &st.flight[j->kind];
        if (f->queued) {
            *j = f->next;
            f->queued = false;
            memory_cleanse(&f->next, sizeof(f->next));
            pthread_mutex_unlock(&st.lock);
            continue;
        }
        f->running = false;
        pthread_mutex_unlock(&st.lock);
        break;
    }
    memory_cleanse(j, sizeof(*j));
    free(j);
    return NULL;
}
/* Starts the workers submit asked for. */
static void dispatch(struct job *jobs, size_t count)
{
    static const struct reply failed = {0};
    for (size_t i = 0; i < count; ++i) {
        struct job *heap = jobs[i].env.async ? malloc(sizeof(*heap)) : NULL;
        pthread_t thread;
        if (!jobs[i].env.async) { run_job(&jobs[i]); continue; }
        if (heap) {
            *heap = jobs[i];
            if (pthread_create(&thread, NULL, job_main, heap) == 0) { pthread_detach(thread); continue; }
            memory_cleanse(heap, sizeof(*heap));
            free(heap);
        }
        finish(&jobs[i], &failed);
        pthread_mutex_lock(&st.lock);
        st.flight[jobs[i].kind].running = false;
        pthread_mutex_unlock(&st.lock);
    }
    memory_cleanse(jobs, count * sizeof(*jobs));
}
/* Caller holds the lock. Asks for a command: one that is running keeps going and the newest request waits
 * behind it; a request that creates an address is refused while one is being made. False when refused. */
static bool submit(struct job *jobs, size_t *count, enum kind kind, const char *op, const char *arg)
{
    struct job j;
    memset(&j, 0, sizeof(j));
    j.env = st.env;
    copy(j.op, sizeof(j.op), op);
    copy(j.arg, sizeof(j.arg), arg);
    j.epoch = st.epoch;
    j.kind = kind;
    struct flight *f = &st.flight[kind];
    bool sync = !st.env.async, refused = !sync && f->running && kind == K_NEW;
    if (!refused && !sync && f->running) { f->next = j; f->queued = true; }
    else if (!refused) { f->running = !sync; jobs[(*count)++] = j; }
    memory_cleanse(&j, sizeof(j));
    return !refused;
}

/* Caller holds the lock. Reads where the request stands. The summary is asked for again when the wallet opened or locked,
 * so the private lines appear or return to hidden at once. */
static size_t reveal_poll(struct job *jobs)
{
    size_t count = 0;
    if (!st.env.reveal_state) return 0;
    enum wallet_reveal state = st.env.reveal_state(st.env.ctx);
    if (state == st.d.reveal) return 0;
    bool amounts_change = state == WALLET_REVEAL_OPEN || st.d.reveal == WALLET_REVEAL_OPEN;
    st.d.reveal = state;
    touch();
    if (amounts_change) (void)submit(jobs, &count, K_SUMMARY, "summary", "");
    return count;
}
/* The tap on Show private balance: only on a wallet whose summary offers it, and not while a request runs. */
static size_t show_private(struct job *jobs)
{
    bool offered = st.d.view.can_reveal && st.env.reveal_start && st.d.reveal != WALLET_REVEAL_ASKING &&
                   st.d.reveal != WALLET_REVEAL_OPEN;
    if (!offered) return 0;
    (void)st.env.reveal_start(st.env.ctx);
    return reveal_poll(jobs);
}

/* ---- navigation ---- */

static void wipe(void) { memory_cleanse(&st.d, sizeof(st.d)); }
static void drop_queued(void)
{
    for (int k = 0; k < K_COUNT; ++k) { st.flight[k].queued = false; memory_cleanse(&st.flight[k].next, sizeof(st.flight[k].next)); }
}
/* Caller holds the lock. Replaces the screen and starts the commands it needs. */
static size_t enter(enum wallet_page page, struct job *jobs)
{
    size_t count = 0;
    st.dropped = 0;
    wipe();
    if (page != WALLET_PAGE_RECEIVE) clear_pending_share_notice();
    ++st.epoch;
    st.page = page;
    if (page == WALLET_PAGE_FUNDS) {
        cache_load();
        send_refresh();
        st.d.requested_at = now();
        (void)submit(jobs, &count, K_SUMMARY, "summary", "");
        (void)submit(jobs, &count, K_FLEET, "fleet", "");
    }
    if (page == WALLET_PAGE_RECEIVE) {
        char address[ZAPP_PAY_ADDRESS_MAX];
        uint64_t generation = 0;
        if (st.env.setup_address && st.env.setup_address(st.env.ctx, address, sizeof(address), &generation)) {
            show_address(address);
            st.d.address_fallback = st.d.address[0] != 0;
            st.d.setup_bound = st.d.address_fallback;
            if (st.d.setup_bound) copy(st.d.setup_anchor, sizeof(st.d.setup_anchor), address);
            st.d.address_generation = generation;
        }
        st.d.address_pending = true; (void)submit(jobs, &count, K_LATEST, "latest", "");
    }
    if (page == WALLET_PAGE_HISTORY) {
        st.d.history_pending = true;
        (void)submit(jobs, &count, K_HISTORY, "history", "");
        (void)submit(jobs, &count, K_SUMMARY, "summary", "");
    }
    touch();
    return count;
}

bool wallet_screens_init(const struct wallet_env *env)
{
    if (!env || !env->secure || !env->run || !env->now_ms) return false;
    pthread_mutex_lock(&st.lock);
    memset(&st.d, 0, sizeof(st.d));
    clear_pending_share_notice();
    request_clear();
    drop_queued();
    st.env = *env;
    st.ready = true; st.secure = false; st.blocked = false;
    st.page = WALLET_PAGE_NONE;
    ++st.epoch; touch();
    pthread_mutex_unlock(&st.lock);
    return true;
}

static void leave_locked(bool keep_protection)
{
    if (st.env.reveal_end) st.env.reveal_end(st.env.ctx);
    st.held = keep_protection && st.secure;
    st.held_at = st.held ? now() : 0;
    st.held_ticks = 0;
    ++st.epoch;
    wipe();
    drop_queued();
    st.page = WALLET_PAGE_NONE;
    st.blocked = false;
    if (st.secure && !keep_protection) (void)st.env.secure(st.env.ctx, false);
    if (!keep_protection) st.secure = false;
    touch();
}
void wallet_screens_close(void)
{
    pthread_mutex_lock(&st.lock);
    if (st.ready) leave_locked(false);
    pthread_mutex_unlock(&st.lock);
}
void wallet_screens_pause(void)
{
    pthread_mutex_lock(&st.lock);
    if (st.ready) leave_locked(true);
    pthread_mutex_unlock(&st.lock);
}
void wallet_screens_shutdown(void)
{
    pthread_mutex_lock(&st.lock);
    if (st.ready) leave_locked(false);
    st.ready = false;
    clear_pending_share_notice();
    request_clear();
    memset(&st.env, 0, sizeof(st.env));
    pthread_mutex_unlock(&st.lock);
}

bool wallet_screens_open(enum wallet_page page)
{
    struct job jobs[2];
    size_t count = 0;
    pthread_mutex_lock(&st.lock);
    if (!st.ready || page == WALLET_PAGE_NONE) { pthread_mutex_unlock(&st.lock); return false; }
    if (!st.secure) {
        st.secure = st.env.secure(st.env.ctx, true);
        st.blocked = !st.secure;
        st.why[0] = '\0';
        if (st.blocked && st.env.refusal) {
            const char *words = st.env.refusal(st.env.ctx);
            if (words) copy(st.why, sizeof(st.why), words);
        }
        if (st.blocked) (void)st.env.secure(st.env.ctx, false);
    }
    if (st.blocked) { ++st.epoch; wipe(); st.page = page; touch(); }
    else count = enter(page, jobs);
    bool shown = !st.blocked;
    pthread_mutex_unlock(&st.lock);
    dispatch(jobs, count);
    return shown;
}

bool wallet_screens_back(void)
{
    struct job jobs[2];
    size_t count = 0;
    bool moved = true;
    pthread_mutex_lock(&st.lock);
    if (!st.ready || st.blocked || st.page == WALLET_PAGE_NONE || st.page == WALLET_PAGE_FUNDS) moved = false;
    else if (st.page == WALLET_PAGE_DETAIL) {
        ++st.epoch;
        st.page = WALLET_PAGE_HISTORY;
        st.d.detail_pending = st.d.detail_failed = st.d.memo_loaded = st.d.memo_hex = st.d.memo_over = false;
        memory_cleanse(st.d.memo, sizeof(st.d.memo));
        touch();
    } else count = enter(WALLET_PAGE_FUNDS, jobs);
    pthread_mutex_unlock(&st.lock);
    dispatch(jobs, count);
    return moved;
}

/* Caller holds the lock. Shows the history page whose cursor is stored, and asks for it. */
static size_t history_page(unsigned page, struct job *jobs)
{
    size_t count = 0;
    ++st.epoch;
    st.d.page = page;
    st.d.history_pending = true;
    st.d.history_failed = false;
    st.d.rows = 0;
    st.d.has_more = false;
    memory_cleanse(st.d.entry, sizeof(st.d.entry));
    (void)submit(jobs, &count, K_HISTORY, "history", st.d.cursor[page]);
    touch();
    return count;
}
static size_t older(struct job *jobs)
{
    copy(st.d.cursor[st.d.page + 1], sizeof(st.d.cursor[0]), st.d.next);
    return history_page(st.d.page + 1, jobs);
}
static size_t open_detail(unsigned row, struct job *jobs)
{
    size_t count = 0;
    st.d.detail = row;
    st.page = WALLET_PAGE_DETAIL;
    st.d.detail_pending = st.d.entry[row].memo_present && st.d.entry[row].txid[0];
    st.d.detail_failed = st.d.entry[row].memo_present && !st.d.entry[row].txid[0];
    if (st.d.detail_pending) (void)submit(jobs, &count, K_DETAIL, "detail", st.d.entry[row].txid);
    touch();
    return count;
}
/* New address: drops the shown one and asks for a fresh one, unless one is already being made. */
static size_t new_address(struct job *jobs)
{
    size_t count = 0;
    if (st.d.no_receive || st.d.address_unavailable || st.d.address_read_failed) return 0;
    ++st.epoch;
    if (!submit(jobs, &count, K_NEW, "receive", "")) { --st.epoch; return 0; }
    request_clear(); st.d.has_amount = false; st.d.amount_zat = 0; clear_share_notice();
    memory_cleanse(st.d.address, sizeof(st.d.address));
    memory_cleanse(st.d.code, sizeof(st.d.code));
    st.d.note[0] = '\0';
    st.d.address_pending = true;
    touch();
    return count;
}

/* Retry only the read; an unsafe reservation never triggers a new address. */
static size_t retry_address(struct job *jobs)
{
    size_t count = 0;
    if ((!st.d.address_unavailable && !st.d.address_read_failed) || st.d.address_pending) return 0;
    st.d.address_pending = true;
    (void)submit(jobs, &count, K_LATEST, "latest", "");
    touch();
    return count;
}

/* Copy address: the clipboard gets the bare address, never the grouped text. The reply is a note on the screen. */
static void copy_address(void)
{
    char address[ZAPP_PAY_ADDRESS_MAX];
    if (!st.d.address[0]) return;
    copy(address, sizeof(address), st.d.address);
    bool ok = st.env.copy_address && st.env.copy_address(st.env.ctx, address);
    memory_cleanse(address, sizeof(address));
    clear_share_notice();
    copy(st.d.note, sizeof(st.d.note), ok ? WALLET_COPIED_NOTE : WALLET_COPY_FAILED_NOTE);
    touch();
}

static size_t retry_summary(struct job *jobs)
{
    size_t count = 0;
    if (!funds_unavailable(&st.d) || !submit(jobs, &count, K_SUMMARY, "summary", "")) return 0;
    st.d.funds_loaded = false;
    st.d.initial_failures = 0;
    st.d.initial_retry_wait = false;
    st.d.requested_at = now();
    touch();
    return count;
}

/* The jobs a tap on the Funds page starts, or WALLET_SEND for Send. */
static size_t from_funds(enum wallet_action action, struct job *jobs, enum wallet_outcome *outcome)
{
    if (action == WALLET_ACT_RECEIVE) return enter(WALLET_PAGE_RECEIVE, jobs);
    if (action == WALLET_ACT_HISTORY) return enter(WALLET_PAGE_HISTORY, jobs);
    if (action == WALLET_ACT_RETRY_SUMMARY) return retry_summary(jobs);
    if (action == WALLET_ACT_SEND && st.d.funds_fresh && !st.d.summary_failed) *outcome = WALLET_SEND;
    if (action == WALLET_ACT_MAKE_PRIVATE && st.d.funds_loaded && !st.d.summary_failed && !st.d.node_silent && st.d.view.can_make_private)
        *outcome = WALLET_MAKE_PRIVATE;
    if (action == WALLET_ACT_START_NODE) *outcome = WALLET_START_NODE;
    if (action == WALLET_ACT_DISMISS_SEND) dismiss_send();
    if (action == WALLET_ACT_SHOW_PRIVATE) return show_private(jobs);
    return 0;
}
/* The jobs a tap on the History page starts. */
static size_t from_history(enum wallet_action action, unsigned arg, struct job *jobs)
{
    if (action == WALLET_ACT_OLDER && st.d.has_more && st.d.page + 1 < PAGES_MAX) return older(jobs);
    if (action == WALLET_ACT_NEWER && st.d.page) return history_page(st.d.page - 1, jobs);
    if (action == WALLET_ACT_DETAIL && arg < st.d.rows) return open_detail(arg, jobs);
    return 0;
}

static size_t receive_action(enum wallet_action action, enum wallet_outcome *outcome, struct job *jobs)
{
    if (action == WALLET_ACT_NEW_ADDRESS) return new_address(jobs);
    if (action == WALLET_ACT_COPY_ADDRESS) copy_address();
    if (action == WALLET_ACT_SHARE_REQUEST) *outcome = WALLET_SHARE;
    if (action == WALLET_ACT_SHARE_TEXT) *outcome = WALLET_SHARE_TEXT;
    if (action == WALLET_ACT_RETRY_ADDRESS) return retry_address(jobs);
    return 0;
}

enum wallet_outcome wallet_screens_activate(enum wallet_action action, unsigned arg)
{
    struct job jobs[2];
    size_t count = 0;
    enum wallet_outcome outcome = WALLET_STAY;
    pthread_mutex_lock(&st.lock);
    (void)fallback_current();
    if (st.dropped && action != WALLET_ACT_BACK) { st.dropped = 0; touch(); }
    if (st.ready && !st.blocked) {
        if (st.page == WALLET_PAGE_FUNDS) count = from_funds(action, jobs, &outcome);
        else if (st.page == WALLET_PAGE_RECEIVE) count = receive_action(action, &outcome, jobs);
        else if (st.page == WALLET_PAGE_HISTORY) count = from_history(action, arg, jobs);
    }
    pthread_mutex_unlock(&st.lock);
    dispatch(jobs, count);
    if (action == WALLET_ACT_BACK && !wallet_screens_back()) outcome = WALLET_LEAVE;
    return outcome;
}

bool wallet_screens_share_code(char *out, size_t cap)
{
    pthread_mutex_lock(&st.lock);
    bool ok = out && cap && st.d.address[0] && st.d.code[0] && strlen(st.d.code) < cap;
    if (ok) snprintf(out, cap, "%s", st.d.code);
    pthread_mutex_unlock(&st.lock);
    return ok;
}

void wallet_screens_receive_notice(const char *text)
{
    if (!text) return;
    pthread_mutex_lock(&st.lock);
    if (st.ready && !st.blocked && st.page == WALLET_PAGE_RECEIVE && st.d.address[0]) {
        st.d.share_notice = text[0] != '\0';
        copy(st.d.note, sizeof(st.d.note), text);
        clear_pending_share_notice();
    } else {
        if (st.d.share_notice) st.d.note[0] = '\0';
        st.d.share_notice = false;
        copy(st.pending_share, sizeof(st.pending_share), text);
    }
    touch();
    pthread_mutex_unlock(&st.lock);
}

bool wallet_screens_set_amount(const char *text)
{
    uint64_t zat = 0;
    bool ok = false, blank = true;
    pthread_mutex_lock(&st.lock);
    (void)fallback_current();
    for (const char *c = text ? text : ""; *c; ++c) if (*c != ' ') blank = false;
    if (st.ready && !st.blocked && st.page == WALLET_PAGE_RECEIVE && text) {
        st.dropped = 0;
        clear_share_notice();
        st.d.note[0] = '\0';
        if (blank) { st.d.has_amount = false; ok = true; }
        else if (zapp_zat_parse(text, &zat) && zat > 0) { st.d.has_amount = true; st.d.amount_zat = zat; ok = true; }
        else copy(st.d.note, sizeof(st.d.note), "Enter an amount above zero in ZCL, with up to 8 decimals.");
        if (ok) { request_save(); if (st.d.address[0]) rebuild_code(); }
        touch();
    }
    pthread_mutex_unlock(&st.lock);
    return ok;
}

void wallet_screens_scan_notice(const char *text)
{
    pthread_mutex_lock(&st.lock);
    if (st.ready && !st.blocked && st.page == WALLET_PAGE_FUNDS && text) {
        copy(st.d.scan_note, sizeof(st.d.scan_note), text);
        touch();
    }
    pthread_mutex_unlock(&st.lock);
}

void wallet_screens_refresh_send(void)
{
    struct job jobs[1];
    size_t count = 0;
    pthread_mutex_lock(&st.lock);
    if (st.ready && !st.blocked && st.page == WALLET_PAGE_FUNDS) {
        send_refresh();
        count = reveal_poll(jobs);
    }
    pthread_mutex_unlock(&st.lock);
    dispatch(jobs, count);
}

void wallet_screens_dropped(unsigned taps)
{
    pthread_mutex_lock(&st.lock);
    if (st.ready && !st.blocked && taps && st.dropped < 1000u) { st.dropped += taps; touch(); }
    pthread_mutex_unlock(&st.lock);
}

/* Schedule at most one summary in this tick, including a reveal-triggered read. */
static void funds_schedule_refresh(struct job *jobs, size_t *count, uint64_t t)
{
    bool scheduled = *count != 0;
    if (!scheduled && st.d.initial_retry_wait && !st.flight[K_SUMMARY].running &&
        t - st.d.initial_retry_at >= WALLET_INITIAL_RETRY_MS &&
        submit(jobs, count, K_SUMMARY, "summary", "")) {
        st.d.initial_retry_wait = false;
        scheduled = true;
    }
    if (t - st.d.requested_at < WALLET_REFRESH_MS) return;
    st.d.requested_at = t;
    if (!scheduled && (st.d.funds_loaded || !st.d.initial_failures))
        (void)submit(jobs, count, K_SUMMARY, "summary", "");
    (void)submit(jobs, count, K_FLEET, "fleet", "");
}

static void preload_schedule(struct job *jobs, size_t *count)
{
    if (!st.ready || st.blocked || st.page != WALLET_PAGE_RECEIVE || st.d.address[0] ||
        st.d.preload_tried || !st.env.preload_ready || !st.env.preload_ready(st.env.ctx)) return;
    st.d.preload_tried = true;
    (void)submit(jobs, count, K_PRELOAD, "preload", "");
}

void wallet_screens_tick(void)
{
    struct job jobs[3];
    size_t count = 0;
    pthread_mutex_lock(&st.lock);
    if (st.ready && !st.blocked && st.page == WALLET_PAGE_FUNDS) {
        send_refresh();
        count = reveal_poll(jobs);
        uint64_t t = now();
        bool funds = st.d.funds_loaded && !st.d.summary_failed && t - st.d.summary_at <= WALLET_STALE_MS;
        bool fleet = st.d.fleet_loaded && t - st.d.fleet_at <= WALLET_STALE_MS;
        if (funds != st.d.funds_fresh || fleet != st.d.fleet_fresh) { st.d.funds_fresh = funds; st.d.fleet_fresh = fleet; touch(); }
        if (st.d.cache.valid && (!st.d.funds_loaded || st.d.node_silent) && cache_minutes(&st.d.cache) != st.d.cache.minutes) {
            st.d.cache.minutes = cache_minutes(&st.d.cache);
            touch();
        }
        funds_schedule_refresh(jobs, &count, t);
    }
    preload_schedule(jobs, &count);
    pthread_mutex_unlock(&st.lock);
    dispatch(jobs, count);
}

/* The caller has drawn a screen without wallet data since the pause. */
void wallet_screens_settle(void)
{
    pthread_mutex_lock(&st.lock);
    if (st.ready && st.held && st.page == WALLET_PAGE_NONE) {
        if (st.held_ticks < WALLET_SETTLE_TICKS) ++st.held_ticks;
        if (st.held_ticks >= WALLET_SETTLE_TICKS && now() - st.held_at >= WALLET_SETTLE_MS) leave_locked(false);
    }
    pthread_mutex_unlock(&st.lock);
}

bool wallet_screens_active(void)
{
    pthread_mutex_lock(&st.lock);
    bool active = st.ready && st.page != WALLET_PAGE_NONE;
    pthread_mutex_unlock(&st.lock);
    return active;
}

bool wallet_screens_spendable(uint64_t *zat)
{
    pthread_mutex_lock(&st.lock);
    const struct data *d = &st.d;
    bool known = st.ready && !st.blocked && st.page == WALLET_PAGE_FUNDS && d->funds_loaded && !d->summary_failed && !d->node_silent &&
                 now() - d->summary_at <= WALLET_STALE_MS && d->view.known && d->view.spendable_known;
    if (known) *zat = d->view.spendable_zat;
    pthread_mutex_unlock(&st.lock);
    return known;
}

bool wallet_screens_residue(const void *bytes, size_t len)
{
    const unsigned char *all = (const unsigned char *)&st, *want = bytes;
    bool found = false;
    pthread_mutex_lock(&st.lock);
    for (size_t i = 0; len && !found && i + len <= sizeof(st); ++i) found = !memcmp(all + i, want, len);
    pthread_mutex_unlock(&st.lock);
    return found;
}
