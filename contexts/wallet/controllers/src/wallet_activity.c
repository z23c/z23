/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pure aggregation for core.wallet.summary and core.wallet.history over the
 * wallet fact rows. No database, key or node state is read here. */

#include "controllers/wallet_activity.h"

#include "base/hex.h"
#include "util/safe_alloc.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int wa_cmp32(const void *a, const void *b)
{
    return memcmp(a, b, 32);
}

static bool wa_ivk_loaded(const uint8_t (*ivks)[32], size_t nk,
                          const uint8_t ivk[32])
{
    for (size_t i = 0; i < nk; i++)
        if (memcmp(ivks[i], ivk, 32) == 0)
            return true;
    return false;
}

static int wa_confs(int height, int tip)
{
    return height > 0 && height <= tip ? tip - height + 1 : 0;
}

static bool wa_note_same(const struct db_wallet_note_fact *a,
                         const struct db_wallet_note_fact *b)
{
    return a->output_index == b->output_index &&
           memcmp(a->txid, b->txid, 32) == 0;
}

static bool wa_coin_same(const struct db_wallet_coin_fact *a,
                         const struct db_wallet_coin_fact *b)
{
    return a->vout == b->vout && memcmp(a->txid, b->txid, 32) == 0;
}

/* Sorted txids of every transaction that spent a wallet note or coin. */
static uint8_t (*wa_spenders(const struct db_wallet_note_fact *notes,
                             size_t nn,
                             const struct db_wallet_coin_fact *coins,
                             size_t nc, const uint8_t (*ivks)[32], size_t nk,
                             size_t *count))[32]
{
    *count = 0;
    uint8_t (*sp)[32] = zcl_calloc(nn + nc + 1, 32, "wallet spenders");
    if (!sp)
        return NULL;
    for (size_t i = 0; i < nn; i++)
        if (notes[i].spent && wa_ivk_loaded(ivks, nk, notes[i].ivk))
            memcpy(sp[(*count)++], notes[i].spent_txid, 32);
    for (size_t i = 0; i < nc; i++)
        if (coins[i].spent)
            memcpy(sp[(*count)++], coins[i].spent_txid, 32);
    qsort(sp, *count, 32, wa_cmp32);
    return sp;
}

static const struct db_wallet_tx_fact *wa_find_tx(
    const struct db_wallet_tx_fact *txs, size_t nt, const uint8_t txid[32])
{
    size_t lo = 0, hi = nt;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = memcmp(txs[mid].txid, txid, 32);
        if (c == 0)
            return &txs[mid];
        if (c < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return NULL;
}

static void wa_add_note(const struct db_wallet_note_fact *n,
                        const uint8_t (*spenders)[32], size_t ns, int tip,
                        struct wallet_summary *out)
{
    bool change = bsearch(n->txid, spenders, ns, 32, wa_cmp32) != NULL;
    int need = change ? WALLET_CONF_CHANGE : WALLET_CONF_RECEIVED;
    int confs = wa_confs(n->block_height, tip);
    if (confs >= need) {
        out->spendable += n->value;
        return;
    }
    out->pending += n->value;
    out->pending_count++;
    if (out->pending_min_confs_needed == 0 ||
        need - confs < out->pending_min_confs_needed)
        out->pending_min_confs_needed = need - confs;
}

static void wa_add_coin(const struct db_wallet_coin_fact *c, int tip,
                        struct wallet_summary *out)
{
    if (c->height < 1 || c->height > tip)
        return;
    if (c->coinbase && c->height > tip - WALLET_COINBASE_MATURITY)
        out->immature += c->value;
    else
        out->public_confirmed += c->value;
}

static bool wa_unconfirmed_spender(const struct db_wallet_tx_fact *txs,
                                   size_t nt, const uint8_t txid[32])
{
    const struct db_wallet_tx_fact *t = wa_find_tx(txs, nt, txid);
    return t && t->block_height <= 0;
}

void wallet_summary_accumulate(const struct db_wallet_note_fact *notes,
                               size_t nn,
                               const struct db_wallet_coin_fact *coins,
                               size_t nc,
                               const struct db_wallet_tx_fact *txs, size_t nt,
                               const uint8_t (*ivks)[32], size_t nk, int tip,
                               struct wallet_summary *out)
{
    memset(out, 0, sizeof(*out));
    size_t ns = 0;
    uint8_t (*sp)[32] = wa_spenders(notes, nn, coins, nc, ivks, nk, &ns);
    if (!sp)
        return;
    for (size_t i = 0; i < nn; i++) {
        if (i > 0 && wa_note_same(&notes[i], &notes[i - 1]))
            continue;
        if (!wa_ivk_loaded(ivks, nk, notes[i].ivk))
            continue;
        if (!notes[i].spent)
            wa_add_note(&notes[i], (const uint8_t (*)[32])sp, ns, tip, out);
        else if (wa_unconfirmed_spender(txs, nt, notes[i].spent_txid))
            out->sending += notes[i].value;
    }
    for (size_t i = 0; i < nc; i++) {
        if (i > 0 && wa_coin_same(&coins[i], &coins[i - 1]))
            continue;
        if (!coins[i].spent)
            wa_add_coin(&coins[i], tip, out);
        else if (wa_unconfirmed_spender(txs, nt, coins[i].spent_txid))
            out->sending += coins[i].value;
    }
    free(sp);
}

/* ── history ─────────────────────────────────────────────────────── */

struct wa_acc {
    uint8_t txid[32];
    int64_t in_z, in_t, out_z, out_t;
    int height;
    bool shielded;
    bool memo;
};

struct wa_accs {
    struct wa_acc *v;
    size_t n;
};

/* Find or insert the accumulator for txid, keeping v sorted by txid. */
static struct wa_acc *wa_acc_get(struct wa_accs *a, const uint8_t txid[32])
{
    size_t lo = 0, hi = a->n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = memcmp(a->v[mid].txid, txid, 32);
        if (c == 0)
            return &a->v[mid];
        if (c < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    memmove(&a->v[lo + 1], &a->v[lo], (a->n - lo) * sizeof(a->v[0]));
    memset(&a->v[lo], 0, sizeof(a->v[0]));
    memcpy(a->v[lo].txid, txid, 32);
    a->n++;
    return &a->v[lo];
}

static void wa_acc_notes(struct wa_accs *a,
                         const struct db_wallet_note_fact *notes, size_t nn,
                         const uint8_t (*ivks)[32], size_t nk)
{
    for (size_t i = 0; i < nn; i++) {
        const struct db_wallet_note_fact *n = &notes[i];
        if ((i > 0 && wa_note_same(n, &notes[i - 1])) ||
            !wa_ivk_loaded(ivks, nk, n->ivk))
            continue;
        struct wa_acc *c = wa_acc_get(a, n->txid);
        c->out_z += n->value;
        c->shielded = true;
        c->memo = c->memo || n->memo_present;
        if (n->block_height > c->height)
            c->height = n->block_height;
        if (n->spent) {
            struct wa_acc *s = wa_acc_get(a, n->spent_txid);
            s->in_z += n->value;
            s->shielded = true;
        }
    }
}

static void wa_acc_coins(struct wa_accs *a,
                         const struct db_wallet_coin_fact *coins, size_t nc)
{
    for (size_t i = 0; i < nc; i++) {
        const struct db_wallet_coin_fact *k = &coins[i];
        if (i > 0 && wa_coin_same(k, &coins[i - 1]))
            continue;
        struct wa_acc *c = wa_acc_get(a, k->txid);
        c->out_t += k->value;
        if (k->height > c->height)
            c->height = k->height;
        if (k->spent)
            wa_acc_get(a, k->spent_txid)->in_t += k->value;
    }
}

/* Split an outgoing transaction into sent, internal or unknown. */
static void wa_classify_outgoing(struct wallet_history_entry *e, int64_t in,
                                 int64_t out,
                                 const struct db_wallet_tx_fact *tx)
{
    int64_t outflow = in - out;
    e->net = -outflow;
    e->direction = WALLET_DIR_UNKNOWN;
    if (outflow < 0)
        return;
    bool fee_known = outflow == 0 || (tx && tx->from_me && tx->fee > 0);
    if (!fee_known)
        return;
    int64_t fee = outflow == 0 ? 0 : tx->fee;
    if (fee > outflow)
        return;
    e->fee_known = true;
    e->fee = fee;
    e->amount_known = true;
    e->amount = outflow - fee;
    e->direction = e->amount == 0 ? WALLET_DIR_INTERNAL : WALLET_DIR_SENT;
}

static void wa_fill_entry(struct wallet_history_entry *e,
                          const struct wa_acc *c,
                          const struct db_wallet_tx_fact *tx, int tip)
{
    int64_t in = c->in_z + c->in_t, out = c->out_z + c->out_t;
    memset(e, 0, sizeof(*e));
    memcpy(e->txid, c->txid, 32);
    e->height = c->height > 0 ? c->height : (tx ? tx->block_height : 0);
    if (e->height < 0)
        e->height = 0;
    e->confirmations = wa_confs(e->height, tip);
    if (tx)
        e->time = tx->time_received;
    e->private_kind = c->shielded;
    e->memo_present = c->memo;
    if (in == 0) {
        e->direction = WALLET_DIR_RECEIVED;
        e->net = out;
        e->amount_known = true;
        e->amount = out;
    } else {
        wa_classify_outgoing(e, in, out, tx);
    }
}

static int wa_sort_key(const struct wallet_history_entry *e)
{
    return e->height > 0 ? e->height : INT32_MAX;
}

static int wa_entry_cmp(const void *x, const void *y)
{
    const struct wallet_history_entry *a = x, *b = y;
    int ka = wa_sort_key(a), kb = wa_sort_key(b);
    if (ka != kb)
        return ka > kb ? -1 : 1;
    return memcmp(a->txid, b->txid, 32);
}

int wallet_history_build(const struct db_wallet_note_fact *notes, size_t nn,
                         const struct db_wallet_coin_fact *coins, size_t nc,
                         const struct db_wallet_tx_fact *txs, size_t nt,
                         const uint8_t (*ivks)[32], size_t nk, int tip,
                         struct wallet_history_entry **out)
{
    *out = NULL;
    struct wa_accs a = { zcl_calloc(2 * (nn + nc) + 1, sizeof(struct wa_acc),
                                    "wallet history acc"), 0 };
    if (!a.v)
        return -1;
    wa_acc_notes(&a, notes, nn, ivks, nk);
    wa_acc_coins(&a, coins, nc);
    struct wallet_history_entry *e =
        zcl_calloc(a.n + 1, sizeof(*e), "wallet history entries");
    if (!e) {
        free(a.v);
        return -1;
    }
    for (size_t i = 0; i < a.n; i++)
        wa_fill_entry(&e[i], &a.v[i], wa_find_tx(txs, nt, a.v[i].txid), tip);
    qsort(e, a.n, sizeof(*e), wa_entry_cmp);
    free(a.v);
    *out = e;
    return (int)a.n;
}

/* ── paging ──────────────────────────────────────────────────────── */

bool wallet_history_cursor_parse(const char *text,
                                 struct wallet_history_cursor *out)
{
    memset(out, 0, sizeof(*out));
    if (!text || !text[0])
        return false;
    char *end = NULL;
    if (text[0] == 'p' && text[1] == ':') {
        out->key = INT32_MAX;
        end = (char *)text + 1;
    } else {
        long h = strtol(text, &end, 10);
        if (end == text || h < 1 || h >= INT32_MAX)
            return false;
        out->key = (int)h;
    }
    if (*end != ':' || !zcl_hex_decode(end + 1, out->txid, 32))
        return false;
    out->set = true;
    return true;
}

void wallet_history_cursor_format(const struct wallet_history_entry *e,
                                  char *out, size_t cap)
{
    char head[16];
    if (e->height > 0)
        snprintf(head, sizeof(head), "%d", e->height);
    else
        snprintf(head, sizeof(head), "p");
    char hex[65];
    zcl_hex_encode(e->txid, 32, hex);
    snprintf(out, cap, "%s:%s", head, hex);
}

size_t wallet_history_page_start(const struct wallet_history_entry *e,
                                 size_t n,
                                 const struct wallet_history_cursor *cur)
{
    if (!cur->set)
        return 0;
    for (size_t i = 0; i < n; i++) {
        int k = wa_sort_key(&e[i]);
        if (k < cur->key ||
            (k == cur->key && memcmp(e[i].txid, cur->txid, 32) > 0))
            return i;
    }
    return n;
}
