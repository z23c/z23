/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the send flow as pure logic, a C port of beta13's sendflow.h.
 * One confirmation gets one idempotency key. A z_sendmany whose answer is
 * lost is repeated with the same key, so the node answers with the operation
 * it already has and never builds a second transaction; only a JSON-RPC
 * answer (or a refusal of the credentials) ends the attempts as a failure.
 * The operation queue (z_getoperationstatus) and the send journal
 * (z_listsendjournal) decide together what a started send became. Also the
 * humane headline for a raw node error and the key generator. Node replies
 * are untrusted: every field is type-checked and bounded. */
#if defined(_WIN32)
#define _CRT_RAND_S /* rand_s: the CRT front of RtlGenRandom; no extra library */
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zw_send.h"

/* ---- the wallet's own wording ---- */

static const char k_expired[] =
    "This payment expired before it was mined, so it was not sent. Funds are available again.";
static const char k_lost[] =
    "The node no longer has a record of this send (it may have restarted), so its outcome is unknown. "
    "Check your transactions before sending again.";
static const char k_interrupted[] = "The send was interrupted before the transaction was built. Nothing was sent.";
static const char k_gave_up[] =
    "The wallet could not reach the node to confirm this payment. It may or may not have been queued. "
    "This wallet will not send it again: check your transactions before sending again.";
static const char k_old_node[] =
    "The connection was lost while sending, and this node is too old to tell whether the payment was queued. "
    "Check your transactions before sending again.";
static const char k_refused_prefix[] =
    "The node refused a repeat of this payment, and an earlier attempt may already have been queued.";

const char *zw_flow_text(enum zw_flow_state s)
{
    switch (s) {
    case ZW_FLOW_SENDING: return ZW_TXT_SENDING;
    case ZW_FLOW_UNKNOWN: return ZW_TXT_UNKNOWN;
    case ZW_FLOW_EXPIRED: return k_expired;
    case ZW_FLOW_LOST: return k_lost;
    case ZW_FLOW_FAILED: return k_interrupted;
    default: return "";
    }
}

const char *zw_flow_gave_up_text(void) { return k_gave_up; }
const char *zw_flow_old_node_text(void) { return k_old_node; }

void zw_flow_retry_refused(const char *reason, char *buf, size_t cap)
{
    snprintf(buf, cap, "%s This wallet will not send it again: check your transactions before sending again. (%s)",
             k_refused_prefix, reason);
}

bool zw_flow_is_flow_text(const char *s)
{
    return !strcmp(s, ZW_TXT_UNKNOWN) || !strcmp(s, k_expired) || !strcmp(s, k_lost) ||
           !strcmp(s, k_interrupted) || !strcmp(s, k_gave_up) || !strcmp(s, k_old_node) ||
           !strncmp(s, k_refused_prefix, strlen(k_refused_prefix));
}

/* ---- classifying the answer to z_sendmany itself ---- */

enum zw_call_class zw_flow_classify(enum zw_err err, const struct zw_rpc_error *e, bool keyed, bool first,
                                    char *msg, size_t cap)
{
    msg[0] = 0;
    if (err == ZW_ERR_RPC) { /* a JSON-RPC answer: nothing was queued, unless warming */
        snprintf(msg, cap, "%s", e->message);
        if (keyed && e->code == -28) return ZW_CALL_AMBIGUOUS;
        if (keyed && !strncmp(e->message, "z_sendmany", 10) && !strstr(e->message, "idempotency_key"))
            return ZW_CALL_KEY_UNSUPPORTED;
        return ZW_CALL_DEFINITIVE;
    }
    if (err == ZW_ERR_AUTH) {
        snprintf(msg, cap, "The node refused the wallet's credentials (HTTP 401).");
        return ZW_CALL_DEFINITIVE;
    }
    if (first && (err == ZW_ERR_REFUSED || err == ZW_ERR_SEARCHING)) {
        snprintf(msg, cap, "There is no connection to the node.");
        return ZW_CALL_DEFINITIVE;
    }
    return ZW_CALL_AMBIGUOUS;
}

uint32_t zw_flow_retry_delay_ms(int attempt, uint32_t base_ms)
{
    if (attempt < 1) attempt = 1;
    int shift = attempt - 1 < 4 ? attempt - 1 : 4;
    uint64_t d = (uint64_t)base_ms << shift, cap = (uint64_t)base_ms * 15u;
    return (uint32_t)(d < cap ? d : cap);
}

/* ---- what the node says about a started operation ---- */

static void copy_field(char *dst, size_t cap, const struct json_value *o, const char *k)
{
    const struct json_value *v = o ? json_get(o, k) : NULL;
    dst[0] = 0;
    if (v && v->type == JSON_STR) snprintf(dst, cap, "%s", json_get_str(v));
}

static void parse_queue_entry(const struct json_value *it, struct zw_queue_entry *q)
{
    memset(q, 0, sizeof(*q));
    q->present = true;
    copy_field(q->status, sizeof(q->status), it, "status");
    const struct json_value *r = json_get(it, "result");
    if (r && r->type == JSON_OBJ) copy_field(q->txid, sizeof(q->txid), r, "txid");
    if (!q->txid[0]) copy_field(q->txid, sizeof(q->txid), it, "txid");
    const struct json_value *e = json_get(it, "error");
    if (e && e->type == JSON_OBJ) copy_field(q->error, sizeof(q->error), e, "message");
    q->has_last_error = json_get(it, "last_error") != NULL;
}

static const struct json_value *find_by(const struct json_value *arr, const char *key, const char *opid)
{
    if (!arr || arr->type != JSON_ARR) return NULL;
    for (size_t i = 0, n = json_size(arr); i < n; i++) {
        const struct json_value *it = json_at(arr, i), *id = it && it->type == JSON_OBJ ? json_get(it, key) : NULL;
        if (id && id->type == JSON_STR && !strcmp(json_get_str(id), opid)) return it;
    }
    return NULL;
}

bool zw_flow_queue_find(const struct json_value *reply, const char *opid, struct zw_queue_entry *q)
{
    memset(q, 0, sizeof(*q));
    if (!reply || reply->type != JSON_ARR) return false;
    const struct json_value *it = find_by(reply, "id", opid);
    if (it) parse_queue_entry(it, q);
    return true;
}

bool zw_flow_journal_find(const struct json_value *reply, const char *opid, struct zw_journal_entry *j)
{
    memset(j, 0, sizeof(*j));
    if (!reply || reply->type != JSON_ARR) return false;
    const struct json_value *it = find_by(reply, "opid", opid);
    if (!it) return true;
    j->present = true;
    copy_field(j->state, sizeof(j->state), it, "state");
    copy_field(j->txid, sizeof(j->txid), it, "txid");
    return true;
}

bool zw_flow_needs_journal(bool keyed, const struct zw_queue_entry *q, bool unknown)
{
    if (!keyed) return false;
    if (unknown) return true;
    return !q->present || !strcmp(q->status, "failed");
}

static void verdict(struct zw_verdict *v, enum zw_flow_state s, const char *txid, const char *text)
{
    v->state = s;
    snprintf(v->txid, sizeof(v->txid), "%s", txid ? txid : "");
    snprintf(v->text, sizeof(v->text), "%s", text ? text : zw_flow_text(s));
}

static bool resolve_journal(const struct zw_queue_entry *q, const struct zw_journal_entry *j, struct zw_verdict *v)
{
    if (!strcmp(j->state, "committed")) verdict(v, ZW_FLOW_SENT, j->txid[0] ? j->txid : q->txid, "");
    else if (!strcmp(j->state, "expired")) verdict(v, ZW_FLOW_EXPIRED, "", NULL);
    else if (!strcmp(j->state, "outcome_unknown")) verdict(v, ZW_FLOW_UNKNOWN, j->txid, NULL);
    else if (!strcmp(j->state, "released")) verdict(v, ZW_FLOW_FAILED, "", q->error[0] ? q->error : k_interrupted);
    else verdict(v, ZW_FLOW_SENDING, "", NULL); /* started: the operation is live */
    return true;
}

static void resolve_queue(const struct zw_queue_entry *q, struct zw_verdict *v)
{
    if (!strcmp(q->status, "success")) verdict(v, ZW_FLOW_SENT, q->txid, "");
    else if (!strcmp(q->status, "failed") || !strcmp(q->status, "cancelled"))
        verdict(v, ZW_FLOW_FAILED, "", q->error[0] ? q->error : "The send failed.");
    else if (q->txid[0] || q->has_last_error) verdict(v, ZW_FLOW_UNKNOWN, q->txid, NULL);
    else verdict(v, ZW_FLOW_SENDING, "", NULL); /* queued / executing */
}

void zw_flow_resolve(bool keyed, const struct zw_queue_entry *q, bool journal_known,
                     const struct zw_journal_entry *j, struct zw_verdict *v)
{
    if (keyed && journal_known && j->present) resolve_journal(q, j, v);
    else if (q->present) resolve_queue(q, v);
    else if (keyed && journal_known) verdict(v, ZW_FLOW_FAILED, "", k_interrupted);
    else verdict(v, ZW_FLOW_LOST, "", NULL);
}

/* A keyed Z23 z_sendmany: {"state":"committed","txid","replayed"} and its
 * refusals (released, in_progress, fee_changed, outcome_unknown, key_conflict). */
void zw_flow_z23_state(const struct json_value *body, struct zw_verdict *v)
{
    char state[32], txid[80], msg[256];
    copy_field(state, sizeof(state), body, "state");
    copy_field(txid, sizeof(txid), body, "txid");
    copy_field(msg, sizeof(msg), body, "message");
    if (!strcmp(state, "committed") && strlen(txid) == 64) verdict(v, ZW_FLOW_SENT, txid, "");
    else if (!strcmp(state, "in_progress")) verdict(v, ZW_FLOW_SENDING, "", NULL);
    else if (!strcmp(state, "outcome_unknown")) verdict(v, ZW_FLOW_UNKNOWN, txid, NULL);
    else if (!strcmp(state, "released"))
        verdict(v, ZW_FLOW_FAILED, "", msg[0] ? msg : "The node refused the send before recording it. Nothing was sent.");
    else if (!strcmp(state, "fee_changed"))
        verdict(v, ZW_FLOW_FAILED, "", "The wallet fee changed since you reviewed this payment. Nothing was sent.");
    else if (!strcmp(state, "key_conflict"))
        verdict(v, ZW_FLOW_FAILED, "", "The node already used this payment's key for a different request.");
    else verdict(v, ZW_FLOW_FAILED, "", "The node's answer to the send was not understood.");
}

/* ---- humaneSendError: the most specific cause first ---- */

struct humane_rule { const char *needles; const char *text; }; /* needles: "|"-separated, lowercase */

static const struct humane_rule k_humane[] = {
    { "token-bearing|zslp|mint baton",
      "Some of the coins in this wallet carry ZSLP tokens (or a token mint baton). They are protected and were not "
      "spent, because paying with them would destroy the tokens. Use other coins, or send the tokens with a "
      "token-aware wallet." },
    { "coinbase|must be sent to a single z|to a zaddr|shielding coinbase",
      "Mined (coinbase) ZCL must be sent to exactly one shielded (z) address at a time. Send it to a single "
      "z-address first, then spend normally." },
    { "no utxo|no unspent",
      "These coins aren't confirmed yet. Wait a few minutes for the network to confirm them, then try again." },
    { "insufficient|not enough",
      "You don't have enough confirmed ZCL to cover this amount plus the network fee. Wait for recent deposits to "
      "confirm, or send a smaller amount." },
    { "try again|still syncing|downloading blocks|is downloading|loading block index|rescanning",
      "Your wallet is still catching up with the network. Let it finish syncing, then try sending again." },
    { "wallet is locked|walletpassphrase",
      "Your wallet is locked (it is encrypted with a passphrase), and this wallet app has no unlock button. Nothing "
      "was sent and no funds moved. To send, unlock the node with its walletpassphrase command (for example "
      "zclassic-cli walletpassphrase <passphrase> 120), then try sending again." },
    { "amount out of range|invalid amount|too small|dust", "That amount is too small to send. Try a larger amount." },
};

static bool has_any(const char *lower, const char *needles)
{
    char one[64];
    for (const char *p = needles; *p;) {
        size_t n = strcspn(p, "|");
        snprintf(one, sizeof(one), "%.*s", (int)n, p);
        if (strstr(lower, one)) return true;
        p += n + (p[n] == '|');
    }
    return false;
}

const char *zw_flow_humane(const char *raw)
{
    if (zw_flow_is_flow_text(raw)) return raw;
    char e[400];
    size_t i = 0;
    for (; raw[i] && i + 1 < sizeof(e); i++) e[i] = raw[i] >= 'A' && raw[i] <= 'Z' ? (char)(raw[i] + 32) : raw[i];
    e[i] = 0;
    for (size_t r = 0; r < sizeof(k_humane) / sizeof(k_humane[0]); r++)
        if (has_any(e, k_humane[r].needles)) return k_humane[r].text;
    return "Your transaction couldn't be sent. The details are below -- you can try again.";
}

/* ---- the idempotency key ---- */

static bool random_bytes(uint8_t *out, size_t n)
{
#if defined(_WIN32)
    for (size_t i = 0; i < n; i += 4) {
        unsigned int r = 0;
        if (rand_s(&r) != 0) return false;
        for (size_t k = 0; k < 4 && i + k < n; k++) out[i + k] = (uint8_t)(r >> (8 * k));
    }
    return true;
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return false;
    bool ok = fread(out, 1, n, f) == n;
    fclose(f);
    return ok;
#endif
}

/* 3 + 32 characters of [A-Za-z0-9], about 190 bits; the node accepts 1..128
 * of [A-Za-z0-9._:-]. Rejection sampling keeps every character uniform. */
bool zw_flow_new_key(char out[ZW_SEND_KEY_MAX])
{
    static const char b62[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    uint8_t pool[64];
    size_t have = 0, used = sizeof(pool);
    memcpy(out, "zq-", 3);
    while (have < 32) {
        if (used == sizeof(pool)) {
            if (!random_bytes(pool, sizeof(pool))) return false;
            used = 0;
        }
        uint8_t b = pool[used++];
        if (b < 248) out[3 + have++] = b62[b % 62];
    }
    out[35] = 0;
    return true;
}
