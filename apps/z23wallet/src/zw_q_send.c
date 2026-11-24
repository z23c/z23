/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the Send screen's node work. zw_q_send_poll keeps the pay-from
 * balances fresh while Send is shown. The send runner is one short-lived
 * thread per confirmed payment, with its own RPC client pinned to the node
 * the page shows (no auto hand-over to another node mid-send), so a slow
 * send never stalls the read worker or trips its watchdog. It carries out
 * beta13's RPC::executeTransaction: keyed z_sendmany, the same key again
 * after an unanswered call (1, 2, 4, 8, then every 15 s, at most 40 calls),
 * the unkeyed form only for a node that rejects the key, then
 * z_getoperationstatus polling with z_listsendjournal when the queue alone
 * cannot decide. A keyed Z23 node answers the send synchronously. The UI
 * thread reads the status after a window wake. Logs carry no address,
 * amount, memo, key, operation id or txid. */
#if defined(_WIN32)
#include <windows.h>
#endif
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "base/safe_alloc.h"
#include "zw_send.h"

void zw_q_send_poll(struct zw_worker *w, const struct zw_model *m)
{
    if (m->conn == ZW_CONN_ONLINE) zw_worker_enqueue(w, ZW_Q_BALANCES, m->generation);
}

static struct zw_sender_timing g_timing = { 1000, 2000, 60000, 300000, 3600000 };

void zw_sender_set_timing(const struct zw_sender_timing *t) { g_timing = *t; }

struct zw_sender {
    pthread_t thread;
    pthread_mutex_t mu;
    struct gui_window *win;
    struct zw_options opt; /* a copy, pinned to one node and one profile */
    struct zw_rpc rpc;
    struct zw_cancel *cancel;
    char *keyed, *plain;
    bool z23, stop, finished, started;
    struct zw_send_status st;
    uint32_t read_seq;
};

static bool stopping(struct zw_sender *s)
{
    pthread_mutex_lock(&s->mu);
    bool st = s->stop;
    pthread_mutex_unlock(&s->mu);
    return st;
}

static void nap_ms(uint32_t ms)
{
#if defined(_WIN32)
    Sleep(ms);
#else
    struct timespec ts = { (time_t)(ms / 1000u), (long)(ms % 1000u) * 1000000L };
    nanosleep(&ts, NULL);
#endif
}

/* Wait ms in short slices unless asked to stop; true when it ran out normally. */
static bool wait_ms(struct zw_sender *s, uint32_t ms)
{
    uint64_t end = zw_monotonic_ms() + ms;
    while (!stopping(s)) {
        uint64_t now = zw_monotonic_ms();
        if (now >= end) return true;
        nap_ms(end - now < 20 ? (uint32_t)(end - now) : 20);
    }
    return false;
}

static void publish(struct zw_sender *s, enum zw_send_phase ph, const char *opid, const char *txid,
                    const char *text, const char *raw)
{
    pthread_mutex_lock(&s->mu);
    s->st.phase = ph;
    if (opid) snprintf(s->st.opid, sizeof(s->st.opid), "%s", opid);
    if (txid) snprintf(s->st.txid, sizeof(s->st.txid), "%s", txid);
    if (text) snprintf(s->st.text, sizeof(s->st.text), "%s", text);
    if (raw) snprintf(s->st.raw, sizeof(s->st.raw), "%s", raw);
    s->st.seq++;
    if (ph == ZW_SP_SENT || ph == ZW_SP_FAILED) s->finished = true;
    pthread_mutex_unlock(&s->mu);
    gui_window_wake(s->win);
}

static void fail(struct zw_sender *s, const char *text)
{
    zw_log("send: not sent (or outcome unknown); the page explains it");
    publish(s, ZW_SP_FAILED, NULL, NULL, text, text);
}

static bool is_hex64(const char *s)
{
    size_t n = 0;
    for (; s[n]; n++)
        if (!((s[n] >= '0' && s[n] <= '9') || (s[n] >= 'a' && s[n] <= 'f') || (s[n] >= 'A' && s[n] <= 'F')))
            return false;
    return n == 64;
}

static bool is_opid(const char *s)
{
    size_t n = 0;
    for (; s[n]; n++) {
        char c = s[n];
        bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || strchr("._:-", c);
        if (!ok) return false;
    }
    return n > 0 && n < 120;
}

/* ---- the answer to z_sendmany ---- */

enum answer { A_DONE, A_POLL, A_REPEAT };

static enum answer on_answer(struct zw_sender *s, const struct json_value *res, char *opid, size_t cap)
{
    if (res->type == JSON_STR) {
        const char *v = json_get_str(res);
        if (is_hex64(v)) { /* a node that sends synchronously and returns the txid */
            zw_log("send: the node returned the transaction");
            publish(s, ZW_SP_SENT, NULL, v, "", NULL);
            return A_DONE;
        }
        if (is_opid(v)) {
            snprintf(opid, cap, "%s", v);
            zw_log("send: submitted; polling the operation");
            publish(s, ZW_SP_PROGRESS, v, NULL, ZW_TXT_SENDING, NULL);
            return A_POLL;
        }
    }
    if (res->type == JSON_OBJ && json_get(res, "state")) {
        struct zw_verdict v;
        zw_flow_z23_state(res, &v);
        if (v.state == ZW_FLOW_SENT) {
            zw_log("send: the node committed the transaction");
            publish(s, ZW_SP_SENT, NULL, v.txid, "", NULL);
            return A_DONE;
        }
        if (v.state == ZW_FLOW_SENDING) {
            publish(s, ZW_SP_PROGRESS, NULL, NULL, ZW_TXT_SENDING, NULL);
            return A_REPEAT;
        }
        fail(s, v.state == ZW_FLOW_UNKNOWN ? zw_flow_gave_up_text() : v.text);
        return A_DONE;
    }
    fail(s, "The node's answer to the send was not understood.");
    return A_DONE;
}

/* One failed call: true to call again (after the delay it waited). */
static bool on_error(struct zw_sender *s, enum zw_err err, const struct zw_rpc_error *e, bool *keyed, int attempts)
{
    char msg[256], text[400];
    switch (zw_flow_classify(err, e, *keyed, attempts == 1, msg, sizeof(msg))) {
    case ZW_CALL_DEFINITIVE:
        if (*keyed && attempts > 1) {
            zw_flow_retry_refused(msg, text, sizeof(text));
            fail(s, text);
        } else {
            fail(s, msg);
        }
        return false;
    case ZW_CALL_KEY_UNSUPPORTED:
        zw_log("send: the node does not take a send key; sending without one");
        *keyed = false;
        return true;
    default:
        break;
    }
    if (!*keyed) { fail(s, zw_flow_old_node_text()); return false; }
    if (attempts >= ZW_SEND_MAX_ATTEMPTS) { fail(s, zw_flow_gave_up_text()); return false; }
    zw_log("send: no answer from the node (attempt %d); asking again with the same key", attempts);
    publish(s, ZW_SP_PROGRESS, NULL, NULL, ZW_TXT_UNKNOWN, NULL);
    return wait_ms(s, zw_flow_retry_delay_ms(attempts, g_timing.retry_base_ms));
}

/* ---- operation status polling ---- */

static bool journal_of(struct zw_sender *s, const char *opid, struct zw_journal_entry *j)
{
    struct json_value r;
    struct zw_rpc_error e;
    json_init(&r);
    bool ok = zw_rpc_call(&s->rpc, "z_listsendjournal", "[]", &r, &e) == ZW_OK && zw_flow_journal_find(&r, opid, j);
    json_free(&r);
    return ok;
}

static bool queue_of(struct zw_sender *s, const char *opid, struct zw_queue_entry *q)
{
    char p[160];
    struct json_value r;
    struct zw_rpc_error e;
    snprintf(p, sizeof(p), "[[\"%s\"]]", opid);
    json_init(&r);
    bool ok = zw_rpc_call(&s->rpc, "z_getoperationstatus", p, &r, &e) == ZW_OK && zw_flow_queue_find(&r, opid, q);
    json_free(&r);
    return ok;
}

/* One poll: true while the operation is still open. */
static bool poll_once(struct zw_sender *s, const char *opid, bool keyed, bool *unknown, int *missed)
{
    struct zw_queue_entry q;
    struct zw_journal_entry j = { .present = false };
    if (!queue_of(s, opid, &q)) return true; /* a failed poll is asked again next time */
    bool jk = false;
    if (zw_flow_needs_journal(keyed, &q, *unknown)) {
        if (!journal_of(s, opid, &j)) return true;
        jk = true;
    }
    if (q.present) *missed = 0;
    else if (!keyed && ++*missed < 2) return true; /* an older node: two misses in a row */
    struct zw_verdict v;
    zw_flow_resolve(keyed, &q, jk, &j, &v);
    if (v.state == ZW_FLOW_SENDING || v.state == ZW_FLOW_UNKNOWN) {
        *unknown = v.state == ZW_FLOW_UNKNOWN;
        if (strcmp(v.text, s->st.text)) publish(s, ZW_SP_PROGRESS, NULL, NULL, v.text, NULL);
        return true;
    }
    if (v.state == ZW_FLOW_SENT) {
        zw_log("send: the operation finished and the transaction was sent");
        publish(s, ZW_SP_SENT, NULL, v.txid, "", NULL);
    } else {
        fail(s, v.text);
    }
    return false;
}

static void poll_operation(struct zw_sender *s, const char *opid, bool keyed)
{
    bool unknown = false;
    int missed = 0;
    uint64_t start = zw_monotonic_ms();
    s->rpc.deadline_ms = 5000;
    while (wait_ms(s, g_timing.poll_ms)) {
        if (zw_monotonic_ms() - start > g_timing.poll_limit_ms) { fail(s, zw_flow_text(ZW_FLOW_LOST)); return; }
        if (!poll_once(s, opid, keyed, &unknown, &missed)) return;
    }
}

static void *sender_main(void *arg)
{
    struct zw_sender *s = arg;
    bool keyed = true;
    char opid[128] = "";
    for (int attempts = 1; !stopping(s); attempts++) {
        struct json_value res;
        struct zw_rpc_error e;
        json_init(&res);
        s->rpc.deadline_ms = s->z23 ? g_timing.z23_deadline_ms : g_timing.legacy_deadline_ms;
        enum zw_err err = zw_rpc_call(&s->rpc, "z_sendmany", keyed ? s->keyed : s->plain, &res, &e);
        if (err != ZW_OK) {
            json_free(&res);
            if (!on_error(s, err, &e, &keyed, attempts)) break;
            continue;
        }
        enum answer a = on_answer(s, &res, opid, sizeof(opid));
        json_free(&res);
        if (a == A_POLL) poll_operation(s, opid, keyed);
        if (a != A_REPEAT) break;
        /* in_progress: the node is still on it; the same key reads its result */
        if (attempts >= ZW_SEND_MAX_ATTEMPTS) { fail(s, zw_flow_gave_up_text()); break; }
        if (!wait_ms(s, zw_flow_retry_delay_ms(attempts, g_timing.retry_base_ms))) break;
    }
    return NULL;
}

struct zw_sender *zw_sender_start(struct gui_window *win, const struct zw_options *o, const struct zw_model *m,
                                  const char *params_keyed, const char *params_plain)
{
    struct zw_sender *s = zcl_calloc(1, sizeof(*s), "zw_sender");
    if (!s) return NULL;
    s->opt = *o;
    s->opt.profile = m->profile == ZW_PROFILE_ZCLASSICD ? ZW_PROFILE_ZCLASSICD : ZW_PROFILE_Z23;
    if (m->datadir[0]) snprintf(s->opt.datadir, sizeof(s->opt.datadir), "%s", m->datadir);
    if (m->port) s->opt.rpcport = m->port;
    s->z23 = s->opt.profile == ZW_PROFILE_Z23;
    s->keyed = zcl_strdup(params_keyed, "zw_send_params");
    s->plain = zcl_strdup(params_plain, "zw_send_params");
    s->cancel = zw_cancel_new();
    s->win = win;
    if (!s->keyed || !s->plain || !s->cancel) goto fail;
    s->rpc.opt = &s->opt;
    s->rpc.cancel = s->cancel;
    s->rpc.may_send = true;
    s->st.phase = ZW_SP_SUBMITTING;
    snprintf(s->st.text, sizeof(s->st.text), "%s", ZW_TXT_SENDING);
    pthread_mutex_init(&s->mu, NULL);
    if (pthread_create(&s->thread, NULL, sender_main, s) != 0) {
        zw_log("send: cannot start the send thread");
        pthread_mutex_destroy(&s->mu);
        goto fail;
    }
    s->started = true;
    return s;
fail:
    zw_cancel_free(s->cancel);
    free(s->keyed);
    free(s->plain);
    free(s);
    return NULL;
}

bool zw_sender_poll(struct zw_sender *s, struct zw_send_status *out)
{
    pthread_mutex_lock(&s->mu);
    bool changed = s->st.seq != s->read_seq;
    *out = s->st;
    s->read_seq = s->st.seq;
    pthread_mutex_unlock(&s->mu);
    return changed;
}

bool zw_sender_finished(struct zw_sender *s)
{
    pthread_mutex_lock(&s->mu);
    bool f = s->finished;
    pthread_mutex_unlock(&s->mu);
    return f;
}

void zw_sender_free(struct zw_sender *s)
{
    if (!s) return;
    pthread_mutex_lock(&s->mu);
    s->stop = true;
    pthread_mutex_unlock(&s->mu);
    zw_cancel_fire(s->cancel); /* a request in flight ends within one wait slice */
    pthread_join(s->thread, NULL);
    pthread_mutex_destroy(&s->mu);
    zw_endpoint_wipe(&s->rpc.ep);
    zw_cancel_free(s->cancel);
    free(s->keyed);
    free(s->plain);
    free(s);
}
