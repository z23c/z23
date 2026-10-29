/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "controller.h"
#include "conversation.h"
#include "bridge_client.h"
#include "operations.h"
#include "camera.h"
#include "fleet.h"
#include "json/json.h"
#include "base/cleanse.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <time.h>

struct controller {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    struct zapp_runtime runtime;
    struct zapp_view view;
    char files[1024], action[32], argument[24000];
    uint64_t camera_ticket;
    void (*notify)(void);
    bool pending;
    atomic_bool reply_cancel;
};
static pthread_mutex_t startup_lock = PTHREAD_MUTEX_INITIALIZER;
static struct controller *current;

static void copy_text(char *out, size_t cap, const char *text)
{
    if (cap) snprintf(out, cap, "%s", text ? text : "");
}
static void notify_view(struct controller *c)
{
    pthread_mutex_lock(&c->lock);
    void (*notify)(void) = c->notify;
    pthread_mutex_unlock(&c->lock);
    if (notify) notify();
}
static bool parse_receipt(const char *text, char *receipt, size_t cap)
{
    struct json_value root = {0};
    bool ok = json_read(&root, text, strlen(text));
    const char *value = json_get_str(json_get(json_get(&root, "data"), "receipt"));
    ok = ok && value && value[0] && strlen(value) < cap;
    if (ok) copy_text(receipt, cap, value);
    json_free(&root); return ok;
}
static bool invitation(struct controller *c, const char *text)
{
    char token[8192];
    bool ok = zapp_fleet_invite_text(text, token, sizeof(token));
    pthread_mutex_lock(&c->lock);
    c->view.fleet_token[0] = 0;
    c->view.fleet_preview[0] = 0;
    if (ok) {
        copy_text(c->view.fleet_token, sizeof(c->view.fleet_token), token);
        copy_text(c->view.fleet_preview, sizeof(c->view.fleet_preview),
            "Invitation received. Confirm it came from your fleet manager before joining. Z23 checks its signature and expiry when you join.");
    }
    pthread_mutex_unlock(&c->lock);
    memory_cleanse(token, sizeof(token)); return ok;
}
static void observe_balance(struct controller *c, char *output)
{
    char balance[512] = "";
    bool ok = output &&
        zapp_operation_run(&c->runtime, "wallet_balance", output, ZAPP_TEXT_CAP) &&
        zapp_balance_format(output, balance, sizeof(balance));
    pthread_mutex_lock(&c->lock);
    if (ok) {
        copy_text(c->view.balance, sizeof(c->view.balance), balance);
        c->view.balance_known = true;
    }
    c->view.balance_stale = !ok && c->view.balance_known;
    pthread_mutex_unlock(&c->lock);
}
static void observe_node(struct controller *c)
{
    bool responding = false;
    char *output = calloc(1, ZAPP_TEXT_CAP);
    char status[1024] = "Node status unavailable. Sync progress is unknown.";
    if (output) {
        bool ok = zapp_operation_run(&c->runtime, "status", output, ZAPP_TEXT_CAP);
        struct json_value root = {0};
        ok = ok && json_read(&root, output, strlen(output));
        const struct json_value *success = json_get(&root, "ok");
        ok = ok && success && success->type == JSON_BOOL && json_get_bool(success);
        const struct json_value *data = json_get(&root, "data");
        const struct json_value *height = json_get(data, "provable_tip");
        const struct json_value *peers = json_get(data, "peers");
        const struct json_value *target = json_get(data, "max_peer_height");
        if (ok && height && height->type == JSON_INT) {
            responding = true;
            if (target && target->type == JSON_INT && json_get_int(target) > 0)
                snprintf(status, sizeof(status), "Local height %lld\nPeer-reported height %lld · %lld peers\nFull validation is still being checked.",
                    (long long)json_get_int(height), (long long)json_get_int(target),
                    (long long)json_get_int(peers));
            else snprintf(status, sizeof(status), "Local height %lld\nWaiting for peers with a current chain view.", (long long)json_get_int(height));
        }
        json_free(&root);
    }
    observe_balance(c, output);
    free(output);
    pthread_mutex_lock(&c->lock);
    c->view.node_running = responding;
    copy_text(c->view.sync_status, sizeof(c->view.sync_status), status);
    pthread_mutex_unlock(&c->lock);
    notify_view(c);
}
static void chat_result(struct controller *c, const char *prompt, const char *answer)
{
    size_t needed = strlen(prompt) + strlen(answer) + 24;
    size_t used = strlen(c->view.transcript);
    if (needed >= sizeof(c->view.transcript)) {
        copy_text(c->view.transcript, sizeof(c->view.transcript), answer); return;
    }
    if (needed >= sizeof(c->view.transcript) - used) used = 0;
    snprintf(c->view.transcript + used, sizeof(c->view.transcript) - used,
        "%sYou: %s\n\nZ23: %s\n", used ? "\n" : "", prompt, answer);
}
static bool conversation_chat(struct controller *c, const char *question, char *out)
{
    struct zapp_conversation_snapshot snapshot = {0};
    observe_node(c);
    if (atomic_load(&c->reply_cancel)) return false;
    pthread_mutex_lock(&c->lock);
    copy_text(snapshot.sync_status, sizeof(snapshot.sync_status), c->view.sync_status);
    copy_text(snapshot.balance, sizeof(snapshot.balance), c->view.balance);
    snapshot.balance_known = c->view.balance_known;
    snapshot.balance_stale = c->view.balance_stale;
    snapshot.node_running = c->view.node_running;
    pthread_mutex_unlock(&c->lock);
    char *prompt = calloc(1, ZAPP_CONVERSATION_CAP);
    if (!prompt) { copy_text(out, ZAPP_TEXT_CAP, "Not enough memory to prepare the question."); return false; }
    bool ok = zapp_conversation_format(&snapshot, question, prompt, ZAPP_CONVERSATION_CAP);
    if (ok) ok = zapp_bridge_chat(c->files, prompt, out, ZAPP_TEXT_CAP, &c->reply_cancel);
    else copy_text(out, ZAPP_TEXT_CAP, "Question is invalid or too long.");
    memory_cleanse(prompt, ZAPP_CONVERSATION_CAP);
    free(prompt);
    return ok;
}

static bool execute_action(struct controller *c, const char *action, const char *arg,
                           uint64_t ticket, char *out)
{
    bool ok = false;
    if (!strcmp(action, "node_start")) ok = zapp_node_start(&c->runtime, out, ZAPP_TEXT_CAP);
    else if (!strcmp(action, "node_stop")) ok = zapp_node_stop(&c->runtime, out, ZAPP_TEXT_CAP);
    else if (!strcmp(action, "operation")) ok = zapp_operation_run(&c->runtime, arg, out, ZAPP_TEXT_CAP);
    else if (!strcmp(action, "fleet_refresh")) ok = zapp_operation_run(&c->runtime, "fleet_doctor", out, ZAPP_TEXT_CAP);
    else if (!strcmp(action, "fleet_join")) ok = zapp_fleet_join_run(&c->runtime, arg, out, ZAPP_TEXT_CAP);
    else if (!strcmp(action, "fleet_preview")) {
        ok = invitation(c, arg);
        copy_text(out, ZAPP_TEXT_CAP, ok ? "Review the manager invitation." : "This is not a valid fleet invitation.");
    } else if (!strcmp(action, "fleet_scan")) {
        char error[256] = "";
        ok = zapp_camera_scan(ticket, out, ZAPP_TEXT_CAP, error, sizeof(error));
        if (ok) { ok = invitation(c, out); copy_text(out, ZAPP_TEXT_CAP, ok ? "Invitation scanned. Review before joining." : "The QR code is not a fleet invitation."); }
        else copy_text(out, ZAPP_TEXT_CAP, error);
    } else if (!strcmp(action, "chat")) ok = conversation_chat(c, arg, out);
    return ok;
}

static void execute_result(struct controller *c, const char *action, const char *arg,
                           char *out, bool ok)
{
    pthread_mutex_lock(&c->lock);
    if (!strcmp(action, "chat")) {
        c->view.reply_state = ZAPP_REPLY_READY;
        if (atomic_load(&c->reply_cancel)) {
            copy_text(c->view.notice, sizeof(c->view.notice), "Reply cancelled.");
            pthread_mutex_unlock(&c->lock);
            return;
        }
    }
    if (!strcmp(action, "fleet_join") && ok) {
        ok = parse_receipt(out, c->view.fleet_receipt, sizeof(c->view.fleet_receipt));
        if (ok) { c->view.fleet_token[0] = 0; copy_text(out, ZAPP_TEXT_CAP, "Show the receipt QR to your manager. Admission and network connection are still pending."); }
    }
    if (!strcmp(action, "chat") && ok) {
        chat_result(c, arg, out);
        copy_text(c->view.connection, sizeof(c->view.connection), "Last reply used your laptop’s Codex subscription.");
    }
    if (!strcmp(action, "chat") && !ok && strcmp(out, "Question is invalid or too long.") &&
        strcmp(out, "Not enough memory to prepare the question."))
        copy_text(c->view.connection, sizeof(c->view.connection), "Laptop connection unavailable. Connect the paired laptop over USB.");
    copy_text(c->view.output, sizeof(c->view.output), out);
    copy_text(c->view.notice, sizeof(c->view.notice), ok ? "" : out[0] ? out : "Operation could not complete.");
    c->view.scanning = false;
    pthread_mutex_unlock(&c->lock);
}

static void execute(struct controller *c, const char *action, const char *arg, uint64_t ticket)
{
    char *out = calloc(1, ZAPP_TEXT_CAP);
    if (!out) {
        char error[] = "Not enough memory to complete that action.";
        execute_result(c, action, arg, error, false);
        return;
    }
    bool ok = execute_action(c, action, arg, ticket, out);
    execute_result(c, action, arg, out, ok);
    memory_cleanse(out, ZAPP_TEXT_CAP); free(out);
}
static void *worker(void *opaque)
{
    struct controller *c = opaque;
    bool first = true;
    for (;;) {
        char action[32] = "", arg[24000] = ""; uint64_t ticket = 0;
        pthread_mutex_lock(&c->lock);
        struct timespec until;
        if (clock_gettime(CLOCK_REALTIME, &until)) { pthread_mutex_unlock(&c->lock); break; }
        until.tv_sec += 10;
        if (!c->pending && !first) (void)pthread_cond_timedwait(&c->changed, &c->lock, &until);
        first = false;
        if (c->pending) {
            copy_text(action, sizeof(action), c->action); copy_text(arg, sizeof(arg), c->argument);
            ticket = c->camera_ticket; c->pending = false;
            memory_cleanse(c->argument, sizeof(c->argument));
        }
        pthread_mutex_unlock(&c->lock);
        if (action[0]) {
            execute(c, action, arg, ticket);
            memory_cleanse(arg, sizeof(arg));
            pthread_mutex_lock(&c->lock); c->view.busy = false; pthread_mutex_unlock(&c->lock);
            notify_view(c);
        }
        observe_node(c);
    }
    return NULL;
}
bool zapp_controller_start(const char *files, const char *libs, void (*notify)(void))
{
    if (!files || !libs || strlen(files) >= 1024) return false;
    pthread_mutex_lock(&startup_lock);
    if (current) {
        pthread_mutex_lock(&current->lock); current->notify = notify; pthread_mutex_unlock(&current->lock);
        pthread_mutex_unlock(&startup_lock); return true;
    }
    struct controller *c = calloc(1, sizeof(*c));
    if (!c) { pthread_mutex_unlock(&startup_lock); return false; }
    atomic_init(&c->reply_cancel, false);
    if (pthread_mutex_init(&c->lock, NULL)) goto fail;
    if (pthread_cond_init(&c->changed, NULL)) { pthread_mutex_destroy(&c->lock); goto fail; }
    if (!zapp_runtime_init(&c->runtime, files, libs)) { pthread_cond_destroy(&c->changed); pthread_mutex_destroy(&c->lock); goto fail; }
    copy_text(c->files, sizeof(c->files), files); c->notify = notify;
    copy_text(c->view.sync_status, sizeof(c->view.sync_status), "Node status unavailable. Sync progress is unknown.");
    copy_text(c->view.connection, sizeof(c->view.connection), "Connect your laptop to use its Codex subscription.");
    zapp_device_info(c->view.hardware, sizeof(c->view.hardware));
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, c)) {
        zapp_runtime_destroy(&c->runtime); pthread_cond_destroy(&c->changed); pthread_mutex_destroy(&c->lock); goto fail;
    }
    pthread_detach(thread); current = c;
    pthread_mutex_unlock(&startup_lock); return true;
fail:
    free(c); pthread_mutex_unlock(&startup_lock); return false;
}
void zapp_controller_snapshot(struct zapp_view *view)
{
    if (!view) return;
    pthread_mutex_lock(&startup_lock);
    if (current) { pthread_mutex_lock(&current->lock); *view = current->view; pthread_mutex_unlock(&current->lock); }
    else memset(view, 0, sizeof(*view));
    pthread_mutex_unlock(&startup_lock);
}
static bool action_allowed(const char *action)
{
    static const char *const allowed[] = {"node_start", "node_stop", "operation", "fleet_refresh", "fleet_join", "fleet_preview", "fleet_scan", "chat"};
    for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); ++i)
        if (!strcmp(action, allowed[i])) return true;
    return false;
}

static bool cancel_reply(void)
{
    pthread_mutex_lock(&startup_lock);
    struct controller *c = current;
    if (!c) { pthread_mutex_unlock(&startup_lock); return false; }
    pthread_mutex_lock(&c->lock);
    if (c->view.reply_state != ZAPP_REPLY_READY) {
        atomic_store(&c->reply_cancel, true);
        c->view.reply_state = ZAPP_REPLY_CANCELLING;
        copy_text(c->view.notice, sizeof(c->view.notice), "Stopping reply…");
    }
    pthread_mutex_unlock(&c->lock);
    pthread_mutex_unlock(&startup_lock);
    notify_view(c);
    return true;
}

static bool valid_action_request(const char *action, const char *arg)
{
    return action && arg && strlen(action) < 32 && strlen(arg) < 24000 &&
        (!strcmp(action, "chat_cancel") || action_allowed(action));
}

bool zapp_controller_action(const char *action, const char *arg, const char *model)
{
    (void)model;
    if (!valid_action_request(action, arg)) return false;
    if (!strcmp(action, "chat_cancel")) return cancel_reply();
    pthread_mutex_lock(&startup_lock); struct controller *c = current;
    if (!c) { pthread_mutex_unlock(&startup_lock); return false; }
    pthread_mutex_lock(&c->lock);
    bool ok = !c->view.busy;
    if (ok && !strcmp(action, "fleet_join")) arg = c->view.fleet_token;
    if (ok && (!strcmp(action, "chat") || !strcmp(action, "fleet_join")) && !arg[0]) ok = false;
    if (ok) {
        copy_text(c->action, sizeof(c->action), action); copy_text(c->argument, sizeof(c->argument), arg);
        c->camera_ticket = zapp_camera_ticket(); c->pending = true; c->view.busy = true;
        c->view.scanning = !strcmp(action, "fleet_scan"); c->view.notice[0] = 0;
        if (!strcmp(action, "chat")) {
            atomic_store(&c->reply_cancel, false);
            c->view.reply_state = ZAPP_REPLY_WAITING;
        }
        pthread_cond_signal(&c->changed);
    }
    pthread_mutex_unlock(&c->lock); pthread_mutex_unlock(&startup_lock);
    if (ok) notify_view(c);
    return ok;
}
void zapp_controller_detach(void)
{
    pthread_mutex_lock(&startup_lock);
    if (current) { pthread_mutex_lock(&current->lock); current->notify = NULL; pthread_mutex_unlock(&current->lock); }
    zapp_camera_stop(); pthread_mutex_unlock(&startup_lock);
}
