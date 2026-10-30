/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "controller.h"
#include "conversation.h"
#include "hosts.h"
#include "pairing.h"
#include "operations.h"
#include "camera.h"
#include "audio.h"
#include "voice.h"
#include "speech_client.h"
#include "fleet.h"
#include "json/json.h"
#include "base/cleanse.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <time.h>

#define VOICE_TURNS 8u
#define VOICE_FIRST_WAIT_MS 8000u
#define VOICE_FOLLOW_UP_WAIT_MS 6000u
struct controller {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    struct zapp_runtime runtime;
    struct zapp_view view;
    struct zapp_history history;
    char files[1024], action[32], argument[24000];
    uint64_t camera_ticket;
    void (*notify)(void);
    bool pending, autostart_checked, hidden, shown;
    time_t fleet_at;
    bool seen_responding;
    int64_t seen_height, seen_target, seen_peers; /* Latest node reading, for the suggestion. */
    char asked[96];                               /* Question last answered by the model. */
    atomic_bool reply_cancel;
    atomic_bool voice_cancel, voice_stop;
    pthread_mutex_t pace_lock; /* Serializes thermal callbacks: previous pace, file write, view. */
};
static pthread_mutex_t startup_lock = PTHREAD_MUTEX_INITIALIZER;
static struct controller *current;

static void copy_text(char *out, size_t cap, const char *text)
{
    if (cap) snprintf(out, cap, "%s", text ? text : "");
}
/* Records the question being answered for display; a long one is cut on a character boundary. */
static void set_pending(char *out, const char *question)
{
    copy_text(out, ZAPP_PENDING_CAP, question);
    size_t n = strlen(out);
    if (question[n]) {
        while (n && ((unsigned char)question[n] & 0xC0) == 0x80) n--;
        out[n] = 0;
    }
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
            "Invitation received. Join only if it came from your fleet manager. Z23 checks its signature and expiry when you join.");
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
/* Heights and peer count from a status reply; values the reply lacks stay negative. */
struct node_reading { bool responding; int64_t height, target, peers; };
static struct node_reading read_status(const char *output)
{
    struct node_reading n = {.height = -1, .target = -1, .peers = -1};
    struct json_value root = {0};
    if (!output || !json_read(&root, output, strlen(output))) return n;
    const struct json_value *success = json_get(&root, "ok"), *data = json_get(&root, "data");
    const struct json_value *height = json_get(data, "provable_tip"), *target = json_get(data, "max_peer_height");
    const struct json_value *peers = json_get(data, "peers");
    n.responding = success && success->type == JSON_BOOL && json_get_bool(success) && height &&
        height->type == JSON_INT;
    if (n.responding) {
        n.height = json_get_int(height);
        if (target && target->type == JSON_INT) n.target = json_get_int(target);
        if (peers && peers->type == JSON_INT) n.peers = json_get_int(peers);
    }
    json_free(&root);
    return n;
}
/* Caller holds c->lock. Offers one question from the latest node reading, the current fleet report
 * and the question last answered. */
static void refresh_suggestion(struct controller *c)
{
    zapp_suggestion(c->view.fleet_paired, c->seen_responding, c->seen_height, c->seen_target, c->seen_peers,
                    c->view.fleet_stale ? NULL : c->view.fleet_status, c->asked,
                    c->view.suggestion, sizeof(c->view.suggestion));
}
/* Runs on a platform binder thread; the pace file write is small and done inline. The view shows the
 * pace the node reports, not the one written here, so a node that ignores the file is not misreported. */
#ifdef __ANDROID__
static void thermal_status(int status, void *ctx)
{
    struct controller *c = ctx;
    pthread_mutex_lock(&c->pace_lock);
    (void)zapp_node_pace_write(&c->runtime, zapp_pace_next(zapp_node_pace(&c->runtime), status));
    pthread_mutex_unlock(&c->pace_lock);
}
#endif
static void observe_node(struct controller *c)
{
    char *output = calloc(1, ZAPP_TEXT_CAP);
    bool ran = output && zapp_operation_run(&c->runtime, "status", output, ZAPP_TEXT_CAP);
    struct node_reading n = read_status(ran ? output : NULL);
    enum zapp_pace pace = zapp_status_pace(ran ? output : NULL);
    observe_balance(c, output);
    free(output);
    bool process_running = zapp_node_running(&c->runtime), stopping = zapp_node_stopping(&c->runtime);
    bool wanted = zapp_node_wanted(&c->runtime);
    char status[1024], line[96];
    zapp_sync_line(n.responding, process_running, n.height, n.target, status, sizeof(status));
    if (stopping) copy_text(status, sizeof(status), "The node is saving its data before it exits.");
    zapp_node_line(n.responding, process_running, stopping, n.height, n.target, n.peers, line, sizeof(line));
    pthread_mutex_lock(&c->lock);
    c->view.node_running = n.responding;
    c->view.node_process_running = process_running;
    c->view.pace = pace;
    c->view.node_wanted = wanted;
    copy_text(c->view.sync_status, sizeof(c->view.sync_status), status);
    copy_text(c->view.node_line, sizeof(c->view.node_line), line);
    c->seen_responding = n.responding; c->seen_height = n.height; c->seen_target = n.target; c->seen_peers = n.peers;
    refresh_suggestion(c);
    pthread_mutex_unlock(&c->lock);
    notify_view(c);
}
/* Caller holds c->lock. Shows the exchange first; only answers from the model join the history sent
 * with later questions and move the suggestion on to a follow-up. */
static void chat_result(struct controller *c, const char *prompt, const char *answer, bool from_model)
{
    if (from_model) {
        (void)zapp_history_append(&c->history, prompt, answer);
        copy_text(c->asked, sizeof(c->asked), prompt);
        refresh_suggestion(c);
    }
    zapp_transcript_prepend(c->view.transcript, sizeof(c->view.transcript), prompt, answer);
    c->view.pending_question[0] = 0;
}
static void voice_stage(struct controller *c, enum zapp_voice_state state, const char *text)
{
    pthread_mutex_lock(&c->lock);
    c->view.voice_state = state;
    copy_text(c->view.voice_status, sizeof(c->view.voice_status), text);
    pthread_mutex_unlock(&c->lock);
    notify_view(c);
}
/* Audio relayed while the private model is still writing; the player opens on the first samples. */
struct voice_stream {
    struct controller *c;
    struct zapp_player *player;
    char error[256];
    bool failed;
};
static void stream_pcm(const int16_t *samples, size_t count, int rate, void *opaque)
{
    struct voice_stream *v = opaque;
    if (v->failed) return;
    if (!v->player) {
        v->failed = !zapp_player_open(&v->player, rate, v->error, sizeof(v->error));
        if (!v->failed) voice_stage(v->c, ZAPP_VOICE_PLAYING, "Speaking…");
    } else if (rate != zapp_player_rate(v->player)) {
        copy_text(v->error, sizeof(v->error), "Spoken audio changed format."); v->failed = true;
    }
    if (!v->failed && !zapp_player_write(v->player, samples, count, &v->c->voice_cancel,
                                         v->error, sizeof(v->error))) v->failed = true;
}
/* Asks the paired laptop's private model with a fresh node snapshot and earlier exchanges; with a
 * stream, the answer is spoken as it is written. */
static bool ask_with(struct controller *c, const char *question, char *out, const atomic_bool *cancel,
                     struct voice_stream *stream)
{
    struct zapp_conversation_snapshot snapshot = {0};
    struct json_value history = {0};
    char *prompt = calloc(1, ZAPP_CONVERSATION_CAP);
    if (!prompt) { copy_text(out, ZAPP_TEXT_CAP, "Not enough memory to prepare the question."); return false; }
    observe_node(c);
    pthread_mutex_lock(&c->lock);
    copy_text(snapshot.sync_status, sizeof(snapshot.sync_status), c->view.sync_status);
    copy_text(snapshot.balance, sizeof(snapshot.balance), c->view.balance);
    snapshot.balance_known = c->view.balance_known;
    snapshot.balance_stale = c->view.balance_stale;
    snapshot.node_running = c->view.node_running;
    const struct json_value *earlier = zapp_history_json(&c->history, &history) ? &history : NULL;
    pthread_mutex_unlock(&c->lock);
    bool ok = !atomic_load(cancel) &&
        zapp_conversation_format(&snapshot, question, prompt, ZAPP_CONVERSATION_CAP);
    if (ok) ok = stream ? zapp_speech_client_respond(c->files, prompt, earlier, NULL, stream_pcm, stream,
                                                     out, ZAPP_TEXT_CAP, cancel) :
        zapp_speech_client_chat(c->files, prompt, earlier, out, ZAPP_TEXT_CAP, cancel);
    else if (!atomic_load(cancel)) copy_text(out, ZAPP_TEXT_CAP, "Question is invalid or too long.");
    memory_cleanse(prompt, ZAPP_CONVERSATION_CAP); free(prompt);
    memory_cleanse(&snapshot, sizeof(snapshot));
    json_cleanse_strings(&history); json_free(&history);
    return ok && !atomic_load(cancel);
}
static bool ask_assistant(struct controller *c, const char *question, char *out, const atomic_bool *cancel)
{
    return ask_with(c, question, out, cancel, NULL);
}
static bool conversation_chat(struct controller *c, const char *question, char *out)
{
    return ask_assistant(c, question, out, &c->reply_cancel);
}
static bool fleet_hosts(struct controller *c, bool refresh, char *out)
{
    char *formatted = calloc(1, sizeof(c->view.fleet_status));
    bool answered = formatted && zapp_speech_client_fleet(c->files, refresh, out, ZAPP_TEXT_CAP, NULL);
    bool ok = answered && zapp_hosts_format(out, formatted, sizeof(c->view.fleet_status));
    pthread_mutex_lock(&c->lock);
    if (ok) {
        copy_text(c->view.fleet_status, sizeof(c->view.fleet_status), formatted);
        c->view.fleet_stale = false;
        /* An answered fleet request proves the paired host is reachable. */
        c->view.fleet_paired = true;
        copy_text(c->view.connection, sizeof(c->view.connection), "Laptop host connected.");
    } else {
        /* The last report, if any, stays visible, marked old, once no current one arrives. */
        c->view.fleet_stale = true;
        if (c->view.fleet_paired) copy_text(c->view.connection, sizeof(c->view.connection), answered ?
                  "Laptop host connected. It sent no fleet report." :
                  "Laptop host not answering. Connect it over USB and keep it running.");
    }
    refresh_suggestion(c);
    pthread_mutex_unlock(&c->lock);
    copy_text(out, ZAPP_TEXT_CAP, ok ? formatted : "Fleet status is unavailable. Connect the laptop host over USB.");
    free(formatted);
    return ok;
}

static void voice_answer(struct controller *c, enum zapp_voice_intent intent, char answer[120])
{
    observe_node(c);
    pthread_mutex_lock(&c->lock);
    if (intent == ZAPP_VOICE_STATUS)
        copy_text(answer, 120, c->view.node_running ?
            "Node responding. Check sync progress on screen." :
            "Node status is unavailable.");
    else if (intent == ZAPP_VOICE_BALANCE) {
        if (!c->view.balance_known || c->view.balance_stale)
            copy_text(answer, 120, "Current balance is unavailable.");
        else if (strcspn(c->view.balance, "\n") < 100)
            snprintf(answer, 120, "%.*s", (int)strcspn(c->view.balance, "\n"), c->view.balance);
        else copy_text(answer, 120, "The refreshed balance is displayed on screen.");
    } else if (intent == ZAPP_VOICE_START && c->runtime.preview) {
        copy_text(answer, 120, "The preview app does not run a node.");
    } else if (intent == ZAPP_VOICE_START || intent == ZAPP_VOICE_STOP) {
        copy_text(c->view.voice_proposal, sizeof(c->view.voice_proposal),
            intent == ZAPP_VOICE_START ? "node_start" : "node_stop");
        copy_text(answer, 120, intent == ZAPP_VOICE_START ?
            "Confirm on screen to start the node." : "Confirm on screen to stop the node.");
    } else copy_text(answer, 120, "Say node status, balance, start node, or stop node.");
    pthread_mutex_unlock(&c->lock);
}
static bool voice_transcribe(struct controller *c, const int16_t *samples, size_t count, char *transcript,
                             size_t cap, char *error, size_t error_cap)
{
    voice_stage(c, ZAPP_VOICE_TRANSCRIBING, "Transcribing on your laptop…");
    bool ok = zapp_speech_client_transcribe(c->files, samples, count, transcript, cap, &c->voice_cancel);
    if (!ok) copy_text(error, error_cap, transcript[0] ? transcript : "Transcription unavailable. Type your question instead.");
    return ok;
}
enum listen_result { LISTEN_FAILED, LISTEN_SILENT, LISTEN_HEARD };
static enum listen_result voice_listen(struct controller *c, bool follow_up, char *transcript, size_t cap,
                                       char *error, size_t error_cap)
{
    int16_t *samples = calloc(320000, sizeof(*samples));
    size_t count = 0;
    bool heard = false;
    if (!samples) { copy_text(error, error_cap, "Not enough memory for recording."); return LISTEN_FAILED; }
    atomic_store(&c->voice_stop, false);
    voice_stage(c, ZAPP_VOICE_RECORDING, follow_up ? "Listening for a follow-up… stay quiet to finish." :
                "Listening… pause when you are done.");
    bool ok = zapp_audio_capture(samples, 320000, &count, follow_up ? VOICE_FOLLOW_UP_WAIT_MS : VOICE_FIRST_WAIT_MS,
                                 &heard, &c->voice_stop, &c->voice_cancel, error, error_cap);
    /* On the first turn Done talking counts as speech: the owner may speak below the threshold. */
    heard = heard || (!follow_up && atomic_load(&c->voice_stop));
    if (ok && heard && !atomic_load(&c->voice_cancel))
        ok = voice_transcribe(c, samples, count, transcript, cap, error, error_cap);
    memory_cleanse(samples, 320000 * sizeof(*samples)); free(samples);
    if (!ok || atomic_load(&c->voice_cancel)) return LISTEN_FAILED;
    return heard ? LISTEN_HEARD : LISTEN_SILENT;
}
/* Start and stop stay on-screen proposals; everything else goes to the private model, which
 * streams its audio when the laptop supports it. Without any audio the caller speaks the text.
 * Returns whether the private model answered. */
static bool voice_reply(struct controller *c, const char *transcript, char *answer, struct voice_stream *stream)
{
    enum zapp_voice_intent intent = zapp_voice_interpret(transcript);
    char brief[120] = "";
    if (intent == ZAPP_VOICE_START || intent == ZAPP_VOICE_STOP) {
        voice_answer(c, intent, brief); copy_text(answer, ZAPP_TEXT_CAP, brief); return false;
    }
    pthread_mutex_lock(&c->lock);
    set_pending(c->view.pending_question, transcript);
    pthread_mutex_unlock(&c->lock);
    voice_stage(c, ZAPP_VOICE_OBSERVING, "Thinking privately on your laptop…");
    if (ask_with(c, transcript, answer, &c->voice_cancel, stream)) return true;
    if (atomic_load(&c->voice_cancel) || stream->player) return false;
    if (ask_assistant(c, transcript, answer, &c->voice_cancel)) return true;
    if (atomic_load(&c->voice_cancel)) return false;
    voice_answer(c, intent, brief);
    copy_text(answer, ZAPP_TEXT_CAP, brief);
    return false;
}
static bool speak_chunk(struct controller *c, const char *chunk, struct zapp_player **player,
                        char *error, size_t error_cap)
{
    int16_t *samples = NULL; size_t count = 0; int rate = 0;
    bool ok = zapp_speech_client_speak(c->files, chunk, &samples, &count, &rate,
                                       &c->voice_cancel, error, error_cap);
    if (ok && !*player && (ok = zapp_player_open(player, rate, error, error_cap)))
        voice_stage(c, ZAPP_VOICE_PLAYING, "Speaking…");
    if (ok && rate != zapp_player_rate(*player)) {
        copy_text(error, error_cap, "Spoken audio changed format."); ok = false;
    }
    if (ok) ok = zapp_player_write(*player, samples, count, &c->voice_cancel, error, error_cap);
    if (samples) memory_cleanse(samples, count * sizeof(*samples));
    free(samples);
    return ok;
}
/* Speaks the answer in chunks of similar length: laptop synthesis runs near real time with
 * a fixed cost per request, so the next chunk is ready about when the previous one ends. */
static bool voice_speak(struct controller *c, const char *text, char *error, size_t error_cap)
{
    struct zapp_player *player = NULL;
    bool ok = true;
    for (const char *p = text; ok && !atomic_load(&c->voice_cancel);) {
        while (*p == ' ' || *p == '\n') p++;
        size_t n = zapp_voice_chunk(p, 80);
        if (!n) break;
        char chunk[81];
        snprintf(chunk, sizeof(chunk), "%.*s", (int)n, p);
        p += n;
        ok = speak_chunk(c, chunk, &player, error, error_cap);
    }
    bool drain = !atomic_load(&c->voice_cancel);
    return zapp_player_close(player, drain, &c->voice_cancel, ok ? error : NULL, ok ? error_cap : 0) && ok;
}
/* Finishes a streamed answer, or speaks the text when no audio was streamed. A cancel closes the
 * player without draining it. Returns whether the spoken answer played to its end. */
static bool voice_finish(struct controller *c, struct voice_stream *stream, const char *text, char *error, size_t error_cap)
{
    bool drain = !atomic_load(&c->voice_cancel), ok = false;
    if (stream->player) {
        ok = zapp_player_close(stream->player, drain, &c->voice_cancel, error, error_cap) && drain &&
            !stream->failed;
        stream->player = NULL;
    } else if (drain) {
        voice_stage(c, ZAPP_VOICE_SYNTHESIZING, "Preparing the spoken answer…");
        ok = voice_speak(c, text, error, error_cap);
    }
    if (!ok && !atomic_load(&c->voice_cancel))
        voice_stage(c, ZAPP_VOICE_READY, "Spoken audio unavailable. The answer is shown in the conversation.");
    return ok;
}
/* TURN_HELD: answered, but a proposal waits for a tap or the answer could not be spoken. */
enum turn_result { TURN_FAILED, TURN_SILENT, TURN_ANSWERED, TURN_HELD };
/* One spoken exchange; out keeps the previous answer when nothing was heard. */
static enum turn_result voice_turn(struct controller *c, bool follow_up, char *out)
{
    char transcript[4096] = "", error[256] = "";
    enum listen_result heard = voice_listen(c, follow_up, transcript, sizeof(transcript), error, sizeof(error));
    if (heard == LISTEN_FAILED) copy_text(out, ZAPP_TEXT_CAP, error);
    if (heard != LISTEN_HEARD) return heard == LISTEN_SILENT ? TURN_SILENT : TURN_FAILED;
    struct voice_stream stream = {.c = c};
    bool answered = voice_reply(c, transcript, out, &stream), proposed = false;
    if (!atomic_load(&c->voice_cancel)) {
        pthread_mutex_lock(&c->lock);
        chat_result(c, transcript, out, answered);
        proposed = c->view.voice_proposal[0] != 0;
        pthread_mutex_unlock(&c->lock);
    }
    bool spoken = voice_finish(c, &stream, out, error, sizeof(error));
    if (atomic_load(&c->voice_cancel)) return TURN_FAILED;
    return proposed || !spoken ? TURN_HELD : TURN_ANSWERED;
}
/* Listens again after each spoken answer until the owner stays quiet or cancels, a proposal waits
 * for a tap on screen, or an answer could not be spoken, for at most VOICE_TURNS exchanges. */
static bool voice_conversation(struct controller *c, char *out)
{
    enum turn_result r = voice_turn(c, false, out);
    if (r == TURN_SILENT) { copy_text(out, ZAPP_TEXT_CAP, "No speech heard. Press Talk and speak."); return false; }
    for (unsigned turn = 1; r == TURN_ANSWERED && turn < VOICE_TURNS; turn++) r = voice_turn(c, true, out);
    if (r == TURN_FAILED) return false;
    if (r != TURN_HELD) voice_stage(c, ZAPP_VOICE_READY, "Conversation ended. Press Talk to begin.");
    return true;
}

static bool scan_invitation(struct controller *c, uint64_t ticket, char *out)
{
    char error[256] = "";
    bool ok = zapp_camera_scan(ticket, out, ZAPP_TEXT_CAP, error, sizeof(error));
    if (!ok) { copy_text(out, ZAPP_TEXT_CAP, error); return false; }
    ok = invitation(c, out);
    copy_text(out, ZAPP_TEXT_CAP, ok ? "Invitation scanned. Review before joining." : "The QR code is not a fleet invitation.");
    return ok;
}
static bool execute_fleet(struct controller *c, const char *action, const char *arg,
                          uint64_t ticket, char *out)
{
    bool ok = false;
    if (!strcmp(action, "fleet_hosts")) ok = fleet_hosts(c, !strcmp(arg, "refresh"), out);
    else if (!strcmp(action, "fleet_join")) ok = zapp_fleet_join_run(&c->runtime, arg, out, ZAPP_TEXT_CAP);
    else if (!strcmp(action, "fleet_preview")) {
        ok = invitation(c, arg);
        copy_text(out, ZAPP_TEXT_CAP, ok ? "Review the manager invitation." : "This is not a valid fleet invitation.");
    } else if (!strcmp(action, "fleet_scan")) ok = scan_invitation(c, ticket, out);
    return ok;
}
static bool pair_voice_host(struct controller *c, const char *arg, char *out)
{
    char error[256] = "";
    bool ok = zapp_speech_client_pair(c->files, arg, error, sizeof(error));
    copy_text(out, ZAPP_TEXT_CAP, ok ? "Laptop host paired. Press Talk to begin." :
        "Pairing failed. Restart the laptop host to offer pairing again.");
    if (ok) {
        pthread_mutex_lock(&c->lock);
        c->view.pair_offer[0] = 0; c->view.pair_code[0] = 0;
        c->view.fleet_paired = true;
        c->fleet_at = 0;
        copy_text(c->view.voice_status, sizeof(c->view.voice_status), "Laptop host paired. Press Talk to begin.");
        pthread_mutex_unlock(&c->lock);
    }
    memory_cleanse(error, sizeof(error));
    return ok;
}
static bool execute_action(struct controller *c, const char *action, const char *arg,
                           uint64_t ticket, char *out)
{
    if (!strncmp(action, "fleet_", 6)) return execute_fleet(c, action, arg, ticket, out);
    if (!strcmp(action, "node_start")) return zapp_node_start(&c->runtime, out, ZAPP_TEXT_CAP);
    if (!strcmp(action, "node_stop")) return zapp_node_stop(&c->runtime, out, ZAPP_TEXT_CAP);
    if (!strcmp(action, "chat")) return conversation_chat(c, arg, out);
    if (!strcmp(action, "voice_start")) return voice_conversation(c, out);
    if (!strcmp(action, "voice_pair")) return pair_voice_host(c, arg, out);
    return false;
}

/* Caller holds c->lock. Returns false when the voice turn was cancelled. */
static bool voice_result(struct controller *c, bool ok, const char *out)
{
    c->view.voice_state = ZAPP_VOICE_READY;
    c->view.pending_question[0] = 0;
    if (atomic_load(&c->voice_cancel)) {
        c->view.voice_proposal[0] = 0;
        copy_text(c->view.voice_status, sizeof(c->view.voice_status), "Voice cancelled. Press Talk to begin again.");
        return false;
    }
    if (!ok) copy_text(c->view.voice_status, sizeof(c->view.voice_status), out);
    else if (!strcmp(c->view.voice_status, "Speaking…"))
        copy_text(c->view.voice_status, sizeof(c->view.voice_status), "Ready. Press Talk to begin.");
    return true;
}
/* Caller holds c->lock. Returns false when the reply was cancelled. */
static bool chat_state(struct controller *c)
{
    c->view.reply_state = ZAPP_REPLY_READY;
    c->view.pending_question[0] = 0;
    if (!atomic_load(&c->reply_cancel)) return true;
    copy_text(c->view.notice, sizeof(c->view.notice), "Reply cancelled.");
    return false;
}
/* Caller holds c->lock. */
static void chat_outcome(struct controller *c, const char *arg, bool ok, char *out)
{
    if (ok) {
        chat_result(c, arg, out, true);
        copy_text(c->view.connection, sizeof(c->view.connection), "Answered privately by the model on your laptop.");
    } else if (strcmp(out, "Question is invalid or too long.") &&
               strcmp(out, "Not enough memory to prepare the question."))
        copy_text(c->view.connection, sizeof(c->view.connection), "Laptop host not answering. Connect it over USB and keep it running.");
}
/* Caller holds c->lock. */
static bool join_result(struct controller *c, char *out)
{
    bool ok = parse_receipt(out, c->view.fleet_receipt, sizeof(c->view.fleet_receipt));
    if (ok) { c->view.fleet_token[0] = 0; copy_text(out, ZAPP_TEXT_CAP, "Show this QR code to your fleet manager. The phone joins once they admit it."); }
    return ok;
}
/* The node line already shows a start or stop; a notice is needed only when the choice was not saved. */
static bool node_choice_saved(struct controller *c, const char *action)
{
    if (strcmp(action, "node_start") && strcmp(action, "node_stop")) return false;
    return zapp_node_wanted(&c->runtime) == !strcmp(action, "node_start");
}
/* Caller holds c->lock. Actions under More report beside their controls and the rest on the main
 * screen; a success already shown by the node line, transcript or host list leaves no notice. */
static void report(struct controller *c, const char *action, bool ok, const char *out)
{
    bool more = !strncmp(action, "fleet_", 6) || !strcmp(action, "voice_pair");
    bool shown = ok && (!strcmp(action, "chat") || !strcmp(action, "voice_start") ||
                        !strcmp(action, "fleet_hosts") || node_choice_saved(c, action));
    copy_text(more ? c->view.result : c->view.notice, ZAPP_NOTICE_CAP,
              shown ? "" : out[0] ? out : "Operation could not complete.");
}
static void execute_result(struct controller *c, const char *action, const char *arg,
                           char *out, bool ok)
{
    bool chat = !strcmp(action, "chat");
    pthread_mutex_lock(&c->lock);
    if (!strcmp(action, "voice_start") && !voice_result(c, ok, out)) {
        pthread_mutex_unlock(&c->lock); return;
    }
    if (chat && !chat_state(c)) { pthread_mutex_unlock(&c->lock); return; }
    if (!strcmp(action, "fleet_join") && ok) ok = join_result(c, out);
    if (chat) chat_outcome(c, arg, ok, out);
    zapp_plain_text(out, ZAPP_TEXT_CAP);
    report(c, action, ok, out);
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
/* The laptop host refreshes its fleet snapshot every minute; reading its copy as often keeps the
 * fleet headline current without probing the hosts again. */
static void observe_fleet(struct controller *c)
{
    time_t now = time(NULL);
    if (now != (time_t)-1 && now - c->fleet_at < 60) return;
    c->fleet_at = now;
    char *out = calloc(1, ZAPP_TEXT_CAP);
    if (out) (void)fleet_hosts(c, false, out);
    free(out);
}
static void queue_action(struct controller *c, const char *action, const char *arg);
/* Opening the app starts the node once when the owner last chose Start node and no node runs. */
static void start_if_wanted(struct controller *c)
{
    c->autostart_checked = true;
    bool wanted = zapp_node_wanted(&c->runtime);
    pthread_mutex_lock(&c->lock);
    bool idle = !c->pending && !c->view.busy && !c->view.node_running && !c->view.node_process_running;
    if (wanted && idle) queue_action(c, "node_start", "");
    pthread_mutex_unlock(&c->lock);
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
        /* While hidden no screen shows the node or fleet; only an action or showing the app wakes it.
         * shown also covers an app shown while the worker was busy, when no waiter took the signal. */
        bool wait = !c->pending && !first && !c->shown;
        if (wait && c->hidden) (void)pthread_cond_wait(&c->changed, &c->lock);
        else if (wait) (void)pthread_cond_timedwait(&c->changed, &c->lock, &until);
        first = false; c->shown = false;
        bool hidden = c->hidden;
        if (c->pending) {
            copy_text(action, sizeof(action), c->action); copy_text(arg, sizeof(arg), c->argument);
            ticket = c->camera_ticket; c->pending = false;
            memory_cleanse(c->argument, sizeof(c->argument));
        }
        pthread_mutex_unlock(&c->lock);
        if (action[0]) {
            execute(c, action, arg, ticket);
            memory_cleanse(arg, sizeof(arg));
            bool process_running = zapp_node_running(&c->runtime), stopping = zapp_node_stopping(&c->runtime);
            bool wanted = zapp_node_wanted(&c->runtime);
            pthread_mutex_lock(&c->lock);
            c->view.node_process_running = process_running;
            c->view.node_wanted = wanted;
            if (!c->view.node_running) {
                zapp_sync_line(false, process_running, -1, -1, c->view.sync_status, sizeof(c->view.sync_status));
                zapp_node_line(false, process_running, stopping, -1, -1, -1, c->view.node_line, sizeof(c->view.node_line));
            }
            c->view.busy = false;
            pthread_mutex_unlock(&c->lock);
            notify_view(c);
        }
        if (!hidden) { observe_node(c); observe_fleet(c); }
        if (!c->autostart_checked) start_if_wanted(c);
    }
    return NULL;
}
bool zapp_controller_start(const char *files, const char *libs, bool preview, void (*notify)(void))
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
    atomic_init(&c->voice_cancel, false);
    atomic_init(&c->voice_stop, false);
    c->pace_lock = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
    if (pthread_mutex_init(&c->lock, NULL)) goto fail;
    if (pthread_cond_init(&c->changed, NULL)) { pthread_mutex_destroy(&c->lock); goto fail; }
    if (!zapp_runtime_init(&c->runtime, files, libs, preview)) { pthread_cond_destroy(&c->changed); pthread_mutex_destroy(&c->lock); goto fail; }
    c->view.node_process_running = zapp_node_running(&c->runtime);
    c->view.node_wanted = zapp_node_wanted(&c->runtime);
    copy_text(c->files, sizeof(c->files), files); c->notify = notify;
    copy_text(c->view.sync_status, sizeof(c->view.sync_status), "Start the node to begin synchronization.");
    zapp_node_line(false, c->view.node_process_running, false, -1, -1, -1, c->view.node_line, sizeof(c->view.node_line));
    c->view.fleet_paired = zapp_speech_client_has_host(files);
    copy_text(c->view.connection, sizeof(c->view.connection), c->view.fleet_paired ?
              "Laptop host paired. Connecting." : "Private assistant: pair your laptop host over USB.");
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, c)) {
        zapp_runtime_destroy(&c->runtime); pthread_cond_destroy(&c->changed); pthread_mutex_destroy(&c->lock); goto fail;
    }
    pthread_detach(thread); current = c;
#ifdef __ANDROID__
    /* The listener outlives the activity: the foreground service keeps the process, and so the pace,
     * alive while the app is hidden. The controller lives as long as the process. */
    (void)zapp_thermal_start(thermal_status, c);
#endif
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
    static const char *const allowed[] = {"node_start", "node_stop", "fleet_join", "fleet_preview", "fleet_scan", "chat", "voice_start", "voice_confirm", "fleet_hosts", "pair_accept"};
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
        c->view.pending_question[0] = 0;
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
        (!strcmp(action, "chat_cancel") || !strcmp(action, "voice_finish") || !strcmp(action, "voice_cancel") || !strcmp(action, "pair_offer") || !strcmp(action, "pair_reject") ||
        action_allowed(action));
}

static bool is_voice_control(const char *action)
{
    return !strcmp(action, "voice_finish") || !strcmp(action, "voice_cancel");
}
/* Caller holds c->lock. */
static void voice_control(struct controller *c, const char *action)
{
    if (!strcmp(action, "voice_finish")) { atomic_store(&c->voice_stop, true); return; }
    atomic_store(&c->voice_cancel, true);
    c->view.voice_proposal[0] = 0;
    c->view.pending_question[0] = 0;
    if (c->view.voice_state != ZAPP_VOICE_READY) c->view.voice_state = ZAPP_VOICE_CANCELLING;
}
static bool is_pair_control(const char *action)
{
    return !strcmp(action, "pair_offer") || !strcmp(action, "pair_reject");
}
/* Caller holds c->lock. Returns whether the request was accepted. */
static bool pair_control(struct controller *c, const char *action, const char *arg)
{
    bool known = !strcmp(action, "pair_offer") && zapp_speech_client_paired(c->files, arg);
    bool offer = !known && !strcmp(action, "pair_offer") && strlen(arg) < sizeof(c->view.pair_offer) &&
        zapp_pair_code(arg, c->view.pair_code);
    copy_text(c->view.pair_offer, sizeof(c->view.pair_offer), offer ? arg : "");
    if (!offer) c->view.pair_code[0] = 0;
    if (known) copy_text(c->view.connection, sizeof(c->view.connection), "Laptop host connected.");
    return offer || known || !strcmp(action, "pair_reject");
}
static const char *confirmed_action(const struct controller *c)
{
    if (!strcmp(c->view.voice_proposal, "node_start")) return "node_start";
    if (!strcmp(c->view.voice_proposal, "node_stop")) return "node_stop";
    return NULL;
}
/* Caller holds c->lock. Rewrites `action` and `arg` for confirmations; false rejects the request. */
static bool resolve_action(struct controller *c, const char **action, const char **arg)
{
    if (c->view.busy) return false;
    if (!strcmp(*action, "pair_accept")) {
        if (!c->view.pair_offer[0]) return false;
        *action = "voice_pair"; *arg = c->view.pair_offer;
    }
    if (!strcmp(*action, "voice_confirm") && !(*action = confirmed_action(c))) return false;
    if (!strcmp(*action, "fleet_join")) *arg = c->view.fleet_token;
    return (*arg)[0] || (strcmp(*action, "chat") && strcmp(*action, "fleet_join"));
}
/* Caller holds c->lock. */
static void queue_action(struct controller *c, const char *action, const char *arg)
{
    c->view.voice_proposal[0] = 0;
    if (!strcmp(action, "voice_start")) {
        atomic_store(&c->voice_cancel, false); atomic_store(&c->voice_stop, false);
        c->view.voice_state = ZAPP_VOICE_RECORDING;
        copy_text(c->view.voice_status, sizeof(c->view.voice_status), "Starting recording…");
    }
    copy_text(c->action, sizeof(c->action), action); copy_text(c->argument, sizeof(c->argument), arg);
    c->camera_ticket = zapp_camera_ticket(); c->pending = true; c->view.busy = true;
    c->view.scanning = !strcmp(action, "fleet_scan"); c->view.notice[0] = 0; c->view.result[0] = 0;
    if (!strcmp(action, "chat")) {
        atomic_store(&c->reply_cancel, false);
        c->view.reply_state = ZAPP_REPLY_WAITING;
        set_pending(c->view.pending_question, arg);
    }
    pthread_cond_signal(&c->changed);
}
bool zapp_controller_action(const char *action, const char *arg, const char *model)
{
    (void)model;
    if (!valid_action_request(action, arg)) return false;
    if (!strcmp(action, "chat_cancel")) return cancel_reply();
    pthread_mutex_lock(&startup_lock); struct controller *c = current;
    if (!c) { pthread_mutex_unlock(&startup_lock); return false; }
    pthread_mutex_lock(&c->lock);
    bool control = is_voice_control(action), pairing = is_pair_control(action);
    bool ok = true;
    if (control) voice_control(c, action);
    else if (pairing) ok = pair_control(c, action, arg);
    else if ((ok = resolve_action(c, &action, &arg))) queue_action(c, action, arg);
    pthread_mutex_unlock(&c->lock); pthread_mutex_unlock(&startup_lock);
    if (ok) notify_view(c);
    return ok;
}
void zapp_controller_detach(void)
{
    zapp_controller_visible(false);
    pthread_mutex_lock(&startup_lock);
    if (current) { pthread_mutex_lock(&current->lock); current->notify = NULL; pthread_mutex_unlock(&current->lock); }
    zapp_camera_stop(); pthread_mutex_unlock(&startup_lock);
}
void zapp_controller_visible(bool visible)
{
    if (!visible) (void)zapp_controller_action("voice_cancel", "", "");
    pthread_mutex_lock(&startup_lock);
    if (current) {
        pthread_mutex_lock(&current->lock);
        current->shown = visible && current->hidden; current->hidden = !visible;
        pthread_cond_signal(&current->changed);
        pthread_mutex_unlock(&current->lock);
    }
    pthread_mutex_unlock(&startup_lock);
}
bool zapp_controller_node_running(void)
{
    pthread_mutex_lock(&startup_lock);
    struct controller *c = current;
    pthread_mutex_unlock(&startup_lock);
    return c && zapp_node_running(&c->runtime);
}
