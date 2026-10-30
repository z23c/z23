/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "assistant.h"
#include "fleet_probe.h"
#include "host_ops.h"
#include "host.h"
#include "hosts.h"
#include "relay.h"
#include "json/json.h"
#include <getopt.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#define CAPTURE_HEX_CAP 1280088u
#define REPLY_WAV_CAP 2880044u
#define TEXT_CAP 65536u
#define FLEET_CAP 65536u
#define OPS_CAP 4096
struct options {
    const char *dir, *llama, *models, *speaker, *fleet, *adb, *serial, *app;
    uint16_t port;
};
static struct zapp_assistant assistant;
static struct zapp_fleet_host fleet_hosts[16];
static size_t fleet_count;
static pthread_mutex_t fleet_lock = PTHREAD_MUTEX_INITIALIZER;
static char fleet_snapshot[FLEET_CAP];
static time_t fleet_time;

static bool string_is(const struct json_value *root, const char *key, const char *expected)
{
    const char *value = json_get_str(json_get(root, key));
    return value && !strcmp(value, expected);
}
static bool no_nul_escape(const char *wire)
{
    for (size_t i = 0; wire[i]; ++i) {
        if (wire[i] != '\\') continue;
        if (!wire[++i]) return false;
        if (wire[i] == 'u' && !strncmp(wire + i, "u0000", 5)) return false;
    }
    return true;
}
static int hex_digit(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}
static bool refresh_fleet(void)
{
    char *text = fleet_count ? malloc(FLEET_CAP) : NULL;
    bool ok = text && zapp_fleet_probe(fleet_hosts, fleet_count, 25000, text, FLEET_CAP);
    if (ok) {
        pthread_mutex_lock(&fleet_lock);
        memcpy(fleet_snapshot, text, strlen(text) + 1); fleet_time = time(NULL);
        pthread_mutex_unlock(&fleet_lock);
    }
    free(text);
    return ok;
}
static void *fleet_loop(void *unused)
{
    (void)unused;
    while (!zapp_relay_stopping()) {
        (void)refresh_fleet();
        for (int i = 0; i < 600 && !zapp_relay_stopping(); i++) usleep(100000);
    }
    return NULL;
}
static bool transcribe(const struct json_value *request, int client, struct json_value *response)
{
    const char *hex = json_get_str(json_get(request, "wav"));
    size_t length = hex ? strlen(hex) : 0, bytes = length / 2;
    if (!length || length > CAPTURE_HEX_CAP || (length & 1)) return false;
    unsigned char *wav = malloc(bytes);
    char *text = calloc(1, TEXT_CAP);
    bool ok = wav && text;
    for (size_t i = 0; ok && i < bytes; ++i) {
        int high = hex_digit((unsigned char)hex[i * 2]), low = hex_digit((unsigned char)hex[i * 2 + 1]);
        if (high < 0 || low < 0) ok = false;
        else wav[i] = (unsigned char)(high * 16 + low);
    }
    ok = ok && zapp_assistant_transcribe(&assistant, wav, bytes, client, text, TEXT_CAP);
    ok = ok && json_push_kv_str(response, "text", text);
    if (text) { memory_cleanse(text, TEXT_CAP); free(text); }
    if (wav) { memory_cleanse(wav, bytes); free(wav); }
    return ok;
}
static bool chat(const struct json_value *request, int client, struct json_value *response, bool stream)
{
    const char *prompt = json_get_str(json_get(request, "prompt"));
    char *context = malloc(FLEET_CAP + 128), *answer = calloc(1, TEXT_CAP);
    bool ok = prompt && prompt[0] && context && answer;
    if (ok) {
        pthread_mutex_lock(&fleet_lock);
        int n = fleet_time ? snprintf(context, FLEET_CAP + 128, "Owner's fleet, observed %lld seconds ago:\n",
            (long long)(time(NULL) - fleet_time)) : 0;
        if (n <= 0 || !zapp_hosts_verdicts(fleet_snapshot, context + n, FLEET_CAP + 128 - (size_t)n))
            snprintf(context, FLEET_CAP + 128, "Fleet status not yet observed.");
        pthread_mutex_unlock(&fleet_lock);
        ok = (stream ? zapp_assistant_respond : zapp_assistant_chat)(&assistant, prompt,
                json_get(request, "history"), context, client, answer, TEXT_CAP) &&
            json_push_kv_str(response, "text", answer);
    }
    if (answer) { memory_cleanse(answer, TEXT_CAP); free(answer); }
    free(context);
    return ok;
}
static bool synthesize(const struct json_value *request, int client, struct json_value *response)
{
    const char *text = json_get_str(json_get(request, "text"));
    unsigned char *wav = NULL; size_t bytes = 0;
    bool ok = text && text[0] && strlen(text) <= 1000 &&
        zapp_assistant_speak(&assistant, text, client, &wav, &bytes) && bytes <= REPLY_WAV_CAP;
    char *hex = ok ? malloc(bytes * 2 + 1) : NULL;
    if (hex) {
        static const char digits[] = "0123456789abcdef";
        for (size_t i = 0; i < bytes; ++i) { hex[i * 2] = digits[wav[i] >> 4]; hex[i * 2 + 1] = digits[wav[i] & 15]; }
        hex[bytes * 2] = 0;
    }
    ok = hex && json_push_kv_str(response, "wav", hex);
    if (hex) { memory_cleanse(hex, bytes * 2 + 1); free(hex); }
    if (wav) { memory_cleanse(wav, bytes); free(wav); }
    return ok;
}
static bool fleet(const struct json_value *request, struct json_value *response)
{
    bool refresh = string_is(request, "scope", "refresh");
    if (!refresh && !string_is(request, "scope", "status")) return false;
    pthread_mutex_lock(&fleet_lock);
    bool observed = fleet_time != 0;
    pthread_mutex_unlock(&fleet_lock);
    if (refresh || !observed) (void)refresh_fleet();
    struct json_value snapshot = {0};
    pthread_mutex_lock(&fleet_lock);
    bool ok = fleet_time && json_read(&snapshot, fleet_snapshot, strlen(fleet_snapshot)) &&
        json_push_kv(response, "fleet", &snapshot);
    pthread_mutex_unlock(&fleet_lock);
    json_free(&snapshot);
    return ok;
}
static bool ops_exec(const struct zapp_fleet_host *host, const char *command, int timeout_ms,
                     char *out, size_t cap, void *unused)
{
    (void)unused;
    return zapp_fleet_run(host, command, timeout_ms, out, cap);
}
static struct zapp_ops host_ops = {.exec = ops_exec};
static pthread_mutex_t host_ops_lock = PTHREAD_MUTEX_INITIALIZER;
/* The phone's request for one host's recent errors or restart steps; the table in host_ops.c is
 * the only thing it can reach. A refusal is answered in the reply, not as a failed request. */
static bool host_op(const struct json_value *request, struct json_value *response)
{
    char *text = fleet_count ? malloc(OPS_CAP) : NULL;
    struct json_value reply = {0};
    pthread_mutex_lock(&host_ops_lock);
    bool ok = text && zapp_ops_handle(&host_ops, fleet_hosts, fleet_count,
        json_get_str(json_get(request, "scope")), (int64_t)time(NULL), text, OPS_CAP);
    pthread_mutex_unlock(&host_ops_lock);
    ok = ok && json_read(&reply, text, strlen(text)) && json_push_kv(response, "ops", &reply);
    json_free(&reply); free(text);
    return ok;
}
static const char *const ops[] = {"transcribe", "chat", "synthesize", "fleet", "respond", "hostops"};
static size_t find_op(const struct json_value *request)
{
    size_t op = 0;
    while (op < 6 && !string_is(request, "op", ops[op])) op++;
    return op;
}
static bool run_op(size_t op, const struct json_value *request, int client, struct json_value *response)
{
    if (op == 0) return transcribe(request, client, response);
    if (op == 1 || op == 4) return chat(request, client, response, op == 4);
    if (op == 2) return synthesize(request, client, response);
    if (op == 3) return fleet(request, response);
    if (op == 5) return host_op(request, response);
    return false;
}
static bool timed_op(size_t op, const struct json_value *request, int client, struct json_value *response)
{
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    bool ok = run_op(op, request, client, response);
    clock_gettime(CLOCK_MONOTONIC, &end);
    if (op < 6) fprintf(stderr, "%s %s in %lld ms\n", ops[op], ok ? "answered" : "failed",
        (long long)(end.tv_sec - start.tv_sec) * 1000 + (end.tv_nsec - start.tv_nsec) / 1000000);
    return ok;
}
static bool answer(int client, const char *prompt, char *out, size_t capacity, const char **error)
{
    struct json_value request = {0}, response = {0};
    *error = "The laptop host could not complete that request.";
    json_set_object(&response);
    bool ok = prompt && no_nul_escape(prompt) && json_read(&request, prompt, strlen(prompt)) &&
        request.type == JSON_OBJ && string_is(&request, "schema", "z23.voice/1") &&
        request.num_children == (json_get(&request, "history") ? 4u : 3u);
    if (ok) ok = timed_op(find_op(&request), &request, client, &response);
    if (ok) ok = json_write(&response, out, capacity) < capacity;
    if (!ok && capacity) out[0] = 0;
    json_cleanse_strings(&request); json_free(&request);
    json_cleanse_strings(&response); json_free(&response);
    return ok;
}
static void *pairing_loop(void *opaque)
{
    const struct options *o = opaque;
    bool offered = false;
    for (int tick = 0; !zapp_relay_stopping(); tick++) {
        if (!offered && tick % 10 == 0 &&
            (offered = zapp_host_offer_pairing(o->adb, o->serial, o->app, o->port, o->dir)))
            fputs("Pairing offered to the phone. Confirm it on the phone screen.\n", stderr);
        else if (offered && tick % 100 == 0) (void)zapp_host_route(o->adb, o->serial, o->port);
        usleep(200000);
    }
    return NULL;
}
static struct json_value tool_schema;
static bool run_tool(const char *name, const char *arguments, char *out, size_t cap)
{
    const struct zapp_fleet_host *host = zapp_fleet_tool_host(fleet_hosts, fleet_count, name, arguments);
    return host && zapp_fleet_blockers(host, 5000, out, cap);
}
static bool tool_wanted(const char *prompt, char *name, size_t name_cap, char *arguments, size_t arguments_cap)
{
    return zapp_fleet_tool_wanted(fleet_hosts, fleet_count, prompt, name, name_cap, arguments, arguments_cap);
}
static const struct zapp_assistant_tools fleet_tools = {.schema = &tool_schema, .guide = zapp_fleet_tool_guide,
                                                       .run = run_tool, .wanted = tool_wanted};
static const char usage[] =
    "Usage: z23-speech-bridge --dir DIR --llama-server PATH --models DIR [--port N]\n"
    "         [--speaker WAV] [--fleet label=ssh-destination,...]\n"
    "         [--adb PATH --serial SERIAL [--app PACKAGE]]\n";
static bool set_option(int c, struct options *o)
{
    switch (c) {
    case 'd': o->dir = optarg; return true;
    case 'l': o->llama = optarg; return true;
    case 'm': o->models = optarg; return true;
    case 's': o->speaker = optarg; return true;
    case 'f': o->fleet = optarg; return true;
    case 'a': o->adb = optarg; return true;
    case 'S': o->serial = optarg; return true;
    case 'A': o->app = optarg; return true;
    case 'p': {
        long v = strtol(optarg, NULL, 10);
        if (v < 1024 || v > 65530) return false;
        o->port = (uint16_t)v; return true;
    }
    default: return false;
    }
}
static bool options_valid(const struct options *o)
{
    return o->dir && o->llama && o->models && !o->adb == !o->serial &&
        strspn(o->app, "abcdefghijklmnopqrstuvwxyz0123456789._") == strlen(o->app) &&
        (!o->fleet || zapp_fleet_hosts_parse(o->fleet, fleet_hosts, 16, &fleet_count));
}
static bool parse(int argc, char **argv, struct options *o)
{
    static const struct option longs[] = {{"dir", 1, 0, 'd'}, {"llama-server", 1, 0, 'l'},
        {"models", 1, 0, 'm'}, {"port", 1, 0, 'p'}, {"speaker", 1, 0, 's'}, {"fleet", 1, 0, 'f'},
        {"adb", 1, 0, 'a'}, {"serial", 1, 0, 'S'}, {"app", 1, 0, 'A'}, {0, 0, 0, 0}};
    *o = (struct options){.port = 8770, .app = "org.z23.nativeapp"};
    for (int c; (c = getopt_long(argc, argv, "", longs, NULL)) != -1;)
        if (!set_option(c, o)) return false;
    return optind == argc && options_valid(o);
}
static char *load_speaker(const char *path)
{
    unsigned char *wav = NULL; size_t size = 0;
    char *b64 = path && zapp_host_read_file(path, 4194304, &wav, &size) ? zapp_assistant_base64(wav, size) : NULL;
    free(wav);
    return b64;
}
int main(int argc, char **argv)
{
    struct options o;
    if (!parse(argc, argv, &o)) { fputs(usage, stderr); return 2; }
    signal(SIGPIPE, SIG_IGN);
    struct zapp_host_servers servers;
    char *speaker = load_speaker(o.speaker);
    if (o.speaker && !speaker) { fputs("Could not read the speaker reference WAV.\n", stderr); return 1; }
    if (!zapp_host_start(o.llama, o.models, o.dir, o.port, &servers)) { free(speaker); return 1; }
    assistant = (struct zapp_assistant){.chat_port = servers.port[ZAPP_HOST_CHAT],
        .asr_port = servers.port[ZAPP_HOST_ASR], .tts_port = servers.port[ZAPP_HOST_TTS], .speaker_b64 = speaker};
    if (fleet_count && zapp_fleet_tool_schema(fleet_hosts, fleet_count, &tool_schema))
        assistant.tools = &fleet_tools;
    pthread_t thread;
    if (fleet_count && !pthread_create(&thread, NULL, fleet_loop, NULL)) pthread_detach(thread);
    if (o.adb && !pthread_create(&thread, NULL, pairing_loop, &o)) pthread_detach(thread);
    fprintf(stderr, "Z23 laptop host listening on 127.0.0.1:%u. Press Ctrl-C to stop.\n", o.port);
    int rc = zapp_relay_run_persistent(o.dir, o.port, answer, 1300000, 1950000);
    if (rc) fprintf(stderr, "The laptop host stopped: port %u is in use or %s is not a private directory.\n",
        o.port, o.dir);
    zapp_host_stop(&servers);
    json_free(&tool_schema);
    free(speaker);
    return rc;
}
