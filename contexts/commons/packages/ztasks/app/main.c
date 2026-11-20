/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: task-list program; resident mode uses Z23's existing fd3 wire. */
#include "ztasks/ztasks.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <signal.h>
#include <unistd.h>
#include <time.h>

static struct timespec task_entry_time;

/* Public resident_launch v1 wire, not a second launcher. Package sources
 * deliberately have no dependency on node/platform implementation headers.
 * The host regression compares offsets and size against resident_launch.h. */
struct task_frame { char magic[16]; char nonce[65]; uint32_t payload_len; };
static_assert(sizeof(struct task_frame) == 88, "resident v1 frame ABI");

static bool task_io(void *buffer, size_t size, bool sending)
{
    unsigned char *bytes = buffer;
    for (size_t done = 0; done < size;) {
        ssize_t n = sending ? write(3, bytes + done, size - done)
                            : read(3, bytes + done, size - done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { fprintf(stderr, "ztasks: resident IPC incomplete\n"); return false; }
        done += (size_t)n;
    }
    return true;
}

static bool task_reply(const char *nonce, const char *text)
{
    struct task_frame frame = {0};
    memcpy(frame.magic, "z23-res-run-v1", sizeof("z23-res-run-v1"));
    memcpy(frame.nonce, nonce, sizeof(frame.nonce));
    frame.payload_len = (uint32_t)strlen(text);
    return task_io(&frame, sizeof(frame), true) &&
           task_io((void *)text, frame.payload_len, true);
}

static bool task_render(const struct ta_state *state, char out[TA_PAYLOAD])
{
    size_t used = 0;
    for (uint32_t i = 0; i < state->count; ++i) {
        int n = snprintf(out + used, TA_PAYLOAD - used, "%llu [%s] %s\n",
            (unsigned long long)state->tasks[i].id,
            state->tasks[i].done ? "DONE" : "OPEN", state->tasks[i].title);
        if (n < 0 || (size_t)n >= TA_PAYLOAD - used) {
            fprintf(stderr, "ztasks: rendered task list exceeds bound\n"); return false;
        }
        used += (size_t)n;
    }
    if (!used) (void)snprintf(out, TA_PAYLOAD, "No tasks yet.\n");
    return true;
}

/* Preview authority is supplied by the host: these are isolated files, never
 * the live database. Decode and re-encode both current contents and undo. */
static bool task_preview_state(const char *input, const char *output,
                               struct ta_state *state)
{
    unsigned char bytes[TA_PAYLOAD + 1u], canonical[TA_PAYLOAD];
    FILE *file = fopen(input, "rb");
    if (!file) { fprintf(stderr, "ztasks: preview input unavailable\n"); return false; }
    size_t size = fread(bytes, 1, sizeof(bytes), file);
    bool read_ok = !ferror(file) && size <= TA_PAYLOAD;
    if (fclose(file) != 0) read_ok = false;
    uint32_t length = 0;
    if (!read_ok || !ta_state_decode(bytes, (uint32_t)size, state) ||
        !ta_state_encode(state, canonical, &length)) {
        fprintf(stderr, "ztasks: preview data is incompatible\n"); return false;
    }
    file = fopen(output, "wb");
    if (!file) { fprintf(stderr, "ztasks: preview output unavailable\n"); return false; }
    bool written = fwrite(canonical, 1, length, file) == length;
    if (fclose(file) != 0) written = false;
    if (!written) fprintf(stderr, "ztasks: preview output incomplete\n");
    return written;
}

static int task_preview(char **argv)
{
    if (strlen(argv[2]) != 64 || strspn(argv[2], "0123456789abcdef") != 64) {
        fprintf(stderr, "ztasks: preview nonce invalid\n"); return 2;
    }
    struct ta_state state, undo;
    char view[TA_PAYLOAD];
    if (!task_preview_state(argv[3], argv[5], &state) ||
        !task_preview_state(argv[4], argv[6], &undo) || !task_render(&state, view)) return 3;
    FILE *file = fopen(argv[7], "wb");
    if (!file) { fprintf(stderr, "ztasks: preview view unavailable\n"); return 3; }
    size_t size = strlen(view);
    bool written = fwrite(view, 1, size, file) == size;
    if (fclose(file) != 0) written = false;
    if (!written) { fprintf(stderr, "ztasks: preview view incomplete\n"); return 3; }
    printf("READY %s\n", argv[2]);
    return 0;
}

static bool task_apply(struct ta_state *state, const char *input, const char *nonce)
{
    if (strncmp(input, "add ", 4) == 0 && ta_title_valid(input + 4) && state->count < TA_MAX_TASKS) {
        struct ta_task *task = &state->tasks[state->count];
        task->id = (uint64_t)state->count + 1u;
        (void)snprintf(task->title, sizeof(task->title), "%.*s",
                       (int)sizeof(task->title) - 1, input + 4);
        state->count++;
        state->revision++;
        state->last_write++;
    } else if (strcmp(input, "list") != 0) {
        fprintf(stderr, "ztasks: use add TITLE or list\n"); return false;
    }
    unsigned char canonical[TA_PAYLOAD];
    char view[TA_PAYLOAD];
    uint32_t length = 0;
    struct ta_state checked;
    if (!ta_state_encode(state, canonical, &length) ||
        !ta_state_decode(canonical, length, &checked) ||
        !task_render(&checked, view) || !task_reply(nonce, view)) {
        fprintf(stderr, "ztasks: state or rendered result refused\n"); return false;
    }
    return true;
}

/* Negative means one request completed; otherwise return the process code. */
static int task_request(struct ta_state *state, const char *nonce)
{
    struct task_frame frame = {0};
    /* STOP is the seam's 81-byte nonce-bound command. All other input
     * is a normal 88-byte resident frame carrying a bounded text command. */
    if (!task_io(&frame, 81, false)) return 3;
    if (memcmp(frame.nonce, nonce, sizeof(frame.nonce)) != 0) {
        fprintf(stderr, "ztasks: stale input nonce\n"); return 4;
    }
    if (memcmp(frame.magic, "z23-res-stop-v1", sizeof("z23-res-stop-v1")) == 0)
        return 0;
    if (memcmp(frame.magic, "z23-res-run-v1", sizeof("z23-res-run-v1")) != 0 ||
        !task_io((unsigned char *)&frame + 81, sizeof(frame) - 81, false) ||
        frame.payload_len > TA_PAYLOAD) {
        fprintf(stderr, "ztasks: invalid resident input frame\n"); return 4;
    }
    char input[TA_TITLE + 5u] = {0};
    if (frame.payload_len >= sizeof(input) ||
        !task_io(input, frame.payload_len, false) ||
        memchr(input, 0, frame.payload_len) != NULL) {
        fprintf(stderr, "ztasks: bounded text command required\n"); return 5;
    }
    if (!task_apply(state, input, nonce)) return 5;
    return -1;
}

static int task_resident(const char *nonce)
{
    if (strlen(nonce) != 64 || strspn(nonce, "0123456789abcdef") != 64) {
        fprintf(stderr, "ztasks: exact resident nonce required\n"); return 2;
    }
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        fprintf(stderr, "ztasks: SIGPIPE setup failed\n"); return 2;
    }
    (void)alarm(30);
    const char *startup = getenv("Z23_RESIDENT_STARTUP_V2");
    if (startup && strcmp(startup, "1") == 0) {
        char entry[64];
        uint64_t ns = (uint64_t)task_entry_time.tv_sec * UINT64_C(1000000000) +
                      (uint64_t)task_entry_time.tv_nsec;
        (void)snprintf(entry, sizeof(entry), "ENTRY %llu", (unsigned long long)ns);
        if (!task_reply(nonce, entry)) return 3;
    }
    if (!task_reply(nonce, "READY")) return 3;
    struct ta_state state = {0};
    for (unsigned request = 0; request < 64; ++request) {
        int result = task_request(&state, nonce);
        if (result >= 0) return result;
    }
    fprintf(stderr, "ztasks: request budget exhausted\n");
    return 6;
}
#endif

int main(int argc, char **argv)
{
#if !defined(_WIN32)
    if (clock_gettime(CLOCK_MONOTONIC, &task_entry_time) != 0) {
        fprintf(stderr, "ztasks: startup clock failed\n"); return 2;
    }
    if (argc == 3 && strcmp(argv[1], "--resident") == 0)
        return task_resident(argv[2]);
    if (argc == 8 && strcmp(argv[1], "--app-preview") == 0)
        return task_preview(argv);
#else
    (void)argc; (void)argv;
#endif
    fprintf(stderr, "ztasks: run the exact installed version through app invoke package\n");
    return 2;
}
