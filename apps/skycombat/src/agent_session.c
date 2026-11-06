#include "sky_combat/agent_session.h"
#include "json/json.h"
#include "util/png_writer.h"
#include "zbase64/zbase64.h"
#include <raylib.h>
#include <rlgl.h>
#include <external/stb_image_resize2.h>
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#define sky_dup _dup
#define sky_dup2 _dup2
#define sky_fdopen _fdopen
#define sky_fileno _fileno
#define sky_close _close
#define sky_read _read
#else
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>
#define sky_dup dup
#define sky_dup2 dup2
#define sky_fdopen fdopen
#define sky_fileno fileno
#define sky_close close
#define sky_read read
#endif

enum sky_agent_op { SKY_OBSERVE, SKY_STEP, SKY_CLOSE };
struct sky_agent_request {
    uint32_t id;
    enum sky_agent_op op;
    unsigned frames;
    bool capture;
    input_state_fast_t input;
};

#if !defined(_WIN32)
/* Capture every original slot before opening anything: open/dup must never
 * mistake a newly occupied low slot for an inherited standard descriptor. */
static bool sky_resident_stdio_prepare(unsigned *closed_mask)
{
    *closed_mask = 0;
    for (int fd = 0; fd < 3; fd++) {
        if (fcntl(fd, F_GETFD) >= 0) continue;
        if (errno != EBADF) return false;
        *closed_mask |= 1u << fd;
    }
    for (int fd = 0; fd < 3; fd++) {
        if (!(*closed_mask & (1u << fd))) continue;
        int sink = open("/dev/null", (fd == 0 ? O_RDONLY : O_WRONLY) | O_CLOEXEC);
        if (sink < 0) return false;
        if (sink != fd) {
            bool copied = dup2(sink, fd) >= 0;
            bool closed = close(sink) == 0;
            if (!copied || !closed) return false;
        }
        clearerr(fd == 0 ? stdin : fd == 1 ? stdout : stderr);
    }
    return true;
}

static bool sky_resident_stdio_restore(struct sky_agent_session *session)
{
    unsigned mask = session->resident_closed_stdio;
    session->resident_closed_stdio = 0;
    bool ok = true;
    for (int fd = 0; fd < 3; fd++) {
        if (!(mask & (1u << fd))) continue;
        if (close(fd) != 0 && errno != EBADF) ok = false;
        clearerr(fd == 0 ? stdin : fd == 1 ? stdout : stderr);
    }
    return ok;
}
#endif

bool sky_agent_open(struct sky_agent_session *session)
{
    memset(session, 0, sizeof(*session));
#if !defined(_WIN32)
    session->previous_sigpipe = SIG_ERR;
#endif
    if (fflush(stdout) != 0) return false;
    int descriptor = sky_dup(sky_fileno(stdout));
    if (descriptor < 0) return false;
    session->reply = sky_fdopen(descriptor, "wb");
    if (!session->reply) { sky_close(descriptor); return false; }
#if defined(_WIN32)
    session->previous_stdin_mode = _setmode(sky_fileno(stdin), _O_BINARY);
    if (session->previous_stdin_mode < 0) {
        fclose(session->reply);
        session->reply = NULL;
        return false;
    }
#endif
    if (sky_dup2(sky_fileno(stderr), sky_fileno(stdout)) < 0) {
        (void)sky_agent_close(session);
        return false;
    }
#if !defined(_WIN32)
    session->previous_sigpipe = signal(SIGPIPE, SIG_IGN);
    if (session->previous_sigpipe == SIG_ERR) {
        (void)sky_agent_close(session);
        return false;
    }
#endif
    return true;
}

bool sky_agent_close(struct sky_agent_session *session)
{
    bool ok = sky_game_raise_close();
    if (session->resident.active && !sky_resident_close(&session->resident)) ok = false;
    if (!session->reply) {
#if !defined(_WIN32)
        if (!sky_resident_stdio_restore(session)) ok = false;
#endif
        return ok;
    }
    if (fflush(stdout) != 0) ok = false;
    if (sky_dup2(sky_fileno(session->reply), sky_fileno(stdout)) < 0) ok = false;
    if (fclose(session->reply) != 0) ok = false;
    session->reply = NULL;
#if defined(_WIN32)
    if (_setmode(sky_fileno(stdin), session->previous_stdin_mode) < 0) ok = false;
#else
    if (session->previous_sigpipe != SIG_ERR)
        if (signal(SIGPIPE, session->previous_sigpipe) == SIG_ERR) ok = false;
#endif
    if (!ok) fputs("Sky Combat agent: transport cleanup failed\n", stderr);
#if !defined(_WIN32)
    if (!sky_resident_stdio_restore(session)) ok = false;
#endif
    return ok;
}

bool sky_agent_open_resident(struct sky_agent_session *session, const char *nonce)
{
#if defined(_WIN32)
    memset(session, 0, sizeof(*session));
    (void)nonce;
    return false;
#else
    /* Reuse checked stdout save/redirect and signal cleanup. The saved stream
     * is only for restoration here; resident replies always use fd 3. */
    unsigned closed_mask;
    bool prepared = sky_resident_stdio_prepare(&closed_mask);
    bool opened = prepared && sky_agent_open(session);
    if (!opened) {
        /* sky_agent_open initializes session itself; prepare failure does not. */
        if (!prepared) memset(session, 0, sizeof(*session));
        session->resident_closed_stdio = closed_mask;
        (void)sky_agent_close(session);
        return false;
    }
    session->resident_closed_stdio = closed_mask;
    if (sky_resident_open(&session->resident, nonce)) return true;
    (void)sky_agent_close(session);
    return false;
#endif
}

/* Only pipes and regular redirected input are the agent transport. Waiting
 * never advances the simulation; window events remain responsive. */
static int sky_agent_input_ready(void)
{
#if defined(_WIN32)
    HANDLE input = (HANDLE)_get_osfhandle(sky_fileno(stdin));
    DWORD available = 0, type = GetFileType(input);
    if (type == FILE_TYPE_DISK) return 1;
    if (type != FILE_TYPE_PIPE) return -1;
    if (!PeekNamedPipe(input, NULL, 0, NULL, &available, NULL))
        return GetLastError() == ERROR_BROKEN_PIPE ? 1 : -1;
    if (available) return 1;
    Sleep(16);
    return 0;
#else
    struct pollfd descriptor = { .fd = sky_fileno(stdin), .events = POLLIN };
    int ready = poll(&descriptor, 1, 16);
    if (ready < 0 && errno == EINTR) return 0;
    return ready;
#endif
}

static int sky_agent_line(char line[SKY_AGENT_LINE_MAX + 1], size_t *length)
{
    *length = 0;
    for (;;) {
        sky_game_event_pump();
        if (WindowShouldClose()) return 0;
        int ready = sky_agent_input_ready();
        if (ready < 0) return -1;
        if (!ready) continue;
        unsigned char byte;
        int got = (int)sky_read(sky_fileno(stdin), &byte, 1);
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) return -1;
        if (!got) return *length ? -2 : 0;
        if (byte == '\n') {
            line[*length] = '\0';
            return 1;
        }
        if (*length == SKY_AGENT_LINE_MAX) return -3;
        line[(*length)++] = (char)byte;
    }
}

static bool sky_agent_members(const struct json_value *object, const char *const *keys,
                               size_t count)
{
    if (!object || object->type != JSON_OBJ) return false;
    for (size_t i = 0; i < object->num_children; i++) {
        bool known = false;
        for (size_t k = 0; k < count; k++)
            if (strcmp(object->keys[i], keys[k]) == 0) known = true;
        if (!known) return false;
        for (size_t j = 0; j < i; j++)
            if (strcmp(object->keys[i], object->keys[j]) == 0) return false;
    }
    return true;
}

static bool sky_agent_axis(const struct json_value *input, const char *key, float *out)
{
    const struct json_value *value = json_get(input, key);
    if (!value) return true;
    if (value->type != JSON_REAL && value->type != JSON_INT) return false;
    double number = value->type == JSON_INT ? (double)json_get_int(value) : json_get_real(value);
    if (!isfinite(number) || number < -1.0 || number > 1.0) return false;
    *out = (float)number;
    return true;
}

static bool sky_agent_bool(const struct json_value *object, const char *key, bool *out)
{
    const struct json_value *value = json_get(object, key);
    if (!value) return true;
    if (value->type != JSON_BOOL) return false;
    *out = json_get_bool(value);
    return true;
}

static bool sky_agent_controls(const struct json_value *object, input_state_fast_t *input)
{
    static const char *const keys[] = { "move_x", "move_y", "camera_x",
        "fire_guns", "speed_boost", "throttle" };
    return sky_agent_members(object, keys, sizeof(keys) / sizeof(keys[0])) &&
        sky_agent_axis(object, "move_x", &input->move_x) &&
        sky_agent_axis(object, "move_y", &input->move_y) &&
        sky_agent_axis(object, "camera_x", &input->camera_x) &&
        sky_agent_bool(object, "fire_guns", &input->fire_guns) &&
        sky_agent_bool(object, "speed_boost", &input->speed_boost) &&
        sky_agent_bool(object, "throttle", &input->brake);
}

static bool sky_agent_identity(const struct json_value *doc, uint32_t *request_id)
{
    const struct json_value *version = json_get(doc, "v"), *id = json_get(doc, "id");
    if (!version || version->type != JSON_INT || json_get_int(version) != 1 ||
        !id || id->type != JSON_INT || json_get_int(id) < 0 || json_get_int(id) > UINT32_MAX)
        return false;
    *request_id = (uint32_t)json_get_int(id);
    return true;
}

static bool sky_agent_decode(const struct json_value *doc, struct sky_agent_request *request)
{
    static const char *const keys[] = { "v", "id", "op", "frames", "input", "capture" };
    if (!sky_agent_members(doc, keys, sizeof(keys) / sizeof(keys[0])) ||
        !sky_agent_identity(doc, &request->id)) return false;
    const char *op = json_get_str(json_get(doc, "op"));
    if (!op || !sky_agent_bool(doc, "capture", &request->capture)) return false;
    if (strcmp(op, "step") == 0) {
        const struct json_value *frames = json_get(doc, "frames");
        if (!frames || frames->type != JSON_INT || json_get_int(frames) < 1 ||
            json_get_int(frames) > SKY_AGENT_STEP_MAX) return false;
        request->op = SKY_STEP;
        request->frames = (unsigned)json_get_int(frames);
        return sky_agent_controls(json_get(doc, "input"), &request->input);
    }
    if (json_get(doc, "frames") || json_get(doc, "input")) return false;
    if (strcmp(op, "observe") == 0) { request->op = SKY_OBSERVE; return true; }
    if (strcmp(op, "close") || json_get(doc, "capture")) return false;
    request->op = SKY_CLOSE;
    return true;
}

static bool sky_agent_parse(const char *line, size_t length, struct sky_agent_request *request)
{
    memset(request, 0, sizeof(*request));
    /* v1 names and operations are ASCII. Reject hidden NUL before C-string
     * comparisons, including escaped NUL in keys and operation names. */
    for (size_t i = 0; i < length; i++)
        if (!line[i] || (unsigned char)line[i] >= 128) return false;
    if (strstr(line, "\\u0000")) return false;
    struct json_value doc;
    json_init(&doc);
    bool ok = json_read(&doc, line, length) && sky_agent_decode(&doc, request);
    json_free(&doc);
    return ok;
}

static bool sky_agent_resize(Image *image)
{
    int width = image->width, height = image->height;
    if (width <= 640 && height <= 360) return true;
    if ((int64_t)width * 360 >= (int64_t)height * 640) {
        height = (int)((int64_t)height * 640 / width);
        width = 640;
    } else {
        width = (int)((int64_t)width * 360 / height);
        height = 360;
    }
    if (width < 1) width = 1;
    if (height < 1) height = 1;
    /* ImageResize discards this return value. Use its same RGBA resampler,
     * exported by raylib, but retain the old image until allocation AND resize
     * succeed. NULL output requests checked allocation by the existing API. */
    unsigned char *pixels = stbir_resize_uint8_linear(image->data, image->width,
        image->height, 0, NULL, width, height, 0, STBIR_RGBA);
    if (!pixels) return false;
    UnloadImage(*image);
    *image = (Image){.data = pixels, .width = width, .height = height,
                     .mipmaps = 1, .format = PIXELFORMAT_UNCOMPRESSED_R8G8B8A8};
    return true;
}

static void sky_agent_encode(const Image *image, struct sky_agent_capture *capture)
{
    size_t needed = 0;
    capture->error = "CAPTURE_ENCODE";
    if (!png_encode_rgba(image->data, (uint32_t)image->width, (uint32_t)image->height,
                         NULL, 0, &needed) || needed > SKY_AGENT_PNG_MAX) return;
    capture->png = malloc(needed);
    capture->error = "CAPTURE_ALLOC";
    if (!capture->png) return;
    capture->error = "CAPTURE_ENCODE";
    if (!png_encode_rgba(image->data, (uint32_t)image->width, (uint32_t)image->height,
                         capture->png, needed, &capture->size)) return;
    capture->width = image->width;
    capture->height = image->height;
    capture->error = NULL;
}

void sky_agent_capture_frame(struct sky_agent_capture *capture)
{
    int width = GetRenderWidth(), height = GetRenderHeight();
    capture->error = "CAPTURE_SIZE";
    if (width < 1 || height < 1 || (uint64_t)width * (uint64_t)height > 1920u * 1080u)
        return;
    rlDrawRenderBatchActive();
    Image image = LoadImageFromScreen();
    capture->error = "CAPTURE_READBACK";
    if (!image.data) return;
    bool shape = image.width == width && image.height == height &&
        image.format == PIXELFORMAT_UNCOMPRESSED_R8G8B8A8;
    capture->error = "CAPTURE_RESIZE";
    if (shape && sky_agent_resize(&image)) sky_agent_encode(&image, capture);
    UnloadImage(image);
    if (capture->error) { free(capture->png); capture->png = NULL; capture->size = 0; }
}

static bool sky_agent_base64(FILE *output, const unsigned char *bytes, size_t length)
{
    /* Full chunks are divisible by three; only the final one may be padded. */
    for (size_t offset = 0; offset < length;) {
        size_t count = length - offset;
        if (count > 3072) count = 3072;
        char encoded[4097];
        size_t encoded_size = zbase64_encode_len(count);
        if (!zbase64_encode(bytes + offset, count, encoded, sizeof(encoded)) ||
            fwrite(encoded, 1, encoded_size, output) != encoded_size) return false;
        offset += count;
    }
    return true;
}

static bool sky_agent_player(FILE *out, const struct sky_agent_observation *state)
{
    if (!state->player_present) return fputs("null", out) != EOF;
    return fprintf(out, "{\"x\":%.9g,\"y\":%.9g,\"z\":%.9g,\"yaw\":%.9g,\"speed\":%.9g,\"health\":%.9g}",
            (double)state->x, (double)state->y, (double)state->z,
            (double)state->yaw, (double)state->speed, (double)state->health) >= 0;
}

static bool sky_agent_image(FILE *out, const struct sky_agent_capture *capture)
{
    if (!capture || !capture->png) return true;
    if (capture->size > SKY_AGENT_PNG_MAX ||
        ((capture->size + 2u) / 3u) * 4u + 1024u > SKY_AGENT_REPLY_MAX) return false;
    return fprintf(out, ",\"png\":{\"width\":%d,\"height\":%d,\"bytes\":%zu,\"base64\":\"",
        capture->width, capture->height, capture->size) >= 0 &&
        sky_agent_base64(out, capture->png, capture->size) && fputs("\"}", out) != EOF;
}

static bool sky_agent_reply_body(FILE *out, struct sky_agent_session *session, uint32_t id,
    const struct sky_agent_observation *state, const struct sky_agent_capture *capture,
    const char *error)
{
    if (fprintf(out, "{\"v\":1,\"id\":%u,\"ok\":%s,\"frame\":%u,\"time\":%.17g,\"player\":",
        id, error ? "false" : "true", state->frame, (double)state->time) < 0 ||
        !sky_agent_player(out, state)) return false;
    if (session->has_accepted_id) {
        if (fprintf(out, ",\"accepted_id\":%u", session->accepted_id) < 0) return false;
    } else if (fputs(",\"accepted_id\":null", out) == EOF) return false;
    if (error && fprintf(out, ",\"error\":\"%s\"", error) < 0) return false;
    if (!error && !sky_agent_image(out, capture)) return false;
    return fputs("}\n", out) != EOF && fflush(out) == 0 && !ferror(out);
}

static bool sky_agent_reply(struct sky_agent_session *session, uint32_t id,
    const struct sky_agent_observation *state, const struct sky_agent_capture *capture,
    const char *error)
{
    if (!session->resident.active)
        return sky_agent_reply_body(session->reply, session, id, state, capture, error);
#if defined(_WIN32)
    return false;
#else
    char *payload = NULL;
    size_t length = 0;
    FILE *out = open_memstream(&payload, &length);
    if (!out) return false;
    bool ok = sky_agent_reply_body(out, session, id, state, capture, error);
    if (fclose(out) != 0) ok = false;
    if (ok) ok = sky_resident_write(&session->resident, payload, length);
    free(payload);
    return ok;
#endif
}

static const char *sky_agent_execute(struct sky_agent_request *request, bool *boost_held,
    void *context, sky_agent_frame_fn frame, struct sky_agent_observation *state,
    struct sky_agent_capture *capture)
{
    if (request->op == SKY_CLOSE) return NULL;
    if (request->op == SKY_OBSERVE) {
        frame(context, NULL, state, request->capture ? capture : NULL);
        return capture->error;
    }
    if (request->frames > SKY_AGENT_FRAME_MAX - state->frame) return "FRAME_BUDGET";
    bool boost = request->input.speed_boost;
    request->input.speed_boost = boost && !*boost_held;
    *boost_held = boost;
    for (unsigned i = 0; i < request->frames; i++) {
        sky_game_raise_apply();
        if (WindowShouldClose()) return "WINDOW_CLOSED";
        frame(context, &request->input, state,
            request->capture && i + 1 == request->frames ? capture : NULL);
        request->input.speed_boost = false;
    }
    return capture->error;
}

int sky_agent_run(struct sky_agent_session *session, void *context, sky_agent_frame_fn frame)
{
    struct sky_agent_observation state = {0};
    bool boost_held = false;
    frame(context, NULL, &state, NULL);
    for (unsigned count = 0; count < SKY_AGENT_REQUEST_MAX; count++) {
        char line[SKY_AGENT_LINE_MAX + 1];
        size_t length;
        int status = session->resident.active
            ? sky_resident_read(&session->resident, line, &length)
            : sky_agent_line(line, &length);
        if (!status) return 0;
        struct sky_agent_request request = {0};
        struct sky_agent_capture capture = {0};
        const char *error = NULL;
        if (status == -1) error = "INPUT_IO";
        else if (status == -2) error = "INCOMPLETE_REQUEST";
        else if (status == -3) error = "REQUEST_TOO_LARGE";
        else if (status == -4) error = "INVALID_FRAME";
        else if (!sky_agent_parse(line, length, &request)) error = "INVALID_REQUEST";
        else if (session->has_accepted_id && request.id <= session->accepted_id)
            error = "STALE_REQUEST_ID";
        else {
            /* Consume before execution, including a subsequently failed capture.
             * Retrying an uncertain step must never execute it twice. */
            session->has_accepted_id = true;
            session->accepted_id = request.id;
            error = sky_agent_execute(&request, &boost_held, context, frame, &state, &capture);
        }
        bool wrote = sky_agent_reply(session, request.id, &state, &capture, error);
        free(capture.png);
        if (!wrote) { fputs("Sky Combat agent: reply IO failed\n", stderr); return 1; }
        if (status < 0) return 1;
        if (!error && request.op == SKY_CLOSE) return 0;
    }
    (void)sky_agent_reply(session, 0, &state, NULL, "REQUEST_BUDGET");
    return 1;
}
