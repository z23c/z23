/* Real-display agent acceptance fixture. Run under z23_bounded_run and Xvfb.
 * Linux-only private child pipes; the outer runner bounds the complete tree. */
#define _POSIX_C_SOURCE 200809L
#include "json/json.h"
#include "zbase64/zbase64.h"
#include "zutf8/zutf8.h"
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* Like test_test_png_writer.c, reuse the maintained checksum primitives.
 * Raster decoding below follows that test's pngw_inflate_stored, not the
 * encoder's layout generation. This fixture accepts the producer's RGBA8,
 * unfiltered, stored-DEFLATE profile, not every possible PNG encoding. */
#include "../../platform/modules/util/src/png_writer.c"

#define RESPONSE_LIMIT (2u * 1024u * 1024u)
#define PNG_LIMIT (1024u * 1024u)

struct client {
    pid_t child;
    FILE *reply;
    int request;
    int directory;
    char *line;
};
struct state {
    double x, y, z, yaw, speed, health, time;
};

static bool unique_document(const struct json_value *value)
{
    if (value->num_children > 32) return false;
    for (size_t i = 0; i < value->num_children; ++i) {
        if (value->type == JSON_OBJ) {
            for (size_t j = 0; j < i; ++j)
                if (strcmp(value->keys[i], value->keys[j]) == 0) return false;
        }
        if (!unique_document(&value->children[i])) return false;
    }
    return true;
}

static const struct json_value *member(const struct json_value *object,
                                      const char *key)
{
    const struct json_value *found = NULL;
    if (!object || object->type != JSON_OBJ) return NULL;
    for (size_t i = 0; i < object->num_children; ++i) {
        if (strcmp(object->keys[i], key) != 0) continue;
        if (found) return NULL;
        found = &object->children[i];
    }
    return found;
}

static bool integer(const struct json_value *object, const char *key, int64_t value)
{
    const struct json_value *field = member(object, key);
    return field && field->type == JSON_INT && field->val.i == value;
}

static bool number(const struct json_value *object, const char *key, double *out)
{
    const struct json_value *field = member(object, key);
    if (!field || (field->type != JSON_INT && field->type != JSON_REAL)) return false;
    *out = field->type == JSON_INT ? (double)field->val.i : field->val.d;
    return isfinite(*out);
}

static bool write_bytes(int descriptor, const void *data, size_t size)
{
    const unsigned char *bytes = data;
    while (size) {
        ssize_t written = write(descriptor, bytes, size);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return false;
        bytes += (size_t)written;
        size -= (size_t)written;
    }
    return true;
}

static bool save_bytes(struct client *client, const char *name,
                       const void *bytes, size_t size)
{
    int descriptor = openat(client->directory, name,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (descriptor < 0) return false;
    bool ok = write_bytes(descriptor, bytes, size);
    if (close(descriptor) != 0) ok = false;
    return ok;
}

static bool read_reply(struct client *client, struct json_value *reply,
                       const char *name)
{
    size_t length = 0;
    int byte;
    while ((byte = fgetc(client->reply)) != EOF && byte != '\n') {
        if (length == RESPONSE_LIMIT || byte == 0) return false;
        client->line[length++] = (char)byte;
    }
    if (byte != '\n' || ferror(client->reply)) return false;
    client->line[length] = '\n';
    if (!save_bytes(client, name, client->line, length + 1)) return false;
    return zutf8_validate_n(client->line, length) &&
        json_read(reply, client->line, length) && reply->type == JSON_OBJ &&
        unique_document(reply);
}

static uint32_t big_endian(const unsigned char *bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | bytes[3];
}

static bool decode_stored(const unsigned char *input, size_t size,
                          unsigned char *output, size_t expected)
{
    if (size < 6 || input[0] != 0x78 || input[1] != 0x01) return false;
    size_t position = 2, used = 0;
    bool final = false;
    while (!final) {
        if (size - 4 - position < 5) return false;
        unsigned header = input[position++];
        if (header > 1) return false;
        final = header != 0;
        unsigned length = input[position] | ((unsigned)input[position + 1] << 8);
        unsigned inverse = input[position + 2] | ((unsigned)input[position + 3] << 8);
        position += 4;
        if ((length ^ inverse) != 65535 || length > size - 4 - position ||
            length > expected - used) return false;
        memcpy(output + used, input + position, length);
        used += length;
        position += length;
    }
    return used == expected && position == size - 4 &&
        big_endian(input + position) == adler32(output, used);
}

static bool png_chunk(const unsigned char *bytes, size_t size, size_t *position,
                      const char *type, const unsigned char **data, size_t *length)
{
    if (*position > size || size - *position < 12) return false;
    const unsigned char *chunk = bytes + *position;
    *length = big_endian(chunk);
    if (*length > size - *position - 12 || memcmp(chunk + 4, type, 4) != 0 ||
        big_endian(chunk + 8 + *length) != crc32_update(0, chunk + 4, *length + 4))
        return false;
    *data = chunk + 8;
    *position += *length + 12;
    return true;
}

static bool png_header(const unsigned char *bytes, size_t size,
                       uint32_t width, uint32_t height)
{
    static const unsigned char signature[] = {137,80,78,71,13,10,26,10};
    if (size < 33 || size > PNG_LIMIT || width == 0 || width > 640 ||
        height == 0 || height > 360 || memcmp(bytes, signature, 8) != 0) return false;
    size_t position = 8, length = 0;
    const unsigned char *data = NULL;
    return png_chunk(bytes, size, &position, "IHDR", &data, &length) && length == 13 &&
        big_endian(data) == width && big_endian(data + 4) == height &&
        memcmp(data + 8, "\x08\x06\x00\x00\x00", 5) == 0;
}

static bool complete_png(const unsigned char *bytes, size_t size,
                         uint32_t width, uint32_t height)
{
    if (!png_header(bytes, size, width, height)) return false;
    size_t position = 33, length = 0;
    const unsigned char *data = NULL;
    if (!png_chunk(bytes, size, &position, "IDAT", &data, &length)) return false;
    size_t stride = (size_t)width * 4 + 1, raster_size = stride * height;
    unsigned char *raster = malloc(raster_size);
    if (!raster) return false;
    bool ok = decode_stored(data, length, raster, raster_size);
    for (size_t row = 0; ok && row < height; ++row)
        ok = raster[row * stride] == 0;
    free(raster);
    return ok && png_chunk(bytes, size, &position, "IEND", &data, &length) &&
        length == 0 && position == size;
}

static bool save_png(struct client *client, const struct json_value *reply,
                     const char *name)
{
    const struct json_value *png = member(reply, "png");
    const struct json_value *encoded = member(png, "base64");
    const struct json_value *count = member(png, "bytes");
    if (!encoded || encoded->type != JSON_STR || !count || count->type != JSON_INT ||
        count->val.i < 33 || count->val.i > PNG_LIMIT) return false;
    size_t capacity = (size_t)count->val.i;
    unsigned char *bytes = malloc(capacity);
    if (!bytes) return false;
    size_t decoded = 0;
    bool ok = zbase64_decode(encoded->val.s, strlen(encoded->val.s), bytes,
                            capacity, &decoded) && decoded == capacity;
    if (ok) {
        uint32_t width = big_endian(bytes + 16), height = big_endian(bytes + 20);
        ok = complete_png(bytes, decoded, width, height) &&
             integer(png, "width", width) && integer(png, "height", height);
    }
    if (ok) ok = save_bytes(client, name, bytes, decoded);
    free(bytes);
    return ok;
}

static bool get_state(const struct json_value *reply, struct state *state)
{
    const struct json_value *player = member(reply, "player");
    return number(player, "x", &state->x) && number(player, "y", &state->y) &&
        number(player, "z", &state->z) && number(player, "yaw", &state->yaw) &&
        number(player, "speed", &state->speed) && number(player, "health", &state->health) &&
        number(reply, "time", &state->time);
}

static bool reply_status(const struct json_value *reply, unsigned id,
                         unsigned accepted, unsigned frame, const char *error)
{
    const struct json_value *success = member(reply, "ok");
    return integer(reply, "v", 1) && integer(reply, "id", id) &&
        integer(reply, "accepted_id", accepted) && integer(reply, "frame", frame) &&
        success && success->type == JSON_BOOL && success->val.b == (error == NULL);
}

static bool reply_error(const struct json_value *reply, const char *error)
{
    const struct json_value *reason = member(reply, "error");
    if (!error) return reason == NULL;
    return reason && reason->type == JSON_STR &&
        strcmp(reason->val.s, error) == 0 && !member(reply, "png");
}

static bool exchange(struct client *client, const char *request, unsigned id,
                     unsigned accepted, unsigned frame, const char *error,
                     const char *stem, bool capture, struct state *state)
{
    size_t length = strlen(request);
    if (length > 4096 || !write_bytes(client->request, request, length)) return false;
    char filename[80];
    int count = snprintf(filename, sizeof filename, "%s.json", stem);
    if (count < 0 || (size_t)count >= sizeof filename) return false;
    struct json_value reply = {0};
    bool ok = read_reply(client, &reply, filename);
    ok = ok && reply_status(&reply, id, accepted, frame, error) &&
        get_state(&reply, state) && reply_error(&reply, error);
    if (ok && capture) {
        count = snprintf(filename, sizeof filename, "%s.png", stem);
        ok = count > 0 && (size_t)count < sizeof filename && save_png(client, &reply, filename);
    }
    json_free(&reply);
    if (!ok) fprintf(stderr, "agent acceptance: exchange failed: %s\n", stem);
    return ok;
}

static bool unchanged(const struct state *left, const struct state *right)
{
    return left->x == right->x && left->y == right->y && left->z == right->z &&
        left->yaw == right->yaw && left->speed == right->speed &&
        left->health == right->health && left->time == right->time;
}

static bool movement_changed(const struct state *initial, const struct state *neutral,
                             const struct state *turned)
{
    return fabs(neutral->yaw - initial->yaw) <= 0.0001 &&
        fabs(turned->yaw - neutral->yaw) >= 0.001 && turned->speed != neutral->speed &&
        initial->time < neutral->time && neutral->time < turned->time &&
        !(turned->x == neutral->x && turned->y == neutral->y && turned->z == neutral->z);
}

static bool exercise_movement(struct client *client, struct state *turned)
{
    struct state initial, neutral;
    if (!exchange(client, "{\"v\":1,\"id\":1,\"op\":\"observe\",\"capture\":true}\n",
        1, 1, 0, NULL, "observe", true, &initial)) return false;
    if (!exchange(client, "{\"v\":1,\"id\":2,\"op\":\"step\",\"frames\":60,\"input\":{}}\n",
        2, 2, 60, NULL, "neutral", false, &neutral)) return false;
    if (!exchange(client, "{\"v\":1,\"id\":3,\"op\":\"step\",\"frames\":60,\"input\":{\"move_x\":0.5,\"throttle\":true},\"capture\":true}\n",
        3, 3, 120, NULL, "turn", true, turned)) return false;
    if (!movement_changed(&initial, &neutral, turned)) {
        fputs("agent acceptance: input-dependent state change missing\n", stderr);
        return false;
    }
    return true;
}

static bool exercise(struct client *client)
{
    struct state turned, refused, observed;
    if (!exercise_movement(client, &turned)) return false;
    if (!exchange(client, "{\"v\":1,\"id\":3,\"op\":\"step\",\"frames\":60,\"input\":{}}\n",
        3, 3, 120, "STALE_REQUEST_ID", "duplicate", false, &refused) ||
        !unchanged(&turned, &refused)) return false;
    if (!exchange(client, "{\"v\":1,\"id\":4,\"op\":\"step\",\"frames\":0,\"input\":{}}\n",
        4, 3, 120, "INVALID_REQUEST", "invalid", false, &refused) ||
        !unchanged(&turned, &refused)) return false;
    if (!exchange(client, "{\"v\":1,\"id\":4,\"op\":\"observe\"}\n",
        4, 4, 120, NULL, "fresh", false, &observed) ||
        !unchanged(&turned, &observed)) return false;
    return exchange(client, "{\"v\":1,\"id\":5,\"op\":\"close\"}\n",
        5, 5, 120, NULL, "close", false, &observed) && unchanged(&turned, &observed);
}

static bool launch(struct client *client, const char *binary)
{
    int input[2], output[2];
    if (pipe(input) != 0) return false;
    if (pipe(output) != 0) { close(input[0]); close(input[1]); return false; }
    client->child = fork();
    if (client->child == 0) {
        if (dup2(input[0], STDIN_FILENO) < 0 || dup2(output[1], STDOUT_FILENO) < 0) _Exit(126);
        close(input[0]); close(input[1]); close(output[0]); close(output[1]);
        execl(binary, binary, "--agent-stdio", (char *)NULL);
        _Exit(127);
    }
    close(input[0]); close(output[1]);
    if (client->child < 0) { close(input[1]); close(output[0]); return false; }
    client->request = input[1];
    client->reply = fdopen(output[0], "r");
    if (!client->reply) { close(output[0]); return false; }
    return true;
}

static bool corrupt_png_refused(unsigned char *bytes, size_t size,
                                uint32_t width, uint32_t height)
{
    size_t position = 33, length = 0;
    const unsigned char *data = NULL;
    if (!png_chunk(bytes, size, &position, "IDAT", &data, &length) || length <= 12)
        return false;
    size_t offset = (size_t)(data - bytes);
    bytes[offset + 8] ^= 1;
    bool ok = !complete_png(bytes, size, width, height);
    zcl_write_u32_be(bytes + offset + length,
                     crc32_update(0, bytes + offset - 4, length + 4));
    return ok && !complete_png(bytes, size, width, height);
}

/* Uses the actual captured image as positive input, never a regenerated
 * expected picture. Mutations test the same decoder called by save_png. */
static int check_png_controls(const char *path)
{
    FILE *file = fopen(path, "rb");
    if (!file) { perror("agent acceptance: open PNG control"); return 1; }
    unsigned char *bytes = malloc(PNG_LIMIT + 1u);
    size_t size = bytes ? fread(bytes, 1, PNG_LIMIT + 1u, file) : 0;
    bool ok = bytes && size >= 33 && size <= PNG_LIMIT && !ferror(file);
    if (fclose(file) != 0) ok = false;
    if (!ok) { free(bytes); return 1; }
    uint32_t width = big_endian(bytes + 16), height = big_endian(bytes + 20);
    ok = complete_png(bytes, size, width, height);
    unsigned char prefix[33] = {137,80,78,71,13,10,26,10,0,0,0,13,'I','H','D','R'};
    prefix[19] = 1;
    prefix[23] = 1;
    ok = ok && !complete_png(prefix, sizeof prefix, 1, 1) &&
        !complete_png(bytes, 33, width, height) &&
        !complete_png(bytes, size - 1, width, height) &&
        !complete_png(bytes, size / 2, width, height);
    /* Damage raster bytes, first with bad chunk CRC, then repair only CRC:
     * the latter must still fail the independently decoded Adler checksum. */
    ok = ok && corrupt_png_refused(bytes, size, width, height);
    free(bytes);
    fprintf(stderr, "agent PNG controls (actual/prefix/truncation/CRC/raster): %s\n",
            ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

static bool open_output(struct client *client, const char *path)
{
    struct stat status;
    client->directory = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (client->directory < 0 || fstat(client->directory, &status) != 0 ||
        status.st_uid != geteuid() || (status.st_mode & 077) != 0) {
        fputs("agent acceptance: output directory must be private and owned\n", stderr);
        if (client->directory >= 0) close(client->directory);
        client->directory = -1;
        return false;
    }
    return true;
}

static bool reap_child(pid_t child)
{
    pid_t waited;
    int child_status = 0;
    do { waited = waitpid(child, &child_status, 0); } while (waited < 0 && errno == EINTR);
    return waited == child && WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0;
}

static bool finish_child(struct client *client, bool ok)
{
    if (client->request >= 0 && close(client->request) != 0) ok = false;
    if (ok) ok = fgetc(client->reply) == EOF && !ferror(client->reply);
    if (client->reply && fclose(client->reply) != 0) ok = false;
    if (client->child <= 0) return false;
    if (!ok && kill(client->child, SIGKILL) != 0 && errno != ESRCH)
        perror("agent acceptance: kill child");
    bool reaped = reap_child(client->child);
    return ok && reaped;
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "--check-png") == 0)
        return check_png_controls(argv[2]);
    if (argc != 3 || argv[1][0] != '/' || argv[2][0] != '/') {
        fputs("usage: skycombat_agent_client /absolute/game /private/output-directory\n", stderr);
        return 2;
    }
    struct client client = {.child = -1, .request = -1, .directory = -1};
    if (!open_output(&client, argv[2])) return 2;
    client.line = malloc(RESPONSE_LIMIT + 1u);
    bool ok = client.line && signal(SIGPIPE, SIG_IGN) != SIG_ERR && launch(&client, argv[1]);
    if (ok) ok = exercise(&client);
    ok = finish_child(&client, ok);
    free(client.line);
    if (close(client.directory) != 0) ok = false;
    fprintf(stderr, "skycombat agent acceptance: %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
