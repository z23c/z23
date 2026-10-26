/* zrate CLI: simulate a token bucket over a synthetic timeline.
 *
 *   zrate bucket <capacity> <rate_per_sec> <t_ms:n>...
 *       At each timestamp t try to take n tokens; prints ok/deny.
 *   zrate window <limit> <interval_ms> <t_ms>...
 *       Hit a sliding-window counter at each timestamp; prints ok/deny.
 */
#include "zrate/zrate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

static int usage(void)
{
    fprintf(stderr,
        "usage: zrate bucket <capacity> <rate/s> <t_ms:n>...\n"
        "       zrate window <limit> <interval_ms> <t_ms>...\n");
    return 2;
}

static bool parse_time(const char *text, char delimiter, uint64_t *value,
                        const char **tail)
{
    const char *sign = text;
    while (isspace((unsigned char)*sign)) sign++;
    bool negative = *sign == '-';
    errno = 0;
    char *end;
    unsigned long long n = strtoull(text, &end, 10);
    if (end == text || *end != delimiter || errno == ERANGE ||
        n > UINT64_MAX || (negative && n != 0)) return false;
    *value = (uint64_t)n;
    if (tail) *tail = end;
    return true;
}

static bool parse_number(const char *text, double *value)
{
    errno = 0;
    char *end;
    double n = strtod(text, &end);
    if (end == text || *end || errno == ERANGE) return false;
    *value = n;
    return true;
}

struct output_state { bool attempted, failed; };

static void record_output(struct output_state *out, int result)
{
    out->attempted = true;
    if (result < 0) out->failed = true;
}

static int finish_output(const struct output_state *out, int result)
{
    if (out->attempted && (out->failed || fflush(stdout) != 0 || ferror(stdout))) {
        fprintf(stderr, "zrate: output write failed\n");
        return 2;
    }
    return result;
}

static int bucket_event(zrate_bucket *b, const char *text, struct output_state *out)
{
    uint64_t t;
    const char *colon;
    double n;
    if (!parse_time(text, ':', &t, &colon) || !parse_number(colon + 1, &n)) {
        fprintf(stderr, "zrate: bad bucket event\n");
        return 2;
    }
    bool ok = zrate_bucket_take(b, n, t);
    if (ok) record_output(out, printf("%llu ok (left %.3f)\n", (unsigned long long)t,
                                     zrate_bucket_peek(b, t)));
    else record_output(out, printf("%llu deny (wait %llu ms)\n", (unsigned long long)t,
                                   (unsigned long long)zrate_bucket_wait_ms(b, n, t)));
    return ok ? 0 : 1;
}

static int run_bucket(int argc, char **argv, struct output_state *out)
{
    double capacity, rate;
    if (!parse_number(argv[2], &capacity) || !parse_number(argv[3], &rate)) {
        fprintf(stderr, "zrate: bad bucket capacity or rate\n");
        return 2;
    }
    zrate_bucket b;
    zrate_bucket_init(&b, capacity, rate, 0);
    int denied = 0;
    for (int i = 4; i < argc; i++) {
        int rc = bucket_event(&b, argv[i], out);
        if (rc == 2 || out->failed) return 2;
        if (rc) denied = 1;
    }
    return denied;
}

static int window_event(zrate_window *w, const char *text, struct output_state *out)
{
    uint64_t t;
    if (!parse_time(text, '\0', &t, NULL)) {
        fprintf(stderr, "zrate: bad window event\n");
        return 2;
    }
    bool ok = zrate_window_hit(w, t);
    if (ok) record_output(out, printf("%llu ok (%u/%u)\n", (unsigned long long)t,
                                     zrate_window_count(w, t), w->limit));
    else record_output(out, printf("%llu deny (wait %llu ms)\n", (unsigned long long)t,
                                   (unsigned long long)zrate_window_wait_ms(w, t)));
    return ok ? 0 : 1;
}

static int run_window(int argc, char **argv, struct output_state *out)
{
    uint64_t limit, interval;
    if (!parse_time(argv[2], '\0', &limit, NULL) || limit < 1 || limit > 1024 ||
        !parse_time(argv[3], '\0', &interval, NULL)) {
        fprintf(stderr, "zrate: bad window limit or interval\n");
        return 2;
    }
    uint64_t events[1024];
    zrate_window w;
    zrate_window_init(&w, events, (uint32_t)limit, interval);
    int denied = 0;
    for (int i = 4; i < argc; i++) {
        int rc = window_event(&w, argv[i], out);
        if (rc == 2 || out->failed) return 2;
        if (rc) denied = 1;
    }
    return denied;
}

int main(int argc, char **argv)
{
    if (argc < 4) return usage();
    struct output_state out = {0};
    int result;
    if (strcmp(argv[1], "bucket") == 0) result = run_bucket(argc, argv, &out);
    else if (strcmp(argv[1], "window") == 0) result = run_window(argc, argv, &out);
    else return usage();
    return finish_output(&out, result);
}
