/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "command/refold_rate_verdict.h"

#include "json/json.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool samples_valid(const struct zcl_refold_rate_sample *samples,
                          size_t count)
{
    if ((!samples && count != 0) || count > ZCL_REFOLD_RATE_MAX_SAMPLES)
        return false;
    for (size_t i = 0; i < count; i++) {
        if (samples[i].monotonic_ns < 0 || samples[i].hstar < 0)
            return false;
        if (i > 0 && samples[i].monotonic_ns <= samples[i - 1].monotonic_ns)
            return false;
    }
    return true;
}

static size_t last_minimum(const struct zcl_refold_rate_sample *samples,
                           size_t count)
{
    size_t minimum = 0;
    for (size_t i = 1; i < count; i++) {
        if (samples[i].hstar <= samples[minimum].hstar)
            minimum = i;
    }
    return minimum;
}

static double interval_rate(const struct zcl_refold_rate_sample *current,
                            const struct zcl_refold_rate_sample *previous)
{
    const int64_t blocks = current->hstar - previous->hstar;
    const int64_t elapsed_ns = current->monotonic_ns - previous->monotonic_ns;
    return ((double)blocks * 1000000000.0) / (double)elapsed_ns;
}

static void summarize_rates(const double *rates, size_t count,
                            struct zcl_refold_rate_result *result)
{
    size_t third = count / 3;
    if (third == 0)
        third = 1;
    double first_sum = 0.0;
    double last_sum = 0.0;
    for (size_t i = 0; i < third; i++) {
        first_sum += rates[i];
        last_sum += rates[count - third + i];
    }
    result->first_third_rate = first_sum / (double)third;
    result->last_third_rate = last_sum / (double)third;
}

enum zcl_refold_rate_verdict zcl_refold_rate_classify(
    const struct zcl_refold_rate_sample *samples, size_t count,
    struct zcl_refold_rate_result *result)
{
    if (!result)
        return ZCL_REFOLD_RATE_INVALID_INPUT;
    *result = (struct zcl_refold_rate_result){0};
    result->samples = count;
    if (!samples_valid(samples, count)) {
        result->verdict = ZCL_REFOLD_RATE_INVALID_INPUT;
        return result->verdict;
    }
    if (count < 2) {
        result->verdict = ZCL_REFOLD_RATE_NO_CLIMB;
        return result->verdict;
    }

    const size_t minimum = last_minimum(samples, count);
    result->min_at = minimum + 1;
    result->climb = samples[count - 1].hstar - samples[minimum].hstar;
    if (result->climb <= 0) {
        result->verdict = ZCL_REFOLD_RATE_NO_CLIMB;
        return result->verdict;
    }

    const size_t interval_count = count - minimum - 1;
    result->intervals = interval_count;
    if (interval_count < 3) {
        result->verdict = ZCL_REFOLD_RATE_DECAYING;
        return result->verdict;
    }

    double rates[ZCL_REFOLD_RATE_MAX_SAMPLES];
    for (size_t i = 0; i < interval_count; i++)
        rates[i] = interval_rate(&samples[minimum + i + 1],
                                 &samples[minimum + i]);
    const int64_t elapsed_ns =
        samples[count - 1].monotonic_ns - samples[minimum].monotonic_ns;
    result->overall_rate =
        ((double)result->climb * 1000000000.0) / (double)elapsed_ns;
    summarize_rates(rates, interval_count, result);

    const bool ratio_ok =
        result->last_third_rate >=
        (result->first_third_rate *
         (double)ZCL_REFOLD_RATE_RATIO_FLOOR_PER_MILLE / 1000.0);
    const bool rate_ok =
        result->overall_rate >= ZCL_REFOLD_RATE_MIN_BLOCKS_PER_SECOND;
    result->verdict = ratio_ok && rate_ok ? ZCL_REFOLD_RATE_FLAT
                                          : ZCL_REFOLD_RATE_DECAYING;
    return result->verdict;
}

const char *zcl_refold_rate_verdict_name(enum zcl_refold_rate_verdict verdict)
{
    switch (verdict) {
    case ZCL_REFOLD_RATE_FLAT: return "FLAT";
    case ZCL_REFOLD_RATE_DECAYING: return "DECAYING";
    case ZCL_REFOLD_RATE_NO_CLIMB: return "NO_CLIMB";
    case ZCL_REFOLD_RATE_INVALID_INPUT: return "INVALID_INPUT";
    }
    return "INVALID_INPUT";
}

enum line_status { LINE_OK, LINE_END, LINE_BAD };

/* Reads one physical line (without its newline) into line[]. Rejects an
 * embedded NUL and any line longer than ZCL_REFOLD_RATE_MAX_LINE_BYTES. An
 * unterminated final line is a line. */
static enum line_status read_line(FILE *input,
                                  char line[ZCL_REFOLD_RATE_MAX_LINE_BYTES + 1],
                                  size_t *length)
{
    size_t used = 0;
    int c;
    while ((c = fgetc(input)) != EOF && c != '\n') {
        if (c == 0 || used >= ZCL_REFOLD_RATE_MAX_LINE_BYTES)
            return LINE_BAD;
        line[used++] = (char)c;
    }
    if (c == EOF && (ferror(input) || used == 0))
        return ferror(input) ? LINE_BAD : LINE_END;
    line[used] = '\0';
    *length = used;
    return LINE_OK;
}

static bool parse_row(const char *text, struct zcl_refold_rate_sample *out)
{
    struct json_value row;
    json_init(&row);
    bool ok = json_read(&row, text, strlen(text)) && row.type == JSON_OBJ;
    const struct json_value *mono = ok ? json_get(&row, "mono_ns") : NULL;
    const struct json_value *height = ok ? json_get(&row, "hstar") : NULL;
    const struct json_value *wall = ok ? json_get(&row, "ts") : NULL;
    ok = ok && mono && mono->type == JSON_INT &&
         height && height->type == JSON_INT &&
         (!wall || wall->type == JSON_INT);
    if (ok)
        *out = (struct zcl_refold_rate_sample){
            .monotonic_ns = json_get_int(mono),
            .hstar = json_get_int(height),
            .wall_epoch_s = wall ? json_get_int(wall) : 0
        };
    json_free(&row);
    return ok;
}

/* Handles one record: skips blanks and comments, otherwise appends a sample. */
static bool add_record(char *line, size_t length,
                       struct zcl_refold_rate_sample *samples, size_t *count)
{
    if (length > 0 && line[length - 1] == '\r')
        line[length - 1] = '\0';
    const char *first = line;
    while (*first && isspace((unsigned char)*first))
        first++;
    if (!*first || *first == '#')
        return true;
    if (*count >= ZCL_REFOLD_RATE_MAX_SAMPLES)
        return false;
    if (!parse_row(first, &samples[*count]))
        return false;
    (*count)++;
    return true;
}

bool zcl_refold_rate_read_jsonl(const char *path,
                                struct zcl_refold_rate_sample *samples,
                                size_t *count)
{
    if (!path || !samples || !count)
        return false;
    FILE *input = fopen(path, "rb");
    if (!input)
        return false;
    char line[ZCL_REFOLD_RATE_MAX_LINE_BYTES + 1];
    bool valid = true;
    size_t lines = 0;
    *count = 0;
    for (;;) {
        size_t length = 0;
        const enum line_status status = read_line(input, line, &length);
        if (status == LINE_END)
            break;
        valid = status == LINE_OK && ++lines <= ZCL_REFOLD_RATE_MAX_LINES &&
                add_record(line, length, samples, count);
        if (!valid)
            break;
    }
    if (fclose(input) != 0)
        valid = false;
    return valid;
}
