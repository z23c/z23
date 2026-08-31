/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: strict batch adapter for the maintained retrieval evaluator. */

#include "retrieval/retrieval.h"
#include "base/hex.h"
#include "sha3/sha3.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    EVAL_TASK_MAX = 32,
    EVAL_RELEVANT_MAX = ZCL_RETRIEVAL_EVAL_RANK_MAX,
    EVAL_RELEVANCE_TOTAL_MAX = EVAL_TASK_MAX * EVAL_RELEVANT_MAX,
    EVAL_ID_MAX = 128,
    EVAL_PATH_MAX = 255,
    EVAL_QUERY_MAX = 768,
    EVAL_LINE_MAX = 1024,
};

struct eval_arm_storage {
    struct zcl_retrieval_ranked_file ranked[ZCL_RETRIEVAL_EVAL_RANK_MAX];
    char paths[ZCL_RETRIEVAL_EVAL_RANK_MAX][EVAL_PATH_MAX + 1];
    size_t count;
    bool complete;
};

struct eval_task_storage {
    char id[EVAL_ID_MAX + 1];
    char query[EVAL_QUERY_MAX + 1];
    char relevant[EVAL_RELEVANT_MAX][EVAL_PATH_MAX + 1];
    const char *relevant_ptrs[EVAL_RELEVANT_MAX];
    size_t relevant_count;
    struct eval_arm_storage literal;
    struct eval_arm_storage bm25;
};

static struct eval_task_storage g_tasks[EVAL_TASK_MAX];
static size_t g_line_no;

static bool fail(const char *message)
{
    fprintf(stderr, "retrieval-eval: line %zu: %s\n", g_line_no, message);
    return false;
}

static bool read_line(char out[EVAL_LINE_MAX])
{
    if (!fgets(out, EVAL_LINE_MAX, stdin)) return false;
    g_line_no++;
    size_t n = strlen(out);
    if (n == 0 || out[n - 1] != '\n') return fail("overlong or unterminated line");
    out[--n] = '\0';
    if (n > 0 && out[n - 1] == '\r') return fail("carriage return is not canonical");
    return true;
}

static bool ascii_lower(unsigned char c)
{
    return c >= (unsigned char)'a' && c <= (unsigned char)'z';
}

static bool ascii_digit(unsigned char c)
{
    return c >= (unsigned char)'0' && c <= (unsigned char)'9';
}

static bool ascii_alnum(unsigned char c)
{
    return ascii_lower(c) || (c >= (unsigned char)'A' &&
                              c <= (unsigned char)'Z') || ascii_digit(c);
}

static bool token_safe(const char *value, bool task_id)
{
    if (!value || !value[0]) return false;
    size_t n = strlen(value);
    if (n > (task_id ? EVAL_ID_MAX : EVAL_PATH_MAX)) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)value[i];
        if (task_id) {
            if (!(ascii_lower(c) || ascii_digit(c) || c == '_')) return false;
        } else if (!(ascii_alnum(c) || c == '.' || c == '_' || c == '/' ||
                     c == '+' || c == '@' || c == '-')) {
            return false;
        }
    }
    if (task_id && !(ascii_lower((unsigned char)value[0]) ||
                     ascii_digit((unsigned char)value[0])))
        return false;
    if (!task_id && !ascii_alnum((unsigned char)value[0])) return false;
    const char *component = value;
    for (const char *p = value;; p++) {
        if (*p == '/' || *p == '\0') {
            size_t length = (size_t)(p - component);
            if (length == 0 || (length == 1 && component[0] == '.') ||
                (length == 2 && component[0] == '.' && component[1] == '.'))
                return false;
            if (*p == '\0') break;
            component = p + 1;
        }
    }
    return true;
}

static bool split_exact(char *line, char **fields, size_t expected)
{
    size_t count = 0;
    if (!line[0] || line[0] == ' ') return false;
    fields[count++] = line;
    for (char *p = line; *p; p++) {
        if (*p != ' ') continue;
        if (p[1] == '\0' || p[1] == ' ' || count == expected) return false;
        *p = '\0';
        fields[count++] = p + 1;
    }
    return count == expected;
}

static bool parse_size(const char *text, size_t maximum, size_t *out)
{
    if (!text[0] || (text[0] == '0' && text[1] != '\0')) return false;
    size_t value = 0;
    for (size_t i = 0; text[i]; i++) {
        if (!ascii_digit((unsigned char)text[i])) return false;
        size_t digit = (size_t)(text[i] - '0');
        if (digit > maximum || value > (maximum - digit) / 10u) return false;
        value = value * 10u + digit;
    }
    *out = value;
    return true;
}

static bool parse_header(char *line, size_t *tasks,
                         size_t *eligible_relevance_judgments)
{
    char *fields[3];
    static const char tasks_prefix[] = "tasks=";
    static const char relevance_prefix[] =
        "eligible_relevance_judgments=";
    return split_exact(line, fields, 3) &&
        strcmp(fields[0], "zcl.retrieval_eval_batch.v3") == 0 &&
        strncmp(fields[1], tasks_prefix, sizeof(tasks_prefix) - 1u) == 0 &&
        parse_size(fields[1] + sizeof(tasks_prefix) - 1u,
                   EVAL_TASK_MAX, tasks) &&
        strncmp(fields[2], relevance_prefix,
                sizeof(relevance_prefix) - 1u) == 0 &&
        parse_size(fields[2] + sizeof(relevance_prefix) - 1u,
                   EVAL_RELEVANCE_TOTAL_MAX,
                   eligible_relevance_judgments) &&
        *tasks > 0 && *eligible_relevance_judgments > 0;
}

static bool parse_task(struct eval_task_storage *task, char *line)
{
    char *fields[3];
    size_t relevant_count = 0;
    if (!split_exact(line, fields, 3) || strcmp(fields[0], "task") != 0 ||
        !token_safe(fields[1], true) ||
        !parse_size(fields[2], EVAL_RELEVANT_MAX, &relevant_count) ||
        relevant_count == 0)
        return fail("invalid task declaration");
    memcpy(task->id, fields[1], strlen(fields[1]) + 1);
    task->relevant_count = relevant_count;
    return true;
}

static bool parse_query(struct eval_task_storage *task, const char *line)
{
    static const char prefix[] = "query ";
    size_t length;
    if (strncmp(line, prefix, sizeof(prefix) - 1u) != 0 ||
        line[sizeof(prefix) - 1u] == '\0')
        return fail("invalid query declaration");
    length = strlen(line + sizeof(prefix) - 1u);
    if (length > EVAL_QUERY_MAX) return fail("query is too long");
    for (size_t i = 0; i < length; i++) {
        unsigned char c = (unsigned char)line[sizeof(prefix) - 1u + i];
        if (c < 0x20u || c > 0x7eu) return fail("query is not canonical ASCII");
    }
    memcpy(task->query, line + sizeof(prefix) - 1u, length + 1u);
    return true;
}

static bool parse_relevant(struct eval_task_storage *task, size_t index,
                           char *line)
{
    char *fields[2];
    if (!split_exact(line, fields, 2) || strcmp(fields[0], "relevant") != 0 ||
        !token_safe(fields[1], false))
        return fail("invalid relevant path");
    for (size_t i = 0; i < index; i++)
        if (strcmp(task->relevant[i], fields[1]) == 0)
            return fail("duplicate relevant path");
    memcpy(task->relevant[index], fields[1], strlen(fields[1]) + 1);
    task->relevant_ptrs[index] = task->relevant[index];
    return true;
}

static bool parse_arm(struct eval_arm_storage *arm, const char *name,
                      char *line)
{
    char *fields[4];
    size_t complete = 0, count = 0;
    if (!split_exact(line, fields, 4) || strcmp(fields[0], name) != 0 ||
        strcmp(fields[1], "observed") != 0 ||
        !parse_size(fields[2], 1, &complete) ||
        !parse_size(fields[3], ZCL_RETRIEVAL_EVAL_RANK_MAX, &count))
        return fail("invalid ranker declaration");
    arm->complete = complete != 0;
    arm->count = count;
    return true;
}

static bool parse_rank(struct eval_arm_storage *arm, size_t index,
                       char *line)
{
    char *fields[5];
    size_t context_bytes = 0, scope_available = 0, in_scope = 0;
    if (!split_exact(line, fields, 5) || strcmp(fields[0], "rank") != 0 ||
        !parse_size(fields[1], SIZE_MAX, &context_bytes) ||
        !parse_size(fields[2], 1, &scope_available) ||
        !parse_size(fields[3], 1, &in_scope) ||
        !token_safe(fields[4], false) || (!scope_available && in_scope))
        return fail("invalid ranked file");
    for (size_t i = 0; i < index; i++)
        if (strcmp(arm->paths[i], fields[4]) == 0)
            return fail("duplicate ranked path");
    memcpy(arm->paths[index], fields[4], strlen(fields[4]) + 1);
    arm->ranked[index] = (struct zcl_retrieval_ranked_file){
        .path = arm->paths[index],
        .context_bytes = (uint64_t)context_bytes,
        .in_scope = in_scope != 0,
        .in_scope_available = scope_available != 0,
    };
    return true;
}

static bool read_arm(struct eval_arm_storage *arm, const char *name,
                     char line[EVAL_LINE_MAX])
{
    if (!read_line(line) || !parse_arm(arm, name, line)) return false;
    for (size_t i = 0; i < arm->count; i++)
        if (!read_line(line) || !parse_rank(arm, i, line)) return false;
    return true;
}

static void u64le(uint8_t out[8], uint64_t value)
{
    for (size_t i = 0; i < 8; i++) {
        out[i] = (uint8_t)(value & 0xffu);
        value >>= 8;
    }
}

static int rank_root_mode(const char *complete_text)
{
    size_t complete = 0, count = 0;
    char line[EVAL_LINE_MAX];
    if (!parse_size(complete_text, 1, &complete)) {
        (void)fail("rank-root completeness must be 0 or 1");
        return 1;
    }
    struct eval_arm_storage *arm = &g_tasks[0].literal;
    while (read_line(line)) {
        if (count == ZCL_RETRIEVAL_EVAL_RANK_MAX) {
            (void)fail("rank-root input exceeds 128 rows");
            return 1;
        }
        char *fields[3] = {line, NULL, NULL};
        char *first_tab = strchr(line, '\t');
        char *second_tab = first_tab ? strchr(first_tab + 1, '\t') : NULL;
        if (!first_tab || !second_tab || strchr(second_tab + 1, '\t')) {
            (void)fail("rank-root row is not rank<TAB>bytes<TAB>path");
            return 1;
        }
        *first_tab = '\0';
        *second_tab = '\0';
        fields[1] = first_tab + 1;
        fields[2] = second_tab + 1;
        size_t rank = 0, context_bytes = 0;
        if (!parse_size(fields[0], ZCL_RETRIEVAL_EVAL_RANK_MAX, &rank) ||
            rank != count + 1u ||
            !parse_size(fields[1], SIZE_MAX, &context_bytes) ||
            !token_safe(fields[2], false)) {
            (void)fail("invalid rank-root row");
            return 1;
        }
        for (size_t i = 0; i < count; i++)
            if (strcmp(arm->paths[i], fields[2]) == 0) {
                (void)fail("duplicate rank-root path");
                return 1;
            }
        memcpy(arm->paths[count], fields[2], strlen(fields[2]) + 1u);
        arm->ranked[count].path = arm->paths[count];
        arm->ranked[count].context_bytes = (uint64_t)context_bytes;
        count++;
    }
    if (ferror(stdin)) {
        (void)fail("rank-root input read failed");
        return 1;
    }
    static const char domain[] = "zcl.retrieval_ranked_files.v1";
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    const uint8_t complete_byte = complete ? 1u : 0u;
    sha3_256_write(&sha, &complete_byte, 1u);
    uint8_t encoded[8];
    u64le(encoded, (uint64_t)count);
    sha3_256_write(&sha, encoded, sizeof(encoded));
    for (size_t i = 0; i < count; i++) {
        sha3_256_write(&sha, (const uint8_t *)arm->ranked[i].path,
                       strlen(arm->ranked[i].path) + 1u);
        u64le(encoded, arm->ranked[i].context_bytes);
        sha3_256_write(&sha, encoded, sizeof(encoded));
    }
    uint8_t digest[SHA3_256_OUTPUT_SIZE];
    char hex[SHA3_256_OUTPUT_SIZE * 2u + 1u];
    sha3_256_finalize(&sha, digest);
    zcl_hex_encode(digest, sizeof(digest), hex);
    printf("%s\n", hex);
    return ferror(stdout) ? 1 : 0;
}

static void print_metric(const char *name, bool available, uint32_t value,
                         bool comma)
{
    printf("\"%s\":{\"available\":%s,\"basis_points\":",
           name, available ? "true" : "false");
    if (available) printf("%" PRIu32, value);
    else fputs("null", stdout);
    printf("}%s", comma ? "," : "");
}

static void print_arm(const struct zcl_retrieval_eval_metrics *m)
{
    putchar('{');
    print_metric("recall_at_5", m->recall_at_5_available,
                 m->recall_at_5_bp, true);
    print_metric("recall_at_20", m->recall_at_20_available,
                 m->recall_at_20_bp, true);
    print_metric("mrr", m->mrr_available, m->mrr_bp, true);
    printf("\"task_unique_file_selections_at_5\":%" PRIu64 ","
           "\"projected_context_bytes_at_5\":%" PRIu64 ","
           "\"approximate_tokens_at_5\":%" PRIu64 ",",
           m->unique_files_at_5, m->context_bytes_at_5,
           m->approximate_tokens_at_5);
    print_metric("wrong_scope_at_5", m->wrong_scope_at_5_available,
                 m->wrong_scope_at_5_bp, false);
    putchar('}');
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "--rank-root") == 0)
        return rank_root_mode(argv[2]);
    if (argc != 1) {
        fputs("usage: retrieval-eval < batch.txt\n"
              "       retrieval-eval --rank-root 0|1 < ranks.tsv\n", stderr);
        return 64;
    }
    char line[EVAL_LINE_MAX];
    size_t task_count, declared_relevance_judgments;
    if (!read_line(line) ||
        !parse_header(line, &task_count, &declared_relevance_judgments)) {
        (void)fail("invalid batch header");
        return 1;
    }
    size_t observed_relevance_judgments = 0;
    for (size_t t = 0; t < task_count; t++) {
        if (!read_line(line) || !parse_task(&g_tasks[t], line)) return 1;
        if (g_tasks[t].relevant_count >
            SIZE_MAX - observed_relevance_judgments) {
            (void)fail("eligible relevance-judgment count overflow");
            return 1;
        }
        observed_relevance_judgments += g_tasks[t].relevant_count;
        for (size_t prior = 0; prior < t; prior++)
            if (strcmp(g_tasks[prior].id, g_tasks[t].id) == 0) {
                (void)fail("duplicate task id");
                return 1;
            }
        if (!read_line(line) || !parse_query(&g_tasks[t], line)) return 1;
        for (size_t i = 0; i < g_tasks[t].relevant_count; i++)
            if (!read_line(line) || !parse_relevant(&g_tasks[t], i, line))
                return 1;
        if (!read_arm(&g_tasks[t].literal, "literal", line) ||
            !read_arm(&g_tasks[t].bm25, "bm25", line))
            return 1;
    }
    if (observed_relevance_judgments != declared_relevance_judgments) {
        (void)fail("declared eligible relevance-judgment count differs from tasks");
        return 1;
    }
    if (!read_line(line) || strcmp(line, "end") != 0 ||
        fgetc(stdin) != EOF || ferror(stdin)) {
        (void)fail("missing canonical end or trailing input");
        return 1;
    }
    struct zcl_retrieval_gold_task literal[EVAL_TASK_MAX] = {0};
    struct zcl_retrieval_gold_task bm25[EVAL_TASK_MAX] = {0};
    for (size_t t = 0; t < task_count; t++) {
        literal[t] = (struct zcl_retrieval_gold_task){
            .task_id = g_tasks[t].id,
            .query = g_tasks[t].query,
            .relevant_paths = g_tasks[t].relevant_ptrs,
            .relevant_count = g_tasks[t].relevant_count,
            .ranked = g_tasks[t].literal.ranked,
            .ranked_count = g_tasks[t].literal.count,
            .ranking_complete = g_tasks[t].literal.complete,
        };
        bm25[t] = literal[t];
        bm25[t].ranked = g_tasks[t].bm25.ranked;
        bm25[t].ranked_count = g_tasks[t].bm25.count;
        bm25[t].ranking_complete = g_tasks[t].bm25.complete;
    }
    struct zcl_retrieval_eval_metrics literal_metrics, bm25_metrics;
    if (!zcl_retrieval_evaluate(literal, task_count, &literal_metrics) ||
        !zcl_retrieval_evaluate(bm25, task_count, &bm25_metrics)) {
        (void)fail("maintained evaluator refused the batch");
        return 1;
    }
    printf("{\"schema\":\"zcl.retrieval_eval_batch_result.v3\","
           "\"tasks_evaluated\":%zu,"
           "\"aggregation_kind\":\"macro_equal_task_weight\","
           "\"tasks_denominator\":%zu,"
           "\"eligible_relevance_judgments\":%zu,"
           "\"binding_kind\":\"metrics_only_runner_seals_provenance\","
           "\"context_cost_kind\":\"projected_not_read\","
           "\"token_basis\":\"ceil(context_bytes/4)\",\"literal\":",
           task_count, task_count, observed_relevance_judgments);
    print_arm(&literal_metrics);
    fputs(",\"bm25\":", stdout);
    print_arm(&bm25_metrics);
    fputs("}\n", stdout);
    if (ferror(stdout)) {
        fputs("retrieval-eval: output write failed\n", stderr);
        return 1;
    }
    return 0;
}
