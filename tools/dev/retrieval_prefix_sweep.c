/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Rebuild the six-prefix retrieval experiment from frozen batches
 *          and emit the sweep receipt. The transcript goes to stdout. */

#include "retrieval_prefix_sweep.h"

#include <stdio.h>
#include <string.h>

static int rx_fail(const char *msg)
{
    fprintf(stderr, "retrieval-prefix-sweep: FAIL \xe2\x80\x94 %s\n", msg);
    return 1;
}

#if !defined(_WIN32)
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

struct rx_job {
    const struct zcl_rx_tools *tools;
    char tmp[PATH_MAX];
    char batch[PATH_MAX];
    char transcript[PATH_MAX];
    long recall[6];
    long bytes[6];
};

struct rx_base {
    const char *tmp;
    int task;
    int pre;
    int rel;
    int take;
};

static int rx_usage(const char *argv0, int argc, char **argv)
{
    const char *name = argv0 != NULL && argv0[0] != '\0' ? argv0
                                                         : "retrieval-prefix-sweep";
    if (argc == 2 && argv != NULL && argv[1] != NULL && strcmp(argv[1], "--check") == 0)
        return 0;
    fprintf(stderr, "retrieval-prefix-sweep: FAIL \xe2\x80\x94 usage: %s --check\n", name);
    return 1;
}

static int rx_can_exec(const char *path)
{
    if (path == NULL || path[0] == '\0')
        return 0;
    return access(path, X_OK) == 0;
}

static int rx_ready(const struct zcl_rx_tools *tools)
{
    if (tools == NULL)
        return rx_fail("build jsonq, agent-sha3, and retrieval-eval first");
    if (!rx_can_exec(tools->checker) || !rx_can_exec(tools->evaluator))
        return rx_fail("build jsonq, agent-sha3, and retrieval-eval first");
    if (!rx_can_exec(tools->jsonq) || !rx_can_exec(tools->sha3))
        return rx_fail("build jsonq, agent-sha3, and retrieval-eval first");
    return 0;
}

static int rx_send(int fd, const char *text)
{
    size_t left;
    const char *p;
    if (text == NULL)
        text = "";
    p = text;
    left = strlen(p);
    while (left > 0) {
        size_t chunk = left > 256 ? 256 : left;
        ssize_t n = write(fd, p, chunk);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        p += n;
        left -= (size_t)n;
    }
    return 0;
}

static int rx_reap(pid_t pid)
{
    int status = 0;
    for (;;) {
        pid_t got = waitpid(pid, &status, 0);
        if (got < 0 && errno == EINTR)
            continue;
        if (got != pid)
            return 126;
        break;
    }
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return 126;
}

static int rx_slurp(int fd, char *out, size_t cap)
{
    size_t n = 0;
    int overflow = 0;
    if (out == NULL || cap == 0) {
        close(fd);
        return -1;
    }
    out[0] = '\0';
    for (;;) {
        char buf[256];
        ssize_t got = read(fd, buf, sizeof buf);
        size_t i = 0;
        if (got == 0)
            break;
        if (got < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return -1;
        }
        while (i < (size_t)got) {
            if (n + 1 >= cap)
                overflow = 1;
            else
                out[n++] = buf[i];
            i++;
        }
        out[n] = '\0';
    }
    close(fd);
    return overflow ? -1 : 0;
}

static void rx_chomp(char *text)
{
    char *tail;
    if (text == NULL)
        return;
    tail = strchr(text, '\0');
    while (tail != text) {
        if (tail[-1] != '\n')
            break;
        *--tail = '\0';
    }
}

static int rx_child(char *const argv[], int in_fd, int out_fd)
{
    if (in_fd >= 0) {
        if (dup2(in_fd, STDIN_FILENO) < 0)
            _exit(127);
        if (in_fd > STDERR_FILENO)
            close(in_fd);
    }
    if (out_fd >= 0) {
        if (dup2(out_fd, STDOUT_FILENO) < 0)
            _exit(127);
        if (out_fd > STDERR_FILENO)
            close(out_fd);
    } else {
        int sink = open("/dev/null", O_WRONLY);
        if (sink < 0 || dup2(sink, STDOUT_FILENO) < 0)
            _exit(127);
        if (sink > STDERR_FILENO)
            close(sink);
    }
    if (setenv("LC_ALL", "C", 1) != 0)
        _exit(127);
    execvp(argv[0], argv);
    _exit(127);
}

static void rx_shut(int fd)
{
    if (fd >= 0)
        close(fd);
}

static int rx_pipes(const char *mem, char *out, int feed[2], int back[2])
{
    feed[0] = -1;
    feed[1] = -1;
    back[0] = -1;
    back[1] = -1;
    if (mem != NULL && pipe(feed) != 0)
        return -1;
    if (out != NULL && pipe(back) != 0) {
        rx_shut(feed[0]);
        rx_shut(feed[1]);
        return -1;
    }
    return 0;
}

static void rx_become(char *const argv[], int in_fd, const char *mem, char *out,
                      int feed[2], int back[2])
{
    int child_in = mem != NULL ? feed[0] : in_fd;
    rx_shut(feed[1]);
    rx_shut(back[0]);
    rx_child(argv, child_in, out != NULL ? back[1] : -1);
    _exit(127);
}

static int rx_feed(pid_t pid, const char *mem, int feed_w, int back_r)
{
    int bad = 0;
    if (mem != NULL)
        bad = rx_send(feed_w, mem);
    if (bad == 0 && mem != NULL)
        bad = rx_send(feed_w, "\n");
    rx_shut(feed_w);
    if (bad != 0) {
        rx_shut(back_r);
        rx_reap(pid);
        return -1;
    }
    return 0;
}

static int rx_launch(char *const argv[], int in_fd, const char *mem, char *out,
                     size_t cap, int *status)
{
    int feed[2];
    int back[2];
    pid_t pid;
    if (status == NULL)
        return -1;
    if (rx_pipes(mem, out, feed, back) != 0)
        return -1;
    pid = fork();
    if (pid < 0) {
        rx_shut(feed[0]);
        rx_shut(feed[1]);
        rx_shut(back[0]);
        rx_shut(back[1]);
        return -1;
    }
    if (pid == 0)
        rx_become(argv, in_fd, mem, out, feed, back);
    rx_shut(feed[0]);
    rx_shut(back[1]);
    if (rx_feed(pid, mem, feed[1], back[0]) != 0)
        return -1;
    if (out != NULL && rx_slurp(back[0], out, cap) != 0) {
        rx_reap(pid);
        return -1;
    }
    *status = rx_reap(pid);
    return *status == 126 ? -1 : 0;
}

static int rx_hash(const char *sha3, const char *path, char *out, size_t cap)
{
    char raw[1200];
    char *argv[3];
    int status = 1;
    size_t i;
    argv[0] = (char *)sha3;
    argv[1] = (char *)path;
    argv[2] = NULL;
    if (rx_launch(argv, -1, NULL, raw, sizeof raw, &status) != 0 || status != 0)
        return -1;
    rx_chomp(raw);
    if (strlen(raw) < 64 || cap < 65)
        return -1;
    for (i = 0; i < 64; i++) {
        char c = raw[i];
        int dec = c >= '0' && c <= '9';
        int hex = c >= 'a' && c <= 'f';
        if (!dec && !hex)
            return -1;
    }
    if (raw[64] != '\0' && raw[64] != ' ')
        return -1;
    memcpy(out, raw, 64);
    out[64] = '\0';
    return 0;
}

static int rx_json(const char *jsonq, const char *row, const char *key, char *out,
                   size_t cap)
{
    char *argv[4];
    int status = 1;
    int launched;
    argv[0] = (char *)jsonq;
    argv[1] = "get";
    argv[2] = (char *)key;
    argv[3] = NULL;
    launched = rx_launch(argv, -1, row, out, cap, &status);
    if (launched != 0)
        return -1;
    rx_chomp(out);
    if (status != 0)
        return -1;
    return 0;
}

static int rx_num(const char *text, long *out)
{
    char *end = NULL;
    long value;
    if (text == NULL || text[0] < '0' || text[0] > '9')
        return -1;
    errno = 0;
    value = strtol(text, &end, 10);
    if (end == NULL || *end != '\0' || errno != 0)
        return -1;
    *out = value;
    return 0;
}

static int rx_same(const char *jsonq, const char *row, const char *key, const char *want)
{
    char got[160];
    if (rx_json(jsonq, row, key, got, sizeof got) != 0)
        return 0;
    return strcmp(got, want) == 0;
}

static int rx_add(const char *path, const char *line)
{
    FILE *file = fopen(path, "a");
    if (file == NULL)
        return -1;
    if (fprintf(file, "%s\n", line) < 0) {
        fclose(file);
        return -1;
    }
    return fclose(file) == 0 ? 0 : -1;
}

static int rx_note(const char *tmp, const char *kind, int task, const char *line)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof path, "%s/%s-%d", tmp, kind, task);
    if (n < 0 || (size_t)n >= sizeof path)
        return -1;
    return rx_add(path, line);
}

static int rx_token(const char *line, int index, char *out, size_t cap)
{
    const char *p = line;
    int seen = 0;
    if (out == NULL || cap == 0)
        return -1;
    out[0] = '\0';
    while (*p != '\0') {
        size_t k = 0;
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '\0')
            break;
        while (*p != '\0' && *p != ' ' && *p != '\t') {
            if (seen == index) {
                if (k + 1 >= cap)
                    return -1;
                out[k++] = *p;
            }
            p++;
        }
        if (seen == index) {
            out[k] = '\0';
            return 0;
        }
        seen++;
    }
    return -1;
}

static int rx_base_task(struct rx_base *st, const char *line)
{
    char count[32];
    long rel = 0;
    st->task++;
    st->pre = 1;
    st->take = 0;
    if (rx_token(line, 2, count, sizeof count) != 0)
        return -1;
    if (rx_num(count, &rel) != 0)
        return -1;
    st->rel = (int)rel;
    return rx_note(st->tmp, "pre", st->task, line);
}

static int rx_base_relevant(struct rx_base *st, const char *line)
{
    if (rx_note(st->tmp, "pre", st->task, line) != 0)
        return -1;
    st->rel--;
    if (st->rel == 0)
        st->pre = 0;
    return 0;
}

static int rx_base_bm25(struct rx_base *st, const char *line)
{
    char a[128];
    char b[64];
    char c[64];
    char built[256];
    int n;
    st->take = 1;
    if (rx_token(line, 1, a, sizeof a) != 0)
        return -1;
    if (rx_token(line, 2, b, sizeof b) != 0)
        return -1;
    if (rx_token(line, 3, c, sizeof c) != 0)
        return -1;
    n = snprintf(built, sizeof built, "literal %s %s %s", a, b, c);
    if (n < 0 || (size_t)n >= sizeof built)
        return -1;
    return rx_note(st->tmp, "base", st->task, built);
}

static int rx_base_line(struct rx_base *st, const char *line)
{
    char kind[32];
    if (rx_token(line, 0, kind, sizeof kind) != 0)
        return 0;
    if (strcmp(kind, "task") == 0)
        return rx_base_task(st, line);
    if (st->pre && strcmp(kind, "query") == 0)
        return rx_note(st->tmp, "pre", st->task, line);
    if (st->pre && strcmp(kind, "relevant") == 0)
        return rx_base_relevant(st, line);
    if (strcmp(kind, "literal") == 0) {
        st->take = 0;
        return 0;
    }
    if (strcmp(kind, "bm25") == 0)
        return rx_base_bm25(st, line);
    if (strcmp(kind, "rank") == 0 && st->take)
        return rx_note(st->tmp, "base", st->task, line);
    return 0;
}

static int rx_graph_line(struct rx_base *st, const char *line)
{
    char kind[32];
    if (rx_token(line, 0, kind, sizeof kind) != 0)
        return 0;
    if (strcmp(kind, "task") == 0) {
        st->task++;
        return 0;
    }
    if (strcmp(kind, "literal") == 0) {
        st->take = 0;
        return 0;
    }
    if (strcmp(kind, "bm25") == 0) {
        st->take = 1;
        return rx_note(st->tmp, "parent", st->task, line);
    }
    if (strcmp(kind, "rank") == 0 && st->take)
        return rx_note(st->tmp, "parent", st->task, line);
    return 0;
}

static int rx_walk(const char *path, struct rx_base *st, int graph)
{
    FILE *file = fopen(path, "r");
    char buf[1024];
    if (file == NULL)
        return -1;
    while (fgets(buf, sizeof buf, file) != NULL) {
        size_t n = strlen(buf);
        int rc;
        if (n == sizeof buf - 1 && buf[n - 1] != '\n') {
            fclose(file);
            return -1;
        }
        if (n > 0 && buf[n - 1] == '\n')
            buf[--n] = '\0';
        rc = graph ? rx_graph_line(st, buf) : rx_base_line(st, buf);
        if (rc != 0) {
            fclose(file);
            return -1;
        }
    }
    fclose(file);
    return 0;
}

static int rx_filled(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return 0;
    return st.st_size > 0;
}

static int rx_task_ok(const char *tmp, int task)
{
    char path[PATH_MAX];
    const char *kind[] = {"pre", "base", "parent"};
    int i;
    for (i = 0; i < 3; i++) {
        int n = snprintf(path, sizeof path, "%s/%s-%d", tmp, kind[i], task);
        if (n < 0 || (size_t)n >= sizeof path || !rx_filled(path))
            return 0;
    }
    return 1;
}

static int rx_cat3(FILE *out, const char *tmp, int task)
{
    const char *kind[] = {"pre", "base", "parent"};
    int i;
    for (i = 0; i < 3; i++) {
        char path[PATH_MAX];
        FILE *in;
        char buf[1024];
        size_t n;
        int wr = snprintf(path, sizeof path, "%s/%s-%d", tmp, kind[i], task);
        if (wr < 0 || (size_t)wr >= sizeof path)
            return -1;
        in = fopen(path, "r");
        if (in == NULL)
            return -1;
        while ((n = fread(buf, 1, sizeof buf, in)) > 0) {
            if (fwrite(buf, 1, n, out) != n) {
                fclose(in);
                return -1;
            }
        }
        fclose(in);
    }
    return 0;
}

static int rx_write_experiment(struct rx_job *job);

static int rx_rebuild(struct rx_job *job)
{
    struct rx_base base;
    struct rx_base graph;
    char base_path[PATH_MAX];
    char graph_path[PATH_MAX];
    int n;
    memset(&base, 0, sizeof base);
    memset(&graph, 0, sizeof graph);
    base.tmp = job->tmp;
    graph.tmp = job->tmp;
    n = snprintf(base_path, sizeof base_path, "%s/base.batch", job->tmp);
    if (n < 0 || (size_t)n >= sizeof base_path)
        return -1;
    if (rename(job->batch, base_path) != 0)
        return -1;
    n = snprintf(graph_path, sizeof graph_path, "%s/identifier-graph-evaluator.batch", job->tmp);
    if (n < 0 || (size_t)n >= sizeof graph_path)
        return -1;
    if (rx_walk(base_path, &base, 0) != 0)
        return -1;
    if (rx_walk(graph_path, &graph, 1) != 0)
        return -1;
    return rx_write_experiment(job);
}

static int rx_write_header(FILE *out)
{
    if (fprintf(out, "%s\n",
                "zcl.retrieval_eval_batch.v3 tasks=9 eligible_relevance_judgments=43") < 0)
        return -1;
    return 0;
}

static int rx_stitch(struct rx_job *job, FILE *out)
{
    int task;
    for (task = 1; task <= 9; task++) {
        if (!rx_task_ok(job->tmp, task))
            return task;
        if (rx_cat3(out, job->tmp, task) != 0)
            return task;
    }
    if (fprintf(out, "end\n") < 0)
        return -1;
    return 0;
}

static int rx_write_experiment(struct rx_job *job)
{
    FILE *out;
    int stitched;
    int n = snprintf(job->batch, sizeof job->batch, "%s/experiment.batch", job->tmp);
    if (n < 0 || (size_t)n >= sizeof job->batch)
        return -1;
    out = fopen(job->batch, "w");
    if (out == NULL)
        return -1;
    if (rx_write_header(out) != 0) {
        fclose(out);
        return -1;
    }
    stitched = rx_stitch(job, out);
    if (fclose(out) != 0 && stitched == 0)
        return -1;
    return stitched;
}

static int rx_bounds(const char *jsonq, const char *row, int prefix)
{
    char want[16];
    int n = snprintf(want, sizeof want, "%d", prefix);
    if (n < 0 || (size_t)n >= sizeof want)
        return -1;
    if (!rx_same(jsonq, row, "schema", "zcl.retrieval_experiment_eval_result.v1"))
        return -1;
    if (!rx_same(jsonq, row, "bm25_prefix", want))
        return -1;
    if (!rx_same(jsonq, row, "tasks_evaluated", "9"))
        return -1;
    if (!rx_same(jsonq, row, "candidate.recall_at_20.basis_points", "3502"))
        return -1;
    if (!rx_same(jsonq, row, "top20_membership_preserved", "true"))
        return -1;
    return 0;
}

static int rx_bounds_rest(const char *jsonq, const char *row)
{
    if (!rx_same(jsonq, row, "full_retained_set_preserved", "true"))
        return -1;
    if (!rx_same(jsonq, row, "context_ceiling_preserved", "true"))
        return -1;
    if (!rx_same(jsonq, row, "candidate.wrong_scope_at_5.available", "false"))
        return -1;
    if (!rx_same(jsonq, row, "projector_gold_input", "none"))
        return -1;
    if (!rx_same(jsonq, row, "promotion_authorized", "false"))
        return -1;
    return 0;
}

static int rx_field_long(const char *jsonq, const char *row, const char *key, long *out)
{
    char text[40];
    if (rx_json(jsonq, row, key, text, sizeof text) != 0)
        return -1;
    return rx_num(text, out);
}

static int rx_metrics(struct rx_job *job, const char *row, int prefix)
{
    long recall_v = 0;
    long bytes_v = 0;
    if (rx_field_long(job->tools->jsonq, row, "candidate.recall_at_5.basis_points",
                      &recall_v) != 0)
        return -1;
    if (rx_field_long(job->tools->jsonq, row,
                      "candidate.projected_context_bytes_at_5", &bytes_v) != 0)
        return -1;
    job->recall[prefix] = recall_v;
    job->bytes[prefix] = bytes_v;
    return 0;
}

static int rx_fail_prefix(int prefix, const char *what)
{
    fprintf(stderr, "retrieval-prefix-sweep: FAIL \xe2\x80\x94 prefix %d %s\n",
            prefix, what);
    return 1;
}

static int rx_fail_task(int task)
{
    fprintf(stderr,
            "retrieval-prefix-sweep: FAIL \xe2\x80\x94 "
            "task %d did not reconstruct completely\n",
            task);
    return 1;
}

static int rx_one(struct rx_job *job, int prefix)
{
    char row[4096];
    char label[16];
    char *argv[4];
    int fd;
    int status = 1;
    int n = snprintf(label, sizeof label, "%d", prefix);
    if (n < 0 || (size_t)n >= sizeof label)
        return rx_fail_prefix(prefix, "evaluation was refused");
    fd = open(job->batch, O_RDONLY);
    if (fd < 0)
        return rx_fail_prefix(prefix, "evaluation was refused");
    argv[0] = (char *)job->tools->evaluator;
    argv[1] = "--experiment-prefix";
    argv[2] = label;
    argv[3] = NULL;
    n = rx_launch(argv, fd, NULL, row, sizeof row, &status);
    close(fd);
    if (n != 0 || status != 0) {
        return rx_fail_prefix(prefix, "evaluation was refused");
    }
    rx_chomp(row);
    if (rx_bounds(job->tools->jsonq, row, prefix) != 0 ||
        rx_bounds_rest(job->tools->jsonq, row) != 0)
        return rx_fail_prefix(prefix, "evidence boundary differs");
    if (rx_metrics(job, row, prefix) != 0)
        return rx_fail_prefix(prefix, "evidence boundary differs");
    if (rx_add(job->transcript, row) != 0)
        return rx_fail_prefix(prefix, "evaluation was refused");
    return 0;
}

static int rx_dominates(long peer_recall, long peer_bytes, long cand_recall, long cand_bytes)
{
    if (peer_recall < cand_recall)
        return 0;
    if (peer_bytes > cand_bytes)
        return 0;
    if (peer_recall == cand_recall && peer_bytes == cand_bytes)
        return 0;
    return 1;
}

static int rx_pareto_ok(const struct rx_job *job)
{
    int candidate;
    int kept = 0;
    int kept_id = -1;
    for (candidate = 0; candidate <= 5; candidate++) {
        int peer;
        int lost = 0;
        for (peer = 0; peer <= 5; peer++) {
            if (rx_dominates(job->recall[peer], job->bytes[peer],
                             job->recall[candidate], job->bytes[candidate]))
                lost = 1;
        }
        if (lost)
            continue;
        kept++;
        kept_id = candidate;
    }
    return kept == 1 && kept_id == 0;
}

static int rx_show(const char *path)
{
    FILE *file = fopen(path, "r");
    char buf[2048];
    if (file == NULL)
        return -1;
    while (fgets(buf, sizeof buf, file) != NULL) {
        if (fputs(buf, stdout) == EOF) {
            fclose(file);
            return -1;
        }
    }
    fclose(file);
    return fflush(stdout) == 0 ? 0 : -1;
}

static void rx_emit(const char *receipt, const char *batch, const char *evaluator,
                    const char *jsonq, const char *source, const char *transcript)
{
    printf("{\"schema\":\"zcl.retrieval_prefix_sweep.v1\","
           "\"input_receipt_sha3\":\"%s\","
           "\"reconstructed_batch_sha3\":\"%s\","
           "\"evaluator_binary_sha3\":\"%s\","
           "\"json_parser_binary_sha3\":\"%s\","
           "\"sweep_script_sha3\":\"%s\","
           "\"candidate_transcript_sha3\":\"%s\","
           "\"prefixes_evaluated\":6,\"tasks_evaluated\":9,"
           "\"primary_metric\":\"recall_at_5\","
           "\"cost_metric\":\"projected_context_bytes_at_5\","
           "\"pareto_prefixes\":[0],"
           "\"selection_status\":\"retain_for_replication_not_promotion\","
           "\"replication_status\":\"not_run\","
           "\"promotion_authorized\":false}\n",
           receipt, batch, evaluator, jsonq, source, transcript);
}

static int rx_finish(struct rx_job *job)
{
    char receipt[80];
    char batch[80];
    char evaluator[80];
    char jsonq[80];
    char source[80];
    char transcript[80];
    if (!rx_pareto_ok(job))
        return rx_fail("reviewed Pareto known answer changed");
    if (rx_show(job->transcript) != 0)
        return rx_fail("cannot read transcript");
    if (rx_hash(job->tools->sha3, job->tools->receipt, receipt, sizeof receipt) != 0)
        return rx_fail("cannot hash receipt");
    if (rx_hash(job->tools->sha3, job->batch, batch, sizeof batch) != 0)
        return rx_fail("cannot hash reconstructed batch");
    if (rx_hash(job->tools->sha3, job->tools->evaluator, evaluator, sizeof evaluator) != 0)
        return rx_fail("cannot hash evaluator");
    if (rx_hash(job->tools->sha3, job->tools->sweep_source, source, sizeof source) != 0)
        return rx_fail("cannot hash sweep script");
    if (rx_hash(job->tools->sha3, job->tools->jsonq, jsonq, sizeof jsonq) != 0)
        return rx_fail("cannot hash JSON parser");
    if (rx_hash(job->tools->sha3, job->transcript, transcript, sizeof transcript) != 0)
        return rx_fail("cannot hash transcript");
    rx_emit(receipt, batch, evaluator, jsonq, source, transcript);
    return 0;
}

static int rx_workdir(struct rx_job *job)
{
    const char *base = getenv("TMPDIR");
    char templ[PATH_MAX];
    int n;
    if (base == NULL || base[0] == '\0')
        base = "/tmp";
    n = snprintf(templ, sizeof templ, "%s/%s.XXXXXX", base, "z23-retrieval-prefix-sweep");
    if (n < 0 || (size_t)n >= sizeof templ)
        return -1;
    if (mkdtemp(templ) == NULL)
        return -1;
    if (strlen(templ) >= sizeof job->tmp)
        return -1;
    memcpy(job->tmp, templ, strlen(templ) + 1);
    return 0;
}

static void rx_wipe(const char *dir)
{
    DIR *handle = opendir(dir);
    if (handle == NULL)
        return;
    for (;;) {
        struct dirent *ent = readdir(handle);
        char path[PATH_MAX];
        int n;
        if (ent == NULL)
            break;
        if (ent->d_name[0] == '.')
            continue;
        n = snprintf(path, sizeof path, "%s/%s", dir, ent->d_name);
        if (n > 0 && (size_t)n < sizeof path)
            unlink(path);
    }
    closedir(handle);
    rmdir(dir);
}

static void rx_end(struct rx_job *job)
{
    if (job->tmp[0] != '\0')
        rx_wipe(job->tmp);
    job->tmp[0] = '\0';
}

static int rx_begin(struct rx_job *job, const struct zcl_rx_tools *tools)
{
    char *argv[4];
    int status = 1;
    int built;
    job->tools = tools;
    if (rx_workdir(job) != 0)
        return rx_fail("cannot create a work directory");
    argv[0] = (char *)tools->checker;
    argv[1] = "--emit-evaluator-batches";
    argv[2] = job->tmp;
    argv[3] = NULL;
    if (rx_launch(argv, -1, NULL, NULL, 0, &status) != 0 || status != 0)
        return rx_fail("frozen parent evidence did not verify or decode");
    if (snprintf(job->batch, sizeof job->batch, "%s/evaluator.batch", job->tmp) >=
        (int)sizeof job->batch)
        return rx_fail("frozen parent evidence did not verify or decode");
    if (snprintf(job->transcript, sizeof job->transcript, "%s/candidate-transcript.jsonl",
                 job->tmp) >= (int)sizeof job->transcript)
        return rx_fail("frozen parent evidence did not verify or decode");
    built = rx_rebuild(job);
    if (built > 0)
        return rx_fail_task(built);
    if (built != 0)
        return rx_fail("frozen parent evidence did not verify or decode");
    return 0;
}

static int rx_all(struct rx_job *job)
{
    int prefix;
    for (prefix = 0; prefix <= 5; prefix++) {
        if (rx_one(job, prefix) != 0)
            return 1;
    }
    return 0;
}

static int rx_invoke(const char *argv0, int argc, char **argv,
                     const struct zcl_rx_tools *tools)
{
    struct rx_job job;
    int rc = 1;
    memset(&job, 0, sizeof job);
    if (rx_usage(argv0, argc, argv) == 0 && rx_ready(tools) == 0) {
        if (rx_begin(&job, tools) == 0)
            rc = rx_all(&job);
    }
    if (rc == 0)
        rc = rx_finish(&job);
    rx_end(&job);
    return rc;
}

#endif /* !_WIN32 */

int zcl_retrieval_prefix_sweep(const char *argv0, int argc, char **argv,
                               const struct zcl_rx_tools *tools)
{
#if defined(_WIN32)
    (void)argv0;
    (void)argc;
    (void)argv;
    (void)tools;
    return rx_fail("unavailable on Windows");
#else
    return rx_invoke(argv0, argc, argv, tools);
#endif
}
