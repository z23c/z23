/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#define _GNU_SOURCE
#include "util/cpu_topology.h"

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef __ANDROID__
#error This acceptance test requires Android Bionic.
#endif

static atomic_bool release_worker;
static atomic_bool worker_ready;
static int worker_affinity_rc;
static cpu_set_t worker_before;
static cpu_set_t worker_after;

static void *worker(void *unused)
{
    (void)unused;
    worker_affinity_rc = sched_getaffinity(0, sizeof(worker_before), &worker_before);
    atomic_store(&worker_ready, true);
    while (!atomic_load(&release_worker)) {
        struct timespec delay = { .tv_nsec = 1000000L };
        (void)nanosleep(&delay, NULL);
    }
    if (sched_getaffinity(0, sizeof(worker_after), &worker_after) != 0)
        worker_affinity_rc = -1;
    return NULL;
}

static bool cache_fixture(const char *root, int cpu, const char *members)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/cpu%d/cache", root, cpu);
    if (mkdir(path, 0700) != 0) return false;
    snprintf(path, sizeof(path), "%s/cpu%d/cache/index0", root, cpu);
    if (mkdir(path, 0700) != 0) return false;
    const char *names[] = { "level", "size", "shared_cpu_list" };
    const char *values[] = { "3", "1024K", members };
    for (int i = 0; i < 3; ++i) {
        snprintf(path, sizeof(path), "%s/cpu%d/cache/index0/%s", root, cpu, names[i]);
        FILE *file = fopen(path, "w");
        if (!file) return false;
        bool ok = fprintf(file, "%s\n", values[i]) > 0;
        if (fclose(file) != 0) ok = false;
        if (!ok) return false;
    }
    return true;
}

static void remove_fixture(const char *root, int last_cpu)
{
    char path[256];
    const char *names[] = { "level", "size", "shared_cpu_list" };
    for (int cpu = 0; cpu <= last_cpu; ++cpu) {
        for (int i = 0; i < 3; ++i) {
            snprintf(path, sizeof(path), "%s/cpu%d/cache/index0/%s", root, cpu, names[i]);
            (void)unlink(path);
        }
        snprintf(path, sizeof(path), "%s/cpu%d/cache/index0", root, cpu);
        (void)rmdir(path);
        snprintf(path, sizeof(path), "%s/cpu%d/cache", root, cpu);
        (void)rmdir(path);
        snprintf(path, sizeof(path), "%s/cpu%d", root, cpu);
        (void)rmdir(path);
    }
    (void)rmdir(root);
}

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); \
        goto cleanup; \
    } \
} while (0)

static int select_cpu(const cpu_set_t *allowed)
{
    for (int cpu = 0; cpu < CPU_SETSIZE && cpu < CPU_TOPOLOGY_MAX_CPUS; ++cpu) {
        if (CPU_ISSET(cpu, allowed)) return cpu;
    }
    return -1;
}

static bool populate_fixture(const char *root, int selected)
{
    char path[256], members[32];
    for (int cpu = 0; cpu <= selected; ++cpu) {
        snprintf(path, sizeof(path), "%s/cpu%d", root, cpu);
        CHECK(mkdir(path, 0700) == 0);
    }
    if (selected > 0) {
        snprintf(members, sizeof(members), "0-%d", selected - 1);
        CHECK(cache_fixture(root, 0, members));
    }
    snprintf(members, sizeof(members), "%d", selected);
    CHECK(cache_fixture(root, selected, members));
    return true;
cleanup:
    return false;
}

static bool wait_worker_ready(void)
{
    struct timespec deadline;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &deadline) == 0);
    deadline.tv_sec += 2;
    while (!atomic_load(&worker_ready)) {
        struct timespec now;
        CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
        CHECK(now.tv_sec < deadline.tv_sec ||
              (now.tv_sec == deadline.tv_sec && now.tv_nsec < deadline.tv_nsec));
        struct timespec delay = { .tv_nsec = 1000000L };
        (void)nanosleep(&delay, NULL);
    }
    return worker_affinity_rc == 0;
cleanup:
    return false;
}

static int finish_worker(pthread_t thread)
{
    atomic_store(&release_worker, true);
    if (pthread_join(thread, NULL) != 0 || worker_affinity_rc != 0 ||
        !CPU_EQUAL(&worker_before, &worker_after)) return 1;
    return 0;
}

static int restore_affinity(const cpu_set_t *original)
{
    cpu_set_t observed;
    if (sched_setaffinity(0, sizeof(*original), original) != 0 ||
        sched_getaffinity(0, sizeof(observed), &observed) != 0 ||
        !CPU_EQUAL(original, &observed)) return 1;
    return 0;
}

int main(void)
{
    int status = 1;
    int selected = -1;
    bool have_original = false;
    bool have_fixture = false;
    bool have_worker = false;
    pthread_t thread;
    cpu_set_t original, observed, expected;
    char root[] = "/data/local/tmp/z23-affinity-XXXXXX";

    CHECK(sched_getaffinity(0, sizeof(original), &original) == 0);
    have_original = true;
    selected = select_cpu(&original);
    CHECK(selected >= 0);
    CHECK(mkdtemp(root) != NULL);
    have_fixture = true;
    CHECK(populate_fixture(root, selected));
    cpu_topology_set_sysfs_root_for_testing(root);
    CHECK(cpu_topology_init());
    int domain = cpu_topology_domain_of(selected);
    CHECK(domain >= 0);

    /* raw-pthread-ok: standalone test owns the complete worker lifecycle. */
    CHECK(pthread_create(&thread, NULL, worker, NULL) == 0);
    have_worker = true;
    CHECK(wait_worker_ready());
    CHECK(!cpu_topology_pin_thread(thread, domain));
    CHECK(sched_getaffinity(0, sizeof(observed), &observed) == 0);
    CHECK(CPU_EQUAL(&observed, &original));
    CHECK(cpu_topology_pin_thread(pthread_self(), domain));
    CPU_ZERO(&expected);
    CPU_SET(selected, &expected);
    CHECK(sched_getaffinity(0, sizeof(observed), &observed) == 0);
    CHECK(CPU_EQUAL(&observed, &expected));
    status = 0;

cleanup:
    if (have_worker) status |= finish_worker(thread);
    if (have_original) status |= restore_affinity(&original);
    if (have_fixture) remove_fixture(root, selected);
    if (status == 0)
        puts("PASS Android CPU affinity: self placement, foreign refusal, masks restored");
    return status;
}
