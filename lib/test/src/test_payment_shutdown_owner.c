#define _DEFAULT_SOURCE
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Store-payment lifecycle acceptance. The payment worker writes through the
 * canonical node.db lane, so frontend teardown must remain independent while
 * runtime teardown retains DB and state ownership until the worker joins. */

#include "config/boot_internal.h"
#include "kernel/service_kernel.h"
#include "test/test_core.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

struct payment_shutdown_fixture {
    struct zcl_service_kernel frontend;
    struct zcl_service_kernel runtime;
    pthread_t payment_thread;
    pthread_t shutdown_thread;
    pthread_mutex_t mutex;
    pthread_cond_t release_cond;
    _Atomic bool running;
    _Atomic bool callback_entered;
    _Atomic bool frontend_stopped;
    _Atomic bool runtime_stop_entered;
    _Atomic bool runtime_stop_done;
    _Atomic bool db_closed;
    _Atomic bool state_released;
    _Atomic bool resource_race;
    bool release_callback;
    bool payment_started;
    bool shutdown_started;
};

static bool payment_fixture_wait(_Atomic bool *value)
{
    for (int i = 0; i < 200 && !atomic_load(value); i++)
        usleep(5000);
    return atomic_load(value);
}

static void *payment_fixture_db_callback(void *arg)
{
    struct payment_shutdown_fixture *fixture = arg;

    atomic_store(&fixture->callback_entered, true);
    pthread_mutex_lock(&fixture->mutex);
    while (!fixture->release_callback)
        pthread_cond_wait(&fixture->release_cond, &fixture->mutex);
    pthread_mutex_unlock(&fixture->mutex);

    if (atomic_load(&fixture->db_closed) ||
        atomic_load(&fixture->state_released))
        atomic_store(&fixture->resource_race, true);
    return NULL;
}

static bool payment_fixture_start(void *arg)
{
    struct payment_shutdown_fixture *fixture = arg;

    if (!atomic_load(&fixture->running))
        return false;
    if (pthread_create(&fixture->payment_thread, NULL,
                       payment_fixture_db_callback, fixture) != 0)
        return false;
    fixture->payment_started = true;
    return true;
}

static void payment_fixture_stop(void *arg)
{
    struct payment_shutdown_fixture *fixture = arg;

    atomic_store(&fixture->runtime_stop_entered, true);
    if (fixture->payment_started) {
        pthread_join(fixture->payment_thread, NULL);
        fixture->payment_started = false;
    }
    atomic_store(&fixture->runtime_stop_done, true);
}

static bool frontend_fixture_start(void *arg)
{
    return arg != NULL;
}

static void frontend_fixture_stop(void *arg)
{
    struct payment_shutdown_fixture *fixture = arg;
    atomic_store(&fixture->frontend_stopped, true);
}

static void *payment_fixture_runtime_shutdown(void *arg)
{
    struct payment_shutdown_fixture *fixture = arg;

    zcl_service_kernel_stop_all(&fixture->runtime);
    atomic_store(&fixture->db_closed, true);
    atomic_store(&fixture->state_released, true);
    return NULL;
}

static void payment_fixture_release(struct payment_shutdown_fixture *fixture)
{
    pthread_mutex_lock(&fixture->mutex);
    fixture->release_callback = true;
    pthread_cond_broadcast(&fixture->release_cond);
    pthread_mutex_unlock(&fixture->mutex);
}

static bool payment_shutdown_lifecycle_acceptance(void)
{
    struct payment_shutdown_fixture fixture;
    memset(&fixture, 0, sizeof(fixture));
    atomic_init(&fixture.running, false);
    atomic_init(&fixture.callback_entered, false);
    atomic_init(&fixture.frontend_stopped, false);
    atomic_init(&fixture.runtime_stop_entered, false);
    atomic_init(&fixture.runtime_stop_done, false);
    atomic_init(&fixture.db_closed, false);
    atomic_init(&fixture.state_released, false);
    atomic_init(&fixture.resource_race, false);
    if (pthread_mutex_init(&fixture.mutex, NULL) != 0)
        return false;
    if (pthread_cond_init(&fixture.release_cond, NULL) != 0) {
        pthread_mutex_destroy(&fixture.mutex);
        return false;
    }

    bool ok = !payment_fixture_start(&fixture) &&
              !fixture.payment_started;
    zcl_service_kernel_init(&fixture.frontend);
    zcl_service_kernel_init(&fixture.runtime);
    const struct zcl_service_spec frontend = {
        .name = "rpc_frontend",
        .start = frontend_fixture_start,
        .stop = frontend_fixture_stop,
        .ctx = &fixture,
    };
    const struct zcl_service_spec payment = {
        .name = "store_payment",
        .start = payment_fixture_start,
        .stop = payment_fixture_stop,
        .ctx = &fixture,
    };
    ok = ok && zcl_service_kernel_register(&fixture.frontend, &frontend) &&
         zcl_service_kernel_register(&fixture.runtime, &payment);

    atomic_store(&fixture.running, true);
    ok = ok && zcl_service_kernel_start_all(&fixture.frontend) &&
         zcl_service_kernel_start_all(&fixture.runtime) &&
         payment_fixture_wait(&fixture.callback_entered);

    zcl_service_kernel_stop_all(&fixture.frontend);
    ok = ok && atomic_load(&fixture.frontend_stopped) &&
         !atomic_load(&fixture.runtime_stop_entered) &&
         !atomic_load(&fixture.db_closed) &&
         !atomic_load(&fixture.state_released);

    if (pthread_create(&fixture.shutdown_thread, NULL,
                       payment_fixture_runtime_shutdown, &fixture) == 0) {
        fixture.shutdown_started = true;
        ok = ok && payment_fixture_wait(&fixture.runtime_stop_entered) &&
             !atomic_load(&fixture.runtime_stop_done) &&
             !atomic_load(&fixture.db_closed) &&
             !atomic_load(&fixture.state_released);
    } else {
        ok = false;
    }

    payment_fixture_release(&fixture);
    if (fixture.shutdown_started) {
        if (pthread_join(fixture.shutdown_thread, NULL) != 0)
            ok = false;
        fixture.shutdown_started = false;
    } else if (fixture.payment_started) {
        payment_fixture_stop(&fixture);
    }

    ok = ok && atomic_load(&fixture.runtime_stop_done) &&
         atomic_load(&fixture.db_closed) &&
         atomic_load(&fixture.state_released) &&
         !atomic_load(&fixture.resource_race);
    pthread_cond_destroy(&fixture.release_cond);
    pthread_mutex_destroy(&fixture.mutex);
    return ok;
}

static bool payment_production_registration_acceptance(void)
{
    _Atomic bool running = false;
    struct app_context app = {
        .runtime_profile = ZCL_RUNTIME_FULL,
    };
    struct boot_svc_ctx svc = {
        .running = &running,
        .app_ctx = &app,
    };

    zcl_service_kernel_init(&svc.frontend_kernel);
    zcl_service_kernel_init(&svc.runtime_kernel);
    if (!boot_register_store_payment_runtime(&svc))
        return false;
    const struct zcl_service_entry *payment = zcl_service_kernel_find(
        &svc.runtime_kernel, "store_payment");
    if (!payment || zcl_service_kernel_find(&svc.frontend_kernel,
                                             "store_payment"))
        return false;
    if (payment->spec.start(&svc) || svc.payment_thread_started)
        return false;
    return true;
}

int test_payment_shutdown_owner(void)
{
    int failures = 0;
    TEST("payment shutdown: runtime owns DB-writing payment work") {
        ASSERT(payment_production_registration_acceptance());
        ASSERT(payment_shutdown_lifecycle_acceptance());
        PASS();
    } _test_next:;
    return failures;
}
