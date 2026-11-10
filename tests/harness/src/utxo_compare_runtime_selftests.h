/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: qualify actual standalone signal and cleanup ownership bodies. */
#ifndef ZCL_UTXO_COMPARE_RUNTIME_SELFTESTS_H
#define ZCL_UTXO_COMPARE_RUNTIME_SELFTESTS_H
#include <signal.h>
#include <errno.h>
#include <poll.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
/* Wrappers are defined BEFORE the macro substitutions: their normal paths
 * call real syscalls. Only this exact-source twin sees interposition. */
enum ucrt_fault_kind { UCRT_NONE, UCRT_MASK, UCRT_ACTION, UCRT_PENDING };
static struct { enum ucrt_fault_kind kind; unsigned target, calls; } ucrt_fault;
static bool ucrt_fail_once(enum ucrt_fault_kind kind)
{
    if (ucrt_fault.kind != kind || ++ucrt_fault.calls != ucrt_fault.target) return false;
    errno = EIO; return true;
}
static int ucrt_sigaction(int number, const struct sigaction *action, struct sigaction *old)
{
    return ucrt_fail_once(UCRT_ACTION) ? -1 : sigaction(number, action, old);
}
static int ucrt_sigprocmask(int how, const sigset_t *mask, sigset_t *old)
{
    return ucrt_fail_once(UCRT_MASK) ? -1 : sigprocmask(how, mask, old);
}
static int ucrt_sigpending(sigset_t *pending)
{
    return ucrt_fail_once(UCRT_PENDING) ? -1 : sigpending(pending);
}
#define sigaction(...) ucrt_sigaction(__VA_ARGS__)
#define sigprocmask(...) ucrt_sigprocmask(__VA_ARGS__)
#define sigpending(...) ucrt_sigpending(__VA_ARGS__)
#define cli_compare_scope_begin ucrt_scope_begin
#define cli_compare_scope_end ucrt_scope_end
#define cli_compare_reserve ucrt_reserve
#define cli_compare_cleanup ucrt_cleanup
#define cli_compare_scope_cancelled ucrt_scope_cancelled
#include "../../../engine/entry/cli_compare_runtime.c"
#undef cli_compare_scope_cancelled
#undef cli_compare_cleanup
#undef cli_compare_reserve
#undef cli_compare_scope_end
#undef cli_compare_scope_begin
#undef sigpending
#undef sigprocmask
#undef sigaction

struct ucrt_saved {
    struct sigaction original[2], expected[2];
    sigset_t original_mask, expected_mask;
    unsigned saved;
    bool mask_saved;
};
static void ucrt_original_handler(int number) { (void)number; }
static bool ucrt_mask_equal(const sigset_t *a, const sigset_t *b)
{
    for (int number = 1; number < NSIG; number++)
        if (sigismember(a, number) != sigismember(b, number)) return false;
    return true;
}
static bool ucrt_restore(const struct ucrt_saved *saved)
{
    bool ok = true;
    for (unsigned i = 0; i < saved->saved; i++)
        if (sigaction(i ? SIGTERM : SIGINT, &saved->original[i], NULL) != 0) ok = false;
    if (saved->mask_saved && sigprocmask(SIG_SETMASK, &saved->original_mask, NULL) != 0) ok = false;
    return ok;
}
static bool ucrt_prepare(struct ucrt_saved *saved)
{
    memset(saved, 0, sizeof(*saved));
    if (sigprocmask(SIG_SETMASK, NULL, &saved->original_mask) != 0) return false;
    saved->mask_saved = true;
    for (unsigned i = 0; i < 2; i++) {
        if (sigaction(i ? SIGTERM : SIGINT, NULL, &saved->original[i]) != 0) return false;
        saved->saved++;
    }
    struct sigaction action; memset(&action, 0, sizeof(action));
    action.sa_handler = ucrt_original_handler; action.sa_flags = SA_RESTART;
    sigemptyset(&action.sa_mask); sigaddset(&action.sa_mask, SIGUSR2);
    for (unsigned i = 0; i < 2; i++) {
        int number = i ? SIGTERM : SIGINT;
        if (sigaction(number, &action, NULL) != 0 || sigaction(number, NULL, &saved->expected[i]) != 0)
            return false;
    }
    saved->expected_mask = saved->original_mask;
    sigdelset(&saved->expected_mask, SIGINT); sigdelset(&saved->expected_mask, SIGTERM);
    sigaddset(&saved->expected_mask, SIGUSR1);
    return sigprocmask(SIG_SETMASK, &saved->expected_mask, NULL) == 0;
}
static bool ucrt_restored(const struct ucrt_saved *saved)
{
    sigset_t mask;
    if (sigprocmask(SIG_SETMASK, NULL, &mask) != 0 || !ucrt_mask_equal(&mask, &saved->expected_mask)) return false;
    for (unsigned i = 0; i < 2; i++) {
        struct sigaction action;
        if (sigaction(i ? SIGTERM : SIGINT, NULL, &action) != 0 ||
            action.sa_handler != saved->expected[i].sa_handler || action.sa_flags != saved->expected[i].sa_flags ||
            !ucrt_mask_equal(&action.sa_mask, &saved->expected[i].sa_mask)) return false;
    }
    return true;
}
static void ucrt_arm(enum ucrt_fault_kind kind, unsigned target)
{
    ucrt_fault.kind = kind; ucrt_fault.target = target; ucrt_fault.calls = 0;
}
static unsigned ucrt_expected_calls(enum ucrt_fault_kind kind, unsigned target, bool ending)
{
    if (ending) return kind == UCRT_PENDING ? 1u : 2u;
    if (kind == UCRT_MASK) return target == 1 ? 1u : 4u;
    return target == 1 ? 1u : 3u;
}
static bool ucrt_fault_case(enum ucrt_fault_kind kind, unsigned target, bool ending)
{
    struct ucrt_saved saved; struct cli_compare_signals state = {0};
    bool prepared = ucrt_prepare(&saved), began = false, result = false;
    ucrt_arm(UCRT_NONE, 0);
    if (prepared && ending) began = ucrt_scope_begin(&state);
    ucrt_arm(kind, target);
    if (prepared && (!ending || began)) {
        if (ending) result = !ucrt_scope_end(&state);
        else {
            result = !ucrt_scope_begin(&state);
            bool rolled_back = ucrt_scope_end(&state);
            result = result && rolled_back;
        }
    }
    bool injected = ucrt_fault.calls >= target &&
        ucrt_fault.calls == ucrt_expected_calls(kind, target, ending);
    ucrt_arm(UCRT_NONE, 0);
    /* Successful begin rollback must restore exact initial state. End-fault
     * cases intentionally may not; repair them with real syscalls before exit. */
    bool observation = ending || ucrt_restored(&saved);
    bool repaired = ucrt_restore(&saved);
    return prepared && result && injected && observation && repaired;
}
static bool ucrt_release_ok(void **owner)
{
    unsigned *calls = *owner; ++*calls; *owner = NULL; return true;
}
static bool ucrt_release_terminal(void **owner)
{
    unsigned *calls = *owner; ++*calls; *owner = NULL; return false;
}
static bool ucrt_release_retry(void **owner)
{
    unsigned *calls = *owner;
    if (++*calls == 1) return false;
    *owner = NULL; return true;
}
static bool ucrt_capsule_first(const struct cli_compare_signals *state,
                               const unsigned *first, unsigned second, bool retained)
{
    return *first == 1 && second == 1 && state->slots[0].release_failed &&
        !state->slots[1].release_failed && state->slots[1].owner == NULL &&
        state->slots[0].owner == (retained ? first : NULL);
}
static bool ucrt_capsule_case(bool retained)
{
    struct cli_compare_signals state = {0}; unsigned first = 0, second = 0;
    state.slots[0].owner = &first;
    state.slots[0].release = retained ? ucrt_release_retry : ucrt_release_terminal;
    state.slots[1].owner = &second; state.slots[1].release = ucrt_release_ok;
    bool one = !ucrt_cleanup(&state) && ucrt_capsule_first(&state, &first, second, retained);
    bool two = !ucrt_cleanup(&state) && state.slots[0].owner == NULL &&
        state.slots[1].owner == NULL && state.slots[0].release_failed &&
        first == (retained ? 2u : 1u) && second == 1;
    return one && two;
}
static bool ucrt_nested_distinct(bool began, struct cli_compare_signals *fresh,
                                  const struct cli_compare_signals *original,
                                  const unsigned char *snapshot)
{
    unsigned char zero[sizeof(*fresh)]; memcpy(zero, fresh, sizeof(*fresh));
    return began && !ucrt_scope_begin(fresh) &&
        memcmp(zero, fresh, sizeof(*fresh)) == 0 && ucrt_scope_end(fresh) &&
        !ucrt_scope_begin(fresh) && memcmp(snapshot, original, sizeof(*original)) == 0;
}
static bool ucrt_nested_cleanup(struct cli_compare_signals *original,
                                 struct ucrt_saved *saved, bool began, const unsigned *calls)
{
    bool released = ucrt_cleanup(original);
    bool ended = ucrt_scope_end(original);
    bool restored = !began || ucrt_restored(saved);
    bool repaired = ucrt_restore(saved);
    return released && *calls == 1 && ended && restored && repaired;
}
static bool ucrt_nested_case(void)
{
    struct ucrt_saved saved; struct cli_compare_signals original = {0}, fresh = {0};
    struct zcl_command_cleanup_slot *slots = NULL; unsigned calls = 0;
    bool prepared = ucrt_prepare(&saved);
    bool began = prepared && ucrt_scope_begin(&original);
    bool reserved = began && ucrt_reserve(&original, 2, &slots);
    if (reserved) { slots[0].owner = &calls; slots[0].release = ucrt_release_ok; }
    unsigned char snapshot[sizeof(original)]; memcpy(snapshot, &original, sizeof(original));
    bool refused = reserved && !ucrt_scope_begin(&original) &&
        memcmp(snapshot, &original, sizeof(original)) == 0 && slots[0].owner == &calls;
    /* Never end a refused same-context attempt: original is still acquired. */
    bool distinct = ucrt_nested_distinct(began, &fresh, &original, snapshot);
    bool null_refused = !ucrt_scope_begin(NULL);
    bool cleaned = ucrt_nested_cleanup(&original, &saved, began, &calls);
    return prepared && refused && distinct && null_refused && cleaned;
}
static bool ucrt_blocked_case(void)
{
    struct ucrt_saved saved; struct cli_compare_signals state = {0};
    bool prepared = ucrt_prepare(&saved);
    sigset_t blocked = saved.expected_mask; sigaddset(&blocked, SIGINT);
    bool changed = prepared && sigprocmask(SIG_SETMASK, &blocked, NULL) == 0;
    bool refused = changed && !ucrt_scope_begin(&state);
    bool ended = ucrt_scope_end(&state); sigset_t actual;
    bool preserved = sigprocmask(SIG_SETMASK, NULL, &actual) == 0 && ucrt_mask_equal(&actual, &blocked);
    bool repaired = ucrt_restore(&saved);
    return changed && refused && ended && preserved && repaired;
}
static int64_t ucrt_now_ms(void)
{
    struct timespec now;
    return clock_gettime(CLOCK_MONOTONIC, &now) == 0 ?
        (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000 : -1;
}
static bool ucrt_read_byte(int fd, char *byte)
{
    int64_t start = ucrt_now_ms();
    if (start < 0) return false;
    for (;;) {
        int64_t now = ucrt_now_ms();
        if (now < 0 || now - start >= 2000) return false;
        struct pollfd p = {.fd = fd, .events = POLLIN};
        int ready = poll(&p, 1, (int)(2000 - (now - start)));
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) return false;
        ssize_t n = read(fd, byte, 1);
        if (n < 0 && errno == EINTR) continue;
        return n == 1;
    }
}
enum ucrt_reap_outcome { UCRT_REAPED, UCRT_REAP_DEADLINE, UCRT_REAP_ERROR };
static enum ucrt_reap_outcome ucrt_reap(pid_t child, int *status, int *error)
{
    int64_t started = ucrt_now_ms();
    *error = 0;
    if (started < 0) { *error = errno; return UCRT_REAP_ERROR; }
    for (;;) {
        pid_t got = waitpid(child, status, WNOHANG);
        if (got == child) return UCRT_REAPED;
        if (got < 0 && errno != EINTR) { *error = errno; return UCRT_REAP_ERROR; }
        int64_t now = ucrt_now_ms();
        if (now < 0) { *error = errno; return UCRT_REAP_ERROR; }
        if (now - started > 3000) return UCRT_REAP_DEADLINE;
        (void)poll(NULL, 0, 10);
    }
}
static void ucrt_custody_failure(pid_t child, enum ucrt_reap_outcome outcome,
                                 int wait_error, bool kill_attempted, int kill_error)
{
    /* child_run captures stderr and treats exit2 as group failure. Do not
     * return to later cases after losing fixture-child custody. This does
     * not claim cleanup or transfer to another owner has completed. */
    fprintf(stderr, "ucrt fixture terminal failure: child_pid=%lld custody=%s "
        "wait_outcome=%d wait_errno=%d kill_attempted=%d kill_errno=%d group_exit=2\n",
        (long long)child, outcome == UCRT_REAP_ERROR ? "unknown" : "unreaped",
        (int)outcome, wait_error, (int)kill_attempted, kill_error);
    fflush(stderr);
    _exit(2);
}
static bool ucrt_finish_child(pid_t child, int *status)
{
    if (child <= 0) return false;
    int wait_error = 0;
    enum ucrt_reap_outcome outcome = ucrt_reap(child, status, &wait_error);
    if (outcome == UCRT_REAPED) return true;
    /* ECHILD/other wait errors do not establish a live owned PID. Never send
     * a signal after ownership becomes uncertain (PID reuse could target a
     * stranger). This fixture process has no other child-reaping thread. */
    if (outcome == UCRT_REAP_ERROR)
        ucrt_custody_failure(child, outcome, wait_error, false, 0);
    int killed = kill(child, SIGKILL);
    int kill_error = killed == 0 ? 0 : errno;
    outcome = ucrt_reap(child, status, &wait_error);
    if (outcome != UCRT_REAPED)
        ucrt_custody_failure(child, outcome, wait_error, true, kill_error);
    fprintf(stderr, "ucrt fixture deadline failure: child_pid=%lld custody=reaped "
        "kill_errno=%d\n", (long long)child, kill_error);
    return false; /* A killed deadline case never passes its original test. */
}
static bool ucrt_signal_child(int ready_fd)
{
    struct ucrt_saved saved; struct cli_compare_signals state = {0};
    bool prepared = ucrt_prepare(&saved), began = prepared && ucrt_scope_begin(&state);
    bool handshake = began && write(ready_fd, "R", 1) == 1;
    int64_t start = ucrt_now_ms();
    while (handshake && !ucrt_scope_cancelled(&state)) {
        int64_t now = ucrt_now_ms();
        if (start < 0 || now < 0 || now - start > 1000) { handshake = false; break; }
        (void)poll(NULL, 0, 5);
    }
    bool cancelled = began && ucrt_scope_cancelled(&state);
    bool ended = ucrt_scope_end(&state);
    bool restored = !began || ucrt_restored(&saved);
    bool repaired = ucrt_restore(&saved);
    return handshake && cancelled && ended && restored && repaired;
}
static bool ucrt_signal_case(int number)
{
    int ready[2];
    if (pipe(ready) != 0) return false;
    pid_t child = fork();
    if (child == 0) {
        close(ready[0]);
        bool ok = ucrt_signal_child(ready[1]);
        close(ready[1]); _exit(ok ? 0 : 1);
    }
    close(ready[1]); char byte = 0; int status = 0;
    bool observed = child > 0 && ucrt_read_byte(ready[0], &byte) && byte == 'R' && kill(child, number) == 0;
    close(ready[0]);
    bool reaped = ucrt_finish_child(child, &status);
    return observed && reaped && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
static bool ucrt_isolated_case(unsigned mode, enum ucrt_fault_kind kind, unsigned target)
{
    pid_t child = fork();
    if (child == 0) {
        bool ok = mode == 0 ? ucrt_fault_case(kind, target, false) :
            mode == 1 ? ucrt_fault_case(kind, target, true) :
            mode == 2 ? ucrt_nested_case() : mode == 3 ? ucrt_blocked_case() :
            ucrt_capsule_case(mode == 5);
        _exit(ok ? 0 : 1);
    }
    int status = 0; bool reaped = ucrt_finish_child(child, &status);
    return reaped && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
static int csi_compare_runtime_cases(void)
{
    int failures = 0;
    CSI_CHECK("standalone actual scope observes real SIGINT and restores inherited state", ucrt_signal_case(SIGINT));
    CSI_CHECK("standalone actual scope observes real SIGTERM and restores inherited state", ucrt_signal_case(SIGTERM));
    const enum ucrt_fault_kind begin_kind[] = {UCRT_MASK, UCRT_ACTION, UCRT_ACTION, UCRT_MASK};
    const unsigned begin_at[] = {1, 1, 2, 2};
    for (unsigned i = 0; i < 4; i++) {
        char label[96]; snprintf(label, sizeof(label), "standalone begin fail-once rollback stage %u", i);
        CSI_CHECK(label, ucrt_isolated_case(0, begin_kind[i], begin_at[i]));
    }
    const enum ucrt_fault_kind end_kind[] = {UCRT_MASK, UCRT_PENDING, UCRT_ACTION, UCRT_ACTION, UCRT_MASK};
    const unsigned end_at[] = {1, 1, 1, 2, 2};
    for (unsigned i = 0; i < 5; i++) {
        char label[96]; snprintf(label, sizeof(label), "standalone end fail-once refuses stage %u", i);
        CSI_CHECK(label, ucrt_isolated_case(1, end_kind[i], end_at[i]));
    }
    CSI_CHECK("standalone active same-context refusal preserves owner; fresh refusal ends safely", ucrt_isolated_case(2, UCRT_NONE, 0));
    CSI_CHECK("standalone inherited blocked cancellation refuses and preserves mask", ucrt_isolated_case(3, UCRT_NONE, 0));
    CSI_CHECK("standalone actual capsule terminal false-NULL is sticky and visits both slots", ucrt_isolated_case(4, UCRT_NONE, 0));
    CSI_CHECK("standalone actual capsule retains then releases owner without clearing failure", ucrt_isolated_case(5, UCRT_NONE, 0));
    return failures;
}
#endif
