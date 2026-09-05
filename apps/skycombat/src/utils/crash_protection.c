/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <execinfo.h>
#include <unistd.h>
#include <sys/resource.h>
#include <math.h>

// Enhanced signal handler for catching crashes
static void crash_handler(int sig, siginfo_t *info, void *context) {
    // Use write() instead of printf() - signal safe
    const char *msg = "\n=== CRASH PROTECTION ACTIVATED ===\n";
    write(STDERR_FILENO, msg, strlen(msg));
    
    // Signal type
    char sig_msg[128];
    snprintf(sig_msg, sizeof(sig_msg), "Signal: %d (", sig);
    write(STDERR_FILENO, sig_msg, strlen(sig_msg));
    
    switch(sig) {
        case SIGSEGV:
            write(STDERR_FILENO, "Segmentation fault", 18);
            break;
        case SIGFPE:
            write(STDERR_FILENO, "Floating point exception", 24);
            break;
        case SIGBUS:
            write(STDERR_FILENO, "Bus error", 9);
            break;
        case SIGILL:
            write(STDERR_FILENO, "Illegal instruction", 19);
            break;
        case SIGABRT:
            write(STDERR_FILENO, "Abort", 5);
            break;
        default:
            write(STDERR_FILENO, "Unknown", 7);
            break;
    }
    write(STDERR_FILENO, ")\n", 2);
    
    // Additional info for SIGSEGV and SIGBUS
    if (sig == SIGSEGV || sig == SIGBUS) {
        char addr_msg[128];
        snprintf(addr_msg, sizeof(addr_msg), "Fault address: %p\n", info->si_addr);
        write(STDERR_FILENO, addr_msg, strlen(addr_msg));
    }
    
    // Backtrace
    write(STDERR_FILENO, "\nBacktrace:\n", 12);
    void *buffer[30];
    int nptrs = backtrace(buffer, 30);
    backtrace_symbols_fd(buffer, nptrs, STDERR_FILENO);
    
    // Graceful exit message
    write(STDERR_FILENO, "\nSafety system prevented crash!\n", 32);
    write(STDERR_FILENO, "Exiting cleanly...\n", 19);
    
    // Exit cleanly instead of dumping core
    _exit(1);
}

// Initialize crash protection
void crash_protection_init(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    
    sa.sa_sigaction = crash_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    
    // Install handlers for common crash signals
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    
    // Disable core dumps
    struct rlimit rlim = {0, 0};
    setrlimit(RLIMIT_CORE, &rlim);
}

// Cleanup function
void crash_protection_cleanup(void) {
    // Reset signal handlers to default
    signal(SIGSEGV, SIG_DFL);
    signal(SIGFPE, SIG_DFL);
    signal(SIGBUS, SIG_DFL);
    signal(SIGILL, SIG_DFL);
    signal(SIGABRT, SIG_DFL);
}

// Safe division helpers
float safe_divide_f(float numerator, float denominator) {
    if (fabsf(denominator) < 0.0001f) {
        return 0.0f;
    }
    return numerator / denominator;
}

int safe_divide_i(int numerator, int denominator) {
    if (denominator == 0) {
        return 0;
    }
    return numerator / denominator;
}

// Safe math operations
float safe_asinf(float value) {
    if (value < -1.0f) value = -1.0f;
    if (value > 1.0f) value = 1.0f;
    return asinf(value);
}

float safe_acosf(float value) {
    if (value < -1.0f) value = -1.0f;
    if (value > 1.0f) value = 1.0f;
    return acosf(value);
}

float safe_sqrtf(float value) {
    if (value < 0.0f) value = 0.0f;
    return sqrtf(value);
}