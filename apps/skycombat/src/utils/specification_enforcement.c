/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sky_combat/specification_enforcement.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <string.h>

// ============================================================================
// SPECIFICATION MONITORING STATE
// ============================================================================

typedef struct {
    bool initialized;
    unsigned long violations_caught;
    unsigned long specifications_verified;
    char current_critical_section[64];
    FILE* spec_log;
} spec_monitor_state_t;

static spec_monitor_state_t g_spec_monitor = {0};

// ============================================================================
// INITIALIZATION
// ============================================================================

void spec_enforcement_init(void) {
    if (g_spec_monitor.initialized) return;
    
    g_spec_monitor.initialized = true;
    g_spec_monitor.violations_caught = 0;
    g_spec_monitor.specifications_verified = 0;
    
    // Open specification log
    g_spec_monitor.spec_log = fopen("specifications.log", "a");
    if (g_spec_monitor.spec_log) {
        fprintf(g_spec_monitor.spec_log, 
                "\n=== SPECIFICATION ENFORCEMENT STARTED ===\n");
        fprintf(g_spec_monitor.spec_log, "Time: %ld\n", time(NULL));
        fflush(g_spec_monitor.spec_log);
    }
    
    // Install safety signal handlers as backup
    signal(SIGSEGV, SIG_DFL);  // Let our crash protection handle it
    signal(SIGFPE, SIG_DFL);
    
    printf("Specification enforcement system initialized\n");
}

// ============================================================================
// VIOLATION HANDLERS
// ============================================================================

void spec_violation_handler(const char* file, int line, const char* condition) {
    g_spec_monitor.violations_caught++;
    
    fprintf(stderr, "\n!!! SPECIFICATION VIOLATION !!!\n");
    fprintf(stderr, "Location: %s:%d\n", file, line);
    fprintf(stderr, "Condition: %s\n", condition);
    fprintf(stderr, "Violations caught: %lu\n", g_spec_monitor.violations_caught);
    
    if (g_spec_monitor.spec_log) {
        fprintf(g_spec_monitor.spec_log, 
                "VIOLATION: %s at %s:%d\n", condition, file, line);
        fflush(g_spec_monitor.spec_log);
    }
    
    // In debug mode, break into debugger
    #ifdef DEBUG
    raise(SIGTRAP);
    #endif
}

void spec_precondition_failed(const char* function, const char* condition) {
    fprintf(stderr, "PRECONDITION FAILED in %s: %s\n", function, condition);
    spec_violation_handler(__FILE__, __LINE__, condition);
}

void spec_postcondition_failed(const char* function, const char* condition) {
    fprintf(stderr, "POSTCONDITION FAILED in %s: %s\n", function, condition);
    spec_violation_handler(__FILE__, __LINE__, condition);
}

void spec_invariant_violated(const char* condition) {
    fprintf(stderr, "INVARIANT VIOLATED: %s\n", condition);
    spec_violation_handler(__FILE__, __LINE__, condition);
    
    // Invariant violations are critical - safe exit
    exit(1);
}

// ============================================================================
// SPECIFIC VIOLATIONS
// ============================================================================

void spec_division_by_zero(void) {
    spec_violation_handler(__FILE__, __LINE__, "division by zero attempted");
}

void spec_array_overflow(void) {
    spec_violation_handler(__FILE__, __LINE__, "array bounds exceeded");
}

void spec_null_deref(void) {
    spec_violation_handler(__FILE__, __LINE__, "null pointer dereference");
}

// ============================================================================
// CRITICAL SECTION MONITORING
// ============================================================================

void spec_enter_critical(const char* name) {
    if (strlen(g_spec_monitor.current_critical_section) > 0) {
        fprintf(stderr, "WARNING: Nested critical section: %s -> %s\n",
                g_spec_monitor.current_critical_section, name);
    }
    
    strncpy(g_spec_monitor.current_critical_section, name, 63);
    g_spec_monitor.current_critical_section[63] = '\0';
    
    if (g_spec_monitor.spec_log) {
        fprintf(g_spec_monitor.spec_log, "ENTER_CRITICAL: %s\n", name);
        fflush(g_spec_monitor.spec_log);
    }
}

void spec_exit_critical(const char* name) {
    if (strcmp(g_spec_monitor.current_critical_section, name) != 0) {
        fprintf(stderr, "ERROR: Critical section mismatch: expected %s, got %s\n",
                g_spec_monitor.current_critical_section, name);
    }
    
    g_spec_monitor.current_critical_section[0] = '\0';
    
    if (g_spec_monitor.spec_log) {
        fprintf(g_spec_monitor.spec_log, "EXIT_CRITICAL: %s\n", name);
        fflush(g_spec_monitor.spec_log);
    }
}

// ============================================================================
// RUNTIME VERIFICATION
// ============================================================================

bool spec_verify_runtime(const char* spec_name, bool condition) {
    g_spec_monitor.specifications_verified++;
    
    if (!condition) {
        fprintf(stderr, "SPECIFICATION FAILED: %s\n", spec_name);
        spec_violation_handler(__FILE__, __LINE__, spec_name);
        return false;
    }
    
    // Log successful verifications periodically
    if (g_spec_monitor.specifications_verified % 1000 == 0) {
        if (g_spec_monitor.spec_log) {
            fprintf(g_spec_monitor.spec_log, 
                    "Verified %lu specifications, caught %lu violations\n",
                    g_spec_monitor.specifications_verified,
                    g_spec_monitor.violations_caught);
            fflush(g_spec_monitor.spec_log);
        }
    }
    
    return true;
}

// ============================================================================
// SPECIFICATION STATISTICS
// ============================================================================

void spec_print_statistics(void) {
    printf("\n=== SPECIFICATION ENFORCEMENT STATISTICS ===\n");
    printf("Specifications verified: %lu\n", g_spec_monitor.specifications_verified);
    printf("Violations caught: %lu\n", g_spec_monitor.violations_caught);
    printf("Success rate: %.2f%%\n", 
           g_spec_monitor.specifications_verified > 0 ?
           (100.0 * (g_spec_monitor.specifications_verified - g_spec_monitor.violations_caught) / 
            g_spec_monitor.specifications_verified) : 100.0);
}

// ============================================================================
// CLEANUP
// ============================================================================

__attribute__((destructor))
void spec_enforcement_cleanup(void) {
    if (g_spec_monitor.spec_log) {
        spec_print_statistics();
        fprintf(g_spec_monitor.spec_log, "\n=== SPECIFICATION ENFORCEMENT ENDED ===\n");
        fprintf(g_spec_monitor.spec_log, "Total verified: %lu\n", 
                g_spec_monitor.specifications_verified);
        fprintf(g_spec_monitor.spec_log, "Total violations: %lu\n", 
                g_spec_monitor.violations_caught);
        fclose(g_spec_monitor.spec_log);
    }
}