/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef CRASH_PROTECTION_H
#define CRASH_PROTECTION_H

// Initialize the crash protection system
void crash_protection_init(void);

// Cleanup crash protection
void crash_protection_cleanup(void);

// Safe math operations that prevent crashes
float safe_divide_f(float numerator, float denominator);
int safe_divide_i(int numerator, int denominator);
float safe_asinf(float value);
float safe_acosf(float value);
float safe_sqrtf(float value);

#endif // CRASH_PROTECTION_H