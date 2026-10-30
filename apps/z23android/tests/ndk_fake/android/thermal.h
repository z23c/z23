/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_FAKE_ANDROID_THERMAL_H
#define ZAPP_FAKE_ANDROID_THERMAL_H
/* Host fake of the NDK thermal header, only for tests/thermal_start_test.c. */
typedef struct AThermalManager AThermalManager;
typedef enum { ATHERMAL_STATUS_ERROR = -1, ATHERMAL_STATUS_NONE = 0 } AThermalStatus;
typedef void (*AThermal_StatusCallback)(void *data, AThermalStatus status);
AThermalManager *AThermal_acquireManager(void);
void AThermal_releaseManager(AThermalManager *m);
int AThermal_registerThermalStatusListener(AThermalManager *m, AThermal_StatusCallback cb, void *data);
int AThermal_unregisterThermalStatusListener(AThermalManager *m, AThermal_StatusCallback cb, void *data);
AThermalStatus AThermal_getCurrentThermalStatus(AThermalManager *m);
#endif
