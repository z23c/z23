/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Advisory accelerator report for `make doctor-build`. Missing
 *          tools are reported and never fatal. Always returns 0. */

#ifndef ZCL_DOCTOR_BUILD_H
#define ZCL_DOCTOR_BUILD_H

/* Write the accelerator report to out_fd. PATH selects the tools. */
int zcl_doctor_build(int out_fd);

#endif
