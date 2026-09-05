/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sky_combat/controllers/input_controller_fast.h"
#include <fcntl.h>
#include <unistd.h>
#include <linux/joystick.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#define DEFAULT_BUFFER_SIZE 64

input_controller_fast_t* input_controller_fast_create(input_model_fast_t* model) {
    if (!model) return NULL;
    
    input_controller_fast_t* controller = calloc(1, sizeof(input_controller_fast_t));
    if (!controller) return NULL;
    
    controller->model = model;
    
    // Open joystick with non-blocking I/O
    controller->fd = open("/dev/input/js0", O_RDONLY | O_NONBLOCK);
    if (controller->fd < 0) {
        model->connected = false;
        printf("No controller found\n");
    } else {
        model->connected = true;
        
        // Detect ASTRO C40
        char name[128] = {0};
        if (ioctl(controller->fd, JSIOCGNAME(sizeof(name)), name) >= 0) {
            if (strstr(name, "ASTRO") && strstr(name, "C40")) {
                model->is_astro_c40 = true;
                printf("ASTRO C40 detected - optimized controls active\n");
            }
        }
        
        // Get initial axis count for validation
        uint8_t axes = 0;
        ioctl(controller->fd, JSIOCGAXES, &axes);
        
        // Enable event batching by default
        controller->use_event_batching = true;
        controller->buffer_size = DEFAULT_BUFFER_SIZE;
        controller->event_buffer = malloc(sizeof(struct js_event) * controller->buffer_size);
    }
    
    return controller;
}

void input_controller_fast_destroy(input_controller_fast_t* controller) {
    if (!controller) return;
    
    if (controller->fd >= 0) close(controller->fd);
    free(controller->event_buffer);
    free(controller);
}

void input_controller_fast_update(input_controller_fast_t* controller) {
    if (!controller || !controller->model->connected || controller->fd < 0) return;
    
    if (controller->use_event_batching && controller->event_buffer) {
        // Batch read for efficiency
        while (1) {
            ssize_t bytes = read(controller->fd, controller->event_buffer, 
                               sizeof(struct js_event) * controller->buffer_size);
            
            if (bytes <= 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // No more events
                    break;
                }
                // Real error - disconnect
                controller->model->connected = false;
                break;
            }
            
            int event_count = bytes / sizeof(struct js_event);
            
            // Process all events in batch
            for (int i = 0; i < event_count; i++) {
                struct js_event* event = &controller->event_buffer[i];
                
                // Direct write to model - no validation needed
                if (event->type & JS_EVENT_BUTTON) {
                    if (event->number < 16) {
                        controller->model->raw.buttons[event->number] = event->value;
                    }
                } else if (event->type & JS_EVENT_AXIS) {
                    if (event->number < 8) {
                        controller->model->raw.axes[event->number] = event->value;
                    }
                }
            }
        }
    } else {
        // Single event read fallback
        struct js_event event;
        while (read(controller->fd, &event, sizeof(event)) > 0) {
            if (event.type & JS_EVENT_BUTTON) {
                if (event.number < 16) {
                    controller->model->raw.buttons[event.number] = event.value;
                }
            } else if (event.type & JS_EVENT_AXIS) {
                if (event.number < 8) {
                    controller->model->raw.axes[event.number] = event.value;
                }
            }
        }
    }
    
    // Process raw input into normalized values
    input_model_fast_process(controller->model);
}

void input_controller_fast_set_batching(input_controller_fast_t* controller, bool enable, int buffer_size) {
    if (!controller) return;
    
    controller->use_event_batching = enable;
    
    if (enable && buffer_size > 0 && buffer_size != controller->buffer_size) {
        free(controller->event_buffer);
        controller->buffer_size = buffer_size;
        controller->event_buffer = malloc(sizeof(struct js_event) * buffer_size);
        
        if (!controller->event_buffer) {
            // Allocation failed, disable batching
            controller->use_event_batching = false;
            controller->buffer_size = 0;
        }
    }
}