/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sky_combat/controllers/input_mvc_fast.h"
#include <stdlib.h>

input_mvc_fast_t* input_mvc_fast_create(void) {
    input_mvc_fast_t* mvc = calloc(1, sizeof(input_mvc_fast_t));
    if (!mvc) return NULL;
    
    // Initialize model
    input_model_fast_init(&mvc->model);
    
    // Create controller with direct model access
    mvc->controller = input_controller_fast_create(&mvc->model);
    if (!mvc->controller) {
        free(mvc);
        return NULL;
    }
    
    // View is just a lightweight wrapper
    mvc->view = input_view_fast_create(&mvc->model);
    
    return mvc;
}

void input_mvc_fast_destroy(input_mvc_fast_t* mvc) {
    if (!mvc) return;
    
    input_controller_fast_destroy(mvc->controller);
    free(mvc);
}