/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "encoding/qr.h"
#include "command/native_command.h"
#include "json/json.h"
#include "presentation/canvas.h"
#include "presentation/model.h"
#include "presentation/model_render.h"
#include "presentation/model_text.h"
#include "presentation/presentation.h"
#include "presentation/zclassic_brand.h"
#include "views/qr_popup.h"
#include "views/ui_present.h"
#include "views/ui_present_document.h"
#include "views/ui_present_host_transport.h"
#include "vcs/zcode_work_node.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test/test_qr_priv.h"

/* The shared failure counter, handed out only through a pointer. */
int *qr_failures_ptr(void)
{
    static int failures;
    return &failures;
}
int test_qr(void)
{
    printf("\n=== qr ===\n");
    (*qr_failures_ptr()) = 0;
    QR_CHECK("native QR backend is compiled", qr_matrix_backend_available());
    if (!qr_matrix_backend_available()) return (*qr_failures_ptr());

    if (!qr_case_payment_uri_encode_and_finders()) return (*qr_failures_ptr());
    qr_case_zclassic_window_icon();
    qr_case_canvas_primitives();
    qr_case_chart_scale_maximum();
    qr_case_canvas_text_metrics();
    qr_case_deposit_card();
    qr_case_generic_qr_compositor();
    qr_case_presentation_clipboard_bmp();
    qr_case_confirmation_action_clicks();
    qr_case_chart_hover();
    qr_case_image_copy_control();
    qr_case_chart_keys();
    qr_case_chart_axis_cadence();
    qr_case_chart_rendering_page_bound();
    qr_case_shared_qr_model_rejects();
    qr_case_maximum_qr_chunks();
    qr_case_qr_text_companion_pages();
    qr_case_qr_text_export_and_backend();
    qr_case_progress_model();
    qr_case_chart_model();
    qr_case_timeline_model();
    qr_case_evidence_graph();
    qr_case_choice_model();
    qr_case_form_model_render();
    qr_case_form_bridge_and_typing();
    qr_case_form_focus();
    qr_case_form_submission_mutants();
    qr_case_canvas_model_render();
    qr_case_canvas_reducer_and_submit();
    qr_case_host_reply();
    qr_case_visual_model_wire();
    qr_case_confirmation_model();
    qr_case_status_facts();
    qr_case_corpus_instrument();
    qr_case_corpus_text_export();
    qr_case_corpus_command();
    qr_case_code_change_model();
    qr_case_development_reflex_red();
    qr_case_development_pending_and_compile();
    qr_case_unchanged_candidate_bytes();
    qr_case_publication_confirm();
    qr_case_publication_confirm_chrome();
    qr_case_publication_evidence_boundaries();
    qr_case_release_confirm();
    qr_case_publication_local_commit();
    qr_case_publication_pointer_and_self();
    qr_case_publication_peer_fetch();
    qr_case_reproduction_progress();
    qr_case_package_worker_diagnostic();
    qr_case_progress_native_pixels();
    qr_case_bounded_table_pages();
    qr_case_bounded_table_text();
    qr_case_bounded_table_pixels();
    qr_case_bounded_table_keys();
    qr_case_typed_visual_json();
    qr_case_typed_chart_command();
    qr_case_typed_timeline_command();
    qr_case_typed_evidence_graph_command();
    qr_case_typed_choice_command();
    qr_case_typed_form_command();
    qr_case_typed_canvas_command();
    qr_case_shared_presentation_response();
    qr_case_shared_text_paging_fallback();
    qr_case_visual_command_smuggling();
    printf("=== qr: %d failure(s) ===\n", (*qr_failures_ptr()));
    return (*qr_failures_ptr());
}
