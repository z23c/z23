/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Private facet shared by the qr test scenario check files
 * (test_qr.c and its test_qr_*.c siblings).
 *
 * Every scenario grades itself through QR_CHECK, which increments a
 * shared failure counter. That counter lives behind qr_failures_ptr(),
 * a pointer to a function-local singleton defined once in test_qr.c —
 * no sibling declares its own file-scope mutable state. */

#ifndef TEST_QR_PRIV_H
#define TEST_QR_PRIV_H

#include <stdbool.h>
#include <stdio.h>

/* Returns the single shared failure counter. Defined in test_qr.c. */
int *qr_failures_ptr(void);

#define QR_CHECK(name, condition) do {                                      \
    printf("  %-58s ", (name));                                             \
    if (condition) printf("PASS\n");                                       \
    else { printf("FAIL\n"); (*qr_failures_ptr())++; }                     \
} while (0)

/* Scenario checks — test_qr.c's entry point calls every one of these in
 * order; each lives in the sibling file its scenario names. */

/* test_qr_rendering.c — canvas/chart primitives, QR chunking and text
 * companion pages, and the progress/chart/timeline/evidence/choice/form
 * presentation data models. */
bool qr_case_payment_uri_encode_and_finders(void);
void qr_case_zclassic_window_icon(void);
void qr_case_canvas_primitives(void);
void qr_case_chart_scale_maximum(void);
void qr_case_canvas_text_metrics(void);
void qr_case_deposit_card(void);
void qr_case_generic_qr_compositor(void);
void qr_case_presentation_clipboard_bmp(void);
void qr_case_confirmation_action_clicks(void);
void qr_case_chart_hover(void);
void qr_case_image_copy_control(void);
void qr_case_chart_keys(void);
void qr_case_chart_axis_cadence(void);
void qr_case_chart_rendering_page_bound(void);
void qr_case_shared_qr_model_rejects(void);
void qr_case_maximum_qr_chunks(void);
void qr_case_qr_text_companion_pages(void);
void qr_case_qr_text_export_and_backend(void);
void qr_case_progress_model(void);
void qr_case_chart_model(void);
void qr_case_timeline_model(void);
void qr_case_evidence_graph(void);
void qr_case_choice_model(void);
void qr_case_form_model_render(void);

/* test_qr_interaction.c — form bridge/focus/submission, canvas
 * reducer/host/visual/confirmation models, status facts, corpus checks,
 * and code-change/development reflex checks. */
void qr_case_form_bridge_and_typing(void);
void qr_case_form_focus(void);
void qr_case_form_submission_mutants(void);
void qr_case_canvas_model_render(void);
void qr_case_canvas_reducer_and_submit(void);
void qr_case_host_reply(void);
void qr_case_visual_model_wire(void);
void qr_case_confirmation_model(void);
void qr_case_status_facts(void);
void qr_case_corpus_instrument(void);
void qr_case_corpus_text_export(void);
void qr_case_corpus_command(void);
void qr_case_code_change_model(void);
void qr_case_development_reflex_red(void);
void qr_case_development_pending_and_compile(void);

/* test_qr_publication.c — publication/release confirm flows,
 * reproduction/package progress, bounded-table rendering, typed command
 * dispatch, shared presentation/text paging, and the visual
 * command-smuggling guard. */
void qr_case_unchanged_candidate_bytes(void);
void qr_case_publication_confirm(void);
void qr_case_publication_confirm_chrome(void);
void qr_case_publication_evidence_boundaries(void);
void qr_case_release_confirm(void);
void qr_case_publication_local_commit(void);
void qr_case_publication_pointer_and_self(void);
void qr_case_publication_peer_fetch(void);
void qr_case_reproduction_progress(void);
void qr_case_package_worker_diagnostic(void);
void qr_case_progress_native_pixels(void);
void qr_case_bounded_table_pages(void);
void qr_case_bounded_table_text(void);
void qr_case_bounded_table_pixels(void);
void qr_case_bounded_table_keys(void);
void qr_case_typed_visual_json(void);
void qr_case_typed_chart_command(void);
void qr_case_typed_timeline_command(void);
void qr_case_typed_evidence_graph_command(void);
void qr_case_typed_choice_command(void);
void qr_case_typed_form_command(void);
void qr_case_typed_canvas_command(void);
void qr_case_shared_presentation_response(void);
void qr_case_shared_text_paging_fallback(void);
void qr_case_visual_command_smuggling(void);

#endif
