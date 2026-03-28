#include "../seader_i.h"
#include <gui/elements.h>

static void seader_scene_sam_missing_alloc_strings(Seader* seader) {
    if(!seader->temp_string1) {
        seader->temp_string1 = furi_string_alloc();
    }
    if(!seader->temp_string2) {
        seader->temp_string2 = furi_string_alloc();
    }
}

static void seader_scene_sam_missing_free_strings(Seader* seader) {
    if(seader->temp_string1) {
        furi_string_free(seader->temp_string1);
        seader->temp_string1 = NULL;
    }
    if(seader->temp_string2) {
        furi_string_free(seader->temp_string2);
        seader->temp_string2 = NULL;
    }
}

void seader_scene_sam_missing_widget_callback(GuiButtonType result, InputType type, void* context) {
    Seader* seader = context;
    if(type == InputTypeShort) {
        view_dispatcher_send_custom_event(seader->view_dispatcher, result);
    }
}

void seader_scene_sam_missing_on_enter(void* context) {
    Seader* seader = context;
    Widget* widget = seader->widget;
    const bool retry_exhausted = (seader->board_retry_remaining == 0U);

    seader_scene_sam_missing_alloc_strings(seader);
    furi_string_reset(seader->temp_string1);
    furi_string_set_str(
        seader->temp_string1,
        seader_board_status_detail_body(seader->board_status, retry_exhausted));
    furi_string_reset(seader->temp_string2);
    furi_string_set_str(
        seader->temp_string2, seader_board_status_detail_hint(seader->board_status));

    widget_add_button_element(
        widget, GuiButtonTypeLeft, "Back", seader_scene_sam_missing_widget_callback, seader);
    widget_add_button_element(
        widget, GuiButtonTypeCenter, "Saved", seader_scene_sam_missing_widget_callback, seader);
    widget_add_button_element(
        widget, GuiButtonTypeRight, "Retry", seader_scene_sam_missing_widget_callback, seader);

    widget_add_string_element(
        widget,
        64,
        12,
        AlignCenter,
        AlignCenter,
        FontPrimary,
        seader_board_status_detail_title(seader->board_status));
    widget_add_text_box_element(
        widget,
        8,
        21,
        112,
        16,
        AlignCenter,
        AlignTop,
        furi_string_get_cstr(seader->temp_string1),
        false);
    widget_add_string_element(
        widget,
        64,
        42,
        AlignCenter,
        AlignCenter,
        FontSecondary,
        furi_string_get_cstr(seader->temp_string2));

    view_dispatcher_switch_to_view(seader->view_dispatcher, SeaderViewWidget);
}

bool seader_scene_sam_missing_on_event(void* context, SceneManagerEvent event) {
    Seader* seader = context;
    bool consumed = false;

    if(event.type == SceneManagerEventTypeCustom) {
        if(event.event == GuiButtonTypeRight) {
            seader->board_status = SeaderBoardStatusRetryRequested;
            scene_manager_next_scene(seader->scene_manager, SeaderSceneStart);
            consumed = true;
        } else if(event.event == GuiButtonTypeCenter) {
            scene_manager_next_scene(seader->scene_manager, SeaderSceneFileSelect);
            consumed = true;
        } else if(event.event == GuiButtonTypeLeft) {
            scene_manager_stop(seader->scene_manager);
            view_dispatcher_stop(seader->view_dispatcher);
            consumed = true;
        } else if(event.event == SeaderWorkerEventSamPresent) {
            seader->board_status = SeaderBoardStatusReady;
            seader->sam_present_menu_guard_active = true;
            scene_manager_next_scene(seader->scene_manager, SeaderSceneSamPresent);
            consumed = true;
        }
    } else if(event.type == SceneManagerEventTypeBack) {
        scene_manager_stop(seader->scene_manager);
        view_dispatcher_stop(seader->view_dispatcher);
        consumed = true;
    }

    return consumed;
}

void seader_scene_sam_missing_on_exit(void* context) {
    Seader* seader = context;
    widget_reset(seader->widget);
    seader_scene_sam_missing_free_strings(seader);
}
