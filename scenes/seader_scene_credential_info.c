#include "../seader_i.h"
#include <dolphin/dolphin.h>

#define TAG "SeaderCredentialInfoScene"

void seader_scene_credential_info_widget_callback(
    GuiButtonType result,
    InputType type,
    void* context) {
    Seader* seader = context;
    if(type == InputTypeShort) {
        view_dispatcher_send_custom_event(seader->view_dispatcher, result);
    }
}

void seader_scene_credential_info_on_enter(void* context) {
    Seader* seader = context;
    SeaderCredential* credential = seader->credential;
    PluginWiegand* plugin = seader->plugin_wiegand;
    Widget* widget = seader->widget;

    // Use reusable strings instead of allocating new ones
    FuriString* type_str = seader->temp_string1;
    FuriString* bitlength_str = seader->temp_string2;
    FuriString* credential_str = seader->temp_string3;
    FuriString* sio_str = seader->temp_string4;

    furi_string_set(credential_str, "");
    furi_string_set(bitlength_str, "");
    furi_string_set(sio_str, "");
    if(credential->bit_length > 0) {
        furi_string_cat_printf(bitlength_str, "%d bit", credential->bit_length);
        furi_string_cat_printf(credential_str, "0x%llX", credential->credential);

        if(credential->type == SeaderCredentialTypeNone) {
            furi_string_set(type_str, "Unknown");
        } else if(credential->type == SeaderCredentialType14A) {
            furi_string_set(type_str, "14443A");
        } else if(credential->type == SeaderCredentialTypePicopass) {
            furi_string_set(type_str, "Picopass");
        } else {
            furi_string_set(type_str, "");
        }
    }

    widget_add_button_element(
        seader->widget,
        GuiButtonTypeLeft,
        "Back",
        seader_scene_credential_info_widget_callback,
        seader);

    if(plugin) {
        size_t format_count = plugin->count(credential->bit_length, credential->credential);
        if(format_count > 0) {
            widget_add_button_element(
                seader->widget,
                GuiButtonTypeCenter,
                "Parse",
                seader_scene_credential_info_widget_callback,
                seader);
        }
    }

    widget_add_string_element(
        widget, 64, 5, AlignCenter, AlignCenter, FontPrimary, furi_string_get_cstr(type_str));
    widget_add_string_element(
        widget,
        64,
        24,
        AlignCenter,
        AlignCenter,
        FontSecondary,
        furi_string_get_cstr(bitlength_str));
    widget_add_string_element(
        widget,
        64,
        36,
        AlignCenter,
        AlignCenter,
        FontSecondary,
        furi_string_get_cstr(credential_str));

    if(credential->sio[0] == 0x30) {
        furi_string_set(sio_str, "+SIO");
        widget_add_string_element(
            widget, 64, 48, AlignCenter, AlignCenter, FontSecondary, furi_string_get_cstr(sio_str));
    }

    // No need to free strings as they are reused from seader struct

    view_dispatcher_switch_to_view(seader->view_dispatcher, SeaderViewWidget);
}

bool seader_scene_credential_info_on_event(void* context, SceneManagerEvent event) {
    Seader* seader = context;
    bool consumed = false;

    if(event.type == SceneManagerEventTypeCustom) {
        if(event.event == GuiButtonTypeLeft) {
            consumed = scene_manager_previous_scene(seader->scene_manager);
        } else if(event.event == GuiButtonTypeCenter) {
            scene_manager_next_scene(seader->scene_manager, SeaderSceneFormats);
            consumed = true;
        } else if(event.event == SeaderCustomEventViewExit) {
            view_dispatcher_switch_to_view(seader->view_dispatcher, SeaderViewWidget);
            consumed = true;
        }
    } else if(event.type == SceneManagerEventTypeBack) {
        view_dispatcher_switch_to_view(seader->view_dispatcher, SeaderViewWidget);
        consumed = true;
    }
    return consumed;
}

void seader_scene_credential_info_on_exit(void* context) {
    Seader* seader = context;

    // Clear views
    widget_reset(seader->widget);
}
