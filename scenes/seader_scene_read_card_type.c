#include "../seader_i.h"

static const char* seader_scene_read_card_type_label(SeaderCredentialType type) {
    switch(type) {
    case SeaderCredentialType14A:
        return "Read as 14443A";
    case SeaderCredentialTypeMifareClassic:
        return "Read as Mifare Classic";
    case SeaderCredentialTypePicopass:
        return "Read as Picopass";
    default:
        return "Read";
    }
}

void seader_scene_read_card_type_submenu_callback(void* context, uint32_t index) {
    Seader* seader = context;
    view_dispatcher_send_custom_event(seader->view_dispatcher, index);
}

void seader_scene_read_card_type_on_enter(void* context) {
    Seader* seader = context;
    Submenu* submenu = seader->submenu;
    const SeaderCredentialType* detected_types = seader_hf_mode_get_detected_types(seader);
    const size_t detected_type_count = seader_hf_mode_get_detected_type_count(seader);

    submenu_reset(submenu);
    for(size_t i = 0; i < detected_type_count; i++) {
        const SeaderCredentialType type = detected_types[i];
        submenu_add_item(
            submenu,
            seader_scene_read_card_type_label(type),
            type,
            seader_scene_read_card_type_submenu_callback,
            seader);
    }

    view_dispatcher_switch_to_view(seader->view_dispatcher, SeaderViewMenu);
}

bool seader_scene_read_card_type_on_event(void* context, SceneManagerEvent event) {
    Seader* seader = context;
    bool consumed = false;

    if(event.type == SceneManagerEventTypeCustom) {
        const SeaderCredentialType type = event.event;
        if(type == SeaderCredentialType14A || type == SeaderCredentialTypeMifareClassic ||
           type == SeaderCredentialTypePicopass) {
            seader_hf_mode_set_selected_read_type(seader, type);
            seader_hf_mode_clear_detected_types(seader);
            scene_manager_next_scene(seader->scene_manager, SeaderSceneRead);
            consumed = true;
        }
    } else if(event.type == SceneManagerEventTypeBack) {
        seader_hf_mode_set_selected_read_type(seader, SeaderCredentialTypeNone);
        seader_hf_mode_clear_detected_types(seader);
        seader_hf_mode_deactivate(seader);
        seader_hf_plugin_release(seader);
        scene_manager_search_and_switch_to_previous_scene(
            seader->scene_manager, SeaderSceneSamPresent);
        consumed = true;
    }

    return consumed;
}

void seader_scene_read_card_type_on_exit(void* context) {
    Seader* seader = context;
    submenu_reset(seader->submenu);
}
