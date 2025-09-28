#include "../seader_i.h"
#include <dolphin/dolphin.h>

void seader_read_config_card_worker_callback(SeaderWorkerEvent event, void* context) {
    UNUSED(event);
    Seader* seader = context;
    view_dispatcher_send_custom_event(seader->view_dispatcher, SeaderCustomEventWorkerExit);
}

void seader_scene_read_config_card_on_enter(void* context) {
    Seader* seader = context;

    // Setup view
    Popup* popup = seader->popup;
    popup_set_header(popup, "Detecting\nConfig\ncard", 68, 30, AlignLeft, AlignTop);
    popup_set_icon(popup, 0, 3, &I_RFIDDolphinReceive_97x61);

    // Start worker
    view_dispatcher_switch_to_view(seader->view_dispatcher, SeaderViewPopup);

    seader->poller = nfc_poller_alloc(seader->nfc, NfcProtocolIso14443_4a);

    seader->worker->stage = SeaderPollerEventTypeCardDetect;
    seader_credential_clear(seader->credential);
    seader->credential->type = SeaderCredentialTypeConfig;
    nfc_poller_start(seader->poller, seader_worker_poller_callback_iso14443_4a, seader);

    seader_blink_start(seader);
}

bool seader_scene_read_config_card_on_event(void* context, SceneManagerEvent event) {
    Seader* seader = context;
    bool consumed = false;

    if(event.type == SceneManagerEventTypeCustom) {
        if(event.event == SeaderCustomEventWorkerExit) {
            scene_manager_next_scene(seader->scene_manager, SeaderSceneReadConfigCardSuccess);
            consumed = true;
        } else if(event.event == SeaderCustomEventPollerSuccess) {
            scene_manager_next_scene(seader->scene_manager, SeaderSceneReadConfigCardSuccess);
            consumed = true;
        }
    } else if(event.type == SceneManagerEventTypeBack) {
        scene_manager_search_and_switch_to_previous_scene(
            seader->scene_manager, SeaderSceneSamPresent);
        consumed = true;
    }

    return consumed;
}

void seader_scene_read_config_card_on_exit(void* context) {
    Seader* seader = context;

    if(seader->poller) {
        nfc_poller_stop(seader->poller);
        nfc_poller_free(seader->poller);
    }

    // Clear view
    popup_reset(seader->popup);

    seader_blink_stop(seader);
}
