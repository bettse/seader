#include "seader_i.h"
#include "trace_log.h"

#define TAG "Seader"
#define SEADER_PLUGIN_DIR APP_ASSETS_PATH("plugins")
#define SEADER_WIEGAND_PLUGIN_PATH APP_ASSETS_PATH("plugins/plugin_wiegand.fal")
#define SEADER_HF_PLUGIN_PATH APP_ASSETS_PATH("plugins/plugin_hf.fal")

typedef struct {
    bool done;
    bool detected;
} SeaderHfPicopassDetectContext;

static NfcCommand seader_hf_picopass_detect_callback(PicopassPollerEvent event, void* context) {
    SeaderHfPicopassDetectContext* detect_context = context;

    if(event.type == PicopassPollerEventTypeCardDetected ||
       event.type == PicopassPollerEventTypeSuccess) {
        detect_context->detected = true;
        detect_context->done = true;
        return NfcCommandStop;
    } else if(event.type == PicopassPollerEventTypeFail) {
        detect_context->done = true;
        return NfcCommandStop;
    }

    return NfcCommandContinue;
}

static void seader_hf_plugin_notify_event(void* host_ctx, uint32_t event) {
    Seader* seader = host_ctx;
    if(!seader || !seader->view_dispatcher) {
        FURI_LOG_W(TAG, "Drop HF plugin event %lu without dispatcher", event);
        return;
    }
    view_dispatcher_send_custom_event(seader->view_dispatcher, event);
}

static void seader_hf_plugin_notify_card_detected(void* host_ctx) {
    seader_hf_plugin_notify_event(host_ctx, SeaderCustomEventPollerDetect);
}

static void seader_hf_plugin_notify_worker_exit(void* host_ctx) {
    seader_hf_plugin_notify_event(host_ctx, SeaderCustomEventWorkerExit);
}

static bool seader_hf_plugin_sam_can_accept_card(void* host_ctx) {
    return seader_sam_can_accept_card(host_ctx);
}

static void seader_hf_plugin_send_card_detected(
    void* host_ctx,
    uint8_t sak,
    const uint8_t* uid,
    uint8_t uid_len,
    const uint8_t* ats,
    uint8_t ats_len) {
    Seader* seader = host_ctx;
    if(!seader || !seader->worker || !seader->credential || !uid || uid_len == 0U) {
        FURI_LOG_E(
            TAG,
            "Drop HF cardDetected invalid state seader=%p worker=%p cred=%p uid=%p uid_len=%u",
            (void*)seader,
            seader ? (void*)seader->worker : NULL,
            seader ? (void*)seader->credential : NULL,
            (const void*)uid,
            uid_len);
        return;
    }
    FURI_LOG_D(
        TAG,
        "HF plugin cardDetected sak=%02x uid_len=%u ats_len=%u stage=%d",
        sak,
        uid_len,
        ats_len,
        seader->worker->stage);
    seader_worker_card_detect(seader, sak, NULL, uid, uid_len, (uint8_t*)ats, ats_len);
}

static void seader_hf_plugin_send_nfc_rx(void* host_ctx, uint8_t* buffer, size_t len) {
    Seader* seader = host_ctx;
    seader_send_nfc_rx(seader, buffer, len);
}

static void seader_hf_plugin_run_conversation(void* host_ctx) {
    Seader* seader = host_ctx;
    if(!seader || !seader->worker) {
        FURI_LOG_W(TAG, "Skip HF conversation without worker");
        return;
    }
    FURI_LOG_D(TAG, "HF plugin run conversation stage=%d", seader->worker->stage);
    seader_worker_run_hf_conversation(seader);
}

static void seader_hf_plugin_set_stage(void* host_ctx, PluginHfStage stage) {
    Seader* seader = host_ctx;
    if(seader->worker) {
        switch(stage) {
        case PluginHfStageCardDetect:
            seader->worker->stage = SeaderPollerEventTypeCardDetect;
            break;
        case PluginHfStageConversation:
            seader->worker->stage = SeaderPollerEventTypeConversation;
            break;
        case PluginHfStageComplete:
            seader->worker->stage = SeaderPollerEventTypeComplete;
            break;
        case PluginHfStageSuccess:
            seader->worker->stage = SeaderPollerEventTypeSuccess;
            break;
        case PluginHfStageFail:
        default:
            seader->worker->stage = SeaderPollerEventTypeFail;
            break;
        }
    }
}

static PluginHfStage seader_hf_plugin_get_stage(void* host_ctx) {
    Seader* seader = host_ctx;
    if(!seader->worker) {
        return PluginHfStageFail;
    }

    switch(seader->worker->stage) {
    case SeaderPollerEventTypeCardDetect:
        return PluginHfStageCardDetect;
    case SeaderPollerEventTypeConversation:
        return PluginHfStageConversation;
    case SeaderPollerEventTypeComplete:
        return PluginHfStageComplete;
    case SeaderPollerEventTypeSuccess:
        return PluginHfStageSuccess;
    case SeaderPollerEventTypeFail:
    default:
        return PluginHfStageFail;
    }
}

static void seader_hf_plugin_set_credential_type(void* host_ctx, SeaderCredentialType type) {
    Seader* seader = host_ctx;
    seader->credential->type = type;
    seader->credential->sio_len = 0U;
    seader->credential->sio_start_block = 0U;
    seader->credential->isDesfireEV2 = false;
}

static SeaderCredentialType seader_hf_plugin_get_credential_type(void* host_ctx) {
    Seader* seader = host_ctx;
    return seader->credential->type;
}

static bool seader_hf_plugin_get_desfire_ev2(void* host_ctx) {
    Seader* seader = host_ctx;
    return seader->credential->isDesfireEV2;
}

static void seader_hf_plugin_set_desfire_ev2(void* host_ctx, bool is_desfire_ev2) {
    Seader* seader = host_ctx;
    seader->credential->isDesfireEV2 = is_desfire_ev2;
}

static void seader_hf_plugin_append_picopass_sio(
    void* host_ctx,
    uint8_t block_num,
    const uint8_t* data,
    size_t len) {
    Seader* seader = host_ctx;
    SeaderCredential* credential = seader->credential;

    if(!data || len == 0U || credential->type != SeaderCredentialTypePicopass) {
        return;
    }

    if(credential->sio_len == 0U && data[0] == 0x30U) {
        credential->sio_start_block = block_num;
    }

    const size_t offset = (size_t)(block_num - credential->sio_start_block) * PICOPASS_BLOCK_LEN;
    if(offset >= sizeof(credential->sio)) {
        return;
    }

    const size_t copy_len = MIN(len, sizeof(credential->sio) - offset);
    memcpy(credential->sio + offset, data, copy_len);
    credential->sio_len = MAX(credential->sio_len, offset + copy_len);
}

static void seader_hf_plugin_set_14a_sio(void* host_ctx, const uint8_t* data, size_t len) {
    Seader* seader = host_ctx;
    SeaderCredential* credential = seader->credential;

    if(!data || credential->type != SeaderCredentialType14A) {
        return;
    }

    const size_t copy_len = MIN(len, sizeof(credential->sio));
    memcpy(credential->sio, data, copy_len);
    credential->sio_len = copy_len;
}

static Nfc* seader_hf_plugin_get_nfc(void* host_ctx) {
    Seader* seader = host_ctx;
    return seader ? seader->nfc : NULL;
}

static NfcDevice* seader_hf_plugin_get_nfc_device(void* host_ctx) {
    Seader* seader = host_ctx;
    return seader ? seader->nfc_device : NULL;
}

static bool seader_hf_plugin_picopass_detect(void* host_ctx) {
    Seader* seader = host_ctx;
    bool detected = false;
    PicopassPoller* poller = picopass_poller_alloc(seader->nfc);
    SeaderHfPicopassDetectContext detect_context = {0};

    picopass_poller_start(poller, seader_hf_picopass_detect_callback, &detect_context);
    for(uint8_t i = 0; i < 10 && !detect_context.done; i++) {
        furi_delay_ms(10);
    }

    detected = detect_context.detected;
    picopass_poller_stop(poller);
    picopass_poller_free(poller);

    return detected;
}

static bool seader_hf_plugin_picopass_start(
    void* host_ctx,
    PicopassPollerCallback callback,
    void* callback_ctx) {
    Seader* seader = host_ctx;

    if(seader->picopass_poller) {
        picopass_poller_stop(seader->picopass_poller);
        picopass_poller_free(seader->picopass_poller);
        seader->picopass_poller = NULL;
    }

    seader->picopass_poller = picopass_poller_alloc(seader->nfc);
    if(!seader->picopass_poller) {
        return false;
    }

    picopass_poller_start(seader->picopass_poller, callback, callback_ctx);
    return true;
}

static void seader_hf_plugin_picopass_stop(void* host_ctx) {
    Seader* seader = host_ctx;

    if(seader->picopass_poller) {
        picopass_poller_stop(seader->picopass_poller);
        picopass_poller_free(seader->picopass_poller);
        seader->picopass_poller = NULL;
    }
}

static uint8_t* seader_hf_plugin_picopass_get_csn(void* host_ctx) {
    Seader* seader = host_ctx;
    if(!seader->picopass_poller) {
        return NULL;
    }

    return picopass_poller_get_csn(seader->picopass_poller);
}

static bool seader_hf_plugin_picopass_transmit(
    void* host_ctx,
    const uint8_t* tx_data,
    size_t tx_len,
    uint8_t* rx_data,
    size_t rx_capacity,
    size_t* rx_len,
    uint32_t fwt_fc) {
    Seader* seader = host_ctx;
    if(!seader->picopass_poller || !tx_data || !rx_data || !rx_len) {
        return false;
    }

    BitBuffer* tx_buffer = bit_buffer_alloc(tx_len);
    BitBuffer* rx_buffer = bit_buffer_alloc(rx_capacity);
    bool success = false;
    if(!tx_buffer || !rx_buffer) {
        FURI_LOG_E(TAG, "Failed to allocate picopass host tx/rx buffers");
        if(tx_buffer) bit_buffer_free(tx_buffer);
        if(rx_buffer) bit_buffer_free(rx_buffer);
        return false;
    }

    bit_buffer_append_bytes(tx_buffer, tx_data, tx_len);
    PicopassError error =
        picopass_poller_send_frame(seader->picopass_poller, tx_buffer, rx_buffer, fwt_fc);
    if(error == PicopassErrorIncorrectCrc) {
        error = PicopassErrorNone;
    }

    if(error == PicopassErrorNone) {
        *rx_len = bit_buffer_get_size_bytes(rx_buffer);
        memcpy(rx_data, bit_buffer_get_data(rx_buffer), *rx_len);
        success = true;
    }

    bit_buffer_free(tx_buffer);
    bit_buffer_free(rx_buffer);
    return success;
}

static void seader_hf_plugin_set_read_error(void* host_ctx, const char* text) {
    Seader* seader = host_ctx;
    if(!text) {
        seader->read_error[0] = '\0';
        return;
    }
    strlcpy(seader->read_error, text, sizeof(seader->read_error));
}

static const PluginHfHostApi seader_hf_plugin_host_api = {
    .notify_card_detected = seader_hf_plugin_notify_card_detected,
    .notify_worker_exit = seader_hf_plugin_notify_worker_exit,
    .sam_can_accept_card = seader_hf_plugin_sam_can_accept_card,
    .send_card_detected = seader_hf_plugin_send_card_detected,
    .send_nfc_rx = seader_hf_plugin_send_nfc_rx,
    .run_conversation = seader_hf_plugin_run_conversation,
    .set_stage = seader_hf_plugin_set_stage,
    .get_stage = seader_hf_plugin_get_stage,
    .set_credential_type = seader_hf_plugin_set_credential_type,
    .get_credential_type = seader_hf_plugin_get_credential_type,
    .get_desfire_ev2 = seader_hf_plugin_get_desfire_ev2,
    .set_desfire_ev2 = seader_hf_plugin_set_desfire_ev2,
    .append_picopass_sio = seader_hf_plugin_append_picopass_sio,
    .set_14a_sio = seader_hf_plugin_set_14a_sio,
    .get_nfc = seader_hf_plugin_get_nfc,
    .get_nfc_device = seader_hf_plugin_get_nfc_device,
    .picopass_detect = seader_hf_plugin_picopass_detect,
    .picopass_start = seader_hf_plugin_picopass_start,
    .picopass_stop = seader_hf_plugin_picopass_stop,
    .picopass_get_csn = seader_hf_plugin_picopass_get_csn,
    .picopass_transmit = seader_hf_plugin_picopass_transmit,
    .show_loading_popup = seader_show_loading_popup,
    .set_read_error = seader_hf_plugin_set_read_error,
};

bool seader_custom_event_callback(void* context, uint32_t event) {
    furi_assert(context);
    Seader* seader = context;
    return scene_manager_handle_custom_event(seader->scene_manager, event);
}

bool seader_back_event_callback(void* context) {
    furi_assert(context);
    Seader* seader = context;
    return scene_manager_handle_back_event(seader->scene_manager);
}

void seader_tick_event_callback(void* context) {
    furi_assert(context);
    Seader* seader = context;
    scene_manager_handle_tick_event(seader->scene_manager);
}

static bool seader_align_is_valid(size_t align) {
    return align != 0U && ((align & (align - 1U)) == 0U);
}

Seader* seader_alloc() {
    Seader* seader = malloc(sizeof(Seader));
    seader_trace_reset();

    seader->revert_power = !furi_hal_power_is_otg_enabled();
    if(seader->revert_power) {
        furi_hal_power_enable_otg();
    }
    seader->is_debug_enabled = furi_hal_rtc_is_flag_set(FuriHalRtcFlagDebug);
    seader->samCommand = SamCommand_PR_NOTHING;
    seader->sam_state = SeaderSamStateIdle;
    seader->sam_intent = SeaderSamIntentNone;
    seader->sam_present = false;
    memset(seader->sam_version, 0, sizeof(seader->sam_version));
    seader_sam_key_label_format(
        false, NULL, 0U, seader->sam_key_label, sizeof(seader->sam_key_label));
    seader_uhf_status_label_format(
        false, false, false, false, seader->uhf_status_label, sizeof(seader->uhf_status_label));
    seader_uhf_snmp_probe_init(&seader->snmp_probe);
    seader->nfc = NULL;
    seader->nfc_device = NULL;
    seader->scratch.offset = 0U;
    seader->scratch.high_water = 0U;
    seader->hf_mode = NULL;

    seader->worker = seader_worker_alloc();
    seader->view_dispatcher = view_dispatcher_alloc();
    seader->scene_manager = scene_manager_alloc(&seader_scene_handlers, seader);
    view_dispatcher_set_event_callback_context(seader->view_dispatcher, seader);
    view_dispatcher_set_custom_event_callback(
        seader->view_dispatcher, seader_custom_event_callback);
    view_dispatcher_set_navigation_event_callback(
        seader->view_dispatcher, seader_back_event_callback);
    view_dispatcher_set_tick_event_callback(
        seader->view_dispatcher, seader_tick_event_callback, 100);

    seader->uart = seader_uart_alloc(seader);

    seader->credential = seader_credential_alloc();

    seader->nfc = NULL;
    seader->nfc_device = NULL;

    // Open GUI record
    seader->gui = furi_record_open(RECORD_GUI);
    view_dispatcher_attach_to_gui(
        seader->view_dispatcher, seader->gui, ViewDispatcherTypeFullscreen);

    // Open Notification record
    seader->notifications = furi_record_open(RECORD_NOTIFICATION);

    // Submenu
    seader->submenu = submenu_alloc();
    view_dispatcher_add_view(
        seader->view_dispatcher, SeaderViewMenu, submenu_get_view(seader->submenu));

    // Popup
    seader->popup = popup_alloc();
    view_dispatcher_add_view(
        seader->view_dispatcher, SeaderViewPopup, popup_get_view(seader->popup));

    // Loading
    seader->loading = loading_alloc();
    view_dispatcher_add_view(
        seader->view_dispatcher, SeaderViewLoading, loading_get_view(seader->loading));

    // Text Input
    seader->text_input = text_input_alloc();
    view_dispatcher_add_view(
        seader->view_dispatcher, SeaderViewTextInput, text_input_get_view(seader->text_input));

    // TextBox
    seader->text_box = text_box_alloc();
    view_dispatcher_add_view(
        seader->view_dispatcher, SeaderViewTextBox, text_box_get_view(seader->text_box));
    seader->text_box_store = furi_string_alloc();

    // Custom Widget
    seader->widget = widget_alloc();
    view_dispatcher_add_view(
        seader->view_dispatcher, SeaderViewWidget, widget_get_view(seader->widget));

    // Allocate reusable strings for scene optimization
    seader->temp_string1 = furi_string_alloc();
    seader->temp_string2 = furi_string_alloc();
    seader->temp_string3 = furi_string_alloc();
    seader->temp_string4 = furi_string_alloc();

    seader->plugin_manager = NULL;
    seader->plugin_wiegand = NULL;
    seader->hf_plugin_manager = NULL;
    seader->plugin_hf = NULL;
    seader->hf_plugin_ctx = NULL;

    return seader;
}

void seader_free(Seader* seader) {
    furi_assert(seader);

    if(seader->revert_power) {
        furi_hal_power_disable_otg();
    }

    seader_uart_free(seader->uart);
    seader->uart = NULL;

    seader_credential_free(seader->credential);
    seader->credential = NULL;

    if(seader->nfc) {
        nfc_free(seader->nfc);
        seader->nfc = NULL;
    }

    if(seader->nfc_device) {
        nfc_device_free(seader->nfc_device);
        seader->nfc_device = NULL;
    }

    // Submenu
    view_dispatcher_remove_view(seader->view_dispatcher, SeaderViewMenu);
    submenu_free(seader->submenu);

    // Popup
    view_dispatcher_remove_view(seader->view_dispatcher, SeaderViewPopup);
    popup_free(seader->popup);

    // Loading
    view_dispatcher_remove_view(seader->view_dispatcher, SeaderViewLoading);
    loading_free(seader->loading);

    // TextInput
    view_dispatcher_remove_view(seader->view_dispatcher, SeaderViewTextInput);
    text_input_free(seader->text_input);

    // TextBox
    view_dispatcher_remove_view(seader->view_dispatcher, SeaderViewTextBox);
    text_box_free(seader->text_box);
    furi_string_free(seader->text_box_store);

    // Custom Widget
    view_dispatcher_remove_view(seader->view_dispatcher, SeaderViewWidget);
    widget_free(seader->widget);

    // Free reusable strings
    furi_string_free(seader->temp_string1);
    furi_string_free(seader->temp_string2);
    furi_string_free(seader->temp_string3);
    furi_string_free(seader->temp_string4);

    seader_hf_mode_deactivate(seader);
    seader_worker_release(seader);
    if(seader->worker) {
        seader_worker_free(seader->worker);
        seader->worker = NULL;
    }

    // View Dispatcher
    view_dispatcher_free(seader->view_dispatcher);

    // Scene Manager
    scene_manager_free(seader->scene_manager);

    // GUI
    furi_record_close(RECORD_GUI);
    seader->gui = NULL;

    // Notifications
    furi_record_close(RECORD_NOTIFICATION);
    seader->notifications = NULL;

    seader_wiegand_plugin_release(seader);
    seader_hf_plugin_release(seader);

    free(seader);
}

void seader_text_store_set(Seader* seader, const char* text, ...) {
    va_list args;
    va_start(args, text);

    vsnprintf(seader->text_store, sizeof(seader->text_store), text, args);

    va_end(args);
}

void seader_text_store_clear(Seader* seader) {
    memset(seader->text_store, 0, sizeof(seader->text_store));
}

static const NotificationSequence seader_sequence_blink_start_blue = {
    &message_blink_start_10,
    &message_blink_set_color_blue,
    &message_do_not_reset,
    NULL,
};

static const NotificationSequence seader_sequence_blink_stop = {
    &message_blink_stop,
    NULL,
};

void seader_blink_start(Seader* seader) {
    notification_message(seader->notifications, &seader_sequence_blink_start_blue);
}

void seader_blink_stop(Seader* seader) {
    notification_message(seader->notifications, &seader_sequence_blink_stop);
}

void seader_show_loading_popup(void* context, bool show) {
    Seader* seader = context;

    if(show) {
        // Raise timer priority so that animations can play
        furi_timer_set_thread_priority(FuriTimerThreadPriorityElevated);
        view_dispatcher_switch_to_view(seader->view_dispatcher, SeaderViewLoading);
    } else {
        // Restore default timer priority
        furi_timer_set_thread_priority(FuriTimerThreadPriorityNormal);
    }
}

bool seader_wiegand_plugin_acquire(Seader* seader) {
    furi_assert(seader);

    if(seader->plugin_wiegand) {
        return true;
    }

    if(!seader->plugin_manager) {
        seader->plugin_manager =
            plugin_manager_alloc(PLUGIN_APP_ID, PLUGIN_API_VERSION, firmware_api_interface);
        if(!seader->plugin_manager) {
            FURI_LOG_E(TAG, "Failed to allocate plugin manager");
            return false;
        }
    }

    FURI_LOG_I(TAG, "Loading Wiegand plugin from %s", SEADER_WIEGAND_PLUGIN_PATH);
    if(plugin_manager_load_single(seader->plugin_manager, SEADER_WIEGAND_PLUGIN_PATH) !=
       PluginManagerErrorNone) {
        FURI_LOG_E(TAG, "Failed to load Wiegand plugin");
        plugin_manager_free(seader->plugin_manager);
        seader->plugin_manager = NULL;
        return false;
    }

    if(plugin_manager_get_count(seader->plugin_manager) == 0) {
        FURI_LOG_E(TAG, "Wiegand plugin manager is empty after load");
        plugin_manager_free(seader->plugin_manager);
        seader->plugin_manager = NULL;
        return false;
    }

    seader->plugin_wiegand = (PluginWiegand*)plugin_manager_get_ep(seader->plugin_manager, 0);

    if(!seader->plugin_wiegand) {
        FURI_LOG_E(TAG, "Failed to resolve Wiegand plugin entry point");
        plugin_manager_free(seader->plugin_manager);
        seader->plugin_manager = NULL;
        return false;
    }

    FURI_LOG_I(TAG, "Wiegand plugin loaded: %s", seader->plugin_wiegand->name);
    return true;
}

void seader_wiegand_plugin_release(Seader* seader) {
    furi_assert(seader);

    if(!seader->plugin_manager) {
        seader->plugin_wiegand = NULL;
        return;
    }

    FURI_LOG_I(TAG, "Unloading Wiegand plugin");
    seader->plugin_wiegand = NULL;
    plugin_manager_free(seader->plugin_manager);
    seader->plugin_manager = NULL;
}

bool seader_hf_plugin_acquire(Seader* seader) {
    furi_assert(seader);

    if(seader->plugin_hf && seader->hf_plugin_ctx) {
        return true;
    }

    if(!seader->nfc) {
        seader->nfc = nfc_alloc();
        if(!seader->nfc) {
            FURI_LOG_E(TAG, "Failed to allocate host NFC");
            return false;
        }
    }

    if(!seader->nfc_device) {
        seader->nfc_device = nfc_device_alloc();
        if(!seader->nfc_device) {
            FURI_LOG_E(TAG, "Failed to allocate host NFC device");
            nfc_free(seader->nfc);
            seader->nfc = NULL;
            return false;
        }
    }

    if(!seader->hf_plugin_manager) {
        seader->hf_plugin_manager =
            plugin_manager_alloc(HF_PLUGIN_APP_ID, HF_PLUGIN_API_VERSION, firmware_api_interface);
        if(!seader->hf_plugin_manager) {
            FURI_LOG_E(TAG, "Failed to allocate HF plugin manager");
            return false;
        }
    }

    FURI_LOG_I(TAG, "Loading HF plugin from %s", SEADER_HF_PLUGIN_PATH);
    if(plugin_manager_load_single(seader->hf_plugin_manager, SEADER_HF_PLUGIN_PATH) !=
       PluginManagerErrorNone) {
        FURI_LOG_E(TAG, "Failed to load HF plugin");
        plugin_manager_free(seader->hf_plugin_manager);
        seader->hf_plugin_manager = NULL;
        return false;
    }

    seader->plugin_hf = (PluginHf*)plugin_manager_get_ep(seader->hf_plugin_manager, 0);

    if(!seader->plugin_hf) {
        FURI_LOG_E(TAG, "Failed to resolve HF plugin entry point");
        plugin_manager_free(seader->hf_plugin_manager);
        seader->hf_plugin_manager = NULL;
        return false;
    }

    seader->hf_plugin_ctx = seader->plugin_hf->alloc(&seader_hf_plugin_host_api, seader);
    if(!seader->hf_plugin_ctx) {
        FURI_LOG_E(TAG, "Failed to allocate HF plugin context");
        plugin_manager_free(seader->hf_plugin_manager);
        seader->hf_plugin_manager = NULL;
        seader->plugin_hf = NULL;
        return false;
    }

    FURI_LOG_I(TAG, "HF plugin loaded: %s", seader->plugin_hf->name);
    return true;
}

void seader_hf_plugin_release(Seader* seader) {
    furi_assert(seader);

    if(seader->nfc_device) {
        nfc_device_set_loading_callback(seader->nfc_device, NULL, NULL);
    }

    if(seader->plugin_hf && seader->hf_plugin_ctx) {
        seader->plugin_hf->stop(seader->hf_plugin_ctx);
        seader->plugin_hf->free(seader->hf_plugin_ctx);
    }
    seader->hf_plugin_ctx = NULL;
    seader->plugin_hf = NULL;

    if(seader->hf_plugin_manager) {
        FURI_LOG_I(TAG, "Unloading HF plugin");
        plugin_manager_free(seader->hf_plugin_manager);
        seader->hf_plugin_manager = NULL;
    }

    if(seader->nfc_device) {
        nfc_device_free(seader->nfc_device);
        seader->nfc_device = NULL;
    }

    if(seader->nfc) {
        nfc_free(seader->nfc);
        seader->nfc = NULL;
    }
}

bool seader_worker_acquire(Seader* seader) {
    furi_assert(seader);

    if(seader->worker) {
        return true;
    }

    seader->worker = seader_worker_alloc();
    return seader->worker != NULL;
}

void seader_worker_release(Seader* seader) {
    furi_assert(seader);

    if(!seader->worker) {
        return;
    }

    seader_worker_stop(seader->worker);
    seader->worker->callback = NULL;
    seader->worker->context = NULL;
    seader_worker_change_state(seader->worker, SeaderWorkerStateReady);
}

void seader_scratch_reset(Seader* seader) {
    furi_assert(seader);
    seader->scratch.offset = 0U;
}

void* seader_scratch_alloc(Seader* seader, size_t size, size_t align) {
    furi_assert(seader);
    furi_assert(seader_align_is_valid(align));

    const size_t mask = align - 1U;
    const size_t aligned_offset = (seader->scratch.offset + mask) & ~mask;
    if(aligned_offset + size > sizeof(seader->scratch.arena)) {
        FURI_LOG_E(TAG, "Scratch overflow: need=%zu offset=%zu", size, aligned_offset);
        return NULL;
    }

    void* ptr = &seader->scratch.arena[aligned_offset];
    memset(ptr, 0, size);
    seader->scratch.offset = aligned_offset + size;
    if(seader->scratch.offset > seader->scratch.high_water) {
        seader->scratch.high_water = seader->scratch.offset;
    }

    return ptr;
}

bool seader_hf_mode_activate(Seader* seader) {
    furi_assert(seader);

    if(seader->hf_mode) {
        return true;
    }

    seader_scratch_reset(seader);
    seader->hf_mode =
        seader_scratch_alloc(seader, sizeof(SeaderHfModeContext), _Alignof(SeaderHfModeContext));
    if(!seader->hf_mode) {
        return false;
    }

    seader->hf_mode->selected_read_type = SeaderCredentialTypeNone;
    return true;
}

void seader_hf_mode_deactivate(Seader* seader) {
    furi_assert(seader);

    seader->hf_mode = NULL;
    seader_scratch_reset(seader);
}

SeaderCredentialType seader_hf_mode_get_selected_read_type(const Seader* seader) {
    return seader && seader->hf_mode ? seader->hf_mode->selected_read_type : SeaderCredentialTypeNone;
}

void seader_hf_mode_set_selected_read_type(Seader* seader, SeaderCredentialType type) {
    if(!seader || !seader->hf_mode) {
        FURI_LOG_W(
            TAG,
            "Ignoring HF selected read type update without mode context seader=%p hf_mode=%p type=%d",
            seader,
            seader ? seader->hf_mode : NULL,
            type);
        return;
    }
    seader->hf_mode->selected_read_type = type;
}

void seader_hf_mode_set_detected_types(
    Seader* seader,
    const SeaderCredentialType* types,
    size_t count) {
    if(!seader || !seader->hf_mode) {
        FURI_LOG_W(
            TAG,
            "Ignoring HF detected types update without mode context seader=%p hf_mode=%p count=%zu",
            seader,
            seader ? seader->hf_mode : NULL,
            count);
        return;
    }

    if(count > SEADER_MAX_DETECTED_CARD_TYPES) {
        count = SEADER_MAX_DETECTED_CARD_TYPES;
    }

    memset(seader->hf_mode->detected_card_types, 0, sizeof(seader->hf_mode->detected_card_types));
    if(types && count > 0) {
        memcpy(seader->hf_mode->detected_card_types, types, count * sizeof(types[0]));
    }
    seader->hf_mode->detected_card_type_count = count;
}

size_t seader_hf_mode_get_detected_type_count(const Seader* seader) {
    return seader && seader->hf_mode ? seader->hf_mode->detected_card_type_count : 0U;
}

const SeaderCredentialType* seader_hf_mode_get_detected_types(const Seader* seader) {
    return seader && seader->hf_mode ? seader->hf_mode->detected_card_types : NULL;
}

void seader_hf_mode_clear_detected_types(Seader* seader) {
    seader_hf_mode_set_detected_types(seader, NULL, 0U);
}

int32_t seader_app(void* p) {
    UNUSED(p);
    Seader* seader = seader_alloc();

    scene_manager_next_scene(seader->scene_manager, SeaderSceneStart);

    view_dispatcher_run(seader->view_dispatcher);

    seader_free(seader);

    return 0;
}
