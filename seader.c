#include "seader_i.h"
#include "trace_log.h"

#define TAG "Seader"
#define SEADER_PLUGIN_DIR APP_ASSETS_PATH("plugins")

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

    FURI_LOG_I(TAG, "Loading Wiegand plugin from %s", SEADER_PLUGIN_DIR);
    if(plugin_manager_load_all(seader->plugin_manager, SEADER_PLUGIN_DIR) !=
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

    seader->plugin_wiegand = NULL;
    const uint32_t plugin_count = plugin_manager_get_count(seader->plugin_manager);
    for(uint32_t i = 0; i < plugin_count; i++) {
        const PluginWiegand* plugin = plugin_manager_get_ep(seader->plugin_manager, i);
        if(plugin && strcmp(plugin->name, "Plugin Wiegand") == 0) {
            seader->plugin_wiegand = (PluginWiegand*)plugin;
            break;
        }
    }

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
