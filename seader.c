#include "seader_i.h"

#define TAG "Seader"

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

Seader* seader_alloc() {
    Seader* seader = malloc(sizeof(Seader));

    seader->revert_power = !furi_hal_power_is_otg_enabled();
    if(seader->revert_power) {
        furi_hal_power_enable_otg();
    }
    seader->is_debug_enabled = furi_hal_rtc_is_flag_set(FuriHalRtcFlagDebug);
    seader->samCommand = SamCommand_PR_NOTHING;

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

    seader->nfc = nfc_alloc();

    // Nfc device
    seader->nfc_device = nfc_device_alloc();
    nfc_device_set_loading_callback(seader->nfc_device, seader_show_loading_popup, seader);

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

    seader->plugin_manager =
        plugin_manager_alloc(PLUGIN_APP_ID, PLUGIN_API_VERSION, firmware_api_interface);

    seader->plugin_wiegand = NULL;
    if(plugin_manager_load_all(seader->plugin_manager, APP_ASSETS_PATH("plugins")) !=
       PluginManagerErrorNone) {
        FURI_LOG_E(TAG, "Failed to load all libs");
    } else {
        uint32_t plugin_count = plugin_manager_get_count(seader->plugin_manager);
        FURI_LOG_I(TAG, "Loaded %lu plugin(s)", plugin_count);

        for(uint32_t i = 0; i < plugin_count; i++) {
            const PluginWiegand* plugin = plugin_manager_get_ep(seader->plugin_manager, i);
            FURI_LOG_I(TAG, "plugin name: %s", plugin->name);
            if(strcmp(plugin->name, "Plugin Wiegand") == 0) {
                // Have to cast to drop "const" qualifier
                seader->plugin_wiegand = (PluginWiegand*)plugin;
            }
        }
    }

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

    nfc_free(seader->nfc);

    // Nfc device
    nfc_device_free(seader->nfc_device);

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

    // Worker
    seader_worker_stop(seader->worker);
    seader_worker_free(seader->worker);

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

    plugin_manager_free(seader->plugin_manager);

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

int32_t seader_app(void* p) {
    UNUSED(p);
    Seader* seader = seader_alloc();

    scene_manager_next_scene(seader->scene_manager, SeaderSceneStart);

    view_dispatcher_run(seader->view_dispatcher);

    seader_free(seader);

    return 0;
}
