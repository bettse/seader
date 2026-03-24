#include "hf_release_sequence.h"

static void seader_hf_release_callback_invoke(
    SeaderHfReleaseCallback callback,
    void* context) {
    if(callback) {
        callback(context);
    }
}

void seader_hf_release_sequence_run(SeaderHfReleaseSequence* sequence) {
    if(!sequence) {
        return;
    }

    if(sequence->hf_session_state) {
        *sequence->hf_session_state = SeaderHfSessionStateTearingDown;
    }
    seader_hf_release_callback_invoke(sequence->plugin_stop, sequence->context);
    seader_hf_release_callback_invoke(sequence->host_poller_release, sequence->context);
    seader_hf_release_callback_invoke(sequence->host_picopass_release, sequence->context);
    seader_hf_release_callback_invoke(sequence->plugin_free, sequence->context);
    seader_hf_release_callback_invoke(sequence->plugin_manager_unload, sequence->context);
    seader_hf_release_callback_invoke(sequence->worker_reset, sequence->context);
    if(sequence->hf_session_state) {
        *sequence->hf_session_state = SeaderHfSessionStateUnloaded;
    }
    if(sequence->mode_runtime && *sequence->mode_runtime == SeaderModeRuntimeHF) {
        *sequence->mode_runtime = SeaderModeRuntimeNone;
    }
}
